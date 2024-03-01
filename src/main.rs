#![allow(dead_code)]
extern crate libc;
extern crate nix;

use angry_oxide::config::Arguments;
use angry_oxide::processing::process_frame;
use angry_oxide::util::read_frame;
use angry_oxide::{oxideruntime, pcapng, targets};
use anyhow::Result;


use chrono::Local;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseEventKind,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

use libc::EXIT_FAILURE;
use libwifi::frame::components::MacAddress;
use nix::unistd::geteuid;
use nl80211_ng::{get_interface_info_idx, set_interface_chan};

use flate2::write::GzEncoder;
use flate2::Compression;

use oxideruntime::OxideRuntime;
use pcapng::PcapWriter;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tar::Builder;
use targets::Target;

use tracing_appender::rolling;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use angry_oxide::ascii::get_art;

use angry_oxide::eventhandler::EventType;
use angry_oxide::status::*;
use angry_oxide::ui::{print_ui, MenuType};

use crossterm::{cursor::Hide, cursor::Show, execute};

use std::collections::HashMap;
use std::fs::{remove_file, File, OpenOptions};
use std::io::stdout;
use std::io::Write;
use std::io::{self};
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::from_env("AO_LOG_LEVEL");
    let file_appender = rolling::minutely("./logs", "angryoxide.log");

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    Registry::default()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
        .init();

    let cli = Arguments::parse();

    if !geteuid().is_root() {
        println!("{}", get_art("You need to run as root!"));
        exit(EXIT_FAILURE);
    }

    let mut oxide = OxideRuntime::new(&cli);

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        "Starting...".to_string(),
    ));

    let iface = oxide.if_hardware.interface.clone();
    let idx = iface.index.unwrap();
    let interface_name = String::from_utf8(iface.clone().name.unwrap())
        .expect("cannot get interface name from bytes.");

    let duration = Duration::from_secs(1);
    thread::sleep(duration);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let mut seconds_timer = Instant::now();
    let seconds_interval = Duration::from_secs(1);
    let mut frame_count_old = 0u64;
    let mut frame_rate = 0u64;

    let mut last_status_time = Instant::now();

    let status_interval = if oxide.config.headless {
        Duration::from_secs(1)
    } else {
        Duration::from_millis(50)
    };

    // Setup hop data
    let mut last_hop_time = Instant::now();
    let mut first_channel = (0u8, 0u32);
    let mut hop_cycle: u32 = 0;

    // Set starting channel and create the hopper cycle.
    let mut old_hops = oxide.if_hardware.hop_channels.clone();
    let mut channels_binding = oxide.if_hardware.hop_channels.clone();
    let mut cycle_iter = channels_binding.iter().cycle();
    if let Some(&(band, channel)) = cycle_iter.next() {
        first_channel = (band, channel);
        if let Err(e) = set_interface_chan(idx, channel, band) {
            eprintln!("{}", e);
        }
    }

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!(
            "Setting channel hopper: {:?}",
            oxide.if_hardware.hop_channels
        ),
    ));

    let start_time = Instant::now();

    let mut err: Option<String> = None;
    let mut exit_on_succ = false;
    let mut terminal =
        Terminal::new(CrosstermBackend::new(stdout())).expect("Cannot allocate terminal");

    if !oxide.config.headless {
        // UI is in normal mode
        execute!(stdout(), Hide)?;
        execute!(stdout(), EnterAlternateScreen)?;
        execute!(stdout(), EnableMouseCapture)?;
        enable_raw_mode()?;
        initialize_panic_handler();
    } else {
        // UI is in headless mode
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
    }

    while running.load(Ordering::SeqCst) {
        // Update our interface
        oxide.if_hardware.interface =
            match get_interface_info_idx(oxide.if_hardware.interface.index.unwrap()) {
                Ok(interface) => interface,
                Err(e) => {
                    // Uh oh... no interfacee
                    err = Some(e);
                    running.store(false, Ordering::SeqCst);
                    break;
                }
            };

        // Handle Hunting
        let target_chans = oxide.if_hardware.target_chans.clone();
        if oxide.config.autohunt
            && hop_cycle >= 3
            && !target_chans.values().any(|value| value.is_empty())
        {
            // We are done auto-hunting.
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Priority,
                "=== AutoHunting Complete! ===".to_string(),
            ));
            for target in oxide.target_data.targets.get_ref() {
                if let Some(channels) = target_chans.get(target) {
                    let chans = format_channels(channels);
                    oxide.status_log.add_message(StatusMessage::new(
                        MessageType::Priority,
                        format!("Target: {} | Channels: [ {} ]", target.get_string(), chans),
                    ));
                }
            }

            let mut new_hops: Vec<(u8, u32)> = Vec::new();
            for (_, chan) in target_chans {
                for ch in chan {
                    if !new_hops.contains(&ch) {
                        new_hops.push(ch);
                    }
                }
            }

            // Setup channels hops
            oxide.if_hardware.hop_channels = new_hops;
            old_hops = oxide.if_hardware.hop_channels.clone();
            oxide.if_hardware.hop_interval = Duration::from_secs(cli.dwell);
            channels_binding = oxide.if_hardware.hop_channels.clone();
            cycle_iter = channels_binding.iter().cycle();
            first_channel = *cycle_iter.next().unwrap();

            oxide.config.autohunt = false; // Disable autohunt.
            if !cli.notransmit {
                oxide.config.notx = false; // Turn notx back to false unless CLI notransmit is true.
            }
        }

        // Calculate status rates
        if seconds_timer.elapsed() >= seconds_interval {
            seconds_timer = Instant::now();

            // Calculate the frame rate
            let frames_processed = oxide.counters.frame_count - frame_count_old;
            frame_count_old = oxide.counters.frame_count;
            frame_rate = frames_processed;

            // Update the empty reads rate
            oxide.counters.empty_reads_rate = oxide.counters.empty_reads;
            oxide.counters.empty_reads = 0;
        }

        // Make sure our pcap isn't too big, replace if it is.
        if oxide.file_data.current_pcap.check_size() >= 100000000u64 {
            oxide.file_data.current_pcap.stop();
            let now: chrono::prelude::DateTime<Local> = Local::now();
            let date_time = now.format("-%Y-%m-%d_%H-%M-%S").to_string();
            let pcap_filename = format!("{}{}.pcapng", oxide.file_data.file_prefix, date_time);
            let mut pcap_file = PcapWriter::new(&iface, &pcap_filename);
            pcap_file.start();
            oxide.file_data.current_pcap = pcap_file;
            oxide.file_data.output_files.push(pcap_filename);
        }

        // Channel hopping. This can still interrupt multi-step attacks but isn't likely to do so.
        if last_hop_time.elapsed() >= oxide.if_hardware.hop_interval {
            if let Some(&(band, channel)) = cycle_iter.next() {
                if (band, channel) == first_channel {
                    hop_cycle += 1;
                }
                if let Err(e) = oxide
                    .if_hardware
                    .netlink
                    .set_interface_chan(idx, channel, band)
                {
                    oxide.status_log.add_message(StatusMessage::new(
                        MessageType::Error,
                        format!("Channel Switch Error: {e:?}"),
                    ));
                }
                oxide.if_hardware.current_channel = channel;
                last_hop_time = Instant::now();
            }
        }
        let table_len = oxide.get_current_menu_len();

        // This should ONLY apply to normal UI mode.
        if !oxide.config.headless {
            if let Some(ev) = oxide.eventhandler.get() {
                match ev {
                    EventType::Key(event) => {
                        if let Event::Key(key) = event {
                            if key.kind == KeyEventKind::Press {
                                match key.code {
                                    KeyCode::Char('d') | KeyCode::Right => {
                                        oxide.ui_state.menu_next()
                                    }
                                    KeyCode::Char('a') | KeyCode::Left => {
                                        oxide.ui_state.menu_back()
                                    }
                                    KeyCode::Char('w') | KeyCode::Char('W') | KeyCode::Up => {
                                        if key.modifiers.intersects(KeyModifiers::SHIFT) {
                                            oxide.ui_state.table_previous_item_big();
                                        } else {
                                            oxide.ui_state.table_previous_item();
                                        }
                                    }
                                    KeyCode::Char('s') | KeyCode::Char('S') | KeyCode::Down => {
                                        if key.modifiers.intersects(KeyModifiers::SHIFT) {
                                            oxide.ui_state.table_next_item_big(table_len);
                                        } else {
                                            oxide.ui_state.table_next_item(table_len);
                                        }
                                    }
                                    KeyCode::Char('q') => {
                                        oxide.ui_state.show_quit = !oxide.ui_state.show_quit;
                                    }
                                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                                        if oxide.ui_state.show_quit {
                                            running.store(false, Ordering::SeqCst)
                                        }
                                    }
                                    KeyCode::Char('n') | KeyCode::Char('N') => {
                                        if oxide.ui_state.show_quit {
                                            oxide.ui_state.show_quit = false;
                                        }
                                    }
                                    KeyCode::Char(' ') => oxide.ui_state.toggle_pause(),
                                    KeyCode::Char('e') => oxide.ui_state.sort_next(),
                                    KeyCode::Char('r') => oxide.ui_state.toggle_reverse(),
                                    KeyCode::Char('c') => {
                                        oxide.ui_state.copy_short = true;
                                    }
                                    KeyCode::Char('C') => {
                                        oxide.ui_state.copy_long = true;
                                    }
                                    KeyCode::Char('t') => {
                                        oxide.ui_state.add_target = true;
                                    }
                                    KeyCode::Char('T') => {
                                        oxide.ui_state.add_target = true;
                                        oxide.ui_state.set_autoexit = true;
                                    }
                                    KeyCode::Char('k') => {
                                        oxide.ui_state.show_keybinds =
                                            !oxide.ui_state.show_keybinds;
                                    }
                                    KeyCode::Char('l') => {
                                        if oxide.if_hardware.locked {
                                            oxide.status_log.add_message(StatusMessage::new(
                                                MessageType::Info,
                                                "Unlocking Channel".to_string(),
                                            ));

                                            // Setup channels hops
                                            oxide.if_hardware.hop_channels = old_hops.clone();
                                            channels_binding =
                                                oxide.if_hardware.hop_channels.clone();
                                            cycle_iter = channels_binding.iter().cycle();
                                            first_channel = *cycle_iter.next().unwrap();
                                            oxide.if_hardware.locked = !oxide.if_hardware.locked;
                                        } else {
                                            // Get target_chans
                                            old_hops = oxide.if_hardware.hop_channels.clone();
                                            let new_hops: Vec<(u8, u32)> = vec![(
                                                oxide.if_hardware.current_band.to_u8(),
                                                oxide.if_hardware.current_channel,
                                            )];

                                            if !new_hops.is_empty() {
                                                // Setup channels hops
                                                oxide.if_hardware.hop_channels = new_hops;
                                                channels_binding =
                                                    oxide.if_hardware.hop_channels.clone();
                                                cycle_iter = channels_binding.iter().cycle();
                                                first_channel = *cycle_iter.next().unwrap();

                                                oxide.status_log.add_message(StatusMessage::new(
                                                    MessageType::Info,
                                                    format!(
                                                        "Locking to Channel {} ({:?})",
                                                        oxide.if_hardware.current_channel,
                                                        oxide.if_hardware.current_band,
                                                    ),
                                                ));

                                                oxide.if_hardware.locked =
                                                    !oxide.if_hardware.locked;
                                            } else {
                                                oxide.status_log.add_message(StatusMessage::new(
                                                    MessageType::Warning,
                                                    "Could not lock: No Channel".to_string(),
                                                ));
                                            }
                                        }
                                    }
                                    KeyCode::Char('L') => {
                                        if oxide.if_hardware.locked {
                                            // Setup channels hops
                                            oxide.if_hardware.hop_channels = old_hops.clone();
                                            channels_binding =
                                                oxide.if_hardware.hop_channels.clone();
                                            cycle_iter = channels_binding.iter().cycle();
                                            first_channel = *cycle_iter.next().unwrap();

                                            oxide.status_log.add_message(StatusMessage::new(
                                                MessageType::Info,
                                                "Unlocking Channel".to_string(),
                                            ));
                                            oxide.if_hardware.locked = !oxide.if_hardware.locked;
                                        } else {
                                            // Get target_chans
                                            old_hops = oxide.if_hardware.hop_channels.clone();
                                            let target_chans =
                                                oxide.if_hardware.target_chans.clone();
                                            let mut new_hops: Vec<(u8, u32)> = Vec::new();

                                            for (_, chan) in target_chans {
                                                for ch in chan {
                                                    if !new_hops.contains(&ch) {
                                                        new_hops.push(ch);
                                                    }
                                                }
                                            }

                                            if !new_hops.is_empty() {
                                                // Setup channels hops
                                                oxide.if_hardware.hop_channels = new_hops;
                                                channels_binding =
                                                    oxide.if_hardware.hop_channels.clone();
                                                cycle_iter = channels_binding.iter().cycle();
                                                first_channel = *cycle_iter.next().unwrap();

                                                oxide.status_log.add_message(StatusMessage::new(
                                                    MessageType::Info,
                                                    format!(
                                                        "Locking to Target Channels! {:?}",
                                                        oxide.if_hardware.hop_channels,
                                                    ),
                                                ));

                                                oxide.if_hardware.locked =
                                                    !oxide.if_hardware.locked;
                                            } else {
                                                oxide.status_log.add_message(StatusMessage::new(
                                                    MessageType::Warning,
                                                    "Could not lock: No Target Channels"
                                                        .to_string(),
                                                ));
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        } else if let Event::Mouse(event) = event {
                            match event.kind {
                                MouseEventKind::ScrollDown => {
                                    oxide.ui_state.table_next_item(table_len)
                                }
                                MouseEventKind::ScrollUp => oxide.ui_state.table_previous_item(),
                                _ => {}
                            }
                        }
                    }
                    EventType::Tick => {
                        let _ = print_ui(&mut terminal, &mut oxide, start_time, frame_rate);
                    }
                }
            }
        }

        if oxide.ui_state.add_target {
            match oxide.ui_state.current_menu {
                MenuType::AccessPoints => {
                    if let Some(ref ap) = oxide.ui_state.ap_selected_item {
                        if let Some(accesspoint) = oxide.access_points.get_device(&ap.mac_address) {
                            oxide
                                .target_data
                                .targets
                                .add(Target::MAC(targets::TargetMAC {
                                    addr: ap.mac_address,
                                }));
                            accesspoint.is_target = true;
                            if let Some(ssid) = &ap.ssid {
                                oxide
                                    .target_data
                                    .targets
                                    .add(Target::SSID(targets::TargetSSID {
                                        ssid: ssid.to_string(),
                                    }));
                            }
                            if oxide.config.notx {
                                oxide.config.notx = false;
                            }
                            if oxide.ui_state.set_autoexit {
                                oxide.config.autoexit = true;
                            }
                        }
                    }
                }
                MenuType::Clients => {}
                MenuType::Handshakes => {}
                MenuType::Messages => {}
            }
            oxide.ui_state.add_target = false;
            oxide.ui_state.set_autoexit = false;
        }

        // Headless UI status messages

        if last_status_time.elapsed() >= status_interval {
            last_status_time = Instant::now();
            if oxide.config.headless {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Status,
                    format!(
                        "Frames: {} | Rate: {} | ERs: {} | Channel: {}",
                        oxide.counters.frame_count,
                        frame_rate,
                        oxide.counters.empty_reads_rate,
                        oxide.if_hardware.current_channel,
                    ),
                ));
                //print_handshakes_headless(&mut oxide);
            }
        }

        // Read Frame
        match read_frame(&mut oxide) {
            Ok(packet) => {
                if !packet.is_empty() {
                    let _ = process_frame(&mut oxide, &packet);
                }
            }
            Err(code) => {
                if code.kind().to_string() == "network down" {
                    oxide
                        .if_hardware
                        .netlink
                        .set_interface_up(oxide.if_hardware.interface.index.unwrap())
                        .ok();
                } else {
                    // This will result in error message.
                    err = Some(code.kind().to_string());
                    running.store(false, Ordering::SeqCst);
                }
            }
        };

        // Exit on targets success
        if oxide.config.autoexit && oxide.get_target_success() {
            running.store(false, Ordering::SeqCst);
            exit_on_succ = true;
        }

        // Handshake writing
        for handshakes in oxide.handshake_storage.get_handshakes().values_mut() {
            if !handshakes.is_empty() {
                for hs in handshakes {
                    if hs.complete() && !hs.is_wpa3() && !hs.written() {
                        if let Some(hashcat_string) = hs.to_hashcat_22000_format() {
                            let essid = hs.essid_to_string();
                            let hashline = hashcat_string;

                            // Determine filename to use
                            let file_name = if oxide.config.combine {
                                if oxide.file_data.file_prefix == "oxide" {
                                    format!(
                                        "{}{}.hc22000",
                                        oxide.file_data.file_prefix, oxide.file_data.start_time
                                    )
                                } else {
                                    format!("{}.hc22000", oxide.file_data.file_prefix)
                                }
                            } else {
                                format!("{}.hc22000", essid)
                            };

                            let path = Path::new(&file_name);

                            let mut file = OpenOptions::new()
                                .write(true)
                                .create(true)
                                .append(true)
                                .open(path)
                                .unwrap_or_else(|_| {
                                    panic!("Could not open hashfile for writing. ({file_name}).")
                                });

                            writeln!(file, "{}", hashline).unwrap_or_else(|_| {
                                panic!("Couldn't  write to hashfile. ({file_name}).")
                            });

                            if !oxide.file_data.output_files.contains(&file_name) {
                                oxide.file_data.output_files.push(file_name);
                            }

                            // Mark this handshake as written
                            hs.written = true;

                            // Mark this AP has having collected HS / PMKID
                            if let Some(ap) = oxide.access_points.get_device(&hs.mac_ap.unwrap()) {
                                if hs.has_pmkid() && ap.information.akm_mask() {
                                    ap.has_pmkid = true;
                                }
                                if hs.has_4whs() && !hs.is_wpa3() {
                                    ap.has_hs = true;
                                }
                            }

                            oxide.status_log.add_message(StatusMessage::new(
                                MessageType::Priority,
                                format!(
                                    "hc22000 Written: {} => {} ({})",
                                    hs.mac_ap.unwrap_or(MacAddress::zeroed()),
                                    hs.mac_client.unwrap_or(MacAddress::zeroed()),
                                    hs.essid.clone().unwrap_or("".to_string())
                                ),
                            ));

                            // fill the hashlines data (for reference later)
                            oxide
                                .file_data
                                .hashlines
                                .entry(essid)
                                .and_modify(|e| {
                                    if hs.has_4whs() {
                                        e.0 += 1;
                                    }
                                    if hs.has_pmkid() {
                                        e.1 += 1;
                                    }
                                })
                                .or_insert_with(|| {
                                    (
                                        if hs.has_4whs() { 1 } else { 0 },
                                        if hs.has_pmkid() { 1 } else { 0 },
                                    )
                                });
                        }
                    }
                }
            }
        }

        // Save those precious CPU cycles when we can. Any more of a wait and we can't process fast enough.
        thread::sleep(Duration::from_micros(1));
    }

    // Execute cleanup
    if !oxide.config.headless {
        reset_terminal();
    }

    if exit_on_succ {
        println!("💲 Auto Exit Initiated");
    }

    println!("💲 Cleaning up...");
    if let Some(err) = err {
        println!("{}", get_art(&format!("Error: {}", err)))
    }

    println!("💲 Setting {} down.", interface_name);
    match oxide.if_hardware.netlink.set_interface_down(idx) {
        Ok(_) => {}
        Err(e) => println!("Error: {e:?}"),
    }

    println!(
        "💲 Restoring {} MAC back to {}.",
        interface_name, oxide.if_hardware.original_address
    );
    oxide
        .if_hardware
        .netlink
        .set_interface_mac(idx, &oxide.if_hardware.original_address.0)
        .ok();

    println!("💲 Setting {} to station mode.", interface_name);
    match oxide.if_hardware.netlink.set_interface_station(idx) {
        Ok(_) => {}
        Err(e) => println!("Error: {e:?}"),
    }

    println!("💲 Stopping Threads");
    oxide.file_data.current_pcap.stop();
    oxide.file_data.gps_source.stop();
    oxide.file_data.db_writer.stop();

    println!();

    if !oxide.file_data.hashlines.is_empty() {
        println!("😈 Results:");
        for (key, (handshake_acc, pmkid_acc)) in oxide.file_data.hashlines {
            println!("[{}] : 4wHS: {} | PMKID: {}", key, handshake_acc, pmkid_acc);
        }
        println!();
    } else {
        println!(
            "AngryOxide did not collect any results. 😔 Try running longer, or check your interface?"
        );
    }

    let mut tarfile = oxide.file_data.file_prefix.to_owned();
    if tarfile == "oxide" {
        tarfile = format!("oxide{}", oxide.file_data.start_time);
    }

    if !oxide.config.notar {
        println!("📦 Creating Output Tarball ({}.tar.gz).", tarfile);
        println!("Please wait...");
        let _ = tar_and_compress_files(oxide.file_data.output_files, &tarfile);
    }
    println!();
    println!("Complete! Happy Cracking! 🤙");

    Ok(())
}

fn tar_and_compress_files(output_files: Vec<String>, filename: &str) -> io::Result<()> {
    let tgz = File::create(format!("{}.tar.gz", filename))?;
    let enc = GzEncoder::new(tgz, Compression::default());
    let mut tar = Builder::new(enc);

    for path in &output_files {
        let mut file = File::open(path)?;
        tar.append_file(path, &mut file)?;
    }

    tar.into_inner()?;

    // Delete original files after they are successfully added to the tarball
    for path in &output_files {
        if let Err(e) = remove_file(path) {
            eprintln!("Failed to delete file {}: {}", path, e);
        }
    }

    Ok(())
}

pub fn initialize_panic_handler() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        reset_terminal();
        original_hook(panic_info);
    }));
}

fn reset_terminal() {
    execute!(stdout(), Show).expect("Could not show cursor.");
    execute!(io::stdout(), LeaveAlternateScreen).expect("Could not leave alternate screen");
    execute!(stdout(), DisableMouseCapture).expect("Could not disable mouse capture.");
    disable_raw_mode().expect("Could not disable raw mode.");
}

fn format_channels(channels: &Vec<(u8, u32)>) -> String {
    let mut band_map: HashMap<u8, Vec<u32>> = HashMap::new();

    // Group by band
    for &(band, channel) in channels {
        band_map.entry(band).or_default().push(channel);
    }

    // Sort channels within each band
    for channels in band_map.values_mut() {
        channels.sort();
    }

    // Collect and format the string
    let mut parts: Vec<String> = Vec::new();
    for (&band, channels) in &band_map {
        let channels_str = channels
            .iter()
            .map(|channel| channel.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("Band {}: {}", band, channels_str));
    }

    // Sort the bands for consistent ordering
    parts.sort();

    // Join all parts into a single string
    parts.join(" | ")
}
