use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufRead, BufReader},
    os::fd::AsRawFd,
    process::exit,
    str::FromStr,
    thread,
    time::{Duration, SystemTime},
};

use crate::{
    attackrate::AttackRate,
    database::DatabaseWriter,
    gps::GPSDSource,
    matrix::MatrixSnowstorm,
    oui::OuiDatabase,
    pcapng::PcapWriter,
    rawsocks::{open_socket_rx, open_socket_tx},
    snowstorm::Snowstorm,
    targets::{Target, TargetList, TargetMAC, TargetSSID},
    ui::MenuType,
    util::parse_ip_address_port,
    whitelist::{White, WhiteList, WhiteMAC, WhiteSSID},
};
use chrono::Local;
use libc::EXIT_FAILURE;
use libwifi::frame::{components::MacAddress, EapolKey};
use nl80211_ng::{
    attr::Nl80211Iftype,
    channels::{map_str_to_band_and_channel, WiFiBand},
    get_interface_info_idx, Nl80211,
};
use rand::{thread_rng, Rng};
use ratatui::{layout::Rect, widgets::TableState};
use uuid::Uuid;

use crate::config::Arguments;
use crate::setup::{Config, Counters, FileData, IfHardware, RawSockets, TargetData};
use crate::{
    ascii::get_art,
    auth::HandshakeStorage,
    devices::{AccessPoint, Station, WiFiDeviceList},
    eventhandler::EventHandler,
    status,
    ui::UiState,
};

pub struct OxideRuntime {
    pub ui_state: UiState,
    pub counters: Counters,
    pub access_points: WiFiDeviceList<AccessPoint>,
    pub unassoc_clients: WiFiDeviceList<Station>,
    pub handshake_storage: HandshakeStorage,
    pub status_log: status::MessageLog,
    pub eventhandler: EventHandler,
    pub raw_sockets: RawSockets,
    pub file_data: FileData,
    pub target_data: TargetData,
    pub if_hardware: IfHardware,
    pub config: Config,
}

impl OxideRuntime {
    #[tracing::instrument(skip(cli_args))]
    pub fn new(cli_args: &Arguments) -> Self {
        println!("Starting AngryOxide... 😈");

        let rogue = cli_args.rogue.clone();
        let interface_name = cli_args.interface.clone();
        let targets = cli_args.target_entry.clone();
        let wh_list = cli_args.whitelist_entry.clone();
        let targetsfile = cli_args.targetlist.clone();
        let wh_listfile = cli_args.whitelist.clone();
        let dwell = cli_args.dwell;
        let mut notransmit = cli_args.notransmit;

        // Setup initial lists / logs
        let access_points = WiFiDeviceList::new();
        let unassoc_clients = WiFiDeviceList::new();
        let handshake_storage = HandshakeStorage::new();
        let log = status::MessageLog::new(cli_args.headless, Some(500));

        // Get + Setup Interface

        let mut netlink = Nl80211::new().expect("Cannot open Nl80211");

        tracing::debug!(%interface_name, "Searching for network interface");

        let iface = if let Some(interface) = netlink
            .get_interfaces()
            .iter()
            .find(|&(_, iface)| iface.name_as_string() == interface_name)
            .map(|(_, iface)| iface.clone())
        {
            tracing::info!(%interface_name, "Network interface found");
            interface
        } else {
            tracing::error!(%interface_name, "Interface not found");
            println!("{}", get_art("Interface not found"));
            std::process::exit(EXIT_FAILURE);
        };

        let original_address = MacAddress::from_vec(iface.clone().mac.unwrap()).unwrap();

        let idx = iface.index.unwrap();
        let interface_uuid = Uuid::new_v4();
        println!("💲 Interface Summary:");
        println!("{}", iface.pretty_print());

        // Setup targets
        let mut target_vec: Vec<Target> = if let Some(vec_targets) = targets {
            vec_targets
                .into_iter()
                .map(|f| match MacAddress::from_str(&f) {
                    Ok(mac) => Target::MAC(TargetMAC::new(mac)),
                    Err(_) => Target::SSID(TargetSSID::new(&f)),
                })
                .collect()
        } else {
            vec![]
        };

        if let Some(file) = targetsfile {
            match File::open(file) {
                Ok(f) => {
                    let reader = BufReader::new(f);

                    for line in reader.lines() {
                        if line.as_ref().is_ok_and(|f| f.is_empty()) {
                            continue;
                        }
                        let target = match line {
                            Ok(l) => match MacAddress::from_str(&l) {
                                Ok(mac) => Target::MAC(TargetMAC::new(mac)),
                                Err(_) => Target::SSID(TargetSSID::new(&l)),
                            },
                            Err(_) => {
                                continue;
                            }
                        };
                        target_vec.push(target);
                    }
                }
                Err(e) => {
                    tracing::error!(%e, "Error opening target file");
                    println!("❌ Error opening target file: {}", e);
                    println!("❌ Exiting...");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if !target_vec.is_empty() {
            println!();
            println!("========= Target List =========");
            for (index, target) in target_vec.iter().enumerate() {
                let tree = if index == target_vec.len() - 1 {
                    "└"
                } else {
                    "├"
                };
                match target {
                    Target::MAC(tgt) => {
                        println!(" {} MAC: {}", tree, tgt.addr)
                    }
                    Target::SSID(tgt) => {
                        println!(" {} SSID: {}", tree, tgt.ssid)
                    }
                }
            }
            println!("========== Total: {:<2} ==========", target_vec.len());
            println!();
            if cli_args.autoexit {
                println!(
                    "💲 --autoexit set - will shutdown when hashline collected for ALL targets."
                );
            }
        } else {
            println!("💲 No target list provided... everything is a target 😏");
        }

        let targ_list = TargetList::from_vec(target_vec.clone());

        // Setup Whitelist
        let mut whitelist_vec: Vec<White> = if let Some(vec_whitelist) = wh_list {
            vec_whitelist
                .into_iter()
                .filter_map(|f| match MacAddress::from_str(&f) {
                    Ok(mac) => {
                        if targ_list.is_actual_target_mac(&mac) {
                            println!("❌ Whitelist {} is a target. Cannot add to whitelist.", mac);
                            None
                        } else {
                            Some(White::MAC(WhiteMAC::new(mac)))
                        }
                    }
                    Err(_) => {
                        if targ_list.is_actual_target_ssid(&f) {
                            println!("❌ Whitelist {} is a target. Cannot add to whitelist.", f);
                            None
                        } else {
                            Some(White::SSID(WhiteSSID::new(&f)))
                        }
                    }
                })
                .collect()
        } else {
            vec![]
        };

        if let Some(file) = wh_listfile {
            match File::open(file) {
                Ok(f) => {
                    let reader = BufReader::new(f);

                    for line in reader.lines() {
                        if line.as_ref().is_ok_and(|f| f.is_empty()) {
                            continue;
                        }
                        let white = match line {
                            Ok(l) => {
                                match MacAddress::from_str(&l) {
                                    Ok(mac) => {
                                        if targ_list.is_actual_target_mac(&mac) {
                                            println!("❌ Whitelist {} is a target. Cannot add to whitelist.", mac);
                                            continue;
                                        } else {
                                            White::MAC(WhiteMAC::new(mac))
                                        }
                                    }
                                    Err(_) => {
                                        if targ_list.is_actual_target_ssid(&l) {
                                            println!("❌ Whitelist {} is a target. Cannot add to whitelist.", l);
                                            continue;
                                        } else {
                                            White::SSID(WhiteSSID::new(&l))
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                continue;
                            }
                        };
                        whitelist_vec.push(white);
                    }
                }
                Err(e) => {
                    tracing::error!(%e, "Error opening whitelist file:");
                    println!("❌ Error opening whitelist file: {}", e);
                    println!("❌ Exiting...");
                    exit(EXIT_FAILURE);
                }
            }
        }

        if !whitelist_vec.is_empty() {
            println!();
            println!("========= White List =========");
            for (index, device) in whitelist_vec.iter().enumerate() {
                let tree = if index == whitelist_vec.len() - 1 {
                    "└"
                } else {
                    "├"
                };
                match device {
                    White::MAC(dev) => {
                        println!(" {} MAC: {}", tree, dev.addr)
                    }
                    White::SSID(dev) => {
                        println!(" {} SSID: {}", tree, dev.ssid)
                    }
                }
            }
            println!("========== Total: {:<2} ==========", whitelist_vec.len());
            println!();
        } else {
            println!("💲 No whitelist list provided.");
        }

        let white_list = WhiteList::from_vec(whitelist_vec.clone());

        /////////////////////////////////////////////////////////////////////

        //// Setup Channels ////

        let mut iface_bands: BTreeMap<u8, Vec<u32>> = iface
            .get_frequency_list_simple()
            .unwrap()
            .into_iter()
            .collect();
        for (_key, value) in iface_bands.iter_mut() {
            value.sort(); // This sorts each vector in place
        }

        let mut hop_channels: Vec<(u8, u32)> = Vec::new();
        let mut hop_interval: Duration = Duration::from_secs(dwell);
        let mut target_chans: HashMap<Target, Vec<(u8, u32)>> = HashMap::new();
        let mut can_autohunt = cli_args.autohunt;

        if can_autohunt && targ_list.empty() {
            can_autohunt = false;
            println!("❌ --autohunt enabled but no targets given... ignoring.")
        }

        if can_autohunt && (!cli_args.band.is_empty() || !cli_args.channel.is_empty()) {
            println!("❌ --autohunt and channels/bands given. Ignoring supplied channels/bands.")
        }

        if can_autohunt {
            println!("🏹 Auto Hunting enabled - will attempt to locate target channels.");

            // Because we are autohunting - let's just add every available channel
            for (band, channels) in iface_bands {
                for channel in channels {
                    hop_channels.push((band, channel));
                }
            }

            // Set our hop interval much faster while hunting
            hop_interval = Duration::from_millis(100);
            // Set notx to true
            notransmit = true;

            // Setup our initial** target_chans
            for target in target_vec {
                target_chans.insert(target, vec![]);
            }
        } else {
            let mut channels = cli_args.channel.clone();
            let bands = cli_args.band.clone();
            let mut default_chans = false;

            if bands.is_empty() && channels.is_empty() {
                channels.extend(vec![
                    String::from("1"),
                    String::from("6"),
                    String::from("11"),
                ]);
                default_chans = true;
            }

            // Add all channels from bands
            for band in &bands {
                let band_chans = if let Some(chans) = iface_bands.get(band) {
                    chans.clone()
                } else {
                    println!(
                        "WARNING: Band {} not available for interface {}... ignoring",
                        band,
                        iface.name_as_string()
                    );
                    vec![]
                };
                for chan in band_chans {
                    hop_channels.push((*band, chan));
                }
            }

            // Add all individual channels (if valid)

            for channel in &channels {
                if let Some((band, channel)) = map_str_to_band_and_channel(channel) {
                    let band_u8 = band.to_u8();
                    if !hop_channels.contains(&(band_u8, channel)) {
                        if iface_bands.get(&band_u8).unwrap().contains(&channel) {
                            hop_channels.push((band_u8, channel));
                        } else {
                            println!(
                                "WARNING: Channel {} not available for interface {}... ignoring.",
                                channel,
                                iface.name_as_string()
                            );
                        }
                    }
                }
            }

            // Exit if we tried to provide channels but nothing made it to the hopper.
            if !default_chans && hop_channels.is_empty() {
                println!(
                    "{}",
                    get_art(&format!(
                        "No channels provided are supported by {}",
                        iface.name_as_string()
                    ))
                );
                exit(EXIT_FAILURE);
            }

            // Organize channels by band
            let mut channels_by_band: HashMap<u8, Vec<u32>> = HashMap::new();
            for (band, channel) in hop_channels.clone() {
                channels_by_band.entry(band).or_default().push(channel);
            }

            // Sort channels within each band
            for channels in channels_by_band.values_mut() {
                channels.sort();
            }

            // Print channels by band
            println!();
            println!("======== Hop Channels ========");
            for (index, (band, channels)) in channels_by_band.iter().enumerate() {
                let band_tree = if index == channels_by_band.len() - 1 {
                    "└"
                } else {
                    "├"
                };
                println!(" {} Band {} Channels:", band_tree, band,);
                for (idx, channel) in channels.iter().enumerate() {
                    let chan_b_tree = if index == channels_by_band.len() - 1 {
                        " "
                    } else {
                        "│"
                    };
                    let chan_tree = if idx == channels.len() - 1 {
                        "└"
                    } else {
                        "├"
                    };
                    println!(" {} {} {}", chan_b_tree, chan_tree, channel)
                }
            }
            println!("==============================");
            println!();
        }

        // Print Dwell Time
        println!("💲 Dwell Time: {}", cli_args.dwell);

        // Print attack Rate

        if notransmit && !can_autohunt {
            println!(
                "💲 Attack Rate: {} ({}) [NO TRANSMIT ENABLED]",
                AttackRate::from_u8(cli_args.rate),
                cli_args.rate
            );
        } else {
            println!(
                "💲 Attack Rate: {} ({})",
                AttackRate::from_u8(cli_args.rate),
                cli_args.rate
            );
        }

        ///////////////////////////////

        if let Some(ref phy) = iface.phy {
            if !phy.iftypes.clone().is_some_and(|types| {
                types.contains(&nl80211_ng::attr::Nl80211Iftype::IftypeMonitor)
            }) {
                println!(
                    "{}",
                    get_art("Monitor Mode not available for this interface.")
                );
                tracing::error!("Monitor Mode not available for this interface");
                exit(EXIT_FAILURE);
            }
        }

        // Put interface into the right mode
        thread::sleep(Duration::from_secs(1));
        println!("💲 Setting {} down.", interface_name);
        netlink.set_interface_down(idx).ok();
        thread::sleep(Duration::from_millis(500));

        // Setup Rogue Mac's
        let mut rogue_client = MacAddress::random();

        if let Some(rogue) = rogue {
            if let Ok(mac) = MacAddress::from_str(&rogue) {
                println!("💲 Setting {} mac to {} (from rogue)", interface_name, mac);
                rogue_client = mac;
            } else {
                println!(
                    "Invalid rogue supplied - randomizing {} mac to {}",
                    interface_name, rogue_client
                );
            }
        } else {
            println!("💲 Randomizing {} mac to {}", interface_name, rogue_client);
        }
        netlink.set_interface_mac(idx, &rogue_client.0).ok();

        thread::sleep(Duration::from_millis(500));

        // Setting Monitor
        println!(
            "💲 Setting {} to Monitor mode. (\"active\" flag: {})",
            interface_name,
            (iface.phy.clone().unwrap().active_monitor.is_some_and(|x| x) && !cli_args.noactive)
        );

        if iface.phy.clone().unwrap().active_monitor.is_some_and(|x| x) && !cli_args.noactive {
            netlink.set_interface_monitor(true, idx).ok();
        } else {
            netlink.set_interface_monitor(false, idx).ok();
        }

        if let Ok(after) = get_interface_info_idx(idx) {
            if let Some(iftype) = after.current_iftype {
                if iftype != Nl80211Iftype::IftypeMonitor {
                    tracing::error!("Interface did not go into Monitor mode");
                    println!("{}", get_art("Interface did not go into Monitor mode"));
                    exit(EXIT_FAILURE);
                }
            }
        } else {
            tracing::error!("Couldn't re-retrieve interface info.");
            println!("{}", get_art("Couldn't re-retrieve interface info."));
            exit(EXIT_FAILURE);
        }

        // Set interface up
        thread::sleep(Duration::from_millis(500));
        println!("💲 Setting {} up.", interface_name);
        netlink.set_interface_up(idx).ok();

        // Setup OUI Database
        let oui_db = OuiDatabase::new();
        println!("💲 OUI Records Imported: {}", oui_db.record_count());

        // Open sockets
        let rx_socket = open_socket_rx(idx.try_into().unwrap()).expect("Failed to open RX Socket.");
        let tx_socket = open_socket_tx(idx.try_into().unwrap()).expect("Failed to open TX Socket.");
        thread::sleep(Duration::from_millis(500));

        println!(
            "💲 Sockets Opened [Rx: {} | Tx: {}]",
            rx_socket.as_raw_fd(),
            tx_socket.as_raw_fd()
        );

        // Setup RogueM1 Data
        let mut rng = thread_rng();
        let key_nonce: [u8; 32] = rng.gen();

        let rogue_m1 = EapolKey {
            protocol_version: 2u8,
            timestamp: SystemTime::now(),
            packet_type: 3u8,
            packet_length: 0u16,
            descriptor_type: 2u8,
            key_information: 138u16,
            key_length: 16u16,
            replay_counter: 1u64,
            key_nonce,
            key_iv: [0u8; 16],
            key_rsc: 0u64,
            key_id: 0u64,
            key_mic: [0u8; 16],
            key_data_length: 0u16,
            key_data: Vec::new(),
        };

        // Decide whether to use matrix or snowfall for UI state
        // 50/50 change of getting snowflakes or the matrix
        let use_snowstorm = rand::thread_rng().gen_bool(0.5);

        let state = UiState {
            current_menu: MenuType::AccessPoints,
            paused: false,
            show_quit: false,
            copy_short: false,
            copy_long: false,
            add_target: false,
            set_autoexit: false,
            show_keybinds: false,
            ui_snowstorm: use_snowstorm,
            ap_sort: 0,
            ap_state: TableState::new(),
            ap_table_data: access_points.clone(),
            ap_sort_reverse: false,
            ap_selected_item: None,
            sta_sort: 0,
            sta_state: TableState::new(),
            sta_table_data: unassoc_clients.clone(),
            sta_sort_reverse: false,
            sta_selected_item: None,
            hs_sort: 0,
            hs_state: TableState::new(),
            hs_table_data: handshake_storage.clone(),
            hs_sort_reverse: false,
            hs_selected_item: None,
            messages_sort: 0,
            messages_state: TableState::new(),
            messages_table_data: log.get_all_messages(),
            messages_sort_reverse: false,
            snowstorm: Snowstorm::new_rainbow(Rect::new(1, 2, 3, 4)),
            matrix_snowstorm: MatrixSnowstorm::new(Rect::new(1, 2, 3, 4)),
        };

        // Setup Filename Prefix
        let file_prefix = if let Some(fname) = cli_args.output.clone() {
            fname.to_string()
        } else {
            "oxide".to_string()
        };

        let now: chrono::prelude::DateTime<Local> = Local::now();
        let date_time = now.format("-%Y-%m-%d_%H-%M-%S").to_string();
        let pcap_filename = format!("{}{}.pcapng", file_prefix, date_time);
        let mut pcap_file = PcapWriter::new(&iface, &pcap_filename);
        pcap_file.start();

        // Setup KismetDB Writing
        let kismetdb_filename = format!("{}.kismet", file_prefix);
        let mut database = DatabaseWriter::new(
            &kismetdb_filename,
            interface_uuid.hyphenated().to_string(),
            iface.clone(),
        );
        database.start();

        // Setup GPSD
        let (host, port) = if let Ok((host, port)) = parse_ip_address_port(&cli_args.gpsd) {
            (host, port)
        } else {
            tracing::warn!(%cli_args.gpsd, "GPSD argument not valid, using default.");
            println!("GPSD argument {} not valid... ignoring.", cli_args.gpsd);
            parse_ip_address_port("127.0.0.1:2974").unwrap()
        };

        // TODO: Allow plugins to overwrite this with a new GPS_Source?
        let mut gps_source = GPSDSource::new(host, port);
        gps_source.start();

        let file_data: FileData = FileData {
            oui_database: oui_db,
            file_prefix,
            start_time: date_time,
            current_pcap: pcap_file,
            db_writer: database,
            output_files: vec![pcap_filename, kismetdb_filename],
            gps_source,
            hashlines: HashMap::new(),
        };

        // Setup Rogue_ESSID's tracker
        let rogue_essids: HashMap<MacAddress, String> = HashMap::new();

        let mut eventhandler = EventHandler::new();
        if !cli_args.headless {
            eventhandler.start();
        }

        println!();
        println!("🎩 KICKING UP THE 4D3D3D3 🎩");
        println!();
        println!("======================================================================");
        println!();
        thread::sleep(Duration::from_secs(2));

        let raw_sockets = RawSockets {
            rx_socket,
            tx_socket,
        };

        let config = Config {
            notx: notransmit,
            deauth: !cli_args.nodeauth,
            autoexit: cli_args.autoexit,
            headless: cli_args.headless,
            notar: cli_args.notar,
            autohunt: can_autohunt,
            combine: cli_args.combine,
        };

        let if_hardware = IfHardware {
            netlink,
            original_address,
            current_band: WiFiBand::Unknown,
            current_channel: 0,
            hop_channels,
            hop_interval,
            target_chans,
            locked: false,
            interface: iface,
            interface_uuid,
        };

        let target_data: TargetData = TargetData {
            whitelist: white_list,
            targets: targ_list,
            rogue_client,
            rogue_m1,
            rogue_essids,
            attack_rate: AttackRate::from_u8(cli_args.rate),
        };

        OxideRuntime {
            raw_sockets,
            config,
            handshake_storage,
            access_points,
            unassoc_clients,
            ui_state: state,
            if_hardware,
            target_data,
            file_data,
            counters: Counters::default(),
            status_log: log,
            eventhandler,
        }
    }

    pub fn get_current_menu_len(&self) -> usize {
        match self.ui_state.current_menu {
            MenuType::AccessPoints => self.access_points.size(),
            MenuType::Clients => self.unassoc_clients.size(),
            MenuType::Handshakes => self.handshake_storage.count(),
            MenuType::Messages => self.status_log.size(),
        }
    }

    pub fn get_adjacent_channel(&self) -> Option<u32> {
        let band_channels = self
            .if_hardware
            .interface
            .get_frequency_list_simple()
            .unwrap();
        let current_channel = self.if_hardware.current_channel;
        let mut band: u8 = 0;

        // Get our band
        for (hashband, channels) in band_channels.clone() {
            if channels.contains(&current_channel) {
                band = hashband;
            }
        }

        if band == 0 {
            return None;
        }

        // Get the adjacent channel
        if let Some(channels) = band_channels.get(&band) {
            let mut closest_distance = u32::MAX;
            let mut closest_channel = None;

            for &channel in channels {
                let distance = if channel > current_channel {
                    channel - current_channel
                } else {
                    current_channel - channel
                };

                if distance < closest_distance && distance != 0 {
                    closest_distance = distance;
                    closest_channel = Some(channel);
                }
            }

            closest_channel
        } else {
            None
        }
    }

    pub fn get_target_success(&mut self) -> bool {
        // If there are no targets always return false (not complete)
        if self.target_data.targets.empty() {
            return false;
        }

        let mut all_completes: Vec<bool> = Vec::new();

        for target in self.target_data.targets.get_ref() {
            match target {
                Target::MAC(tgt) => {
                    if self
                        .handshake_storage
                        .has_complete_handshake_for_ap(&tgt.addr)
                    {
                        all_completes.push(true);
                    } else {
                        all_completes.push(false);
                    }
                }
                Target::SSID(tgt) => {
                    if let Some(ap) = self.access_points.get_device_by_ssid(&tgt.ssid) {
                        if self
                            .handshake_storage
                            .has_complete_handshake_for_ap(&ap.mac_address)
                        {
                            all_completes.push(true);
                        } else {
                            all_completes.push(false);
                        }
                    } else {
                        all_completes.push(false);
                    }
                }
            }
        }
        !all_completes.contains(&false)
    }
}
