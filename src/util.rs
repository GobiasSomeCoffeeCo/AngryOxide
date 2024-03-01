use chrono::{DateTime, Utc};
use libwifi::frame::components::WpsInformation;
use libwifi::frame::{DataFrame, EapolKey, KeyInformation, NullDataFrame};
use libwifi::Addresses;
use radiotap::field::ext::TimeUnit;
use radiotap::field::{AntennaSignal, Field};
use radiotap::Radiotap;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::devices::{AccessPoint, Station, WiFiDeviceList};
use crate::oxideruntime::OxideRuntime;
use crate::status::{MessageType, StatusMessage};
use crate::tx::build_disassocation_from_client;

pub fn epoch_to_string(epoch: u64) -> String {
    match UNIX_EPOCH.checked_add(Duration::from_secs(epoch)) {
        Some(epoch_time) => match SystemTime::now().duration_since(epoch_time) {
            Ok(duration_since) => {
                let elapsed_seconds = duration_since.as_secs();
                if elapsed_seconds > 3600 {
                    format!("{}h", elapsed_seconds / 3600)
                } else if duration_since.as_secs() > 60 {
                    format!("{}m", elapsed_seconds / 60)
                } else {
                    format!("{}s", elapsed_seconds)
                }
            }
            Err(_) => "Time is in the future".to_string(),
        },
        None => "Invalid timestamp".to_string(),
    }
}

pub fn slice_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn epoch_to_iso_string(epoch: u64) -> String {
    match UNIX_EPOCH.checked_add(Duration::from_secs(epoch)) {
        Some(epoch_time) => DateTime::<Utc>::from(epoch_time).format("%+").to_string(),
        None => "Invalid timestamp".to_string(),
    }
}

pub fn system_time_to_iso8601(system_time: SystemTime) -> String {
    let datetime: DateTime<Utc> = system_time.into();
    datetime.to_rfc3339()
}

pub fn key_info_to_json_str(keyinfo: KeyInformation) -> String {
    format!(
        "{{\"descriptor_version\": {},\"key_type\": {},\"key_index\": {},\"install\": {},\"key_ack\": {},\"key_mic\": {},\"secure\": {},\"error\": {},\"request\": {},\"encrypted_key_data\": {},\"smk_message\": {}}}",
        keyinfo.descriptor_version,
        keyinfo.key_type,
        keyinfo.key_index,
        keyinfo.install,
        keyinfo.key_ack,
        keyinfo.key_mic,
        keyinfo.secure,
        keyinfo.error,
        keyinfo.request,
        keyinfo.encrypted_key_data,
        keyinfo.smk_message
    )
}

pub fn eapol_to_json_str(key: &EapolKey) -> String {
    format!("{{\"protocol_version\": {},\"timestamp\": \"{}\",\"key_information\": {},\"key_length\": {},\"replay_counter\": {},\"key_nonce\": \"{}\",\"key_iv\": \"{}\",\"key_rsc\": {},\"key_id\": {},\"key_mic\": \"{}\",\"key_data\": \"{}\"}}",
    key.protocol_version,
    system_time_to_iso8601(key.timestamp),
    key_info_to_json_str(key.parse_key_information()),
    key.key_length,
    key.replay_counter,
    slice_to_hex_string(&key.key_nonce),
    slice_to_hex_string(&key.key_iv),
    key.key_rsc,
    &key.key_id,
    slice_to_hex_string(&key.key_mic),
    slice_to_hex_string(&key.key_data))
}

pub fn option_bool_to_json_string(option: Option<bool>) -> String {
    match option {
        Some(true) => "true".to_string(),
        Some(false) => "false".to_string(),
        None => "\"none\"".to_string(),
    }
}

pub fn merge_with_newline(vec1: Vec<String>, vec2: Vec<String>) -> Vec<String> {
    let min_length = std::cmp::min(vec1.len(), vec2.len());

    // Iterate up to the shortest length, merging corresponding elements with a newline
    let mut merged = Vec::with_capacity(min_length);
    for i in 0..min_length {
        let new_str = format!("{}\n{}", vec1[i], vec2[i]);
        merged.push(new_str);
    }

    merged
}

pub fn ts_to_system_time(timestamp: u64, unit: TimeUnit) -> SystemTime {
    match unit {
        TimeUnit::Milliseconds => UNIX_EPOCH + Duration::from_millis(timestamp),
        TimeUnit::Microseconds => UNIX_EPOCH + Duration::from_micros(timestamp),
        TimeUnit::Nanoseconds => UNIX_EPOCH + Duration::from_nanos(timestamp),
    }
}

pub fn parse_ip_address_port(input: &str) -> Result<(IpAddr, u16), &'static str> {
    let parts: Vec<&str> = input.split(':').collect();

    // Check if there are exactly two parts
    if parts.len() != 2 {
        return Err("Input should be in the format IP_ADDRESS:PORT");
    }

    // Parse IP address
    let ip = match IpAddr::from_str(parts[0]) {
        Ok(ip) => ip,
        Err(_) => return Err("Invalid IP address"),
    };

    // Parse port
    let port = match parts[1].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err("Invalid port number"),
    };

    Ok((ip, port))
}

pub fn is_file_less_than_100mb(file: &File) -> io::Result<bool> {
    let metadata = file.metadata()?;
    Ok(metadata.len() < 100 * 1024 * 1024)
}

pub fn max_column_widths(headers: &[String], rows: &[(Vec<String>, u16)]) -> Vec<usize> {
    let mut max_widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();

    for (row_data, _) in rows {
        for (i, cell) in row_data.iter().enumerate() {
            let adjusted_length = cell
                .chars()
                .fold(0, |acc, ch| acc + if ch == '✅' { 2 } else { 1 });
            max_widths[i] = max_widths[i].max(adjusted_length);
        }
    }

    max_widths
}

pub fn format_row(row: &[String], widths: &[usize]) -> String {
    row.iter()
        .enumerate()
        .map(|(i, cell)| {
            // Count the number of special characters
            let special_chars_count = cell.chars().filter(|&ch| ch == '✅').count();
            // Adjust width by reducing 1 space for each special character
            let adjusted_width = if special_chars_count > 0 {
                widths[i].saturating_sub(special_chars_count)
            } else {
                widths[i]
            };
            format!("{:width$}", cell, width = adjusted_width)
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

pub fn wps_to_json(wps_info: &Option<WpsInformation>) -> String {
    if let Some(wps) = wps_info {
        format!("{{\"setup_state\": \"{:?}\", \"manufacturer\": \"{}\", \"model\": \"{}\", \"model_number\": \"{}\", \"serial_number\": \"{}\", \"primary_device_type\": \"{}\", \"device_name\": \"{}\"}}",
    wps.setup_state,
    wps.manufacturer,
    wps.model,
    wps.model_number,
    wps.serial_number,
    wps.primary_device_type,
    wps.device_name)
    } else {
        "{}".to_string()
    }
}

pub fn write_packet(fd: i32, packet: &[u8]) -> Result<(), String> {
    let bytes_written =
        unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

    if bytes_written < 0 {
        // An error occurred during write
        let error_code = io::Error::last_os_error();

        return Err(error_code.to_string());
    }

    Ok(())
}

#[tracing::instrument(skip(data_frame, oxide))]
pub fn handle_data_frame(
    data_frame: &impl DataFrame,
    rthdr: &Radiotap,
    oxide: &mut OxideRuntime,
) -> Result<(), String> {
    oxide.counters.data += 1;

    let source = data_frame.header().src().expect("Unable to get src");
    let dest = data_frame.header().dest();
    let from_ds: bool = data_frame.header().frame_control.from_ds();
    let to_ds: bool = data_frame.header().frame_control.to_ds();
    let ap_addr = if from_ds && !to_ds {
        data_frame.header().address_2
    } else if !from_ds && to_ds {
        data_frame.header().address_1
    } else {
        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
        // lets just ignore it lol
        return Ok(());
    };

    let station_addr = if !from_ds && to_ds {
        data_frame.header().address_2
    } else {
        data_frame.header().address_1
    };

    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
    let signal = rthdr
        .antenna_signal
        .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

    if ap_addr != oxide.target_data.rogue_client {
        if station_addr.is_real_device() && station_addr != oxide.target_data.rogue_client {
            // Make sure this isn't a broadcast or something
            let client = &Station::new_station(
                station_addr,
                if to_ds {
                    signal
                } else {
                    AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                },
                Some(ap_addr),
                oxide.file_data.oui_database.search(&station_addr),
            );
            clients.add_or_update_device(station_addr, client);
            oxide.unassoc_clients.remove_device(&station_addr);
        }

        // Create and Add/Update AccessPoint
        let ap = AccessPoint::new_with_clients(
            ap_addr,
            if from_ds {
                signal
            } else {
                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
            },
            None,
            None,
            None,
            clients,
            oxide.target_data.rogue_client,
            None,
            oxide.file_data.oui_database.search(&ap_addr),
        );
        oxide.access_points.add_or_update_device(ap_addr, &ap);
    }

    // Handle frames that contain EAPOL.
    if let Some(eapol) = data_frame.eapol_key().clone() {
        oxide.counters.eapol_count += 1;

        if ap_addr == oxide.target_data.rogue_client
            && (eapol.determine_key_type() == libwifi::frame::MessageType::Message2)
        {
            let essid = oxide.target_data.rogue_essids.get(&station_addr);
            let mut rogue_eapol = oxide.target_data.rogue_m1.clone();
            rogue_eapol.timestamp = eapol
                .timestamp
                .checked_sub(Duration::from_millis(10))
                .unwrap_or(eapol.timestamp);

            // Add our rogue M1
            let _ = oxide.handshake_storage.add_or_update_handshake(
                &ap_addr,
                &station_addr,
                rogue_eapol,
                essid.cloned(),
            );

            // Add the RogueM2
            let result = oxide.handshake_storage.add_or_update_handshake(
                &ap_addr,
                &station_addr,
                eapol.clone(),
                essid.cloned(),
            );

            // Set to apless
            if let Ok(handshake) = result {
                handshake.apless = true;
            }

            // Set to apless
            //oxide.handshake_storage.set_apless_for_ap(&ap_addr);

            // Set the Station that we collected a RogueM2
            if let Some(station) = oxide.unassoc_clients.get_device(&station_addr) {
                station.has_rogue_m2 = true;
                station
                    .rogue_actions
                    .entry(essid.unwrap().to_string())
                    .or_insert(true);
            }

            // Print a status so we have it for headless

            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Priority,
                format!(
                    "RogueM2 Collected!: {dest} => {source} ({})",
                    essid.unwrap()
                ),
            ));

            // Don't need to go any further, because we know this wasn't a valid handshake otherwise.
            return Ok(());
        }

        let ap = if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
            ap
        } else {
            return Ok(());
        };

        let essid = ap.ssid.clone();

        if station_addr == oxide.target_data.rogue_client
            && eapol.determine_key_type() == libwifi::frame::MessageType::Message1
        {
            let frx = build_disassocation_from_client(
                &ap_addr,
                &station_addr,
                oxide.counters.sequence2(),
            );
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
            ap.interactions += 1;
            if oxide.handshake_storage.has_m1_for_ap(&ap_addr) {
                return Ok(());
            }
        }

        let result = oxide.handshake_storage.add_or_update_handshake(
            &ap_addr,
            &station_addr,
            eapol.clone(),
            essid,
        );
        match result {
            Ok(_) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!(
                        "New Eapol: {dest} => {source} ({})",
                        eapol.determine_key_type()
                    ),
                ));
            }
            Err(e) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Warning,
                    format!(
                        "Eapol Failed to Add: {dest} => {source} ({}) | {e}",
                        eapol.determine_key_type(),
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub fn handle_null_data_frame(
    data_frame: &impl NullDataFrame,
    rthdr: &Radiotap,
    oxide: &mut OxideRuntime,
) -> Result<(), String> {
    oxide.counters.null_data += 1;
    let from_ds: bool = data_frame.header().frame_control.from_ds();
    let to_ds: bool = data_frame.header().frame_control.to_ds();
    let powersave: bool = data_frame.header().frame_control.pwr_mgmt();
    let ap_addr = if from_ds && !to_ds {
        data_frame.header().address_2
    } else if !from_ds && to_ds {
        data_frame.header().address_1
    } else {
        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
        // lets just ignore it lol
        return Ok(());
    };

    let station_addr = if !from_ds && to_ds {
        data_frame.header().address_2
    } else {
        data_frame.header().address_1
    };

    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
    let signal = rthdr
        .antenna_signal
        .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

    if station_addr.is_real_device() && station_addr != oxide.target_data.rogue_client {
        // Make sure this isn't a broadcast or something

        let client = &Station::new_station(
            station_addr,
            if to_ds {
                signal
            } else {
                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
            },
            Some(ap_addr),
            oxide.file_data.oui_database.search(&station_addr),
        );
        clients.add_or_update_device(station_addr, client);
        oxide.unassoc_clients.remove_device(&station_addr);
    }
    let ap = AccessPoint::new_with_clients(
        ap_addr,
        if from_ds {
            signal
        } else {
            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
        },
        None,
        None,
        None,
        clients,
        oxide.target_data.rogue_client,
        None,
        oxide.file_data.oui_database.search(&ap_addr),
    );
    oxide.access_points.add_or_update_device(ap_addr, &ap);

    // Check PS State:
    if !powersave && station_addr != oxide.target_data.rogue_client {
        // Client is awake... potentially... try reassociation attack?
        //anon_reassociation_attack(oxide, &ap_addr)?;
    }

    Ok(())
}

pub fn read_frame(oxide: &mut OxideRuntime) -> Result<Vec<u8>, io::Error> {
    let mut buffer = vec![0u8; 6000];
    let packet_len = unsafe {
        libc::read(
            oxide.raw_sockets.rx_socket.as_raw_fd(),
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        )
    };

    // Handle non-blocking read
    if packet_len < 0 {
        let error_code = io::Error::last_os_error();
        if error_code.kind() == io::ErrorKind::WouldBlock {
            oxide.counters.empty_reads += 1;
            return Ok(Vec::new());
        } else {
            // An actual error occurred
            oxide.counters.error_count += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Error Reading from Socket: {:?}", error_code.kind()),
            ));
            return Err(error_code);
        }
    }

    buffer.truncate(packet_len as usize);
    Ok(buffer)
}