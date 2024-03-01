use std::{collections::HashMap, os::fd::OwnedFd, time::Duration};

use libwifi::frame::{components::MacAddress, EapolKey};
use nl80211_ng::{channels::WiFiBand, Interface, Nl80211};
use uuid::Uuid;

use crate::{
    attackrate::AttackRate,
    database::DatabaseWriter,
    gps::GPSDSource,
    oui::OuiDatabase,
    pcapng::PcapWriter,
    targets::{Target, TargetList},
    whitelist::WhiteList,
};

pub struct RawSockets {
    pub rx_socket: OwnedFd,
    pub tx_socket: OwnedFd,
}

pub struct Config {
    pub notx: bool,
    pub deauth: bool,
    pub autoexit: bool,
    pub headless: bool,
    pub notar: bool,
    pub autohunt: bool,
    pub combine: bool,
}

pub struct IfHardware {
    pub netlink: Nl80211,
    pub original_address: MacAddress,
    pub current_band: WiFiBand,
    pub current_channel: u32,
    pub hop_channels: Vec<(u8, u32)>,
    pub target_chans: HashMap<Target, Vec<(u8, u32)>>,
    pub locked: bool,
    pub hop_interval: Duration,
    pub interface: Interface,
    pub interface_uuid: Uuid,
}

pub struct TargetData {
    pub whitelist: WhiteList,
    pub targets: TargetList,
    pub attack_rate: AttackRate,
    pub rogue_client: MacAddress,
    pub rogue_m1: EapolKey,
    pub rogue_essids: HashMap<MacAddress, String>,
}

pub struct FileData {
    pub oui_database: OuiDatabase,
    pub file_prefix: String,
    pub start_time: String,
    pub current_pcap: PcapWriter,
    pub db_writer: DatabaseWriter,
    pub output_files: Vec<String>,
    pub gps_source: GPSDSource,
    pub hashlines: HashMap<String, (usize, usize)>,
}

#[derive(Default)]
pub struct Counters {
    pub frame_count: u64,
    pub eapol_count: u64,
    pub error_count: u64,
    pub packet_id: u64,
    pub empty_reads: u64,
    pub empty_reads_rate: u64,
    pub seq1: u16,
    pub seq2: u16,
    pub seq3: u16,
    pub seq4: u16,
    pub prespidx: u8,
    pub beacons: usize,
    pub data: usize,
    pub null_data: usize,
    pub probe_requests: usize,
    pub probe_responses: usize,
    pub control_frames: usize,
    pub authentication: usize,
    pub deauthentication: usize,
    pub association: usize,
    pub reassociation: usize,
}

impl Counters {
    pub fn packet_id(&mut self) -> u64 {
        self.packet_id += 1;
        self.packet_id
    }

    pub fn sequence1(&mut self) -> u16 {
        self.seq1 = if self.seq1 >= 4096 { 1 } else { self.seq1 + 1 };
        self.seq1
    }

    pub fn sequence2(&mut self) -> u16 {
        self.seq2 = if self.seq2 >= 4096 { 1 } else { self.seq2 + 1 };
        self.seq2
    }

    pub fn sequence3(&mut self) -> u16 {
        self.seq3 = if self.seq3 >= 4096 { 1 } else { self.seq3 + 1 };
        self.seq3
    }

    pub fn sequence4(&mut self) -> u16 {
        self.seq4 = if self.seq4 >= 4096 { 1 } else { self.seq4 + 1 };
        self.seq4
    }

    pub fn proberesponseindex(&mut self) -> u8 {
        self.prespidx = if self.prespidx >= 10 {
            0
        } else {
            self.prespidx + 1
        };
        self.prespidx
    }
}
