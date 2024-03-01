use clap::Parser;

#[derive(Parser)]
#[command(name = "AngryOxide")]
#[command(author = "Ryan Butler (rage)")]
#[command(about = "Does awesome things... with wifi.", long_about = None)]
#[command(version)]
pub struct Arguments {
    /// Interface to use.
    #[arg(short, long)]
    pub interface: String,

    /// Optional - Channel to scan. Will use "-c 1,6,11" if none specified.
    #[arg(short, long, use_value_delimiter = true, action = clap::ArgAction::Append)]
    pub channel: Vec<String>,

    /// Optional - Entire band to scan - will include all channels interface can support.
    #[arg(short = 'b', long, name = "band", help = "2 | 5 | 6 | 60")]
    pub band: Vec<u8>,

    /// Optional - Target (MAC or SSID) to attack - will attack everything if none specified.
    #[arg(
        short = 't',
        long,
        name = "target_entry",
        help_heading = "Targeting",
        help = "Target MAC/SSID"
    )]
    pub target_entry: Option<Vec<String>>,

    /// Optional - Whitelist (MAC or SSID) to NOT attack.
    #[arg(
        short = 'w',
        long,
        name = "whitelist_entry",
        help_heading = "Targeting",
        help = "Whitelist MAC/SSID"
    )]
    pub whitelist_entry: Option<Vec<String>>,

    /// Optional - File to load target entries from.
    #[arg(
        long,
        help_heading = "Targeting",
        name = "targetlist",
        help = "Targets File"
    )]
    pub targetlist: Option<String>,

    /// Optional - File to load whitelist entries from.
    #[arg(
        long,
        help_heading = "Targeting",
        name = "whitelist",
        help = "Whitelist File"
    )]
    pub whitelist: Option<String>,

    /// Optional - Attack rate (1, 2, 3 || 3 is most aggressive)
    #[arg(short = 'r', long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=3), num_args = 1, help_heading = "Advanced Options", name = "rate", help = "1 | 2 | 3")]
    pub rate: u8,

    /// Optional - Output filename.
    #[arg(short = 'o', long, name = "output", help = "Output Filename")]
    pub output: Option<String>,

    /// Optional - Combine all hc22000 files into one large file for bulk processing.
    #[arg(long, help_heading = "Advanced Options", name = "combine")]
    pub combine: bool,

    /// Optional - Disable Active Monitor mode.
    #[arg(long, help_heading = "Advanced Options", name = "noactive")]
    pub noactive: bool,

    /// Optional - Tx MAC for rogue-based attacks - will randomize if excluded.
    #[arg(
        long,
        help_heading = "Advanced Options",
        name = "rogue",
        help = "MAC Address"
    )]
    pub rogue: Option<String>,

    /// Optional - Alter default HOST:Port for GPSD connection.
    #[arg(
        long,
        default_value = "127.0.0.1:2947",
        help_heading = "Advanced Options",
        name = "gpsd",
        help = "IP:PORT"
    )]
    pub gpsd: String,

    /// Optional - AO will auto-hunt all channels then lock in on the ones targets are on.
    #[arg(long, help_heading = "Advanced Options", name = "autohunt")]
    pub autohunt: bool,

    /// Optional - Set the tool to headless mode without a UI. (useful with --autoexit)
    #[arg(long, help_heading = "Advanced Options", name = "headless")]
    pub headless: bool,

    /// Optional - AO will auto-exit when all targets have a valid hashline.
    #[arg(long, help_heading = "Advanced Options", name = "autoexit")]
    pub autoexit: bool,

    /// Optional - Do not transmit - passive only.
    #[arg(long, help_heading = "Advanced Options", name = "notransmit")]
    pub notransmit: bool,

    /// Optional - Do NOT send deauths (will try other attacks only).
    #[arg(long, help_heading = "Advanced Options", name = "nodeauth")]
    pub nodeauth: bool,

    /// Optional - Do not tar output files.
    #[arg(long, help_heading = "Advanced Options", name = "notar")]
    pub notar: bool,

    /// Optional - Adjust channel hop dwell time.
    #[arg(
        long,
        help_heading = "Advanced Options",
        default_value_t = 2,
        name = "dwell",
        help = "Dwell Time (seconds)"
    )]
    pub dwell: u64,
}
