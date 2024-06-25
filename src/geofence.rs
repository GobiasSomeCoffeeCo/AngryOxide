use geo::algorithm::haversine_distance::HaversineDistance;
use geo_types::Point;
use geoconvert::{LatLon, Mgrs};
use geomorph::coord::Coord;
use gpsd_proto::{get_data, handshake, ResponseData};
use std::io::{self, BufReader};
use std::net::TcpStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

use crate::Arguments;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GpsData {
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub alt: Option<f32>,
    pub alt_g: Option<f32>,
    pub eph: Option<f32>,
    pub epv: Option<f32>,
    pub speed: Option<f32>,
    pub heading: Option<f32>,
    pub fix: Option<u8>,
    pub hdop: Option<f32>,
    pub vdop: Option<f32>,
    pub timestamp: Option<String>,
}

pub struct GPSDSource {
    handle: Option<thread::JoinHandle<()>>,
    pub alive: Arc<AtomicBool>,
    host: String,
    port: u16,
    latest: Arc<Mutex<GpsData>>,
}

impl GPSDSource {
    pub fn new(host: String, port: u16) -> GPSDSource {
        GPSDSource {
            handle: None,
            alive: Arc::new(AtomicBool::new(false)),
            host,
            port,
            latest: Arc::new(Mutex::new(GpsData::default())),
        }
    }

    pub fn get_gps(&mut self) -> GpsData {
        let gps_data_lock = self.latest.lock().unwrap();
        gps_data_lock.clone()
    }

    pub fn start(&mut self) {
        self.alive.store(true, Ordering::SeqCst);
        let alive = self.alive.clone();
        let host = self.host.clone();
        let port = self.port;
        let latest = self.latest.clone();

        self.handle = Some(thread::spawn(move || {
            let mut reader: BufReader<TcpStream>;
            'th: while alive.load(Ordering::SeqCst) {
                'setup: loop {
                    if !alive.load(Ordering::SeqCst) {
                        break 'th;
                    }
                    let stream = match TcpStream::connect(format!("{}:{}", host, port)) {
                        Ok(strm) => strm,
                        Err(_) => {
                            thread::sleep(Duration::from_secs(3));
                            continue;
                        }
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("set_read_timeout call failed");

                    let mut r = io::BufReader::new(stream.try_clone().unwrap());
                    let mut w = io::BufWriter::new(stream);
                    if handshake(&mut r, &mut w).is_err() {
                        // Something went wrong in our handshake... let's try again...
                        thread::sleep(Duration::from_secs(3));
                        continue;
                    }
                    reader = r;
                    break 'setup;
                }

                while let Ok(msg) = get_data(&mut reader) {
                    if !alive.load(Ordering::SeqCst) {
                        break 'th;
                    }
                    match msg {
                        ResponseData::Tpv(t) => {
                            let mut latest = latest.lock().unwrap();
                            latest.lat = Some(t.lat.unwrap_or(0.0));
                            latest.lon = Some(t.lon.unwrap_or(0.0));
                        }
                        _ => {}
                    }
                }
                let mut latest = latest.lock().unwrap();
                latest.lat = None;
                latest.lon = None;
            }
        }));
    }

    pub fn stop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        self.handle
            .take()
            .expect("Called stop on non-running thread")
            .join()
            .expect("Could not join spawned thread");
    }
}

pub struct Geofence {
    target_coord: LatLon,
    target_radius: f64,
}

impl Geofence {
    pub fn new(target_grid: String, target_radius: f64) -> Geofence {
        let mgrs_string = Mgrs::parse_str(&target_grid).unwrap();
        let target_coord_latlon = LatLon::from_mgrs(&mgrs_string);
        Geofence {
            target_coord: target_coord_latlon,
            target_radius: target_radius,
        }
    }

    pub fn distance_to_target(&self, current_point: (f64, f64)) -> f64 {
        let current_coord_latlon = LatLon::create(current_point.0, current_point.1).unwrap();
        self.target_coord.haversine(&current_coord_latlon)
    }

    pub fn is_within_area(&self, current_point: (f64, f64)) -> bool {
        let current_coord = Coord::new(current_point.0, current_point.1);
        let target_point = Point::new(self.target_coord.longitude(), self.target_coord.latitude());
        let current_point = Point::new(current_coord.lon, current_coord.lat);
        current_point.haversine_distance(&target_point) <= self.target_radius
    }

    pub fn monitor_location(&self, args: &Arguments) {
        let gpsd_parts: Vec<&str> = args.gpsd.split(':').collect();
        if gpsd_parts.len() != 2 {
            eprintln!("Error: Invalid GPSD Host:Port format.");
            std::process::exit(1);
        }
        let gpsd_host = gpsd_parts[0].to_string();
        let gpsd_port: u16 = gpsd_parts[1].parse().expect("Error: Invalid port number.");
        let mut gpsd = GPSDSource::new(gpsd_host, gpsd_port);
        gpsd.start();

        loop {
            let gps_data = gpsd.get_gps();
            if let (Some(lat), Some(lon)) = (gps_data.lat, gps_data.lon) {
                let current_point = (lat, lon);
                let distance = self.distance_to_target(current_point);
                let rounded_distance = distance.round();
                let coord = LatLon::create(current_point.0, current_point.1)
                    .expect("Unable to read Lat/Lon");
                let coord_mgrs = coord.to_mgrs(5);
                if self.is_within_area(current_point) {
                    println!(
                        "🚨 Our location ({}) is within the target area! Getting Angry... 😠",
                        coord_mgrs
                    );
                    gpsd.stop();
                    return;
                } else {
                    println!(
                        "Current location ({}) is {} meters from the target grid.",
                        coord_mgrs, rounded_distance
                    );
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
}
