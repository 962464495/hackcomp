use std::fs::File;

use log::info;

fn main() {
    pretty_env_logger::init();
    info!("Hello");

    let h = hackcomp::Builder::new().build().unwrap();
    h.install().unwrap();

    info!("installed");

    let r = std::fs::read_to_string("/proc/self/status");
    dbg!(r);
}
