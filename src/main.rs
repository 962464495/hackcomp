use std::path::PathBuf;

use log::info;
use syscalls::Sysno;

fn main() {
    pretty_env_logger::init();
    info!("Hello");

    let h = hackcomp::Builder::new()
        .add_hook(hackcomp::HideSeccomp::new())
        .add_hook(hackcomp::SysLogger::new(&[Sysno::openat, Sysno::read]))
        .add_hook(hackcomp::FDRedirect::new(
            PathBuf::from("/proc/self/cmdline"),
            PathBuf::from("/etc/hosts"),
        ))
        .build()
        .unwrap();
    h.install().unwrap();

    info!("installed");

    // let r = std::fs::read_to_string("/proc/self/cmdline");
    // if let Ok(s) = r {
    //     info!("cmdline: {s:?}");
    // } else {
    //     info!("failed to read cmdline: {r:?}");
    // }

    // std::thread::spawn(|| {
    //     info!("in thread");
    //     let r = std::fs::read_to_string("/proc/self/cmdline");
    //     if let Ok(s) = r {
    //         info!("thread: cmdline: {s:?}");
    //     } else {
    //         info!("thread: failed to read cmdline: {r:?}");
    //     }
    // })
    // .join()
    // .ok();

    // unsafe {
    //     dbg!(ndk_sys::syscall(
    //         hackcomp::Sysno::prctl as i64,
    //         libc::PR_GET_NO_NEW_PRIVS,
    //         0,
    //         0,
    //         0,
    //         0
    //     ));
    // }

    // 持续监听
    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
        info!("hook still active");
        // 可以添加定期检测逻辑
    }
}
