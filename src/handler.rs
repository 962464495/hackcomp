use std::ffi::{CStr, c_void};

use libc::{c_char, c_int};
use log::info;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct SiginfoSeccompHead {
    si_signo: c_int,
    si_errno: c_int,
    si_code: c_int,
    _pad0: c_int, // alignment slot
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct SiginfoSeccompBody {
    si_call_addr: *mut c_void,
    si_syscall: c_int,
    si_arch: u32,
}

// An overlay that matches the beginning of siginfo_t for the _sigsys variant.
// We DO NOT model the full 128 bytes, only the prefix we need.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SiginfoSeccompOverlay {
    head: SiginfoSeccompHead,
    body: SiginfoSeccompBody,
}

#[cfg(target_arch = "aarch64")]
const ARG_REGS: [libc::c_int; 6] = [0, 1, 2, 3, 4, 5];

#[cfg(target_arch = "aarch64")]
const RET_REG: libc::c_int = 0;

#[cfg(target_arch = "aarch64")]
const SYSCALL_REG: libc::c_int = 8; // x8

#[cfg(target_arch = "x86_64")]
const ARG_REGS: [libc::c_int; 6] = [
    libc::REG_RDI,
    libc::REG_RSI,
    libc::REG_RDX,
    libc::REG_R10,
    libc::REG_R8,
    libc::REG_R9,
];

#[cfg(target_arch = "x86_64")]
const RET_REG: libc::c_int = libc::REG_RAX;

#[cfg(target_arch = "x86_64")]
fn get_arg(context: *const libc::ucontext_t, idx: usize) -> usize {
    unsafe { (*context).uc_mcontext.gregs[ARG_REGS[idx] as usize] as usize }
}

#[cfg(target_arch = "x86_64")]
fn set_ret(context: *mut libc::ucontext_t, ret: usize) {
    unsafe {
        (*context).uc_mcontext.gregs[RET_REG as usize] = ret as i64;
    }
}

#[cfg(target_arch = "aarch64")]
fn get_arg(context: *const ndk_sys::ucontext_t, idx: usize) -> usize {
    unsafe { (*context).uc_mcontext.regs[ARG_REGS[idx] as usize] as usize }
}

#[cfg(target_arch = "aarch64")]
fn set_ret(context: *mut ndk_sys::ucontext_t, ret: usize) {
    unsafe {
        (*context).uc_mcontext.regs[RET_REG as usize] = ret as u64;
    }
}

pub unsafe extern "C" fn sigsys_handler(
    signal: libc::c_int,
    siginfo: *mut SiginfoSeccompOverlay,
    context: *mut ndk_sys::ucontext_t,
) {
    if signal != libc::SIGSYS {
        return;
    }

    unsafe {
        dbg!(*siginfo);

        info!("Caught signal: {signal}");
        info!("Syscall: {}", (*siginfo).body.si_syscall);

        dbg!((*context).uc_mcontext.regs);
        dbg!((*context).uc_mcontext.regs[8]);

        let dirfd = get_arg(context, 0) as i32;
        let mut pathname_ptr = get_arg(context, 1) as *const c_char;
        let flags = get_arg(context, 2);
        dbg!(dirfd, pathname_ptr, flags);

        let pathname = CStr::from_ptr(pathname_ptr);
        info!("Trying to openat: dirfd={dirfd} pathname={pathname:?} flags={flags}");

        if pathname.to_bytes().starts_with(b"/proc/") {
            info!("Redir access to /proc/*");
            pathname_ptr = CStr::from_bytes_with_nul(b"/proc/self/cmdline\0")
                .unwrap()
                .as_ptr();
        }

        let r = match syscalls::syscall!(syscalls::Sysno::openat, dirfd, pathname_ptr, flags) {
            Ok(ret) => ret as isize,
            Err(e) => -e.into_raw() as isize,
        };

        set_ret(context, r as usize);
    }
}
