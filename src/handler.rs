use std::{
    arch::asm,
    ffi::{c_int, c_void},
};

use log::info;
use syscalls::Sysno;

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
const ARG_REGS: [c_int; 6] = [0, 1, 2, 3, 4, 5];

#[cfg(target_arch = "aarch64")]
const RET_REG: c_int = 0;

#[cfg(target_arch = "aarch64")]
type Context = ndk_sys::ucontext_t;

#[cfg(target_arch = "aarch64")]
fn get_arg(context: *const Context, idx: usize) -> usize {
    unsafe { (*context).uc_mcontext.regs[ARG_REGS[idx] as usize] as usize }
}

#[cfg(target_arch = "aarch64")]
fn set_ret(context: *mut Context, ret: usize) {
    unsafe {
        (*context).uc_mcontext.regs[RET_REG as usize] = ret as u64;
    }
}

pub unsafe extern "C" fn sigsys_handler(
    signal: c_int,
    siginfo: *mut SiginfoSeccompOverlay,
    context: *mut Context,
) {
    if signal != ndk_sys::SIGSYS as c_int {
        return;
    }

    unsafe {
        // Prepare
        let mut args = [0usize; 6];

        for (i, arg) in args.iter_mut().enumerate() {
            *arg = get_arg(context, i);
        }
        // (*siginfo).body.si_call_addr

        let mut ctx = crate::SyscallContext {
            syscall_number: Sysno::from((*siginfo).body.si_syscall),
            args,
            regs: (*context).uc_mcontext.regs,
            call_addr: (*siginfo).body.si_call_addr as usize,
            return_value: None,
        };

        let sysno = ctx.syscall_number;
        // OnceLock will make sure no two handlers run concurrently
        let mut h = crate::Hackcomp::get_installed().unwrap();
        let mut hooks = h
            .syscall_hooks
            .iter_mut()
            .filter(|hook| {
                let hooked = hook.hooked_syscalls();
                hooked.is_empty() || hooked.contains(&sysno)
            })
            .collect::<Vec<_>>();

        // Run before hooks
        for hook in hooks.iter_mut() {
            hook.before(&mut ctx);
        }

        // If return_value is not set, do the real syscall
        if ctx.return_value.is_none() {
            // Fallback stub
            let r = match syscalls::syscall6(
                ctx.syscall_number,
                ctx.args[0],
                ctx.args[1],
                ctx.args[2],
                ctx.args[3],
                ctx.args[4],
                ctx.args[5],
            ) {
                Ok(ret) => ret as isize,
                Err(e) => -e.into_raw() as isize,
            };
            ctx.return_value = Some(r as usize);
        }

        // Run after hooks
        for hook in hooks {
            hook.after(&mut ctx);
        }

        set_ret(context, ctx.return_value.unwrap());
    }
}
