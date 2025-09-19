use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    path::PathBuf,
};

use log::debug;
pub use syscalls::Sysno; // Re-export Sysno for convenience

pub trait MappedNode: std::fmt::Debug {
    fn lseek(&mut self, offset: usize, whence: usize) -> usize;
    fn read(&mut self, count: usize) -> Vec<u8>;
}

#[derive(Debug)]
pub struct SyscallContext {
    pub syscall_number: Sysno,
    pub call_addr: usize,
    pub regs: [u64; 31],
    pub args: [usize; 6],
    pub return_value: Option<usize>,
}

pub trait SyscallHook: Send + Sync {
    fn hooked_syscalls(&self) -> &[Sysno] {
        &[]
    }

    /// To be called before the syscall is executed.
    /// If you set `ctx.return_value`, the syscall will be skipped, but `after` hooks will still be called.
    fn before(&mut self, _ctx: &mut SyscallContext) {}

    /// To be called after the syscall is executed.
    fn after(&mut self, _ctx: &mut SyscallContext) {}
}

pub struct SysLogger {
    hooked_syscalls: Vec<Sysno>,
}

impl SysLogger {
    pub fn new(hooked_syscalls: &[Sysno]) -> Self {
        Self {
            hooked_syscalls: hooked_syscalls.to_vec(),
        }
    }
}

impl SyscallHook for SysLogger {
    fn hooked_syscalls(&self) -> &[Sysno] {
        &self.hooked_syscalls
    }

    fn before(&mut self, ctx: &mut SyscallContext) {
        debug!("TID {}", unsafe {
            syscalls::syscall!(Sysno::gettid).unwrap()
        });
        debug!("SYSCALL {} - ARGS: {:?}", ctx.syscall_number, ctx.args);
    }

    fn after(&mut self, ctx: &mut SyscallContext) {
        debug!(
            "SYSCALL {} - RETURN: {:?}",
            ctx.syscall_number, ctx.return_value
        );
    }
}

pub struct FDRedirect {
    from_path: PathBuf,
    to_path: PathBuf,
    fd_map: HashMap<usize, usize>, // from_fd -> to_fd
}

impl FDRedirect {
    pub fn new(from_path: PathBuf, to_path: PathBuf) -> Self {
        // Ensure that both paths exist
        if !from_path.exists() {
            panic!("from_path does not exist: {from_path:?}");
        }
        if !to_path.exists() {
            panic!("to_path does not exist: {to_path:?}");
        }
        Self {
            from_path,
            to_path,
            fd_map: HashMap::new(),
        }
    }
}

impl SyscallHook for FDRedirect {
    fn hooked_syscalls(&self) -> &[Sysno] {
        &[Sysno::openat, Sysno::read, Sysno::lseek, Sysno::close]
    }

    fn before(&mut self, ctx: &mut SyscallContext) {
        match ctx.syscall_number {
            Sysno::openat => {
                let dirfd = ctx.args[0] as i32;
                let pathname_ptr = ctx.args[1] as *const u8;
                let flags = ctx.args[2] as i32;
                let mode = ctx.args[3] as u32;

                let pathname = unsafe { CStr::from_ptr(pathname_ptr) }
                    .to_string_lossy()
                    .into_owned();
                let full_path = if dirfd == nc::AT_FDCWD {
                    PathBuf::from(&pathname)
                } else if let Some(fd) = self.fd_map.get(&(dirfd as usize)) {
                    if let Ok(dir_path) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
                        dir_path.join(&pathname)
                    } else {
                        PathBuf::from(&pathname)
                    }
                } else {
                    PathBuf::from(&pathname)
                };

                if full_path != self.from_path {
                    // pass
                    return;
                }
                debug!(
                    "Redirecting openat from {} to {}",
                    full_path.display(),
                    self.to_path.display()
                );

                let to_path = CString::new(self.to_path.to_string_lossy().as_bytes()).unwrap();

                // Open both files to get their fds
                unsafe {
                    let from_fd =
                        syscalls::syscall!(Sysno::openat, dirfd, pathname_ptr, flags, mode);

                    if let Err(e) = from_fd {
                        ctx.return_value = Some(-e.into_raw() as usize);
                        return;
                    }

                    let to_fd =
                        syscalls::syscall!(Sysno::openat, dirfd, to_path.as_ptr(), flags, mode);

                    if let Err(e) = from_fd {
                        ctx.return_value = Some(-e.into_raw() as usize);
                        return;
                    }

                    self.fd_map
                        .insert(from_fd.unwrap() as usize, to_fd.unwrap() as usize);
                    ctx.return_value = Some(to_fd.unwrap() as usize);
                }
            }
            Sysno::read | Sysno::lseek | Sysno::write => {
                let fd = ctx.args[0];
                if let Some(&to_fd) = self.fd_map.get(&fd) {
                    ctx.args[0] = to_fd;
                    debug!("Redirected read/lseek from fd {fd} to fd {to_fd}");
                }
            }
            Sysno::close => {
                let fd = ctx.args[0];
                if let Some(&to_fd) = self.fd_map.get(&fd) {
                    // We close both
                    unsafe {
                        syscalls::syscall!(Sysno::close, to_fd as i32).ok();
                        syscalls::syscall!(Sysno::close, fd as i32).ok();
                        ctx.return_value = Some(0);
                    }
                    self.fd_map.remove(&fd);
                }
            }
            _ => unimplemented!(),
        }
    }
}
