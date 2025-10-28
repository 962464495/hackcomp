use std::{
    ffi::{CStr, CString},
    path::PathBuf,
};

use log::debug;
use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition};
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

    fn bpf_rules(&self, _sysno: Sysno) -> Vec<Vec<SeccompCondition>> {
        vec![]
    }

    /// To be called before the syscall is executed.
    /// If you set `ctx.return_value`, the syscall will be skipped, but `after` hooks will still be called.
    fn before(&mut self, _ctx: &mut SyscallContext) {}

    /// To be called after the syscall is executed.
    fn after(&mut self, _ctx: &mut SyscallContext) {}
}

fn usize_to_string(ptr: usize) -> String {
    if ptr == 0 {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr as *const u8) }
        .to_string_lossy()
        .into_owned()
}

fn write_string_to_usize(s: &str, ptr: usize, max_len: usize) {
    let c_string = CString::new(s).unwrap();
    let bytes = c_string.as_bytes_with_nul();
    let len = bytes.len();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, len);
    }
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
fn get_thread_name() -> String {
    let mut name = [0_u8; 16];
    unsafe {
        if nc::prctl(nc::PR_GET_NAME, name.as_mut_ptr() as usize, 0, 0, 0).is_ok() {
            if let Ok(cstr) = CStr::from_bytes_until_nul(&name) {
                return cstr.to_string_lossy().into_owned();
            }
        }
    }
    String::new()
}

impl SyscallHook for SysLogger {
    fn hooked_syscalls(&self) -> &[Sysno] {
        &self.hooked_syscalls
    }

    fn before(&mut self, ctx: &mut SyscallContext) {
        debug!(
            "PID {} TID {} {}",
            unsafe { nc::getpid() },
            unsafe { nc::gettid() },
            get_thread_name()
        );
        match ctx.syscall_number {
            Sysno::openat => {
                let dirfd = ctx.args[0] as i32;
                let pathname = usize_to_string(ctx.args[1]);
                let flags = ctx.args[2] as i32;
                let mode = ctx.args[3] as u32;
                debug!(
                    "SYSCALL openat - dirfd: {dirfd}, pathname: {pathname}, flags: {flags:#x}, mode: {mode:#o}",
                );
            }
            Sysno::fstat => {
                let fd = ctx.args[0] as i32;
                let statbuf_ptr = ctx.args[1] as *mut nc::stat_t;
                debug!("SYSCALL fstat - fd: {fd}, statbuf: {statbuf_ptr:p}");
            }
            Sysno::readlinkat => {
                let dirfd = ctx.args[0] as i32;
                let pathname = usize_to_string(ctx.args[1]);
                let buf_ptr = ctx.args[2] as *mut u8;
                debug!(
                    "SYSCALL readlinkat - dirfd: {dirfd}, pathname: {pathname}, buf: {buf_ptr:p}",
                );
            }
            _ => {
                debug!("SYSCALL {} - ARGS: {:?}", ctx.syscall_number, ctx.args);
            }
        }
    }

    fn after(&mut self, ctx: &mut SyscallContext) {
        let ret = ctx.return_value.unwrap() as isize;
        match ctx.syscall_number {
            Sysno::openat => {
                if ret < 0 {
                    debug!("SYSCALL openat - RETURN: ERR {}", -ret);
                } else {
                    debug!("SYSCALL openat - RETURN: FD {}", ret);
                }
            }
            Sysno::fstat => {
                if ret < 0 {
                    debug!("SYSCALL fstat - RETURN: ERR {}", -ret);
                } else {
                    let statbuf_ptr = ctx.args[1] as *const nc::stat_t;
                    unsafe {
                        let statbuf = &*statbuf_ptr;
                        debug!(
                            "SYSCALL fstat - RETURN: 0, st_mode: {:#o}, st_size: {}",
                            statbuf.st_mode, statbuf.st_size
                        );
                    }
                }
            }
            Sysno::readlinkat => {
                if ret < 0 {
                    debug!("SYSCALL readlinkat - RETURN: ERR {}", -ret);
                } else {
                    let link = usize_to_string(ctx.args[2]);
                    debug!("SYSCALL readlinkat - RETURN: {ret}, link: {link}",);
                }
            }
            _ => {
                debug!("SYSCALL {} - RETURN: {:?}", ctx.syscall_number, ret,);
            }
        }
    }
}

pub struct FDRedirect {
    from_path: PathBuf,
    to_path: PathBuf,
    fd_map: Vec<(usize, usize)>, // from_fd, to_fd
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
            fd_map: Vec::new(),
        }
    }

    fn get_mapped(&self, fd: usize) -> Option<usize> {
        for (from_fd, to_fd) in &self.fd_map {
            if *from_fd == fd {
                return Some(*to_fd);
            }
        }
        None
    }
}

impl SyscallHook for FDRedirect {
    fn hooked_syscalls(&self) -> &[Sysno] {
        &[
            Sysno::openat,
            Sysno::read,
            Sysno::lseek,
            Sysno::close,
            Sysno::readlinkat,
        ]
    }

    fn before(&mut self, ctx: &mut SyscallContext) {
        match ctx.syscall_number {
            Sysno::openat => {
                let dirfd = ctx.args[0] as i32;
                let pathname = usize_to_string(ctx.args[1]);
                let flags = ctx.args[2] as i32;
                let mode = ctx.args[3] as u32;

                let full_path = if dirfd == nc::AT_FDCWD {
                    PathBuf::from(&pathname)
                } else {
                    let mut dir_path = [0_u8; nc::PATH_MAX as usize + 1];
                    if unsafe {
                        nc::readlinkat(
                            nc::AT_FDCWD,
                            format!("/proc/self/fd/{dirfd}"),
                            &mut dir_path,
                        )
                        .is_ok()
                    } {
                        PathBuf::from(
                            CStr::from_bytes_with_nul(&dir_path)
                                .unwrap()
                                .to_str()
                                .unwrap(),
                        )
                        .join(&pathname)
                    } else {
                        PathBuf::from(&pathname)
                    }
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

                // Open both files to get their fds
                unsafe {
                    let from_fd = nc::openat(dirfd, pathname, flags, mode);
                    debug!("from_fd: {from_fd:?}");

                    if let Err(e) = from_fd {
                        ctx.return_value = Some(-e as usize);
                        return;
                    }

                    let to_fd = nc::openat(dirfd, &self.to_path, flags, mode);
                    debug!("to_fd: {to_fd:?}");

                    if let Err(e) = from_fd {
                        ctx.return_value = Some(-e as usize);
                        return;
                    }

                    self.fd_map
                        .push((from_fd.unwrap() as usize, to_fd.unwrap() as usize));
                    ctx.return_value = Some(to_fd.unwrap() as usize);
                }
            }
            Sysno::readlinkat => {
                let _dirfd = ctx.args[0];
                let pathname = usize_to_string(ctx.args[1]);
                let buf = ctx.args[2];
                let bufsize = ctx.args[3];

                if !pathname.starts_with("/proc/self/fd/") {
                    return;
                }

                let fd = usize::from_str_radix(pathname.trim_start_matches("/proc/self/fd/"), 10);
                if fd.is_err() {
                    return;
                }
                let fd = fd.unwrap();

                for (from_fd, to_fd) in &self.fd_map {
                    if *to_fd == fd {
                        debug!("Redirecting readlinkat from fd {} to fd {}", from_fd, to_fd);
                        let from_path_str = self.from_path.to_str().unwrap();
                        write_string_to_usize(from_path_str, buf, bufsize);
                        ctx.return_value = Some(from_path_str.len());
                        return;
                    }
                }
            }
            Sysno::read | Sysno::lseek | Sysno::write => {
                let fd = ctx.args[0];
                if let Some(to_fd) = self.get_mapped(fd) {
                    ctx.args[0] = to_fd;
                    debug!("Redirected read/lseek from fd {fd} to fd {to_fd}");
                }
            }
            Sysno::close => {
                let fd = ctx.args[0];
                if let Some(to_fd) = self.get_mapped(fd) {
                    // We close both
                    unsafe {
                        syscalls::syscall!(Sysno::close, to_fd as i32).ok();
                        syscalls::syscall!(Sysno::close, fd as i32).ok();
                        ctx.return_value = Some(0);
                    }
                    self.fd_map.retain(|(f, _)| *f != fd);
                }
            }
            _ => unimplemented!(),
        }
    }
}

pub struct HideSeccomp {}

impl HideSeccomp {
    pub fn new() -> Self {
        Self {}
    }
}

impl SyscallHook for HideSeccomp {
    fn hooked_syscalls(&self) -> &[Sysno] {
        &[Sysno::prctl]
    }
    fn bpf_rules(&self, sysno: Sysno) -> Vec<Vec<SeccompCondition>> {
        if sysno == Sysno::prctl {
            // Allow prctl but we will handle it in before()
            let mut rules = vec![];

            let keys = vec![
                nc::PR_SET_SECCOMP,
                nc::PR_GET_SECCOMP,
                nc::PR_SET_NO_NEW_PRIVS,
                nc::PR_GET_NO_NEW_PRIVS,
            ];

            for key in keys {
                rules.push(vec![
                    SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, key as u64)
                        .unwrap(),
                ]);
            }

            rules
        } else {
            vec![]
        }
    }

    fn before(&mut self, ctx: &mut SyscallContext) {
        if ctx.syscall_number == Sysno::prctl {
            log::info!("Hiding seccomp prctl call");
            let option = ctx.args[0];
            if option == nc::PR_SET_SECCOMP as usize
                || option == nc::PR_GET_SECCOMP as usize
                || option == nc::PR_SET_NO_NEW_PRIVS as usize
                || option == nc::PR_GET_NO_NEW_PRIVS as usize
            {
                ctx.return_value = Some(0); // pretend success
            }
        }
    }
}

pub struct HideMaps {
    modified_maps: Vec<u8>,
    keywords: Vec<String>,
    offset: usize,
}

impl HideMaps {
    pub fn new(keywords: &[&str]) -> Self {
        Self {
            modified_maps: Vec::new(),
            keywords: keywords.iter().map(|s| s.to_string()).collect(),
            offset: 0,
        }
    }

    fn modify_maps(&self, original: &str) -> Vec<u8> {
        let mut modified = String::new();
        'outer: for line in original.lines() {
            // Check if any keyword matches this line
            for k in &self.keywords {
                if line.contains(k) {
                    continue 'outer;  // Skip this line entirely
                }
            }
            // No keyword matched, keep this line
            modified.push_str(line);
            modified.push('\n');
        }
        modified.into_bytes()
    }
}

const HIDE_MAPS_MAGIC: usize = 0xABBADED;

impl SyscallHook for HideMaps {
    fn hooked_syscalls(&self) -> &[Sysno] {
        &[Sysno::openat, Sysno::close, Sysno::read, Sysno::lseek]
    }

    fn bpf_rules(&self, _sysno: Sysno) -> Vec<Vec<SeccompCondition>> {
        match _sysno {
            Sysno::openat => vec![], // match all openat
            // for the rest, only match our magic fd
            Sysno::close | Sysno::read | Sysno::lseek => vec![vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    HIDE_MAPS_MAGIC as u64,
                )
                .unwrap(),
            ]],
            _ => unimplemented!(),
        }
    }

    fn before(&mut self, ctx: &mut SyscallContext) {
        match ctx.syscall_number {
            Sysno::openat => {
                let pathname_ptr = ctx.args[1] as *const u8;

                let pathname = unsafe { CStr::from_ptr(pathname_ptr) }
                    .to_string_lossy()
                    .into_owned();

                let my_pid = unsafe { nc::getpid() };

                if pathname == "/proc/self/maps" || pathname == format!("/proc/{my_pid}/maps") {
                    debug!("Hiding {pathname} openat call");

                    // Update self.original_maps to the latest maps
                    let original_maps =
                        String::from_utf8(crate::fs::read_all("/proc/self/maps").unwrap()).unwrap();
                    self.modified_maps = self.modify_maps(&original_maps);
                    ctx.return_value = Some(HIDE_MAPS_MAGIC);
                }
            }
            Sysno::read => {
                let fd = ctx.args[0];
                if fd != HIDE_MAPS_MAGIC {
                    return;
                }
                let buf_ptr = ctx.args[1] as *mut u8;
                let count = ctx.args[2];
                debug!("HideMaps read at {} count: {count}", self.offset);

                let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, count) };
                // Copy from modified_maps to buf
                let read_len = std::cmp::min(count, self.modified_maps.len() - self.offset);

                debug!("read_len = {read_len}");

                buf[..read_len]
                    .copy_from_slice(&self.modified_maps[self.offset..self.offset + read_len]);
                self.offset += read_len;
                ctx.return_value = Some(read_len);
            }
            Sysno::lseek => {
                let fd = ctx.args[0];
                if fd != HIDE_MAPS_MAGIC {
                    return;
                }

                let offset = ctx.args[1];
                let whence = ctx.args[2];

                debug!("HideMaps lseek {offset} {whence}");

                let new_offset = match whence as i32 {
                    nc::SEEK_SET => offset,
                    nc::SEEK_CUR => self.offset + offset,
                    nc::SEEK_END => self.modified_maps.len() + offset,
                    _ => {
                        ctx.return_value = Some(usize::MAX); // errno EINVAL
                        return;
                    }
                };

                if new_offset > self.modified_maps.len() {
                    ctx.return_value = Some(usize::MAX); // errno EINVAL
                    return;
                }

                self.offset = new_offset;
                ctx.return_value = Some(self.offset);
            }
            Sysno::close => {
                let fd = ctx.args[0];
                if fd != HIDE_MAPS_MAGIC {
                    return;
                }

                // Do nothing
                ctx.return_value = Some(0);
            }
            _ => unimplemented!(),
        }
    }
}
