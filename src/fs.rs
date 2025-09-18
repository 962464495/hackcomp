/// fs.rs - util funcs with direct SVC calls
use std::{
    ffi::{CStr, CString, OsStr},
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
    path::Path,
    str::FromStr,
};
use syscalls::{Sysno, syscall};

impl From<syscalls::Errno> for crate::Error {
    fn from(value: syscalls::Errno) -> Self {
        std::io::Error::from_raw_os_error(value.into_raw()).into()
    }
}

pub fn read_all(path: impl AsRef<Path>) -> crate::Result<Vec<u8>> {
    const CHUNK_SIZE: usize = 4096; // Read in 4KB chunks

    unsafe {
        // std::io::Error::from_raw_os_error
        let path = path.as_ref();

        let fd = syscalls::syscall!(
            Sysno::openat,
            libc::AT_FDCWD,
            CString::new(path.as_os_str().as_bytes()).unwrap().as_ptr(),
            libc::O_RDONLY
        )?;

        let mut stat_buf = MaybeUninit::<libc::stat>::uninit();
        syscall!(Sysno::fstat, fd, stat_buf.as_mut_ptr())?;

        let size = stat_buf.assume_init().st_size as usize;
        dbg!(size);

        let mut buf;

        if size > 0 {
            // --- Path 1: Known Size (for regular files) ---
            buf = vec![0u8; size];
            syscall!(Sysno::read, fd, buf.as_mut_ptr() as usize, size)?;
        } else {
            // --- Path 2: Zero Size (for /proc files or empty files) ---
            buf = Vec::with_capacity(CHUNK_SIZE); // Start with a reasonable capacity
            let mut tmp_buf = [0u8; CHUNK_SIZE];

            loop {
                // Read a chunk from the file
                let bytes_read =
                    syscall!(Sysno::read, fd, tmp_buf.as_mut_ptr() as usize, CHUNK_SIZE)?;

                if bytes_read == 0 {
                    // 0 bytes read means we've reached the end of the file
                    break;
                }

                // Append the chunk we just read to our main buffer
                buf.extend_from_slice(&tmp_buf[..bytes_read]);
            }
        }

        syscall!(Sysno::close, fd)?;
        Ok(buf)
    }
}
