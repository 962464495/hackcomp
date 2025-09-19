/// fs.rs - util funcs with direct SVC calls
use std::path::Path;

pub fn read_all(path: impl AsRef<Path>) -> crate::Result<Vec<u8>> {
    const CHUNK_SIZE: usize = 4096; // Read in 4KB chunks

    unsafe {
        // std::io::Error::from_raw_os_error
        let path = path.as_ref();

        let fd = nc::openat(nc::AT_FDCWD, path, nc::O_RDONLY, 0)?;

        let mut stat_buf = nc::stat_t::default();
        nc::fstat(fd, &mut stat_buf)?;

        let size = stat_buf.st_size as usize;
        dbg!(size);

        let mut buf;

        if size > 0 {
            // --- Path 1: Known Size (for regular files) ---
            buf = vec![0u8; size];
            nc::read(fd, &mut buf)?;
        } else {
            // --- Path 2: Zero Size (for /proc files or empty files) ---
            buf = Vec::with_capacity(CHUNK_SIZE); // Start with a reasonable capacity
            let mut tmp_buf = [0u8; CHUNK_SIZE];

            loop {
                // Read a chunk from the file
                let bytes_read = nc::read(fd, &mut tmp_buf)? as usize;

                if bytes_read == 0 {
                    // 0 bytes read means we've reached the end of the file
                    break;
                }

                // Append the chunk we just read to our main buffer
                buf.extend_from_slice(&tmp_buf[..bytes_read]);
            }
        }

        nc::close(fd)?;
        Ok(buf)
    }
}
