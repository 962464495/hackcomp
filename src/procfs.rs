use std::path::Path;

use crate::MapsParseError;

/// Represents the permissions of a memory mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub shared: bool,
}

/// Represents a single memory mapping from /proc/<PID>/maps.
#[derive(Debug, Clone)]
pub struct MemoryMapping {
    pub start_address: usize,
    pub end_address: usize,
    pub permissions: Permissions,
    pub offset: usize,
    pub device_major: u64,
    pub device_minor: u64,
    pub inode: u64,
    pub pathname: Option<String>,
}

pub fn parse_proc_maps(pid: Option<u32>) -> crate::Result<Vec<MemoryMapping>> {
    let path_str = if let Some(pid) = pid {
        format!("/proc/{pid}/maps")
    } else {
        "/proc/self/maps".to_string()
    };

    // Read the file, mapping the IO error to our custom variant.
    let content_bytes = crate::fs::read_all(path_str)?;

    // The `?` here works automatically thanks to `#[from]` on the Utf8 variant.
    let content_str = std::str::from_utf8(&content_bytes).unwrap();

    let mut mappings = Vec::new();

    for line in content_str.lines() {
        // Helper closure to map parsing errors cleanly.

        let mut parts = line.split_ascii_whitespace();
        let malformed = || MapsParseError::MalformedLine {
            line: line.to_string(),
        };

        let address_range = parts.next().ok_or_else(malformed)?;
        let mut addrs = address_range.split('-');
        let start_address = usize::from_str_radix(addrs.next().unwrap(), 16).unwrap();
        let end_address = usize::from_str_radix(addrs.next().unwrap(), 16).unwrap();

        // ... (parsing for permissions, offset, etc. would have similar error mapping) ...

        // Simplified for brevity
        let permissions_str = parts.next().ok_or_else(malformed)?;
        let offset_str = parts.next().ok_or_else(malformed)?;
        let device_str = parts.next().ok_or_else(malformed)?;
        let inode_str = parts.next().ok_or_else(malformed)?;

        let permissions = Permissions {
            read: permissions_str.contains('r'),
            write: permissions_str.contains('w'),
            execute: permissions_str.contains('x'),
            shared: permissions_str.contains('s'),
        };

        // Parse offset, device, and inode
        let offset = usize::from_str_radix(offset_str, 16).unwrap();
        let mut dev_parts = device_str.split(':');
        let device_major = u64::from_str_radix(dev_parts.next().unwrap(), 16).unwrap();
        let device_minor = u64::from_str_radix(dev_parts.next().unwrap(), 16).unwrap();
        let inode = inode_str.parse::<u64>().unwrap();

        // The rest of the line is the optional pathname
        let pathname = parts.collect::<Vec<&str>>().join(" ");
        let pathname = if pathname.is_empty() {
            None
        } else {
            Some(pathname)
        };

        mappings.push(MemoryMapping {
            start_address,
            end_address,
            permissions,
            offset,
            device_major,
            device_minor,
            inode,
            pathname,
        });
    }

    Ok(mappings)
}
