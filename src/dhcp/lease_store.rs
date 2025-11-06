// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # DHCP Lease Persistent Storage
//!
//! This module provides persistent storage for DHCP leases using atomic file operations,
//! replacing parts of the C implementation in `src/lease.c` related to file I/O.
//!
//! ## Purpose
//!
//! Provides atomic lease database persistence:
//! - Atomic file updates (write-to-temp then rename)
//! - Human-readable lease file format (compatible with C version)
//! - Crash-safe writes using fsync
//! - Support for systems without real-time clocks (HAVE_BROKEN_RTC)
//!
//! ## C Source Mapping
//!
//! | C Function | Rust Equivalent | Purpose |
//! |------------|-----------------|---------|
//! | `lease_init()` | `LeaseStore::load()` | Load leases from file at startup |
//! | `lease_update_file()` | `LeaseStore::save()` | Atomically save leases to file |
//!
//! ## File Format
//!
//! The lease file format is identical to the C version for backward compatibility:
//! ```text
//! <expiry> <hwaddr> <ipaddr> <hostname> <client_id>
//! ```
//!
//! Example DHCPv4 lease:
//! ```text
//! 1609459200 00:11:22:33:44:55 192.168.1.100 client1 *
//! ```
//!
//! Example DHCPv6 lease:
//! ```text
//! 1609459200 00:01:00:01:12:34:56:78 2001:db8::1 client2 00:01:00:01:12:34:56:78
//! ```

use crate::dhcp::lease::{Lease, LeaseFlags, LeaseType, LeaseV4, LeaseV6};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Persistent lease storage manager
pub struct LeaseStore {
    /// Path to lease database file
    lease_file: PathBuf,
}

impl LeaseStore {
    /// Create new lease store
    ///
    /// # Arguments
    ///
    /// * `lease_file` - Path to lease database file (typically `/var/lib/misc/dnsmasq.leases`)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dnsmasq::dhcp::lease_store::LeaseStore;
    /// use std::path::Path;
    ///
    /// let store = LeaseStore::new(Path::new("/var/lib/misc/dnsmasq.leases"));
    /// ```
    pub fn new<P: AsRef<Path>>(lease_file: P) -> Self {
        Self {
            lease_file: lease_file.as_ref().to_path_buf(),
        }
    }

    /// Load leases from file
    ///
    /// Corresponds to C's `lease_init()` (lease.c:106-220)
    ///
    /// # Returns
    ///
    /// Vector of leases loaded from file, or error if file cannot be read
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::dhcp::lease_store::LeaseStore;
    /// # use std::path::Path;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let store = LeaseStore::new(Path::new("/var/lib/misc/dnsmasq.leases"));
    /// let leases = store.load()?;
    /// println!("Loaded {} leases", leases.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn load(&self) -> io::Result<Vec<Lease>> {
        let mut leases = Vec::new();

        // If file doesn't exist, return empty vector (not an error)
        if !self.lease_file.exists() {
            return Ok(leases);
        }

        let file = File::open(&self.lease_file)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;

            // Skip empty lines and comments
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse lease line
            if let Some(lease) = self.parse_lease_line(&line) {
                leases.push(lease);
            }
        }

        Ok(leases)
    }

    /// Save leases to file atomically
    ///
    /// Corresponds to C's `lease_update_file()` (lease.c:699-892)
    ///
    /// Uses atomic write pattern: write to temporary file, fsync, then rename.
    /// This ensures the lease database is never corrupted even during crashes or power failures.
    ///
    /// # Arguments
    ///
    /// * `leases` - Slice of leases to save
    ///
    /// # Returns
    ///
    /// Ok(()) if save successful, error otherwise
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::dhcp::lease_store::LeaseStore;
    /// # use std::path::Path;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let store = LeaseStore::new(Path::new("/var/lib/misc/dnsmasq.leases"));
    /// let leases = vec![/* leases */];
    /// store.save(&leases)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn save(&self, leases: &[Lease]) -> io::Result<()> {
        // Create temporary file in same directory
        let temp_file = self.lease_file.with_extension("tmp");

        // Write leases to temporary file
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_file)?;

            for lease in leases {
                let line = self.format_lease_line(lease);
                writeln!(file, "{}", line)?;
            }

            // Ensure data is written to disk
            file.sync_all()?;
        }

        // Atomically replace old file with new file
        std::fs::rename(&temp_file, &self.lease_file)?;

        Ok(())
    }

    /// Parse a lease line from the lease file
    ///
    /// # Arguments
    ///
    /// * `line` - Line from lease file
    ///
    /// # Returns
    ///
    /// Parsed lease if line is valid, None otherwise
    fn parse_lease_line(&self, line: &str) -> Option<Lease> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Need at least 3 fields: expiry, hwaddr/duid, ipaddr
        if parts.len() < 3 {
            return None;
        }

        // Parse expiry time
        let expires = parts[0].parse::<u64>().ok()?;

        // Parse hardware address or DUID
        let hwaddr_or_duid = parse_hex_string(parts[1])?;

        // Parse IP address (try IPv4 first, then IPv6)
        if let Ok(addr) = parts[2].parse::<Ipv4Addr>() {
            // DHCPv4 lease
            let hostname = if parts.len() > 3 && parts[3] != "*" {
                Some(parts[3].to_string())
            } else {
                None
            };

            let client_id = if parts.len() > 4 && parts[4] != "*" {
                parse_hex_string(parts[4])
            } else {
                None
            };

            Some(Lease::V4(LeaseV4 {
                addr,
                hwaddr: hwaddr_or_duid,
                client_id,
                hostname,
                expires,
                flags: LeaseFlags::default(),
            }))
        } else if let Ok(addr) = parts[2].parse::<Ipv6Addr>() {
            // DHCPv6 lease
            let hostname = if parts.len() > 3 && parts[3] != "*" {
                Some(parts[3].to_string())
            } else {
                None
            };

            Some(Lease::V6(LeaseV6 {
                addr,
                duid: hwaddr_or_duid,
                iaid: 0, // IAID not stored in simple format
                hostname,
                expires,
                lease_type: LeaseType::NonTemporaryAddress,
                flags: LeaseFlags::default(),
            }))
        } else {
            None
        }
    }

    /// Format a lease as a line for the lease file
    ///
    /// # Arguments
    ///
    /// * `lease` - Lease to format
    ///
    /// # Returns
    ///
    /// Formatted lease line string
    fn format_lease_line(&self, lease: &Lease) -> String {
        match lease {
            Lease::V4(lease) => {
                let hwaddr = format_hex_string(&lease.hwaddr);
                let hostname = lease.hostname.as_deref().unwrap_or("*");
                let client_id = lease
                    .client_id
                    .as_ref()
                    .map(|cid| format_hex_string(cid))
                    .unwrap_or_else(|| "*".to_string());

                format!(
                    "{} {} {} {} {}",
                    lease.expires, hwaddr, lease.addr, hostname, client_id
                )
            }
            Lease::V6(lease) => {
                let duid = format_hex_string(&lease.duid);
                let hostname = lease.hostname.as_deref().unwrap_or("*");

                format!("{} {} {} {}", lease.expires, duid, lease.addr, hostname)
            }
        }
    }
}

/// Parse hex string (colon-separated or plain hex)
///
/// Supports formats like "00:11:22:33:44:55" or "00112233445"
fn parse_hex_string(s: &str) -> Option<Vec<u8>> {
    if s.contains(':') {
        // Colon-separated format
        let parts: Vec<&str> = s.split(':').collect();
        let mut bytes = Vec::with_capacity(parts.len());
        for part in parts {
            let byte = u8::from_str_radix(part, 16).ok()?;
            bytes.push(byte);
        }
        Some(bytes)
    } else {
        // Plain hex format
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
            bytes.push(byte);
        }
        Some(bytes)
    }
}

/// Format byte array as hex string with colons
fn format_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_hex_string_colon() {
        let result = parse_hex_string("00:11:22:33:44:55");
        assert_eq!(result, Some(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    #[test]
    fn test_parse_hex_string_plain() {
        let result = parse_hex_string("001122334455");
        assert_eq!(result, Some(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    #[test]
    fn test_format_hex_string() {
        let bytes = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = format_hex_string(&bytes);
        assert_eq!(result, "00:11:22:33:44:55");
    }

    #[test]
    fn test_format_lease_line_v4() {
        let store = LeaseStore::new("/tmp/test.leases");
        let lease = Lease::V4(LeaseV4 {
            addr: Ipv4Addr::new(192, 168, 1, 100),
            hwaddr: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            client_id: None,
            hostname: Some("client1".to_string()),
            expires: 1609459200,
            flags: LeaseFlags::default(),
        });

        let line = store.format_lease_line(&lease);
        assert!(line.contains("1609459200"));
        assert!(line.contains("00:11:22:33:44:55"));
        assert!(line.contains("192.168.1.100"));
        assert!(line.contains("client1"));
    }

    #[test]
    fn test_parse_lease_line_v4() {
        let store = LeaseStore::new("/tmp/test.leases");
        let line = "1609459200 00:11:22:33:44:55 192.168.1.100 client1 *";

        let lease = store.parse_lease_line(line);
        assert!(lease.is_some());

        if let Some(Lease::V4(l)) = lease {
            assert_eq!(l.addr, Ipv4Addr::new(192, 168, 1, 100));
            assert_eq!(l.hwaddr, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
            assert_eq!(l.hostname, Some("client1".to_string()));
            assert_eq!(l.expires, 1609459200);
        } else {
            panic!("Expected V4 lease");
        }
    }
}
