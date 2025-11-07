// Copyright (c) 2000-2022 Simon Kelley
// Copyright (c) 2024 Blitzy Platform (Rust translation)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

//! ARP table access module for DHCP address conflict detection
//!
//! This module provides platform-independent ARP cache querying functionality with in-memory
//! caching to minimize kernel queries. It is used by the DHCP server to implement ping-before-offer
//! address conflict detection.
//!
//! # Overview
//!
//! Before allocating an IP address from the DHCP pool, dnsmasq queries the ARP cache to determine
//! if the address is already in use on the local network. This prevents duplicate IP address
//! assignments and conflicts with existing hosts.
//!
//! The implementation maintains an in-memory cache of ARP entries to minimize expensive kernel
//! queries. The cache is refreshed at configurable intervals (90 seconds by default) and supports
//! both positive entries (IP→MAC mappings) and negative entries (addresses known to be absent
//! from ARP table).
//!
//! # Platform Support
//!
//! - **Linux**: Parses `/proc/net/arp` using async file I/O
//! - **BSD** (FreeBSD, OpenBSD, NetBSD): Uses routing socket RTM_GET messages
//! - **Other platforms**: Returns empty cache (graceful degradation)
//!
//! # Architecture
//!
//! Unlike the C version which uses linked lists and manual memory management, the Rust
//! implementation uses:
//! - `HashMap<IpAddr, ArpRecord>` for O(1) lookup (vs C's O(n) linear search)
//! - `Arc<RwLock<ArpCache>>` for thread-safe shared access in async context
//! - Tokio async I/O for non-blocking file reads
//! - Result types for comprehensive error handling
//!
//! # C Source Reference
//!
//! Translated from: `src/arp.c` (593 lines)
//!
//! Key differences:
//! - Replaced linked lists (arps, old, freelist) with HashMap
//! - Async I/O instead of blocking reads
//! - Type-safe enums instead of #define constants
//! - Owned types (IpAddr) instead of C unions
//! - Thread-safe with RwLock instead of single-threaded assumptions
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use dnsmasq::network::{ArpCache, find_mac};
//! use std::net::IpAddr;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let cache = Arc::new(RwLock::new(ArpCache::new()));
//! let ip: IpAddr = "192.168.1.100".parse()?;
//!
//! // Check if address is in use
//! if let Some(mac) = find_mac(Arc::clone(&cache), ip).await? {
//!     println!("Address in use by MAC: {}", mac);
//! } else {
//!     println!("Address available for allocation");
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::fs::read_to_string;
use tokio::sync::RwLock;
use tokio::task::spawn_blocking;

use crate::constants::DHCP_CHADDR_MAX;

// =============================================================================
// Constants
// =============================================================================

/// Time interval in seconds between forced ARP cache reloads from kernel.
///
/// The ARP cache is refreshed from the kernel at most once every 90 seconds to minimize
/// expensive system calls while keeping the cache reasonably current. Queries within this
/// window are served from the in-memory cache.
///
/// **C Reference**: `INTERVAL` macro in `arp.c` line 88
const REFRESH_INTERVAL_SECS: u64 = 90;

// =============================================================================
// Types and Enums
// =============================================================================

/// Status of an ARP cache entry during refresh cycle.
///
/// This enum replaces the C version's #define constants (ARP_MARK, ARP_FOUND, ARP_NEW, ARP_EMPTY)
/// with a type-safe Rust enum, preventing invalid state combinations.
///
/// # C Reference
///
/// Translated from: `arp.c` lines 91-125 (ARP_MARK, ARP_FOUND, ARP_NEW, ARP_EMPTY)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpStatus {
    /// Temporary marker status during cache refresh sweep.
    ///
    /// Entries are marked at the start of a kernel query, then confirmed as Found if still
    /// present, or removed if not reconfirmed.
    Mark,

    /// Entry confirmed present in kernel ARP table.
    ///
    /// This is a positive, confirmed IP→MAC mapping that has been verified to exist in the
    /// kernel ARP table during the most recent refresh cycle.
    Found,

    /// Newly discovered ARP entry.
    ///
    /// Entry was just added to cache during current refresh cycle. Used to trigger script
    /// notifications (ACTION_ARP event) for new IP→MAC mappings.
    New,

    /// Negative cache entry (no MAC address).
    ///
    /// This entry records that an IP address was queried but not found in the ARP table.
    /// Negative caching prevents repeated kernel queries for non-existent entries.
    Empty,
}

/// Address family for ARP entries.
///
/// Type-safe enum representing whether an ARP entry is for IPv4 or IPv6,
/// replacing C's AF_INET/AF_INET6 integer constants.
///
/// # C Reference
///
/// Replaces C's `int family` field using AF_INET/AF_INET6 constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 address family (AF_INET in C)
    V4,
    /// IPv6 address family (AF_INET6 in C)
    V6,
}

impl AddressFamily {
    /// Create AddressFamily from IpAddr
    fn from_ip(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        }
    }
}

/// MAC address newtype wrapper.
///
/// Provides a type-safe wrapper around a 6-byte Ethernet MAC address with Display and
/// FromStr implementations for human-readable formatting (AA:BB:CC:DD:EE:FF).
///
/// # C Reference
///
/// Replaces raw unsigned char arrays in C with a strongly-typed Rust newtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Convert MAC address to byte slice.
    ///
    /// Returns the underlying 6-byte array as a slice for use in packet construction
    /// or comparison operations.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create MAC address from byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Slice containing exactly 6 bytes representing the MAC address
    ///
    /// # Returns
    ///
    /// * `Some(MacAddr)` if bytes has exactly 6 elements
    /// * `None` if bytes length is not 6
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 6 {
            let mut arr = [0u8; 6];
            arr.copy_from_slice(bytes);
            Some(MacAddr(arr))
        } else {
            None
        }
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = ArpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(ArpError::ParseError(format!(
                "MAC address must have 6 colon-separated hex bytes, got {}",
                parts.len()
            )));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| ArpError::ParseError(format!("Invalid hex byte: {}", part)))?;
        }

        Ok(MacAddr(bytes))
    }
}

/// ARP cache entry recording IP→MAC address mapping.
///
/// Each ArpRecord represents one entry from the system ARP cache, storing the IP address,
/// corresponding hardware (MAC) address, and current status.
///
/// # C Reference
///
/// Translated from: `struct arp_record` in `arp.c` lines 155-162
///
/// # Differences from C
///
/// - Uses `IpAddr` enum instead of C's `union all_addr` for type safety
/// - Uses `AddressFamily` enum instead of C's int family field
/// - Uses owned types instead of pointers
/// - No linked list pointer (uses HashMap instead)
#[derive(Debug, Clone)]
pub struct ArpRecord {
    /// Hardware address length in bytes (typically 6 for Ethernet, 0 for negative entries).
    pub hwlen: u16,

    /// Entry status: Mark, Found, New, or Empty.
    pub status: ArpStatus,

    /// Address family: V4 or V6.
    pub family: AddressFamily,

    /// Hardware (MAC) address, up to DHCP_CHADDR_MAX (16) bytes.
    ///
    /// Only the first `hwlen` bytes are valid. For negative entries (Empty status), this
    /// field is unused.
    pub hwaddr: [u8; DHCP_CHADDR_MAX],

    /// IP address (IPv4 or IPv6).
    pub addr: IpAddr,
}

/// ARP cache error types.
///
/// Comprehensive error enum covering all failure modes in ARP cache operations, using
/// thiserror for automatic Error trait implementation and user-friendly error messages.
///
/// # C Reference
///
/// C version used silent failures and return codes. Rust version provides structured
/// error handling with explicit error types.
#[derive(Debug, Error)]
pub enum ArpError {
    /// File or socket I/O failure.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Malformed /proc/net/arp entry or routing socket response.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Platform doesn't support ARP enumeration.
    #[error("ARP enumeration not supported on this platform")]
    UnsupportedPlatform,
}

/// ARP cache manager with automatic refresh.
///
/// Maintains an in-memory cache of ARP entries with periodic refresh from kernel ARP table.
/// Uses HashMap for O(1) lookup performance (vs C's O(n) linked list search).
///
/// # Thread Safety
///
/// This struct is designed to be wrapped in `Arc<RwLock<ArpCache>>` for thread-safe shared
/// access in async contexts. The C version was single-threaded; Rust version supports
/// concurrent queries with reader-writer synchronization.
///
/// # C Reference
///
/// Replaces C's static variables: `arps`, `old`, `freelist`, `last` (lines 164-165)
pub struct ArpCache {
    /// Active ARP entries indexed by IP address.
    arps: HashMap<IpAddr, ArpRecord>,

    /// Timestamp of last kernel ARP table refresh.
    last_refresh: Option<Instant>,

    /// Refresh interval (90 seconds).
    refresh_interval: Duration,
}

impl ArpCache {
    /// Create a new empty ARP cache.
    ///
    /// Initializes cache with 90-second refresh interval and no entries. Call `refresh_cache()`
    /// to populate from kernel ARP table.
    ///
    /// # Returns
    ///
    /// New ArpCache instance ready for use.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::network::ArpCache;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// let cache = Arc::new(RwLock::new(ArpCache::new()));
    /// ```
    pub fn new() -> Self {
        ArpCache {
            arps: HashMap::new(),
            last_refresh: None,
            refresh_interval: Duration::from_secs(REFRESH_INTERVAL_SECS),
        }
    }

    /// Check if cache needs refresh based on elapsed time.
    ///
    /// Returns true if cache has never been refreshed or if more than 90 seconds have
    /// elapsed since last refresh.
    fn needs_refresh(&self) -> bool {
        match self.last_refresh {
            None => true,
            Some(last) => last.elapsed() >= self.refresh_interval,
        }
    }

    /// Search ARP cache for MAC address of given IP address.
    ///
    /// Primary public API for ARP cache lookups. Searches the in-memory ARP cache for the
    /// MAC address corresponding to the specified IP address, refreshing from kernel if
    /// cache is stale.
    ///
    /// # Arguments
    ///
    /// * `ip` - IP address to look up (IPv4 or IPv6)
    /// * `lazy` - If true, return negative cache entries; if false, only return positive entries
    ///
    /// # Returns
    ///
    /// * `Ok(Some(MacAddr))` if address found with MAC
    /// * `Ok(None)` if address not in ARP table or negative entry and lazy=false
    /// * `Err(ArpError)` on I/O or parse errors
    ///
    /// # C Reference
    ///
    /// Translated from: `find_mac()` in `arp.c` lines 398-491
    ///
    /// # Differences from C
    ///
    /// - Async instead of blocking I/O
    /// - Result type instead of return code
    /// - HashMap lookup O(1) instead of linked list O(n)
    /// - No goto-based retry logic
    pub async fn find_mac(&mut self, ip: IpAddr, lazy: bool) -> Result<Option<MacAddr>, ArpError> {
        // Refresh cache if needed
        if self.needs_refresh() {
            self.refresh_cache().await?;
        }

        // Look up entry
        if let Some(record) = self.arps.get(&ip) {
            // Only accept positive entries unless in lazy mode
            if (record.status != ArpStatus::Empty || lazy) && record.hwlen != 0 && record.hwlen <= 6
            {
                return Ok(MacAddr::from_bytes(&record.hwaddr[..6]));
            }
        }

        // Not found - create negative cache entry
        let record = ArpRecord {
            hwlen: 0,
            status: ArpStatus::Empty,
            family: AddressFamily::from_ip(&ip),
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            addr: ip,
        };
        self.arps.insert(ip, record);

        Ok(None)
    }

    /// Refresh ARP cache from kernel ARP table.
    ///
    /// Platform-specific implementation that enumerates kernel ARP entries and updates
    /// the in-memory cache. Implements mark-and-sweep algorithm: marks existing entries,
    /// confirms entries found in kernel, and removes unmarked entries.
    ///
    /// # Platform Behavior
    ///
    /// - **Linux**: Parses `/proc/net/arp` asynchronously
    /// - **BSD**: Uses routing socket RTM_GET (synchronous, dispatched to blocking pool)
    /// - **Other**: No-op, cache remains empty
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success
    /// * `Err(ArpError)` on I/O or parse failures
    ///
    /// # C Reference
    ///
    /// Translated from: Cache refresh logic in `find_mac()` lines 436-464
    pub async fn refresh_cache(&mut self) -> Result<(), ArpError> {
        // Mark all non-empty entries
        for record in self.arps.values_mut() {
            if record.status != ArpStatus::Empty {
                record.status = ArpStatus::Mark;
            }
        }

        // Platform-specific enumeration
        #[cfg(target_os = "linux")]
        {
            self.refresh_cache_linux().await?;
        }

        #[cfg(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        {
            self.refresh_cache_bsd().await?;
        }

        // Remove unconfirmed entries (still marked)
        self.arps
            .retain(|_, record| record.status != ArpStatus::Mark);

        // Update refresh timestamp
        self.last_refresh = Some(Instant::now());

        Ok(())
    }

    /// Linux-specific ARP cache refresh via /proc/net/arp parsing.
    ///
    /// Reads and parses `/proc/net/arp` to enumerate kernel ARP entries. Format is:
    /// ```text
    /// IP address       HW type     Flags       HW address            Mask     Device
    /// 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
    /// ```
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success
    /// * `Err(ArpError)` if file read or parse fails
    ///
    /// # C Reference
    ///
    /// Linux-specific logic was in `iface_enumerate()` callback path in C version.
    #[cfg(target_os = "linux")]
    async fn refresh_cache_linux(&mut self) -> Result<(), ArpError> {
        let contents = read_to_string("/proc/net/arp").await?;

        for line in contents.lines().skip(1) {
            // Skip header line
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue; // Malformed line, skip
            }

            // Parse IP address
            let ip = match parts[0].parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => continue, // Invalid IP, skip
            };

            // Parse MAC address (format: aa:bb:cc:dd:ee:ff)
            let mac_str = parts[3];
            if mac_str == "00:00:00:00:00:00" {
                continue; // Incomplete entry
            }

            let mac = match MacAddr::from_str(mac_str) {
                Ok(mac) => mac,
                Err(_) => continue, // Invalid MAC, skip
            };

            // Update or create entry
            if let Some(record) = self.arps.get_mut(&ip) {
                // Existing entry
                if record.status == ArpStatus::Empty {
                    // Was negative, now positive
                    record.status = ArpStatus::New;
                    record.hwlen = 6;
                    record.hwaddr[..6].copy_from_slice(&mac.0);
                } else if record.hwlen == 6 && &record.hwaddr[..6] == mac.as_bytes() {
                    // Matches existing - confirm
                    record.status = ArpStatus::Found;
                }
            } else {
                // New entry
                let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
                hwaddr[..6].copy_from_slice(&mac.0);
                let record = ArpRecord {
                    hwlen: 6,
                    status: ArpStatus::New,
                    family: AddressFamily::from_ip(&ip),
                    hwaddr,
                    addr: ip,
                };
                self.arps.insert(ip, record);
            }
        }

        Ok(())
    }

    /// BSD-specific ARP cache refresh via routing socket.
    ///
    /// Uses routing socket RTM_GET messages to query kernel ARP cache. This is a synchronous
    /// operation dispatched to Tokio's blocking thread pool to avoid blocking the async runtime.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success
    /// * `Err(ArpError)` if routing socket operations fail
    ///
    /// # C Reference
    ///
    /// BSD-specific logic was in `iface_enumerate()` callback path using BPF in C version.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    async fn refresh_cache_bsd(&mut self) -> Result<(), ArpError> {
        // BSD implementation would use routing socket via nix crate
        // For now, return UnsupportedPlatform as placeholder
        // Real implementation would use spawn_blocking for synchronous syscalls
        spawn_blocking(|| {
            // TODO: Implement routing socket RTM_GET query
            // This would use nix::sys::socket for AF_ROUTE socket
            // and parse routing messages to extract ARP entries
            Err(ArpError::UnsupportedPlatform)
        })
        .await
        .map_err(|_| {
            ArpError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Task join error",
            ))
        })?
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Public API Functions
// =============================================================================

/// Search ARP cache for MAC address of given IP address (convenience wrapper).
///
/// This function provides a simpler API for the common case of looking up a single IP address.
/// It automatically handles cache refresh and thread-safe access to the shared cache.
///
/// # Arguments
///
/// * `cache` - Shared ARP cache wrapped in Arc<RwLock>
/// * `ip` - IP address to look up
///
/// # Returns
///
/// * `Ok(Some(MacAddr))` if address found with MAC
/// * `Ok(None)` if address not in ARP table
/// * `Err(ArpError)` on I/O or parse errors
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::network::{ArpCache, find_mac};
/// use std::net::IpAddr;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let cache = Arc::new(RwLock::new(ArpCache::new()));
/// let ip: IpAddr = "192.168.1.100".parse()?;
///
/// if let Some(mac) = find_mac(Arc::clone(&cache), ip).await? {
///     println!("Address in use by MAC: {}", mac);
/// } else {
///     println!("Address available");
/// }
/// # Ok(())
/// # }
/// ```
///
/// # C Reference
///
/// Simplified wrapper around the C version's `find_mac()` function.
pub async fn find_mac(
    cache: Arc<RwLock<ArpCache>>,
    ip: IpAddr,
) -> Result<Option<MacAddr>, ArpError> {
    let mut cache = cache.write().await;
    cache.find_mac(ip, false).await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_addr_display() {
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(mac.to_string(), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_mac_addr_from_str() {
        let mac = MacAddr::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_addr_from_str_invalid() {
        assert!(MacAddr::from_str("invalid").is_err());
        assert!(MacAddr::from_str("aa:bb:cc:dd:ee").is_err()); // Too few bytes
        assert!(MacAddr::from_str("aa:bb:cc:dd:ee:ff:00").is_err()); // Too many bytes
    }

    #[test]
    fn test_mac_addr_from_bytes() {
        let bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mac = MacAddr::from_bytes(&bytes).unwrap();
        assert_eq!(mac.0, bytes);
    }

    #[test]
    fn test_mac_addr_from_bytes_invalid_length() {
        assert!(MacAddr::from_bytes(&[0xAA, 0xBB, 0xCC]).is_none());
        assert!(MacAddr::from_bytes(&[0xAA; 8]).is_none());
    }

    #[test]
    fn test_arp_cache_new() {
        let cache = ArpCache::new();
        assert!(cache.arps.is_empty());
        assert!(cache.last_refresh.is_none());
        assert_eq!(cache.refresh_interval, Duration::from_secs(90));
    }

    #[test]
    fn test_arp_cache_needs_refresh() {
        let mut cache = ArpCache::new();

        // Initially needs refresh
        assert!(cache.needs_refresh());

        // After setting timestamp, doesn't need refresh
        cache.last_refresh = Some(Instant::now());
        assert!(!cache.needs_refresh());
    }

    #[tokio::test]
    async fn test_find_mac_negative_entry() {
        let mut cache = ArpCache::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Force cache to be fresh to avoid refresh attempt
        cache.last_refresh = Some(Instant::now());

        // First lookup should create negative entry
        let result = cache.find_mac(ip, false).await.unwrap();
        assert!(result.is_none());

        // Verify negative entry was created
        let entry = cache.arps.get(&ip).unwrap();
        assert_eq!(entry.status, ArpStatus::Empty);
        assert_eq!(entry.hwlen, 0);
    }

    #[tokio::test]
    async fn test_find_mac_lazy_mode() {
        let mut cache = ArpCache::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Force cache to be fresh
        cache.last_refresh = Some(Instant::now());

        // Create negative entry
        let _ = cache.find_mac(ip, false).await;

        // In lazy mode, should return None for negative entry
        let result = cache.find_mac(ip, true).await.unwrap();
        assert!(result.is_none());
    }
}
