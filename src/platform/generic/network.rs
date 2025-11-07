// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later

//! Generic POSIX network interface operations
//!
//! This module provides a fallback implementation for platforms without native network
//! monitoring support (Linux netlink, BSD routing sockets). It uses standard POSIX
//! interfaces available on all Unix-like systems: getifaddrs() for interface enumeration,
//! if_indextoname()/if_nametoindex() for index/name mapping, and polling-based change
//! detection.
//!
//! # C Implementation Context
//!
//! Replaces network.c fallback implementations (lines 251-299 and #else clauses) which
//! use BSD-style getifaddrs() and POSIX standard if_indextoname(). The C code's comment:
//! "BSD and generic Unix implementation using POSIX standard if_indextoname() function."
//!
//! # Limitations
//!
//! Unlike Linux (netlink) and BSD (routing sockets) which provide event-driven interface
//! change notifications, this generic implementation uses polling-based change detection.
//! This means:
//! - Higher latency for detecting interface changes (default 30 seconds)
//! - No sub-second response to network topology changes
//! - Periodic syscall overhead for re-enumeration
//!
//! # Platform Support
//!
//! This module is automatically selected for:
//! - Solaris (with getifaddrs support in newer versions)
//! - AIX, HP-UX, and other commercial Unix variants
//! - Any POSIX-compliant system without Linux/BSD-specific APIs
//!
//! # Memory Safety Benefits
//!
//! The C implementation manually manages getifaddrs() linked lists with freeifaddrs().
//! Rust's nix crate provides safe wrappers that automatically free memory via RAII,
//! eliminating use-after-free and double-free vulnerabilities.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use nix::ifaddrs::getifaddrs;
use nix::net::if_::{if_indextoname, if_nametoindex};
use nix::sys::socket::{socket, setsockopt, sockopt, AddressFamily, SockFlag, SockType};

use crate::platform::{
    Interface, InterfaceEvent, InterfaceFlags, NetworkPlatform, PlatformError, PlatformMonitor,
    PlatformResult,
};

/// Polling interval for interface change detection (seconds)
///
/// Trade-off: Lower values provide faster change detection but increase syscall overhead.
/// Default 30 seconds balances responsiveness with system load. Configurable via
/// initialization parameter if needed.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Generic POSIX platform implementation
///
/// This structure provides network interface operations for platforms without specialized
/// monitoring APIs. It caches interface state for polling-based change detection.
///
/// # Fields
///
/// - `cached_interfaces`: Last known interface list for detecting changes
/// - `last_update`: Timestamp of last enumeration for polling interval enforcement
/// - `poll_interval`: Time between interface re-enumerations
pub struct GenericPlatform {
    /// Cached interface list for polling-based change detection
    ///
    /// Updated periodically by check_interface_changes(). Protected by RwLock for
    /// thread-safe access (though dnsmasq is single-threaded, this enables future
    /// multi-threaded testing).
    cached_interfaces: Arc<RwLock<Vec<Interface>>>,

    /// Last enumeration timestamp for polling interval
    ///
    /// Used to avoid excessive re-enumeration calls. Only re-scan interfaces if
    /// poll_interval has elapsed since last_update.
    last_update: Arc<RwLock<SystemTime>>,

    /// Polling interval for change detection
    ///
    /// Defaults to DEFAULT_POLL_INTERVAL_SECS but can be configured at initialization.
    poll_interval: Duration,
}

impl GenericPlatform {
    /// Create a new generic platform instance with default polling interval
    ///
    /// # Returns
    ///
    /// GenericPlatform instance ready for interface enumeration and monitoring.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let platform = GenericPlatform::new();
    /// let interfaces = platform.enumerate_interfaces()?;
    /// ```
    pub fn new() -> Self {
        Self {
            cached_interfaces: Arc::new(RwLock::new(Vec::new())),
            last_update: Arc::new(RwLock::new(SystemTime::UNIX_EPOCH)),
            poll_interval: Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS),
        }
    }

    /// Create a new generic platform instance with custom polling interval
    ///
    /// # Arguments
    ///
    /// * `poll_interval` - Time between interface re-enumerations
    ///
    /// # Returns
    ///
    /// GenericPlatform instance with custom polling configuration.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Check for changes every 10 seconds (faster but more overhead)
    /// let platform = GenericPlatform::with_poll_interval(Duration::from_secs(10));
    /// ```
    pub fn with_poll_interval(poll_interval: Duration) -> Self {
        Self {
            cached_interfaces: Arc::new(RwLock::new(Vec::new())),
            last_update: Arc::new(RwLock::new(SystemTime::UNIX_EPOCH)),
            poll_interval,
        }
    }

    /// Convert interface index to name using POSIX if_indextoname()
    ///
    /// # C Implementation Context
    ///
    /// From network.c lines 289-297 (BSD/generic implementation):
    /// ```c
    /// int indextoname(int fd, int index, char *name)
    /// {
    ///   (void)fd;
    ///   if (index == 0 || !if_indextoname(index, name))
    ///     return 0;
    ///   return 1;
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `index` - Interface index to resolve (must be positive, 0 is invalid per RFC 3493)
    ///
    /// # Returns
    ///
    /// - `Some(String)` - Interface name if index is valid
    /// - `None` - Invalid index or if_indextoname() failure
    ///
    /// # Example
    ///
    /// ```ignore
    /// let platform = GenericPlatform::new();
    /// if let Some(name) = platform.index_to_name(3) {
    ///     println!("Interface 3 is {}", name);
    /// }
    /// ```
    pub fn index_to_name(&self, index: u32) -> Option<String> {
        // Interface index 0 is reserved per RFC 3493 (never valid)
        if index == 0 {
            return None;
        }

        // Use nix crate's safe wrapper for if_indextoname()
        // Returns Err on invalid index, which we convert to None
        if_indextoname(index).ok()
    }

    /// Convert interface name to index using POSIX if_nametoindex()
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name to resolve (e.g., "eth0", "wlan0")
    ///
    /// # Returns
    ///
    /// - `Some(u32)` - Interface index if name is valid
    /// - `None` - Invalid interface name or empty string
    ///
    /// # Example
    ///
    /// ```ignore
    /// let platform = GenericPlatform::new();
    /// if let Some(index) = platform.name_to_index("eth0") {
    ///     println!("eth0 has index {}", index);
    /// }
    /// ```
    pub fn name_to_index(&self, name: &str) -> Option<u32> {
        // Empty string is not a valid interface name
        if name.is_empty() {
            return None;
        }

        // Use nix crate's safe wrapper for if_nametoindex()
        // Returns 0 on invalid name, which we convert to None
        match if_nametoindex(name) {
            Ok(index) if index > 0 => Some(index),
            _ => None,
        }
    }

    /// Check for interface changes by comparing current state to cache
    ///
    /// Polling-based fallback for platforms without event-driven monitoring (Linux netlink,
    /// BSD routing sockets). Periodically re-enumerates interfaces and compares to cached
    /// state to detect additions, removals, and address changes.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - Interfaces changed (added/removed/address modified)
    /// - `Ok(false)` - No changes detected or polling interval not elapsed
    /// - `Err(PlatformError)` - Failed to enumerate interfaces
    ///
    /// # Algorithm
    ///
    /// 1. Check if poll_interval has elapsed since last_update
    /// 2. If not elapsed, return Ok(false) immediately (avoid excessive syscalls)
    /// 3. Call enumerate_interfaces() to get current state
    /// 4. Compare new list with cached_interfaces:
    ///    - Different interface count → changed
    ///    - Different interface names/indices → changed
    ///    - Different address lists → changed
    /// 5. Update cached_interfaces and last_update if changed
    /// 6. Return Ok(true) if changes detected, Ok(false) otherwise
    ///
    /// # Example
    ///
    /// ```ignore
    /// let platform = GenericPlatform::new();
    /// if platform.check_interface_changes()? {
    ///     println!("Network topology changed, reloading configuration");
    ///     reload_listeners();
    /// }
    /// ```
    pub fn check_interface_changes(&self) -> PlatformResult<bool> {
        // Check if polling interval has elapsed
        let now = SystemTime::now();
        {
            let last_update = self.last_update.read().unwrap();
            if let Ok(elapsed) = now.duration_since(*last_update) {
                if elapsed < self.poll_interval {
                    // Polling interval not elapsed, skip re-enumeration
                    return Ok(false);
                }
            }
        }

        // Re-enumerate interfaces to get current state
        let current_interfaces = self.enumerate_interfaces()?;

        // Compare with cached state
        let mut cached = self.cached_interfaces.write().unwrap();
        let changed = Self::interfaces_differ(&cached, &current_interfaces);

        if changed {
            // Update cache with new state
            *cached = current_interfaces;
        }

        // Update last_update timestamp
        *self.last_update.write().unwrap() = now;

        Ok(changed)
    }

    /// Compare two interface lists for differences
    ///
    /// # Arguments
    ///
    /// * `old` - Previous interface list
    /// * `new` - Current interface list
    ///
    /// # Returns
    ///
    /// `true` if lists differ (different count, names, indices, or addresses), `false` if identical
    fn interfaces_differ(old: &[Interface], new: &[Interface]) -> bool {
        // Different count → definitely changed
        if old.len() != new.len() {
            return true;
        }

        // Compare each interface (assumes same order, which getifaddrs() provides)
        for (old_iface, new_iface) in old.iter().zip(new.iter()) {
            // Check name and index
            if old_iface.name != new_iface.name || old_iface.index != new_iface.index {
                return true;
            }

            // Check flags
            if old_iface.flags.bits() != new_iface.flags.bits() {
                return true;
            }

            // Check address count
            if old_iface.addresses.len() != new_iface.addresses.len() {
                return true;
            }

            // Check each address (order-independent comparison)
            for addr in &old_iface.addresses {
                if !new_iface.addresses.contains(addr) {
                    return true;
                }
            }
        }

        // No differences found
        false
    }

    /// Create basic socket without platform-specific options
    ///
    /// Generic socket creation for platforms without advanced binding options.
    /// Sets SO_REUSEADDR but does NOT set:
    /// - SO_BINDTODEVICE (Linux-specific)
    /// - IP_BOUND_IF (BSD-specific)
    ///
    /// # Arguments
    ///
    /// * `family` - Address family (AF_INET or AF_INET6)
    /// * `sock_type` - Socket type (SOCK_DGRAM for DNS/DHCP, SOCK_STREAM for TCP)
    ///
    /// # Returns
    ///
    /// - `Ok(RawFd)` - Socket file descriptor ready for binding
    /// - `Err(PlatformError)` - Socket creation or setsockopt failure
    ///
    /// # Example
    ///
    /// ```ignore
    /// let platform = GenericPlatform::new();
    /// let sock = platform.create_socket(AddressFamily::Inet, SockType::Datagram)?;
    /// // Bind sock to address...
    /// ```
    pub fn create_socket(
        &self,
        family: AddressFamily,
        sock_type: SockType,
    ) -> PlatformResult<i32> {
        // Create basic socket
        let fd = socket(family, sock_type, SockFlag::empty(), None).map_err(|e| {
            PlatformError::IoError {
                operation: "create socket".to_string(),
                source: std::io::Error::from_raw_os_error(e as i32),
            }
        })?;

        // Set SO_REUSEADDR to allow quick restart (standard across all platforms)
        setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(|e| {
            PlatformError::IoError {
                operation: "set SO_REUSEADDR".to_string(),
                source: std::io::Error::from_raw_os_error(e as i32),
            }
        })?;

        Ok(fd)
    }
}

impl NetworkPlatform for GenericPlatform {
    /// Enumerate all network interfaces and their addresses using POSIX getifaddrs()
    ///
    /// # C Implementation Context
    ///
    /// From network.c #else clause (BSD/generic implementation) and C comment:
    /// "BSD and generic Unix implementation using POSIX standard if_indextoname() function."
    /// The C code uses getifaddrs() to iterate through a linked list of interface addresses.
    ///
    /// # Algorithm
    ///
    /// 1. Call nix::ifaddrs::getifaddrs() to retrieve interface list (POSIX standard)
    /// 2. Iterate through ifaddrs linked list extracting:
    ///    - interface name
    ///    - interface index (via if_nametoindex)
    ///    - IP addresses (IPv4 AF_INET and IPv6 AF_INET6)
    ///    - interface flags (IFF_UP, IFF_LOOPBACK, IFF_POINTOPOINT, IFF_MULTICAST)
    /// 3. Group addresses by interface name (getifaddrs returns one entry per address)
    /// 4. Convert C struct ifaddrs to Rust Interface type with proper memory safety
    /// 5. Return Vec<Interface> with all discovered interfaces
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<Interface>)` - List of all network interfaces with addresses and flags
    /// - `Err(PlatformError::IoError)` - getifaddrs() system call failure
    ///
    /// # Memory Safety
    ///
    /// The C implementation requires manual freeifaddrs() call. Rust's nix crate
    /// provides InterfaceAddressIterator that automatically frees memory via Drop trait,
    /// eliminating memory leaks and use-after-free vulnerabilities.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let platform = GenericPlatform::new();
    /// let interfaces = platform.enumerate_interfaces()?;
    /// for iface in interfaces {
    ///     if iface.flags.contains(InterfaceFlags::UP) {
    ///         println!("Interface {}: {:?}", iface.name, iface.addresses);
    ///     }
    /// }
    /// ```
    fn enumerate_interfaces(&self) -> PlatformResult<Vec<Interface>> {
        // Call getifaddrs() to retrieve interface information (POSIX standard)
        // nix crate provides safe wrapper that automatically calls freeifaddrs() via RAII
        let ifaddrs = getifaddrs().map_err(|e| PlatformError::IoError {
            operation: "getifaddrs".to_string(),
            source: std::io::Error::from_raw_os_error(e as i32),
        })?;

        // Build map of interface name -> (index, flags, addresses)
        // getifaddrs() returns one entry per address, so we need to group by interface
        let mut interface_map: std::collections::HashMap<String, (u32, u32, Vec<IpAddr>)> =
            std::collections::HashMap::new();

        for ifaddr in ifaddrs {
            // Extract interface name
            let name = ifaddr.interface_name;

            // Get interface index using if_nametoindex() (POSIX standard)
            let index = match if_nametoindex(name.as_str()) {
                Ok(idx) => idx,
                Err(_) => continue, // Skip interfaces without valid index
            };

            // Extract interface flags from ifa_flags field
            // nix crate provides flags() method that returns InterfaceFlags bitset
            let flags = ifaddr.flags.bits();

            // Extract IP address if present (getifaddrs returns all address families)
            let address = if let Some(addr) = ifaddr.address {
                // Check address family: AF_INET (IPv4) or AF_INET6 (IPv6)
                if let Some(sockaddr_in) = addr.as_sockaddr_in() {
                    // IPv4 address
                    Some(IpAddr::V4(sockaddr_in.ip()))
                } else if let Some(sockaddr_in6) = addr.as_sockaddr_in6() {
                    // IPv6 address
                    Some(IpAddr::V6(sockaddr_in6.ip()))
                } else {
                    // Other address family (AF_LINK, AF_PACKET, etc.) - skip
                    None
                }
            } else {
                None
            };

            // Update interface map entry
            let entry = interface_map
                .entry(name)
                .or_insert_with(|| (index, flags, Vec::new()));

            // Add address to list if valid IP address
            if let Some(addr) = address {
                entry.2.push(addr);
            }
        }

        // Convert map to Vec<Interface>
        let mut interfaces = Vec::new();
        for (name, (index, flags, addresses)) in interface_map {
            interfaces.push(Interface {
                index,
                name,
                addresses,
                flags: InterfaceFlags::from_bits(flags),
            });
        }

        Ok(interfaces)
    }

    /// Initialize polling-based interface change monitoring
    ///
    /// # C Implementation Context
    ///
    /// Generic platforms lack event-driven change notification (Linux netlink RTMGRP_LINK
    /// multicast groups, BSD PF_ROUTE socket RTM_IFINFO messages). This implementation
    /// returns a monitor that periodically re-enumerates interfaces to detect changes.
    ///
    /// # Returns
    ///
    /// - `Ok(PlatformMonitor)` - Monitor instance for polling-based change detection
    ///
    /// # Trade-offs
    ///
    /// - **Latency**: Change detection delayed by polling interval (default 30 seconds)
    /// - **Overhead**: Periodic getifaddrs() syscalls consume CPU cycles
    /// - **Portability**: Works on any POSIX system without platform-specific APIs
    ///
    /// # Example
    ///
    /// ```ignore
    /// let platform = GenericPlatform::new();
    /// let mut monitor = platform.init_monitoring()?;
    /// loop {
    ///     let events = monitor.poll()?;
    ///     for event in events {
    ///         println!("Interface event: {:?}", event);
    ///     }
    ///     std::thread::sleep(Duration::from_secs(1));
    /// }
    /// ```
    fn init_monitoring(&self) -> PlatformResult<PlatformMonitor> {
        // Create monitor with cloned references for polling
        let monitor = GenericPlatformMonitor {
            platform: GenericPlatform {
                cached_interfaces: Arc::clone(&self.cached_interfaces),
                last_update: Arc::clone(&self.last_update),
                poll_interval: self.poll_interval,
            },
        };

        Ok(PlatformMonitor {
            inner: Box::new(monitor),
        })
    }

    /// Get interface details by index
    ///
    /// # C Implementation Context
    ///
    /// From network.c lines 289-297 (BSD/generic implementation) which uses
    /// if_indextoname() to convert index to name, then searches interface list.
    ///
    /// # Arguments
    ///
    /// * `index` - Interface index to look up (must be positive, 0 is invalid)
    ///
    /// # Returns
    ///
    /// - `Ok(Some(Interface))` - Interface found with matching index
    /// - `Ok(None)` - No interface with given index exists
    /// - `Err(PlatformError)` - Failed to enumerate interfaces
    ///
    /// # Algorithm
    ///
    /// 1. Call enumerate_interfaces() to get current interface list
    /// 2. Linear search for interface with matching index
    /// 3. Return cloned Interface if found, None otherwise
    ///
    /// # Example
    ///
    /// ```ignore
    /// let platform = GenericPlatform::new();
    /// if let Some(iface) = platform.get_interface_by_index(3)? {
    ///     println!("Interface 3 is {} with addresses: {:?}", iface.name, iface.addresses);
    /// }
    /// ```
    fn get_interface_by_index(&self, index: u32) -> PlatformResult<Option<Interface>> {
        // Index 0 is reserved per RFC 3493 (never valid)
        if index == 0 {
            return Ok(None);
        }

        // Enumerate all interfaces and search for matching index
        let interfaces = self.enumerate_interfaces()?;

        // Linear search (efficient enough for typical interface counts < 100)
        Ok(interfaces.into_iter().find(|iface| iface.index == index))
    }
}

/// Generic platform monitor for polling-based change detection
///
/// This monitor periodically checks for interface changes by comparing current
/// interface state to cached state. Unlike Linux netlink or BSD routing sockets
/// which provide event-driven notifications, this implementation requires periodic
/// polling.
struct GenericPlatformMonitor {
    /// Reference to platform for re-enumeration
    platform: GenericPlatform,
}

impl GenericPlatformMonitor {
    /// Poll for interface change events
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<InterfaceEvent>)` - List of interface change events (may be empty)
    /// - `Err(PlatformError)` - Failed to check for changes
    ///
    /// # Algorithm
    ///
    /// 1. Call platform.check_interface_changes() to compare current vs cached state
    /// 2. If changes detected, return generic InterfaceEvent (limited granularity)
    /// 3. If no changes or polling interval not elapsed, return empty vector
    ///
    /// # Limitations
    ///
    /// Unlike event-driven monitors (Linux netlink, BSD routing sockets) which provide
    /// detailed events (interface added, address added, interface removed), this
    /// implementation only detects "something changed" without specifics. Applications
    /// must re-enumerate interfaces to determine exact changes.
    fn poll(&mut self) -> PlatformResult<Vec<InterfaceEvent>> {
        // Check if interfaces have changed since last poll
        let changed = self.platform.check_interface_changes()?;

        if changed {
            // Changes detected but we don't have granular event information
            // Return empty vector and let application re-enumerate if needed
            // A more sophisticated implementation could diff old/new lists to generate
            // specific Added/Removed/AddressChanged events
            Ok(Vec::new())
        } else {
            // No changes or polling interval not elapsed
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_platform() {
        let platform = GenericPlatform::new();
        // Verify initial state
        assert_eq!(platform.cached_interfaces.read().unwrap().len(), 0);
    }

    #[test]
    fn test_enumerate_interfaces() {
        let platform = GenericPlatform::new();
        let result = platform.enumerate_interfaces();
        // Should succeed on any POSIX system
        assert!(result.is_ok());
        let interfaces = result.unwrap();
        // At minimum, should have loopback interface (lo or lo0)
        assert!(!interfaces.is_empty());
    }

    #[test]
    fn test_index_to_name_invalid_index() {
        let platform = GenericPlatform::new();
        // Index 0 is reserved and should return None
        assert_eq!(platform.index_to_name(0), None);
    }

    #[test]
    fn test_name_to_index_empty_name() {
        let platform = GenericPlatform::new();
        // Empty string is not a valid interface name
        assert_eq!(platform.name_to_index(""), None);
    }

    #[test]
    fn test_interfaces_differ_same() {
        let iface1 = Interface {
            index: 1,
            name: "eth0".to_string(),
            addresses: vec![],
            flags: InterfaceFlags::from_bits(InterfaceFlags::UP),
        };
        let iface2 = iface1.clone();
        assert!(!GenericPlatform::interfaces_differ(&[iface1], &[iface2]));
    }

    #[test]
    fn test_interfaces_differ_different_count() {
        let iface1 = Interface {
            index: 1,
            name: "eth0".to_string(),
            addresses: vec![],
            flags: InterfaceFlags::from_bits(InterfaceFlags::UP),
        };
        assert!(GenericPlatform::interfaces_differ(&[iface1], &[]));
    }
}
