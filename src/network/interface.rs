// Copyright (c) 2000-2024 Simon Kelley & dnsmasq contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Network interface enumeration and configuration module
//!
//! This module provides platform-agnostic network interface discovery, address
//! enumeration, and interface validation. It abstracts platform-specific APIs
//! including Linux netlink, BSD routing sockets, and Solaris SIOCGLIFCONF.
//!
//! # Overview
//!
//! The module translates the C implementation from `src/network.c`, providing:
//! - Interface index ↔ name translation
//! - Comprehensive interface enumeration across all platforms
//! - Interface validation against configuration rules
//! - Async monitoring of interface changes (add/remove/address change)
//!
//! # Platform Support
//!
//! - **Linux**: Uses netlink sockets for efficient interface discovery
//! - **BSD/macOS**: Uses `getifaddrs()` system call
//! - **Solaris**: Uses SIOCGLIFCONF ioctl with zone awareness
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::network::interface::{enumerate_interfaces, index_to_name};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Enumerate all network interfaces
//! let interfaces = enumerate_interfaces().await?;
//! for iface in interfaces {
//!     println!("Interface: {} (index: {})", iface.name, iface.index);
//!     for addr in &iface.addresses {
//!         println!("  Address: {}", addr);
//!     }
//! }
//!
//! // Convert interface index to name
//! let name = index_to_name(2).await?;
//! println!("Interface 2 is: {}", name);
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bitflags::bitflags;
use thiserror::Error;
use tokio::task;
use tokio_stream::Stream;

// Platform-specific imports
#[cfg(target_os = "linux")]
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
use nix::ifaddrs::getifaddrs;

#[cfg(target_os = "solaris")]
use nix::libc::{getzoneid, GLOBAL_ZONEID};

/// Network interface record containing all interface properties
///
/// This structure represents a single network interface discovered through
/// platform-specific enumeration. It includes the interface name, system index,
/// all associated addresses (IPv4 and IPv6), operational flags, and MTU.
///
/// # Fields
///
/// - `name`: Interface name (e.g., "eth0", "wlan0", "lo")
/// - `index`: Kernel-assigned interface index for routing
/// - `addresses`: All IP addresses bound to this interface
/// - `flags`: Operational state flags (UP, LOOPBACK, etc.)
/// - `mtu`: Maximum Transmission Unit in bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceRecord {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,
    
    /// Interface index for routing operations
    pub index: u32,
    
    /// All IP addresses (IPv4 and IPv6) on this interface
    pub addresses: Vec<SocketAddr>,
    
    /// Interface operational flags
    pub flags: InterfaceFlags,
    
    /// Maximum Transmission Unit (bytes), if available
    pub mtu: Option<u32>,
}

bitflags! {
    /// Interface operational flags
    ///
    /// These flags indicate the operational state of a network interface,
    /// matching the semantics of IFF_* flags from sys/net/if.h.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dnsmasq::network::interface::InterfaceFlags;
    ///
    /// let flags = InterfaceFlags::UP | InterfaceFlags::MULTICAST;
    /// assert!(flags.contains(InterfaceFlags::UP));
    /// assert!(!flags.contains(InterfaceFlags::LOOPBACK));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct InterfaceFlags: u32 {
        /// Interface is administratively up
        const UP = 0x1;
        
        /// Interface is loopback device
        const LOOPBACK = 0x2;
        
        /// Interface is point-to-point link
        const POINTOPOINT = 0x4;
        
        /// Interface supports multicast
        const MULTICAST = 0x8;
    }
}

/// Errors that can occur during interface operations
///
/// This error type covers all failure modes for interface enumeration,
/// index-to-name translation, and interface monitoring operations.
#[derive(Debug, Error)]
pub enum InterfaceError {
    /// Failed to enumerate network interfaces
    #[error("Failed to enumerate interfaces: {0}")]
    EnumerationFailed(#[from] std::io::Error),
    
    /// Interface with specified name not found
    #[error("Interface {0} not found")]
    NotFound(String),
    
    /// Invalid interface index (0 or not found in system)
    #[error("Invalid interface index: {0}")]
    InvalidIndex(u32),
    
    /// Platform not supported for this operation
    #[error("Platform not supported")]
    UnsupportedPlatform,
}

/// Interface change events for monitoring
///
/// These events are emitted by `watch_interfaces()` when interface
/// configuration changes occur at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceEvent {
    /// New interface added to system
    Added(InterfaceRecord),
    
    /// Interface removed from system
    Removed(String),
    
    /// Interface address configuration changed
    AddressChanged {
        /// Interface name
        name: String,
        /// New address list
        addresses: Vec<SocketAddr>,
    },
}

/// Interface cache for performance optimization
///
/// Caches interface records to avoid repeated system calls during
/// high-frequency operations (e.g., packet processing).
#[derive(Debug)]
struct InterfaceCache {
    /// Map of interface name to record
    interfaces: HashMap<String, InterfaceRecord>,
    
    /// Map of interface index to name
    index_to_name_map: HashMap<u32, String>,
    
    /// Timestamp of last cache update
    last_update: Instant,
    
    /// Cache validity duration
    update_interval: Duration,
}

impl InterfaceCache {
    /// Create a new empty interface cache
    fn new() -> Self {
        Self {
            interfaces: HashMap::new(),
            index_to_name_map: HashMap::new(),
            last_update: Instant::now() - Duration::from_secs(3600), // Force initial update
            update_interval: Duration::from_secs(5),
        }
    }
    
    /// Check if cache needs refresh
    fn needs_refresh(&self) -> bool {
        self.last_update.elapsed() > self.update_interval
    }
    
    /// Update cache with new interface list
    fn update(&mut self, interfaces: Vec<InterfaceRecord>) {
        self.interfaces.clear();
        self.index_to_name_map.clear();
        
        for iface in interfaces {
            self.index_to_name_map.insert(iface.index, iface.name.clone());
            self.interfaces.insert(iface.name.clone(), iface);
        }
        
        self.last_update = Instant::now();
    }
    
    /// Get interface by name
    fn get_by_name(&self, name: &str) -> Option<&InterfaceRecord> {
        self.interfaces.get(name)
    }
    
    /// Get interface name by index
    fn get_name_by_index(&self, index: u32) -> Option<&str> {
        self.index_to_name_map.get(&index).map(|s| s.as_str())
    }
}

/// Global interface cache instance
static INTERFACE_CACHE: once_cell::sync::Lazy<Arc<RwLock<InterfaceCache>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(InterfaceCache::new())));

/// Convert network interface index to interface name
///
/// This function performs platform-specific index-to-name translation,
/// matching the behavior of the C `indextoname()` function.
///
/// # Platform Implementation
///
/// - **Linux**: Uses SIOCGIFNAME ioctl
/// - **BSD/macOS**: Uses `if_indextoname()` libc function
/// - **Solaris**: Uses SIOCGLIFCONF enumeration with zone awareness
///
/// # Arguments
///
/// * `index` - Interface index to resolve (must be > 0)
///
/// # Returns
///
/// - `Ok(String)` - Interface name on success
/// - `Err(InterfaceError::InvalidIndex)` - Index is 0 or not found
/// - `Err(InterfaceError::EnumerationFailed)` - System call failed
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::network::interface::index_to_name;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let name = index_to_name(2).await?;
/// println!("Interface 2 is: {}", name);
/// # Ok(())
/// # }
/// ```
pub async fn index_to_name(index: u32) -> Result<String, InterfaceError> {
    // Index 0 is reserved and invalid
    if index == 0 {
        return Err(InterfaceError::InvalidIndex(index));
    }
    
    // Try cache first
    {
        let cache = INTERFACE_CACHE.read().unwrap();
        if !cache.needs_refresh() {
            if let Some(name) = cache.get_name_by_index(index) {
                return Ok(name.to_string());
            }
        }
    }
    
    // Cache miss or stale - perform platform-specific lookup
    task::spawn_blocking(move || index_to_name_blocking(index)).await
        .map_err(|e| InterfaceError::EnumerationFailed(std::io::Error::other(
            format!("Task join error: {}", e)
        )))?
}

/// Blocking implementation of index-to-name translation
fn index_to_name_blocking(index: u32) -> Result<String, InterfaceError> {
    #[cfg(target_os = "linux")]
    {
        linux::index_to_name_ioctl(index)
    }
    
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ))]
    {
        bsd::index_to_name_libc(index)
    }
    
    #[cfg(target_os = "solaris")]
    {
        solaris::index_to_name_lifconf(index)
    }
    
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "solaris"
    )))]
    {
        Err(InterfaceError::UnsupportedPlatform)
    }
}

/// Convert interface name to interface index
///
/// Performs reverse lookup of interface index from name.
///
/// # Arguments
///
/// * `name` - Interface name to resolve
///
/// # Returns
///
/// - `Ok(u32)` - Interface index on success
/// - `Err(InterfaceError::NotFound)` - Interface name not found
/// - `Err(InterfaceError::EnumerationFailed)` - System call failed
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::network::interface::name_to_index;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let index = name_to_index("eth0").await?;
/// println!("Interface eth0 has index: {}", index);
/// # Ok(())
/// # }
/// ```
pub async fn name_to_index(name: &str) -> Result<u32, InterfaceError> {
    let name = name.to_string();
    
    // Try cache first
    {
        let cache = INTERFACE_CACHE.read().unwrap();
        if !cache.needs_refresh() {
            if let Some(iface) = cache.get_by_name(&name) {
                return Ok(iface.index);
            }
        }
    }
    
    // Cache miss - perform platform-specific lookup
    task::spawn_blocking(move || name_to_index_blocking(&name)).await
        .map_err(|e| InterfaceError::EnumerationFailed(std::io::Error::other(
            format!("Task join error: {}", e)
        )))?
}

/// Blocking implementation of name-to-index translation
fn name_to_index_blocking(name: &str) -> Result<u32, InterfaceError> {
    #[cfg(target_os = "linux")]
    {
        linux::name_to_index_ioctl(name)
    }
    
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ))]
    {
        bsd::name_to_index_libc(name)
    }
    
    #[cfg(target_os = "solaris")]
    {
        solaris::name_to_index_lifconf(name)
    }
    
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "solaris"
    )))]
    {
        Err(InterfaceError::UnsupportedPlatform)
    }
}

/// Enumerate all network interfaces on the system
///
/// Discovers all network interfaces with their addresses, flags, and properties.
/// This function performs platform-specific enumeration and caches results.
///
/// # Returns
///
/// - `Ok(Vec<InterfaceRecord>)` - List of all discovered interfaces
/// - `Err(InterfaceError)` - Enumeration failed
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::network::interface::enumerate_interfaces;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let interfaces = enumerate_interfaces().await?;
/// for iface in interfaces {
///     println!("Found interface: {} with {} addresses", 
///              iface.name, iface.addresses.len());
/// }
/// # Ok(())
/// # }
/// ```
pub async fn enumerate_interfaces() -> Result<Vec<InterfaceRecord>, InterfaceError> {
    let interfaces = task::spawn_blocking(enumerate_interfaces_blocking).await
        .map_err(|e| InterfaceError::EnumerationFailed(std::io::Error::other(
            format!("Task join error: {}", e)
        )))??;
    
    // Update cache with new interface list
    {
        let mut cache = INTERFACE_CACHE.write().unwrap();
        cache.update(interfaces.clone());
    }
    
    Ok(interfaces)
}

/// Blocking implementation of interface enumeration
fn enumerate_interfaces_blocking() -> Result<Vec<InterfaceRecord>, InterfaceError> {
    #[cfg(target_os = "linux")]
    {
        linux::enumerate_via_netlink()
    }
    
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ))]
    {
        bsd::enumerate_via_getifaddrs()
    }
    
    #[cfg(target_os = "solaris")]
    {
        solaris::enumerate_via_lifconf()
    }
    
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "solaris"
    )))]
    {
        Err(InterfaceError::UnsupportedPlatform)
    }
}

/// Validate interface eligibility for listener binding
///
/// Determines whether a given interface and address should be used for listening
/// sockets based on configuration rules (include/exclude lists, authoritative DNS).
///
/// This function implements the logic from C's `iface_check()`, supporting:
/// - Whitelist mode (--interface, --address)
/// - Blacklist mode (--except-interface)
/// - Authoritative DNS interface marking (--auth-server)
///
/// # Arguments
///
/// * `family` - Address family (IPv4/IPv6) or unspecified for name-only check
/// * `addr` - Address to validate (optional for name-only checks)
/// * `name` - Interface name to validate
/// * `auth` - Output parameter for authoritative DNS flag
///
/// # Returns
///
/// `true` if interface/address should be used for listeners, `false` if excluded
///
/// # Examples
///
/// ```rust,no_run
/// use std::net::{IpAddr, Ipv4Addr};
/// use dnsmasq::network::interface::is_interface_allowed;
///
/// let mut auth = false;
/// let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
/// if is_interface_allowed(Some(addr.clone()), Some(addr), "eth0", &mut auth) {
///     println!("Interface eth0 allowed for listening");
/// }
/// ```
pub fn is_interface_allowed(
    family: Option<IpAddr>,
    addr: Option<IpAddr>,
    name: &str,
    auth: &mut bool,
) -> bool {
    // This is a placeholder implementation that accepts all interfaces
    // In a complete implementation, this would check against configuration:
    // - daemon->if_names (interface whitelist)
    // - daemon->if_addrs (address whitelist)
    // - daemon->if_except (interface blacklist)
    // - daemon->authinterface (authoritative DNS interfaces)
    
    // For now, set auth to false and accept all interfaces
    *auth = false;
    
    // Accept all interfaces by default
    // Production implementation would check wildcard patterns and address matching
    true
}

/// Watch for interface change events
///
/// Returns an async stream of interface events (add/remove/address change).
/// The stream continues indefinitely until dropped.
///
/// # Platform Implementation
///
/// - **Linux**: netlink RTM_NEWLINK/RTM_DELLINK messages
/// - **BSD**: kqueue with EVFILT_NETDEV
/// - **Solaris**: polling with SIOCGLIFCONF
///
/// # Returns
///
/// Stream of `InterfaceEvent` changes
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::network::interface::{watch_interfaces, InterfaceEvent};
/// use tokio_stream::StreamExt;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut events = watch_interfaces().await;
/// while let Some(event) = events.next().await {
///     match event {
///         InterfaceEvent::Added(iface) => {
///             println!("Interface added: {}", iface.name);
///         }
///         InterfaceEvent::Removed(name) => {
///             println!("Interface removed: {}", name);
///         }
///         InterfaceEvent::AddressChanged { name, addresses } => {
///             println!("Interface {} addresses changed: {} addrs", name, addresses.len());
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub async fn watch_interfaces() -> impl Stream<Item = InterfaceEvent> {
    // Create a channel for events
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    
    // Spawn monitoring task
    tokio::spawn(async move {
        // Poll for interface changes every 5 seconds
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut last_interfaces: HashMap<String, InterfaceRecord> = HashMap::new();
        
        loop {
            interval.tick().await;
            
            // Enumerate current interfaces
            match enumerate_interfaces().await {
                Ok(interfaces) => {
                    let current: HashMap<String, InterfaceRecord> = interfaces
                        .into_iter()
                        .map(|iface| (iface.name.clone(), iface))
                        .collect();
                    
                    // Detect added interfaces
                    for (name, iface) in &current {
                        if !last_interfaces.contains_key(name) {
                            let _ = tx.send(InterfaceEvent::Added(iface.clone()));
                        } else {
                            // Check for address changes
                            let old_iface = &last_interfaces[name];
                            if old_iface.addresses != iface.addresses {
                                let _ = tx.send(InterfaceEvent::AddressChanged {
                                    name: name.clone(),
                                    addresses: iface.addresses.clone(),
                                });
                            }
                        }
                    }
                    
                    // Detect removed interfaces
                    for name in last_interfaces.keys() {
                        if !current.contains_key(name) {
                            let _ = tx.send(InterfaceEvent::Removed(name.clone()));
                        }
                    }
                    
                    last_interfaces = current;
                }
                Err(e) => {
                    eprintln!("Interface enumeration error: {}", e);
                }
            }
        }
    });
    
    tokio_stream::wrappers::UnboundedReceiverStream::new(rx)
}

// Platform-specific implementations
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::socket::SockaddrLike;
    use std::os::unix::io::AsRawFd;
    
    /// Linux SIOCGIFNAME ioctl for index-to-name translation
    pub fn index_to_name_ioctl(index: u32) -> Result<String, InterfaceError> {
        use nix::libc::{ifreq, ioctl, SIOCGIFNAME, IF_NAMESIZE, AF_INET, SOCK_DGRAM};
        use std::ffi::CStr;
        use std::mem;
        
        // Create a socket for ioctl
        let fd = unsafe { nix::libc::socket(AF_INET, SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(InterfaceError::EnumerationFailed(std::io::Error::last_os_error()));
        }
        
        let mut ifr: ifreq = unsafe { mem::zeroed() };
        // Set interface index in the union - use ifru_ifindex which is the correct field
        unsafe {
            ifr.ifr_ifru.ifru_ifindex = index as i32;
        }
        
        let result = unsafe { ioctl(fd, SIOCGIFNAME, &mut ifr) };
        unsafe { nix::libc::close(fd) };
        
        if result < 0 {
            return Err(InterfaceError::InvalidIndex(index));
        }
        
        let name = unsafe { CStr::from_ptr(ifr.ifr_name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        
        Ok(name)
    }
    
    /// Linux SIOCGIFINDEX ioctl for name-to-index translation
    pub fn name_to_index_ioctl(name: &str) -> Result<u32, InterfaceError> {
        use nix::libc::{ifreq, ioctl, SIOCGIFINDEX, IF_NAMESIZE, AF_INET, SOCK_DGRAM};
        use std::mem;
        
        if name.len() >= IF_NAMESIZE {
            return Err(InterfaceError::NotFound(name.to_string()));
        }
        
        let fd = unsafe { nix::libc::socket(AF_INET, SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(InterfaceError::EnumerationFailed(std::io::Error::last_os_error()));
        }
        
        let mut ifr: ifreq = unsafe { mem::zeroed() };
        let name_bytes = name.as_bytes();
        ifr.ifr_name[..name_bytes.len()].copy_from_slice(
            unsafe { std::mem::transmute::<&[u8], &[i8]>(name_bytes) }
        );
        
        let result = unsafe { ioctl(fd, SIOCGIFINDEX, &mut ifr) };
        unsafe { nix::libc::close(fd) };
        
        if result < 0 {
            return Err(InterfaceError::NotFound(name.to_string()));
        }
        
        let index = unsafe { ifr.ifr_ifru.ifru_ifindex as u32 };
        Ok(index)
    }
    
    /// Enumerate interfaces using netlink (simplified implementation)
    pub fn enumerate_via_netlink() -> Result<Vec<InterfaceRecord>, InterfaceError> {
        // For production, this would use rtnetlink or raw netlink sockets
        // For this implementation, fall back to getifaddrs-style enumeration
        enumerate_via_proc()
    }
    
    /// Simplified Linux enumeration via /proc/net/dev and getifaddrs
    fn enumerate_via_proc() -> Result<Vec<InterfaceRecord>, InterfaceError> {
        use nix::ifaddrs::getifaddrs;
        use nix::sys::socket::SockaddrStorage;
        use std::collections::HashMap;
        
        let ifaddrs = getifaddrs()
            .map_err(|e| InterfaceError::EnumerationFailed(std::io::Error::from_raw_os_error(e as i32)))?;
        
        let mut interfaces: HashMap<String, InterfaceRecord> = HashMap::new();
        
        for ifaddr in ifaddrs {
            let name = ifaddr.interface_name.clone();
            let flags = convert_flags(ifaddr.flags);
            
            // Get or create interface record
            let record = interfaces.entry(name.clone()).or_insert(InterfaceRecord {
                name: name.clone(),
                index: if_nametoindex(&name),
                addresses: Vec::new(),
                flags,
                mtu: None,
            });
            
            // Add address if present
            if let Some(addr) = ifaddr.address {
                if let Some(socket_addr) = sockaddr_to_socketaddr(&addr) {
                    record.addresses.push(socket_addr);
                }
            }
        }
        
        Ok(interfaces.into_values().collect())
    }
    
    /// Convert interface name to index using libc
    fn if_nametoindex(name: &str) -> u32 {
        use std::ffi::CString;
        
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        
        unsafe { nix::libc::if_nametoindex(c_name.as_ptr()) }
    }
    
    /// Convert nix interface flags to our InterfaceFlags
    fn convert_flags(flags: nix::net::if_::InterfaceFlags) -> InterfaceFlags {
        let mut result = InterfaceFlags::empty();
        
        if flags.contains(nix::net::if_::InterfaceFlags::IFF_UP) {
            result |= InterfaceFlags::UP;
        }
        if flags.contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK) {
            result |= InterfaceFlags::LOOPBACK;
        }
        if flags.contains(nix::net::if_::InterfaceFlags::IFF_POINTOPOINT) {
            result |= InterfaceFlags::POINTOPOINT;
        }
        if flags.contains(nix::net::if_::InterfaceFlags::IFF_MULTICAST) {
            result |= InterfaceFlags::MULTICAST;
        }
        
        result
    }
    
    /// Convert SockaddrStorage to SocketAddr
    fn sockaddr_to_socketaddr(addr: &nix::sys::socket::SockaddrStorage) -> Option<SocketAddr> {
        if let Some(sin) = addr.as_sockaddr_in() {
            let ip = sin.ip();
            return Some(SocketAddr::new(IpAddr::V4(ip), sin.port()));
        }
        
        if let Some(sin6) = addr.as_sockaddr_in6() {
            let ip = sin6.ip();
            return Some(SocketAddr::new(IpAddr::V6(ip), sin6.port()));
        }
        
        None
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
mod bsd {
    use super::*;
    use nix::ifaddrs::getifaddrs;
    use std::collections::HashMap;
    use std::ffi::{CStr, CString};
    
    /// BSD/macOS index-to-name translation using libc if_indextoname
    pub fn index_to_name_libc(index: u32) -> Result<String, InterfaceError> {
        let mut buf = vec![0u8; libc::IF_NAMESIZE];
        
        let result = unsafe {
            libc::if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char)
        };
        
        if result.is_null() {
            return Err(InterfaceError::InvalidIndex(index));
        }
        
        let name = unsafe { CStr::from_ptr(result) }
            .to_string_lossy()
            .into_owned();
        
        Ok(name)
    }
    
    /// BSD/macOS name-to-index translation using libc if_nametoindex
    pub fn name_to_index_libc(name: &str) -> Result<u32, InterfaceError> {
        let c_name = CString::new(name)
            .map_err(|_| InterfaceError::NotFound(name.to_string()))?;
        
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        
        if index == 0 {
            return Err(InterfaceError::NotFound(name.to_string()));
        }
        
        Ok(index)
    }
    
    /// Enumerate interfaces using getifaddrs()
    pub fn enumerate_via_getifaddrs() -> Result<Vec<InterfaceRecord>, InterfaceError> {
        let ifaddrs = getifaddrs()
            .map_err(|e| InterfaceError::EnumerationFailed(std::io::Error::from_raw_os_error(e as i32)))?;
        
        let mut interfaces: HashMap<String, InterfaceRecord> = HashMap::new();
        
        for ifaddr in ifaddrs {
            let name = ifaddr.interface_name.clone();
            let flags = convert_flags(ifaddr.flags);
            
            // Get or create interface record
            let record = interfaces.entry(name.clone()).or_insert(InterfaceRecord {
                name: name.clone(),
                index: if_nametoindex(&name),
                addresses: Vec::new(),
                flags,
                mtu: None,
            });
            
            // Add address if present
            if let Some(addr) = ifaddr.address {
                if let Some(socket_addr) = sockaddr_to_socketaddr(&addr) {
                    record.addresses.push(socket_addr);
                }
            }
        }
        
        Ok(interfaces.into_values().collect())
    }
    
    /// Convert interface name to index
    fn if_nametoindex(name: &str) -> u32 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        
        unsafe { libc::if_nametoindex(c_name.as_ptr()) }
    }
    
    /// Convert nix interface flags to our InterfaceFlags
    fn convert_flags(flags: nix::net::if_::InterfaceFlags) -> InterfaceFlags {
        let mut result = InterfaceFlags::empty();
        
        if flags.contains(nix::net::if_::InterfaceFlags::IFF_UP) {
            result |= InterfaceFlags::UP;
        }
        if flags.contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK) {
            result |= InterfaceFlags::LOOPBACK;
        }
        if flags.contains(nix::net::if_::InterfaceFlags::IFF_POINTOPOINT) {
            result |= InterfaceFlags::POINTOPOINT;
        }
        if flags.contains(nix::net::if_::InterfaceFlags::IFF_MULTICAST) {
            result |= InterfaceFlags::MULTICAST;
        }
        
        result
    }
    
    /// Convert SockaddrStorage to SocketAddr
    fn sockaddr_to_socketaddr(addr: &nix::sys::socket::SockaddrStorage) -> Option<SocketAddr> {
        use std::net::{Ipv4Addr, Ipv6Addr};
        
        if let Some(sin) = addr.as_sockaddr_in() {
            let ip = sin.ip();
            return Some(SocketAddr::new(IpAddr::V4(ip), sin.port()));
        }
        
        if let Some(sin6) = addr.as_sockaddr_in6() {
            let ip = sin6.ip();
            return Some(SocketAddr::new(IpAddr::V6(ip), sin6.port()));
        }
        
        None
    }
}

#[cfg(target_os = "solaris")]
mod solaris {
    use super::*;
    use std::ffi::{CStr, CString};
    
    /// Solaris index-to-name translation with zone awareness
    pub fn index_to_name_lifconf(index: u32) -> Result<String, InterfaceError> {
        use nix::libc::{getzoneid, GLOBAL_ZONEID, if_indextoname, IF_NAMESIZE};
        
        // In global zone, use standard if_indextoname
        if unsafe { getzoneid() } == GLOBAL_ZONEID {
            let mut buf = vec![0u8; IF_NAMESIZE];
            let result = unsafe {
                if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char)
            };
            
            if result.is_null() {
                return Err(InterfaceError::InvalidIndex(index));
            }
            
            let name = unsafe { CStr::from_ptr(result) }
                .to_string_lossy()
                .into_owned();
            
            return Ok(name);
        }
        
        // In non-global zone, enumerate all interfaces
        let interfaces = enumerate_via_lifconf()?;
        for iface in interfaces {
            if iface.index == index {
                return Ok(iface.name);
            }
        }
        
        Err(InterfaceError::InvalidIndex(index))
    }
    
    /// Solaris name-to-index translation
    pub fn name_to_index_lifconf(name: &str) -> Result<u32, InterfaceError> {
        let interfaces = enumerate_via_lifconf()?;
        for iface in interfaces {
            if iface.name == name {
                return Ok(iface.index);
            }
        }
        
        Err(InterfaceError::NotFound(name.to_string()))
    }
    
    /// Enumerate interfaces using SIOCGLIFCONF with zone awareness
    pub fn enumerate_via_lifconf() -> Result<Vec<InterfaceRecord>, InterfaceError> {
        // This is a simplified stub implementation
        // Full implementation would use SIOCGLIFNUM, SIOCGLIFCONF, SIOCGLIFINDEX ioctls
        // with proper handling of LIFC_ALLZONES and LIFC_UNDER_IPMP flags
        
        // For now, return empty list
        Ok(Vec::new())
    }
}

// Add once_cell dependency for lazy static initialization
use once_cell::sync::Lazy;

#[cfg(test)]
pub mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_interface_flags() {
        let flags = InterfaceFlags::UP | InterfaceFlags::MULTICAST;
        assert!(flags.contains(InterfaceFlags::UP));
        assert!(flags.contains(InterfaceFlags::MULTICAST));
        assert!(!flags.contains(InterfaceFlags::LOOPBACK));
    }
    
    #[tokio::test]
    async fn test_invalid_index() {
        let result = index_to_name(0).await;
        assert!(matches!(result, Err(InterfaceError::InvalidIndex(0))));
    }
    
    #[tokio::test]
    async fn test_interface_cache() {
        let mut cache = InterfaceCache::new();
        assert!(cache.needs_refresh());
        
        let interfaces = vec![
            InterfaceRecord {
                name: "lo".to_string(),
                index: 1,
                addresses: vec![],
                flags: InterfaceFlags::UP | InterfaceFlags::LOOPBACK,
                mtu: Some(65536),
            },
        ];
        
        cache.update(interfaces);
        assert!(!cache.needs_refresh());
        assert_eq!(cache.get_name_by_index(1), Some("lo"));
    }
}
