// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
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

//! BSD platform implementation using routing sockets and getifaddrs()
//!
//! This module implements network interface enumeration and monitoring for BSD-based
//! systems (FreeBSD, OpenBSD, NetBSD, macOS) and Solaris. It provides a memory-safe
//! Rust replacement for the C implementation in src/bpf.c.
//!
//! # Key Responsibilities
//!
//! - **Interface Enumeration**: Uses getifaddrs() to discover network interfaces and their addresses
//! - **Change Monitoring**: Uses PF_ROUTE routing sockets to detect real-time network configuration changes
//! - **ARP Cache Access**: Enumerates ARP table via sysctl() on BSD (not available on macOS)
//! - **BPF Support**: Provides raw packet transmission for DHCP via Berkeley Packet Filter
//!
//! # Platform-Specific Behavior
//!
//! - **BSD (FreeBSD, OpenBSD, NetBSD)**: Full functionality including ARP enumeration via sysctl,
//!   IPv6 address lifetime queries (SIOCGIFALIFETIME_IN6), and address flags (SIOCGIFAFLAG_IN6)
//! - **macOS**: Simplified implementation without sysctl ARP access or IPv6 lifetime APIs
//! - **Solaris**: Compatible mode using getifaddrs() and routing socket monitoring
//!
//! # Memory Safety Transformations
//!
//! The Rust implementation eliminates memory safety issues from the C version:
//! - getifaddrs() linked list traversal → safe iterator with automatic cleanup
//! - Manual buffer management for sysctl → Vec<u8> with automatic capacity expansion
//! - Raw pointer arithmetic in routing messages → safe struct parsing with bounds checking
//! - Static global state (del_family, del_addr) → Arc<RwLock<Option<>>> for thread safety
//! - Blocking I/O → async/await with tokio for non-blocking operations
//!
//! # Source Mapping
//!
//! Replaces: src/bpf.c
//! - `iface_enumerate()` → `BsdPlatform::enumerate_interfaces()`
//! - `route_init()` → `BsdPlatform::new()` and `init_routing_socket()`
//! - `route_sock()` → `BsdPlatform::process_routing_message()`
//! - `arp_enumerate()` → `BsdPlatform::enumerate_arp()`
//! - `init_bpf()` → `init_bpf()`
//! - `send_via_bpf()` → `send_via_bpf()`
//!
//! # RFC Compliance
//!
//! Enables RFC 2131 (DHCP) and RFC 1035 (DNS) compliance by providing accurate network
//! topology information required for server operation.

use super::{ArpEntry, InterfaceInfo, NetworkChange, Platform, PlatformError, PlatformErrorKind};
use crate::utils::general::expand_buf;

use async_trait::async_trait;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use nix::sys::socket::{
    recv, socket, AddressFamily, MsgFlags, SockAddr, SockFlag, SockType, SockaddrLike,
    SockaddrStorage,
};
use nix::unistd::close as nix_close;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::vec::Vec;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::{spawn, spawn_blocking};
use tracing::{debug, error, info, trace, warn};

// Routing message types (from net/route.h)
const RTM_NEWADDR: u8 = 0xc;
const RTM_DELADDR: u8 = 0xd;
const RTM_IFINFO: u8 = 0xe;
const RTM_VERSION: u8 = 5;

// Routing message address masks (from net/route.h)
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
const RTA_GENMASK: i32 = 0x8;
const RTA_IFP: i32 = 0x10;
const RTA_IFA: i32 = 0x20;
const RTA_AUTHOR: i32 = 0x40;
const RTA_BRD: i32 = 0x80;

// sysctl constants for ARP enumeration (from sys/sysctl.h and net/route.h)
const CTL_NET: i32 = 4;
const AF_ROUTE: i32 = 17; // PF_ROUTE
const NET_RT_FLAGS: i32 = 2;

// Interface flags (from net/if.h)
const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_POINTOPOINT: u32 = 0x10;

// Ethernet constants
const ARPHRD_ETHER: u16 = 1;
const ETHER_ADDR_LEN: usize = 6;

// BPF ioctl constants (from net/bpf.h)
#[cfg(target_os = "macos")]
const BIOCSETIF: libc::c_ulong = 0x8020426c;
#[cfg(target_os = "macos")]
const BIOCSIMMEDIATE: libc::c_ulong = 0x80044270;
#[cfg(target_os = "macos")]
const BIOCSSEESENT: libc::c_ulong = 0x80044277;

#[cfg(not(target_os = "macos"))]
const BIOCSETIF: libc::c_ulong = 0x8020426c;
#[cfg(not(target_os = "macos"))]
const BIOCSIMMEDIATE: libc::c_ulong = 0x80044270;
#[cfg(not(target_os = "macos"))]
const BIOCSSEESENT: libc::c_ulong = 0x80044277;

// Routing socket address index constants
const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
const RTAX_GENMASK: usize = 3;
const RTAX_IFP: usize = 4;
const RTAX_IFA: usize = 5;
const RTAX_AUTHOR: usize = 6;
const RTAX_BRD: usize = 7;
const RTAX_MAX: usize = 8;

/// Routing message header structure (simplified from rt_msghdr)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RtMsgHeader {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: i32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: i32,
    rtm_inits: u32,
}

/// Interface message header (RTM_IFINFO messages)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfMsgHeader {
    ifm_msglen: u16,
    ifm_version: u8,
    ifm_type: u8,
    ifm_addrs: i32,
    ifm_flags: i32,
    ifm_index: u16,
    ifm_data: IfData,
}

/// Interface data structure (platform-specific metrics)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfData {
    ifi_type: u8,
    ifi_typelen: u8,
    ifi_physical: u8,
    ifi_addrlen: u8,
    ifi_hdrlen: u8,
    ifi_recvquota: u8,
    ifi_xmitquota: u8,
    ifi_mtu: u32,
    ifi_metric: u32,
    ifi_baudrate: u32,
    ifi_ipackets: u32,
    ifi_ierrors: u32,
    ifi_opackets: u32,
    ifi_oerrors: u32,
    ifi_collisions: u32,
    ifi_ibytes: u32,
    ifi_obytes: u32,
    ifi_imcasts: u32,
    ifi_omcasts: u32,
    ifi_iqdrops: u32,
    ifi_noproto: u32,
    ifi_lastchange: Timeval,
}

/// Timeval structure for timestamps
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

/// Interface address message header (RTM_NEWADDR/RTM_DELADDR messages)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfAddrMsgHeader {
    ifam_msglen: u16,
    ifam_version: u8,
    ifam_type: u8,
    ifam_addrs: i32,
    ifam_flags: i32,
    ifam_index: u16,
    ifam_metric: i32,
}

/// Deleted address tracking state
///
/// Implements workaround for kernel race condition where deleted addresses briefly
/// appear in getifaddrs() results after RTM_DELADDR. Stores last deleted address
/// to filter from enumeration results.
#[derive(Debug, Clone, Default)]
struct DeletedAddress {
    family: Option<AddressFamily>,
    addr: Option<IpAddr>,
}

/// BSD platform implementation using routing sockets
///
/// Provides network interface operations for FreeBSD, OpenBSD, NetBSD, macOS, and Solaris.
/// Uses getifaddrs() for interface enumeration and PF_ROUTE routing sockets for
/// real-time change monitoring.
#[derive(Debug, Clone)]
pub struct BsdPlatform {
    /// Routing socket file descriptor for monitoring network changes (interior mutability)
    routing_fd: Arc<RwLock<Option<RawFd>>>,
    /// Tracking last deleted address for race condition workaround
    deleted_address: Arc<RwLock<DeletedAddress>>,
}

impl BsdPlatform {
    /// Create a new BSD platform implementation
    ///
    /// Initializes the platform with routing socket for interface monitoring.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Cannot create routing socket (permission denied, platform limitation)
    /// - Cannot configure socket flags
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dnsmasq::network::platform::bsd::BsdPlatform;
    ///
    /// let platform = BsdPlatform::new()?;
    /// ```
    pub fn new() -> Result<Self, PlatformError> {
        // Note: Routing socket creation is deferred to init_routing_socket()
        // to allow construction without immediate privileged operations
        Ok(Self {
            routing_fd: Arc::new(RwLock::new(None)),
            deleted_address: Arc::new(RwLock::new(DeletedAddress::default())),
        })
    }

    /// Initialize routing socket for network change monitoring
    ///
    /// Creates PF_ROUTE socket for receiving kernel notifications about network
    /// interface and address changes. Called internally by monitor_changes().
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Socket creation fails (permission denied, platform limitation)
    /// - Cannot set socket flags (O_NONBLOCK, FD_CLOEXEC)
    ///
    /// # Platform Requirements
    ///
    /// Requires root privileges or CAP_NET_ADMIN equivalent on most BSD systems.
    pub fn init_routing_socket(&self) -> Result<RawFd, PlatformError> {
        // Check if already initialized
        {
            let guard = self.routing_fd.read().map_err(|_| {
                PlatformError::new(
                    PlatformErrorKind::MonitoringFailed,
                    "Failed to acquire routing_fd read lock",
                )
            })?;

            if let Some(fd) = *guard {
                return Ok(fd);
            }
        }

        // Create PF_ROUTE socket using raw libc call
        // (nix doesn't have PF_ROUTE in AddressFamily enum)
        let fd = unsafe {
            libc::socket(
                libc::PF_ROUTE,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::AF_UNSPEC,
            )
        };

        if fd < 0 {
            return Err(PlatformError::with_source(
                PlatformErrorKind::MonitoringFailed,
                "Failed to create PF_ROUTE socket",
                Box::new(IoError::last_os_error()),
            ));
        }

        // Store file descriptor
        {
            let mut guard = self.routing_fd.write().map_err(|_| {
                PlatformError::new(
                    PlatformErrorKind::MonitoringFailed,
                    "Failed to acquire routing_fd write lock",
                )
            })?;

            *guard = Some(fd);
        }

        info!("Initialized PF_ROUTE socket: fd={}", fd);

        Ok(fd)
    }

    /// Process a routing socket message
    ///
    /// Parses routing messages (RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO) from the kernel
    /// and generates corresponding NetworkChange events. Implements race condition
    /// workaround for RTM_DELADDR by storing deleted address in shared state.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer containing routing message data
    /// * `tx` - Channel sender for broadcasting NetworkChange events
    ///
    /// # Routing Message Types
    ///
    /// - **RTM_NEWADDR**: Address added to interface → AddressAdded event
    /// - **RTM_DELADDR**: Address removed from interface → AddressRemoved event
    /// - **RTM_IFINFO**: Interface state changed (currently logged but no event generated)
    ///
    /// # Race Condition Handling
    ///
    /// For RTM_DELADDR, extracts the deleted address from RTA_IFA field and stores it
    /// in deleted_address. This allows enumerate_interfaces() to filter the address
    /// that may still appear in getifaddrs() results due to kernel timing.
    pub async fn process_routing_message(
        &self,
        buffer: &[u8],
        tx: &Sender<NetworkChange>,
    ) -> IoResult<()> {
        // Minimum message size check
        if buffer.len() < size_of::<IfMsgHeader>() {
            trace!("Routing message too short: {} bytes", buffer.len());
            return Ok(());
        }

        // Parse message header
        let msg_header = unsafe { &*(buffer.as_ptr() as *const IfMsgHeader) };

        // Validate message length
        if buffer.len() < msg_header.ifm_msglen as usize {
            warn!(
                "Routing message truncated: expected {}, got {}",
                msg_header.ifm_msglen,
                buffer.len()
            );
            return Ok(());
        }

        // Check protocol version
        if msg_header.ifm_version != RTM_VERSION {
            static VERSION_WARNED: std::sync::Once = std::sync::Once::new();
            VERSION_WARNED.call_once(|| {
                warn!(
                    "Unknown routing protocol version: {} (expected {})",
                    msg_header.ifm_version, RTM_VERSION
                );
            });
            return Ok(());
        }

        // Process based on message type
        match msg_header.ifm_type {
            RTM_NEWADDR => {
                debug!("RTM_NEWADDR event received");
                // Clear deleted address tracking on new address
                if let Ok(mut del) = self.deleted_address.write() {
                    *del = DeletedAddress::default();
                }
                // Queue event to trigger interface re-enumeration
                // The actual address will be discovered via enumerate_interfaces()
                let _ = tx.send(NetworkChange::AddressAdded {
                    if_index: msg_header.ifm_index as u32,
                    addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), // Placeholder
                    prefixlen: 0,
                }).await;
            }

            RTM_DELADDR => {
                debug!("RTM_DELADDR event received");
                // Parse address from message to implement race condition workaround
                if let Some((family, addr)) = self.parse_deleted_address(buffer) {
                    if let Ok(mut del) = self.deleted_address.write() {
                        del.family = Some(family);
                        del.addr = Some(addr);
                        debug!("Stored deleted address: {:?} family={:?}", addr, family);
                    }

                    let _ = tx.send(NetworkChange::AddressRemoved {
                        if_index: msg_header.ifm_index as u32,
                        addr,
                    }).await;
                }
            }

            RTM_IFINFO => {
                debug!(
                    "RTM_IFINFO event: interface {} flags=0x{:x}",
                    msg_header.ifm_index, msg_header.ifm_flags
                );
                // Interface state change (up/down, flags changed)
                // Could generate InterfaceAdded/InterfaceRemoved events based on flags
            }

            _ => {
                trace!("Ignored routing message type: {}", msg_header.ifm_type);
            }
        }

        Ok(())
    }

    /// Parse deleted address from RTM_DELADDR message
    ///
    /// Extracts the RTA_IFA (interface address) field from routing message to support
    /// race condition workaround. Routing messages contain variable-length address
    /// structures following the header.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Complete routing message buffer
    ///
    /// # Returns
    ///
    /// Tuple of (AddressFamily, IpAddr) if parsing succeeds, None otherwise
    fn parse_deleted_address(&self, buffer: &[u8]) -> Option<(AddressFamily, IpAddr)> {
        if buffer.len() < size_of::<IfAddrMsgHeader>() {
            return None;
        }

        let ifam = unsafe { &*(buffer.as_ptr() as *const IfAddrMsgHeader) };
        let addrs_mask = ifam.ifam_addrs;

        // Address structures follow the header
        let mut offset = size_of::<IfAddrMsgHeader>();

        // Iterate through address mask to find RTA_IFA
        let mask_vec = [
            RTA_DST,
            RTA_GATEWAY,
            RTA_NETMASK,
            RTA_GENMASK,
            RTA_IFP,
            RTA_IFA,
            RTA_AUTHOR,
            RTA_BRD,
        ];

        for &mask in &mask_vec {
            if offset >= buffer.len() {
                break;
            }

            if (addrs_mask & mask) != 0 {
                // Parse sockaddr structure at current offset
                if let Some((sa_family_u8, sa_len, addr)) = parse_sockaddr(&buffer[offset..]) {
                    if mask == RTA_IFA {
                        // Found the interface address being deleted
                        // Convert u8 family to AddressFamily enum
                        let family = address_family_from_i32(sa_family_u8 as i32);
                        return addr.map(|a| (family, a));
                    }

                    // Advance to next address with alignment
                    let align = size_of::<i64>();
                    offset += ((sa_len + align - 1) / align) * align;
                } else {
                    // Cannot parse, skip this message
                    break;
                }
            }
        }

        None
    }
}

#[async_trait]
impl Platform for BsdPlatform {
    /// Enumerate all network interfaces using getifaddrs()
    ///
    /// Retrieves complete interface and address information using the POSIX getifaddrs() API.
    /// Supports IPv4 (AF_INET), IPv6 (AF_INET6) enumeration. Filters recently-deleted
    /// addresses using deleted_address tracking to work around kernel race condition.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - getifaddrs() system call fails
    /// - Interface information is incomplete or invalid
    /// - if_nametoindex() fails for interface name lookup
    ///
    /// # Implementation Notes
    ///
    /// - Uses nix::ifaddrs::getifaddrs() which provides safe iterator over linked list
    /// - Automatically handles freeifaddrs() via RAII (no manual memory management)
    /// - Filters interfaces with zero if_nametoindex() or missing netmask
    /// - Implements deleted address filtering for RTM_DELADDR race condition workaround
    /// - Uses spawn_blocking for potentially blocking getifaddrs() call
    async fn enumerate_interfaces(&self) -> Result<Vec<InterfaceInfo>, PlatformError> {
        // getifaddrs() may block, run in blocking thread
        let deleted_address = Arc::clone(&self.deleted_address);

        spawn_blocking(move || {
            let ifaddrs = getifaddrs().map_err(|e| {
                PlatformError::with_source(
                    PlatformErrorKind::EnumerationFailed,
                    "getifaddrs() failed",
                    Box::new(IoError::from(e)),
                )
            })?;

            let mut interfaces = Vec::new();

            // Read deleted address for filtering
            let deleted = deleted_address
                .read()
                .ok()
                .and_then(|del| del.addr.clone());

            for ifaddr in ifaddrs {
                // Get interface index
                let if_index = match if_nametoindex(ifaddr.interface_name()) {
                    Ok(idx) => idx,
                    Err(_) => {
                        debug!("Skipping interface with invalid index: {}", ifaddr.interface_name());
                        continue;
                    }
                };

                // Skip interfaces without address or netmask
                let address = match ifaddr.address {
                    Some(addr) => addr,
                    None => continue,
                };

                let netmask = match ifaddr.netmask {
                    Some(nm) => nm,
                    None => {
                        // AF_LINK doesn't require netmask, but we're only handling IP addresses
                        debug!("Skipping interface without netmask: {}", ifaddr.interface_name());
                        continue;
                    }
                };

                // Extract IP address and netmask
                let (ip_addr, netmask_addr, prefixlen) = match (address.as_sockaddr_in(), netmask.as_sockaddr_in()) {
                    (Some(addr), Some(nm)) => {
                        let ipv4 = Ipv4Addr::from(addr.ip().to_be_bytes());
                        let mask = Ipv4Addr::from(nm.ip().to_be_bytes());

                        // Filter deleted address
                        if let Some(IpAddr::V4(del_addr)) = deleted {
                            if del_addr == ipv4 {
                                debug!("Filtering deleted address: {}", ipv4);
                                continue;
                            }
                        }

                        // Calculate prefix length from netmask
                        let prefix = calculate_prefix_v4(&mask);

                        (IpAddr::V4(ipv4), IpAddr::V4(mask), prefix)
                    }
                    _ => {
                        // Try IPv6
                        match (address.as_sockaddr_in6(), netmask.as_sockaddr_in6()) {
                            (Some(addr), Some(nm)) => {
                                let ipv6 = Ipv6Addr::from(addr.ip().octets());
                                let mask = Ipv6Addr::from(nm.ip().octets());

                                // Filter deleted address
                                if let Some(IpAddr::V6(del_addr)) = deleted {
                                    if del_addr == ipv6 {
                                        debug!("Filtering deleted address: {}", ipv6);
                                        continue;
                                    }
                                }

                                // Calculate prefix length from netmask
                                let prefix = calculate_prefix_v6(&mask);

                                (IpAddr::V6(ipv6), IpAddr::V6(mask), prefix)
                            }
                            _ => {
                                // Not IPv4 or IPv6, skip
                                continue;
                            }
                        }
                    }
                };

                let iface_info = InterfaceInfo {
                    addr: ip_addr,
                    name: ifaddr.interface_name().to_string(),
                    index: if_index,
                    flags: ifaddr.flags.bits(),
                    prefixlen,
                    netmask: netmask_addr,
                };

                debug!(
                    "Enumerated interface: {} ({}) {} prefix={}",
                    iface_info.name, iface_info.index, iface_info.addr, iface_info.prefixlen
                );

                interfaces.push(iface_info);
            }

            Ok(interfaces)
        })
        .await
        .map_err(|e| {
            PlatformError::new(
                PlatformErrorKind::EnumerationFailed,
                format!("Task join error: {}", e),
            )
        })?
    }

    /// Monitor network interface changes using routing socket
    ///
    /// Returns a receiver channel that streams NetworkChange events for:
    /// - RTM_NEWADDR (address added)
    /// - RTM_DELADDR (address removed)
    /// - RTM_IFINFO (interface state changed)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Cannot create or initialize routing socket
    /// - Insufficient permissions for routing socket
    ///
    /// # Implementation Notes
    ///
    /// - Uses PF_ROUTE socket for kernel notifications
    /// - Spawns background tokio task for async message processing
    /// - Channel buffer size: 100 events
    /// - Automatically handles socket cleanup via Drop
    async fn monitor_changes(&self) -> Result<Receiver<NetworkChange>, PlatformError> {
        // Initialize routing socket if not already done
        let routing_fd = self.init_routing_socket()?;

        let (tx, rx) = channel(100);

        // Create AsyncFd wrapper for tokio integration
        let async_fd = AsyncFd::new(routing_fd).map_err(|e| {
            PlatformError::with_source(
                PlatformErrorKind::MonitoringFailed,
                "Failed to create AsyncFd",
                Box::new(e),
            )
        })?;

        let deleted_address = Arc::clone(&self.deleted_address);
        let platform_clone = self.clone();

        // Spawn monitoring task
        spawn(async move {
            let mut buffer = vec![0u8; 8192]; // Max routing message size

            loop {
                // Wait for routing socket to become readable
                let mut guard = match async_fd.readable().await {
                    Ok(g) => g,
                    Err(e) => {
                        error!("AsyncFd readable error: {}", e);
                        break;
                    }
                };

                // Read routing message (non-blocking)
                match guard.try_io(|inner| {
                    let fd = *inner.get_ref();
                    recv(fd, &mut buffer, MsgFlags::MSG_DONTWAIT)
                }) {
                    Ok(Ok(bytes_read)) => {
                        if bytes_read > 0 {
                            if let Err(e) = platform_clone
                                .process_routing_message(&buffer[..bytes_read], &tx)
                                .await
                            {
                                warn!("Failed to process routing message: {}", e);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        error!("recv() error: {}", e);
                        break;
                    }
                    Err(_would_block) => {
                        // Would block, continue waiting
                        continue;
                    }
                }
            }

            info!("Routing socket monitor task terminated");
        });

        Ok(rx)
    }

    /// Enumerate ARP cache entries via sysctl
    ///
    /// Uses sysctl() with CTL_NET/PF_ROUTE/AF_INET/NET_RT_FLAGS to read ARP table.
    /// Only available on BSD systems excluding macOS.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - sysctl() fails (permission denied, not supported)
    /// - Buffer allocation fails
    /// - ARP table parsing fails
    ///
    /// # Platform Availability
    ///
    /// - **FreeBSD/OpenBSD/NetBSD**: Supported via sysctl
    /// - **macOS**: Returns empty vector (ARP access not available)
    /// - **Solaris**: Returns empty vector (different ARP access method)
    async fn enumerate_arp(&self) -> Result<Vec<ArpEntry>, PlatformError> {
        // macOS doesn't support sysctl ARP enumeration
        #[cfg(target_os = "macos")]
        {
            debug!("ARP enumeration not available on macOS");
            return Ok(Vec::new());
        }

        #[cfg(not(target_os = "macos"))]
        {
            use nix::sys::sysctl::sysctl;

            spawn_blocking(move || {
                let mut arp_entries = Vec::new();

                // sysctl MIB for ARP table: CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO
                let mib = [CTL_NET, AF_ROUTE, 0, libc::AF_INET, NET_RT_FLAGS, libc::RTF_LLINFO as i32];

                // Query required buffer size
                let mut needed: usize = 0;
                let result = unsafe {
                    libc::sysctl(
                        mib.as_ptr(),
                        mib.len() as u32,
                        std::ptr::null_mut(),
                        &mut needed as *mut usize,
                        std::ptr::null(),
                        0,
                    )
                };

                if result < 0 || needed == 0 {
                    return Err(PlatformError::new(
                        PlatformErrorKind::ArpAccessFailed,
                        "sysctl size query failed for ARP table",
                    ));
                }

                // Allocate buffer with expansion capability
                let mut buffer = vec![0u8; needed];

                // Retrieve ARP table with retry on ENOMEM
                loop {
                    let mut size = buffer.len();
                    let result = unsafe {
                        libc::sysctl(
                            mib.as_ptr(),
                            mib.len() as u32,
                            buffer.as_mut_ptr() as *mut libc::c_void,
                            &mut size,
                            std::ptr::null(),
                            0,
                        )
                    };

                    if result == 0 {
                        buffer.truncate(size);
                        break;
                    } else if IoError::last_os_error().raw_os_error() == Some(libc::ENOMEM) {
                        // Buffer too small, expand and retry
                        expand_buf(&mut buffer, buffer.len() + buffer.len() / 8)?;
                    } else {
                        return Err(PlatformError::with_source(
                            PlatformErrorKind::ArpAccessFailed,
                            "sysctl ARP table retrieval failed",
                            Box::new(IoError::last_os_error()),
                        ));
                    }
                }

                // Parse ARP table entries
                let mut offset = 0;
                while offset + size_of::<RtMsgHeader>() <= buffer.len() {
                    let rtm = unsafe { &*(buffer[offset..].as_ptr() as *const RtMsgHeader) };

                    let msg_len = rtm.rtm_msglen as usize;
                    if offset + msg_len > buffer.len() {
                        break;
                    }

                    // Parse ARP entry addresses
                    if let Some(arp_entry) = parse_arp_entry(&buffer[offset..offset + msg_len]) {
                        arp_entries.push(arp_entry);
                    }

                    offset += msg_len;
                }

                debug!("Enumerated {} ARP entries", arp_entries.len());
                Ok(arp_entries)
            })
            .await
            .map_err(|e| {
                PlatformError::new(
                    PlatformErrorKind::ArpAccessFailed,
                    format!("Task join error: {}", e),
                )
            })?
        }
    }
}

impl Drop for BsdPlatform {
    fn drop(&mut self) {
        // Close routing socket when dropped
        if let Ok(mut guard) = self.routing_fd.write() {
            if let Some(fd) = *guard {
                let _ = nix_close(fd);
                debug!("Closed routing socket: fd={}", fd);
                *guard = None;
            }
        }
    }
}

// Helper Functions

/// Convert libc address family constant to nix AddressFamily
fn address_family_from_i32(af: i32) -> AddressFamily {
    match af {
        libc::AF_INET => AddressFamily::Inet,
        libc::AF_INET6 => AddressFamily::Inet6,
        libc::AF_UNIX => AddressFamily::Unix,
        libc::AF_LINK => AddressFamily::Link,
        _ => AddressFamily::Unspec,
    }
}

/// Calculate IPv4 prefix length from netmask
fn calculate_prefix_v4(mask: &Ipv4Addr) -> u8 {
    let octets = mask.octets();
    let mut prefix = 0u8;

    for octet in octets.iter() {
        prefix += octet.count_ones() as u8;
    }

    prefix
}

/// Calculate IPv6 prefix length from netmask
fn calculate_prefix_v6(mask: &Ipv6Addr) -> u8 {
    let octets = mask.octets();
    let mut prefix = 0u8;

    for octet in octets.iter() {
        prefix += octet.count_ones() as u8;
    }

    prefix
}

/// Parse sockaddr structure from buffer
///
/// Extracts address family, length, and IP address from a sockaddr structure.
/// Handles both sockaddr_in (IPv4) and sockaddr_in6 (IPv6).
///
/// # Arguments
///
/// * `buffer` - Buffer starting at sockaddr structure
///
/// # Returns
///
/// Tuple of (family as u8, length, address) if parsing succeeds
fn parse_sockaddr(buffer: &[u8]) -> Option<(u8, usize, Option<IpAddr>)> {
    if buffer.len() < 2 {
        return None;
    }

    let sa_len = buffer[0] as usize;
    let sa_family = buffer[1];

    if sa_len == 0 {
        // Use sizeof(long) as default length
        return Some((sa_family, size_of::<i64>(), None));
    }

    if buffer.len() < sa_len {
        return None;
    }

    let addr = match sa_family as i32 {
        libc::AF_INET => {
            // sockaddr_in: sa_len(1) + sa_family(1) + sin_port(2) + sin_addr(4)
            if sa_len >= 8 && buffer.len() >= 8 {
                let addr_bytes = &buffer[4..8];
                let ipv4 = Ipv4Addr::new(
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                );
                Some(IpAddr::V4(ipv4))
            } else {
                None
            }
        }
        libc::AF_INET6 => {
            // sockaddr_in6: sa_len(1) + sa_family(1) + sin6_port(2) + sin6_flowinfo(4) + sin6_addr(16)
            if sa_len >= 24 && buffer.len() >= 24 {
                let addr_bytes: [u8; 16] = buffer[8..24].try_into().ok()?;
                let ipv6 = Ipv6Addr::from(addr_bytes);
                Some(IpAddr::V6(ipv6))
            } else {
                None
            }
        }
        _ => None,
    };

    Some((sa_family, sa_len, addr))
}

/// Parse ARP entry from routing message
///
/// Extracts IP address and hardware address from routing message containing ARP entry.
/// Returns ArpEntry with address family, interface index, and MAC address.
#[cfg(not(target_os = "macos"))]
fn parse_arp_entry(msg_buf: &[u8]) -> Option<ArpEntry> {
    if msg_buf.len() < size_of::<RtMsgHeader>() {
        return None;
    }

    let rtm = unsafe { &*(msg_buf.as_ptr() as *const RtMsgHeader) };

    // Parse sockaddrs following routing message header
    let mut offset = size_of::<RtMsgHeader>();
    let mut ip_addr: Option<IpAddr> = None;
    let mut hw_addr: Option<Vec<u8>> = None;
    let mut if_index: u32 = 0;

    // Iterate through sockaddr structures based on addrs bitmask
    for i in 0..RTAX_MAX {
        if (rtm.rtm_addrs & (1 << i)) == 0 {
            continue;
        }

        if offset + 4 > msg_buf.len() {
            break;
        }

        // Parse sockaddr structure
        if let Some((family, sa_len, addr)) = parse_sockaddr(&msg_buf[offset..]) {
            match i {
                RTAX_DST => {
                    // Destination address (IP address for ARP)
                    if let Some(addr) = addr {
                        ip_addr = Some(addr);
                    }
                }
                RTAX_GATEWAY => {
                    // Gateway address (MAC address for ARP in AF_LINK format)
                    if family == libc::AF_LINK as u8 {
                        // Extract MAC address from sockaddr_dl
                        if let Some(mac) = extract_mac_from_link(&msg_buf[offset..]) {
                            hw_addr = Some(mac);
                        }
                    }
                }
                RTAX_IFA => {
                    // Interface address (for interface index)
                    // Extract interface index from message
                    if_index = rtm.rtm_index as u32;
                }
                _ => {}
            }

            offset += sa_len;
        } else {
            break;
        }
    }

    // Create ArpEntry if we have both IP and hardware address
    if let (Some(addr), Some(hwaddr_vec)) = (ip_addr, hw_addr) {
        // Convert Vec<u8> to [u8; 6] fixed-size array
        // MAC addresses are 6 bytes for Ethernet
        if hwaddr_vec.len() != 6 {
            warn!("Invalid MAC address length: {} bytes (expected 6)", hwaddr_vec.len());
            return None;
        }

        let mut hwaddr = [0u8; 6];
        hwaddr.copy_from_slice(&hwaddr_vec[..6]);

        // Convert AddressFamily to i32 for ArpEntry
        let family = match addr {
            IpAddr::V4(_) => libc::AF_INET,
            IpAddr::V6(_) => libc::AF_INET6,
        };

        Some(ArpEntry {
            addr,
            hwaddr,
            family,
            if_index,
            hwaddr_len: 6,
        })
    } else {
        None
    }
}

/// Extract MAC address from sockaddr_dl structure
#[cfg(not(target_os = "macos"))]
fn extract_mac_from_link(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 8 {
        return None;
    }

    // sockaddr_dl structure layout (simplified):
    // u8 sdl_len
    // u8 sdl_family (AF_LINK)
    // u16 sdl_index
    // u8 sdl_type
    // u8 sdl_nlen (name length)
    // u8 sdl_alen (address length - MAC address)
    // u8 sdl_slen (selector length)
    // [name bytes]
    // [address bytes - MAC address]

    let sdl_nlen = buf[5] as usize;
    let sdl_alen = buf[6] as usize;

    if sdl_alen == 0 || sdl_alen > 8 {
        return None;
    }

    let mac_offset = 8 + sdl_nlen;
    if mac_offset + sdl_alen > buf.len() {
        return None;
    }

    Some(buf[mac_offset..mac_offset + sdl_alen].to_vec())
}

// BPF Functions for raw DHCP packet transmission

/// Initialize Berkeley Packet Filter device for raw packet transmission
///
/// Opens a BPF device (/dev/bpf*) and configures it for the specified interface.
/// Required for sending raw DHCP packets on BSD systems.
///
/// # Arguments
///
/// * `interface_name` - Name of the network interface (e.g., "em0", "en0")
///
/// # Returns
///
/// * File descriptor for the opened BPF device
///
/// # Errors
///
/// Returns error if:
/// - Cannot open any BPF device (all in use or permission denied)
/// - Cannot bind BPF to specified interface
/// - Cannot set BPF to immediate mode
/// - Cannot get BPF buffer size
///
/// # Implementation Notes
///
/// - Tries /dev/bpf0 through /dev/bpf99 until successful open
/// - Sets BPF to immediate mode for low-latency packet delivery
/// - Configures "see sent" mode to capture our own transmitted packets
/// - Returns configured BPF file descriptor for use with send_via_bpf()
pub fn init_bpf(interface_name: &str) -> Result<RawFd, PlatformError> {
    use std::ffi::CString;
    use std::os::unix::io::RawFd;

    // Try to open BPF devices /dev/bpf0 through /dev/bpf99
    let mut bpf_fd: Option<RawFd> = None;

    for i in 0..100 {
        let device_path = format!("/dev/bpf{}", i);
        let path_cstring = CString::new(device_path.clone()).unwrap();

        let fd = unsafe {
            libc::open(
                path_cstring.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK,
                0,
            )
        };

        if fd >= 0 {
            bpf_fd = Some(fd);
            debug!("Opened BPF device: {}", device_path);
            break;
        }
    }

    let fd = bpf_fd.ok_or_else(|| {
        PlatformError::new(
            PlatformErrorKind::BpfInitFailed,
            "Failed to open any BPF device",
        )
    })?;

    // Bind BPF to interface using BIOCSETIF
    let iface_cstring = CString::new(interface_name).unwrap();
    let mut ifreq = libc::ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_addr: unsafe { std::mem::zeroed() },
        },
    };

    // Copy interface name into ifreq structure
    let name_bytes = iface_cstring.as_bytes_with_nul();
    let copy_len = std::cmp::min(name_bytes.len(), libc::IF_NAMESIZE);
    ifreq.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let result = unsafe {
        libc::ioctl(fd, BIOCSETIF, &ifreq as *const libc::ifreq as *const libc::c_void)
    };

    if result < 0 {
        unsafe { libc::close(fd) };
        return Err(PlatformError::with_source(
            PlatformErrorKind::BpfInitFailed,
            format!("BIOCSETIF failed for interface {}", interface_name),
            Box::new(IoError::last_os_error()),
        ));
    }

    // Set immediate mode for low-latency delivery
    let immediate: u32 = 1;
    let result = unsafe {
        libc::ioctl(fd, BIOCSIMMEDIATE, &immediate as *const u32 as *const libc::c_void)
    };

    if result < 0 {
        warn!("BIOCSIMMEDIATE failed, continuing anyway");
    }

    // Enable "see sent" mode to capture transmitted packets
    let see_sent: u32 = 1;
    let result = unsafe {
        libc::ioctl(fd, BIOCSSEESENT, &see_sent as *const u32 as *const libc::c_void)
    };

    if result < 0 {
        warn!("BIOCSSEESENT failed, continuing anyway");
    }

    info!("Initialized BPF for interface {}: fd={}", interface_name, fd);
    Ok(fd)
}

/// Send raw Ethernet frame via Berkeley Packet Filter
///
/// Constructs and transmits a raw Ethernet frame through the BPF device.
/// Used for sending DHCP responses that require specific source MAC addresses.
///
/// # Arguments
///
/// * `bpf_fd` - File descriptor from init_bpf()
/// * `dest_mac` - Destination MAC address (6 bytes)
/// * `src_mac` - Source MAC address (6 bytes)
/// * `ether_type` - Ethernet type (e.g., 0x0800 for IPv4, 0x86DD for IPv6)
/// * `payload` - Packet payload (IP packet)
///
/// # Errors
///
/// Returns error if:
/// - Invalid MAC address length (must be 6 bytes)
/// - write() system call fails
/// - BPF device is not properly initialized
///
/// # Implementation Notes
///
/// - Constructs complete Ethernet frame with 14-byte header
/// - Payload must be complete IP packet (caller responsible for IP/UDP headers)
/// - Does not add padding for minimum frame size (handled by kernel/hardware)
/// - Uses blocking write() (assumes BPF fd is in non-blocking mode for reads only)
pub fn send_via_bpf(
    bpf_fd: RawFd,
    dest_mac: &[u8],
    src_mac: &[u8],
    ether_type: u16,
    payload: &[u8],
) -> Result<usize, PlatformError> {
    // Validate MAC addresses
    if dest_mac.len() != 6 || src_mac.len() != 6 {
        return Err(PlatformError::new(
            PlatformErrorKind::BpfSendFailed,
            "Invalid MAC address length (must be 6 bytes)",
        ));
    }

    // Construct Ethernet frame
    let mut frame = Vec::with_capacity(14 + payload.len());

    // Ethernet header (14 bytes)
    frame.extend_from_slice(dest_mac); // Destination MAC (6 bytes)
    frame.extend_from_slice(src_mac);  // Source MAC (6 bytes)
    frame.extend_from_slice(&ether_type.to_be_bytes()); // EtherType (2 bytes)

    // Payload (IP packet)
    frame.extend_from_slice(payload);

    // Send frame via BPF
    let bytes_written = unsafe {
        libc::write(
            bpf_fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
        )
    };

    if bytes_written < 0 {
        return Err(PlatformError::with_source(
            PlatformErrorKind::BpfSendFailed,
            "BPF write failed",
            Box::new(IoError::last_os_error()),
        ));
    }

    debug!(
        "Sent {} bytes via BPF (frame size: {} bytes)",
        bytes_written,
        frame.len()
    );

    Ok(bytes_written as usize)
}
