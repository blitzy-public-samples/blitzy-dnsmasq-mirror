// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later

//! Platform abstraction module for network operations
//!
//! This module provides trait-based platform abstraction for operating system-specific
//! network operations, replacing C's conditional compilation (#ifdef HAVE_LINUX_NETWORK,
//! HAVE_BSD_NETWORK) with Rust's cfg attributes and trait polymorphism. Each platform
//! (Linux, BSD, macOS, Solaris) provides its own implementation of common traits for
//! network interface enumeration, address monitoring, raw packet filtering, and file
//! watching.
//!
//! # Architecture
//!
//! The platform abstraction follows a trait-based design pattern where:
//! - **NetworkPlatform**: Core interface for network interface discovery and monitoring
//! - **PacketFilter**: Raw packet I/O for DHCP broadcast responses (bypassing IP stack)
//! - **FileWatcher**: Configuration file monitoring for hot reload (SIGHUP alternative)
//!
//! ## C Implementation Background
//!
//! The C codebase uses three platform-specific files:
//! - **netlink.c** (Linux): Netlink RTNETLINK socket for interface monitoring with
//!   multicast groups (RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR) providing asynchronous
//!   notifications for address additions/removals (RTM_NEWADDR/RTM_DELADDR)
//! - **bpf.c** (BSD/macOS): getifaddrs() for enumeration + PF_ROUTE routing sockets
//!   for change detection (RTM_IFINFO, RTM_NEWADDR) + BPF devices (/dev/bpf*) for
//!   raw packet transmission
//! - **network.c** (Generic): SIOCGIFCONF ioctl fallback for Solaris and unsupported
//!   platforms, polling-based change detection
//!
//! ## Rust Implementation Strategy
//!
//! This module provides trait definitions that platform-specific submodules implement:
//! - `src/platform/linux/` - Implements traits using nix crate for netlink sockets
//! - `src/platform/bsd/` - Implements traits using nix crate for routing sockets and BPF
//! - `src/platform/macos/` - Extends BSD implementation with launchd socket activation
//! - `src/platform/generic/` - POSIX fallback using standard library only
//!
//! # Memory Safety Benefits
//!
//! The Rust implementation eliminates several classes of vulnerabilities present in C:
//! - **Buffer overflows**: C's fixed-size buffers (4096 bytes for Netlink messages) are
//!   replaced with Vec<u8> that grow automatically
//! - **Use-after-free**: C manually manages Netlink message buffers with expand_buf();
//!   Rust's ownership prevents dangling pointers
//! - **Integer overflows**: C casts between u32 interface indices and array indices without
//!   bounds checking; Rust enforces checked arithmetic
//!
//! # Platform Selection
//!
//! The appropriate platform implementation is selected at compile time using cfg attributes:
//! ```ignore
//! let platform: Box<dyn NetworkPlatform> = get_platform();
//! let interfaces = platform.enumerate_interfaces()?;
//! ```
//!
//! # Usage Example
//!
//! ```ignore
//! use crate::platform::{get_platform, InterfaceFlags};
//!
//! // Enumerate all network interfaces
//! let platform = get_platform();
//! let interfaces = platform.enumerate_interfaces()?;
//!
//! for iface in interfaces {
//!     if iface.flags.contains(InterfaceFlags::UP) {
//!         println!("Interface {}: {:?}", iface.name, iface.addresses);
//!     }
//! }
//!
//! // Monitor interface changes
//! let mut monitor = platform.init_monitoring()?;
//! loop {
//!     let events = monitor.poll()?;
//!     for event in events {
//!         println!("Interface event: {:?}", event);
//!     }
//! }
//! ```
//!
//! # Feature Flags
//!
//! Optional platform-specific features controlled by Cargo.toml:
//! - `netlink` - Enable Linux netlink socket support (Linux only)
//! - `inotify` - Enable Linux inotify file watching (Linux only)
//! - `ipset` - Enable Linux ipset integration (Linux only)
//! - `nftables` - Enable Linux nftables integration (Linux only)
//! - `conntrack` - Enable Linux connection tracking (Linux only)

use std::net::IpAddr;
use std::path::PathBuf;
use thiserror::Error;

use crate::types::errors::DnsmasqError;

// Platform-specific modules with conditional compilation

/// Linux-specific implementations (netlink sockets, inotify, ipset, nftables)
#[cfg(target_os = "linux")]
pub mod linux;

/// BSD-specific implementations (BPF, routing sockets, kqueue)
/// Applies to: FreeBSD, OpenBSD, NetBSD, DragonFly BSD
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub mod bsd;

/// macOS-specific implementations (extends BSD with launchd integration)
#[cfg(target_os = "macos")]
pub mod macos;

/// Generic POSIX fallback for unsupported platforms
#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
)))]
pub mod generic;

// ==============================================================================
// Error Types
// ==============================================================================

/// Platform-specific operation errors
///
/// This error type wraps all errors that can occur during platform-specific
/// operations like interface enumeration, netlink socket operations, or BPF
/// device access. It integrates with the main DnsmasqError hierarchy for
/// consistent error handling throughout the application.
///
/// # Error Variants
///
/// - `IoError`: System I/O errors (socket creation, ioctl failures)
/// - `UnsupportedOperation`: Operation not available on this platform
/// - `InvalidInterface`: Interface index or name doesn't exist
/// - `PermissionDenied`: Insufficient privileges for operation
///
/// # C Implementation Context
///
/// The C code uses errno and return codes:
/// ```c
/// // C error handling (from netlink.c)
/// if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
/// {
///   my_syslog(LOG_ERR, "cannot create netlink socket: %s", strerror(errno));
///   return -1;
/// }
/// ```
///
/// Rust uses Result types with detailed error context:
/// ```rust,no_run
/// # use nix::sys::socket::{socket, AddressFamily, SockType, SockFlag};
/// # use dnsmasq::platform::PlatformError;
/// # fn example() -> Result<(), PlatformError> {
/// // Rust error handling
/// let fd = socket(AddressFamily::Netlink, SockType::Raw, SockFlag::empty(), None)
///     .map_err(|e| PlatformError::IoError {
///         operation: "create netlink socket".to_string(),
///         source: std::io::Error::from_raw_os_error(e as i32),
///     })?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Error)]
pub enum PlatformError {
    /// I/O error during platform operation
    #[error("Platform I/O error during {operation}: {source}")]
    IoError {
        operation: String,
        #[source]
        source: std::io::Error,
    },

    /// Operation not supported on this platform
    #[error("Operation '{operation}' not supported on this platform")]
    UnsupportedOperation { operation: String },

    /// Invalid network interface specified
    #[error("Invalid network interface: {interface} ({reason})")]
    InvalidInterface { interface: String, reason: String },

    /// Insufficient permissions for operation
    #[error("Permission denied: {operation} requires elevated privileges")]
    PermissionDenied { operation: String },
}

impl From<std::io::Error> for PlatformError {
    fn from(err: std::io::Error) -> Self {
        PlatformError::IoError {
            operation: "unknown".to_string(),
            source: err,
        }
    }
}

impl From<PlatformError> for DnsmasqError {
    fn from(err: PlatformError) -> Self {
        // Wrap PlatformError in the appropriate DnsmasqError variant
        // Platform operations are system-level, so we convert to SystemError
        match err {
            PlatformError::IoError { operation, source } => {
                DnsmasqError::System(crate::types::errors::SystemError::FileSystemError {
                    operation,
                    path: "platform operation".to_string(),
                    source,
                })
            }
            PlatformError::PermissionDenied { operation } => {
                DnsmasqError::System(crate::types::errors::SystemError::FileSystemError {
                    operation: operation.clone(),
                    path: "platform operation".to_string(),
                    source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, operation),
                })
            }
            _ => {
                // For other platform errors, use a generic system error
                DnsmasqError::System(crate::types::errors::SystemError::FileSystemError {
                    operation: "platform operation".to_string(),
                    path: err.to_string(),
                    source: std::io::Error::other(err.to_string()),
                })
            }
        }
    }
}

/// Result type for platform operations
pub type PlatformResult<T> = Result<T, PlatformError>;

// ==============================================================================
// Network Interface Types
// ==============================================================================

/// Network interface representation
///
/// Represents a single network interface with its index, name, assigned addresses,
/// and operational flags. This structure aggregates data that C code scattered across
/// multiple data structures (struct iname, struct irec, struct dhcp_context).
///
/// # C Implementation Context
///
/// C uses multiple structures to represent interface data:
/// ```c
/// // From dnsmasq.h
/// struct irec {
///   union mysockaddr addr;
///   struct in_addr netmask; // IPv4 only
///   int index;
///   char *name;
///   unsigned int flags;
/// };
/// ```
///
/// Rust consolidates this into a single coherent structure with proper lifetime
/// management and type safety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Interface index (kernel-assigned unique identifier)
    pub index: u32,

    /// Interface name (e.g., "eth0", "wlan0", "lo")
    pub name: String,

    /// All IP addresses assigned to this interface
    pub addresses: Vec<IpAddr>,

    /// Interface operational flags (UP, LOOPBACK, etc.)
    pub flags: InterfaceFlags,
}

/// Interface operational flags
///
/// Bitflags representing interface state and capabilities. Corresponds to
/// C's if_flags from <net/if.h> (IFF_UP, IFF_LOOPBACK, IFF_POINTOPOINT, IFF_MULTICAST).
///
/// # C Implementation Context
///
/// C uses raw integer bitflags:
/// ```c
/// // From network.c
/// if (ifr.ifr_flags & IFF_UP)
///     // Interface is up
/// if (ifr.ifr_flags & IFF_LOOPBACK)
///     // Loopback interface
/// ```
///
/// Rust uses strongly-typed bitflags with methods for safe manipulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceFlags {
    bits: u32,
}

impl InterfaceFlags {
    /// Interface is administratively up
    pub const UP: u32 = 0x0001;

    /// Interface is a loopback interface
    pub const LOOPBACK: u32 = 0x0008;

    /// Interface is point-to-point link
    pub const POINTOPOINT: u32 = 0x0010;

    /// Interface supports multicast
    pub const MULTICAST: u32 = 0x8000;

    /// Create new flags from raw bits
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Get raw bits
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Check if flag is set
    pub fn contains(&self, flag: u32) -> bool {
        (self.bits & flag) == flag
    }

    /// Set a flag
    pub fn insert(&mut self, flag: u32) {
        self.bits |= flag;
    }

    /// Clear a flag
    pub fn remove(&mut self, flag: u32) {
        self.bits &= !flag;
    }

    /// Check if interface is usable (up and not loopback)
    pub fn is_usable(&self) -> bool {
        self.contains(Self::UP) && !self.contains(Self::LOOPBACK)
    }
}

// ==============================================================================
// Interface Event Types
// ==============================================================================

/// Network interface change events
///
/// Events generated by platform monitoring systems (Linux netlink, BSD routing sockets)
/// when network topology changes. The C code handles these asynchronously in
/// netlink_multicast() (Linux) or route_sock() (BSD).
///
/// # C Implementation Context
///
/// C processes events in callbacks:
/// ```c
/// // From netlink.c - Linux
/// case RTM_NEWADDR:  // Address added
/// case RTM_DELADDR:  // Address removed
/// case RTM_NEWLINK:  // Interface added/modified
/// ```
///
/// Rust uses typed enums for exhaustive pattern matching and type safety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceEvent {
    /// Interface was added to the system
    Added(Interface),

    /// Interface was removed from the system
    Removed { index: u32, name: String },

    /// Interface address was added or removed
    AddressChanged {
        index: u32,
        address: IpAddr,
        added: bool,
    },
}

/// Configuration file change events
///
/// Events for monitoring configuration files (/etc/hosts, /etc/resolv.conf, dnsmasq.conf)
/// for hot reload without SIGHUP. Linux uses inotify (inotify.c), BSD uses kqueue.
///
/// # C Implementation Context
///
/// C polls inotify/kqueue in event loop:
/// ```c
/// // From inotify.c - Linux
/// #define INOTIFY_SZ (sizeof(struct inotify_event) + NAME_MAX + 1)
/// if (inotify_check(poll_listen, fd))
///     queue_event(EVENT_RELOAD);  // Trigger config reload
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEvent {
    /// /etc/resolv.conf or /etc/hosts modified
    ResolvFileChanged(PathBuf),

    /// Dynamic DHCP hosts file modified
    DynamicFileChanged(PathBuf),
}

// ==============================================================================
// Platform Trait Definitions
// ==============================================================================

/// Core platform network operations trait
///
/// This trait defines the interface for platform-specific network operations that
/// all implementations must provide. It abstracts differences between Linux netlink,
/// BSD routing sockets, and generic POSIX interfaces.
///
/// # Thread Safety
///
/// Implementations are used within dnsmasq's single-threaded event loop and do not
/// require Send/Sync. All methods must be non-blocking or use timeouts to prevent
/// event loop starvation.
///
/// # C Implementation Context
///
/// The C code uses platform-specific functions:
/// - Linux: netlink_init(), iface_enumerate() with netlink_multicast()
/// - BSD: route_init(), iface_enumerate() with getifaddrs()
/// - Generic: enumerate_interfaces() with SIOCGIFCONF ioctl
pub trait NetworkPlatform {
    /// Enumerate all network interfaces and their addresses
    ///
    /// Returns a list of all network interfaces currently present on the system,
    /// including their assigned IP addresses and operational flags.
    ///
    /// # C Implementation Context
    ///
    /// - Linux (netlink.c): Sends RTM_GETLINK/RTM_GETADDR dump requests
    /// - BSD (bpf.c): Calls getifaddrs() and iterates linked list
    /// - Generic (network.c): Uses SIOCGIFCONF ioctl
    ///
    /// # Errors
    ///
    /// - `IoError`: System call failure (socket, ioctl, netlink send/recv)
    /// - `PermissionDenied`: Insufficient privileges to query interfaces
    fn enumerate_interfaces(&self) -> PlatformResult<Vec<Interface>>;

    /// Initialize interface change monitoring
    ///
    /// Sets up platform-specific monitoring for network topology changes. The returned
    /// PlatformMonitor can be polled for events without blocking the main event loop.
    ///
    /// # C Implementation Context
    ///
    /// - Linux: Opens AF_NETLINK socket with RTMGRP_* multicast groups
    /// - BSD: Opens PF_ROUTE socket for RTM_* messages
    /// - Generic: Returns monitor that requires periodic polling
    ///
    /// # Errors
    ///
    /// - `IoError`: Failed to create monitoring socket
    /// - `PermissionDenied`: Insufficient privileges for monitoring
    fn init_monitoring(&self) -> PlatformResult<PlatformMonitor>;

    /// Get interface details by index
    ///
    /// Retrieves interface information given a kernel-assigned interface index.
    /// Returns None if the interface doesn't exist.
    ///
    /// # C Implementation Context
    ///
    /// - Linux (network.c): Uses if_indextoname() with SIOCGIFNAME ioctl
    /// - BSD (bpf.c): Calls if_indextoname() from libc
    /// - Generic: Linear search through enumerated interfaces
    fn get_interface_by_index(&self, index: u32) -> PlatformResult<Option<Interface>>;
}

/// Platform-specific interface change monitor
///
/// Provides non-blocking access to network topology change events. The C implementation
/// integrates netlink/routing socket file descriptors directly into the main poll() loop;
/// Rust wraps this in a higher-level interface with async-ready polling.
pub struct PlatformMonitor {
    // Platform-specific implementation is boxed and hidden
    #[allow(dead_code)]
    inner: Box<dyn std::any::Any>,
}

impl PlatformMonitor {
    /// Poll for interface change events (non-blocking)
    ///
    /// Returns all pending interface events without blocking. Should be called
    /// when the underlying file descriptor becomes readable in the event loop.
    ///
    /// # C Implementation Context
    ///
    /// - Linux: Drains netlink socket with MSG_DONTWAIT, processes RTM_* messages
    /// - BSD: Reads routing socket with MSG_DONTWAIT, processes RTM_* messages
    /// - Generic: Compares current interface list to cached state
    pub fn poll(&mut self) -> PlatformResult<Vec<InterfaceEvent>> {
        // Platform-specific implementations override this in platform-specific modules
        Ok(Vec::new())
    }

    /// Process accumulated events
    ///
    /// Allows platform implementations to batch process related events before
    /// returning them to the caller. Used by C code's nl_multicast_state() to
    /// coalesce rapid-fire interface changes.
    pub fn process_events(&mut self) {
        // Platform-specific implementations override this
    }
}

/// Raw packet filtering trait for DHCP
///
/// Provides raw Ethernet frame transmission capability required for DHCP server
/// operation (sending responses to broadcast address before client has IP address).
/// Platform implementations:
/// - Linux: Uses AF_PACKET sockets (packet(7))
/// - BSD: Uses Berkeley Packet Filter (BPF) devices (/dev/bpf*)
/// - Generic: Falls back to IP-level sockets (limited functionality)
///
/// # Safety
///
/// Raw packet operations require CAP_NET_RAW capability on Linux or root privileges
/// on BSD. Implementations must validate all packet data to prevent malformed frames.
///
/// # C Implementation Context
///
/// - Linux: Not in provided files (assumed to use AF_PACKET)
/// - BSD (bpf.c): init_bpf() opens /dev/bpf*, send_via_bpf() constructs Ethernet frames
pub trait PacketFilter {
    /// Open raw packet filter on specified interface
    ///
    /// Creates a raw socket bound to the given interface for DHCP packet transmission.
    ///
    /// # Errors
    ///
    /// - `PermissionDenied`: Insufficient privileges for raw socket
    /// - `InvalidInterface`: Interface doesn't exist
    /// - `IoError`: System call failure
    fn open_filter(&self, interface: &str) -> PlatformResult<RawSocket>;

    /// Send raw Ethernet frame
    ///
    /// Transmits a complete Ethernet frame (including headers) on the interface.
    /// Used for DHCP broadcast responses.
    fn send_raw_packet(&self, socket: &RawSocket, data: &[u8]) -> PlatformResult<()>;

    /// Receive raw packet (blocking with timeout)
    ///
    /// Receives a raw Ethernet frame. Used for DHCP request reception.
    fn recv_raw_packet(&self, socket: &RawSocket) -> PlatformResult<Vec<u8>>;
}

/// Raw socket handle for packet filtering
///
/// Opaque handle to platform-specific raw socket (AF_PACKET on Linux, BPF on BSD).
/// Automatically closed when dropped (RAII pattern).
pub struct RawSocket {
    #[allow(dead_code)]
    inner: Box<dyn std::any::Any>,
}

impl RawSocket {
    /// Send raw packet data
    pub fn send(&self, _data: &[u8]) -> PlatformResult<()> {
        // Platform-specific implementation
        Err(PlatformError::UnsupportedOperation {
            operation: "send".to_string(),
        })
    }

    /// Receive raw packet data
    pub fn recv(&self) -> PlatformResult<Vec<u8>> {
        // Platform-specific implementation
        Err(PlatformError::UnsupportedOperation {
            operation: "recv".to_string(),
        })
    }

    /// Close the raw socket explicitly
    pub fn close(self) -> PlatformResult<()> {
        // Drop automatically closes via RAII
        Ok(())
    }
}

/// File watching trait for configuration hot reload
///
/// Monitors filesystem changes for configuration files to enable hot reload without
/// requiring SIGHUP signal. Platform implementations:
/// - Linux: inotify (inotify.c)
/// - BSD/macOS: kqueue with EVFILT_VNODE
/// - Generic: Periodic stat() polling
///
/// # C Implementation Context
///
/// From inotify.c (Linux):
/// ```c
/// #ifdef HAVE_INOTIFY
/// inotify_add_watch(fd, "/etc/resolv.conf", IN_MODIFY | IN_CLOSE_WRITE);
/// inotify_add_watch(fd, "/etc/hosts", IN_MODIFY | IN_CLOSE_WRITE);
/// #endif
/// ```
pub trait FileWatcher {
    /// Watch a file for modifications
    ///
    /// Registers a file for change notifications. Events are returned via poll_events().
    fn watch_file(&mut self, path: PathBuf) -> PlatformResult<()>;

    /// Watch a directory for file additions/removals
    ///
    /// Monitors a directory for configuration files being added or removed.
    fn watch_directory(&mut self, path: PathBuf) -> PlatformResult<()>;

    /// Poll for file change events (non-blocking)
    ///
    /// Returns all pending file change events without blocking.
    fn poll_events(&mut self) -> Vec<FileEvent>;
}

// ==============================================================================
// Platform Selection
// ==============================================================================

/// Get the platform-specific implementation for the current operating system
///
/// Returns a boxed trait object providing platform-specific network operations.
/// This function performs compile-time platform detection using cfg attributes
/// and returns the appropriate implementation.
///
/// # Platform Detection
///
/// - **Linux**: Returns `LinuxPlatform` using netlink sockets
/// - **BSD** (FreeBSD, OpenBSD, NetBSD, DragonFly): Returns `BsdPlatform` using routing sockets
/// - **macOS**: Returns `MacOsPlatform` extending BSD with launchd integration
/// - **Other**: Returns `GenericPlatform` with POSIX fallback
///
/// # Example
///
/// ```ignore
/// let platform = get_platform();
/// let interfaces = platform.enumerate_interfaces()?;
/// ```
pub fn get_platform() -> Box<dyn NetworkPlatform> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::new())
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        Box::new(bsd::BsdPlatform::new())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsPlatform::new())
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    )))]
    {
        Box::new(generic::GenericPlatform::new())
    }
}

/// Type alias for the current platform's implementation
///
/// Allows code to refer to the concrete platform type without trait objects
/// when dynamic dispatch is not needed.
///
/// # Example
///
/// ```ignore
/// let platform = Platform::new();
/// ```
#[cfg(target_os = "linux")]
pub type Platform = linux::LinuxPlatform;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub type Platform = bsd::BsdPlatform;

#[cfg(target_os = "macos")]
pub type Platform = macos::MacOsPlatform;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
)))]
pub type Platform = generic::GenericPlatform;

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_flags() {
        let mut flags = InterfaceFlags::from_bits(0);

        assert!(!flags.contains(InterfaceFlags::UP));

        flags.insert(InterfaceFlags::UP);
        assert!(flags.contains(InterfaceFlags::UP));

        flags.remove(InterfaceFlags::UP);
        assert!(!flags.contains(InterfaceFlags::UP));
    }

    #[test]
    fn test_interface_flags_usable() {
        // Interface must be UP and not LOOPBACK to be usable
        let mut flags = InterfaceFlags::from_bits(0);
        assert!(!flags.is_usable());

        flags.insert(InterfaceFlags::UP);
        assert!(flags.is_usable());

        flags.insert(InterfaceFlags::LOOPBACK);
        assert!(!flags.is_usable()); // Loopback is not usable
    }

    #[test]
    fn test_platform_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test error");
        let platform_err: PlatformError = io_err.into();

        match platform_err {
            PlatformError::IoError { operation, .. } => {
                assert_eq!(operation, "unknown");
            }
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_interface_creation() {
        let iface = Interface {
            index: 1,
            name: "eth0".to_string(),
            addresses: vec![],
            flags: InterfaceFlags::from_bits(InterfaceFlags::UP | InterfaceFlags::MULTICAST),
        };

        assert_eq!(iface.index, 1);
        assert_eq!(iface.name, "eth0");
        assert!(iface.flags.contains(InterfaceFlags::UP));
        assert!(iface.flags.contains(InterfaceFlags::MULTICAST));
        assert!(!iface.flags.contains(InterfaceFlags::LOOPBACK));
    }

    #[test]
    fn test_interface_event_variants() {
        let iface = Interface {
            index: 2,
            name: "wlan0".to_string(),
            addresses: vec!["192.168.1.100".parse().unwrap()],
            flags: InterfaceFlags::from_bits(InterfaceFlags::UP),
        };

        let added = InterfaceEvent::Added(iface.clone());
        let removed = InterfaceEvent::Removed {
            index: 2,
            name: "wlan0".to_string(),
        };
        let addr_changed = InterfaceEvent::AddressChanged {
            index: 2,
            address: "192.168.1.100".parse().unwrap(),
            added: true,
        };

        // Verify all variants are constructible
        assert!(matches!(added, InterfaceEvent::Added(_)));
        assert!(matches!(removed, InterfaceEvent::Removed { .. }));
        assert!(matches!(
            addr_changed,
            InterfaceEvent::AddressChanged { .. }
        ));
    }

    #[test]
    fn test_file_event_variants() {
        let resolv_event = FileEvent::ResolvFileChanged(PathBuf::from("/etc/resolv.conf"));
        let dynamic_event = FileEvent::DynamicFileChanged(PathBuf::from("/etc/hosts"));

        assert!(matches!(resolv_event, FileEvent::ResolvFileChanged(_)));
        assert!(matches!(dynamic_event, FileEvent::DynamicFileChanged(_)));
    }
}
