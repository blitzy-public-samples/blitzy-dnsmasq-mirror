//! Platform abstraction layer for network interface operations
//!
//! This module provides a unified API for platform-specific network interface operations
//! across Linux, BSD variants, and Solaris. It replaces the C implementation's preprocessor-based
//! platform selection (#ifdef HAVE_LINUX_NETWORK, HAVE_BSD_NETWORK, HAVE_SOLARIS_NETWORK)
//! with Rust's cfg attributes and trait-based polymorphism.
//!
//! # Supported Platforms
//!
//! - **Linux 2.6+**: Uses netlink sockets for interface enumeration and monitoring
//! - **FreeBSD 10+**: Uses routing sockets and getifaddrs()
//! - **OpenBSD 6.0+**: Uses routing sockets and getifaddrs()
//! - **NetBSD 7.0+**: Uses routing sockets and getifaddrs()
//! - **macOS 10.10+**: Uses routing sockets and getifaddrs()
//! - **Solaris 11+**: Uses ioctl-based interface enumeration
//!
//! # Architecture
//!
//! The module uses compile-time platform specialization through Rust's #[cfg] attributes:
//! - Platform-specific implementations are in separate submodules (linux, bsd, solaris)
//! - The `Platform` trait defines the common interface
//! - `PlatformImpl` type alias points to the active platform implementation
//! - `create_platform()` factory function provides dependency injection
//!
//! # Example Usage
//!
//! ```no_run
//! use dnsmasq::network::platform::{create_platform, Platform};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let platform = create_platform()?;
//!     let interfaces = platform.enumerate_interfaces().await?;
//!     
//!     for iface in interfaces {
//!         println!("Interface: {} ({}) - {}", iface.name, iface.index, iface.addr);
//!     }
//!     
//!     Ok(())
//! }
//! ```

use async_trait::async_trait;
use std::fmt;
use std::net::IpAddr;
use tokio::sync::mpsc::Receiver;

// For address family constants (AF_INET, AF_INET6)
// Using explicit libc constants ensures compatibility with C behavior
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

// Conditional module imports based on target platform
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
pub mod bsd;

#[cfg(target_os = "solaris")]
pub mod solaris;

/// Network interface information
///
/// Represents a network interface with its addressing configuration.
/// Replaces C's `struct irec` with type-safe address handling.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceInfo {
    /// IP address assigned to this interface
    pub addr: IpAddr,
    
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,
    
    /// System interface index
    pub index: u32,
    
    /// Interface flags (IFF_UP, IFF_BROADCAST, IFF_LOOPBACK, etc.)
    pub flags: u32,
    
    /// Network prefix length (CIDR notation)
    pub prefixlen: u8,
    
    /// Network mask address
    pub netmask: IpAddr,
}

impl InterfaceInfo {
    /// Check if interface is up and running
    pub fn is_up(&self) -> bool {
        const IFF_UP: u32 = 0x1;
        (self.flags & IFF_UP) != 0
    }
    
    /// Check if interface supports broadcast
    pub fn is_broadcast(&self) -> bool {
        const IFF_BROADCAST: u32 = 0x2;
        (self.flags & IFF_BROADCAST) != 0
    }
    
    /// Check if interface is loopback
    pub fn is_loopback(&self) -> bool {
        const IFF_LOOPBACK: u32 = 0x8;
        (self.flags & IFF_LOOPBACK) != 0
    }
    
    /// Check if interface is point-to-point
    pub fn is_point_to_point(&self) -> bool {
        const IFF_POINTOPOINT: u32 = 0x10;
        (self.flags & IFF_POINTOPOINT) != 0
    }
}

/// ARP cache entry
///
/// Represents an ARP table entry mapping IP addresses to hardware addresses.
/// Replaces C's manual ARP table parsing with type-safe representation.
#[derive(Debug, Clone, PartialEq)]
pub struct ArpEntry {
    /// IP address
    pub addr: IpAddr,
    
    /// Hardware (MAC) address
    pub hwaddr: [u8; 6],
    
    /// Address family (AF_INET or AF_INET6)
    pub family: i32,
    
    /// Interface index
    pub if_index: u32,
    
    /// Hardware address length (typically 6 for Ethernet)
    pub hwaddr_len: u8,
}

impl ArpEntry {
    /// Create a new ARP entry
    pub fn new(addr: IpAddr, hwaddr: [u8; 6], if_index: u32) -> Self {
        let family = match addr {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };
        
        Self {
            addr,
            hwaddr,
            family,
            if_index,
            hwaddr_len: 6,
        }
    }
    
    /// Format hardware address as string (e.g., "00:11:22:33:44:55")
    pub fn hwaddr_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.hwaddr[0],
            self.hwaddr[1],
            self.hwaddr[2],
            self.hwaddr[3],
            self.hwaddr[4],
            self.hwaddr[5]
        )
    }
}

/// Network change event
///
/// Represents real-time changes to network configuration that dnsmasq must respond to.
/// Replaces C's callback-based notification with async channel-based event delivery.
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkChange {
    /// A new network interface was added
    InterfaceAdded {
        /// Interface name
        name: String,
        /// Interface index
        index: u32,
    },
    
    /// A network interface was removed
    InterfaceRemoved {
        /// Interface name
        name: String,
        /// Interface index
        index: u32,
    },
    
    /// An IP address was added to an interface
    AddressAdded {
        /// Interface index
        if_index: u32,
        /// New address
        addr: IpAddr,
        /// Prefix length
        prefixlen: u8,
    },
    
    /// An IP address was removed from an interface
    AddressRemoved {
        /// Interface index
        if_index: u32,
        /// Removed address
        addr: IpAddr,
    },
    
    /// Routing table changed
    RouteChanged {
        /// Destination network
        destination: Option<IpAddr>,
        /// Gateway address
        gateway: Option<IpAddr>,
    },
}

/// Platform-specific error type
///
/// Wraps platform-specific errors with additional context for diagnostics.
#[derive(Debug)]
pub struct PlatformError {
    /// Error kind
    pub kind: PlatformErrorKind,
    /// Error message
    pub message: String,
    /// Underlying system error (if any)
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl PlatformError {
    /// Create a new platform error
    pub fn new(kind: PlatformErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }
    
    /// Create a platform error with source
    pub fn with_source(
        kind: PlatformErrorKind,
        message: impl Into<String>,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(source),
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)?;
        if let Some(ref source) = self.source {
            write!(f, " (caused by: {})", source)?;
        }
        Ok(())
    }
}

impl std::error::Error for PlatformError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Platform error kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformErrorKind {
    /// Failed to enumerate network interfaces
    EnumerationFailed,
    /// Failed to monitor network changes
    MonitoringFailed,
    /// Failed to access ARP cache
    ArpAccessFailed,
    /// Platform not supported
    UnsupportedPlatform,
    /// Invalid interface configuration
    InvalidConfiguration,
    /// Permission denied
    PermissionDenied,
}

impl fmt::Display for PlatformErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnumerationFailed => write!(f, "Interface enumeration failed"),
            Self::MonitoringFailed => write!(f, "Network monitoring failed"),
            Self::ArpAccessFailed => write!(f, "ARP cache access failed"),
            Self::UnsupportedPlatform => write!(f, "Platform not supported"),
            Self::InvalidConfiguration => write!(f, "Invalid configuration"),
            Self::PermissionDenied => write!(f, "Permission denied"),
        }
    }
}

/// Platform abstraction trait
///
/// Defines the common interface for platform-specific network operations.
/// Each platform (Linux, BSD, Solaris) provides its own implementation.
///
/// # Memory Safety
///
/// This trait replaces C's raw pointer-based platform functions with safe async methods:
/// - Automatic resource cleanup via RAII
/// - No manual memory management
/// - Compile-time interface verification
/// - Runtime errors via Result types
///
/// # Async Design
///
/// All methods are async to support non-blocking I/O:
/// - Interface enumeration may involve multiple system calls
/// - Network monitoring streams events continuously
/// - ARP cache access may require kernel queries
#[async_trait]
pub trait Platform: Send + Sync {
    /// Enumerate all network interfaces
    ///
    /// Returns a list of all network interfaces with their addressing configuration.
    /// This method performs a point-in-time snapshot of the network state.
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::EnumerationFailed` if:
    /// - System calls fail (permission denied, invalid state)
    /// - Interface information is incomplete or invalid
    /// - Platform-specific enumeration mechanism is unavailable
    ///
    /// # Implementation Notes
    ///
    /// - **Linux**: Uses netlink RTM_GETLINK and RTM_GETADDR messages
    /// - **BSD**: Uses getifaddrs() system call
    /// - **Solaris**: Uses SIOCGIFCONF ioctl
    async fn enumerate_interfaces(&self) -> Result<Vec<InterfaceInfo>, PlatformError>;
    
    /// Monitor network interface changes
    ///
    /// Returns a receiver channel that streams network change events in real-time.
    /// The channel remains open until the platform monitor is dropped or an error occurs.
    ///
    /// # Events
    ///
    /// The returned channel emits `NetworkChange` events for:
    /// - Interface addition/removal
    /// - IP address assignment/removal
    /// - Routing table changes
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::MonitoringFailed` if:
    /// - Cannot create monitoring socket/descriptor
    /// - Insufficient permissions for network monitoring
    /// - Platform does not support change notification
    ///
    /// # Implementation Notes
    ///
    /// - **Linux**: Uses netlink RTMGRP_LINK, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR multicast groups
    /// - **BSD**: Uses routing socket with RTM_IFINFO, RTM_NEWADDR, RTM_DELADDR messages
    /// - **Solaris**: Polls via periodic interface enumeration (no native event mechanism)
    ///
    /// # Cancellation Safety
    ///
    /// This method is cancellation-safe. Dropping the receiver stops monitoring.
    async fn monitor_changes(&self) -> Result<Receiver<NetworkChange>, PlatformError>;
    
    /// Enumerate ARP cache entries
    ///
    /// Returns a snapshot of the system ARP cache mapping IP addresses to hardware addresses.
    /// This is used for DHCP client identification and conflict detection.
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::ArpAccessFailed` if:
    /// - Cannot read ARP cache (permission denied)
    /// - ARP cache format is invalid
    /// - Platform does not expose ARP cache to userspace
    ///
    /// # Implementation Notes
    ///
    /// - **Linux**: Reads /proc/net/arp or uses netlink RTM_GETNEIGH
    /// - **BSD**: Uses sysctl net.link.ether.inet.host or routing socket RTM_GET
    /// - **Solaris**: Reads ARP cache via ioctl or /dev/arp
    ///
    /// # Platform Availability
    ///
    /// Some platforms may not support ARP enumeration. In such cases, an empty
    /// vector is returned rather than an error.
    async fn enumerate_arp(&self) -> Result<Vec<ArpEntry>, PlatformError>;
}

// Platform-specific type aliases and factory function
//
// These use #[cfg] attributes to select the appropriate implementation at compile time,
// providing zero-cost abstraction over platform differences.

/// Platform-specific implementation type (Linux)
#[cfg(target_os = "linux")]
pub type PlatformImpl = linux::LinuxPlatform;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
pub type PlatformImpl = bsd::BsdPlatform;

#[cfg(target_os = "solaris")]
pub type PlatformImpl = solaris::SolarisPlatform;

// Ensure at compile time that exactly one platform is selected
#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "solaris"
)))]
compile_error!("Unsupported platform: dnsmasq requires Linux, BSD, or Solaris");

/// Create a platform-specific implementation
///
/// Factory function that instantiates the appropriate platform implementation
/// based on the compile-time target. Returns a boxed trait object for
/// dependency injection into the daemon.
///
/// # Errors
///
/// Returns `PlatformError::UnsupportedPlatform` if:
/// - Platform detection fails
/// - Required platform features are unavailable
/// - Platform initialization fails
///
/// # Example
///
/// ```no_run
/// use dnsmasq::network::platform::create_platform;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let platform = create_platform()?;
///     let interfaces = platform.enumerate_interfaces().await?;
///     println!("Found {} interfaces", interfaces.len());
///     Ok(())
/// }
/// ```
pub fn create_platform() -> Result<Box<dyn Platform>, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxPlatform::new()?))
    }
    
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos"
    ))]
    {
        Ok(Box::new(bsd::BsdPlatform::new()?))
    }
    
    #[cfg(target_os = "solaris")]
    {
        Ok(Box::new(solaris::SolarisPlatform::new()?))
    }
}

/// Helper function to convert libc errors to PlatformError
///
/// Provides consistent error mapping across platform implementations.
pub(crate) fn io_error_to_platform_error(
    kind: PlatformErrorKind,
    message: impl Into<String>,
    error: std::io::Error,
) -> PlatformError {
    PlatformError::with_source(kind, message, Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    
    #[test]
    fn test_interface_info_flags() {
        let iface = InterfaceInfo {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            name: "eth0".to_string(),
            index: 1,
            flags: 0x1 | 0x2, // IFF_UP | IFF_BROADCAST
            prefixlen: 24,
            netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        };
        
        assert!(iface.is_up());
        assert!(iface.is_broadcast());
        assert!(!iface.is_loopback());
        assert!(!iface.is_point_to_point());
    }
    
    #[test]
    fn test_arp_entry_hwaddr_string() {
        let entry = ArpEntry::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            1,
        );
        
        assert_eq!(entry.hwaddr_string(), "00:11:22:33:44:55");
    }
    
    #[test]
    fn test_network_change_variants() {
        let change = NetworkChange::InterfaceAdded {
            name: "eth0".to_string(),
            index: 1,
        };
        
        match change {
            NetworkChange::InterfaceAdded { name, index } => {
                assert_eq!(name, "eth0");
                assert_eq!(index, 1);
            }
            _ => panic!("Wrong variant"),
        }
    }
    
    #[test]
    fn test_platform_error_display() {
        let error = PlatformError::new(
            PlatformErrorKind::EnumerationFailed,
            "Failed to enumerate interfaces",
        );
        
        let error_string = error.to_string();
        assert!(error_string.contains("Interface enumeration failed"));
        assert!(error_string.contains("Failed to enumerate interfaces"));
    }
    
    // Additional comprehensive ad-hoc tests
    
    #[test]
    fn test_interface_info_ipv6() {
        let iface = InterfaceInfo {
            addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0)),
            name: "eth0".to_string(),
            index: 2,
            flags: 0x1, // IFF_UP
            prefixlen: 64,
            netmask: IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0)),
        };
        
        assert!(iface.is_up(), "IPv6 interface should be up");
        assert_eq!(iface.prefixlen, 64, "Standard IPv6 prefix length");
        
        match iface.addr {
            IpAddr::V6(addr) => {
                assert!(addr.is_unicast_link_local(), "Should be link-local IPv6");
            }
            _ => panic!("Expected IPv6 address"),
        }
    }
    
    #[test]
    fn test_interface_info_broadcast_detection() {
        let eth = InterfaceInfo {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            name: "eth0".to_string(),
            index: 2,
            flags: 0x2 | 0x1, // IFF_BROADCAST | IFF_UP
            prefixlen: 24,
            netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        };
        
        assert!(eth.is_broadcast(), "Should detect broadcast flag");
        assert!(eth.is_up(), "Should detect up flag");
        assert!(!eth.is_loopback(), "Ethernet is not loopback");
    }
    
    #[test]
    fn test_interface_info_point_to_point() {
        let ppp = InterfaceInfo {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            name: "ppp0".to_string(),
            index: 3,
            flags: 0x10 | 0x1, // IFF_POINTOPOINT | IFF_UP
            prefixlen: 32,
            netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        };
        
        assert!(ppp.is_point_to_point(), "Should detect point-to-point flag");
        assert!(!ppp.is_broadcast(), "PPP is not broadcast");
    }
    
    #[test]
    fn test_arp_entry_zero_hwaddr() {
        let zero_entry = ArpEntry::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            2,
        );
        
        assert_eq!(zero_entry.hwaddr_string(), "00:00:00:00:00:00");
        assert_eq!(zero_entry.if_index, 2);
    }
    
    #[test]
    fn test_network_change_address_added() {
        let addr_added = NetworkChange::AddressAdded {
            if_index: 2,
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            prefixlen: 24,
        };
        
        match addr_added {
            NetworkChange::AddressAdded { if_index, addr, prefixlen } => {
                assert_eq!(if_index, 2);
                assert_eq!(prefixlen, 24);
                match addr {
                    IpAddr::V4(v4) => assert_eq!(v4, Ipv4Addr::new(192, 168, 1, 10)),
                    _ => panic!("Expected IPv4"),
                }
            }
            _ => panic!("Wrong variant"),
        }
    }
    
    #[test]
    fn test_network_change_route_changed() {
        let route = NetworkChange::RouteChanged {
            destination: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        };
        
        match route {
            NetworkChange::RouteChanged { destination, gateway } => {
                assert!(destination.is_some());
                assert!(gateway.is_some());
            }
            _ => panic!("Wrong variant"),
        }
    }
    
    #[test]
    fn test_platform_error_with_source() {
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let error_with_source = PlatformError::with_source(
            PlatformErrorKind::MonitoringFailed,
            "Cannot monitor network",
            Box::new(io_error),
        );
        
        let error_string = error_with_source.to_string();
        assert!(error_string.contains("Network monitoring failed"));
        assert!(error_string.contains("Cannot monitor network"));
        assert!(error_string.contains("caused by"));
        assert!(error_with_source.source.is_some());
    }
    
    #[test]
    fn test_all_platform_error_kinds() {
        let test_cases = vec![
            (PlatformErrorKind::EnumerationFailed, "Interface enumeration failed"),
            (PlatformErrorKind::MonitoringFailed, "Network monitoring failed"),
            (PlatformErrorKind::ArpAccessFailed, "ARP cache access failed"),
            (PlatformErrorKind::UnsupportedPlatform, "Platform not supported"),
            (PlatformErrorKind::InvalidConfiguration, "Invalid configuration"),
            (PlatformErrorKind::PermissionDenied, "Permission denied"),
        ];
        
        for (kind, expected_msg) in test_cases {
            let error = PlatformError::new(kind, "test message");
            let error_string = error.to_string();
            assert!(
                error_string.contains(expected_msg),
                "Error kind {:?} should contain '{}', got '{}'",
                kind,
                expected_msg,
                error_string
            );
        }
    }
    
    #[test]
    fn test_network_change_interface_removed() {
        let removed = NetworkChange::InterfaceRemoved {
            name: "eth1".to_string(),
            index: 3,
        };
        
        match removed {
            NetworkChange::InterfaceRemoved { name, index } => {
                assert_eq!(name, "eth1");
                assert_eq!(index, 3);
            }
            _ => panic!("Wrong variant"),
        }
    }
    
    #[test]
    fn test_network_change_address_removed() {
        let addr_removed = NetworkChange::AddressRemoved {
            if_index: 2,
            addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        };
        
        match addr_removed {
            NetworkChange::AddressRemoved { if_index, addr } => {
                assert_eq!(if_index, 2);
                match addr {
                    IpAddr::V6(_) => {},
                    _ => panic!("Expected IPv6"),
                }
            }
            _ => panic!("Wrong variant"),
        }
    }
    
    #[tokio::test]
    async fn test_create_platform_returns_valid_boxed_trait() {
        let result = create_platform();
        assert!(result.is_ok(), "Platform creation should succeed");
        
        let _platform: Box<dyn Platform> = result.unwrap();
        // Successfully created and type-checked as Box<dyn Platform>
    }
}
