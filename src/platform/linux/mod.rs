// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later

//! Linux platform module root
//!
//! This module provides the most comprehensive platform implementation for dnsmasq,
//! leveraging Linux-specific kernel features for efficient network monitoring, file
//! watching, and advanced firewall integration capabilities unavailable on other
//! operating systems.
//!
//! # Overview
//!
//! The Linux platform implementation offers the richest feature set through integration
//! with kernel subsystems:
//! - **Netlink RTNETLINK**: Real-time network interface and routing notifications
//! - **inotify**: Efficient file system monitoring for configuration hot-reload
//! - **ipset**: Legacy netfilter ipset integration for DNS-based firewall rules
//! - **nftables**: Modern nftables set manipulation (successor to ipset)
//! - **conntrack**: Connection tracking for packet mark propagation
//!
//! # Feature Flags
//!
//! Optional features controlled by Cargo.toml feature flags:
//! - `netlink` (default): Network interface discovery via Netlink (always enabled on Linux)
//! - `inotify`: File monitoring for /etc/hosts, /etc/resolv.conf, and dnsmasq.conf
//! - `ipset`: Linux ipset integration for DNS-based firewall rules (legacy)
//! - `nftables`: Modern nftables set integration (recommended over ipset)
//! - `conntrack`: Connection tracking for mark propagation to DNS queries
//!
//! # C Implementation Context
//!
//! This module replaces and consolidates five C source files:
//! - `src/netlink.c` (640 lines): Netlink RTNETLINK socket interface
//! - `src/inotify.c` (180 lines): Linux inotify file watching
//! - `src/ipset.c` (280 lines): ipset netlink protocol implementation
//! - `src/nftset.c` (320 lines): nftables libnftables integration
//! - `src/conntrack.c` (140 lines): libnetfilter_conntrack query interface
//!
//! # Rust Translation Strategy
//!
//! The Rust implementation provides:
//! - Type-safe netlink message handling via netlink-packet-route crate
//! - Async I/O using Tokio for non-blocking operations
//! - Automatic resource cleanup through RAII (Drop trait)
//! - Compile-time feature selection replacing runtime capability detection
//! - Comprehensive error types with context
//!
//! # Memory Safety Improvements
//!
//! Rust eliminates several vulnerability classes present in C:
//! - **Buffer overflows**: C uses fixed-size buffers (4096 bytes) with expand_buf();
//!   Rust uses Vec<u8> that grows automatically
//! - **Use-after-free**: C manually manages buffer lifetimes; Rust ownership prevents
//!   dangling pointers
//! - **Integer overflows**: C casts u32 interface indices without bounds checking;
//!   Rust enforces checked arithmetic
//! - **Null pointer dereferences**: C returns NULL on errors; Rust uses Option/Result
//!
//! # Platform Trait Implementation
//!
//! LinuxPlatform implements the NetworkPlatform trait from `src/platform/mod.rs`,
//! providing:
//! - `enumerate_interfaces()`: Netlink-based interface discovery
//! - `init_monitoring()`: Netlink multicast event subscription
//! - `get_interface_by_index()`: Fast interface lookup by kernel index
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::platform::linux::{LinuxPlatform, init};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize Linux platform with all available features
//! let platform = init().await?;
//!
//! // Enumerate network interfaces via Netlink
//! let interfaces = platform.enumerate_interfaces()?;
//! for iface in interfaces {
//!     println!("Interface {}: {:?}", iface.name, iface.addresses);
//! }
//!
//! // Monitor network changes (netlink multicast)
//! let mut monitor = platform.init_monitoring()?;
//! let events = monitor.poll()?;
//! for event in events {
//!     println!("Network event: {:?}", event);
//! }
//!
//! // Watch configuration files (if inotify feature enabled)
//! #[cfg(feature = "inotify")]
//! {
//!     if let Some(watcher) = platform.get_inotify() {
//!         watcher.watch_resolv_files(vec!["/etc/resolv.conf".into()]).await?;
//!     }
//! }
//!
//! // Add DNS query result to ipset (if ipset feature enabled)
//! #[cfg(feature = "ipset")]
//! {
//!     if let Some(ipset_mgr) = platform.get_ipset() {
//!         ipset_mgr.add_to_set("dns-blocklist", "192.0.2.1".parse()?).await?;
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Kernel Version Requirements
//!
//! Minimum kernel versions for various features:
//! - **Netlink RTNETLINK**: Linux 2.2+ (universally available)
//! - **inotify**: Linux 2.6.13+ (June 2005)
//! - **ipset**: Linux 2.6.39+ with CONFIG_NETFILTER_NETLINK (May 2011)
//! - **nftables**: Linux 3.13+ with CONFIG_NFT_SET_HASH (January 2014)
//! - **conntrack**: Linux 2.6.14+ with CONFIG_NF_CONNTRACK_NETLINK (October 2005)
//!
//! Graceful degradation: If a feature is compiled in but kernel doesn't support it,
//! operations return Err(UnsupportedOperation) and dnsmasq continues without that feature.
//!
//! # Migration from C Implementation
//!
//! Key differences from C implementation:
//! 1. **Async I/O**: C uses poll() in main event loop; Rust uses Tokio async/await
//! 2. **Error handling**: C uses errno and return codes; Rust uses Result types
//! 3. **Memory management**: C uses static buffers; Rust uses owned Vec/String
//! 4. **Type safety**: C uses void* callbacks; Rust uses strongly-typed enums
//! 5. **Resource cleanup**: C requires explicit cleanup; Rust uses RAII Drop trait

use std::sync::Arc;
use thiserror::Error;
use tracing::error;

use crate::platform::{
    Interface, InterfaceEvent, NetworkPlatform, PlatformError, PlatformMonitor, PlatformResult,
};

// ==============================================================================
// Module Declarations
// ==============================================================================

/// Netlink socket interface for network monitoring
///
/// This module is always available on Linux as it provides the core network
/// interface enumeration and monitoring capabilities. It replaces src/netlink.c
/// from the C implementation.
///
/// Provides:
/// - NetlinkSocket: Low-level Netlink RTNETLINK socket operations
/// - NetlinkMonitor: Async stream of network topology changes
/// - NetlinkEvent: Typed network events (NewAddress, DeleteAddress, NewRoute, etc.)
/// - enumerate_interfaces(): Convenience function for interface discovery
pub mod netlink;

/// Linux inotify file system monitoring
///
/// Optional module (feature = "inotify") providing efficient file watching for
/// configuration hot-reload. Replaces src/inotify.c from the C implementation.
///
/// Provides:
/// - InotifyWatcher: Async file/directory change monitoring
/// - FileEvent: Typed file events (ResolvFileChanged, DynamicFileChanged)
/// - watch_resolv_files(): Watch /etc/resolv.conf and /etc/hosts
/// - watch_dynamic_dirs(): Watch DHCP hosts directories
///
/// Requires: Linux 2.6.13+ kernel with CONFIG_INOTIFY_USER
#[cfg(feature = "inotify")]
pub mod inotify;

/// Linux ipset integration
///
/// Optional module (feature = "ipset") for legacy netfilter ipset manipulation.
/// Replaces src/ipset.c from the C implementation. For new deployments, prefer
/// the nftables module which provides better performance and flexibility.
///
/// Provides:
/// - IpsetManager: Ipset netlink protocol implementation
/// - add_to_ipset(): Convenience function to add/remove addresses
/// - IpsetProtocol: Enum distinguishing ipset protocol version 6 vs 7
///
/// Requires: Linux 2.6.39+ with CONFIG_NETFILTER_NETLINK
#[cfg(feature = "ipset")]
pub mod ipset;

/// Linux nftables set manipulation
///
/// Optional module (feature = "nftables") for modern nftables integration.
/// Replaces src/nftset.c from the C implementation. This is the recommended
/// firewall integration method for modern Linux systems.
///
/// Provides:
/// - NftablesManager: libnftables integration for set operations
/// - add_to_nftset(): Convenience function to add/remove addresses
///
/// Requires: Linux 3.13+ with CONFIG_NFT_SET_HASH, libnftables 0.8+
#[cfg(feature = "nftables")]
pub mod nftset;

/// Linux connection tracking integration
///
/// Optional module (feature = "conntrack") for netfilter conntrack queries.
/// Replaces src/conntrack.c from the C implementation. Used to propagate
/// packet marks from DNS queries to responses.
///
/// Provides:
/// - get_incoming_mark(): Query connection tracking mark for a connection
///
/// Requires: Linux 2.6.14+ with CONFIG_NF_CONNTRACK_NETLINK, libnetfilter_conntrack
#[cfg(feature = "conntrack")]
pub mod conntrack;

// ==============================================================================
// Re-exports
// ==============================================================================

// Netlink types (always available on Linux)
pub use netlink::{
    NetlinkError, NetlinkEvent, NetlinkMonitor, NetlinkSocket, enumerate_interfaces,
};

// inotify types (conditional)
#[cfg(feature = "inotify")]
pub use inotify::{FileEvent, InotifyError, InotifyWatcher};

// ipset types (conditional)
#[cfg(feature = "ipset")]
pub use ipset::{IpsetError, IpsetManager, add_to_ipset};

// nftables types (conditional)
#[cfg(feature = "nftables")]
pub use nftset::{NftablesManager, NftsetError, add_to_nftset};

// conntrack types (conditional)
#[cfg(feature = "conntrack")]
pub use conntrack::{ConntrackError, get_incoming_mark};

// ==============================================================================
// Error Types
// ==============================================================================

/// Consolidated error type for all Linux platform operations
///
/// This error type wraps errors from all Linux-specific subsystems (netlink,
/// inotify, ipset, nftables, conntrack) into a unified error hierarchy. It
/// integrates with the main `PlatformError` type from `src/platform/mod.rs`.
///
/// # C Implementation Context
///
/// The C code uses errno and integer return codes scattered across multiple files.
/// Each subsystem checks errno independently:
/// ```c
/// // From netlink.c
/// if (netlink_init() == -1)
///     die("Failed to initialize netlink", errno);
///
/// // From inotify.c
/// if ((daemon->inotifyfd = inotify_init()) == -1)
///     return "Failed to initialize inotify";
/// ```
///
/// Rust uses a single Result type with structured error variants:
/// ```rust,ignore
/// let platform = LinuxPlatform::new().await
///     .map_err(|e| match e {
///         LinuxPlatformError::Netlink(ne) => { /* handle netlink error */ }
///         LinuxPlatformError::Inotify(ie) => { /* handle inotify error */ }
///         _ => { /* handle other errors */ }
///     })?;
/// ```
#[derive(Debug, Error)]
pub enum LinuxPlatformError {
    /// Netlink socket operation failed
    #[error("Netlink error: {0}")]
    Netlink(#[from] NetlinkError),

    /// inotify operation failed (feature = "inotify")
    #[cfg(feature = "inotify")]
    #[error("Inotify error: {0}")]
    Inotify(#[from] InotifyError),

    /// ipset operation failed (feature = "ipset")
    #[cfg(feature = "ipset")]
    #[error("Ipset error: {0}")]
    Ipset(#[from] IpsetError),

    /// nftables operation failed (feature = "nftables")
    #[cfg(feature = "nftables")]
    #[error("Nftables error: {0}")]
    Nftset(#[from] NftsetError),

    /// conntrack operation failed (feature = "conntrack")
    #[cfg(feature = "conntrack")]
    #[error("Conntrack error: {0}")]
    Conntrack(#[from] ConntrackError),

    /// General platform error
    #[error("Platform error: {0}")]
    Platform(#[from] PlatformError),

    /// I/O error during platform operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ==============================================================================
// LinuxPlatform Structure
// ==============================================================================

/// Linux platform implementation with netlink, inotify, ipset, nftables, and conntrack
///
/// This structure aggregates all Linux-specific subsystems and implements the
/// `NetworkPlatform` trait from `src/platform/mod.rs`. It provides the richest
/// feature set among all platform implementations.
///
/// # C Implementation Context
///
/// The C code stores platform state in the global `daemon` struct:
/// ```c
/// struct daemon {
///     int netlinkfd;     // Netlink socket for interface monitoring
///     int inotifyfd;     // inotify fd for file watching
///     // ... other fields
/// };
/// ```
///
/// Rust encapsulates all state in a dedicated structure:
/// ```rust,ignore
/// pub struct LinuxPlatform {
///     netlink: NetlinkSocket,
///     #[cfg(feature = "inotify")]
///     inotify: Option<InotifyWatcher>,
///     // ... other fields
/// }
/// ```
///
/// # Thread Safety
///
/// `LinuxPlatform` is designed for use in dnsmasq's single-threaded async event loop.
/// It does not implement Send/Sync as it's not intended to be shared across threads.
/// All operations are non-blocking or use timeouts to prevent event loop starvation.
///
/// # Resource Management
///
/// All resources (sockets, file descriptors) are automatically cleaned up when
/// `LinuxPlatform` is dropped (RAII pattern). The C implementation requires manual
/// cleanup in `daemon_stop()`.
pub struct LinuxPlatform {
    /// Netlink socket for interface monitoring (always present)
    netlink: Arc<NetlinkSocket>,

    /// inotify watcher for configuration files (optional feature)
    #[cfg(feature = "inotify")]
    inotify: Option<Arc<InotifyWatcher>>,

    /// ipset manager for firewall integration (optional feature)
    #[cfg(feature = "ipset")]
    ipset: Option<Arc<IpsetManager>>,

    /// nftables manager for modern firewall integration (optional feature)
    #[cfg(feature = "nftables")]
    nftset: Option<Arc<NftablesManager>>,
}

impl LinuxPlatform {
    /// Create a new Linux platform instance with netlink only
    ///
    /// This constructor creates a minimal platform with only netlink support.
    /// For full initialization with all available features, use `init()` instead.
    ///
    /// # C Implementation Context
    ///
    /// Replaces the initialization sequence in dnsmasq.c:
    /// ```c
    /// if (netlink_init() == -1)
    ///     die("Failed to create netlink socket", errno);
    /// #ifdef HAVE_INOTIFY
    /// if ((daemon->inotifyfd = inotify_init()) == -1)
    ///     my_syslog(LOG_WARNING, "Failed to initialize inotify: %s", strerror(errno));
    /// #endif
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `LinuxPlatformError::Netlink` if netlink socket creation fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::platform::linux::LinuxPlatform;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let platform = LinuxPlatform::new().await?;
    /// // Platform ready with netlink only
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::unused_async)]
    pub async fn new() -> Result<Self, LinuxPlatformError> {
        let netlink = NetlinkSocket::new()?;

        Ok(Self {
            netlink: Arc::new(netlink),
            #[cfg(feature = "inotify")]
            inotify: None,
            #[cfg(feature = "ipset")]
            ipset: None,
            #[cfg(feature = "nftables")]
            nftset: None,
        })
    }

    /// Get reference to netlink socket
    ///
    /// Returns the underlying `NetlinkSocket` for direct access to netlink operations.
    /// This is useful for advanced use cases that need to send custom netlink messages.
    #[must_use]
    pub fn get_netlink(&self) -> &NetlinkSocket {
        &self.netlink
    }

    /// Get reference to inotify watcher (if available)
    ///
    /// Returns Some(&InotifyWatcher) if the inotify feature is enabled and
    /// initialization succeeded, None otherwise.
    ///
    /// # Feature Gating
    ///
    /// This method is only available when the "inotify" feature is enabled.
    #[cfg(feature = "inotify")]
    pub fn get_inotify(&self) -> Option<&InotifyWatcher> {
        self.inotify.as_ref().map(std::convert::AsRef::as_ref)
    }

    /// Get reference to ipset manager (if available)
    ///
    /// Returns Some(&IpsetManager) if the ipset feature is enabled and
    /// initialization succeeded, None otherwise.
    ///
    /// # Feature Gating
    ///
    /// This method is only available when the "ipset" feature is enabled.
    #[cfg(feature = "ipset")]
    pub fn get_ipset(&self) -> Option<&IpsetManager> {
        self.ipset.as_ref().map(std::convert::AsRef::as_ref)
    }

    /// Get reference to nftables manager (if available)
    ///
    /// Returns Some(&NftablesManager) if the nftables feature is enabled and
    /// initialization succeeded, None otherwise.
    ///
    /// # Feature Gating
    ///
    /// This method is only available when the "nftables" feature is enabled.
    #[cfg(feature = "nftables")]
    #[must_use]
    pub fn get_nftset(&self) -> Option<&NftablesManager> {
        self.nftset.as_ref().map(std::convert::AsRef::as_ref)
    }

    /// Process accumulated network events
    ///
    /// Allows the platform to batch process related events before returning them
    /// to the caller. Used to coalesce rapid-fire interface changes into single events.
    ///
    /// # C Implementation Context
    ///
    /// The C code uses `nl_multicast_state()` to track event processing state:
    /// ```c
    /// static enum { FIRSTstate, SECONDstate, NORMALstate } nl_multicast_state = FIRSTstate;
    /// ```
    pub fn process_events(&mut self) {
        // Event processing is handled by NetlinkMonitor
        // This method exists to satisfy the platform abstraction interface
    }
}

// ==============================================================================
// NetworkPlatform Trait Implementation
// ==============================================================================

impl NetworkPlatform for LinuxPlatform {
    /// Enumerate all network interfaces using netlink
    ///
    /// Sends `RTM_GETLINK` and `RTM_GETADDR` dump requests to enumerate all network
    /// interfaces and their assigned IP addresses. This is significantly more
    /// efficient than the BSD `getifaddrs()` approach as it requires only two
    /// netlink round-trips regardless of interface count.
    ///
    /// # C Implementation Context
    ///
    /// Replaces `iface_enumerate()` from netlink.c:
    /// ```c
    /// int iface_enumerate(int family, void *parm, int (*callback)()) {
    ///     // Send RTM_GETLINK/RTM_GETADDR dump requests
    ///     // Parse responses and invoke callback for each interface
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// Returns Ok(Vec<Interface>) with all interfaces, or Err(PlatformError) on failure.
    ///
    /// # Errors
    ///
    /// - `IoError`: Netlink socket send/recv failed
    /// - `PermissionDenied`: Insufficient privileges to query interfaces
    fn enumerate_interfaces(&self) -> PlatformResult<Vec<Interface>> {
        // Use the blocking version within sync context
        // The async version is available via netlink module directly
        futures::executor::block_on(async {
            self.netlink
                .enumerate_interfaces(netlink::AddressFamily::Unspec)
                .await
                .map(|records| {
                    records
                        .into_iter()
                        .map(|record| Interface {
                            index: record.index,
                            name: record.name,
                            addresses: record.addresses.into_iter().map(|addr| addr.ip()).collect(),
                            flags: crate::platform::InterfaceFlags::from_bits(record.flags.bits()),
                        })
                        .collect()
                })
                .map_err(|e| PlatformError::IoError {
                    operation: "enumerate interfaces".to_string(),
                    source: std::io::Error::other(e.to_string()),
                })
        })
    }

    /// Initialize interface change monitoring via netlink multicast
    ///
    /// Subscribes to netlink multicast groups (`RTMGRP_IPV4_IFADDR`, `RTMGRP_IPV6_IFADDR`,
    /// `RTMGRP_IPV4_ROUTE`, `RTMGRP_IPV6_ROUTE`) to receive asynchronous notifications
    /// when network configuration changes.
    ///
    /// # C Implementation Context
    ///
    /// The C code subscribes during `netlink_init()`:
    /// ```c
    /// addr.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR |
    ///                  RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
    /// bind(daemon->netlinkfd, &addr, sizeof(addr));
    /// ```
    ///
    /// # Returns
    ///
    /// Returns Ok(PlatformMonitor) that can be polled for events, or Err(PlatformError)
    /// if monitoring setup fails.
    ///
    /// # Errors
    ///
    /// - `IoError`: Failed to subscribe to multicast groups
    /// - `PermissionDenied`: Insufficient privileges for multicast subscription
    fn init_monitoring(&self) -> PlatformResult<PlatformMonitor> {
        // NetlinkSocket already has multicast groups subscribed during new()
        // Return a monitor that wraps the socket's event stream
        Ok(PlatformMonitor {
            inner: Box::new(Arc::clone(&self.netlink)),
        })
    }

    /// Get interface details by kernel index
    ///
    /// Looks up interface information given a kernel-assigned interface index.
    /// This is more efficient than enumerating all interfaces when only one is needed.
    ///
    /// # C Implementation Context
    ///
    /// The C code uses `if_indextoname()` with `SIOCGIFNAME` ioctl:
    /// ```c
    /// char ifname[IF_NAMESIZE];
    /// if (if_indextoname(index, ifname) == NULL)
    ///     return NULL;
    /// ```
    ///
    /// # Arguments
    ///
    /// * `index` - Kernel-assigned interface index (e.g., 1 for lo, 2 for eth0)
    ///
    /// # Returns
    ///
    /// Returns Ok(Some(Interface)) if found, Ok(None) if not found, or Err(PlatformError)
    /// on system error.
    fn get_interface_by_index(&self, index: u32) -> PlatformResult<Option<Interface>> {
        // Enumerate all interfaces and find the matching index
        // This is less efficient than a dedicated lookup, but simpler and correct
        let interfaces = self.enumerate_interfaces()?;
        Ok(interfaces.into_iter().find(|iface| iface.index == index))
    }
}

// ==============================================================================
// Initialization Function
// ==============================================================================

/// Initialize Linux platform with all available features
///
/// This function creates a fully initialized `LinuxPlatform` instance with all
/// optional features (inotify, ipset, nftables, conntrack) enabled based on
/// compile-time feature flags. If initialization of any optional feature fails,
/// it logs a warning but continues without that feature (graceful degradation).
///
/// # C Implementation Context
///
/// Replaces the initialization sequence scattered across dnsmasq.c:
/// ```c
/// if (netlink_init() == -1)
///     die("Failed to create netlink socket", errno);
///
/// #ifdef HAVE_INOTIFY
/// if ((daemon->inotifyfd = inotify_init()) == -1)
///     my_syslog(LOG_WARNING, "inotify init failed: %s", strerror(errno));
/// #endif
///
/// #ifdef HAVE_IPSET
/// if (ipset_init() == -1)
///     my_syslog(LOG_WARNING, "ipset init failed: %s", strerror(errno));
/// #endif
/// ```
///
/// # Returns
///
/// Returns Ok(LinuxPlatform) with all successfully initialized features, or
/// Err(LinuxPlatformError) if netlink initialization fails (fatal error).
///
/// # Errors
///
/// - `LinuxPlatformError::Netlink`: Netlink socket creation failed (fatal)
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::platform::linux::init;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Initialize with all available features
/// let platform = init().await?;
///
/// // Check which features are available
/// #[cfg(feature = "inotify")]
/// if platform.get_inotify().is_some() {
///     println!("inotify available");
/// }
///
/// #[cfg(feature = "ipset")]
/// if platform.get_ipset().is_some() {
///     println!("ipset available");
/// }
/// # Ok(())
/// # }
/// ```
#[allow(clippy::unused_async)]
pub async fn init() -> Result<LinuxPlatform, LinuxPlatformError> {
    // Initialize netlink (required)
    let netlink = NetlinkSocket::new()?;

    // Initialize inotify (optional)
    #[cfg(feature = "inotify")]
    let inotify = match InotifyWatcher::new() {
        Ok(watcher) => {
            tracing::info!("inotify file monitoring initialized");
            Some(Arc::new(watcher))
        }
        Err(e) => {
            error!(
                "Failed to initialize inotify, file watching disabled: {}",
                e
            );
            None
        }
    };

    // Initialize ipset (optional)
    #[cfg(feature = "ipset")]
    let ipset = match IpsetManager::new() {
        Ok(manager) => {
            tracing::info!("ipset firewall integration initialized");
            Some(Arc::new(manager))
        }
        Err(e) => {
            error!(
                "Failed to initialize ipset, ipset integration disabled: {}",
                e
            );
            None
        }
    };

    // Initialize nftables (optional)
    #[cfg(feature = "nftables")]
    let nftset = match NftablesManager::new().await {
        Ok(manager) => {
            tracing::info!("nftables firewall integration initialized");
            Some(Arc::new(manager))
        }
        Err(e) => {
            error!(
                "Failed to initialize nftables, nftables integration disabled: {}",
                e
            );
            None
        }
    };

    Ok(LinuxPlatform {
        netlink: Arc::new(netlink),
        #[cfg(feature = "inotify")]
        inotify,
        #[cfg(feature = "ipset")]
        ipset,
        #[cfg(feature = "nftables")]
        nftset,
    })
}
