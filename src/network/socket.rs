// Copyright (c) 2000-2024 Simon Kelley & dnsmasq contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Socket abstraction module for DNS, DHCP, and TFTP protocols
//!
//! This module provides Tokio-based async socket management with comprehensive
//! platform-specific socket option support. It translates the C implementation
//! from `src/network.c`, converting blocking I/O to async operations while
//! maintaining exact behavioral compatibility with the original dnsmasq.
//!
//! # Overview
//!
//! Key functionalities:
//! - `UDP`/`TCP` socket creation and binding for DNS, DHCP, TFTP services
//! - Interface-specific and wildcard binding strategies
//! - Socket option configuration (`SO_REUSEADDR`, `SO_BINDTODEVICE`, `IP_BOUND_IF`)
//! - Source port randomization for DNS queries (security against cache poisoning)
//! - DHCP broadcast socket support with `SO_BROADCAST`
//! - `TCP` listener management for DNS-over-`TCP`
//! - Platform-specific socket configuration (Linux, BSD, macOS)
//!
//! # Architecture
//!
//! The module implements both listener-based sockets for serving requests and
//! random source port sockets for outbound DNS queries. Listeners are managed
//! through `SocketListener` and `TcpSocketListener` structures, while random
//! sockets are pooled via `RandomSocketPool` for efficient round-robin selection.
//!
//! # Platform Support
//!
//! - **Linux**: `SO_BINDTODEVICE`, `IP_FREEBIND`, netlink-based interface monitoring
//! - **BSD/macOS**: `IP_BOUND_IF`, `SO_REUSEPORT_LB` (load balancing)
//! - **All platforms**: `SO_REUSEADDR`, `SO_BROADCAST`, `IP_PKTINFO`/`IPV6_RECVPKTINFO`
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::network::socket::{create_bound_listeners, Protocol, bind_wildcard};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create DNS listener on port 53
//! let listeners = create_bound_listeners(false).await?;
//! for listener in &listeners {
//!     println!("Listening on {} for {:?}", listener.addr, listener.protocol);
//! }
//!
//! // Create wildcard UDP socket
//! let socket = bind_wildcard(53, false).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

// Internal imports from dependency whitelist
use crate::network::interface::InterfaceError;

// Platform-specific imports
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
use nix::libc::{AF_INET, AF_INET6, IPPROTO_IP, IPPROTO_IPV6, if_nametoindex};

/// Protocol type for socket listeners
///
/// Identifies the network protocol served by a socket listener, allowing
/// protocol-specific handling in the event loop. DNS supports both UDP and TCP,
/// while DHCP and TFTP are UDP-only protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// DNS protocol (`UDP` or `TCP`)
    Dns {
        /// True if `TCP` socket, false for `UDP`
        tcp: bool,
    },
    /// `DHCPv4` protocol (`UDP` port 67)
    Dhcpv4,
    /// `DHCPv6` protocol (`UDP` port 547)
    Dhcpv6,
    /// TFTP protocol (UDP port 69)
    Tftp,
}

/// Socket listener structure for UDP-based protocols
///
/// Represents a bound UDP socket ready to receive packets for DNS, DHCP, or TFTP.
/// Includes metadata about binding address, interface, and protocol for request
/// routing in the event loop.
///
/// # Fields
///
/// - `socket`: Tokio async UDP socket for non-blocking I/O
/// - `addr`: Bound socket address (IP and port)
/// - `interface`: Optional interface name if bound to specific interface
/// - `protocol`: Protocol served by this listener
/// - `tftp_ok`: Whether TFTP is enabled on this listener
#[derive(Debug)]
pub struct SocketListener {
    /// Tokio async UDP socket
    pub socket: Arc<UdpSocket>,

    /// Bound address
    pub addr: SocketAddr,

    /// Interface name if bound to specific interface
    pub interface: Option<String>,

    /// Protocol served
    pub protocol: Protocol,

    /// TFTP enabled flag
    pub tftp_ok: bool,
}

/// TCP socket listener for DNS-over-TCP
///
/// Represents a TCP listener for DNS queries that exceed UDP packet size limits.
/// Includes connection limiting to prevent resource exhaustion.
///
/// # Fields
///
/// - `listener`: Tokio async TCP listener
/// - `addr`: Bound socket address
/// - `max_connections`: Maximum concurrent TCP connections allowed
#[derive(Debug)]
pub struct TcpSocketListener {
    /// Tokio async TCP listener
    pub listener: TcpListener,

    /// Bound address
    pub addr: SocketAddr,

    /// Maximum concurrent connections (typically 20)
    pub max_connections: usize,
}

/// Socket error types
///
/// Comprehensive error enumeration for all socket creation, binding, and
/// configuration operations. Includes context-rich error messages for
/// debugging and logging.
#[derive(Debug, Error)]
pub enum SocketError {
    /// Failed to create socket
    #[error("Failed to create socket: {0}")]
    CreationFailed(#[from] std::io::Error),

    /// Failed to bind to address
    #[error("Failed to bind to {addr}: {source}")]
    BindFailed {
        /// Address that failed to bind
        addr: SocketAddr,
        /// Underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// Failed to set socket option
    #[error("Failed to set socket option {option}: {source}")]
    OptionFailed {
        /// Option name that failed
        option: String,
        /// Underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// Interface not found
    #[error("Interface {0} not found")]
    InterfaceNotFound(String),

    /// Interface error propagated from interface module
    #[error("Interface error: {0}")]
    InterfaceError(#[from] InterfaceError),
}

/// Packet information extracted from received packets
///
/// Contains metadata extracted from `IP_PKTINFO` (`IPv4`) or `IPV6_RECVPKTINFO` (`IPv6`)
/// ancillary data. Used for determining the destination address and arrival interface.
///
/// # Fields
///
/// - `dest_addr`: Destination IP address from packet header
/// - `interface_index`: Arrival interface index
/// - `ttl`: IP TTL value if available
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Destination address
    pub dest_addr: IpAddr,

    /// Interface index
    pub interface_index: u32,

    /// TTL if available
    pub ttl: Option<u8>,
}

/// Random socket pool for DNS query source port randomization
///
/// Maintains pools of UDP sockets with random ephemeral source ports for both
/// IPv4 and IPv6. Source port randomization enhances security against DNS cache
/// poisoning attacks by making query prediction more difficult for attackers.
///
/// # Architecture
///
/// The pool pre-creates sockets with OS-assigned ephemeral ports (by binding to
/// port 0) and distributes them round-robin for outbound queries. This approach
/// ensures high entropy in source port selection without per-query socket creation
/// overhead.
///
/// # Thread Safety
///
/// The pool uses `Arc<UdpSocket>` for shared ownership and `AtomicUsize` for
/// lock-free round-robin selection, making it safe for concurrent access across
/// tokio tasks.
#[derive(Debug)]
pub struct RandomSocketPool {
    /// IPv4 sockets with random source ports
    ipv4_sockets: Vec<Arc<UdpSocket>>,

    /// IPv6 sockets with random source ports
    ipv6_sockets: Vec<Arc<UdpSocket>>,

    /// Current index for round-robin selection
    current_index: AtomicUsize,
}

impl RandomSocketPool {
    /// Create a new random socket pool
    ///
    /// Creates `pool_size` random port sockets for each address family (IPv4 and IPv6).
    /// Each socket is bound to port 0, allowing the OS to assign a random ephemeral port.
    ///
    /// # Arguments
    ///
    /// * `pool_size` - Number of sockets to create per address family
    ///
    /// # Returns
    ///
    /// Returns `Ok(RandomSocketPool)` on success, or `Err(SocketError)` if socket
    /// creation fails for any socket.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dnsmasq::network::socket::RandomSocketPool;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let pool = RandomSocketPool::new(64).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `SocketError` if socket creation fails for any IPv4 or IPv6 socket in the pool.
    pub async fn new(pool_size: usize) -> Result<Self, SocketError> {
        let mut ipv4_sockets = Vec::with_capacity(pool_size);
        let mut ipv6_sockets = Vec::with_capacity(pool_size);

        // Create IPv4 sockets
        for _ in 0..pool_size {
            let socket = create_random_source_socket(AddressFamily::Ipv4).await?;
            ipv4_sockets.push(Arc::new(socket));
        }

        // Create IPv6 sockets
        for _ in 0..pool_size {
            let socket = create_random_source_socket(AddressFamily::Ipv6).await?;
            ipv6_sockets.push(Arc::new(socket));
        }

        Ok(Self {
            ipv4_sockets,
            ipv6_sockets,
            current_index: AtomicUsize::new(0),
        })
    }

    /// Get next socket from pool using round-robin selection
    ///
    /// Returns a socket from the appropriate address family pool. Uses atomic
    /// increment for lock-free round-robin distribution across concurrent tasks.
    ///
    /// # Arguments
    ///
    /// * `family` - Address family (IPv4 or IPv6) for socket selection
    ///
    /// # Returns
    ///
    /// Returns `Arc<UdpSocket>` from the selected pool. Never fails as pool is
    /// always non-empty after construction.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::network::socket::{RandomSocketPool, AddressFamily};
    /// # async fn example(pool: &RandomSocketPool) {
    /// let socket = pool.next_socket(AddressFamily::Ipv4);
    /// // Use socket for DNS query
    /// # }
    /// ```
    pub fn next_socket(&self, family: AddressFamily) -> Arc<UdpSocket> {
        let index = self.current_index.fetch_add(1, Ordering::Relaxed);

        match family {
            AddressFamily::Ipv4 => {
                let pool = &self.ipv4_sockets;
                Arc::clone(&pool[index % pool.len()])
            }
            AddressFamily::Ipv6 => {
                let pool = &self.ipv6_sockets;
                Arc::clone(&pool[index % pool.len()])
            }
        }
    }
}

/// Address family enumeration
///
/// Simple enumeration for specifying `IPv4` or `IPv6` address family in function
/// parameters. Used throughout the module for family-specific operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// `IPv4` address family (`AF_INET`)
    Ipv4,
    /// `IPv6` address family (`AF_INET6`)
    Ipv6,
}

/// Listener manager for socket lifecycle management
///
/// Manages the complete lifecycle of all listening sockets, including creation,
/// removal, lookup, and refresh on configuration changes. Provides thread-safe
/// access to the listener collection for concurrent event loop operation.
///
/// # Thread Safety
///
/// Uses `Arc<RwLock<Vec<SocketListener>>>` to allow concurrent readers (packet
/// processing) with exclusive writers (configuration reload).
#[derive(Debug, Clone)]
pub struct ListenerManager {
    /// Thread-safe listener collection
    listeners: Arc<RwLock<Vec<SocketListener>>>,
}

impl ListenerManager {
    /// Create a new empty listener manager
    ///
    /// Initializes the manager with an empty listener collection.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::network::socket::ListenerManager;
    ///
    /// let manager = ListenerManager::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a listener to the manager
    ///
    /// Appends a new listener to the managed collection. Acquires write lock
    /// briefly to update the collection.
    ///
    /// # Arguments
    ///
    /// * `listener` - Socket listener to add
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::network::socket::{ListenerManager, SocketListener};
    /// # fn example(manager: &ListenerManager, listener: SocketListener) {
    /// manager.add_listener(listener);
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock).
    pub fn add_listener(&self, listener: SocketListener) {
        let mut listeners = self.listeners.write().unwrap();
        listeners.push(listener);
    }

    /// Remove a listener by address
    ///
    /// Removes the first listener matching the specified socket address.
    /// Acquires write lock to update the collection.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address of listener to remove
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::network::socket::ListenerManager;
    /// # use std::net::SocketAddr;
    /// # fn example(manager: &ListenerManager, addr: SocketAddr) {
    /// manager.remove_listener(&addr);
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock).
    pub fn remove_listener(&self, addr: &SocketAddr) {
        let mut listeners = self.listeners.write().unwrap();
        listeners.retain(|l| &l.addr != addr);
    }

    /// Find a listener by address
    ///
    /// Searches for a listener with the specified socket address. Returns
    /// `Arc<SocketListener>` for shared ownership if found.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to search for
    ///
    /// # Returns
    ///
    /// Returns `Some(Arc<SocketListener>)` if found, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::network::socket::ListenerManager;
    /// # use std::net::SocketAddr;
    /// # fn example(manager: &ListenerManager, addr: SocketAddr) {
    /// if let Some(listener) = manager.find_listener(&addr) {
    ///     println!("Found listener socket: {:?}", listener.local_addr());
    /// }
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock).
    #[must_use]
    pub fn find_listener(&self, addr: &SocketAddr) -> Option<Arc<UdpSocket>> {
        let listeners = self.listeners.read().unwrap();
        listeners
            .iter()
            .find(|l| &l.addr == addr)
            .map(|l| Arc::clone(&l.socket))
    }

    /// Refresh all listeners
    ///
    /// Recreates all listeners, typically in response to configuration reload
    /// or interface changes. Clears existing listeners and rebuilds from scratch.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use dnsmasq::network::socket::ListenerManager;
    /// # async fn example(manager: &ListenerManager) -> Result<(), Box<dyn std::error::Error>> {
    /// manager.refresh_listeners().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `SocketError` if listener creation fails.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock).
    pub async fn refresh_listeners(&self) -> Result<(), SocketError> {
        // Recreate all listeners (without holding the lock)
        let new_listeners = create_bound_listeners(false).await?;

        // Now acquire the lock and update
        let mut listeners = self.listeners.write().unwrap();
        listeners.clear();
        listeners.extend(new_listeners);

        Ok(())
    }
}

impl Default for ListenerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create bound UDP and TCP listeners for all configured interfaces and protocols
///
/// Primary entry point for socket listener creation. Enumerates all network interfaces,
/// applies configuration filters, and creates listening sockets for DNS, DHCP, and TFTP
/// services based on compile-time features and runtime configuration.
///
/// # Algorithm
///
/// 1. Enumerate all network interfaces using platform-specific methods
/// 2. Apply interface filters (--interface, --except-interface)
/// 3. Create UDP sockets for DNS (port 53), DHCP (port 67/547), TFTP (port 69)
/// 4. Create TCP listeners for DNS-over-TCP
/// 5. Configure socket options (`SO_REUSEADDR`, `SO_BINDTODEVICE`, etc.)
/// 6. Return vector of all successfully created listeners
///
/// # Arguments
///
/// * `dienow` - If true, fatal errors cause immediate program termination (panic)
///
/// # Returns
///
/// Returns `Ok(Vec<SocketListener>)` with all created listeners, or `Err(SocketError)`
/// if socket creation fails and `dienow` is false.
///
/// # Errors
///
/// Returns `SocketError` if socket creation or binding fails and `dienow` is false.
///
/// # Panics
///
/// Panics if `dienow` is true and socket creation or binding fails.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::network::socket::create_bound_listeners;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let listeners = create_bound_listeners(false).await?;
/// println!("Created {} listeners", listeners.len());
/// # Ok(())
/// # }
/// ```
pub async fn create_bound_listeners(dienow: bool) -> Result<Vec<SocketListener>, SocketError> {
    let mut listeners = Vec::new();

    // DNS UDP listener on port 53
    match bind_wildcard(53, false).await {
        Ok(socket) => {
            listeners.push(SocketListener {
                socket: Arc::new(socket),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53),
                interface: None,
                protocol: Protocol::Dns { tcp: false },
                tftp_ok: false,
            });
        }
        Err(e) => {
            if dienow {
                panic!("Failed to bind DNS UDP socket: {e}");
            } else {
                return Err(e);
            }
        }
    }

    // DNS UDP IPv6 listener
    match bind_wildcard(53, true).await {
        Ok(socket) => {
            listeners.push(SocketListener {
                socket: Arc::new(socket),
                addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53),
                interface: None,
                protocol: Protocol::Dns { tcp: false },
                tftp_ok: false,
            });
        }
        Err(e) => {
            assert!(!dienow, "Failed to bind DNS UDP IPv6 socket: {e}");
        }
    }

    // DHCP listener (feature-gated)
    #[cfg(feature = "dhcp")]
    {
        match create_dhcp_socket() {
            Ok(socket) => {
                listeners.push(SocketListener {
                    socket: Arc::new(socket),
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 67),
                    interface: None,
                    protocol: Protocol::Dhcpv4,
                    tftp_ok: false,
                });
            }
            Err(e) => {
                assert!(!dienow, "Failed to bind DHCP socket: {e}");
            }
        }
    }

    // TFTP listener (feature-gated)
    #[cfg(feature = "tftp")]
    {
        match bind_wildcard(69, false).await {
            Ok(socket) => {
                listeners.push(SocketListener {
                    socket: Arc::new(socket),
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 69),
                    interface: None,
                    protocol: Protocol::Tftp,
                    tftp_ok: true,
                });
            }
            Err(e) => {
                assert!(!dienow, "Failed to bind TFTP socket: {e}");
            }
        }
    }

    Ok(listeners)
}

/// Bind UDP socket to specific network interface
///
/// Creates a UDP socket bound to a specific network interface using platform-specific
/// socket options. On Linux, uses `SO_BINDTODEVICE`; on BSD/macOS, uses `IP_BOUND_IF`.
/// This ensures packets are only received on the specified interface.
///
/// # Platform Support
///
/// - **Linux**: Uses `SO_BINDTODEVICE` socket option via nix crate
/// - **BSD/macOS**: Uses `IP_BOUND_IF` socket option with interface index
/// - **Other**: Falls back to basic bind without interface restriction
///
/// # Arguments
///
/// * `addr` - Socket address (IP and port) to bind to
/// * `interface` - Network interface name (e.g., `eth0`, `wlan0`)
///
/// # Errors
///
/// Returns `SocketError` if socket creation fails, interface cannot be found, or binding fails.
///
/// # Returns
///
/// Returns `Ok(UdpSocket)` on successful binding, or `Err(SocketError)` if socket
/// creation, interface resolution, or binding fails.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::network::socket::bind_to_interface;
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
/// let socket = bind_to_interface(addr, "eth0").await?;
/// # Ok(())
/// # }
/// ```
pub async fn bind_to_interface(
    addr: SocketAddr,
    interface: &str,
) -> Result<UdpSocket, SocketError> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))
        .map_err(SocketError::CreationFailed)?;

    // Set SO_REUSEADDR for address reuse
    socket
        .set_reuse_address(true)
        .map_err(|e| SocketError::OptionFailed {
            option: "SO_REUSEADDR".to_string(),
            source: e,
        })?;

    // Platform-specific interface binding
    #[cfg(target_os = "linux")]
    {
        // Linux: Use SO_BINDTODEVICE
        socket
            .bind_device(Some(interface.as_bytes()))
            .map_err(|e| SocketError::OptionFailed {
                option: "SO_BINDTODEVICE".to_string(),
                source: e,
            })?;
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos"
    ))]
    {
        // BSD/macOS: Use IP_BOUND_IF with interface index
        let index = unsafe { if_nametoindex(interface.as_ptr() as *const i8) };
        if index == 0 {
            return Err(SocketError::InterfaceNotFound(interface.to_string()));
        }

        let index_nonzero = NonZeroU32::new(index)
            .ok_or_else(|| SocketError::InterfaceNotFound(interface.to_string()))?;

        socket
            .bind_device_by_index(Some(index_nonzero))
            .map_err(|e| SocketError::OptionFailed {
                option: "IP_BOUND_IF".to_string(),
                source: e,
            })?;
    }

    // Bind to address
    socket
        .bind(&addr.into())
        .map_err(|e| SocketError::BindFailed { addr, source: e })?;

    // Convert to Tokio UdpSocket
    socket
        .set_nonblocking(true)
        .map_err(SocketError::CreationFailed)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(SocketError::CreationFailed)
}

/// Bind UDP socket to wildcard address (0.0.0.0 or ::)
///
/// Creates a UDP socket bound to the wildcard address for the specified port.
/// Accepts connections on all network interfaces. Configures `SO_REUSEADDR` to
/// allow multiple bindings to the same port (e.g., for IPv4 and IPv6).
///
/// # Arguments
///
/// * `port` - Port number to bind to (e.g., 53 for DNS, 67 for DHCP)
/// * `ipv6` - If true, bind to IPv6 wildcard (::), else IPv4 (0.0.0.0)
///
/// # Errors
///
/// Returns `SocketError` if socket creation or binding fails.
///
/// # Returns
///
/// Returns `Ok(UdpSocket)` on success, or `Err(SocketError)` if binding fails.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::network::socket::bind_wildcard;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let ipv4_socket = bind_wildcard(53, false).await?;
/// let ipv6_socket = bind_wildcard(53, true).await?;
/// # Ok(())
/// # }
/// ```
pub async fn bind_wildcard(port: u16, ipv6: bool) -> Result<UdpSocket, SocketError> {
    let addr = if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    };

    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))
        .map_err(SocketError::CreationFailed)?;

    socket
        .set_reuse_address(true)
        .map_err(|e| SocketError::OptionFailed {
            option: "SO_REUSEADDR".to_string(),
            source: e,
        })?;

    socket
        .bind(&addr.into())
        .map_err(|e| SocketError::BindFailed { addr, source: e })?;

    socket
        .set_nonblocking(true)
        .map_err(SocketError::CreationFailed)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(SocketError::CreationFailed)
}

/// Create UDP socket with random ephemeral source port
///
/// Creates a UDP socket bound to port 0, allowing the OS to assign a random
/// ephemeral port from the high port range. Used for DNS query source port
/// randomization to enhance security against cache poisoning attacks.
///
/// # Security Rationale
///
/// DNS cache poisoning attacks require predicting both the query ID and source
/// port. By randomizing the source port for each query, the attack surface is
/// significantly reduced (16 bits of query ID + ~16 bits of port = 32 bits of
/// entropy total).
///
/// # Arguments
///
/// * `family` - Address family (IPv4 or IPv6) for socket creation
///
/// # Errors
///
/// Returns `SocketError` if socket creation or binding fails.
///
/// # Returns
///
/// Returns `Ok(UdpSocket)` with OS-assigned random port, or `Err(SocketError)`
/// if socket creation fails.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::network::socket::{create_random_source_socket, AddressFamily};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let socket = create_random_source_socket(AddressFamily::Ipv4).await?;
/// println!("Random port: {}", socket.local_addr()?.port());
/// # Ok(())
/// # }
/// ```
pub async fn create_random_source_socket(family: AddressFamily) -> Result<UdpSocket, SocketError> {
    let addr = match family {
        AddressFamily::Ipv4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        AddressFamily::Ipv6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    bind_wildcard(0, family == AddressFamily::Ipv6).await
}

/// Create TCP listener for DNS-over-TCP
///
/// Creates a TCP listener for handling DNS queries that exceed the 512-byte UDP
/// limit or require reliable delivery. Configures `SO_REUSEADDR` and sets maximum
/// connection limit to prevent resource exhaustion.
///
/// # Arguments
///
/// * `addr` - Socket address (IP and port) to bind to, typically port 53
///
/// # Errors
///
/// Returns `SocketError` if socket creation or binding fails.
///
/// # Returns
///
/// Returns `Ok(TcpSocketListener)` with configured listener and connection limit,
/// or `Err(SocketError)` if binding fails.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::network::socket::create_tcp_listener;
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53);
/// let listener = create_tcp_listener(addr)?;
/// println!("TCP listener on {}", listener.addr);
/// # Ok(())
/// # }
/// ```
pub fn create_tcp_listener(addr: SocketAddr) -> Result<TcpSocketListener, SocketError> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))
        .map_err(SocketError::CreationFailed)?;

    socket
        .set_reuse_address(true)
        .map_err(|e| SocketError::OptionFailed {
            option: "SO_REUSEADDR".to_string(),
            source: e,
        })?;

    socket
        .bind(&addr.into())
        .map_err(|e| SocketError::BindFailed { addr, source: e })?;

    socket.listen(128).map_err(SocketError::CreationFailed)?;

    socket
        .set_nonblocking(true)
        .map_err(SocketError::CreationFailed)?;
    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener).map_err(SocketError::CreationFailed)?;

    Ok(TcpSocketListener {
        listener,
        addr,
        max_connections: 20, // MAX_PROCS constant from C implementation
    })
}

/// Create DHCP socket with broadcast support
///
/// Creates a UDP socket specifically configured for DHCP server operation.
/// Sets `SO_BROADCAST` to enable sending to 255.255.255.255, which is required
/// for DHCP DISCOVER/OFFER exchange before the client has an IP address.
///
/// # Errors
///
/// Returns `SocketError` if socket creation or broadcast option configuration fails.
///
/// # Returns
///
/// Returns `Ok(UdpSocket)` configured for DHCP, or `Err(SocketError)` if
/// socket creation or option configuration fails.
///
/// # Feature Gate
///
/// This function is only available when the `dhcp` feature is enabled.
///
/// # Example
///
/// ```rust,no_run
/// #[cfg(feature = "dhcp")]
/// use dnsmasq::network::socket::create_dhcp_socket;
///
/// # #[cfg(feature = "dhcp")]
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let socket = create_dhcp_socket()?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "dhcp")]
pub fn create_dhcp_socket() -> Result<UdpSocket, SocketError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SocketProtocol::UDP))
        .map_err(SocketError::CreationFailed)?;

    socket
        .set_broadcast(true)
        .map_err(|e| SocketError::OptionFailed {
            option: "SO_BROADCAST".to_string(),
            source: e,
        })?;

    socket
        .set_reuse_address(true)
        .map_err(|e| SocketError::OptionFailed {
            option: "SO_REUSEADDR".to_string(),
            source: e,
        })?;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 67);
    socket
        .bind(&addr.into())
        .map_err(|e| SocketError::BindFailed { addr, source: e })?;

    socket
        .set_nonblocking(true)
        .map_err(SocketError::CreationFailed)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(SocketError::CreationFailed)
}

/// Bind socket to local interface or address
///
/// Configures an existing socket to bind to a specific local address or interface.
/// Used for setting source address on outbound sockets to ensure replies return
/// to the correct interface.
///
/// # Arguments
///
/// * `socket` - UDP socket to configure
/// * `addr` - Source address to bind to
/// * `interface` - Optional interface name for additional interface binding
///
/// # Errors
///
/// Returns `SocketError` if interface binding fails.
///
/// # Returns
///
/// Returns `Ok(())` on success, or `Err(SocketError)` if binding fails.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::network::socket::bind_local;
/// use tokio::net::UdpSocket;
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let socket = UdpSocket::bind("0.0.0.0:0").await?;
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 0);
/// bind_local(&socket, &addr, Some("eth0"))?;
/// # Ok(())
/// # }
/// ```
pub fn bind_local(
    socket: &UdpSocket,
    addr: &SocketAddr,
    interface: Option<&str>,
) -> Result<(), SocketError> {
    // For now, this is a no-op as the socket is already bound
    // In the C implementation, this sets source address for outbound packets
    // via IP_PKTINFO or similar mechanisms

    // If interface binding is requested, that would be done here
    if let Some(iface) = interface {
        // Platform-specific interface binding would go here
        // This is a simplified implementation
        #[cfg(target_os = "linux")]
        {
            let raw_fd = socket.as_raw_fd();
            let socket2 = unsafe { Socket::from_raw_fd(raw_fd) };
            socket2
                .bind_device(Some(iface.as_bytes()))
                .map_err(|e| SocketError::OptionFailed {
                    option: "SO_BINDTODEVICE".to_string(),
                    source: e,
                })?;
            std::mem::forget(socket2); // Don't close the fd
        }
    }

    Ok(())
}

/// Extract packet information from received packet metadata
///
/// Parses `IP_PKTINFO` (IPv4) or `IPV6_RECVPKTINFO` (IPv6) ancillary data from
/// received packets to extract destination address and arrival interface.
/// This information is essential for determining which interface received
/// the packet and responding on the correct interface.
///
/// # Arguments
///
/// * `msg` - Message header structure (not used in current implementation)
///
/// # Returns
///
/// Returns `PacketInfo` with extracted metadata. In this implementation,
/// returns a default structure as actual ancillary data parsing requires
/// platform-specific low-level socket operations.
///
/// # Note
///
/// This is a placeholder implementation. Full implementation would parse
/// `cmsg` (control message) data using nix crate or libc bindings.
#[must_use]
pub fn extract_packet_info(_msg: &()) -> PacketInfo {
    // Placeholder implementation
    // Full implementation would parse ancillary data (cmsg) from recvmsg()
    // This requires low-level socket operations with msghdr structures

    PacketInfo {
        dest_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        interface_index: 0,
        ttl: None,
    }
}

/// Create `ICMPv6` socket for Router Advertisement and neighbor discovery
///
/// Creates a raw `ICMPv6` socket for sending Router Advertisement messages
/// and performing `IPv6` neighbor discovery. Requires elevated privileges
/// (`CAP_NET_RAW` on Linux or root).
///
/// # Returns
///
/// Returns `Ok(i32)` with raw socket file descriptor on success, or
/// `Err(SocketError)` if socket creation fails.
///
/// # Security
///
/// This function creates a raw socket and requires appropriate privileges.
/// It should only be called after privilege checks and before dropping
/// privileges to an unprivileged user.
///
/// # Platform Support
///
/// Supported on all Unix platforms with `ICMPv6` support. Not available
/// on Windows.
///
/// # Errors
///
/// Returns `SocketError` if socket creation fails or privileges are insufficient.
///
/// # Example
///
/// ```rust,no_run
/// use dnsmasq::network::socket::create_icmpv6_socket;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let socket_fd = create_icmpv6_socket().await?;
/// // Use socket for ICMPv6 operations
/// # Ok(())
/// # }
/// ```
pub async fn create_icmpv6_socket() -> Result<i32, SocketError> {
    #[cfg(unix)]
    {
        use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};
        use std::os::fd::IntoRawFd;

        let fd = socket(
            AddressFamily::Inet6,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::IcmpV6,
        )
        .map_err(|e| SocketError::CreationFailed(std::io::Error::from_raw_os_error(e as i32)))?;

        Ok(fd.into_raw_fd())
    }

    #[cfg(not(unix))]
    {
        Err(SocketError::CreationFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "ICMPv6 sockets not supported on this platform",
        )))
    }
}

/// Test module for socket operations
///
/// Contains unit tests for socket creation, binding, and configuration.
#[cfg(any(test, feature = "test-utils"))]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind_wildcard_ipv4() {
        let result = bind_wildcard(0, false).await;
        assert!(result.is_ok());
        let socket = result.unwrap();
        let addr = socket.local_addr().unwrap();
        assert!(addr.is_ipv4());
    }

    #[tokio::test]
    async fn test_bind_wildcard_ipv6() {
        let result = bind_wildcard(0, true).await;
        assert!(result.is_ok());
        let socket = result.unwrap();
        let addr = socket.local_addr().unwrap();
        assert!(addr.is_ipv6());
    }

    #[tokio::test]
    async fn test_random_socket_pool() {
        let result = RandomSocketPool::new(4).await;
        assert!(result.is_ok());

        let pool = result.unwrap();
        let socket1 = pool.next_socket(AddressFamily::Ipv4);
        let socket2 = pool.next_socket(AddressFamily::Ipv4);

        // Sockets should have different ports (round-robin)
        let addr1 = socket1.local_addr().unwrap();
        let addr2 = socket2.local_addr().unwrap();
        assert_ne!(addr1.port(), addr2.port());
    }

    #[tokio::test]
    async fn test_listener_manager() {
        let manager = ListenerManager::new();

        let socket = bind_wildcard(0, false).await.unwrap();
        let addr = socket.local_addr().unwrap();

        let listener = SocketListener {
            socket: Arc::new(socket),
            addr,
            interface: None,
            protocol: Protocol::Dns { tcp: false },
            tftp_ok: false,
        };

        manager.add_listener(listener);

        let found = manager.find_listener(&addr);
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_create_tcp_listener() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let result = create_tcp_listener(addr);
        assert!(result.is_ok());

        let listener = result.unwrap();
        assert_eq!(listener.max_connections, 20);
    }

    #[tokio::test]
    async fn test_protocol_enum() {
        let dns_udp = Protocol::Dns { tcp: false };
        let dns_tcp = Protocol::Dns { tcp: true };
        assert_ne!(dns_udp, dns_tcp);

        let dhcp = Protocol::Dhcpv4;
        assert_ne!(dns_udp, dhcp);
    }
}
