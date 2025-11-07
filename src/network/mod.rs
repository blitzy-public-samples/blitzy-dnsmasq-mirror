// Copyright (c) 2000-2024 Simon Kelley & dnsmasq contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Network layer abstractions for dnsmasq-rs
//!
//! This module provides platform-agnostic networking primitives used by
//! DNS, DHCP, and TFTP subsystems. It replaces C's manual socket management
//! and poll()-based I/O with Tokio async abstractions.
//!
//! # Major Components
//!
//! - **Socket Management** ([`socket`]): Async UDP/TCP socket creation, binding
//!   strategies (wildcard, interface-specific), and socket options
//! - **Packet Buffers** ([`packet`]): Safe buffer allocation and management for
//!   protocol packet I/O
//! - **Interface Enumeration** ([`interface`]): Platform-specific interface
//!   discovery with Linux netlink, BSD getifaddrs, Solaris SIOCGLIFCONF
//! - **ARP Table Access** ([`arp`]): DHCP address conflict detection via ARP
//!   cache queries
//!
//! # Platform Support
//!
//! - **Linux**: netlink sockets, SO_BINDTODEVICE, inotify
//! - **BSD/macOS**: getifaddrs(), IP_BOUND_IF, kqueue
//! - **Solaris**: SIOCGLIFCONF, zone awareness, IPMP support
//!
//! # Examples
//!
//! ## Creating DNS listener sockets
//!
//! ```rust,no_run
//! use dnsmasq::network::{create_bound_listeners, Protocol};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let listeners = create_bound_listeners(false).await?;
//!     for listener in listeners {
//!         println!("Listening on {:?}", listener.addr);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Enumerating network interfaces
//!
//! ```rust,no_run
//! use dnsmasq::network::enumerate_interfaces;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let interfaces = enumerate_interfaces().await?;
//!     for iface in interfaces {
//!         println!("{}: {:?}", iface.name, iface.addresses);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Querying ARP cache
//!
//! ```rust,ignore
//! use dnsmasq::network::{find_mac, ArpCache};
//! use std::net::Ipv4Addr;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let arp_cache = Arc::new(RwLock::new(ArpCache::new()));
//!     let ip = Ipv4Addr::new(192, 168, 1, 100);
//!     if let Some(mac) = find_mac(arp_cache, ip.into()).await? {
//!         println!("MAC address: {}", mac);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Architecture
//!
//! The network module replaces C's synchronous, poll()-based I/O with Tokio's
//! async runtime. Key transformations:
//!
//! - `poll.c` event loop → `tokio::select!` multiplexing
//! - `recv()/send()` → `UdpSocket::recv_from()/send_to().await`
//! - Manual socket option setup → `socket2` crate abstractions
//! - Platform-specific `#ifdef` → Rust `#[cfg(...)]` conditional compilation
//!
//! # C Source Reference
//!
//! This module translates functionality from:
//! - `src/network.c` - Socket management and interface enumeration
//! - `src/arp.c` - ARP table access
//! - `src/poll.c` - Event loop (replaced by Tokio runtime)
//!
//! # Thread Safety
//!
//! All types in this module are designed for use in Tokio's multi-threaded
//! runtime. Shared state uses `Arc<RwLock<T>>` for thread-safe access.
//! The C implementation was single-threaded and not re-entrant; Rust version
//! is fully thread-safe.
//!
//! # Memory Safety
//!
//! - No manual memory management (C's malloc/free)
//! - Buffer overflows prevented by Rust's slice bounds checking
//! - No use-after-free due to ownership system
//! - No null pointer dereferences (Option types)

use thiserror::Error;

// =============================================================================
// Module Declarations
// =============================================================================

pub mod arp;
pub mod interface;
pub mod packet;
pub mod socket;

// =============================================================================
// Network-Wide Error Type
// =============================================================================

/// Network error that can originate from any submodule
///
/// This enum aggregates all network-related errors from socket, packet,
/// interface, and arp submodules into a single error type for convenience.
/// Each variant wraps the specific error type from its submodule.
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::network::{NetworkError, create_bound_listeners};
///
/// async fn example() -> Result<(), NetworkError> {
///     let listeners = create_bound_listeners(false).await
///         .map_err(NetworkError::Socket)?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Error from socket operations
    #[error(transparent)]
    Socket(#[from] socket::SocketError),

    /// Error from packet buffer operations
    #[error(transparent)]
    Packet(#[from] packet::PacketError),

    /// Error from interface enumeration operations
    #[error(transparent)]
    Interface(#[from] interface::InterfaceError),

    /// Error from ARP cache operations
    #[error(transparent)]
    Arp(#[from] arp::ArpError),
}

/// Result type for network operations
///
/// Convenience type alias for operations that can fail with any network-related error.
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::network::{Result, enumerate_interfaces, InterfaceRecord};
///
/// async fn get_interfaces() -> Result<Vec<InterfaceRecord>> {
///     Ok(enumerate_interfaces().await?)
/// }
/// ```
pub type Result<T> = std::result::Result<T, NetworkError>;

// =============================================================================
// Network Protocol Constants
// =============================================================================

/// Default DNS port (UDP and TCP)
///
/// Standard port number for DNS service as defined in RFC 1035.
/// Both UDP and TCP DNS queries use this port.
pub const DNS_PORT: u16 = 53;

/// DHCPv4 server port (UDP)
///
/// Server-side port for DHCPv4 protocol as defined in RFC 2131.
/// DHCP servers listen on this port for client requests.
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCPv4 client port (UDP)
///
/// Client-side port for DHCPv4 protocol as defined in RFC 2131.
/// DHCP clients receive responses on this port.
pub const DHCP_CLIENT_PORT: u16 = 68;

/// DHCPv6 server port (UDP)
///
/// Server-side port for DHCPv6 protocol as defined in RFC 3315.
/// DHCPv6 servers listen on this port for client messages.
pub const DHCP6_SERVER_PORT: u16 = 547;

/// DHCPv6 client port (UDP)
///
/// Client-side port for DHCPv6 protocol as defined in RFC 3315.
/// DHCPv6 clients receive responses on this port.
pub const DHCP6_CLIENT_PORT: u16 = 546;

/// TFTP port (UDP)
///
/// Standard port for Trivial File Transfer Protocol as defined in RFC 1350.
/// Used for network boot and PXE environments.
pub const TFTP_PORT: u16 = 69;

/// Number of random source port sockets for DNS queries
///
/// dnsmasq maintains a pool of UDP sockets with randomized source ports to
/// enhance security against DNS cache poisoning attacks. This constant defines
/// the pool size, matching the C implementation's behavior.
///
/// # Security Note
///
/// Source port randomization is a critical security measure. Multiple sockets
/// provide better entropy and reduce predictability of DNS query source ports.
pub const RANDOM_SOURCE_PORTS: usize = 4;

// =============================================================================
// Public Re-exports - Socket Module
// =============================================================================

// Socket types and functions
pub use socket::{
    Protocol, RandomSocketPool, SocketError, SocketListener, TcpSocketListener, bind_to_interface,
    bind_wildcard, create_bound_listeners, create_random_source_socket,
};

// =============================================================================
// Public Re-exports - Packet Module
// =============================================================================

// Packet buffer types
pub use packet::{
    PacketBuffer, PacketBufferPool, PacketError, PacketReader, PacketWriter,
    Protocol as PacketProtocol,
};

// DNSSEC buffers (feature-gated)
#[cfg(feature = "dnssec")]
pub use packet::DnssecBuffers;

// =============================================================================
// Public Re-exports - Interface Module
// =============================================================================

// Interface enumeration types
pub use interface::{
    InterfaceError, InterfaceEvent, InterfaceFlags, InterfaceRecord, enumerate_interfaces,
    index_to_name, is_interface_allowed, name_to_index, watch_interfaces,
};

// =============================================================================
// Public Re-exports - ARP Module
// =============================================================================

// ARP table access
pub use arp::{ArpCache, ArpError, ArpRecord, ArpStatus, MacAddr, find_mac};

// =============================================================================
// Prelude Module
// =============================================================================

/// Commonly used network types and functions
///
/// This prelude module provides convenient glob imports for the most frequently
/// used types and functions from the network module. Import with:
///
/// ```rust
/// use dnsmasq::network::prelude::*;
/// ```
///
/// This is equivalent to individually importing the most common items but
/// reduces boilerplate in files that use many network types.
pub mod prelude {
    pub use super::{
        InterfaceRecord, PacketBuffer, SocketListener, create_bound_listeners, enumerate_interfaces,
    };
}

// =============================================================================
// Test Utilities (feature-gated)
// =============================================================================

/// Test utilities for network module
///
/// This module re-exports test utilities from submodules when the `test-utils`
/// feature is enabled or when running tests. These utilities provide mock
/// implementations and test helpers for unit and integration testing.
///
/// # Feature Flag
///
/// Enable with:
/// ```toml
/// [dependencies]
/// dnsmasq = { version = "...", features = ["test-utils"] }
/// ```
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    pub use super::interface::tests::*;
    pub use super::socket::tests::*;
}
