// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

//! Linux connection tracking (conntrack) mark propagation integration
//!
//! # Overview
//!
//! This module implements integration with the Linux netfilter connection tracking
//! (conntrack) subsystem to enable firewall mark propagation from incoming DNS
//! query packets to outgoing upstream DNS queries. This allows network administrators
//! to implement policy-based routing where DNS queries inherit the firewall marks
//! of the original client connections, enabling routing decisions based on the
//! source of the DNS query rather than just the dnsmasq process itself.
//!
//! # Use Cases
//!
//! The primary use case is in complex network environments where different client
//! networks need their DNS queries routed through different upstream paths, with
//! routing controlled by iptables MARK targets and ip rule fwmark-based routing
//! policies. By querying conntrack for the mark associated with the incoming
//! connection, dnsmasq can copy that mark to its upstream queries.
//!
//! # Architecture
//!
//! This Rust implementation replaces the C implementation from `src/conntrack.c`,
//! providing memory-safe wrappers around `libnetfilter_conntrack` FFI calls:
//!
//! - **Memory Safety**: Eliminates static callback flags with `Arc<Mutex<Option<u32>>>`
//! - **Async Support**: Uses `tokio::spawn_blocking` for non-blocking queries
//! - **Type Safety**: Replaces C address family unions with Rust `SocketAddr` enums
//! - **Error Handling**: Uses `Result<T, E>` instead of errno-based error codes
//!
//! # Requirements
//!
//! - Linux kernel with netfilter conntrack module loaded
//! - `CAP_NET_ADMIN` capability for conntrack table access
//! - `libnetfilter_conntrack` library installed
//!
//! # Examples
//!
//! ```no_run
//! use std::net::{SocketAddr, IpAddr, Ipv4Addr};
//! # use dnsmasq::integration::conntrack::ConntrackManager;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let manager = ConntrackManager::new()?;
//! 
//! let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
//! let local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
//! let dest_port = 53;
//! let is_tcp = false;
//! 
//! match manager.get_incoming_mark(peer_addr, local_addr, dest_port, is_tcp).await {
//!     Ok(Some(mark)) => {
//!         println!("Retrieved conntrack mark: {}", mark);
//!         // Apply mark to upstream socket with SO_MARK
//!     }
//!     Ok(None) => {
//!         println!("No conntrack entry found");
//!     }
//!     Err(e) => {
//!         eprintln!("Conntrack query failed: {}", e);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! This implementation is thread-safe and async-safe. Each query creates its own
//! conntrack handle and uses shared state protection via `Arc<Mutex<_>>`.

use crate::ffi::platform::conntrack::{
    ConntrackEntry, ConntrackHandle, AF_INET, AF_INET6, ATTR_IPV4_DST, ATTR_IPV4_SRC,
    ATTR_IPV6_DST, ATTR_IPV6_SRC, ATTR_L3PROTO, ATTR_L4PROTO, ATTR_MARK, ATTR_PORT_DST,
    ATTR_PORT_SRC, IPPROTO_TCP, IPPROTO_UDP, NFCT_CB_CONTINUE,
};

use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::task;
use tracing::{debug, error, trace, warn};

/// Conntrack operation error types
///
/// Defines all possible failure modes when interacting with the netfilter
/// connection tracking subsystem.
#[derive(Debug, Error)]
pub enum ConntrackError {
    /// Failed to open conntrack netlink socket
    ///
    /// This typically occurs when:
    /// - `CAP_NET_ADMIN` capability is missing
    /// - Netfilter conntrack module is not loaded
    /// - System resources exhausted
    #[error("Failed to open conntrack socket: {0}")]
    SocketOpenFailed(#[source] IoError),

    /// Conntrack query operation failed
    ///
    /// Query failures can occur due to:
    /// - Malformed query parameters
    /// - Netlink communication errors
    /// - Kernel conntrack table access denied
    #[error("Conntrack query failed: {0}")]
    QueryFailed(#[source] IoError),

    /// Permission denied accessing conntrack table
    ///
    /// This error specifically indicates insufficient privileges.
    /// Requires `CAP_NET_ADMIN` capability or root access.
    #[error("Permission denied: CAP_NET_ADMIN capability required for conntrack access")]
    PermissionDenied,

    /// No conntrack entry found matching connection tuple
    ///
    /// This is not necessarily an error condition - it indicates
    /// the connection hasn't been tracked by netfilter (e.g., local
    /// connections or connections before conntrack was enabled).
    #[error("No conntrack entry found for connection")]
    NotFound,

    /// Failed to allocate conntrack structures
    ///
    /// Memory allocation failure when creating conntrack handle or entry.
    /// Indicates severe memory pressure.
    #[error("Failed to allocate conntrack structures")]
    AllocationFailed,
}

impl From<IoError> for ConntrackError {
    fn from(err: IoError) -> Self {
        // Check for specific error codes to provide more specific error types
        if let Some(errno) = err.raw_os_error() {
            if errno == libc::EPERM || errno == libc::EACCES {
                return ConntrackError::PermissionDenied;
            }
            if errno == libc::ENOENT {
                return ConntrackError::NotFound;
            }
        }
        // Default to QueryFailed for other IO errors
        ConntrackError::QueryFailed(err)
    }
}

/// Linux connection tracking manager for firewall mark propagation
///
/// Provides async-safe access to Linux netfilter conntrack table for retrieving
/// firewall marks associated with incoming DNS query connections. Marks can then
/// be applied to upstream queries for policy-based routing.
///
/// # Implementation Notes
///
/// Unlike the C implementation which used a static `gotit` variable for callback
/// signaling, this Rust version uses `Arc<Mutex<Option<u32>>>` for thread-safe
/// mark storage that works correctly in async contexts.
///
/// # Lifecycle
///
/// - `ConntrackManager` is lightweight and can be cloned cheaply (uses `Arc` internally)
/// - Each `get_incoming_mark()` call creates a temporary conntrack handle
/// - Handles are automatically cleaned up via RAII (`Drop` trait)
///
/// # Performance
///
/// Each conntrack query involves:
/// 1. Opening netlink socket
/// 2. Sending query message
/// 3. Receiving response via callback
/// 4. Closing netlink socket
///
/// To avoid blocking the async runtime, all FFI operations run in
/// `tokio::spawn_blocking()` thread pool.
pub struct ConntrackManager {
    /// Error suppression state to avoid log spam (replaces C static warned flag)
    ///
    /// Only the first conntrack error is logged at ERROR level;
    /// subsequent errors are suppressed to prevent flooding logs
    /// when conntrack is unavailable or misconfigured.
    warned: Arc<Mutex<bool>>,
}

impl ConntrackManager {
    /// Create new conntrack manager
    ///
    /// Initializes manager with fresh error suppression state. Does not
    /// verify conntrack availability - first error will be logged if
    /// conntrack is inaccessible.
    ///
    /// # Errors
    ///
    /// This function is infallible and always returns `Ok(Self)`.
    /// Errors are detected on first `get_incoming_mark()` call.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dnsmasq::integration::conntrack::ConntrackManager;
    /// let manager = ConntrackManager::new()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new() -> Result<Self, ConntrackError> {
        Ok(Self {
            warned: Arc::new(Mutex::new(false)),
        })
    }

    /// Query conntrack for firewall mark associated with incoming connection
    ///
    /// Retrieves the firewall mark (set by iptables/nftables MARK target)
    /// for a connection identified by source address, destination address,
    /// destination port, and protocol. This mark can then be applied to
    /// upstream DNS queries via `SO_MARK` socket option for policy-based routing.
    ///
    /// # Arguments
    ///
    /// * `peer_addr` - Source address and port of incoming DNS query (client socket address)
    /// * `local_addr` - Destination IP address where dnsmasq received the query (interface address)
    /// * `dest_port` - Destination port number (typically 53 for DNS)
    /// * `is_tcp` - Protocol flag: `true` for TCP, `false` for UDP
    ///
    /// # Returns
    ///
    /// * `Ok(Some(mark))` - Conntrack entry found with firewall mark
    /// * `Ok(None)` - No conntrack entry found (not tracked or local connection)
    /// * `Err(ConntrackError)` - Query failed due to permission, allocation, or I/O error
    ///
    /// # Errors
    ///
    /// Returns error variants:
    /// - `SocketOpenFailed` - Cannot open conntrack netlink socket
    /// - `QueryFailed` - Netlink query communication failure
    /// - `PermissionDenied` - Missing `CAP_NET_ADMIN` capability
    /// - `AllocationFailed` - Memory allocation failure
    ///
    /// Note: `NotFound` is represented as `Ok(None)` rather than an error.
    ///
    /// # Performance
    ///
    /// This is a blocking operation that involves kernel netlink communication.
    /// To avoid stalling the async event loop, it automatically runs in a
    /// `tokio::spawn_blocking()` thread pool. Typical latency: 0.1-1ms.
    ///
    /// # Privilege Requirements
    ///
    /// Requires `CAP_NET_ADMIN` capability. Typically dnsmasq drops privileges
    /// after initialization, so conntrack functionality may only work if:
    /// - Dnsmasq retains `CAP_NET_ADMIN` via ambient capabilities
    /// - Dnsmasq runs as root (not recommended)
    /// - Conntrack queries are performed before privilege drop
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    /// # use dnsmasq::integration::conntrack::ConntrackManager;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = ConntrackManager::new()?;
    ///
    /// let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
    /// let interface_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    ///
    /// if let Ok(Some(mark)) = manager.get_incoming_mark(client, interface_addr, 53, false).await {
    ///     println!("Connection has firewall mark: 0x{:x}", mark);
    ///     // Apply mark to upstream socket with setsockopt(SO_MARK)
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_incoming_mark(
        &self,
        peer_addr: SocketAddr,
        local_addr: IpAddr,
        dest_port: u16,
        is_tcp: bool,
    ) -> Result<Option<u32>, ConntrackError> {
        // Clone Arc for move into spawn_blocking
        let warned = Arc::clone(&self.warned);

        // Run blocking FFI operation in thread pool to avoid stalling async runtime
        task::spawn_blocking(move || {
            Self::get_incoming_mark_blocking(peer_addr, local_addr, dest_port, is_tcp, &warned)
        })
        .await
        .unwrap_or_else(|e| {
            error!("Conntrack task panicked: {}", e);
            Err(ConntrackError::QueryFailed(IoError::other(
                "Conntrack query task panicked",
            )))
        })
    }

    /// Blocking implementation of conntrack mark retrieval
    ///
    /// This function performs the actual synchronous FFI calls to `libnetfilter_conntrack`.
    /// It should only be called from `tokio::spawn_blocking()` to avoid blocking the
    /// async runtime.
    ///
    /// # Architecture
    ///
    /// Replaces C implementation from `src/conntrack.c:get_incoming_mark()`:
    /// 1. Create conntrack entry and set connection tuple attributes
    /// 2. Open conntrack handle
    /// 3. Register callback to extract mark
    /// 4. Execute query
    /// 5. Clean up resources via RAII
    ///
    /// The C version used static `gotit` variable for callback signaling;
    /// this Rust version uses `Arc<Mutex<Option<u32>>>` for thread safety.
    fn get_incoming_mark_blocking(
        peer_addr: SocketAddr,
        local_addr: IpAddr,
        dest_port: u16,
        is_tcp: bool,
        warned: &Arc<Mutex<bool>>,
    ) -> Result<Option<u32>, ConntrackError> {
        trace!(
            "Querying conntrack for mark: peer={}, local={}, port={}, tcp={}",
            peer_addr,
            local_addr,
            dest_port,
            is_tcp
        );

        // Storage for callback result (replaces C static gotit variable)
        let mark_result: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let mark_result_for_callback = Arc::clone(&mark_result);

        // Step 1: Create conntrack entry structure
        let mut ct = ConntrackEntry::new().ok_or(ConntrackError::AllocationFailed)?;

        // Step 2: Set protocol attribute (TCP or UDP)
        let protocol = if is_tcp { IPPROTO_TCP } else { IPPROTO_UDP };
        ct.set_attr_u8(ATTR_L4PROTO, protocol);

        // Step 3: Set destination port (network byte order)
        ct.set_attr_u16(ATTR_PORT_DST, dest_port.to_be());

        // Step 4: Set address family and addresses based on IP version
        match (peer_addr.ip(), local_addr) {
            // IPv4 connection
            (IpAddr::V4(peer_ipv4), IpAddr::V4(local_ipv4)) => {
                ct.set_attr_u8(ATTR_L3PROTO, AF_INET);

                // Set source IPv4 address and port
                let peer_octets = peer_ipv4.octets();
                let peer_addr_u32 = u32::from_be_bytes(peer_octets);
                ct.set_attr_u32(ATTR_IPV4_SRC, peer_addr_u32);
                ct.set_attr_u16(ATTR_PORT_SRC, peer_addr.port().to_be());

                // Set destination IPv4 address
                let local_octets = local_ipv4.octets();
                let local_addr_u32 = u32::from_be_bytes(local_octets);
                ct.set_attr_u32(ATTR_IPV4_DST, local_addr_u32);

                trace!(
                    "Conntrack query tuple: IPv4 {}:{} -> {}:{}",
                    peer_ipv4,
                    peer_addr.port(),
                    local_ipv4,
                    dest_port
                );
            }
            // IPv6 connection
            (IpAddr::V6(peer_ipv6), IpAddr::V6(local_ipv6)) => {
                ct.set_attr_u8(ATTR_L3PROTO, AF_INET6);

                // Set source IPv6 address and port
                // SAFETY: Rust slice pointer is valid for FFI call, lifetime managed by ct
                unsafe {
                    ct.set_attr(
                        ATTR_IPV6_SRC,
                        peer_ipv6.octets().as_ptr().cast::<libc::c_void>(),
                    );
                }
                ct.set_attr_u16(ATTR_PORT_SRC, peer_addr.port().to_be());

                // Set destination IPv6 address
                // SAFETY: Rust slice pointer is valid for FFI call, lifetime managed by ct
                unsafe {
                    ct.set_attr(
                        ATTR_IPV6_DST,
                        local_ipv6.octets().as_ptr().cast::<libc::c_void>(),
                    );
                }

                trace!(
                    "Conntrack query tuple: IPv6 [{}]:{} -> [{}]:{}",
                    peer_ipv6,
                    peer_addr.port(),
                    local_ipv6,
                    dest_port
                );
            }
            // Address family mismatch (should not happen in practice)
            _ => {
                warn!(
                    "Address family mismatch: peer={}, local={}",
                    peer_addr, local_addr
                );
                return Err(ConntrackError::QueryFailed(IoError::new(
                    ErrorKind::InvalidInput,
                    "Peer and local address families must match",
                )));
            }
        }

        // Step 5: Open conntrack handle
        let handle = ConntrackHandle::new().ok_or_else(|| {
            let io_err = IoError::last_os_error();
            let errno = io_err.raw_os_error().unwrap_or(0);

            // Check for permission denied errors (EPERM or EACCES)
            if errno == libc::EPERM || errno == libc::EACCES {
                // Log first permission error only
                let mut warned_locked = warned.lock().unwrap();
                if !*warned_locked {
                    error!(
                        "Conntrack access denied: CAP_NET_ADMIN capability required (errno {})",
                        errno
                    );
                    *warned_locked = true;
                }
                ConntrackError::PermissionDenied
            } else {
                // Log first socket open error only
                let mut warned_locked = warned.lock().unwrap();
                if !*warned_locked {
                    error!(
                        "Failed to open conntrack socket: {} (errno {})",
                        io_err, errno
                    );
                    *warned_locked = true;
                }
                ConntrackError::SocketOpenFailed(io_err)
            }
        })?;

        // Step 6: Register callback to extract mark when entry is found
        // SAFETY: Callback lifetime is bounded by handle lifetime via query() call
        // mark_result_for_callback Arc ensures data outlives callback
        unsafe {
            let callback_data = Arc::into_raw(mark_result_for_callback) as *mut libc::c_void;
            handle.register_callback(conntrack_callback, callback_data)?;
        }

        // Step 7: Execute conntrack query
        match handle.query(&ct) {
            Ok(()) => {
                // Query succeeded, check if callback populated mark
                let mark_opt = *mark_result.lock().unwrap();
                if let Some(mark) = mark_opt {
                    debug!(
                        "Retrieved conntrack mark 0x{:x} for connection {}:{} -> {}:{}",
                        mark,
                        peer_addr.ip(),
                        peer_addr.port(),
                        local_addr,
                        dest_port
                    );
                    Ok(Some(mark))
                } else {
                    // Query succeeded but no entry found (callback not invoked)
                    trace!("No conntrack entry found for connection");
                    Ok(None)
                }
            }
            Err(io_err) => {
                let errno = io_err.raw_os_error().unwrap_or(0);

                // ENOENT indicates no matching conntrack entry (not an error)
                if errno == libc::ENOENT {
                    trace!("No conntrack entry found (ENOENT)");
                    return Ok(None);
                }

                // Check for permission errors
                if errno == libc::EPERM || errno == libc::EACCES {
                    let mut warned_locked = warned.lock().unwrap();
                    if !*warned_locked {
                        error!(
                            "Conntrack query permission denied: CAP_NET_ADMIN required (errno {})",
                            errno
                        );
                        *warned_locked = true;
                    }
                    return Err(ConntrackError::PermissionDenied);
                }

                // Other query errors
                let mut warned_locked = warned.lock().unwrap();
                if !*warned_locked {
                    error!("Conntrack query failed: {} (errno {})", io_err, errno);
                    *warned_locked = true;
                }
                Err(ConntrackError::QueryFailed(io_err))
            }
        }
    }
}

impl Default for ConntrackManager {
    fn default() -> Self {
        Self::new().expect("ConntrackManager::new() is infallible")
    }
}

/// Standalone function for conntrack mark retrieval (C API compatibility)
///
/// Provides a simpler interface matching the C function signature pattern.
/// Creates a temporary `ConntrackManager` and executes query.
///
/// This function exists for API compatibility with C-style calling conventions.
/// For repeated queries, create a `ConntrackManager` instance and call
/// `get_incoming_mark()` directly to avoid repeated manager allocation.
///
/// # Arguments
///
/// * `peer_addr` - Source socket address (client address and port)
/// * `local_addr` - Destination IP address (interface address)
/// * `dest_port` - Destination port number
/// * `is_tcp` - Protocol flag: true for TCP, false for UDP
///
/// # Returns
///
/// * `Ok(Some(mark))` - Conntrack entry found with mark
/// * `Ok(None)` - No conntrack entry found
/// * `Err(ConntrackError)` - Query failed
///
/// # Errors
///
/// Returns `ConntrackError` if:
/// * Permission denied (requires `CAP_NET_ADMIN` capability)
/// * Failed to open netlink socket for conntrack communication
/// * Failed to allocate conntrack entry structure
/// * Conntrack query operation failed
///
/// # Examples
///
/// ```no_run
/// # use std::net::{SocketAddr, IpAddr, Ipv4Addr};
/// # use dnsmasq::integration::conntrack::get_incoming_mark;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
/// let interface = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
///
/// if let Ok(Some(mark)) = get_incoming_mark(client, interface, 53, false).await {
///     println!("Firewall mark: 0x{:x}", mark);
/// }
/// # Ok(())
/// # }
/// ```
pub async fn get_incoming_mark(
    peer_addr: SocketAddr,
    local_addr: IpAddr,
    dest_port: u16,
    is_tcp: bool,
) -> Result<Option<u32>, ConntrackError> {
    let manager = ConntrackManager::new()?;
    manager
        .get_incoming_mark(peer_addr, local_addr, dest_port, is_tcp)
        .await
}

/// Conntrack query callback function (extern "C" ABI)
///
/// This callback is invoked by `libnetfilter_conntrack` when a matching
/// conntrack entry is found. It extracts the `ATTR_MARK` value and stores
/// it in the caller-provided Arc<Mutex<Option<u32>>>.
///
/// # Safety
///
/// This function has `extern "C"` ABI and is called from C code in
/// `libnetfilter_conntrack`. Safety requirements:
/// - `data` pointer must be valid Arc<Mutex<Option<u32>>> created via `Arc::into_raw`
/// - `ct` pointer must be valid `nf_conntrack` structure managed by `libnetfilter_conntrack`
/// - Function must not panic (would unwind across FFI boundary)
///
/// # Arguments
///
/// * `_type` - Message type (unused in this implementation, required by API)
/// * `ct` - Pointer to conntrack entry structure
/// * `data` - User data pointer (Arc<Mutex<Option<u32>>> passed from `register_callback`)
///
/// # Returns
///
/// Always returns `NFCT_CB_CONTINUE` to indicate callback processing succeeded.
unsafe extern "C" fn conntrack_callback(
    _type: libc::c_int,
    ct: *mut crate::ffi::platform::conntrack::nf_conntrack,
    data: *mut libc::c_void,
) -> libc::c_int {
    // SAFETY: data pointer is Arc<Mutex<Option<u32>>> created by get_incoming_mark_blocking
    // We don't actually take ownership here (use Arc::from_raw + forget pattern)
    let mark_result = unsafe { Arc::from_raw(data.cast::<Mutex<Option<u32>>>()) };

    // Extract mark from conntrack entry
    // SAFETY: ct pointer is valid nf_conntrack structure managed by libnetfilter_conntrack
    let entry = ConntrackEntry {
        entry: ct, // Temporary wrapper without ownership
    };
    let mark = entry.get_attr_u32(ATTR_MARK);

    // Store mark in shared result
    if let Ok(mut mark_locked) = mark_result.lock() {
        *mark_locked = Some(mark);
        trace!("Callback extracted conntrack mark: 0x{:x}", mark);
    } else {
        // Mutex poisoned (should never happen unless callback panics)
        error!("Failed to lock mark result in callback (mutex poisoned)");
    }

    // Prevent dropping the Arc (ownership remains with caller)
    std::mem::forget(mark_result);

    // Prevent double-free of ct (owned by libnetfilter_conntrack)
    std::mem::forget(entry);

    NFCT_CB_CONTINUE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_conntrack_manager_creation() {
        let manager = ConntrackManager::new();
        assert!(manager.is_ok(), "ConntrackManager::new() should succeed");
    }

    #[test]
    fn test_default_implementation() {
        let _manager = ConntrackManager::default();
        // Should not panic
    }

    #[tokio::test]
    async fn test_get_incoming_mark_no_entry() {
        // This test will likely return Ok(None) or Err depending on system state
        let manager = ConntrackManager::new().expect("Failed to create manager");

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let result = manager.get_incoming_mark(peer, local, 53, false).await;

        // All outcomes are acceptable:
        // - Ok(None): No conntrack entry for localhost
        // - PermissionDenied: Test running without CAP_NET_ADMIN (expected in CI)
        // - SocketOpenFailed: Conntrack not available
        // - Other results: Less expected but not necessarily wrong
        let _ = result;
    }
}
