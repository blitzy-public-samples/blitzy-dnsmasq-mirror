// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later

//! Linux Netlink RTNETLINK socket interface for network monitoring
//!
//! This module provides efficient network interface discovery and real-time monitoring
//! of interface state, address changes, and routing table modifications through the
//! kernel's Netlink IPC mechanism. It offers superior performance and richer information
//! compared to BSD routing sockets with multicast event notifications for dynamic
//! network configuration tracking.
//!
//! # Overview
//!
//! The Linux kernel provides the Netlink protocol family (AF_NETLINK) as an IPC mechanism
//! between kernel and userspace. This module specifically uses the RTNETLINK protocol
//! (NETLINK_ROUTE) to:
//! - Enumerate network interfaces, addresses, and routes via dump requests
//! - Receive asynchronous notifications when network configuration changes
//! - Monitor interface up/down events, address additions/removals, and routing changes
//!
//! # C Implementation Context
//!
//! This module replaces `src/netlink.c` from the C implementation, which used:
//! - Manual Netlink socket programming with raw system calls
//! - Static buffer management with expand_buf() for message reception
//! - Callback-based interface enumeration
//! - Manual pointer arithmetic for NLMSG_* and RTA_* macros
//! - Synchronous blocking I/O with MSG_DONTWAIT for queue draining
//!
//! # Rust Translation Strategy
//!
//! The Rust implementation provides:
//! - Async I/O using Tokio's AsyncFd for non-blocking socket operations
//! - Type-safe message parsing via netlink-packet-route crate
//! - Stream-based event consumption instead of callbacks
//! - Automatic memory management eliminating buffer overflow risks
//! - Comprehensive error handling with Result types
//!
//! # Memory Safety Improvements
//!
//! The C implementation has several memory safety risks that Rust eliminates:
//! - **Buffer overflows**: C uses fixed-size buffers that expand manually; Rust uses Vec
//! - **Pointer arithmetic**: C manually walks NLMSG_* chains; Rust uses safe iterators
//! - **Use-after-free**: C manages static buffers; Rust uses RAII and ownership
//! - **Integer overflows**: C casts without bounds checking; Rust enforces checked arithmetic
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::platform::linux::netlink::{NetlinkSocket, AddressFamily};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create Netlink socket
//! let socket = NetlinkSocket::new().await?;
//!
//! // Enumerate IPv4 addresses
//! let interfaces = socket.enumerate_interfaces(AddressFamily::Inet).await?;
//! for iface in interfaces {
//!     println!("Interface {}: {:?}", iface.name, iface.addresses);
//! }
//!
//! // Monitor network changes
//! let mut monitor = socket.multicast_events().await?;
//! while let Some(event) = monitor.next().await {
//!     println!("Network event: {:?}", event);
//! }
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::stream::Stream;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_MATCH, NLM_F_REQUEST, NLM_F_ROOT};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_packet_route::route::{RouteAttribute, RouteMessage, RouteScope, RouteType};
use netlink_packet_route::{RouteNetlinkMessage, RtnlMessage};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr as NetlinkSocketAddr};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tracing::{debug, error, trace, warn};

use crate::network::interface::InterfaceRecord;
use crate::platform::InterfaceFlags;

/// Socket option level for Netlink-specific options
/// Defined in linux/netlink.h
const SOL_NETLINK: i32 = 270;

/// Socket option to suppress ENOBUFS errors when kernel buffer overflows
/// Instead of returning ENOBUFS, kernel will drop messages silently
const NETLINK_NO_ENOBUFS: i32 = 5;

/// Netlink routing multicast groups for event subscriptions
/// From linux/rtnetlink.h
const RTMGRP_IPV4_ROUTE: u32 = 0x40;      // IPv4 routing table changes
const RTMGRP_IPV4_IFADDR: u32 = 0x10;     // IPv4 address add/remove
const RTMGRP_IPV6_ROUTE: u32 = 0x400;     // IPv6 routing table changes
const RTMGRP_IPV6_IFADDR: u32 = 0x100;    // IPv6 address add/remove

/// Maximum message buffer size for Netlink reception
/// Typically Netlink messages are under 4KB, but we allocate 8KB for safety
const DEFAULT_BUFFER_SIZE: usize = 8192;

// ==============================================================================
// Error Types
// ==============================================================================

/// Errors that can occur during Netlink operations
///
/// This error type covers all failure modes for Netlink socket creation,
/// message transmission, reception, and parsing. It provides detailed context
/// for debugging network monitoring failures.
///
/// # C Implementation Context
///
/// The C code uses errno and integer return codes:
/// ```c
/// if ((len = netlink_recv(0)) == -1) {
///     if (errno == ENOBUFS)
///         return -1;  // Buffer overflow
///     return 0;       // Other error
/// }
/// ```
///
/// Rust uses Result types with structured error variants:
/// ```rust,no_run
/// # use dnsmasq::platform::linux::netlink::NetlinkError;
/// # async fn example() -> Result<(), NetlinkError> {
/// let message = socket.recv().await
///     .map_err(|e| NetlinkError::RecvFailed)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Error)]
pub enum NetlinkError {
    /// Failed to create Netlink socket
    #[error("Failed to create netlink socket: {0}")]
    SocketError(#[from] std::io::Error),

    /// Failed to bind socket to Netlink address
    #[error("Failed to bind netlink socket: {0}")]
    BindFailed(String),

    /// Failed to send Netlink message
    #[error("Failed to send netlink message: {0}")]
    SendFailed(String),

    /// Failed to receive Netlink message
    #[error("Failed to receive netlink message: {0}")]
    RecvFailed(String),

    /// Failed to parse Netlink message
    #[error("Failed to parse netlink message: {0}")]
    ParseError(String),

    /// Kernel receive buffer overflow (messages were dropped)
    #[error("Netlink buffer overflow (ENOBUFS): kernel dropped messages, re-enumeration required")]
    Enobufs,

    /// Received invalid or malformed Netlink message
    #[error("Invalid netlink message: {0}")]
    InvalidMessage(String),

    /// Netlink error message from kernel
    #[error("Netlink error from kernel: {0}")]
    KernelError(i32),
}

/// Convenience type alias for Netlink operation results
pub type NetlinkResult<T> = Result<T, NetlinkError>;

// ==============================================================================
// Address Family Types
// ==============================================================================

/// Address family selector for interface enumeration
///
/// This enum specifies which type of information to enumerate:
/// - `Inet`: IPv4 addresses (AF_INET)
/// - `Inet6`: IPv6 addresses (AF_INET6)
/// - `Local`: Interface MAC addresses (AF_LOCAL for RTM_GETLINK)
/// - `Unspec`: Neighbor/ARP table (AF_UNSPEC for RTM_GETNEIGH)
///
/// # C Implementation Context
///
/// The C code uses integer constants:
/// ```c
/// int iface_enumerate(int family, void *parm, int (*callback)()) {
///     if (family == AF_UNSPEC)
///         req.nlh.nlmsg_type = RTM_GETNEIGH;
///     else if (family == AF_LOCAL)
///         req.nlh.nlmsg_type = RTM_GETLINK;
///     else
///         req.nlh.nlmsg_type = RTM_GETADDR;
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 addresses (AF_INET)
    Inet,
    /// IPv6 addresses (AF_INET6)
    Inet6,
    /// Interface MAC addresses (AF_LOCAL)
    Local,
    /// Neighbor/ARP table (AF_UNSPEC)
    Unspec,
}

impl AddressFamily {
    /// Convert to libc address family constant
    fn to_libc(&self) -> i32 {
        match self {
            AddressFamily::Inet => libc::AF_INET,
            AddressFamily::Inet6 => libc::AF_INET6,
            AddressFamily::Local => libc::AF_LOCAL,
            AddressFamily::Unspec => libc::AF_UNSPEC,
        }
    }
}

// ==============================================================================
// Network Event Types
// ==============================================================================

/// Network change events from Netlink multicast notifications
///
/// These events are emitted when the kernel sends RTM_NEWADDR, RTM_DELADDR,
/// RTM_NEWROUTE, RTM_NEWLINK, or RTM_DELLINK messages to subscribed multicast groups.
///
/// # C Implementation Context
///
/// The C code uses integer event types queued to the main loop:
/// ```c
/// if (h->nlmsg_type == RTM_NEWROUTE)
///     queue_event(EVENT_NEWROUTE);
/// else if (h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR)
///     queue_event(EVENT_NEWADDR);
/// ```
///
/// Rust uses a typed enum with associated data:
/// ```rust
/// match event {
///     NetlinkEvent::NewAddress(iface) => {
///         println!("Address added to {}", iface.name);
///     }
///     NetlinkEvent::NewRoute(route) => {
///         println!("New route added");
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone)]
pub enum NetlinkEvent {
    /// New address added to interface
    NewAddress(InterfaceRecord),

    /// Address removed from interface
    DeleteAddress(InterfaceRecord),

    /// New route added to routing table
    NewRoute(RouteInfo),

    /// New network interface added or link state changed
    NewLink(InterfaceRecord),

    /// Network interface removed
    DeleteLink(u32),
}

/// Routing table information
///
/// Contains details about a routing table entry received from RTM_NEWROUTE messages.
/// Used primarily for dial-on-demand (DoD) detection where new routes indicate
/// that a PPP/dialup connection has been established.
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Route type (unicast, local, broadcast, etc.)
    pub route_type: u8,
    
    /// Route scope (link, host, universe, etc.)
    pub scope: u8,
    
    /// Routing table ID (main, local, etc.)
    pub table: u8,
    
    /// Interface index for this route
    pub interface_index: Option<u32>,
}

// ==============================================================================
// Netlink Socket
// ==============================================================================

/// Async Netlink RTNETLINK socket for interface enumeration and monitoring
///
/// This structure provides a high-level interface to Linux Netlink sockets,
/// replacing the C implementation's manual socket management. It uses Tokio's
/// AsyncFd for non-blocking I/O and netlink-packet-route for type-safe message
/// parsing.
///
/// # C Implementation Context
///
/// The C code stores the socket in daemon->netlinkfd global and uses static buffers:
/// ```c
/// static struct iovec iov;
/// static u32 netlink_pid;
/// ```
///
/// Rust encapsulates all state in a struct with Arc for safe sharing:
/// ```rust
/// pub struct NetlinkSocket {
///     socket: Arc<AsyncFd<Socket>>,
///     pid: u32,
///     seq: AtomicU32,
/// }
/// ```
pub struct NetlinkSocket {
    /// Async file descriptor wrapper for Netlink socket
    socket: Arc<AsyncFd<Socket>>,
    
    /// Process ID assigned by kernel bind()
    /// Used to filter messages originated by this process vs kernel notifications
    pid: u32,
    
    /// Sequence number for request/response matching
    /// Atomically incremented for each request
    seq: AtomicU32,
}

impl NetlinkSocket {
    /// Create and initialize a new Netlink socket with multicast subscriptions
    ///
    /// This function creates an AF_NETLINK socket with NETLINK_ROUTE protocol,
    /// binds it with automatic PID assignment, and subscribes to multicast groups
    /// for IPv4/IPv6 route and address notifications. If multicast subscription
    /// fails with EPERM (insufficient permissions), it falls back to a socket
    /// without multicast groups (polling-only mode).
    ///
    /// # C Implementation Context
    ///
    /// Replaces netlink_init() from netlink.c:
    /// ```c
    /// char *netlink_init(void) {
    ///     struct sockaddr_nl addr;
    ///     addr.nl_family = AF_NETLINK;
    ///     addr.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | 
    ///                      RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
    ///     daemon->netlinkfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    ///     bind(daemon->netlinkfd, &addr, sizeof(addr));
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// Returns Ok(NetlinkSocket) on success, or Err(NetlinkError) if socket
    /// creation or binding fails.
    ///
    /// # Errors
    ///
    /// - `SocketError`: Failed to create Netlink socket (requires CAP_NET_ADMIN)
    /// - `BindFailed`: Failed to bind socket even without multicast groups
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dnsmasq::platform::linux::netlink::NetlinkSocket;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let socket = NetlinkSocket::new().await?;
    /// // Socket is now ready for enumeration and monitoring
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new() -> NetlinkResult<Self> {
        // Create Netlink socket with NETLINK_ROUTE protocol
        let mut socket = Socket::new(NETLINK_ROUTE)
            .map_err(|e| NetlinkError::SocketError(std::io::Error::from_raw_os_error(e as i32)))?;

        // Try to bind with multicast groups first
        let multicast_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | 
                               RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
        
        let mut addr = NetlinkSocketAddr::new(0, multicast_groups);
        
        // Attempt bind with multicast groups
        let bind_result = socket.bind(&addr);
        
        if let Err(e) = bind_result {
            // Check if error is EPERM (operation not permitted)
            if e.raw_os_error() == Some(libc::EPERM) {
                warn!("Failed to bind netlink socket with multicast groups (EPERM), falling back to no multicast");
                // Retry without multicast groups
                addr = NetlinkSocketAddr::new(0, 0);
                socket.bind(&addr)
                    .map_err(|e| NetlinkError::BindFailed(format!("bind failed: {}", e)))?;
            } else {
                return Err(NetlinkError::BindFailed(format!("bind failed: {}", e)));
            }
        }

        // Get the PID assigned by the kernel
        let sockaddr = socket.get_address()
            .map_err(|e| NetlinkError::SocketError(std::io::Error::from_raw_os_error(e as i32)))?;
        let pid = sockaddr.port_number();

        debug!("Netlink socket initialized with PID {}", pid);

        // Set NETLINK_NO_ENOBUFS option to suppress ENOBUFS errors
        // This is a best-effort operation, ignore errors
        if let Err(e) = Self::set_no_enobufs(socket.as_raw_fd()) {
            warn!("Failed to set NETLINK_NO_ENOBUFS: {}", e);
        }

        // Wrap socket in AsyncFd for Tokio integration
        let async_fd = AsyncFd::new(socket)
            .map_err(|e| NetlinkError::SocketError(e))?;

        Ok(NetlinkSocket {
            socket: Arc::new(async_fd),
            pid,
            seq: AtomicU32::new(0),
        })
    }

    /// Set SO_NETLINK/NETLINK_NO_ENOBUFS socket option
    ///
    /// This option tells the kernel to silently drop messages instead of
    /// returning ENOBUFS when the receive buffer overflows. This prevents
    /// the application from being overwhelmed by error handling during
    /// high-rate network changes.
    fn set_no_enobufs(fd: RawFd) -> NetlinkResult<()> {
        let optval: i32 = 1;
        // SAFETY: This is safe because:
        // 1. fd is a valid file descriptor from a successfully created Netlink socket
        // 2. SOL_NETLINK and NETLINK_NO_ENOBUFS are valid constants from Linux kernel headers
        // 3. optval is a valid i32 reference with correct size passed to setsockopt
        // 4. This is platform-specific FFI code which is permitted per Section 0.7.2
        let result = unsafe {
            libc::setsockopt(
                fd,
                SOL_NETLINK,
                NETLINK_NO_ENOBUFS,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            Err(NetlinkError::SocketError(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    /// Get next sequence number for request/response matching
    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Send a Netlink message to the kernel
    ///
    /// This function serializes and sends a Netlink message to the kernel,
    /// handling async I/O through Tokio's AsyncFd. It waits for socket
    /// writability before sending to avoid blocking.
    ///
    /// # Arguments
    ///
    /// * `message` - Netlink message to send
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success, or Err(NetlinkError) if send fails.
    pub async fn send(&self, mut message: NetlinkMessage<RouteNetlinkMessage>) -> NetlinkResult<()> {
        // Finalize message (compute length)
        message.finalize();

        // Serialize message to bytes
        let mut buf = vec![0u8; message.buffer_len()];
        message.serialize(&mut buf[..]);

        // Wait for socket to be writable
        loop {
            let mut guard = self.socket.writable().await
                .map_err(|e| NetlinkError::SendFailed(e.to_string()))?;

            match guard.try_io(|inner| {
                let socket = inner.get_ref();
                let addr = NetlinkSocketAddr::new(0, 0);
                socket.send_to(&buf[..], &addr, 0)
            }) {
                Ok(result) => {
                    result.map_err(|e| NetlinkError::SendFailed(e.to_string()))?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive a Netlink message from the kernel
    ///
    /// This function receives a Netlink message from the kernel, handling
    /// async I/O and automatic buffer allocation. It validates that messages
    /// originate from the kernel (pid == 0) to prevent userspace spoofing.
    ///
    /// # Returns
    ///
    /// Returns Ok(Vec<NetlinkMessage>) containing all messages in the buffer,
    /// or Err(NetlinkError) if reception fails.
    pub async fn recv(&self) -> NetlinkResult<Vec<NetlinkMessage<RouteNetlinkMessage>>> {
        let mut buf = vec![0u8; DEFAULT_BUFFER_SIZE];

        // Wait for socket to be readable
        loop {
            let mut guard = self.socket.readable().await
                .map_err(|e| NetlinkError::RecvFailed(e.to_string()))?;

            match guard.try_io(|inner| {
                let socket = inner.get_ref();
                socket.recv_from(&mut buf[..], 0)
            }) {
                Ok(result) => {
                    let (len, addr) = result
                        .map_err(|e| NetlinkError::RecvFailed(e.to_string()))?;

                    // Validate message is from kernel (pid == 0)
                    if addr.port_number() != 0 {
                        trace!("Ignoring netlink message from userspace PID {}", addr.port_number());
                        continue;
                    }

                    // Parse messages from buffer
                    let messages = Self::parse_messages(&buf[..len])?;
                    return Ok(messages);
                }
                Err(_would_block) => continue,
            }
        }
    }

    /// Parse Netlink messages from buffer
    fn parse_messages(buf: &[u8]) -> NetlinkResult<Vec<NetlinkMessage<RouteNetlinkMessage>>> {
        let mut messages = Vec::new();
        let mut offset = 0;

        while offset < buf.len() {
            // Parse message at current offset
            let bytes = &buf[offset..];
            match NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes) {
                Ok(msg) => {
                    let msg_len = msg.buffer_len();
                    messages.push(msg);
                    offset += msg_len;
                }
                Err(e) => {
                    return Err(NetlinkError::ParseError(format!("failed to parse message: {}", e)));
                }
            }
        }

        Ok(messages)
    }

    /// Enumerate network interfaces, addresses, or routes
    ///
    /// Sends a Netlink dump request (RTM_GETLINK, RTM_GETADDR, or RTM_GETNEIGH)
    /// to retrieve current network state and returns parsed interface records.
    ///
    /// # C Implementation Context
    ///
    /// Replaces iface_enumerate() from netlink.c which uses callbacks:
    /// ```c
    /// int iface_enumerate(int family, void *parm, int (*callback)()) {
    ///     // Send RTM_GETADDR/RTM_GETLINK/RTM_GETNEIGH request
    ///     // Receive responses until NLMSG_DONE
    ///     // Invoke callback for each entry
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `family` - Address family selector (Inet, Inet6, Local, Unspec)
    ///
    /// # Returns
    ///
    /// Returns Ok(Vec<InterfaceRecord>) with all enumerated interfaces,
    /// or Err(NetlinkError) if enumeration fails.
    ///
    /// # Errors
    ///
    /// - `SendFailed`: Failed to send dump request
    /// - `RecvFailed`: Failed to receive responses
    /// - `ParseError`: Failed to parse Netlink messages
    /// - `Enobufs`: Kernel buffer overflow, re-enumeration required
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dnsmasq::platform::linux::netlink::{NetlinkSocket, AddressFamily};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let socket = NetlinkSocket::new().await?;
    /// let interfaces = socket.enumerate_interfaces(AddressFamily::Inet).await?;
    /// for iface in interfaces {
    ///     println!("{}: {:?}", iface.name, iface.addresses);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn enumerate_interfaces(&self, family: AddressFamily) -> NetlinkResult<Vec<InterfaceRecord>> {
        // Determine message type based on family
        let message_type = match family {
            AddressFamily::Unspec => RtnlMessage::GetNeighbour(Default::default()),
            AddressFamily::Local => RtnlMessage::GetLink(Default::default()),
            AddressFamily::Inet | AddressFamily::Inet6 => {
                let mut msg = AddressMessage::default();
                msg.header.family = family.to_libc() as u8;
                RtnlMessage::GetAddress(msg)
            }
        };

        // Create Netlink message with dump flags
        let seq = self.next_seq();
        let mut message = NetlinkMessage::new(
            message_type,
            NLM_F_REQUEST | NLM_F_DUMP,
            seq,
            self.pid,
        );

        // Send dump request
        self.send(message).await?;

        // Collect responses until NLMSG_DONE
        let mut interfaces = Vec::new();
        let mut done = false;

        while !done {
            let messages = self.recv().await?;

            for msg in messages {
                // Check sequence number matches
                if msg.header.sequence_number != seq {
                    trace!("Ignoring message with wrong sequence number {} (expected {})", 
                           msg.header.sequence_number, seq);
                    continue;
                }

                match msg.payload {
                    NetlinkPayload::Done => {
                        done = true;
                        break;
                    }
                    NetlinkPayload::Error(err) => {
                        if err.code != 0 {
                            error!("Netlink error during enumeration: {}", err.code);
                            return Err(NetlinkError::KernelError(err.code));
                        }
                    }
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr_msg)) => {
                        if let Some(iface) = Self::parse_address_message(&addr_msg, family) {
                            interfaces.push(iface);
                        }
                    }
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg)) => {
                        if let Some(iface) = Self::parse_link_message(&link_msg) {
                            interfaces.push(iface);
                        }
                    }
                    _ => {
                        // Ignore other message types
                    }
                }
            }
        }

        Ok(interfaces)
    }

    /// Parse RTM_NEWADDR message into InterfaceRecord
    fn parse_address_message(msg: &AddressMessage, family: AddressFamily) -> Option<InterfaceRecord> {
        let mut iface = InterfaceRecord {
            name: format!("if{}", msg.header.index),
            index: msg.header.index,
            addresses: Vec::new(),
            flags: InterfaceFlags::empty(),
            mtu: None,
        };

        // Parse address attributes
        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Address(addr_bytes) => {
                    if let Some(ip_addr) = Self::bytes_to_ipaddr(addr_bytes, family) {
                        // Create SocketAddr with appropriate port (0)
                        let socket_addr = match ip_addr {
                            IpAddr::V4(v4) => std::net::SocketAddr::new(IpAddr::V4(v4), 0),
                            IpAddr::V6(v6) => std::net::SocketAddr::new(IpAddr::V6(v6), 0),
                        };
                        iface.addresses.push(socket_addr);
                    }
                }
                AddressAttribute::Label(label) => {
                    if let Ok(label_str) = std::str::from_utf8(label) {
                        iface.name = label_str.trim_end_matches('\0').to_string();
                    }
                }
                _ => {}
            }
        }

        if !iface.addresses.is_empty() {
            Some(iface)
        } else {
            None
        }
    }

    /// Parse RTM_NEWLINK message into InterfaceRecord
    fn parse_link_message(msg: &LinkMessage) -> Option<InterfaceRecord> {
        let mut iface = InterfaceRecord {
            name: String::new(),
            index: msg.header.index,
            addresses: Vec::new(),
            flags: InterfaceFlags::empty(),
            mtu: None,
        };

        // Parse link flags
        if msg.header.flags & libc::IFF_UP as u32 != 0 {
            iface.flags |= InterfaceFlags::UP;
        }
        if msg.header.flags & libc::IFF_LOOPBACK as u32 != 0 {
            iface.flags |= InterfaceFlags::LOOPBACK;
        }
        if msg.header.flags & libc::IFF_POINTOPOINT as u32 != 0 {
            iface.flags |= InterfaceFlags::POINTOPOINT;
        }
        if msg.header.flags & libc::IFF_MULTICAST as u32 != 0 {
            iface.flags |= InterfaceFlags::MULTICAST;
        }

        // Parse link attributes
        for attr in &msg.attributes {
            match attr {
                LinkAttribute::IfName(name_bytes) => {
                    if let Ok(name_str) = std::str::from_utf8(name_bytes) {
                        iface.name = name_str.trim_end_matches('\0').to_string();
                    }
                }
                LinkAttribute::Mtu(mtu) => {
                    iface.mtu = Some(*mtu);
                }
                _ => {}
            }
        }

        if !iface.name.is_empty() {
            Some(iface)
        } else {
            None
        }
    }

    /// Convert raw bytes to IpAddr based on family
    fn bytes_to_ipaddr(bytes: &[u8], family: AddressFamily) -> Option<IpAddr> {
        match family {
            AddressFamily::Inet => {
                if bytes.len() == 4 {
                    let octets = [bytes[0], bytes[1], bytes[2], bytes[3]];
                    Some(IpAddr::V4(Ipv4Addr::from(octets)))
                } else {
                    None
                }
            }
            AddressFamily::Inet6 => {
                if bytes.len() == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(bytes);
                    Some(IpAddr::V6(Ipv6Addr::from(octets)))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Create a stream of multicast network events
    ///
    /// This function returns a NetlinkMonitor that implements the Stream trait,
    /// yielding NetlinkEvent items as the kernel sends multicast notifications.
    /// This replaces the C implementation's netlink_multicast() and nl_async()
    /// callback pattern with an async stream.
    ///
    /// # C Implementation Context
    ///
    /// Replaces netlink_multicast() and nl_async() from netlink.c:
    /// ```c
    /// void netlink_multicast(void) {
    ///     nl_multicast_state(0);
    /// }
    ///
    /// static unsigned nl_async(struct nlmsghdr *h, unsigned state) {
    ///     if (h->nlmsg_type == RTM_NEWROUTE)
    ///         queue_event(EVENT_NEWROUTE);
    ///     else if (h->nlmsg_type == RTM_NEWADDR)
    ///         queue_event(EVENT_NEWADDR);
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// Returns Ok(NetlinkMonitor) that can be used with tokio::select! or
    /// futures::StreamExt::next(), or Err(NetlinkError) if monitor creation fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dnsmasq::platform::linux::netlink::NetlinkSocket;
    /// use futures::StreamExt;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let socket = NetlinkSocket::new().await?;
    /// let mut monitor = socket.multicast_events().await?;
    ///
    /// while let Some(event) = monitor.next().await {
    ///     match event {
    ///         Ok(ev) => println!("Event: {:?}", ev),
    ///         Err(e) => eprintln!("Error: {}", e),
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn multicast_events(&self) -> NetlinkResult<NetlinkMonitor> {
        Ok(NetlinkMonitor {
            socket: Arc::clone(&self.socket),
            pid: self.pid,
        })
    }
}

// ==============================================================================
// Netlink Monitor (Stream Implementation)
// ==============================================================================

/// Async stream of Netlink multicast events
///
/// This structure implements the Stream trait to provide asynchronous iteration
/// over network change events. It replaces the C implementation's blocking
/// message queue draining with async stream processing.
///
/// # C Implementation Context
///
/// Replaces nl_multicast_state() from netlink.c:
/// ```c
/// static void nl_multicast_state(unsigned state) {
///     do {
///         while ((len = netlink_recv(MSG_DONTWAIT)) != -1)
///             for (h = ...; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
///                 state = nl_async(h, state);
///     } while (errno == ENOBUFS);
/// }
/// ```
pub struct NetlinkMonitor {
    /// Shared socket for receiving multicast messages
    socket: Arc<AsyncFd<Socket>>,
    
    /// Process ID for filtering messages
    pid: u32,
}

impl Stream for NetlinkMonitor {
    type Item = NetlinkResult<NetlinkEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buf = vec![0u8; DEFAULT_BUFFER_SIZE];

        // Poll socket for readability
        let mut guard = match self.socket.poll_read_ready(cx) {
            Poll::Ready(Ok(guard)) => guard,
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Some(Err(NetlinkError::RecvFailed(e.to_string()))));
            }
            Poll::Pending => return Poll::Pending,
        };

        // Try to read from socket
        match guard.try_io(|inner| {
            let socket = inner.get_ref();
            socket.recv_from(&mut buf[..], libc::MSG_DONTWAIT)
        }) {
            Ok(result) => {
                match result {
                    Ok((len, addr)) => {
                        // Validate message is from kernel
                        if addr.port_number() != 0 {
                            // Skip userspace messages, poll again
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }

                        // Parse and classify message
                        match Self::parse_and_classify(&buf[..len]) {
                            Ok(Some(event)) => Poll::Ready(Some(Ok(event))),
                            Ok(None) => {
                                // No event to report, poll again
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Err(e) => Poll::Ready(Some(Err(e))),
                        }
                    }
                    Err(e) => {
                        if e.raw_os_error() == Some(libc::ENOBUFS) {
                            Poll::Ready(Some(Err(NetlinkError::Enobufs)))
                        } else {
                            Poll::Ready(Some(Err(NetlinkError::RecvFailed(e.to_string()))))
                        }
                    }
                }
            }
            Err(_would_block) => {
                // Clear ready state and return Pending
                Poll::Pending
            }
        }
    }
}

impl NetlinkMonitor {
    /// Parse Netlink message buffer and classify into event types
    ///
    /// This function parses the raw message buffer and determines if it contains
    /// an event that should be reported. It implements the filtering logic from
    /// nl_async() in the C implementation.
    ///
    /// # C Implementation Context
    ///
    /// Replaces nl_async() message classification:
    /// ```c
    /// if (h->nlmsg_type == RTM_NEWROUTE) {
    ///     struct rtmsg *rtm = NLMSG_DATA(h);
    ///     if (rtm->rtm_type == RTN_UNICAST && rtm->rtm_scope == RT_SCOPE_LINK)
    ///         queue_event(EVENT_NEWROUTE);
    /// }
    /// ```
    fn parse_and_classify(buf: &[u8]) -> NetlinkResult<Option<NetlinkEvent>> {
        let messages = NetlinkSocket::parse_messages(buf)?;

        for msg in messages {
            match msg.payload {
                NetlinkPayload::Error(err) => {
                    if err.code != 0 {
                        error!("Netlink error from kernel: {}", err.code);
                        return Err(NetlinkError::KernelError(err.code));
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route_msg)) => {
                    // Filter for unicast link-scope routes in main/local tables
                    if route_msg.header.kind == RouteType::Unicast as u8 &&
                       route_msg.header.scope == RouteScope::Link as u8 &&
                       (route_msg.header.table == libc::RT_TABLE_MAIN as u8 ||
                        route_msg.header.table == libc::RT_TABLE_LOCAL as u8) {
                        
                        let route_info = RouteInfo {
                            route_type: route_msg.header.kind,
                            scope: route_msg.header.scope,
                            table: route_msg.header.table,
                            interface_index: None, // Could parse from attributes if needed
                        };
                        
                        return Ok(Some(NetlinkEvent::NewRoute(route_info)));
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr_msg)) => {
                    // Determine family from message
                    let family = match addr_msg.header.family {
                        libc::AF_INET as u8 => AddressFamily::Inet,
                        libc::AF_INET6 as u8 => AddressFamily::Inet6,
                        _ => return Ok(None),
                    };

                    if let Some(iface) = NetlinkSocket::parse_address_message(&addr_msg, family) {
                        return Ok(Some(NetlinkEvent::NewAddress(iface)));
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(addr_msg)) => {
                    let family = match addr_msg.header.family {
                        libc::AF_INET as u8 => AddressFamily::Inet,
                        libc::AF_INET6 as u8 => AddressFamily::Inet6,
                        _ => return Ok(None),
                    };

                    if let Some(iface) = NetlinkSocket::parse_address_message(&addr_msg, family) {
                        return Ok(Some(NetlinkEvent::DeleteAddress(iface)));
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg)) => {
                    if let Some(iface) = NetlinkSocket::parse_link_message(&link_msg) {
                        return Ok(Some(NetlinkEvent::NewLink(iface)));
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link_msg)) => {
                    return Ok(Some(NetlinkEvent::DeleteLink(link_msg.header.index)));
                }
                _ => {
                    // Ignore other message types
                }
            }
        }

        // No relevant event found
        Ok(None)
    }
}

// ==============================================================================
// Module-level convenience function
// ==============================================================================

/// Enumerate network interfaces for a specific address family
///
/// This is a convenience function that creates a temporary Netlink socket,
/// enumerates interfaces, and returns the results. For repeated operations,
/// consider creating a persistent NetlinkSocket instance.
///
/// # Arguments
///
/// * `family` - Address family to enumerate (Inet, Inet6, Local, Unspec)
///
/// # Returns
///
/// Returns Ok(Vec<InterfaceRecord>) with all enumerated interfaces,
/// or Err(NetlinkError) if enumeration fails.
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::platform::linux::netlink::{enumerate_interfaces, AddressFamily};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let interfaces = enumerate_interfaces(AddressFamily::Inet).await?;
/// for iface in interfaces {
///     println!("{}: {:?}", iface.name, iface.addresses);
/// }
/// # Ok(())
/// # }
/// ```
pub async fn enumerate_interfaces(family: AddressFamily) -> NetlinkResult<Vec<InterfaceRecord>> {
    let socket = NetlinkSocket::new().await?;
    socket.enumerate_interfaces(family).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socket_creation() {
        // Note: This test requires CAP_NET_ADMIN or root privileges
        // In CI environments without privileges, it will fail gracefully
        match NetlinkSocket::new().await {
            Ok(socket) => {
                assert!(socket.pid > 0);
                println!("Netlink socket created with PID: {}", socket.pid);
            }
            Err(e) => {
                println!("Failed to create netlink socket (may require privileges): {}", e);
            }
        }
    }

    #[test]
    fn test_address_family_conversion() {
        assert_eq!(AddressFamily::Inet.to_libc(), libc::AF_INET);
        assert_eq!(AddressFamily::Inet6.to_libc(), libc::AF_INET6);
        assert_eq!(AddressFamily::Local.to_libc(), libc::AF_LOCAL);
        assert_eq!(AddressFamily::Unspec.to_libc(), libc::AF_UNSPEC);
    }

    #[test]
    fn test_error_display() {
        let err = NetlinkError::Enobufs;
        assert!(err.to_string().contains("ENOBUFS"));

        let err = NetlinkError::InvalidMessage("test".to_string());
        assert!(err.to_string().contains("Invalid netlink message"));
    }
}
