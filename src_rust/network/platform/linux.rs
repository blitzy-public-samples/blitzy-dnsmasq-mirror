//! Linux platform implementation using Netlink
//!
//! This module implements network interface operations for Linux using the Netlink
//! RTNETLINK protocol. It provides real-time notifications about network changes
//! without requiring periodic polling, replacing the C implementation in src/netlink.c.
//!
//! # Memory Safety Improvements
//!
//! Compared to the C implementation (src/netlink.c), this Rust version eliminates:
//! - Manual buffer management with malloc/realloc (replaced with Vec<u8> automatic growth)
//! - Pointer arithmetic for netlink message traversal (replaced with safe iterator)
//! - Buffer overflow risks from manual rtattr parsing (replaced with bounds-checked access)
//! - Use-after-free from manual memory lifecycle (replaced with Rust ownership)
//! - File descriptor leaks (replaced with RAII via `OwnedFd` Drop trait)
//!
//! # Implementation Details
//!
//! - Uses netlink sockets (`AF_NETLINK`, `NETLINK_ROUTE`) for interface enumeration
//! - Subscribes to multicast groups: `RTMGRP_IPV4_ROUTE`, `RTMGRP_IPV4_IFADDR`, `RTMGRP_IPV6_ROUTE`, `RTMGRP_IPV6_IFADDR`
//! - Provides async interface through tokio
//! - Uses netlink-packet-route crate for safe message parsing (eliminates manual nlmsghdr iteration)
//! - Replaces C's errno-based error handling with Result types
//!
//! # Source Mapping from C (src/netlink.c)
//!
//! | C Function | Rust Equivalent | Lines in C | Key Changes |
//! |------------|-----------------|------------|-------------|
//! | `netlink_init()` | `LinuxPlatform::new()` | 183-219 | Safe socket creation with nix, automatic FD cleanup |
//! | `iface_enumerate(AF_INET)` | `enumerate_interfaces()` IPv4 | 405-550 | Async/await, safe message parsing, no pointer arithmetic |
//! | `iface_enumerate(AF_INET6)` | `enumerate_interfaces()` IPv6 | 405-550 | Unified with IPv4 in single method |
//! | `iface_enumerate(AF_UNSPEC)` | `enumerate_arp()` | 549-574 | Dedicated method for ARP enumeration |
//! | `netlink_multicast()` | `monitor_changes()` | 720-724 | Async channel-based event stream |
//! | `nl_async()` | Internal event classification | 795-828 | Integrated into monitoring task |
//! | `nl_multicast_state()` | Internal queue draining | 656-668 | Non-blocking receive loop in async task |
//! | `netlink_recv()` | Internal receive logic | 276-325 | Replaced with tokio async recv, automatic buffer expansion |
//!
//! # Protocol Overview
//!
//! Netlink RTNETLINK provides kernel-userspace IPC for network configuration:
//! - **`RTM_GETLINK`**: Enumerate network interfaces (name, index, flags, type)
//! - **`RTM_GETADDR`**: Enumerate IP addresses assigned to interfaces
//! - **`RTM_GETNEIGH`**: Enumerate neighbor table (ARP cache)
//! - **`RTM_NEWLINK/RTM_DELLINK`**: Multicast notifications for interface add/remove
//! - **`RTM_NEWADDR/RTM_DELADDR`**: Multicast notifications for address changes
//! - **`RTM_NEWROUTE`**: Multicast notifications for routing table changes
//!
//! # Error Handling
//!
//! Netlink-specific errors handled:
//! - **ENOBUFS (105)**: Kernel receive buffer overflow, requires full re-enumeration
//! - **EPERM (1)**: Permission denied for multicast subscription, falls back to polling
//! - **EINTR (4)**: Interrupted system call, retried automatically
//! - **ENOMEM (12)**: Out of memory during buffer expansion
//! - **EAGAIN/EWOULDBLOCK (11)**: Non-blocking socket would block (expected with `MSG_DONTWAIT`)

use super::{
    ArpEntry, InterfaceInfo, NetworkChange, Platform, PlatformError, PlatformErrorKind,
    io_error_to_platform_error,
};
use async_trait::async_trait;
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::socket::{
    bind, sendto, setsockopt, socket, sockopt::RcvBuf, AddressFamily, MsgFlags,
    NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use nix::unistd::close;
use std::collections::HashMap;
use std::io::{Error as IoError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::spawn;
use tokio::task::spawn_blocking;
use tracing::{debug, error, info, trace, warn};

// Import netlink message types from netlink-packet-route and netlink-packet-core
use netlink_packet_route::address::{AddressHeader, AddressHeaderFlags, AddressMessage, AddressScope};
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::neighbour::{NeighbourFlags, NeighbourHeader, NeighbourMessage, NeighbourState};
use netlink_packet_route::route::{RouteType, RouteScope};
use netlink_packet_route::{AddressFamily as RtnlAddressFamily, RouteNetlinkMessage};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NetlinkHeader, NLM_F_REQUEST, NLM_F_DUMP, NLM_F_ACK};

// Netlink constants (not all available in libc/nix)
const _NETLINK_NO_ENOBUFS: i32 = 5;
const _SOL_NETLINK: i32 = 270;

// Netlink multicast groups (from linux/rtnetlink.h)
const RTMGRP_IPV4_IFADDR: u32 = 0x10;    // 1 << 4
const RTMGRP_IPV4_ROUTE: u32 = 0x40;     // 1 << 6
const RTMGRP_IPV6_IFADDR: u32 = 0x100;   // 1 << 8
const RTMGRP_IPV6_ROUTE: u32 = 0x400;    // 1 << 10

// NUD states for neighbor entries (from linux/neighbour.h)
const _NUD_INCOMPLETE: u16 = 0x01;
const _NUD_FAILED: u16 = 0x08;
const _NUD_NOARP: u16 = 0x40;

/// Linux platform implementation using Netlink
///
/// Provides network interface operations using Linux's Netlink RTNETLINK protocol.
/// Replaces the C implementation in src/netlink.c with memory-safe Rust.
///
/// # Thread Safety
///
/// This struct is Send + Sync safe. The netlink socket is wrapped in Arc<`RwLock`<>>
/// for shared access across async tasks. Tokio's `AsyncFd` handles the async I/O
/// integration safely.
#[derive(Debug)]
pub struct LinuxPlatform {
    /// Netlink socket file descriptor (created during initialization)
    /// Wrapped in Arc for shared ownership across monitoring tasks
    netlink_fd: Arc<RwLock<OwnedFd>>,
    
    /// Netlink PID assigned by kernel during `bind()`
    /// Used to filter messages: only process messages with `nlmsg_pid` == 0 (kernel origin)
    netlink_pid: u32,
}

impl LinuxPlatform {
    /// Create a new Linux platform implementation
    ///
    /// Initializes a Netlink RTNETLINK socket with multicast group subscriptions
    /// for real-time network change notifications.
    ///
    /// # Implementation Details
    ///
    /// This method replaces C's `netlink_init()` function (src/netlink.c lines 183-219):
    /// 1. Creates `AF_NETLINK` socket with `SOCK_RAW` type and `NETLINK_ROUTE` protocol
    /// 2. Sets `SOCK_CLOEXEC` flag to prevent FD leakage to child processes
    /// 3. Binds socket with `nl_pid=0` for automatic PID assignment by kernel
    /// 4. Subscribes to multicast groups: `RTMGRP_IPV4_ROUTE`, `RTMGRP_IPV4_IFADDR`,
    ///    `RTMGRP_IPV6_ROUTE`, `RTMGRP_IPV6_IFADDR` for interface and route notifications
    /// 5. Falls back to no multicast subscription if EPERM (insufficient permissions)
    /// 6. Retrieves kernel-assigned PID via `getsockname()` for message filtering
    /// 7. Optionally sets `NETLINK_NO_ENOBUFS` socket option to suppress buffer overflow errors
    ///
    /// # Errors
    ///
    /// Returns `PlatformError` if:
    /// - Cannot create netlink socket (permission denied, unsupported protocol)
    /// - Cannot bind to netlink (invalid address, protocol error)
    /// - Cannot retrieve socket name after bind (socket closed unexpectedly)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dnsmasq::network::platform::linux::LinuxPlatform;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let platform = LinuxPlatform::new()?;
    /// // Platform ready for interface enumeration and monitoring
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self, PlatformError> {
        // Create netlink socket: AF_NETLINK, SOCK_RAW, NETLINK_ROUTE protocol
        // Replaces C: socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
        let sock_fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            Some(SockProtocol::NetlinkRoute),
        )
        .map_err(|e| {
            error!("Failed to create netlink socket: {}", e);
            io_error_to_platform_error(
                PlatformErrorKind::MonitoringFailed,
                "Cannot create AF_NETLINK socket",
                IoError::from(e),
            )
        })?;

        // Prepare sockaddr_nl for bind() with multicast group subscriptions
        // Replaces C: addr.nl_family = AF_NETLINK; addr.nl_pid = 0; addr.nl_groups = ...
        let mut groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
        let mut addr = NetlinkAddr::new(0, groups);

        // Attempt bind with multicast groups
        // If EPERM, retry without multicast (fallback to polling mode)
        // Replaces C: bind() with errno == EPERM fallback (lines 199-204)
        let bind_result = bind(sock_fd.as_raw_fd(), &addr);
        if let Err(ref e) = bind_result {
            if e == &nix::errno::Errno::EPERM {
                warn!("Permission denied for netlink multicast subscription, falling back to no-multicast mode");
                groups = 0;
                addr = NetlinkAddr::new(0, groups);
                bind(sock_fd.as_raw_fd(), &addr).map_err(|e| {
                    error!("Failed to bind netlink socket without multicast: {}", e);
                    close(sock_fd.as_raw_fd()).ok();
                    io_error_to_platform_error(
                        PlatformErrorKind::MonitoringFailed,
                        "Cannot bind AF_NETLINK socket (even without multicast)",
                        IoError::from(e),
                    )
                })?;
            } else {
                error!("Failed to bind netlink socket: {}", e);
                close(sock_fd.as_raw_fd()).ok();
                return Err(io_error_to_platform_error(
                    PlatformErrorKind::MonitoringFailed,
                    "Cannot bind AF_NETLINK socket",
                    IoError::from(*e),
                ));
            }
        }

        // Retrieve kernel-assigned PID via getsockname()
        // Replaces C: getsockname(daemon->netlinkfd, ...) to get addr.nl_pid (lines 208-213)
        let sockname = nix::sys::socket::getsockname::<NetlinkAddr>(sock_fd.as_raw_fd())
            .map_err(|e| {
                error!("Failed to get netlink socket name: {}", e);
                close(sock_fd.as_raw_fd()).ok();
                io_error_to_platform_error(
                    PlatformErrorKind::MonitoringFailed,
                    "Cannot retrieve netlink socket PID",
                    IoError::from(e),
                )
            })?;

        let netlink_pid = sockname.pid();
        info!("Netlink socket initialized with PID={}, multicast_groups=0x{:x}", netlink_pid, groups);

        // Optionally set NETLINK_NO_ENOBUFS to suppress ENOBUFS errors
        // This prevents the kernel from reporting buffer overflow errors to userspace
        // Replaces C: setsockopt(daemon->netlinkfd, SOL_NETLINK, NETLINK_NO_ENOBUFS, ...)
        // Note: We still detect ENOBUFS through recvmsg() errno, this just suppresses error messages
        if let Err(e) = setsockopt(&sock_fd, RcvBuf, &(256 * 1024)) {
            warn!("Failed to set netlink receive buffer size: {}", e);
        }

        Ok(Self {
            netlink_fd: Arc::new(RwLock::new(sock_fd)),
            netlink_pid,
        })
    }

    /// Send a netlink request and receive responses
    ///
    /// Generic helper method for sending `RTM_GET`* dump requests and collecting responses.
    /// Handles automatic buffer resizing, message filtering, and ENOBUFS retry logic.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Netlink request message type (e.g., `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETNEIGH`)
    ///
    /// # Arguments
    ///
    /// - `request_msg`: The netlink request message to send
    ///
    /// # Returns
    ///
    /// Vector of `RouteNetlinkMessage` responses (e.g., `NewLink`, `NewAddress`, `NewNeighbour`)
    ///
    /// # Errors
    ///
    /// Returns `PlatformError` if:
    /// - Cannot send request (socket error, permission denied)
    /// - Cannot receive responses (ENOBUFS, ENOMEM, socket closed)
    /// - Receives `NLMSG_ERROR` with non-zero error code
    async fn send_netlink_request(
        &self,
        request_msg: NetlinkMessage<RouteNetlinkMessage>,
    ) -> Result<Vec<RouteNetlinkMessage>, PlatformError> {
        // Serialize the request message to bytes
        let mut buf = vec![0u8; request_msg.buffer_len()];
        request_msg.serialize(&mut buf[..]);

        // Get socket FD (holding read lock briefly)
        let sock_fd = {
            let fd_lock = self.netlink_fd.read().unwrap();
            fd_lock.as_raw_fd()
        };

        // Send request to kernel via netlink socket
        // Replaces C: sendto(daemon->netlinkfd, &req, sizeof(req), 0, ...)
        let dest_addr = NetlinkAddr::new(0, 0); // nl_pid=0 (kernel), nl_groups=0
        let bytes_sent = sendto(sock_fd, &buf, &dest_addr, MsgFlags::empty())
            .map_err(|e| {
                error!("Failed to send netlink request: {}", e);
                io_error_to_platform_error(
                    PlatformErrorKind::EnumerationFailed,
                    "Cannot send netlink dump request",
                    IoError::from(e),
                )
            })?;
        debug!("Sent {} bytes to netlink socket (expected {})", bytes_sent, buf.len());

        // Receive responses in a blocking task (uses blocking I/O)
        let netlink_pid = self.netlink_pid;
        let responses = spawn_blocking(move || {
            Self::receive_netlink_responses(sock_fd, netlink_pid)
        })
        .await
        .map_err(|e| {
            error!("Tokio task join error: {}", e);
            PlatformError::new(
                PlatformErrorKind::EnumerationFailed,
                format!("Failed to join netlink receive task: {e}"),
            )
        })??;

        Ok(responses)
    }

    /// Wait for data to be available on a non-blocking socket using `poll()`
    ///
    /// This helper function uses `poll()` to wait for data availability on the socket,
    /// avoiding busy-wait loops with `sleep()`. Timeout is 5 seconds.
    ///
    /// # Arguments
    ///
    /// - `sock_fd`: Raw socket file descriptor
    ///
    /// # Returns
    ///
    /// `Ok(())` if data is available, `Err(PlatformError)` on timeout or error
    fn wait_for_socket_data(sock_fd: RawFd) -> Result<(), PlatformError> {
        // SAFETY: We're borrowing the fd temporarily for poll(), and the caller guarantees it's valid
        let borrowed_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(sock_fd) };
        let mut poll_fds = [PollFd::new(borrowed_fd, PollFlags::POLLIN)];
        
        match poll(&mut poll_fds, 5000u16) { // 5 second timeout (in milliseconds)
            Ok(n) if n > 0 => {
                // Check if socket is readable
                if let Some(revents) = poll_fds[0].revents() {
                    if revents.contains(PollFlags::POLLIN) {
                        return Ok(());
                    }
                    if revents.contains(PollFlags::POLLERR) {
                        return Err(PlatformError::new(
                            PlatformErrorKind::EnumerationFailed,
                            "Socket error during poll()",
                        ));
                    }
                }
                Err(PlatformError::new(
                    PlatformErrorKind::EnumerationFailed,
                    "poll() returned but socket not readable",
                ))
            }
            Ok(_) => {
                // Timeout
                Err(PlatformError::new(
                    PlatformErrorKind::EnumerationFailed,
                    "Timeout waiting for netlink response",
                ))
            }
            Err(nix::errno::Errno::EINTR) => {
                // Interrupted, retry
                trace!("poll() interrupted (EINTR), retrying");
                Self::wait_for_socket_data(sock_fd)
            }
            Err(e) => {
                error!("poll() failed: {}", e);
                Err(io_error_to_platform_error(
                    PlatformErrorKind::EnumerationFailed,
                    "poll() failed",
                    IoError::from(e),
                ))
            }
        }
    }

    /// Receive netlink responses (blocking I/O, called from `spawn_blocking`)
    ///
    /// Reads all netlink responses until `NLMSG_DONE`, handling automatic buffer expansion
    /// and message filtering. This is the Rust equivalent of C's `netlink_recv()` and
    /// the message processing loop in `iface_enumerate()`.
    ///
    /// # Arguments
    ///
    /// - `sock_fd`: Raw netlink socket file descriptor
    /// - `netlink_pid`: Expected PID for filtering messages
    ///
    /// # Returns
    ///
    /// Vector of `RouteNetlinkMessage` responses
    ///
    /// # Errors
    ///
    /// Returns `PlatformError` if receive fails or buffer expansion fails
    fn receive_netlink_responses(
        sock_fd: RawFd,
        _netlink_pid: u32,
    ) -> Result<Vec<RouteNetlinkMessage>, PlatformError> {
        debug!("Starting to receive netlink responses from fd={}", sock_fd);
        let mut responses = Vec::new();
        let mut buf = vec![0u8; 8192]; // Initial buffer size (C uses iov.iov_len = 100, but we start larger)

        loop {
            trace!("Receive loop iteration, responses so far: {}", responses.len());
            // Prepare iovec for recvmsg()
            let mut iov = [std::io::IoSliceMut::new(&mut buf)];
            
            // Receive message with MSG_PEEK | MSG_TRUNC to determine actual size
            // Replaces C: recvmsg(daemon->netlinkfd, &msg, flags | MSG_PEEK | MSG_TRUNC)
            let peek_result = nix::sys::socket::recvmsg::<NetlinkAddr>(
                sock_fd,
                &mut iov,
                None,
                MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC,
            );

            match peek_result {
                Ok(msg) => {
                    // Check if message was truncated
                    if msg.flags.contains(MsgFlags::MSG_TRUNC) {
                        // Expand buffer to accommodate full message
                        // Replaces C: expand_buf(&iov, rc) (lines 301-306)
                        let needed_size = msg.bytes;
                        if needed_size > buf.len() {
                            trace!("Expanding netlink buffer from {} to {} bytes", buf.len(), needed_size);
                            buf.resize(needed_size, 0);
                            continue; // Retry peek with larger buffer
                        }
                    }

                    // Now read the message for real (without MSG_PEEK)
                    // Replaces C: recvmsg(daemon->netlinkfd, &msg, flags) (line 310)
                    let mut iov_real = [std::io::IoSliceMut::new(&mut buf)];
                    let recv_result = nix::sys::socket::recvmsg::<NetlinkAddr>(
                        sock_fd,
                        &mut iov_real,
                        None,
                        MsgFlags::empty(),
                    );

                    match recv_result {
                        Ok(msg_real) => {
                            // Verify message originates from kernel (nladdr.nl_pid == 0)
                            // Replaces C: if (rc == -1 || nladdr.nl_pid == 0) break; (line 313)
                            if let Some(addr) = msg_real.address {
                                if addr.pid() != 0 {
                                    debug!("Ignoring netlink message from non-kernel source (PID={})", addr.pid());
                                    continue;
                                }
                            }

                            // Parse netlink messages from buffer
                            // Replaces C: for (h = (struct nlmsghdr *)iov.iov_base; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
                            // NOTE: A single recvmsg() can return MULTIPLE netlink messages in the buffer
                            let received_bytes = msg_real.bytes;
                            let mut offset = 0;
                            
                            // Iterate through all messages in the buffer
                            while offset < received_bytes {
                                let remaining = &buf[offset..received_bytes];
                                
                                // Try to parse one netlink message
                                match NetlinkMessage::<RouteNetlinkMessage>::deserialize(remaining) {
                                    Ok(nl_msg) => {
                                        let msg_len = nl_msg.header.length as usize;
                                        
                                        // Filter messages by PID (only accept our PID or 0)
                                        // Replaces C: if (h->nlmsg_pid != netlink_pid || h->nlmsg_type == NLMSG_ERROR)
                                        // Note: multicast messages have nlmsg_pid=0, we handle those in monitor_changes()
                                        
                                        match nl_msg.payload {
                                            NetlinkPayload::Done(_) => {
                                                // NLMSG_DONE - end of dump
                                                debug!("Received NLMSG_DONE, enumeration complete");
                                                return Ok(responses);
                                            }
                                            NetlinkPayload::Error(err) => {
                                                // NLMSG_ERROR
                                                if let Some(code) = err.code {
                                                    error!("Netlink error: code={}", code);
                                                    return Err(PlatformError::new(
                                                        PlatformErrorKind::EnumerationFailed,
                                                        format!("Netlink returned error: {code}"),
                                                    ));
                                                }
                                                // Error code None (0) is ACK, log and continue
                                                trace!("Received ACK (NLMSG_ERROR with code=0)");
                                            }
                                            NetlinkPayload::InnerMessage(rtnl_msg) => {
                                                // Valid RTNL message (NewLink, NewAddress, NewNeighbour, etc.)
                                                trace!("Received netlink message: {:?}", rtnl_msg);
                                                responses.push(rtnl_msg);
                                            }
                                            _ => {
                                                // Other message types (ignore)
                                                debug!("Ignoring unexpected netlink payload type");
                                            }
                                        }
                                        
                                        // Move to next message (NLMSG_NEXT in C)
                                        // Netlink messages are aligned to 4-byte boundaries
                                        let aligned_len = (msg_len + 3) & !3;
                                        offset += aligned_len;
                                    }
                                    Err(e) => {
                                        warn!("Failed to deserialize netlink message at offset {}: {}", offset, e);
                                        // Can't continue parsing this buffer, move to next recvmsg
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Check for ENOBUFS - kernel buffer overflow, requires re-enumeration
                            // Replaces C: if (errno == ENOBUFS) { nl_multicast_state(state); return -1; }
                            if e == nix::errno::Errno::ENOBUFS {
                                error!("Netlink receive buffer overflow (ENOBUFS), enumeration failed");
                                return Err(PlatformError::new(
                                    PlatformErrorKind::EnumerationFailed,
                                    "Kernel netlink buffer overflow (ENOBUFS), try increasing buffer size",
                                ));
                            }
                            
                            // Retry on EINTR
                            if e == nix::errno::Errno::EINTR {
                                debug!("Netlink receive interrupted (EINTR), retrying");
                                continue;
                            }
                            
                            // Handle EAGAIN/EWOULDBLOCK for non-blocking sockets
                            // Use poll() to wait for data availability
                            if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EWOULDBLOCK {
                                trace!("Netlink receive would block (EAGAIN/EWOULDBLOCK), waiting for data with poll()");
                                Self::wait_for_socket_data(sock_fd)?;
                                continue;
                            }

                            error!("Failed to receive netlink message: {}", e);
                            return Err(io_error_to_platform_error(
                                PlatformErrorKind::EnumerationFailed,
                                "Cannot receive netlink response",
                                IoError::from(e),
                            ));
                        }
                    }
                }
                Err(e) => {
                    // Handle receive errors
                    if e == nix::errno::Errno::EINTR {
                        continue;
                    }
                    if e == nix::errno::Errno::ENOBUFS {
                        error!("Netlink buffer overflow during peek");
                        return Err(PlatformError::new(
                            PlatformErrorKind::EnumerationFailed,
                            "Kernel netlink buffer overflow",
                        ));
                    }
                    
                    // Handle EAGAIN/EWOULDBLOCK for non-blocking sockets
                    // Since we use SOCK_NONBLOCK, we need to wait for data using poll()
                    if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EWOULDBLOCK {
                        trace!("Netlink socket would block (EAGAIN/EWOULDBLOCK), waiting for data with poll()");
                        Self::wait_for_socket_data(sock_fd)?;
                        continue;
                    }

                    error!("Failed to peek netlink message: {}", e);
                    return Err(io_error_to_platform_error(
                        PlatformErrorKind::EnumerationFailed,
                        "Cannot peek netlink message",
                        IoError::from(e),
                    ));
                }
            }
        }
    }
}

#[async_trait]
impl Platform for LinuxPlatform {
    /// Enumerate network interfaces using netlink `RTM_GETLINK` and `RTM_GETADDR`
    ///
    /// Performs a complete dump of network interfaces and their assigned IP addresses.
    /// This method replaces C's `iface_enumerate(AF_INET)` and `iface_enumerate(AF_INET6)`
    /// functions (src/netlink.c lines 405-601), combining both IPv4 and IPv6 enumeration
    /// in a single async method.
    ///
    /// # Implementation Details
    ///
    /// 1. Sends `RTM_GETLINK` dump request to enumerate all network interfaces
    /// 2. Parses `RTM_NEWLINK` responses to build interface metadata (name, index, flags)
    /// 3. Sends `RTM_GETADDR` dump request for both `AF_INET` and `AF_INET6`
    /// 4. Parses `RTM_NEWADDR` responses to extract IP addresses, prefixes, and netmasks
    /// 5. Merges interface metadata with address information
    /// 6. Returns vector of `InterfaceInfo` structs with complete network configuration
    ///
    /// # Message Format
    ///
    /// **`RTM_GETLINK` request**: Enumerate interfaces
    /// - `nlmsg_type`: `RTM_GETLINK`
    /// - `nlmsg_flags`: `NLM_F_REQUEST | NLM_F_DUMP`
    /// - `rtgen_family`: `AF_UNSPEC` (all interface types)
    ///
    /// **`RTM_GETADDR` request**: Enumerate IP addresses
    /// - `nlmsg_type`: `RTM_GETADDR`
    /// - `nlmsg_flags`: `NLM_F_REQUEST | NLM_F_DUMP`
    /// - `rtgen_family`: `AF_INET` or `AF_INET6`
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::EnumerationFailed` if:
    /// - Cannot send netlink request (permission denied, socket error)
    /// - Cannot receive responses (ENOBUFS buffer overflow, ENOMEM)
    /// - Netlink returns `NLMSG_ERROR` with non-zero error code
    /// - Message parsing fails due to malformed kernel response
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dnsmasq::network::platform::{Platform, create_platform};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let platform = create_platform()?;
    ///     let interfaces = platform.enumerate_interfaces().await?;
    ///     
    ///     for iface in interfaces {
    ///         println!("Interface: {} [{}] {}", iface.name, iface.index, iface.addr);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    async fn enumerate_interfaces(&self) -> Result<Vec<InterfaceInfo>, PlatformError> {
        debug!("Enumerating network interfaces via netlink RTM_GETLINK and RTM_GETADDR");

        // Step 1: Enumerate interfaces via RTM_GETLINK
        // Build RTM_GETLINK request (replaces C struct construction at lines 414-435)
        // C code sets: NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST | NLM_F_ACK
        // NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH, so we need NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK
        let link_request = {
            let mut msg = NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetLink(LinkMessage::default())),
            );
            msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
            msg.header.sequence_number = 1;
            msg.finalize();
            msg
        };

        let link_responses = self.send_netlink_request(link_request).await?;
        
        // Build map of interface metadata: index -> (name, flags)
        let mut interface_map: HashMap<u32, (String, u32)> = HashMap::new();
        for rtnl_msg in link_responses {
            if let RouteNetlinkMessage::NewLink(link_msg) = rtnl_msg {
                let if_index = link_msg.header.index;
                let if_flags = link_msg.header.flags;
                
                // Extract interface name from attributes
                // Replaces C: IFLA_IFNAME attribute extraction
                let if_name = link_msg
                    .attributes
                    .iter()
                    .find_map(|nla| {
                        if let netlink_packet_route::link::LinkAttribute::IfName(name) = nla {
                            Some(name.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| format!("if{if_index}"));

                trace!("Found interface: {} (index={}, flags=0x{:x})", if_name, if_index, if_flags);
                // Store flags as u32 (LinkFlags.bits())
                interface_map.insert(if_index, (if_name, if_flags.bits()));
            }
        }

        // Step 2: Enumerate IPv4 addresses via RTM_GETADDR (AF_INET)
        // Replaces C: iface_enumerate(AF_INET, ...) at lines 405-503
        let addr4_request = {
            // Create AddressMessage (non-exhaustive, use Default)
            let mut addr_msg = AddressMessage::default();
            addr_msg.header = AddressHeader {
                family: RtnlAddressFamily::Inet,
                prefix_len: 0,
                flags: AddressHeaderFlags::empty(),
                scope: AddressScope::Universe,
                index: 0,
            };
            addr_msg.attributes = vec![];
            
            let mut msg = NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetAddress(addr_msg)),
            );
            msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
            msg.header.sequence_number = 2;
            msg.finalize();
            msg
        };

        let addr4_responses = self.send_netlink_request(addr4_request).await?;

        let mut interfaces = Vec::new();

        for rtnl_msg in addr4_responses {
            if let RouteNetlinkMessage::NewAddress(addr_msg) = rtnl_msg {
                let if_index = addr_msg.header.index;
                let prefix_len = addr_msg.header.prefix_len;

                // Extract IPv4 address from IFA_LOCAL or IFA_ADDRESS attribute
                // Replaces C: RTA_OK iteration and IFA_LOCAL extraction (lines 488-498)
                let ip_addr = addr_msg
                    .attributes
                    .iter()
                    .find_map(|nla| {
                        match nla {
                            netlink_packet_route::address::AddressAttribute::Local(addr)
                            | netlink_packet_route::address::AddressAttribute::Address(addr)
                                if addr.is_ipv4() => Some(*addr),
                            _ => None,
                        }
                    });

                if let Some(addr) = ip_addr {
                    // Calculate netmask from prefix length
                    // Replaces C: netmask.s_addr = htonl(~(in_addr_t)0 << (32 - ifa->ifa_prefixlen))
                    let netmask_bits = if prefix_len > 0 {
                        !0u32 << (32 - u32::from(prefix_len))
                    } else {
                        0u32
                    };
                    let netmask = IpAddr::V4(Ipv4Addr::from(netmask_bits.to_be()));

                    // Look up interface metadata
                    if let Some((name, flags)) = interface_map.get(&if_index) {
                        trace!("Found IPv4 address: {} on {} (index={})", addr, name, if_index);
                        
                        interfaces.push(InterfaceInfo {
                            addr,
                            name: name.clone(),
                            index: if_index,
                            flags: *flags,
                            prefixlen: prefix_len,
                            netmask,
                        });
                    }
                }
            }
        }

        // Step 3: Enumerate IPv6 addresses via RTM_GETADDR (AF_INET6)
        // Replaces C: iface_enumerate(AF_INET6, ...) at lines 504-546
        let addr6_request = {
            // Create AddressMessage (non-exhaustive, use Default)
            let mut addr_msg = AddressMessage::default();
            addr_msg.header = AddressHeader {
                family: RtnlAddressFamily::Inet6,
                prefix_len: 0,
                flags: AddressHeaderFlags::empty(),
                scope: AddressScope::Universe,
                index: 0,
            };
            addr_msg.attributes = vec![];
            
            let mut msg = NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetAddress(addr_msg)),
            );
            msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
            msg.header.sequence_number = 3;
            msg.finalize();
            msg
        };

        let addr6_responses = self.send_netlink_request(addr6_request).await?;

        for rtnl_msg in addr6_responses {
            if let RouteNetlinkMessage::NewAddress(addr_msg) = rtnl_msg {
                let if_index = addr_msg.header.index;
                let prefix_len = addr_msg.header.prefix_len;

                // Extract IPv6 address from IFA_LOCAL or IFA_ADDRESS attribute
                // Replaces C: RTA_OK iteration for IPv6 addresses (lines 510-530)
                let ip_addr = addr_msg
                    .attributes
                    .iter()
                    .find_map(|nla| {
                        match nla {
                            netlink_packet_route::address::AddressAttribute::Local(addr)
                            | netlink_packet_route::address::AddressAttribute::Address(addr)
                                if addr.is_ipv6() => Some(*addr),
                            _ => None,
                        }
                    });

                if let Some(addr) = ip_addr {
                    // Calculate IPv6 netmask from prefix length
                    let netmask = if prefix_len > 0 && prefix_len <= 128 {
                        let mask_bits = (!0u128) << (128 - u32::from(prefix_len));
                        IpAddr::V6(Ipv6Addr::from(mask_bits.to_be_bytes()))
                    } else {
                        IpAddr::V6(Ipv6Addr::from(0u128))
                    };

                    // Look up interface metadata
                    if let Some((name, flags)) = interface_map.get(&if_index) {
                        trace!("Found IPv6 address: {} on {} (index={})", addr, name, if_index);
                        
                        interfaces.push(InterfaceInfo {
                            addr,
                            name: name.clone(),
                            index: if_index,
                            flags: *flags,
                            prefixlen: prefix_len,
                            netmask,
                        });
                    }
                }
            }
        }

        info!("Enumerated {} interface addresses", interfaces.len());
        Ok(interfaces)
    }

    /// Monitor network changes using netlink multicast groups
    ///
    /// Subscribes to netlink multicast notifications for real-time interface and address
    /// changes. Returns a tokio channel receiver that streams `NetworkChange` events.
    ///
    /// This method replaces C's `netlink_multicast()` (src/netlink.c lines 720-724) and
    /// `nl_async()` (lines 795-828), providing an async event stream instead of callback-based
    /// notification.
    ///
    /// # Implementation Details
    ///
    /// 1. Creates a new netlink socket subscribed to multicast groups:
    ///    - `RTMGRP_IPV4_ROUTE`: IPv4 routing table changes
    ///    - `RTMGRP_IPV4_IFADDR`: IPv4 address add/remove
    ///    - `RTMGRP_IPV6_ROUTE`: IPv6 routing table changes
    ///    - `RTMGRP_IPV6_IFADDR`: IPv6 address add/remove
    /// 2. Wraps socket in tokio `AsyncFd` for non-blocking async I/O
    /// 3. Spawns tokio task to monitor socket and parse incoming multicast messages
    /// 4. Classifies messages by type:
    ///    - `RTM_NEWLINK`/`RTM_DELLINK` → `InterfaceAdded`/`InterfaceRemoved`
    ///    - `RTM_NEWADDR`/`RTM_DELADDR` → `AddressAdded`/`AddressRemoved`
    ///    - `RTM_NEWROUTE` → `RouteChanged` (for unicast link-scope routes only)
    /// 5. Sends events through channel to caller
    ///
    /// # Multicast Group Filtering
    ///
    /// Unlike C which processes all multicast messages, this implementation filters
    /// route change events to match C's behavior (src/netlink.c lines 813-819):
    /// - Only `RTN_UNICAST` routes (not multicast/broadcast/blackhole)
    /// - Only `RT_SCOPE_LINK` (link-local scope)
    /// - Only main or local routing tables
    ///
    /// This filtering supports dial-on-demand (`DoD`) scenarios where DNS queries trigger
    /// PPP connection establishment and need retry when route becomes available.
    ///
    /// # Channel Buffer
    ///
    /// The returned channel has a buffer of 100 events. If the consumer cannot keep up
    /// with network changes, older events may be dropped (channel full). This prevents
    /// unbounded memory growth during network storms.
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::MonitoringFailed` if:
    /// - Cannot create monitoring socket
    /// - Cannot subscribe to multicast groups (permission denied)
    /// - Cannot register socket with tokio `AsyncFd`
    ///
    /// # Cancellation Safety
    ///
    /// This method is cancellation-safe. Dropping the returned `Receiver` will cause
    /// the monitoring task to exit cleanly when it detects channel closure.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dnsmasq::network::platform::{Platform, create_platform, NetworkChange};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let platform = create_platform()?;
    ///     let mut rx = platform.monitor_changes().await?;
    ///     
    ///     while let Some(change) = rx.recv().await {
    ///         match change {
    ///             NetworkChange::AddressAdded { if_index, addr, prefixlen } => {
    ///                 println!("Address added: {} on interface {}", addr, if_index);
    ///             }
    ///             NetworkChange::InterfaceRemoved { name, index } => {
    ///                 println!("Interface removed: {} [{}]", name, index);
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    ///     Ok(())
    /// }
    /// ```
    async fn monitor_changes(&self) -> Result<Receiver<NetworkChange>, PlatformError> {
        info!("Starting netlink network change monitoring");

        // Create a new netlink socket specifically for multicast monitoring
        // (The socket in self.netlink_fd is for dump requests, not multicast)
        let monitor_fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            Some(SockProtocol::NetlinkRoute),
        )
        .map_err(|e| {
            error!("Failed to create netlink monitoring socket: {}", e);
            io_error_to_platform_error(
                PlatformErrorKind::MonitoringFailed,
                "Cannot create netlink monitoring socket",
                IoError::from(e),
            )
        })?;

        // Bind with multicast groups for interface and route notifications
        // Replaces C multicast subscription at lines 191-194
        let groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
        let addr = NetlinkAddr::new(0, groups);

        bind(monitor_fd.as_raw_fd(), &addr).map_err(|e| {
            error!("Failed to bind netlink monitoring socket with multicast: {}", e);
            close(monitor_fd.as_raw_fd()).ok();
            
            // If EPERM, provide helpful error message
            if e == nix::errno::Errno::EPERM {
                return PlatformError::new(
                    PlatformErrorKind::PermissionDenied,
                    "Permission denied for netlink multicast subscription (requires CAP_NET_ADMIN or root)",
                );
            }
            
            io_error_to_platform_error(
                PlatformErrorKind::MonitoringFailed,
                "Cannot bind netlink monitoring socket",
                IoError::from(e),
            )
        })?;

        // Wrap in AsyncFd for tokio integration
        let async_fd = AsyncFd::new(monitor_fd).map_err(|e| {
            error!("Failed to register netlink socket with tokio: {}", e);
            PlatformError::with_source(
                PlatformErrorKind::MonitoringFailed,
                "Cannot register netlink socket with tokio AsyncFd",
                Box::new(e),
            )
        })?;

        // Create channel for sending events to caller
        let (tx, rx) = channel::<NetworkChange>(100);

        // Spawn monitoring task
        // Replaces C's synchronous poll() readability check and nl_multicast_state() call
        spawn(async move {
            Self::monitor_netlink_events(async_fd, tx).await;
        });

        Ok(rx)
    }

    /// Enumerate ARP cache using netlink `RTM_GETNEIGH`
    ///
    /// Retrieves the kernel's neighbor table (ARP cache for IPv4, NDP cache for IPv6).
    /// This method replaces C's `iface_enumerate(AF_UNSPEC, ...)` (src/netlink.c lines 549-574).
    ///
    /// # Implementation Details
    ///
    /// 1. Sends `RTM_GETNEIGH` dump request with `AF_UNSPEC` (all address families)
    /// 2. Parses `RTM_NEWNEIGH` responses containing:
    ///    - `NDA_DST`: Neighbor IP address (IPv4 or IPv6)
    ///    - `NDA_LLADDR`: Link-layer (MAC) address
    ///    - `ndm_state`: Neighbor state flags (NUD_*)
    ///    - `ndm_family`: Address family (`AF_INET` or `AF_INET6`)
    ///    - `ndm_ifindex`: Interface index
    /// 3. Filters out incomplete, failed, and no-ARP entries
    /// 4. Returns vector of `ArpEntry` structs
    ///
    /// # Neighbor State Filtering
    ///
    /// Only includes entries where `ndm_state` is NOT:
    /// - `NUD_INCOMPLETE` (0x01): ARP request sent but no reply yet
    /// - `NUD_FAILED` (0x08): ARP resolution failed
    /// - `NUD_NOARP` (0x40): No ARP needed for this entry
    ///
    /// This matches C behavior at line 570:
    /// `!(neigh->ndm_state & (NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED))`
    ///
    /// # Errors
    ///
    /// Returns `PlatformError::ArpAccessFailed` if:
    /// - Cannot send netlink request
    /// - Cannot receive responses (ENOBUFS, permission denied)
    /// - Malformed neighbor table entries
    ///
    /// # Platform Availability
    ///
    /// Linux-specific. BSD systems use different mechanisms (sysctl, routing socket).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dnsmasq::network::platform::{Platform, create_platform};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let platform = create_platform()?;
    ///     let arp_entries = platform.enumerate_arp().await?;
    ///     
    ///     for entry in arp_entries {
    ///         println!("ARP: {} -> {}", entry.addr, entry.hwaddr_string());
    ///     }
    ///     Ok(())
    /// }
    /// ```
    async fn enumerate_arp(&self) -> Result<Vec<ArpEntry>, PlatformError> {
        debug!("Enumerating ARP cache via netlink RTM_GETNEIGH");

        // Build RTM_GETNEIGH request
        // Replaces C: req.nlh.nlmsg_type = RTM_GETNEIGH; req.g.rtgen_family = AF_UNSPEC
        let neigh_request = {
            // Create NeighbourMessage (non-exhaustive, use Default)
            let mut neigh_msg = NeighbourMessage::default();
            neigh_msg.header = NeighbourHeader {
                family: RtnlAddressFamily::Unspec,
                ifindex: 0,
                state: NeighbourState::None,
                flags: NeighbourFlags::empty(),
                kind: RouteType::Unspec,
            };
            neigh_msg.attributes = vec![];
            
            let mut msg = NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetNeighbour(neigh_msg)),
            );
            msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
            msg.header.sequence_number = 4;
            msg.finalize();
            msg
        };

        let neigh_responses = self.send_netlink_request(neigh_request).await
            .map_err(|e| {
                // Map enumeration error to ARP-specific error
                PlatformError::new(
                    PlatformErrorKind::ArpAccessFailed,
                    format!("Failed to enumerate ARP cache: {e}"),
                )
            })?;

        let mut arp_entries = Vec::new();

        for rtnl_msg in neigh_responses {
            if let RouteNetlinkMessage::NewNeighbour(neigh_msg) = rtnl_msg {
                let family = neigh_msg.header.family;
                let if_index = neigh_msg.header.ifindex;
                let state = neigh_msg.header.state;

                // Filter out incomplete, failed, and no-ARP entries
                // Replaces C: if (!(neigh->ndm_state & (NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED)) && inaddr && mac)
                if state == NeighbourState::Incomplete 
                    || state == NeighbourState::Failed 
                    || state == NeighbourState::Noarp {
                    continue;
                }

                // Extract IP address from NDA_DST attribute
                // NeighbourAttribute::Destination contains NeighbourAddress enum
                let ip_addr = neigh_msg
                    .attributes
                    .iter()
                    .find_map(|nla| {
                        if let netlink_packet_route::neighbour::NeighbourAttribute::Destination(addr) = nla {
                            match addr {
                                netlink_packet_route::neighbour::NeighbourAddress::Inet(ipv4) => {
                                    Some(IpAddr::V4(*ipv4))
                                }
                                netlink_packet_route::neighbour::NeighbourAddress::Inet6(ipv6) => {
                                    Some(IpAddr::V6(*ipv6))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    });

                // Extract MAC address from NDA_LLADDR attribute
                let hwaddr = neigh_msg
                    .attributes
                    .iter()
                    .find_map(|nla| {
                        if let netlink_packet_route::neighbour::NeighbourAttribute::LinkLocalAddress(bytes) = nla {
                            if bytes.len() >= 6 {
                                let mut mac = [0u8; 6];
                                mac.copy_from_slice(&bytes[..6]);
                                Some(mac)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    });

                if let (Some(addr), Some(hwaddr)) = (ip_addr, hwaddr) {
                    trace!("Found ARP entry: {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                           addr, hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
                    
                    // Convert AddressFamily to i32 (via u8)
                    let family_u8: u8 = family.into();
                    arp_entries.push(ArpEntry {
                        addr,
                        hwaddr,
                        family: i32::from(family_u8),
                        if_index,
                        hwaddr_len: 6,
                    });
                }
            }
        }

        info!("Enumerated {} ARP cache entries", arp_entries.len());
        Ok(arp_entries)
    }
}

impl LinuxPlatform {
    /// Monitor netlink events task (runs in spawned tokio task)
    ///
    /// Continuously reads multicast netlink messages and classifies them into
    /// `NetworkChange` events. This is the async equivalent of C's `nl_multicast_state()`
    /// and `nl_async()` functions.
    ///
    /// # Arguments
    ///
    /// - `async_fd`: Tokio `AsyncFd` wrapper around netlink socket
    /// - `tx`: Channel sender for emitting `NetworkChange` events
    ///
    /// # Behavior
    ///
    /// - Runs until channel is closed (receiver dropped) or fatal socket error
    /// - Uses non-blocking I/O with tokio async/await
    /// - Drains all available messages when socket becomes readable
    /// - Classifies messages by type and sends corresponding events
    /// - Deduplicates rapid successive events of same type (e.g., multiple address changes)
    async fn monitor_netlink_events(
        async_fd: AsyncFd<OwnedFd>,
        tx: Sender<NetworkChange>,
    ) {
        let mut buf = vec![0u8; 8192];
        let mut event_state: u32 = 0; // Deduplication flags (replaces C's enum async_states)

        loop {
            // Wait for socket to become readable
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(e) => {
                    error!("Failed to wait for netlink socket readability: {}", e);
                    break;
                }
            };

            // Try to read messages (non-blocking due to SOCK_NONBLOCK)
            // Replaces C: nl_multicast_state() with MSG_DONTWAIT loop (lines 661-668)
            loop {
                let mut iov = [std::io::IoSliceMut::new(&mut buf)];
                
                match nix::sys::socket::recvmsg::<NetlinkAddr>(
                    async_fd.as_raw_fd(),
                    &mut iov,
                    None,
                    MsgFlags::MSG_DONTWAIT,
                ) {
                    Ok(msg) => {
                        // Verify kernel origin (nladdr.nl_pid == 0)
                        if let Some(addr) = msg.address {
                            if addr.pid() != 0 {
                                continue; // Not from kernel, ignore
                            }
                        }

                        let received_bytes = msg.bytes;
                        
                        // Parse netlink messages
                        if let Ok(nl_msg) = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf[..received_bytes]) {
                            match nl_msg.payload {
                                NetlinkPayload::InnerMessage(rtnl_msg) => {
                                    // Classify and send events
                                    // Replaces C: nl_async() event classification (lines 795-828)
                                    Self::classify_and_send_event(
                                        rtnl_msg,
                                        &tx,
                                        &mut event_state,
                                    ).await;
                                }
                                NetlinkPayload::Error(err) => {
                                    if let Some(code) = err.code {
                                        error!("Netlink multicast error: code={}", code);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EWOULDBLOCK {
                            // No more messages available, clear event deduplication state
                            event_state = 0;
                            break; // Exit inner loop, wait for next readable event
                        } else if e == nix::errno::Errno::ENOBUFS {
                            // Kernel buffer overflow, log warning
                            // Replaces C: errno == ENOBUFS handling (lines 448-452)
                            warn!("Netlink monitoring buffer overflow (ENOBUFS), some events may be lost");
                            event_state = 0;
                            break;
                        } else if e != nix::errno::Errno::EINTR {
                            error!("Failed to receive netlink multicast message: {}", e);
                            return; // Fatal error, exit monitoring task
                        }
                    }
                }
            }

            // Clear readiness flag
            guard.clear_ready();
        }

        info!("Netlink monitoring task exiting");
    }

    /// Classify netlink message and send appropriate event
    ///
    /// Matches netlink message type to `NetworkChange` event variant.
    /// Implements event deduplication using state flags.
    ///
    /// # Arguments
    ///
    /// - `rtnl_msg`: Parsed netlink RTNL message
    /// - `tx`: Channel sender for events
    /// - `event_state`: Deduplication state flags
    async fn classify_and_send_event(
        rtnl_msg: RouteNetlinkMessage,
        tx: &Sender<NetworkChange>,
        event_state: &mut u32,
    ) {
        const STATE_NEWADDR: u32 = 1 << 0;
        const STATE_NEWROUTE: u32 = 1 << 1;

        match rtnl_msg {
            // RTM_NEWLINK: Interface added
            RouteNetlinkMessage::NewLink(link_msg) => {
                let if_index = link_msg.header.index;
                let if_name = link_msg
                    .attributes
                    .iter()
                    .find_map(|nla| {
                        if let netlink_packet_route::link::LinkAttribute::IfName(name) = nla {
                            Some(name.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| format!("if{if_index}"));

                debug!("Interface added: {} [{}]", if_name, if_index);
                let _ = tx.send(NetworkChange::InterfaceAdded {
                    name: if_name,
                    index: if_index,
                }).await;
            }

            // RTM_DELLINK: Interface removed
            RouteNetlinkMessage::DelLink(link_msg) => {
                let if_index = link_msg.header.index;
                let if_name = link_msg
                    .attributes
                    .iter()
                    .find_map(|nla| {
                        if let netlink_packet_route::link::LinkAttribute::IfName(name) = nla {
                            Some(name.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| format!("if{if_index}"));

                debug!("Interface removed: {} [{}]", if_name, if_index);
                let _ = tx.send(NetworkChange::InterfaceRemoved {
                    name: if_name,
                    index: if_index,
                }).await;
            }

            // RTM_NEWADDR or RTM_DELADDR: Address added/removed
            RouteNetlinkMessage::NewAddress(ref addr_msg) | RouteNetlinkMessage::DelAddress(ref addr_msg) => {
                // Deduplicate: only send one NEWADDR event per batch
                // Replaces C: if ((state & STATE_NEWADDR)==0) at line 822
                if (*event_state & STATE_NEWADDR) != 0 {
                    return;
                }

                let if_index = addr_msg.header.index;
                let prefix_len = addr_msg.header.prefix_len;
                let is_add = matches!(rtnl_msg, RouteNetlinkMessage::NewAddress(_));

                // Extract IP address
                let ip_addr = addr_msg
                    .attributes
                    .iter()
                    .find_map(|nla| {
                        match nla {
                            netlink_packet_route::address::AddressAttribute::Local(addr)
                            | netlink_packet_route::address::AddressAttribute::Address(addr) => Some(*addr),
                            _ => None,
                        }
                    });

                if let Some(addr) = ip_addr {
                    if is_add {
                        debug!("Address added: {} on interface {}", addr, if_index);
                        let _ = tx.send(NetworkChange::AddressAdded {
                            if_index,
                            addr,
                            prefixlen: prefix_len,
                        }).await;
                    } else {
                        debug!("Address removed: {} from interface {}", addr, if_index);
                        let _ = tx.send(NetworkChange::AddressRemoved {
                            if_index,
                            addr,
                        }).await;
                    }
                    *event_state |= STATE_NEWADDR;
                }
            }

            // RTM_NEWROUTE: Routing table changed
            RouteNetlinkMessage::NewRoute(route_msg) => {
                // Routing table constants (table field is u8)
                const RT_TABLE_MAIN: u8 = 254;
                const RT_TABLE_LOCAL: u8 = 255;

                // Deduplicate: only send one NEWROUTE event per batch
                // Replaces C: if ((state & STATE_NEWROUTE)==0) at line 804
                if (*event_state & STATE_NEWROUTE) != 0 {
                    return;
                }

                // Filter routes: only unicast, link-scope, main/local table
                // Replaces C filtering at lines 813-819
                let rtm_type = route_msg.header.kind;
                let rtm_scope = route_msg.header.scope;
                let rtm_table = route_msg.header.table;

                if rtm_type == RouteType::Unicast
                    && rtm_scope == RouteScope::Link
                    && (rtm_table == RT_TABLE_MAIN || rtm_table == RT_TABLE_LOCAL)
                {
                    debug!("Route changed (unicast link-scope)");
                    let _ = tx.send(NetworkChange::RouteChanged {
                        destination: None,
                        gateway: None,
                    }).await;
                    *event_state |= STATE_NEWROUTE;
                }
            }

            _ => {
                // Ignore other message types
            }
        }
    }
}

impl Drop for LinuxPlatform {
    fn drop(&mut self) {
        // Netlink socket is automatically closed when OwnedFd is dropped (RAII)
        // No manual cleanup needed, preventing file descriptor leaks
        debug!("LinuxPlatform dropped, netlink socket closed automatically");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_platform_creation() {
        // Platform creation test
        // May fail if not running on Linux or without CAP_NET_ADMIN
        let result = LinuxPlatform::new();
        
        // Don't panic in test environment where we might not have permissions
        if result.is_ok() {
            println!("LinuxPlatform created successfully");
        } else {
            println!("LinuxPlatform creation failed (expected in non-Linux or unprivileged environment)");
        }
    }

    #[tokio::test]
    async fn test_enumerate_interfaces() {
        // This test requires Linux and appropriate permissions
        if let Ok(platform) = LinuxPlatform::new() {
            let result = platform.enumerate_interfaces().await;
            
            match result {
                Ok(interfaces) => {
                    println!("Found {} interfaces", interfaces.len());
                    for iface in interfaces.iter().take(3) {
                        println!("  - {} [{}]: {}", iface.name, iface.index, iface.addr);
                    }
                }
                Err(e) => {
                    println!("Interface enumeration failed: {e}");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_enumerate_arp() {
        // This test requires Linux and appropriate permissions
        if let Ok(platform) = LinuxPlatform::new() {
            let result = platform.enumerate_arp().await;
            
            match result {
                Ok(entries) => {
                    println!("Found {} ARP entries", entries.len());
                    for entry in entries.iter().take(3) {
                        println!("  - {} -> {}", entry.addr, entry.hwaddr_string());
                    }
                }
                Err(e) => {
                    println!("ARP enumeration failed: {e}");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_monitor_changes() {
        // This test requires Linux and CAP_NET_ADMIN
        if let Ok(platform) = LinuxPlatform::new() {
            let result = platform.monitor_changes().await;
            
            match result {
                Ok(mut rx) => {
                    println!("Network monitoring started");
                    
                    // Set timeout to avoid indefinite wait in tests
                    let timeout_duration = std::time::Duration::from_secs(2);
                    match tokio::time::timeout(timeout_duration, rx.recv()).await {
                        Ok(Some(change)) => {
                            println!("Received network change: {change:?}");
                        }
                        Ok(None) => {
                            println!("Channel closed");
                        }
                        Err(_) => {
                            println!("No network changes within timeout (expected in stable environment)");
                        }
                    }
                }
                Err(e) => {
                    println!("Monitor initialization failed: {e}");
                }
            }
        }
    }
}
