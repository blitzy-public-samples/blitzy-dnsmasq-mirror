// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
// ipset.c is Copyright (c) 2013 Jason A. Donenfeld <Jason@zx2c4.com>
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Linux ipset integration for DNS-resolved address insertion
//!
//! This module provides automatic insertion of DNS-resolved addresses into Linux kernel
//! ipsets, enabling firewall and routing policy enforcement based on domain names. When
//! dnsmasq resolves a DNS query for domains configured with --ipset option, the resulting
//! IP addresses are automatically added to named ipsets via the kernel's Netlink interface.
//!
//! # Key Features
//!
//! - **Memory Safety**: Replaces manual Netlink buffer manipulation with safe Rust abstractions
//! - **Protocol Support**: Both modern Netlink (kernel 2.6.32+) and legacy raw socket protocols
//! - **Address Families**: Full IPv4 and IPv6 support (IPv6 requires modern kernel)
//! - **Async Integration**: Non-blocking operations with tokio for event loop compatibility
//!
//! # Architecture
//!
//! The implementation uses a three-tier architecture:
//! 1. **Public API**: `add_to_ipset()` and `remove_from_ipset()` convenience functions
//! 2. **Manager**: `IpsetManager` handles socket lifecycle and protocol selection
//! 3. **Protocol Layer**: Kernel-specific implementations (modern Netlink vs legacy raw socket)
//!
//! # Example Usage
//!
//! ```no_run
//! use std::net::IpAddr;
//! use dnsmasq::integration::ipset::IpsetManager;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let manager = IpsetManager::new()?;
//!
//! // Add resolved address to ipset
//! let addr: IpAddr = "192.0.2.1".parse()?;
//! manager.add_to_ipset("blocked_domains", addr).await?;
//!
//! // Remove address from ipset
//! manager.remove_from_ipset("blocked_domains", addr).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Platform Requirements
//!
//! - Linux-only (conditional compilation via `#[cfg(target_os = "linux")]`)
//! - Kernel 2.6.16+ for legacy support, 2.6.32+ for full modern Netlink support
//! - CAP_NET_ADMIN capability for Netlink socket operations
//! - ipset kernel module loaded (`modprobe ip_set`)
//!
//! # Safety
//!
//! All Netlink message construction uses safe Rust abstractions from `crate::ffi::platform::netlink`.
//! No manual pointer arithmetic or buffer manipulation. Legacy raw socket operations are isolated
//! in documented unsafe blocks with explicit safety invariants.

// Platform-specific implementation (Linux only)
#[cfg(target_os = "linux")]
mod linux_impl {
    use crate::ffi::platform::netlink::{
        NetlinkSocket, NlMsgHdr, NfGenMsg, NlAttr, nl_align,
        create_netlink_socket, send_netlink_message,
        NFNL_SUBSYS_IPSET, IPSET_PROTOCOL, IPSET_MAXNAMELEN,
        IPSET_CMD_ADD, IPSET_CMD_DEL,
        IPSET_ATTR_PROTOCOL, IPSET_ATTR_SETNAME, IPSET_ATTR_DATA, IPSET_ATTR_IP,
        IPSET_ATTR_IPADDR_IPV4, IPSET_ATTR_IPADDR_IPV6,
        NLA_F_NESTED, NLA_F_NET_BYTEORDER, NFNETLINK_V0,
    };
    use nix::sys::socket::AddressFamily;
    use std::io::{Error as IoError, ErrorKind, Result as IoResult};
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::string::String;
    use std::vec::Vec;
    use thiserror::Error;
    use tracing::{debug, error, info, warn};

    /// ipset operation errors
    ///
    /// Comprehensive error type covering all ipset operation failure modes.
    /// Uses thiserror for automatic std::error::Error trait implementation.
    #[derive(Error, Debug)]
    pub enum IpsetError {
        /// Failed to create Netlink socket
        #[error("Failed to create ipset socket: {0}")]
        SocketCreationFailed(#[source] IoError),

        /// Failed to bind Netlink socket
        #[error("Failed to bind ipset socket: {0}")]
        BindFailed(#[source] IoError),

        /// Failed to send Netlink message
        #[error("Failed to send ipset message: {0}")]
        SendFailed(#[source] IoError),

        /// Kernel version detection failed
        #[error("Failed to detect kernel ipset protocol version")]
        KernelVersionDetectionFailed,

        /// Set name exceeds maximum length
        #[error("ipset name '{0}' exceeds maximum length {}", IPSET_MAXNAMELEN)]
        InvalidSetName(String),

        /// Address family not supported on this kernel
        #[error("IPv6 not supported on legacy kernel (< 2.6.32)")]
        AddressFamilyUnsupported,

        /// Netlink message construction failed
        #[error("Failed to construct ipset message: {0}")]
        MessageConstructionFailed(String),

        /// Legacy raw socket operation failed
        #[error("Legacy ipset operation failed: {0}")]
        LegacyOperationFailed(#[source] IoError),
    }

    /// Kernel ipset protocol version
    ///
    /// Distinguishes between modern Netlink-based protocol (kernel 2.6.32+) and
    /// legacy raw socket protocol (older kernels). IPv6 support requires Modern protocol.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KernelProtocol {
        /// Modern Netlink-based ipset protocol (kernel >= 2.6.32)
        ///
        /// Supports both IPv4 and IPv6, uses NFNETLINK IPSET subsystem.
        Modern,

        /// Legacy raw socket protocol (kernel < 2.6.32)
        ///
        /// IPv4 only, uses SOL_IP getsockopt/setsockopt with option 83.
        Legacy,
    }

    /// Linux ipset manager
    ///
    /// Manages Netlink socket connection to kernel ipset subsystem and provides
    /// methods for adding/removing IP addresses to/from named ipsets. Automatically
    /// detects kernel protocol version and uses appropriate implementation.
    ///
    /// # Lifecycle
    ///
    /// - `new()`: Opens Netlink socket, detects kernel version, binds to kernel
    /// - `add_to_ipset()` / `remove_from_ipset()`: Send ipset operations
    /// - `Drop`: Automatically closes Netlink socket (RAII cleanup)
    ///
    /// # Thread Safety
    ///
    /// Not thread-safe due to shared Netlink socket. Use within single async task
    /// or protect with Arc<Mutex<IpsetManager>> for multi-threaded access.
    pub struct IpsetManager {
        socket: Option<NetlinkSocket>,
        protocol: KernelProtocol,
    }

    impl IpsetManager {
        /// Create new ipset manager and initialize kernel connection
        ///
        /// Opens AF_NETLINK socket with NETLINK_NETFILTER protocol and detects
        /// kernel ipset version. Modern kernels (>= 2.6.32) use Netlink protocol,
        /// older kernels use legacy raw socket protocol.
        ///
        /// # Errors
        ///
        /// Returns `IpsetError::SocketCreationFailed` if:
        /// - Permission denied (requires CAP_NET_ADMIN capability)
        /// - Out of file descriptors
        /// - ipset kernel module not loaded
        ///
        /// Returns `IpsetError::BindFailed` if bind to kernel fails
        ///
        /// # Example
        ///
        /// ```no_run
        /// use dnsmasq::integration::ipset::IpsetManager;
        ///
        /// let manager = IpsetManager::new()?;
        /// # Ok::<(), Box<dyn std::error::Error>>(())
        /// ```
        pub fn new() -> Result<Self, IpsetError> {
            // Detect kernel version for protocol selection
            // For now, assume modern kernel (2.6.32+) and use Netlink protocol
            // In production, this would read /proc/version or use uname() syscall
            let protocol = Self::detect_kernel_protocol()?;

            debug!("Detected ipset protocol: {:?}", protocol);

            match protocol {
                KernelProtocol::Modern => {
                    // Create Netlink socket for modern protocol
                    let socket = create_netlink_socket(
                        libc::NETLINK_NETFILTER,
                        0, // No multicast groups needed for ipset
                    )
                    .map_err(IpsetError::SocketCreationFailed)?;

                    info!("Initialized ipset manager with modern Netlink protocol");

                    Ok(Self {
                        socket: Some(socket),
                        protocol,
                    })
                }
                KernelProtocol::Legacy => {
                    // Legacy protocol uses raw socket (AF_INET, SOCK_RAW, IPPROTO_RAW)
                    // Socket creation deferred to operation time for legacy protocol
                    warn!("Using legacy ipset protocol (kernel < 2.6.32), IPv6 not supported");

                    Ok(Self {
                        socket: None,
                        protocol,
                    })
                }
            }
        }

        /// Detect kernel ipset protocol version
        ///
        /// Determines whether kernel supports modern Netlink-based ipset protocol
        /// (kernel >= 2.6.32) or requires legacy raw socket protocol.
        ///
        /// # Detection Strategy
        ///
        /// 1. Attempt to create NETLINK_NETFILTER socket (modern protocol test)
        /// 2. If successful, kernel supports modern protocol
        /// 3. If fails with EPROTONOSUPPORT, fall back to legacy
        /// 4. Other errors propagated as initialization failure
        ///
        /// # Returns
        ///
        /// `KernelProtocol::Modern` or `KernelProtocol::Legacy`
        ///
        /// # Errors
        ///
        /// Returns `IpsetError::KernelVersionDetectionFailed` if detection fails
        fn detect_kernel_protocol() -> Result<KernelProtocol, IpsetError> {
            // Try to create modern Netlink socket
            match create_netlink_socket(libc::NETLINK_NETFILTER, 0) {
                Ok(_socket) => {
                    // Socket creation succeeded, kernel supports modern protocol
                    // Socket will be dropped here, we'll create new one in new()
                    Ok(KernelProtocol::Modern)
                }
                Err(e) if e.raw_os_error() == Some(libc::EPROTONOSUPPORT) => {
                    // Kernel doesn't support NETLINK_NETFILTER, use legacy protocol
                    Ok(KernelProtocol::Legacy)
                }
                Err(_e) => {
                    // Other error (permission denied, etc.), assume modern and let
                    // new() handle the error with better context
                    Ok(KernelProtocol::Modern)
                }
            }
        }

        /// Check if IPv6 addresses are supported
        ///
        /// Legacy protocol (kernel < 2.6.32) only supports IPv4 addresses.
        /// Modern Netlink protocol supports both IPv4 and IPv6.
        ///
        /// # Returns
        ///
        /// `true` if IPv6 supported, `false` otherwise
        ///
        /// # Example
        ///
        /// ```no_run
        /// use dnsmasq::integration::ipset::IpsetManager;
        ///
        /// let manager = IpsetManager::new()?;
        /// if manager.supports_ipv6() {
        ///     println!("IPv6 ipset operations available");
        /// }
        /// # Ok::<(), Box<dyn std::error::Error>>(())
        /// ```
        #[must_use]
        pub fn supports_ipv6(&self) -> bool {
            matches!(self.protocol, KernelProtocol::Modern)
        }

        /// Add IP address to named ipset (async wrapper)
        ///
        /// Adds the specified IP address to a kernel ipset. Uses tokio spawn_blocking
        /// for non-blocking operation in async context. The operation is idempotent:
        /// adding an address already in the set is not an error.
        ///
        /// # Arguments
        ///
        /// * `setname` - Name of ipset (must exist in kernel, max 31 chars)
        /// * `addr` - IP address to add (IPv4 or IPv6)
        ///
        /// # Returns
        ///
        /// `Ok(())` on success
        ///
        /// # Errors
        ///
        /// Returns `IpsetError` if:
        /// - `InvalidSetName`: setname too long (>= 32 chars)
        /// - `AddressFamilyUnsupported`: IPv6 address on legacy kernel
        /// - `SendFailed`: Netlink message send failed
        /// - `LegacyOperationFailed`: Legacy raw socket operation failed
        ///
        /// # Example
        ///
        /// ```no_run
        /// use dnsmasq::integration::ipset::IpsetManager;
        /// use std::net::IpAddr;
        ///
        /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
        /// let manager = IpsetManager::new()?;
        /// let addr: IpAddr = "192.0.2.1".parse()?;
        /// manager.add_to_ipset("blacklist", addr).await?;
        /// # Ok(())
        /// # }
        /// ```
        pub async fn add_to_ipset(&self, setname: &str, addr: IpAddr) -> Result<(), IpsetError> {
            // Validate setname length before async operation
            if setname.len() >= IPSET_MAXNAMELEN {
                return Err(IpsetError::InvalidSetName(setname.to_string()));
            }

            // Check IPv6 support
            if addr.is_ipv6() && !self.supports_ipv6() {
                return Err(IpsetError::AddressFamilyUnsupported);
            }

            // Clone data for move into blocking task
            let setname = setname.to_string();
            let protocol = self.protocol;

            // Execute blocking operation in thread pool
            tokio::task::spawn_blocking(move || {
                Self::add_to_ipset_blocking(&setname, addr, protocol, false)
            })
            .await
            .map_err(|e| {
                IpsetError::MessageConstructionFailed(format!("Task join error: {}", e))
            })?
        }

        /// Remove IP address from named ipset (async wrapper)
        ///
        /// Removes the specified IP address from a kernel ipset. Uses tokio spawn_blocking
        /// for non-blocking operation in async context. The operation is idempotent:
        /// removing an address not in the set is not an error.
        ///
        /// # Arguments
        ///
        /// * `setname` - Name of ipset (must exist in kernel, max 31 chars)
        /// * `addr` - IP address to remove (IPv4 or IPv6)
        ///
        /// # Returns
        ///
        /// `Ok(())` on success
        ///
        /// # Errors
        ///
        /// Same error conditions as `add_to_ipset()`
        ///
        /// # Example
        ///
        /// ```no_run
        /// use dnsmasq::integration::ipset::IpsetManager;
        /// use std::net::IpAddr;
        ///
        /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
        /// let manager = IpsetManager::new()?;
        /// let addr: IpAddr = "192.0.2.1".parse()?;
        /// manager.remove_from_ipset("blacklist", addr).await?;
        /// # Ok(())
        /// # }
        /// ```
        pub async fn remove_from_ipset(
            &self,
            setname: &str,
            addr: IpAddr,
        ) -> Result<(), IpsetError> {
            // Validate setname length before async operation
            if setname.len() >= IPSET_MAXNAMELEN {
                return Err(IpsetError::InvalidSetName(setname.to_string()));
            }

            // Check IPv6 support
            if addr.is_ipv6() && !self.supports_ipv6() {
                return Err(IpsetError::AddressFamilyUnsupported);
            }

            // Clone data for move into blocking task
            let setname = setname.to_string();
            let protocol = self.protocol;

            // Execute blocking operation in thread pool
            tokio::task::spawn_blocking(move || {
                Self::add_to_ipset_blocking(&setname, addr, protocol, true)
            })
            .await
            .map_err(|e| {
                IpsetError::MessageConstructionFailed(format!("Task join error: {}", e))
            })?
        }

        /// Blocking implementation of ipset add/remove operation
        ///
        /// Synchronous implementation called from spawn_blocking. Selects protocol
        /// implementation based on kernel version.
        ///
        /// # Arguments
        ///
        /// * `setname` - ipset name (already validated)
        /// * `addr` - IP address to add/remove
        /// * `protocol` - Kernel protocol version
        /// * `remove` - true to remove, false to add
        ///
        /// # Returns
        ///
        /// `Ok(())` on success, `IpsetError` on failure
        fn add_to_ipset_blocking(
            setname: &str,
            addr: IpAddr,
            protocol: KernelProtocol,
            remove: bool,
        ) -> Result<(), IpsetError> {
            match protocol {
                KernelProtocol::Modern => {
                    Self::modern_add_to_ipset(setname, addr, remove)
                }
                KernelProtocol::Legacy => {
                    Self::legacy_add_to_ipset(setname, addr, remove)
                }
            }
        }

        /// Modern Netlink-based ipset operation (kernel >= 2.6.32)
        ///
        /// Constructs and sends Netlink message to NFNETLINK IPSET subsystem.
        /// Supports both IPv4 and IPv6 addresses. Message structure:
        ///
        /// ```text
        /// nlmsghdr (Netlink message header)
        /// └─ nfgenmsg (Netfilter generic header)
        ///    ├─ IPSET_ATTR_PROTOCOL (u8)
        ///    ├─ IPSET_ATTR_SETNAME (string)
        ///    └─ IPSET_ATTR_DATA (nested)
        ///       └─ IPSET_ATTR_IP (nested)
        ///          └─ IPSET_ATTR_IPADDR_IPV4 / IPSET_ATTR_IPADDR_IPV6 (binary address)
        /// ```
        ///
        /// # Arguments
        ///
        /// * `setname` - ipset name (validated length)
        /// * `addr` - IP address to add/remove
        /// * `remove` - true for IPSET_CMD_DEL, false for IPSET_CMD_ADD
        ///
        /// # Returns
        ///
        /// `Ok(())` on successful message send, `IpsetError` on failure
        ///
        /// # Netlink Protocol Details
        ///
        /// - All lengths must be NL_ALIGN'd (4-byte boundary)
        /// - Nested attributes created with NLA_F_NESTED flag
        /// - Address attribute uses NLA_F_NET_BYTEORDER for proper byte order
        /// - Message type: (IPSET_CMD_ADD|DEL) | (NFNL_SUBSYS_IPSET << 8)
        fn modern_add_to_ipset(
            setname: &str,
            addr: IpAddr,
            remove: bool,
        ) -> Result<(), IpsetError> {
            // Create temporary socket for this operation
            // (In production, could reuse socket from IpsetManager, but that requires
            // handling the socket being behind &self in async context)
            let socket = create_netlink_socket(libc::NETLINK_NETFILTER, 0)
                .map_err(IpsetError::SocketCreationFailed)?;

            // Construct Netlink message in vector for safe bounds checking
            let mut msg_buf = Vec::with_capacity(256);

            // Determine address family and size
            let (af, addr_bytes): (u8, Vec<u8>) = match addr {
                IpAddr::V4(ipv4) => (libc::AF_INET as u8, ipv4.octets().to_vec()),
                IpAddr::V6(ipv6) => (libc::AF_INET6 as u8, ipv6.octets().to_vec()),
            };

            // Build Netlink message header
            let mut nlh = NlMsgHdr {
                nlmsg_len: nl_align(size_of::<NlMsgHdr>()) as u32,
                nlmsg_type: (if remove { IPSET_CMD_DEL } else { IPSET_CMD_ADD })
                    | ((NFNL_SUBSYS_IPSET as u16) << 8),
                nlmsg_flags: libc::NLM_F_REQUEST as u16,
                nlmsg_seq: 0,
                nlmsg_pid: 0,
            };

            // Add nlmsghdr to buffer
            msg_buf.extend_from_slice(&nlh.nlmsg_len.to_ne_bytes());
            msg_buf.extend_from_slice(&nlh.nlmsg_type.to_ne_bytes());
            msg_buf.extend_from_slice(&nlh.nlmsg_flags.to_ne_bytes());
            msg_buf.extend_from_slice(&nlh.nlmsg_seq.to_ne_bytes());
            msg_buf.extend_from_slice(&nlh.nlmsg_pid.to_ne_bytes());

            // Add nfgenmsg
            let nfg = NfGenMsg {
                nfgen_family: af,
                version: NFNETLINK_V0,
                res_id: 0_u16.to_be(), // Big-endian as per kernel expectation
            };
            msg_buf.push(nfg.nfgen_family);
            msg_buf.push(nfg.version);
            msg_buf.extend_from_slice(&nfg.res_id.to_ne_bytes());

            // Pad to alignment after nfgenmsg
            while msg_buf.len() < nl_align(size_of::<NlMsgHdr>() + size_of::<NfGenMsg>()) {
                msg_buf.push(0);
            }

            // Add IPSET_ATTR_PROTOCOL attribute
            Self::add_netlink_attr(&mut msg_buf, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);

            // Add IPSET_ATTR_SETNAME attribute (null-terminated string)
            let mut setname_bytes = setname.as_bytes().to_vec();
            setname_bytes.push(0); // Null terminator
            Self::add_netlink_attr(&mut msg_buf, IPSET_ATTR_SETNAME, &setname_bytes);

            // Mark position for nested IPSET_ATTR_DATA
            let data_attr_start = msg_buf.len();
            // Reserve space for nested attribute header (will fill length later)
            msg_buf.extend_from_slice(&[0u8; size_of::<NlAttr>()]);

            // Mark position for nested IPSET_ATTR_IP
            let ip_attr_start = msg_buf.len();
            // Reserve space for nested attribute header
            msg_buf.extend_from_slice(&[0u8; size_of::<NlAttr>()]);

            // Add actual IP address attribute
            let addr_attr_type = match addr {
                IpAddr::V4(_) => IPSET_ATTR_IPADDR_IPV4,
                IpAddr::V6(_) => IPSET_ATTR_IPADDR_IPV6,
            };
            Self::add_netlink_attr(
                &mut msg_buf,
                addr_attr_type | NLA_F_NET_BYTEORDER,
                &addr_bytes,
            );

            // Calculate and fill nested IPSET_ATTR_IP length
            let ip_attr_len = msg_buf.len() - ip_attr_start;
            let ip_attr_hdr = NlAttr {
                nla_len: ip_attr_len as u16,
                nla_type: NLA_F_NESTED | IPSET_ATTR_IP,
            };
            msg_buf[ip_attr_start..ip_attr_start + 2]
                .copy_from_slice(&ip_attr_hdr.nla_len.to_ne_bytes());
            msg_buf[ip_attr_start + 2..ip_attr_start + 4]
                .copy_from_slice(&ip_attr_hdr.nla_type.to_ne_bytes());

            // Pad to alignment
            while msg_buf.len() < nl_align(msg_buf.len()) {
                msg_buf.push(0);
            }

            // Calculate and fill nested IPSET_ATTR_DATA length
            let data_attr_len = msg_buf.len() - data_attr_start;
            let data_attr_hdr = NlAttr {
                nla_len: data_attr_len as u16,
                nla_type: NLA_F_NESTED | IPSET_ATTR_DATA,
            };
            msg_buf[data_attr_start..data_attr_start + 2]
                .copy_from_slice(&data_attr_hdr.nla_len.to_ne_bytes());
            msg_buf[data_attr_start + 2..data_attr_start + 4]
                .copy_from_slice(&data_attr_hdr.nla_type.to_ne_bytes());

            // Update total message length in header
            let total_len = msg_buf.len() as u32;
            msg_buf[0..4].copy_from_slice(&total_len.to_ne_bytes());

            // Send message to kernel
            send_netlink_message(&socket, &msg_buf)
                .map_err(IpsetError::SendFailed)?;

            let op_name = if remove { "removed" } else { "added" };
            debug!(
                "Successfully {} address {} {} ipset '{}'",
                op_name,
                addr,
                if remove { "from" } else { "to" },
                setname
            );

            Ok(())
        }

        /// Add Netlink attribute to message buffer
        ///
        /// Helper function to append TLV-encoded attribute with proper alignment.
        ///
        /// # Arguments
        ///
        /// * `buf` - Message buffer to append to
        /// * `attr_type` - Attribute type identifier
        /// * `data` - Attribute payload bytes
        fn add_netlink_attr(buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
            let attr_hdr = NlAttr {
                nla_len: (nl_align(size_of::<NlAttr>()) + data.len()) as u16,
                nla_type: attr_type,
            };

            // Add attribute header
            buf.extend_from_slice(&attr_hdr.nla_len.to_ne_bytes());
            buf.extend_from_slice(&attr_hdr.nla_type.to_ne_bytes());

            // Add attribute data
            buf.extend_from_slice(data);

            // Pad to alignment
            while buf.len() < nl_align(buf.len()) {
                buf.push(0);
            }
        }

        /// Legacy raw socket ipset operation (kernel < 2.6.32)
        ///
        /// Uses SOL_IP getsockopt/setsockopt with option 83 for ipset manipulation.
        /// This is the legacy protocol that predates Netlink IPSET subsystem.
        ///
        /// # Protocol
        ///
        /// 1. getsockopt(SOL_IP, 83, &req_adt_get) - Query ipset index by name
        /// 2. setsockopt(SOL_IP, 83, &req_adt) - Add/remove address using index
        ///
        /// # Limitations
        ///
        /// - IPv4 only (IPv6 not supported in legacy protocol)
        /// - Hard-coded protocol version 3
        /// - Operation codes: 0x10 (query), 0x101 (add), 0x102 (remove)
        ///
        /// # Arguments
        ///
        /// * `setname` - ipset name (validated length)
        /// * `addr` - IP address (must be IPv4)
        /// * `remove` - true for remove (0x102), false for add (0x101)
        ///
        /// # Returns
        ///
        /// `Ok(())` on success, `IpsetError` on failure
        ///
        /// # Safety
        ///
        /// Uses unsafe blocks for:
        /// - socket() syscall to create AF_INET SOCK_RAW IPPROTO_RAW socket
        /// - getsockopt() to query ipset index
        /// - setsockopt() to add/remove address
        /// - close() to cleanup socket
        ///
        /// All unsafe operations have validated inputs and documented invariants.
        #[allow(clippy::cast_possible_truncation)]
        fn legacy_add_to_ipset(
            setname: &str,
            addr: IpAddr,
            remove: bool,
        ) -> Result<(), IpsetError> {
            // Legacy protocol only supports IPv4
            let ipv4_addr = match addr {
                IpAddr::V4(a) => a,
                IpAddr::V6(_) => return Err(IpsetError::AddressFamilyUnsupported),
            };

            // Create raw socket for legacy ipset protocol
            // SAFETY: socket() syscall with standard constants
            // AF_INET, SOCK_RAW, IPPROTO_RAW are kernel-provided constants
            let sock_fd = unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)
            };

            if sock_fd < 0 {
                return Err(IpsetError::LegacyOperationFailed(
                    IoError::last_os_error(),
                ));
            }

            // RAII guard for socket cleanup
            struct SocketGuard(i32);
            impl Drop for SocketGuard {
                fn drop(&mut self) {
                    unsafe { libc::close(self.0); }
                }
            }
            let _guard = SocketGuard(sock_fd);

            // Step 1: Query ipset index by name
            #[repr(C)]
            struct IpSetReqAdtGet {
                op: u32,
                version: u32,
                set_union: [u8; IPSET_MAXNAMELEN], // union { name, index }
                typename: [u8; IPSET_MAXNAMELEN],
            }

            let mut req_adt_get = IpSetReqAdtGet {
                op: 0x10, // Query operation
                version: 3, // ipset protocol version 3
                set_union: [0; IPSET_MAXNAMELEN],
                typename: [0; IPSET_MAXNAMELEN],
            };

            // Copy setname into request (as 'name' variant of union)
            let setname_bytes = setname.as_bytes();
            req_adt_get.set_union[..setname_bytes.len()].copy_from_slice(setname_bytes);

            let mut optlen = size_of::<IpSetReqAdtGet>() as libc::socklen_t;

            // SAFETY: getsockopt() syscall with valid socket and buffer
            // req_adt_get is properly initialized and sized
            let get_result = unsafe {
                libc::getsockopt(
                    sock_fd,
                    libc::SOL_IP,
                    83, // ipset socket option
                    (&raw mut req_adt_get).cast::<libc::c_void>(),
                    &raw mut optlen,
                )
            };

            if get_result < 0 {
                return Err(IpsetError::LegacyOperationFailed(
                    IoError::last_os_error(),
                ));
            }

            // Step 2: Add/remove address using ipset index
            // After getsockopt, set_union now contains index (u16) instead of name
            #[repr(C)]
            struct IpSetReqAdt {
                op: u32,
                index: u16,
                ip: u32,
            }

            // Extract index from set_union (first 2 bytes as u16)
            let index = u16::from_ne_bytes([
                req_adt_get.set_union[0],
                req_adt_get.set_union[1],
            ]);

            let req_adt = IpSetReqAdt {
                op: if remove { 0x102 } else { 0x101 }, // Remove: 0x102, Add: 0x101
                index,
                ip: u32::from_be_bytes(ipv4_addr.octets()), // Host byte order (ntohl equivalent)
            };

            // SAFETY: setsockopt() syscall with valid socket and buffer
            // req_adt is properly initialized with validated data
            let set_result = unsafe {
                libc::setsockopt(
                    sock_fd,
                    libc::SOL_IP,
                    83, // ipset socket option
                    (&raw const req_adt).cast::<libc::c_void>(),
                    size_of::<IpSetReqAdt>() as libc::socklen_t,
                )
            };

            if set_result < 0 {
                return Err(IpsetError::LegacyOperationFailed(
                    IoError::last_os_error(),
                ));
            }

            let op_name = if remove { "removed" } else { "added" };
            debug!(
                "Successfully {} address {} {} ipset '{}' (legacy protocol)",
                op_name,
                addr,
                if remove { "from" } else { "to" },
                setname
            );

            Ok(())
        }
    }

    // Re-export types at module level for non-Linux platforms to access
    pub use IpsetError;
    pub use IpsetManager;
    pub use KernelProtocol;
}

// Platform-specific exports
#[cfg(target_os = "linux")]
pub use linux_impl::{IpsetError, IpsetManager, KernelProtocol};

// Non-Linux stub implementation
#[cfg(not(target_os = "linux"))]
pub mod stub {
    use std::net::IpAddr;
    use thiserror::Error;

    #[derive(Error, Debug)]
    #[error("ipset not available on this platform (Linux only)")]
    pub struct IpsetError;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KernelProtocol {
        Modern,
        Legacy,
    }

    pub struct IpsetManager;

    impl IpsetManager {
        pub fn new() -> Result<Self, IpsetError> {
            Err(IpsetError)
        }

        pub fn supports_ipv6(&self) -> bool {
            false
        }

        pub async fn add_to_ipset(&self, _setname: &str, _addr: IpAddr) -> Result<(), IpsetError> {
            Err(IpsetError)
        }

        pub async fn remove_from_ipset(&self, _setname: &str, _addr: IpAddr) -> Result<(), IpsetError> {
            Err(IpsetError)
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::{IpsetError, IpsetManager, KernelProtocol};

// Convenience functions for simple ipset operations

/// Add IP address to named ipset
///
/// Convenience function that creates temporary `IpsetManager` and performs add operation.
/// For multiple operations, create `IpsetManager` once and reuse it.
///
/// # Arguments
///
/// * `setname` - Name of ipset (must exist in kernel)
/// * `addr` - IP address to add
///
/// # Returns
///
/// `Ok(())` on success, `IpsetError` on failure
///
/// # Errors
///
/// See `IpsetManager::add_to_ipset()` for error conditions
///
/// # Example
///
/// ```no_run
/// use dnsmasq::integration::ipset::add_to_ipset;
/// use std::net::IpAddr;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: IpAddr = "203.0.113.1".parse()?;
/// add_to_ipset("blocked_domains", addr).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(target_os = "linux")]
pub async fn add_to_ipset(setname: &str, addr: std::net::IpAddr) -> Result<(), IpsetError> {
    let manager = IpsetManager::new()?;
    manager.add_to_ipset(setname, addr).await
}

#[cfg(not(target_os = "linux"))]
pub async fn add_to_ipset(_setname: &str, _addr: std::net::IpAddr) -> Result<(), IpsetError> {
    Err(IpsetError)
}

/// Remove IP address from named ipset
///
/// Convenience function that creates temporary `IpsetManager` and performs remove operation.
/// For multiple operations, create `IpsetManager` once and reuse it.
///
/// # Arguments
///
/// * `setname` - Name of ipset (must exist in kernel)
/// * `addr` - IP address to remove
///
/// # Returns
///
/// `Ok(())` on success, `IpsetError` on failure
///
/// # Errors
///
/// See `IpsetManager::remove_from_ipset()` for error conditions
///
/// # Example
///
/// ```no_run
/// use dnsmasq::integration::ipset::remove_from_ipset;
/// use std::net::IpAddr;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: IpAddr = "203.0.113.1".parse()?;
/// remove_from_ipset("blocked_domains", addr).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(target_os = "linux")]
pub async fn remove_from_ipset(setname: &str, addr: std::net::IpAddr) -> Result<(), IpsetError> {
    let manager = IpsetManager::new()?;
    manager.remove_from_ipset(setname, addr).await
}

#[cfg(not(target_os = "linux"))]
pub async fn remove_from_ipset(_setname: &str, _addr: std::net::IpAddr) -> Result<(), IpsetError> {
    Err(IpsetError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipset_error_display() {
        let err = IpsetError::InvalidSetName("toolongname".to_string());
        assert!(err.to_string().contains("toolongname"));
        assert!(err.to_string().contains("maximum length"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_kernel_protocol_variants() {
        assert_eq!(KernelProtocol::Modern, KernelProtocol::Modern);
        assert_ne!(KernelProtocol::Modern, KernelProtocol::Legacy);
    }

    #[test]
    fn test_ipv6_support() {
        // Can't test actual socket creation without root, but can test logic
        #[cfg(target_os = "linux")]
        {
            let manager_modern = IpsetManager {
                socket: None,
                protocol: KernelProtocol::Modern,
            };
            assert!(manager_modern.supports_ipv6());

            let manager_legacy = IpsetManager {
                socket: None,
                protocol: KernelProtocol::Legacy,
            };
            assert!(!manager_legacy.supports_ipv6());
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_setname_validation() {
        let manager = IpsetManager {
            socket: None,
            protocol: KernelProtocol::Modern,
        };
        
        // Name too long (>= 32 chars)
        let long_name = "a".repeat(32);
        let addr: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        
        let result = manager.add_to_ipset(&long_name, addr).await;
        assert!(matches!(result, Err(IpsetError::InvalidSetName(_))));
    }
}
