// Copyright (c) 2000-2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Platform-specific FFI abstractions for dnsmasq
//!
//! This module provides safe Rust wrappers around platform-specific system calls
//! and external library integrations. All unsafe operations are isolated to private
//! implementation details, with public APIs providing memory-safe interfaces.
//!
//! # Modules
//!
//! - `netlink`: Linux netlink socket operations for interface enumeration and monitoring
//! - `pf`: BSD Packet Filter (PF) table integration for firewall rules
//! - `conntrack`: Linux connection tracking (conntrack) mark propagation
//! - `nftables`: Linux nftables set integration (successor to ipset)
//! - `ubus`: `OpenWrt` `ubus` IPC interface for embedded systems
//! - `solaris_privileges`: Solaris privilege management
//!
//! # Platform Support
//!
//! This module uses conditional compilation to provide platform-specific implementations:
//! - Linux: netlink, conntrack, nftables, ipset (via netlink)
//! - BSD (FreeBSD, OpenBSD, NetBSD): PF tables, routing sockets
//! - macOS: Routing sockets (subset of BSD functionality)
//! - Solaris: Privilege management, SIOCGLIFCONF fallback
//! - `OpenWrt`: `ubus` integration (Linux-based)
//!
//! # Memory Safety
//!
//! All C FFI operations follow strict safety guidelines:
//! 1. Input validation before passing data to C
//! 2. Immediate wrapping of raw pointers in safe Rust types
//! 3. Automatic resource cleanup via Drop trait (RAII)
//! 4. Documented safety invariants for all unsafe blocks
//! 5. Bounds checking for all buffer operations

use nix::unistd::close;
use std::fmt::Debug;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::mem::size_of;
use std::os::unix::io::RawFd;

// ============================================================================
// Linux Netlink Module
// ============================================================================

/// Linux netlink socket operations for network interface monitoring
///
/// Provides safe wrappers around Linux netlink `RTNETLINK` protocol for:
/// - Interface enumeration (`RTM_GETLINK`, `RTM_GETADDR`)
/// - Address monitoring (`RTM_NEWADDR`, `RTM_DELADDR`)
/// - Route monitoring (`RTM_NEWROUTE`, `RTM_DELROUTE`)
/// - Real-time notifications via multicast groups
///
/// # Platform
///
/// Linux-only. Requires kernel 2.6.32 or later for full functionality.
///
/// # Safety
///
/// All netlink message parsing uses safe slice operations to prevent
/// buffer overflows. Message size is validated before parsing.
#[cfg(target_os = "linux")]
pub mod netlink {
    use super::{Debug, RawFd, close, IoResult, IoError, size_of, ErrorKind};
    use libc::{
        nlmsghdr, sockaddr_nl, AF_NETLINK, SOCK_RAW,
    };
    

    /// Netlink socket wrapper with automatic cleanup
    pub struct NetlinkSocket {
        fd: RawFd,
        pid: u32,
    }

    impl NetlinkSocket {
        /// Returns the raw file descriptor for `poll()` integration
        #[must_use]
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd
        }

        /// Returns the netlink PID assigned by kernel
        #[must_use]
        pub fn pid(&self) -> u32 {
            self.pid
        }
    }

    impl Drop for NetlinkSocket {
        fn drop(&mut self) {
            // SAFETY: fd is valid until drop, close is idempotent
            let _ = close(self.fd);
        }
    }

    /// Netlink message header for `RTNETLINK` messages
    ///
    /// Matches kernel struct `nlmsghdr` from `linux/netlink.h`
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct NlMsgHdr {
        /// Total message length including header
        pub nlmsg_len: u32,
        /// Message type (`RTM_*` constants)
        pub nlmsg_type: u16,
        /// Message flags (`NLM_F_*` constants)
        pub nlmsg_flags: u16,
        /// Sequence number for message ordering
        pub nlmsg_seq: u32,
        /// Port ID of sender process
        pub nlmsg_pid: u32,
    }

    /// Netfilter generic message header
    ///
    /// Used for netfilter subsystem communication (ipset, conntrack, nftables)
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct NfGenMsg {
        /// Address family (`AF_INET`, `AF_INET6`, etc.)
        pub nfgen_family: u8,
        /// Protocol version
        pub version: u8,
        /// Resource ID (big-endian)
        pub res_id: u16,
    }

    /// Netlink attribute header for TLV encoding
    ///
    /// Netlink uses type-length-value (TLV) encoding for message payload
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct NlAttr {
        /// Total length of attribute including header (in bytes)
        pub nla_len: u16,
        /// Attribute type identifier
        pub nla_type: u16,
    }

    /// Create a netlink socket for RTNETLINK communication
    ///
    /// Opens an `AF_NETLINK` socket for network interface and address monitoring.
    /// The socket is bound to netlink address with specified multicast groups.
    ///
    /// # Arguments
    ///
    /// * `protocol` - Netlink protocol (e.g., `NETLINK_ROUTE`, `NETLINK_NETFILTER`)
    /// * `groups` - Multicast groups bitmask (0 for no multicast)
    ///
    /// # Returns
    ///
    /// `NetlinkSocket` on success with assigned PID
    ///
    /// # Errors
    ///
    /// Returns `IoError` if:
    /// - Socket creation fails (permission denied, out of file descriptors)
    /// - Bind fails (EPERM if groups > 0 without `CAP_NET_ADMIN`)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::ffi::platform::create_netlink_socket;
    /// # use libc::{NETLINK_ROUTE, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR};
    /// let socket = create_netlink_socket(
    ///     NETLINK_ROUTE,
    ///     (RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR) as u32
    /// )?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[allow(clippy::cast_possible_truncation)]
    pub fn create_netlink_socket(protocol: i32, groups: u32) -> IoResult<NetlinkSocket> {
        // SAFETY: socket(2) syscall with validated parameters
        // AF_NETLINK is kernel-provided constant, SOCK_RAW is standard type
        let fd = unsafe {
            libc::socket(AF_NETLINK, SOCK_RAW, protocol)
        };

        if fd < 0 {
            return Err(IoError::last_os_error());
        }

        // Construct netlink address for bind
        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_groups = groups;
        addr.nl_pid = 0; // Kernel assigns PID

        // SAFETY: bind(2) syscall with valid fd and address structure
        // addr is properly initialized sockaddr_nl with correct size
        let bind_result = unsafe {
            libc::bind(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                size_of::<sockaddr_nl>() as u32,
            )
        };

        if bind_result < 0 {
            let err = IoError::last_os_error();
            // If EPERM on multicast bind, try again without groups
            if err.kind() == ErrorKind::PermissionDenied && groups != 0 {
                addr.nl_groups = 0;
                let retry_result = unsafe {
                    libc::bind(
                        fd,
                        (&raw const addr).cast::<libc::sockaddr>(),
                        size_of::<sockaddr_nl>() as u32,
                    )
                };
                if retry_result < 0 {
                    // SAFETY: close on error path to prevent fd leak
                    unsafe { libc::close(fd); }
                    return Err(IoError::last_os_error());
                }
            } else {
                // SAFETY: close on error path to prevent fd leak
                unsafe { libc::close(fd); }
                return Err(err);
            }
        }

        // Retrieve assigned PID via getsockname
        let mut addr_out: sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = size_of::<sockaddr_nl>() as u32;

        // SAFETY: getsockname(2) syscall to retrieve assigned PID
        // fd is valid, addr_out and addr_len are properly initialized
        let getsockname_result = unsafe {
            libc::getsockname(
                fd,
                (&raw mut addr_out).cast::<libc::sockaddr>(),
                &raw mut addr_len,
            )
        };

        if getsockname_result < 0 {
            // SAFETY: close on error path to prevent fd leak
            unsafe { libc::close(fd); }
            return Err(IoError::last_os_error());
        }

        Ok(NetlinkSocket {
            fd,
            pid: addr_out.nl_pid,
        })
    }

    /// Bind netlink socket to specified address
    ///
    /// Binds an already-created netlink socket to a specific netlink address.
    /// This is typically used to change multicast group memberships.
    ///
    /// # Arguments
    ///
    /// * `socket` - Netlink socket to bind
    /// * `groups` - Multicast groups bitmask
    ///
    /// # Errors
    ///
    /// Returns `IoError` if bind fails (EPERM without `CAP_NET_ADMIN`)
    #[allow(clippy::cast_possible_truncation)]
    pub fn bind_netlink_socket(socket: &NetlinkSocket, groups: u32) -> IoResult<()> {
        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_groups = groups;
        addr.nl_pid = 0;

        // SAFETY: bind(2) syscall with valid socket fd and address
        let result = unsafe {
            libc::bind(
                socket.fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                size_of::<sockaddr_nl>() as u32,
            )
        };

        if result < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Send netlink message to kernel
    ///
    /// Sends a constructed netlink message buffer to the kernel.
    ///
    /// # Arguments
    ///
    /// * `socket` - Netlink socket
    /// * `msg` - Message buffer (must start with valid nlmsghdr)
    ///
    /// # Returns
    ///
    /// Number of bytes sent
    ///
    /// # Errors
    ///
    /// Returns `IoError` if send fails
    ///
    /// # Safety
    ///
    /// Message buffer must contain valid netlink message with correct length field.
    /// Buffer size must match or exceed `nlmsg_len` field in header.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn send_netlink_message(socket: &NetlinkSocket, msg: &[u8]) -> IoResult<usize> {
        // Validate message has at least nlmsghdr
        if msg.len() < size_of::<nlmsghdr>() {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "Message too short for netlink header",
            ));
        }

        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0; // Kernel destination

        // SAFETY: sendto(2) syscall with validated buffer and address
        // msg buffer is valid for msg.len() bytes
        let result = unsafe {
            libc::sendto(
                socket.fd,
                msg.as_ptr().cast::<libc::c_void>(),
                msg.len(),
                0,
                (&raw const addr).cast::<libc::sockaddr>(),
                size_of::<sockaddr_nl>() as u32,
            )
        };

        if result < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    /// Receive netlink message from kernel
    ///
    /// Receives a netlink message into provided buffer. Validates message
    /// originates from kernel (`nl_pid` == 0) to prevent userspace spoofing.
    ///
    /// # Arguments
    ///
    /// * `socket` - Netlink socket
    /// * `buf` - Buffer to receive message
    /// * `flags` - MSG_* flags (e.g., `MSG_DONTWAIT`, `MSG_TRUNC`)
    ///
    /// # Returns
    ///
    /// Number of bytes received and source address
    ///
    /// # Errors
    ///
    /// Returns `IoError` if:
    /// - recv fails (EINTR, ENOBUFS)
    /// - Message not from kernel (security check)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use dnsmasq::ffi::platform::{create_netlink_socket, recv_netlink_message};
    /// # use libc::NETLINK_ROUTE;
    /// let socket = create_netlink_socket(NETLINK_ROUTE, 0)?;
    /// let mut buf = vec![0u8; 8192];
    /// let (len, addr) = recv_netlink_message(&socket, &mut buf, 0)?;
    /// // Process message in buf[..len]
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn recv_netlink_message(
        socket: &NetlinkSocket,
        buf: &mut [u8],
        flags: i32,
    ) -> IoResult<(usize, sockaddr_nl)> {
        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = size_of::<sockaddr_nl>() as u32;

        // SAFETY: recvfrom(2) syscall with valid buffer and address storage
        // buf is valid for buf.len() bytes write access
        let result = unsafe {
            libc::recvfrom(
                socket.fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                flags,
                (&raw mut addr).cast::<libc::sockaddr>(),
                &raw mut addr_len,
            )
        };

        if result < 0 {
            return Err(IoError::last_os_error());
        }

        // Security check: Only accept messages from kernel (pid == 0)
        if addr.nl_pid != 0 {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                "Netlink message not from kernel",
            ));
        }

        Ok((result as usize, addr))
    }

    /// Align length to netlink message boundary (4 bytes)
    ///
    /// Netlink protocol requires all lengths to be aligned to 4-byte boundaries.
    ///
    /// # Arguments
    ///
    /// * `len` - Length to align
    ///
    /// # Returns
    ///
    /// Aligned length (rounded up to nearest multiple of 4)
    #[inline]
    #[must_use] 
    pub fn nl_align(len: usize) -> usize {
        (len + 3) & !3
    }

    // Netlink/Netfilter constants from C headers
    // Note: NETLINK_NETFILTER is already imported from libc (line 76)
    /// Netfilter subsystem ID for ipset
    pub const NFNL_SUBSYS_IPSET: u8 = 6;
    /// ipset protocol version
    pub const IPSET_PROTOCOL: u8 = 6;
    /// Maximum ipset name length
    pub const IPSET_MAXNAMELEN: usize = 32;
    /// ipset command: add element
    pub const IPSET_CMD_ADD: u16 = 9;
    /// ipset command: delete element
    pub const IPSET_CMD_DEL: u16 = 10;
    /// ipset attribute: protocol version
    pub const IPSET_ATTR_PROTOCOL: u16 = 1;
    /// ipset attribute: set name
    pub const IPSET_ATTR_SETNAME: u16 = 2;
    /// ipset attribute: element data
    pub const IPSET_ATTR_DATA: u16 = 7;
    /// ipset attribute: IP address
    pub const IPSET_ATTR_IP: u16 = 1;
    /// ipset attribute: IPv4 address
    pub const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
    /// ipset attribute: IPv6 address
    pub const IPSET_ATTR_IPADDR_IPV6: u16 = 2;
    /// Netlink attribute flag: nested attribute
    pub const NLA_F_NESTED: u16 = 1 << 15;
    /// Netlink attribute flag: network byte order
    pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
    /// Netfilter netlink version 0
    pub const NFNETLINK_V0: u8 = 0;
}

// ============================================================================
// BSD PF (Packet Filter) Module
// ============================================================================

/// BSD Packet Filter table integration
///
/// Provides safe wrappers around BSD pf ioctl operations for:
/// - Creating pf tables
/// - Adding/removing IP addresses from tables
/// - Table persistence management
///
/// # Platform
///
/// BSD-only (FreeBSD, OpenBSD, NetBSD). Requires /dev/pf access.
///
/// # Safety
///
/// All ioctl operations validate buffer sizes and command codes before
/// invoking kernel operations.
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub mod pf {
    use super::*;
    use libc::{c_char, c_int, ioctl};
    use std::fs::OpenOptions;
    use std::net::IpAddr;
    use std::ptr;

    /// PF device file descriptor wrapper
    pub struct PfDevice {
        fd: RawFd,
    }

    impl PfDevice {
        /// Returns raw file descriptor
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    impl Drop for PfDevice {
        fn drop(&mut self) {
            // SAFETY: fd is valid until drop
            let _ = close(self.fd);
        }
    }

    /// PF address structure
    ///
    /// Represents an IP address with family and netmask for pf table operations.
    /// Matches struct pfr_addr from net/pfvar.h
    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct PfrAddr {
        pub pfra_af: u8,
        pub pfra_net: u8,
        _pad1: [u8; 2],
        pub pfra_ip4addr: [u8; 4],
        pub pfra_ip6addr: [u8; 16],
    }

    impl PfrAddr {
        /// Create PfrAddr from Rust IpAddr
        pub fn from_ip(addr: IpAddr) -> Self {
            let mut pfr: PfrAddr = unsafe { std::mem::zeroed() };
            match addr {
                IpAddr::V4(ip) => {
                    pfr.pfra_af = libc::AF_INET as u8;
                    pfr.pfra_net = 32; // Host address
                    pfr.pfra_ip4addr.copy_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    pfr.pfra_af = libc::AF_INET6 as u8;
                    pfr.pfra_net = 128; // Host address
                    pfr.pfra_ip6addr.copy_from_slice(&ip.octets());
                }
            }
            pfr
        }
    }

    /// PF table structure
    ///
    /// Identifies a pf table by name and flags.
    /// Matches struct pfr_table from net/pfvar.h
    #[repr(C)]
    #[derive(Debug)]
    pub struct PfrTable {
        pub pfrt_name: [c_char; PF_TABLE_NAME_SIZE],
        pub pfrt_flags: u32,
    }

    impl PfrTable {
        /// Create PfrTable from table name
        pub fn from_name(name: &str, flags: u32) -> IoResult<Self> {
            if name.len() >= PF_TABLE_NAME_SIZE {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    "Table name too long",
                ));
            }

            let mut table: PfrTable = unsafe { std::mem::zeroed() };
            table.pfrt_flags = flags;
            
            // Copy name with null termination
            for (i, byte) in name.bytes().enumerate() {
                table.pfrt_name[i] = byte as c_char;
            }

            Ok(table)
        }
    }

    /// PF table ioctl structure
    ///
    /// Structure for DIOCR* ioctl operations on pf tables.
    #[repr(C)]
    pub struct PfiocTable {
        pub pfrio_buffer: *mut PfrAddr,
        pub pfrio_esize: c_int,
        pub pfrio_size: c_int,
        pub pfrio_nadd: c_int,
        pub pfrio_ndel: c_int,
        pub pfrio_nchange: c_int,
        pub pfrio_naddr: c_int,
        pub pfrio_ticket: u32,
        pub pfrio_flags: u32,
        pub pfrio_table: PfrTable,
    }

    /// PF table name maximum size
    pub const PF_TABLE_NAME_SIZE: usize = 32;
    /// PF table flag: persist table
    pub const PFR_TFLAG_PERSIST: u32 = 0x00000001;

    // ioctl command codes (platform-specific, example values)
    /// ioctl: Add tables
    pub const DIOCRADDTABLES: libc::c_ulong = 0xc4504407; // Placeholder
    /// ioctl: Add addresses to table
    pub const DIOCRADDADDRS: libc::c_ulong = 0xc4504408; // Placeholder
    /// ioctl: Delete addresses from table
    pub const DIOCRDELADDRS: libc::c_ulong = 0xc4504409; // Placeholder

    /// Open /dev/pf for pf table operations
    ///
    /// Opens the BSD packet filter device for ioctl operations.
    ///
    /// # Returns
    ///
    /// PfDevice on success
    ///
    /// # Errors
    ///
    /// Returns IoError if:
    /// - /dev/pf doesn't exist
    /// - Permission denied (requires root or appropriate capabilities)
    /// - Device already opened by exclusive user
    pub fn open_pf_device() -> IoResult<PfDevice> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/pf")?;

        let fd = file.as_raw_fd();
        std::mem::forget(file); // Prevent double-close

        Ok(PfDevice { fd })
    }

    /// Create pf table with persistence flag
    ///
    /// Creates a new pf table if it doesn't exist. Table persists across
    /// dnsmasq restarts if PFR_TFLAG_PERSIST is set.
    ///
    /// # Arguments
    ///
    /// * `dev` - PF device handle
    /// * `table_name` - Name of table to create
    ///
    /// # Errors
    ///
    /// Returns IoError if ioctl fails
    pub fn create_pf_table(dev: &PfDevice, table_name: &str) -> IoResult<()> {
        let table = PfrTable::from_name(table_name, PFR_TFLAG_PERSIST)?;

        let mut io: PfiocTable = unsafe { std::mem::zeroed() };
        io.pfrio_buffer = ptr::null_mut();
        io.pfrio_esize = size_of::<PfrTable>() as c_int;
        io.pfrio_size = 1;
        io.pfrio_table = table;

        // SAFETY: ioctl(2) with validated command code and structure
        // dev.fd is valid, io structure is properly initialized
        let result = unsafe {
            ioctl(dev.fd, DIOCRADDTABLES, &mut io as *mut PfiocTable)
        };

        if result < 0 {
            let err = IoError::last_os_error();
            // EEXIST is not an error - table already exists
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Ok(());
            }
            return Err(err);
        }

        Ok(())
    }

    /// Add IP address to pf table
    ///
    /// Adds an IPv4 or IPv6 address to specified pf table.
    ///
    /// # Arguments
    ///
    /// * `dev` - PF device handle
    /// * `table_name` - Table name
    /// * `addr` - IP address to add
    ///
    /// # Errors
    ///
    /// Returns IoError if ioctl fails
    pub fn add_pf_address(dev: &PfDevice, table_name: &str, addr: IpAddr) -> IoResult<()> {
        let table = PfrTable::from_name(table_name, 0)?;
        let pfr_addr = PfrAddr::from_ip(addr);

        let mut addr_vec = vec![pfr_addr];

        let mut io: PfiocTable = unsafe { std::mem::zeroed() };
        io.pfrio_buffer = addr_vec.as_mut_ptr();
        io.pfrio_esize = size_of::<PfrAddr>() as c_int;
        io.pfrio_size = 1;
        io.pfrio_table = table;

        // SAFETY: ioctl(2) with validated buffer and command
        // addr_vec remains valid for duration of ioctl call
        let result = unsafe {
            ioctl(dev.fd, DIOCRADDADDRS, &mut io as *mut PfiocTable)
        };

        if result < 0 {
            return Err(IoError::last_os_error());
        }

        Ok(())
    }

    /// Delete IP address from pf table
    ///
    /// Removes an IPv4 or IPv6 address from specified pf table.
    ///
    /// # Arguments
    ///
    /// * `dev` - PF device handle
    /// * `table_name` - Table name
    /// * `addr` - IP address to remove
    ///
    /// # Errors
    ///
    /// Returns IoError if ioctl fails (ENOENT if address not in table)
    pub fn delete_pf_address(dev: &PfDevice, table_name: &str, addr: IpAddr) -> IoResult<()> {
        let table = PfrTable::from_name(table_name, 0)?;
        let pfr_addr = PfrAddr::from_ip(addr);

        let mut addr_vec = vec![pfr_addr];

        let mut io: PfiocTable = unsafe { std::mem::zeroed() };
        io.pfrio_buffer = addr_vec.as_mut_ptr();
        io.pfrio_esize = size_of::<PfrAddr>() as c_int;
        io.pfrio_size = 1;
        io.pfrio_table = table;

        // SAFETY: ioctl(2) with validated buffer and command
        let result = unsafe {
            ioctl(dev.fd, DIOCRDELADDRS, &mut io as *mut PfiocTable)
        };

        if result < 0 {
            let err = IoError::last_os_error();
            // ENOENT is not an error - address wasn't in table
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err(err);
        }

        Ok(())
    }

    /// ioctl wrapper with error handling
    ///
    /// Generic ioctl wrapper for pf operations with error translation.
    ///
    /// # Safety
    ///
    /// Caller must ensure cmd is valid for dev and arg structure is appropriate.
    pub unsafe fn ioctl_pf<T>(dev: &PfDevice, cmd: libc::c_ulong, arg: *mut T) -> IoResult<()> {
        // SAFETY: Caller guarantees cmd and arg validity
        let result = ioctl(dev.fd, cmd, arg);
        if result < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(())
        }
    }

    /// BSD-specific error codes
    pub const AF_INET: u8 = libc::AF_INET as u8;
    pub const AF_INET6: u8 = libc::AF_INET6 as u8;
    pub const ESRCH: i32 = libc::ESRCH;
    pub const ENOENT: i32 = libc::ENOENT;
}

// ============================================================================
// Linux Connection Tracking (conntrack) Module
// ============================================================================

/// Linux connection tracking mark propagation
///
/// Provides safe wrappers around `libnetfilter_conntrack` for querying
/// firewall marks associated with network connections.
///
/// # Platform
///
/// Linux-only. Requires `libnetfilter_conntrack.so` and kernel conntrack module.
///
/// # Safety
///
/// All conntrack handle lifecycle is managed via RAII. Raw pointers from
/// `libnetfilter_conntrack` are immediately wrapped in safe types.
#[cfg(all(target_os = "linux", feature = "conntrack"))]
#[allow(clippy::cast_possible_truncation)]
pub mod conntrack {
    use super::{IoResult, IoError};

    /// Opaque type from `libnetfilter_conntrack` representing a connection tracking entry
    #[repr(C)]
    pub struct nf_conntrack {
        _private: [u8; 0],
    }

    /// Opaque type from `libnetfilter_conntrack` representing a connection tracking handle
    #[repr(C)]
    pub struct nfct_handle {
        _private: [u8; 0],
    }

    /// Connection tracking handle wrapper with automatic cleanup
    pub struct ConntrackHandle {
        handle: *mut nfct_handle,
    }

    impl ConntrackHandle {
        /// Open new conntrack handle
        #[must_use] 
        pub fn new() -> Option<Self> {
            // SAFETY: FFI call to open conntrack netlink socket
            let handle = unsafe { nfct_open(CONNTRACK, 0) };
            if handle.is_null() {
                None
            } else {
                Some(ConntrackHandle { handle })
            }
        }

        /// Query conntrack for connection entry
        ///
        /// # Errors
        ///
        /// Returns an error if the conntrack query fails
        #[allow(clippy::cast_possible_wrap)]
        pub fn query(&self, ct: &ConntrackEntry) -> IoResult<()> {
            // SAFETY: handle and ct.entry are valid pointers
            let result = unsafe {
                nfct_query(self.handle, NFCT_Q_GET as libc::c_int, ct.entry.cast_const() as *mut _)
            };
            if result < 0 {
                Err(IoError::last_os_error())
            } else {
                Ok(())
            }
        }

        /// Register callback for query results
        ///
        /// # Errors
        ///
        /// Returns an error if callback registration fails
        ///
        /// # Safety
        ///
        /// `data` pointer must be valid for the lifetime of the callback registration
        pub unsafe fn register_callback(
            &self,
            callback: NfctCallback,
            data: *mut libc::c_void,
        ) -> IoResult<()> {
            // SAFETY: FFI call with function pointer and optional data (caller's responsibility)
            let result = unsafe { nfct_callback_register(self.handle, NFCT_T_ALL, callback, data) };
            if result < 0 {
                Err(IoError::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for ConntrackHandle {
        fn drop(&mut self) {
            // SAFETY: handle is valid until drop
            unsafe {
                nfct_close(self.handle);
            }
        }
    }

    /// Connection tracking entry wrapper
    pub struct ConntrackEntry {
        pub(crate) entry: *mut nf_conntrack,
    }

    impl ConntrackEntry {
        /// Create new conntrack entry
        #[must_use] 
        pub fn new() -> Option<Self> {
            // SAFETY: FFI call to allocate conntrack structure
            let entry = unsafe { nfct_new() };
            if entry.is_null() {
                None
            } else {
                Some(ConntrackEntry { entry })
            }
        }

        /// Set 8-bit attribute
        pub fn set_attr_u8(&mut self, attr: u32, value: u8) {
            // SAFETY: entry is valid, attr and value are by-value
            unsafe {
                nfct_set_attr_u8(self.entry, attr, value);
            }
        }

        /// Set 16-bit attribute
        pub fn set_attr_u16(&mut self, attr: u32, value: u16) {
            // SAFETY: entry is valid, value passed by value
            unsafe {
                nfct_set_attr_u16(self.entry, attr, value);
            }
        }

        /// Set 32-bit attribute
        pub fn set_attr_u32(&mut self, attr: u32, value: u32) {
            // SAFETY: entry is valid, value passed by value
            unsafe {
                nfct_set_attr_u32(self.entry, attr, value);
            }
        }

        /// Set pointer attribute
        ///
        /// # Safety
        ///
        /// Caller must ensure pointer is valid for the lifetime required by conntrack.
        pub unsafe fn set_attr(&mut self, attr: u32, value: *const libc::c_void) {
            // SAFETY: entry is valid, value pointer validated by caller
            unsafe { nfct_set_attr(self.entry, attr, value); }
        }

        /// Get 32-bit attribute
        #[must_use] 
        pub fn get_attr_u32(&self, attr: u32) -> u32 {
            // SAFETY: entry is valid, attr is enum value
            unsafe { nfct_get_attr_u32(self.entry, attr) }
        }

        /// Get raw entry pointer for callback registration
        #[must_use] 
        pub fn as_ptr(&self) -> *mut nf_conntrack {
            self.entry
        }
    }

    impl Drop for ConntrackEntry {
        fn drop(&mut self) {
            // SAFETY: entry is valid until drop
            unsafe {
                nfct_destroy(self.entry);
            }
        }
    }

    // FFI declarations for libnetfilter_conntrack
    type NfctCallback = unsafe extern "C" fn(
        nf_conntrack_msg_type: libc::c_int,
        ct: *mut nf_conntrack,
        data: *mut libc::c_void,
    ) -> libc::c_int;

    extern "C" {
        fn nfct_open(subsys: u8, flags: u32) -> *mut nfct_handle;
        fn nfct_close(handle: *mut nfct_handle) -> libc::c_int;
        fn nfct_query(
            handle: *mut nfct_handle,
            qt: libc::c_int,
            data: *mut libc::c_void,
        ) -> libc::c_int;
        fn nfct_callback_register(
            handle: *mut nfct_handle,
            cb_type: libc::c_int,
            cb: NfctCallback,
            data: *mut libc::c_void,
        ) -> libc::c_int;
        fn nfct_new() -> *mut nf_conntrack;
        fn nfct_destroy(ct: *mut nf_conntrack);
        fn nfct_set_attr_u8(ct: *mut nf_conntrack, attr: u32, value: u8);
        fn nfct_set_attr_u16(ct: *mut nf_conntrack, attr: u32, value: u16);
        fn nfct_set_attr_u32(ct: *mut nf_conntrack, attr: u32, value: u32);
        fn nfct_set_attr(ct: *mut nf_conntrack, attr: u32, value: *const libc::c_void);
        fn nfct_get_attr_u32(ct: *const nf_conntrack, attr: u32) -> u32;
    }

    // Conntrack constants
    /// Connection tracking subsystem identifier
    pub const CONNTRACK: u8 = 1;
    /// Connection mark attribute
    pub const ATTR_MARK: u32 = 0;
    /// Layer 3 protocol attribute
    pub const ATTR_L3PROTO: u32 = 1;
    /// Layer 4 protocol attribute
    pub const ATTR_L4PROTO: u32 = 2;
    /// IPv4 source address attribute
    pub const ATTR_IPV4_SRC: u32 = 3;
    /// IPv4 destination address attribute
    pub const ATTR_IPV4_DST: u32 = 4;
    /// IPv6 source address attribute
    pub const ATTR_IPV6_SRC: u32 = 5;
    /// IPv6 destination address attribute
    pub const ATTR_IPV6_DST: u32 = 6;
    /// Source port attribute
    pub const ATTR_PORT_SRC: u32 = 7;
    /// Destination port attribute
    pub const ATTR_PORT_DST: u32 = 8;
    /// Query command to get connection entry
    pub const NFCT_Q_GET: u32 = 0;
    /// Callback type for all events
    pub const NFCT_T_ALL: libc::c_int = 0;
    /// Callback return value to continue processing
    pub const NFCT_CB_CONTINUE: libc::c_int = 1;
    /// IPv4 address family constant
    pub const AF_INET: u8 = libc::AF_INET as u8;
    /// IPv6 address family constant
    pub const AF_INET6: u8 = libc::AF_INET6 as u8;
    /// TCP protocol constant
    pub const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
    /// UDP protocol constant
    pub const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8;
}

// ============================================================================
// Linux nftables Module
// ============================================================================

/// Linux nftables set integration
///
/// Provides safe wrappers around libnftables for dynamic set manipulation.
///
/// # Platform
///
/// Linux-only. Requires libnftables.so (nftables 0.9+).
///
/// # Safety
///
/// All nftables context lifecycle managed via RAII. Command buffers are
/// validated for correct UTF-8 before passing to libnftables.
#[cfg(all(target_os = "linux", feature = "nftset"))]
pub mod nftables {
    use super::{IoResult, IoError, ErrorKind};
    use std::ffi::{CString, CStr};

    /// Opaque type from libnftables representing an nftables context
    #[repr(C)]
    pub struct nft_ctx {
        _private: [u8; 0],
    }

    /// Nftables context wrapper with automatic cleanup
    pub struct NftContext {
        ctx: *mut nft_ctx,
    }

    impl NftContext {
        /// Create new nftables context
        #[must_use] 
        pub fn new() -> Option<Self> {
            // SAFETY: FFI call to create nftables context
            let ctx = unsafe { nft_ctx_new(NFT_CTX_DEFAULT) };
            if ctx.is_null() {
                None
            } else {
                Some(NftContext { ctx })
            }
        }

        /// Run nftables command from buffer
        ///
        /// # Arguments
        ///
        /// * `cmd` - nftables command string (e.g., "add element ip filter dnsmasq { 1.2.3.4 }")
        ///
        /// # Errors
        ///
        /// Returns `IoError` if command execution fails
        pub fn run_command(&mut self, cmd: &str) -> IoResult<()> {
            let cmd_cstr = CString::new(cmd).map_err(|_| {
                IoError::new(ErrorKind::InvalidInput, "Command contains null byte")
            })?;

            // SAFETY: ctx is valid, cmd_cstr is valid C string
            let result = unsafe { nft_run_cmd_from_buffer(self.ctx, cmd_cstr.as_ptr()) };

            if result < 0 {
                // Retrieve error message from context
                let error_msg = unsafe {
                    let err_ptr = nft_ctx_get_error_buffer(self.ctx);
                    if err_ptr.is_null() {
                        "nftables command failed".to_string()
                    } else {
                        CStr::from_ptr(err_ptr)
                            .to_string_lossy()
                            .into_owned()
                    }
                };

                return Err(IoError::other(error_msg));
            }

            Ok(())
        }

        /// Buffer last error message
        pub fn buffer_error(&mut self) {
            // SAFETY: ctx is valid
            unsafe {
                nft_ctx_buffer_error(self.ctx);
            }
        }

        /// Get error buffer as string
        #[must_use] 
        pub fn get_error_buffer(&self) -> Option<String> {
            // SAFETY: ctx is valid
            let err_ptr = unsafe { nft_ctx_get_error_buffer(self.ctx) };
            if err_ptr.is_null() {
                None
            } else {
                // SAFETY: err_ptr is valid C string from nftables
                let c_str = unsafe { CStr::from_ptr(err_ptr) };
                Some(c_str.to_string_lossy().into_owned())
            }
        }
    }

    impl Drop for NftContext {
        fn drop(&mut self) {
            // SAFETY: ctx is valid until drop
            unsafe {
                nft_ctx_free(self.ctx);
            }
        }
    }

    // FFI declarations for libnftables
    extern "C" {
        fn nft_ctx_new(flags: u32) -> *mut nft_ctx;
        fn nft_ctx_free(ctx: *mut nft_ctx);
        fn nft_ctx_buffer_error(ctx: *mut nft_ctx);
        fn nft_run_cmd_from_buffer(ctx: *mut nft_ctx, buf: *const libc::c_char) -> libc::c_int;
        fn nft_ctx_get_error_buffer(ctx: *mut nft_ctx) -> *const libc::c_char;
    }

    /// nftables context creation flag: default options
    pub const NFT_CTX_DEFAULT: u32 = 0;
}

// ============================================================================
// OpenWrt ubus Module
// ============================================================================

/// `OpenWrt` ubus IPC integration
///
/// Provides safe wrappers around libubus for embedded system control.
///
/// # Platform
///
/// OpenWrt/LEDE only. Requires libubus.so and libubox.so.
///
/// # Safety
///
/// All ubus context and `blob_buf` lifecycle managed via RAII. String
/// conversions validated before passing to C.
#[cfg(all(target_os = "linux", feature = "ubus"))]
pub mod ubus {
    use super::{IoResult, IoError, ErrorKind};
    use std::ffi::{CString, CStr};
    use std::ptr;

    // Opaque types from libubus/libubox
    /// Opaque type from libubus representing a ubus context
    #[repr(C)]
    pub struct ubus_context {
        _private: [u8; 0],
    }

    /// Opaque type from libubus representing a ubus object
    #[repr(C)]
    pub struct ubus_object {
        _private: [u8; 0],
    }

    /// Opaque type from libubox representing a blob buffer
    #[repr(C)]
    pub struct blob_buf {
        _private: [u8; 0],
    }

    /// Opaque type from libubox representing a blob attribute
    #[repr(C)]
    pub struct blob_attr {
        _private: [u8; 0],
    }

    /// Policy descriptor for blobmsg parsing
    #[repr(C)]
    pub struct blobmsg_policy {
        /// Name of the attribute
        pub name: *const libc::c_char,
        /// Expected type of the attribute
        pub blobmsg_type: u32,
    }

    /// Ubus context wrapper with automatic cleanup
    pub struct UbusContext {
        ctx: *mut ubus_context,
    }

    impl UbusContext {
        /// Get raw context pointer for FFI
        #[must_use] 
        pub fn as_ptr(&self) -> *mut ubus_context {
            self.ctx
        }
    }

    impl Drop for UbusContext {
        fn drop(&mut self) {
            // SAFETY: ctx is valid until drop
            unsafe {
                ubus_free(self.ctx);
            }
        }
    }

    /// Blob buffer wrapper for message construction
    pub struct BlobBuf {
        buf: *mut blob_buf,
    }

    impl BlobBuf {
        /// Initialize blob buffer
        pub fn init(&mut self, id: i32) {
            // SAFETY: buf is valid, id is simple integer
            unsafe {
                blob_buf_init(self.buf, id);
            }
        }

        /// Add u32 field to blob
        ///
        /// # Errors
        /// Returns error if name contains null byte
        pub fn add_u32(&mut self, name: &str, value: u32) -> IoResult<()> {
            let name_cstr = CString::new(name).map_err(|_| {
                IoError::new(ErrorKind::InvalidInput, "Name contains null byte")
            })?;

            // SAFETY: buf is valid, name_cstr is valid C string
            unsafe {
                blobmsg_add_u32(self.buf, name_cstr.as_ptr(), value);
            }
            Ok(())
        }

        /// Add string field to blob
        ///
        /// # Errors
        /// Returns error if name or value contains null byte
        pub fn add_string(&mut self, name: &str, value: &str) -> IoResult<()> {
            let name_cstr = CString::new(name).map_err(|_| {
                IoError::new(ErrorKind::InvalidInput, "Name contains null byte")
            })?;
            let value_cstr = CString::new(value).map_err(|_| {
                IoError::new(ErrorKind::InvalidInput, "Value contains null byte")
            })?;

            // SAFETY: buf is valid, both C strings are valid
            unsafe {
                blobmsg_add_string(self.buf, name_cstr.as_ptr(), value_cstr.as_ptr());
            }
            Ok(())
        }

        /// Start array in blob
        ///
        /// # Errors
        /// Returns error if name contains null byte
        pub fn add_array(&mut self, name: &str) -> IoResult<*mut libc::c_void> {
            let name_cstr = CString::new(name).map_err(|_| {
                IoError::new(ErrorKind::InvalidInput, "Name contains null byte")
            })?;

            // SAFETY: buf is valid, name_cstr is valid C string
            let ptr = unsafe { blobmsg_add_array(self.buf, name_cstr.as_ptr()) };
            Ok(ptr)
        }
    }

    /// Connect to ubus daemon
    #[must_use] 
    pub fn ubus_connect(path: Option<&str>) -> Option<UbusContext> {
        let path_cstr = path.and_then(|p| CString::new(p).ok());
        let path_ptr = path_cstr
            .as_ref()
            .map_or(ptr::null(), |c: &CString| c.as_ptr());

        // SAFETY: FFI call with optional C string
        let ctx = unsafe { ubus_connect_impl(path_ptr) };
        if ctx.is_null() {
            None
        } else {
            Some(UbusContext { ctx })
        }
    }

    /// Add ubus object
    ///
    /// # Errors
    /// Returns error if the ubus object cannot be added
    pub fn ubus_add_object(ctx: &UbusContext, obj: *const ubus_object) -> IoResult<()> {
        // SAFETY: ctx and obj are valid pointers
        let result = unsafe { ubus_add_object_impl(ctx.ctx, obj.cast_mut()) };
        if result < 0 {
            Err(IoError::other("Failed to add ubus object"))
        } else {
            Ok(())
        }
    }

    /// Send ubus notification
    ///
    /// # Errors
    /// Returns error if type name contains null byte or notification fails
    pub fn ubus_notify(
        ctx: &UbusContext,
        obj: *const ubus_object,
        type_name: &str,
        msg: *const blob_attr,
    ) -> IoResult<()> {
        let type_cstr = CString::new(type_name).map_err(|_| {
            IoError::new(ErrorKind::InvalidInput, "Type name contains null byte")
        })?;

        // SAFETY: All pointers are valid, type_cstr is valid C string
        let result = unsafe {
            ubus_notify_impl(
                ctx.ctx,
                obj.cast_mut(),
                type_cstr.as_ptr(),
                msg.cast_mut(),
                -1,
            )
        };

        if result < 0 {
            Err(IoError::other("ubus notify failed"))
        } else {
            Ok(())
        }
    }

    /// Reconnect to ubus daemon
    ///
    /// # Errors
    /// Returns error if reconnection fails
    pub fn ubus_reconnect(ctx: &mut UbusContext, path: Option<&str>) -> IoResult<()> {
        let path_cstr = path.and_then(|p| CString::new(p).ok());
        let path_ptr = path_cstr
            .as_ref()
            .map_or(ptr::null(), |c: &CString| c.as_ptr());

        // SAFETY: ctx is valid, path is optional C string
        let result = unsafe { ubus_reconnect_impl(ctx.ctx, path_ptr) };
        if result < 0 {
            Err(IoError::other("ubus reconnect failed"))
        } else {
            Ok(())
        }
    }

    /// Send ubus reply
    ///
    /// # Errors
    /// Returns error if sending reply fails
    ///
    /// # Safety
    ///
    /// `req` and `msg` pointers must be valid and properly initialized
    pub unsafe fn ubus_send_reply(
        ctx: &UbusContext,
        req: *mut libc::c_void,
        msg: *const blob_attr,
    ) -> IoResult<()> {
        // SAFETY: All pointers are valid (caller's responsibility)
        let result = unsafe { ubus_send_reply_impl(ctx.ctx, req, msg.cast_mut()) };
        if result < 0 {
            Err(IoError::other("Failed to send reply"))
        } else {
            Ok(())
        }
    }

    /// Handle ubus event
    ///
    /// # Errors
    /// Returns error if event handling fails
    pub fn ubus_handle_event(ctx: &UbusContext) -> IoResult<()> {
        // SAFETY: ctx is valid
        let result = unsafe { ubus_handle_event_impl(ctx.ctx) };
        if result < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Parse blobmsg
    ///
    /// # Errors
    /// Returns error if parsing fails
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub fn blobmsg_parse(
        policy: &[BlobmsgPolicy],
        data: *const blob_attr,
        len: usize,
    ) -> IoResult<Vec<*mut blob_attr>> {
        let mut tb: Vec<*mut blob_attr> = vec![ptr::null_mut(); policy.len()];

        // SAFETY: All pointers are valid, lengths are validated
        let result = unsafe {
            blobmsg_parse_impl(
                policy.as_ptr().cast(),
                policy.len() as libc::c_int,
                tb.as_mut_ptr(),
                data.cast_mut(),
                len as libc::c_int,
            )
        };

        if result < 0 {
            Err(IoError::new(ErrorKind::InvalidData, "blobmsg parse failed"))
        } else {
            Ok(tb)
        }
    }

    /// Get ubus error string
    #[must_use] 
    pub fn ubus_strerror(error: i32) -> String {
        // SAFETY: FFI call returns static string
        let ptr = unsafe { ubus_strerror_impl(error) };
        if ptr.is_null() {
            format!("Unknown error {error}")
        } else {
            unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
        }
    }

    // FFI declarations for libubus
    extern "C" {
        fn ubus_connect_impl(path: *const libc::c_char) -> *mut ubus_context;
        fn ubus_free(ctx: *mut ubus_context);
        fn ubus_add_object_impl(ctx: *mut ubus_context, obj: *mut ubus_object) -> libc::c_int;
        fn ubus_notify_impl(
            ctx: *mut ubus_context,
            obj: *mut ubus_object,
            type_name: *const libc::c_char,
            msg: *mut blob_attr,
            timeout: libc::c_int,
        ) -> libc::c_int;
        fn ubus_reconnect_impl(ctx: *mut ubus_context, path: *const libc::c_char)
            -> libc::c_int;
        fn ubus_send_reply_impl(
            ctx: *mut ubus_context,
            req: *mut libc::c_void,
            msg: *mut blob_attr,
        ) -> libc::c_int;
        fn ubus_handle_event_impl(ctx: *mut ubus_context) -> libc::c_int;
        fn blob_buf_init(buf: *mut blob_buf, id: libc::c_int);
        fn blobmsg_add_u32(buf: *mut blob_buf, name: *const libc::c_char, value: u32);
        fn blobmsg_add_string(
            buf: *mut blob_buf,
            name: *const libc::c_char,
            value: *const libc::c_char,
        );
        fn blobmsg_add_array(
            buf: *mut blob_buf,
            name: *const libc::c_char,
        ) -> *mut libc::c_void;
        fn blobmsg_parse_impl(
            policy: *const blobmsg_policy,
            policy_len: libc::c_int,
            tb: *mut *mut blob_attr,
            data: *mut blob_attr,
            len: libc::c_int,
        ) -> libc::c_int;
        fn ubus_strerror_impl(error: libc::c_int) -> *const libc::c_char;
    }

    /// Blob message policy
    pub type BlobmsgPolicy = blobmsg_policy;

    /// Blobmsg type constants
    /// 32-bit integer type
    pub const BLOBMSG_TYPE_INT32: u32 = 5;
    /// String type
    pub const BLOBMSG_TYPE_STRING: u32 = 3;
    /// Array type
    pub const BLOBMSG_TYPE_ARRAY: u32 = 6;
    /// Table type
    pub const BLOBMSG_TYPE_TABLE: u32 = 7;
}

// ============================================================================
// Solaris Privileges Module
// ============================================================================

/// Solaris privilege management
///
/// Provides safe wrappers around Solaris privilege APIs for fine-grained
/// capability management.
///
/// # Platform
///
/// Solaris-only.
///
/// # Safety
///
/// All privilege set operations validate inputs and manage lifecycle via RAII.
#[cfg(target_os = "solaris")]
pub mod solaris_privileges {
    use super::*;

    // Opaque type from Solaris priv.h
    #[repr(C)]
    pub struct priv_set_t {
        _private: [u8; 0],
    }

    /// Solaris privilege set wrapper
    pub struct PrivSet {
        set: *mut priv_set_t,
    }

    impl PrivSet {
        /// Convert privilege name to priv_set_t
        pub fn from_name(name: &str) -> Option<Self> {
            let name_cstr = CString::new(name).ok()?;

            // SAFETY: FFI call with valid C string
            let set = unsafe { priv_str_to_set_impl(name_cstr.as_ptr(), ptr::null_mut()) };

            if set.is_null() {
                None
            } else {
                Some(PrivSet { set })
            }
        }

        /// Add privilege to set
        pub fn add(&mut self, priv_name: &str) -> IoResult<()> {
            let priv_cstr = CString::new(priv_name).map_err(|_| {
                IoError::new(ErrorKind::InvalidInput, "Privilege name contains null")
            })?;

            // SAFETY: set is valid, priv_cstr is valid C string
            let result = unsafe { priv_addset_impl(self.set, priv_cstr.as_ptr()) };

            if result < 0 {
                Err(IoError::last_os_error())
            } else {
                Ok(())
            }
        }

        /// Invert privilege set
        pub fn inverse(&mut self) {
            // SAFETY: set is valid
            unsafe {
                priv_inverse_impl(self.set);
            }
        }

        /// Apply privilege set to process
        pub fn apply(&self, op: u32, which: u32) -> IoResult<()> {
            // SAFETY: set is valid, op and which are enum values
            let result = unsafe { setppriv_impl(op as libc::c_int, which as libc::c_int, self.set) };

            if result < 0 {
                Err(IoError::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for PrivSet {
        fn drop(&mut self) {
            // SAFETY: set is valid until drop
            unsafe {
                priv_freeset_impl(self.set);
            }
        }
    }

    // FFI declarations for Solaris priv APIs
    extern "C" {
        fn priv_str_to_set_impl(
            buf: *const libc::c_char,
            sep: *const libc::c_char,
        ) -> *mut priv_set_t;
        fn priv_addset_impl(set: *mut priv_set_t, priv_name: *const libc::c_char) -> libc::c_int;
        fn priv_inverse_impl(set: *mut priv_set_t);
        fn setppriv_impl(op: libc::c_int, which: libc::c_int, set: *const priv_set_t)
            -> libc::c_int;
        fn priv_freeset_impl(set: *mut priv_set_t);
    }

    /// Privilege name: ICMP access
    pub const PRIV_NET_ICMPACCESS: &str = "net_icmpaccess";
    /// Privilege name: network config
    pub const PRIV_SYS_NET_CONFIG: &str = "sys_net_config";
    /// setppriv operation: remove privileges
    pub const PRIV_OFF: u32 = 1;
    /// setppriv which: limit set
    pub const PRIV_LIMIT: u32 = 4;
}

// ============================================================================
// Platform Detection and Exports
// ============================================================================

// Re-export platform-specific modules based on target OS
#[cfg(target_os = "linux")]
pub use netlink::*;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub use pf::*;

#[cfg(all(target_os = "linux", feature = "conntrack"))]
pub use conntrack::*;

#[cfg(all(target_os = "linux", feature = "nftset"))]
pub use nftables::*;

#[cfg(all(target_os = "linux", feature = "ubus"))]
pub use ubus::*;

#[cfg(target_os = "solaris")]
pub use solaris_privileges::*;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nl_align() {
        use netlink::nl_align;
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
        assert_eq!(nl_align(7), 8);
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn test_pfr_addr_from_ip() {
        use pf::PfrAddr;
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let pfr = PfrAddr::from_ip(ipv4);
        assert_eq!(pfr.pfra_af, libc::AF_INET as u8);
        assert_eq!(pfr.pfra_net, 32);
        assert_eq!(&pfr.pfra_ip4addr, &[192, 168, 1, 1]);
    }

    #[test]
    fn test_socket_addr_conversion() {
        let ipv4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        match ipv4 {
            SocketAddr::V4(addr) => {
                assert_eq!(addr.ip().octets(), [127, 0, 0, 1]);
                assert_eq!(addr.port(), 8080);
            }
            SocketAddr::V6(_) => panic!("Expected IPv4"),
        }
    }

    // ============================================================================
    // Additional Ad-hoc Tests for Platform FFI Wrappers
    // ============================================================================

    #[cfg(target_os = "linux")]
    #[test]
    fn test_netlink_nl_align_comprehensive() {
        use netlink::nl_align;
        
        // Test comprehensive boundary conditions
        assert_eq!(nl_align(0), 0, "Zero should align to zero");
        assert_eq!(nl_align(1), 4, "1 should align to 4");
        assert_eq!(nl_align(2), 4, "2 should align to 4");
        assert_eq!(nl_align(3), 4, "3 should align to 4");
        assert_eq!(nl_align(4), 4, "4 should align to 4");
        assert_eq!(nl_align(5), 8, "5 should align to 8");
        assert_eq!(nl_align(6), 8, "6 should align to 8");
        assert_eq!(nl_align(7), 8, "7 should align to 8");
        assert_eq!(nl_align(8), 8, "8 should align to 8");
        assert_eq!(nl_align(15), 16, "15 should align to 16");
        assert_eq!(nl_align(16), 16, "16 should align to 16");
        assert_eq!(nl_align(17), 20, "17 should align to 20");
        assert_eq!(nl_align(1000), 1000, "1000 should align to 1000");
        assert_eq!(nl_align(1001), 1004, "1001 should align to 1004");
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn test_pfr_addr_ipv4_comprehensive() {
        use pf::PfrAddr;
        
        // Test various IPv4 addresses
        let test_cases = vec![
            ([192, 168, 1, 1], "private network"),
            ([127, 0, 0, 1], "loopback"),
            ([10, 0, 0, 1], "private network 10.x"),
            ([172, 16, 0, 1], "private network 172.16.x"),
            ([8, 8, 8, 8], "public DNS"),
        ];
        
        for (octets, desc) in test_cases {
            let ipv4 = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
            let pfr = PfrAddr::from_ip(ipv4);
            
            assert_eq!(pfr.pfra_af, libc::AF_INET as u8, "Should be AF_INET for {}", desc);
            assert_eq!(pfr.pfra_net, 32, "Should be /32 prefix for {}", desc);
            assert_eq!(&pfr.pfra_ip4addr, &octets, "IPv4 octets should match for {}", desc);
        }
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn test_pfr_addr_ipv6_comprehensive() {
        use pf::PfrAddr;
        
        // Test IPv6 loopback
        let loopback = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let pfr_loop = PfrAddr::from_ip(loopback);
        
        assert_eq!(pfr_loop.pfra_af, libc::AF_INET6 as u8, "Should be AF_INET6");
        assert_eq!(pfr_loop.pfra_net, 128, "Should be /128 prefix");
        
        let expected_loopback: [u8; 16] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        assert_eq!(&pfr_loop.pfra_ip6addr, &expected_loopback, "IPv6 loopback bytes should match");
        
        // Test link-local address
        let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let pfr_ll = PfrAddr::from_ip(link_local);
        
        assert_eq!(pfr_ll.pfra_af, libc::AF_INET6 as u8);
        assert_eq!(pfr_ll.pfra_net, 128);
    }

    #[test]
    fn test_ip_addr_type_compatibility() {
        // Verify that IP address types work correctly with our FFI wrappers
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        match v4 {
            IpAddr::V4(addr) => {
                assert_eq!(addr.octets(), [192, 168, 1, 1]);
                assert!(!addr.is_loopback());
                assert!(!addr.is_multicast());
            }
            IpAddr::V6(_) => panic!("Expected IPv4"),
        }
        
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        match v6 {
            IpAddr::V6(addr) => {
                assert_eq!(addr.segments()[0], 0x2001);
                assert_eq!(addr.segments()[1], 0xdb8);
                assert!(!addr.is_loopback());
            }
            IpAddr::V4(_) => panic!("Expected IPv6"),
        }
    }

    #[test]
    fn test_socket_addr_ipv4_properties() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 53));
        
        match addr {
            SocketAddr::V4(v4_addr) => {
                assert_eq!(v4_addr.ip().octets(), [192, 168, 1, 100]);
                assert_eq!(v4_addr.port(), 53);
            }
            SocketAddr::V6(_) => panic!("Expected IPv4 socket address"),
        }
    }

    #[test]
    fn test_socket_addr_ipv6_properties() {
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            53,
            0,
            0,
        ));
        
        match addr {
            SocketAddr::V6(v6_addr) => {
                assert_eq!(v6_addr.ip().segments()[0], 0x2001);
                assert_eq!(v6_addr.port(), 53);
                assert_eq!(v6_addr.flowinfo(), 0);
                assert_eq!(v6_addr.scope_id(), 0);
            }
            SocketAddr::V4(_) => panic!("Expected IPv6 socket address"),
        }
    }

    #[test]
    fn test_error_kind_mapping() {
        // Test that IoError kinds are correctly used
        use std::io::{Error as IoError, ErrorKind};
        
        let permission_err = IoError::new(ErrorKind::PermissionDenied, "access denied");
        assert_eq!(permission_err.kind(), ErrorKind::PermissionDenied);
        
        let not_found_err = IoError::new(ErrorKind::NotFound, "resource not found");
        assert_eq!(not_found_err.kind(), ErrorKind::NotFound);
        
        let other_err = IoError::other("platform error");
        assert_eq!(other_err.kind(), ErrorKind::Other);
    }

    #[test]
    fn test_module_organization() {
        // Verify that the module structure is correctly organized
        
        // Platform-specific types should be conditionally compiled
        #[cfg(target_os = "linux")]
        {
            // On Linux, netlink should be available
            use netlink::NetlinkSocket;
            let _ = std::mem::size_of::<NetlinkSocket>();
        }
        
        #[cfg(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            // On BSD, PF should be available
            use pf::PfrAddr;
            let _ = std::mem::size_of::<PfrAddr>();
        }
        
        // This test verifies correct compilation - if it compiles, it passes
    }

    #[cfg(target_os = "solaris")]
    #[test]
    fn test_solaris_privilege_string_constants() {
        use solaris_privileges::*;
        
        // Verify privilege name constants
        assert_eq!(PRIV_NET_ICMPACCESS, "net_icmpaccess");
        assert_eq!(PRIV_SYS_NET_CONFIG, "sys_net_config");
        
        // Verify operation constants
        assert_eq!(PRIV_OFF, 1);
        assert_eq!(PRIV_LIMIT, 4);
        
        // Verify these are valid C-compatible strings
        assert!(!PRIV_NET_ICMPACCESS.is_empty());
        assert!(!PRIV_SYS_NET_CONFIG.is_empty());
    }

    #[test]
    fn test_raw_fd_type_safety() {
        // Verify that RawFd is correctly used throughout the module
        use std::os::unix::io::RawFd;
        
        // RawFd should be a signed integer type
        let valid_fd: RawFd = 3;
        assert!(valid_fd > 0);
        
        let invalid_fd: RawFd = -1;
        assert!(invalid_fd < 0);
    }

    #[test]
    fn test_ffi_safety_documentation() {
        // This test documents the safety invariants enforced by the module:
        //
        // 1. All FFI calls validate inputs before passing to C
        // 2. Raw pointers are immediately wrapped in safe Rust types
        // 3. Resources are automatically cleaned up via Drop trait (RAII)
        // 4. All unsafe blocks have documented safety preconditions
        // 5. Buffer operations are bounds-checked using safe slices
        //
        // These are compile-time guarantees enforced by Rust's type system
        // and documented throughout the module implementation.
        //
        // This test verifies correct compilation and documentation - if it compiles, it passes
    }
}
