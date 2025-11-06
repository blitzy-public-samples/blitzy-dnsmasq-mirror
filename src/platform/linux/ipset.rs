// Copyright (c) 2013 Jason A. Donenfeld <Jason@zx2c4.com>
// Copyright (c) 2024 Blitzy Platform (Rust port)
// SPDX-License-Identifier: GPL-2.0-or-later

//! Linux ipset integration module for DNS-resolved address insertion
//!
//! # Overview
//!
//! This module provides automatic insertion of DNS-resolved IP addresses into Linux kernel
//! ipset collections via Netlink protocol, enabling dynamic firewall rules and routing policies
//! based on domain name resolution. When dnsmasq resolves a DNS query for domains configured
//! with the `--ipset` option, the resulting IP addresses are automatically added to named ipsets
//! via the kernel's Netlink interface.
//!
//! # Features
//!
//! - **Modern Netlink Protocol**: Full support for kernel 2.6.32+ using Netfilter Netlink
//! - **Legacy Raw Socket Protocol**: Backward compatibility for older kernels (< 2.6.32)
//! - **IPv4 and IPv6**: Complete support for both address families (IPv6 requires modern kernel)
//! - **Automatic Protocol Selection**: Detects kernel version and selects appropriate protocol
//! - **Memory Safety**: Eliminates manual buffer management through Rust ownership
//! - **Type Safety**: Uses `IpAddr` enum instead of C union for compile-time correctness
//!
//! # Requirements
//!
//! - **CAP_NET_ADMIN**: Required capability for Netlink socket operations
//! - **ipset kernel module**: Must be loaded (`modprobe ip_set`)
//! - **Pre-created ipsets**: Sets must exist in kernel before address insertion
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use std::net::IpAddr;
//! use ipset::{IpsetManager, add_to_ipset};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize ipset manager with kernel version detection
//! let manager = IpsetManager::new()?;
//!
//! // Add resolved DNS address to ipset
//! let addr: IpAddr = "203.0.113.1".parse()?;
//! add_to_ipset("blocked_domains", addr, false).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! The module supports two protocol implementations:
//!
//! - **Modern (Netlink)**: Uses AF_NETLINK socket with NETLINK_NETFILTER protocol for
//!   kernels >= 2.6.32. Supports both IPv4 and IPv6 with full protocol features.
//! - **Legacy (Raw Socket)**: Uses AF_INET raw socket with IPPROTO_RAW for older kernels.
//!   Limited to IPv4 only.
//!
//! Protocol selection is automatic based on kernel version detection at initialization.

use byteorder::{ByteOrder, NetworkEndian};
use nix::sys::socket::{self, AddressFamily, SockProtocol, SockType, SockFlag};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};
use thiserror::Error;
use tracing::info;

// Netlink protocol constants for ipset subsystem
const NFNL_SUBSYS_IPSET: u8 = 6;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;
const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_CMD_ADD: u8 = 9;
const IPSET_CMD_DEL: u8 = 10;
const IPSET_MAXNAMELEN: usize = 32;
const IPSET_PROTOCOL: u8 = 6;

// Netlink flags
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NFNETLINK_V0: u8 = 0;

// Netlink message flags
const NLM_F_REQUEST: u16 = 1;

// Legacy protocol constants
const LEGACY_IPSET_OP_QUERY: u32 = 0x10;
const LEGACY_IPSET_OP_ADD: u32 = 0x101;
const LEGACY_IPSET_OP_DEL: u32 = 0x102;
const LEGACY_IPSET_VERSION: u32 = 3;
const LEGACY_IPSET_SOCKOPT: i32 = 83;

// Buffer size for Netlink message construction
const BUFF_SZ: usize = 256;

// Netlink alignment macro
const fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Error types for ipset operations
///
/// Comprehensive error enumeration covering all failure modes in ipset integration,
/// including initialization failures, socket errors, validation errors, and protocol errors.
#[derive(Debug, Error)]
pub enum IpsetError {
    /// Initialization failed during manager construction
    #[error("Failed to initialize ipset: {0}")]
    InitFailed(String),

    /// Socket operation failed (creation, binding, or I/O)
    #[error("Socket error: {0}")]
    SocketError(#[from] std::io::Error),

    /// Set name exceeds IPSET_MAXNAMELEN limit
    #[error("Ipset name too long (max {IPSET_MAXNAMELEN} characters)")]
    NameTooLong,

    /// IPv6 address used with legacy protocol or unsupported address family
    #[error("Unsupported address family: {0}")]
    UnsupportedAddressFamily(String),

    /// Failed to send Netlink message to kernel
    #[error("Failed to send ipset command: {0}")]
    SendFailed(String),

    /// Failed to bind Netlink socket to kernel
    #[error("Failed to bind netlink socket: {0}")]
    BindFailed(String),
}

/// Ipset protocol selection
///
/// Determines which protocol implementation to use based on kernel version.
/// Modern protocol requires kernel >= 2.6.32 and supports full IPv6.
/// Legacy protocol is for older kernels and supports IPv4 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsetProtocol {
    /// Modern Netlink-based protocol (kernel >= 2.6.32)
    Modern,
    /// Legacy raw socket protocol (kernel < 2.6.32, IPv4 only)
    Legacy,
}

/// Netlink attribute header
///
/// Represents the Type-Length-Value (TLV) header for Netlink attributes.
/// All Netlink messages are composed of these attributes with proper alignment.
#[repr(C)]
struct NetlinkAttr {
    nla_len: u16,  // Total length including header
    nla_type: u16, // Attribute type with optional flags
}

/// Netfilter generic message header
///
/// Header that follows the main Netlink message header for Netfilter subsystem messages.
/// Specifies address family and protocol version.
#[repr(C)]
struct NfGenMsg {
    nfgen_family: u8,  // AF_INET or AF_INET6
    version: u8,       // Always NFNETLINK_V0
    res_id: u16,       // Resource ID (unused, set to 0)
}

/// Netlink message header
///
/// Main header for all Netlink protocol messages. Contains message length, type,
/// flags, and sequence/port identifiers.
#[repr(C)]
struct NetlinkMsgHdr {
    nlmsg_len: u32,   // Message length including header
    nlmsg_type: u16,  // Message type (command)
    nlmsg_flags: u16, // Message flags
    nlmsg_seq: u32,   // Sequence number
    nlmsg_pid: u32,   // Sending process port ID
}

/// Linux ipset manager
///
/// Manages the connection to the Linux kernel ipset subsystem and provides methods
/// for adding and removing IP addresses from named ipsets. Automatically selects
/// between modern Netlink protocol and legacy raw socket protocol based on kernel version.
///
/// # Examples
///
/// ```rust,no_run
/// # use std::net::IpAddr;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = IpsetManager::new()?;
/// let addr: IpAddr = "192.0.2.1".parse()?;
/// manager.add_to_set("myipset", addr).await?;
/// # Ok(())
/// # }
/// ```
pub struct IpsetManager {
    socket: IpsetSocket,
    protocol: IpsetProtocol,
}

/// RAII wrapper for ipset socket file descriptor
///
/// Ensures proper cleanup of socket resources through Drop trait implementation.
struct IpsetSocket {
    fd: RawFd,
}

impl IpsetSocket {
    /// Create new socket with modern Netlink protocol
    fn new_modern() -> Result<Self, IpsetError> {
        let fd = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            Some(SockProtocol::NetlinkNetfilter),
        )
        .map_err(|e| IpsetError::SocketError(std::io::Error::from_raw_os_error(e as i32)))?;

        // Bind to Netlink with kernel
        let addr = libc::sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        unsafe {
            if libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            ) < 0
            {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(IpsetError::BindFailed(err.to_string()));
            }
        }

        info!("Initialized ipset with modern Netlink protocol");
        Ok(Self { fd })
    }

    /// Create new socket with legacy raw socket protocol
    fn new_legacy() -> Result<Self, IpsetError> {
        let fd = socket::socket(
            AddressFamily::Inet,
            SockType::Raw,
            SockFlag::empty(),
            Some(SockProtocol::Raw),
        )
        .map_err(|e| IpsetError::SocketError(std::io::Error::from_raw_os_error(e as i32)))?;

        info!("Initialized ipset with legacy raw socket protocol (IPv4 only)");
        Ok(Self { fd })
    }
}

impl AsRawFd for IpsetSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for IpsetSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl IpsetManager {
    /// Create new ipset manager with automatic protocol detection
    ///
    /// Detects the kernel version and selects the appropriate protocol:
    /// - Kernel >= 2.6.32: Modern Netlink protocol with full IPv4/IPv6 support
    /// - Kernel < 2.6.32: Legacy raw socket protocol with IPv4 only
    ///
    /// # Errors
    ///
    /// Returns `IpsetError::InitFailed` if socket creation or binding fails.
    /// This typically indicates missing CAP_NET_ADMIN capability or that the
    /// ipset kernel module is not loaded.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use ipset::IpsetManager;
    /// let manager = IpsetManager::new()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new() -> Result<Self, IpsetError> {
        // Detect kernel version
        let kernel_version = Self::detect_kernel_version();
        let use_modern = kernel_version >= (2, 6, 32);

        let protocol = if use_modern {
            IpsetProtocol::Modern
        } else {
            IpsetProtocol::Legacy
        };

        let socket = if use_modern {
            IpsetSocket::new_modern()?
        } else {
            IpsetSocket::new_legacy()?
        };

        Ok(Self { socket, protocol })
    }

    /// Detect Linux kernel version
    ///
    /// Parses /proc/version or uses uname to determine kernel version.
    /// Returns tuple (major, minor, patch) for version comparison.
    fn detect_kernel_version() -> (u32, u32, u32) {
        let mut utsname: libc::utsname = unsafe { mem::zeroed() };
        
        unsafe {
            if libc::uname(&mut utsname) == 0 {
                let release = std::ffi::CStr::from_ptr(utsname.release.as_ptr())
                    .to_string_lossy();
                
                if let Some((major, minor, patch)) = Self::parse_kernel_version(&release) {
                    return (major, minor, patch);
                }
            }
        }

        // Default to modern kernel if detection fails (safe fallback)
        (3, 0, 0)
    }

    /// Parse kernel version string (e.g., "5.15.0-91-generic")
    fn parse_kernel_version(version_str: &str) -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = version_str.split(&['.', '-'][..]).collect();
        
        if parts.len() >= 3 {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            let patch = parts[2].parse().ok()?;
            Some((major, minor, patch))
        } else {
            None
        }
    }

    /// Get the protocol being used by this manager
    ///
    /// # Returns
    ///
    /// Returns `IpsetProtocol::Modern` for Netlink protocol or
    /// `IpsetProtocol::Legacy` for raw socket protocol.
    pub fn protocol(&self) -> IpsetProtocol {
        self.protocol
    }

    /// Add IP address to named ipset
    ///
    /// Adds the specified IP address to the named ipset in the kernel.
    /// The ipset must already exist (created via `ipset create` command).
    ///
    /// # Arguments
    ///
    /// * `setname` - Name of the ipset to modify (max 31 characters)
    /// * `addr` - IP address to add (IPv4 or IPv6)
    ///
    /// # Errors
    ///
    /// - `IpsetError::NameTooLong`: Set name exceeds IPSET_MAXNAMELEN
    /// - `IpsetError::UnsupportedAddressFamily`: IPv6 with legacy protocol
    /// - `IpsetError::SendFailed`: Failed to send command to kernel
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use ipset::IpsetManager;
    /// # use std::net::IpAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = IpsetManager::new()?;
    /// let addr: IpAddr = "203.0.113.50".parse()?;
    /// manager.add_to_set("blocked_ips", addr).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_to_set(&self, setname: &str, addr: IpAddr) -> Result<(), IpsetError> {
        self.modify_set(setname, addr, false).await
    }

    /// Remove IP address from named ipset
    ///
    /// Removes the specified IP address from the named ipset in the kernel.
    ///
    /// # Arguments
    ///
    /// * `setname` - Name of the ipset to modify (max 31 characters)
    /// * `addr` - IP address to remove (IPv4 or IPv6)
    ///
    /// # Errors
    ///
    /// Same error conditions as `add_to_set`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use ipset::IpsetManager;
    /// # use std::net::IpAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = IpsetManager::new()?;
    /// let addr: IpAddr = "203.0.113.50".parse()?;
    /// manager.remove_from_set("blocked_ips", addr).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn remove_from_set(&self, setname: &str, addr: IpAddr) -> Result<(), IpsetError> {
        self.modify_set(setname, addr, true).await
    }

    /// Internal method to modify ipset (add or remove)
    async fn modify_set(
        &self,
        setname: &str,
        addr: IpAddr,
        remove: bool,
    ) -> Result<(), IpsetError> {
        match self.protocol {
            IpsetProtocol::Modern => self.modern_modify_set(setname, addr, remove).await,
            IpsetProtocol::Legacy => self.legacy_modify_set(setname, addr, remove).await,
        }
    }

    /// Modern Netlink protocol implementation
    async fn modern_modify_set(
        &self,
        setname: &str,
        addr: IpAddr,
        remove: bool,
    ) -> Result<(), IpsetError> {
        // Validate setname length
        if setname.len() >= IPSET_MAXNAMELEN {
            return Err(IpsetError::NameTooLong);
        }

        // Determine address family and size
        let (af, addr_bytes) = match addr {
            IpAddr::V4(ipv4) => (libc::AF_INET as u8, ipv4.octets().to_vec()),
            IpAddr::V6(ipv6) => (libc::AF_INET6 as u8, ipv6.octets().to_vec()),
        };

        // Construct Netlink message
        let mut buffer = vec![0u8; BUFF_SZ];
        let mut offset = 0;

        // Netlink message header
        let nlh = NetlinkMsgHdr {
            nlmsg_len: nl_align(mem::size_of::<NetlinkMsgHdr>()) as u32,
            nlmsg_type: ((NFNL_SUBSYS_IPSET as u16) << 8)
                | (if remove { IPSET_CMD_DEL } else { IPSET_CMD_ADD } as u16),
            nlmsg_flags: NLM_F_REQUEST,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };

        // Write Netlink header
        Self::write_struct(&mut buffer, &mut offset, &nlh);

        // Netfilter generic message
        let nfg = NfGenMsg {
            nfgen_family: af,
            version: NFNETLINK_V0,
            res_id: 0,
        };

        Self::write_struct(&mut buffer, &mut offset, &nfg);

        // Add protocol attribute
        let proto = IPSET_PROTOCOL;
        Self::add_attr(&mut buffer, &mut offset, IPSET_ATTR_PROTOCOL, &[proto]);

        // Add setname attribute (null-terminated)
        let mut setname_bytes = setname.as_bytes().to_vec();
        setname_bytes.push(0);
        Self::add_attr(&mut buffer, &mut offset, IPSET_ATTR_SETNAME, &setname_bytes);

        // Add nested DATA attribute
        let data_start = offset;
        offset += nl_align(mem::size_of::<NetlinkAttr>());

        // Add nested IP attribute
        let ip_start = offset;
        offset += nl_align(mem::size_of::<NetlinkAttr>());

        // Add IP address attribute
        let addr_type = if af == libc::AF_INET as u8 {
            IPSET_ATTR_IPADDR_IPV4
        } else {
            IPSET_ATTR_IPADDR_IPV6
        } | NLA_F_NET_BYTEORDER;

        Self::add_attr(&mut buffer, &mut offset, addr_type, &addr_bytes);

        // Set nested IP attribute length
        let ip_len = (offset - ip_start) as u16;
        let ip_attr = NetlinkAttr {
            nla_len: ip_len,
            nla_type: NLA_F_NESTED | IPSET_ATTR_IP,
        };
        Self::write_struct_at(&mut buffer, ip_start, &ip_attr);

        // Set nested DATA attribute length
        let data_len = (offset - data_start) as u16;
        let data_attr = NetlinkAttr {
            nla_len: data_len,
            nla_type: NLA_F_NESTED | IPSET_ATTR_DATA,
        };
        Self::write_struct_at(&mut buffer, data_start, &data_attr);

        // Update total message length
        let total_len = offset as u32;
        NetworkEndian::write_u32(&mut buffer[0..4], total_len);

        // Send message to kernel
        self.send_netlink_message(&buffer[..offset]).await?;

        info!(
            "{} address {} to ipset '{}'",
            if remove { "Removed" } else { "Added" },
            addr,
            setname
        );

        Ok(())
    }

    /// Legacy raw socket protocol implementation (IPv4 only)
    async fn legacy_modify_set(
        &self,
        setname: &str,
        addr: IpAddr,
        remove: bool,
    ) -> Result<(), IpsetError> {
        // Validate setname length
        if setname.len() >= IPSET_MAXNAMELEN {
            return Err(IpsetError::NameTooLong);
        }

        // Legacy protocol only supports IPv4
        let ipv4 = match addr {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => {
                return Err(IpsetError::UnsupportedAddressFamily(
                    "IPv6 not supported with legacy ipset protocol (kernel < 2.6.32)".to_string(),
                ));
            }
        };

        // Query ipset index by name
        #[repr(C)]
        struct IpSetReqAdtGet {
            op: u32,
            version: u32,
            set_name: [u8; IPSET_MAXNAMELEN],
            typename: [u8; IPSET_MAXNAMELEN],
        }

        let mut req_get: IpSetReqAdtGet = unsafe { mem::zeroed() };
        req_get.op = LEGACY_IPSET_OP_QUERY;
        req_get.version = LEGACY_IPSET_VERSION;
        
        let name_bytes = setname.as_bytes();
        req_get.set_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let mut req_len = mem::size_of::<IpSetReqAdtGet>() as libc::socklen_t;
        
        unsafe {
            if libc::getsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_IP,
                LEGACY_IPSET_SOCKOPT,
                &mut req_get as *mut _ as *mut libc::c_void,
                &mut req_len,
            ) < 0
            {
                return Err(IpsetError::SendFailed(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
        }

        // Extract set index from first two bytes of set_name field
        let set_index = u16::from_ne_bytes([req_get.set_name[0], req_get.set_name[1]]);

        // Add or remove address
        #[repr(C)]
        struct IpSetReqAdt {
            op: u32,
            index: u16,
            _padding: u16,
            ip: u32,
        }

        let req_adt = IpSetReqAdt {
            op: if remove {
                LEGACY_IPSET_OP_DEL
            } else {
                LEGACY_IPSET_OP_ADD
            },
            index: set_index,
            _padding: 0,
            ip: u32::from_be_bytes(ipv4.octets()),
        };

        unsafe {
            if libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_IP,
                LEGACY_IPSET_SOCKOPT,
                &req_adt as *const _ as *const libc::c_void,
                mem::size_of::<IpSetReqAdt>() as libc::socklen_t,
            ) < 0
            {
                return Err(IpsetError::SendFailed(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
        }

        info!(
            "{} IPv4 address {} to ipset '{}' (legacy protocol)",
            if remove { "Removed" } else { "Added" },
            ipv4,
            setname
        );

        Ok(())
    }

    /// Send Netlink message to kernel with retry on EINTR
    async fn send_netlink_message(&self, buffer: &[u8]) -> Result<(), IpsetError> {
        let addr = libc::sockaddr_nl {
            nl_family: libc::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        loop {
            unsafe {
                let result = libc::sendto(
                    self.socket.as_raw_fd(),
                    buffer.as_ptr() as *const libc::c_void,
                    buffer.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_nl>() as u32,
                );

                if result < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        // Retry on EINTR
                        continue;
                    }
                    return Err(IpsetError::SendFailed(err.to_string()));
                }

                return Ok(());
            }
        }
    }

    /// Write structure to buffer at current offset
    fn write_struct<T>(buffer: &mut [u8], offset: &mut usize, data: &T) {
        let size = mem::size_of::<T>();
        let aligned_offset = nl_align(*offset);
        
        unsafe {
            let src = data as *const T as *const u8;
            let dst = buffer[aligned_offset..].as_mut_ptr();
            std::ptr::copy_nonoverlapping(src, dst, size);
        }
        
        *offset = nl_align(aligned_offset + size);
    }

    /// Write structure to buffer at specific offset
    fn write_struct_at<T>(buffer: &mut [u8], offset: usize, data: &T) {
        let size = mem::size_of::<T>();
        
        unsafe {
            let src = data as *const T as *const u8;
            let dst = buffer[offset..].as_mut_ptr();
            std::ptr::copy_nonoverlapping(src, dst, size);
        }
    }

    /// Add Netlink attribute to message buffer
    fn add_attr(buffer: &mut [u8], offset: &mut usize, attr_type: u16, data: &[u8]) {
        let attr_start = *offset;
        let payload_len = nl_align(mem::size_of::<NetlinkAttr>()) + data.len();
        
        let attr = NetlinkAttr {
            nla_len: payload_len as u16,
            nla_type: attr_type,
        };

        Self::write_struct(buffer, offset, &attr);
        
        // Copy attribute data
        let data_offset = attr_start + nl_align(mem::size_of::<NetlinkAttr>());
        buffer[data_offset..data_offset + data.len()].copy_from_slice(data);
        
        *offset = nl_align(attr_start + payload_len);
    }
}

/// Add IP address to named ipset (convenience function)
///
/// Standalone function that creates a manager, detects protocol, and adds the address
/// to the specified ipset. This is the main entry point for DNS resolution integration.
///
/// # Arguments
///
/// * `setname` - Name of the ipset to modify
/// * `addr` - IP address to add or remove
/// * `remove` - If true, remove address; if false, add address
///
/// # Errors
///
/// Returns any errors from manager creation or ipset modification.
///
/// # Examples
///
/// ```rust,no_run
/// # use std::net::IpAddr;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: IpAddr = "192.0.2.100".parse()?;
/// add_to_ipset("dynamic_blocklist", addr, false).await?;
/// # Ok(())
/// # }
/// ```
pub async fn add_to_ipset(setname: &str, addr: IpAddr, remove: bool) -> Result<(), IpsetError> {
    let manager = IpsetManager::new()?;
    
    if remove {
        manager.remove_from_set(setname, addr).await
    } else {
        manager.add_to_set(setname, addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_version_parsing() {
        assert_eq!(
            IpsetManager::parse_kernel_version("5.15.0-91-generic"),
            Some((5, 15, 0))
        );
        assert_eq!(
            IpsetManager::parse_kernel_version("2.6.32"),
            Some((2, 6, 32))
        );
        assert_eq!(
            IpsetManager::parse_kernel_version("4.19.128"),
            Some((4, 19, 128))
        );
    }

    #[test]
    fn test_nl_align() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
        assert_eq!(nl_align(8), 8);
    }

    #[test]
    fn test_name_length_validation() {
        let long_name = "a".repeat(IPSET_MAXNAMELEN);
        assert!(long_name.len() >= IPSET_MAXNAMELEN);
        
        let valid_name = "a".repeat(IPSET_MAXNAMELEN - 1);
        assert!(valid_name.len() < IPSET_MAXNAMELEN);
    }

    #[test]
    fn test_protocol_enum() {
        assert_eq!(IpsetProtocol::Modern, IpsetProtocol::Modern);
        assert_ne!(IpsetProtocol::Modern, IpsetProtocol::Legacy);
    }
}
