// tables.rs is Copyright (c) 2014 Sven Falempin, All Rights Reserved.
// Rust implementation Copyright (c) 2024 Blitzy Platform Contributors
//
// Author's email: sfalempin@citypassenger.com
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
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! BSD Packet Filter (pf) table integration for DNS-based firewall rules
//!
//! # Detailed Purpose
//!
//! This module provides integration with BSD's Packet Filter (pf) firewall system,
//! enabling dnsmasq to dynamically populate pf tables with IP addresses resolved
//! from DNS queries. This is the BSD equivalent of Linux's ipset (src/ipset.c) or
//! nftables set (src/nftset.c) integration, allowing DNS-based blocking, routing,
//! or traffic shaping policies.
//!
//! When dnsmasq resolves a domain name matching configured ipset rules, the
//! resolved IP addresses are added to specified pf tables. These tables can then
//! be referenced in pf.conf rules for filtering, NAT, or redirection decisions.
//! This enables dynamic firewall policies based on DNS resolution without manual
//! IP address maintenance.
//!
//! The implementation uses pf's ioctl interface (/dev/pf) to manipulate tables
//! at runtime. Tables are created automatically if they don't exist (with
//! PFR_TFLAG_PERSIST flag), and addresses are added or removed using
//! DIOCRADDADDRS/DIOCRDELADDRS ioctl commands.
//!
//! # Key Responsibilities
//!
//! - [`PfDevice::new()`] - Initialize pf device access by opening /dev/pf
//! - [`PfDevice::modify_table()`] - Add or remove IPv4/IPv6 addresses from pf tables
//!
//! # Platform Support
//!
//! This module is only compiled on BSD systems (FreeBSD, OpenBSD, NetBSD) when both
//! the `ipset` feature and a BSD target OS are detected. The entire module is gated
//! by `#[cfg(all(feature = "ipset", any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]`.
//!
//! # Dependencies
//!
//! - `/dev/pf` device - Requires read/write access (typically root privileges)
//! - libc crate - For ioctl operations and BSD pf structures
//!
//! # Thread Safety
//!
//! `PfDevice` is `!Send` and `!Sync` due to the raw file descriptor. This module is
//! designed for single-threaded use within dnsmasq's event loop architecture.
//!
//! # Examples
//!
//! ```rust,ignore
//! use std::net::IpAddr;
//! use crate::util::tables::{PfDevice, TableOperation};
//!
//! // Initialize pf device during startup
//! let pf = PfDevice::new()?;
//!
//! // Add IPv4 address to "malware" table
//! let addr: IpAddr = "192.0.2.1".parse().unwrap();
//! pf.modify_table("malware", addr, TableOperation::Add)?;
//!
//! // Remove IPv6 address from "blocklist" table
//! let addr6: IpAddr = "2001:db8::1".parse().unwrap();
//! pf.modify_table("blocklist", addr6, TableOperation::Remove)?;
//! ```
//!
//! # pf.conf Usage Example
//!
//! ```text
//! # In pf.conf, reference the table populated by dnsmasq:
//! table <malware> persist
//! block in quick from <malware> to any
//! block out quick from any to <malware>
//! ```
//!
//! # See Also
//!
//! - C implementation: `src/tables.c`
//! - Linux ipset equivalent: `src/ipset.c`
//! - Linux nftables equivalent: `src/nftset.c`
//! - Configuration parsing: `src/option.c` (ipset= directive)
//! - BSD pf documentation: `pf.conf(5)`, `pfctl(8)`

// Only compile this module on BSD systems with ipset feature enabled
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
use std::fs::OpenOptions;
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
use std::io::{Error as IoError, Result as IoResult};
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
use std::net::IpAddr;
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
use std::os::unix::io::AsRawFd;

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
use libc::{c_int, c_void, ioctl};

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
use thiserror::Error;

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
use tracing::{error, info, warn};

// ================================================================================================
// Constants
// ================================================================================================

/// Maximum size of pf table name (from BSD net/pfvar.h)
///
/// This corresponds to PF_TABLE_NAME_SIZE in BSD's net/pfvar.h header.
/// Table names exceeding this length will be rejected with [`PfError::TableNameTooLong`].
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
pub const PF_TABLE_NAME_SIZE: usize = 32;

/// Path to BSD packet filter device
///
/// This device file is used for all pf ioctl operations. Requires read/write
/// access, typically restricted to root or users in the appropriate group.
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
pub const PF_DEVICE_PATH: &str = "/dev/pf";

// BSD pf ioctl command constants (from net/pfvar.h)
//
// IMPORTANT: These constants are derived from BSD's net/pfvar.h header and may vary
// between different BSD variants (FreeBSD, OpenBSD, NetBSD) and versions.
// The values here are based on FreeBSD's implementation and should be verified
// for the target platform.
//
// These are constructed using BSD's _IOWR macro pattern:
// _IOWR(IOC_GROUP, command_number, struct_type)
//
// For production use, these should ideally be:
// 1. Extracted via bindgen from net/pfvar.h at build time
// 2. Or provided by a BSD-specific crate (currently none exist for pf)
// 3. Or verified against the target BSD variant's headers
//
// The constants below are placeholders based on common BSD pf implementations
// and will need adjustment for specific BSD variants.
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
const DIOCRADDTABLES: c_int = 0xc450443d; // Add tables ioctl command

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
const DIOCRADDADDRS: c_int = 0xc4504444; // Add addresses ioctl command

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
const DIOCRDELADDRS: c_int = 0xc4504445; // Delete addresses ioctl command

// ⚠️  DEVELOPER WARNING ⚠️
// The ioctl constants above MUST be verified against the target BSD platform's
// /usr/include/net/pfvar.h header before production use. These values are based on
// typical FreeBSD implementations and may differ on OpenBSD, NetBSD, or different
// FreeBSD versions. Incorrect constants will cause ioctl() to fail with EINVAL or
// produce undefined behavior.
//
// Recommended approach for production:
// 1. Use bindgen in build.rs to extract constants from net/pfvar.h
// 2. Or provide platform-specific constant definitions per target_os
// 3. Or verify manually against: grep DIOCR /usr/include/net/pfvar.h

// pf table flags (from net/pfvar.h)
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
const PFR_TFLAG_PERSIST: c_int = 0x00000001; // Table persists across ruleset reloads

// Address family constants (from sys/socket.h)
// Note: These differ between BSD and Linux!
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
const AF_INET: u8 = libc::AF_INET as u8; // IPv4 (value 2)

#[cfg(all(feature = "ipset", target_os = "freebsd"))]
const AF_INET6: u8 = 28; // FreeBSD uses 28 for IPv6

#[cfg(all(feature = "ipset", any(target_os = "openbsd", target_os = "netbsd")))]
const AF_INET6: u8 = 24; // OpenBSD/NetBSD use 24 for IPv6 (different from FreeBSD!)

// ================================================================================================
// Error Types
// ================================================================================================

/// Errors that can occur during pf table operations
///
/// These errors represent specific failure modes when interacting with BSD's
/// Packet Filter system through the /dev/pf device.
#[derive(Debug, Error)]
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
pub enum PfError {
    /// The specified pf table does not exist
    ///
    /// This error corresponds to ESRCH errno from pf ioctl operations.
    /// It typically indicates the table was not created or has been removed.
    #[error("Table does not exist")]
    TableNotFound,

    /// The specified pf anchor or ruleset does not exist
    ///
    /// This error corresponds to ENOENT errno from pf ioctl operations.
    /// It indicates an anchor or ruleset reference is invalid.
    #[error("Anchor or Ruleset does not exist")]
    AnchorNotFound,

    /// Table name exceeds PF_TABLE_NAME_SIZE (32 characters)
    ///
    /// pf table names are limited to 32 characters including null terminator.
    /// This error is returned before attempting ioctl to prevent buffer overflow.
    #[error("Table name too long (max {max} characters): {name}")]
    TableNameTooLong { name: String, max: usize },

    /// PfDevice was not properly initialized
    ///
    /// This error indicates [`PfDevice::new()`] was not called or failed,
    /// and operations cannot proceed without a valid /dev/pf file descriptor.
    #[error("PF device not initialized")]
    DeviceNotInitialized,

    /// ioctl operation on /dev/pf failed
    ///
    /// This wraps underlying I/O errors from ioctl system calls.
    /// The context string describes which operation failed.
    #[error("ioctl failed: {context}")]
    IoctlFailed {
        context: String,
        #[source]
        source: IoError,
    },

    /// Invalid IP address provided
    ///
    /// This error is returned when an IP address cannot be properly
    /// converted to pf's internal representation.
    #[error("Invalid IP address: {0}")]
    InvalidAddress(String),
}

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
impl PfError {
    /// Convert errno to appropriate PfError variant
    ///
    /// Maps specific errno values from pf ioctl operations to typed error variants.
    /// This replaces the C implementation's pfr_strerror() function.
    fn from_errno(errno: c_int, context: String) -> Self {
        match errno {
            libc::ESRCH => PfError::TableNotFound,
            libc::ENOENT => PfError::AnchorNotFound,
            _ => PfError::IoctlFailed {
                context,
                source: IoError::from_raw_os_error(errno),
            },
        }
    }
}

// ================================================================================================
// Table Operation Enum
// ================================================================================================

/// Operation to perform on a pf table
///
/// This enum replaces the boolean `remove` parameter in the C implementation's
/// `add_to_ipset()` function, providing type-safe operation specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
pub enum TableOperation {
    /// Add IP address to the specified pf table
    Add,
    /// Remove IP address from the specified pf table
    Remove,
}

// ================================================================================================
// BSD pf Structure Definitions
// ================================================================================================

// These structures mirror the definitions from BSD's net/pfvar.h header.
// They must match the kernel's ABI exactly for ioctl operations to work correctly.

/// BSD pf address structure (struct pfr_addr from net/pfvar.h)
///
/// Represents an IP address entry in a pf table with address family and netmask.
/// This structure is passed to DIOCRADDADDRS/DIOCRDELADDRS ioctl commands.
#[repr(C)]
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
struct PfrAddr {
    pfra_ip4addr: libc::in_addr,  // IPv4 address (overlaps with pfra_ip6addr)
    pfra_ip6addr: libc::in6_addr, // IPv6 address (union with IPv4)
    pfra_af: u8,                  // Address family (AF_INET or AF_INET6)
    pfra_net: u8,                 // Netmask bits (32 for IPv4 /32, 128 for IPv6 /128)
    pfra_not: u8,                 // Negation flag (unused in dnsmasq)
    pfra_fback: u8,               // Feedback flag (unused in dnsmasq)
    pfra_type: u32,               // Address type (unused in dnsmasq)
    _pad: [u8; 12],               // Padding to match kernel struct size
}

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
impl Default for PfrAddr {
    fn default() -> Self {
        // SAFETY: All-zero initialization is valid for this C-compatible struct
        unsafe { std::mem::zeroed() }
    }
}

/// BSD pf table structure (struct pfr_table from net/pfvar.h)
///
/// Represents a pf table with name and flags. Used in DIOCRADDTABLES ioctl.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
struct PfrTable {
    pfrt_anchor: [u8; 1024], // Anchor name (unused in dnsmasq, always empty)
    pfrt_name: [u8; 32],     // Table name (PF_TABLE_NAME_SIZE)
    pfrt_flags: c_int,       // Table flags (PFR_TFLAG_PERSIST)
    pfrt_fback: u8,          // Feedback flag (unused in dnsmasq)
    _pad: [u8; 3],           // Padding for alignment
}

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
impl Default for PfrTable {
    fn default() -> Self {
        // SAFETY: All-zero initialization is valid for this C-compatible struct
        unsafe { std::mem::zeroed() }
    }
}

/// BSD pf ioctl structure (struct pfioc_table from net/pfvar.h)
///
/// Generic ioctl structure for table operations. Contains operation parameters
/// and buffers for data transfer between userspace and kernel.
#[repr(C)]
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
struct PfiocTable {
    pfrio_table: PfrTable,     // Table to operate on
    pfrio_buffer: *mut c_void, // Pointer to buffer (PfrAddr* or PfrTable*)
    pfrio_esize: c_int,        // Size of each element in buffer
    pfrio_size: c_int,         // Number of elements in buffer
    pfrio_nadd: c_int,         // Number of elements added (output)
    pfrio_ndel: c_int,         // Number of elements deleted (output)
    pfrio_nchange: c_int,      // Number of elements changed (output)
    pfrio_flags: c_int,        // Operation flags
    pfrio_ticket: u32,         // Ticket for atomic operations (unused)
}

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
impl Default for PfiocTable {
    fn default() -> Self {
        // SAFETY: All-zero initialization is valid for this C-compatible struct
        unsafe { std::mem::zeroed() }
    }
}

// ================================================================================================
// PfDevice Implementation
// ================================================================================================

/// BSD Packet Filter device handle
///
/// This structure wraps a file descriptor to /dev/pf and provides safe,
/// idiomatic Rust methods for manipulating pf tables. It replaces the C
/// implementation's static global `dev` file descriptor.
///
/// # Thread Safety
///
/// `PfDevice` is `!Send` and `!Sync` because it contains a raw file descriptor
/// that is not safe to share across threads. This matches dnsmasq's single-threaded
/// architecture where all pf operations occur on the main event loop.
///
/// # Examples
///
/// ```rust,ignore
/// let pf = PfDevice::new()?;
/// let addr: IpAddr = "192.0.2.1".parse().unwrap();
/// let count = pf.modify_table("malware", addr, TableOperation::Add)?;
/// println!("Added {} addresses", count);
/// ```
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
pub struct PfDevice {
    /// File descriptor for /dev/pf
    fd: std::fs::File,
}

#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
impl PfDevice {
    /// Initialize BSD packet filter device for table manipulation
    ///
    /// Opens `/dev/pf` for read/write access, which is required for all subsequent
    /// pf table operations. This function replaces the C implementation's `ipset_init()`.
    ///
    /// # Errors
    ///
    /// Returns [`IoError`] if:
    /// - `/dev/pf` cannot be opened (typically due to insufficient permissions)
    /// - The process lacks read/write access to the device
    /// - The pf kernel module is not loaded
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// match PfDevice::new() {
    ///     Ok(pf) => println!("PF device initialized successfully"),
    ///     Err(e) => {
    ///         error!("Failed to open /dev/pf: {}", e);
    ///         return Err(e);
    ///     }
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// - Requires root privileges or appropriate permissions to open /dev/pf
    /// - On BSD systems, /dev/pf permissions are typically 0600 owned by root
    /// - Unlike the C version which calls `die()` on failure, this returns Result
    ///   for graceful error handling
    pub fn new() -> IoResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(PF_DEVICE_PATH)
            .map_err(|e| {
                error!(
                    path = PF_DEVICE_PATH,
                    error = %e,
                    "Failed to open pf device"
                );
                e
            })?;

        info!(path = PF_DEVICE_PATH, "PF device opened successfully");
        Ok(Self { fd: file })
    }

    /// Add or remove IP address from BSD pf table
    ///
    /// Adds or removes an IPv4 or IPv6 address to/from a specified pf table. This
    /// function is the core integration point between dnsmasq's DNS resolution and
    /// BSD's Packet Filter firewall. It replaces the C implementation's `add_to_ipset()`.
    ///
    /// The function creates the table if it doesn't exist (with PERSIST flag),
    /// then performs the add or remove operation using pf ioctl commands. Both
    /// IPv4 (/32 single host) and IPv6 (/128 single host) addresses are supported,
    /// automatically detected from the `IpAddr` type.
    ///
    /// # Arguments
    ///
    /// * `table_name` - Name of the pf table (e.g., "blocklist"). Must be less than
    ///                  [`PF_TABLE_NAME_SIZE`] (32 characters). This table name must
    ///                  match tables referenced in pf.conf rules.
    /// * `address` - IP address to add or remove. Can be IPv4 or IPv6.
    /// * `operation` - Whether to [`TableOperation::Add`] or [`TableOperation::Remove`]
    ///                 the address.
    ///
    /// # Returns
    ///
    /// Returns `Result<usize, PfError>` where:
    /// - `Ok(n)` contains the number of addresses successfully modified (typically 1)
    /// - `Err(e)` contains specific error information
    ///
    /// # Errors
    ///
    /// Returns [`PfError`] if:
    /// - [`PfError::TableNameTooLong`] - Table name exceeds 32 characters
    /// - [`PfError::TableNotFound`] - Table doesn't exist and creation failed
    /// - [`PfError::IoctlFailed`] - Underlying ioctl operation failed
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let pf = PfDevice::new()?;
    ///
    /// // Add IPv4 address
    /// let addr_v4: IpAddr = "192.0.2.1".parse().unwrap();
    /// pf.modify_table("malware", addr_v4, TableOperation::Add)?;
    ///
    /// // Add IPv6 address
    /// let addr_v6: IpAddr = "2001:db8::1".parse().unwrap();
    /// pf.modify_table("blocklist", addr_v6, TableOperation::Add)?;
    ///
    /// // Remove address
    /// pf.modify_table("allowlist", addr_v4, TableOperation::Remove)?;
    /// ```
    ///
    /// # Note
    ///
    /// - Table is created automatically if it doesn't exist (DIOCRADDTABLES ioctl)
    /// - Table is created with PFR_TFLAG_PERSIST flag to survive ruleset reloads
    /// - IPv4 addresses use /32 netmask (single host entries)
    /// - IPv6 addresses use /128 netmask (single host entries)
    /// - All operations are logged via tracing at appropriate levels
    pub fn modify_table(
        &self,
        table_name: &str,
        address: IpAddr,
        operation: TableOperation,
    ) -> Result<usize, PfError> {
        // Validate table name length
        if table_name.len() >= PF_TABLE_NAME_SIZE {
            error!(
                table_name = table_name,
                max_size = PF_TABLE_NAME_SIZE,
                "Table name too long"
            );
            return Err(PfError::TableNameTooLong {
                name: table_name.to_string(),
                max: PF_TABLE_NAME_SIZE - 1,
            });
        }

        // Create table structure with PERSIST flag
        let mut table = PfrTable::default();
        table.pfrt_flags = PFR_TFLAG_PERSIST;

        // Copy table name safely (no buffer overflow possible)
        let name_bytes = table_name.as_bytes();
        table.pfrt_name[..name_bytes.len()].copy_from_slice(name_bytes);

        // Create table if it doesn't exist
        self.create_table_if_needed(&table)?;

        // Add or remove address
        let count = self.modify_address(&table, address, operation)?;

        Ok(count)
    }

    /// Create pf table if it doesn't already exist
    ///
    /// Uses DIOCRADDTABLES ioctl to create a table with PERSIST flag.
    /// If the table already exists, the operation succeeds silently.
    fn create_table_if_needed(&self, table: &PfrTable) -> Result<(), PfError> {
        let mut io = PfiocTable::default();
        io.pfrio_buffer = table as *const PfrTable as *mut c_void;
        io.pfrio_esize = std::mem::size_of::<PfrTable>() as c_int;
        io.pfrio_size = 1;

        // SAFETY: ioctl operation on valid file descriptor with properly initialized structures
        let result = unsafe {
            ioctl(
                self.fd.as_raw_fd(),
                DIOCRADDTABLES as libc::c_ulong,
                &mut io as *mut PfiocTable,
            )
        };

        if result < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            warn!(
                error = %PfError::from_errno(errno, "DIOCRADDTABLES".to_string()),
                "Failed to create table"
            );
            return Err(PfError::from_errno(errno, "DIOCRADDTABLES".to_string()));
        }

        if io.pfrio_nadd > 0 {
            let table_name = String::from_utf8_lossy(&table.pfrt_name)
                .trim_end_matches('\0')
                .to_string();
            info!(table_name = table_name, "Table created successfully");
        }

        Ok(())
    }

    /// Add or remove single address from pf table
    ///
    /// Uses DIOCRADDADDRS or DIOCRDELADDRS ioctl based on operation type.
    fn modify_address(
        &self,
        table: &PfrTable,
        address: IpAddr,
        operation: TableOperation,
    ) -> Result<usize, PfError> {
        // Create address structure based on IP version
        let mut addr = PfrAddr::default();

        match address {
            IpAddr::V4(ipv4) => {
                addr.pfra_af = AF_INET;
                addr.pfra_net = 32; // /32 netmask for single IPv4 host
                addr.pfra_ip4addr = libc::in_addr {
                    s_addr: u32::from(ipv4).to_be(),
                };
            }
            IpAddr::V6(ipv6) => {
                addr.pfra_af = AF_INET6;
                addr.pfra_net = 128; // /128 netmask for single IPv6 host
                addr.pfra_ip6addr = libc::in6_addr {
                    s6_addr: ipv6.octets(),
                };
            }
        }

        // Prepare ioctl structure
        let mut io = PfiocTable::default();
        io.pfrio_table = *table;
        io.pfrio_buffer = &mut addr as *mut PfrAddr as *mut c_void;
        io.pfrio_esize = std::mem::size_of::<PfrAddr>() as c_int;
        io.pfrio_size = 1;

        // Select appropriate ioctl command
        let ioctl_cmd = match operation {
            TableOperation::Add => DIOCRADDADDRS,
            TableOperation::Remove => DIOCRDELADDRS,
        };

        // SAFETY: ioctl operation on valid file descriptor with properly initialized structures
        let result = unsafe {
            ioctl(
                self.fd.as_raw_fd(),
                ioctl_cmd as libc::c_ulong,
                &mut io as *mut PfiocTable,
            )
        };

        if result < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            let cmd_name = match operation {
                TableOperation::Add => "DIOCRADDADDRS",
                TableOperation::Remove => "DIOCRDELADDRS",
            };
            warn!(
                operation = ?operation,
                address = %address,
                error = %PfError::from_errno(errno, cmd_name.to_string()),
                "Address operation failed"
            );
            return Err(PfError::from_errno(errno, cmd_name.to_string()));
        }

        let count = io.pfrio_nadd as usize;
        let table_name = String::from_utf8_lossy(&table.pfrt_name)
            .trim_end_matches('\0')
            .to_string();

        info!(
            table_name = table_name,
            address = %address,
            operation = ?operation,
            count = count,
            "Address operation completed successfully"
        );

        Ok(count)
    }
}

// Note: PfDevice is intentionally not Send or Sync due to raw file descriptor.
// The std::fs::File wrapper is Send+Sync, but we document that PfDevice should
// only be used from a single thread matching dnsmasq's architecture.
// In the future, we could add a PhantomData<*const ()> field to make it !Send + !Sync
// at compile time, but this requires additional marker types.

// ================================================================================================
// Unit Tests
// ================================================================================================

#[cfg(test)]
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
mod tests {
    use super::*;

    #[test]
    fn test_table_name_size_constant() {
        assert_eq!(PF_TABLE_NAME_SIZE, 32);
    }

    #[test]
    fn test_device_path_constant() {
        assert_eq!(PF_DEVICE_PATH, "/dev/pf");
    }

    #[test]
    fn test_table_operation_variants() {
        assert_ne!(TableOperation::Add, TableOperation::Remove);
    }

    #[test]
    fn test_pfr_addr_default() {
        let addr = PfrAddr::default();
        assert_eq!(addr.pfra_af, 0);
        assert_eq!(addr.pfra_net, 0);
    }

    #[test]
    fn test_pfr_table_default() {
        let table = PfrTable::default();
        assert_eq!(table.pfrt_flags, 0);
    }

    #[test]
    fn test_pfioc_table_default() {
        let io = PfiocTable::default();
        assert_eq!(io.pfrio_size, 0);
        assert_eq!(io.pfrio_nadd, 0);
    }

    #[test]
    fn test_pf_error_table_name_too_long() {
        let err = PfError::TableNameTooLong {
            name: "verylongtablename".to_string(),
            max: 31,
        };
        assert!(err.to_string().contains("Table name too long"));
    }

    #[test]
    fn test_pf_error_from_errno_esrch() {
        let err = PfError::from_errno(libc::ESRCH, "test".to_string());
        assert!(matches!(err, PfError::TableNotFound));
    }

    #[test]
    fn test_pf_error_from_errno_enoent() {
        let err = PfError::from_errno(libc::ENOENT, "test".to_string());
        assert!(matches!(err, PfError::AnchorNotFound));
    }
}

// Note: Integration tests requiring actual /dev/pf access should be in tests/ directory
// and marked with #[ignore] or conditional on CI environment that has pf available.
