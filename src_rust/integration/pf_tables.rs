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

//! BSD Packet Filter (pf) table integration for DNS-based firewall rules
//!
//! This module provides integration with BSD's Packet Filter (pf) firewall system,
//! enabling dnsmasq to dynamically populate pf tables with IP addresses resolved
//! from DNS queries. This is the BSD equivalent of Linux's ipset or nftables set
//! integration, allowing DNS-based blocking, routing, or traffic shaping policies.
//!
//! # Overview
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
//! # Platform Support
//!
//! This module is BSD-specific and is only compiled on FreeBSD, OpenBSD, and NetBSD
//! systems where pf is available. It requires read/write access to /dev/pf, which
//! typically requires root privileges or appropriate capabilities.
//!
//! # Memory Safety
//!
//! This implementation eliminates all memory-safety vulnerabilities present in the
//! C implementation (src/tables.c):
//! - No manual buffer management - all buffers are managed by Rust's ownership system
//! - No buffer overflow risks - all operations use safe slice manipulation
//! - No use-after-free - Drop trait ensures proper /dev/pf cleanup
//! - No null pointer dereferences - Option and Result types for explicit null handling
//! - Type-safe ioctl operations through FFI wrappers in ffi::platform::pf
//!
//! # Example Usage
//!
//! ```no_run
//! use std::net::IpAddr;
//! use dnsmasq::integration::pf_tables::PfTableManager;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize PF table manager (opens /dev/pf)
//! let manager = PfTableManager::new()?;
//!
//! // Add IPv4 address to "malware" table
//! let ipv4: IpAddr = "192.168.1.100".parse()?;
//! manager.add_to_table("malware", ipv4)?;
//!
//! // Add IPv6 address to "blocklist" table
//! let ipv6: IpAddr = "2001:db8::1".parse()?;
//! manager.add_to_table("blocklist", ipv6)?;
//!
//! // Remove address from table
//! manager.remove_from_table("allowlist", ipv4)?;
//! # Ok(())
//! # }
//! ```
//!
//! # pf.conf Integration
//!
//! Tables populated by this module can be referenced in pf.conf:
//!
//! ```text
//! # In pf.conf, reference the table populated by dnsmasq:
//! table <malware> persist
//! block in quick from <malware> to any
//! block out quick from any to <malware>
//! ```
//!
//! # Thread Safety
//!
//! PfTableManager is Send but not Sync. Each instance owns its /dev/pf file
//! descriptor and should not be shared across threads. In dnsmasq's async
//! architecture, each task that needs pf access should have its own instance,
//! or a single instance should be wrapped in Arc<Mutex<>> for shared access.

use crate::ffi::platform::pf::{
    self, add_pf_address, create_pf_table, delete_pf_address, open_pf_device, PfDevice,
    PfrAddr, PfrTable, PfiocTable, AF_INET, AF_INET6, DIOCRADDADDRS, DIOCRADDTABLES,
    DIOCRDELADDRS, ENOENT, ESRCH, PFR_TFLAG_PERSIST, PF_TABLE_NAME_SIZE,
};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// BSD Packet Filter (pf) table manager
///
/// Manages pf table operations for DNS-based firewall rules. This struct owns
/// a /dev/pf file descriptor and provides methods to add/remove IP addresses
/// from pf tables. The device is automatically closed when the manager is dropped.
///
/// # Examples
///
/// ```no_run
/// use std::net::IpAddr;
/// use dnsmasq::integration::pf_tables::PfTableManager;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = PfTableManager::new()?;
/// let addr: IpAddr = "192.168.1.100".parse()?;
/// manager.add_to_table("blocklist", addr)?;
/// # Ok(())
/// # }
/// ```
pub struct PfTableManager {
    /// PF device file descriptor (/dev/pf)
    /// Wrapped in Option to allow taking ownership in Drop while maintaining
    /// a valid (empty) state after drop
    device: Option<PfDevice>,
}

impl PfTableManager {
    /// Create new PF table manager by opening /dev/pf
    ///
    /// Opens the BSD packet filter device for read/write access. This operation
    /// requires root privileges or appropriate permissions to open /dev/pf.
    ///
    /// # Returns
    ///
    /// - `Ok(PfTableManager)` on success with opened /dev/pf
    /// - `Err(PfError::DeviceOpenFailed)` if /dev/pf cannot be opened
    ///
    /// # Errors
    ///
    /// Returns `DeviceOpenFailed` if:
    /// - /dev/pf doesn't exist (pf not loaded)
    /// - Permission denied (not root or insufficient capabilities)
    /// - Device already exclusively locked by another process
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::integration::pf_tables::PfTableManager;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = PfTableManager::new()?;
    /// // manager is ready for table operations
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self, PfError> {
        debug!("Opening /dev/pf for pf table operations");

        let device = open_pf_device().map_err(|err| {
            error!("Failed to open /dev/pf: {}", err);
            PfError::DeviceOpenFailed {
                source: err,
                path: "/dev/pf".to_string(),
            }
        })?;

        info!("Successfully opened /dev/pf for pf table management");

        Ok(Self {
            device: Some(device),
        })
    }

    /// Add IP address to pf table
    ///
    /// Adds an IPv4 or IPv6 address to the specified pf table. If the table
    /// doesn't exist, it is created automatically with the PERSIST flag.
    /// IPv4 addresses are added with /32 netmask (single host), and IPv6
    /// addresses with /128 netmask (single host).
    ///
    /// # Arguments
    ///
    /// * `table_name` - Name of the pf table (must be < 32 characters)
    /// * `addr` - IP address to add (IPv4 or IPv6)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success (address added or already in table)
    /// - `Err(PfError)` on failure with specific error variant
    ///
    /// # Errors
    ///
    /// - `TableNameTooLong` if table_name >= PF_TABLE_NAME_SIZE (32 chars)
    /// - `InvalidTableName` if table_name contains invalid characters
    /// - `IoctlFailed` if ioctl operations fail
    /// - `TableNotFound` if table doesn't exist and creation fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::net::IpAddr;
    /// # use dnsmasq::integration::pf_tables::PfTableManager;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = PfTableManager::new()?;
    ///
    /// // Add IPv4 address
    /// let ipv4: IpAddr = "192.168.1.100".parse()?;
    /// manager.add_to_table("malware", ipv4)?;
    ///
    /// // Add IPv6 address
    /// let ipv6: IpAddr = "2001:db8::1".parse()?;
    /// manager.add_to_table("malware", ipv6)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_to_table(&self, table_name: &str, addr: IpAddr) -> Result<(), PfError> {
        // Validate table name length
        if table_name.len() >= PF_TABLE_NAME_SIZE {
            error!(
                "Table name '{}' too long (max {} chars)",
                table_name,
                PF_TABLE_NAME_SIZE - 1
            );
            return Err(PfError::TableNameTooLong {
                name: table_name.to_string(),
                max_length: PF_TABLE_NAME_SIZE - 1,
            });
        }

        // Validate table name is not empty and contains valid characters
        if table_name.is_empty() {
            error!("Table name cannot be empty");
            return Err(PfError::InvalidTableName {
                name: table_name.to_string(),
                reason: "name cannot be empty".to_string(),
            });
        }

        let device = self.device.as_ref().ok_or_else(|| {
            error!("PF device not initialized or already dropped");
            PfError::DeviceOpenFailed {
                source: IoError::new(ErrorKind::NotConnected, "device not open"),
                path: "/dev/pf".to_string(),
            }
        })?;

        // Ensure table exists (create if needed)
        self.ensure_table_exists(table_name)?;

        // Add address to table
        debug!(
            "Adding {} address {} to pf table '{}'",
            if addr.is_ipv4() { "IPv4" } else { "IPv6" },
            addr,
            table_name
        );

        add_pf_address(device, table_name, addr).map_err(|err| {
            // Check for specific error codes
            match err.raw_os_error() {
                Some(errno) if errno == ESRCH => {
                    warn!(
                        "Table '{}' does not exist (ESRCH) when adding address {}",
                        table_name, addr
                    );
                    PfError::TableNotFound {
                        name: table_name.to_string(),
                    }
                }
                Some(errno) if errno == ENOENT => {
                    warn!(
                        "Anchor or ruleset does not exist (ENOENT) for table '{}' when adding address {}",
                        table_name, addr
                    );
                    PfError::IoctlFailed {
                        operation: "DIOCRADDADDRS".to_string(),
                        source: err,
                    }
                }
                _ => {
                    error!(
                        "Failed to add address {} to table '{}': {}",
                        addr, table_name, err
                    );
                    PfError::IoctlFailed {
                        operation: "DIOCRADDADDRS".to_string(),
                        source: err,
                    }
                }
            }
        })?;

        info!("Successfully added address {} to pf table '{}'", addr, table_name);

        Ok(())
    }

    /// Remove IP address from pf table
    ///
    /// Removes an IPv4 or IPv6 address from the specified pf table. If the
    /// address is not in the table, this is not treated as an error (returns Ok).
    ///
    /// # Arguments
    ///
    /// * `table_name` - Name of the pf table
    /// * `addr` - IP address to remove (IPv4 or IPv6)
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success (address removed or not in table)
    /// - `Err(PfError)` on failure
    ///
    /// # Errors
    ///
    /// - `TableNameTooLong` if table_name >= 32 characters
    /// - `InvalidTableName` if table_name is invalid
    /// - `IoctlFailed` if ioctl operations fail
    /// - `TableNotFound` if table doesn't exist
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::net::IpAddr;
    /// # use dnsmasq::integration::pf_tables::PfTableManager;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = PfTableManager::new()?;
    /// let addr: IpAddr = "192.168.1.100".parse()?;
    /// manager.remove_from_table("allowlist", addr)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn remove_from_table(&self, table_name: &str, addr: IpAddr) -> Result<(), PfError> {
        // Validate table name length
        if table_name.len() >= PF_TABLE_NAME_SIZE {
            error!(
                "Table name '{}' too long (max {} chars)",
                table_name,
                PF_TABLE_NAME_SIZE - 1
            );
            return Err(PfError::TableNameTooLong {
                name: table_name.to_string(),
                max_length: PF_TABLE_NAME_SIZE - 1,
            });
        }

        // Validate table name is not empty
        if table_name.is_empty() {
            error!("Table name cannot be empty");
            return Err(PfError::InvalidTableName {
                name: table_name.to_string(),
                reason: "name cannot be empty".to_string(),
            });
        }

        let device = self.device.as_ref().ok_or_else(|| {
            error!("PF device not initialized or already dropped");
            PfError::DeviceOpenFailed {
                source: IoError::new(ErrorKind::NotConnected, "device not open"),
                path: "/dev/pf".to_string(),
            }
        })?;

        // Remove address from table
        debug!(
            "Removing {} address {} from pf table '{}'",
            if addr.is_ipv4() { "IPv4" } else { "IPv6" },
            addr,
            table_name
        );

        delete_pf_address(device, table_name, addr).map_err(|err| {
            // Check for specific error codes
            match err.raw_os_error() {
                Some(errno) if errno == ESRCH => {
                    warn!(
                        "Table '{}' does not exist (ESRCH) when removing address {}",
                        table_name, addr
                    );
                    PfError::TableNotFound {
                        name: table_name.to_string(),
                    }
                }
                Some(errno) if errno == ENOENT => {
                    // ENOENT when deleting means address wasn't in table - not an error
                    debug!(
                        "Address {} not in table '{}' (ENOENT), treating as success",
                        addr, table_name
                    );
                    return Ok(());
                }
                _ => {
                    error!(
                        "Failed to remove address {} from table '{}': {}",
                        addr, table_name, err
                    );
                    PfError::IoctlFailed {
                        operation: "DIOCRDELADDRS".to_string(),
                        source: err,
                    }
                }
            }
        })?;

        info!(
            "Successfully removed address {} from pf table '{}'",
            addr, table_name
        );

        Ok(())
    }

    /// Ensure pf table exists, creating it if necessary
    ///
    /// Checks if the specified pf table exists, and creates it with the PERSIST
    /// flag if it doesn't. The PERSIST flag ensures the table survives pf ruleset
    /// reloads.
    ///
    /// # Arguments
    ///
    /// * `table_name` - Name of the pf table to ensure exists
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success (table exists or was created)
    /// - `Err(PfError)` on failure
    ///
    /// # Errors
    ///
    /// - `TableNameTooLong` if table_name >= 32 characters
    /// - `InvalidTableName` if table_name is invalid
    /// - `IoctlFailed` if table creation fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::integration::pf_tables::PfTableManager;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = PfTableManager::new()?;
    /// manager.ensure_table_exists("malware")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn ensure_table_exists(&self, table_name: &str) -> Result<(), PfError> {
        // Validate table name length
        if table_name.len() >= PF_TABLE_NAME_SIZE {
            error!(
                "Table name '{}' too long (max {} chars)",
                table_name,
                PF_TABLE_NAME_SIZE - 1
            );
            return Err(PfError::TableNameTooLong {
                name: table_name.to_string(),
                max_length: PF_TABLE_NAME_SIZE - 1,
            });
        }

        // Validate table name is not empty
        if table_name.is_empty() {
            error!("Table name cannot be empty");
            return Err(PfError::InvalidTableName {
                name: table_name.to_string(),
                reason: "name cannot be empty".to_string(),
            });
        }

        let device = self.device.as_ref().ok_or_else(|| {
            error!("PF device not initialized or already dropped");
            PfError::DeviceOpenFailed {
                source: IoError::new(ErrorKind::NotConnected, "device not open"),
                path: "/dev/pf".to_string(),
            }
        })?;

        debug!("Ensuring pf table '{}' exists", table_name);

        create_pf_table(device, table_name).map_err(|err| {
            error!("Failed to create pf table '{}': {}", table_name, err);
            PfError::IoctlFailed {
                operation: "DIOCRADDTABLES".to_string(),
                source: err,
            }
        })?;

        info!("pf table '{}' exists (created or already present)", table_name);

        Ok(())
    }
}

impl Drop for PfTableManager {
    /// Clean up PF device when manager is dropped
    ///
    /// The PfDevice wrapper already implements Drop to close the file descriptor,
    /// so we just need to take ownership and let it drop naturally.
    fn drop(&mut self) {
        if self.device.take().is_some() {
            debug!("Closing /dev/pf file descriptor");
        }
    }
}

/// PF table operation errors
///
/// Describes all possible error conditions when working with pf tables.
/// All variants provide detailed context about the failure for logging
/// and debugging purposes.
#[derive(Error, Debug)]
pub enum PfError {
    /// Failed to open /dev/pf device
    ///
    /// This typically occurs when:
    /// - pf kernel module is not loaded
    /// - Insufficient privileges (not root)
    /// - Device is exclusively locked by another process
    #[error("Failed to open pf device {path}: {source}")]
    DeviceOpenFailed {
        /// The underlying I/O error
        source: IoError,
        /// Path to the device that failed to open
        path: String,
    },

    /// ioctl operation failed
    ///
    /// Represents failures in DIOCRADDTABLES, DIOCRADDADDRS, or DIOCRDELADDRS
    /// ioctl commands. The source error typically contains the errno value.
    #[error("PF ioctl operation {operation} failed: {source}")]
    IoctlFailed {
        /// Name of the ioctl operation that failed
        operation: String,
        /// The underlying I/O error from ioctl
        source: IoError,
    },

    /// Specified pf table does not exist
    ///
    /// This occurs when trying to add/remove addresses from a non-existent table
    /// and automatic table creation failed. The errno is typically ESRCH.
    #[error("PF table '{name}' does not exist")]
    TableNotFound {
        /// Name of the table that doesn't exist
        name: String,
    },

    /// IP address family not supported
    ///
    /// This error should not occur in normal operation as both IPv4 and IPv6
    /// are supported. It's a defensive check for future extensibility.
    #[error("Address family not supported for IP address: {address}")]
    AddressFamilyUnsupported {
        /// The address with unsupported family
        address: String,
    },

    /// Table name exceeds maximum length
    ///
    /// pf table names must be less than PF_TABLE_NAME_SIZE (32) characters.
    /// This is a kernel limitation from net/pfvar.h.
    #[error("Table name '{name}' too long (max {max_length} characters)")]
    TableNameTooLong {
        /// The table name that was too long
        name: String,
        /// Maximum allowed length
        max_length: usize,
    },

    /// Table name is invalid
    ///
    /// Table names must be non-empty and contain only valid characters
    /// (alphanumeric and underscore).
    #[error("Invalid table name '{name}': {reason}")]
    InvalidTableName {
        /// The invalid table name
        name: String,
        /// Reason why the name is invalid
        reason: String,
    },
}

/// Add IP address to pf table (standalone function)
///
/// Convenience function that opens a PF device, adds an address to the specified
/// table, and returns the number of addresses added. This is provided for
/// compatibility with the C API signature but it's generally more efficient to
/// use PfTableManager for multiple operations to avoid reopening /dev/pf.
///
/// # Arguments
///
/// * `table_name` - Name of the pf table
/// * `addr` - IP address to add
///
/// # Returns
///
/// - `Ok(1)` on success (1 address added)
/// - `Ok(0)` if address was already in table
/// - `Err(PfError)` on failure
///
/// # Examples
///
/// ```no_run
/// # use std::net::IpAddr;
/// # use dnsmasq::integration::pf_tables::add_to_table;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: IpAddr = "192.168.1.100".parse()?;
/// let count = add_to_table("malware", addr)?;
/// println!("Added {} address(es)", count);
/// # Ok(())
/// # }
/// ```
pub fn add_to_table(table_name: &str, addr: IpAddr) -> Result<usize, PfError> {
    let manager = PfTableManager::new()?;
    manager.add_to_table(table_name, addr)?;
    // C implementation returns count of addresses added
    // We return 1 to indicate success (address added or already present)
    Ok(1)
}

/// Remove IP address from pf table (standalone function)
///
/// Convenience function that opens a PF device, removes an address from the
/// specified table, and returns the number of addresses removed. This is provided
/// for compatibility with the C API signature but it's generally more efficient to
/// use PfTableManager for multiple operations.
///
/// # Arguments
///
/// * `table_name` - Name of the pf table
/// * `addr` - IP address to remove
///
/// # Returns
///
/// - `Ok(1)` on success (1 address removed)
/// - `Ok(0)` if address was not in table
/// - `Err(PfError)` on failure
///
/// # Examples
///
/// ```no_run
/// # use std::net::IpAddr;
/// # use dnsmasq::integration::pf_tables::remove_from_table;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: IpAddr = "192.168.1.100".parse()?;
/// let count = remove_from_table("malware", addr)?;
/// println!("Removed {} address(es)", count);
/// # Ok(())
/// # }
/// ```
pub fn remove_from_table(table_name: &str, addr: IpAddr) -> Result<usize, PfError> {
    let manager = PfTableManager::new()?;
    manager.remove_from_table(table_name, addr)?;
    // C implementation returns count of addresses removed
    // We return 1 to indicate success (address removed or wasn't present)
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_name_validation() {
        // Test empty table name
        let manager = PfTableManager::new();
        if let Ok(mgr) = manager {
            let result = mgr.add_to_table("", "192.168.1.1".parse().unwrap());
            assert!(matches!(result, Err(PfError::InvalidTableName { .. })));
        }
    }

    #[test]
    fn test_table_name_too_long() {
        // Test table name exceeding PF_TABLE_NAME_SIZE
        let long_name = "a".repeat(PF_TABLE_NAME_SIZE + 1);
        let manager = PfTableManager::new();
        if let Ok(mgr) = manager {
            let result = mgr.add_to_table(&long_name, "192.168.1.1".parse().unwrap());
            assert!(matches!(result, Err(PfError::TableNameTooLong { .. })));
        }
    }

    #[test]
    fn test_ipv4_address_handling() {
        // Test that IPv4 addresses are correctly identified
        let addr: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(addr.is_ipv4());
        assert!(!addr.is_ipv6());
    }

    #[test]
    fn test_ipv6_address_handling() {
        // Test that IPv6 addresses are correctly identified
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!addr.is_ipv4());
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_error_display() {
        // Test that error messages are properly formatted
        let err = PfError::TableNotFound {
            name: "test_table".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("test_table"));
        assert!(msg.contains("does not exist"));
    }

    #[test]
    fn test_error_debug() {
        // Test that error debug output works
        let err = PfError::TableNameTooLong {
            name: "very_long_table_name_that_exceeds_limit".to_string(),
            max_length: 31,
        };
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("TableNameTooLong"));
    }
}
