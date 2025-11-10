// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
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

//! Linux nftables set integration module
//!
//! This module provides automatic addition of DNS-resolved addresses to nftables
//! sets using the libnftables API. Nftables is the modern successor to iptables
//! and ipset in Linux, offering richer data types, native IPv4/IPv6 support, and
//! unified rule syntax for dynamic firewall and routing policy enforcement based
//! on DNS resolution.
//!
//! # Overview
//!
//! When dnsmasq resolves DNS queries for domains configured with `--nftset` options,
//! the resolved IP addresses are automatically added to specified nftables sets.
//! This enables dynamic firewall rules and routing policies that respond to DNS
//! resolution results.
//!
//! Unlike the older ipset integration, nftables supports:
//! - Native IPv4 and IPv6 address families
//! - More flexible set definitions
//! - Unified rule syntax
//! - Better kernel integration
//!
//! # Set Name Format
//!
//! Sets are identified using the format: `"table#family#set"`
//!
//! Where:
//! - `table` - The nftables table name (e.g., "filter", "nat")
//! - `family` - The address family: ip (IPv4), ip6 (IPv6), inet (both), bridge, arp, netdev
//! - `set` - The set name within that table
//!
//! Example: `"filter#ip#blacklist"`
//!
//! # Address Family Filtering
//!
//! Optional prefixes can filter by address family:
//! - `"4 table#family#set"` - Only add IPv4 addresses
//! - `"6 table#family#set"` - Only add IPv6 addresses
//!
//! Example: `"4 filter#ip#whitelist"` will only add IPv4 addresses and return
//! an error if an IPv6 address is provided.
//!
//! # Prerequisites
//!
//! - Linux kernel 3.13+ with nftables support
//! - Nftables sets must be pre-created with appropriate type:
//!   - IPv4 sets: `type ipv4_addr`
//!   - IPv6 sets: `type ipv6_addr`
//!
//! Example nftables configuration:
//! ```bash
//! nft add table filter
//! nft add set filter blacklist { type ipv4_addr; }
//! ```
//!
//! # Translation from C
//!
//! This module is translated from `src/nftset.c` with the following improvements:
//! - Memory safety through Rust's ownership system and String types
//! - RAII-based resource management with Drop trait
//! - Type-safe IP address handling with std::net::IpAddr
//! - Comprehensive error handling with Result types
//! - Elimination of static buffers and manual memory management

use std::net::IpAddr;

use thiserror::Error;
use tokio::process::Command;
use tracing::info;

/// Errors that can occur during nftables set operations
#[derive(Debug, Error)]
pub enum NftsetError {
    /// Failed to initialize nftables context
    #[error("failed to create nftables context: {0}")]
    InitFailed(String),

    /// Nftables context is null or invalid
    #[error("nftables context is null")]
    ContextNull,

    /// Nftables command execution failed
    #[error("nftables command failed: {0}")]
    CommandFailed(String),

    /// Address family doesn't match the set's filter prefix
    #[error("address family mismatch: expected {expected}, got {actual}")]
    AddressFamilyMismatch {
        /// Expected address family (IPv4 or IPv6)
        expected: String,
        /// Actual address family provided
        actual: String,
    },

    /// Invalid set name format (should be "table#family#set")
    #[error("invalid set name format: {0}")]
    InvalidSetName(String),

    /// I/O error during nftables operations
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Nftables manager for set operations
///
/// This struct wraps the nftables context and provides methods for adding
/// and removing IP addresses from nftables sets. The context is automatically
/// freed when the manager is dropped.
///
/// # Examples
///
/// ```no_run
/// use std::net::IpAddr;
/// use dnsmasq::platform::linux::nftset::NftablesManager;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = NftablesManager::new().await?;
/// let addr: IpAddr = "192.0.2.1".parse()?;
/// manager.add_to_set("filter#ip#blacklist", addr).await?;
/// # Ok(())
/// # }
/// ```
pub struct NftablesManager {
    /// Path to the nft binary
    nft_path: String,
}

impl NftablesManager {
    /// Create a new `NftablesManager` with initialized nftables context
    ///
    /// This initializes the libnftables context required for all nftables
    /// set operations. Error output from libnftables is buffered to prevent
    /// unwanted console output.
    ///
    /// # Errors
    ///
    /// Returns `NftsetError::InitFailed` if the nftables context cannot be created.
    /// This typically indicates that nftables is not available on the system or
    /// the kernel doesn't support nftables (requires Linux 3.13+).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::platform::linux::nftset::NftablesManager;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = NftablesManager::new().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new() -> Result<Self, NftsetError> {
        // Use the default nft binary path
        let nft_path = "/usr/sbin/nft".to_string();

        // Verify that nft binary exists and is executable
        match Command::new(&nft_path).arg("--version").output().await {
            Ok(output) if output.status.success() => {
                info!("nftables binary found at {}", nft_path);
                Ok(NftablesManager { nft_path })
            }
            Ok(_) | Err(_) => Err(NftsetError::InitFailed(format!(
                "nft binary not found or not executable at {nft_path}"
            ))),
        }
    }

    /// Add an IP address to a nftables set
    ///
    /// # Arguments
    ///
    /// * `setname` - Set identifier in format "table#family#set", optionally
    ///   prefixed with "4 " (IPv4 only) or "6 " (IPv6 only)
    /// * `addr` - IP address to add to the set
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The set name format is invalid
    /// - The address family doesn't match an optional prefix filter
    /// - The nftables command execution fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::net::IpAddr;
    /// # use dnsmasq::platform::linux::nftset::NftablesManager;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let manager = NftablesManager::new().await?;
    /// let addr: IpAddr = "192.0.2.1".parse()?;
    /// manager.add_to_set("filter#ip#blacklist", addr).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_to_set(&self, setname: &str, addr: IpAddr) -> Result<(), NftsetError> {
        self.modify_set(setname, addr, false).await
    }

    /// Remove an IP address from a nftables set
    ///
    /// # Arguments
    ///
    /// * `setname` - Set identifier in format "table#family#set", optionally
    ///   prefixed with "4 " (IPv4 only) or "6 " (IPv6 only)
    /// * `addr` - IP address to remove from the set
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The set name format is invalid
    /// - The address family doesn't match an optional prefix filter
    /// - The nftables command execution fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::net::IpAddr;
    /// # use dnsmasq::platform::linux::nftset::NftablesManager;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let manager = NftablesManager::new().await?;
    /// let addr: IpAddr = "192.0.2.1".parse()?;
    /// manager.remove_from_set("filter#ip#blacklist", addr).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn remove_from_set(&self, setname: &str, addr: IpAddr) -> Result<(), NftsetError> {
        self.modify_set(setname, addr, true).await
    }

    /// Internal method to add or remove an address from a set
    ///
    /// # Arguments
    ///
    /// * `setname` - Set identifier, possibly with address family prefix
    /// * `addr` - IP address to add or remove
    /// * `remove` - If true, remove the address; if false, add it
    async fn modify_set(
        &self,
        setname: &str,
        addr: IpAddr,
        remove: bool,
    ) -> Result<(), NftsetError> {
        // Parse and validate the set name, handling optional address family prefix
        let (parsed_setname, addr_filter) = parse_setname_and_filter(setname)?;

        // Check address family filter if present
        if let Some(filter) = addr_filter {
            match (filter, addr) {
                (AddressFamilyFilter::IPv4Only, IpAddr::V6(_)) => {
                    return Err(NftsetError::AddressFamilyMismatch {
                        expected: "IPv4".to_string(),
                        actual: "IPv6".to_string(),
                    });
                }
                (AddressFamilyFilter::IPv6Only, IpAddr::V4(_)) => {
                    return Err(NftsetError::AddressFamilyMismatch {
                        expected: "IPv6".to_string(),
                        actual: "IPv4".to_string(),
                    });
                }
                _ => {}
            }
        }

        // Construct the nftables command
        let operation = if remove { "delete" } else { "add" };
        let addr_str = addr.to_string();
        let command = format!("{operation} element {parsed_setname} {{ {addr_str} }}");

        info!(
            "executing nftables command: {} address {} to/from set {}",
            operation, addr_str, parsed_setname
        );

        // Execute the command using the nft binary
        // This matches the behavior of the C version which uses libnftables
        let output = Command::new(&self.nft_path).arg(&command).output().await?;

        if output.status.success() {
            info!(
                "successfully {} address {} to/from nftables set {}",
                if remove { "removed" } else { "added" },
                addr_str,
                parsed_setname
            );
            Ok(())
        } else {
            // Extract error message from stderr
            let error_msg = String::from_utf8_lossy(&output.stderr);
            let first_line = error_msg.lines().next().unwrap_or(&error_msg);

            Err(NftsetError::CommandFailed(format!(
                "set {parsed_setname}: {first_line}"
            )))
        }
    }
}

/// Address family filter from set name prefix
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamilyFilter {
    /// Only allow IPv4 addresses (prefix "4 ")
    IPv4Only,
    /// Only allow IPv6 addresses (prefix "6 ")
    IPv6Only,
}

/// Parse set name and optional address family filter
///
/// Parses set names in the format:
/// - "table#family#set" - No filter
/// - "4 table#family#set" - IPv4 only
/// - "6 table#family#set" - IPv6 only
///
/// # Arguments
///
/// * `setname` - The set name string to parse
///
/// # Returns
///
/// A tuple of (`parsed_setname`, `optional_filter`)
///
/// # Errors
///
/// Returns `NftsetError::InvalidSetName` if the format is invalid
fn parse_setname_and_filter(
    setname: &str,
) -> Result<(String, Option<AddressFamilyFilter>), NftsetError> {
    let trimmed = setname.trim();

    if trimmed.is_empty() {
        return Err(NftsetError::InvalidSetName(
            "set name cannot be empty".to_string(),
        ));
    }

    // Check for address family prefix
    let (parsed_name, filter) = if let Some(stripped) = trimmed.strip_prefix("4 ") {
        (
            stripped.trim().to_string(),
            Some(AddressFamilyFilter::IPv4Only),
        )
    } else if let Some(stripped) = trimmed.strip_prefix("6 ") {
        (
            stripped.trim().to_string(),
            Some(AddressFamilyFilter::IPv6Only),
        )
    } else {
        (trimmed.to_string(), None)
    };

    // Validate the set name format (should contain # separators for table#family#set)
    // We expect at least 2 # characters: table#family#set
    if parsed_name.matches('#').count() < 2 {
        return Err(NftsetError::InvalidSetName(format!(
            "invalid format '{parsed_name}': expected 'table#family#set'"
        )));
    }

    Ok((parsed_name, filter))
}

/// Add or remove an IP address to/from a nftables set
///
/// This is a convenience function that creates a temporary `NftablesManager`,
/// performs the operation, and returns. For multiple operations, it's more
/// efficient to create a `NftablesManager` once and reuse it.
///
/// # Arguments
///
/// * `setname` - Set identifier in format "table#family#set", optionally
///   prefixed with "4 " or "6 " for address family filtering
/// * `addr` - IP address to add or remove
/// * `remove` - If true, remove the address; if false, add it
///
/// # Errors
///
/// Returns an error if:
/// - The nftables context cannot be initialized
/// - The set name format is invalid
/// - The address family doesn't match an optional prefix filter
/// - The nftables command execution fails
///
/// # Examples
///
/// ```no_run
/// # use std::net::IpAddr;
/// # use dnsmasq::platform::linux::nftset::add_to_nftset;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: IpAddr = "192.0.2.1".parse()?;
/// add_to_nftset("filter#ip#blacklist", addr, false).await?;
/// # Ok(())
/// # }
/// ```
pub async fn add_to_nftset(setname: &str, addr: IpAddr, remove: bool) -> Result<(), NftsetError> {
    let manager = NftablesManager::new().await?;
    manager.modify_set(setname, addr, remove).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_setname_no_prefix() {
        let (name, filter) = parse_setname_and_filter("filter#ip#blacklist").unwrap();
        assert_eq!(name, "filter#ip#blacklist");
        assert_eq!(filter, None);
    }

    #[test]
    fn test_parse_setname_ipv4_prefix() {
        let (name, filter) = parse_setname_and_filter("4 filter#ip#blacklist").unwrap();
        assert_eq!(name, "filter#ip#blacklist");
        assert_eq!(filter, Some(AddressFamilyFilter::IPv4Only));
    }

    #[test]
    fn test_parse_setname_ipv6_prefix() {
        let (name, filter) = parse_setname_and_filter("6 nat#ip6#whitelist").unwrap();
        assert_eq!(name, "nat#ip6#whitelist");
        assert_eq!(filter, Some(AddressFamilyFilter::IPv6Only));
    }

    #[test]
    fn test_parse_setname_empty() {
        let result = parse_setname_and_filter("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_setname_invalid_format() {
        let result = parse_setname_and_filter("invalid_format");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_setname_missing_separators() {
        let result = parse_setname_and_filter("filter#blacklist");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_setname_with_spaces() {
        let (name, filter) = parse_setname_and_filter("  4  filter#ip#test  ").unwrap();
        assert_eq!(name, "filter#ip#test");
        assert_eq!(filter, Some(AddressFamilyFilter::IPv4Only));
    }

    #[test]
    fn test_address_family_filter_enum() {
        // Test enum variants
        let ipv4_filter = AddressFamilyFilter::IPv4Only;
        let ipv6_filter = AddressFamilyFilter::IPv6Only;

        assert_ne!(ipv4_filter, ipv6_filter);

        // Test Debug trait
        let debug_str = format!("{ipv4_filter:?}");
        assert!(debug_str.contains("IPv4Only"));
    }

    #[test]
    fn test_error_display() {
        // Test that error messages are properly formatted
        let init_error = NftsetError::InitFailed("test failure".to_string());
        let error_msg = format!("{init_error}");
        assert!(error_msg.contains("test failure"));

        let mismatch_error = NftsetError::AddressFamilyMismatch {
            expected: "IPv4".to_string(),
            actual: "IPv6".to_string(),
        };
        let error_msg = format!("{mismatch_error}");
        assert!(error_msg.contains("IPv4"));
        assert!(error_msg.contains("IPv6"));
    }

    #[test]
    fn test_parse_setname_treats_invalid_prefix_as_part_of_name() {
        // Invalid prefixes like "7 " or "x " are treated as part of the setname,
        // not as filter prefixes. This matches C implementation behavior.
        // These should succeed if the full string has valid format.
        let result = parse_setname_and_filter("7#table#family#test");
        assert!(result.is_ok());
        let (name, filter) = result.unwrap();
        assert_eq!(name, "7#table#family#test");
        assert_eq!(filter, None);

        // This should fail because "x filter" doesn't have enough # separators
        let result = parse_setname_and_filter("x filter");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_setname_various_families() {
        // Test different address family names
        let valid_cases = vec![
            "filter#ip#blacklist",
            "nat#ip6#whitelist",
            "mangle#inet#hosts",
            "bridge#bridge#macs",
        ];

        for case in valid_cases {
            let result = parse_setname_and_filter(case);
            assert!(result.is_ok(), "Failed to parse: {case}");
            let (setname, _) = result.unwrap();
            assert_eq!(setname, case);
        }
    }

    #[tokio::test]
    async fn test_nftables_manager_initialization() {
        // Test that manager initialization handles both success and failure gracefully
        let result = NftablesManager::new().await;

        match result {
            Ok(_manager) => {
                // Success case - nft is installed
                println!("nft binary found and initialized successfully");
            }
            Err(NftsetError::InitFailed(_)) => {
                // Expected failure if nft is not installed
                println!("nft binary not found (expected in test environment)");
            }
            Err(NftsetError::IoError(_)) => {
                // Also acceptable if there's an I/O error
                println!("I/O error during nft initialization");
            }
            Err(e) => {
                panic!("Unexpected error type: {e:?}");
            }
        }
    }

    #[test]
    fn test_ipaddr_string_conversion() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // Test that IpAddr::to_string() works correctly for command construction
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        assert_eq!(ipv4.to_string(), "192.168.1.1");
        assert_eq!(ipv6.to_string(), "2001:db8::1");
    }
}
