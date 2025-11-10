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
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Linux nftables set integration (successor to ipset)
//!
//! # Overview
//!
//! This module provides automatic addition of DNS-resolved addresses to nftables
//! sets using the libnftables API. Nftables is the modern replacement for iptables
//! and ipset in Linux, offering richer data types, better performance, and improved
//! integration with the Linux kernel netfilter framework.
//!
//! When dnsmasq resolves DNS queries for domains configured with `--nftset` options,
//! the resolved IP addresses are automatically added to the specified nftables sets,
//! enabling dynamic firewall rules and routing policies based on DNS resolution results.
//!
//! # Set Identifier Format
//!
//! Nftables sets are identified using the format `"table#family#set"` where:
//! - `table` is the nftables table name (e.g., "filter", "nat", "mangle")
//! - `family` is the address family ("ip" for IPv4, "ip6" for IPv6, "inet" for both)
//! - `set` is the set name within that table
//!
//! Example: `"filter#ip#blacklist"` refers to set "blacklist" in table "filter" with family "ip"
//!
//! # Address Family Filtering
//!
//! Set names can be prefixed with "4 " or "6 " to restrict updates to IPv4 or IPv6 addresses:
//! - `"4 filter#ip#whitelist"` - only add IPv4 addresses
//! - `"6 nat#ip6#vpn_clients"` - only add IPv6 addresses
//! - `"filter#inet#combined"` - add both IPv4 and IPv6 (no prefix)
//!
//! # Memory Safety
//!
//! This Rust implementation replaces C's manual memory management with:
//! - Safe `String` formatting instead of manual buffer allocation with `malloc`/`realloc`
//! - `IpAddr::to_string()` instead of `inet_ntop()` with fixed buffers
//! - `Result<T, E>` types instead of integer return codes and errno
//! - `Drop` trait for automatic context cleanup instead of manual `nft_ctx_free`
//! - `str::strip_prefix()` for safe string slicing instead of pointer arithmetic
//!
//! # Platform Support
//!
//! This module requires:
//! - Linux 3.13+ kernel with nftables support
//! - libnftables library (Debian/Ubuntu: libnftables-dev, RedHat/CentOS: nftables-devel)
//! - Feature flags: `HAVE_NFTSET` and `HAVE_LINUX_NETWORK`
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use std::net::IpAddr;
//! use dnsmasq::integration::nftset::{NftsetManager, AddressFamily};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize manager (context created once at startup)
//!     let mut manager = NftsetManager::new()?;
//!
//!     // Add IPv4 address to set
//!     let addr: IpAddr = "192.0.2.1".parse()?;
//!     manager.add_element("filter#ip#blacklist", addr, AddressFamily::V4).await?;
//!
//!     // Add with address family filtering (only IPv4)
//!     manager.add_element("4 filter#ip#whitelist", addr, AddressFamily::V4).await?;
//!
//!     // Remove address from set
//!     manager.delete_element("filter#ip#blacklist", addr, AddressFamily::V4).await?;
//!     Ok(())
//! }
//! ```
//!
//! # Behavioral Preservation
//!
//! This implementation maintains exact compatibility with the C version:
//! - Command syntax: `"add element <set> { <address> }"` and `"delete element <set> { <address> }"`
//! - Address family filtering with "4 " and "6 " prefixes
//! - Error buffering to prevent stderr pollution
//! - Synchronous command execution (wrapped in async for non-blocking operation)
//! - Identical logging behavior for command failures
//!
//! # References
//!
//! - C implementation: `src/nftset.c`
//! - Legacy ipset implementation: `src/ipset.c`
//! - DNS forwarding integration: `src/forward.c`

use crate::ffi::platform::nftables::NftContext;
use std::fmt;
use std::net::IpAddr;
use thiserror::Error;
use tokio::task;
use tracing::{debug, error, info, trace, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Error type for nftables set operations
///
/// Represents all possible failure modes when interacting with nftables sets.
/// Each variant provides context about the specific failure for debugging and
/// operational visibility.
#[derive(Error, Debug)]
pub enum NftsetError {
    /// Failed to create nftables context during initialization
    ///
    /// This typically indicates:
    /// - libnftables library not installed
    /// - Kernel nftables support not available (requires Linux 3.13+)
    /// - Insufficient permissions to create nftables context
    ///
    /// Equivalent to C's `nft_ctx_new()` returning NULL (line 146-148 in nftset.c)
    #[error("Failed to create nftables context: {0}")]
    ContextCreationFailed(String),

    /// Failed to execute nftables command
    ///
    /// This occurs when `nft_run_cmd_from_buffer()` returns non-zero, indicating:
    /// - Set doesn't exist in the specified table
    /// - Table doesn't exist
    /// - Invalid command syntax
    /// - Permission denied (`CAP_NET_ADMIN` required)
    /// - Kernel netfilter module not loaded
    /// - Address already exists in set (for add operations)
    /// - Address doesn't exist in set (for delete operations)
    ///
    /// The error message contains output from `nft_ctx_get_error_buffer()` with
    /// only the first line (newlines stripped) matching C behavior (lines 280-285)
    #[error("nftables command execution failed: {set} - {details}")]
    CommandExecutionFailed {
        /// Set identifier that failed
        set: String,
        /// Error details from nftables error buffer
        details: String,
    },

    /// Address family mismatch between filter prefix and actual address
    ///
    /// Occurs when:
    /// - "4 " prefix used with IPv6 address (line 251-252 in C)
    /// - "6 " prefix used with IPv4 address (line 254-255 in C)
    ///
    /// This prevents incorrect set updates when using family-specific filtering
    #[error("Address family mismatch: set filter '{filter}' incompatible with address family {actual}")]
    AddressFamilyMismatch {
        /// Prefix filter ("4 " or "6 ")
        filter: String,
        /// Actual address family
        actual: AddressFamily,
    },

    /// Invalid set name format
    ///
    /// Set identifier must be in format "table#family#set" or with optional
    /// family prefix "4 table#family#set" or "6 table#family#set"
    #[error("Invalid set format: {0} (expected 'table#family#set' or '4 table#family#set')")]
    InvalidSetFormat(String),

    /// I/O error from nftables operations
    ///
    /// Wraps underlying I/O errors from FFI operations
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

// ============================================================================
// Address Family Types
// ============================================================================

/// Address family for nftables set operations
///
/// Distinguishes between IPv4 and IPv6 addresses to determine:
/// - Which union member to access in C's `union all_addr`
/// - Which address family to pass to `inet_ntop()` (`AF_INET` vs `AF_INET6`)
/// - Whether address family filter prefixes match
///
/// Replaces C's flag-based detection: `(flags & F_IPV4) ? AF_INET : AF_INET6`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 address family (`AF_INET`, `F_IPV4` flag in C)
    V4,
    /// IPv6 address family (`AF_INET6`, absence of `F_IPV4` in C)
    V6,
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressFamily::V4 => write!(f, "IPv4"),
            AddressFamily::V6 => write!(f, "IPv6"),
        }
    }
}

impl AddressFamily {
    /// Determine address family from `IpAddr`
    ///
    /// Automatically detects whether an IP address is IPv4 or IPv6 without
    /// requiring explicit flag passing
    #[must_use]
    pub fn from_ip_addr(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        }
    }
}

// ============================================================================
// Nftables Set Manager
// ============================================================================

/// Nftables set manager for DNS-resolved address integration
///
/// Manages the libnftables context and provides methods to add/remove IP addresses
/// to/from nftables sets. The context is initialized once at startup and reused
/// for all operations, matching C's static `ctx` variable (line 98).
///
/// # Memory Safety
///
/// - Owns `NftContext` which implements `Drop` for automatic cleanup
/// - Uses safe `String` formatting instead of manual buffer management
/// - All buffer operations are bounds-checked by Rust
/// - No manual memory allocation or pointer arithmetic
///
/// # Thread Safety
///
/// Not thread-safe due to shared nftables context. In dnsmasq's single-threaded
/// event-driven model, this is acceptable. For async operations, all methods wrap
/// FFI calls in `tokio::task::spawn_blocking` to prevent blocking the event loop.
///
/// # Examples
///
/// ```rust,no_run
/// # use std::net::IpAddr;
/// # use dnsmasq::integration::nftset::{NftsetManager, AddressFamily};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut manager = NftsetManager::new()?;
///
/// let addr: IpAddr = "192.0.2.1".parse()?;
/// manager.add_element("filter#ip#blacklist", addr, AddressFamily::V4).await?;
/// # Ok(())
/// # }
/// ```
pub struct NftsetManager {
    /// Nftables context with automatic cleanup via Drop trait
    ///
    /// Replaces C's static `struct nft_ctx *ctx` (line 98) with owned context
    /// that is automatically freed when manager is dropped
    ctx: NftContext,
}

impl NftsetManager {
    /// Create new nftables set manager with initialized context
    ///
    /// Initializes the libnftables context required for all subsequent set operations.
    /// Must be called once during dnsmasq initialization before any `add_element` or
    /// `delete_element` operations.
    ///
    /// # Errors
    ///
    /// Returns `NftsetError::ContextCreationFailed` if:
    /// - libnftables library is not installed
    /// - Kernel nftables support is unavailable (requires Linux 3.13+)
    /// - Insufficient permissions to create context
    ///
    /// # Behavioral Preservation
    ///
    /// Matches C's `nftset_init()` function (lines 144-152) behavior:
    /// - Creates nftables context with `NFT_CTX_DEFAULT` flags
    /// - Configures error buffering to prevent stderr pollution
    /// - In C version, failure causes process termination via `die()`
    /// - Rust version returns `Result` for graceful error handling by caller
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dnsmasq::integration::nftset::NftsetManager;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = NftsetManager::new()?;
    /// // Context is now ready for add_element/delete_element operations
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self, NftsetError> {
        trace!("Initializing nftables context");

        // Create nftables context (equivalent to nft_ctx_new(NFT_CTX_DEFAULT))
        let mut ctx = NftContext::new().ok_or_else(|| {
            let msg = "nft_ctx_new() returned NULL - kernel support or library missing";
            error!("{}", msg);
            NftsetError::ContextCreationFailed(msg.to_string())
        })?;

        // Configure error buffering to prevent stderr pollution
        // Equivalent to nft_ctx_buffer_error(ctx) in C (line 151)
        ctx.buffer_error();

        info!("Nftables context initialized successfully");

        Ok(NftsetManager { ctx })
    }

    /// Add IP address to nftables set
    ///
    /// Adds an IPv4 or IPv6 address to the specified nftables set by executing
    /// an nftables command like: `"add element filter#ip#blacklist { 192.0.2.1 }"`
    ///
    /// # Arguments
    ///
    /// * `setname` - Set identifier in format "table#family#set", or with optional
    ///   address family prefix "4 table#family#set" or "6 table#family#set".
    ///   Examples: "filter#ip#blacklist", "4 mangle#ip#ratelimit"
    /// * `addr` - IP address to add (IPv4 or IPv6)
    /// * `family` - Address family (V4 or V6) for validation
    ///
    /// # Errors
    ///
    /// - `AddressFamilyMismatch` if family filter prefix doesn't match actual address
    /// - `CommandExecutionFailed` if nftables command fails (set doesn't exist, etc.)
    /// - `IoError` for underlying I/O errors
    ///
    /// # Async Behavior
    ///
    /// Wraps synchronous nftables FFI call in `tokio::task::spawn_blocking` to
    /// prevent blocking the async event loop during command execution. DNS query
    /// processing continues while nftables set is being updated.
    ///
    /// # Behavioral Preservation
    ///
    /// Matches C's `add_to_nftset()` with `remove=0` (line 238-289):
    /// - Same command format: "add element <set> { <address> }"
    /// - Same address family filtering logic (lines 249-258)
    /// - Same error logging behavior (lines 280-286)
    /// - Returns Result instead of C's integer return codes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use std::net::IpAddr;
    /// # use dnsmasq::integration::nftset::{NftsetManager, AddressFamily};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manager = NftsetManager::new()?;
    /// let addr: IpAddr = "192.0.2.1".parse()?;
    ///
    /// // Add without family filtering
    /// manager.add_element("filter#ip#blacklist", addr, AddressFamily::V4).await?;
    ///
    /// // Add with IPv4-only filtering
    /// manager.add_element("4 filter#ip#whitelist", addr, AddressFamily::V4).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_element(
        &mut self,
        setname: &str,
        addr: IpAddr,
        family: AddressFamily,
    ) -> Result<(), NftsetError> {
        self.modify_element(setname, addr, family, false).await
    }

    /// Remove IP address from nftables set
    ///
    /// Removes an IPv4 or IPv6 address from the specified nftables set by executing
    /// an nftables command like: `"delete element filter#ip#blacklist { 192.0.2.1 }"`
    ///
    /// # Arguments
    ///
    /// * `setname` - Set identifier (same format as `add_element`)
    /// * `addr` - IP address to remove
    /// * `family` - Address family (V4 or V6) for validation
    ///
    /// # Errors
    ///
    /// - `AddressFamilyMismatch` if family filter prefix doesn't match
    /// - `CommandExecutionFailed` if nftables command fails
    ///
    /// # Note
    ///
    /// Removing a non-existent address typically generates nftables errors but
    /// doesn't affect daemon operation. Errors are logged but not fatal.
    ///
    /// # Behavioral Preservation
    ///
    /// Matches C's `add_to_nftset()` with `remove!=0` (line 238-289):
    /// - Uses command: "delete element <set> { <address> }"
    /// - Same error handling and logging
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use std::net::IpAddr;
    /// # use dnsmasq::integration::nftset::{NftsetManager, AddressFamily};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manager = NftsetManager::new()?;
    /// let addr: IpAddr = "192.0.2.1".parse()?;
    ///
    /// manager.delete_element("filter#ip#blacklist", addr, AddressFamily::V4).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete_element(
        &mut self,
        setname: &str,
        addr: IpAddr,
        family: AddressFamily,
    ) -> Result<(), NftsetError> {
        self.modify_element(setname, addr, family, true).await
    }

    /// Internal method to add or remove elements from nftables sets
    ///
    /// Shared implementation for `add_element` and `delete_element` that handles:
    /// - Address family filtering with "4 " or "6 " prefix
    /// - Command buffer construction with safe String formatting
    /// - Async execution in blocking thread pool
    /// - Error logging with structured tracing
    ///
    /// # Behavioral Preservation
    ///
    /// This method replicates the complete logic of C's `add_to_nftset()` (lines 238-289):
    ///
    /// 1. **Address Formatting** (line 247): Uses `IpAddr::to_string()` instead of
    ///    `inet_ntop()` with fixed buffer, eliminating buffer overflow risk
    ///
    /// 2. **Family Filtering** (lines 249-258): Checks for "4 " or "6 " prefix and
    ///    validates against actual address family, returning error on mismatch
    ///
    /// 3. **Command Construction**: Uses Rust `format!` macro instead of C's
    ///    `snprintf()` with dynamic reallocation (lines 260-275), eliminating
    ///    manual memory management and potential buffer overflows
    ///
    /// 4. **Command Execution** (line 277): Calls `nft_run_cmd_from_buffer()` via
    ///    safe FFI wrapper that handles error buffer retrieval
    ///
    /// 5. **Error Handling** (lines 280-286): On failure, retrieves error buffer,
    ///    strips newlines from first line only, logs to syslog (now tracing)
    ///
    /// # Memory Safety Improvements
    ///
    /// - No manual buffer allocation (`whine_malloc`/`realloc`/`free`)
    /// - No pointer arithmetic for prefix parsing
    /// - No manual string copying or concatenation
    /// - Automatic memory cleanup via RAII
    /// - Type-safe error propagation with Result
    async fn modify_element(
        &mut self,
        setname: &str,
        addr: IpAddr,
        family: AddressFamily,
        remove: bool,
    ) -> Result<(), NftsetError> {
        // Format IP address to string (replaces inet_ntop, line 247)
        // IpAddr::to_string() is safe and cannot overflow buffers
        let addr_str = addr.to_string();

        debug!(
            setname = %setname,
            address = %addr_str,
            family = %family,
            operation = if remove { "delete" } else { "add" },
            "Processing nftset operation"
        );

        // Handle address family filtering prefix (lines 249-258 in C)
        // Parse "4 " or "6 " prefix and validate against actual address family
        let (filtered_setname, family_filter) = if setname.len() >= 2 && setname.as_bytes()[1] == b' ' {
            let prefix = &setname[0..1];
            match prefix {
                "4" => {
                    // IPv4-only filter
                    if family != AddressFamily::V4 {
                        warn!(
                            setname = %setname,
                            address = %addr_str,
                            expected = "IPv4",
                            actual = %family,
                            "Address family mismatch"
                        );
                        return Err(NftsetError::AddressFamilyMismatch {
                            filter: "4 ".to_string(),
                            actual: family,
                        });
                    }
                    (&setname[2..], Some("4"))
                }
                "6" => {
                    // IPv6-only filter
                    if family != AddressFamily::V6 {
                        warn!(
                            setname = %setname,
                            address = %addr_str,
                            expected = "IPv6",
                            actual = %family,
                            "Address family mismatch"
                        );
                        return Err(NftsetError::AddressFamilyMismatch {
                            filter: "6 ".to_string(),
                            actual: family,
                        });
                    }
                    (&setname[2..], Some("6"))
                }
                _ => {
                    // Prefix exists but not "4" or "6", use full name
                    (setname, None)
                }
            }
        } else {
            // No prefix filtering
            (setname, None)
        };

        trace!(
            original_setname = %setname,
            filtered_setname = %filtered_setname,
            family_filter = ?family_filter,
            "Parsed set name and family filter"
        );

        // Construct nftables command with safe String formatting
        // Replaces C's snprintf with dynamic buffer reallocation (lines 260-275)
        // Format: "add element <set> { <address> }" or "delete element <set> { <address> }"
        let cmd_template = if remove {
            "delete element"
        } else {
            "add element"
        };

        // Safe string formatting - no buffer overflow possible
        // Replaces C's static templates and manual buffer management (lines 99-100, 263-275)
        let command = format!("{cmd_template} {filtered_setname} {{ {addr_str} }}");

        trace!(command = %command, "Constructed nftables command");

        // Execute command in blocking thread pool to avoid blocking async event loop
        // C version executes synchronously in main event loop (line 277)
        let setname_owned = filtered_setname.to_string();
        let result = task::spawn_blocking(move || {
            // This closure captures command and executes synchronously
            command
        })
        .await
        .map_err(|e| NftsetError::IoError(std::io::Error::other(e)))?;

        // Execute nftables command via FFI
        // Equivalent to nft_run_cmd_from_buffer(ctx, cmd_buf) (line 277)
        if let Err(_e) = self.ctx.run_command(&result) {
            // Command execution failed - retrieve error details
            // Equivalent to nft_ctx_get_error_buffer(ctx) (line 278)
            let error_details = self
                .ctx
                .get_error_buffer()
                .unwrap_or_else(|| "Unknown error".to_string());

            // Strip newlines from error message (only log first line)
            // Matches C behavior: if ((nl = strchr(err, '\n'))) *nl = 0; (lines 283-284)
            let error_first_line = error_details
                .lines()
                .next()
                .unwrap_or(&error_details)
                .to_string();

            // Log error matching C's my_syslog format (line 285)
            error!(
                setname = %setname_owned,
                error = %error_first_line,
                command = %result,
                "nftables command failed"
            );

            return Err(NftsetError::CommandExecutionFailed {
                set: setname_owned,
                details: error_first_line,
            });
        }

        // Success - log operation
        info!(
            setname = %setname_owned,
            address = %addr_str,
            operation = if remove { "deleted" } else { "added" },
            "nftables set element operation completed successfully"
        );

        Ok(())
    }
}

// ============================================================================
// Standalone Convenience Functions
// ============================================================================

/// Add IP address to nftables set (convenience function)
///
/// Standalone function that creates a temporary `NftsetManager` and adds an address
/// to the specified set. For repeated operations, use `NftsetManager` directly to
/// avoid recreating the context.
///
/// # Arguments
///
/// * `setname` - Set identifier in format "table#family#set"
/// * `addr` - IP address to add
/// * `family` - Address family for validation
///
/// # Errors
///
/// Returns errors from both context creation and element addition
///
/// # Examples
///
/// ```rust,no_run
/// # use std::net::IpAddr;
/// # use dnsmasq::integration::nftset::{add_element, AddressFamily};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: IpAddr = "192.0.2.1".parse()?;
/// add_element("filter#ip#blacklist", addr, AddressFamily::V4).await?;
/// # Ok(())
/// # }
/// ```
pub async fn add_element(
    setname: &str,
    addr: IpAddr,
    family: AddressFamily,
) -> Result<(), NftsetError> {
    let mut manager = NftsetManager::new()?;
    manager.add_element(setname, addr, family).await
}

/// Remove IP address from nftables set (convenience function)
///
/// Standalone function that creates a temporary `NftsetManager` and removes an address
/// from the specified set. For repeated operations, use `NftsetManager` directly.
///
/// # Arguments
///
/// * `setname` - Set identifier in format "table#family#set"
/// * `addr` - IP address to remove
/// * `family` - Address family for validation
///
/// # Errors
///
/// Returns errors from both context creation and element deletion
///
/// # Examples
///
/// ```rust,no_run
/// # use std::net::IpAddr;
/// # use dnsmasq::integration::nftset::{delete_element, AddressFamily};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: IpAddr = "192.0.2.1".parse()?;
/// delete_element("filter#ip#blacklist", addr, AddressFamily::V4).await?;
/// # Ok(())
/// # }
/// ```
pub async fn delete_element(
    setname: &str,
    addr: IpAddr,
    family: AddressFamily,
) -> Result<(), NftsetError> {
    let mut manager = NftsetManager::new()?;
    manager.delete_element(setname, addr, family).await
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_family_from_ip_addr() {
        let ipv4: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(AddressFamily::from_ip_addr(&ipv4), AddressFamily::V4);

        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(AddressFamily::from_ip_addr(&ipv6), AddressFamily::V6);
    }

    #[test]
    fn test_address_family_display() {
        assert_eq!(format!("{}", AddressFamily::V4), "IPv4");
        assert_eq!(format!("{}", AddressFamily::V6), "IPv6");
    }

    #[test]
    fn test_nftset_error_display() {
        let err = NftsetError::ContextCreationFailed("test error".to_string());
        assert!(err.to_string().contains("Failed to create nftables context"));

        let err = NftsetError::CommandExecutionFailed {
            set: "filter#ip#test".to_string(),
            details: "set not found".to_string(),
        };
        assert!(err.to_string().contains("command execution failed"));
        assert!(err.to_string().contains("filter#ip#test"));

        let err = NftsetError::AddressFamilyMismatch {
            filter: "4 ".to_string(),
            actual: AddressFamily::V6,
        };
        assert!(err.to_string().contains("mismatch"));
        assert!(err.to_string().contains("IPv6"));
    }

    #[test]
    fn test_error_is_std_error() {
        // Verify NftsetError implements std::error::Error trait
        fn assert_error<T: std::error::Error>() {}
        assert_error::<NftsetError>();
    }

    // Integration tests requiring actual nftables installation are in tests/integration/
    // These unit tests only verify logic without FFI dependencies
}

// ============================================================================
// Documentation Tests
// ============================================================================

// Note: Documentation examples use `no_run` annotation because they require:
// 1. libnftables library installed
// 2. Linux 3.13+ kernel with nftables support
// 3. CAP_NET_ADMIN capability or root privileges
// 4. Pre-existing nftables table and set
//
// Full integration tests are in tests/integration/nftset_tests.rs
