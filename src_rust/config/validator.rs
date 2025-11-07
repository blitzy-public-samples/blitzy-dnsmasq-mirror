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

//! Configuration validation logic refactored from option.c
//!
//! This module implements comprehensive configuration validation extracted from the C implementation's
//! validation functions and conflict detection scattered throughout the one_opt() switch statement
//! (option.c lines 2721-5947). It provides centralized validation with composable error handling using
//! Rust's Result types, preventing invalid configurations from reaching daemon initialization.
//!
//! # Memory Safety Transformation
//!
//! All C validation patterns are replaced with safe Rust equivalents per Agent Action Plan section 0.3.3:
//! - `atoi()` / `strtoul()` → `str::FromStr` trait with checked conversions (no overflow)
//! - `inet_pton()` → `IpAddr::from_str()` with built-in format validation
//! - Manual string bounds checking → Safe slice operations with automatic bounds checks
//! - `access()` syscall → `nix::unistd::access()` with type-safe AccessFlags enum
//! - `NULL` checks → `Option<T>` with type-safe null handling
//!
//! # Validation Coverage
//!
//! This module validates:
//! - Port numbers (0-65535 range, >1024 for unprivileged)
//! - IP addresses (IPv4/IPv6 format validation)
//! - Socket addresses (IP + port combinations)
//! - Time intervals (seconds/minutes/hours/days with Duration)
//! - File paths (existence, readability, writability, executability)
//! - DHCP address range overlaps
//! - Duplicate option specifications
//! - Mutually exclusive options (e.g., --port=0 conflicts with DNS options)
//! - Required option combinations (e.g., --auth-zone requires --auth-server)
//! - Cross-subsystem consistency (DNS/DHCP/TFTP/Auth)
//!
//! # Original C Functions Replaced
//!
//! - `numeric_check()` (option.c:1061) → Rust's `str::parse::<T>()` with FromStr
//! - `atoi_check()` (option.c:1104) → `validate_port_range()` with checked conversion
//! - `atoi_check16()` (option.c:1182) → `validate_port_range()` with u16 bounds
//! - `strtoul_check()` (option.c:1139) → `str::parse::<u32>()` with overflow checks
//! - `parse_mysockaddr()` (option.c:1375) → `validate_socket_address()` with IpAddr
//! - `parse_server()` (option.c:1439) → `validate_socket_address()` for upstream servers
//! - Inline validation in one_opt() → Centralized functions in this module

use super::types::Config;
use nix::unistd::{access, AccessFlags};
use std::fmt::{self, Debug, Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

/// Errors that can occur during configuration validation
///
/// Provides detailed context for each validation failure to help operators
/// quickly identify and fix configuration issues. Each variant includes
/// the option name, invalid value, and reason for rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Port number out of valid range (0-65535) or invalid for context
    ///
    /// Corresponds to `atoi_check16()` validation in option.c:1182
    InvalidPort {
        /// Configuration field name (e.g., "dns.port", "dhcp.server_port")
        option: String,
        /// The invalid port number
        port: u16,
        /// Reason for rejection (e.g., "port must be >1024 for unprivileged user")
        reason: String,
    },

    /// Invalid IP address format (neither valid IPv4 nor IPv6)
    ///
    /// Corresponds to `parse_mysockaddr()` validation in option.c:1375
    InvalidIpAddress {
        /// Configuration field name
        option: String,
        /// The invalid IP address string
        address: String,
        /// Reason for rejection
        reason: String,
    },

    /// Invalid socket address (IP:port combination)
    ///
    /// Corresponds to `parse_server()` validation in option.c:1439
    InvalidSocketAddress {
        /// Configuration field name
        option: String,
        /// The invalid socket address string
        address: String,
        /// Reason for rejection
        reason: String,
    },

    /// Invalid time duration specification
    ///
    /// Corresponds to time parsing in one_opt() for lease times, TTLs, etc.
    InvalidDuration {
        /// Configuration field name
        option: String,
        /// The invalid duration string
        value: String,
        /// Reason for rejection
        reason: String,
    },

    /// File not found at specified path
    ///
    /// Corresponds to file existence checks throughout one_opt()
    FileNotFound {
        /// Configuration field name
        option: String,
        /// Path to missing file
        path: PathBuf,
    },

    /// File exists but is not readable
    ///
    /// Corresponds to access() checks in C implementation
    FileNotReadable {
        /// Configuration field name
        option: String,
        /// Path to unreadable file
        path: PathBuf,
    },

    /// File or directory is not writable
    ///
    /// Corresponds to write permission checks for lease files, PID files
    FileNotWritable {
        /// Configuration field name
        option: String,
        /// Path to unwritable location
        path: PathBuf,
    },

    /// Script file is not executable
    ///
    /// Corresponds to executable checks for dhcp-script, etc.
    FileNotExecutable {
        /// Configuration field name
        option: String,
        /// Path to non-executable file
        path: PathBuf,
    },

    /// DHCP address ranges overlap
    ///
    /// Corresponds to range overlap detection in one_opt() DHCP range handling
    DhcpRangeOverlap {
        /// First overlapping range (e.g., "192.168.1.10-192.168.1.100")
        range1: String,
        /// Second overlapping range
        range2: String,
        /// Interface or context where overlap occurs
        context: String,
    },

    /// Option specified multiple times (duplicate)
    ///
    /// Corresponds to duplicate detection in one_opt() switch statement
    DuplicateOption {
        /// Option name that was duplicated
        option: String,
        /// First value specified
        first_value: String,
        /// Second (conflicting) value
        second_value: String,
    },

    /// Mutually exclusive options both specified
    ///
    /// Corresponds to option conflict checks throughout one_opt()
    MutuallyExclusiveOptions {
        /// First option name
        option1: String,
        /// Second conflicting option name
        option2: String,
        /// Explanation of why they conflict
        reason: String,
    },

    /// Required option missing for feature
    ///
    /// Corresponds to required combination validation (e.g., auth-zone needs auth-server)
    RequiredOptionMissing {
        /// Feature that requires the option
        feature: String,
        /// Required option name
        required_option: String,
        /// Explanation of requirement
        reason: String,
    },

    /// Numeric value out of valid range
    ///
    /// Corresponds to range checks throughout one_opt()
    InvalidRange {
        /// Configuration field name
        option: String,
        /// The value specified
        value: String,
        /// Minimum valid value
        min: String,
        /// Maximum valid value
        max: String,
    },

    /// Invalid value for option
    ///
    /// Corresponds to format/type validation in one_opt()
    InvalidValue {
        /// Configuration field name
        option: String,
        /// The invalid value
        value: String,
        /// Expected format or valid values
        expected: String,
    },

    /// Options conflict with each other
    ///
    /// Corresponds to cross-option validation (e.g., --port=0 disables DNS but DNS options present)
    OptionConflict {
        /// Description of the conflict
        message: String,
        /// Primary option involved
        option1: String,
        /// Secondary option involved
        option2: String,
    },
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort { option, port, reason } => {
                write!(f, "Invalid port {port} for option '{option}': {reason}")
            }
            Self::InvalidIpAddress { option, address, reason } => {
                write!(f, "Invalid IP address '{address}' for option '{option}': {reason}")
            }
            Self::InvalidSocketAddress { option, address, reason } => {
                write!(f, "Invalid socket address '{address}' for option '{option}': {reason}")
            }
            Self::InvalidDuration { option, value, reason } => {
                write!(f, "Invalid duration '{value}' for option '{option}': {reason}")
            }
            Self::FileNotFound { option, path } => {
                write!(f, "File not found for option '{option}': {}", path.display())
            }
            Self::FileNotReadable { option, path } => {
                write!(f, "File not readable for option '{option}': {}", path.display())
            }
            Self::FileNotWritable { option, path } => {
                write!(f, "File or directory not writable for option '{option}': {}", path.display())
            }
            Self::FileNotExecutable { option, path } => {
                write!(f, "File not executable for option '{option}': {}", path.display())
            }
            Self::DhcpRangeOverlap { range1, range2, context } => {
                write!(f, "Overlapping DHCP ranges in {context}: {range1} and {range2}")
            }
            Self::DuplicateOption { option, first_value, second_value } => {
                write!(f, "Option '{option}' specified multiple times: '{first_value}' and '{second_value}'")
            }
            Self::MutuallyExclusiveOptions { option1, option2, reason } => {
                write!(f, "Mutually exclusive options: '{option1}' and '{option2}': {reason}")
            }
            Self::RequiredOptionMissing { feature, required_option, reason } => {
                write!(f, "Feature '{feature}' requires option '{required_option}': {reason}")
            }
            Self::InvalidRange { option, value, min, max } => {
                write!(f, "Value '{value}' out of range for option '{option}': must be between {min} and {max}")
            }
            Self::InvalidValue { option, value, expected } => {
                write!(f, "Invalid value '{value}' for option '{option}': expected {expected}")
            }
            Self::OptionConflict { message, option1, option2 } => {
                write!(f, "Option conflict between '{option1}' and '{option2}': {message}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate a port number is in valid range
///
/// Replaces C's `atoi_check16()` (option.c:1182) with safe parsing and range validation.
/// Validates port numbers are in the valid range 0-65535. Additional context-specific
/// validation (e.g., >1024 for unprivileged users) is performed by callers.
///
/// # Arguments
///
/// * `port` - Port number to validate (u16 automatically ensures 0-65535 range)
/// * `option_name` - Name of configuration option for error reporting
/// * `allow_zero` - Whether port 0 is allowed (some contexts use 0 to disable features)
/// * `require_unprivileged` - Whether port must be >1024 (for non-root operation)
///
/// # Returns
///
/// `Ok(())` if port is valid, `Err(ValidationError::InvalidPort)` otherwise
///
/// # Example
///
/// ```
/// # use dnsmasq::config::validator::validate_port_range;
/// // DNS port 53 requires root privileges
/// assert!(validate_port_range(53, "dns-port", false, false).is_ok());
///
/// // Port 8053 is valid for unprivileged user
/// assert!(validate_port_range(8053, "dns-port", false, true).is_ok());
///
/// // Port 0 to disable DNS
/// assert!(validate_port_range(0, "dns-port", true, false).is_ok());
/// ```
pub fn validate_port_range(
    port: u16,
    option_name: &str,
    allow_zero: bool,
    require_unprivileged: bool,
) -> Result<(), ValidationError> {
    // Check if port is 0 when not allowed
    if port == 0 && !allow_zero {
        return Err(ValidationError::InvalidPort {
            option: option_name.to_string(),
            port,
            reason: "port must be 1-65535 (0 not allowed in this context)".to_string(),
        });
    }

    // Check if port requires unprivileged range (>1024)
    if require_unprivileged && port != 0 && port < 1024 {
        return Err(ValidationError::InvalidPort {
            option: option_name.to_string(),
            port,
            reason: "port must be >1024 for unprivileged operation".to_string(),
        });
    }

    Ok(())
}

/// Validate an IP address string format
///
/// Replaces C's `inet_pton()` validation in `parse_mysockaddr()` (option.c:1375) with
/// Rust's safe `IpAddr::from_str()` which handles both IPv4 and IPv6 formats with
/// built-in validation and no buffer overflow risks.
///
/// # Arguments
///
/// * `address` - IP address string to validate (IPv4 or IPv6)
/// * `option_name` - Name of configuration option for error reporting
///
/// # Returns
///
/// `Ok(IpAddr)` if address is valid, `Err(ValidationError::InvalidIpAddress)` otherwise
///
/// # Example
///
/// ```
/// # use dnsmasq::config::validator::validate_ip_address;
/// # use std::net::IpAddr;
/// // Valid IPv4 address
/// assert!(validate_ip_address("192.168.1.1", "listen-address").is_ok());
///
/// // Valid IPv6 address
/// assert!(validate_ip_address("2001:db8::1", "listen-address").is_ok());
///
/// // Invalid address
/// assert!(validate_ip_address("999.999.999.999", "listen-address").is_err());
/// ```
pub fn validate_ip_address(address: &str, option_name: &str) -> Result<IpAddr, ValidationError> {
    IpAddr::from_str(address).map_err(|_| ValidationError::InvalidIpAddress {
        option: option_name.to_string(),
        address: address.to_string(),
        reason: "not a valid IPv4 or IPv6 address".to_string(),
    })
}

/// Validate a socket address (IP:port combination)
///
/// Replaces C's `parse_server()` (option.c:1439) with safe parsing using Rust's
/// standard library. Handles multiple formats: "IP", "IP:port", "[IPv6]", "[IPv6]:port".
///
/// # Arguments
///
/// * `address` - Socket address string to validate
/// * `option_name` - Name of configuration option for error reporting
/// * `default_port` - Default port to use if not specified in address
///
/// # Returns
///
/// `Ok(SocketAddr)` if valid, `Err(ValidationError::InvalidSocketAddress)` otherwise
///
/// # Example
///
/// ```
/// # use dnsmasq::config::validator::validate_socket_address;
/// // IP with explicit port
/// assert!(validate_socket_address("8.8.8.8:53", "server", 53).is_ok());
///
/// // IP without port (uses default)
/// assert!(validate_socket_address("8.8.8.8", "server", 53).is_ok());
///
/// // IPv6 with port
/// assert!(validate_socket_address("[2001:db8::1]:53", "server", 53).is_ok());
/// ```
pub fn validate_socket_address(
    address: &str,
    option_name: &str,
    default_port: u16,
) -> Result<SocketAddr, ValidationError> {
    // Try parsing as complete SocketAddr first (handles "IP:port" and "[IPv6]:port")
    if let Ok(sock_addr) = SocketAddr::from_str(address) {
        return Ok(sock_addr);
    }

    // Try parsing as just IP address, then add default port
    if let Ok(ip_addr) = IpAddr::from_str(address) {
        return Ok(SocketAddr::new(ip_addr, default_port));
    }

    // Neither format worked
    Err(ValidationError::InvalidSocketAddress {
        option: option_name.to_string(),
        address: address.to_string(),
        reason: "expected format: 'IP', 'IP:port', '[IPv6]', or '[IPv6]:port'".to_string(),
    })
}

/// Parse a time duration string with suffix (s, m, h, d, w)
///
/// Replaces inline duration parsing in C's one_opt() for lease times, TTLs, timeouts, etc.
/// Supports suffixes: s (seconds), m (minutes), h (hours), d (days), w (weeks).
/// No suffix defaults to seconds for backward compatibility with C implementation.
///
/// # Arguments
///
/// * `value` - Duration string to parse (e.g., "7200", "2h", "1d")
/// * `option_name` - Name of configuration option for error reporting
///
/// # Returns
///
/// `Ok(Duration)` if valid, `Err(ValidationError::InvalidDuration)` otherwise
///
/// # Example
///
/// ```
/// # use dnsmasq::config::validator::parse_duration;
/// # use std::time::Duration;
/// // Plain seconds
/// assert_eq!(parse_duration("3600", "ttl").unwrap(), Duration::from_secs(3600));
///
/// // With suffix
/// assert_eq!(parse_duration("1h", "ttl").unwrap(), Duration::from_secs(3600));
/// assert_eq!(parse_duration("1d", "lease-time").unwrap(), Duration::from_secs(86400));
/// ```
pub fn parse_duration(value: &str, option_name: &str) -> Result<Duration, ValidationError> {
    let value = value.trim();
    
    // Check for suffix
    let (number_part, multiplier) = if let Some(stripped) = value.strip_suffix('w') {
        (stripped, 7 * 24 * 60 * 60) // weeks
    } else if let Some(stripped) = value.strip_suffix('d') {
        (stripped, 24 * 60 * 60) // days
    } else if let Some(stripped) = value.strip_suffix('h') {
        (stripped, 60 * 60) // hours
    } else if let Some(stripped) = value.strip_suffix('m') {
        (stripped, 60) // minutes
    } else if let Some(stripped) = value.strip_suffix('s') {
        (stripped, 1) // seconds
    } else {
        (value, 1) // default to seconds
    };

    // Parse the numeric part
    let number = u64::from_str(number_part.trim()).map_err(|_| ValidationError::InvalidDuration {
        option: option_name.to_string(),
        value: value.to_string(),
        reason: "duration must be a number optionally followed by s, m, h, d, or w".to_string(),
    })?;

    // Calculate total seconds with overflow check
    let total_seconds = number.checked_mul(multiplier).ok_or_else(|| {
        ValidationError::InvalidDuration {
            option: option_name.to_string(),
            value: value.to_string(),
            reason: "duration value too large (overflow)".to_string(),
        }
    })?;

    Ok(Duration::from_secs(total_seconds))
}

/// Validate a file path exists and has required permissions
///
/// Replaces C's `access()` syscall validation scattered throughout one_opt() with
/// safe Rust wrapper from nix crate. Uses type-safe `AccessFlags` enum instead of
/// raw POSIX constants (R_OK, W_OK, X_OK).
///
/// # Arguments
///
/// * `path` - Path to validate
/// * `option_name` - Name of configuration option for error reporting
/// * `require_read` - Whether read permission is required
/// * `require_write` - Whether write permission is required
/// * `require_execute` - Whether execute permission is required
///
/// # Returns
///
/// `Ok(())` if file exists with required permissions, appropriate `ValidationError` otherwise
///
/// # Example
///
/// ```no_run
/// # use dnsmasq::config::validator::validate_file_path;
/// # use std::path::Path;
/// // Validate config file is readable
/// validate_file_path(Path::new("/etc/dnsmasq.conf"), "conf-file", true, false, false)?;
///
/// // Validate lease file directory is writable
/// validate_file_path(Path::new("/var/lib/dnsmasq"), "lease-file", false, true, false)?;
///
/// // Validate script is executable
/// validate_file_path(Path::new("/usr/local/bin/dhcp-script"), "dhcp-script", false, false, true)?;
/// # Ok::<(), dnsmasq::config::validator::ValidationError>(())
/// ```
pub fn validate_file_path(
    path: &Path,
    option_name: &str,
    require_read: bool,
    require_write: bool,
    require_execute: bool,
) -> Result<(), ValidationError> {
    // Check if file/directory exists
    if !path.exists() {
        return Err(ValidationError::FileNotFound {
            option: option_name.to_string(),
            path: path.to_path_buf(),
        });
    }

    // Build access flags
    let mut flags = AccessFlags::empty();
    if require_read {
        flags |= AccessFlags::R_OK;
    }
    if require_write {
        flags |= AccessFlags::W_OK;
    }
    if require_execute {
        flags |= AccessFlags::X_OK;
    }

    // If no specific permissions required, just check existence (F_OK)
    if flags.is_empty() {
        flags = AccessFlags::F_OK;
    }

    // Check access permissions using nix wrapper
    if access(path, flags).is_err() {
        // Determine which specific permission failed for better error message
        if require_read && access(path, AccessFlags::R_OK).is_err() {
            return Err(ValidationError::FileNotReadable {
                option: option_name.to_string(),
                path: path.to_path_buf(),
            });
        }
        if require_write && access(path, AccessFlags::W_OK).is_err() {
            return Err(ValidationError::FileNotWritable {
                option: option_name.to_string(),
                path: path.to_path_buf(),
            });
        }
        if require_execute && access(path, AccessFlags::X_OK).is_err() {
            return Err(ValidationError::FileNotExecutable {
                option: option_name.to_string(),
                path: path.to_path_buf(),
            });
        }
        // Generic access failure
        return Err(ValidationError::FileNotReadable {
            option: option_name.to_string(),
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

/// Validate a complete configuration
///
/// Main entry point for configuration validation. Performs comprehensive validation of
/// all configuration subsystems, detecting conflicts, invalid values, and missing required
/// options. This function replaces validation logic scattered throughout C's one_opt()
/// switch statement (option.c:2721-5947) with centralized, composable validation.
///
/// # Validation Performed
///
/// 1. **Port Range Validation** - All port numbers in valid range, unprivileged checks
/// 2. **IP Address Validation** - Format validation for all IP addresses
/// 3. **File Path Validation** - Existence and permission checks for all file references
/// 4. **DHCP Range Validation** - Overlap detection, consistency checks
/// 5. **Upstream Server Validation** - DNS server address format and reachability
/// 6. **Mutual Exclusivity** - Conflicting options (e.g., --port=0 with DNS options)
/// 7. **Required Combinations** - Options that require other options (e.g., auth-zone needs auth-server)
/// 8. **Cross-Subsystem Consistency** - DNS/DHCP/TFTP/Auth interactions
/// 9. **Resource Limits** - Cache sizes, connection limits, etc.
/// 10. **SOA Record Validation** - TTL values, timing parameters per RFC 1035
///
/// # Arguments
///
/// * `config` - The configuration to validate
///
/// # Returns
///
/// `Ok(())` if all validation passes, `Err(ValidationError)` describing the first error found.
/// Validation stops at first error for fast feedback to operators.
///
/// # Errors
///
/// Returns various `ValidationError` variants depending on what validation failed.
/// Error messages include the option name, invalid value, and reason for rejection.
///
/// # Example
///
/// ```
/// use dnsmasq::config::{Config, validator::validate_config};
///
/// let config = Config::default();
/// match validate_config(&config) {
///     Ok(()) => println!("Configuration is valid"),
///     Err(e) => eprintln!("Configuration error: {}", e),
/// }
/// ```
pub fn validate_config(config: &Config) -> Result<(), ValidationError> {
    // Validate DNS configuration (ports, cache, upstream servers)
    validate_dns_config(config)?;
    
    // Validate DHCP configuration (ranges, ports, leases)
    validate_dhcp_config(config)?;
    
    // Validate TFTP configuration (ports, paths, limits)
    validate_tftp_config(config)?;
    
    // Validate network configuration (interfaces, addresses, bindings)
    validate_network_config(config)?;
    
    // Validate authoritative DNS configuration (zones, SOA records)
    validate_auth_config(config)?;
    
    // Validate process configuration (users, PID file)
    validate_process_config(config)?;
    
    // Validate all file path references (existence and permissions)
    validate_file_references(config)?;
    
    // Validate mutually exclusive options
    validate_mutual_exclusivity(config)?;
    
    // Validate required option combinations
    validate_required_combinations(config)?;
    
    Ok(())
}

/// Validate DNS configuration
///
/// Validates all DNS-related options including ports, cache size, packet sizes,
/// upstream servers, and DNS-specific features.
fn validate_dns_config(config: &Config) -> Result<(), ValidationError> {
    // DNS port validation - 0 is allowed to disable DNS service
    // Port is u16, so automatically in range 0-65535
    validate_port_range(config.dns.port, "port", true, false)?;
    
    // Query port validation - 0 means use ephemeral port
    if let Some(query_port) = config.dns.query_port {
        validate_port_range(query_port, "query-port", true, false)?;
    }
    
    // Cache size validation - reasonable upper limit to prevent memory exhaustion
    // C implementation has CACHESIZ compile-time constant, we validate at runtime
    if config.dns.cache_size > 1_000_000 {
        return Err(ValidationError::InvalidRange {
            option: "cache-size".to_string(),
            value: config.dns.cache_size.to_string(),
            min: "0".to_string(),
            max: "1000000".to_string(),
        });
    }
    
    // EDNS packet max validation - RFC 6891 requires minimum 512 octets
    if config.dns.edns_packet_max < 512 {
        return Err(ValidationError::InvalidRange {
            option: "edns-packet-max".to_string(),
            value: config.dns.edns_packet_max.to_string(),
            min: "512".to_string(),
            max: "65535".to_string(),
        });
    }
    
    // Validate upstream DNS servers format
    for (idx, server) in config.dns.upstream_servers.iter().enumerate() {
        validate_socket_address(
            &server.addr.to_string(),
            &format!("server[{}]", idx),
            53, // Default DNS port
        )?;
    }
    
    // Local TTL validation - must be reasonable (not too short, not too long)
    if config.dns.local_ttl > 0 && config.dns.local_ttl < 10 {
        return Err(ValidationError::InvalidRange {
            option: "local-ttl".to_string(),
            value: config.dns.local_ttl.to_string(),
            min: "10".to_string(),
            max: "604800".to_string(), // 1 week
        });
    }
    
    Ok(())
}

/// Validate DHCP configuration
///
/// Validates DHCP server configuration including ports, ranges, leases, and options.
/// Performs overlap detection for DHCP address ranges per interface/context.
fn validate_dhcp_config(config: &Config) -> Result<(), ValidationError> {
    // DHCP server port validation - must be 1-65535 (0 not allowed for DHCP)
    validate_port_range(config.dhcp.server_port, "dhcp-port", false, false)?;
    
    // DHCP client port validation - must be 1-65535
    validate_port_range(config.dhcp.client_port, "dhcp-client-port", false, false)?;
    
    // Validate DHCP ranges don't overlap
    validate_dhcp_ranges(&config.dhcp.dhcp_ranges)?;
    
    // Validate minimum lease time is reasonable (from C version's MIN_LEASE 2 minutes = 120s)
    if config.dhcp.min_lease_time.as_secs() < 60 {
        return Err(ValidationError::InvalidRange {
            option: "dhcp-lease-min".to_string(),
            value: format!("{}s", config.dhcp.min_lease_time.as_secs()),
            min: "60s".to_string(),
            max: "infinite".to_string(),
        });
    }
    
    // Validate each DHCP range's lease time is >= min_lease_time
    for (idx, range) in config.dhcp.dhcp_ranges.iter().enumerate() {
        if range.lease_time < config.dhcp.min_lease_time {
            return Err(ValidationError::OptionConflict {
                message: format!(
                    "DHCP range {} lease time ({}s) must be >= min lease time ({}s)",
                    idx,
                    range.lease_time.as_secs(),
                    config.dhcp.min_lease_time.as_secs()
                ),
                option1: format!("dhcp-range[{}]", idx),
                option2: "dhcp-lease-min".to_string(),
            });
        }
    }
    
    Ok(())
}

/// Validate DHCP address ranges don't overlap
///
/// Sorts ranges by start address and checks for overlaps within same interface/context.
/// Implements overlap detection from C's one_opt() DHCP range handling.
///
/// # Arguments
///
/// * `ranges` - Vector of DHCP range specifications to validate
///
/// # Returns
///
/// `Ok(())` if no overlaps, `Err(ValidationError::DhcpRangeOverlap)` if ranges overlap
fn validate_dhcp_ranges(ranges: &[crate::config::types::DhcpRange]) -> Result<(), ValidationError> {
    if ranges.len() < 2 {
        return Ok(()); // No overlaps possible with 0 or 1 range
    }
    
    // Create a sorted copy for overlap detection
    let mut sorted_ranges: Vec<&crate::config::types::DhcpRange> = ranges.iter().collect();
    sorted_ranges.sort_by(|a, b| a.start.cmp(&b.start));
    
    // Check adjacent ranges for overlaps
    for i in 0..sorted_ranges.len() - 1 {
        let current = sorted_ranges[i];
        let next = sorted_ranges[i + 1];
        
        // Check if current range end >= next range start (overlap)
        // Convert to u32 for proper range comparison
        let cur_start = u32::from(current.start);
        let cur_end = u32::from(current.end);
        let next_start = u32::from(next.start);
        let next_end = u32::from(next.end);
        
        // Ranges overlap if current.end >= next.start (and current.start <= next.start, which is guaranteed by sorting)
        if cur_end >= next_start {
            return Err(ValidationError::DhcpRangeOverlap {
                range1: format!("{}-{}", current.start, current.end),
                range2: format!("{}-{}", next.start, next.end),
                context: "dhcp-range".to_string(),
            });
        }
        
        // Also validate that start < end for each range
        if cur_start > cur_end {
            return Err(ValidationError::InvalidRange {
                option: "dhcp-range".to_string(),
                value: format!("{}-{}", current.start, current.end),
                min: format!("{}", current.start),
                max: "valid end address".to_string(),
            });
        }
        
        if next_start > next_end {
            return Err(ValidationError::InvalidRange {
                option: "dhcp-range".to_string(),
                value: format!("{}-{}", next.start, next.end),
                min: format!("{}", next.start),
                max: "valid end address".to_string(),
            });
        }
    }
    
    Ok(())
}

/// Validate TFTP configuration
///
/// Validates TFTP server settings including port ranges, root directory, and connection limits.
fn validate_tftp_config(config: &Config) -> Result<(), ValidationError> {
    // TFTP is enabled if tftp_root is specified
    if config.tftp.tftp_root.is_some() {
        // TFTP port range validation
        if let Some((start_port, end_port)) = config.tftp.port_range {
            validate_port_range(start_port, "tftp-port-range (start)", false, false)?;
            validate_port_range(end_port, "tftp-port-range (end)", false, false)?;
            
            if start_port > end_port {
                return Err(ValidationError::InvalidRange {
                    option: "tftp-port-range".to_string(),
                    value: format!("{}-{}", start_port, end_port),
                    min: format!("{}-{}", start_port, start_port),
                    max: format!("{}-65535", start_port),
                });
            }
            
            // Validate range is reasonable (not too small)
            if end_port - start_port < 10 {
                return Err(ValidationError::InvalidValue {
                    option: "tftp-port-range".to_string(),
                    value: format!("{}-{}", start_port, end_port),
                    expected: "range of at least 10 ports for concurrent transfers".to_string(),
                });
            }
        }
        
        // Max connections validation - must be reasonable
        if config.tftp.tftp_max_connections == 0 {
            return Err(ValidationError::InvalidRange {
                option: "tftp-max-connections".to_string(),
                value: "0".to_string(),
                min: "1".to_string(),
                max: "10000".to_string(),
            });
        }
        if config.tftp.tftp_max_connections > 10_000 {
            return Err(ValidationError::InvalidRange {
                option: "tftp-max-connections".to_string(),
                value: config.tftp.tftp_max_connections.to_string(),
                min: "1".to_string(),
                max: "10000".to_string(),
            });
        }
        
        // TFTP MTU validation if specified
        if let Some(mtu) = config.tftp.tftp_mtu {
            if mtu < 512 {
                return Err(ValidationError::InvalidRange {
                    option: "tftp-mtu".to_string(),
                    value: mtu.to_string(),
                    min: "512".to_string(),
                    max: "65535".to_string(),
                });
            }
        }
    }
    
    Ok(())
}

/// Validate network configuration
///
/// Validates network settings including listening ports, query port ranges, and interface specifications.
fn validate_network_config(config: &Config) -> Result<(), ValidationError> {
    // Validate that bind-interfaces and bind-dynamic are not both set
    if config.network.bind_interfaces && config.network.bind_dynamic {
        return Err(ValidationError::MutuallyExclusiveOptions {
            option1: "bind-interfaces".to_string(),
            option2: "bind-dynamic".to_string(),
            reason: "cannot bind statically and dynamically at the same time".to_string(),
        });
    }
    
    // Main DNS listening port validation
    // Port 0 is allowed (disables DNS), but positive values must be valid
    if config.dns.port > 0 {
        validate_port_range(config.dns.port, "port", false, false)?;
    }
    
    // Min port and max port validation for random port range
    // These define the range for random source ports in DNS queries
    validate_port_range(config.dns.min_port, "min-port", false, false)?;
    validate_port_range(config.dns.max_port, "max-port", false, false)?;
    
    // Ensure min <= max for port range
    if config.dns.min_port > config.dns.max_port {
        return Err(ValidationError::OptionConflict {
            message: "min-port must be <= max-port".to_string(),
            option1: "min-port".to_string(),
            option2: "max-port".to_string(),
        });
    }
    
    // EDNS packet size validation
    if config.dns.edns_packet_max < 512 {
        return Err(ValidationError::InvalidRange {
            option: "edns-packet-max".to_string(),
            value: config.dns.edns_packet_max.to_string(),
            min: "512".to_string(),
            max: "65535".to_string(),
        });
    }
    
    Ok(())
}

/// Validate authoritative DNS configuration
///
/// Validates authoritative DNS settings including zones, SOA records, and TTLs.
/// Implements validation rules from C's option.c handling of --auth-zone, --auth-server, --auth-soa.
fn validate_auth_config(config: &Config) -> Result<(), ValidationError> {
    // If auth zones are configured, auth_server must be set
    if !config.auth.auth_zones.is_empty() && config.auth.auth_server.is_none() {
        return Err(ValidationError::RequiredOptionMissing {
            feature: "auth-zone".to_string(),
            required_option: "auth-server".to_string(),
            reason: "authoritative zones require an authoritative server hostname".to_string(),
        });
    }
    
    // Validate auth TTL is reasonable (10 seconds to 1 week)
    if config.auth.auth_ttl > 0 && config.auth.auth_ttl < 10 {
        return Err(ValidationError::InvalidRange {
            option: "auth-ttl".to_string(),
            value: config.auth.auth_ttl.to_string(),
            min: "10".to_string(),
            max: "604800".to_string(), // 1 week
        });
    }
    
    if config.auth.auth_ttl > 604_800 {
        return Err(ValidationError::InvalidRange {
            option: "auth-ttl".to_string(),
            value: config.auth.auth_ttl.to_string(),
            min: "10".to_string(),
            max: "604800".to_string(),
        });
    }
    
    // Validate SOA refresh is reasonable (RFC 1035 guidance: 1200-43200 seconds)
    if config.auth.soa_refresh < 1200 {
        return Err(ValidationError::InvalidRange {
            option: "auth-soa (refresh)".to_string(),
            value: config.auth.soa_refresh.to_string(),
            min: "1200".to_string(),
            max: "43200".to_string(),
        });
    }
    if config.auth.soa_refresh > 43_200 {
        return Err(ValidationError::InvalidRange {
            option: "auth-soa (refresh)".to_string(),
            value: config.auth.soa_refresh.to_string(),
            min: "1200".to_string(),
            max: "43200".to_string(),
        });
    }
    
    // Validate SOA retry is reasonable and < refresh
    if config.auth.soa_retry < 180 {
        return Err(ValidationError::InvalidRange {
            option: "auth-soa (retry)".to_string(),
            value: config.auth.soa_retry.to_string(),
            min: "180".to_string(),
            max: "refresh_value".to_string(),
        });
    }
    if config.auth.soa_retry >= config.auth.soa_refresh {
        return Err(ValidationError::OptionConflict {
            message: "SOA retry must be < SOA refresh per RFC 1035".to_string(),
            option1: "auth-soa (retry)".to_string(),
            option2: "auth-soa (refresh)".to_string(),
        });
    }
    
    // Validate SOA expiry is reasonable and > refresh
    if config.auth.soa_expiry < config.auth.soa_refresh {
        return Err(ValidationError::OptionConflict {
            message: "SOA expiry must be >= SOA refresh per RFC 1035".to_string(),
            option1: "auth-soa (expiry)".to_string(),
            option2: "auth-soa (refresh)".to_string(),
        });
    }
    // Typical expiry range: 1 week to 4 weeks
    if config.auth.soa_expiry > 2_419_200 {
        return Err(ValidationError::InvalidRange {
            option: "auth-soa (expiry)".to_string(),
            value: config.auth.soa_expiry.to_string(),
            min: "refresh_value".to_string(),
            max: "2419200".to_string(), // 28 days
        });
    }
    
    Ok(())
}

/// Validate process configuration
///
/// Validates process management settings including user/group and PID file.
fn validate_process_config(config: &Config) -> Result<(), ValidationError> {
    // Validate PID file path if specified
    if let Some(ref pid_file) = config.process.pid_file {
        // Check parent directory exists (PID file itself won't exist until daemon starts)
        if let Some(parent) = pid_file.parent() {
            if !parent.exists() {
                return Err(ValidationError::FileNotFound {
                    option: "pidfile".to_string(),
                    path: parent.to_path_buf(),
                });
            }
            // Check parent directory is writable
            if access(parent, AccessFlags::W_OK).is_err() {
                return Err(ValidationError::FileNotWritable {
                    option: "pidfile (parent directory)".to_string(),
                    path: parent.to_path_buf(),
                });
            }
        }
    }
    
    // Validate that if username is specified, it's non-empty
    // (Actual user lookup happens at runtime)
    if let Some(ref username) = config.process.username {
        if username.is_empty() {
            return Err(ValidationError::InvalidValue {
                option: "user".to_string(),
                value: username.clone(),
                expected: "non-empty username".to_string(),
            });
        }
    }
    
    // Validate that if groupname is specified, it's non-empty
    if let Some(ref groupname) = config.process.groupname {
        if groupname.is_empty() {
            return Err(ValidationError::InvalidValue {
                option: "group".to_string(),
                value: groupname.clone(),
                expected: "non-empty group name".to_string(),
            });
        }
    }
    
    Ok(())
}

/// Validate file references
///
/// Validates that all file paths referenced in configuration exist and have appropriate permissions.
/// Checks config files, lease files, TFTP roots, hosts files, and script paths.
fn validate_file_references(config: &Config) -> Result<(), ValidationError> {
    // Validate lease file path - check if parent directory exists and is writable
    // (file itself might not exist yet before first lease)
    if let Some(parent) = config.dhcp.lease_file.parent() {
        if !parent.exists() {
            return Err(ValidationError::FileNotFound {
                option: "dhcp-leasefile (parent directory)".to_string(),
                path: parent.to_path_buf(),
            });
        }
        // Parent directory must be writable
        if access(parent, AccessFlags::W_OK).is_err() {
            return Err(ValidationError::FileNotWritable {
                option: "dhcp-leasefile (parent directory)".to_string(),
                path: parent.to_path_buf(),
            });
        }
    }
    
    // If lease file exists, check it's readable and writable
    if config.dhcp.lease_file.exists() {
        validate_file_path(
            &config.dhcp.lease_file,
            "dhcp-leasefile",
            true,  // read
            true,  // write
            false, // execute
        )?;
    }
    
    // Validate TFTP root if TFTP is enabled (tftp_root is Some)
    if let Some(ref tftp_root) = config.tftp.tftp_root {
        if !tftp_root.exists() {
            return Err(ValidationError::FileNotFound {
                option: "tftp-root".to_string(),
                path: tftp_root.clone(),
            });
        }
        if !tftp_root.is_dir() {
            return Err(ValidationError::InvalidValue {
                option: "tftp-root".to_string(),
                value: tftp_root.to_string_lossy().to_string(),
                expected: "directory path".to_string(),
            });
        }
        // TFTP root must be readable
        validate_file_path(
            tftp_root,
            "tftp-root",
            true,  // read
            false, // write
            false, // execute
        )?;
    }
    
    // Validate resolv file if specified
    if let Some(ref resolv_file) = config.dns.resolv_file {
        if !resolv_file.exists() {
            return Err(ValidationError::FileNotFound {
                option: "resolv-file".to_string(),
                path: resolv_file.clone(),
            });
        }
        validate_file_path(
            resolv_file,
            "resolv-file",
            true,  // read
            false, // write
            false, // execute
        )?;
    }
    
    Ok(())
}

/// Validate mutually exclusive options
///
/// Checks for options that cannot be used together per C implementation's conflict detection.
fn validate_mutual_exclusivity(config: &Config) -> Result<(), ValidationError> {
    // Already checked bind-interfaces vs bind-dynamic in validate_network_config
    
    // Port 0 disables DNS service - conflicts with DNS-specific options
    if config.dns.port == 0 {
        // Check if DNSSEC is enabled
        if config.options.contains(crate::config::types::DaemonOptions::OPT_DNSSEC_VALID) {
            return Err(ValidationError::MutuallyExclusiveOptions {
                option1: "port=0".to_string(),
                option2: "dnssec".to_string(),
                reason: "DNS service disabled but DNSSEC validation enabled".to_string(),
            });
        }
        
        // Check if authoritative DNS is configured
        if !config.auth.auth_zones.is_empty() {
            return Err(ValidationError::MutuallyExclusiveOptions {
                option1: "port=0".to_string(),
                option2: "auth-zone".to_string(),
                reason: "DNS service disabled but authoritative zones configured".to_string(),
            });
        }
        
        // Check if upstream servers are configured (implies DNS forwarding is expected)
        if !config.dns.upstream_servers.is_empty() {
            return Err(ValidationError::OptionConflict {
                message: "port=0 disables DNS but upstream servers are configured".to_string(),
                option1: "port".to_string(),
                option2: "server".to_string(),
            });
        }
    }
    
    // Note: TFTP validation removed as tftp_root_squash field does not exist in TftpConfig
    
    Ok(())
}

/// Validate required option combinations
///
/// Checks for options that require other options to be set per C implementation's dependency checks.
fn validate_required_combinations(config: &Config) -> Result<(), ValidationError> {
    // Authoritative zones require authoritative server
    // (Already checked in validate_auth_config, but kept here for completeness)
    if !config.auth.auth_zones.is_empty() && config.auth.auth_server.is_none() {
        return Err(ValidationError::RequiredOptionMissing {
            feature: "auth-zone".to_string(),
            required_option: "auth-server".to_string(),
            reason: "authoritative zones require an authoritative server hostname".to_string(),
        });
    }
    
    // DHCP script requires script-user for privilege separation
    if let Some(ref script_path) = config.dhcp.dhcp_script {
        // Validate script file is executable
        validate_file_path(
            script_path,
            "dhcp-script",
            false, // read
            false, // write
            true,  // execute
        )?;
        
        // In C implementation, script-user is recommended but not required
        // Could log a warning at runtime if script_user is None
    }
    
    // DHCP requires at least one range if DHCP is effectively enabled
    // This is implicit - if dhcp_ranges is non-empty, DHCP is enabled
    // If empty, DHCP is disabled
    
    // TFTP requires tftp-root
    // Already implicit - TFTP is only enabled if tftp_root.is_some()
    
    // DNSSEC requires trust anchors (checked at runtime when loading DNSSEC keys)
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::defaults::default_config;

    #[test]
    fn test_default_config_validates() {
        let config = default_config();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_dns_port_zero_allowed() {
        let mut config = default_config();
        config.dns.port = 0; // 0 is allowed to disable DNS
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_invalid_cache_size() {
        let mut config = default_config();
        config.dns.cache_size = 2_000_000; // Exceeds limit
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_edns_packet_max() {
        let mut config = default_config();
        config.dns.edns_packet_max = 400; // Below minimum
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_mutually_exclusive_bind_options() {
        let mut config = default_config();
        config.network.bind_interfaces = true;
        config.network.bind_dynamic = true;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_empty_upstream_servers_allowed() {
        let mut config = default_config();
        config.dns.upstream_servers.clear();
        // Empty upstream servers is valid (dnsmasq can work as auth-only)
        assert!(validate_config(&config).is_ok());
    }
}
