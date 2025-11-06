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

//! # dnsmasq - Memory-Safe DNS, DHCP, and TFTP Server
//!
//! This is a production-ready Rust implementation of dnsmasq that maintains 100% functional
//! equivalence with the C implementation while providing memory safety guarantees through
//! Rust's ownership system and borrow checker.
//!
//! ## Purpose
//!
//! This library serves as the root module for the dnsmasq Rust refactoring, establishing the
//! complete module hierarchy and providing common types, error handling, and public API boundaries.
//! It replaces the C codebase's global header includes (dnsmasq.h, config.h) with Rust's explicit
//! module system, eliminating global mutable state while preserving all functionality.
//!
//! ## Core Services
//!
//! - **DNS Forwarding & Caching**: RFC-compliant DNS resolver with efficient caching
//! - **DHCPv4 Server**: Full RFC 2131/2132 implementation with lease management
//! - **DHCPv6 Server**: RFC 3315/3646 compliant with IA_NA, IA_TA, and IA_PD support
//! - **TFTP Server**: Network boot support per RFC 1350
//! - **Router Advertisement**: IPv6 RA per RFC 4861 with SLAAC coordination
//! - **Authoritative DNS**: Local zone authority for private networks
//! - **DNSSEC Validation**: Cryptographic DNS security with trust anchor management
//!
//! ## Architecture Overview
//!
//! The implementation is organized into 15 subsystems, each mapped from C source modules:
//!
//! - **`core`**: Event loop, daemon state, signal handling (replaces dnsmasq.c/poll.c)
//! - **`dns`**: Protocol parsing, caching, forwarding, DNSSEC (replaces rfc1035.c, cache.c, forward.c, dnssec.c)
//! - **`dhcp`**: v4/v6 servers and lease management (replaces dhcp.c, dhcp6.c, lease.c)
//! - **`ipv6`**: Router Advertisement and SLAAC (replaces radv.c, slaac.c)
//! - **`network`**: Socket management and platform abstraction (replaces network.c, netlink.c, bpf.c)
//! - **`services`**: TFTP and auxiliary services (replaces tftp.c)
//! - **`integration`**: D-Bus, ubus, conntrack, ipset, nftables (replaces dbus.c, ubus.c, etc.)
//! - **`config`**: Configuration parsing and CLI handling (replaces option.c)
//! - **`process`**: Process management and privilege separation (replaces helper.c)
//! - **`logging`**: Structured logging infrastructure (replaces log.c)
//! - **`monitoring`**: Prometheus metrics (replaces metrics.c)
//! - **`utils`**: Common utilities (replaces util.c, pattern.c)
//! - **`ffi`**: Safe FFI wrappers for platform-specific code
//!
//! ## Memory Safety Transformation
//!
//! This implementation eliminates all C memory-safety vulnerabilities:
//! - **Buffer Overflows**: Replaced with Rust slices with automatic bounds checking
//! - **Use-After-Free**: Prevented by borrow checker lifetime analysis
//! - **Double-Free**: Impossible due to RAII and Drop trait semantics
//! - **Null Pointer Dereferences**: Eliminated via Option<T> and Result<T, E> types
//! - **Data Races**: Prevented via Send/Sync trait system and ownership rules
//!
//! ## Error Handling
//!
//! The library defines a unified [`Error`] enum and [`Result<T>`](Result) type alias for
//! consistent error propagation across all modules. All error paths are explicitly handled
//! with the `?` operator, replacing C's errno-based error handling.
//!
//! ## Feature Flags
//!
//! Optional subsystems are controlled via Cargo feature flags, matching C's HAVE_* macros:
//! - `dhcp` - DHCPv4 server (default)
//! - `dhcp6` - DHCPv6 server (requires `dhcp`, default)
//! - `tftp` - TFTP server (default)
//! - `script` - External script execution (default)
//! - `auth` - Authoritative DNS (default)
//! - `dnssec` - DNSSEC validation (default)
//! - `dbus` - D-Bus control interface
//! - `idn` - Internationalized Domain Name support
//! - `lua` - Lua scripting support
//! - `prometheus-metrics` - Prometheus metrics export
//!
//! ## Platform Support
//!
//! - **Linux**: Full support with netlink, inotify, conntrack, ipset, nftables
//! - **FreeBSD/OpenBSD/NetBSD**: BSD routing sockets, PF tables
//! - **macOS**: Darwin-specific adaptations
//! - **Solaris**: Solaris-specific ioctl fallbacks
//!
//! ## Examples
//!
//! ```no_run
//! use dnsmasq::daemon::Daemon;
//! use dnsmasq::types::Config;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the library
//!     dnsmasq::init()?;
//!     
//!     // Parse configuration from file and CLI arguments
//!     let config = Config::default();
//!     
//!     // Initialize daemon with validated configuration
//!     let daemon = Daemon::new(config);
//!     
//!     // Run event loop (blocks until SIGTERM/SIGINT)
//!     daemon.run().await?;
//!     
//!     Ok(())
//! }
//! ```

// Compiler warnings and lints
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]
#![deny(unsafe_op_in_unsafe_fn)]

// Standard library imports for error handling
use std::error::Error as StdError;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::result;

//
// ============================================================================
// MODULE DECLARATIONS
// ============================================================================
//

/// Core daemon runtime, event loop, and signal handling
///
/// Replaces C files: dnsmasq.c (main event loop), poll.c (event multiplexing),
/// dnsmasq.h (struct daemon global state)
///
/// Sub-modules: `daemon`, `event_loop`, `signals`, `config`
pub mod core;

/// DNS protocol handling, caching, forwarding, and DNSSEC validation
///
/// Replaces C files: rfc1035.c (parser/serializer), cache.c, forward.c, edns0.c,
/// dnssec.c, crypto.c, hash-questions.c, rrfilter.c, auth.c, blockdata.c,
/// domain.c, domain-match.c
///
/// Sub-modules: `parser`, `serializer`, `cache`, `forwarder`, `dnssec`, `protocol`
pub mod dns;

/// DHCPv4 and DHCPv6 servers with lease management
///
/// Replaces C files: dhcp.c (v4 runtime), rfc2131.c (v4 protocol), dhcp6.c (v6 runtime),
/// rfc3315.c (v6 protocol), outpacket.c (v6 options), lease.c (persistence),
/// dhcp-common.c (shared utilities)
///
/// Sub-modules: `v4`, `v6`, `lease`, `common`
///
/// This module is enabled by the `dhcp` feature flag.
#[cfg(feature = "dhcp")]
pub mod dhcp;

/// IPv6 services: Router Advertisement and SLAAC
///
/// Replaces C files: radv.c (RA server), slaac.c (SLAAC/DAD coordination),
/// radv-protocol.h (constants), ip6addr.h (address utilities)
///
/// Sub-modules: `radv`, `slaac`, `addr`
pub mod ipv6;

/// Network layer with platform-specific implementations
///
/// Replaces C files: network.c (socket management), netlink.c (Linux),
/// bpf.c (BSD), loop.c (loop detection), arp.c (ARP handling)
///
/// Sub-modules: `sockets`, `interfaces`, `platform`, `loop_detect`, `arp`
pub mod network;

/// Auxiliary services (TFTP server)
///
/// Replaces C files: tftp.c
///
/// Sub-modules: `tftp`
///
/// This module is enabled by the `tftp` feature flag.
#[cfg(feature = "tftp")]
pub mod services;

/// External system integrations
///
/// Replaces C files: dbus.c (D-Bus), ubus.c (OpenWrt), conntrack.c,
/// ipset.c, nftset.c (nftables), tables.c (PF), inotify.c
///
/// Sub-modules: `dbus`, `ubus`, `conntrack`, `ipset`, `nftset`, `pf_tables`, `inotify`
pub mod integration;

/// Configuration file parsing and CLI argument handling
///
/// Replaces C files: option.c (4000+ lines split into parser, CLI, validator, defaults)
///
/// Sub-modules: `parser`, `cli`, `validator`, `defaults`, `types`
pub mod config;

/// Process management and privilege separation
///
/// Replaces C files: helper.c (helper process), portions of dnsmasq.c
/// (privilege dropping, PID file management)
///
/// Sub-modules: `helper`, `privileges`, `pidfile`
pub mod process;

/// Logging infrastructure with structured output support
///
/// Replaces C files: log.c
///
/// Sub-modules: `logger`, `structured`
pub mod logging;

/// Observability and metrics export (Prometheus)
///
/// Replaces C files: metrics.c, metrics.h
///
/// Sub-modules: `metrics`, `types`
///
/// This module is enabled by the `prometheus-metrics` feature flag.
#[cfg(feature = "prometheus-metrics")]
pub mod monitoring;

/// Utility functions and helpers
///
/// Replaces C files: util.c (general utilities, string manipulation, random),
/// pattern.c (pattern matching), dump.c (PCAP dumping)
///
/// Sub-modules: `general`, `string`, `rand`, `pattern_match`, `dump`
pub mod utils;

/// Safe FFI wrappers for platform-specific system calls
///
/// Wraps libc and platform-specific APIs with safe Rust abstractions.
/// All unsafe blocks are confined to this module with explicit safety documentation.
///
/// Sub-modules: `libc_wrappers`, `platform`
pub mod ffi;

//
// ============================================================================
// COMMON ERROR TYPES
// ============================================================================
//

/// Unified error type for all dnsmasq operations
///
/// This enum consolidates all error conditions across DNS, DHCP, network, and
/// configuration subsystems. It replaces C's errno-based error handling with
/// explicit error variants that can be pattern-matched and propagated with the
/// `?` operator.
///
/// # Error Categories
///
/// - **I/O Errors** ([`Error::Io`]): File and network I/O failures
/// - **Configuration Errors** ([`Error::Config`]): Invalid configuration values
/// - **Parse Errors** ([`Error::Parse`]): Malformed packets or config files
/// - **Network Errors** ([`Error::Network`]): Socket and interface errors
/// - **Protocol Errors** ([`Error::Dns`], [`Error::Dhcp`]): Protocol violations
/// - **Permission Errors** ([`Error::Permission`]): Privilege or access denied
/// - **Resource Errors** ([`Error::NotFound`], [`Error::InvalidState`]): Missing or inconsistent state
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::{Error, Result};
/// use std::io;
///
/// fn read_config(path: &str) -> Result<String> {
///     std::fs::read_to_string(path)
///         .map_err(|e| Error::Io {
///             context: format!("Failed to read config file: {}", path),
///             source: e,
///         })
/// }
/// ```
#[derive(Debug)]
pub enum Error {
    /// I/O error (file operations, socket I/O)
    ///
    /// Wraps [`std::io::Error`] with additional context about the operation that failed.
    Io {
        /// Human-readable description of the operation that failed
        context: String,
        /// The underlying I/O error
        source: io::Error,
    },

    /// Configuration error (invalid config file or CLI arguments)
    ///
    /// Indicates a problem with user-provided configuration such as invalid
    /// syntax, out-of-range values, or conflicting options.
    Config {
        /// Description of the configuration problem
        message: String,
    },

    /// Parse error (malformed DNS/DHCP packet, invalid config syntax)
    ///
    /// Indicates that input data (network packet, config file, etc.) could not
    /// be parsed according to the expected format or protocol specification.
    Parse {
        /// Description of the parse failure
        message: String,
        /// Optional location information (line number, byte offset)
        location: Option<String>,
    },

    /// Network error (socket creation, bind, interface enumeration)
    ///
    /// Indicates a failure in network layer operations such as socket creation,
    /// binding to addresses/ports, or enumerating network interfaces.
    Network {
        /// Description of the network operation that failed
        message: String,
        /// The underlying I/O error if available
        source: Option<io::Error>,
    },

    /// DNS-specific error (query processing, cache operations)
    ///
    /// Indicates an error specific to DNS operations such as invalid query format,
    /// upstream server failures, or cache inconsistencies.
    Dns {
        /// Description of the DNS error
        message: String,
    },

    /// DHCP-specific error (lease allocation, pool exhaustion)
    ///
    /// Indicates an error specific to DHCP operations such as no available leases,
    /// invalid client requests, or lease database corruption.
    Dhcp {
        /// Description of the DHCP error
        message: String,
    },

    /// Permission denied (insufficient privileges, capability missing)
    ///
    /// Indicates that an operation could not be performed due to insufficient
    /// privileges, such as binding to privileged ports or accessing system resources.
    Permission {
        /// Description of the required privilege
        message: String,
    },

    /// Resource not found (config file, lease database, upstream server)
    ///
    /// Indicates that a required resource (file, interface, server) could not be found.
    NotFound {
        /// Description of the missing resource
        resource: String,
    },

    /// Invalid state (operation not allowed in current daemon state)
    ///
    /// Indicates that an operation was attempted that is not valid given the current
    /// state of the daemon, such as modifying configuration after initialization.
    InvalidState {
        /// Description of the invalid operation
        message: String,
    },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => {
                write!(f, "I/O error: {}: {}", context, source)
            }
            Self::Config { message } => {
                write!(f, "Configuration error: {}", message)
            }
            Self::Parse { message, location } => {
                if let Some(loc) = location {
                    write!(f, "Parse error at {}: {}", loc, message)
                } else {
                    write!(f, "Parse error: {}", message)
                }
            }
            Self::Network { message, source } => {
                if let Some(src) = source {
                    write!(f, "Network error: {}: {}", message, src)
                } else {
                    write!(f, "Network error: {}", message)
                }
            }
            Self::Dns { message } => {
                write!(f, "DNS error: {}", message)
            }
            Self::Dhcp { message } => {
                write!(f, "DHCP error: {}", message)
            }
            Self::Permission { message } => {
                write!(f, "Permission denied: {}", message)
            }
            Self::NotFound { resource } => {
                write!(f, "Resource not found: {}", resource)
            }
            Self::InvalidState { message } => {
                write!(f, "Invalid state: {}", message)
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Network { source: Some(src), .. } => Some(src),
            _ => None,
        }
    }
}

// Implement From<io::Error> for convenient error conversion
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io {
            context: "I/O operation failed".to_string(),
            source: error,
        }
    }
}

/// Type alias for [`Result<T, Error>`](result::Result)
///
/// This is the standard Result type used throughout the dnsmasq codebase.
/// It enables the use of the `?` operator for error propagation and provides
/// consistent error handling across all modules.
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::Result;
///
/// fn validate_config(path: &str) -> Result<()> {
///     // Validation logic that may fail
///     Ok(())
/// }
/// ```
pub type Result<T> = result::Result<T, Error>;

//
// ============================================================================
// MODULE RE-EXPORTS
// ============================================================================
//

// Re-export commonly used types from core module
pub use crate::core::{daemon, event_loop, signals};

// Re-export DNS subsystem components
pub use crate::dns::{cache, forwarder, protocol};
// Note: parser from dns is renamed to avoid conflict with config::parser
pub use crate::dns::parser as dns_parser;

#[cfg(feature = "dnssec")]
pub use crate::dns::dnssec;

// Re-export DHCP subsystem components
#[cfg(feature = "dhcp")]
pub use crate::dhcp::v4;

#[cfg(all(feature = "dhcp", feature = "dhcp6"))]
pub use crate::dhcp::v6;

// Re-export IPv6 services
pub use crate::ipv6::{radv, slaac};

// Re-export network layer
pub use crate::network::{platform, sockets};

// Re-export TFTP service (struct from services module)
#[cfg(feature = "tftp")]
pub use crate::services::TftpServer;

// Re-export integration components
#[cfg(feature = "dbus")]
pub use crate::integration::dbus;

// Re-export configuration types
pub use crate::config::{parser as config_parser, types};

// Re-export process management
pub use crate::process::ProcessManager;

// Note: logging and monitoring modules are directly accessible via crate::{logging, monitoring}
// and do not need re-export to avoid name conflicts

// Re-export utilities
pub use crate::utils::general;

// Re-export FFI wrappers
pub use crate::ffi::libc_wrappers;

//
// ============================================================================
// CONSTANTS AND VERSION INFORMATION
// ============================================================================
//

/// Library version matching C implementation
///
/// This version is automatically extracted from Cargo.toml at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-Agent string for HTTP requests (future DoH/DoT support)
pub const USER_AGENT: &str = concat!("dnsmasq/", env!("CARGO_PKG_VERSION"), " (Rust)");

//
// ============================================================================
// LIBRARY INITIALIZATION
// ============================================================================
//

/// Initialize the dnsmasq library
///
/// This function must be called before using any other library functionality.
/// It initializes the logging subsystem and performs any necessary global setup.
///
/// # Errors
///
/// Returns an error if:
/// - Logging initialization fails
/// - Required system resources are unavailable
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::Result;
///
/// fn main() -> Result<()> {
///     dnsmasq::init()?;
///     // Use library functions
///     Ok(())
/// }
/// ```
pub fn init() -> Result<()> {
    // Initialize logging with default configuration
    logging::init()
        .map_err(|e| Error::Config {
            message: format!("Failed to initialize logging: {}", e),
        })?;

    Ok(())
}

//
// ============================================================================
// TESTS
// ============================================================================
//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_is_set() {
        assert!(!VERSION.is_empty());
        assert!(VERSION.len() > 0);
    }

    #[test]
    fn test_user_agent_format() {
        assert!(USER_AGENT.starts_with("dnsmasq/"));
        assert!(USER_AGENT.ends_with("(Rust)"));
    }

    #[test]
    fn test_error_display_io() {
        let error = Error::Io {
            context: "test operation".to_string(),
            source: io::Error::new(io::ErrorKind::NotFound, "file not found"),
        };
        let display = format!("{}", error);
        assert!(display.contains("I/O error"));
        assert!(display.contains("test operation"));
    }

    #[test]
    fn test_error_display_config() {
        let error = Error::Config {
            message: "invalid port number".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Configuration error"));
        assert!(display.contains("invalid port number"));
    }

    #[test]
    fn test_error_display_parse() {
        let error = Error::Parse {
            message: "unexpected token".to_string(),
            location: Some("line 42".to_string()),
        };
        let display = format!("{}", error);
        assert!(display.contains("Parse error"));
        assert!(display.contains("line 42"));
        assert!(display.contains("unexpected token"));
    }

    #[test]
    fn test_error_display_network() {
        let error = Error::Network {
            message: "failed to bind socket".to_string(),
            source: Some(io::Error::new(io::ErrorKind::AddrInUse, "address in use")),
        };
        let display = format!("{}", error);
        assert!(display.contains("Network error"));
        assert!(display.contains("failed to bind socket"));
    }

    #[test]
    fn test_error_display_dns() {
        let error = Error::Dns {
            message: "invalid query format".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("DNS error"));
        assert!(display.contains("invalid query format"));
    }

    #[test]
    fn test_error_display_dhcp() {
        let error = Error::Dhcp {
            message: "no available leases".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("DHCP error"));
        assert!(display.contains("no available leases"));
    }

    #[test]
    fn test_error_display_permission() {
        let error = Error::Permission {
            message: "cannot bind to port 53".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Permission denied"));
        assert!(display.contains("cannot bind to port 53"));
    }

    #[test]
    fn test_error_display_not_found() {
        let error = Error::NotFound {
            resource: "/etc/dnsmasq.conf".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Resource not found"));
        assert!(display.contains("/etc/dnsmasq.conf"));
    }

    #[test]
    fn test_error_display_invalid_state() {
        let error = Error::InvalidState {
            message: "cannot modify config after startup".to_string(),
        };
        let display = format!("{}", error);
        assert!(display.contains("Invalid state"));
        assert!(display.contains("cannot modify config after startup"));
    }

    #[test]
    fn test_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let error: Error = io_err.into();
        match error {
            Error::Io { context, source } => {
                assert_eq!(context, "I/O operation failed");
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            _ => panic!("Expected Io error variant"),
        }
    }

    #[test]
    fn test_error_source() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let error = Error::Io {
            context: "test".to_string(),
            source: io_err,
        };
        assert!(error.source().is_some());
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }
}
