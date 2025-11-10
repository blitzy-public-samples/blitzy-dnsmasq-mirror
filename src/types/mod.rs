// Copyright (c) 2000-2024 Simon Kelley and contributors
// Copyright (C) 2024 Blitzy - dnsmasq Rust Implementation
// Licensed under GPL-2.0-or-later

//! Foundational types and error handling for dnsmasq Rust implementation
//!
//! This module provides centralized access to the core type system that underpins
//! the entire dnsmasq Rust implementation. It serves as the primary entry point
//! for all foundational types used throughout the DNS, DHCP, TFTP, and networking
//! subsystems, replacing C's monolithic `dnsmasq.h` header with a modular, type-safe
//! Rust architecture.
//!
//! # Purpose and Scope
//!
//! The types module establishes the foundational type hierarchy for dnsmasq's
//! services, providing memory-safe alternatives to C's pointer-heavy structures
//! and union types. This module replaces approximately 4,000 lines of C type
//! definitions from `src/dnsmasq.h` with structured Rust modules that leverage
//! the compiler's type system for safety guarantees.
//!
//! # Module Organization
//!
//! The types module is organized into three core submodules, each addressing
//! a distinct category of types:
//!
//! ## 1. Error Types ([`errors`])
//!
//! Comprehensive error handling types replacing C's errno-based error propagation
//! with Rust's `Result` pattern. This submodule defines:
//!
//! - [`DnsmasqError`]: Top-level error enum wrapping all subsystem errors
//! - [`DnsmasqResult<T>`]: Type alias for `Result<T, DnsmasqError>`
//! - [`DnssecError`]: DNSSEC validation and cryptographic errors
//! - [`AuthError`]: Authoritative DNS server errors
//! - Plus subsystem-specific errors: `DnsError`, `DhcpError`, `NetworkError`,
//!   `ConfigError`, `SystemError`, `TftpError`, `LogError`
//!
//! **C Source Reference**: Replaces error handling patterns from all C modules
//! that used `errno`, return codes, and the `die()` function (especially `option.c`,
//! `forward.c`, `dhcp.c`, `dnssec.c`).
//!
//! ## 2. Address Types ([`addresses`])
//!
//! Type-safe IP address abstractions for IPv4/IPv6 dual-stack operation and
//! DNS-specific address types. This submodule provides:
//!
//! - [`AllAddr`]: Universal address container enum replacing C's `union all_addr`
//!   - Supports IPv4, IPv6, CNAME, DNSSEC keys, DS records, and SRV records
//!   - Type-safe variants prevent union access errors from C implementation
//! - IPv6 classification utilities for ULA and link-local addresses
//! - Socket address handling via `std::net::SocketAddr`
//!
//! **C Source Reference**: Replaces `union all_addr` (dnsmasq.h:303) and
//! `union mysockaddr` (dnsmasq.h:669), eliminating unsafe pointer casting
//! throughout `forward.c`, `cache.c`, `dhcp.c`, `network.c`, and `rfc1035.c`.
//!
//! ## 3. Daemon State ([`daemon_state`])
//!
//! Central state management structure for the entire dnsmasq daemon, providing
//! organized access to all runtime state:
//!
//! - [`DaemonState`]: Main daemon state replacing C's `extern struct daemon`
//!   - DNS subsystem state (cache, forward records, upstream servers)
//!   - DHCP subsystem state (leases, contexts, static configurations)
//!   - Network state (interfaces, listeners, sockets)
//!   - Configuration and metrics
//! - Builder pattern for incremental state construction with validation
//!
//! **C Source Reference**: Replaces `extern struct daemon *daemon` global
//! variable (dnsmasq.h:1099-4251) with ~150 fields, eliminating global mutable
//! state and enabling thread-safe concurrent access via `Arc<RwLock<>>`.
//!
//! # Architecture Transformation
//!
//! The C implementation uses a flat type hierarchy with extensive use of unions,
//! void pointers, and manual memory management:
//!
//! ```c
//! // C architecture (from dnsmasq.h)
//! extern struct daemon *daemon;  // Global mutable state
//!
//! union all_addr {
//!     struct in_addr addr4;
//!     struct in6_addr addr6;
//!     struct { /* cname data */ };
//!     struct { /* dnssec key */ };
//!     // ... more variants (unsafe access)
//! };
//! ```
//!
//! The Rust implementation uses enums, ownership, and the type system:
//!
//! ```rust,ignore
//! // Rust architecture (this module)
//! use dnsmasq::types::{DaemonState, AllAddr, DnsmasqResult};
//!
//! // Type-safe state management with ownership
//! let state = DaemonState::new(config)?;
//!
//! // Type-safe address handling with enum discrimination
//! let addr = AllAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));
//! match addr {
//!     AllAddr::Ipv4(ip) => { /* Handle IPv4 */ },
//!     AllAddr::Ipv6(ip) => { /* Handle IPv6 */ },
//!     _ => { /* Other variants */ },
//! }
//! ```
//!
//! # Memory Safety Guarantees
//!
//! This module eliminates all categories of memory safety issues present in
//! the C implementation through Rust's ownership system:
//!
//! - **No buffer overflows**: Slice bounds checking and capacity management
//! - **No use-after-free**: Ownership tracking and lifetime validation
//! - **No null pointer dereferences**: `Option` types replace null pointers
//! - **No type confusion**: Enum discriminants prevent union access errors
//! - **No data races**: `Send`/`Sync` traits enforce thread safety
//! - **No manual memory management**: RAII and Drop trait for cleanup
//!
//! # Usage Patterns
//!
//! ## Error Handling
//!
//! ```rust,ignore
//! use dnsmasq::types::{DnsmasqResult, DnsmasqError};
//!
//! fn process_query(data: &[u8]) -> DnsmasqResult<Response> {
//!     // Use ? operator for error propagation
//!     let query = parse_query(data)?;
//!     let response = lookup_cache(&query)?;
//!     Ok(response)
//! }
//! ```
//!
//! ## Address Handling
//!
//! ```rust,ignore
//! use dnsmasq::types::addresses::AllAddr;
//! use std::net::Ipv4Addr;
//!
//! // Type-safe address construction
//! let addr = AllAddr::from_ipv4(Ipv4Addr::new(8, 8, 8, 8));
//!
//! // Safe pattern matching on variants
//! if let AllAddr::Ipv4(ip) = addr {
//!     println!("IPv4 address: {}", ip);
//! }
//! ```
//!
//! ## State Management
//!
//! ```rust,ignore
//! use dnsmasq::types::daemon_state::{DaemonState, DaemonStateBuilder};
//! use std::sync::{Arc, RwLock};
//!
//! // Build initial state
//! let state = DaemonStateBuilder::new()
//!     .config(config)
//!     .dns_cache(cache)
//!     .build()?;
//!
//! // Share state across async tasks with thread safety
//! let shared_state = Arc::new(RwLock::new(state));
//! ```
//!
//! # Integration with Subsystems
//!
//! Every major subsystem in dnsmasq depends on types from this module:
//!
//! - **DNS subsystem** (`src/dns/`): Uses `AllAddr`, `DaemonState.dns`, `DnsError`
//! - **DHCP subsystem** (`src/dhcp/`): Uses `AllAddr`, `DaemonState.dhcp`, `DhcpError`
//! - **TFTP subsystem** (`src/tftp/`): Uses `DaemonState.network`, `TftpError`
//! - **Network layer** (`src/network/`): Uses `AllAddr`, socket types, `NetworkError`
//! - **Configuration** (`src/config/`): Uses `DaemonState`, `ConfigError`
//! - **Runtime** (`src/runtime/`): Uses `DaemonState`, `SystemError`
//!
//! # Public API
//!
//! This module re-exports commonly used types for convenient access from other
//! modules without requiring deep import paths. Public exports include:
//!
//! - **Core State**: `DaemonState` (main state structure)
//! - **Errors**: `DnsmasqError`, `DnsmasqResult`, `DnssecError`, `AuthError`
//! - **Addresses**: `AllAddr` (universal address container)
//!
//! All other types remain accessible through submodule paths for explicit usage.
//!
//! # C Source Files Replaced
//!
//! This module replaces type definitions from these C files:
//!
//! - `src/dnsmasq.h` (lines 1-4251): Primary type definitions and global state
//! - `src/ip6addr.h`: IPv6 address utilities and classification
//! - `src/config.h`: Compile-time constants now in Cargo feature flags
//!
//! # Design Patterns
//!
//! This module demonstrates several Rust design patterns:
//!
//! - **Newtype Pattern**: Wrapping standard library types for domain-specific behavior
//! - **Builder Pattern**: `DaemonStateBuilder` for validated construction
//! - **Error Chain Pattern**: `thiserror` for hierarchical error handling
//! - **Type State Pattern**: Using types to enforce valid state transitions
//!
//! # Thread Safety
//!
//! All types in this module are designed for safe concurrent access:
//!
//! - `DaemonState` can be wrapped in `Arc<RwLock<>>` for shared mutable access
//! - `AllAddr` is `Clone` for cheap copying between tasks
//! - Error types are `Send + Sync` for cross-thread error propagation
//!
//! # Performance Considerations
//!
//! - **Zero-cost abstractions**: Enum discriminants compiled to efficient matches
//! - **Inline optimization**: Small accessor functions are `#[inline]` eligible
//! - **Arc sharing**: Reference-counted sharing avoids deep copies
//! - **Cache-friendly**: Compact enum layouts minimize memory footprint
//!
//! # Testing Strategy
//!
//! Unit tests for this module verify:
//!
//! - Error type conversions and `From` trait implementations
//! - Address type construction and pattern matching
//! - State builder validation and error handling
//! - Thread safety of shared state access patterns
//!
//! # Future Extensibility
//!
//! The module structure supports future extensions:
//!
//! - Additional address variants for new protocol support
//! - New error types for additional subsystems
//! - State extensions for new features (feature-gated)
//! - Platform-specific type specializations
//!
//! # References
//!
//! - **C Source**: `src/dnsmasq.h` (primary header with all type definitions)
//! - **RFC 1035**: DNS protocol types (AllAddr DNS variants)
//! - **RFC 2131**: DHCPv4 types (AllAddr DHCP usage)
//! - **RFC 3315**: DHCPv6 types (AllAddr IPv6 usage)
//! - **RFC 4034**: DNSSEC types (AllAddr DNSSEC variants)

// Submodule declarations
// These modules contain the actual implementations of types

/// IP address types and utilities
///
/// Provides type-safe IPv4/IPv6 address handling, DNS-specific address types,
/// and IPv6 address classification utilities. Replaces C's `union all_addr`
/// and `union mysockaddr` with safe Rust enums.
///
/// See module documentation for detailed API.
pub mod addresses;

/// Main daemon state structure
///
/// Provides the central state management structure for the dnsmasq daemon,
/// replacing C's `extern struct daemon` global variable with organized,
/// type-safe state management.
///
/// See module documentation for detailed API.
pub mod daemon_state;

/// Error types and Result aliases
///
/// Comprehensive error handling types for all dnsmasq subsystems, replacing
/// C's errno-based error propagation with Rust's type-safe Result pattern.
///
/// See module documentation for detailed API.
pub mod errors;

// Public re-exports for convenient access
//
// These re-exports provide convenient access to the most commonly used types
// from the types module without requiring users to navigate deep module paths.
// Other modules can use `use crate::types::{DaemonState, DnsmasqError};`
// instead of `use crate::types::daemon_state::DaemonState;`.

/// Re-export main daemon state structure for convenient access
///
/// This is the central state container for the entire dnsmasq daemon,
/// replacing C's global `struct daemon` pointer. Access via:
///
/// ```rust,ignore
/// use crate::types::DaemonState;
/// ```
///
/// **C Source Reference**: Replaces `extern struct daemon *daemon` (dnsmasq.h:1099)
pub use daemon_state::DaemonState;

/// Re-export all error types for error handling throughout the codebase
///
/// Provides convenient access to the complete error hierarchy:
/// - `DnsmasqError`: Top-level error enum wrapping all subsystems
/// - `DnsmasqResult<T>`: Type alias for `Result<T, DnsmasqError>`
/// - `DnssecError`: DNSSEC validation errors
/// - `AuthError`: Authoritative DNS errors
/// - Plus subsystem-specific errors
///
/// **C Source Reference**: Replaces errno-based error handling from all C modules
pub use errors::{
    AuthError, ConfigError, DhcpError, DnsError, DnsmasqError, DnsmasqResult, DnssecError,
    LogError, NetworkError, SystemError, TftpError,
};

/// Re-export universal address container for DNS and DHCP operations
///
/// The `AllAddr` enum provides type-safe storage for IPv4, IPv6, CNAME,
/// DNSSEC keys, DS records, and SRV records. Access commonly used variants
/// and constructors:
/// - `AllAddr::Ipv4`: IPv4 address variant
/// - `AllAddr::Ipv6`: IPv6 address variant  
/// - `AllAddr::from_ipv4()`: Construct from IPv4 address
/// - `AllAddr::from_ipv6()`: Construct from IPv6 address
///
/// **C Source Reference**: Replaces `union all_addr` (dnsmasq.h:303)
///
/// # Examples
///
/// ```rust,ignore
/// use crate::types::AllAddr;
/// use std::net::Ipv4Addr;
///
/// let addr = AllAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));
/// match addr {
///     AllAddr::Ipv4(ip) => println!("IPv4: {}", ip),
///     AllAddr::Ipv6(ip) => println!("IPv6: {}", ip),
///     _ => println!("Other address type"),
/// }
/// ```
pub use addresses::AllAddr;
