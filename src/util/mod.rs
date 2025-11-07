// Copyright (c) 2024 dnsmasq-rs Contributors
// This file is part of the dnsmasq Rust rewrite project.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

//! Utility Module - Common Helper Functions and Infrastructure
//!
//! This module provides a comprehensive collection of utility functions and infrastructure
//! used throughout the dnsmasq Rust implementation. It serves as the foundation for common
//! operations including string manipulation, time handling, structured logging, cryptographic
//! operations, pattern matching, metrics collection, and platform-specific table integration.
//!
//! # Module Organization
//!
//! The utility module is organized into several submodules, each serving a specific purpose:
//!
//! ## Core Utilities (Always Available)
//!
//! These utilities are fundamental to dnsmasq's operation and are always compiled:
//!
//! - **[`string`]** - String manipulation and DNS name operations
//!   - Hostname validation and canonicalization
//!   - DNS name encoding and comparison
//!   - Wildcard matching and subdomain checking
//!   - Socket address formatting
//!
//! - **[`time`]** - Time handling and duration management
//!   - Monotonic time sources for reliable timing
//!   - Duration formatting for human-readable output
//!   - Lease expiration checking
//!   - Timestamp and lease time types
//!
//! - **[`logging`]** - Structured logging infrastructure
//!   - Asynchronous non-blocking logging
//!   - Syslog integration
//!   - Structured logging with tracing
//!   - Log configuration and initialization
//!
//! - **[`crypto`]** - Cryptographic operations
//!   - Random number generation for DNS query IDs
//!   - Source port randomization for cache poisoning prevention
//!   - Cryptographically secure RNG initialization
//!   - Transaction ID generation
//!
//! ## Feature-Specific Utilities
//!
//! These utilities are conditionally compiled based on feature flags:
//!
//! - **[`pattern`]** (feature: `conntrack`) - DNS name pattern matching
//!   - RFC 1123 compliant DNS name validation
//!   - Glob-style wildcard pattern matching
//!   - Pattern validation for connection tracking integration
//!
//! - **[`metrics`]** (feature: `metrics`) - Prometheus metrics collection
//!   - Metrics collection and export
//!   - Prometheus-compatible text format output
//!   - HTTP endpoint integration for monitoring
//!
//! ## Platform-Specific Utilities
//!
//! These utilities are conditionally compiled for specific platforms:
//!
//! - **[`tables`]** (feature: `ipset`, platform: BSD) - BSD pf table integration
//!   - FreeBSD, OpenBSD, NetBSD Packet Filter integration
//!   - Dynamic IP address table updates based on DNS resolution
//!   - Equivalent to Linux's ipset/nftables integration
//!
//! # Source File Mapping
//!
//! This module represents the Rust translation of the following C source files:
//!
//! - `src/util.c` → `string` and `time` modules
//! - `src/log.c` → `logging` module
//! - `src/crypto.c` → `crypto` module
//! - `src/pattern.c` → `pattern` module (feature-gated)
//! - `src/metrics.c` → `metrics` module (feature-gated)
//! - `src/tables.c` → `tables` module (platform-specific)
//!
//! # Usage Patterns
//!
//! ## Direct Module Imports (Recommended)
//!
//! Import specific functions from their respective modules:
//!
//! ```rust,no_run
//! use dnsmasq::util::string::is_legal_hostname;
//! use dnsmasq::util::time::monotonic_time;
//! use dnsmasq::util::crypto::generate_dns_id;
//! use dnsmasq::util::logging::init_logging;
//! ```
//!
//! ## Convenience Re-exports
//!
//! Common utilities are re-exported at the module root for convenience:
//!
//! ```rust,no_run
//! use dnsmasq::util::{
//!     is_legal_hostname,
//!     monotonic_time,
//!     generate_dns_id,
//!     init_logging,
//! };
//! ```
//!
//! ## Initialization Sequence
//!
//! Typical initialization order for utility subsystems:
//!
//! ```rust,no_run
//! use dnsmasq::util::{init_logging, init_rng, LogConfig};
//!
//! // 1. Initialize logging first (for error reporting)
//! let log_config = LogConfig::default();
//! init_logging(&log_config)?;
//!
//! // 2. Initialize cryptographic RNG (for DNS security)
//! init_rng();
//!
//! // 3. Proceed with application initialization
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Design Principles
//!
//! This module follows several key design principles:
//!
//! ## Leaf Node Architecture
//!
//! Utility modules are intentionally designed as leaf nodes in the dependency graph.
//! They do not depend on higher-level modules like `dns`, `dhcp`, or `tftp`. This
//! prevents circular dependencies and ensures utilities can be used anywhere in the
//! codebase.
//!
//! ## Memory Safety
//!
//! All utilities maintain Rust's memory safety guarantees. No unsafe code exists in
//! core utility functions (platform-specific FFI may use unsafe for system calls).
//!
//! ## Error Handling
//!
//! Utilities use Result types for operations that can fail, with custom error types
//! defined in each submodule. Panics are avoided except for truly unrecoverable
//! situations (e.g., RNG initialization failure).
//!
//! ## Feature Gating
//!
//! Optional functionality is properly feature-gated to minimize binary size and
//! compilation time when features are not needed. This mirrors the C implementation's
//! compile-time configuration via HAVE_* macros.
//!
//! # Thread Safety
//!
//! While dnsmasq operates in a single-threaded event loop, utility functions are
//! designed to be thread-safe where possible to support testing and potential future
//! enhancements. Specifically:
//!
//! - String and time utilities are fully thread-safe (no shared state)
//! - Logging uses tokio's thread-safe tracing infrastructure
//! - RNG uses thread-local state where appropriate
//! - Metrics use atomic operations for counter updates
//!
//! # Performance Considerations
//!
//! Utilities are optimized for the event-driven architecture:
//!
//! - Logging is asynchronous and non-blocking to prevent event loop stalls
//! - String operations avoid allocations where possible
//! - Time operations use efficient monotonic clock sources
//! - RNG operations are fast enough for per-query DNS ID generation

// ============================================================================
// Core Utilities (Always Available)
// ============================================================================

/// String manipulation and DNS name operations.
///
/// Provides hostname validation, DNS name encoding/decoding, wildcard matching,
/// and socket address formatting utilities.
///
/// Translated from: `src/util.c` (string-related functions)
pub mod string;

/// Time handling and duration management.
///
/// Provides monotonic time sources, duration formatting, lease expiration checking,
/// and time-related type definitions.
///
/// Translated from: `src/util.c` (time-related functions)
pub mod time;

/// Structured logging infrastructure with async support.
///
/// Provides non-blocking logging to syslog, files, and structured outputs using
/// the tracing framework. Prevents deadlocks between dnsmasq and syslogd.
///
/// Translated from: `src/log.c`
pub mod logging;

/// Cryptographic operations and random number generation.
///
/// Provides cryptographically secure random number generation for DNS query IDs
/// and source port randomization to prevent cache poisoning attacks.
///
/// Translated from: `src/crypto.c` (hash functions for DNS security)
pub mod crypto;

// ============================================================================
// Feature-Specific Utilities
// ============================================================================

/// DNS name pattern matching for connection tracking.
///
/// Provides RFC 1123 compliant DNS name validation and glob-style wildcard
/// pattern matching for connection tracking integration.
///
/// **Availability:** Only compiled when the `conntrack` feature is enabled.
///
/// Translated from: `src/pattern.c`
#[cfg(feature = "conntrack")]
pub mod pattern;

/// Prometheus metrics collection and export.
///
/// Provides metrics collection infrastructure and Prometheus-compatible text
/// format export for monitoring and observability integration.
///
/// **Availability:** Only compiled when the `metrics` feature is enabled.
///
/// Translated from: `src/metrics.c`
#[cfg(feature = "metrics")]
pub mod metrics;

// ============================================================================
// Platform-Specific Utilities
// ============================================================================

/// BSD Packet Filter (pf) table integration.
///
/// Provides integration with BSD's pf firewall system, enabling dnsmasq to
/// dynamically populate pf tables with DNS-resolved IP addresses. This is the
/// BSD equivalent of Linux's ipset or nftables integration.
///
/// **Availability:** Only compiled when:
/// - The `ipset` feature is enabled, AND
/// - The target platform is FreeBSD, OpenBSD, or NetBSD
///
/// Translated from: `src/tables.c`
#[cfg(all(
    feature = "ipset",
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
pub mod tables;

// ============================================================================
// Convenience Re-exports
// ============================================================================
//
// The following re-exports provide convenient access to commonly used utility
// functions without requiring full module path imports. This improves ergonomics
// while maintaining clear module organization.

// --- String Utilities ---

pub use string::{
    encode_dns_name, format_socket_addr, hostname_equal, is_legal_hostname, is_subdomain,
    wildcard_match,
};

// --- Time Utilities ---

pub use time::{LeaseTime, Timestamp, format_duration, is_expired, monotonic_time};

// --- Logging ---

pub use logging::{LogConfig, init_logging};

// --- Crypto ---

pub use crypto::{generate_dns_id, init_rng, random_port};

// --- Feature-Gated Re-exports ---

/// Pattern matching utilities (conntrack feature only).
///
/// These functions are only available when the `conntrack` feature is enabled.
#[cfg(feature = "conntrack")]
pub use pattern::{matches_pattern, validate_dns_name, validate_dns_pattern};

/// Metrics collection utilities (metrics feature only).
///
/// These types and functions are only available when the `metrics` feature is enabled.
#[cfg(feature = "metrics")]
pub use metrics::{MetricLabel, MetricsCollector, metric_label};

// ============================================================================
// Module Documentation Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that core utility modules are accessible.
    #[test]
    fn test_module_structure() {
        // This test primarily verifies compilation and module organization.
        // Functional tests are in individual module test suites.

        // Core modules should always be available
        assert!(std::path::Path::new(file!()).exists());
    }

    /// Verify that re-exports are accessible.
    #[test]
    fn test_reexports_available() {
        // Test that commonly used functions are re-exported at module root.
        // This ensures the convenience re-exports are working.

        // We can't easily test function availability at compile time without
        // calling them, but we can verify the module compiles with these
        // re-exports declared. The actual functionality is tested in
        // individual module tests.

        // String utilities
        let _ = is_legal_hostname as fn(&str) -> bool;
        let _ = hostname_equal as fn(&str, &str) -> bool;
        let _ = is_subdomain as fn(&str, &str) -> bool;
        let _ = wildcard_match as fn(&str, &str) -> bool;

        // Time utilities - verify types exist
        let _: Option<Timestamp> = None;
        let _: Option<LeaseTime> = None;

        // Note: Function signature tests for init_logging, init_rng, etc.
        // are in their respective module tests to avoid initialization side effects.
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn test_conntrack_reexports_available() {
        // Verify conntrack-specific re-exports
        let _ = validate_dns_name as fn(&str) -> Result<(), _>;
        let _ = validate_dns_pattern as fn(&str) -> Result<(), _>;
        let _ = matches_pattern as fn(&str, &str) -> bool;
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_metrics_reexports_available() {
        // Verify metrics-specific re-exports exist
        let _: Option<MetricLabel> = None;
        let _: Option<MetricsCollector> = None;
    }
}
