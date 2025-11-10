// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// This file is part of the dnsmasq Rust implementation

//! DNS subsystem for dnsmasq-rs
//!
//! This module implements complete DNS functionality including RFC 1035 protocol parsing,
//! response caching, query forwarding to upstream servers, DNS compression, and optional
//! DNSSEC validation and authoritative DNS serving.
//!
//! # Overview
//!
//! The DNS subsystem is the core component of dnsmasq, providing:
//!
//! - **DNS Protocol Parsing**: RFC 1035 compliant message parsing and serialization with
//!   support for all common record types (A, AAAA, CNAME, MX, PTR, TXT, SRV, SOA, NS)
//! - **Response Caching**: LRU-based DNS cache that stores positive and negative responses
//!   to reduce latency and upstream load
//! - **Query Forwarding**: Intelligent forwarding to upstream DNS servers with domain-specific
//!   routing, load balancing, and timeout handling
//! - **DNS Server**: UDP and TCP DNS server supporting both IPv4 and IPv6 transport
//! - **Name Compression**: RFC 1035 DNS name compression for efficient packet encoding
//! - **EDNS0 Support**: Extended DNS features including larger UDP payloads and client subnet
//! - **Domain Matching**: Wildcard domain matching for conditional forwarding and filtering
//! - **Loop Detection**: Prevents DNS resolution loops in complex forwarding configurations
//! - **DNSSEC Validation** (optional): Cryptographic validation of DNS responses with RRSIG
//!   verification and chain of trust validation
//! - **Authoritative DNS** (optional): Local authoritative serving of DNS records for DHCP
//!   assigned hostnames and static host entries
//!
//! # Architecture
//!
//! The DNS subsystem follows a pipeline architecture where queries flow through several stages:
//!
//! ```text
//! Client Query
//!      ↓
//! DNS Server (UDP/TCP listener)
//!      ↓
//! Cache Lookup (check for cached response)
//!      ↓
//! [Cache Hit] → Return cached response
//!      ↓
//! [Cache Miss] → Query Forwarder
//!      ↓
//! Upstream DNS Server
//!      ↓
//! Response Validation (optional DNSSEC)
//!      ↓
//! Cache Storage (store for future queries)
//!      ↓
//! Return to Client
//! ```
//!
//! # Module Organization
//!
//! The DNS subsystem is organized into focused submodules:
//!
//! - [`protocol`] - DNS message parsing, serialization, and wire format handling
//! - [`cache`] - DNS response cache with LRU eviction and TTL management
//! - [`forward`] - Query forwarding logic with upstream server management
//! - [`server`] - DNS server implementation for UDP and TCP transport
//! - [`compression`] - DNS name compression pointer encoding and decoding
//! - [`domain`] - Domain name utilities including canonicalization and matching
//! - [`blockdata`] - Block-chained buffer management for large DNS records
//! - [`edns`] - EDNS0 extension mechanism support
//! - [`rrfilter`] - Resource record filtering for query responses
//! - [`loop_detect`] - DNS forwarding loop detection
//! - [`auth`] - Authoritative DNS server (feature-gated with `auth-dns`)
//! - [`dnssec`] - DNSSEC validation and cryptographic operations (feature-gated with `dnssec`)
//!
//! # Source File Mapping
//!
//! This module tree is translated from the following C source files:
//!
//! | Rust Module | C Source File | Purpose |
//! |-------------|---------------|---------|
//! | `protocol` | `src/rfc1035.c` | DNS message parsing and RFC 1035 implementation |
//! | `cache` | `src/cache.c` | DNS cache with hash table and LRU eviction |
//! | `forward` | `src/forward.c` | Query forwarding to upstream servers |
//! | `compression` | `src/rfc1035.c` (name functions) | DNS name compression |
//! | `domain` | `src/domain.c`, `src/domain-match.c` | Domain name utilities |
//! | `blockdata` | `src/blockdata.c` | Large record storage |
//! | `edns` | `src/edns0.c` | EDNS0 support |
//! | `rrfilter` | `src/rrfilter.c` | Record filtering |
//! | `loop_detect` | `src/loop.c` | Loop detection |
//! | `auth` | `src/auth.c` | Authoritative DNS |
//! | `dnssec` | `src/dnssec.c`, `src/dnssec-crypto.c` | DNSSEC validation |
//!
//! # Feature Flags
//!
//! The DNS subsystem supports conditional compilation through Cargo feature flags:
//!
//! - **`dns`** (default) - Enable DNS subsystem (includes `dns-cache` and `dns-forward`)
//! - **`dns-cache`** - Enable DNS response caching (included in `dns`)
//! - **`dns-forward`** - Enable DNS query forwarding (included in `dns`)
//! - **`dnssec`** - Enable DNSSEC validation with cryptographic signature verification
//! - **`auth-dns`** - Enable authoritative DNS server for local records
//!
//! # Usage Example
//!
//! Basic DNS server setup:
//!
//! ```rust,no_run
//! use dnsmasq::dns::{DnsServer, ServerConfig};
//! use dnsmasq::config::Config;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load global configuration
//! let global_config = Arc::new(Config::default());
//!
//! // Configure DNS server to listen on port 53
//! let server_config = ServerConfig::default();
//!
//! // Create and run the DNS server
//! let mut server = DnsServer::new(server_config, global_config)?;
//! server.run().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Memory Safety
//!
//! All DNS parsing and processing is implemented in safe Rust without `unsafe` blocks.
//! The C implementation's manual buffer management and pointer arithmetic is replaced by:
//!
//! - Slice bounds checking prevents buffer overflows
//! - Ownership and borrowing prevents use-after-free
//! - Type system prevents null pointer dereferences
//! - Parser combinators (nom) for protocol parsing
//!
//! # Protocol Compliance
//!
//! The implementation maintains byte-for-byte compatibility with the C version for all
//! network protocols to ensure drop-in replacement capability:
//!
//! - DNS message format follows RFC 1035 exactly as implemented in `rfc1035.c`
//! - Compression pointer encoding matches the C algorithm
//! - Query ID generation uses the same hash function for consistency
//! - Response timing and TTL handling preserve C version behavior
//!
//! # Integration Points
//!
//! The DNS subsystem integrates with other dnsmasq components:
//!
//! - **DHCP**: Authoritative DNS serves hostnames for DHCP leases
//! - **Network**: Uses platform-specific socket interfaces for DNS transport
//! - **Config**: Configuration options control cache size, forwarding servers, and domains
//! - **Logging**: Structured logging for DNS queries, cache hits/misses, and errors
//!
//! # Testing Support
//!
//! The DNS subsystem includes comprehensive testing:
//!
//! - Unit tests for protocol parsing and serialization
//! - Property-based tests for round-trip correctness (parse ∘ serialize = identity)
//! - Integration tests for end-to-end DNS resolution
//! - Mock upstream servers for forwarding tests
//! - Malformed packet fuzzing for robustness testing

use crate::types::errors::DnsmasqError;

// ============================================================================
// Core DNS Modules (Always Available)
// ============================================================================

/// DNS protocol message parsing and serialization (RFC 1035)
///
/// Implements complete DNS message wire format handling including all common
/// record types, query/response parsing, and message construction.
///
/// Translated from: `src/rfc1035.c`
pub mod protocol;

/// DNS response cache with LRU eviction
///
/// Provides in-memory caching of DNS responses to reduce latency and upstream
/// server load. Implements LRU eviction when cache is full and TTL-based expiry.
///
/// Translated from: `src/cache.c`
pub mod cache;

/// DNS query forwarding to upstream servers
///
/// Manages forwarding of DNS queries to configured upstream servers with
/// domain-specific routing, server health tracking, and response correlation.
///
/// Translated from: `src/forward.c`
pub mod forward;

/// DNS server implementation for UDP and TCP
///
/// Implements the DNS server listener that receives queries from clients,
/// coordinates cache lookups and query forwarding, and returns responses.
///
/// Translated from: `src/dnsmasq.c` (DNS server portions)
pub mod server;

/// DNS name compression pointer handling
///
/// Implements RFC 1035 DNS name compression for efficient packet encoding
/// by replacing repeated domain name suffixes with pointers.
///
/// Translated from: `src/rfc1035.c` (name compression functions)
pub mod compression;

/// Domain name utilities and matching
///
/// Provides domain name canonicalization, wildcard matching, and domain
/// comparison utilities used throughout the DNS subsystem.
///
/// Translated from: `src/domain.c`, `src/domain-match.c`
pub mod domain;

/// Block-chained buffer management for large DNS records
///
/// Implements efficient storage for large DNS records (like TXT or RRSIG)
/// that exceed typical buffer sizes, using a chain of fixed-size blocks.
///
/// Translated from: `src/blockdata.c`
pub mod blockdata;

/// EDNS0 (Extension Mechanisms for DNS) support
///
/// Implements RFC 6891 EDNS0 features including larger UDP payloads,
/// extended response codes, and EDNS options like client subnet.
///
/// Translated from: `src/edns0.c`
pub mod edns;

/// Resource record filtering
///
/// Filters DNS resource records based on query type and configured policies
/// to control which records are returned to clients.
///
/// Translated from: `src/rrfilter.c`
pub mod rrfilter;

/// DNS forwarding loop detection
///
/// Detects and prevents DNS resolution loops that can occur in complex
/// forwarding configurations with multiple conditional forwarders.
///
/// Translated from: `src/loop.c`
pub mod loop_detect;

// ============================================================================
// Feature-Gated Modules
// ============================================================================

/// Authoritative DNS server for local records
///
/// Provides authoritative DNS serving for locally defined records including
/// DHCP hostnames, static host entries, and synthetic domains.
///
/// **Feature**: `auth-dns`
///
/// Translated from: `src/auth.c`
#[cfg(feature = "auth-dns")]
pub mod auth;

/// DNSSEC validation and cryptographic operations
///
/// Implements DNSSEC signature verification, trust chain validation, and
/// cryptographic primitives for securing DNS responses.
///
/// **Feature**: `dnssec`
///
/// Translated from: `src/dnssec.c`, `src/dnssec-crypto.c`
#[cfg(feature = "dnssec")]
pub mod dnssec;

// ============================================================================
// Public Re-Exports for Common Types
// ============================================================================

// Protocol types - DNS message structures
pub use protocol::{
    DnsHeader,      // DNS message header with ID, flags, and counts
    DnsMessage,     // Complete DNS message with header, questions, and records
    DnsQuestion,    // DNS question section entry
    RecordClass,    // DNS record class enum (IN, CS, CH, HS)
    RecordType,     // DNS record type enum (A, AAAA, CNAME, etc.)
    ResourceRecord, // DNS resource record enum with all record types
};

// Cache types - DNS response caching
pub use cache::{
    CacheEntry, // Individual cached DNS response
    CacheKey,   // Cache lookup key (name, type, class)
    DnsCache,   // DNS cache with LRU eviction
};

// Server types - DNS server configuration and implementation
pub use server::{
    DnsServer,    // DNS server implementation
    ServerConfig, // DNS server configuration
};

// Forward types - Query forwarding state
pub use forward::ForwardRecord; // Forward query tracking record

// EDNS types - Extended DNS support
pub use edns::{
    EdnsOption, // EDNS option enum
    OptRecord,  // EDNS OPT pseudo-record
};

// Domain types - Domain name utilities
pub use domain::{
    ConditionalDomain, // Conditional forwarding domain
    SynthDomain,       // Synthetic domain configuration
};

// ============================================================================
// Error Types
// ============================================================================

/// DNS-specific error type
///
/// Re-exported from the main error module for convenience. Use this for
/// DNS subsystem functions that can fail.
pub use crate::types::errors::DnsError;

/// Type alias for Results in the DNS subsystem
///
/// Convenience alias for `Result<T, DnsError>` used throughout the DNS modules.
///
/// # Example
///
/// ```rust,ignore
/// use crate::dns::DnsResult;
///
/// fn parse_dns_message(data: &[u8]) -> DnsResult<DnsMessage> {
///     // Parse message, return DnsError on failure
/// }
/// ```
pub type DnsResult<T> = Result<T, DnsError>;

// ============================================================================
// Module Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test that all modules are properly declared and compile
    #[test]
    fn test_module_organization() {
        // This test ensures that all module declarations are valid
        // and that the module tree compiles successfully
    }

    /// Verify that all required types are re-exported
    #[test]
    fn test_public_exports() {
        // Ensure key types are accessible from the dns module root
        // This validates that re-exports are correct and complete

        // We can't instantiate these types without full implementations,
        // but we can verify they're in scope by referencing them
        let _: Option<DnsMessage> = None;
        let _: Option<DnsCache> = None;
        let _: Option<DnsServer> = None;
        let _: Option<ForwardRecord> = None;
    }

    /// Verify `DnsResult` type alias works correctly
    #[test]
    fn test_dns_result_alias() {
        // Test that DnsResult<T> is equivalent to Result<T, DnsError>
        fn returns_dns_result(should_fail: bool) -> DnsResult<()> {
            if should_fail {
                Err(DnsError::InvalidQuery {
                    message: "test error".to_string(),
                })
            } else {
                Ok(())
            }
        }

        assert!(returns_dns_result(false).is_ok());
        assert!(returns_dns_result(true).is_err());
    }

    /// Verify error type conversion from `DnsError` to `DnsmasqError`
    #[test]
    fn test_error_conversion() {
        // Test that DnsError can be converted to DnsmasqError
        // This validates the From implementation in the errors module
        let dns_error = DnsError::ProtocolError {
            message: "test error".to_string(),
        };
        let _: DnsmasqError = dns_error.into();
    }
}
