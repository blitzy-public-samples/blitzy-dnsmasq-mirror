// Copyright (c) 2012 Giovanni Bajo <rasky@develer.com>
// Copyright (c) 2012-2024 Simon Kelley
// Copyright (c) 2024 Blitzy Platform (Rust translation)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

// DNSSEC module is only included when the dnssec feature is enabled
// Feature gate applied in parent module: src/dns/mod.rs at line 273
// This matches C's HAVE_DNSSEC compile-time flag

//! DNSSEC validation subsystem for dnsmasq-rs
//!
//! This module implements complete DNSSEC (DNS Security Extensions) validation
//! per RFCs 4033, 4034, and 4035. It provides cryptographic verification of
//! DNS response authenticity and integrity through digital signatures.
//!
//! # Architecture
//!
//! The DNSSEC subsystem is organized into two main components:
//!
//! - `crypto`: Cryptographic primitives using the ring crate for RSA, ECDSA,
//!   and Ed25519 signature verification algorithms
//! - `validation`: Core DNSSEC validation logic including DNSKEY validation,
//!   DS record chain verification, RRSIG signature checking, and NSEC/NSEC3
//!   denial-of-existence proofs
//!
//! # Validation States
//!
//! DNSSEC validation produces one of four states:
//! - **Secure**: Valid signatures with complete chain of trust from root
//! - **Insecure**: Unsigned delegation or zone (provably insecure)
//! - **Bogus**: Invalid or missing signatures (validation failure)
//! - **Indeterminate**: Unable to validate due to missing data or errors
//!
//! # Supported Algorithms
//!
//! The implementation supports these DNSSEC algorithms via the ring crate:
//! - RSA/SHA-256 (algorithm 8) - Recommended
//! - RSA/SHA-512 (algorithm 10)
//! - ECDSA P-256/SHA-256 (algorithm 13) - Recommended
//! - ECDSA P-384/SHA-384 (algorithm 14)
//! - Ed25519 (algorithm 15) - Recommended
//! - Ed448 (algorithm 16)
//!
//! Note: RSA/SHA-1 (algorithms 5, 7) are deprecated per RFC 6944 and not supported
//! in this implementation for security reasons.
//!
//! # Trust Anchor Management
//!
//! Trust anchors (typically the root zone KSK) must be configured to establish
//! the initial point of trust. The validation process builds a chain from these
//! anchors down to the queried domain through DS records.
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dnsmasq::dns::dnssec::{validate_reply, DnssecStatus, TrustAnchor, ValidationResult};
//! use dnsmasq::dns::dnssec::validation::DnsMessage;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut response = unimplemented!();
//! # let trust_anchors: Vec<TrustAnchor> = vec![];
//! # let query_name = String::new();
//! # let keyname = String::new();
//! async fn validate_dns_response(
//!     response: &mut DnsMessage,
//!     trust_anchors: &[TrustAnchor],
//!     query_name: &str,
//!     keyname: &str,
//! ) -> Result<DnssecStatus, Box<dyn std::error::Error>> {
//!     let result = validate_reply(
//!         response,
//!         trust_anchors,
//!         query_name,
//!         keyname,
//!     ).await?;
//!     
//!     match result.status {
//!         DnssecStatus::Secure => println!("Response cryptographically verified"),
//!         DnssecStatus::Insecure => println!("Response unsigned but provably insecure"),
//!         DnssecStatus::Bogus => println!("Response failed validation"),
//!         DnssecStatus::Indeterminate => println!("Unable to validate"),
//!     }
//!     
//!     Ok(result.status)
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Integration Points
//!
//! The DNSSEC module integrates with:
//! - `dns::protocol`: DNS message parsing and DNSSEC record types
//! - `dns::cache`: Caching of validated DNSSEC records and signatures
//! - `dns::forward`: DO bit propagation to upstream servers
//! - `config`: Trust anchor configuration and DNSSEC enable/disable
//!
//! # RFC Compliance
//!
//! - RFC 4033: DNS Security Introduction and Requirements
//! - RFC 4034: Resource Records for DNS Security Extensions
//! - RFC 4035: Protocol Modifications for DNS Security Extensions
//! - RFC 5155: NSEC3 authenticated denial of existence
//! - RFC 6605: ECDSA for DNSSEC
//! - RFC 8080: EdDSA for DNSSEC
//! - RFC 6840: Clarifications and implementation notes
//!
//! # Memory Safety
//!
//! The Rust implementation eliminates entire classes of vulnerabilities present
//! in the C version:
//! - No buffer overflows in signature verification
//! - No use-after-free in DNSSEC record handling
//! - Compile-time prevention of invalid pointer arithmetic
//! - Safe parsing of untrusted network data
//!
//! # Performance Considerations
//!
//! DNSSEC validation is cryptographically intensive. The implementation:
//! - Caches validated DNSKEY and DS records to minimize upstream queries
//! - Uses efficient ring crate cryptographic primitives
//! - Performs validation asynchronously to avoid blocking DNS queries
//! - Supports concurrent validation of multiple queries
//!
//! # Source Mapping
//!
//! Translated from C implementation:
//! - `src/dnssec.c` - Main DNSSEC validation logic (→ validation.rs)
//! - `src/crypto.c` - Cryptographic primitives (→ crypto.rs)
//! - `src/dnsmasq.h` - Common type definitions

use std::time::Duration;

// Import error types from centralized error module
use crate::types::errors::DnssecError;

// Module declarations
pub mod crypto;
pub mod validation;

// ============================================================================
// Public Re-exports from crypto module
// ============================================================================

/// Cryptographic signature verification function
///
/// Verifies DNSSEC signatures using various algorithms (RSA, ECDSA, EdDSA).
/// This is the primary entry point for signature verification operations.
///
/// # Source
///
/// C implementation: `dnsmasq_verify()` in src/crypto.c
pub use crypto::verify_signature;

/// Hash initialization function
///
/// Creates a new hash context for computing digests used in DS records
/// and NSEC3 hashing.
///
/// # Source
///
/// C implementation: `hash_init()` in src/crypto.c
pub use crypto::hash_init;

/// DNSSEC algorithm enumeration
///
/// Supported cryptographic algorithms for signature verification.
/// Includes RSA/SHA-256, RSA/SHA-512, ECDSA variants, and EdDSA variants.
pub use crypto::Algorithm;

/// Hash function enumeration
///
/// Hash algorithms used for DS records, NSEC3 hashing, and signature digests.
/// Includes SHA-1 (legacy), SHA-256, SHA-384, and SHA-512.
pub use crypto::HashFunction;

/// Cryptographic operation error type
///
/// Error enumeration covering all cryptographic operation failures including
/// unsupported algorithms, invalid key/signature formats, verification failures,
/// and hash initialization errors.
pub use crypto::CryptoError;

// ============================================================================
// Public Re-exports from validation module
// ============================================================================

/// Main DNSSEC validation entry point
///
/// Validates all RRsets in a DNS response, checking RRSIG signatures and
/// building the chain of trust from configured trust anchors.
///
/// # Source
///
/// C implementation: `dnssec_validate_reply()` in src/dnssec.c lines 1860-2118
pub use validation::validate_reply;

/// Validates DNSKEY RRset against parent DS records
///
/// Establishes trust for a zone's public keys by verifying that at least one
/// DNSKEY matches the DS record from the parent zone.
///
/// # Source
///
/// C implementation: `dnssec_validate_by_ds()` in src/dnssec.c lines 762-991
pub use validation::validate_by_ds;

/// Validates DS records using child zone DNSKEYs
///
/// Used for building the chain of trust by verifying DS records point to
/// valid DNSKEYs in the child zone.
///
/// # Source
///
/// C implementation: `dnssec_validate_ds()` in src/dnssec.c lines 993-1128
pub use validation::validate_ds;

/// DNSSEC validation status enumeration
///
/// Represents the four possible validation states: Secure, Insecure, Bogus,
/// and Indeterminate.
pub use validation::DnssecStatus;

/// Validation result structure
///
/// Contains detailed validation results including status, AD bit setting,
/// signature information, and failure reasons.
pub use validation::ValidationResult;

/// Trust anchor structure
///
/// Represents a configured trust anchor (typically root zone KSK) used as
/// the starting point for building the chain of trust.
pub use validation::TrustAnchor;

/// Timestamp initialization for systems with unreliable RTC
///
/// Reads last known good timestamp from persistent file to enable RRSIG
/// temporal validation on embedded systems without battery-backed RTC.
///
/// # Source
///
/// C implementation: `setup_timestamp()` in src/dnssec.c lines 143-186
pub use validation::setup_timestamp;

// ============================================================================
// Type Aliases
// ============================================================================

/// Result type for DNSSEC operations
///
/// Convenience alias for Result<T, DnssecError> used throughout the DNSSEC
/// subsystem for consistent error handling.
pub type DnssecResult<T> = Result<T, DnssecError>;

// ============================================================================
// Module Constants
// ============================================================================

/// Maximum DS chain length to prevent excessive validation queries
///
/// Limits the number of DS record hops when building the chain of trust from
/// root to target domain. Prevents resource exhaustion from malicious or
/// misconfigured zones with deep delegation chains.
///
/// Value matches common implementation limits for DNSSEC validation depth.
pub const MAX_VALIDATION_CHAIN_LENGTH: usize = 20;

/// Default signature validity time window for clock skew tolerance
///
/// Allows 5 minutes of clock skew when checking RRSIG inception and expiration
/// times. This accommodates minor time synchronization issues while maintaining
/// security.
///
/// Value: 300 seconds (5 minutes)
///
/// # Source
///
/// C implementation uses similar tolerance in timestamp checking logic
pub const DEFAULT_SIGNATURE_VALIDITY_WINDOW: Duration = Duration::from_secs(300);

// ============================================================================
// Module Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_organization() {
        // Smoke test that submodules compile and are accessible
        // This ensures the module structure is correct
    }

    #[test]
    fn test_dnssec_result_alias() {
        // Verify DnssecResult type alias works correctly
        let success: DnssecResult<bool> = Ok(true);
        assert!(success.is_ok());
        assert_eq!(success.unwrap(), true);

        let failure: DnssecResult<bool> = Err(DnssecError::ChainOfTrustBroken {
            zone: "example.com".to_string(),
        });
        assert!(failure.is_err());
    }

    #[test]
    fn test_validation_chain_length_constant() {
        // Verify constant is within reasonable bounds
        assert!(MAX_VALIDATION_CHAIN_LENGTH > 0);
        assert!(MAX_VALIDATION_CHAIN_LENGTH <= 100);
    }

    #[test]
    fn test_signature_validity_window_constant() {
        // Verify validity window is reasonable (between 1 minute and 1 hour)
        let secs = DEFAULT_SIGNATURE_VALIDITY_WINDOW.as_secs();
        assert!(secs >= 60); // At least 1 minute
        assert!(secs <= 3600); // At most 1 hour
    }

    #[test]
    fn test_crypto_exports_accessible() {
        // Verify crypto module exports are accessible
        use super::crypto::Algorithm;
        let _alg = Algorithm::RsaSha256;
    }

    #[test]
    fn test_validation_exports_accessible() {
        // Verify validation module exports are accessible
        use super::validation::DnssecStatus;
        let _status = DnssecStatus::Secure;
    }
}
