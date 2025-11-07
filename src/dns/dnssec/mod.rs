// Copyright (c) 2000-2024 Simon Kelley & Blitzy Contributors
// This file is part of the dnsmasq Rust implementation
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! DNSSEC (DNS Security Extensions) Implementation
//!
//! This module provides DNSSEC validation capabilities including cryptographic
//! signature verification for securing DNS responses against spoofing and cache
//! poisoning attacks.
//!
//! # Features
//!
//! - **Signature Verification**: RSA, ECDSA, and EdDSA signature validation
//! - **Chain of Trust**: DS record validation and DNSKEY verification
//! - **Algorithm Support**: Modern cryptographic algorithms via the ring crate
//! - **Memory Safety**: Eliminates buffer overflows and timing attacks
//!
//! # Architecture
//!
//! The DNSSEC implementation is organized into:
//! - `crypto`: Cryptographic primitives for signature verification
//! - `validation`: DNSSEC chain of trust validation (planned)
//!
//! # Source Mapping
//!
//! Translated from the C implementation:
//! - `src/dnssec.c` - DNSSEC validation logic
//! - `src/dnssec-crypto.c` - Cryptographic operations (→ crypto.rs)
//!
//! # Example
//!
//! ```no_run
//! use dnsmasq::dns::dnssec::crypto::{verify_signature, Algorithm};
//!
//! let algorithm = Algorithm::Ed25519;
//! let public_key = &[/* DNSKEY data */];
//! let signature = &[/* RRSIG data */];
//! let message = b"DNS message";
//!
//! match verify_signature(algorithm, public_key, signature, message) {
//!     Ok(true) => println!("Signature valid"),
//!     Ok(false) => println!("Signature invalid"),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! ```

pub mod crypto;
pub mod validation;

// Re-export commonly used types for convenience
pub use crypto::{
    Algorithm, CryptoError, HashFunction, algorithm_digest_name, ds_digest_algorithm_name,
    find_hash_algorithm, hash_init, nsec3_hash_algorithm_name, verify_signature,
};

// Re-export validation types
pub use validation::{
    DnssecStatus, TrustAnchor, ValidationResult, RrsigRecord, DnskeyRecord, DsRecord,
    compute_key_tag, generate_dnssec_query, setup_timestamp, validate_by_ds, validate_ds,
    validate_reply, validation_status_to_ede,
};
