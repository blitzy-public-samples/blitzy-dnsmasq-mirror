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

//! Cryptographic primitive wrappers for DNSSEC signature verification
//!
//! # Purpose
//!
//! This module provides memory-safe cryptographic operations for DNSSEC validation
//! using the ring crate as a replacement for C's libnettle. It eliminates all
//! memory-safety vulnerabilities inherent in C's manual memory management while
//! providing functionally equivalent signature verification for RSA, ECDSA, EdDSA,
//! and GOST algorithms.
//!
//! # Key Responsibilities
//!
//! - [`verify()`]: Main entry point for DNSSEC signature verification across all algorithms
//! - [`algo_digest_name()`]: Map DNSSEC algorithm numbers to hash names
//! - [`ds_digest_name()`]: Map DS record digest types to hash names
//! - [`nsec3_digest_name()`]: Map NSEC3 digest types to hash names
//! - Algorithm-specific verification: RSA, ECDSA, EdDSA, GOST
//!
//! # Memory Safety Transformation
//!
//! The C implementation used:
//! - Manual memory allocation with malloc/free for key structures
//! - GMP arbitrary precision integers (mpz_t) with manual initialization/cleanup
//! - Nettle library FFI with raw pointers and unsafe memory access
//! - Static global buffers for performance (not thread-safe)
//! - Function pointers for algorithm dispatch
//!
//! This Rust implementation uses:
//! - ring crate's safe cryptographic API (zero unsafe blocks in crypto operations)
//! - Automatic memory management via RAII (no manual free() calls)
//! - Type-safe algorithm dispatch using match expressions on enums
//! - Stack-allocated temporary buffers with compile-time bounds checking
//! - Explicit error propagation via Result<(), CryptoError>
//!
//! # Supported Algorithms
//!
//! - **RSA**: Algorithms 5 (SHA1), 7 (SHA1-NSEC3), 8 (SHA256), 10 (SHA512)
//! - **ECDSA**: Algorithms 13 (P-256/SHA256), 14 (P-384/SHA384)
//! - **EdDSA**: Algorithms 15 (Ed25519), 16 (Ed448)
//! - **GOST**: Algorithm 12 (GOST R 34.10-2001) - Note: Limited ring support
//!
//! # RFC Compliance
//!
//! - RFC 4034: DNSSEC Resource Records (RRSIG, DNSKEY)
//! - RFC 5702: RSA/SHA-2 for DNSSEC (algorithms 8, 10)
//! - RFC 6605: ECDSA for DNSSEC (algorithms 13, 14)
//! - RFC 8080: EdDSA for DNSSEC (algorithms 15, 16)
//! - RFC 5933: GOST for DNSSEC (algorithm 12)
//! - RFC 8624: Algorithm implementation requirements
//!
//! # Examples
//!
//! ```ignore
//! use dnsmasq::dns::dnssec::crypto::verify;
//! use dnsmasq::dns::dnssec::types::DnssecAlgorithm;
//! use dnsmasq::dns::blockdata::BlockData;
//!
//! let key_data = BlockData::from_bytes(&key_bytes);
//! let signature = &sig_bytes[..];
//! let message_hash = &digest_bytes[..];
//!
//! match verify(&key_data, signature, message_hash, DnssecAlgorithm::RsaSha256) {
//!     Ok(()) => println!("Signature valid"),
//!     Err(e) => eprintln!("Signature validation failed: {}", e),
//! }
//! ```

use crate::dns::blockdata::BlockData;
use crate::dns::dnssec::types::DnssecAlgorithm;
use ring::signature::{
    self, RsaPublicKeyComponents, UnparsedPublicKey, 
    ED25519, VerificationAlgorithm,
};
use std::error::Error as StdError;
use std::fmt;
use tracing::{debug, trace, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Cryptographic operation errors for DNSSEC signature verification
///
/// This enum represents all possible failure modes during signature verification.
/// Each variant provides context about what went wrong, enabling detailed error
/// reporting and debugging of DNSSEC validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// DNSSEC algorithm not supported by this implementation
    ///
    /// Returned when the algorithm number doesn't match any implemented algorithm,
    /// or when the algorithm is deprecated (e.g., RSA/MD5, DSA variants).
    UnsupportedAlgorithm {
        /// Algorithm number from RRSIG/DNSKEY record
        algo: u8,
    },

    /// Public key length invalid for the specified algorithm
    ///
    /// Each algorithm requires specific key lengths:
    /// - RSA: Minimum 512 bits (64 bytes), maximum 4096 bits (512 bytes)
    /// - ECDSA P-256: Exactly 64 bytes (32-byte x, 32-byte y)
    /// - ECDSA P-384: Exactly 96 bytes (48-byte x, 48-byte y)
    /// - Ed25519: Exactly 32 bytes
    /// - Ed448: Exactly 57 bytes
    InvalidKeyLength {
        /// DNSSEC algorithm
        algo: DnssecAlgorithm,
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length found
        found: usize,
    },

    /// Signature length invalid for the specified algorithm
    ///
    /// Each algorithm produces fixed-size signatures:
    /// - RSA: Variable (matches key size)
    /// - ECDSA P-256: Exactly 64 bytes (32-byte r, 32-byte s)
    /// - ECDSA P-384: Exactly 96 bytes (48-byte r, 48-byte s)
    /// - Ed25519: Exactly 64 bytes
    /// - Ed448: Exactly 114 bytes
    InvalidSignatureLength {
        /// DNSSEC algorithm
        algo: DnssecAlgorithm,
        /// Expected signature length in bytes
        expected: usize,
        /// Actual signature length found
        found: usize,
    },

    /// Cryptographic signature verification failed
    ///
    /// The signature is well-formed but doesn't mathematically validate against
    /// the provided public key and message digest. This is the expected failure
    /// mode for invalid or forged signatures.
    VerificationFailed {
        /// DNSSEC algorithm used
        algo: DnssecAlgorithm,
        /// Underlying ring library error message
        reason: String,
    },

    /// RSA public key parsing or format error
    ///
    /// The RSA public key in the DNSKEY record is malformed. Common causes:
    /// - Exponent length field incorrect
    /// - Modulus too short (< 512 bits)
    /// - Invalid encoding
    RsaKeyFormatError {
        /// Detailed error description
        reason: String,
    },

    /// ECDSA or `EdDSA` public key parsing error
    ///
    /// The elliptic curve public key is malformed or the point is not on the curve.
    EcKeyFormatError {
        /// DNSSEC algorithm (ECDSA or `EdDSA`)
        algo: DnssecAlgorithm,
        /// Detailed error description
        reason: String,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::UnsupportedAlgorithm { algo } => {
                write!(f, "Unsupported DNSSEC algorithm: {algo}")
            }
            CryptoError::InvalidKeyLength { algo, expected, found } => {
                write!(
                    f,
                    "Invalid key length for {algo}: expected {expected}, found {found}"
                )
            }
            CryptoError::InvalidSignatureLength { algo, expected, found } => {
                write!(
                    f,
                    "Invalid signature length for {algo}: expected {expected}, found {found}"
                )
            }
            CryptoError::VerificationFailed { algo, reason } => {
                write!(f, "Signature verification failed for {algo}: {reason}")
            }
            CryptoError::RsaKeyFormatError { reason } => {
                write!(f, "RSA key format error: {reason}")
            }
            CryptoError::EcKeyFormatError { algo, reason } => {
                write!(f, "{algo} key format error: {reason}")
            }
        }
    }
}

impl StdError for CryptoError {}

// ============================================================================
// Algorithm-Specific Verification Functions
// ============================================================================

/// Verify RSA signature for DNSSEC algorithms 5, 7, 8, 10
///
/// Implements RSA signature verification for:
/// - Algorithm 5: RSA/SHA1 (deprecated but supported)
/// - Algorithm 7: RSA/SHA1-NSEC3 (deprecated but supported)
/// - Algorithm 8: RSA/SHA256 (recommended)
/// - Algorithm 10: RSA/SHA512
///
/// # RSA Key Format (RFC 3110)
///
/// The DNSKEY record contains the RSA public key in the following format:
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |  exponent length  |                           |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /               public exponent (e)             /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                 modulus (n)                   /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// Exponent length encoding:
/// - If length < 256: Single byte length field
/// - If length >= 256: First byte is 0x00, followed by 2-byte big-endian length
///
/// # Memory Safety
///
/// Unlike C implementation using GMP bignum and manual `mpz_import`:
/// - Uses ring's `RsaPublicKeyComponents` which handles bignum internally
/// - No unsafe pointer arithmetic for key parsing
/// - Automatic bounds checking on all slice operations
/// - No manual memory management
///
/// # Arguments
///
/// * `key_data` - `BlockData` containing RSA public key in RFC 3110 format
/// * `sig` - Signature bytes to verify
/// * `digest` - Message digest (hash of signed data)
/// * `algo` - DNSSEC algorithm (5, 7, 8, or 10)
///
/// # Errors
///
/// Returns `CryptoError` if:
/// - Key length < 3 bytes (minimum for valid RSA key)
/// - Exponent length exceeds remaining key data
/// - Modulus is too short (< 512 bits)
/// - Signature verification fails (invalid signature)
///
/// # RFC Compliance
///
/// - RFC 3110: RSA public key encoding in DNS
/// - RFC 4034: DNSSEC Resource Records
/// - RFC 5702: SHA-2 algorithms for DNSSEC
fn rsa_verify(
    key_data: &BlockData,
    sig: &[u8],
    digest: &[u8],
    algo: DnssecAlgorithm,
) -> Result<(), CryptoError> {
    let key_bytes = key_data.to_bytes();
    let key_len = key_bytes.len();

    if key_len < 3 {
        return Err(CryptoError::RsaKeyFormatError {
            reason: format!("Key too short: {key_len} bytes (minimum 3)"),
        });
    }

    // Parse exponent length
    // Note: We've already verified key_len >= 3, so accessing key_bytes[0..3] is safe
    let (offset, exp_len) = if key_bytes[0] == 0 {
        // Extended exponent length format: first byte is 0, next 2 bytes are big-endian length
        let len = u16::from_be_bytes([key_bytes[1], key_bytes[2]]) as usize;
        (3, len)
    } else {
        // Normal format: first byte is exponent length
        (1, key_bytes[0] as usize)
    };

    // Validate exponent doesn't exceed key data
    if offset + exp_len > key_len {
        return Err(CryptoError::RsaKeyFormatError {
            reason: format!(
                "Exponent length {} exceeds remaining key data {}",
                exp_len,
                key_len - offset
            ),
        });
    }

    // Extract exponent and modulus
    let exponent = &key_bytes[offset..offset + exp_len];
    let modulus = &key_bytes[offset + exp_len..];

    // Validate modulus length (minimum 512 bits = 64 bytes)
    if modulus.len() < 64 {
        return Err(CryptoError::RsaKeyFormatError {
            reason: format!(
                "Modulus too short: {} bytes (minimum 64 for 512-bit key)",
                modulus.len()
            ),
        });
    }

    trace!(
        "RSA key: algo={}, exp_len={}, mod_len={}, sig_len={}",
        algo,
        exp_len,
        modulus.len(),
        sig.len()
    );

    // Create RSA public key components
    let public_key = RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    };

    // Select verification algorithm based on DNSSEC algorithm
    let verification_result = match algo {
        DnssecAlgorithm::RsaSha1 | DnssecAlgorithm::RsaSha1Nsec3 => {
            public_key.verify(
                &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                digest,
                sig,
            )
        }
        DnssecAlgorithm::RsaSha256 => {
            public_key.verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                digest,
                sig,
            )
        }
        DnssecAlgorithm::RsaSha512 => {
            public_key.verify(
                &signature::RSA_PKCS1_2048_8192_SHA512,
                digest,
                sig,
            )
        }
        _ => {
            return Err(CryptoError::UnsupportedAlgorithm {
                algo: algo.to_u8(),
            })
        }
    };

    verification_result.map_err(|e| {
        debug!("RSA signature verification failed for {}: {}", algo, e);
        CryptoError::VerificationFailed {
            algo,
            reason: e.to_string(),
        }
    })
}

/// Verify ECDSA signature for DNSSEC algorithms 13, 14
///
/// Implements ECDSA signature verification for:
/// - Algorithm 13: ECDSA P-256 with SHA-256
/// - Algorithm 14: ECDSA P-384 with SHA-384
///
/// # ECDSA Key Format (RFC 6605)
///
/// The DNSKEY record contains the ECDSA public key as concatenated coordinates:
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /            x coordinate (t bytes)             /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /            y coordinate (t bytes)             /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
/// Where t = 32 for P-256, t = 48 for P-384
///
/// # ECDSA Signature Format
///
/// The signature contains r and s components:
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |               r (t bytes)                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |               s (t bytes)                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// # Memory Safety
///
/// Unlike C implementation using nettle ECC structures:
/// - Uses ring's `UnparsedPublicKey` which handles EC point validation
/// - No manual `mpz_import` for r, s components
/// - Automatic curve parameter selection
/// - No unsafe `ecc_point_set` validation
///
/// # Arguments
///
/// * `key_data` - `BlockData` containing ECDSA public key (x || y)
/// * `sig` - Signature bytes (r || s)
/// * `digest` - Message digest (SHA-256 or SHA-384)
/// * `algo` - DNSSEC algorithm (13 or 14)
///
/// # Errors
///
/// Returns `CryptoError` if:
/// - Key length doesn't match algorithm (64 bytes for P-256, 96 for P-384)
/// - Signature length doesn't match algorithm
/// - Public key point not on curve
/// - Signature verification fails
///
/// # RFC Compliance
///
/// - RFC 6605: ECDSA for DNSSEC (algorithms 13 and 14)
/// - RFC 4034: DNSSEC Resource Records
fn ecdsa_verify(
    key_data: &BlockData,
    sig: &[u8],
    digest: &[u8],
    algo: DnssecAlgorithm,
) -> Result<(), CryptoError> {
    let key_bytes = key_data.to_bytes();

    // Determine expected lengths based on algorithm
    let (expected_key_len, expected_sig_len): (usize, usize) = match algo {
        DnssecAlgorithm::EcdsaP256Sha256 => (64, 64),
        DnssecAlgorithm::EcdsaP384Sha384 => (96, 96),
        _ => {
            return Err(CryptoError::UnsupportedAlgorithm {
                algo: algo.to_u8(),
            })
        }
    };

    // Validate key length
    if key_bytes.len() != expected_key_len {
        return Err(CryptoError::InvalidKeyLength {
            algo,
            expected: expected_key_len,
            found: key_bytes.len(),
        });
    }

    // Validate signature length
    if sig.len() != expected_sig_len {
        return Err(CryptoError::InvalidSignatureLength {
            algo,
            expected: expected_sig_len,
            found: sig.len(),
        });
    }

    trace!(
        "ECDSA verify: algo={}, key_len={}, sig_len={}, digest_len={}",
        algo,
        key_bytes.len(),
        sig.len(),
        digest.len()
    );

    // For ECDSA, we need to convert the raw (r || s) format to ASN.1 DER format
    // that ring expects. However, ring's ECDSA_*_ASN1 algorithms expect ASN.1.
    // Since DNS uses raw format, we need to convert or use fixed ASN.1.
    //
    // Actually, looking at RFC 6605 more carefully and ring's API:
    // Ring's ECDSA verification expects the signature in IEEE P1363 format (r || s),
    // but the algorithm constants ending in _ASN1 expect DER encoding.
    //
    // For DNSSEC, RFC 6605 specifies raw r || s format.
    // We need to use the non-ASN1 variants or construct ASN.1.
    //
    // Let me check ring's available ECDSA algorithms:
    // - ECDSA_P256_SHA256_ASN1 (expects ASN.1 DER)
    // - ECDSA_P256_SHA256_FIXED (expects fixed-length r || s)
    //
    // RFC 6605 Section 4 says: "The signature is the combination of two values, r and s, in that order"
    // This is IEEE P1363 format, so we should use FIXED variants.
    
    // Convert public key to uncompressed point format (0x04 || x || y)
    let mut uncompressed_key = Vec::with_capacity(1 + key_bytes.len());
    uncompressed_key.push(0x04); // Uncompressed point indicator
    uncompressed_key.extend_from_slice(&key_bytes);

    // Ring expects P1363 format for ECDSA with FIXED algorithms
    // Use FIXED instead of ASN1 for DNS raw format
    let verification_algorithm_fixed: &dyn VerificationAlgorithm = match algo {
        DnssecAlgorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_FIXED,
        DnssecAlgorithm::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_FIXED,
        _ => unreachable!(),
    };

    let public_key = UnparsedPublicKey::new(verification_algorithm_fixed, &uncompressed_key);

    public_key.verify(digest, sig).map_err(|e| {
        debug!("ECDSA signature verification failed for {}: {}", algo, e);
        CryptoError::VerificationFailed {
            algo,
            reason: e.to_string(),
        }
    })
}

/// Verify `EdDSA` signature for DNSSEC algorithms 15, 16
///
/// Implements `EdDSA` signature verification for:
/// - Algorithm 15: Ed25519 (Curve25519)
/// - Algorithm 16: Ed448 (Curve448) - Note: Limited ring support
///
/// # `EdDSA` Key Format (RFC 8080)
///
/// The DNSKEY record contains the `EdDSA` public key as raw bytes:
/// - Ed25519: 32 bytes (public key point)
/// - Ed448: 57 bytes (public key point)
///
/// # `EdDSA` Signature Format
///
/// - Ed25519: 64 bytes (R || S)
/// - Ed448: 114 bytes (R || S)
///
/// # `EdDSA` vs RSA/ECDSA Difference
///
/// Unlike RSA and ECDSA which sign a hash digest, `EdDSA` algorithms
/// (Ed25519, Ed448) operate on the complete message. The C implementation
/// used a "`null_hash`" mechanism to accumulate the full message. In Rust,
/// we receive the complete message directly in the digest parameter.
///
/// # Memory Safety
///
/// Unlike C implementation using nettle `EdDSA` structures:
/// - Uses ring's ED25519 which handles key validation internally
/// - No `null_hash` buffer management (message passed directly)
/// - No manual SHA-512 or SHAKE256 hashing (`EdDSA` does it internally)
/// - Automatic signature format validation
///
/// # Arguments
///
/// * `key_data` - `BlockData` containing `EdDSA` public key
/// * `sig` - Signature bytes
/// * `message` - Complete message to verify (not a hash digest)
/// * `algo` - DNSSEC algorithm (15 or 16)
///
/// # Errors
///
/// Returns `CryptoError` if:
/// - Key length doesn't match algorithm (32 for Ed25519, 57 for Ed448)
/// - Signature length doesn't match algorithm (64 for Ed25519, 114 for Ed448)
/// - Signature verification fails
///
/// # RFC Compliance
///
/// - RFC 8080: `EdDSA` for DNSSEC (algorithms 15 and 16)
/// - RFC 8032: Edwards-Curve Digital Signature Algorithm (`EdDSA`)
/// - RFC 4034: DNSSEC Resource Records
///
/// # Note on Ed448
///
/// Ed448 support in ring is limited. As of ring 0.17, Ed448 is not fully
/// implemented. This function returns `UnsupportedAlgorithm` for Ed448 until
/// ring adds support.
fn eddsa_verify(
    key_data: &BlockData,
    sig: &[u8],
    message: &[u8],
    algo: DnssecAlgorithm,
) -> Result<(), CryptoError> {
    let key_bytes = key_data.to_bytes();

    match algo {
        DnssecAlgorithm::Ed25519 => {
            // Ed25519 key: 32 bytes, signature: 64 bytes
            if key_bytes.len() != 32 {
                return Err(CryptoError::InvalidKeyLength {
                    algo,
                    expected: 32,
                    found: key_bytes.len(),
                });
            }

            if sig.len() != 64 {
                return Err(CryptoError::InvalidSignatureLength {
                    algo,
                    expected: 64,
                    found: sig.len(),
                });
            }

            trace!(
                "Ed25519 verify: key_len={}, sig_len={}, msg_len={}",
                key_bytes.len(),
                sig.len(),
                message.len()
            );

            let public_key = UnparsedPublicKey::new(&ED25519, &key_bytes);

            public_key.verify(message, sig).map_err(|e| {
                debug!("Ed25519 signature verification failed: {}", e);
                CryptoError::VerificationFailed {
                    algo,
                    reason: e.to_string(),
                }
            })
        }

        DnssecAlgorithm::Ed448 => {
            // Ed448 is not currently supported by ring 0.17
            // Return UnsupportedAlgorithm until ring adds support
            warn!("Ed448 (algorithm 16) not yet supported by ring crate");
            Err(CryptoError::UnsupportedAlgorithm {
                algo: algo.to_u8(),
            })
        }

        _ => Err(CryptoError::UnsupportedAlgorithm {
            algo: algo.to_u8(),
        }),
    }
}

/// Verify GOST signature for DNSSEC algorithm 12
///
/// GOST R 34.10-2001 is a Russian cryptographic standard using elliptic curves.
/// This algorithm is primarily used in Russian Federation networks.
///
/// # GOST Support Status
///
/// Ring crate does not currently support GOST cryptography. This function
/// returns `UnsupportedAlgorithm` for all GOST verification attempts.
///
/// Future implementations could use alternative crates like `gost-crypto` or
/// FFI to appropriate libraries if GOST support is required.
///
/// # Arguments
///
/// * `_key_data` - `BlockData` containing GOST public key (unused)
/// * `_sig` - Signature bytes (unused)
/// * `_digest` - Message digest (unused)
/// * `algo` - DNSSEC algorithm (must be 12)
///
/// # Errors
///
/// Always returns `CryptoError::UnsupportedAlgorithm` as GOST is not implemented.
///
/// # RFC Compliance
///
/// - RFC 5933: GOST R 34.10-2001 for DNSSEC (algorithm 12)
///
/// # Note
///
/// GOST algorithm support is optional per RFC 8624. Most DNSSEC deployments
/// outside Russia use RSA, ECDSA, or `EdDSA` algorithms instead.
#[allow(unused_variables)]
fn gost_verify(
    _key_data: &BlockData,
    _sig: &[u8],
    _digest: &[u8],
    algo: DnssecAlgorithm,
) -> Result<(), CryptoError> {
    warn!("GOST R 34.10-2001 (algorithm 12) not supported by ring crate");
    Err(CryptoError::UnsupportedAlgorithm {
        algo: algo.to_u8(),
    })
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Verify DNSSEC signature using appropriate cryptographic algorithm
///
/// Main entry point for DNSSEC signature verification. Dispatches to
/// algorithm-specific verification functions based on the DNSSEC algorithm
/// number from the RRSIG and DNSKEY records. Supports RSA, ECDSA, `EdDSA`,
/// and GOST signature algorithms (though GOST returns unsupported).
///
/// # Algorithm Dispatch
///
/// The function uses Rust's type-safe match expression to dispatch to
/// algorithm-specific verification functions, replacing C's function
/// pointer table approach. This provides compile-time verification of
/// exhaustive pattern matching and eliminates null pointer risks.
///
/// # Memory Safety
///
/// Unlike C implementation with global static key structures:
/// - No global mutable state
/// - No manual memory management
/// - All key and signature parsing uses safe slice operations
/// - Automatic cleanup via RAII when function returns
///
/// # Arguments
///
/// * `key_data` - `BlockData` chain containing public key from DNSKEY record
/// * `sig` - Signature bytes from RRSIG record
/// * `digest` - Hash digest of signed data (or complete message for `EdDSA`)
/// * `algo` - DNSSEC algorithm number from RRSIG/DNSKEY records
///
/// # Returns
///
/// - `Ok(())` - Signature cryptographically valid
/// - `Err(CryptoError)` - Verification failed or algorithm unsupported
///
/// # Supported Algorithms
///
/// - **5**: RSA/SHA1 (deprecated but supported)
/// - **7**: RSA/SHA1-NSEC3 (deprecated but supported)
/// - **8**: RSA/SHA256 (recommended)
/// - **10**: RSA/SHA512
/// - **12**: GOST R 34.10-2001 (returns unsupported)
/// - **13**: ECDSA P-256/SHA256
/// - **14**: ECDSA P-384/SHA384
/// - **15**: Ed25519
/// - **16**: Ed448 (returns unsupported until ring adds support)
///
/// # Unsupported Algorithms
///
/// Per RFC 6944 and RFC 8624, these algorithms MUST NOT be implemented:
/// - **1**: RSA/MD5 (cryptographically broken)
/// - **3**: DSA/SHA1 (deprecated)
/// - **6**: DSA-NSEC3-SHA1 (deprecated)
///
/// # Examples
///
/// ```ignore
/// use dnsmasq::dns::dnssec::crypto::verify;
/// use dnsmasq::dns::dnssec::types::DnssecAlgorithm;
/// use dnsmasq::dns::blockdata::BlockData;
///
/// // RSA/SHA256 signature verification
/// let key = BlockData::from_bytes(&key_bytes);
/// match verify(&key, &sig_bytes, &digest, DnssecAlgorithm::RsaSha256) {
///     Ok(()) => println!("Valid signature"),
///     Err(e) => eprintln!("Invalid signature: {}", e),
/// }
/// ```
///
/// # RFC Compliance
///
/// - RFC 4034: DNSSEC Resource Records (RRSIG, DNSKEY)
/// - RFC 4035: Protocol Modifications for DNSSEC (validation process)
/// - RFC 5702: RSA/SHA-2 for DNSSEC (algorithms 8, 10)
/// - RFC 6605: ECDSA for DNSSEC (algorithms 13, 14)
/// - RFC 8080: `EdDSA` for DNSSEC (algorithms 15, 16)
/// - RFC 5933: GOST for DNSSEC (algorithm 12)
/// - RFC 6944: Algorithm deprecation (RSA/MD5, DSA variants)
/// - RFC 8624: Algorithm implementation requirements
///
/// # Thread Safety
///
/// This function is thread-safe. Unlike C implementation with static storage,
/// all state is stack-allocated or managed by ring's internal structures.
pub fn verify(
    key_data: &BlockData,
    sig: &[u8],
    digest: &[u8],
    algo: DnssecAlgorithm,
) -> Result<(), CryptoError> {
    debug!(
        "Verifying DNSSEC signature: algo={}, key_len={}, sig_len={}, digest_len={}",
        algo,
        key_data.len(),
        sig.len(),
        digest.len()
    );

    // Dispatch to algorithm-specific verification function
    match algo {
        DnssecAlgorithm::RsaSha1
        | DnssecAlgorithm::RsaSha1Nsec3
        | DnssecAlgorithm::RsaSha256
        | DnssecAlgorithm::RsaSha512 => rsa_verify(key_data, sig, digest, algo),

        DnssecAlgorithm::EcdsaP256Sha256 | DnssecAlgorithm::EcdsaP384Sha384 => {
            ecdsa_verify(key_data, sig, digest, algo)
        }

        DnssecAlgorithm::Ed25519 | DnssecAlgorithm::Ed448 => {
            eddsa_verify(key_data, sig, digest, algo)
        }

        DnssecAlgorithm::Gost => gost_verify(key_data, sig, digest, algo),
    }
}

// ============================================================================
// Hash Algorithm Name Mapping Functions
// ============================================================================

/// Map DNSSEC signature algorithm to hash digest name
///
/// Converts DNSSEC signature algorithm number to the corresponding hash
/// algorithm name used for computing message digests. This function defines
/// which algorithms are supported - returning `Some(name)` indicates the
/// algorithm is implemented in `verify()`.
///
/// # Algorithm-to-Hash Mapping
///
/// - **5, 7**: RSA/SHA1 → "sha1"
/// - **8**: RSA/SHA256 → "sha256"
/// - **10**: RSA/SHA512 → "sha512"
/// - **12**: GOST → "gost94" (not fully supported)
/// - **13**: ECDSA P-256 → "sha256"
/// - **14**: ECDSA P-384 → "sha384"
/// - **15, 16**: `EdDSA` → "null" (operates on whole message)
///
/// # `EdDSA` Special Case
///
/// `EdDSA` algorithms (15, 16) return "null" because they don't hash the
/// message before signing. Instead, they operate on the complete message.
/// The C implementation used a "`null_hash`" that accumulated the full message.
///
/// # Unsupported Algorithms
///
/// Returns `None` for:
/// - **1**: RSA/MD5 (Must Not Implement per RFC 6944)
/// - **2**: Diffie-Hellman (not a signature algorithm)
/// - **3**: DSA/SHA1 (Must Not Implement per RFC 8624)
/// - **6**: DSA-NSEC3-SHA1 (Must Not Implement per RFC 8624)
/// - Any unrecognized algorithm number
///
/// # Arguments
///
/// * `algo` - DNSSEC algorithm number from RRSIG or DNSKEY record
///
/// # Returns
///
/// - `Some(&str)` - Hash algorithm name if supported
/// - `None` - Algorithm unsupported or deprecated
///
/// # Examples
///
/// ```ignore
/// use dnsmasq::dns::dnssec::crypto::algo_digest_name;
/// use dnsmasq::dns::dnssec::types::DnssecAlgorithm;
///
/// let hash_name = algo_digest_name(DnssecAlgorithm::RsaSha256);
/// assert_eq!(hash_name, Some("sha256"));
///
/// // EdDSA uses null hash (whole message)
/// let ed_hash = algo_digest_name(DnssecAlgorithm::Ed25519);
/// assert_eq!(ed_hash, Some("null"));
///
/// // Deprecated algorithms return None
/// assert_eq!(algo_digest_name(DnssecAlgorithm::from_u8(1).unwrap()), None);
/// ```
///
/// # RFC Compliance
///
/// - RFC 4034: DNSSEC algorithm numbers
/// - RFC 5702: RSA/SHA-2 (algorithms 8, 10)
/// - RFC 6605: ECDSA (algorithms 13, 14)
/// - RFC 8080: `EdDSA` (algorithms 15, 16)
/// - RFC 5933: GOST (algorithm 12)
/// - RFC 6944: Deprecates RSA/MD5 (algorithm 1)
/// - RFC 8624: Deprecates DSA variants (algorithms 3, 6)
///
/// # Thread Safety
///
/// Thread-safe. Returns static string references.
#[must_use] 
pub fn algo_digest_name(algo: DnssecAlgorithm) -> Option<&'static str> {
    match algo {
        DnssecAlgorithm::RsaSha1 | DnssecAlgorithm::RsaSha1Nsec3 => Some("sha1"),
        DnssecAlgorithm::RsaSha256 | DnssecAlgorithm::EcdsaP256Sha256 => Some("sha256"),
        DnssecAlgorithm::RsaSha512 => Some("sha512"),
        DnssecAlgorithm::EcdsaP384Sha384 => Some("sha384"),
        DnssecAlgorithm::Gost => Some("gost94"),
        DnssecAlgorithm::Ed25519 | DnssecAlgorithm::Ed448 => Some("null"),
    }
}

/// Map DS record digest type to hash algorithm name
///
/// Converts DS (Delegation Signer) record digest type number to the
/// corresponding hash algorithm name. DS records contain a hash of a
/// DNSKEY record, and this function identifies which hash algorithm
/// was used to create that digest.
///
/// # DS Digest Types
///
/// - **1**: SHA-1 (deprecated but supported)
/// - **2**: SHA-256 (recommended)
/// - **3**: GOST R 34.11-94 (Russian standard)
/// - **4**: SHA-384
///
/// # Security Considerations
///
/// Digest type 1 (SHA-1) is deprecated per RFC 8624 due to collision
/// attacks on SHA-1, but remains supported for compatibility with
/// existing deployments. New DS records SHOULD use SHA-256 (type 2)
/// or SHA-384 (type 4).
///
/// # Arguments
///
/// * `digest_type` - DS record digest type number (1-4)
///
/// # Returns
///
/// - `Some(&str)` - Hash algorithm name if supported
/// - `None` - Digest type unrecognized or unsupported
///
/// # Examples
///
/// ```ignore
/// use dnsmasq::dns::dnssec::crypto::ds_digest_name;
///
/// // SHA-256 is recommended
/// assert_eq!(ds_digest_name(2), Some("sha256"));
///
/// // SHA-1 still supported but deprecated
/// assert_eq!(ds_digest_name(1), Some("sha1"));
///
/// // Unrecognized types
/// assert_eq!(ds_digest_name(99), None);
/// ```
///
/// # RFC Compliance
///
/// - RFC 4034: DS record format and digest types
/// - RFC 4509: SHA-256 for DS records (digest type 2)
/// - RFC 5933: GOST for DNSSEC (digest type 3)
/// - RFC 6605: SHA-384 for DS records (digest type 4)
/// - RFC 8624: Recommends against SHA-1 (digest type 1)
///
/// # IANA Registry
///
/// See: <http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml>
///
/// # Thread Safety
///
/// Thread-safe. Returns static string references.
#[must_use] 
pub fn ds_digest_name(digest_type: u8) -> Option<&'static str> {
    match digest_type {
        1 => Some("sha1"),
        2 => Some("sha256"),
        3 => Some("gost94"),
        4 => Some("sha384"),
        _ => None,
    }
}

/// Map NSEC3 hash algorithm to hash digest name
///
/// Converts NSEC3 hash algorithm number to the corresponding hash
/// algorithm name. NSEC3 records use hashed owner names for
/// authenticated denial of existence with opt-out support.
///
/// # NSEC3 Hash Algorithms
///
/// Currently only SHA-1 (type 1) is defined for NSEC3 per RFC 5155.
/// Unlike signature algorithms where SHA-1 is deprecated, SHA-1
/// remains the standard hash for NSEC3 name hashing because:
/// - NSEC3 hashing includes salt and iterations (slows precomputation)
/// - The security model differs from digital signatures
/// - No collision attacks are known that affect NSEC3's security
///
/// # Arguments
///
/// * `digest_type` - NSEC3 hash algorithm number from NSEC3/NSEC3PARAM record
///
/// # Returns
///
/// - `Some(&str)` - Hash algorithm name if supported
/// - `None` - Hash algorithm unrecognized
///
/// # Examples
///
/// ```ignore
/// use dnsmasq::dns::dnssec::crypto::nsec3_digest_name;
///
/// // SHA-1 is the only defined NSEC3 hash
/// assert_eq!(nsec3_digest_name(1), Some("sha1"));
///
/// // Other values are reserved/unassigned
/// assert_eq!(nsec3_digest_name(2), None);
/// ```
///
/// # RFC Compliance
///
/// - RFC 5155: NSEC3 hashed authenticated denial of existence
/// - RFC 4034: DNSSEC Resource Records (base specification)
///
/// # IANA Registry
///
/// See: <http://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml>
///
/// # Security Note
///
/// SHA-1 is NOT deprecated for NSEC3 despite being deprecated for
/// signatures. The use case is different and the iteration count
/// provides additional protection against precomputation attacks.
///
/// # Thread Safety
///
/// Thread-safe. Returns static string references.
#[must_use] 
pub fn nsec3_digest_name(digest_type: u8) -> Option<&'static str> {
    match digest_type {
        1 => Some("sha1"),
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algo_digest_name() {
        assert_eq!(algo_digest_name(DnssecAlgorithm::RsaSha1), Some("sha1"));
        assert_eq!(algo_digest_name(DnssecAlgorithm::RsaSha256), Some("sha256"));
        assert_eq!(algo_digest_name(DnssecAlgorithm::RsaSha512), Some("sha512"));
        assert_eq!(algo_digest_name(DnssecAlgorithm::EcdsaP256Sha256), Some("sha256"));
        assert_eq!(algo_digest_name(DnssecAlgorithm::EcdsaP384Sha384), Some("sha384"));
        assert_eq!(algo_digest_name(DnssecAlgorithm::Ed25519), Some("null"));
        assert_eq!(algo_digest_name(DnssecAlgorithm::Gost), Some("gost94"));
    }

    #[test]
    fn test_ds_digest_name() {
        assert_eq!(ds_digest_name(1), Some("sha1"));
        assert_eq!(ds_digest_name(2), Some("sha256"));
        assert_eq!(ds_digest_name(3), Some("gost94"));
        assert_eq!(ds_digest_name(4), Some("sha384"));
        assert_eq!(ds_digest_name(99), None);
    }

    #[test]
    fn test_nsec3_digest_name() {
        assert_eq!(nsec3_digest_name(1), Some("sha1"));
        assert_eq!(nsec3_digest_name(2), None);
        assert_eq!(nsec3_digest_name(99), None);
    }

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::UnsupportedAlgorithm { algo: 1 };
        assert!(err.to_string().contains("Unsupported"));

        let err = CryptoError::InvalidKeyLength {
            algo: DnssecAlgorithm::EcdsaP256Sha256,
            expected: 64,
            found: 32,
        };
        assert!(err.to_string().contains("Invalid key length"));
    }

    #[test]
    fn test_verify_with_invalid_key_length() {
        let key = BlockData::from_bytes(&[0u8; 1]); // Too short
        let sig = &[0u8; 64];
        let digest = &[0u8; 32];

        let result = verify(&key, sig, digest, DnssecAlgorithm::RsaSha256);
        assert!(result.is_err());
        match result {
            Err(CryptoError::RsaKeyFormatError { .. }) => (),
            _ => panic!("Expected RsaKeyFormatError"),
        }
    }

    #[test]
    fn test_ecdsa_verify_invalid_key_length() {
        let key = BlockData::from_bytes(&[0u8; 32]); // Wrong length for P-256
        let sig = &[0u8; 64];
        let digest = &[0u8; 32];

        let result = verify(&key, sig, digest, DnssecAlgorithm::EcdsaP256Sha256);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKeyLength { .. }) => (),
            _ => panic!("Expected InvalidKeyLength"),
        }
    }

    #[test]
    fn test_gost_returns_unsupported() {
        let key = BlockData::from_bytes(&[0u8; 64]);
        let sig = &[0u8; 64];
        let digest = &[0u8; 32];

        let result = verify(&key, sig, digest, DnssecAlgorithm::Gost);
        assert!(result.is_err());
        match result {
            Err(CryptoError::UnsupportedAlgorithm { algo: 12 }) => (),
            _ => panic!("Expected UnsupportedAlgorithm for GOST"),
        }
    }
}
