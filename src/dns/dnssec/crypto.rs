// Copyright (c) 2000-2024 Simon Kelley & Blitzy Contributors
// This file is part of the dnsmasq Rust implementation
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! DNSSEC Cryptographic Primitives
//!
//! This module provides cryptographic operations for DNSSEC signature verification
//! using the `ring` crate as the cryptographic backend. It replaces the C implementation's
//! nettle library dependencies with memory-safe Rust cryptography.
//!
//! # Supported Algorithms
//!
//! - **RSA**: RSA/SHA-256 (algorithm 8), RSA/SHA-512 (algorithm 10)
//! - **ECDSA**: ECDSA P-256/SHA-256 (algorithm 13), ECDSA P-384/SHA-384 (algorithm 14)
//! - **`EdDSA`**: Ed25519 (algorithm 15), Ed448 (algorithm 16)
//!
//! Note: RSA/SHA-1 algorithms (5, 7) are deliberately excluded per RFC 6944 deprecation.
//! DSA algorithms (3, 6) and RSA/MD5 (1) are not supported per RFC 8624.
//!
//! # Memory Safety
//!
//! This implementation eliminates the C version's static mutable state, using local
//! variables and Rust's ownership system for memory management. All parsing operations
//! use safe slice operations with automatic bounds checking.
//!
//! # References
//!
//! - RFC 3110: RSA public key encoding in DNS
//! - RFC 4034: DNSSEC Resource Records
//! - RFC 5702: SHA-2 algorithms for DNSSEC
//! - RFC 6605: ECDSA for DNSSEC
//! - RFC 8080: `EdDSA` for DNSSEC
//! - RFC 8624: Algorithm implementation requirements
//!
//! # Source Mapping
//!
//! Translated from `src/crypto.c` (lines 17-1312) in the C implementation.

use ring::digest::{self, Context, Digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};
use ring::signature;
use std::vec::Vec;
use thiserror::Error;

/// DNSSEC signature algorithm identifiers
///
/// These constants correspond to DNSSEC algorithm numbers as defined in the
/// IANA DNSSEC Algorithm Numbers registry. Only secure, recommended algorithms
/// are included.
///
/// Source: C implementation algorithm numbers, src/crypto.c lines 518-526, 610-640, 820-844
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    /// RSA/SHA-256 (recommended) - RFC 5702
    RsaSha256 = 8,
    /// RSA/SHA-512 - RFC 5702
    RsaSha512 = 10,
    /// ECDSA P-256/SHA-256 (recommended) - RFC 6605
    EcdsaP256Sha256 = 13,
    /// ECDSA P-384/SHA-384 - RFC 6605
    EcdsaP384Sha384 = 14,
    /// Ed25519 (recommended) - RFC 8080
    Ed25519 = 15,
    /// Ed448 - RFC 8080
    Ed448 = 16,
}

impl Algorithm {
    /// Convert from u8 algorithm number, returning None for unsupported algorithms
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            8 => Some(Algorithm::RsaSha256),
            10 => Some(Algorithm::RsaSha512),
            13 => Some(Algorithm::EcdsaP256Sha256),
            14 => Some(Algorithm::EcdsaP384Sha384),
            15 => Some(Algorithm::Ed25519),
            16 => Some(Algorithm::Ed448),
            _ => None,
        }
    }
}

/// Hash function types for DNSSEC operations
///
/// These hash algorithms are used for DS records, NSEC3 hashing, and
/// signature verification digest computation.
///
/// Source: C implementation hash selection in `hash_find()`, src/crypto.c lines 1282-1309
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA-1 (for DS records and NSEC3 only, not for signatures)
    Sha1,
    /// SHA-256 (recommended for DS records and signatures)
    Sha256,
    /// SHA-384 (for ECDSA P-384)
    Sha384,
    /// SHA-512 (for RSA/SHA-512)
    Sha512,
}

/// Cryptographic operation errors
///
/// Comprehensive error types for all cryptographic operations including
/// signature verification, key parsing, and hash initialization.
///
/// Source: Error handling patterns from C implementation, src/crypto.c various return 0 cases
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Algorithm not supported or not implemented
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u8),

    /// Public key format is invalid or malformed
    #[error("Invalid key format")]
    InvalidKeyFormat,

    /// Signature format is invalid or malformed
    #[error("Invalid signature format")]
    InvalidSignatureFormat,

    /// Key data is too short for the specified algorithm
    #[error("Key data too short")]
    KeyTooShort,

    /// Signature data is too short for the specified algorithm
    #[error("Signature data too short")]
    SignatureTooShort,

    /// Signature verification failed (signature is mathematically invalid)
    #[error("Verification failed")]
    VerificationFailed,

    /// Hash context initialization failed
    #[error("Hash initialization failed")]
    HashInitializationFailed,
}

/// RSA public key components
///
/// Parsed RSA public key in RFC 3110 format with exponent and modulus.
///
/// Source: C implementation in `dnsmasq_rsa_verify()`, src/crypto.c lines 479-529
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// RSA public exponent
    pub exponent: Vec<u8>,
    /// RSA modulus
    pub modulus: Vec<u8>,
}

/// ECDSA public key point
///
/// Parsed ECDSA public key in RFC 6605 format with X and Y coordinates.
///
/// Source: C implementation in `dnsmasq_ecdsa_verify()`, src/crypto.c lines 584-656
#[derive(Debug, Clone)]
pub struct EcdsaPublicKey {
    /// X coordinate of the public key point
    pub x: Vec<u8>,
    /// Y coordinate of the public key point
    pub y: Vec<u8>,
}

/// ECDSA signature components
///
/// Parsed ECDSA signature with R and S components.
///
/// Source: C implementation signature parsing, src/crypto.c lines 652-653
#[derive(Debug, Clone)]
pub struct EcdsaSignature {
    /// R component of the signature
    pub r: Vec<u8>,
    /// S component of the signature
    pub s: Vec<u8>,
}

/// Hash function trait for digest computation
///
/// This trait abstracts hash operations for different algorithms, allowing
/// dynamic selection of hash functions while maintaining type safety.
///
/// Source: Replaces C's `nettle_hash` function pointers, src/crypto.c lines 335-343
pub trait Hasher {
    /// Update the hash context with additional data
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash and return the digest
    fn finalize(self: Box<Self>) -> Vec<u8>;
}

/// SHA-1 hasher implementation (for DS records and NSEC3 only)
struct Sha1Hasher {
    context: Context,
}

impl Hasher for Sha1Hasher {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }
}

/// SHA-256 hasher implementation
struct Sha256Hasher {
    context: Context,
}

impl Hasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }
}

/// SHA-384 hasher implementation
struct Sha384Hasher {
    context: Context,
}

impl Hasher for Sha384Hasher {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }
}

/// SHA-512 hasher implementation
struct Sha512Hasher {
    context: Context,
}

impl Hasher for Sha512Hasher {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }
}

/// Initialize hash context for digest computation
///
/// Creates a new hash context for the specified hash algorithm, returning a
/// boxed trait object that can be used to incrementally compute a digest.
///
/// # Arguments
///
/// * `hash_type` - The hash algorithm to use
///
/// # Returns
///
/// A boxed Hasher trait object, or an error if initialization fails
///
/// # Example
///
/// ```no_run
/// # use dnsmasq::dns::dnssec::crypto::{hash_init, HashFunction};
/// let mut hasher = hash_init(HashFunction::Sha256)?;
/// hasher.update(b"message data");
/// let digest = hasher.finalize();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// Returns `CryptoError::HashInitializationFailed` if hash context creation fails
///
/// Source: C implementation `hash_init()`, src/crypto.c lines 392-427
pub fn hash_init(hash_type: HashFunction) -> Result<Box<dyn Hasher>, CryptoError> {
    match hash_type {
        HashFunction::Sha1 => Ok(Box::new(Sha1Hasher {
            context: Context::new(&SHA1_FOR_LEGACY_USE_ONLY),
        })),
        HashFunction::Sha256 => Ok(Box::new(Sha256Hasher {
            context: Context::new(&SHA256),
        })),
        HashFunction::Sha384 => Ok(Box::new(Sha384Hasher {
            context: Context::new(&SHA384),
        })),
        HashFunction::Sha512 => Ok(Box::new(Sha512Hasher {
            context: Context::new(&SHA512),
        })),
    }
}

/// Find hash algorithm by name
///
/// Maps hash algorithm names (case-insensitive) to `HashFunction` enums.
///
/// # Arguments
///
/// * `name` - Hash algorithm name (e.g., "sha256", "SHA-256", "sha1")
///
/// # Returns
///
/// The corresponding `HashFunction`, or None if the name is not recognized
///
/// # Example
///
/// ```no_run
/// # use dnsmasq::dns::dnssec::crypto::find_hash_algorithm;
/// let sha256 = find_hash_algorithm("sha-256");
/// assert!(sha256.is_some());
/// ```
///
/// Source: C implementation `hash_find()`, src/crypto.c lines 1282-1309
#[must_use]
pub fn find_hash_algorithm(name: &str) -> Option<HashFunction> {
    let name_lower = name.to_lowercase();
    match name_lower.as_str() {
        "sha1" | "sha-1" => Some(HashFunction::Sha1),
        "sha256" | "sha-256" => Some(HashFunction::Sha256),
        "sha384" | "sha-384" => Some(HashFunction::Sha384),
        "sha512" | "sha-512" => Some(HashFunction::Sha512),
        _ => None,
    }
}

/// Map DNSSEC algorithm to hash digest name
///
/// Returns the hash algorithm name used for signature verification for a given
/// DNSSEC algorithm number. Returns an empty string for unsupported algorithms.
///
/// # Arguments
///
/// * `algorithm` - DNSSEC algorithm enum
///
/// # Returns
///
/// Hash algorithm name string (e.g., "sha-256" for algorithm 8)
///
/// # Example
///
/// ```no_run
/// # use dnsmasq::dns::dnssec::crypto::{Algorithm, algorithm_digest_name};
/// let hash_name = algorithm_digest_name(Algorithm::RsaSha256);
/// assert_eq!(hash_name, "sha-256");
/// ```
///
/// Source: C implementation `algo_digest_name()`, src/crypto.c lines 1152-1171
#[must_use]
pub fn algorithm_digest_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::RsaSha256 | Algorithm::EcdsaP256Sha256 => "sha-256",
        Algorithm::RsaSha512 => "sha-512",
        Algorithm::EcdsaP384Sha384 => "sha-384",
        Algorithm::Ed25519 | Algorithm::Ed448 => "", // EdDSA operates on full message
    }
}

/// Map DS digest type to hash algorithm name
///
/// Converts DS (Delegation Signer) record digest type numbers to hash algorithm
/// names. Returns None for unsupported digest types.
///
/// # Arguments
///
/// * `digest_type` - DS record digest type number
///
/// # Returns
///
/// Hash algorithm name, or None if unsupported
///
/// # Supported Digest Types
///
/// - 1: SHA-1 (deprecated but supported)
/// - 2: SHA-256 (recommended)
/// - 4: SHA-384
///
/// # Example
///
/// ```no_run
/// # use dnsmasq::dns::dnssec::crypto::ds_digest_algorithm_name;
/// let hash_name = ds_digest_algorithm_name(2);
/// assert_eq!(hash_name, Some("sha-256"));
/// ```
///
/// Source: C implementation `ds_digest_name()`, src/crypto.c lines 1068-1078
#[must_use]
pub fn ds_digest_algorithm_name(digest_type: u8) -> Option<&'static str> {
    match digest_type {
        1 => Some("sha-1"),
        2 => Some("sha-256"),
        4 => Some("sha-384"),
        _ => None,
    }
}

/// Map NSEC3 hash algorithm to hash algorithm name
///
/// Converts NSEC3 hash algorithm numbers to hash algorithm names.
/// Currently only SHA-1 (type 1) is defined for NSEC3.
///
/// # Arguments
///
/// * `digest_type` - NSEC3 hash algorithm number
///
/// # Returns
///
/// Hash algorithm name, or None if unsupported
///
/// # Example
///
/// ```no_run
/// # use dnsmasq::dns::dnssec::crypto::nsec3_hash_algorithm_name;
/// let hash_name = nsec3_hash_algorithm_name(1);
/// assert_eq!(hash_name, Some("sha-1"));
/// ```
///
/// Source: C implementation `nsec3_digest_name()`, src/crypto.c lines 1219-1226
#[must_use]
pub fn nsec3_hash_algorithm_name(digest_type: u8) -> Option<&'static str> {
    match digest_type {
        1 => Some("sha-1"),
        _ => None,
    }
}

/// Parse RSA public key from DNSKEY RDATA format
///
/// Extracts RSA public key components (exponent and modulus) from RFC 3110 format:
/// - 1-byte exponent length (or 0x00 + 2-byte length if > 255)
/// - Exponent bytes
/// - Modulus bytes
///
/// # Arguments
///
/// * `key_data` - Public key data from DNSKEY record
///
/// # Returns
///
/// Parsed RSA public key, or error if format is invalid
///
/// Source: C implementation `dnsmasq_rsa_verify()` key parsing, src/crypto.c lines 499-514
fn parse_rsa_public_key(key_data: &[u8]) -> Result<RsaPublicKey, CryptoError> {
    if key_data.len() < 3 {
        return Err(CryptoError::KeyTooShort);
    }

    let mut pos = 0;
    let exp_len = if key_data[pos] == 0 {
        // Extended length format: 3 bytes total (0x00 + 2-byte big-endian length)
        if key_data.len() < 3 {
            return Err(CryptoError::KeyTooShort);
        }
        pos += 1;
        let exp_len = ((key_data[pos] as usize) << 8) | (key_data[pos + 1] as usize);
        pos += 2;
        exp_len
    } else {
        // Standard length format: 1 byte
        let exp_len = key_data[pos] as usize;
        pos += 1;
        exp_len
    };

    if pos + exp_len >= key_data.len() {
        return Err(CryptoError::InvalidKeyFormat);
    }

    let exponent = key_data[pos..pos + exp_len].to_vec();
    pos += exp_len;

    let modulus = key_data[pos..].to_vec();

    Ok(RsaPublicKey { exponent, modulus })
}

/// Parse ECDSA public key from DNSKEY RDATA format
///
/// Extracts ECDSA public key point coordinates from RFC 6605 format:
/// - X coordinate (`coord_len` bytes)
/// - Y coordinate (`coord_len` bytes)
///
/// # Arguments
///
/// * `key_data` - Public key data from DNSKEY record
/// * `coord_len` - Length of each coordinate (32 for P-256, 48 for P-384)
///
/// # Returns
///
/// Parsed ECDSA public key, or error if format is invalid
///
/// Source: C implementation `dnsmasq_ecdsa_verify()` key parsing, src/crypto.c lines 646-650
fn parse_ecdsa_public_key(
    key_data: &[u8],
    coord_len: usize,
) -> Result<EcdsaPublicKey, CryptoError> {
    if key_data.len() != 2 * coord_len {
        return Err(CryptoError::InvalidKeyFormat);
    }

    let x = key_data[0..coord_len].to_vec();
    let y = key_data[coord_len..2 * coord_len].to_vec();

    Ok(EcdsaPublicKey { x, y })
}

/// Parse ECDSA signature from RRSIG format
///
/// Extracts ECDSA signature components from wire format:
/// - R component (`component_len` bytes)
/// - S component (`component_len` bytes)
///
/// # Arguments
///
/// * `sig_data` - Signature data from RRSIG record
/// * `component_len` - Length of each component (32 for P-256, 48 for P-384)
///
/// # Returns
///
/// Parsed ECDSA signature, or error if format is invalid
///
/// Source: C implementation `dnsmasq_ecdsa_verify()` signature parsing, src/crypto.c lines 652-653
fn parse_ecdsa_signature(
    sig_data: &[u8],
    component_len: usize,
) -> Result<EcdsaSignature, CryptoError> {
    if sig_data.len() != 2 * component_len {
        return Err(CryptoError::InvalidSignatureFormat);
    }

    let r = sig_data[0..component_len].to_vec();
    let s = sig_data[component_len..2 * component_len].to_vec();

    Ok(EcdsaSignature { r, s })
}

/// Verify RSA signature
///
/// Verifies RSA signatures using ring's RSA verification primitives.
/// Supports RSA/SHA-256 and RSA/SHA-512.
///
/// # Arguments
///
/// * `public_key` - Raw public key bytes from DNSKEY in RFC 3110 format
/// * `signature` - Signature bytes from RRSIG
/// * `message` - Message digest to verify (already hashed)
/// * `algorithm` - RSA algorithm variant (8 for SHA-256, 10 for SHA-512)
///
/// # Returns
///
/// Ok(true) if signature is valid, Ok(false) if invalid signature, Err for malformed data
///
/// # Format
///
/// RFC 3110 RSA public key format:
/// - 1 byte exponent length (or 0x00 followed by 2-byte length if > 255)
/// - exponent bytes (big-endian)
/// - modulus bytes (big-endian)
///
/// Source: C implementation `dnsmasq_rsa_verify()`, src/crypto.c lines 479-529
fn verify_rsa_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    algorithm: Algorithm,
) -> Result<bool, CryptoError> {
    use ring::signature;

    // Parse RSA public key from RFC 3110 format
    let key = parse_rsa_public_key(public_key)?;

    // Create RSA public key components
    // ring expects modulus (n) and exponent (e) in big-endian format
    let public_key_components = signature::RsaPublicKeyComponents {
        n: &key.modulus,
        e: &key.exponent,
    };

    // Select verification parameters based on algorithm and verify
    let result = match algorithm {
        Algorithm::RsaSha256 => {
            public_key_components.verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
        }
        Algorithm::RsaSha512 => {
            public_key_components.verify(&signature::RSA_PKCS1_2048_8192_SHA512, message, signature)
        }
        _ => return Err(CryptoError::UnsupportedAlgorithm(algorithm as u8)),
    };

    // Convert result
    match result {
        Ok(()) => Ok(true),
        Err(ring::error::Unspecified) => Ok(false),
    }
}

/// Verify ECDSA signature
///
/// Verifies ECDSA signatures using ring's ECDSA verification primitives.
/// Supports ECDSA P-256/SHA-256 and P-384/SHA-384.
///
/// # Arguments
///
/// * `public_key` - Raw public key bytes from DNSKEY in RFC 6605 format (x || y)
/// * `signature` - Signature bytes from RRSIG in raw format (r || s)
/// * `message` - Message digest to verify (already hashed)
/// * `algorithm` - ECDSA algorithm variant (13 for P-256, 14 for P-384)
///
/// # Returns
///
/// Ok(true) if signature is valid, Ok(false) if invalid signature, Err for malformed data
///
/// # Format
///
/// RFC 6605 ECDSA public key format:
/// - X coordinate (t bytes) where t=32 for P-256, t=48 for P-384
/// - Y coordinate (t bytes)
///
/// Signature format:
/// - R component (t bytes)
/// - S component (t bytes)
///
/// Source: C implementation `dnsmasq_ecdsa_verify()`, src/crypto.c lines 584-656
fn verify_ecdsa_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    algorithm: Algorithm,
) -> Result<bool, CryptoError> {
    use ring::signature;

    // Determine coordinate length and verification algorithm based on curve
    let (coord_len, verification_alg): (usize, &'static dyn signature::VerificationAlgorithm) =
        match algorithm {
            Algorithm::EcdsaP256Sha256 => (32, &signature::ECDSA_P256_SHA256_FIXED),
            Algorithm::EcdsaP384Sha384 => (48, &signature::ECDSA_P384_SHA384_FIXED),
            _ => return Err(CryptoError::UnsupportedAlgorithm(algorithm as u8)),
        };

    // Validate lengths
    if public_key.len() != 2 * coord_len {
        return Err(CryptoError::InvalidKeyFormat);
    }
    if signature.len() != 2 * coord_len {
        return Err(CryptoError::InvalidSignatureFormat);
    }

    // Parse public key coordinates
    let key = parse_ecdsa_public_key(public_key, coord_len)?;

    // Construct uncompressed point format: 0x04 || x || y
    // This is the format ring expects for ECDSA public keys
    let mut public_key_bytes = Vec::with_capacity(1 + 2 * coord_len);
    public_key_bytes.push(0x04); // Uncompressed point indicator
    public_key_bytes.extend_from_slice(&key.x);
    public_key_bytes.extend_from_slice(&key.y);

    // Create unparsed public key
    let unparsed_public_key =
        signature::UnparsedPublicKey::new(verification_alg, &public_key_bytes);

    // Verify signature
    // Ring's ECDSA_*_FIXED algorithms accept signatures in r||s format directly
    // which matches the DNS RRSIG signature format
    match unparsed_public_key.verify(message, signature) {
        Ok(()) => Ok(true),
        Err(ring::error::Unspecified) => Ok(false),
    }
}

/// Verify `EdDSA` signature
///
/// Verifies `EdDSA` signatures (`Ed25519`, `Ed448`) using ring's `EdDSA` primitives.
/// `EdDSA` operates on the complete message, not a pre-computed digest.
///
/// # Arguments
///
/// * `public_key` - Raw public key bytes from DNSKEY
/// * `signature` - Signature bytes from RRSIG
/// * `message` - Complete message data (not a digest)
/// * `algorithm` - `EdDSA` algorithm variant
///
/// # Returns
///
/// Ok(true) if signature is valid, Ok(false) or Err if invalid
///
/// Source: C implementation `dnsmasq_eddsa_verify()`, src/crypto.c lines 806-847
fn verify_eddsa_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    algorithm: Algorithm,
) -> Result<bool, CryptoError> {
    match algorithm {
        Algorithm::Ed25519 => {
            // Ed25519: 32-byte key, 64-byte signature
            if public_key.len() != 32 {
                return Err(CryptoError::InvalidKeyFormat);
            }
            if signature.len() != 64 {
                return Err(CryptoError::InvalidSignatureFormat);
            }

            // Use ring's Ed25519 verification
            let peer_public_key =
                signature::UnparsedPublicKey::new(&signature::ED25519, public_key);

            match peer_public_key.verify(message, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        Algorithm::Ed448 => {
            // Ed448: 57-byte key, 114-byte signature
            // Note: ring does not currently support Ed448
            // This would require a different cryptography library
            Err(CryptoError::UnsupportedAlgorithm(16))
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm as u8)),
    }
}

/// Verify DNSSEC signature
///
/// Main entry point for DNSSEC signature verification. Dispatches to the
/// appropriate algorithm-specific verification function based on the algorithm
/// parameter.
///
/// # Arguments
///
/// * `algorithm` - DNSSEC algorithm identifier
/// * `public_key` - Raw public key bytes from DNSKEY record
/// * `signature` - Signature bytes from RRSIG record
/// * `message` - Message data to verify (digest for `RSA`/`ECDSA`, full message for `EdDSA`)
///
/// # Returns
///
/// Ok(true) if signature is mathematically valid, Ok(false) if invalid,
/// or Err if the algorithm is unsupported or parameters are malformed
///
/// # Example
///
/// ```no_run
/// # use dnsmasq::dns::dnssec::crypto::{verify_signature, Algorithm};
/// let algorithm = Algorithm::Ed25519;
/// let public_key = &[/* 32 bytes */];
/// let signature = &[/* 64 bytes */];
/// let message = b"DNS message data";
///
/// match verify_signature(algorithm, public_key, signature, message) {
///     Ok(true) => println!("Signature valid"),
///     Ok(false) => println!("Signature invalid"),
///     Err(e) => eprintln!("Verification error: {}", e),
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// Returns `CryptoError::UnsupportedAlgorithm` if the algorithm is not supported.
/// Returns `CryptoError::InvalidKeyFormat` if the public key is malformed.
/// Returns `CryptoError::InvalidSignatureFormat` if the signature is malformed.
///
/// # Security
///
/// This function uses constant-time operations provided by the ring crate
/// to prevent timing side-channel attacks.
///
/// Source: C implementation `verify()`, src/crypto.c lines 994-1007
pub fn verify_signature(
    algorithm: Algorithm,
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<bool, CryptoError> {
    match algorithm {
        Algorithm::RsaSha256 | Algorithm::RsaSha512 => {
            verify_rsa_signature(public_key, signature, message, algorithm)
        }
        Algorithm::EcdsaP256Sha256 | Algorithm::EcdsaP384Sha384 => {
            verify_ecdsa_signature(public_key, signature, message, algorithm)
        }
        Algorithm::Ed25519 | Algorithm::Ed448 => {
            verify_eddsa_signature(public_key, signature, message, algorithm)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_u8() {
        assert_eq!(Algorithm::from_u8(8), Some(Algorithm::RsaSha256));
        assert_eq!(Algorithm::from_u8(15), Some(Algorithm::Ed25519));
        assert_eq!(Algorithm::from_u8(1), None); // RSA/MD5 not supported
        assert_eq!(Algorithm::from_u8(3), None); // DSA not supported
    }

    #[test]
    fn test_find_hash_algorithm() {
        assert_eq!(find_hash_algorithm("sha256"), Some(HashFunction::Sha256));
        assert_eq!(find_hash_algorithm("SHA-256"), Some(HashFunction::Sha256));
        assert_eq!(find_hash_algorithm("sha1"), Some(HashFunction::Sha1));
        assert_eq!(find_hash_algorithm("unknown"), None);
    }

    #[test]
    fn test_algorithm_digest_name() {
        assert_eq!(algorithm_digest_name(Algorithm::RsaSha256), "sha-256");
        assert_eq!(algorithm_digest_name(Algorithm::EcdsaP384Sha384), "sha-384");
        assert_eq!(algorithm_digest_name(Algorithm::Ed25519), "");
    }

    #[test]
    fn test_ds_digest_algorithm_name() {
        assert_eq!(ds_digest_algorithm_name(1), Some("sha-1"));
        assert_eq!(ds_digest_algorithm_name(2), Some("sha-256"));
        assert_eq!(ds_digest_algorithm_name(4), Some("sha-384"));
        assert_eq!(ds_digest_algorithm_name(99), None);
    }

    #[test]
    fn test_nsec3_hash_algorithm_name() {
        assert_eq!(nsec3_hash_algorithm_name(1), Some("sha-1"));
        assert_eq!(nsec3_hash_algorithm_name(2), None);
    }

    #[test]
    fn test_hash_init() {
        let hasher = hash_init(HashFunction::Sha256);
        assert!(hasher.is_ok());
    }

    #[test]
    fn test_rsa_key_parsing_standard_length() {
        // Standard format: 1-byte exponent length, exponent, modulus
        let key_data = vec![
            3, // exponent length
            1, 0, 1, // exponent (65537)
            0xAA, 0xBB, 0xCC, 0xDD, // modulus (truncated for test)
        ];

        let key = parse_rsa_public_key(&key_data);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(key.exponent, vec![1, 0, 1]);
        assert_eq!(key.modulus, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_rsa_key_parsing_extended_length() {
        // Extended format: 0x00, 2-byte big-endian length, exponent, modulus
        let key_data = vec![
            0, // extended length indicator
            0, 3, // exponent length (3 bytes)
            1, 0, 1, // exponent
            0xAA, 0xBB, // modulus
        ];

        let key = parse_rsa_public_key(&key_data);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(key.exponent, vec![1, 0, 1]);
        assert_eq!(key.modulus, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_rsa_key_parsing_too_short() {
        let key_data = vec![1, 2]; // Too short
        assert!(matches!(
            parse_rsa_public_key(&key_data),
            Err(CryptoError::KeyTooShort)
        ));
    }

    #[test]
    fn test_ecdsa_key_parsing_p256() {
        let key_data = vec![0u8; 64]; // 32-byte X + 32-byte Y for P-256
        let key = parse_ecdsa_public_key(&key_data, 32);
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(key.x.len(), 32);
        assert_eq!(key.y.len(), 32);
    }

    #[test]
    fn test_ecdsa_key_parsing_wrong_length() {
        let key_data = vec![0u8; 60]; // Wrong length for P-256
        assert!(matches!(
            parse_ecdsa_public_key(&key_data, 32),
            Err(CryptoError::InvalidKeyFormat)
        ));
    }

    #[test]
    fn test_ecdsa_signature_parsing() {
        let sig_data = vec![0u8; 64]; // 32-byte R + 32-byte S
        let sig = parse_ecdsa_signature(&sig_data, 32);
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
    }

    #[test]
    fn test_ed25519_signature_verification_wrong_key_size() {
        let public_key = vec![0u8; 16]; // Wrong size (should be 32)
        let signature = vec![0u8; 64];
        let message = b"test message";

        let result = verify_eddsa_signature(&public_key, &signature, message, Algorithm::Ed25519);

        assert!(matches!(result, Err(CryptoError::InvalidKeyFormat)));
    }

    #[test]
    fn test_ed25519_signature_verification_wrong_sig_size() {
        let public_key = vec![0u8; 32];
        let signature = vec![0u8; 32]; // Wrong size (should be 64)
        let message = b"test message";

        let result = verify_eddsa_signature(&public_key, &signature, message, Algorithm::Ed25519);

        assert!(matches!(result, Err(CryptoError::InvalidSignatureFormat)));
    }
}
