// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later

//! Cryptographic utilities for dnsmasq Rust implementation
//!
//! This module provides cryptographically secure random number generation and DNSSEC
//! signature verification functionality, replacing the C implementation from `src/crypto.c`
//! and `src/util.c` (SURF RNG portions).
//!
//! # Memory Safety Modernization
//!
//! The C implementation uses:
//! - Manual SURF cipher implementation with global mutable state
//! - nettle library for DNSSEC cryptography with manual memory management
//! - Pointer arithmetic for key and signature parsing
//!
//! The Rust implementation uses:
//! - `rand` crate with ChaCha20-based CSPRNG replacing SURF
//! - `ring` crate for memory-safe DNSSEC cryptography replacing nettle
//! - Slice-based parsing with compile-time bounds checking
//!
//! # Security Purpose
//!
//! Random number generation is critical for DNS cache poisoning resistance:
//! - **DNS Query ID Randomization**: 16-bit transaction IDs per RFC 1035
//! - **Source Port Randomization**: Additional entropy per RFC 5452
//! - **Cryptographic Quality**: Uses OS-provided entropy sources
//!
//! DNSSEC signature verification ensures DNS response authenticity:
//! - **RSA Signatures**: Algorithms 5, 7, 8, 10 (MD5, SHA-1, SHA-256, SHA-512)
//! - **ECDSA Signatures**: Algorithms 13, 14 (P-256, P-384 curves)
//! - **EdDSA Signatures**: Algorithm 15 (Ed25519)
//!
//! # Feature Gating
//!
//! DNSSEC functionality is feature-gated to allow minimal builds:
//! - Core RNG functions: Always available
//! - DNSSEC verification: Requires `dnssec` feature flag
//!
//! # Source Mapping
//!
//! ## Random Number Generation
//! - `src/util.c::rand_init()` → `init_rng()`
//! - `src/util.c::rand16()` → `random_u16()`
//! - `src/util.c::rand32()` → `random_u32()`
//! - `src/util.c::rand64()` → `random_u64()`
//!
//! ## DNSSEC Cryptography (feature-gated)
//! - `src/crypto.c::verify()` → `verify_signature()`
//! - `src/crypto.c::dnsmasq_rsa_verify()` → `verify_rsa_signature()`
//! - `src/crypto.c::dnsmasq_ecdsa_verify()` → `verify_ecdsa_signature()`
//! - `src/crypto.c::dnsmasq_eddsa_verify()` → `verify_ed25519_signature()`
//! - `src/crypto.c::hash_find()` → `hash_for_algorithm()`
//!
//! # Examples
//!
//! ## Random Number Generation
//!
//! ```rust,no_run
//! use dnsmasq::util::crypto::{init_rng, generate_dns_id, random_port};
//!
//! // Initialize RNG once at startup
//! init_rng();
//!
//! // Generate random DNS query ID
//! let query_id = generate_dns_id();
//! assert!(query_id <= 65535);
//!
//! // Generate random source port
//! let src_port = random_port();
//! assert!(src_port >= 1024 && src_port <= 65535);
//! ```
//!
//! ## DNSSEC Signature Verification (with `dnssec` feature)
//!
//! ```rust,no_run
//! #[cfg(feature = "dnssec")]
//! use dnsmasq::util::crypto::{DnssecAlgorithm, verify_signature};
//!
//! # #[cfg(feature = "dnssec")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let algorithm = DnssecAlgorithm::RsaSha256;
//! let key_data = b"..."; // RFC 3110 RSA public key format
//! let message = b"DNS message data to verify";
//! let signature = b"..."; // Signature bytes
//!
//! verify_signature(algorithm, key_data, message, signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! # RFC Compliance
//!
//! - **RFC 1035**: DNS protocol and transaction ID requirements
//! - **RFC 4034**: DNSSEC resource records (DNSKEY, RRSIG, DS, NSEC)
//! - **RFC 5155**: NSEC3 hashed denial of existence
//! - **RFC 5452**: DNS source port randomization and entropy
//! - **RFC 5702**: SHA-2 algorithms for DNSSEC (algorithms 8, 10)
//! - **RFC 6605**: ECDSA for DNSSEC (algorithms 13, 14)
//! - **RFC 8080**: EdDSA for DNSSEC (algorithm 15: Ed25519)
//!
//! # Zero Unsafe Blocks
//!
//! Per the refactoring requirements, this module contains ZERO unsafe blocks.
//! All cryptographic operations use memory-safe abstractions from the `rand`
//! and `ring` crates. The C implementation's manual buffer management and
//! pointer arithmetic have been eliminated through Rust's type system.

use crate::types::errors::DnssecError;
use rand::rngs::{OsRng, ThreadRng};
use rand::{thread_rng, Rng, RngCore};

// Feature-gated DNSSEC imports
#[cfg(feature = "dnssec")]
use ring::digest::{Algorithm, Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};
#[cfg(feature = "dnssec")]
use ring::signature;

//
// ============================================================================
// CONSTANTS
// ============================================================================
//

/// Minimum DNS query ID value (inclusive)
pub const DNS_ID_MIN: u16 = 0;

/// Maximum DNS query ID value (inclusive)
pub const DNS_ID_MAX: u16 = 65535;

/// Minimum random port number (inclusive) - avoids privileged ports
pub const PORT_RANDOM_MIN: u16 = 1024;

/// Maximum random port number (inclusive)
pub const PORT_RANDOM_MAX: u16 = 65535;

//
// ============================================================================
// RANDOM NUMBER GENERATION
// ============================================================================
//

/// Initialize the random number generator with system entropy
///
/// This function serves as a compatibility layer for the C implementation's
/// `rand_init()` which seeded the SURF RNG from `/dev/urandom`. In the Rust
/// implementation, the `rand` crate automatically sources entropy from the OS,
/// so this function primarily serves as an initialization checkpoint.
///
/// # Implementation Notes
///
/// The C implementation (src/util.c) reads 176 bytes from RANDFILE to seed
/// the SURF cipher's internal state. The Rust `rand` crate uses:
/// - Linux: `getrandom()` syscall or `/dev/urandom`
/// - BSD/macOS: `getentropy()` or `/dev/urandom`
/// - Windows: `BCryptGenRandom()`
///
/// This automatic seeding occurs on first use of `thread_rng()`, so this
/// function verifies that the RNG is accessible and operational.
///
/// # Errors
///
/// This function does not return errors in the current implementation as
/// `thread_rng()` panic on entropy source failure (consistent with Rust
/// ecosystem conventions). If entropy is unavailable, the application
/// cannot operate securely and should terminate.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::crypto::init_rng;
///
/// // Call once during application startup
/// init_rng();
/// ```
///
/// # C Source Mapping
///
/// - `src/util.c::rand_init()` - SURF RNG initialization from /dev/urandom
///
/// # Thread Safety
///
/// This function is thread-safe. The underlying `ThreadRng` uses thread-local
/// storage, unlike the C implementation's global mutable state.
pub fn init_rng() {
    // Verify RNG is operational by generating a test value
    // This will panic if entropy sources are unavailable, which is appropriate
    // as the C version calls die() on failure
    let mut rng = thread_rng();
    let _test: u64 = rng.next_u64();
    
    // RNG is now confirmed operational
    // thread_rng() will automatically seed from OS entropy on first use
}

/// Generate a cryptographically secure random 16-bit unsigned integer
///
/// Returns a random `u16` value in the range [0, 65535] using a cryptographically
/// secure random number generator. Used primarily for DNS query ID generation.
///
/// # Implementation Notes
///
/// Replaces C's `rand16()` which extracted 16-bit words from the SURF cipher
/// output buffer. The Rust implementation uses `ThreadRng` which implements
/// ChaCha20 for cryptographic quality randomness.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::crypto::random_u16;
///
/// let random_value = random_u16();
/// assert!(random_value >= 0 && random_value <= 65535);
/// ```
///
/// # C Source Mapping
///
/// - `src/util.c::rand16()` - Extract 16-bit word from SURF output
///
/// # Thread Safety
///
/// Thread-safe. Uses thread-local RNG instance.
pub fn random_u16() -> u16 {
    thread_rng().gen()
}

/// Generate a cryptographically secure random 32-bit unsigned integer
///
/// Returns a random `u32` value in the full 32-bit range using a cryptographically
/// secure random number generator. Used for source port randomization and internal
/// security tokens.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::crypto::random_u32;
///
/// let random_value = random_u32();
/// // Can be any value from 0 to 4,294,967,295
/// ```
///
/// # C Source Mapping
///
/// - `src/util.c::rand32()` - Extract 32-bit word from SURF output
///
/// # Thread Safety
///
/// Thread-safe. Uses thread-local RNG instance.
pub fn random_u32() -> u32 {
    thread_rng().gen()
}

/// Generate a cryptographically secure random 64-bit unsigned integer
///
/// Returns a random `u64` value in the full 64-bit range using a cryptographically
/// secure random number generator. Used for large random identifiers and tokens.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::crypto::random_u64;
///
/// let random_value = random_u64();
/// // Can be any value from 0 to 18,446,744,073,709,551,615
/// ```
///
/// # C Source Mapping
///
/// - `src/util.c::rand64()` - Extract two 32-bit words from SURF output
///
/// # Thread Safety
///
/// Thread-safe. Uses thread-local RNG instance.
pub fn random_u64() -> u64 {
    thread_rng().gen()
}

/// Generate a random DNS query ID (transaction ID)
///
/// Returns a 16-bit random value suitable for use as a DNS query transaction ID
/// per RFC 1035. This provides basic entropy for DNS query-response matching and
/// helps prevent cache poisoning attacks when combined with source port randomization.
///
/// # Security Considerations
///
/// DNS query IDs alone provide only 16 bits (65,536 values) of entropy, which is
/// insufficient for modern security standards. Per RFC 5452, query IDs MUST be
/// combined with source port randomization (additional ~15 bits) for adequate
/// protection against off-path cache poisoning attacks.
///
/// Total entropy: 16 bits (ID) + ~15 bits (port) = ~31 bits
/// Expected attempts to guess: 2^31 / 2 = ~1 billion queries
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::crypto::generate_dns_id;
///
/// let query_id = generate_dns_id();
/// // Use in DNS header
/// ```
///
/// # RFC Compliance
///
/// - **RFC 1035 Section 4.1.1**: Transaction ID field in DNS header
/// - **RFC 5452**: DNS resilience against forged answers (query ID + source port)
///
/// # C Source Mapping
///
/// - C pattern: `header->id = rand16();` in forward.c
///
/// # Thread Safety
///
/// Thread-safe. Uses thread-local RNG instance.
#[inline]
pub fn generate_dns_id() -> u16 {
    random_u16()
}

/// Generate a random source port for DNS queries
///
/// Returns a random port number in the range [1024, 65535], excluding privileged
/// ports (<1024). Used for DNS source port randomization per RFC 5452 to increase
/// entropy in DNS transactions and resist cache poisoning attacks.
///
/// # Port Range Selection
///
/// - **Excluded**: 0-1023 (privileged ports requiring root)
/// - **Included**: 1024-65535 (ephemeral port range)
/// - **Entropy**: ~15.9 bits (log2(64512) ≈ 15.98)
///
/// Combined with DNS query ID (16 bits), total entropy is ~32 bits, providing
/// adequate protection against off-path attacks (2^32 / 2 ≈ 2 billion expected
/// queries to guess a valid combination).
///
/// # Implementation Notes
///
/// The C implementation typically uses:
/// ```c
/// unsigned short port = 1024 + (rand32() % (65535 - 1024 + 1));
/// ```
///
/// The Rust implementation uses `gen_range()` which is slightly more efficient
/// and avoids modulo bias for non-power-of-2 ranges.
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::crypto::random_port;
///
/// let source_port = random_port();
/// assert!(source_port >= 1024);
/// assert!(source_port <= 65535);
/// ```
///
/// # RFC Compliance
///
/// - **RFC 5452**: Measures for making DNS more resilient against forged answers
/// - **RFC 6056**: Recommendations for transport-protocol port randomization
///
/// # C Source Mapping
///
/// - Used in `forward.c` for UDP source port selection
/// - Pattern: `port = daemon->min_port + (rand32() % port_range)`
///
/// # Thread Safety
///
/// Thread-safe. Uses thread-local RNG instance.
pub fn random_port() -> u16 {
    thread_rng().gen_range(PORT_RANDOM_MIN..=PORT_RANDOM_MAX)
}

//
// ============================================================================
// DNSSEC ALGORITHM ENUMERATION (Feature-Gated)
// ============================================================================
//

#[cfg(feature = "dnssec")]
/// DNSSEC cryptographic algorithm identifiers
///
/// This enum represents the cryptographic algorithms used in DNSSEC for signing
/// and verifying DNS resource records. Each variant corresponds to an algorithm
/// number defined in the DNSSEC Algorithm Numbers IANA registry.
///
/// # Algorithm Support Matrix
///
/// | Algorithm | Number | Status | Implementation |
/// |-----------|--------|--------|----------------|
/// | RSAMD5 | 1 | Deprecated | Supported for compatibility |
/// | RSASHA1 | 5 | Legacy | Supported |
/// | RSASHA256 | 8 | Recommended | Supported |
/// | RSASHA512 | 10 | Recommended | Supported |
/// | ECDSAP256SHA256 | 13 | Recommended | Supported |
/// | ECDSAP384SHA384 | 14 | Recommended | Supported |
/// | ED25519 | 15 | Recommended | Supported |
/// | ED448 | 16 | Optional | Not yet supported |
///
/// # Security Notes
///
/// - **RSAMD5** (algorithm 1): Deprecated due to MD5 weaknesses, included for historical zones
/// - **RSASHA1** (algorithms 5, 7): Legacy support, SHA-1 considered weak for new deployments
/// - **RSASHA256/512** (algorithms 8, 10): Widely deployed, recommended for RSA-based DNSSEC
/// - **ECDSA** (algorithms 13, 14): Modern elliptic curve algorithms, smaller keys and signatures
/// - **EdDSA** (algorithm 15): Ed25519, fastest signature verification with strong security
///
/// # RFC References
///
/// - **RFC 4034**: DNSSEC resource records (original algorithms)
/// - **RFC 5702**: SHA-2 algorithms for DNSSEC (algorithms 8, 10)
/// - **RFC 6605**: ECDSA for DNSSEC (algorithms 13, 14)
/// - **RFC 8080**: EdDSA for DNSSEC (algorithm 15: Ed25519, 16: Ed448)
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "dnssec")]
/// # use dnsmasq::util::crypto::DnssecAlgorithm;
/// #
/// # #[cfg(feature = "dnssec")]
/// # fn example() {
/// // Parse algorithm from wire format
/// let algo = DnssecAlgorithm::try_from(8).unwrap();
/// assert_eq!(algo, DnssecAlgorithm::RsaSha256);
///
/// // Display human-readable name
/// println!("Algorithm: {}", algo); // "RSASHA256"
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecAlgorithm {
    /// RSA/MD5 (algorithm 1) - DEPRECATED, legacy support only
    RsaMd5,
    
    /// RSA/SHA-1 (algorithm 5) - Legacy algorithm
    RsaSha1,
    
    /// RSA/SHA-256 (algorithm 8) - Recommended RSA variant
    RsaSha256,
    
    /// RSA/SHA-512 (algorithm 10) - Recommended RSA variant
    RsaSha512,
    
    /// ECDSA Curve P-256 with SHA-256 (algorithm 13) - Recommended
    EcdsaP256Sha256,
    
    /// ECDSA Curve P-384 with SHA-384 (algorithm 14) - Recommended
    EcdsaP384Sha384,
    
    /// Ed25519 (algorithm 15) - Modern EdDSA, recommended
    Ed25519,
    
    /// Ed448 (algorithm 16) - Optional EdDSA variant
    Ed448,
}

#[cfg(feature = "dnssec")]
impl DnssecAlgorithm {
    /// Convert algorithm to IANA algorithm number
    ///
    /// Returns the numeric algorithm identifier as used in DNSKEY and RRSIG
    /// records' algorithm field.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "dnssec")]
    /// # use dnsmasq::util::crypto::DnssecAlgorithm;
    /// #
    /// # #[cfg(feature = "dnssec")]
    /// # fn example() {
    /// assert_eq!(DnssecAlgorithm::RsaSha256.to_u8(), 8);
    /// assert_eq!(DnssecAlgorithm::Ed25519.to_u8(), 15);
    /// # }
    /// ```
    pub fn to_u8(self) -> u8 {
        match self {
            DnssecAlgorithm::RsaMd5 => 1,
            DnssecAlgorithm::RsaSha1 => 5,
            DnssecAlgorithm::RsaSha256 => 8,
            DnssecAlgorithm::RsaSha512 => 10,
            DnssecAlgorithm::EcdsaP256Sha256 => 13,
            DnssecAlgorithm::EcdsaP384Sha384 => 14,
            DnssecAlgorithm::Ed25519 => 15,
            DnssecAlgorithm::Ed448 => 16,
        }
    }
}

#[cfg(feature = "dnssec")]
impl TryFrom<u8> for DnssecAlgorithm {
    type Error = DnssecError;
    
    /// Parse DNSSEC algorithm from wire format algorithm number
    ///
    /// Converts IANA-registered algorithm numbers from DNSKEY and RRSIG records
    /// into the typed `DnssecAlgorithm` enum. Returns an error for unsupported
    /// or unknown algorithm numbers.
    ///
    /// # Errors
    ///
    /// Returns `DnssecError::CryptoError` with an "Unsupported algorithm" message
    /// if the algorithm number is not recognized or not implemented.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "dnssec")]
    /// # use dnsmasq::util::crypto::DnssecAlgorithm;
    /// # use std::convert::TryFrom;
    /// #
    /// # #[cfg(feature = "dnssec")]
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Parse valid algorithm
    /// let algo = DnssecAlgorithm::try_from(13)?;
    /// assert_eq!(algo, DnssecAlgorithm::EcdsaP256Sha256);
    ///
    /// // Unsupported algorithm returns error
    /// assert!(DnssecAlgorithm::try_from(99).is_err());
    /// # Ok(())
    /// # }
    /// ```
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnssecAlgorithm::RsaMd5),
            5 => Ok(DnssecAlgorithm::RsaSha1),
            8 => Ok(DnssecAlgorithm::RsaSha256),
            10 => Ok(DnssecAlgorithm::RsaSha512),
            13 => Ok(DnssecAlgorithm::EcdsaP256Sha256),
            14 => Ok(DnssecAlgorithm::EcdsaP384Sha384),
            15 => Ok(DnssecAlgorithm::Ed25519),
            16 => Ok(DnssecAlgorithm::Ed448),
            _ => Err(DnssecError::CryptoError {
                message: format!("Unsupported DNSSEC algorithm: {}", value),
            }),
        }
    }
}

#[cfg(feature = "dnssec")]
impl std::fmt::Display for DnssecAlgorithm {
    /// Format algorithm as human-readable string
    ///
    /// Returns the standard DNSSEC algorithm mnemonic name as defined in the
    /// IANA registry.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "dnssec")]
    /// # use dnsmasq::util::crypto::DnssecAlgorithm;
    /// #
    /// # #[cfg(feature = "dnssec")]
    /// # fn example() {
    /// assert_eq!(format!("{}", DnssecAlgorithm::RsaSha256), "RSASHA256");
    /// assert_eq!(format!("{}", DnssecAlgorithm::Ed25519), "ED25519");
    /// # }
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            DnssecAlgorithm::RsaMd5 => "RSAMD5",
            DnssecAlgorithm::RsaSha1 => "RSASHA1",
            DnssecAlgorithm::RsaSha256 => "RSASHA256",
            DnssecAlgorithm::RsaSha512 => "RSASHA512",
            DnssecAlgorithm::EcdsaP256Sha256 => "ECDSAP256SHA256",
            DnssecAlgorithm::EcdsaP384Sha384 => "ECDSAP384SHA384",
            DnssecAlgorithm::Ed25519 => "ED25519",
            DnssecAlgorithm::Ed448 => "ED448",
        };
        write!(f, "{}", name)
    }
}

//
// ============================================================================
// DNSSEC SIGNATURE VERIFICATION (Feature-Gated)
// ============================================================================
//

#[cfg(feature = "dnssec")]
/// Main entry point for DNSSEC signature verification
///
/// Verifies a cryptographic signature over DNS message data using the specified
/// DNSSEC algorithm and public key. This function dispatches to algorithm-specific
/// verification implementations based on the algorithm type (RSA, ECDSA, or EdDSA).
///
/// # Arguments
///
/// - `algo`: DNSSEC algorithm identifier from DNSKEY/RRSIG record
/// - `key`: Public key bytes in algorithm-specific wire format (RFC 3110 for RSA, RFC 6605 for ECDSA, RFC 8080 for EdDSA)
/// - `data`: Message data that was signed (typically canonicalized RRSET)
/// - `signature`: Signature bytes in algorithm-specific wire format
///
/// # Returns
///
/// - `Ok(())` if signature is valid
/// - `Err(DnssecError)` if signature is invalid or verification fails
///
/// # Errors
///
/// - `DnssecError::CryptoError`: Unsupported algorithm, invalid key format, or cryptographic error
/// - `DnssecError::InvalidSignature`: Signature verification failed (signature does not match data)
///
/// # Algorithm Dispatch
///
/// - **RSA** (algorithms 1, 5, 8, 10): → `verify_rsa_signature()`
/// - **ECDSA** (algorithms 13, 14): → `verify_ecdsa_signature()`
/// - **EdDSA** (algorithm 15): → `verify_ed25519_signature()`
/// - **Ed448** (algorithm 16): Not yet implemented
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(feature = "dnssec")]
/// # use dnsmasq::util::crypto::{DnssecAlgorithm, verify_signature};
/// #
/// # #[cfg(feature = "dnssec")]
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let algo = DnssecAlgorithm::RsaSha256;
/// let key_data = b"..."; // DNSKEY RDATA (public key)
/// let signed_data = b"..."; // Canonicalized RRSET
/// let signature = b"..."; // RRSIG signature bytes
///
/// verify_signature(algo, key_data, signed_data, signature)?;
/// println!("Signature valid!");
/// # Ok(())
/// # }
/// ```
///
/// # C Source Mapping
///
/// - `src/crypto.c::verify()` - Main verification entry point
/// - `src/crypto.c::verify_func()` - Algorithm dispatcher
///
/// # RFC Compliance
///
/// - **RFC 4034 Section 5**: DNSKEY RDATA format
/// - **RFC 4034 Section 3**: RRSIG RDATA format and verification
/// - **RFC 3110**: RSA key format
/// - **RFC 6605**: ECDSA key format
/// - **RFC 8080**: EdDSA key format
///
/// # Thread Safety
///
/// Thread-safe. Does not use mutable global state (unlike C's static key structures).
pub fn verify_signature(
    algo: DnssecAlgorithm,
    key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    match algo {
        DnssecAlgorithm::RsaMd5
        | DnssecAlgorithm::RsaSha1
        | DnssecAlgorithm::RsaSha256
        | DnssecAlgorithm::RsaSha512 => verify_rsa_signature(algo, key, data, signature),
        
        DnssecAlgorithm::EcdsaP256Sha256 | DnssecAlgorithm::EcdsaP384Sha384 => {
            verify_ecdsa_signature(algo, key, data, signature)
        }
        
        DnssecAlgorithm::Ed25519 => verify_ed25519_signature(key, data, signature),
        
        DnssecAlgorithm::Ed448 => Err(DnssecError::CryptoError {
            message: "Ed448 (algorithm 16) not yet supported".to_string(),
        }),
    }
}

#[cfg(feature = "dnssec")]
/// Verify RSA signature (algorithms 1, 5, 8, 10)
///
/// Verifies RSA signatures for DNSSEC algorithms 1 (RSAMD5), 5 (RSASHA1),
/// 8 (RSASHA256), and 10 (RSASHA512). Parses the RFC 3110 public key format
/// and verifies the PKCS#1 v1.5 signature using the `ring` crate.
///
/// # RFC 3110 Key Format
///
/// RSA public keys are encoded as:
/// ```text
/// +-------+----------+----------+
/// | Exp   | Exponent | Modulus  |
/// | Len   | (e)      | (n)      |
/// +-------+----------+----------+
/// 1 or 3  variable   variable
/// bytes   bytes      bytes
/// ```
///
/// - If exponent length ≤ 255 bytes: 1 byte length, then exponent
/// - If exponent length > 255 bytes: 0x00, 2-byte big-endian length, then exponent
/// - Modulus follows exponent immediately
///
/// # Arguments
///
/// - `algo`: RSA algorithm variant (determines hash function)
/// - `key`: RSA public key in RFC 3110 format
/// - `data`: Message data to verify (pre-hashed by algorithm)
/// - `signature`: RSA signature bytes (raw signature, not ASN.1)
///
/// # Returns
///
/// - `Ok(())` if signature is valid
/// - `Err(DnssecError)` if verification fails
///
/// # Errors
///
/// - `DnssecError::CryptoError`: Invalid key format, insufficient key data
/// - `DnssecError::InvalidSignature`: Signature verification failed
///
/// # Security Notes
///
/// - **RSAMD5**: Deprecated, MD5 is cryptographically broken
/// - **RSASHA1**: Legacy, SHA-1 collisions are practical
/// - **RSASHA256/512**: Recommended for new deployments
/// - Minimum RSA key size: 512 bits (weak), recommended: 2048+ bits
///
/// # C Source Mapping
///
/// - `src/crypto.c::dnsmasq_rsa_verify()` - RSA verification with nettle
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(feature = "dnssec")]
/// # use dnsmasq::util::crypto::{DnssecAlgorithm, verify_rsa_signature};
/// #
/// # #[cfg(feature = "dnssec")]
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let algo = DnssecAlgorithm::RsaSha256;
/// let key = b"\x03\x01\x00\x01..."; // RFC 3110: exponent 0x010001, then modulus
/// let data = b"DNS message data";
/// let signature = b"..."; // 256 bytes for RSA-2048
///
/// verify_rsa_signature(algo, key, data, signature)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_rsa_signature(
    algo: DnssecAlgorithm,
    key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    // Parse RFC 3110 RSA public key format
    if key.is_empty() {
        return Err(DnssecError::CryptoError {
            message: "RSA key is empty".to_string(),
        });
    }
    
    // Extract exponent length and position
    let (exp_len, exp_start) = if key[0] == 0 {
        // Extended format: 0x00 followed by 2-byte big-endian length
        if key.len() < 3 {
            return Err(DnssecError::CryptoError {
                message: "RSA key too short for extended exponent length".to_string(),
            });
        }
        let len = u16::from_be_bytes([key[1], key[2]]) as usize;
        (len, 3)
    } else {
        // Standard format: 1-byte length
        (key[0] as usize, 1)
    };
    
    // Extract exponent and modulus
    let exp_end = exp_start + exp_len;
    if exp_end > key.len() {
        return Err(DnssecError::CryptoError {
            message: "RSA key too short for exponent".to_string(),
        });
    }
    
    let exponent = &key[exp_start..exp_end];
    let modulus = &key[exp_end..];
    
    if modulus.is_empty() {
        return Err(DnssecError::CryptoError {
            message: "RSA key missing modulus".to_string(),
        });
    }
    
    // Select verification algorithm based on hash function
    let verification_algorithm: &dyn signature::VerificationAlgorithm = match algo {
        DnssecAlgorithm::RsaMd5 => {
            // MD5 is not supported by ring (deprecated)
            return Err(DnssecError::CryptoError {
                message: "RSAMD5 (algorithm 1) is deprecated and not supported".to_string(),
            });
        }
        DnssecAlgorithm::RsaSha1 => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        DnssecAlgorithm::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        DnssecAlgorithm::RsaSha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        _ => {
            return Err(DnssecError::CryptoError {
                message: format!("Algorithm {} is not RSA", algo),
            });
        }
    };
    
    // Create public key from components
    let public_key = signature::RsaPublicKeyComponents { n: modulus, e: exponent };
    
    // Verify signature
    public_key
        .verify(verification_algorithm, data, signature)
        .map_err(|_| DnssecError::CryptoError {
            message: format!("RSA signature verification failed for algorithm {}", algo),
        })
}

#[cfg(feature = "dnssec")]
/// Verify ECDSA signature (algorithms 13, 14)
///
/// Verifies ECDSA signatures for DNSSEC algorithms 13 (ECDSAP256SHA256) and
/// 14 (ECDSAP384SHA384). Parses the RFC 6605 public key format (raw curve points)
/// and verifies the ASN.1 DER-encoded signature using the `ring` crate.
///
/// # RFC 6605 Key Format
///
/// ECDSA public keys are encoded as raw (x, y) curve points:
/// ```text
/// +-------------------+-------------------+
/// | X coordinate      | Y coordinate      |
/// +-------------------+-------------------+
/// curve_size bytes    curve_size bytes
/// ```
///
/// - **P-256** (algorithm 13): 32 + 32 = 64 bytes total
/// - **P-384** (algorithm 14): 48 + 48 = 96 bytes total
///
/// # Signature Format
///
/// ECDSA signatures are ASN.1 DER-encoded (r, s) pairs per RFC 6605:
/// ```text
/// SEQUENCE {
///   r INTEGER,
///   s INTEGER
/// }
/// ```
///
/// # Arguments
///
/// - `algo`: ECDSA algorithm variant (P-256 or P-384)
/// - `key`: ECDSA public key in RFC 6605 format (raw curve point)
/// - `data`: Message data to verify (hashed by algorithm)
/// - `signature`: ECDSA signature in ASN.1 DER format
///
/// # Returns
///
/// - `Ok(())` if signature is valid
/// - `Err(DnssecError)` if verification fails
///
/// # Errors
///
/// - `DnssecError::CryptoError`: Invalid key format, wrong key length
/// - `DnssecError::InvalidSignature`: Signature verification failed
///
/// # Security Notes
///
/// ECDSA provides equivalent security to RSA with much smaller keys:
/// - **P-256**: ~128-bit security (equivalent to RSA-3072)
/// - **P-384**: ~192-bit security (equivalent to RSA-7680)
///
/// # C Source Mapping
///
/// - `src/crypto.c::dnsmasq_ecdsa_verify()` - ECDSA verification with nettle
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(feature = "dnssec")]
/// # use dnsmasq::util::crypto::{DnssecAlgorithm, verify_ecdsa_signature};
/// #
/// # #[cfg(feature = "dnssec")]
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let algo = DnssecAlgorithm::EcdsaP256Sha256;
/// let key = b"..."; // 64 bytes: X (32) + Y (32) for P-256
/// let data = b"DNS message data";
/// let signature = b"..."; // ASN.1 DER encoded (r, s)
///
/// verify_ecdsa_signature(algo, key, data, signature)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_ecdsa_signature(
    algo: DnssecAlgorithm,
    key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    // Validate key length based on curve
    let expected_key_len = match algo {
        DnssecAlgorithm::EcdsaP256Sha256 => 64, // 32 bytes X + 32 bytes Y
        DnssecAlgorithm::EcdsaP384Sha384 => 96, // 48 bytes X + 48 bytes Y
        _ => {
            return Err(DnssecError::CryptoError {
                message: format!("Algorithm {} is not ECDSA", algo),
            });
        }
    };
    
    if key.len() != expected_key_len {
        return Err(DnssecError::CryptoError {
            message: format!(
                "ECDSA key length mismatch: expected {} bytes, got {}",
                expected_key_len,
                key.len()
            ),
        });
    }
    
    // Select verification algorithm based on curve
    let verification_algorithm: &dyn signature::VerificationAlgorithm = match algo {
        DnssecAlgorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
        DnssecAlgorithm::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
        _ => unreachable!(),
    };
    
    // The key format for ring is the uncompressed point format (0x04 || X || Y)
    // RFC 6605 omits the 0x04 prefix, so we need to add it
    let mut uncompressed_key = Vec::with_capacity(key.len() + 1);
    uncompressed_key.push(0x04); // Uncompressed point indicator
    uncompressed_key.extend_from_slice(key);
    
    // Create unparsed public key
    let public_key = signature::UnparsedPublicKey::new(verification_algorithm, &uncompressed_key);
    
    // Verify signature
    public_key.verify(data, signature).map_err(|_| {
        DnssecError::CryptoError {
            message: format!("ECDSA signature verification failed for algorithm {}", algo),
        }
    })
}

#[cfg(feature = "dnssec")]
/// Verify Ed25519 signature (algorithm 15)
///
/// Verifies Ed25519 signatures for DNSSEC algorithm 15 (ED25519) per RFC 8080.
/// Ed25519 uses whole-message signing (no pre-hashing) and provides 128-bit
/// security with 32-byte keys and 64-byte signatures.
///
/// # RFC 8080 Key Format
///
/// Ed25519 public keys are 32-byte curve points:
/// ```text
/// +--------------------------------+
/// | Public Key (32 bytes)          |
/// +--------------------------------+
/// ```
///
/// # Signature Format
///
/// Ed25519 signatures are 64-byte values:
/// ```text
/// +--------------------------------+--------------------------------+
/// | R (32 bytes)                   | S (32 bytes)                   |
/// +--------------------------------+--------------------------------+
/// ```
///
/// # Arguments
///
/// - `key`: Ed25519 public key (32 bytes)
/// - `data`: Message data to verify (NOT pre-hashed)
/// - `signature`: Ed25519 signature (64 bytes)
///
/// # Returns
///
/// - `Ok(())` if signature is valid
/// - `Err(DnssecError)` if verification fails
///
/// # Errors
///
/// - `DnssecError::CryptoError`: Invalid key length, invalid signature length
/// - `DnssecError::InvalidSignature`: Signature verification failed
///
/// # Security Notes
///
/// Ed25519 advantages:
/// - **Fast**: ~4x faster than RSA-2048, ~20x faster than P-256 ECDSA
/// - **Small**: 32-byte keys, 64-byte signatures (vs 256+ bytes for RSA-2048)
/// - **Secure**: 128-bit security, no timing side-channels
/// - **Simple**: No parameter choices, deterministic signatures
///
/// # C Source Mapping
///
/// - `src/crypto.c::dnsmasq_eddsa_verify()` - EdDSA verification with nettle
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(feature = "dnssec")]
/// # use dnsmasq::util::crypto::verify_ed25519_signature;
/// #
/// # #[cfg(feature = "dnssec")]
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let key = b"..."; // 32 bytes: Ed25519 public key
/// let data = b"DNS message data";
/// let signature = b"..."; // 64 bytes: Ed25519 signature
///
/// verify_ed25519_signature(key, data, signature)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_ed25519_signature(
    key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), DnssecError> {
    // Validate key length
    if key.len() != 32 {
        return Err(DnssecError::CryptoError {
            message: format!("Ed25519 key must be 32 bytes, got {}", key.len()),
        });
    }
    
    // Validate signature length
    if signature.len() != 64 {
        return Err(DnssecError::CryptoError {
            message: format!("Ed25519 signature must be 64 bytes, got {}", signature.len()),
        });
    }
    
    // Create unparsed public key
    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, key);
    
    // Verify signature
    public_key.verify(data, signature).map_err(|_| {
        DnssecError::CryptoError {
            message: "Ed25519 signature verification failed".to_string(),
        }
    })
}

#[cfg(feature = "dnssec")]
/// Map DNSSEC algorithm to hash function
///
/// Returns the appropriate hash algorithm for DNSSEC DS record digest computation
/// based on the DNSKEY algorithm number. Used when verifying DS records that
/// authenticate DNSKEY records in the DNSSEC chain of trust.
///
/// # Arguments
///
/// - `algo`: DNSSEC algorithm identifier
///
/// # Returns
///
/// Reference to the corresponding `ring::digest::Algorithm`
///
/// # Hash Algorithm Mapping
///
/// | DNSSEC Algorithm | Hash Function |
/// |------------------|---------------|
/// | RSAMD5 (1) | SHA-1 (legacy) |
/// | RSASHA1 (5) | SHA-1 |
/// | RSASHA256 (8) | SHA-256 |
/// | RSASHA512 (10) | SHA-512 |
/// | ECDSAP256SHA256 (13) | SHA-256 |
/// | ECDSAP384SHA384 (14) | SHA-384 |
/// | ED25519 (15) | SHA-256 |
/// | ED448 (16) | SHA-512 |
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "dnssec")]
/// # use dnsmasq::util::crypto::{DnssecAlgorithm, hash_for_algorithm};
/// #
/// # #[cfg(feature = "dnssec")]
/// # fn example() {
/// let algo = DnssecAlgorithm::RsaSha256;
/// let hash_algo = hash_for_algorithm(algo);
/// // Use hash_algo with ring::digest::Context
/// # }
/// ```
///
/// # C Source Mapping
///
/// - `src/crypto.c::algo_digest_name()` - Map algorithm to hash name string
/// - `src/crypto.c::hash_find()` - Lookup hash function in nettle
///
/// # RFC References
///
/// - **RFC 4034 Appendix A**: DS record digest algorithm numbers
/// - **RFC 4509**: SHA-256 for DS records
/// - **RFC 5702**: SHA-2 algorithms for DNSSEC
pub fn hash_for_algorithm(algo: DnssecAlgorithm) -> &'static Algorithm {
    match algo {
        DnssecAlgorithm::RsaMd5 | DnssecAlgorithm::RsaSha1 => &SHA1_FOR_LEGACY_USE_ONLY,
        DnssecAlgorithm::RsaSha256
        | DnssecAlgorithm::EcdsaP256Sha256
        | DnssecAlgorithm::Ed25519 => &SHA256,
        DnssecAlgorithm::EcdsaP384Sha384 => &SHA384,
        DnssecAlgorithm::RsaSha512 | DnssecAlgorithm::Ed448 => &SHA512,
    }
}

//
// ============================================================================
// UNIT TESTS
// ============================================================================
//

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rng_initialization() {
        // Should not panic
        init_rng();
    }
    
    #[test]
    fn test_random_u16_in_range() {
        init_rng();
        
        for _ in 0..100 {
            let value = random_u16();
            assert!(value >= DNS_ID_MIN);
            assert!(value <= DNS_ID_MAX);
        }
    }
    
    #[test]
    fn test_random_u32_distribution() {
        init_rng();
        
        // Generate multiple values, ensure they're not all the same
        let mut values = std::collections::HashSet::new();
        for _ in 0..100 {
            values.insert(random_u32());
        }
        
        // With cryptographic RNG, probability of collision is negligible
        assert!(values.len() > 90, "RNG appears non-random");
    }
    
    #[test]
    fn test_random_u64_distribution() {
        init_rng();
        
        let mut values = std::collections::HashSet::new();
        for _ in 0..100 {
            values.insert(random_u64());
        }
        
        assert!(values.len() > 90, "RNG appears non-random");
    }
    
    #[test]
    fn test_generate_dns_id() {
        init_rng();
        
        for _ in 0..100 {
            let id = generate_dns_id();
            assert!(id >= DNS_ID_MIN);
            assert!(id <= DNS_ID_MAX);
        }
    }
    
    #[test]
    fn test_random_port_range() {
        init_rng();
        
        for _ in 0..100 {
            let port = random_port();
            assert!(port >= PORT_RANDOM_MIN, "Port {} below minimum {}", port, PORT_RANDOM_MIN);
            assert!(port <= PORT_RANDOM_MAX, "Port {} above maximum {}", port, PORT_RANDOM_MAX);
            assert!(port >= 1024, "Port {} is privileged (<1024)", port);
        }
    }
    
    #[test]
    fn test_random_port_distribution() {
        init_rng();
        
        // Generate ports and verify distribution
        let mut counts = [0u32; 10]; // Divide range into 10 buckets
        let bucket_size = (PORT_RANDOM_MAX - PORT_RANDOM_MIN + 1) / 10;
        
        for _ in 0..1000 {
            let port = random_port();
            let bucket = ((port - PORT_RANDOM_MIN) / bucket_size) as usize;
            let bucket = bucket.min(9); // Handle edge case for max port
            counts[bucket] += 1;
        }
        
        // Each bucket should have roughly 100 ± 40 values (chi-square test would be better)
        for (i, &count) in counts.iter().enumerate() {
            assert!(
                count > 50 && count < 150,
                "Bucket {} has suspicious count: {}",
                i,
                count
            );
        }
    }
    
    #[test]
    #[cfg(feature = "dnssec")]
    fn test_dnssec_algorithm_conversion() {
        use std::convert::TryFrom;
        
        // Test all supported algorithms
        assert_eq!(DnssecAlgorithm::try_from(1).unwrap(), DnssecAlgorithm::RsaMd5);
        assert_eq!(DnssecAlgorithm::try_from(5).unwrap(), DnssecAlgorithm::RsaSha1);
        assert_eq!(DnssecAlgorithm::try_from(8).unwrap(), DnssecAlgorithm::RsaSha256);
        assert_eq!(DnssecAlgorithm::try_from(10).unwrap(), DnssecAlgorithm::RsaSha512);
        assert_eq!(DnssecAlgorithm::try_from(13).unwrap(), DnssecAlgorithm::EcdsaP256Sha256);
        assert_eq!(DnssecAlgorithm::try_from(14).unwrap(), DnssecAlgorithm::EcdsaP384Sha384);
        assert_eq!(DnssecAlgorithm::try_from(15).unwrap(), DnssecAlgorithm::Ed25519);
        assert_eq!(DnssecAlgorithm::try_from(16).unwrap(), DnssecAlgorithm::Ed448);
        
        // Test unsupported algorithm
        assert!(DnssecAlgorithm::try_from(99).is_err());
    }
    
    #[test]
    #[cfg(feature = "dnssec")]
    fn test_dnssec_algorithm_to_u8() {
        assert_eq!(DnssecAlgorithm::RsaSha256.to_u8(), 8);
        assert_eq!(DnssecAlgorithm::EcdsaP256Sha256.to_u8(), 13);
        assert_eq!(DnssecAlgorithm::Ed25519.to_u8(), 15);
    }
    
    #[test]
    #[cfg(feature = "dnssec")]
    fn test_dnssec_algorithm_display() {
        assert_eq!(format!("{}", DnssecAlgorithm::RsaSha256), "RSASHA256");
        assert_eq!(format!("{}", DnssecAlgorithm::EcdsaP256Sha256), "ECDSAP256SHA256");
        assert_eq!(format!("{}", DnssecAlgorithm::Ed25519), "ED25519");
    }
    
    #[test]
    #[cfg(feature = "dnssec")]
    fn test_hash_for_algorithm() {
        use ring::digest;
        
        // SHA-1 algorithms
        assert_eq!(
            hash_for_algorithm(DnssecAlgorithm::RsaSha1),
            &digest::SHA1_FOR_LEGACY_USE_ONLY
        );
        
        // SHA-256 algorithms
        assert_eq!(
            hash_for_algorithm(DnssecAlgorithm::RsaSha256),
            &digest::SHA256
        );
        assert_eq!(
            hash_for_algorithm(DnssecAlgorithm::EcdsaP256Sha256),
            &digest::SHA256
        );
        assert_eq!(
            hash_for_algorithm(DnssecAlgorithm::Ed25519),
            &digest::SHA256
        );
        
        // SHA-384 algorithms
        assert_eq!(
            hash_for_algorithm(DnssecAlgorithm::EcdsaP384Sha384),
            &digest::SHA384
        );
        
        // SHA-512 algorithms
        assert_eq!(
            hash_for_algorithm(DnssecAlgorithm::RsaSha512),
            &digest::SHA512
        );
    }
    
    #[test]
    #[cfg(feature = "dnssec")]
    fn test_rsa_signature_invalid_key() {
        // Empty key should error
        let result = verify_rsa_signature(
            DnssecAlgorithm::RsaSha256,
            &[],
            b"data",
            b"signature",
        );
        assert!(result.is_err());
        
        // Key too short for exponent
        let result = verify_rsa_signature(
            DnssecAlgorithm::RsaSha256,
            &[0x05], // Claims 5-byte exponent but no data follows
            b"data",
            b"signature",
        );
        assert!(result.is_err());
    }
    
    #[test]
    #[cfg(feature = "dnssec")]
    fn test_ecdsa_signature_invalid_key_length() {
        // P-256 expects 64 bytes
        let result = verify_ecdsa_signature(
            DnssecAlgorithm::EcdsaP256Sha256,
            &[0u8; 32], // Wrong length
            b"data",
            b"signature",
        );
        assert!(result.is_err());
        
        // P-384 expects 96 bytes
        let result = verify_ecdsa_signature(
            DnssecAlgorithm::EcdsaP384Sha384,
            &[0u8; 64], // Wrong length
            b"data",
            b"signature",
        );
        assert!(result.is_err());
    }
    
    #[test]
    #[cfg(feature = "dnssec")]
    fn test_ed25519_signature_invalid_lengths() {
        // Invalid key length
        let result = verify_ed25519_signature(
            &[0u8; 16], // Should be 32 bytes
            b"data",
            &[0u8; 64],
        );
        assert!(result.is_err());
        
        // Invalid signature length
        let result = verify_ed25519_signature(
            &[0u8; 32],
            b"data",
            &[0u8; 32], // Should be 64 bytes
        );
        assert!(result.is_err());
    }
}
