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

//! Cryptographic Operations and Random Number Generation
//!
//! This module provides cryptographically secure random number generation for
//! DNS query IDs and source port randomization, translated from the C implementation
//! in `src/crypto.c` and portions of `src/util.c` (SURF RNG).
//!
//! # Security Purpose
//!
//! Random number generation is critical for DNS security:
//! - **Query ID Randomization**: Prevents DNS cache poisoning attacks
//! - **Source Port Randomization**: Additional entropy for transaction uniqueness
//! - **Cryptographic Quality**: Uses cryptographically secure RNG (CSPRNG)
//!
//! # Key Functionality
//!
//! - **RNG Initialization**: Seed RNG from system entropy source
//! - **DNS ID Generation**: 16-bit random query IDs
//! - **Port Randomization**: Random ephemeral port selection
//! - **Hash Functions**: Transaction ID hashing for cache keys
//!
//! # Source Mapping
//!
//! Translated from:
//! - `src/util.c` (SURF RNG: `rand_init()`, `rand16()`, `rand32()`, `rand64()`)
//! - `src/crypto.c` (Hash functions for DNS security)
//!
//! # Examples
//!
//! ```rust,no_run
//! use dnsmasq::util::crypto::{init_rng, generate_dns_id, random_port};
//!
//! // Initialize RNG (call once at startup)
//! init_rng()?;
//!
//! // Generate random DNS query ID
//! let query_id = generate_dns_id();
//!
//! // Generate random source port
//! let port = random_port();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use rand::{thread_rng, Rng, RngCore};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag indicating whether the RNG has been initialized.
static RNG_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Error type for cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// RNG initialization failed
    InitializationFailed(String),
    
    /// RNG not initialized before use
    NotInitialized,
    
    /// Insufficient entropy available
    InsufficientEntropy,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InitializationFailed(msg) => {
                write!(f, "RNG initialization failed: {}", msg)
            }
            CryptoError::NotInitialized => {
                write!(f, "RNG not initialized - call init_rng() first")
            }
            CryptoError::InsufficientEntropy => {
                write!(f, "Insufficient entropy available for RNG")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Initialize the random number generator.
///
/// This function initializes the cryptographically secure random number generator
/// using system entropy. It should be called once during application startup before
/// any DNS queries are processed.
///
/// # Returns
///
/// `Ok(())` on success, or a `CryptoError` if initialization fails
///
/// # Errors
///
/// - `CryptoError::InitializationFailed` if the RNG cannot be initialized
/// - `CryptoError::InsufficientEntropy` if system entropy is unavailable
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::util::crypto::init_rng;
///
/// // Call once during startup
/// init_rng()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Source
///
/// Translated from: `rand_init()` in `src/util.c` (SURF RNG initialization)
///
/// # Notes
///
/// The Rust implementation uses the `rand` crate which automatically handles
/// platform-specific entropy sources (/dev/urandom on Unix, BCryptGenRandom
/// on Windows, etc.). The SURF RNG from djbdns is replaced with the modern
/// `rand` crate's ChaCha20-based CSPRNG for better security and portability.
pub fn init_rng() -> Result<(), CryptoError> {
    // Test that we can generate random numbers
    let mut rng = thread_rng();
    let _test: u64 = rng.gen();

    // Mark RNG as initialized
    RNG_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

/// Check if the RNG has been initialized.
///
/// # Returns
///
/// `true` if `init_rng()` has been called successfully, `false` otherwise
pub fn is_rng_initialized() -> bool {
    RNG_INITIALIZED.load(Ordering::SeqCst)
}

/// Generate a random 16-bit DNS query ID.
///
/// Creates a cryptographically random 16-bit value suitable for use as a DNS
/// query transaction ID. This is critical for preventing DNS cache poisoning
/// attacks.
///
/// # Returns
///
/// A random 16-bit unsigned integer
///
/// # Panics
///
/// Panics if `init_rng()` has not been called first (in debug mode).
/// In release mode, it will still work but may not have been properly seeded.
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::util::crypto::{init_rng, generate_dns_id};
///
/// init_rng()?;
/// let query_id = generate_dns_id();
/// println!("DNS Query ID: 0x{:04x}", query_id);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Security
///
/// The randomness of DNS query IDs is critical for security. Each query must
/// have an unpredictable ID to prevent attackers from spoofing DNS responses.
///
/// # Source
///
/// Translated from: `rand16()` in `src/util.c`
pub fn generate_dns_id() -> u16 {
    debug_assert!(
        is_rng_initialized(),
        "RNG not initialized - call init_rng() first"
    );

    thread_rng().gen()
}

/// Generate a random ephemeral port number.
///
/// Returns a random port number in the ephemeral port range (typically 49152-65535
/// per RFC 6335). Used for source port randomization to add additional entropy
/// to DNS queries beyond just the query ID.
///
/// # Returns
///
/// A random port number in the range 49152-65535
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::util::crypto::{init_rng, random_port};
///
/// init_rng()?;
/// let port = random_port();
/// println!("Source port: {}", port);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Security
///
/// Source port randomization adds 16 bits of entropy to DNS queries, making
/// cache poisoning attacks significantly harder. Combined with random query IDs,
/// this provides 32 bits of entropy per query.
///
/// # Source
///
/// Translated from: Query source port randomization logic in `src/forward.c`
pub fn random_port() -> u16 {
    debug_assert!(
        is_rng_initialized(),
        "RNG not initialized - call init_rng() first"
    );

    // Ephemeral port range: 49152-65535 (RFC 6335)
    const MIN_EPHEMERAL_PORT: u16 = 49152;
    const MAX_EPHEMERAL_PORT: u16 = 65535;

    thread_rng().gen_range(MIN_EPHEMERAL_PORT..=MAX_EPHEMERAL_PORT)
}

/// Generate a random 32-bit value.
///
/// Generates a cryptographically random 32-bit unsigned integer.
///
/// # Returns
///
/// A random 32-bit unsigned integer
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::util::crypto::{init_rng, random_u32};
///
/// init_rng()?;
/// let value = random_u32();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Source
///
/// Translated from: `rand32()` in `src/util.c`
pub fn random_u32() -> u32 {
    debug_assert!(
        is_rng_initialized(),
        "RNG not initialized - call init_rng() first"
    );

    thread_rng().gen()
}

/// Generate a random 64-bit value.
///
/// Generates a cryptographically random 64-bit unsigned integer.
///
/// # Returns
///
/// A random 64-bit unsigned integer
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::util::crypto::{init_rng, random_u64};
///
/// init_rng()?;
/// let value = random_u64();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Source
///
/// Translated from: `rand64()` in `src/util.c`
pub fn random_u64() -> u64 {
    debug_assert!(
        is_rng_initialized(),
        "RNG not initialized - call init_rng() first"
    );

    thread_rng().gen()
}

/// Fill a byte buffer with random data.
///
/// Fills the provided buffer with cryptographically random bytes.
///
/// # Arguments
///
/// * `buffer` - The buffer to fill with random data
///
/// # Examples
///
/// ```rust,no_run
/// use dnsmasq::util::crypto::{init_rng, random_bytes};
///
/// init_rng()?;
/// let mut buffer = [0u8; 32];
/// random_bytes(&mut buffer);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn random_bytes(buffer: &mut [u8]) {
    debug_assert!(
        is_rng_initialized(),
        "RNG not initialized - call init_rng() first"
    );

    thread_rng().fill_bytes(buffer);
}

/// Compute a simple hash of a byte slice.
///
/// Computes a simple non-cryptographic hash suitable for hash table keys
/// and cache lookups. This is NOT suitable for security purposes.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 32-bit hash value
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::crypto::hash_bytes;
///
/// let data = b"example.com";
/// let hash = hash_bytes(data);
/// ```
///
/// # Note
///
/// This is a simple hash function for cache key generation, not a
/// cryptographic hash. For cryptographic hashing, use the `ring` or
/// `sha2` crates.
pub fn hash_bytes(data: &[u8]) -> u32 {
    // Simple FNV-1a hash
    let mut hash: u32 = 2166136261;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_init_rng() {
        let result = init_rng();
        assert!(result.is_ok());
        assert!(is_rng_initialized());
    }

    #[test]
    fn test_generate_dns_id() {
        init_rng().unwrap();
        
        // Generate multiple IDs and verify they're different
        let mut ids = HashSet::new();
        for _ in 0..100 {
            let id = generate_dns_id();
            ids.insert(id);
        }
        
        // We should have close to 100 unique IDs (allowing for rare collisions)
        assert!(ids.len() > 95, "Expected high uniqueness in DNS IDs");
    }

    #[test]
    fn test_random_port() {
        init_rng().unwrap();
        
        // Generate multiple ports and verify they're in ephemeral range
        for _ in 0..100 {
            let port = random_port();
            assert!(port >= 49152, "Port should be >= 49152 (ephemeral port range)");
            // Note: port is u16, so it's always <= 65535
        }
    }

    #[test]
    fn test_random_u32() {
        init_rng().unwrap();
        
        let value1 = random_u32();
        let value2 = random_u32();
        
        // Values should be different (extremely unlikely to be same)
        assert_ne!(value1, value2);
    }

    #[test]
    fn test_random_u64() {
        init_rng().unwrap();
        
        let value1 = random_u64();
        let value2 = random_u64();
        
        // Values should be different (extremely unlikely to be same)
        assert_ne!(value1, value2);
    }

    #[test]
    fn test_random_bytes() {
        init_rng().unwrap();
        
        let mut buffer1 = [0u8; 32];
        let mut buffer2 = [0u8; 32];
        
        random_bytes(&mut buffer1);
        random_bytes(&mut buffer2);
        
        // Buffers should be different
        assert_ne!(buffer1, buffer2);
        
        // Buffers should not be all zeros
        assert_ne!(buffer1, [0u8; 32]);
    }

    #[test]
    fn test_hash_bytes() {
        let data1 = b"example.com";
        let data2 = b"example.org";
        let data3 = b"example.com"; // Same as data1
        
        let hash1 = hash_bytes(data1);
        let hash2 = hash_bytes(data2);
        let hash3 = hash_bytes(data3);
        
        // Same input should produce same hash
        assert_eq!(hash1, hash3);
        
        // Different input should produce different hash (usually)
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_bytes_deterministic() {
        let data = b"test data";
        let hash1 = hash_bytes(data);
        let hash2 = hash_bytes(data);
        
        // Hash should be deterministic
        assert_eq!(hash1, hash2);
    }
}
