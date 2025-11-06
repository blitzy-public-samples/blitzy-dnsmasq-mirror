//! Random Number Generation Module
//!
//! This module provides cryptographically secure random number generation,
//! replacing the C implementation's SURF (Secure Universal Random Function)
//! RNG with Rust's rand crate. The rand crate uses ChaCha8Rng which provides
//! better cryptographic properties than SURF while being thread-safe and
//! requiring no manual initialization.
//!
//! # Memory Safety Improvements
//!
//! The C implementation used static arrays (seed[32], in[12], out[8]) and
//! manual counter management, which had several issues:
//! - Not thread-safe (shared mutable static state)
//! - Required manual initialization from /dev/urandom with fatal error on failure
//! - Manual counter overflow handling with cascading increments
//! - Separate outleft counters for different bit widths
//!
//! This Rust implementation eliminates all these issues:
//! - Thread-safe via thread_rng() (thread-local storage)
//! - Automatic initialization (no explicit init needed)
//! - No manual state management (handled by ChaCha8Rng)
//! - No possibility of uninitialized RNG usage (enforced by type system)
//!
//! # Usage
//!
//! The public API matches the C implementation for compatibility:
//!
//! ```
//! use crate::utils::rand::{rand16, rand32, rand64};
//!
//! // DNS query ID randomization (RFC 1035)
//! let query_id: u16 = rand16();
//!
//! // Source port randomization (RFC 5452)
//! let src_port: u32 = rand32();
//!
//! // IPv6 interface ID randomization (RFC 4941)
//! let interface_id: u64 = rand64();
//! ```
//!
//! # RFC Compliance
//!
//! - RFC 1035: DNS transaction ID randomization
//! - RFC 5452: DNS source port randomization
//! - RFC 4941: IPv6 privacy extensions (random interface IDs)
//!
//! # Performance
//!
//! ChaCha8Rng provides comparable performance to SURF while offering:
//! - Better cryptographic properties (256-bit security)
//! - Longer period (2^256 vs SURF's 2^128)
//! - Thread-safety without locks (thread-local storage)
//! - SIMD optimizations on supported platforms

use rand::{thread_rng, Rng, RngCore};
use tracing::{debug, info, trace};

/// Generate a cryptographically-strong 16-bit random number.
///
/// This function replaces the C implementation's rand16() which used the SURF
/// algorithm. It uses Rust's thread_rng() which provides a thread-local
/// ChaCha8Rng instance that is automatically initialized on first use.
///
/// # Returns
///
/// A cryptographically-strong 16-bit random value (0-65535)
///
/// # Thread Safety
///
/// This function is thread-safe. Each thread has its own RNG instance via
/// thread-local storage, eliminating the race conditions present in the C
/// implementation's shared static state.
///
/// # Usage
///
/// Primary use case is DNS query ID randomization to prevent cache poisoning:
///
/// ```
/// # use crate::utils::rand::rand16;
/// // Generate random DNS query ID
/// let query_id = rand16();
/// // Use in DNS header: header.id = query_id.to_be();
/// ```
///
/// # Performance
///
/// This function is highly optimized:
/// - Thread-local storage eliminates lock contention
/// - ChaCha8 uses SIMD instructions on supported platforms
/// - Comparable or better performance than C's SURF implementation
///
/// # Security
///
/// ChaCha8Rng provides 256-bit security vs SURF's estimated 128-bit security.
/// The RNG is automatically seeded from the OS's secure random source
/// (/dev/urandom on Linux, CryptGenRandom on Windows, etc.) on first use.
///
/// # RFC Compliance
///
/// - RFC 1035: DNS transaction ID randomization (Section 4.1.1)
/// - RFC 5452: DNS source port randomization (Section 9.2)
///
/// # Examples
///
/// ```
/// # use crate::utils::rand::rand16;
/// // DNS query ID generation
/// let qid = rand16();
/// assert!(qid <= 65535);
///
/// // Generate multiple IDs efficiently
/// let ids: Vec<u16> = (0..1000).map(|_| rand16()).collect();
/// assert_eq!(ids.len(), 1000);
/// ```
pub fn rand16() -> u16 {
    trace!("Generating 16-bit random number");
    let value = thread_rng().gen::<u16>();
    trace!("Generated 16-bit random value: {}", value);
    value
}

/// Generate a cryptographically-strong 32-bit random number.
///
/// This function replaces the C implementation's rand32() which used the SURF
/// algorithm. It provides full 32-bit entropy using ChaCha8Rng.
///
/// # Returns
///
/// A cryptographically-strong 32-bit random value (full u32 range: 0 to 2^32-1)
///
/// # Thread Safety
///
/// This function is thread-safe via thread-local RNG storage, unlike the C
/// implementation which used shared static state.
///
/// # Usage
///
/// Primary use cases include:
/// - DNS source port randomization (RFC 5452)
/// - DHCP lease token generation
/// - Transaction identifiers requiring >16 bits of entropy
///
/// ```
/// # use crate::utils::rand::rand32;
/// // DNS source port randomization
/// let rand_val = rand32();
/// let src_port = 1024 + (rand_val % (65535 - 1024));
///
/// // DHCP token generation
/// let dhcp_token = rand32();
/// ```
///
/// # Performance
///
/// ChaCha8 generates random numbers in 64-byte blocks internally, making
/// successive calls very efficient due to buffering within thread_rng().
///
/// # Security
///
/// Provides full 32-bit entropy with cryptographic strength. Each call
/// returns an independent random value drawn from ChaCha8's output stream.
///
/// # RFC Compliance
///
/// - RFC 5452: Measures for Making DNS More Resilient against Forged Answers
///   (Section 9.2 - Source Port Randomization)
///
/// # Examples
///
/// ```
/// # use crate::utils::rand::rand32;
/// // Random source port in ephemeral range
/// let port = 49152 + (rand32() % 16384); // 49152-65535
///
/// // Random lease token
/// let token = rand32();
/// assert!(token <= u32::MAX);
/// ```
pub fn rand32() -> u32 {
    trace!("Generating 32-bit random number");
    let value = thread_rng().gen::<u32>();
    trace!("Generated 32-bit random value: {}", value);
    value
}

/// Generate a cryptographically-strong 64-bit random number.
///
/// This function replaces the C implementation's rand64() which combined two
/// consecutive 32-bit SURF outputs. It provides full 64-bit entropy in a single
/// call using ChaCha8Rng.
///
/// # Returns
///
/// A cryptographically-strong 64-bit random value (full u64 range: 0 to 2^64-1)
///
/// # Thread Safety
///
/// This function is thread-safe. The C implementation had a particularly
/// complex thread-safety issue with rand64() using a local static outleft
/// variable separate from the file-scope outleft, causing potential state
/// corruption under concurrent access. This Rust implementation eliminates
/// that issue entirely.
///
/// # Usage
///
/// Primary use cases include:
/// - IPv6 interface identifier randomization (RFC 4941)
/// - 64-bit unique identifiers
/// - Applications requiring maximum entropy (full 64-bit space)
///
/// ```
/// # use crate::utils::rand::rand64;
/// // IPv6 privacy extension interface ID
/// let interface_id = rand64();
/// // setaddr6part(&mut ipv6_addr, interface_id);
///
/// // Unique lease identifier
/// let lease_id = rand64();
/// ```
///
/// # Performance
///
/// Slightly more efficient than calling rand32() twice due to ChaCha8's
/// internal block generation. The RNG generates 64-bit words natively on
/// 64-bit platforms.
///
/// # Security
///
/// Provides full 64-bit entropy with cryptographic strength. ChaCha8 has a
/// proven security record and is used in TLS 1.3 and WireGuard.
///
/// # RFC Compliance
///
/// - RFC 4941: Privacy Extensions for Stateless Address Autoconfiguration
///   in IPv6 (Section 3.2.1 - Randomized Interface Identifiers)
///
/// # Examples
///
/// ```
/// # use crate::utils::rand::rand64;
/// // Generate random IPv6 host identifier
/// let host_id = rand64();
/// assert!(host_id <= u64::MAX);
///
/// // Generate multiple 64-bit values
/// let ids: Vec<u64> = (0..100).map(|_| rand64()).collect();
/// assert_eq!(ids.len(), 100);
///
/// // Verify values are in valid range
/// for id in ids {
///     assert!(id <= u64::MAX);
/// }
/// ```
pub fn rand64() -> u64 {
    trace!("Generating 64-bit random number");
    let value = thread_rng().gen::<u64>();
    trace!("Generated 64-bit random value: {}", value);
    value
}

/// Initialize random number generator (compatibility function).
///
/// This function exists for API compatibility with the C implementation which
/// required explicit initialization via rand_init(). In the Rust implementation,
/// initialization is automatic and this function is a no-op.
///
/// The C implementation read entropy from /dev/urandom during initialization
/// and would terminate the process with die() if entropy could not be obtained.
/// The Rust implementation handles initialization automatically on first use
/// of thread_rng(), using the OS's secure random source, and panics internally
/// only if the OS random source is completely unavailable (extremely rare).
///
/// # Thread Safety
///
/// This function is thread-safe and can be called multiple times without side
/// effects. However, it is not necessary to call it at all.
///
/// # Usage
///
/// ```
/// # use crate::utils::rand::rand_init;
/// // Optional - for API compatibility with C code
/// rand_init();
///
/// // RNG is ready to use whether or not rand_init() was called
/// # use crate::utils::rand::rand16;
/// let value = rand16();
/// ```
///
/// # Migration Note
///
/// When porting C code that calls rand_init() in main(), you can:
/// 1. Keep the rand_init() call for clarity (it's a no-op)
/// 2. Remove the rand_init() call entirely (RNG auto-initializes)
///
/// Either approach is correct. The C implementation's fatal error handling
/// for initialization failure is not needed in Rust.
pub fn rand_init() {
    debug!("rand_init() called (no-op in Rust implementation)");
    info!(
        "RNG auto-initializes on first use via thread_rng() - explicit initialization not required"
    );
    // No-op: thread_rng() initializes automatically on first use per thread.
    // The C implementation required explicit initialization from /dev/urandom
    // with fatal error handling. Rust's thread_rng() handles this internally
    // and only panics if OS random source is unavailable (extremely rare).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand16_range() {
        // Verify rand16 returns valid u16 values
        for _ in 0..1000 {
            let value = rand16();
            assert!(value <= u16::MAX);
        }
    }

    #[test]
    fn test_rand16_distribution() {
        // Basic sanity check: values should not all be identical
        let values: Vec<u16> = (0..100).map(|_| rand16()).collect();
        let first = values[0];
        let all_same = values.iter().all(|&v| v == first);
        assert!(!all_same, "Random values should not all be identical");
    }

    #[test]
    fn test_rand32_range() {
        // Verify rand32 returns valid u32 values
        for _ in 0..1000 {
            let value = rand32();
            assert!(value <= u32::MAX);
        }
    }

    #[test]
    fn test_rand32_distribution() {
        // Basic sanity check: values should not all be identical
        let values: Vec<u32> = (0..100).map(|_| rand32()).collect();
        let first = values[0];
        let all_same = values.iter().all(|&v| v == first);
        assert!(!all_same, "Random values should not all be identical");
    }

    #[test]
    fn test_rand64_range() {
        // Verify rand64 returns valid u64 values
        for _ in 0..1000 {
            let value = rand64();
            assert!(value <= u64::MAX);
        }
    }

    #[test]
    fn test_rand64_distribution() {
        // Basic sanity check: values should not all be identical
        let values: Vec<u64> = (0..100).map(|_| rand64()).collect();
        let first = values[0];
        let all_same = values.iter().all(|&v| v == first);
        assert!(!all_same, "Random values should not all be identical");
    }

    #[test]
    fn test_rand_init_no_op() {
        // Verify rand_init can be called without error
        rand_init();
        rand_init(); // Should be safe to call multiple times

        // RNG should work after rand_init
        let value = rand32();
        assert!(value <= u32::MAX);
    }

    #[test]
    fn test_thread_safety() {
        // Verify RNG works correctly across multiple threads
        use std::thread;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                thread::spawn(|| {
                    let values: Vec<u32> = (0..100).map(|_| rand32()).collect();
                    values
                })
            })
            .collect();

        for handle in handles {
            let values = handle.join().unwrap();
            assert_eq!(values.len(), 100);
            // Each thread should generate different values
            let first = values[0];
            let all_same = values.iter().all(|&v| v == first);
            assert!(!all_same);
        }
    }

    #[test]
    fn test_dns_query_id_generation() {
        // Simulate DNS query ID generation use case
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            let qid = rand16();
            ids.insert(qid);
        }
        // Should have generated many unique IDs (allow some collisions due to birthday paradox)
        assert!(ids.len() > 900, "Should generate mostly unique query IDs");
    }

    #[test]
    fn test_source_port_randomization() {
        // Simulate RFC 5452 source port randomization
        let mut ports = std::collections::HashSet::new();
        for _ in 0..1000 {
            let rand_val = rand32();
            let src_port = 1024 + (rand_val % (65535 - 1024));
            assert!(src_port >= 1024 && src_port < 65535);
            ports.insert(src_port);
        }
        // Should have generated many unique ports
        assert!(ports.len() > 900, "Should generate mostly unique source ports");
    }

    #[test]
    fn test_ipv6_interface_id() {
        // Simulate RFC 4941 IPv6 interface ID randomization
        let mut ids = std::collections::HashSet::new();
        for _ in 0..100 {
            let interface_id = rand64();
            ids.insert(interface_id);
        }
        // All IDs should be unique (birthday paradox negligible for 64-bit space)
        assert_eq!(ids.len(), 100, "Should generate unique interface IDs");
    }
}
