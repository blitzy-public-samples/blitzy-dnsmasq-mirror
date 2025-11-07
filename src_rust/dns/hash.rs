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

//! DNS question section SHA-256 hashing for cryptographic verification
//!
//! This module implements SHA-256 hashing of DNS question sections to provide
//! cryptographic verification of DNS responses, preventing cache poisoning attacks
//! and detecting query retransmissions. The implementation computes a digest over
//! the decoded question name (with case normalization per DNS rules), question type,
//! and question class.
//!
//! By hashing the decoded name rather than raw bytes, the implementation correctly
//! handles DNS name compression variations that may occur between queries and responses.
//!
//! # Key Responsibilities
//!
//! - `hash_questions_init()`: Initialize SHA-256 hashing context at daemon startup
//! - `hash_questions()`: Compute SHA-256 digest of all questions in DNS packet
//! - SHA-256 implementation: Uses sha2 crate for memory-safe cryptographic operations
//!
//! # Memory Safety
//!
//! This Rust implementation replaces C's manual SHA-256 context management with the
//! sha2 crate's safe interface, eliminating:
//! - Manual buffer management for SHA256_CTX structures
//! - Manual bounds checking (CHECK_LEN macro) with nom parser validation
//! - Pointer arithmetic with safe slice operations
//! - Compile-time selection between Nettle and standalone implementations
//!
//! # RFC Compliance
//!
//! - DNS name canonicalization per RFC 1035 (case-insensitive comparison)
//! - Cryptographic verification supports DNS security best practices
//! - SHA-256 algorithm per FIPS PUB 180-4
//!
//! # Security Considerations
//!
//! This module is critical for DNS cache poisoning prevention. The SHA-256 hash
//! provides collision resistance to detect unauthorized response substitution.
//! Case normalization ensures hash consistency across different name encodings.
//!
//! # Example Usage
//!
//! ```rust
//! use dnsmasq::dns::hash::{hash_questions_init, hash_questions};
//! use dnsmasq::dns::protocol::MAXDNAME;
//!
//! // Initialize at daemon startup
//! hash_questions_init();
//!
//! // Compute digest for DNS packet
//! let packet: &[u8] = &[/* DNS packet bytes */];
//! if let Some(digest) = hash_questions(packet) {
//!     println!("Question section digest computed: {} bytes", digest.len());
//!     // Compare with stored digest to verify response authenticity
//! }
//! ```

use crate::dns::parser::extract_name;
use sha2::{Sha256, Digest};

// ============================================================================
// Constants
// ============================================================================

/// SHA-256 digest output size in bytes (32 bytes = 256 bits)
///
/// SHA-256 always produces a 32-byte digest regardless of input size.
/// This constant is used for digest buffer allocation and validation.
pub const SHA256_DIGEST_SIZE: usize = 32;

/// Minimum DNS packet size (12-byte header)
const DNS_HEADER_SIZE: usize = 12;

// ============================================================================
// DNS Header Structure (minimal representation for parsing)
// ============================================================================

/// DNS header flags offset for question count
const QDCOUNT_OFFSET: usize = 4;

// ============================================================================
// Initialization Function
// ============================================================================

/// Initialize SHA-256 hashing context for DNS question verification
///
/// In the C implementation, this function either initializes Nettle library context
/// (allocating memory for hash context and digest buffer) or is a no-op for the
/// standalone implementation. In Rust, using the sha2 crate eliminates the need for
/// global context initialization, so this function is a compatibility no-op.
///
/// The Rust implementation creates fresh Sha256 instances on each call to
/// `hash_questions()`, avoiding shared mutable state and improving thread safety.
/// The sha2 crate handles all context management internally with safe RAII semantics.
///
/// # Example
///
/// ```rust
/// use dnsmasq::dns::hash::hash_questions_init;
///
/// // Called during daemon initialization
/// hash_questions_init();
/// // No-op in Rust - context is created per hash_questions() call
/// ```
///
/// # Thread Safety
///
/// Fully thread-safe (no-op). Unlike the C version with module-level static variables,
/// the Rust implementation has no shared state requiring initialization.
pub fn hash_questions_init() {
    // No-op: sha2 crate handles context management internally.
    // Each hash_questions() call creates its own Sha256 instance.
}

// ============================================================================
// DNS Question Hashing Function
// ============================================================================

/// Compute SHA-256 digest of DNS question section for response verification
///
/// Computes a cryptographic SHA-256 hash over all questions in a DNS packet to
/// enable detection of cache poisoning attacks and query retransmissions. The
/// function iterates through all questions in the DNS header's question section,
/// extracts and canonicalizes each question name (converting to lowercase per
/// RFC 1035 case-insensitivity rules), and includes the question type and class
/// in the hash computation.
///
/// This approach ensures the hash remains consistent despite DNS name compression
/// variations between queries and responses. The function validates packet structure
/// using safe Rust slice operations and the parser module's extract_name() function,
/// eliminating manual bounds checking (C's CHECK_LEN macro).
///
/// # Arguments
///
/// * `packet` - Complete DNS packet bytes including 12-byte header and questions
///
/// # Returns
///
/// * `Some([u8; 32])` - 32-byte SHA-256 digest on success
/// * `None` - Packet is malformed, truncated, or has invalid question format
///
/// # Memory Safety
///
/// This implementation replaces C's manual pointer arithmetic and bounds checking with:
/// - Safe slice indexing for header field extraction
/// - parser::extract_name() for validated name decompression
/// - sha2::Digest trait for safe incremental hashing
/// - Automatic cleanup via RAII (no manual free() needed)
///
/// # Case Normalization
///
/// Domain names are converted to lowercase (A-Z → a-z) per RFC 1035 Section 3.1
/// for case-insensitive DNS name comparison. This ensures hash consistency across
/// different name capitalizations in queries and responses.
///
/// # RFC Compliance
///
/// - RFC 1035 Section 3.1: Domain name case-insensitive comparison
/// - DNS Security: Cryptographic verification of question section integrity
/// - FIPS PUB 180-4: SHA-256 cryptographic hash algorithm
///
/// # Example
///
/// ```rust
/// use dnsmasq::dns::hash::hash_questions;
///
/// let packet: &[u8] = &[/* DNS packet with questions */];
/// 
/// if let Some(digest) = hash_questions(packet) {
///     // Compare digest with expected value for response verification
///     println!("Computed digest: {:?}", digest);
/// } else {
///     eprintln!("Failed to hash questions - malformed packet");
/// }
/// ```
///
/// # Differences from C Implementation
///
/// - No global digest buffer (returns owned array, thread-safe)
/// - No manual SHA256_CTX allocation (sha2 handles internally)
/// - No compile-time Nettle vs standalone selection (always uses sha2 crate)
/// - No pointer advancement (uses safe iterator pattern)
/// - Automatic bounds validation (no CHECK_LEN macro)
pub fn hash_questions(packet: &[u8]) -> Option<[u8; SHA256_DIGEST_SIZE]> {
    // Validate minimum packet size (12-byte DNS header)
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }

    // Extract question count from DNS header (bytes 4-5, big-endian u16)
    let qdcount = u16::from_be_bytes([packet[QDCOUNT_OFFSET], packet[QDCOUNT_OFFSET + 1]]);

    // Initialize SHA-256 hasher
    let mut hasher = Sha256::new();

    // Start parsing after 12-byte DNS header
    let mut position = DNS_HEADER_SIZE;

    // Iterate through all questions in the question section
    for _ in 0..qdcount {
        // Extract question name using parser module (handles compression pointers)
        let (remaining, name) = extract_name(packet, &packet[position..]).ok()?;

        // Calculate how many bytes were consumed by name extraction
        let name_bytes_consumed = packet.len() - position - remaining.len();
        position += name_bytes_consumed;

        // Normalize name to lowercase for case-insensitive hashing per RFC 1035
        let normalized_name = name.to_ascii_lowercase();

        // Hash the normalized question name
        hasher.update(normalized_name.as_bytes());

        // Ensure we have 4 bytes remaining for type (2 bytes) and class (2 bytes)
        if position + 4 > packet.len() {
            return None; // Truncated packet
        }

        // Hash the question type and class (4 bytes total)
        // These are in network byte order and hashed as-is
        hasher.update(&packet[position..position + 4]);

        // Advance position past type and class fields
        position += 4;
    }

    // Finalize hash and extract 32-byte digest
    let result = hasher.finalize();

    // Convert GenericArray to fixed-size array
    let mut digest = [0u8; SHA256_DIGEST_SIZE];
    digest.copy_from_slice(&result);

    Some(digest)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test initialization function (no-op)
    #[test]
    fn test_hash_questions_init() {
        // Should not panic, just a no-op
        hash_questions_init();
    }

    /// Test SHA256_DIGEST_SIZE constant
    #[test]
    fn test_digest_size_constant() {
        assert_eq!(SHA256_DIGEST_SIZE, 32);
    }

    /// Test hash_questions with invalid packet (too short)
    #[test]
    fn test_hash_questions_too_short() {
        let short_packet = [0u8; 5]; // Less than 12-byte header
        assert_eq!(hash_questions(&short_packet), None);
    }

    /// Test hash_questions with zero questions
    #[test]
    fn test_hash_questions_zero_questions() {
        // DNS header with qdcount = 0
        let packet = [
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        
        // Should successfully hash empty question section
        let digest = hash_questions(&packet);
        assert!(digest.is_some());
        assert_eq!(digest.unwrap().len(), SHA256_DIGEST_SIZE);
    }

    /// Test hash_questions with single question
    #[test]
    fn test_hash_questions_single_question() {
        // DNS header with qdcount = 1, followed by question for "example.com" A record
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // QTYPE = A (1)
            0x00, 0x01, // QCLASS = IN (1)
        ];
        
        let digest = hash_questions(&packet);
        assert!(digest.is_some());
        assert_eq!(digest.unwrap().len(), SHA256_DIGEST_SIZE);
    }

    /// Test hash_questions with multiple questions
    #[test]
    fn test_hash_questions_multiple_questions() {
        // DNS header with qdcount = 2
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x02, // QDCOUNT = 2
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question 1: example.com A
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Question 2: test.com AAAA
            0x04, b't', b'e', b's', b't',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x1c, // QTYPE = AAAA (28)
            0x00, 0x01, // QCLASS = IN
        ];
        
        let digest = hash_questions(&packet);
        assert!(digest.is_some());
        assert_eq!(digest.unwrap().len(), SHA256_DIGEST_SIZE);
    }

    /// Test case normalization: "EXAMPLE.COM" and "example.com" should produce same hash
    #[test]
    fn test_case_normalization() {
        // Packet 1: EXAMPLE.COM (uppercase)
        let packet1 = vec![
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'E', b'X', b'A', b'M', b'P', b'L', b'E',
            0x03, b'C', b'O', b'M',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        
        // Packet 2: example.com (lowercase)
        let packet2 = vec![
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        
        let digest1 = hash_questions(&packet1);
        let digest2 = hash_questions(&packet2);
        
        assert!(digest1.is_some());
        assert!(digest2.is_some());
        assert_eq!(digest1.unwrap(), digest2.unwrap(), "Case normalization failed");
    }

    /// Test truncated packet (question incomplete)
    #[test]
    fn test_hash_questions_truncated() {
        // Packet with qdcount=1 but incomplete question
        let packet = vec![
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            // Missing rest of name and type/class
        ];
        
        assert_eq!(hash_questions(&packet), None);
    }

    /// Test that same question produces identical hashes
    #[test]
    fn test_hash_determinism() {
        let packet = vec![
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        
        let digest1 = hash_questions(&packet);
        let digest2 = hash_questions(&packet);
        
        assert_eq!(digest1, digest2, "Hash function should be deterministic");
    }

    /// Test that different questions produce different hashes
    #[test]
    fn test_hash_uniqueness() {
        let packet1 = vec![
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        
        let packet2 = vec![
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, b't', b'e', b's', b't',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        
        let digest1 = hash_questions(&packet1);
        let digest2 = hash_questions(&packet2);
        
        assert_ne!(digest1.unwrap(), digest2.unwrap(), "Different questions should produce different hashes");
    }
}

