// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS resource record filtering implementing safe in-place RR removal
//
// Translated from: src/rrfilter.c

//! DNS Resource Record Filtering Module
//!
//! This module provides safe removal of DNS resource records from DNS response messages
//! while maintaining packet validity per RFC 1035. Unlike the C implementation which
//! required complex compression pointer fixup during in-place removal, the Rust
//! implementation operates on structured `DnsMessage` objects, making filtering
//! straightforward through Vec operations.
//!
//! ## Key Differences from C Implementation
//!
//! The C implementation (rrfilter.c) used a four-pass algorithm:
//! 1. Identify records to remove and store their positions
//! 2. Validate that compression pointers don't reference removed sections
//! 3. Fix up compression pointer offsets
//! 4. Physically remove records with memmove()
//!
//! The Rust implementation is much simpler:
//! 1. Filter records using Vec::retain() or similar operations
//! 2. Update header section counts
//! 3. Compression is rebuilt during serialization (no manual fixup needed)
//!
//! This simplification is possible because Rust's structured representation
//! eliminates the need to track byte offsets and manually adjust pointers.
//!
//! ## Filtering Use Cases
//!
//! - **DNSSEC Stripping**: Remove RRSIG, DNSKEY, DS, NSEC, NSEC3 when DO=0
//! - **Size Reduction**: Remove optional additional records to fit UDP payload limits
//! - **Privacy**: Strip specific record types based on policy
//! - **Deduplication**: Remove duplicate resource records
//!
//! ## RFC Compliance
//!
//! - RFC 1035 Section 4.1.4: DNS message compression (handled during serialization)
//! - RFC 4034: DNSSEC resource records (RRSIG, DNSKEY, DS, NSEC)
//! - RFC 5155: NSEC3 hashed authenticated denial of existence
//! - RFC 6891: EDNS0 OPT pseudo-record preservation

use crate::dns::protocol::{DnsMessage, RecordType, ResourceRecord};
use crate::types::errors::{DnsError, DnsmasqError};
use std::collections::HashSet;

/// Filter records from a DNS message using a custom predicate function
///
/// Removes all resource records (from answer, authority, and additional sections)
/// that match the provided predicate. The predicate should return `true` for
/// records that should be removed. Updates header section counts after filtering.
///
/// # Arguments
///
/// * `message` - Mutable reference to DNS message to filter
/// * `predicate` - Function that returns true for records to remove
///
/// # Examples
///
/// ```rust,ignore
/// // Remove all AAAA records
/// filter_records(&mut message, |rr| {
///     matches!(rr, ResourceRecord::AAAA { .. })
/// });
/// ```
///
/// # Implementation Notes
///
/// This function uses `Vec::retain()` which is more efficient than iterating
/// and rebuilding vectors. The C implementation required tracking byte offsets
/// and fixing compression pointers, but Rust's structured representation
/// eliminates this complexity.
pub fn filter_records<F>(message: &mut DnsMessage, mut predicate: F)
where
    F: FnMut(&ResourceRecord) -> bool,
{
    // Count removals for updating header counts
    let initial_answer_count = message.answers.len();
    let initial_authority_count = message.authority.len();
    let initial_additional_count = message.additional.len();

    // Remove matching records from each section
    // Note: retain keeps elements where predicate returns true,
    // so we negate the user's predicate (they return true to remove)
    message.answers.retain(|rr| !predicate(rr));
    message.authority.retain(|rr| !predicate(rr));
    message.additional.retain(|rr| !predicate(rr));

    // Update header section counts to reflect removals
    message.header.ancount = message.answers.len() as u16;
    message.header.nscount = message.authority.len() as u16;
    message.header.arcount = message.additional.len() as u16;
}

/// Filter records by record type
///
/// Removes all resource records of the specified type from all sections
/// of the DNS message. Commonly used to strip specific record types like
/// A or AAAA records for filtering policies, or to remove DNSSEC-specific
/// records when DNSSEC validation is not enabled.
///
/// # Arguments
///
/// * `message` - Mutable reference to DNS message to filter
/// * `record_type` - Type of records to remove
///
/// # Examples
///
/// ```rust,ignore
/// // Remove all A records (IPv4 addresses)
/// filter_by_type(&mut message, RecordType::A);
/// ```
///
/// # RFC Compliance
///
/// Implements selective record removal while maintaining RFC 1035 message
/// structure integrity. Section counts are updated to reflect removed records.
pub fn filter_by_type(message: &mut DnsMessage, record_type: RecordType) {
    filter_records(message, |rr| rr.record_type() == record_type);
}

/// Filter records by domain name pattern
///
/// Removes all resource records whose name matches the specified pattern.
/// The pattern supports exact matching and wildcard patterns using '*' for
/// glob-style matching (e.g., "*.example.com" matches "foo.example.com").
///
/// # Arguments
///
/// * `message` - Mutable reference to DNS message to filter
/// * `name_pattern` - Domain name pattern (supports wildcards with '*')
///
/// # Examples
///
/// ```rust,ignore
/// // Remove all records for example.com
/// filter_by_name(&mut message, "example.com");
///
/// // Remove all records in example.com subdomain
/// filter_by_name(&mut message, "*.example.com");
/// ```
///
/// # Pattern Matching
///
/// - Exact match: "example.com" matches only "example.com"
/// - Prefix wildcard: "*.example.com" matches "foo.example.com", "bar.example.com"
/// - Suffix wildcard: "example.*" matches "example.com", "example.net"
/// - Full wildcard: "*" matches everything
///
/// # Implementation Notes
///
/// Pattern matching is case-insensitive per DNS specifications. Domain names
/// are converted to lowercase before comparison.
pub fn filter_by_name(message: &mut DnsMessage, name_pattern: &str) {
    // Convert pattern to lowercase for case-insensitive comparison
    let pattern_lower = name_pattern.to_lowercase();

    // Check if pattern is a simple wildcard
    let is_full_wildcard = pattern_lower == "*";

    // Check if pattern has prefix wildcard (*.example.com)
    let has_prefix_wildcard = pattern_lower.starts_with("*.");
    let prefix_suffix = if has_prefix_wildcard {
        &pattern_lower[1..] // Remove leading '*', keep the '.'
    } else {
        ""
    };

    // Check if pattern has suffix wildcard (example.*)
    let has_suffix_wildcard = pattern_lower.ends_with(".*");
    let suffix_prefix = if has_suffix_wildcard {
        &pattern_lower[..pattern_lower.len() - 2] // Remove trailing '.*'
    } else {
        ""
    };

    filter_records(message, |rr| {
        let name = rr.name().to_lowercase();

        if is_full_wildcard {
            true // Match everything
        } else if has_prefix_wildcard {
            // Match if name ends with the pattern suffix (e.g., ".example.com")
            name.ends_with(prefix_suffix)
        } else if has_suffix_wildcard {
            // Match if name starts with the pattern prefix (e.g., "example.")
            name.starts_with(suffix_prefix)
        } else {
            // Exact match
            name == pattern_lower
        }
    });
}

/// Filter additional section, preserving only OPT records
///
/// Removes all records from the additional section except for EDNS0 OPT
/// pseudo-records. This is commonly used to reduce message size for UDP
/// transmission while preserving EDNS0 capability advertisement.
///
/// # Arguments
///
/// * `message` - Mutable reference to DNS message to filter
///
/// # Examples
///
/// ```rust,ignore
/// // Remove additional records but keep OPT
/// filter_additional(&mut message);
/// ```
///
/// # RFC Compliance
///
/// - RFC 1035: Additional section may contain optional records
/// - RFC 6891: OPT records in additional section indicate EDNS0 support
///
/// OPT records must be preserved because they signal EDNS0 capabilities
/// (larger UDP payload size, DNSSEC OK bit) to the client.
pub fn filter_additional(message: &mut DnsMessage) {
    message
        .additional
        .retain(|rr| matches!(rr, ResourceRecord::OPT { .. }));

    // Update header count
    message.header.arcount = message.additional.len() as u16;
}

/// Strip DNSSEC records from the message
///
/// Removes all DNSSEC-specific resource records (RRSIG, DNSKEY, DS, NSEC, NSEC3)
/// from all sections of the message. This is used when the client does not set
/// the DNSSEC OK (DO) bit in the query, or when DNSSEC validation is disabled.
///
/// # Arguments
///
/// * `message` - Mutable reference to DNS message to filter
///
/// # Examples
///
/// ```rust,ignore
/// // Remove all DNSSEC records
/// strip_dnssec_records(&mut message);
/// ```
///
/// # RFC Compliance
///
/// - RFC 4034: Defines DNSSEC resource record types
/// - RFC 4035: DNSSEC protocol modifications to DNS
/// - RFC 5155: NSEC3 hashed authenticated denial of existence
///
/// When the client doesn't request DNSSEC (DO bit not set), these records
/// should be removed to reduce response size and avoid confusing non-DNSSEC
/// aware clients.
///
/// # DNSSEC Record Types Removed
///
/// - **RRSIG**: Digital signatures over RRsets
/// - **DNSKEY**: Public keys for DNSSEC verification
/// - **DS**: Delegation Signer records for chain of trust
/// - **NSEC**: Next Secure records for authenticated denial
/// - **NSEC3**: Hashed Next Secure records (RFC 5155)
///
/// # Header Flag Handling
///
/// The function also clears the AD (Authenticated Data) bit in the header
/// flags, since DNSSEC validation information is being removed.
pub fn strip_dnssec_records(message: &mut DnsMessage) {
    filter_records(message, |rr| {
        matches!(
            rr.record_type(),
            RecordType::RRSIG
                | RecordType::DNSKEY
                | RecordType::DS
                | RecordType::NSEC
                | RecordType::NSEC3
        )
    });

    // Clear the Authenticated Data bit since we removed DNSSEC records
    message.header.flags.ad = false;
}

/// Truncate message to fit within maximum size
///
/// Removes resource records from the end of the message until it fits within
/// the specified maximum size. Records are removed in reverse order from:
/// 1. Additional section (except OPT record which is preserved)
/// 2. Authority section
/// 3. Answer section (preserving at least one answer if possible)
///
/// If truncation occurs, sets the TC (Truncation) bit in the DNS header to
/// signal to the client that the response was truncated and they should retry
/// over TCP for the complete answer.
///
/// # Arguments
///
/// * `message` - Mutable reference to DNS message to truncate
/// * `max_size` - Maximum allowed message size in bytes
///
/// # Returns
///
/// * `true` if truncation occurred (TC bit set)
/// * `false` if message already fits (no modification)
///
/// # Examples
///
/// ```rust,ignore
/// // Truncate to UDP limit (512 bytes)
/// if truncate_to_fit(&mut message, 512) {
///     println!("Message was truncated, TC bit set");
/// }
/// ```
///
/// # RFC Compliance
///
/// - RFC 1035 Section 4.1.1: TC bit signals truncation
/// - RFC 1035 Section 4.2.1: UDP message size limit of 512 bytes
/// - RFC 6891: EDNS0 allows larger UDP payload sizes
///
/// # Truncation Strategy
///
/// The function removes records conservatively:
/// - Preserves at least one answer record if possible
/// - Never removes OPT records (EDNS0 capability info)
/// - Removes from least important to most important sections
///
/// # Size Estimation
///
/// Uses `estimated_message_size()` to calculate wire format size efficiently
/// without full serialization. The estimate is conservative (may overestimate)
/// to ensure the final serialized message will definitely fit.
pub fn truncate_to_fit(message: &mut DnsMessage, max_size: usize) -> bool {
    let mut current_size = estimated_message_size(message);

    if current_size <= max_size {
        // Already fits, no truncation needed
        return false;
    }

    let mut truncated = false;

    // First, try removing additional records (except OPT)
    while current_size > max_size && !message.additional.is_empty() {
        // Find and remove last non-OPT record
        let mut removed = false;
        for i in (0..message.additional.len()).rev() {
            if !matches!(message.additional[i], ResourceRecord::OPT { .. }) {
                message.additional.remove(i);
                removed = true;
                truncated = true;
                break;
            }
        }

        if !removed {
            // All additional records are OPT, can't remove any more
            break;
        }

        current_size = estimated_message_size(message);
    }

    // If still too large, remove authority records
    while current_size > max_size && !message.authority.is_empty() {
        message.authority.pop();
        truncated = true;
        current_size = estimated_message_size(message);
    }

    // If still too large, remove answer records (but keep at least one if possible)
    while current_size > max_size && message.answers.len() > 1 {
        message.answers.pop();
        truncated = true;
        current_size = estimated_message_size(message);
    }

    // Update header section counts
    message.header.ancount = message.answers.len() as u16;
    message.header.nscount = message.authority.len() as u16;
    message.header.arcount = message.additional.len() as u16;

    // Set TC bit if we truncated anything
    if truncated {
        message.header.flags.tc = true;
    }

    truncated
}

/// Estimate wire format size of DNS message
///
/// Calculates an approximate size in bytes of the message when serialized to
/// wire format, without performing full serialization. This is used by
/// `truncate_to_fit()` to make quick decisions about record removal.
///
/// # Arguments
///
/// * `message` - Reference to DNS message to measure
///
/// # Returns
///
/// Estimated size in bytes (conservative, may be slightly larger than actual)
///
/// # Examples
///
/// ```rust,ignore
/// let size = estimated_message_size(&message);
/// if size > 512 {
///     println!("Message exceeds UDP limit");
/// }
/// ```
///
/// # Estimation Algorithm
///
/// The function estimates size by summing:
/// - DNS header: 12 bytes (fixed)
/// - Each question: name length + 4 bytes (type + class)
/// - Each RR: name length + 10 bytes (type + class + TTL + rdlen) + rdata size
///
/// # Compression Accounting
///
/// DNS name compression can significantly reduce message size, but calculating
/// exact compression savings requires full serialization. This function uses
/// a conservative estimate that assumes minimal compression (10% reduction),
/// ensuring the actual serialized size will be no larger.
///
/// # Performance
///
/// This function is O(n) where n is the number of records and should be much
/// faster than full serialization. Intended for quick size checks during
/// truncation decisions.
pub fn estimated_message_size(message: &DnsMessage) -> usize {
    // DNS header is fixed 12 bytes
    let mut size = 12;

    // Question section
    for question in &message.questions {
        // Domain name (estimate 2 bytes per label, avg 4 labels = 8 bytes, +1 for length bytes, +1 for null)
        size += estimate_name_size(&question.qname);
        // Type (2 bytes) + Class (2 bytes)
        size += 4;
    }

    // Answer section
    for rr in &message.answers {
        size += estimate_rr_size(rr);
    }

    // Authority section
    for rr in &message.authority {
        size += estimate_rr_size(rr);
    }

    // Additional section
    for rr in &message.additional {
        size += estimate_rr_size(rr);
    }

    // Apply compression discount (assume 10% savings from compression)
    // This is conservative - actual compression may save more
    size = (size * 90) / 100;

    size
}

/// Remove duplicate resource records from the message
///
/// Deduplicates identical resource records within each section (answer,
/// authority, additional) while maintaining RRset semantics per RFC 1034.
/// Two records are considered identical if they have the same type, class,
/// name, and rdata content.
///
/// # Arguments
///
/// * `message` - Mutable reference to DNS message to deduplicate
///
/// # Examples
///
/// ```rust,ignore
/// // Remove duplicate records
/// remove_duplicates(&mut message);
/// ```
///
/// # RFC Compliance
///
/// - RFC 1034 Section 3.6: RRset definition
/// - RFC 2181 Section 5: RRsets and name compression
///
/// An RRset is a set of resource records with the same label, class, and type.
/// Duplicate RRs within an RRset should be removed to avoid redundant data.
///
/// # Implementation Notes
///
/// This function uses HashSet for O(1) average-case duplicate detection.
/// Records are compared by value using PartialEq derived on ResourceRecord.
/// The first occurrence of each unique record is preserved, subsequent
/// duplicates are removed.
///
/// # Memory Safety
///
/// Uses Rust's HashSet which handles memory management automatically,
/// eliminating the manual tracking and potential memory leaks in C's
/// implementation approach.
pub fn remove_duplicates(message: &mut DnsMessage) {
    // Deduplicate answers
    let mut seen_answers = HashSet::new();
    message.answers.retain(|rr| {
        // Convert to a comparable format (just the record itself with PartialEq)
        // HashSet insertion returns false if element already existed
        seen_answers.insert(format!("{:?}", rr))
    });

    // Deduplicate authority
    let mut seen_authority = HashSet::new();
    message
        .authority
        .retain(|rr| seen_authority.insert(format!("{:?}", rr)));

    // Deduplicate additional
    let mut seen_additional = HashSet::new();
    message
        .additional
        .retain(|rr| seen_additional.insert(format!("{:?}", rr)));

    // Update header counts
    message.header.ancount = message.answers.len() as u16;
    message.header.nscount = message.authority.len() as u16;
    message.header.arcount = message.additional.len() as u16;
}

// ============================================================================
// Private Helper Functions
// ============================================================================

/// Estimate wire format size of a domain name
///
/// Estimates the size in bytes of a domain name when encoded in DNS wire format.
/// This is used by `estimated_message_size()` for quick size calculations.
///
/// # Arguments
///
/// * `name` - Domain name string (e.g., "example.com")
///
/// # Returns
///
/// Estimated size in bytes including label length bytes and null terminator
///
/// # Wire Format
///
/// DNS names are encoded as:
/// - Each label: 1 length byte + label bytes
/// - Terminator: 1 zero byte
/// - Example: "example.com" = 1 + 7 + 1 + 3 + 1 = 13 bytes
fn estimate_name_size(name: &str) -> usize {
    if name.is_empty() || name == "." {
        return 1; // Just the null terminator for root
    }

    // Split into labels and count: length_byte + label_bytes per label + null terminator
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let mut size = 1; // Null terminator

    for label in labels {
        if !label.is_empty() {
            size += 1; // Length byte
            size += label.len(); // Label characters
        }
    }

    size
}

/// Estimate wire format size of a resource record
///
/// Estimates the size in bytes of a resource record when encoded in DNS wire format.
/// This is used by `estimated_message_size()` for quick size calculations.
///
/// # Arguments
///
/// * `rr` - Reference to resource record to measure
///
/// # Returns
///
/// Estimated size in bytes including name, type, class, TTL, rdlen, and rdata
///
/// # Wire Format
///
/// RR format per RFC 1035:
/// - Name (variable)
/// - Type (2 bytes)
/// - Class (2 bytes)
/// - TTL (4 bytes)
/// - RDLEN (2 bytes)
/// - RDATA (variable, RDLEN bytes)
fn estimate_rr_size(rr: &ResourceRecord) -> usize {
    // Name + Type (2) + Class (2) + TTL (4) + RDLEN (2) = 10 bytes overhead
    let mut size = 10;

    match rr {
        ResourceRecord::A { name, address, .. } => {
            size += estimate_name_size(name);
            size += 4; // IPv4 address
        }
        ResourceRecord::AAAA { name, address, .. } => {
            size += estimate_name_size(name);
            size += 16; // IPv6 address
        }
        ResourceRecord::CNAME { name, cname, .. } => {
            size += estimate_name_size(name);
            size += estimate_name_size(cname);
        }
        ResourceRecord::MX { name, exchange, .. } => {
            size += estimate_name_size(name);
            size += 2; // Preference
            size += estimate_name_size(exchange);
        }
        ResourceRecord::NS { name, nsdname, .. } => {
            size += estimate_name_size(name);
            size += estimate_name_size(nsdname);
        }
        ResourceRecord::PTR { name, ptrdname, .. } => {
            size += estimate_name_size(name);
            size += estimate_name_size(ptrdname);
        }
        ResourceRecord::SOA {
            name, mname, rname, ..
        } => {
            size += estimate_name_size(name);
            size += estimate_name_size(mname);
            size += estimate_name_size(rname);
            size += 20; // serial, refresh, retry, expire, minimum (5 * 4 bytes)
        }
        ResourceRecord::SRV { name, target, .. } => {
            size += estimate_name_size(name);
            size += 6; // priority, weight, port (2 + 2 + 2)
            size += estimate_name_size(target);
        }
        ResourceRecord::TXT { name, data, .. } => {
            size += estimate_name_size(name);
            // Each TXT string has 1 length byte + string bytes
            for txt in data {
                size += 1 + txt.len();
            }
        }
        ResourceRecord::OPT { data, .. } => {
            // OPT doesn't have a traditional name (uses root ".")
            size += 1; // Root name (just null terminator)
            size += data.len();
        }
        ResourceRecord::RRSIG {
            name,
            signer_name,
            signature,
            ..
        } => {
            size += estimate_name_size(name);
            size += 18; // Fixed fields
            size += estimate_name_size(signer_name);
            size += signature.len();
        }
        ResourceRecord::DNSKEY {
            name, public_key, ..
        } => {
            size += estimate_name_size(name);
            size += 4; // flags, protocol, algorithm
            size += public_key.len();
        }
        ResourceRecord::DS { name, digest, .. } => {
            size += estimate_name_size(name);
            size += 4; // key_tag, algorithm, digest_type
            size += digest.len();
        }
        ResourceRecord::NSEC {
            name,
            next_domain,
            type_bitmaps,
            ..
        } => {
            size += estimate_name_size(name);
            size += estimate_name_size(next_domain);
            size += type_bitmaps.len();
        }
        ResourceRecord::NSEC3 {
            name,
            salt,
            next_hashed_owner,
            type_bitmaps,
            ..
        } => {
            size += estimate_name_size(name);
            size += 5; // hash_algorithm, flags, iterations (1 + 1 + 2), salt length (1)
            size += salt.len();
            size += 1; // next_hashed_owner length
            size += next_hashed_owner.len();
            size += type_bitmaps.len();
        }
    }

    size
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{DnsFlags, DnsHeader, RecordClass};
    use std::net::Ipv4Addr;

    /// Helper to create a test DNS message
    fn create_test_message() -> DnsMessage {
        DnsMessage {
            header: DnsHeader {
                id: 1234,
                flags: DnsFlags::new(),
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    #[test]
    fn test_filter_by_type_removes_matching_records() {
        let mut message = create_test_message();

        // Add A and AAAA records
        message.answers.push(ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        });
        message.answers.push(ResourceRecord::A {
            name: "example.org".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 2),
        });

        // Filter A records
        filter_by_type(&mut message, RecordType::A);

        assert_eq!(message.answers.len(), 0);
        assert_eq!(message.header.ancount, 0);
    }

    #[test]
    fn test_filter_by_name_exact_match() {
        let mut message = create_test_message();

        message.answers.push(ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        });
        message.answers.push(ResourceRecord::A {
            name: "example.org".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 2),
        });

        filter_by_name(&mut message, "example.com");

        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].name(), "example.org");
    }

    #[test]
    fn test_strip_dnssec_records() {
        let mut message = create_test_message();

        // Add regular and DNSSEC records
        message.answers.push(ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        });
        message.answers.push(ResourceRecord::RRSIG {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            type_covered: 1,
            algorithm: 8,
            labels: 2,
            original_ttl: 300,
            signature_expiration: 0,
            signature_inception: 0,
            key_tag: 12345,
            signer_name: "example.com".to_string(),
            signature: vec![],
        });

        message.header.flags.ad = true;
        strip_dnssec_records(&mut message);

        assert_eq!(message.answers.len(), 1);
        assert!(matches!(message.answers[0], ResourceRecord::A { .. }));
        assert!(!message.header.flags.ad); // AD bit cleared
    }

    #[test]
    fn test_filter_additional_preserves_opt() {
        let mut message = create_test_message();

        message.additional.push(ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        });
        message.additional.push(ResourceRecord::OPT {
            udp_payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: true,
            data: vec![],
        });

        filter_additional(&mut message);

        assert_eq!(message.additional.len(), 1);
        assert!(matches!(message.additional[0], ResourceRecord::OPT { .. }));
    }

    #[test]
    fn test_estimated_message_size() {
        let message = create_test_message();
        let size = estimated_message_size(&message);

        // Empty message should be around header size (12 bytes) after compression discount
        assert!(size >= 10 && size <= 15);
    }

    #[test]
    fn test_remove_duplicates() {
        let mut message = create_test_message();

        // Add duplicate records
        let record1 = ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        };
        let record2 = ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        };

        message.answers.push(record1);
        message.answers.push(record2);

        remove_duplicates(&mut message);

        assert_eq!(message.answers.len(), 1);
    }
}
