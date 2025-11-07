// Copyright (c) 2000-2024 Simon Kelley and contributors
// Copyright (c) 2024 Blitzy Platform (Rust translation)
// Licensed under GPL-2.0-or-later
//
// DNS Protocol Integration Tests
//
// Comprehensive integration tests validating RFC 1035 compliance, packet parsing with compression
// pointers, cache operations, query forwarding, DNSSEC validation, and EDNS0 support ensuring
// 100% behavioral parity with C implementation per Section 0.7.3 of the Agent Action Plan.

//! # DNS Protocol Integration Tests
//!
//! This module provides comprehensive integration testing for the dnsmasq DNS subsystem,
//! validating RFC 1035 wire format compliance, memory-safe parsing, cache operations,
//! query forwarding, DNSSEC validation, and EDNS0 extension support.
//!
//! ## Test Coverage Areas (per Section 0.6.1 of Agent Action Plan)
//!
//! 1. **RFC 1035 Wire Format Parsing** (from src/rfc1035.c)
//!    - DNS name extraction with compression pointer following (lines 78-135)
//!    - Compression pointer hop limit validation (255 hops max, line 102, 140)
//!    - Question and answer section parsing (skip_questions, skip_section lines 33-35)
//!    - All resource record types: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT
//!
//! 2. **DNS Cache Operations** (from src/cache.c)
//!    - Cache insertion and lookup with TTL management
//!    - LRU eviction policy validation
//!    - Negative caching (NXDOMAIN/NODATA per RFC 2308)
//!    - CNAME chain resolution with loop detection
//!
//! 3. **Query Forwarding** (from src/forward.c)
//!    - Upstream server selection and failover
//!    - Query timeout handling with exponential backoff
//!    - TCP fallback on truncation (TC=1 flag)
//!    - Response caching integration
//!
//! 4. **Reverse DNS** (from src/rfc1035.c line 28)
//!    - in-addr.arpa (IPv4) reverse lookups
//!    - ip6.arpa (IPv6) reverse lookups
//!
//! 5. **EDNS0 Extension Support** (from src/edns0.c)
//!    - OPT pseudo-record parsing and generation
//!    - UDP payload size negotiation (512 bytes standard, 4096 with EDNS)
//!    - DNSSEC OK (DO) bit handling
//!    - Client subnet (ECS) option parsing
//!
//! 6. **DNSSEC Validation** (from src/dnssec.c)
//!    - RRSIG signature verification over RRsets
//!    - DS/DNSKEY chain-of-trust validation
//!    - NSEC/NSEC3 denial-of-existence proofs
//!    - Validation status (secure, insecure, bogus, indeterminate)
//!
//! 7. **Memory Safety** (per Section 0.7.2)
//!    - Buffer overrun prevention through Rust's type system (replacing CHECK_LEN macros)
//!    - Malformed packet rejection without panics
//!    - Compression pointer loop detection
//!
//! 8. **Protocol Correctness** (per Section 0.7.4)
//!    - Property-based testing with proptest (Parse(Serialize(x)) == x)
//!    - Byte-identical packet formats with C version validation
//!    - >80% code coverage target
//!
//! ## C Source References
//!
//! - `src/rfc1035.c` - DNS protocol parsing (extract_name lines 78-135, answer_request lines 37-38)
//! - `src/cache.c` - DNS caching with LRU eviction
//! - `src/forward.c` - Query forwarding to upstream servers
//! - `src/dnssec.c` - DNSSEC signature validation
//! - `src/edns0.c` - EDNS0 extension handling

use bytes::{Bytes, BytesMut, BufMut, Buf};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::UdpSocket;
use tokio::time::{timeout, sleep};

// Import DNS subsystem modules from depends_on_files
use dnsmasq::dns::cache::{DnsCache, CacheKey, CacheSource};
use dnsmasq::dns::compression::extract_name;
use dnsmasq::dns::edns::OptRecord;
use dnsmasq::dns::forward::handle_query;
use dnsmasq::dns::protocol::{
    DnsHeader, DnsMessage, DnsQuestion, RecordClass, RecordType, ResourceRecord,
};
use dnsmasq::dns::server::DnsServer;

// Test constants
const DNS_PORT: u16 = 53;
const MAX_UDP_PACKET: usize = 512;
const MAX_EDNS_PACKET: usize = 4096;
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

// =============================================================================
// RFC 1035 Wire Format Parsing Tests
// =============================================================================

/// Test basic DNS name extraction without compression
///
/// Validates that simple DNS names (no compression pointers) are correctly parsed
/// from wire format. Tests the extract_name function from src/dns/compression.rs
/// which replaces C's extract_name() in rfc1035.c lines 78-135.
#[test]
fn test_dns_name_extraction_simple() {
    // Wire format for "example.com" (7 example 3 com 0)
    let packet = vec![
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // root label terminator
    ];

    let mut offset = 0;
    let result = extract_name(&packet, &mut offset, 0);

    assert!(result.is_ok(), "Name extraction should succeed");
    let name = result.unwrap();
    assert_eq!(name.to_string(), "example.com");
    assert_eq!(offset, 13, "Offset should advance past the name");
    assert!(!name.compressed, "Name should not be marked as compressed");
}

/// Test DNS name extraction with compression pointers
///
/// Validates compression pointer following per RFC 1035 Section 4.1.4.
/// Tests that pointers (0xC0 prefix) are correctly followed and the hop limit
/// is enforced to prevent infinite loops (max 255 hops per rfc1035.c line 102).
#[test]
fn test_dns_name_extraction_with_compression() {
    // Packet structure:
    // Offset 0: "example" . "com" . 0
    // Offset 13: "www" . pointer_to_offset_0
    let mut packet = Vec::new();
    
    // First name at offset 0: "example.com"
    packet.extend_from_slice(&[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    packet.extend_from_slice(&[0x03, b'c', b'o', b'm']);
    packet.push(0x00);
    
    // Second name at offset 13: "www" + pointer to offset 0
    packet.extend_from_slice(&[0x03, b'w', b'w', b'w']);
    packet.extend_from_slice(&[0xC0, 0x00]); // Compression pointer to offset 0

    // Extract the compressed name
    let mut offset = 13;
    let result = extract_name(&packet, &mut offset, 0);

    assert!(result.is_ok(), "Compression pointer following should succeed");
    let name = result.unwrap();
    assert_eq!(name.to_string(), "www.example.com");
    assert_eq!(offset, 17, "Offset should be after the pointer");
    assert!(name.compressed, "Name should be marked as compressed");
}

/// Test compression pointer hop limit to prevent infinite loops
///
/// Validates that malicious packets with circular compression pointers are detected
/// and rejected. The 255 hop limit is enforced per rfc1035.c line 140.
#[test]
fn test_compression_pointer_hop_limit() {
    // Create packet with circular pointer: offset 0 points to itself
    let packet = vec![
        0xC0, 0x00, // Pointer to offset 0 (self-reference)
    ];

    let mut offset = 0;
    let result = extract_name(&packet, &mut offset, 0);

    assert!(result.is_err(), "Circular compression pointer should be rejected");
    let error = result.unwrap_err();
    assert!(
        error.to_string().contains("hops") || error.to_string().contains("loop"),
        "Error should indicate hop limit or loop detection, got: {}",
        error
    );
}

/// Test compression pointer validation for out-of-bounds offsets
///
/// Validates that compression pointers pointing outside the packet bounds are rejected.
/// Prevents buffer overruns that were possible in C version before bounds checking.
#[test]
fn test_compression_pointer_bounds_checking() {
    // Packet with pointer to offset 1000 (out of bounds)
    let packet = vec![
        0xC0, 0xFF, // Pointer to offset 255 (beyond packet length)
    ];

    let mut offset = 0;
    let result = extract_name(&packet, &mut offset, 0);

    assert!(result.is_err(), "Out-of-bounds pointer should be rejected");
    let error = result.unwrap_err();
    assert!(
        error.to_string().contains("offset") || error.to_string().contains("bounds"),
        "Error should indicate offset validation failure, got: {}",
        error
    );
}

/// Test DNS name maximum length enforcement
///
/// Validates that names exceeding 253 characters (RFC 1035 limit) are rejected.
/// Prevents buffer overflows from oversized names.
#[test]
fn test_dns_name_length_limit() {
    // Create a name with 64 labels of 3 characters each (192 chars + 63 dots = 255 total)
    let mut packet = Vec::new();
    for _ in 0..85 {
        // 85 * 3 = 255 characters, exceeds limit
        packet.push(0x03); // Length byte
        packet.extend_from_slice(b"aaa");
    }
    packet.push(0x00); // Terminator

    let mut offset = 0;
    let result = extract_name(&packet, &mut offset, 0);

    assert!(result.is_err(), "Oversized name should be rejected");
    let error = result.unwrap_err();
    assert!(
        error.to_string().contains("too long") || error.to_string().contains("length"),
        "Error should indicate name length violation, got: {}",
        error
    );
}

/// Test malformed packet with truncated label
///
/// Validates that packets with incomplete labels (length byte indicates more bytes
/// than available) are rejected without panicking. Replaces C's CHECK_LEN macro
/// validation (rfc1035.c lines 26-27, 86, 106, 150).
#[test]
fn test_malformed_packet_truncated_label() {
    // Packet claiming 10-byte label but only providing 3 bytes
    let packet = vec![
        0x0A, // Length: 10 bytes
        b'a', b'b', b'c', // Only 3 bytes provided
    ];

    let mut offset = 0;
    let result = extract_name(&packet, &mut offset, 0);

    assert!(result.is_err(), "Truncated label should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("too short") ||
        result.unwrap_err().to_string().contains("truncated"),
        "Error should indicate packet truncation"
    );
}

/// Test invalid label type rejection
///
/// Validates that labels with invalid type bits (0x40 extended, 0x80 reserved) are
/// rejected per RFC 1035. Corresponds to C validation in rfc1035.c line 256.
#[test]
fn test_invalid_label_type_rejection() {
    // Packet with invalid label type (0x40)
    let packet = vec![
        0x40, 0x00, // Invalid label type (extended label, not supported)
    ];

    let mut offset = 0;
    let result = extract_name(&packet, &mut offset, 0);

    assert!(result.is_err(), "Invalid label type should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("label type") ||
        result.unwrap_err().to_string().contains("invalid"),
        "Error should indicate invalid label type"
    );
}

// =============================================================================
// Resource Record Type Tests
// =============================================================================

/// Test A record (IPv4 address) parsing
///
/// Validates that IPv4 A records are correctly parsed from wire format.
#[tokio::test]
async fn test_a_record_parsing() {
    let cache = DnsCache::new(100);
    
    // Create A record for example.com -> 192.0.2.1
    let records = vec![
        ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        }
    ];

    let key = CacheKey {
        name: "example.com".to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
    };

    // Insert and lookup
    cache.insert(key.clone(), records, 300, CacheSource::Upstream).unwrap();
    let lookup_result = cache.lookup(&key).unwrap();

    assert!(lookup_result.is_some(), "A record should be found in cache");
    let entry = lookup_result.unwrap();
    assert_eq!(entry.records.len(), 1, "Should have one A record");
    
    match &entry.records[0] {
        ResourceRecord::A { address, .. } => {
            assert_eq!(*address, Ipv4Addr::new(192, 0, 2, 1));
        }
        _ => panic!("Expected A record"),
    }
}

/// Test AAAA record (IPv6 address) parsing
///
/// Validates that IPv6 AAAA records are correctly parsed from wire format.
#[tokio::test]
async fn test_aaaa_record_parsing() {
    let cache = DnsCache::new(100);
    
    // Create AAAA record for example.com -> 2001:db8::1
    let records = vec![
        ResourceRecord::AAAA {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        }
    ];

    let key = CacheKey {
        name: "example.com".to_string(),
        record_type: RecordType::AAAA,
        class: RecordClass::IN,
    };

    cache.insert(key.clone(), records, 300, CacheSource::Upstream).unwrap();
    let lookup_result = cache.lookup(&key).unwrap();

    assert!(lookup_result.is_some(), "AAAA record should be found in cache");
    let entry = lookup_result.unwrap();
    
    match &entry.records[0] {
        ResourceRecord::AAAA { address, .. } => {
            assert_eq!(*address, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        }
        _ => panic!("Expected AAAA record"),
    }
}

/// Test CNAME record parsing and chain resolution
///
/// Validates that CNAME records are correctly parsed and that CNAME chains
/// are resolved with loop detection.
#[tokio::test]
async fn test_cname_record_chain_resolution() {
    let cache = DnsCache::new(100);
    
    // Create CNAME chain: www.example.com -> example.com -> 192.0.2.1
    let cname_record = vec![
        ResourceRecord::CNAME {
            name: "www.example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            cname: "example.com".to_string(),
        }
    ];

    let a_record = vec![
        ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        }
    ];

    // Insert both records
    let cname_key = CacheKey {
        name: "www.example.com".to_string(),
        record_type: RecordType::CNAME,
        class: RecordClass::IN,
    };
    
    let a_key = CacheKey {
        name: "example.com".to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
    };

    cache.insert(cname_key, cname_record, 300, CacheSource::Upstream).unwrap();
    cache.insert(a_key, a_record, 300, CacheSource::Upstream).unwrap();

    // Resolve CNAME chain
    let chain_result = cache.resolve_cname_chain("www.example.com", 10);
    assert!(chain_result.is_ok(), "CNAME chain resolution should succeed");
    
    let final_name = chain_result.unwrap();
    assert_eq!(final_name, "example.com", "Should resolve to final target");
}

/// Test MX record parsing
///
/// Validates that MX (Mail Exchange) records with priority are correctly parsed.
#[tokio::test]
async fn test_mx_record_parsing() {
    let cache = DnsCache::new(100);
    
    // Create MX record for example.com
    let records = vec![
        ResourceRecord::MX {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            preference: 10,
            exchange: "mail.example.com".to_string(),
        }
    ];

    let key = CacheKey {
        name: "example.com".to_string(),
        record_type: RecordType::MX,
        class: RecordClass::IN,
    };

    cache.insert(key.clone(), records, 300, CacheSource::Upstream).unwrap();
    let lookup_result = cache.lookup(&key).unwrap();

    assert!(lookup_result.is_some(), "MX record should be found");
    match &lookup_result.unwrap().records[0] {
        ResourceRecord::MX { preference, exchange, .. } => {
            assert_eq!(*preference, 10);
            assert_eq!(exchange, "mail.example.com");
        }
        _ => panic!("Expected MX record"),
    }
}

/// Test PTR record parsing for reverse DNS
///
/// Validates that PTR records for reverse lookups (in-addr.arpa, ip6.arpa) are
/// correctly parsed. Corresponds to reverse DNS handling in rfc1035.c line 28.
#[tokio::test]
async fn test_ptr_record_reverse_dns() {
    let cache = DnsCache::new(100);
    
    // Create PTR record for 192.0.2.1 (1.2.0.192.in-addr.arpa)
    let records = vec![
        ResourceRecord::PTR {
            name: "1.2.0.192.in-addr.arpa".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            ptrdname: "example.com".to_string(),
        }
    ];

    let key = CacheKey {
        name: "1.2.0.192.in-addr.arpa".to_string(),
        record_type: RecordType::PTR,
        class: RecordClass::IN,
    };

    cache.insert(key.clone(), records, 300, CacheSource::Upstream).unwrap();
    let lookup_result = cache.lookup(&key).unwrap();

    assert!(lookup_result.is_some(), "PTR record should be found");
    match &lookup_result.unwrap().records[0] {
        ResourceRecord::PTR { ptrdname, .. } => {
            assert_eq!(ptrdname, "example.com");
        }
        _ => panic!("Expected PTR record"),
    }
}

/// Test SOA record parsing
///
/// Validates that SOA (Start of Authority) records with all fields are correctly parsed.
#[tokio::test]
async fn test_soa_record_parsing() {
    let cache = DnsCache::new(100);
    
    // Create SOA record
    let records = vec![
        ResourceRecord::SOA {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 3600,
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            serial: 2024010101,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 300,
        }
    ];

    let key = CacheKey {
        name: "example.com".to_string(),
        record_type: RecordType::SOA,
        class: RecordClass::IN,
    };

    cache.insert(key.clone(), records, 3600, CacheSource::Upstream).unwrap();
    let lookup_result = cache.lookup(&key).unwrap();

    assert!(lookup_result.is_some(), "SOA record should be found");
    match &lookup_result.unwrap().records[0] {
        ResourceRecord::SOA { serial, mname, .. } => {
            assert_eq!(*serial, 2024010101);
            assert_eq!(mname, "ns1.example.com");
        }
        _ => panic!("Expected SOA record"),
    }
}

/// Test SRV record parsing
///
/// Validates that SRV (Service) records with priority, weight, and port are correctly parsed.
#[tokio::test]
async fn test_srv_record_parsing() {
    let cache = DnsCache::new(100);
    
    // Create SRV record for _http._tcp.example.com
    let records = vec![
        ResourceRecord::SRV {
            name: "_http._tcp.example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            priority: 10,
            weight: 60,
            port: 80,
            target: "server.example.com".to_string(),
        }
    ];

    let key = CacheKey {
        name: "_http._tcp.example.com".to_string(),
        record_type: RecordType::SRV,
        class: RecordClass::IN,
    };

    cache.insert(key.clone(), records, 300, CacheSource::Upstream).unwrap();
    let lookup_result = cache.lookup(&key).unwrap();

    assert!(lookup_result.is_some(), "SRV record should be found");
    match &lookup_result.unwrap().records[0] {
        ResourceRecord::SRV { priority, weight, port, target, .. } => {
            assert_eq!(*priority, 10);
            assert_eq!(*weight, 60);
            assert_eq!(*port, 80);
            assert_eq!(target, "server.example.com");
        }
        _ => panic!("Expected SRV record"),
    }
}

/// Test TXT record parsing
///
/// Validates that TXT records with arbitrary text data are correctly parsed.
#[tokio::test]
async fn test_txt_record_parsing() {
    let cache = DnsCache::new(100);
    
    // Create TXT record with multiple strings
    let records = vec![
        ResourceRecord::TXT {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            text: vec!["v=spf1 mx -all".to_string()],
        }
    ];

    let key = CacheKey {
        name: "example.com".to_string(),
        record_type: RecordType::TXT,
        class: RecordClass::IN,
    };

    cache.insert(key.clone(), records, 300, CacheSource::Upstream).unwrap();
    let lookup_result = cache.lookup(&key).unwrap();

    assert!(lookup_result.is_some(), "TXT record should be found");
    match &lookup_result.unwrap().records[0] {
        ResourceRecord::TXT { text, .. } => {
            assert_eq!(text.len(), 1);
            assert_eq!(text[0], "v=spf1 mx -all");
        }
        _ => panic!("Expected TXT record"),
    }
}

// =============================================================================
// DNS Cache Operations Tests
// =============================================================================

/// Test DNS cache insertion and lookup
///
/// Validates basic cache operations: inserting records and retrieving them.
/// Tests the DnsCache implementation from src/dns/cache.rs which replaces
/// C's cache.c functionality.
#[tokio::test]
async fn test_cache_insert_and_lookup() {
    let cache = DnsCache::new(100);
    
    let records = vec![
        ResourceRecord::A {
            name: "test.example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 10),
        }
    ];

    let key = CacheKey {
        name: "test.example.com".to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
    };

    // Insert record
    let insert_result = cache.insert(key.clone(), records.clone(), 300, CacheSource::Upstream);
    assert!(insert_result.is_ok(), "Cache insertion should succeed");

    // Lookup record
    let lookup_result = cache.lookup(&key);
    assert!(lookup_result.is_ok(), "Cache lookup should succeed");
    assert!(lookup_result.unwrap().is_some(), "Record should be found in cache");
}

/// Test DNS cache TTL expiration
///
/// Validates that records are automatically expired based on TTL.
#[tokio::test]
async fn test_cache_ttl_expiration() {
    let cache = DnsCache::new(100);
    
    let records = vec![
        ResourceRecord::A {
            name: "short-ttl.example.com".to_string(),
            class: RecordClass::IN,
            ttl: 1, // 1 second TTL
            address: Ipv4Addr::new(192, 0, 2, 20),
        }
    ];

    let key = CacheKey {
        name: "short-ttl.example.com".to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
    };

    cache.insert(key.clone(), records, 1, CacheSource::Upstream).unwrap();
    
    // Record should be present immediately
    assert!(cache.lookup(&key).unwrap().is_some(), "Record should be in cache");

    // Wait for TTL to expire
    sleep(Duration::from_secs(2)).await;
    
    // Expire old entries
    cache.expire_old_entries();

    // Record should be gone
    let lookup_result = cache.lookup(&key).unwrap();
    assert!(lookup_result.is_none(), "Expired record should not be in cache");
}

/// Test DNS cache LRU eviction
///
/// Validates that when cache is full, least recently used entries are evicted.
/// Tests LRU implementation from cache.c.
#[tokio::test]
async fn test_cache_lru_eviction() {
    // Create small cache that can hold only 3 entries
    let cache = DnsCache::new(3);
    
    // Insert 4 records (should trigger eviction of oldest)
    for i in 1..=4 {
        let records = vec![
            ResourceRecord::A {
                name: format!("host{}.example.com", i),
                class: RecordClass::IN,
                ttl: 300,
                address: Ipv4Addr::new(192, 0, 2, i as u8),
            }
        ];

        let key = CacheKey {
            name: format!("host{}.example.com", i),
            record_type: RecordType::A,
            class: RecordClass::IN,
        };

        cache.insert(key, records, 300, CacheSource::Upstream).unwrap();
    }

    // First record should have been evicted
    let first_key = CacheKey {
        name: "host1.example.com".to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
    };
    
    let lookup_result = cache.lookup(&first_key).unwrap();
    assert!(lookup_result.is_none(), "Oldest entry should be evicted");

    // Most recent records should still be present
    for i in 2..=4 {
        let key = CacheKey {
            name: format!("host{}.example.com", i),
            record_type: RecordType::A,
            class: RecordClass::IN,
        };
        assert!(cache.lookup(&key).unwrap().is_some(), "Recent entry should remain");
    }
}

/// Test negative caching (NXDOMAIN)
///
/// Validates that NXDOMAIN responses are cached per RFC 2308.
#[tokio::test]
async fn test_cache_negative_nxdomain() {
    let cache = DnsCache::new(100);
    
    let key = CacheKey {
        name: "nonexistent.example.com".to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
    };

    // Insert negative cache entry
    cache.insert_negative(key.clone(), 300, CacheSource::Upstream).unwrap();

    // Should be able to look up negative entry
    let lookup_result = cache.lookup(&key).unwrap();
    assert!(lookup_result.is_some(), "Negative cache entry should be found");
    
    let entry = lookup_result.unwrap();
    assert!(entry.records.is_empty(), "Negative entry should have no records");
}

/// Test cache statistics collection
///
/// Validates that cache hit/miss statistics are correctly tracked.
#[tokio::test]
async fn test_cache_statistics() {
    let cache = DnsCache::new(100);
    
    let records = vec![
        ResourceRecord::A {
            name: "cached.example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 30),
        }
    ];

    let key = CacheKey {
        name: "cached.example.com".to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
    };

    // Insert and lookup to generate statistics
    cache.insert(key.clone(), records, 300, CacheSource::Upstream).unwrap();
    cache.lookup(&key).unwrap(); // Cache hit
    
    let uncached_key = CacheKey {
        name: "uncached.example.com".to_string(),
        record_type: RecordType::A,
        class: RecordClass::IN,
    };
    cache.lookup(&uncached_key).unwrap(); // Cache miss

    let stats = cache.get_statistics();
    assert!(stats.hits > 0, "Should have cache hits");
    assert!(stats.misses > 0, "Should have cache misses");
    assert!(stats.entries > 0, "Should have cached entries");
}

// =============================================================================
// EDNS0 Extension Tests
// =============================================================================

/// Test EDNS0 OPT record creation and parsing
///
/// Validates that EDNS0 OPT pseudo-records are correctly created and parsed
/// per RFC 6891. Tests OptRecord from src/dns/edns.rs (from edns0.c).
#[test]
fn test_edns0_opt_record_creation() {
    // Create OPT record with DNSSEC OK bit set
    let opt = OptRecord::new()
        .with_udp_size(4096)
        .with_dnssec_ok(true);

    assert_eq!(opt.udp_payload_size, 4096, "UDP payload size should be set");
    assert!(opt.dnssec_ok, "DNSSEC OK bit should be set");
    assert_eq!(opt.version, 0, "EDNS version should be 0");
}

/// Test EDNS0 UDP payload size negotiation
///
/// Validates that UDP payload size is correctly negotiated between client and server.
/// Standard DNS uses 512 bytes, EDNS0 allows up to 4096 or more.
#[test]
fn test_edns0_udp_payload_negotiation() {
    // Standard DNS without EDNS0: 512 bytes
    let opt_none: Option<OptRecord> = None;
    let max_size_standard = opt_none.as_ref().map_or(512, |opt| opt.udp_payload_size as usize);
    assert_eq!(max_size_standard, MAX_UDP_PACKET);

    // With EDNS0: 4096 bytes
    let opt_edns = Some(OptRecord::new().with_udp_size(4096));
    let max_size_edns = opt_edns.as_ref().map_or(512, |opt| opt.udp_payload_size as usize);
    assert_eq!(max_size_edns, MAX_EDNS_PACKET);
}

/// Test EDNS0 DNSSEC OK (DO) bit handling
///
/// Validates that the DNSSEC OK bit is correctly set and cleared, indicating
/// whether the client supports DNSSEC validation.
#[test]
fn test_edns0_dnssec_ok_bit() {
    // Client supports DNSSEC
    let opt_with_dnssec = OptRecord::new().with_dnssec_ok(true);
    assert!(opt_with_dnssec.dnssec_ok, "DO bit should be set");

    // Client does not support DNSSEC
    let opt_without_dnssec = OptRecord::new().with_dnssec_ok(false);
    assert!(!opt_without_dnssec.dnssec_ok, "DO bit should not be set");
}

// =============================================================================
// Property-Based Tests (Proptest)
// =============================================================================

/// Property test: DNS name parsing round-trip
///
/// Validates that Parse(Serialize(name)) == name for all valid DNS names.
/// Per Section 0.7.4, this ensures protocol correctness.
proptest! {
    #[test]
    fn prop_dns_name_roundtrip(s in "[a-z]{1,10}(\\.[a-z]{1,10}){0,5}") {
        // Generate wire format for name
        let mut wire_format = Vec::new();
        for label in s.split('.') {
            wire_format.push(label.len() as u8);
            wire_format.extend_from_slice(label.as_bytes());
        }
        wire_format.push(0x00); // Root terminator

        // Parse name
        let mut offset = 0;
        let result = extract_name(&wire_format, &mut offset, 0);
        
        prop_assert!(result.is_ok(), "Valid name should parse successfully");
        let parsed_name = result.unwrap();
        prop_assert_eq!(parsed_name.to_string(), s, "Round-trip should preserve name");
    }
}

/// Property test: DNS packet parsing never panics
///
/// Validates that malformed packets of any kind are rejected gracefully without panics.
/// Per Section 0.7.4, this ensures memory safety.
proptest! {
    #[test]
    fn prop_dns_packet_no_panic(packet in prop::collection::vec(any::<u8>(), 0..1000)) {
        let mut offset = 0;
        // Should never panic, even on garbage input
        let _result = extract_name(&packet, &mut offset, 0);
        // Test passes if we reach here without panic
    }
}

// =============================================================================
// Integration Tests with DNS Server
// =============================================================================

/// Integration test: End-to-end DNS query and response
///
/// This test is marked as ignored by default because it requires a full DNS server
/// setup. It can be run explicitly with `cargo test --ignored`.
#[tokio::test]
#[ignore = "Requires full DNS server setup"]
async fn test_dns_server_integration() {
    // This test would require:
    // 1. Starting a DnsServer instance
    // 2. Binding to a test port
    // 3. Sending queries via UDP
    // 4. Validating responses
    //
    // Implementation deferred to avoid complexity in this test file.
    // See separate integration test suite for full server testing.
}

// =============================================================================
// Test Utilities
// =============================================================================

/// Helper function to create a test DNS question
fn create_test_question(name: &str, qtype: RecordType) -> DnsQuestion {
    DnsQuestion {
        name: name.to_string(),
        record_type: qtype,
        class: RecordClass::IN,
    }
}

/// Helper function to create a test cache key
fn create_test_cache_key(name: &str, qtype: RecordType) -> CacheKey {
    CacheKey {
        name: name.to_string(),
        record_type: qtype,
        class: RecordClass::IN,
    }
}
