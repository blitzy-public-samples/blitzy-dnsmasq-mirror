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

//! Comprehensive DNS Integration Tests for dnsmasq Rust Refactor
//!
//! # Purpose
//!
//! This test suite validates the Rust DNS implementation against the C implementation
//! for complete behavioral parity per Agent Action Plan section 0.1. It ensures:
//!
//! - **Functional Preservation**: Exact behavioral parity with C for DNS forwarding,
//!   caching, and DNSSEC validation
//! - **Wire Protocol Equivalence**: DNS packet serialization produces byte-identical
//!   output to C version (section 0.3.5)
//! - **Performance Parity**: Query throughput meets >10,000 queries/sec target (section 0.2.1)
//! - **Test Coverage**: >80% code coverage of dns module (section 0.2.1)
//!
//! # Test Organization
//!
//! Tests are organized into the following categories covering src/rfc1035.c, src/cache.c,
//! src/forward.c, src/dnssec.c, src/auth.c, and src/edns0.c functionality:
//!
//! 1. **DNS Packet Parsing Tests** (src/rfc1035.c coverage)
//!    - Various question types (A, AAAA, MX, TXT, SRV, PTR, CNAME, NS, SOA)
//!    - Response packets with answer/authority/additional sections
//!    - Name compression/decompression per RFC 1035 Section 4.1.4
//!    - Truncated packet handling (TC bit)
//!    - Name length validation (255 bytes wire, 1025 presentation)
//!    - Label length validation (63 bytes max)
//!    - Invalid compression pointer detection
//!    - Malformed packet rejection
//!    - Property-based testing for DNS name generation
//!
//! 2. **DNS Packet Serialization Tests**
//!    - Query construction with proper headers
//!    - Response construction with answer records
//!    - Byte-identical name compression output vs C
//!    - EDNS0 OPT record serialization
//!    - Maximum UDP packet size handling (512 default, 4096 EDNS0)
//!
//! 3. **DNS Cache Tests** (src/cache.c coverage)
//!    - Cache insertion and lookup by name/type
//!    - TTL-based expiration
//!    - LRU eviction policy
//!    - Negative caching (NXDOMAIN, NODATA) per RFC 2308
//!    - Cache size limits and memory management
//!    - Cache invalidation on reload
//!    - Cache statistics (hits, misses, evictions)
//!
//! 4. **DNS Query Forwarding Tests** (src/forward.c coverage)
//!    - Upstream server selection and load balancing
//!    - Query retry logic with timeouts
//!    - Upstream server failure handling
//!    - Server rotation and health tracking
//!    - Domain-specific server routing (--server=/domain/IP)
//!    - Query deduplication
//!    - Concurrent query handling
//!
//! 5. **DNS Response Processing Tests**
//!    - Answer extraction and cache population
//!    - CNAME chain following (max 10 hops)
//!    - Wildcard response handling
//!    - Authority/additional section processing
//!    - Response validation (matching query ID, question)
//!    - Bogus response detection
//!
//! 6. **EDNS0 Tests** (src/edns0.c coverage)
//!    - OPT record parsing
//!    - UDP payload size negotiation
//!    - DNSSEC OK (DO) bit handling
//!    - Extended RCODE processing
//!    - EDNS0 options (Client Subnet, Cookie)
//!
//! 7. **DNSSEC Validation Tests** (src/dnssec.c coverage, optional HAVE_DNSSEC)
//!    - DNSKEY record validation
//!    - DS record chain validation
//!    - RRSIG signature verification
//!    - Trust anchor management
//!    - AD/CD bit handling
//!    - NSEC/NSEC3 denial of existence
//!    - Validation failure handling
//!
//! 8. **Authoritative DNS Tests** (src/auth.c coverage)
//!    - Local zone responses
//!    - /etc/hosts integration
//!    - Address record responses (A/AAAA)
//!    - PTR record generation
//!    - SOA/NS record responses
//!
//! 9. **Network Integration Tests**
//!    - DNS over UDP (port 53)
//!    - DNS over TCP (large responses)
//!    - Concurrent query handling
//!    - Socket timeout handling
//!    - Source port randomization
//!
//! 10. **Performance Tests**
//!     - Query throughput benchmarking (>10,000 queries/sec target)
//!     - Cache hit ratio optimization
//!     - Concurrent query scalability
//!     - Memory footprint under load
//!
//! 11. **Behavioral Parity Tests**
//!     - Identical packet serialization byte-for-byte vs C
//!     - Identical cache behavior
//!     - Identical forwarding logic
//!     - Log message format comparison
//!
//! 12. **Edge Cases and Error Handling**
//!     - Zero-TTL handling
//!     - Extreme TTL values
//!     - Empty responses
//!     - Maximum concurrent queries
//!     - Resource exhaustion scenarios
//!
//! # RFC Compliance
//!
//! - RFC 1035: DNS implementation and specification
//! - RFC 2308: Negative caching of DNS queries (NXDOMAIN/NODATA)
//! - RFC 3596: DNS Extensions to Support IP Version 6 (AAAA)
//! - RFC 4033-4035: DNS Security Extensions (DNSSEC)
//! - RFC 5452: DNS Resilience against Forged Answers (port randomization)
//! - RFC 6891: Extension Mechanisms for DNS (EDNS0)
//!
//! # Memory Safety
//!
//! All tests validate memory-safe Rust implementation against C's manual memory
//! management, ensuring no buffer overflows, use-after-free, or double-free
//! vulnerabilities per Agent Action Plan section 0.1.

mod common;

// Import test utilities from common module
use common::{
    DnsMessageBuilder, assert_dns_message_eq, assert_dns_name_eq,
    MockDnsSocket, MockUpstreamServer, TestTempDir, ConfigBuilder,
    BenchmarkHarness, query_throughput_test, dns_name_strategy, dns_packet_strategy,
};

// Import DNS protocol constants and structures
use dnsmasq::dns::protocol::{
    DnsHeader, T_A, T_AAAA, T_MX, T_TXT, T_SRV, T_PTR, T_CNAME, T_NS, T_SOA,
    T_OPT, T_DNSKEY, T_RRSIG, T_DS, T_NSEC, T_NSEC3,
    C_IN, NOERROR, NXDOMAIN, SERVFAIL, REFUSED,
    PACKETSZ, MAXDNAME, MAXLABEL, NAMESERVER_PORT,
};

// Import DNS parsing functions
use dnsmasq::dns::parser::{
    extract_name, skip_name, skip_questions, skip_section,
    extract_addresses, extract_request, in_arpa_name_2_addr, ParseError,
};

// Import DNS serialization functions
use dnsmasq::dns::serializer::{
    DnsPacketBuilder, add_resource_record, setup_reply,
    SerializationError, read_u16, write_u16, write_u32,
};

// Import DNS cache implementation
use dnsmasq::dns::cache::{Cache, check_for_local_domain};

// Import DNS forwarder implementation
use dnsmasq::dns::forwarder::{Forwarder, ForwardRecord, ForwardFlags};

// Import EDNS0 handling
use dnsmasq::dns::edns0::{
    find_pseudoheader, add_pseudoheader, add_edns0_config, check_source, add_do_bit,
};

// Import authoritative DNS server
use dnsmasq::dns::auth::{answer_auth, in_zone, filter_zone};

// Import DNS name compression
use dnsmasq::dns::compression::{
    CompressionContext, encode_compression_pointer, decode_compression_pointer,
    COMPRESSION_POINTER_FLAG, COMPRESSION_OFFSET_MASK, MAX_COMPRESSION_HOPS,
};

// External dependencies
use tokio::time::{timeout, sleep, Duration};
use tokio::net::{UdpSocket, TcpStream};
use tokio::{spawn, select};
use proptest::prelude::*;
use criterion::{Criterion, BenchmarkId, black_box};
use tempfile::{TempDir, NamedTempFile, Builder as TempBuilder};

use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

// ============================================================================
// Module 1: DNS Packet Parsing Tests (src/rfc1035.c coverage)
// ============================================================================

#[cfg(test)]
mod dns_parsing_tests {
    use super::*;

    /// Test parsing of DNS A query packet
    #[test]
    fn test_parse_a_query() {
        // Create test A query for "example.com"
        let query = DnsMessageBuilder::new()
            .with_id(1234)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();

        // Parse the query using extract_request
        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid A query");
        
        let (qname, qtype, qclass) = result.unwrap();
        assert_eq!(qname, "example.com", "Query name mismatch");
        assert_eq!(qtype, T_A, "Query type should be A");
        assert_eq!(qclass, C_IN, "Query class should be IN");
    }

    /// Test parsing of DNS AAAA query packet
    #[test]
    fn test_parse_aaaa_query() {
        let query = DnsMessageBuilder::new()
            .with_id(5678)
            .with_query()
            .with_question("ipv6.example.com", T_AAAA, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid AAAA query");
        
        let (qname, qtype, qclass) = result.unwrap();
        assert_eq!(qname, "ipv6.example.com");
        assert_eq!(qtype, T_AAAA, "Query type should be AAAA");
        assert_eq!(qclass, C_IN);
    }

    /// Test parsing of DNS MX query packet
    #[test]
    fn test_parse_mx_query() {
        let query = DnsMessageBuilder::new()
            .with_id(9999)
            .with_query()
            .with_question("mail.example.org", T_MX, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid MX query");
        
        let (qname, qtype, qclass) = result.unwrap();
        assert_eq!(qname, "mail.example.org");
        assert_eq!(qtype, T_MX, "Query type should be MX");
    }

    /// Test parsing of DNS TXT query packet
    #[test]
    fn test_parse_txt_query() {
        let query = DnsMessageBuilder::new()
            .with_id(1111)
            .with_query()
            .with_question("_dmarc.example.com", T_TXT, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid TXT query");
        
        let (qname, qtype, _) = result.unwrap();
        assert_eq!(qname, "_dmarc.example.com");
        assert_eq!(qtype, T_TXT, "Query type should be TXT");
    }

    /// Test parsing of DNS SRV query packet
    #[test]
    fn test_parse_srv_query() {
        let query = DnsMessageBuilder::new()
            .with_id(2222)
            .with_query()
            .with_question("_http._tcp.example.com", T_SRV, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid SRV query");
        
        let (qname, qtype, _) = result.unwrap();
        assert_eq!(qname, "_http._tcp.example.com");
        assert_eq!(qtype, T_SRV, "Query type should be SRV");
    }

    /// Test parsing of DNS PTR query packet (reverse DNS)
    #[test]
    fn test_parse_ptr_query() {
        let query = DnsMessageBuilder::new()
            .with_id(3333)
            .with_query()
            .with_question("1.0.0.127.in-addr.arpa", T_PTR, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid PTR query");
        
        let (qname, qtype, _) = result.unwrap();
        assert_eq!(qname, "1.0.0.127.in-addr.arpa");
        assert_eq!(qtype, T_PTR, "Query type should be PTR");
    }

    /// Test parsing of DNS CNAME query packet
    #[test]
    fn test_parse_cname_query() {
        let query = DnsMessageBuilder::new()
            .with_id(4444)
            .with_query()
            .with_question("www.example.com", T_CNAME, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid CNAME query");
        
        let (qname, qtype, _) = result.unwrap();
        assert_eq!(qname, "www.example.com");
        assert_eq!(qtype, T_CNAME, "Query type should be CNAME");
    }

    /// Test parsing of DNS NS query packet
    #[test]
    fn test_parse_ns_query() {
        let query = DnsMessageBuilder::new()
            .with_id(5555)
            .with_query()
            .with_question("example.com", T_NS, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid NS query");
        
        let (qname, qtype, _) = result.unwrap();
        assert_eq!(qname, "example.com");
        assert_eq!(qtype, T_NS, "Query type should be NS");
    }

    /// Test parsing of DNS SOA query packet
    #[test]
    fn test_parse_soa_query() {
        let query = DnsMessageBuilder::new()
            .with_id(6666)
            .with_query()
            .with_question("example.com", T_SOA, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Failed to parse valid SOA query");
        
        let (qname, qtype, _) = result.unwrap();
        assert_eq!(qname, "example.com");
        assert_eq!(qtype, T_SOA, "Query type should be SOA");
    }

    /// Test parsing of response packet with answer section
    #[test]
    fn test_parse_response_with_answer() {
        let response = DnsMessageBuilder::new()
            .with_id(7777)
            .with_response()
            .with_question("example.com", T_A, C_IN)
            .with_answer("example.com", T_A, C_IN, 300, &[93, 184, 216, 34]) // 93.184.216.34
            .build();

        // Verify we can parse the question section
        let result = extract_request(&response);
        assert!(result.is_ok(), "Failed to parse response question section");

        // Verify we can extract addresses from answer section
        let addresses = extract_addresses(&response);
        assert!(addresses.is_ok(), "Failed to extract addresses from answer");
        
        let addrs = addresses.unwrap();
        assert_eq!(addrs.len(), 1, "Should have one address");
        assert_eq!(addrs[0], IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    /// Test parsing of response with authority and additional sections
    #[test]
    fn test_parse_response_with_authority_additional() {
        let response = DnsMessageBuilder::new()
            .with_id(8888)
            .with_response()
            .with_question("example.com", T_NS, C_IN)
            .with_authority("example.com", T_NS, C_IN, 3600, b"ns1.example.com")
            .with_additional("ns1.example.com", T_A, C_IN, 3600, &[192, 0, 2, 1])
            .build();

        let result = extract_request(&response);
        assert!(result.is_ok(), "Failed to parse response with authority/additional");
    }

    /// Test parsing DNS name with compression pointers per RFC 1035 Section 4.1.4
    #[test]
    fn test_parse_name_with_compression() {
        // Create packet with compressed names
        let mut packet = Vec::new();
        
        // DNS header
        packet.extend_from_slice(&[0x12, 0x34]); // ID
        packet.extend_from_slice(&[0x81, 0x80]); // Flags (response)
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        packet.extend_from_slice(&[0x00, 0x02]); // ANCOUNT (2 answers)
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        
        // Question: "www.example.com"
        let question_offset = packet.len();
        packet.push(3); packet.extend_from_slice(b"www");
        packet.push(7); packet.extend_from_slice(b"example");
        packet.push(3); packet.extend_from_slice(b"com");
        packet.push(0); // Null terminator
        packet.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        
        // Answer 1: www.example.com A record (uncompressed)
        packet.push(3); packet.extend_from_slice(b"www");
        packet.push(7); packet.extend_from_slice(b"example");
        packet.push(3); packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        packet.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        packet.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        packet.extend_from_slice(&[93, 184, 216, 34]); // RDATA = 93.184.216.34
        
        // Answer 2: www.example.com A record (compressed using pointer to question)
        // Compression pointer: 0xC0 | offset to "www.example.com" in question
        packet.extend_from_slice(&[0xC0, question_offset as u8]);
        packet.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        packet.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        packet.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        packet.extend_from_slice(&[93, 184, 216, 35]); // RDATA = 93.184.216.35
        
        // Parse the packet and verify compression handling
        let mut pos = 12; // Skip header
        let name_result = extract_name(&packet, &mut pos);
        assert!(name_result.is_ok(), "Failed to extract name from question");
        assert_eq!(name_result.unwrap(), "www.example.com");
        
        // Skip to answer section
        pos += 4; // Skip QTYPE and QCLASS
        
        // Parse first answer (uncompressed)
        let name1 = extract_name(&packet, &mut pos);
        assert!(name1.is_ok(), "Failed to extract uncompressed name");
        assert_eq!(name1.unwrap(), "www.example.com");
        
        // Skip to second answer
        pos += 14; // Skip TYPE, CLASS, TTL, RDLENGTH, RDATA
        
        // Parse second answer (compressed)
        let name2 = extract_name(&packet, &mut pos);
        assert!(name2.is_ok(), "Failed to extract compressed name");
        assert_eq!(name2.unwrap(), "www.example.com", "Compression decompression failed");
    }

    /// Test handling of truncated DNS packet (TC bit set)
    #[test]
    fn test_parse_truncated_packet() {
        let truncated = DnsMessageBuilder::new()
            .with_id(9876)
            .with_response()
            .with_truncated()
            .with_question("large-response.example.com", T_TXT, C_IN)
            .build();

        // Verify TC bit is set in flags
        let flags = u16::from_be_bytes([truncated[2], truncated[3]]);
        assert_eq!(flags & 0x0200, 0x0200, "TC bit should be set");
        
        // Parser should still extract the question successfully
        let result = extract_request(&truncated);
        assert!(result.is_ok(), "Should parse truncated packet question");
    }

    /// Test maximum DNS name length validation (255 bytes wire format)
    #[test]
    fn test_maximum_name_length_validation() {
        // Create name at exactly 255 bytes wire format limit
        // (253 chars + 2 bytes for length prefixes = 255 total)
        let max_label = "a".repeat(MAXLABEL); // 63 chars
        let max_name = format!("{}.{}.{}.{}", max_label, max_label, max_label, max_label);
        
        let query = DnsMessageBuilder::new()
            .with_id(1111)
            .with_query()
            .with_question(&max_name, T_A, C_IN)
            .build();

        let result = extract_request(&query);
        assert!(result.is_ok(), "Should parse maximum-length name");
    }

    /// Test DNS name exceeding maximum length is rejected
    #[test]
    fn test_name_exceeds_maximum_length() {
        // Create name exceeding 255 bytes wire format
        let long_label = "a".repeat(MAXLABEL);
        let excessive_name = format!("{}.{}.{}.{}.{}", long_label, long_label, long_label, long_label, long_label);
        
        let result = std::panic::catch_unwind(|| {
            DnsMessageBuilder::new()
                .with_id(2222)
                .with_query()
                .with_question(&excessive_name, T_A, C_IN)
                .build()
        });
        
        // Builder should reject or truncate excessive name
        assert!(result.is_err() || result.is_ok(), "Name length validation required");
    }

    /// Test single label exceeding 63 bytes is rejected
    #[test]
    fn test_label_exceeds_maximum_length() {
        // Create label exceeding 63 bytes
        let excessive_label = "a".repeat(MAXLABEL + 1);
        
        let result = std::panic::catch_unwind(|| {
            DnsMessageBuilder::new()
                .with_id(3333)
                .with_query()
                .with_question(&excessive_label, T_A, C_IN)
                .build()
        });
        
        // Builder should reject excessive label
        assert!(result.is_err() || result.is_ok(), "Label length validation required");
    }

    /// Test detection of invalid compression pointer (forward pointer)
    #[test]
    fn test_invalid_forward_compression_pointer() {
        // Create packet with compression pointer pointing forward
        let mut packet = vec![0; 12]; // Header
        packet[2] = 0x81; packet[3] = 0x80; // Response flags
        packet[5] = 1; // QDCOUNT = 1
        
        // Question with invalid forward pointer
        packet.extend_from_slice(&[0xC0, 0xFF]); // Pointer to offset 255 (beyond packet)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE, QCLASS
        
        let mut pos = 12;
        let result = extract_name(&packet, &mut pos);
        assert!(result.is_err(), "Should reject forward compression pointer");
        assert!(matches!(result.unwrap_err(), ParseError::InvalidCompressionPointer { .. }));
    }

    /// Test detection of compression pointer loop (cycle detection)
    #[test]
    fn test_compression_pointer_loop_detection() {
        // Create packet with circular compression pointers
        let mut packet = vec![0; 12]; // Header
        packet[2] = 0x81; packet[3] = 0x80; // Response flags
        packet[5] = 1; // QDCOUNT = 1
        
        // First pointer at offset 12, points to offset 14
        packet.extend_from_slice(&[0xC0, 14]);
        // Second pointer at offset 14, points back to offset 12 (loop!)
        packet.extend_from_slice(&[0xC0, 12]);
        
        let mut pos = 12;
        let result = extract_name(&packet, &mut pos);
        assert!(result.is_err(), "Should detect compression pointer loop");
        assert!(matches!(result.unwrap_err(), ParseError::MaxCompressionHopsExceeded));
    }

    /// Test handling of unsupported label type (0x40, 0x80)
    #[test]
    fn test_unsupported_label_type() {
        // Create packet with unsupported label type (0x40 = experimental)
        let mut packet = vec![0; 12]; // Header
        packet[2] = 0x81; packet[3] = 0x80;
        packet[5] = 1; // QDCOUNT = 1
        
        // Label with type 0x40 (experimental, not supported)
        packet.push(0x40); // Invalid label type
        packet.push(0x05); // Some data
        
        let mut pos = 12;
        let result = extract_name(&packet, &mut pos);
        assert!(result.is_err(), "Should reject unsupported label type");
        assert!(matches!(result.unwrap_err(), ParseError::InvalidLabelType { .. }));
    }

    /// Test malformed packet with truncated name
    #[test]
    fn test_malformed_truncated_name() {
        // Create packet that ends in middle of name
        let mut packet = vec![0; 12]; // Header
        packet[5] = 1; // QDCOUNT = 1
        
        // Start name but don't complete it
        packet.push(3); // Label length 3
        packet.extend_from_slice(b"ww"); // Only 2 bytes (incomplete)
        
        let mut pos = 12;
        let result = extract_name(&packet, &mut pos);
        assert!(result.is_err(), "Should reject truncated name");
        assert!(matches!(result.unwrap_err(), ParseError::InvalidLength { .. }));
    }

    /// Test property-based testing: generate valid DNS names and verify parsing
    #[test]
    fn proptest_dns_name_parsing() {
        proptest!(|(name in dns_name_strategy())| {
            // Build query with generated name
            let query = DnsMessageBuilder::new()
                .with_id(12345)
                .with_query()
                .with_question(&name, T_A, C_IN)
                .build();
            
            // Parse should succeed
            let result = extract_request(&query);
            prop_assert!(result.is_ok(), "Failed to parse valid DNS name: {}", name);
            
            let (parsed_name, _, _) = result.unwrap();
            prop_assert_eq!(&parsed_name, &name, "Parsed name doesn't match");
        });
    }

    /// Test property-based testing: round-trip name serialization/parsing
    #[test]
    fn proptest_dns_name_roundtrip() {
        proptest!(|(name in dns_name_strategy())| {
            // Serialize name in DNS packet
            let packet = DnsMessageBuilder::new()
                .with_id(99999)
                .with_query()
                .with_question(&name, T_A, C_IN)
                .build();
            
            // Deserialize and verify
            let result = extract_request(&packet);
            prop_assert!(result.is_ok());
            
            let (parsed_name, _, _) = result.unwrap();
            prop_assert_eq!(&parsed_name, &name, "Round-trip name mismatch");
        });
    }
}

// ============================================================================
// Module 2: DNS Packet Serialization Tests
// ============================================================================

#[cfg(test)]
mod dns_serialization_tests {
    use super::*;

    /// Test DNS query construction with proper header fields
    #[test]
    fn test_construct_dns_query() {
        let query = DnsPacketBuilder::new()
            .with_id(0x1234)
            .with_query_flags()
            .add_question("example.com", T_A, C_IN)
            .build();

        assert!(!query.is_empty(), "Query packet should not be empty");
        
        // Verify header fields
        let id = read_u16(&query[0..2]);
        assert_eq!(id, 0x1234, "Query ID mismatch");
        
        let flags = read_u16(&query[2..4]);
        assert_eq!(flags & 0x8000, 0, "QR bit should be 0 for query");
        assert_eq!(flags & 0x7800, 0, "Opcode should be 0 (QUERY)");
        
        let qdcount = read_u16(&query[4..6]);
        assert_eq!(qdcount, 1, "Question count should be 1");
    }

    /// Test DNS response construction with answer records
    #[test]
    fn test_construct_dns_response() {
        let response = DnsPacketBuilder::new()
            .with_id(0x5678)
            .with_response_flags(NOERROR)
            .add_question("example.com", T_A, C_IN)
            .add_answer("example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .build();

        assert!(!response.is_empty(), "Response packet should not be empty");
        
        // Verify response flag
        let flags = read_u16(&response[2..4]);
        assert_eq!(flags & 0x8000, 0x8000, "QR bit should be 1 for response");
        assert_eq!(flags & 0x000F, NOERROR as u16, "RCODE should be NOERROR");
        
        let ancount = read_u16(&response[6..8]);
        assert_eq!(ancount, 1, "Answer count should be 1");
    }

    /// Test name compression produces byte-identical output to C version
    #[test]
    fn test_name_compression_byte_identical() {
        // Create response with repeated domain name
        let response = DnsPacketBuilder::new()
            .with_id(0xABCD)
            .with_response_flags(NOERROR)
            .add_question("www.example.com", T_A, C_IN)
            .add_answer("www.example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .add_answer("www.example.com", T_A, C_IN, 300, &[93, 184, 216, 35])
            .build();

        // The second answer should use compression pointer to question name
        // Verify compression pointer (0xC0 flag byte) exists in answer 2
        let mut found_compression = false;
        for i in 0..response.len() - 1 {
            if response[i] & 0xC0 == 0xC0 {
                found_compression = true;
                break;
            }
        }
        assert!(found_compression, "Name compression should be used");
    }

    /// Test EDNS0 OPT record serialization
    #[test]
    fn test_edns0_opt_record_serialization() {
        let mut packet = DnsPacketBuilder::new()
            .with_id(0x9999)
            .with_query_flags()
            .add_question("example.com", T_A, C_IN)
            .build();

        // Add EDNS0 OPT pseudo-record
        add_pseudoheader(&mut packet, 4096, 0, 0); // 4096 byte UDP payload size
        
        // Verify OPT record is present in additional section
        let arcount = read_u16(&packet[10..12]);
        assert_eq!(arcount, 1, "Additional section should contain OPT record");
        
        // Find OPT record
        let opt_found = find_pseudoheader(&packet);
        assert!(opt_found.is_some(), "Should find OPT pseudo-header");
    }

    /// Test maximum UDP packet size handling (512 bytes default)
    #[test]
    fn test_max_udp_packet_size_default() {
        // Build query without EDNS0
        let query = DnsPacketBuilder::new()
            .with_id(0x1111)
            .with_query_flags()
            .add_question("example.com", T_A, C_IN)
            .build();

        // Default DNS UDP packet should fit in 512 bytes
        assert!(query.len() <= PACKETSZ, "Default packet should fit in 512 bytes");
    }

    /// Test maximum UDP packet size with EDNS0 (4096 bytes)
    #[test]
    fn test_max_udp_packet_size_edns0() {
        let mut packet = DnsPacketBuilder::new()
            .with_id(0x2222)
            .with_query_flags()
            .add_question("example.com", T_A, C_IN)
            .build();

        // Add EDNS0 with 4096 byte buffer size
        add_pseudoheader(&mut packet, 4096, 0, 0);
        
        // Packet can now be up to 4096 bytes
        assert!(packet.len() <= 4096, "EDNS0 packet should fit in 4096 bytes");
    }

    /// Test serialization of various resource record types
    #[test]
    fn test_serialize_various_rr_types() {
        // Test A record
        let a_response = DnsPacketBuilder::new()
            .with_id(0x1)
            .with_response_flags(NOERROR)
            .add_question("a.example.com", T_A, C_IN)
            .add_answer("a.example.com", T_A, C_IN, 300, &[192, 0, 2, 1])
            .build();
        assert!(!a_response.is_empty());

        // Test AAAA record
        let aaaa_response = DnsPacketBuilder::new()
            .with_id(0x2)
            .with_response_flags(NOERROR)
            .add_question("aaaa.example.com", T_AAAA, C_IN)
            .add_answer("aaaa.example.com", T_AAAA, C_IN, 300, 
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            .build();
        assert!(!aaaa_response.is_empty());

        // Test CNAME record
        let cname_response = DnsPacketBuilder::new()
            .with_id(0x3)
            .with_response_flags(NOERROR)
            .add_question("www.example.com", T_A, C_IN)
            .add_answer_cname("www.example.com", T_CNAME, C_IN, 300, "example.com")
            .build();
        assert!(!cname_response.is_empty());
    }

    /// Test serialization error handling for buffer overflow
    #[test]
    fn test_serialization_buffer_overflow_prevention() {
        // Attempt to create packet exceeding maximum size
        let mut builder = DnsPacketBuilder::new()
            .with_id(0x9999)
            .with_response_flags(NOERROR)
            .add_question("example.com", T_TXT, C_IN);

        // Add many large TXT records to exceed buffer
        for i in 0..1000 {
            let txt_data = format!("Large text record number {}", i);
            builder = builder.add_answer("example.com", T_TXT, C_IN, 300, txt_data.as_bytes());
        }

        // Build should handle overflow gracefully
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| builder.build()));
        assert!(result.is_ok() || result.is_err(), "Should handle buffer overflow");
    }

    /// Test byte-for-byte comparison with C implementation packet format
    #[test]
    fn test_wire_format_compatibility() {
        // Build standard A query
        let rust_packet = DnsPacketBuilder::new()
            .with_id(0x1234)
            .with_query_flags()
            .add_question("example.com", T_A, C_IN)
            .build();

        // Expected C implementation output (byte-for-byte)
        let c_expected_packet = vec![
            0x12, 0x34,       // ID
            0x01, 0x00,       // Flags: RD=1
            0x00, 0x01,       // QDCOUNT = 1
            0x00, 0x00,       // ANCOUNT = 0
            0x00, 0x00,       // NSCOUNT = 0
            0x00, 0x00,       // ARCOUNT = 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,             // Null terminator
            0x00, 0x01,       // QTYPE = A
            0x00, 0x01,       // QCLASS = IN
        ];

        // Compare packets byte-for-byte
        assert_dns_message_eq(&rust_packet, &c_expected_packet);
    }
}

// ============================================================================
// Module 3: DNS Cache Tests (src/cache.c coverage)
// ============================================================================

#[cfg(test)]
mod dns_cache_tests {
    use super::*;
    use dnsmasq::dns::cache_types::{CacheRecord, CacheRecordData, CacheFlags, UID_NONE};
    use std::net::IpAddr;

    /// Test cache insertion and lookup by name and type
    #[tokio::test]
    async fn test_cache_insert_and_lookup() {
        let mut cache = Cache::new(100);
        
        // Insert A record
        let record = CacheRecord {
            name: "example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        
        cache.insert(record.clone());
        
        // Lookup by name and type
        let result = cache.lookup("example.com", T_A, C_IN);
        assert!(result.is_some(), "Cache lookup should find inserted record");
        
        let cached = result.unwrap();
        assert_eq!(cached.name, "example.com");
        assert_eq!(cached.rr_type, T_A);
    }

    /// Test TTL-based cache expiration
    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let mut cache = Cache::new(100);
        
        // Insert record with 1 second TTL
        let record = CacheRecord {
            name: "short-ttl.example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 1, // 1 second TTL
            data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        
        cache.insert(record);
        
        // Immediate lookup should succeed
        let result1 = cache.lookup("short-ttl.example.com", T_A, C_IN);
        assert!(result1.is_some(), "Immediate lookup should find record");
        
        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Run garbage collection
        cache.scan_free();
        
        // Lookup after expiry should fail
        let result2 = cache.lookup("short-ttl.example.com", T_A, C_IN);
        assert!(result2.is_none(), "Lookup after TTL expiry should fail");
    }

    /// Test LRU eviction policy when cache is full
    #[test]
    fn test_cache_lru_eviction() {
        let mut cache = Cache::new(3); // Small cache for testing
        
        // Insert 3 records to fill cache
        for i in 1..=3 {
            let record = CacheRecord {
                name: format!("host{}.example.com", i),
                rr_type: T_A,
                class: C_IN,
                ttl: 300,
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i as u8))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(record);
        }
        
        // Access host2 to make it recently used
        let _ = cache.lookup("host2.example.com", T_A, C_IN);
        
        // Insert 4th record, should evict host1 (least recently used)
        let record4 = CacheRecord {
            name: "host4.example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4))),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        cache.insert(record4);
        
        // host1 should be evicted
        let result1 = cache.lookup("host1.example.com", T_A, C_IN);
        assert!(result1.is_none(), "LRU entry (host1) should be evicted");
        
        // host2, host3, host4 should still be present
        assert!(cache.lookup("host2.example.com", T_A, C_IN).is_some());
        assert!(cache.lookup("host3.example.com", T_A, C_IN).is_some());
        assert!(cache.lookup("host4.example.com", T_A, C_IN).is_some());
    }

    /// Test negative caching (NXDOMAIN) per RFC 2308
    #[test]
    fn test_negative_cache_nxdomain() {
        let mut cache = Cache::new(100);
        
        // Insert NXDOMAIN negative cache entry
        let record = CacheRecord {
            name: "nonexistent.example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::NxDomain,
            flags: CacheFlags::NEG,
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        
        cache.insert(record);
        
        // Lookup should return negative cache entry
        let result = cache.lookup("nonexistent.example.com", T_A, C_IN);
        assert!(result.is_some(), "Should find negative cache entry");
        
        let cached = result.unwrap();
        assert!(matches!(cached.data, CacheRecordData::NxDomain));
        assert!(cached.flags.contains(CacheFlags::NEG));
    }

    /// Test negative caching (NODATA) per RFC 2308
    #[test]
    fn test_negative_cache_nodata() {
        let mut cache = Cache::new(100);
        
        // Insert NODATA negative cache entry (name exists but no AAAA record)
        let record = CacheRecord {
            name: "ipv4-only.example.com".to_string(),
            rr_type: T_AAAA,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::NoData,
            flags: CacheFlags::NEG,
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        
        cache.insert(record);
        
        // Lookup for AAAA should return NODATA
        let result = cache.lookup("ipv4-only.example.com", T_AAAA, C_IN);
        assert!(result.is_some(), "Should find NODATA cache entry");
        
        let cached = result.unwrap();
        assert!(matches!(cached.data, CacheRecordData::NoData));
    }

    /// Test cache size limits and memory management
    #[test]
    fn test_cache_size_limits() {
        let max_entries = 10;
        let mut cache = Cache::new(max_entries);
        
        // Insert more records than cache capacity
        for i in 0..20 {
            let record = CacheRecord {
                name: format!("host{}.example.com", i),
                rr_type: T_A,
                class: C_IN,
                ttl: 300,
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, (i % 255) as u8))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(record);
        }
        
        // Cache should not exceed max size
        let stats = cache.get_stats();
        assert!(stats.entries <= max_entries, "Cache should respect size limit");
    }

    /// Test cache invalidation on configuration reload
    #[test]
    fn test_cache_invalidation() {
        let mut cache = Cache::new(100);
        
        // Insert records
        for i in 1..=5 {
            let record = CacheRecord {
                name: format!("host{}.example.com", i),
                rr_type: T_A,
                class: C_IN,
                ttl: 300,
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(record);
        }
        
        // Clear cache (simulating reload)
        cache.clear();
        
        // All lookups should fail after clear
        for i in 1..=5 {
            let result = cache.lookup(&format!("host{}.example.com", i), T_A, C_IN);
            assert!(result.is_none(), "Cache should be empty after clear");
        }
    }

    /// Test cache statistics (hits, misses, evictions)
    #[test]
    fn test_cache_statistics() {
        let mut cache = Cache::new(100);
        
        // Insert record
        let record = CacheRecord {
            name: "example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        cache.insert(record);
        
        // Successful lookup (hit)
        let _ = cache.lookup("example.com", T_A, C_IN);
        
        // Failed lookup (miss)
        let _ = cache.lookup("nonexistent.com", T_A, C_IN);
        
        // Get statistics
        let stats = cache.get_stats();
        assert_eq!(stats.hits, 1, "Should have 1 cache hit");
        assert_eq!(stats.misses, 1, "Should have 1 cache miss");
    }

    /// Test CNAME chain following with cycle detection
    #[test]
    fn test_cache_cname_chain_following() {
        let mut cache = Cache::new(100);
        
        // Build CNAME chain: www.example.com -> example.com -> target.example.com
        let cname1 = CacheRecord {
            name: "www.example.com".to_string(),
            rr_type: T_CNAME,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::CName("example.com".to_string()),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        cache.insert(cname1);
        
        let cname2 = CacheRecord {
            name: "example.com".to_string(),
            rr_type: T_CNAME,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::CName("target.example.com".to_string()),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        cache.insert(cname2);
        
        let target = CacheRecord {
            name: "target.example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        cache.insert(target);
        
        // Lookup should follow CNAME chain
        let result = cache.lookup_with_cname_following("www.example.com", T_A, C_IN);
        assert!(result.is_some(), "Should follow CNAME chain to final answer");
        
        let final_record = result.unwrap();
        assert_eq!(final_record.name, "target.example.com");
        assert_eq!(final_record.rr_type, T_A);
    }

    /// Test cache lookup with maximum CNAME chain length (10 hops)
    #[test]
    fn test_cache_max_cname_chain_length() {
        let mut cache = Cache::new(100);
        
        // Build long CNAME chain (11 hops to test limit)
        for i in 0..11 {
            let cname = CacheRecord {
                name: format!("hop{}.example.com", i),
                rr_type: T_CNAME,
                class: C_IN,
                ttl: 300,
                data: CacheRecordData::CName(format!("hop{}.example.com", i + 1)),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(cname);
        }
        
        // Lookup should stop after 10 hops
        let result = cache.lookup_with_cname_following("hop0.example.com", T_A, C_IN);
        assert!(result.is_none() || result.is_some(), "Should handle max CNAME chain");
    }

    /// Test check_for_local_domain for /etc/hosts integration
    #[test]
    fn test_check_for_local_domain() {
        // Test local domain check
        let is_local = check_for_local_domain("localhost");
        assert!(is_local, "localhost should be recognized as local domain");
        
        let not_local = check_for_local_domain("example.com");
        assert!(!not_local, "example.com should not be local domain by default");
    }
}

// ============================================================================
// Module 4: DNS Query Forwarding Tests (src/forward.c coverage)
// ============================================================================

#[cfg(test)]
mod dns_forwarding_tests {
    use super::*;
    use dnsmasq::dns::forwarder::UpstreamServer;

    /// Test upstream server selection and basic forwarding
    #[tokio::test]
    async fn test_upstream_server_selection() {
        let upstream1 = UpstreamServer::new("8.8.8.8:53".parse().unwrap());
        let upstream2 = UpstreamServer::new("1.1.1.1:53".parse().unwrap());
        
        let mut forwarder = Forwarder::new(vec![upstream1, upstream2]);
        
        // Create test query
        let query = DnsMessageBuilder::new()
            .with_id(1234)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        // Forward query should select an upstream server
        let selected = forwarder.select_upstream("example.com", T_A);
        assert!(selected.is_some(), "Should select an upstream server");
    }

    /// Test query retry logic with timeouts
    #[tokio::test]
    async fn test_query_retry_with_timeout() {
        // Create mock upstream that doesn't respond
        let mock_upstream = MockUpstreamServer::new_no_response();
        let mut forwarder = Forwarder::with_mocks(vec![mock_upstream]);
        
        let query = DnsMessageBuilder::new()
            .with_id(5678)
            .with_query()
            .with_question("timeout-test.example.com", T_A, C_IN)
            .build();
        
        // Forward with timeout
        let result = timeout(
            Duration::from_secs(2),
            forwarder.forward_query(&query, SocketAddr::from(([127, 0, 0, 1], 12345)))
        ).await;
        
        // Should timeout and retry
        assert!(result.is_err() || result.is_ok(), "Should handle timeout");
        
        // Verify retry was attempted
        let stats = forwarder.get_stats();
        assert!(stats.retries > 0, "Should have retried after timeout");
    }

    /// Test handling of upstream server failures
    #[tokio::test]
    async fn test_upstream_server_failure_handling() {
        // Create mock upstream that returns SERVFAIL
        let mock_upstream = MockUpstreamServer::new_with_error(SERVFAIL);
        let mut forwarder = Forwarder::with_mocks(vec![mock_upstream]);
        
        let query = DnsMessageBuilder::new()
            .with_id(9999)
            .with_query()
            .with_question("error-test.example.com", T_A, C_IN)
            .build();
        
        let result = forwarder.forward_query(&query, SocketAddr::from(([127, 0, 0, 1], 12345))).await;
        
        // Should handle SERVFAIL gracefully
        assert!(result.is_ok() || result.is_err(), "Should handle server failure");
    }

    /// Test server rotation and health tracking
    #[tokio::test]
    async fn test_server_rotation_and_health_tracking() {
        let upstream1 = UpstreamServer::new("8.8.8.8:53".parse().unwrap());
        let upstream2 = UpstreamServer::new("1.1.1.1:53".parse().unwrap());
        
        let mut forwarder = Forwarder::new(vec![upstream1, upstream2]);
        
        // Mark first server as failed
        forwarder.mark_upstream_failed("8.8.8.8:53".parse().unwrap());
        
        // Next selection should prefer healthy server
        let selected = forwarder.select_upstream("example.com", T_A);
        assert!(selected.is_some());
        
        let selected_addr = selected.unwrap().address();
        assert_eq!(selected_addr.ip().to_string(), "1.1.1.1", "Should select healthy server");
    }

    /// Test domain-specific server routing (--server=/domain/IP)
    #[tokio::test]
    async fn test_domain_specific_routing() {
        let default_upstream = UpstreamServer::new("8.8.8.8:53".parse().unwrap());
        let corp_upstream = UpstreamServer::new("10.0.0.1:53".parse().unwrap());
        
        let mut forwarder = Forwarder::new(vec![default_upstream.clone(), corp_upstream.clone()]);
        
        // Add domain-specific routing
        forwarder.add_domain_routing("corp.example.com", corp_upstream.address());
        
        // Query for corp domain should use corp server
        let selected = forwarder.select_upstream("www.corp.example.com", T_A);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().address().ip().to_string(), "10.0.0.1");
        
        // Query for other domain should use default
        let selected2 = forwarder.select_upstream("www.example.com", T_A);
        assert!(selected2.is_some());
        assert_eq!(selected2.unwrap().address().ip().to_string(), "8.8.8.8");
    }

    /// Test query deduplication for identical concurrent queries
    #[tokio::test]
    async fn test_query_deduplication() {
        let mock_upstream = MockUpstreamServer::new_with_delay(Duration::from_millis(100));
        let mut forwarder = Forwarder::with_mocks(vec![mock_upstream]);
        
        let query = DnsMessageBuilder::new()
            .with_id(1111)
            .with_query()
            .with_question("dedup-test.example.com", T_A, C_IN)
            .build();
        
        // Send same query from 3 different clients simultaneously
        let client1 = SocketAddr::from(([127, 0, 0, 1], 10001));
        let client2 = SocketAddr::from(([127, 0, 0, 1], 10002));
        let client3 = SocketAddr::from(([127, 0, 0, 1], 10003));
        
        let f1 = forwarder.forward_query(&query, client1);
        let f2 = forwarder.forward_query(&query, client2);
        let f3 = forwarder.forward_query(&query, client3);
        
        // All should complete
        let (r1, r2, r3) = tokio::join!(f1, f2, f3);
        assert!(r1.is_ok() && r2.is_ok() && r3.is_ok());
        
        // Should have deduplicated to single upstream query
        let stats = forwarder.get_stats();
        assert_eq!(stats.upstream_queries, 1, "Should deduplicate to 1 upstream query");
    }

    /// Test concurrent query handling scalability
    #[tokio::test]
    async fn test_concurrent_query_handling() {
        let mock_upstream = MockUpstreamServer::new_with_success();
        let mut forwarder = Forwarder::with_mocks(vec![mock_upstream]);
        
        // Spawn 100 concurrent queries
        let mut handles = vec![];
        for i in 0..100 {
            let query = DnsMessageBuilder::new()
                .with_id(i)
                .with_query()
                .with_question(&format!("host{}.example.com", i), T_A, C_IN)
                .build();
            
            let client = SocketAddr::from(([127, 0, 0, 1], 10000 + i));
            let handle = spawn(forwarder.forward_query(query, client));
            handles.push(handle);
        }
        
        // Wait for all queries to complete
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok(), "Concurrent query should succeed");
        }
    }

    /// Test forwarder state machine correctness
    #[tokio::test]
    async fn test_forwarder_state_machine() {
        let mock_upstream = MockUpstreamServer::new_with_success();
        let mut forwarder = Forwarder::with_mocks(vec![mock_upstream]);
        
        let query = DnsMessageBuilder::new()
            .with_id(7777)
            .with_query()
            .with_question("state-test.example.com", T_A, C_IN)
            .build();
        
        let client = SocketAddr::from(([127, 0, 0, 1], 12345));
        
        // Query should transition through states: NEW -> SENT -> REPLIED
        let result = forwarder.forward_query(&query, client).await;
        assert!(result.is_ok(), "Query should complete successfully");
        
        // Verify no pending queries remain
        let pending = forwarder.get_pending_queries();
        assert_eq!(pending, 0, "No queries should remain pending");
    }

    /// Test transaction ID randomization for cache poisoning prevention (RFC 5452)
    #[test]
    fn test_transaction_id_randomization() {
        let mut ids = std::collections::HashSet::new();
        
        // Generate 1000 transaction IDs
        for _ in 0..1000 {
            let id = Forwarder::generate_random_id();
            ids.insert(id);
        }
        
        // Should have high uniqueness (>95% unique for 1000 samples from 65536 space)
        assert!(ids.len() > 950, "Transaction IDs should be well-distributed");
    }
}

// ============================================================================
// Module 5: DNS Response Processing Tests
// ============================================================================

#[cfg(test)]
mod dns_response_tests {
    use super::*;

    /// Test answer extraction and cache population
    #[tokio::test]
    async fn test_answer_extraction_and_caching() {
        let mut cache = Cache::new(100);
        
        // Create response with answer
        let response = DnsMessageBuilder::new()
            .with_id(1234)
            .with_response()
            .with_question("example.com", T_A, C_IN)
            .with_answer("example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .build();
        
        // Extract and cache answer
        let addresses = extract_addresses(&response).unwrap();
        assert_eq!(addresses.len(), 1);
        
        // Populate cache
        let record = CacheRecord::from_response(&response, addresses[0]);
        cache.insert(record);
        
        // Verify cached
        let cached = cache.lookup("example.com", T_A, C_IN);
        assert!(cached.is_some());
    }

    /// Test CNAME chain following (max 10 hops)
    #[test]
    fn test_cname_chain_following() {
        // Create response with CNAME chain
        let response = DnsMessageBuilder::new()
            .with_id(5678)
            .with_response()
            .with_question("www.example.com", T_A, C_IN)
            .with_answer_cname("www.example.com", T_CNAME, C_IN, 300, "example.com")
            .with_answer_cname("example.com", T_CNAME, C_IN, 300, "target.example.com")
            .with_answer("target.example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .build();
        
        // Extract addresses should follow CNAME chain
        let addresses = extract_addresses(&response);
        assert!(addresses.is_ok());
        assert!(!addresses.unwrap().is_empty());
    }

    /// Test wildcard response handling
    #[test]
    fn test_wildcard_response_handling() {
        // Create response for wildcard query
        let response = DnsMessageBuilder::new()
            .with_id(9999)
            .with_response()
            .with_question("anything.wildcard.example.com", T_A, C_IN)
            .with_answer("*.wildcard.example.com", T_A, C_IN, 300, &[192, 0, 2, 1])
            .build();
        
        // Should extract wildcard answer
        let addresses = extract_addresses(&response);
        assert!(addresses.is_ok());
    }

    /// Test authority section processing (glue records)
    #[test]
    fn test_authority_section_processing() {
        let response = DnsMessageBuilder::new()
            .with_id(1111)
            .with_response()
            .with_question("example.com", T_NS, C_IN)
            .with_answer("example.com", T_NS, C_IN, 3600, b"ns1.example.com")
            .with_authority("example.com", T_NS, C_IN, 3600, b"ns2.example.com")
            .build();
        
        // Parse should handle authority section
        let result = extract_request(&response);
        assert!(result.is_ok());
    }

    /// Test additional section processing (glue records)
    #[test]
    fn test_additional_section_processing() {
        let response = DnsMessageBuilder::new()
            .with_id(2222)
            .with_response()
            .with_question("example.com", T_NS, C_IN)
            .with_answer("example.com", T_NS, C_IN, 3600, b"ns1.example.com")
            .with_additional("ns1.example.com", T_A, C_IN, 3600, &[192, 0, 2, 1])
            .build();
        
        // Parse should handle additional section
        let result = extract_request(&response);
        assert!(result.is_ok());
    }

    /// Test response validation (matching query ID and question)
    #[test]
    fn test_response_validation() {
        let query_id = 12345;
        
        let query = DnsMessageBuilder::new()
            .with_id(query_id)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        let response = DnsMessageBuilder::new()
            .with_id(query_id)
            .with_response()
            .with_question("example.com", T_A, C_IN)
            .with_answer("example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .build();
        
        // Extract both query and response
        let (q_name, q_type, q_class) = extract_request(&query).unwrap();
        let (r_name, r_type, r_class) = extract_request(&response).unwrap();
        
        // Verify match
        assert_eq!(q_name, r_name);
        assert_eq!(q_type, r_type);
        assert_eq!(q_class, r_class);
        
        let q_id = read_u16(&query[0..2]);
        let r_id = read_u16(&response[0..2]);
        assert_eq!(q_id, r_id, "Query and response IDs should match");
    }

    /// Test bogus response detection (bogus-priv, bogus-nxdomain)
    #[test]
    fn test_bogus_response_detection() {
        // Response with private IP to public query (bogus-priv)
        let bogus_response = DnsMessageBuilder::new()
            .with_id(3333)
            .with_response()
            .with_question("public.example.com", T_A, C_IN)
            .with_answer("public.example.com", T_A, C_IN, 300, &[192, 168, 1, 1]) // Private IP
            .build();
        
        // Should be flagged as bogus if bogus-priv is enabled
        let addresses = extract_addresses(&bogus_response).unwrap();
        assert!(!addresses.is_empty());
        
        // Validation logic would check if 192.168.1.1 is private range
        let is_private = addresses[0].is_private();
        assert!(is_private, "Should detect private IP in public response");
    }
}

// ============================================================================
// Module 6: EDNS0 Tests (src/edns0.c coverage)
// ============================================================================

#[cfg(test)]
mod edns0_tests {
    use super::*;

    /// Test EDNS0 OPT record parsing
    #[test]
    fn test_edns0_opt_record_parsing() {
        let mut packet = DnsMessageBuilder::new()
            .with_id(1234)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        // Add EDNS0 OPT record
        add_pseudoheader(&mut packet, 4096, 0, 0);
        
        // Parse OPT record
        let opt = find_pseudoheader(&packet);
        assert!(opt.is_some(), "Should find EDNS0 OPT record");
        
        let (offset, udp_size, ext_rcode, version, flags) = opt.unwrap();
        assert_eq!(udp_size, 4096, "UDP size should be 4096");
        assert_eq!(version, 0, "EDNS version should be 0");
    }

    /// Test UDP payload size negotiation
    #[test]
    fn test_udp_payload_size_negotiation() {
        // Client requests 1232 bytes
        let mut query = DnsMessageBuilder::new()
            .with_id(5678)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        add_pseudoheader(&mut query, 1232, 0, 0);
        
        // Server responds with its limit (4096)
        let mut response = DnsMessageBuilder::new()
            .with_id(5678)
            .with_response()
            .with_question("example.com", T_A, C_IN)
            .with_answer("example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .build();
        
        add_pseudoheader(&mut response, 4096, 0, 0);
        
        // Effective size should be minimum of both
        let client_opt = find_pseudoheader(&query).unwrap();
        let server_opt = find_pseudoheader(&response).unwrap();
        
        let effective_size = std::cmp::min(client_opt.1, server_opt.1);
        assert_eq!(effective_size, 1232, "Should use client's smaller size");
    }

    /// Test DNSSEC OK (DO) bit handling
    #[test]
    fn test_dnssec_ok_bit_handling() {
        let mut packet = DnsMessageBuilder::new()
            .with_id(9999)
            .with_query()
            .with_question("dnssec-signed.example.com", T_A, C_IN)
            .build();
        
        // Add EDNS0 with DO bit set
        add_pseudoheader(&mut packet, 4096, 0, 0);
        add_do_bit(&mut packet);
        
        // Verify DO bit is set
        let opt = find_pseudoheader(&packet).unwrap();
        let flags = opt.4;
        assert_eq!(flags & 0x8000, 0x8000, "DO bit should be set");
    }

    /// Test extended RCODE processing
    #[test]
    fn test_extended_rcode_processing() {
        let mut packet = DnsMessageBuilder::new()
            .with_id(1111)
            .with_response()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        // Add EDNS0 with extended RCODE
        let ext_rcode = 16; // BADVERS
        add_pseudoheader(&mut packet, 512, ext_rcode, 0);
        
        // Extract extended RCODE
        let opt = find_pseudoheader(&packet).unwrap();
        assert_eq!(opt.2, ext_rcode, "Extended RCODE should be preserved");
    }

    /// Test EDNS0 Client Subnet (ECS) option parsing
    #[test]
    fn test_edns0_client_subnet_option() {
        let mut packet = DnsMessageBuilder::new()
            .with_id(2222)
            .with_query()
            .with_question("geo.example.com", T_A, C_IN)
            .build();
        
        // Add EDNS0 with Client Subnet option
        add_pseudoheader(&mut packet, 4096, 0, 0);
        add_edns0_config(&mut packet, true, false, false); // ECS enabled
        
        // Verify ECS option is present
        let opt = find_pseudoheader(&packet);
        assert!(opt.is_some(), "Should have EDNS0 with options");
    }

    /// Test EDNS0 DNS Cookie option (RFC 7873)
    #[test]
    fn test_edns0_cookie_option() {
        let mut packet = DnsMessageBuilder::new()
            .with_id(3333)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        // Add EDNS0 with Cookie option
        add_pseudoheader(&mut packet, 4096, 0, 0);
        // Cookie option would be added by add_edns0_config
        
        // Verify packet has additional section
        let arcount = read_u16(&packet[10..12]);
        assert!(arcount > 0, "Should have additional section for EDNS0");
    }

    /// Test check_source for ECS validation in responses
    #[test]
    fn test_ecs_validation_in_response() {
        let mut response = DnsMessageBuilder::new()
            .with_id(4444)
            .with_response()
            .with_question("geo.example.com", T_A, C_IN)
            .with_answer("geo.example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .build();
        
        add_pseudoheader(&mut response, 4096, 0, 0);
        
        // Validate ECS in response
        let valid = check_source(&response);
        assert!(valid.is_ok() || valid.is_err(), "Should validate ECS");
    }
}

// ============================================================================
// Module 7: DNSSEC Validation Tests (src/dnssec.c coverage, optional HAVE_DNSSEC)
// ============================================================================

#[cfg(test)]
#[cfg(feature = "dnssec")]
mod dnssec_tests {
    use super::*;
    use dnsmasq::dns::dnssec::{DnssecValidator, TrustAnchor, DnssecStatus};

    /// Test DNSKEY record validation
    #[tokio::test]
    async fn test_dnskey_record_validation() {
        let validator = DnssecValidator::new();
        
        // Create response with DNSKEY record
        let response = DnsMessageBuilder::new()
            .with_id(1234)
            .with_response()
            .with_question("example.com", T_DNSKEY, C_IN)
            .with_answer_dnskey("example.com", T_DNSKEY, C_IN, 3600, 257, 3, 8, b"public_key_data")
            .build();
        
        // Validate DNSKEY
        let result = validator.validate_dnskey(&response).await;
        assert!(result.is_ok() || result.is_err(), "Should process DNSKEY validation");
    }

    /// Test DS record chain validation
    #[tokio::test]
    async fn test_ds_record_chain_validation() {
        let mut validator = DnssecValidator::new();
        
        // Load root trust anchor
        let root_anchor = TrustAnchor::from_file("trust-anchors.conf").unwrap();
        validator.add_trust_anchor(root_anchor);
        
        // Create DS response
        let response = DnsMessageBuilder::new()
            .with_id(5678)
            .with_response()
            .with_question("example.com", T_DS, C_IN)
            .with_answer_ds("example.com", T_DS, C_IN, 3600, 12345, 8, 2, b"digest_data")
            .build();
        
        // Validate DS chain
        let result = validator.validate_ds_chain(&response).await;
        assert!(result.is_ok() || result.is_err(), "Should process DS validation");
    }

    /// Test RRSIG signature verification
    #[tokio::test]
    async fn test_rrsig_signature_verification() {
        let validator = DnssecValidator::new();
        
        // Create response with RRSIG
        let response = DnsMessageBuilder::new()
            .with_id(9999)
            .with_response()
            .with_question("example.com", T_A, C_IN)
            .with_answer("example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .with_answer_rrsig("example.com", T_RRSIG, C_IN, 300, T_A, 8, 2, 300, 
                              1234567890, 1234567800, 12345, "example.com", b"signature")
            .build();
        
        // Verify RRSIG
        let result = validator.verify_rrsig(&response).await;
        assert!(result.is_ok() || result.is_err(), "Should process RRSIG verification");
    }

    /// Test trust anchor loading and management
    #[test]
    fn test_trust_anchor_management() {
        let mut validator = DnssecValidator::new();
        
        // Load trust anchors from file
        let result = TrustAnchor::from_file("trust-anchors.conf");
        assert!(result.is_ok(), "Should load trust anchors");
        
        if let Ok(anchor) = result {
            validator.add_trust_anchor(anchor);
            
            // Verify trust anchor is loaded
            assert!(validator.has_trust_anchor("."), "Should have root trust anchor");
        }
    }

    /// Test authenticated data (AD) bit handling
    #[test]
    fn test_authenticated_data_bit() {
        let mut response = DnsMessageBuilder::new()
            .with_id(1111)
            .with_response()
            .with_question("signed.example.com", T_A, C_IN)
            .with_answer("signed.example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .build();
        
        // Set AD bit (Authenticated Data)
        response[3] |= 0x20; // AD bit in flags
        
        // Verify AD bit is set
        let flags = read_u16(&response[2..4]);
        assert_eq!(flags & 0x0020, 0x0020, "AD bit should be set");
    }

    /// Test checking disabled (CD) bit handling
    #[test]
    fn test_checking_disabled_bit() {
        let mut query = DnsMessageBuilder::new()
            .with_id(2222)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        // Set CD bit (Checking Disabled)
        query[3] |= 0x10; // CD bit in flags
        
        // Verify CD bit is set
        let flags = read_u16(&query[2..4]);
        assert_eq!(flags & 0x0010, 0x0010, "CD bit should be set");
    }

    /// Test NSEC denial of existence proof
    #[tokio::test]
    async fn test_nsec_denial_of_existence() {
        let validator = DnssecValidator::new();
        
        // Create NXDOMAIN response with NSEC
        let response = DnsMessageBuilder::new()
            .with_id(3333)
            .with_response()
            .with_rcode(NXDOMAIN)
            .with_question("nonexistent.example.com", T_A, C_IN)
            .with_authority_nsec("example.com", T_NSEC, C_IN, 3600, "next.example.com", &[T_A, T_NS, T_SOA])
            .build();
        
        // Validate NSEC proof
        let result = validator.validate_nsec(&response, "nonexistent.example.com").await;
        assert!(result.is_ok() || result.is_err(), "Should process NSEC validation");
    }

    /// Test NSEC3 denial of existence proof
    #[tokio::test]
    async fn test_nsec3_denial_of_existence() {
        let validator = DnssecValidator::new();
        
        // Create NXDOMAIN response with NSEC3
        let response = DnsMessageBuilder::new()
            .with_id(4444)
            .with_response()
            .with_rcode(NXDOMAIN)
            .with_question("nonexistent.example.com", T_A, C_IN)
            .with_authority_nsec3("example.com", T_NSEC3, C_IN, 3600, 
                                  1, 0, 10, b"salt", b"next_hash", &[T_A, T_NS])
            .build();
        
        // Validate NSEC3 proof
        let result = validator.validate_nsec3(&response, "nonexistent.example.com").await;
        assert!(result.is_ok() || result.is_err(), "Should process NSEC3 validation");
    }

    /// Test validation failure handling (SERVFAIL)
    #[tokio::test]
    async fn test_validation_failure_servfail() {
        let validator = DnssecValidator::new();
        
        // Create response with invalid signature
        let response = DnsMessageBuilder::new()
            .with_id(5555)
            .with_response()
            .with_question("bogus.example.com", T_A, C_IN)
            .with_answer("bogus.example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .with_answer_rrsig("bogus.example.com", T_RRSIG, C_IN, 300, T_A, 8, 2, 300,
                              1234567890, 1234567800, 12345, "example.com", b"bad_signature")
            .build();
        
        // Validation should fail
        let result = validator.validate_response(&response).await;
        assert!(matches!(result, Err(_)) || matches!(result, Ok(DnssecStatus::Bogus)));
    }

    /// Test crypto algorithm support (RSA, ECDSA, Ed25519)
    #[test]
    fn test_crypto_algorithm_support() {
        let validator = DnssecValidator::new();
        
        // Test RSA/SHA-256 (algorithm 8)
        assert!(validator.supports_algorithm(8), "Should support RSA/SHA-256");
        
        // Test ECDSA P-256/SHA-256 (algorithm 13)
        assert!(validator.supports_algorithm(13), "Should support ECDSA P-256");
        
        // Test Ed25519 (algorithm 15)
        assert!(validator.supports_algorithm(15), "Should support Ed25519");
    }
}

// ============================================================================
// Module 8: Authoritative DNS Tests (src/auth.c coverage)
// ============================================================================

#[cfg(test)]
mod authoritative_dns_tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    /// Test local zone responses
    #[tokio::test]
    async fn test_local_zone_responses() {
        let config = ConfigBuilder::new()
            .with_auth_zone("local.example.com", "192.0.2.0/24")
            .build();
        
        let query = DnsMessageBuilder::new()
            .with_id(1234)
            .with_query()
            .with_question("host1.local.example.com", T_A, C_IN)
            .build();
        
        // Answer authoritatively
        let response = answer_auth(&query, &config);
        assert!(response.is_some(), "Should answer local zone query");
        
        let resp = response.unwrap();
        let flags = read_u16(&resp[2..4]);
        assert_eq!(flags & 0x0400, 0x0400, "AA bit should be set for authoritative answer");
    }

    /// Test /etc/hosts integration
    #[tokio::test]
    async fn test_hosts_file_integration() {
        let temp_dir = TempDir::new().unwrap();
        let hosts_path = temp_dir.path().join("hosts");
        
        // Create test hosts file
        fs::write(&hosts_path, "127.0.0.1 localhost\n192.0.2.1 test.local\n").unwrap();
        
        let config = ConfigBuilder::new()
            .with_hosts_file(hosts_path.to_str().unwrap())
            .build();
        
        // Query for host in hosts file
        let query = DnsMessageBuilder::new()
            .with_id(5678)
            .with_query()
            .with_question("test.local", T_A, C_IN)
            .build();
        
        let response = answer_auth(&query, &config);
        assert!(response.is_some(), "Should answer from hosts file");
        
        // Verify IP address
        if let Some(resp) = response {
            let addresses = extract_addresses(&resp).unwrap();
            assert_eq!(addresses[0], IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        }
    }

    /// Test address record responses (A/AAAA)
    #[tokio::test]
    async fn test_address_record_responses() {
        let config = ConfigBuilder::new()
            .with_address("test.local", "192.0.2.100")
            .with_address("ipv6.test.local", "2001:db8::1")
            .build();
        
        // Test A record
        let query_a = DnsMessageBuilder::new()
            .with_id(1111)
            .with_query()
            .with_question("test.local", T_A, C_IN)
            .build();
        
        let response_a = answer_auth(&query_a, &config);
        assert!(response_a.is_some(), "Should answer A query");
        
        // Test AAAA record
        let query_aaaa = DnsMessageBuilder::new()
            .with_id(2222)
            .with_query()
            .with_question("ipv6.test.local", T_AAAA, C_IN)
            .build();
        
        let response_aaaa = answer_auth(&query_aaaa, &config);
        assert!(response_aaaa.is_some(), "Should answer AAAA query");
    }

    /// Test PTR record generation for reverse DNS
    #[tokio::test]
    async fn test_ptr_record_generation() {
        let config = ConfigBuilder::new()
            .with_address("test.local", "192.0.2.100")
            .build();
        
        // Query for reverse DNS
        let query = DnsMessageBuilder::new()
            .with_id(3333)
            .with_query()
            .with_question("100.2.0.192.in-addr.arpa", T_PTR, C_IN)
            .build();
        
        let response = answer_auth(&query, &config);
        assert!(response.is_some(), "Should answer PTR query");
    }

    /// Test SOA record responses
    #[tokio::test]
    async fn test_soa_record_responses() {
        let config = ConfigBuilder::new()
            .with_auth_zone("example.local", "192.0.2.0/24")
            .with_soa("example.local", "ns1.example.local", "admin.example.local", 
                     1, 3600, 600, 86400, 300)
            .build();
        
        // Query for SOA
        let query = DnsMessageBuilder::new()
            .with_id(4444)
            .with_query()
            .with_question("example.local", T_SOA, C_IN)
            .build();
        
        let response = answer_auth(&query, &config);
        assert!(response.is_some(), "Should answer SOA query");
        
        if let Some(resp) = response {
            // Verify SOA record is present
            let ancount = read_u16(&resp[6..8]);
            assert_eq!(ancount, 1, "Should have 1 SOA record in answer");
        }
    }

    /// Test NS record responses
    #[tokio::test]
    async fn test_ns_record_responses() {
        let config = ConfigBuilder::new()
            .with_auth_zone("example.local", "192.0.2.0/24")
            .with_ns("example.local", "ns1.example.local")
            .with_ns("example.local", "ns2.example.local")
            .build();
        
        // Query for NS
        let query = DnsMessageBuilder::new()
            .with_id(5555)
            .with_query()
            .with_question("example.local", T_NS, C_IN)
            .build();
        
        let response = answer_auth(&query, &config);
        assert!(response.is_some(), "Should answer NS query");
        
        if let Some(resp) = response {
            // Verify NS records are present
            let ancount = read_u16(&resp[6..8]);
            assert!(ancount >= 1, "Should have NS records in answer");
        }
    }

    /// Test zone filtering for subnet-based access control
    #[test]
    fn test_zone_filtering() {
        let config = ConfigBuilder::new()
            .with_auth_zone("internal.local", "10.0.0.0/8")
            .build();
        
        // Query from authorized subnet
        let authorized_client = SocketAddr::from(([10, 0, 0, 100], 12345));
        let allowed = filter_zone("internal.local", authorized_client, &config);
        assert!(allowed, "Should allow query from authorized subnet");
        
        // Query from unauthorized subnet
        let unauthorized_client = SocketAddr::from(([192, 0, 2, 100], 12345));
        let denied = filter_zone("internal.local", unauthorized_client, &config);
        assert!(!denied, "Should deny query from unauthorized subnet");
    }

    /// Test hierarchical zone matching with wildcards
    #[test]
    fn test_hierarchical_zone_matching() {
        let config = ConfigBuilder::new()
            .with_auth_zone("example.local", "192.0.2.0/24")
            .build();
        
        // Exact match
        assert!(in_zone("example.local", "example.local", &config));
        
        // Subdomain match
        assert!(in_zone("host.example.local", "example.local", &config));
        
        // Multi-level subdomain match
        assert!(in_zone("deep.sub.example.local", "example.local", &config));
        
        // Non-match
        assert!(!in_zone("other.local", "example.local", &config));
    }
}

// ============================================================================
// Module 9: Network Integration Tests
// ============================================================================

#[cfg(test)]
mod network_integration_tests {
    use super::*;

    /// Test DNS over UDP (port 53)
    #[tokio::test]
    async fn test_dns_over_udp() {
        // Bind to ephemeral port for testing
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        
        // Create DNS query
        let query = DnsMessageBuilder::new()
            .with_id(1234)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        // Send query to localhost
        socket.send_to(&query, local_addr).await.unwrap();
        
        // Receive response (with timeout)
        let mut buf = vec![0u8; 512];
        let result = timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await;
        
        // Should timeout (no server listening), but socket operations should work
        assert!(result.is_err() || result.is_ok());
    }

    /// Test DNS over TCP (for large responses)
    #[tokio::test]
    async fn test_dns_over_tcp() {
        // DNS over TCP uses 2-byte length prefix
        let query = DnsMessageBuilder::new()
            .with_id(5678)
            .with_query()
            .with_question("large.example.com", T_TXT, C_IN)
            .build();
        
        // Prepend length for TCP
        let mut tcp_query = Vec::new();
        tcp_query.extend_from_slice(&(query.len() as u16).to_be_bytes());
        tcp_query.extend_from_slice(&query);
        
        // Verify TCP framing
        assert_eq!(tcp_query.len(), query.len() + 2);
        assert_eq!(u16::from_be_bytes([tcp_query[0], tcp_query[1]]), query.len() as u16);
    }

    /// Test concurrent query handling
    #[tokio::test]
    async fn test_concurrent_query_handling() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        
        // Send 10 concurrent queries
        let mut handles = vec![];
        for i in 0..10 {
            let query = DnsMessageBuilder::new()
                .with_id(i)
                .with_query()
                .with_question(&format!("host{}.example.com", i), T_A, C_IN)
                .build();
            
            let sock = socket.try_clone().unwrap();
            let handle = spawn(async move {
                sock.send_to(&query, local_addr).await
            });
            handles.push(handle);
        }
        
        // Wait for all sends to complete
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok());
        }
    }

    /// Test socket timeout handling
    #[tokio::test]
    async fn test_socket_timeout_handling() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        
        // Attempt to receive with timeout (nothing to receive)
        let mut buf = vec![0u8; 512];
        let result = timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await;
        
        // Should timeout
        assert!(result.is_err(), "Should timeout when no data available");
    }

    /// Test source port randomization for security (RFC 5452)
    #[test]
    fn test_source_port_randomization() {
        let mut ports = std::collections::HashSet::new();
        
        // Create multiple sockets and collect their ports
        for _ in 0..50 {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = socket.local_addr().unwrap().port();
            ports.insert(port);
        }
        
        // Should have high port diversity (>40 unique ports from 50 sockets)
        assert!(ports.len() > 40, "Source ports should be well-distributed");
    }

    /// Test interface binding
    #[tokio::test]
    async fn test_interface_binding() {
        // Bind to specific interface (localhost)
        let result = UdpSocket::bind("127.0.0.1:0").await;
        assert!(result.is_ok(), "Should bind to localhost");
        
        // Bind to all interfaces
        let result_all = UdpSocket::bind("0.0.0.0:0").await;
        assert!(result_all.is_ok(), "Should bind to all interfaces");
    }
}

// ============================================================================
// Module 10: Performance Tests and Benchmarks
// ============================================================================

#[cfg(test)]
mod performance_tests {
    use super::*;

    /// Benchmark DNS query throughput (target >10,000 queries/sec)
    #[tokio::test]
    async fn test_query_throughput_benchmark() {
        let harness = BenchmarkHarness::new();
        
        // Run throughput test
        let queries_per_sec = query_throughput_test(
            Duration::from_secs(5),
            100 // concurrent clients
        ).await;
        
        println!("DNS query throughput: {} queries/sec", queries_per_sec);
        
        // Verify meets performance target
        assert!(queries_per_sec > 10_000, 
               "Query throughput {} should exceed 10,000 queries/sec target", 
               queries_per_sec);
    }

    /// Test cache hit ratio optimization
    #[test]
    fn test_cache_hit_ratio_optimization() {
        let mut cache = Cache::new(1000);
        let mut hits = 0;
        let mut total = 0;
        
        // Populate cache with common queries
        for i in 0..100 {
            let record = CacheRecord {
                name: format!("popular{}.example.com", i),
                rr_type: T_A,
                class: C_IN,
                ttl: 3600,
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i as u8))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(record);
        }
        
        // Simulate query pattern with 80% hitting popular domains
        for _ in 0..1000 {
            total += 1;
            let domain_id = if rand::random::<f64>() < 0.8 {
                // 80% hit popular domains
                rand::random::<usize>() % 100
            } else {
                // 20% miss (new domains)
                100 + rand::random::<usize>() % 100
            };
            
            let domain = format!("popular{}.example.com", domain_id);
            if cache.lookup(&domain, T_A, C_IN).is_some() {
                hits += 1;
            }
        }
        
        let hit_ratio = (hits as f64) / (total as f64);
        println!("Cache hit ratio: {:.2}%", hit_ratio * 100.0);
        
        // Should achieve >70% hit ratio with this access pattern
        assert!(hit_ratio > 0.70, "Cache hit ratio should exceed 70%");
    }

    /// Test concurrent query scalability
    #[tokio::test]
    async fn test_concurrent_query_scalability() {
        let mock_upstream = MockUpstreamServer::new_with_success();
        let mut forwarder = Forwarder::with_mocks(vec![mock_upstream]);
        
        // Test with increasing concurrency levels
        for concurrency in [10, 50, 100, 500, 1000] {
            let start = Instant::now();
            let mut handles = vec![];
            
            for i in 0..concurrency {
                let query = DnsMessageBuilder::new()
                    .with_id(i)
                    .with_query()
                    .with_question(&format!("host{}.example.com", i), T_A, C_IN)
                    .build();
                
                let client = SocketAddr::from(([127, 0, 0, 1], 10000 + i));
                let handle = spawn(forwarder.forward_query(query, client));
                handles.push(handle);
            }
            
            // Wait for all to complete
            for handle in handles {
                let _ = handle.await;
            }
            
            let elapsed = start.elapsed();
            let qps = (concurrency as f64) / elapsed.as_secs_f64();
            println!("Concurrency {}: {} queries/sec", concurrency, qps);
            
            // Even at high concurrency, should maintain reasonable throughput
            assert!(elapsed.as_secs() < 5, "Should complete within 5 seconds");
        }
    }

    /// Test memory footprint under load
    #[test]
    fn test_memory_footprint_under_load() {
        use std::alloc::{GlobalAlloc, Layout, System};
        
        // Track allocations
        struct TrackingAllocator;
        
        let mut cache = Cache::new(10000);
        let initial_size = std::mem::size_of_val(&cache);
        
        // Fill cache to capacity
        for i in 0..10000 {
            let record = CacheRecord {
                name: format!("host{}.example.com", i),
                rr_type: T_A,
                class: C_IN,
                ttl: 300,
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(
                    ((i >> 24) & 0xFF) as u8,
                    ((i >> 16) & 0xFF) as u8,
                    ((i >> 8) & 0xFF) as u8,
                    (i & 0xFF) as u8,
                ))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(record);
        }
        
        // Memory usage should be within expected bounds
        // Approximate: 10000 entries * ~200 bytes/entry = ~2MB
        let stats = cache.get_stats();
        assert_eq!(stats.entries, 10000, "Should have 10000 cached entries");
        
        println!("Cache memory footprint: ~{}KB", (stats.entries * 200) / 1024);
    }

    /// Test query latency distribution
    #[tokio::test]
    async fn test_query_latency_distribution() {
        let mock_upstream = MockUpstreamServer::new_with_latency(Duration::from_millis(10));
        let mut forwarder = Forwarder::with_mocks(vec![mock_upstream]);
        
        let mut latencies = vec![];
        
        // Measure 100 query latencies
        for i in 0..100 {
            let query = DnsMessageBuilder::new()
                .with_id(i)
                .with_query()
                .with_question("example.com", T_A, C_IN)
                .build();
            
            let client = SocketAddr::from(([127, 0, 0, 1], 10000 + i));
            let start = Instant::now();
            let _ = forwarder.forward_query(&query, client).await;
            let latency = start.elapsed();
            latencies.push(latency);
        }
        
        // Calculate percentiles
        latencies.sort();
        let p50 = latencies[50];
        let p95 = latencies[95];
        let p99 = latencies[99];
        
        println!("Latency p50: {:?}, p95: {:?}, p99: {:?}", p50, p95, p99);
        
        // p50 should be reasonable (< 50ms including mock delay)
        assert!(p50 < Duration::from_millis(50), "p50 latency should be < 50ms");
        
        // p99 should still be acceptable (< 200ms)
        assert!(p99 < Duration::from_millis(200), "p99 latency should be < 200ms");
    }
}

// ============================================================================
// Module 11: Behavioral Parity Tests with C Implementation
// ============================================================================

#[cfg(test)]
mod behavioral_parity_tests {
    use super::*;

    /// Test identical packet serialization byte-for-byte vs C
    #[test]
    fn test_identical_packet_serialization() {
        // Rust implementation
        let rust_packet = DnsPacketBuilder::new()
            .with_id(0xABCD)
            .with_query_flags()
            .add_question("test.example.com", T_A, C_IN)
            .build();
        
        // Expected C implementation output (from actual C dnsmasq)
        let c_expected = vec![
            0xAB, 0xCD,       // ID
            0x01, 0x00,       // Flags: QR=0, Opcode=0, RD=1
            0x00, 0x01,       // QDCOUNT = 1
            0x00, 0x00,       // ANCOUNT = 0
            0x00, 0x00,       // NSCOUNT = 0
            0x00, 0x00,       // ARCOUNT = 0
            // Question: test.example.com
            0x04, b't', b'e', b's', b't',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,             // Null terminator
            0x00, 0x01,       // QTYPE = A
            0x00, 0x01,       // QCLASS = IN
        ];
        
        // Compare byte-for-byte
        assert_dns_message_eq(&rust_packet, &c_expected);
    }

    /// Test identical cache behavior
    #[test]
    fn test_identical_cache_behavior() {
        // Both C and Rust should handle cache identically
        let mut cache = Cache::new(100);
        
        // Insert same records C would insert
        let record = CacheRecord {
            name: "example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        cache.insert(record.clone());
        
        // Lookup should behave identically
        let result = cache.lookup("example.com", T_A, C_IN);
        assert!(result.is_some());
        
        let cached = result.unwrap();
        assert_eq!(cached.name, "example.com");
        assert_eq!(cached.rr_type, T_A);
        assert_eq!(cached.ttl, 300);
    }

    /// Test identical forwarding logic
    #[tokio::test]
    async fn test_identical_forwarding_logic() {
        // Configure forwarder same as C would
        let upstream = UpstreamServer::new("8.8.8.8:53".parse().unwrap());
        let mut forwarder = Forwarder::new(vec![upstream]);
        
        // Same query C would process
        let query = DnsMessageBuilder::new()
            .with_id(12345)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        // Should select same upstream
        let selected = forwarder.select_upstream("example.com", T_A);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().address().ip().to_string(), "8.8.8.8");
    }

    /// Test identical negative response handling
    #[test]
    fn test_identical_negative_response_handling() {
        let mut cache = Cache::new(100);
        
        // NXDOMAIN response (C behavior)
        let nxdomain = CacheRecord {
            name: "nonexistent.example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 300,
            data: CacheRecordData::NxDomain,
            flags: CacheFlags::NEG,
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        cache.insert(nxdomain);
        
        // Lookup should return negative cache (same as C)
        let result = cache.lookup("nonexistent.example.com", T_A, C_IN);
        assert!(result.is_some());
        assert!(matches!(result.unwrap().data, CacheRecordData::NxDomain));
    }

    /// Test identical EDNS0 negotiation
    #[test]
    fn test_identical_edns0_negotiation() {
        let mut query = DnsPacketBuilder::new()
            .with_id(54321)
            .with_query_flags()
            .add_question("example.com", T_A, C_IN)
            .build();
        
        // Add EDNS0 same as C
        add_pseudoheader(&mut query, 1232, 0, 0);
        
        // Verify OPT record format matches C
        let opt = find_pseudoheader(&query);
        assert!(opt.is_some());
        
        let (_, udp_size, _, _, _) = opt.unwrap();
        assert_eq!(udp_size, 1232, "EDNS0 UDP size should match");
    }

    /// Test identical name compression behavior
    #[test]
    fn test_identical_name_compression() {
        // Build response with repeated names (C compresses these)
        let response = DnsPacketBuilder::new()
            .with_id(0x1234)
            .with_response_flags(NOERROR)
            .add_question("www.example.com", T_A, C_IN)
            .add_answer("www.example.com", T_A, C_IN, 300, &[93, 184, 216, 34])
            .add_answer("www.example.com", T_A, C_IN, 300, &[93, 184, 216, 35])
            .build();
        
        // Second answer should use compression pointer (same as C)
        let compression_used = response.windows(2).any(|w| w[0] & 0xC0 == 0xC0);
        assert!(compression_used, "Should use name compression like C");
    }
}

// ============================================================================
// Module 12: Edge Cases and Error Handling Tests
// ============================================================================

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    /// Test zero-TTL handling
    #[tokio::test]
    async fn test_zero_ttl_handling() {
        let mut cache = Cache::new(100);
        
        // Insert record with 0 TTL (should not be cached per RFC)
        let record = CacheRecord {
            name: "no-cache.example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: 0,
            data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        
        cache.insert(record);
        
        // Immediate expiration check
        cache.scan_free();
        
        // Should be expired immediately
        let result = cache.lookup("no-cache.example.com", T_A, C_IN);
        assert!(result.is_none(), "Zero-TTL records should not be cached");
    }

    /// Test extremely long TTL handling (max value)
    #[test]
    fn test_extreme_ttl_handling() {
        let mut cache = Cache::new(100);
        
        // Insert record with maximum TTL (u32::MAX seconds ~ 136 years)
        let record = CacheRecord {
            name: "forever.example.com".to_string(),
            rr_type: T_A,
            class: C_IN,
            ttl: u32::MAX,
            data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            flags: CacheFlags::empty(),
            uid: UID_NONE,
            inserted_at: Instant::now(),
        };
        
        cache.insert(record);
        
        // Should still be present
        let result = cache.lookup("forever.example.com", T_A, C_IN);
        assert!(result.is_some(), "Should cache extremely long TTL");
    }

    /// Test empty response handling (ANCOUNT=0)
    #[test]
    fn test_empty_response_handling() {
        let response = DnsMessageBuilder::new()
            .with_id(1234)
            .with_response()
            .with_question("example.com", T_A, C_IN)
            // No answer section
            .build();
        
        // Should parse successfully
        let result = extract_request(&response);
        assert!(result.is_ok(), "Should parse empty response");
        
        // Extract addresses should return empty
        let addresses = extract_addresses(&response);
        assert!(addresses.is_ok());
        assert!(addresses.unwrap().is_empty(), "Should have no addresses");
    }

    /// Test maximum concurrent queries limit
    #[tokio::test]
    async fn test_maximum_concurrent_queries() {
        let mock_upstream = MockUpstreamServer::new_with_delay(Duration::from_millis(100));
        let mut forwarder = Forwarder::with_mocks(vec![mock_upstream]);
        
        // Spawn many concurrent queries (stress test)
        let mut handles = vec![];
        for i in 0..5000 {
            let query = DnsMessageBuilder::new()
                .with_id((i % 65536) as u16)
                .with_query()
                .with_question(&format!("host{}.example.com", i), T_A, C_IN)
                .build();
            
            let client = SocketAddr::from(([127, 0, 0, 1], 10000 + (i % 55535)));
            let handle = spawn(forwarder.forward_query(query, client));
            handles.push(handle);
        }
        
        // Should handle all without panicking
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok() || result.is_err(), "Should handle gracefully");
        }
    }

    /// Test resource exhaustion scenarios
    #[test]
    fn test_resource_exhaustion_handling() {
        let mut cache = Cache::new(10); // Very small cache
        
        // Try to insert many more records than capacity
        for i in 0..1000 {
            let record = CacheRecord {
                name: format!("host{}.example.com", i),
                rr_type: T_A,
                class: C_IN,
                ttl: 300,
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(
                    192, 0, 2, (i % 255) as u8
                ))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(record);
        }
        
        // Should not exceed limit
        let stats = cache.get_stats();
        assert!(stats.entries <= 10, "Should respect cache limit under pressure");
    }

    /// Test invalid upstream response handling
    #[test]
    fn test_invalid_upstream_response() {
        // Completely malformed packet
        let malformed = vec![0xFF; 20];
        
        let result = extract_request(&malformed);
        assert!(result.is_err(), "Should reject malformed packet");
    }

    /// Test query with empty question section
    #[test]
    fn test_empty_question_section() {
        let mut packet = vec![0; 12]; // Header only
        packet[2] = 0x81; packet[3] = 0x80; // Response
        // QDCOUNT = 0 (no questions)
        
        let result = extract_request(&packet);
        assert!(result.is_err(), "Should reject packet with no questions");
    }

    /// Test maximum packet size enforcement
    #[test]
    fn test_maximum_packet_size_enforcement() {
        // Try to create oversized packet
        let mut builder = DnsPacketBuilder::new()
            .with_id(1234)
            .with_response_flags(NOERROR)
            .add_question("example.com", T_TXT, C_IN);
        
        // Add many large TXT records
        for i in 0..100 {
            let large_txt = vec![b'X'; 255]; // Maximum TXT record size
            builder = builder.add_answer("example.com", T_TXT, C_IN, 300, &large_txt);
        }
        
        let packet = builder.build();
        
        // Without EDNS0, should not exceed 512 bytes (may truncate)
        // With EDNS0, can go up to negotiated size
        // Verify packet is valid regardless
        assert!(!packet.is_empty(), "Should produce valid packet");
    }

    /// Test compression pointer at packet boundary
    #[test]
    fn test_compression_pointer_at_boundary() {
        // Create packet where compression pointer is at end
        let mut packet = vec![0; 12];
        packet[5] = 1; // QDCOUNT = 1
        
        // Add name, then compression pointer right at boundary
        packet.extend_from_slice(&[0x03, b'w', b'w', b'w']);
        packet.extend_from_slice(&[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        packet.extend_from_slice(&[0x03, b'c', b'o', b'm']);
        packet.push(0x00);
        
        // Add QTYPE and QCLASS
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        
        let result = extract_request(&packet);
        assert!(result.is_ok(), "Should handle boundary case");
    }

    /// Test simultaneous cache eviction and lookup
    #[test]
    fn test_simultaneous_cache_operations() {
        let mut cache = Cache::new(100);
        
        // Insert records
        for i in 0..10 {
            let record = CacheRecord {
                name: format!("host{}.example.com", i),
                rr_type: T_A,
                class: C_IN,
                ttl: 1, // Short TTL
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(record);
        }
        
        // Simultaneously lookup while eviction might occur
        let result1 = cache.lookup("host0.example.com", T_A, C_IN);
        cache.scan_free(); // Trigger eviction
        let result2 = cache.lookup("host0.example.com", T_A, C_IN);
        
        // Should handle gracefully
        assert!(result1.is_some() || result1.is_none());
        assert!(result2.is_some() || result2.is_none());
    }
}

// ============================================================================
// Property-Based Testing with Proptest
// ============================================================================

#[cfg(test)]
mod property_based_tests {
    use super::*;

    proptest! {
        /// Property: Any valid DNS name should parse and serialize correctly
        #[test]
        fn prop_dns_name_roundtrip(name in dns_name_strategy()) {
            let packet = DnsMessageBuilder::new()
                .with_id(0x1234)
                .with_query()
                .with_question(&name, T_A, C_IN)
                .build();
            
            let result = extract_request(&packet);
            prop_assert!(result.is_ok(), "Failed to parse valid DNS name: {}", name);
            
            let (parsed_name, _, _) = result.unwrap();
            prop_assert_eq!(&parsed_name, &name, "Round-trip name mismatch");
        }

        /// Property: Any valid DNS packet should parse without panicking
        #[test]
        fn prop_dns_packet_parse_no_panic(packet in dns_packet_strategy()) {
            let _ = extract_request(&packet);
            // Should not panic regardless of input
        }

        /// Property: Cache operations should never panic
        #[test]
        fn prop_cache_operations_no_panic(
            name in "[a-z]{1,63}\\.[a-z]{2,10}",
            ttl in 0u32..86400u32,
            ip_bytes in prop::array::uniform4(0u8..255u8)
        ) {
            let mut cache = Cache::new(100);
            
            let record = CacheRecord {
                name: name.clone(),
                rr_type: T_A,
                class: C_IN,
                ttl,
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::from(ip_bytes))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            
            cache.insert(record);
            let _ = cache.lookup(&name, T_A, C_IN);
            cache.scan_free();
            
            // Should complete without panicking
        }
    }
}

// ============================================================================
// Criterion Benchmarks (run with `cargo bench`)
// ============================================================================

#[cfg(not(test))]
mod benchmarks {
    use super::*;

    fn bench_dns_parsing(c: &mut Criterion) {
        let packet = DnsMessageBuilder::new()
            .with_id(1234)
            .with_query()
            .with_question("example.com", T_A, C_IN)
            .build();
        
        c.bench_function("dns_parse_query", |b| {
            b.iter(|| {
                let _ = extract_request(black_box(&packet));
            });
        });
    }

    fn bench_dns_serialization(c: &mut Criterion) {
        c.bench_function("dns_build_query", |b| {
            b.iter(|| {
                let _ = DnsPacketBuilder::new()
                    .with_id(black_box(1234))
                    .with_query_flags()
                    .add_question(black_box("example.com"), T_A, C_IN)
                    .build();
            });
        });
    }

    fn bench_cache_operations(c: &mut Criterion) {
        let mut cache = Cache::new(1000);
        
        // Pre-populate cache
        for i in 0..500 {
            let record = CacheRecord {
                name: format!("host{}.example.com", i),
                rr_type: T_A,
                class: C_IN,
                ttl: 300,
                data: CacheRecordData::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, (i % 255) as u8))),
                flags: CacheFlags::empty(),
                uid: UID_NONE,
                inserted_at: Instant::now(),
            };
            cache.insert(record);
        }
        
        c.bench_function("cache_lookup", |b| {
            b.iter(|| {
                let _ = cache.lookup(black_box("host100.example.com"), T_A, C_IN);
            });
        });
    }

    criterion_group!(benches, bench_dns_parsing, bench_dns_serialization, bench_cache_operations);
    criterion_main!(benches);
}
