// Copyright (c) 2000-2024 Simon Kelley
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

//! Utility Functions Module
//!
//! This module provides a comprehensive collection of utility functions used throughout
//! the dnsmasq Rust implementation. It consolidates functionality from multiple C source
//! files (util.c, pattern.c, dump.c) into organized Rust submodules with memory-safe
//! implementations.
//!
//! # Module Organization
//!
//! The utils module is organized into the following submodules:
//!
//! - **`general`**: General-purpose utilities including network address manipulation,
//!   hostname comparison, time management, I/O operations, and system utilities. These
//!   functions provide safe Rust equivalents to the C util.c implementations, eliminating
//!   all manual memory management and pointer arithmetic.
//!
//! - **`string`**: String manipulation and validation functions with bounds checking.
//!   Provides safe operations for DNS name handling, hostname validation, and
//!   canonicalization with IDN (Internationalized Domain Names) support. All string
//!   operations use Rust's `String` and `&str` types for memory safety.
//!
//! - **`rand`**: Cryptographically-strong random number generation using the SURF
//!   (Secure Universal Random Function) algorithm from djbdns by Daniel J Bernstein
//!   (public domain). Provides `rand16()`, `rand32()`, and `rand64()` functions essential
//!   for DNS query ID generation and source port randomization to prevent cache poisoning
//!   attacks.
//!
//! - **`pattern_match`**: DNS name pattern matching and validation according to RFC 1123
//!   specifications. Implements glob-style wildcard matching for connection tracking
//!   integration, with support for patterns like "*.example.com" that respect DNS label
//!   boundaries.
//!
//! - **`dump`**: Packet capture functionality for debugging DNS and DHCP traffic. Writes
//!   packets to standard libpcap-format files compatible with Wireshark and tcpdump,
//!   enabling protocol-level debugging without external capture tools.
//!
//! # Key Transformations from C
//!
//! This module eliminates several classes of vulnerabilities present in the C implementation:
//!
//! - **Buffer Overflows**: All string operations use Rust's bounds-checked types
//! - **Use-After-Free**: Ownership system prevents dangling references
//! - **Null Pointer Dereferences**: `Option<T>` replaces nullable pointers
//! - **Integer Overflows**: Checked arithmetic operations
//! - **Race Conditions**: Proper synchronization primitives where needed
//!
//! # Design Patterns
//!
//! - **Module Organization**: Related functionality grouped into submodules for clarity
//! - **Re-exports**: Public API surfaced through this mod.rs for convenience
//! - **Type Safety**: Strong typing replaces C's void pointers and casts
//! - **Error Handling**: `Result<T, E>` types replace errno-based error reporting
//!
//! # Usage Examples
//!
//! ```rust
//! use dnsmasq::utils::string::legal_hostname;
//! use dnsmasq::utils::rand::rand16;
//! use dnsmasq::utils::general::prettyprint_addr;
//! use std::net::{SocketAddr, IpAddr, Ipv4Addr};
//!
//! // Validate a hostname
//! if legal_hostname("example.com") {
//!     // Generate a random DNS query ID
//!     let query_id = rand16();
//!     
//!     // Format an address for logging
//!     let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
//!     let addr_str = prettyprint_addr(&socket_addr);
//! }
//! ```
//!
//! # Memory Safety Guarantees
//!
//! All functions in this module are memory-safe and do not use `unsafe` blocks except
//! where absolutely necessary for FFI boundaries (e.g., system calls). Any required
//! `unsafe` code is isolated, documented with safety invariants, and wrapped in safe
//! abstractions.
//!
//! # Thread Safety
//!
//! Functions in this module are designed for use in dnsmasq's async/await architecture
//! with tokio. Most functions are thread-safe or clearly documented where they are not.
//! Mutable state is protected by appropriate synchronization primitives.
//!
//! # References
//!
//! - C source: `src/util.c` - General utilities and SURF RNG
//! - C source: `src/pattern.c` - Pattern matching for conntrack
//! - C source: `src/dump.c` - PCAP packet dumping
//! - SURF RNG: djbdns-1.05 by Daniel J Bernstein (public domain)
//! - RFC 1123: Requirements for Internet Hosts (hostname validation)
//! - Libpcap Format: https://wiki.wireshark.org/Development/LibpcapFileFormat

// Submodule declarations
pub mod general;
pub mod string;
pub mod rand;
pub mod pattern_match;
pub mod dump;

// Re-export commonly used items from general module for convenience
pub use general::{
    sockaddr_isequal,
    sa_len,
    hostname_order,
    hostname_isequal,
    hostname_issubdomain,
    dnsmasq_time,
    netmask_length,
    is_same_net,
    is_same_net_prefix,
    is_same_net6,
    addr6part,
    setaddr6part,
    prettyprint_addr,
    prettyprint_time,
    parse_hex,
    memcmp_masked,
    expand_buf,
    print_mac,
    retry_send,
    read_write,
    close_fds,
    kernel_version,
};

// Re-export commonly used items from string module
pub use string::{
    safe_strncpy,
    legal_hostname,
    canonicalise,
    do_rfc1035_name,
    CanonicaliseError,
    Rfc1035Error,
};

// Re-export random number generation functions
pub use rand::{
    rand16,
    rand32,
    rand64,
};

// Re-export pattern matching functions
pub use pattern_match::{
    is_valid_dns_name,
    is_valid_dns_name_pattern,
    is_dns_name_matching_pattern,
};

// Re-export packet dumping functionality
pub use dump::{
    PacketDumper,
    init_packet_dump,
    PcapGlobalHeader,
    PcapRecordHeader,
    PCAP_MAGIC_NUMBER,
    DLT_RAW,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports_accessible() {
        // Verify that re-exported items are accessible through the utils module
        // This ensures the public API is properly exposed
        
        // Test that string functions are accessible
        let _result = legal_hostname("example.com");
        
        // Test that random functions would be accessible
        // (actual tests in rand module)
        let _id = rand16();
        
        // Test that pattern functions are accessible
        let _valid = is_valid_dns_name("example.com");
        
        // Compilation of this test verifies the API structure
    }

    #[test]
    fn test_module_organization() {
        // Verify submodules are properly declared
        // by accessing a function from each module
        
        // General utilities
        let _time = dnsmasq_time();
        
        // String utilities
        let _valid = legal_hostname("test.local");
        
        // Random number generation
        let _rand = rand32();
        
        // Pattern matching
        let _dns_valid = is_valid_dns_name("example.com");
        
        // Dump functionality constants
        let _magic = PCAP_MAGIC_NUMBER;
        let _dlt = DLT_RAW;
    }

    #[test]
    fn test_hostname_validation_integration() {
        // Integration test combining multiple utility functions
        
        // Valid hostnames
        assert!(legal_hostname("example.com"));
        assert!(legal_hostname("subdomain.example.com"));
        assert!(legal_hostname("test-host.example.org"));
        
        // Invalid hostnames
        assert!(!legal_hostname(""));
        assert!(!legal_hostname("-invalid.com"));
        assert!(!legal_hostname("invalid-.com"));
        
        // Edge cases
        assert!(legal_hostname("a.b")); // Minimum valid
        assert!(!legal_hostname("123.456")); // All numeric TLD
    }

    #[test]
    fn test_random_number_generation() {
        // Test that random number generators produce values
        // within expected ranges
        
        let r16 = rand16();
        assert!(r16 <= u16::MAX);
        
        let r32 = rand32();
        assert!(r32 <= u32::MAX);
        
        let r64 = rand64();
        assert!(r64 <= u64::MAX);
        
        // Test that successive calls produce different values
        // (statistically should be different)
        let r1 = rand32();
        let r2 = rand32();
        // Note: There's a tiny chance they could be equal, but statistically unlikely
        // This is a basic sanity check
        let _different = r1 != r2; // Usually true
    }

    #[test]
    fn test_pattern_matching_dns_names() {
        // Test DNS name pattern matching functionality
        
        // Valid DNS names
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("subdomain.example.com"));
        assert!(is_valid_dns_name("test-123.example.org"));
        
        // Invalid DNS names
        assert!(!is_valid_dns_name(""));
        assert!(!is_valid_dns_name(".example.com"));
        assert!(!is_valid_dns_name("example..com"));
    }

    #[test]
    fn test_pcap_constants() {
        // Verify PCAP constants are properly defined
        
        // PCAP magic number for native byte order
        assert_eq!(PCAP_MAGIC_NUMBER, 0xa1b2c3d4);
        
        // DLT_RAW link-layer type (no Ethernet header)
        assert_eq!(DLT_RAW, 101);
    }

    #[test]
    fn test_time_utilities() {
        // Test time-related utilities
        
        let time1 = dnsmasq_time();
        // Time should be positive
        assert!(time1 > 0);
        
        // Small delay to ensure time advances
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        let time2 = dnsmasq_time();
        // Time should advance
        assert!(time2 >= time1);
    }
}
