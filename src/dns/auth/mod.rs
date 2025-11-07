// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// Authoritative DNS module organization for zone management and authoritative
// query response generation, providing feature-gated compilation via 'auth-dns'
// Cargo feature flag to match C's HAVE_AUTH conditional compilation.
//
// Translated from: src/auth.c (module organization, lines 73-1251)

//! Authoritative DNS server module
//!
//! This module implements authoritative DNS serving for configured local zones,
//! allowing dnsmasq to act as the primary nameserver for specific domains.
//!
//! # Features
//!
//! - **Local zone authority**: Serve authoritative answers for configured domains
//! - **SOA and NS records**: Proper zone authority with Start of Authority records
//! - **DHCP integration**: Serve A/AAAA records for DHCP-assigned hostnames
//! - **Split-horizon DNS**: Different answers based on client subnet
//! - **AXFR support**: Zone transfers to secondary nameservers
//! - **PTR records**: Reverse DNS from DHCP leases and static configuration
//!
//! # Configuration
//!
//! Authoritative zones are configured via the `auth-zone` directive:
//!
//! ```text
//! auth-zone=example.local,192.168.1.0/24
//! auth-soa=12345,hostmaster.example.local
//! ```
//!
//! # Architecture
//!
//! The authoritative module integrates with:
//! - **DNS cache**: Lookup DHCP hostnames and /etc/hosts entries
//! - **DNS protocol**: Parse queries and construct authoritative responses
//! - **Configuration**: Load zone definitions and SOA parameters
//! - **Network**: Subnet-based filtering for split-horizon DNS
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use dnsmasq::dns::auth::{AuthZone, SoaRecord, answer_authoritative_query};
//! use dnsmasq::dns::{DnsMessage, DnsHeader};
//! use dnsmasq::dns::cache::DnsCache;
//! use dnsmasq::config::types::Config;
//! use std::net::SocketAddr;
//! use std::sync::{Arc, RwLock};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # // Set up example context with dummy values
//! # let query_packet = vec![0u8; 512]; // Dummy DNS query packet
//! # let mut header = DnsHeader::default();
//! # let peer_addr: SocketAddr = "127.0.0.1:53".parse()?;
//! # let cache = Arc::new(RwLock::new(DnsCache::new(1000)));
//! # let config = Config::default();
//! #
//! let zones = vec![
//!     AuthZone {
//!         domain: "local".to_string(),
//!         subnets: Vec::new(),
//!         excluded: Vec::new(),
//!         soa: SoaRecord::new(
//!             "ns1.local".to_string(),
//!             "admin.local".to_string()
//!         ),
//!         nameservers: vec!["ns1.local".to_string()],
//!         interface_names: Vec::new(),
//!     }
//! ];
//!
//! let query = DnsMessage::parse(&query_packet)?;
//! let response = answer_authoritative_query(
//!     &mut header,
//!     &query,
//!     peer_addr,
//!     false,
//!     &zones,
//!     cache,
//!     &config
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - AXFR zone transfers should be restricted to authorized secondaries
//! - Subnet filtering prevents information disclosure across network boundaries
//! - Integration with DHCP requires careful hostname validation
//!
//! # Standards Compliance
//!
//! - RFC 1034: Domain Names - Concepts and Facilities
//! - RFC 1035: Domain Names - Implementation and Specification
//! - RFC 2136: Dynamic Updates (future enhancement)
//! - RFC 5936: DNS Zone Transfer Protocol (AXFR)
//!
//! # Feature Flag
//!
//! This module is only compiled when the `auth-dns` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! dnsmasq = { version = "*", features = ["auth-dns"] }
//! ```
//!
//! This corresponds to the C implementation's `HAVE_AUTH` compile-time macro
//! from auth.c line 73.
//!
//! # Memory Safety
//!
//! All authoritative DNS operations use Rust's ownership system for memory
//! safety. Zone data structures use Vec and String for dynamic allocation,
//! eliminating buffer overflows present in C's fixed-size arrays. Subnet
//! matching uses standard library IP address types instead of manual pointer
//! arithmetic.
//!
//! # C Implementation Reference
//!
//! This module replaces src/auth.c functionality:
//! - Zone matching and filtering (find_subnet, find_exclude, filter_zone)
//! - Authoritative query processing (answer_auth)
//! - Domain membership checking (in_zone)
//! - SOA and NS record generation
//! - Integration with cache for DHCP hostname lookups

// Feature gate - matches C's #ifdef HAVE_AUTH from auth.c line 73
#[cfg(feature = "auth-dns")]
pub mod zone;

// Re-export commonly used types for convenience
#[cfg(feature = "auth-dns")]
pub use zone::{
    AuthZone,                   // Main zone configuration structure
    IpNetwork,                  // IP network with CIDR prefix for subnet matching
    SoaRecord,                  // SOA record data for zone authority
    answer_authoritative_query, // Primary entry point for query processing
    is_in_zone,                 // Check if domain name is within zone
    should_answer_for_subnet,   // Subnet-based filtering for split-horizon DNS
};

// Re-export error type for authoritative DNS operations
#[cfg(feature = "auth-dns")]
pub use crate::types::errors::AuthError;

#[cfg(test)]
#[cfg(feature = "auth-dns")]
mod tests {
    use super::*;

    #[test]
    fn test_module_compiles() {
        // Smoke test that module compiles with feature enabled
        // Verifies all re-exports are accessible
    }

    #[test]
    fn test_exports_available() {
        // Verify public API exports are accessible
        // This ensures re-exports work correctly
        let _ = answer_authoritative_query;
        let _ = is_in_zone;
        let _ = should_answer_for_subnet;
    }
}
