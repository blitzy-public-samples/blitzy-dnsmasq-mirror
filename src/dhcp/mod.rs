// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # DHCP Subsystem
//!
//! This module provides the complete DHCP server implementation for dnsmasq-rs,
//! supporting DHCPv4 (RFC 2131), DHCPv6 (RFC 3315), IPv6 Router Advertisement
//! (RFC 4861), and IPv6 Stateless Address Autoconfiguration (SLAAC, RFC 4862).
//!
//! ## Architecture
//!
//! The DHCP subsystem is organized into several specialized modules:
//!
//! - **v4**: DHCPv4 server implementation (RFC 2131)
//!   - Server logic, state machine, protocol handling, and options parsing
//! - **v6**: DHCPv6 server implementation (RFC 3315)
//!   - Stateful and stateless DHCPv6, DUID handling, prefix delegation
//! - **ipv6**: IPv6-specific functionality
//!   - Router Advertisement (RA) and SLAAC support
//! - **common**: Shared utilities for both DHCPv4 and DHCPv6
//!   - Client configuration matching, option filtering, vendor class matching
//! - **lease**: In-memory lease management
//!   - Lease allocation, lookup, expiration tracking
//! - **lease_store**: Persistent lease storage
//!   - Atomic file operations, database reading/writing
//! - **outpacket**: DHCP packet construction
//!   - Packet builders for DHCPv4 and DHCPv6 responses
//!
//! ## C Source Mapping
//!
//! This Rust implementation replaces approximately 9,000 lines of C code:
//!
//! | C Source File       | Rust Module          | Functionality |
//! |---------------------|----------------------|---------------|
//! | `src/dhcp.c`        | `v4/server.rs`       | DHCPv4 server core logic |
//! | `src/rfc2131.c`     | `v4/protocol.rs`     | RFC 2131 protocol implementation |
//! | `src/dhcp6.c`       | `v6/server.rs`       | DHCPv6 server core logic |
//! | `src/rfc3315.c`     | `v6/protocol.rs`     | RFC 3315 protocol implementation |
//! | `src/dhcp-common.c` | `common.rs`          | Shared DHCPv4/v6 utilities |
//! | `src/lease.c`       | `lease.rs`, `lease_store.rs` | Lease database management |
//! | `src/outpacket.c`   | `outpacket.rs`       | Packet construction helpers |
//! | `src/radv.c`        | `ipv6/radv.rs`       | Router Advertisement |
//! | `src/slaac.c`       | `ipv6/slaac.rs`      | SLAAC implementation |
//!
//! ## Memory Safety Improvements
//!
//! The Rust implementation provides automatic memory safety guarantees:
//!
//! - **No buffer overflows**: Packet parsing uses bounds-checked slices
//! - **No use-after-free**: Borrow checker enforces lifetime correctness
//! - **No null pointer dereferences**: `Option<T>` replaces null pointers
//! - **No double-free**: `Drop` trait ensures single cleanup
//! - **Thread safety**: Type system prevents data races
//!
//! ## Feature Flags
//!
//! The DHCP subsystem respects Cargo feature flags for conditional compilation,
//! mirroring the C implementation's `HAVE_*` macros:
//!
//! - `dhcp-v4`: Enables DHCPv4 server (default enabled)
//! - `dhcp-v6`: Enables DHCPv6 server (default enabled)
//! - `ipv6`: Enables IPv6 Router Advertisement and SLAAC
//! - `scripts`: Enables DHCP lease-change script execution
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::dhcp::{Dhcpv4Server, LeaseDatabase};
//! use std::net::Ipv4Addr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize lease database
//! let lease_db = LeaseDatabase::new(1000); // Max 1000 leases
//!
//! // Create DHCPv4 server
//! let mut dhcp_server = Dhcpv4Server::new(
//!     Ipv4Addr::new(192, 168, 1, 1),  // Server IP
//!     lease_db,
//! );
//!
//! // Bind to DHCP port (requires root privileges initially)
//! dhcp_server.bind().await?;
//!
//! // Process incoming DHCP packets in event loop
//! loop {
//!     let packet = dhcp_server.receive_packet().await?;
//!     dhcp_server.handle_packet(packet).await?;
//! }
//! # }
//! ```
//!
//! ## Configuration Compatibility
//!
//! All configuration options from the C implementation's `dnsmasq.conf` are
//! supported with identical semantics:
//!
//! - `dhcp-range`: Configures address pools
//! - `dhcp-host`: Static host reservations
//! - `dhcp-option`: DHCP option specification
//! - `dhcp-script`: Lease-change script execution
//! - `dhcp-leasefile`: Lease database file path
//!
//! ## Protocol Compliance
//!
//! The implementation maintains strict RFC compliance:
//!
//! - **DHCPv4**: Full RFC 2131 compliance with identical packet formats
//! - **DHCPv6**: Full RFC 3315 compliance including prefix delegation
//! - **Router Advertisement**: RFC 4861 compliance
//! - **SLAAC**: RFC 4862 compliance
//!
//! ## Testing
//!
//! The DHCP subsystem includes comprehensive test coverage:
//!
//! - Unit tests: Inline tests in each module (>80% coverage target)
//! - Integration tests: Protocol compliance tests in `tests/integration/dhcp_tests.rs`
//! - Property tests: Fuzz testing for packet parsing using `proptest`
//! - Acceptance tests: C test suite validates Rust implementation behavior

// =============================================================================
// Submodule Declarations
// =============================================================================

// DHCPv4 implementation (conditionally compiled with dhcp-v4 feature)
#[cfg(feature = "dhcp-v4")]
pub mod v4;

// DHCPv6 implementation (conditionally compiled with dhcp-v6 feature)
#[cfg(feature = "dhcp-v6")]
pub mod v6;

// IPv6 Router Advertisement and SLAAC (conditionally compiled with ipv6 feature)
#[cfg(feature = "ipv6")]
pub mod ipv6;

// Shared utilities for DHCPv4 and DHCPv6 (always available when dhcp feature is enabled)
pub mod common;

// Lease management (in-memory operations)
pub mod lease;

// Lease persistence (file I/O operations)
pub mod lease_store;

// DHCP packet construction utilities
pub mod outpacket;

// =============================================================================
// Public Re-exports
// =============================================================================

// Re-export core types from lease module for ergonomic access
pub use lease::{Lease, LeaseDatabase};

// Re-export lease persistence types
pub use lease_store::LeaseStore;

// Re-export packet construction utilities
pub use outpacket::OutPacket;

// Re-export common utilities
pub use common::find_config;

// DHCPv4 server re-exports (conditional on dhcp-v4 feature)
#[cfg(feature = "dhcp-v4")]
pub use v4::server::Dhcpv4Server;

// DHCPv6 server re-exports (conditional on dhcp-v6 feature)
#[cfg(feature = "dhcp-v6")]
pub use v6::server::Dhcpv6Server;

// IPv6 Router Advertisement re-exports (conditional on ipv6 feature)
#[cfg(feature = "ipv6")]
pub use ipv6::radv::{RouterAdvertiser, RouterAdvertisement, PrefixInfo};

// =============================================================================
// Module Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_organization() {
        // Verify that the module structure is properly organized
        // This is a compile-time verification that all modules exist
        
        // Common module should always be available
        use crate::dhcp::common::DhcpConfig;
        let type_name = std::any::type_name::<DhcpConfig>();
        assert!(type_name.contains("dhcp"));
        assert!(type_name.contains("DhcpConfig"));
    }

    #[cfg(feature = "dhcp-v4")]
    #[test]
    fn test_dhcpv4_feature_enabled() {
        // Verify DHCPv4 types are available when feature is enabled
        let type_name = std::any::type_name::<Dhcpv4Server>();
        assert!(type_name.contains("Dhcpv4Server"));
    }

    #[cfg(feature = "dhcp-v6")]
    #[test]
    fn test_dhcpv6_feature_enabled() {
        // Verify DHCPv6 types are available when feature is enabled
        let type_name = std::any::type_name::<Dhcpv6Server>();
        assert!(type_name.contains("Dhcpv6Server"));
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn test_ipv6_feature_enabled() {
        // Verify IPv6 functionality is available when feature is enabled
        let type_name = std::any::type_name::<RouterAdvertiser>();
        assert!(type_name.contains("RouterAdvertiser"));
    }
}
