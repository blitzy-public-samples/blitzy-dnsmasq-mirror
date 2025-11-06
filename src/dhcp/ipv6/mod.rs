// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # IPv6 DHCP Extensions: Router Advertisement and SLAAC
//!
//! This module provides comprehensive IPv6 stateless configuration functionality through
//! Router Advertisement (RA) per RFC 4861 and Stateless Address Autoconfiguration (SLAAC)
//! per RFC 4862. It serves as the organizational entry point for IPv6 network configuration
//! capabilities, replacing the C source files `src/radv.c` and `src/slaac.c`.
//!
//! ## Architecture Overview
//!
//! The IPv6 stateless configuration architecture consists of two primary components:
//!
//! ### Router Advertisement (`radv` module)
//!
//! Implements ICMPv6 Router Advertisement transmission as specified in RFC 4861 Section 6.
//! Router Advertisements inform IPv6 clients about:
//! - Available network prefixes for address autoconfiguration
//! - Router lifetime and reachability
//! - Maximum Transmission Unit (MTU) for the link
//! - Managed (M) and Other (O) configuration flags for DHCPv6 coordination
//! - Recursive DNS Server (RDNSS) options per RFC 6106
//! - DNS Search List (DNSSL) options per RFC 6106
//! - Router preferences and advertisement intervals
//!
//! The implementation supports both periodic unsolicited advertisements (sent to the
//! all-nodes multicast address FF02::1) and solicited advertisements (triggered by
//! Router Solicitation messages received on the all-routers multicast address FF02::2).
//!
//! ### SLAAC (`slaac` module)
//!
//! Implements IPv6 Stateless Address Autoconfiguration as specified in RFC 4862.
//! SLAAC enables hosts to automatically configure IPv6 addresses by:
//! - Deriving interface identifiers from MAC addresses using Modified EUI-64 format (RFC 4291)
//! - Combining interface identifiers with advertised prefixes
//! - Performing Duplicate Address Detection (DAD) via ICMPv6 Echo Request/Reply
//! - Automatically registering confirmed addresses in the DNS cache
//! - Managing address lifetimes (valid and preferred lifetimes)
//!
//! ## RFC Compliance
//!
//! This module implements the following RFCs:
//!
//! - **RFC 4861**: Neighbor Discovery for IP version 6 (IPv6)
//!   - Section 4: Message formats (Router Advertisement, Router Solicitation)
//!   - Section 6: Router Advertisement transmission behavior
//!   - Section 4.6: Prefix Information Option format
//!
//! - **RFC 4862**: IPv6 Stateless Address Autoconfiguration
//!   - Section 5.5.3: Address formation from prefixes and interface identifiers
//!   - Address state transitions (tentative, preferred, deprecated, valid, invalid)
//!
//! - **RFC 4291**: IP Version 6 Addressing Architecture
//!   - Appendix A: Modified EUI-64 interface identifier format
//!   - Section 2.7.1: Link-local multicast addresses (all-nodes, all-routers)
//!
//! - **RFC 4443**: Internet Control Message Protocol (ICMPv6)
//!   - Echo Request/Reply for Duplicate Address Detection
//!
//! - **RFC 6106**: IPv6 Router Advertisement Options for DNS Configuration
//!   - RDNSS option format and processing
//!   - DNSSL option format and processing
//!
//! - **RFC 2464**: Transmission of IPv6 Packets over Ethernet Networks
//!   - MAC-48 to EUI-64 conversion algorithm
//!
//! ## C Source File Mapping
//!
//! This Rust module provides equivalent functionality to the following C source files:
//!
//! | C Source File | Rust Module | Description |
//! |---------------|-------------|-------------|
//! | `src/radv.c` | `radv.rs` | Router Advertisement transmission and ICMPv6 handling |
//! | `src/slaac.c` | `slaac.rs` | SLAAC address generation and Duplicate Address Detection |
//! | `src/radv-protocol.h` | `radv.rs` (types) | ICMPv6 packet structures and protocol constants |
//!
//! ### Key Functional Transformations
//!
//! #### From C to Rust Memory Safety:
//!
//! - **C Pattern**: Manual buffer allocation with fixed-size arrays
//!   ```c
//!   struct ra_packet *ra = (struct ra_packet *)daemon->outpacket;
//!   ```
//!   **Rust Pattern**: Owned buffers with automatic bounds checking
//!   ```rust
//!   let mut packet = RaPacket::new();
//!   ```
//!
//! - **C Pattern**: Raw pointer manipulation for packet construction
//!   ```c
//!   opt = (struct prefix_opt *)((char *)ra + len);
//!   ```
//!   **Rust Pattern**: Type-safe serialization with slices
//!   ```rust
//!   buffer.extend_from_slice(&prefix_opt.to_bytes());
//!   ```
//!
//! - **C Pattern**: Global state with explicit cleanup
//!   ```c
//!   static int ping_id = 0;
//!   ```
//!   **Rust Pattern**: Encapsulated state with RAII
//!   ```rust
//!   struct SlaacManager { ping_id: u16 }
//!   ```
//!
//! ## Integration with DHCPv6
//!
//! Router Advertisement and SLAAC functionality integrates with the DHCPv6 subsystem
//! to provide comprehensive IPv6 address management:
//!
//! - **Stateless Configuration**: SLAAC with RA prefix advertisements (M=0, O=0 or O=1)
//! - **Stateful Configuration**: DHCPv6 address assignment with RA as supplement (M=1)
//! - **Prefix Delegation**: DHCPv6-PD with RA on delegated prefixes
//! - **DNS Configuration**: RDNSS and DNSSL options coordinated with DHCPv6 options
//!
//! ## Usage Examples
//!
//! ### Initializing Router Advertisement Service
//!
//! ```rust,no_run
//! use dnsmasq::dhcp::ipv6::{ra_init, send_ra, periodic_ra};
//! use std::net::Ipv6Addr;
//!
//! // Initialize ICMPv6 socket for Router Advertisement
//! // This sets up packet filters for Router Solicitation and Echo Reply
//! let icmp6_fd = ra_init()?;
//!
//! // Send an initial Router Advertisement on interface "eth0"
//! let interface_index = 2;
//! let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
//! let prefix_len = 64;
//! send_ra(icmp6_fd, interface_index, prefix, prefix_len)?;
//!
//! // Schedule periodic Router Advertisements
//! // Returns the time until the next advertisement is due
//! let next_ra_time = periodic_ra(icmp6_fd)?;
//! ```
//!
//! ### Handling Router Solicitation
//!
//! ```rust,no_run
//! use dnsmasq::dhcp::ipv6::icmp6_packet;
//!
//! // Process incoming ICMPv6 packet (typically called from event loop)
//! // Automatically responds to Router Solicitation with RA
//! let packet_buffer = receive_icmp6_packet()?;
//! icmp6_packet(&packet_buffer)?;
//! ```
//!
//! ### SLAAC Address Generation and Validation
//!
//! ```rust,no_run
//! use dnsmasq::dhcp::ipv6::{slaac_add_addrs, periodic_slaac, slaac_ping_reply};
//! use std::net::Ipv6Addr;
//!
//! // Generate SLAAC addresses from hardware address and RA prefixes
//! // Converts MAC-48 to Modified EUI-64 interface identifier
//! let mac_address = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
//! let hostname = "client-host";
//! slaac_add_addrs(&mac_address, hostname)?;
//!
//! // Perform periodic Duplicate Address Detection via ICMPv6 ping
//! // Returns time until next DAD check is needed
//! let next_dad_time = periodic_slaac()?;
//!
//! // Process ICMPv6 Echo Reply to confirm address uniqueness
//! // Automatically registers confirmed addresses in DNS cache
//! let echo_reply_buffer = receive_echo_reply()?;
//! slaac_ping_reply(&echo_reply_buffer)?;
//! ```
//!
//! ## Conditional Compilation
//!
//! This entire module is conditionally compiled based on the `ipv6` feature flag,
//! which corresponds to the C preprocessor macro `HAVE_DHCP6`. To include IPv6
//! Router Advertisement and SLAAC support, enable the feature in `Cargo.toml`:
//!
//! ```toml
//! [features]
//! default = ["dhcp", "dns", "ipv6"]
//! ipv6 = ["dhcp-v6", "radv", "slaac"]
//! radv = ["ipv6"]
//! slaac = ["ipv6"]
//! ```
//!
//! ## Platform-Specific Considerations
//!
//! ### Linux
//! - Uses netlink for interface enumeration and configuration
//! - Reads MTU from `/proc/sys/net/ipv6/conf/*/mtu`
//! - Supports IPV6_TCLASS socket option for traffic class (IPTOS_CLASS_CS6)
//!
//! ### BSD (FreeBSD, OpenBSD, NetBSD, DragonFly)
//! - Uses BPF for interface monitoring
//! - MTU retrieved via SIOCGIFMTU ioctl
//! - Supports IPV6_TCLASS or IPV6_USE_MIN_MTU depending on platform
//!
//! ### macOS
//! - Similar to BSD but with additional launchd integration
//! - Interface enumeration via getifaddrs()
//!
//! ## Security Considerations
//!
//! ### Router Advertisement Security
//!
//! - **Hop Limit Validation**: All received RA/RS messages must have hop limit 255
//!   to prevent off-link injection attacks
//! - **Source Address Validation**: Router Solicitations must come from link-local
//!   addresses (fe80::/10)
//! - **Rate Limiting**: Implements RFC 4861 rate limiting for RA transmission
//!   (MIN_DELAY_BETWEEN_RAS = 3 seconds)
//!
//! ### SLAAC Security
//!
//! - **Duplicate Address Detection**: Mandatory DAD prevents address conflicts
//! - **Privacy Extensions**: Can be combined with RFC 4941 temporary addresses
//!   (handled by kernel, not dnsmasq)
//! - **Prefix Validation**: Only advertises prefixes from authorized DHCPv6 contexts
//!
//! ## Threading and Concurrency
//!
//! This module operates within dnsmasq's single-process, event-driven architecture:
//!
//! - All functions are called from the main event loop context
//! - No internal locking required (single-threaded execution)
//! - Uses Tokio async I/O for non-blocking socket operations
//! - ICMPv6 socket (`icmp6_fd`) managed by the network layer
//! - Timer-based periodic execution via return values scheduling next events
//!
//! ## Error Handling
//!
//! All public functions return `Result<T, Error>` types for comprehensive error handling:
//!
//! - I/O errors from socket operations
//! - Protocol parsing errors for malformed ICMPv6 packets
//! - Configuration errors for invalid prefix/lifetime combinations
//! - Resource allocation failures
//!
//! Errors are propagated using the `?` operator and logged with structured context
//! via the `tracing` crate.
//!
//! ## Performance Characteristics
//!
//! - **Router Advertisement Rate**: Configurable interval (default 200-600 seconds)
//!   with minimum 3-second delay between advertisements per RFC 4861
//! - **SLAAC DAD Timing**: Exponential backoff for ping retries (1s, 2s, 4s, 8s)
//!   with maximum 5 retries before address confirmation
//! - **Memory Usage**: Minimal overhead - stores only active SLAAC addresses
//!   and RA context state
//! - **Zero-Copy Where Possible**: Direct packet buffer manipulation for RA
//!   construction to minimize allocations
//!
//! ## Testing Strategy
//!
//! - **Unit Tests**: Inline tests for packet parsing and address generation
//! - **Integration Tests**: Full RA/SLAAC protocol flow with virtual interfaces
//! - **Property Tests**: RFC compliance verification with proptest
//! - **Interoperability Tests**: Validation against Linux kernel IPv6 stack,
//!   *BSD implementations, and other DHCPv6/RA servers (ISC DHCPv6, Dibbler)
//!
//! ## See Also
//!
//! - [`radv`] module: Router Advertisement implementation details
//! - [`slaac`] module: SLAAC implementation details
//! - [`crate::dhcp::v6`]: DHCPv6 server for stateful configuration
//! - [`crate::dns`]: DNS cache integration for SLAAC address registration

// Conditionally compile this entire module only when IPv6 support is enabled.
// This matches the C preprocessor directive `#ifdef HAVE_DHCP6` used in radv.c and slaac.c.
#[cfg(feature = "ipv6")]
pub mod radv;

#[cfg(feature = "ipv6")]
pub mod slaac;

// Re-export key types and functions from the radv module for convenient access.
// These exports provide the primary public API for Router Advertisement functionality.
#[cfg(feature = "ipv6")]
pub use radv::{
    // Initialize ICMPv6 socket with packet filters for Router Solicitation and Echo Reply
    ra_init,
    
    // Construct and transmit Router Advertisement packets with prefix options
    send_ra,
    
    // Process incoming Router Solicitation messages and respond with solicited RAs
    icmp6_packet,
    
    // Schedule and execute periodic unsolicited Router Advertisements per RFC 4861 timing
    periodic_ra,
    
    // ICMPv6 Router Advertisement packet structure (RFC 4861 Section 4.2)
    RaPacket,
    
    // Prefix Information option structure (RFC 4861 Section 4.6.2)
    PrefixOpt,
    
    // IPv6 multicast address "FF02::1" for all-nodes group (link-local scope)
    // All IPv6 nodes automatically join this group for receiving Router Advertisements
    ALL_NODES,
    
    // IPv6 multicast address "FF02::2" for all-routers group (link-local scope)
    // Hosts send Router Solicitation messages to this address
    ALL_ROUTERS,
};

// Re-export key types and functions from the slaac module for convenient access.
// These exports provide the primary public API for SLAAC functionality.
#[cfg(feature = "ipv6")]
pub use slaac::{
    // Generate SLAAC IPv6 addresses from RA prefixes and hardware addresses
    // Converts MAC-48 addresses to Modified EUI-64 interface identifiers
    slaac_add_addrs,
    
    // Perform periodic Duplicate Address Detection via ICMPv6 Echo Request
    // Returns time in seconds until next DAD check is needed
    periodic_slaac,
    
    // Process ICMPv6 Echo Reply to detect address conflicts and confirm addresses
    // Automatically registers confirmed SLAAC addresses in the DNS cache
    slaac_ping_reply,
    
    // SLAAC address tracking structure with ping timing and exponential backoff
    // Stores address state for Duplicate Address Detection and DNS registration
    SlaacAddress,
};
