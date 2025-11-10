// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
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

//! IPv6 Router Advertisement Subsystem
//!
//! This module implements `ICMPv6` Router Advertisement (RA) functionality per RFC 4861
//! (Neighbor Discovery for IPv6) and RFC 4862 (IPv6 Stateless Address Autoconfiguration).
//! It provides the Router Advertisement server, protocol constants, and option builders
//! required for IPv6 prefix announcement and SLAAC support.
//!
//! # Purpose
//!
//! The Router Advertisement subsystem serves as the cornerstone of IPv6 network
//! autoconfiguration in dnsmasq, providing:
//!
//! - **Periodic RA Transmission**: Unsolicited Router Advertisements sent at regular
//!   intervals (default 200-600 seconds per RFC 4861 Section 6.2.1) to announce
//!   router presence and network configuration parameters to all IPv6 nodes on the link.
//!
//! - **Solicited RA Response**: Immediate Router Advertisement responses to Router
//!   Solicitation (`ICMPv6` Type 133) messages from hosts joining the network, enabling
//!   fast network bootstrap without waiting for periodic RAs.
//!
//! - **SLAAC Support**: Prefix Information options (Type 3) with A-bit (Autonomous
//!   Address-Configuration flag) set, enabling hosts to generate IPv6 addresses using
//!   Modified EUI-64 or privacy extensions per RFC 4862 without requiring `DHCPv6`
//!   stateful address assignment.
//!
//! - **`DHCPv6` Coordination**: M-bit (Managed Address Configuration) and O-bit (Other
//!   Configuration) flags in Router Advertisements coordinate with the `DHCPv6` server
//!   to signal whether clients should use:
//!   - M=0, O=0: Pure SLAAC (no `DHCPv6`)
//!   - M=0, O=1: SLAAC for addresses + stateless `DHCPv6` for DNS/NTP
//!   - M=1, O=1: Stateful `DHCPv6` for addresses and configuration
//!
//! - **DNS Configuration**: RDNSS (Recursive DNS Server, Type 25) and DNSSL (DNS Search
//!   List, Type 31) options per RFC 8106 enable stateless DNS configuration without
//!   `DHCPv6`, allowing hosts to autoconfigure DNS resolvers and search domains directly
//!   from Router Advertisements.
//!
//! - **MTU Advertisement**: Link MTU option (Type 5) per RFC 4861 Section 4.6.4 enables
//!   path MTU discovery optimization by announcing the link's maximum transmission unit,
//!   preventing fragmentation and improving network efficiency.
//!
//! # Module Organization
//!
//! This module is organized into three sub-modules following Rust best practices for
//! protocol implementation separation:
//!
//! - **`protocol`**: `ICMPv6` packet structures and wire-format constants
//!   - Defines `RaPacket`, `PingPacket`, `NeighPacket` structs for type-safe packet representation
//!   - Provides protocol constants (`ALL_NODES`, `ALL_ROUTERS`, `ICMP6_OPT_*`)
//!   - Handles serialization/deserialization with safe bounds checking
//!
//! - **`server`**: Router Advertisement server implementation and state management
//!   - `RadVServer` struct manages `ICMPv6` socket, `DHCPv6` coordination, and interface tracking
//!   - Async task spawning for periodic RAs and Router Solicitation processing
//!   - Packet construction with all required options
//!
//! - **`options`**: `ICMPv6` RA option builders with type-safe construction
//!   - `PrefixOption`: Prefix Information for SLAAC (A-flag, L-flag control)
//!   - `RdnssOption`: Recursive DNS Server addresses with lifetimes
//!   - `DnsslOption`: DNS Search List domains
//!   - `MtuOption`: Link MTU advertisement
//!   - `AdvIntervalOption`: Mobile IPv6 advertisement interval
//!
//! # Integration Points
//!
//! The Router Advertisement subsystem integrates tightly with other dnsmasq components:
//!
//! - **`dhcp::v6`**: `DHCPv6` server coordination via shared `DhcpContext` structures
//!   - M-bit flag synchronization for managed address configuration mode
//!   - O-bit flag coordination for `DHCPv6` information-request handling
//!   - Prefix pool sharing to prevent SLAAC/DHCPv6 address conflicts
//!   - Lease database coordination for duplicate address detection
//!
//! - **`ipv6::slaac`**: SLAAC address generation and Duplicate Address Detection (DAD)
//!   - Prefix lifetime management for address deprecation
//!   - DAD coordination using `ICMPv6` Neighbor Solicitation
//!   - Privacy extension support per RFC 4941
//!
//! - **`network::sockets`**: `ICMPv6` raw socket management for multicast transmission
//!   - Socket creation with `IPV6_RECVPKTINFO` for interface identification
//!   - Multicast group join/leave (`ff02::1` for all-nodes, `ff02::2` for all-routers)
//!   - Hop limit control (255 for on-link verification)
//!
//! - **`network::interfaces`**: Network interface enumeration and state tracking
//!   - Interface index to name mapping via `indextoname()`
//!   - Link-local address discovery for source address selection
//!   - Interface state change detection (up/down events)
//!
//! - **`dns::cache`**: Hostname resolution for RDNSS advertisement population
//!   - DNS server address extraction for RDNSS options
//!   - Search domain list for DNSSL options
//!
//! - **`config::types`**: Configuration parsing and validation
//!   - `DhcpContext` structures containing RA parameters
//!   - Interface-specific RA intervals via --ra-param
//!   - Prefix configuration with valid/preferred lifetimes
//!
//! # RFC Compliance
//!
//! This implementation strictly adheres to the following RFCs:
//!
//! - **RFC 4861**: Neighbor Discovery for IPv6
//!   - Section 4.2: Router Advertisement Message Format
//!   - Section 4.6: Router Advertisement Options
//!   - Section 6.2: Router Configuration Variables (`MinRtrAdvInterval`, `MaxRtrAdvInterval`)
//!
//! - **RFC 4862**: IPv6 Stateless Address Autoconfiguration (SLAAC)
//!   - Section 5.5.3: Router Advertisement Processing
//!   - Section 5.5.4: Address Lifetime Expiration
//!
//! - **RFC 4443**: Internet Control Message Protocol (`ICMPv6`) for IPv6
//!   - `ICMPv6` message types and checksum calculation
//!
//! - **RFC 8106**: IPv6 Router Advertisement Options for DNS Configuration
//!   - RDNSS option (Type 25) format and processing
//!   - DNSSL option (Type 31) format and processing
//!
//! - **RFC 4191**: Default Router Preferences and More-Specific Routes
//!   - Router preference encoding in RA flags
//!   - Route Information option for prefix-specific routing
//!
//! - **RFC 6275**: Mobility Support in IPv6
//!   - Advertisement Interval option (Type 7) for mobile node timing
//!
//! - **RFC 6204**: Basic Requirements for IPv6 Customer Edge Routers
//!   - Old prefix deprecation when prefix changes
//!   - Prefix Information option lifetime management
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use crate::ipv6::radv::{RadVServer, PrefixOption, RdnssOption};
//! use std::sync::{Arc, RwLock};
//! use std::net::Ipv6Addr;
//!
//! // Create RA server with shared contexts and interfaces
//! let logger = Arc::new(Logger::new(/* ... */));
//! let dhcp_contexts = Arc::new(RwLock::new(Vec::new()));
//! let interfaces = Arc::new(RwLock::new(Vec::new()));
//!
//! let mut server = RadVServer::new(logger, dhcp_contexts, interfaces).await?;
//!
//! // Configure prefix for SLAAC
//! let prefix = PrefixOption::new()
//!     .prefix(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
//!     .prefix_len(64)
//!     .autonomous(true)  // Enable SLAAC via A-bit
//!     .on_link(true)     // Set L-bit for on-link determination
//!     .valid_lifetime(2592000)      // 30 days
//!     .preferred_lifetime(604800);  // 7 days
//!
//! // Configure DNS servers for RDNSS option
//! let rdnss = RdnssOption::new()
//!     .add_server(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))
//!     .add_server(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844))
//!     .lifetime(600);
//!
//! // Start periodic RA transmission (spawns async task)
//! let now = SystemTime::now();
//! server.start(now).await?;
//! ```
//!
//! # Memory Safety Benefits (C to Rust Refactor)
//!
//! This Rust refactoring of `src/radv.c` and `src/radv-protocol.h` eliminates entire
//! classes of memory safety vulnerabilities present in the C implementation:
//!
//! | C Implementation | Rust Implementation | Safety Improvement |
//! |------------------|---------------------|-------------------|
//! | Manual packet buffer management with `daemon->outpacket.iov_base` | `Vec<u8>` with automatic capacity growth | No buffer overflow, automatic cleanup via RAII |
//! | Pointer arithmetic for option serialization (`opt += len`) | Safe slice operations with bounds checking | Panic on out-of-bounds instead of memory corruption |
//! | Manual `htons()`/`htonl()` byte order conversion | `to_be_bytes()` methods and `byteorder` crate | Type-safe endian conversion, impossible to forget |
//! | Global `daemon` state with manual locking | `Arc<RwLock<T>>` for shared ownership | Rust borrow checker prevents data races |
//! | Blocking `sendto()` syscalls in event loop | `tokio::net::UdpSocket::send_to().await` | Non-blocking async I/O, better concurrency |
//! | Manual interface iteration with `ioctl()` | `nix` crate abstractions | Safe FFI boundaries with error handling |
//! | Null pointer checks for optional parameters | `Option<T>` type with pattern matching | Type-safe null handling, impossible to dereference null |
//! | Manual struct padding with `__attribute__((packed))` | Explicit field-by-field serialization | No alignment bugs, portable across architectures |
//!
//! # Performance Characteristics
//!
//! - **CPU Usage**: Minimal overhead from periodic RA transmission (every 200-600s)
//! - **Memory Footprint**: ~4-8 KB per active interface (RA state + packet buffers)
//! - **Network Load**: Typical RA size 64-256 bytes, sent every 5-10 minutes
//! - **Async Task Count**: 2 tasks per `RadVServer` (periodic RA sender + packet receiver)
//!
//! # Security Considerations
//!
//! - **RA Guard**: This implementation does not validate RA authenticity (RFC 6105 RA Guard
//!   must be implemented at the switch level)
//! - **Hop Limit Verification**: All RAs sent with hop limit 255, receivers verify hop=255
//!   per RFC 4861 Section 6.1.2 to prevent off-link RA injection
//! - **Prefix Lifetime Attacks**: Malicious RAs can advertise short lifetimes causing
//!   address deprecation (mitigated by ignoring untrusted RAs via RA Guard)
//!
//! # Thread Safety
//!
//! All state is protected by `Arc<RwLock<T>>` allowing safe concurrent access from
//! multiple async tasks. The Rust borrow checker guarantees no data races.

// Declare sub-modules (each implemented in separate files)
pub mod protocol;
pub mod server;
pub mod options;

// Re-export commonly used protocol constants for convenient access
// These are the fundamental ICMPv6 multicast addresses used for RA transmission
pub use protocol::{
    ALL_NODES,       // IPv6 multicast ff02::1 for all-nodes RA transmission
    ALL_ROUTERS,     // IPv6 multicast ff02::2 for Router Solicitation destination
};

// Re-export ICMPv6 option type constants for packet parsing and construction
pub use protocol::{
    ICMP6_OPT_PREFIX,       // Type 3: Prefix Information for SLAAC
    ICMP6_OPT_RDNSS,        // Type 25: Recursive DNS Server (RFC 8106)
    ICMP6_OPT_SOURCE_MAC,   // Type 1: Source Link-Layer Address
    ICMP6_OPT_MTU,          // Type 5: MTU option
};

// Re-export ICMPv6 packet structures for protocol handling
pub use protocol::{
    RaPacket,      // Router Advertisement message structure (Type 134)
    PingPacket,    // ICMPv6 Echo Request/Reply for DAD (Types 128/129)
    NeighPacket,   // Neighbor Solicitation/Advertisement (Types 135/136)
};

// Re-export ICMP6_ECHO_REQUEST constant for DAD ping operations
pub use protocol::ICMP6_ECHO_REQUEST;

// Re-export the main Router Advertisement server for RA management
pub use server::RadVServer;

// Re-export ICMPv6 option builder types for packet construction
pub use options::{
    PrefixOption,        // Builder for Prefix Information option (Type 3)
    RdnssOption,         // Builder for RDNSS option (Type 25)
    DnsslOption,         // Builder for DNSSL option (Type 31)
    MtuOption,           // Builder for MTU option (Type 5)
    AdvIntervalOption,   // Builder for Advertisement Interval option (Type 7)
};
