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
//! This module implements ICMPv6 Router Advertisement per RFC 4861 (Neighbor Discovery
//! for IPv6) and RFC 4862 (IPv6 Stateless Address Autoconfiguration).
//!
//! # Purpose
//!
//! The Router Advertisement subsystem provides:
//!
//! - **Periodic RA Transmission**: Unsolicited Router Advertisements sent at regular
//!   intervals (default 200-600 seconds) to announce router presence and configuration
//!
//! - **Solicited RA Response**: Immediate Router Advertisements in response to Router
//!   Solicitation messages from hosts
//!
//! - **SLAAC Support**: Prefix Information options enabling Stateless Address
//!   Autoconfiguration with Modified EUI-64 interface identifiers
//!
//! - **DHCPv6 Coordination**: M-bit (Managed) and O-bit (Other) flags indicating
//!   DHCPv6 availability for address assignment and additional configuration
//!
//! - **DNS Configuration**: RDNSS (Recursive DNS Server) and DNSSL (DNS Search List)
//!   options per RFC 8106 for stateless DNS configuration
//!
//! # Module Organization
//!
//! - **protocol**: ICMPv6 packet structures and constants (wire format definitions)
//! - **server**: Router Advertisement server state and periodic transmission logic
//! - **options**: ICMPv6 RA option types (RDNSS, DNSSL, MTU, Route Info, etc.)
//!
//! # Integration Points
//!
//! - **dhcp::v6**: DHCPv6 coordination via M-bit/O-bit flags
//! - **network::sockets**: ICMPv6 raw socket handling for multicast transmission
//! - **dns::cache**: Hostname resolution for RDNSS advertisements
//! - **ipv6::slaac**: SLAAC address generation and DAD coordination
//!
//! # RFC Compliance
//!
//! - **RFC 4861**: Neighbor Discovery for IPv6 (Router Advertisement, Neighbor Solicitation/Advertisement)
//! - **RFC 4862**: IPv6 Stateless Address Autoconfiguration (SLAAC)
//! - **RFC 4191**: Default Router Preferences and More-Specific Routes (Route Information option)
//! - **RFC 8106**: IPv6 Router Advertisement Options for DNS Configuration (RDNSS, DNSSL)
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use crate::ipv6::radv::{RadVServer, RadVServerBuilder};
//! use std::net::Ipv6Addr;
//!
//! // Create RA server with DHCPv6 coordination
//! let server = RadVServerBuilder::new("eth0".to_string())
//!     .with_managed_flag(true)   // M-bit: use DHCPv6 for addresses
//!     .with_other_flag(true)     // O-bit: use DHCPv6 for other config
//!     .add_prefix("2001:db8::".parse()?, 64, 2592000, 604800)
//!     .with_router_lifetime(1800)
//!     .build();
//!
//! // Start periodic RA transmission (async task)
//! server.start().await?;
//! ```
//!
//! # Memory Safety Benefits (C to Rust Refactor)
//!
//! | C Implementation | Rust Implementation | Safety Improvement |
//! |------------------|---------------------|-------------------|
//! | Manual packet buffer management | `Vec<u8>` with RAII | No memory leaks |
//! | Pointer arithmetic for options | Safe slice operations | No buffer overflows |
//! | `htons/htonl` byte order | `to_be_bytes()` methods | No endian bugs |
//! | Global daemon state | `Arc<RwLock<T>>` | Thread-safe sharing |
//! | Blocking sendto() | `tokio::net::UdpSocket::send_to().await` | Non-blocking I/O |

pub mod protocol;
pub mod server;
pub mod options;

// Re-export commonly used types
pub use protocol::{
    RaPacket, PrefixOption, PingPacket, NeighPacket,
    ALL_NODES, ALL_ROUTERS,
    ICMP6_ROUTER_ADVERTISEMENT, ICMP6_ROUTER_SOLICITATION,
    RA_FLAG_MANAGED, RA_FLAG_OTHER,
    PREFIX_FLAG_ONLINK, PREFIX_FLAG_AUTO,
};

pub use server::{RadVServer, RadVServerBuilder};

pub use options::{
    SourceLinkLayerOption, MtuOption, RdnssOption, DnsslOption, RouteInfoOption,
};
