//! IPv6 Services Module
//!
//! This module provides IPv6-related services for dnsmasq, implementing Router Advertisement (RA),
//! Stateless Address Autoconfiguration (SLAAC), and IPv6 address utilities. This replaces the C
//! implementation from `src/radv.c`, `src/slaac.c`, and `src/ip6addr.h`.
//!
//! # Architecture Overview
//!
//! The IPv6 module is organized into three main subsystems:
//!
//! ## Router Advertisement (radv)
//!
//! Implements ICMPv6-based Router Advertisement as defined in RFC 4861. The RA server periodically
//! multicasts Router Advertisement messages to all nodes on a link, providing:
//!
//! - **Prefix Information**: IPv6 address prefixes for SLAAC (Stateless Address Autoconfiguration)
//! - **Router Lifetime**: How long the router should be used as a default router
//! - **Configuration Flags**: Managed (M) and Other (O) configuration flags for DHCPv6 coordination
//! - **DNS Configuration**: Recursive DNS Server (RDNSS) and DNS Search List (DNSSL) options per RFC 8106
//! - **Route Information**: More-specific routes (Route Information Option per RFC 4191)
//!
//! The M-bit and O-bit flags coordinate with the DHCPv6 server:
//! - **M-bit=1**: Addresses are available via DHCPv6 (managed configuration)
//! - **O-bit=1**: Other configuration (DNS, NTP) is available via DHCPv6
//! - **M-bit=0, O-bit=0**: Pure SLAAC mode with no DHCPv6
//!
//! ### Key RFCs Implemented
//!
//! - **RFC 4861**: Neighbor Discovery for IPv6 (Router Advertisement core)
//! - **RFC 4191**: Default Router Preferences and More-Specific Routes
//! - **RFC 8106**: IPv6 Router Advertisement Options for DNS Configuration
//! - **RFC 6106**: IPv6 Router Advertisement Options for DNS Configuration (deprecated by RFC 8106)
//!
//! ## Stateless Address Autoconfiguration (slaac)
//!
//! Implements SLAAC as defined in RFC 4862, allowing hosts to automatically generate IPv6 addresses
//! without requiring a DHCPv6 server. The process involves:
//!
//! 1. **Modified EUI-64 Interface Identifier**: Generate a 64-bit interface ID from MAC address
//! 2. **Tentative Address Formation**: Combine prefix from RA with interface ID
//! 3. **Duplicate Address Detection (DAD)**: Verify address uniqueness via Neighbor Solicitation
//! 4. **Address Assignment**: Mark address as valid if no duplicate detected
//!
//! ### DAD Protocol
//!
//! Duplicate Address Detection prevents address conflicts:
//!
//! 1. Send ICMPv6 Neighbor Solicitation for the tentative address (target = tentative address)
//! 2. Wait for DAD timeout (typically 1 second per RFC 4862)
//! 3. If Neighbor Advertisement received, address is duplicate → abort
//! 4. If no response, address is unique → assign to interface
//!
//! The implementation uses exponential backoff for retry attempts and integrates with the DNS cache
//! to provide hostname resolution for SLAAC-assigned addresses.
//!
//! ### Key RFCs Implemented
//!
//! - **RFC 4862**: IPv6 Stateless Address Autoconfiguration
//! - **RFC 4291**: IPv6 Addressing Architecture (address format)
//! - **RFC 4941**: Privacy Extensions for SLAAC (temporary addresses)
//! - **RFC 7217**: Stable Privacy Addresses (semantic-free interface IDs)
//!
//! ## IPv6 Address Utilities (addr)
//!
//! Provides extension traits and utility functions for IPv6 address classification and manipulation:
//!
//! - **ULA Detection**: Identify Unique Local Addresses (RFC 4193, fc00::/7)
//! - **Link-Local Detection**: Identify link-local addresses (RFC 4291, fe80::/10)
//! - **Zero Address Detection**: Check for unspecified addresses (::)
//! - **Scope Determination**: Determine address scope (interface-local, link-local, site-local, global)
//!
//! ### Key RFCs Implemented
//!
//! - **RFC 4193**: Unique Local IPv6 Unicast Addresses
//! - **RFC 4291**: IPv6 Addressing Architecture
//! - **RFC 3513**: IPv6 Addressing Architecture (obsoleted by RFC 4291)
//!
//! # Integration Points
//!
//! ## DHCPv6 Integration (`dhcp::v6`)
//!
//! The RA server coordinates with the DHCPv6 server through configuration flags:
//!
//! ```rust,ignore
//! use crate::ipv6::radv::RadVServer;
//! use crate::dhcp::v6::Dhcp6Server;
//!
//! // DHCPv6 server active → set M-bit and O-bit
//! if dhcp6_server.is_active() {
//!     radv_server.set_managed_flag(true);  // M-bit: addresses via DHCPv6
//!     radv_server.set_other_config_flag(true);  // O-bit: other config via DHCPv6
//! }
//! ```
//!
//! ## Network Socket Integration (`network::sockets`)
//!
//! Uses raw ICMPv6 sockets for Router Advertisement and Neighbor Discovery:
//!
//! ```rust,ignore
//! use crate::network::sockets::Icmpv6Socket;
//!
//! let socket = Icmpv6Socket::new(interface_index)?;
//! socket.join_multicast(&ALL_NODES_MULTICAST)?;
//! socket.send_router_advertisement(&ra_message).await?;
//! ```
//!
//! ## DNS Cache Integration (`dns::cache`)
//!
//! Registers SLAAC-assigned addresses in the DNS cache for reverse lookups:
//!
//! ```rust,ignore
//! use crate::dns::cache::DnsCache;
//! use crate::ipv6::slaac::SlaacAddress;
//!
//! let slaac_addr = SlaacAddress::from_mac(&mac_address, &prefix);
//! dns_cache.add_ptr_record(slaac_addr.address(), hostname)?;
//! ```
//!
//! # Async Runtime Requirements
//!
//! All IPv6 services are designed for async operation with tokio:
//!
//! - **Periodic RA Transmission**: Uses `tokio::time::interval()` for scheduled broadcasts
//! - **DAD Timeout Handling**: Uses `tokio::time::timeout()` for exponential backoff
//! - **ICMPv6 Socket I/O**: Uses `tokio::net` async sockets with `nix` for raw socket operations
//! - **Concurrent Operations**: Uses `tokio::spawn()` for parallel DAD probes on multiple interfaces
//!
//! # Memory Safety Guarantees
//!
//! This module eliminates memory safety vulnerabilities present in the C implementation:
//!
//! - **No Buffer Overflows**: Rust's bounds checking prevents ICMPv6 packet buffer overruns
//! - **No Use-After-Free**: Ownership system prevents accessing freed RA/SLAAC state
//! - **No Null Pointer Dereferences**: `Option<T>` replaces NULL pointer checks
//! - **No Data Races**: `Arc<RwLock<T>>` ensures thread-safe access to shared RA/SLAAC configuration
//!
//! # Examples
//!
//! ## Periodic Router Advertisement
//!
//! ```rust,ignore
//! use crate::ipv6::radv::{RadVServer, PrefixOption};
//! use std::time::Duration;
//! use tokio::time::interval;
//!
//! async fn run_radv_server(server: RadVServer) -> Result<(), Box<dyn std::error::Error>> {
//!     let mut interval = interval(Duration::from_secs(600)); // RA every 10 minutes
//!     
//!     loop {
//!         interval.tick().await;
//!         
//!         // Send Router Advertisement with prefix
//!         let prefix = PrefixOption::new(
//!             "2001:db8::/64".parse()?,
//!             7200,  // Valid lifetime: 2 hours
//!             3600,  // Preferred lifetime: 1 hour
//!         );
//!         
//!         server.send_router_advertisement(&[prefix]).await?;
//!     }
//! }
//! ```
//!
//! ## SLAAC Address Generation
//!
//! ```rust,ignore
//! use crate::ipv6::slaac::{SlaacManager, SlaacAddress};
//! use std::net::Ipv6Addr;
//!
//! async fn generate_slaac_address() -> Result<Ipv6Addr, Box<dyn std::error::Error>> {
//!     let manager = SlaacManager::new();
//!     let mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
//!     let prefix = "2001:db8::/64".parse()?;
//!     
//!     // Generate address using Modified EUI-64
//!     let slaac_addr = SlaacAddress::from_mac(&mac, &prefix);
//!     
//!     // Perform DAD with exponential backoff
//!     manager.duplicate_address_detection(&slaac_addr).await?;
//!     
//!     Ok(slaac_addr.address())
//! }
//! ```
//!
//! ## IPv6 Address Classification
//!
//! ```rust,ignore
//! use crate::ipv6::addr::Ipv6AddrExt;
//! use std::net::Ipv6Addr;
//!
//! fn classify_address(addr: &Ipv6Addr) {
//!     if addr.is_ula() {
//!         println!("Unique Local Address (fc00::/7)");
//!     } else if addr.is_link_local_zero() {
//!         println!("Link-local address (fe80::/10)");
//!     } else if addr.is_global() {
//!         println!("Global unicast address");
//!     }
//! }
//! ```
//!
//! # Performance Characteristics
//!
//! - **RA Transmission**: O(1) per interface, multicast to all nodes
//! - **SLAAC Address Generation**: O(1) computation, O(n) DAD probes for n tentative addresses
//! - **DAD Timeout**: 1-3 seconds typical with exponential backoff
//! - **Memory Footprint**: ~200 bytes per RA configuration, ~100 bytes per SLAAC address
//!
//! # Platform Support
//!
//! - **Linux**: Full support via `AF_INET6` raw sockets with `IPV6_RECVPKTINFO`
//! - **BSD** (FreeBSD, OpenBSD, NetBSD): Full support via `AF_INET6` raw sockets
//! - **macOS**: Full support via `AF_INET6` raw sockets
//! - **Solaris**: Full support via `AF_INET6` raw sockets
//!
//! All platforms require `CAP_NET_RAW` capability or root privileges for ICMPv6 socket operations.

// Submodule declarations
pub mod radv;
pub mod slaac;
pub mod addr;

// Re-export commonly used types and constants for convenience
pub use radv::{
    RadVServer,
    PrefixOption,
    RdnssOption,
    DnsslOption,
    ALL_NODES,
    ALL_ROUTERS,
};

pub use slaac::{
    SlaacManager,
    SlaacAddress,
    slaac_add_addrs,
    periodic_slaac,
    slaac_ping_reply,
};

pub use addr::{
    Ipv6AddrExt,
    is_ula,
    is_ula_zero,
    is_link_local_zero,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify module structure and re-exports are accessible
    #[test]
    fn test_module_structure() {
        // This test ensures that all re-exported types are accessible
        // Individual functionality is tested in submodule test suites
        
        // Type existence checks (will fail to compile if types don't exist)
        fn _assert_radv_types_exist() {
            let _: Option<RadVServer> = None;
            let _: Option<PrefixOption> = None;
            let _: Option<RdnssOption> = None;
            let _: Option<DnsslOption> = None;
        }
        
        fn _assert_slaac_types_exist() {
            let _: Option<SlaacManager> = None;
            let _: Option<SlaacAddress> = None;
        }
        
        // This test always passes if compilation succeeds
    }
}
