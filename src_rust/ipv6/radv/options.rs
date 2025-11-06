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

//! ICMPv6 Router Advertisement Options
//!
//! This module provides safe Rust implementations of ICMPv6 RA options defined
//! in RFC 4861 (Neighbor Discovery), RFC 8106 (DNS Configuration), and RFC 4191
//! (Route Information).
//!
//! # Purpose
//!
//! Router Advertisement messages carry variable-length options that provide
//! additional configuration information beyond the base RA packet. This module
//! implements type-safe option structures with safe serialization/deserialization.
//!
//! # Supported Options
//!
//! - **Source Link-Layer Address** (Type 1): Router's MAC address
//! - **Prefix Information** (Type 3): IPv6 prefixes for SLAAC (implemented in protocol.rs)
//! - **MTU** (Type 5): Link MTU value
//! - **Route Information** (Type 24): Specific routes beyond default gateway
//! - **Recursive DNS Server** (Type 25): DNS resolver IPv6 addresses
//! - **DNS Search List** (Type 31): DNS search domain suffixes
//!
//! # Memory Safety
//!
//! Compared to C implementation:
//! - No manual TLV (Type-Length-Value) pointer arithmetic
//! - Safe slice operations with automatic bounds checking
//! - Vec<u8> for dynamic option buffers (automatic deallocation)
//! - No buffer overflows in option construction

use std::net::Ipv6Addr;

use super::protocol::{
    ICMP6_OPT_SOURCE_MAC, ICMP6_OPT_MTU, ICMP6_OPT_RDNSS, 
    ICMP6_OPT_DNSSL, ICMP6_OPT_RT_INFO,
};

/// Source Link-Layer Address option (Type 1)
///
/// Provides the sender's link-layer (MAC) address for efficient neighbor
/// cache population without additional Neighbor Solicitation exchanges.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |    Link-Layer Address ...     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Length is in units of 8 bytes. For Ethernet (6-byte MAC), length = 1 (8 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLinkLayerOption {
    /// Option type (always 1)
    pub option_type: u8,
    /// Option length in units of 8 bytes
    pub len: u8,
    /// Link-layer address (e.g., 6 bytes for Ethernet MAC)
    pub address: Vec<u8>,
}

impl SourceLinkLayerOption {
    /// Create a new Source Link-Layer Address option
    ///
    /// # Arguments
    ///
    /// * `address` - Link-layer address bytes (typically 6 bytes for Ethernet)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let option = SourceLinkLayerOption::new(mac);
    /// ```
    pub fn new(address: Vec<u8>) -> Self {
        // Calculate length in units of 8 bytes, rounding up
        let len = ((address.len() + 2) + 7) / 8;
        Self {
            option_type: ICMP6_OPT_SOURCE_MAC,
            len: len as u8,
            address,
        }
    }

    /// Serialize the option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.option_type);
        bytes.push(self.len);
        bytes.extend_from_slice(&self.address);
        
        // Pad to multiple of 8 bytes
        let total_len = self.len as usize * 8;
        while bytes.len() < total_len {
            bytes.push(0);
        }
        
        bytes
    }
}

/// MTU option (Type 5)
///
/// Advertises the Maximum Transmission Unit for the link, allowing hosts
/// to optimize packet sizing and avoid fragmentation.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              MTU                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Length is always 1 (8 bytes total).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuOption {
    /// Option type (always 5)
    pub option_type: u8,
    /// Option length (always 1 for 8 bytes)
    pub len: u8,
    /// Reserved field (must be 0)
    pub reserved: u16,
    /// MTU value in bytes (e.g., 1500 for Ethernet, 1280 minimum for IPv6)
    pub mtu: u32,
}

impl MtuOption {
    /// Create a new MTU option
    ///
    /// # Arguments
    ///
    /// * `mtu` - MTU value in bytes
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let option = MtuOption::new(1500); // Standard Ethernet MTU
    /// ```
    pub fn new(mtu: u32) -> Self {
        Self {
            option_type: ICMP6_OPT_MTU,
            len: 1,
            reserved: 0,
            mtu,
        }
    }

    /// Serialize the option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.option_type);
        bytes.push(self.len);
        bytes.extend_from_slice(&self.reserved.to_be_bytes());
        bytes.extend_from_slice(&self.mtu.to_be_bytes());
        bytes
    }
}

/// Recursive DNS Server option (Type 25) per RFC 8106
///
/// Advertises IPv6 addresses of DNS recursive resolvers for stateless
/// DNS configuration without DHCPv6.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Lifetime                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// :            Addresses of IPv6 Recursive DNS Servers           :
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Length is in units of 8 bytes: (1 + 2 * number of addresses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdnssOption {
    /// Option type (always 25)
    pub option_type: u8,
    /// Option length in units of 8 bytes
    pub len: u8,
    /// Reserved field (must be 0)
    pub reserved: u16,
    /// Lifetime in seconds (0xFFFFFFFF = infinity)
    pub lifetime: u32,
    /// IPv6 addresses of recursive DNS servers
    pub addresses: Vec<Ipv6Addr>,
}

impl RdnssOption {
    /// Create a new Recursive DNS Server option
    ///
    /// # Arguments
    ///
    /// * `addresses` - IPv6 addresses of DNS servers
    /// * `lifetime` - Lifetime in seconds (how long addresses remain valid)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let dns_servers = vec![
    ///     "2001:4860:4860::8888".parse()?,
    ///     "2001:4860:4860::8844".parse()?,
    /// ];
    /// let option = RdnssOption::new(dns_servers, 3600);
    /// ```
    pub fn new(addresses: Vec<Ipv6Addr>, lifetime: u32) -> Self {
        // Length = 1 (for type/len/reserved/lifetime) + 2 * number of addresses
        let len = 1 + (addresses.len() * 2) as u8;
        Self {
            option_type: ICMP6_OPT_RDNSS,
            len,
            reserved: 0,
            lifetime,
            addresses,
        }
    }

    /// Serialize the option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.option_type);
        bytes.push(self.len);
        bytes.extend_from_slice(&self.reserved.to_be_bytes());
        bytes.extend_from_slice(&self.lifetime.to_be_bytes());
        
        for addr in &self.addresses {
            bytes.extend_from_slice(&addr.octets());
        }
        
        bytes
    }
}

/// DNS Search List option (Type 31) per RFC 8106
///
/// Advertises DNS search domain suffixes for stateless DNS configuration.
/// Hosts append these domains to unqualified hostname lookups.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Lifetime                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// :                Domain Names (DNS wire format)                :
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsslOption {
    /// Option type (always 31)
    pub option_type: u8,
    /// Option length in units of 8 bytes
    pub len: u8,
    /// Reserved field (must be 0)
    pub reserved: u16,
    /// Lifetime in seconds
    pub lifetime: u32,
    /// Domain names in human-readable format (e.g., "example.com")
    pub domains: Vec<String>,
}

impl DnsslOption {
    /// Create a new DNS Search List option
    ///
    /// # Arguments
    ///
    /// * `domains` - List of domain names (e.g., ["example.com", "local.domain"])
    /// * `lifetime` - Lifetime in seconds
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let domains = vec!["example.com".to_string(), "corp.example.com".to_string()];
    /// let option = DnsslOption::new(domains, 3600);
    /// ```
    pub fn new(domains: Vec<String>, lifetime: u32) -> Self {
        // Calculate encoded domain name length
        let mut domain_bytes_len = 0;
        for domain in &domains {
            domain_bytes_len += Self::dns_name_len(domain);
        }
        
        // Length in units of 8 bytes (round up)
        let len = ((8 + domain_bytes_len) + 7) / 8;
        
        Self {
            option_type: ICMP6_OPT_DNSSL,
            len: len as u8,
            reserved: 0,
            lifetime,
            domains,
        }
    }

    /// Calculate the DNS wire format length for a domain name
    fn dns_name_len(domain: &str) -> usize {
        // DNS wire format: each label preceded by length byte, terminated by 0
        let labels: Vec<&str> = domain.split('.').collect();
        let mut len = 0;
        for label in labels {
            len += 1 + label.len(); // length byte + label bytes
        }
        len += 1; // Terminating 0
        len
    }

    /// Encode a domain name to DNS wire format
    fn encode_dns_name(domain: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in domain.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0); // Terminating 0
        bytes
    }

    /// Serialize the option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.option_type);
        bytes.push(self.len);
        bytes.extend_from_slice(&self.reserved.to_be_bytes());
        bytes.extend_from_slice(&self.lifetime.to_be_bytes());
        
        for domain in &self.domains {
            bytes.extend_from_slice(&Self::encode_dns_name(domain));
        }
        
        // Pad to multiple of 8 bytes
        let total_len = self.len as usize * 8;
        while bytes.len() < total_len {
            bytes.push(0);
        }
        
        bytes
    }
}

/// Route Information option (Type 24) per RFC 4191
///
/// Advertises specific routes beyond the default gateway for multi-homing
/// scenarios where hosts need to select among multiple routers for specific
/// destination prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInfoOption {
    /// Option type (always 24)
    pub option_type: u8,
    /// Option length in units of 8 bytes
    pub len: u8,
    /// Prefix length in bits
    pub prefix_len: u8,
    /// Route preference and reserved bits
    pub pref_reserved: u8,
    /// Route lifetime in seconds
    pub route_lifetime: u32,
    /// Prefix (significant bits determined by prefix_len)
    pub prefix: Ipv6Addr,
}

impl RouteInfoOption {
    /// Route preference: High (0x08)
    pub const PREF_HIGH: u8 = 0x08;
    /// Route preference: Medium/Default (0x00)
    pub const PREF_MEDIUM: u8 = 0x00;
    /// Route preference: Low (0x18)
    pub const PREF_LOW: u8 = 0x18;

    /// Create a new Route Information option
    ///
    /// # Arguments
    ///
    /// * `prefix` - Route prefix
    /// * `prefix_len` - Prefix length in bits
    /// * `route_lifetime` - Route lifetime in seconds
    /// * `preference` - Route preference (PREF_HIGH, PREF_MEDIUM, or PREF_LOW)
    pub fn new(prefix: Ipv6Addr, prefix_len: u8, route_lifetime: u32, preference: u8) -> Self {
        // Length depends on prefix_len: 1, 2, or 3 (for 0-64, 65-128 bits)
        let len = if prefix_len == 0 {
            1
        } else if prefix_len <= 64 {
            2
        } else {
            3
        };
        
        Self {
            option_type: ICMP6_OPT_RT_INFO,
            len,
            prefix_len,
            pref_reserved: preference,
            route_lifetime,
            prefix,
        }
    }

    /// Serialize the option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.option_type);
        bytes.push(self.len);
        bytes.push(self.prefix_len);
        bytes.push(self.pref_reserved);
        bytes.extend_from_slice(&self.route_lifetime.to_be_bytes());
        
        // Include prefix bytes based on prefix_len
        let prefix_bytes = self.prefix.octets();
        let bytes_needed = if self.prefix_len == 0 {
            0
        } else if self.prefix_len <= 64 {
            8
        } else {
            16
        };
        
        bytes.extend_from_slice(&prefix_bytes[..bytes_needed]);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_link_layer_option() {
        let mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let option = SourceLinkLayerOption::new(mac.clone());
        
        assert_eq!(option.option_type, ICMP6_OPT_SOURCE_MAC);
        assert_eq!(option.len, 1); // 8 bytes total
        assert_eq!(option.address, mac);
        
        let bytes = option.to_bytes();
        assert_eq!(bytes.len(), 8); // Padded to 8 bytes
    }

    #[test]
    fn test_mtu_option() {
        let option = MtuOption::new(1500);
        
        assert_eq!(option.option_type, ICMP6_OPT_MTU);
        assert_eq!(option.len, 1);
        assert_eq!(option.mtu, 1500);
        
        let bytes = option.to_bytes();
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_rdnss_option() {
        let dns1: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let dns2: Ipv6Addr = "2001:4860:4860::8844".parse().unwrap();
        let option = RdnssOption::new(vec![dns1, dns2], 3600);
        
        assert_eq!(option.option_type, ICMP6_OPT_RDNSS);
        assert_eq!(option.len, 5); // 1 + 2*2 = 5 (40 bytes)
        assert_eq!(option.lifetime, 3600);
        assert_eq!(option.addresses.len(), 2);
        
        let bytes = option.to_bytes();
        assert_eq!(bytes.len(), 40);
    }

    #[test]
    fn test_dnssl_option() {
        let domains = vec!["example.com".to_string()];
        let option = DnsslOption::new(domains, 3600);
        
        assert_eq!(option.option_type, ICMP6_OPT_DNSSL);
        assert_eq!(option.lifetime, 3600);
        
        let bytes = option.to_bytes();
        assert!(bytes.len() % 8 == 0); // Must be multiple of 8
    }

    #[test]
    fn test_route_info_option() {
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let option = RouteInfoOption::new(prefix, 64, 1800, RouteInfoOption::PREF_MEDIUM);
        
        assert_eq!(option.option_type, ICMP6_OPT_RT_INFO);
        assert_eq!(option.prefix_len, 64);
        assert_eq!(option.route_lifetime, 1800);
        
        let bytes = option.to_bytes();
        assert_eq!(bytes.len(), 16); // Type(1) + Len(1) + PrefixLen(1) + Pref(1) + Lifetime(4) + Prefix(8)
    }
}
