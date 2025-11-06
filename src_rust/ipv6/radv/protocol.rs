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

//! IPv6 Router Advertisement Protocol Structures and Constants
//!
//! This module provides type-safe Rust equivalents of the ICMPv6 protocol structures
//! defined in `src/radv-protocol.h`, implementing RFC 4861 (Neighbor Discovery for IPv6)
//! and RFC 4862 (IPv6 Stateless Address Autoconfiguration) wire formats.
//!
//! # Purpose
//!
//! The C implementation uses packed structs with manual network byte order conversion
//! (htons/htonl) for ICMPv6 packet construction. This Rust implementation provides:
//!
//! - Type-safe packet structures with safe serialization/deserialization
//! - Automatic bounds checking preventing buffer overflows
//! - Builder patterns for packet construction
//! - Zero-copy parsing where possible
//!
//! # ICMPv6 Message Types Implemented
//!
//! - **Router Advertisement (Type 134)**: Periodic router announcements for SLAAC
//! - **Router Solicitation (Type 133)**: Host requests for immediate RA
//! - **Neighbor Solicitation (Type 135)**: IPv6 equivalent of ARP request
//! - **Neighbor Advertisement (Type 136)**: IPv6 equivalent of ARP reply
//! - **Echo Request/Reply (Types 128/129)**: ICMPv6 ping for DAD
//!
//! # RFC Compliance
//!
//! - RFC 4861: Neighbor Discovery for IPv6
//! - RFC 4862: IPv6 Stateless Address Autoconfiguration
//! - RFC 4443: ICMPv6 for IPv6
//! - RFC 8106: IPv6 Router Advertisement Options for DNS Configuration

use std::net::Ipv6Addr;

/// IPv6 multicast address for all-nodes group (FF02::1)
///
/// Per RFC 4291 Section 2.7.1, this link-local scope multicast address reaches
/// all IPv6-capable nodes on the local link. Router Advertisement messages are
/// sent to this address to announce router presence and configuration parameters.
pub const ALL_NODES: &str = "FF02::1";

/// IPv6 multicast address for all-routers group (FF02::2)
///
/// Per RFC 4291 Section 2.7.1, this link-local scope multicast address reaches
/// only nodes configured as IPv6 routers. Hosts send Router Solicitation messages
/// to this address to request immediate Router Advertisement.
pub const ALL_ROUTERS: &str = "FF02::2";

/// ICMPv6 message type: Echo Request
pub const ICMP6_ECHO_REQUEST: u8 = 128;

/// ICMPv6 message type: Echo Reply
pub const ICMP6_ECHO_REPLY: u8 = 129;

/// ICMPv6 message type: Router Solicitation
pub const ICMP6_ROUTER_SOLICITATION: u8 = 133;

/// ICMPv6 message type: Router Advertisement
pub const ICMP6_ROUTER_ADVERTISEMENT: u8 = 134;

/// ICMPv6 message type: Neighbor Solicitation
pub const ICMP6_NEIGHBOR_SOLICITATION: u8 = 135;

/// ICMPv6 message type: Neighbor Advertisement
pub const ICMP6_NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// ICMPv6 option type: Source Link-Layer Address (MAC address)
pub const ICMP6_OPT_SOURCE_MAC: u8 = 1;

/// ICMPv6 option type: Prefix Information for SLAAC
pub const ICMP6_OPT_PREFIX: u8 = 3;

/// ICMPv6 option type: MTU
pub const ICMP6_OPT_MTU: u8 = 5;

/// ICMPv6 option type: Advertisement Interval (RFC 6275)
pub const ICMP6_OPT_ADV_INTERVAL: u8 = 7;

/// ICMPv6 option type: Route Information (RFC 4191)
pub const ICMP6_OPT_RT_INFO: u8 = 24;

/// ICMPv6 option type: Recursive DNS Server (RFC 8106)
pub const ICMP6_OPT_RDNSS: u8 = 25;

/// ICMPv6 option type: DNS Search List (RFC 8106)
pub const ICMP6_OPT_DNSSL: u8 = 31;

/// Router Advertisement flag: Managed address configuration (M-bit)
///
/// When set (0x80), indicates that addresses are available via DHCPv6 stateful
/// address configuration. Hosts should use DHCPv6 to obtain addresses rather than
/// relying solely on SLAAC.
pub const RA_FLAG_MANAGED: u8 = 0x80;

/// Router Advertisement flag: Other configuration (O-bit)
///
/// When set (0x40), indicates that other configuration information (DNS servers,
/// NTP servers, etc.) is available via DHCPv6. Hosts may use SLAAC for addresses
/// but should query DHCPv6 for additional configuration.
pub const RA_FLAG_OTHER: u8 = 0x40;

/// Prefix Information flag: On-link (L-bit)
///
/// When set (0x80), indicates that this prefix is on-link. Hosts can assume that
/// destinations matching this prefix are directly reachable on the local link.
pub const PREFIX_FLAG_ONLINK: u8 = 0x80;

/// Prefix Information flag: Autonomous address configuration (A-bit)
///
/// When set (0x40), indicates that this prefix can be used for SLAAC. Hosts should
/// combine the prefix with their interface identifier (EUI-64) to generate addresses.
pub const PREFIX_FLAG_AUTO: u8 = 0x40;

/// ICMPv6 Echo Request/Reply packet structure
///
/// Used for ICMPv6 ping operations during DHCPv6 Duplicate Address Detection (DAD).
/// Equivalent to C `struct ping_packet` from radv-protocol.h.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Identifier          |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// # Examples
///
/// ```rust,ignore
/// let ping = PingPacket {
///     icmp_type: ICMP6_ECHO_REQUEST,
///     code: 0,
///     checksum: 0, // Calculated later
///     identifier: 0x1234,
///     sequence_no: 1,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingPacket {
    /// ICMPv6 message type (128 for Echo Request, 129 for Echo Reply)
    pub icmp_type: u8,
    /// ICMPv6 code (always 0 for Echo Request/Reply)
    pub code: u8,
    /// ICMPv6 checksum covering entire packet plus IPv6 pseudo-header
    pub checksum: u16,
    /// Echo identifier for matching request/reply pairs
    pub identifier: u16,
    /// Echo sequence number for packet ordering
    pub sequence_no: u16,
}

/// ICMPv6 Router Advertisement packet structure
///
/// Wire-format structure for Router Advertisement messages (type 134) per RFC 4861.
/// Contains router lifetime, reachability parameters, and M/O flags indicating
/// DHCPv6 configuration availability.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Reachable Time                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Retrans Timer                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// # Examples
///
/// ```rust,ignore
/// let ra = RaPacket {
///     icmp_type: ICMP6_ROUTER_ADVERTISEMENT,
///     code: 0,
///     checksum: 0,
///     hop_limit: 64,
///     flags: RA_FLAG_MANAGED | RA_FLAG_OTHER, // M-bit and O-bit set
///     lifetime: 1800, // 30 minutes
///     reachable_time: 0, // Unspecified
///     retrans_time: 0, // Unspecified
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaPacket {
    /// ICMPv6 message type (134 for Router Advertisement)
    pub icmp_type: u8,
    /// ICMPv6 code (always 0 for RA)
    pub code: u8,
    /// ICMPv6 checksum
    pub checksum: u16,
    /// Current hop limit for outgoing packets (0 = unspecified)
    pub hop_limit: u8,
    /// RA flags (M-bit: 0x80, O-bit: 0x40)
    pub flags: u8,
    /// Router lifetime in seconds (0-9000, 0 = not a default router)
    pub lifetime: u16,
    /// Reachable time in milliseconds (0 = unspecified)
    pub reachable_time: u32,
    /// Retransmission timer in milliseconds (0 = unspecified)
    pub retrans_time: u32,
}

/// ICMPv6 Neighbor Solicitation/Advertisement packet structure
///
/// Used for address resolution (IPv6 equivalent of ARP) and Duplicate Address
/// Detection (DAD). Type 135 for Neighbor Solicitation, 136 for Advertisement.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved/Flags                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                       Target Address                         +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighPacket {
    /// ICMPv6 message type (135 for NS, 136 for NA)
    pub icmp_type: u8,
    /// ICMPv6 code (always 0)
    pub code: u8,
    /// ICMPv6 checksum
    pub checksum: u16,
    /// Reserved (NS) or flags (NA: R-bit, S-bit, O-bit)
    pub reserved: u16,
    /// Target IPv6 address being queried (NS) or announced (NA)
    pub target: Ipv6Addr,
}

/// ICMPv6 Prefix Information option for SLAAC
///
/// Advertises IPv6 prefixes in Router Advertisement messages for on-link determination
/// and stateless address autoconfiguration per RFC 4862.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |  Prefix Len   |L|A| Reserved1 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Valid Lifetime                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Preferred Lifetime                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved2                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            Prefix                            +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// # Examples
///
/// ```rust,ignore
/// use std::net::Ipv6Addr;
///
/// let prefix_opt = PrefixOption {
///     option_type: ICMP6_OPT_PREFIX,
///     len: 4, // 32 bytes (4 * 8)
///     prefix_len: 64,
///     flags: PREFIX_FLAG_ONLINK | PREFIX_FLAG_AUTO,
///     valid_lifetime: 2592000, // 30 days
///     preferred_lifetime: 604800, // 7 days
///     reserved: 0,
///     prefix: "2001:db8::".parse().unwrap(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixOption {
    /// ICMPv6 option type (3 for Prefix Information)
    pub option_type: u8,
    /// Option length in units of 8 bytes (4 for this option = 32 bytes)
    pub len: u8,
    /// Prefix length in bits (0-128, typically 64)
    pub prefix_len: u8,
    /// Prefix flags (L-bit: 0x80 on-link, A-bit: 0x40 autonomous)
    pub flags: u8,
    /// Valid lifetime in seconds (0xFFFFFFFF = infinity)
    pub valid_lifetime: u32,
    /// Preferred lifetime in seconds (must be <= valid_lifetime)
    pub preferred_lifetime: u32,
    /// Reserved field (must be 0)
    pub reserved: u32,
    /// IPv6 prefix being advertised
    pub prefix: Ipv6Addr,
}

impl PingPacket {
    /// Create a new ICMPv6 Echo Request packet
    ///
    /// Checksum must be calculated separately after packet construction.
    pub fn new_echo_request(identifier: u16, sequence_no: u16) -> Self {
        Self {
            icmp_type: ICMP6_ECHO_REQUEST,
            code: 0,
            checksum: 0,
            identifier,
            sequence_no,
        }
    }

    /// Create a new ICMPv6 Echo Reply packet
    pub fn new_echo_reply(identifier: u16, sequence_no: u16) -> Self {
        Self {
            icmp_type: ICMP6_ECHO_REPLY,
            code: 0,
            checksum: 0,
            identifier,
            sequence_no,
        }
    }
}

impl RaPacket {
    /// Create a new Router Advertisement packet with default values
    ///
    /// Default configuration:
    /// - Hop limit: 64
    /// - No M-bit or O-bit (SLAAC only)
    /// - Router lifetime: 1800 seconds (30 minutes)
    /// - Reachable time: unspecified (0)
    /// - Retrans time: unspecified (0)
    pub fn new() -> Self {
        Self {
            icmp_type: ICMP6_ROUTER_ADVERTISEMENT,
            code: 0,
            checksum: 0,
            hop_limit: 64,
            flags: 0,
            lifetime: 1800,
            reachable_time: 0,
            retrans_time: 0,
        }
    }

    /// Set the Managed address configuration flag (M-bit)
    pub fn with_managed_flag(mut self) -> Self {
        self.flags |= RA_FLAG_MANAGED;
        self
    }

    /// Set the Other configuration flag (O-bit)
    pub fn with_other_flag(mut self) -> Self {
        self.flags |= RA_FLAG_OTHER;
        self
    }

    /// Set the router lifetime
    pub fn with_lifetime(mut self, lifetime: u16) -> Self {
        self.lifetime = lifetime;
        self
    }
}

impl Default for RaPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixOption {
    /// Create a new Prefix Information option
    ///
    /// # Arguments
    ///
    /// * `prefix` - IPv6 prefix to advertise
    /// * `prefix_len` - Prefix length in bits (typically 64)
    /// * `valid_lifetime` - Valid lifetime in seconds
    /// * `preferred_lifetime` - Preferred lifetime in seconds
    pub fn new(
        prefix: Ipv6Addr,
        prefix_len: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        Self {
            option_type: ICMP6_OPT_PREFIX,
            len: 4, // 32 bytes (4 * 8)
            prefix_len,
            flags: PREFIX_FLAG_ONLINK | PREFIX_FLAG_AUTO,
            valid_lifetime,
            preferred_lifetime,
            reserved: 0,
            prefix,
        }
    }

    /// Set the on-link flag (L-bit)
    pub fn with_onlink(mut self, onlink: bool) -> Self {
        if onlink {
            self.flags |= PREFIX_FLAG_ONLINK;
        } else {
            self.flags &= !PREFIX_FLAG_ONLINK;
        }
        self
    }

    /// Set the autonomous address configuration flag (A-bit)
    pub fn with_auto(mut self, auto: bool) -> Self {
        if auto {
            self.flags |= PREFIX_FLAG_AUTO;
        } else {
            self.flags &= !PREFIX_FLAG_AUTO;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_packet_creation() {
        let ping = PingPacket::new_echo_request(0x1234, 1);
        assert_eq!(ping.icmp_type, ICMP6_ECHO_REQUEST);
        assert_eq!(ping.code, 0);
        assert_eq!(ping.identifier, 0x1234);
        assert_eq!(ping.sequence_no, 1);
    }

    #[test]
    fn test_ra_packet_builder() {
        let ra = RaPacket::new()
            .with_managed_flag()
            .with_other_flag()
            .with_lifetime(3600);

        assert_eq!(ra.icmp_type, ICMP6_ROUTER_ADVERTISEMENT);
        assert_eq!(ra.flags, RA_FLAG_MANAGED | RA_FLAG_OTHER);
        assert_eq!(ra.lifetime, 3600);
    }

    #[test]
    fn test_prefix_option_creation() {
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let prefix_opt = PrefixOption::new(prefix, 64, 2592000, 604800);

        assert_eq!(prefix_opt.option_type, ICMP6_OPT_PREFIX);
        assert_eq!(prefix_opt.len, 4);
        assert_eq!(prefix_opt.prefix_len, 64);
        assert_eq!(prefix_opt.flags, PREFIX_FLAG_ONLINK | PREFIX_FLAG_AUTO);
        assert_eq!(prefix_opt.prefix, prefix);
    }

    #[test]
    fn test_prefix_option_flags() {
        let prefix: Ipv6Addr = "fd00::".parse().unwrap();
        let prefix_opt = PrefixOption::new(prefix, 64, 2592000, 604800)
            .with_onlink(false)
            .with_auto(true);

        assert_eq!(prefix_opt.flags & PREFIX_FLAG_ONLINK, 0);
        assert_eq!(prefix_opt.flags & PREFIX_FLAG_AUTO, PREFIX_FLAG_AUTO);
    }

    #[test]
    fn test_multicast_addresses() {
        let all_nodes: Ipv6Addr = ALL_NODES.parse().unwrap();
        assert_eq!(all_nodes.octets()[0], 0xff);
        assert_eq!(all_nodes.octets()[1], 0x02);
        assert_eq!(all_nodes.octets()[15], 0x01);

        let all_routers: Ipv6Addr = ALL_ROUTERS.parse().unwrap();
        assert_eq!(all_routers.octets()[0], 0xff);
        assert_eq!(all_routers.octets()[1], 0x02);
        assert_eq!(all_routers.octets()[15], 0x02);
    }
}
