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
//! # Memory Safety Improvements
//!
//! This Rust refactoring eliminates several classes of memory safety vulnerabilities
//! present in the C implementation:
//!
//! ## Buffer Overflow Elimination
//!
//! The C implementation uses fixed-size wire-format structs (e.g., `struct ra_packet`,
//! `struct prefix_opt`) that are directly cast from network packet buffers. This requires
//! manual bounds checking before every access. Rust's type system and slice bounds checking
//! automatically prevents buffer overflows - any out-of-bounds access results in a panic
//! rather than undefined behavior or memory corruption.
//!
//! ## Network Byte Order Safety
//!
//! C requires manual `htons()`, `htonl()`, `ntohs()`, `ntohl()` conversions for all
//! multi-byte fields. Forgetting a conversion or using the wrong function causes subtle
//! bugs. The Rust implementation uses explicit types and the `byteorder` crate (or manual
//! conversion methods) that make byte order explicit in the type system, preventing
//! accidental misuse.
//!
//! ## Struct Padding and Alignment
//!
//! C packed structs require `__attribute__((packed))` or manual padding to match wire
//! formats exactly. Incorrect padding causes misaligned accesses and protocol violations.
//! Rust's explicit field-by-field serialization eliminates padding concerns entirely -
//! there's no assumption that in-memory layout matches wire format.
//!
//! ## Pointer Aliasing
//!
//! C code casts raw packet buffers to struct pointers (e.g., `(struct ra_packet*)buffer`),
//! creating aliasing and alignment issues. Rust's ownership system prevents multiple
//! mutable references, and explicit serialization avoids pointer casts entirely.
//!
//! # ICMPv6 Message Types Implemented
//!
//! - **Router Advertisement (Type 134)**: Periodic router announcements for SLAAC
//! - **Router Solicitation (Type 133)**: Host requests for immediate RA
//! - **Neighbor Solicitation (Type 135)**: IPv6 equivalent of ARP request
//! - **Neighbor Advertisement (Type 136)**: IPv6 equivalent of ARP reply
//! - **Echo Request/Reply (Types 128/129)**: ICMPv6 ping for DAD
//!
//! # Wire Format Serialization
//!
//! These structures represent logical packet contents. Actual wire-format serialization
//! (converting to/from byte arrays with proper network byte order) is handled by
//! separate serialization methods in the `radv::server` module. This separation enables:
//!
//! - Safe in-memory representation (native byte order, Rust types)
//! - Explicit serialization boundaries (no struct memory reinterpretation)
//! - Independent testing of protocol logic vs. wire format
//!
//! # RFC Compliance
//!
//! - RFC 4861: Neighbor Discovery for IPv6
//! - RFC 4862: IPv6 Stateless Address Autoconfiguration
//! - RFC 4443: ICMPv6 for IPv6
//! - RFC 8106: IPv6 Router Advertisement Options for DNS Configuration
//! - RFC 4191: Default Router Preferences and More-Specific Routes
//! - RFC 6275: Mobility Support in IPv6 (Advertisement Interval option)

use std::net::Ipv6Addr;

/// IPv6 multicast address for all-nodes group (FF02::1)
///
/// Per RFC 4291 Section 2.7.1, this link-local scope multicast address reaches
/// all IPv6-capable nodes on the local link. Router Advertisement messages are
/// sent to this address to announce router presence and configuration parameters.
///
/// This replaces the C implementation's string literal "FF02::1" with a compile-time
/// constant Ipv6Addr value, eliminating runtime parsing overhead and enabling const
/// evaluation for multicast destinations used by Router Advertisement transmission.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0001);

/// IPv6 multicast address for all-routers group (FF02::2)
///
/// Per RFC 4291 Section 2.7.1, this link-local scope multicast address reaches
/// only nodes configured as IPv6 routers. Hosts send Router Solicitation messages
/// to this address to request immediate Router Advertisement.
///
/// This replaces the C implementation's string literal "FF02::2" with a compile-time
/// constant Ipv6Addr value, providing type safety and const evaluation capability.
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0002);

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

/// Special lifetime value indicating infinite lifetime
///
/// Per RFC 4861 Section 4.6.2, the value 0xFFFFFFFF in valid_lifetime or
/// preferred_lifetime fields indicates that the lifetime is infinite (no expiration).
/// This is used for permanent prefixes that should never be deprecated or invalidated.
pub const INFINITE_LIFETIME: u32 = 0xFFFFFFFF;

/// Router Advertisement flag: Managed address configuration (M-bit)
///
/// When set (0x80), indicates that addresses are available via DHCPv6 stateful
/// address configuration. Hosts should use DHCPv6 to obtain addresses rather than
/// relying solely on SLAAC.
///
/// # DHCPv6 Integration
///
/// When M-bit is set, dnsmasq's DHCPv6 server expects clients to perform full
/// stateful DHCPv6 address acquisition using SOLICIT/ADVERTISE/REQUEST/REPLY
/// message exchange per RFC 8415. This flag coordinates Router Advertisement
/// behavior with the DHCPv6 server to prevent address conflicts between SLAAC
/// and DHCPv6-assigned addresses.
///
/// # RFC Compliance
///
/// Per RFC 4861 Section 4.2, the M-bit is bit 7 (0x80) of the flags field.
/// When both M-bit and O-bit are set, clients should use DHCPv6 for both
/// addresses and other configuration.
pub const RA_FLAG_MANAGED: u8 = 0x80;

/// Router Advertisement flag: Other configuration (O-bit)
///
/// When set (0x40), indicates that other configuration information (DNS servers,
/// NTP servers, etc.) is available via DHCPv6. Hosts may use SLAAC for addresses
/// but should query DHCPv6 for additional configuration.
///
/// # DHCPv6 Integration
///
/// When O-bit is set without M-bit, clients use SLAAC for address configuration
/// but query DHCPv6 for additional parameters using INFORMATION-REQUEST messages
/// per RFC 8415 Section 18.2.6. This enables stateless DHCPv6 configuration
/// where dnsmasq provides DNS servers, domain search lists, and other options
/// without maintaining address state.
///
/// # RFC Compliance
///
/// Per RFC 4861 Section 4.2, the O-bit is bit 6 (0x40) of the flags field.
/// Common configuration: M=0, O=1 for SLAAC + stateless DHCPv6.
pub const RA_FLAG_OTHER: u8 = 0x40;

/// Prefix Information flag: On-link (L-bit)
///
/// When set (0x80), indicates that this prefix is on-link. Hosts can assume that
/// destinations matching this prefix are directly reachable on the local link.
///
/// # On-Link Determination
///
/// Per RFC 4861 Section 6.3.4, when L-bit is set, hosts add the prefix to their
/// on-link prefix list. Packets destined to addresses matching this prefix are
/// sent directly on the link without going through a router, enabling efficient
/// local communication.
///
/// # SLAAC Integration
///
/// The L-bit is typically set together with the A-bit for standard /64 prefixes
/// used for stateless address autoconfiguration. This allows hosts to both
/// generate addresses from the prefix (A-bit) and recognize local destinations
/// (L-bit).
///
/// # RFC Compliance
///
/// Per RFC 4861 Section 4.6.2, the L-bit is bit 7 (0x80) of the prefix flags field.
pub const PREFIX_FLAG_ONLINK: u8 = 0x80;

/// Prefix Information flag: Autonomous address configuration (A-bit)
///
/// When set (0x40), indicates that this prefix can be used for SLAAC. Hosts should
/// combine the prefix with their interface identifier (EUI-64 or privacy extension)
/// to generate IPv6 addresses without DHCPv6 server interaction.
///
/// # SLAAC Operation
///
/// Per RFC 4862 Section 5.5.3, when A-bit is set, hosts perform stateless address
/// autoconfiguration by:
/// 1. Extracting the advertised prefix (typically /64)
/// 2. Combining prefix with interface identifier (EUI-64, Modified EUI-64, or RFC 7217)
/// 3. Performing Duplicate Address Detection (DAD) on generated address
/// 4. Assigning address with valid/preferred lifetimes from this option
///
/// # DHCPv6 Coordination
///
/// When M-bit is set in Router Advertisement flags, the A-bit should typically be
/// cleared (0) to prevent SLAAC, forcing clients to use DHCPv6 for addresses. When
/// M-bit is clear, A-bit enables pure SLAAC or hybrid SLAAC + stateless DHCPv6.
///
/// # RFC Compliance
///
/// Per RFC 4861 Section 4.6.2, the A-bit is bit 6 (0x40) of the prefix flags field.
/// Per RFC 4862, A-bit=1 is required for SLAAC operation.
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

impl NeighPacket {
    /// Create a new Neighbor Solicitation packet
    ///
    /// Used for address resolution (discovering link-layer address) and
    /// Duplicate Address Detection (DAD).
    ///
    /// # Arguments
    ///
    /// * `target` - IPv6 address being queried
    pub fn new_solicitation(target: Ipv6Addr) -> Self {
        Self {
            icmp_type: ICMP6_NEIGHBOR_SOLICITATION,
            code: 0,
            checksum: 0,
            reserved: 0,
            target,
        }
    }
    
    /// Create a new Neighbor Advertisement packet
    ///
    /// Used to respond to Neighbor Solicitation or announce link-layer address changes.
    ///
    /// # Arguments
    ///
    /// * `target` - IPv6 address being announced
    /// * `flags` - NA flags (R-bit: router, S-bit: solicited, O-bit: override)
    pub fn new_advertisement(target: Ipv6Addr, flags: u16) -> Self {
        Self {
            icmp_type: ICMP6_NEIGHBOR_ADVERTISEMENT,
            code: 0,
            checksum: 0,
            reserved: flags,
            target,
        }
    }
}

/// ICMPv6 Prefix Information option for SLAAC
///
/// Advertises IPv6 prefixes in Router Advertisement messages for on-link determination
/// and stateless address autoconfiguration per RFC 4862.
///
/// # Lifetime Semantics
///
/// The valid and preferred lifetimes control address lifetime behavior per RFC 4862:
///
/// - **Valid Lifetime**: Time in seconds that addresses configured from this prefix
///   remain valid (usable for sending/receiving packets). Value 0xFFFFFFFF represents
///   infinity (unlimited validity). When valid lifetime expires, addresses become
///   invalid and must not be used for new connections or existing communication.
///
/// - **Preferred Lifetime**: Time in seconds that addresses remain preferred for new
///   connections. Must be ≤ valid lifetime. Value 0xFFFFFFFF represents infinity.
///   After preferred lifetime expires but before valid lifetime expires, addresses
///   become deprecated - they can still be used for existing connections but should
///   not be used for new outgoing connections.
///
/// Common configurations:
/// - Standard prefix: valid=2592000 (30 days), preferred=604800 (7 days)
/// - Infinite prefix: valid=0xFFFFFFFF, preferred=0xFFFFFFFF
/// - Deprecating prefix: valid=2592000, preferred=0 (immediate deprecation)
///
/// # DHCPv6 Integration
///
/// When Router Advertisement M-bit is set, prefix options should typically have
/// A-bit cleared to disable SLAAC, forcing DHCPv6 address assignment. When M-bit
/// is clear and A-bit is set, hosts use SLAAC with these lifetime values to
/// manage address lifecycle without DHCPv6 state.
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
/// # RFC Compliance
///
/// - RFC 4861 Section 4.6.2: Prefix Information Option format
/// - RFC 4862 Section 5.5.3: Prefix Information processing for SLAAC
/// - RFC 4862 Section 5.5.4: Address lifetime management
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
    /// - Hop limit: 64 (typical value per RFC 4861)
    /// - No M-bit or O-bit (SLAAC only, no DHCPv6)
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
    ///
    /// When enabled, instructs clients to use DHCPv6 for stateful address configuration.
    pub fn with_managed_flag(mut self) -> Self {
        self.flags |= RA_FLAG_MANAGED;
        self
    }

    /// Set the Other configuration flag (O-bit)
    ///
    /// When enabled, instructs clients to use DHCPv6 for additional configuration
    /// (DNS servers, NTP servers, etc.) via INFORMATION-REQUEST.
    pub fn with_other_flag(mut self) -> Self {
        self.flags |= RA_FLAG_OTHER;
        self
    }

    /// Set the router lifetime in seconds
    ///
    /// # Arguments
    ///
    /// * `lifetime` - Router lifetime (0-9000 seconds). Use 0 to indicate this
    ///   router should not be used as a default router.
    ///
    /// # RFC Compliance
    ///
    /// Per RFC 4861 Section 4.2, values > 9000 seconds may be used but are
    /// uncommon. Recommended range is 0-9000.
    pub fn with_lifetime(mut self, lifetime: u16) -> Self {
        self.lifetime = lifetime;
        self
    }
    
    /// Set the current hop limit
    ///
    /// Suggests the hop limit value for outgoing IPv6 packets. Use 0 for unspecified.
    pub fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }
    
    /// Set the reachable time in milliseconds
    ///
    /// Time a neighbor is considered reachable after receiving reachability confirmation.
    /// Use 0 for unspecified (host should use its own value).
    pub fn with_reachable_time(mut self, reachable_time: u32) -> Self {
        self.reachable_time = reachable_time;
        self
    }
    
    /// Set the retransmission timer in milliseconds
    ///
    /// Time between retransmitted Neighbor Solicitation messages.
    /// Use 0 for unspecified (host should use its own value).
    pub fn with_retrans_time(mut self, retrans_time: u32) -> Self {
        self.retrans_time = retrans_time;
        self
    }
    
    /// Check if M-bit (Managed address configuration) is set
    pub fn is_managed(&self) -> bool {
        (self.flags & RA_FLAG_MANAGED) != 0
    }
    
    /// Check if O-bit (Other configuration) is set
    pub fn is_other_config(&self) -> bool {
        (self.flags & RA_FLAG_OTHER) != 0
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
    /// * `valid_lifetime` - Valid lifetime in seconds (use INFINITE_LIFETIME for permanent)
    /// * `preferred_lifetime` - Preferred lifetime in seconds (must be ≤ valid_lifetime)
    ///
    /// # Panics
    ///
    /// Panics if `preferred_lifetime > valid_lifetime` (violates RFC 4861 Section 4.6.2)
    pub fn new(
        prefix: Ipv6Addr,
        prefix_len: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        // RFC 4861 requires preferred_lifetime <= valid_lifetime
        assert!(
            preferred_lifetime <= valid_lifetime,
            "preferred_lifetime ({}) must be <= valid_lifetime ({})",
            preferred_lifetime,
            valid_lifetime
        );
        
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

    /// Create a prefix option with infinite lifetime
    ///
    /// Useful for permanent network prefixes that should never expire.
    /// Sets both valid and preferred lifetimes to 0xFFFFFFFF.
    pub fn new_infinite(prefix: Ipv6Addr, prefix_len: u8) -> Self {
        Self::new(prefix, prefix_len, INFINITE_LIFETIME, INFINITE_LIFETIME)
    }

    /// Set the on-link flag (L-bit)
    ///
    /// When enabled, hosts consider addresses matching this prefix to be on-link
    /// (directly reachable without routing).
    pub fn with_onlink(mut self, onlink: bool) -> Self {
        if onlink {
            self.flags |= PREFIX_FLAG_ONLINK;
        } else {
            self.flags &= !PREFIX_FLAG_ONLINK;
        }
        self
    }

    /// Set the autonomous address configuration flag (A-bit)
    ///
    /// When enabled, hosts use this prefix for SLAAC (Stateless Address
    /// Autoconfiguration) per RFC 4862.
    pub fn with_auto(mut self, auto: bool) -> Self {
        if auto {
            self.flags |= PREFIX_FLAG_AUTO;
        } else {
            self.flags &= !PREFIX_FLAG_AUTO;
        }
        self
    }
    
    /// Check if this prefix is configured for SLAAC (A-bit set)
    pub fn is_autonomous(&self) -> bool {
        (self.flags & PREFIX_FLAG_AUTO) != 0
    }
    
    /// Check if this prefix is on-link (L-bit set)
    pub fn is_onlink(&self) -> bool {
        (self.flags & PREFIX_FLAG_ONLINK) != 0
    }
    
    /// Check if this prefix has infinite lifetime
    pub fn is_infinite(&self) -> bool {
        self.valid_lifetime == INFINITE_LIFETIME
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
        // ALL_NODES is now a const Ipv6Addr, no parsing needed
        assert_eq!(ALL_NODES.octets()[0], 0xff);
        assert_eq!(ALL_NODES.octets()[1], 0x02);
        assert_eq!(ALL_NODES.octets()[15], 0x01);

        // ALL_ROUTERS is now a const Ipv6Addr, no parsing needed
        assert_eq!(ALL_ROUTERS.octets()[0], 0xff);
        assert_eq!(ALL_ROUTERS.octets()[1], 0x02);
        assert_eq!(ALL_ROUTERS.octets()[15], 0x02);
    }
    
    #[test]
    fn test_all_nodes_multicast_format() {
        // Verify ALL_NODES matches FF02::1 format
        assert_eq!(ALL_NODES, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert!(ALL_NODES.is_multicast());
    }
    
    #[test]
    fn test_all_routers_multicast_format() {
        // Verify ALL_ROUTERS matches FF02::2 format
        assert_eq!(ALL_ROUTERS, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
        assert!(ALL_ROUTERS.is_multicast());
    }
    
    #[test]
    fn test_ra_packet_flags() {
        let ra = RaPacket::new()
            .with_managed_flag()
            .with_other_flag();
        
        assert!(ra.is_managed());
        assert!(ra.is_other_config());
        assert_eq!(ra.flags, RA_FLAG_MANAGED | RA_FLAG_OTHER);
    }
    
    #[test]
    fn test_ra_packet_with_all_params() {
        let ra = RaPacket::new()
            .with_hop_limit(255)
            .with_lifetime(9000)
            .with_reachable_time(30000)
            .with_retrans_time(1000)
            .with_managed_flag();
        
        assert_eq!(ra.hop_limit, 255);
        assert_eq!(ra.lifetime, 9000);
        assert_eq!(ra.reachable_time, 30000);
        assert_eq!(ra.retrans_time, 1000);
        assert!(ra.is_managed());
        assert!(!ra.is_other_config());
    }
    
    #[test]
    fn test_prefix_option_infinite_lifetime() {
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let prefix_opt = PrefixOption::new_infinite(prefix, 64);
        
        assert_eq!(prefix_opt.valid_lifetime, INFINITE_LIFETIME);
        assert_eq!(prefix_opt.preferred_lifetime, INFINITE_LIFETIME);
        assert!(prefix_opt.is_infinite());
    }
    
    #[test]
    fn test_prefix_option_flag_checks() {
        let prefix: Ipv6Addr = "fd00::".parse().unwrap();
        let prefix_opt = PrefixOption::new(prefix, 64, 2592000, 604800)
            .with_auto(true)
            .with_onlink(true);
        
        assert!(prefix_opt.is_autonomous());
        assert!(prefix_opt.is_onlink());
        
        let prefix_opt_no_auto = prefix_opt.clone().with_auto(false);
        assert!(!prefix_opt_no_auto.is_autonomous());
        assert!(prefix_opt_no_auto.is_onlink());
    }
    
    #[test]
    #[should_panic(expected = "preferred_lifetime")]
    fn test_prefix_option_invalid_lifetimes() {
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        // This should panic because preferred > valid
        PrefixOption::new(prefix, 64, 604800, 2592000);
    }
    
    #[test]
    fn test_neigh_packet_solicitation() {
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ns = NeighPacket::new_solicitation(target);
        
        assert_eq!(ns.icmp_type, ICMP6_NEIGHBOR_SOLICITATION);
        assert_eq!(ns.code, 0);
        assert_eq!(ns.reserved, 0);
        assert_eq!(ns.target, target);
    }
    
    #[test]
    fn test_neigh_packet_advertisement() {
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let flags = 0xE000; // R, S, O bits set
        let na = NeighPacket::new_advertisement(target, flags);
        
        assert_eq!(na.icmp_type, ICMP6_NEIGHBOR_ADVERTISEMENT);
        assert_eq!(na.code, 0);
        assert_eq!(na.reserved, flags);
        assert_eq!(na.target, target);
    }
    
    #[test]
    fn test_icmpv6_constants() {
        // Verify all ICMPv6 type constants
        assert_eq!(ICMP6_ECHO_REQUEST, 128);
        assert_eq!(ICMP6_ECHO_REPLY, 129);
        assert_eq!(ICMP6_ROUTER_SOLICITATION, 133);
        assert_eq!(ICMP6_ROUTER_ADVERTISEMENT, 134);
        assert_eq!(ICMP6_NEIGHBOR_SOLICITATION, 135);
        assert_eq!(ICMP6_NEIGHBOR_ADVERTISEMENT, 136);
    }
    
    #[test]
    fn test_icmpv6_option_constants() {
        // Verify all ICMPv6 option type constants
        assert_eq!(ICMP6_OPT_SOURCE_MAC, 1);
        assert_eq!(ICMP6_OPT_PREFIX, 3);
        assert_eq!(ICMP6_OPT_MTU, 5);
        assert_eq!(ICMP6_OPT_ADV_INTERVAL, 7);
        assert_eq!(ICMP6_OPT_RT_INFO, 24);
        assert_eq!(ICMP6_OPT_RDNSS, 25);
        assert_eq!(ICMP6_OPT_DNSSL, 31);
    }
    
    #[test]
    fn test_flag_constants() {
        // Verify flag bit patterns
        assert_eq!(RA_FLAG_MANAGED, 0x80);
        assert_eq!(RA_FLAG_OTHER, 0x40);
        assert_eq!(PREFIX_FLAG_ONLINK, 0x80);
        assert_eq!(PREFIX_FLAG_AUTO, 0x40);
    }
    
    #[test]
    fn test_infinite_lifetime_constant() {
        assert_eq!(INFINITE_LIFETIME, 0xFFFFFFFF);
    }
    
    #[test]
    fn test_ra_packet_default() {
        let ra1 = RaPacket::new();
        let ra2 = RaPacket::default();
        
        assert_eq!(ra1, ra2);
        assert_eq!(ra1.icmp_type, ICMP6_ROUTER_ADVERTISEMENT);
        assert_eq!(ra1.hop_limit, 64);
        assert_eq!(ra1.flags, 0);
    }
    
    #[test]
    fn test_prefix_option_wire_format_fields() {
        let prefix: Ipv6Addr = "2001:db8:1234:5678::".parse().unwrap();
        let prefix_opt = PrefixOption::new(prefix, 64, 7200, 1800);
        
        // Verify wire format constants
        assert_eq!(prefix_opt.option_type, ICMP6_OPT_PREFIX);
        assert_eq!(prefix_opt.len, 4); // 32 bytes = 4 * 8
        assert_eq!(prefix_opt.prefix_len, 64);
        assert_eq!(prefix_opt.reserved, 0);
    }
}
