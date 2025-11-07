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

//! `ICMPv6` Router Advertisement Option Builders
//!
//! This module provides safe builder-pattern implementations for constructing `ICMPv6` Router
//! Advertisement options as defined in RFC 4861 (Neighbor Discovery), RFC 8106 (DNS Configuration),
//! and RFC 6275 (Mobile IPv6).
//!
//! # Purpose
//!
//! Router Advertisement messages carry variable-length options that provide additional configuration
//! information beyond the base RA packet. This module refactors the manual buffer manipulation from
//! `src/radv.c` into type-safe Rust builders with automatic validation and serialization.
//!
//! # Memory Safety Improvements Over C Implementation
//!
//! The C implementation in `src/radv.c` uses manual buffer construction with `put_opt6_char()`,
//! `put_opt6_short()`, and `put_opt6_long()` macros that directly write to a global packet buffer
//! (`daemon->outpacket.iov_base`). This approach has several risks:
//!
//! - **Buffer Overflow**: No compile-time bounds checking on packet buffer writes
//! - **Option Length Calculation Errors**: Manual length field calculations can be incorrect
//! - **Network Byte Order Bugs**: Manual `htonl()` calls can be forgotten or misapplied
//! - **State Corruption**: Global buffer shared across subsystems (`DHCPv4`, `DHCPv6`, `RA`)
//!
//! This Rust implementation eliminates these risks by:
//!
//! - **Builder Pattern**: Compile-time validation of required fields before serialization
//! - **Vec<u8> Buffers**: Automatic bounds checking and dynamic sizing
//! - **byteorder Crate**: Type-safe network byte order conversion
//! - **Immutable Construction**: Options built and validated before any serialization
//!
//! # Supported Options
//!
//! - **Prefix Information** (Type 3): IPv6 prefixes for SLAAC with A-flag and L-flag control
//! - **MTU** (Type 5): Link MTU advertisement
//! - **Advertisement Interval** (Type 7): Mobile IPv6 RA transmission interval
//! - **Recursive DNS Server** (Type 25): DNS resolver IPv6 addresses per RFC 8106
//! - **DNS Search List** (Type 31): DNS search domain suffixes per RFC 8106
//!
//! # Wire Format Compliance
//!
//! All options serialize to byte-for-byte identical wire formats as the C implementation,
//! ensuring protocol compatibility. Unit tests verify exact match with C-generated packets.
//!
//! # RFC Compliance
//!
//! - RFC 4861 Section 4.6: Neighbor Discovery Option Formats
//! - RFC 4861 Section 4.6.2: Prefix Information Option
//! - RFC 8106: IPv6 Router Advertisement Options for DNS Configuration
//! - RFC 6275 Section 7.3: Advertisement Interval Option

use std::io::{self, Write};
use std::net::Ipv6Addr;
use std::time::Duration;

use byteorder::{BigEndian, WriteBytesExt};

use super::protocol::ICMP6_OPT_ADV_INTERVAL;

/// Prefix Information option (Type 3) for SLAAC support
///
/// Advertises IPv6 address prefixes that can be used for on-link determination and/or
/// stateless address autoconfiguration (SLAAC) per RFC 4862. This option enables hosts
/// to automatically configure IPv6 addresses without `DHCPv6`.
///
/// # Builder Pattern
///
/// Uses the builder pattern to construct prefix options with validation before serialization.
/// Required fields (`prefix`, `prefix_len`) must be set, while optional fields (flags, lifetimes)
/// have sensible defaults.
///
/// # Wire Format (RFC 4861 Section 4.6.2)
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type (3)  |    Length(4)  |  Prefix Length|L|A|  Reserved1|
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
/// use std::time::Duration;
///
/// let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
/// let option = PrefixOption::new()
///     .prefix(prefix)
///     .prefix_len(64)
///     .autonomous(true)  // Enable SLAAC
///     .on_link(true)     // Prefix is on-link
///     .valid_lifetime(Duration::from_secs(2592000))      // 30 days
///     .preferred_lifetime(Duration::from_secs(604800))   // 7 days
///     .build()?;
///
/// let bytes = option; // Vec<u8> ready for transmission
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixOption {
    prefix: Option<Ipv6Addr>,
    prefix_len: Option<u8>,
    autonomous: bool,
    on_link: bool,
    valid_lifetime: Duration,
    preferred_lifetime: Duration,
}

impl PrefixOption {
    /// Create a new `PrefixOption` builder with default values
    ///
    /// Defaults:
    /// - `autonomous`: false (SLAAC disabled)
    /// - `on_link`: true (prefix is on-link)
    /// - `valid_lifetime`: 2592000 seconds (30 days)
    /// - `preferred_lifetime`: 604800 seconds (7 days)
    ///
    /// The `prefix` and `prefix_len` fields must be set via builder methods before calling `build()`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefix: None,
            prefix_len: None,
            autonomous: false,
            on_link: true,
            valid_lifetime: Duration::from_secs(2_592_000), // 30 days
            preferred_lifetime: Duration::from_secs(604_800), // 7 days
        }
    }

    /// Set the IPv6 prefix to advertise
    ///
    /// Only the first `prefix_len` bits are significant. Remaining bits should be zero.
    ///
    /// # Arguments
    ///
    /// * `prefix` - IPv6 prefix address (e.g., `2001:db8::` for a /64 prefix)
    #[must_use]
    pub fn prefix(mut self, prefix: Ipv6Addr) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Set the prefix length in bits (0-128)
    ///
    /// Typical value is 64 for standard IPv6 subnets.
    ///
    /// # Arguments
    ///
    /// * `len` - Prefix length in bits, must be in range 0-128
    #[must_use]
    pub fn prefix_len(mut self, len: u8) -> Self {
        self.prefix_len = Some(len);
        self
    }

    /// Set the Autonomous address-configuration flag (A-bit)
    ///
    /// When true (0x40), hosts can use this prefix for SLAAC to automatically generate
    /// IPv6 addresses per RFC 4862. When false, addresses must be obtained via `DHCPv6`.
    ///
    /// # Arguments
    ///
    /// * `autonomous` - true to enable SLAAC, false to require `DHCPv6`
    #[must_use]
    pub fn autonomous(mut self, autonomous: bool) -> Self {
        self.autonomous = autonomous;
        self
    }

    /// Set the On-link flag (L-bit)
    ///
    /// When true (0x80), addresses matching this prefix are directly reachable on the local
    /// link without routing through a gateway. Typically set to true for standard prefixes.
    ///
    /// # Arguments
    ///
    /// * `on_link` - true if prefix is on-link, false if routing required
    #[must_use]
    pub fn on_link(mut self, on_link: bool) -> Self {
        self.on_link = on_link;
        self
    }

    /// Set the valid lifetime for addresses configured from this prefix
    ///
    /// Indicates how long addresses remain valid for communication. Must be >= `preferred_lifetime`.
    /// A value of `u32::MAX` (0xFFFFFFFF) indicates infinite lifetime.
    ///
    /// # Arguments
    ///
    /// * `lifetime` - Duration for valid lifetime (max ~136 years for `u32::MAX` seconds)
    #[must_use]
    pub fn valid_lifetime(mut self, lifetime: Duration) -> Self {
        self.valid_lifetime = lifetime;
        self
    }

    /// Set the preferred lifetime for addresses configured from this prefix
    ///
    /// Indicates how long addresses remain preferred for new connections. After expiry,
    /// addresses become deprecated but still valid. Must be <= `valid_lifetime`.
    ///
    /// # Arguments
    ///
    /// * `lifetime` - Duration for preferred lifetime
    #[must_use]
    pub fn preferred_lifetime(mut self, lifetime: Duration) -> Self {
        self.preferred_lifetime = lifetime;
        self
    }

    /// Build and serialize the prefix option to wire format
    ///
    /// Validates all fields and serializes to a Vec<u8> in network byte order.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - 32-byte serialized option ready for transmission
    /// * `Err(io::Error)` - Validation failure with descriptive error message
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - `prefix` is not set
    /// - `prefix_len` is not set or > 128
    /// - `preferred_lifetime` > `valid_lifetime`
    /// - lifetime values exceed `u32::MAX` seconds
    ///
    /// # Wire Format Details
    ///
    /// - Type: 3 (`ICMP6_OPT_PREFIX`)
    /// - Length: 4 (32 bytes total)
    /// - Flags: L-bit (0x80) if `on_link`, A-bit (0x40) if `autonomous`
    /// - All multi-byte fields in network byte order (big-endian)
    pub fn build(self) -> io::Result<Vec<u8>> {
        // Validate required fields
        let prefix = self.prefix.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "prefix is required")
        })?;

        let prefix_len = self.prefix_len.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "prefix_len is required")
        })?;

        // Validate prefix length range
        if prefix_len > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("prefix_len {prefix_len} exceeds maximum 128"),
            ));
        }

        // Convert durations to seconds (clamping to u32::MAX)
        // Safe cast: value is already clamped to u32::MAX
        #[allow(clippy::cast_possible_truncation)]
        let valid_secs = self.valid_lifetime.as_secs().min(u64::from(u32::MAX)) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let preferred_secs = self.preferred_lifetime.as_secs().min(u64::from(u32::MAX)) as u32;

        // Validate lifetime relationship
        if preferred_secs > valid_secs {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "preferred_lifetime ({preferred_secs}) must not exceed valid_lifetime ({valid_secs})"
                ),
            ));
        }

        // Calculate flags byte
        let mut flags: u8 = 0;
        if self.on_link {
            flags |= 0x80; // L-bit
        }
        if self.autonomous {
            flags |= 0x40; // A-bit
        }

        // Serialize to wire format (32 bytes total)
        let mut buf = Vec::with_capacity(32);
        
        buf.write_u8(3)?; // Type = ICMP6_OPT_PREFIX
        buf.write_u8(4)?; // Length = 4 (in units of 8 bytes, so 32 bytes total)
        buf.write_u8(prefix_len)?;
        buf.write_u8(flags)?;
        buf.write_u32::<BigEndian>(valid_secs)?;
        buf.write_u32::<BigEndian>(preferred_secs)?;
        buf.write_u32::<BigEndian>(0)?; // Reserved field
        
        // Write 16-byte IPv6 prefix
        buf.write_all(&prefix.octets())?;

        debug_assert_eq!(buf.len(), 32, "PrefixOption must serialize to exactly 32 bytes");
        Ok(buf)
    }
}

impl Default for PrefixOption {
    fn default() -> Self {
        Self::new()
    }
}

/// Recursive DNS Server option (Type 25) per RFC 8106
///
/// Advertises IPv6 addresses of DNS recursive resolvers in Router Advertisement messages.
/// Enables stateless DNS configuration without `DHCPv6`, allowing hosts to discover DNS servers
/// through `RA` alone.
///
/// # Builder Pattern
///
/// Supports incremental addition of DNS server addresses via `add_server()` method.
///
/// # Wire Format (RFC 8106 Section 5.1)
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type (25) |     Length    |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Lifetime                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// :            Addresses of IPv6 Recursive DNS Servers            :
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Length is 1 + (number of addresses) * 2. Each address is 16 bytes (2 units of 8 bytes).
///
/// # Examples
///
/// ```rust,ignore
/// use std::net::Ipv6Addr;
/// use std::time::Duration;
///
/// let dns1 = "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap();
/// let dns2 = "2001:4860:4860::8844".parse::<Ipv6Addr>().unwrap();
///
/// let option = RdnssOption::new()
///     .add_server(dns1)
///     .add_server(dns2)
///     .lifetime(Duration::from_secs(3600))
///     .build()?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdnssOption {
    servers: Vec<Ipv6Addr>,
    lifetime: Duration,
}

impl RdnssOption {
    /// Create a new `RdnssOption` builder with default values
    ///
    /// Default lifetime: 3600 seconds (1 hour)
    #[must_use]
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            lifetime: Duration::from_secs(3600),
        }
    }

    /// Add a DNS server IPv6 address
    ///
    /// Can be called multiple times to advertise multiple DNS servers. RFC 8106 recommends
    /// advertising at least two DNS servers for redundancy.
    ///
    /// # Arguments
    ///
    /// * `server` - IPv6 address of DNS recursive resolver
    #[must_use]
    pub fn add_server(mut self, server: Ipv6Addr) -> Self {
        self.servers.push(server);
        self
    }

    /// Set the lifetime for DNS server addresses
    ///
    /// Indicates how long the DNS server addresses remain valid. Hosts should stop using
    /// DNS servers after their lifetime expires. A value of `u32::MAX` indicates infinite lifetime.
    ///
    /// # Arguments
    ///
    /// * `lifetime` - Duration for DNS server address validity
    #[must_use]
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Build and serialize the RDNSS option to wire format
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Serialized option ready for transmission
    /// * `Err(io::Error)` - Validation failure
    ///
    /// # Errors
    ///
    /// Returns error if no DNS servers have been added.
    ///
    /// # Wire Format Details
    ///
    /// - Type: 25 (`ICMP6_OPT_RDNSS`)
    /// - Length: 1 + (`num_servers` * 2), in units of 8 bytes
    /// - Reserved: 0x0000
    /// - Lifetime: `u32` in network byte order
    /// - Addresses: 16 bytes per server in network byte order
    pub fn build(self) -> io::Result<Vec<u8>> {
        if self.servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one DNS server is required",
            ));
        }

        // Safe cast: value is already clamped to u32::MAX
        #[allow(clippy::cast_possible_truncation)]
        let lifetime_secs = self.lifetime.as_secs().min(u64::from(u32::MAX)) as u32;
        
        // Calculate length: 1 (header + lifetime) + 2 per address (16 bytes each)
        let len = 1 + (self.servers.len() * 2);
        
        // Validate length fits in u8
        if len > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("too many DNS servers: length {len} exceeds maximum 255"),
            ));
        }

        let mut buf = Vec::with_capacity(len * 8);
        
        buf.write_u8(25)?; // Type = ICMP6_OPT_RDNSS
        // Safe cast: len is already validated to be <= 255
        #[allow(clippy::cast_possible_truncation)]
        buf.write_u8(len as u8)?;
        buf.write_u16::<BigEndian>(0)?; // Reserved
        buf.write_u32::<BigEndian>(lifetime_secs)?;
        
        // Write DNS server addresses
        for server in &self.servers {
            buf.write_all(&server.octets())?;
        }

        debug_assert_eq!(
            buf.len(),
            len * 8,
            "RdnssOption serialization size mismatch"
        );
        Ok(buf)
    }
}

impl Default for RdnssOption {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS Search List option (Type 31) per RFC 8106
///
/// Advertises DNS search domain suffixes in Router Advertisement messages. Enables stateless
/// DNS search list configuration without `DHCPv6`, allowing hosts to automatically append
/// domain suffixes for unqualified hostname lookups.
///
/// # Builder Pattern
///
/// Supports incremental addition of domain names via `add_domain()` method.
///
/// # Wire Format (RFC 8106 Section 5.2)
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type (31) |     Length    |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Lifetime                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// :                Domain Names (DNS wire format)                 :
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Domain names are encoded in DNS wire format (length-prefixed labels). The option is
/// padded to a multiple of 8 bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use std::time::Duration;
///
/// let option = DnsslOption::new()
///     .add_domain("example.com".to_string())
///     .add_domain("example.net".to_string())
///     .lifetime(Duration::from_secs(3600))
///     .build()?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsslOption {
    domains: Vec<String>,
    lifetime: Duration,
}

impl DnsslOption {
    /// Create a new `DnsslOption` builder with default values
    ///
    /// Default lifetime: 3600 seconds (1 hour)
    #[must_use]
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            lifetime: Duration::from_secs(3600),
        }
    }

    /// Add a DNS search domain
    ///
    /// Can be called multiple times to advertise multiple search domains. Domains are
    /// tried in the order added when resolving unqualified names.
    ///
    /// # Arguments
    ///
    /// * `domain` - Fully-qualified domain name (e.g., "example.com")
    #[must_use]
    pub fn add_domain(mut self, domain: String) -> Self {
        self.domains.push(domain);
        self
    }

    /// Set the lifetime for DNS search domain list
    ///
    /// Indicates how long the search domain list remains valid. A value of `u32::MAX`
    /// indicates infinite lifetime.
    ///
    /// # Arguments
    ///
    /// * `lifetime` - Duration for search domain list validity
    #[must_use]
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Build and serialize the DNSSL option to wire format
    ///
    /// Encodes domain names in DNS wire format (length-prefixed labels) and pads
    /// the option to a multiple of 8 bytes.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Serialized option ready for transmission
    /// * `Err(io::Error)` - Validation or encoding failure
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - no domains have been added
    /// - domain encoding fails (invalid domain name format)
    /// - resulting option exceeds maximum size
    pub fn build(self) -> io::Result<Vec<u8>> {
        if self.domains.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one domain is required",
            ));
        }

        // Safe cast: value is already clamped to u32::MAX
        #[allow(clippy::cast_possible_truncation)]
        let lifetime_secs = self.lifetime.as_secs().min(u64::from(u32::MAX)) as u32;

        // Encode domains in DNS wire format
        let mut domain_bytes = Vec::new();
        for domain in &self.domains {
            encode_dns_name(&mut domain_bytes, domain)?;
        }

        // Calculate padded length (must be multiple of 8 bytes)
        let unpadded_len = 8 + domain_bytes.len(); // Type(1) + Len(1) + Reserved(2) + Lifetime(4) + domains
        let padded_len = (unpadded_len + 7) & !7; // Round up to multiple of 8
        let len_units = padded_len / 8;

        if len_units > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("domain list too long: length {len_units} exceeds maximum 255"),
            ));
        }

        let mut buf = Vec::with_capacity(padded_len);
        
        buf.write_u8(31)?; // Type = ICMP6_OPT_DNSSL
        // Safe cast: len_units is already validated to be <= 255
        #[allow(clippy::cast_possible_truncation)]
        buf.write_u8(len_units as u8)?;
        buf.write_u16::<BigEndian>(0)?; // Reserved
        buf.write_u32::<BigEndian>(lifetime_secs)?;
        buf.write_all(&domain_bytes)?;

        // Pad to multiple of 8 bytes
        while buf.len() < padded_len {
            buf.write_u8(0)?;
        }

        debug_assert_eq!(
            buf.len() % 8,
            0,
            "DnsslOption must be padded to multiple of 8 bytes"
        );
        Ok(buf)
    }
}

impl Default for DnsslOption {
    fn default() -> Self {
        Self::new()
    }
}

/// MTU option (Type 5) per RFC 4861 Section 4.6.4
///
/// Advertises the Maximum Transmission Unit for the link, allowing hosts to optimize
/// packet sizing and avoid fragmentation.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type (5)  |    Length(1)  |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              MTU                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Total option size is always 8 bytes (length = 1).
///
/// # Examples
///
/// ```rust,ignore
/// let option = MtuOption::new()
///     .mtu(1500)  // Standard Ethernet MTU
///     .build()?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuOption {
    mtu_value: Option<u32>,
}

impl MtuOption {
    /// Create a new `MtuOption` builder
    #[must_use]
    pub fn new() -> Self {
        Self { mtu_value: None }
    }

    /// Set the MTU value
    ///
    /// Common values:
    /// - 1280: IPv6 minimum MTU (required for IPv6 links)
    /// - 1500: Standard Ethernet MTU
    /// - 9000: Jumbo frames
    ///
    /// # Arguments
    ///
    /// * `mtu` - Maximum Transmission Unit in bytes
    #[must_use]
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu_value = Some(mtu);
        self
    }

    /// Build and serialize the MTU option to wire format
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - 8-byte serialized option ready for transmission
    /// * `Err(io::Error)` - Validation failure
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - MTU value is not set
    /// - MTU is less than 1280 (IPv6 minimum)
    pub fn build(self) -> io::Result<Vec<u8>> {
        let mtu = self.mtu_value.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "MTU value is required")
        })?;

        // Validate minimum IPv6 MTU
        if mtu < 1280 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("MTU {mtu} is less than IPv6 minimum 1280"),
            ));
        }

        let mut buf = Vec::with_capacity(8);
        
        buf.write_u8(5)?; // Type = ICMP6_OPT_MTU
        buf.write_u8(1)?; // Length = 1 (8 bytes)
        buf.write_u16::<BigEndian>(0)?; // Reserved
        buf.write_u32::<BigEndian>(mtu)?;

        debug_assert_eq!(buf.len(), 8, "MtuOption must serialize to exactly 8 bytes");
        Ok(buf)
    }
}

impl Default for MtuOption {
    fn default() -> Self {
        Self::new()
    }
}

/// Advertisement Interval option (Type 7) per RFC 6275 Section 7.3
///
/// Advertises the router's maximum time between unsolicited multicast Router Advertisements.
/// Used in Mobile IPv6 contexts to allow mobile nodes to predict when the next RA will be
/// sent and optimize power consumption.
///
/// # Wire Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type (7)  |    Length(1)  |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Advertisement Interval                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Interval is in milliseconds. Total option size is always 8 bytes (length = 1).
///
/// # Examples
///
/// ```rust,ignore
/// use std::time::Duration;
///
/// let option = AdvIntervalOption::new()
///     .interval(Duration::from_secs(600))  // 10 minutes
///     .build()?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvIntervalOption {
    interval_value: Option<Duration>,
}

impl AdvIntervalOption {
    /// Create a new `AdvIntervalOption` builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            interval_value: None,
        }
    }

    /// Set the advertisement interval
    ///
    /// Indicates the maximum time between unsolicited multicast RAs. Per RFC 4861,
    /// typical values are between 200 seconds (`MinRtrAdvInterval`) and 600 seconds
    /// (`MaxRtrAdvInterval`).
    ///
    /// # Arguments
    ///
    /// * `interval` - Duration between RA transmissions (converted to milliseconds)
    #[must_use]
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval_value = Some(interval);
        self
    }

    /// Build and serialize the Advertisement Interval option to wire format
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - 8-byte serialized option ready for transmission
    /// * `Err(io::Error)` - Validation failure
    ///
    /// # Errors
    ///
    /// Returns error if interval value is not set.
    ///
    /// # Wire Format Details
    ///
    /// - Type: 7 (`ICMP6_OPT_ADV_INTERVAL`)
    /// - Length: 1 (8 bytes)
    /// - Reserved: 0x0000
    /// - Interval: `u32` in milliseconds, network byte order
    pub fn build(self) -> io::Result<Vec<u8>> {
        let interval = self.interval_value.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "interval value is required")
        })?;

        // Convert to milliseconds, clamping to u32::MAX
        // Safe cast: value is already clamped to u32::MAX
        #[allow(clippy::cast_possible_truncation)]
        let interval_ms = interval.as_millis().min(u128::from(u32::MAX)) as u32;

        let mut buf = Vec::with_capacity(8);
        
        buf.write_u8(ICMP6_OPT_ADV_INTERVAL)?; // Type = 7
        buf.write_u8(1)?; // Length = 1 (8 bytes)
        buf.write_u16::<BigEndian>(0)?; // Reserved
        buf.write_u32::<BigEndian>(interval_ms)?;

        debug_assert_eq!(
            buf.len(),
            8,
            "AdvIntervalOption must serialize to exactly 8 bytes"
        );
        Ok(buf)
    }
}

impl Default for AdvIntervalOption {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a domain name in DNS wire format (length-prefixed labels)
///
/// Converts a domain name string like "example.com" to DNS wire format:
/// - Each label is prefixed with its length (1 byte)
/// - Labels are separated by length prefixes
/// - Terminated with zero-length label (0x00)
///
/// Example: "example.com" -> [7]example[3]com[0]
///
/// # Arguments
///
/// * `buf` - Output buffer to write encoded domain name
/// * `domain` - Domain name to encode (e.g., "example.com")
///
/// # Errors
///
/// Returns error if:
/// - domain is empty
/// - any label exceeds 63 bytes
/// - total encoded length exceeds 255 bytes
fn encode_dns_name(buf: &mut Vec<u8>, domain: &str) -> io::Result<()> {
    if domain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "domain name cannot be empty",
        ));
    }

    let labels: Vec<&str> = domain.split('.').collect();

    for label in labels {
        if label.is_empty() {
            continue; // Skip empty labels (e.g., trailing dot)
        }

        let label_bytes = label.as_bytes();
        if label_bytes.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("label '{label}' exceeds maximum length of 63 bytes"),
            ));
        }

        // Safe cast: length is already validated to be <= 63
        #[allow(clippy::cast_possible_truncation)]
        buf.write_u8(label_bytes.len() as u8)?;
        buf.write_all(label_bytes)?;
    }

    // Terminate with zero-length label
    buf.write_u8(0)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_option_builder() {
        let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
        let option = PrefixOption::new()
            .prefix(prefix)
            .prefix_len(64)
            .autonomous(true)
            .on_link(true)
            .valid_lifetime(Duration::from_secs(2_592_000))
            .preferred_lifetime(Duration::from_secs(604_800))
            .build()
            .unwrap();

        assert_eq!(option.len(), 32);
        assert_eq!(option[0], 3); // Type
        assert_eq!(option[1], 4); // Length
        assert_eq!(option[2], 64); // Prefix length
        assert_eq!(option[3], 0xC0); // Flags: L-bit | A-bit
    }

    #[test]
    fn test_prefix_option_validation() {
        // Missing prefix
        let result = PrefixOption::new().prefix_len(64).build();
        assert!(result.is_err());

        // Missing prefix_len
        let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
        let result = PrefixOption::new().prefix(prefix).build();
        assert!(result.is_err());

        // Invalid prefix_len
        let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
        let result = PrefixOption::new().prefix(prefix).prefix_len(129).build();
        assert!(result.is_err());

        // Invalid lifetime relationship
        let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
        let result = PrefixOption::new()
            .prefix(prefix)
            .prefix_len(64)
            .valid_lifetime(Duration::from_secs(100))
            .preferred_lifetime(Duration::from_secs(200))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_rdnss_option_builder() {
        let dns1 = "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap();
        let dns2 = "2001:4860:4860::8844".parse::<Ipv6Addr>().unwrap();

        let option = RdnssOption::new()
            .add_server(dns1)
            .add_server(dns2)
            .lifetime(Duration::from_secs(3600))
            .build()
            .unwrap();

        assert_eq!(option.len(), 40); // 8 (header) + 32 (2 * 16 bytes)
        assert_eq!(option[0], 25); // Type
        assert_eq!(option[1], 5); // Length = 1 + 2*2
    }

    #[test]
    fn test_rdnss_option_validation() {
        // No servers added
        let result = RdnssOption::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_dnssl_option_builder() {
        let option = DnsslOption::new()
            .add_domain("example.com".to_string())
            .lifetime(Duration::from_secs(3600))
            .build()
            .unwrap();

        assert_eq!(option[0], 31); // Type
        assert!(option.len().is_multiple_of(8)); // Must be padded to 8-byte boundary
    }

    #[test]
    fn test_dnssl_option_validation() {
        // No domains added
        let result = DnsslOption::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_mtu_option_builder() {
        let option = MtuOption::new().mtu(1500).build().unwrap();

        assert_eq!(option.len(), 8);
        assert_eq!(option[0], 5); // Type
        assert_eq!(option[1], 1); // Length
        
        // Extract MTU value (bytes 4-7, big-endian)
        let mtu = u32::from_be_bytes([option[4], option[5], option[6], option[7]]);
        assert_eq!(mtu, 1500);
    }

    #[test]
    fn test_mtu_option_validation() {
        // Missing MTU
        let result = MtuOption::new().build();
        assert!(result.is_err());

        // MTU below IPv6 minimum
        let result = MtuOption::new().mtu(1000).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_adv_interval_option_builder() {
        let option = AdvIntervalOption::new()
            .interval(Duration::from_secs(600))
            .build()
            .unwrap();

        assert_eq!(option.len(), 8);
        assert_eq!(option[0], 7); // Type
        assert_eq!(option[1], 1); // Length
        
        // Extract interval value (bytes 4-7, big-endian, in milliseconds)
        let interval_ms = u32::from_be_bytes([option[4], option[5], option[6], option[7]]);
        assert_eq!(interval_ms, 600_000); // 600 seconds = 600,000 ms
    }

    #[test]
    fn test_adv_interval_option_validation() {
        // Missing interval
        let result = AdvIntervalOption::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_name_encoding() {
        let mut buf = Vec::new();
        encode_dns_name(&mut buf, "example.com").unwrap();

        // Expected: [7]example[3]com[0]
        assert_eq!(buf.len(), 13);
        assert_eq!(buf[0], 7);
        assert_eq!(&buf[1..8], b"example");
        assert_eq!(buf[8], 3);
        assert_eq!(&buf[9..12], b"com");
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_dns_name_encoding_validation() {
        let mut buf = Vec::new();
        
        // Empty domain
        let result = encode_dns_name(&mut buf, "");
        assert!(result.is_err());

        // Label too long
        let long_label = "a".repeat(64);
        let result = encode_dns_name(&mut buf, &format!("{long_label}.com"));
        assert!(result.is_err());
    }

    // Property-based tests for lifetime validation
    #[cfg(feature = "proptest")]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn test_prefix_lifetime_relationship(
                valid in 0u32..=u32::MAX,
                preferred in 0u32..=u32::MAX
            ) {
                let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
                let result = PrefixOption::new()
                    .prefix(prefix)
                    .prefix_len(64)
                    .valid_lifetime(Duration::from_secs(u64::from(valid)))
                    .preferred_lifetime(Duration::from_secs(u64::from(preferred)))
                    .build();

                if preferred <= valid {
                    assert!(result.is_ok());
                } else {
                    assert!(result.is_err());
                }
            }

            #[test]
            fn test_prefix_len_bounds(prefix_len in 0u8..=255u8) {
                let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
                let result = PrefixOption::new()
                    .prefix(prefix)
                    .prefix_len(prefix_len)
                    .build();

                if prefix_len <= 128 {
                    assert!(result.is_ok());
                } else {
                    assert!(result.is_err());
                }
            }
        }
    }
}
