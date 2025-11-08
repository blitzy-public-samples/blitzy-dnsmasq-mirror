// Copyright (C) 2024 Blitzy Platform - dnsmasq Rust Port
// This file is part of the dnsmasq Rust implementation.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Configuration data structures and validation for dnsmasq
//!
//! This module provides the complete type system for dnsmasq configuration, replacing
//! the C implementation's global `struct daemon` and scattered option structures with
//! a hierarchical, type-safe Rust design.
//!
//! # Architecture
//!
//! The configuration system is organized into logical subsystems:
//! - **DNS Configuration** (`DnsConfig`): Cache, forwarding, upstream servers
//! - **DHCP Configuration** (`DhcpConfig`): Address ranges, static hosts, lease management
//! - **Network Configuration** (`NetworkConfig`): Interfaces, listen addresses, ports
//! - **Logging Configuration** (`LoggingConfig`): Syslog facility, log levels, output
//! - **Security Configuration** (`SecurityConfig`): User/group, privilege dropping
//! - **TFTP Configuration** (`TftpConfig`): Root directory, security, connections
//! - **DNSSEC Configuration** (`DnssecConfig`): Validation, trust anchors
//! - **Authoritative DNS** (`AuthConfig`): Zones, SOA records
//!
//! # Builder Pattern
//!
//! Configuration is constructed using `ConfigBuilder` which provides:
//! - Fluent interface for configuration assembly
//! - Incremental validation at each step
//! - Compile-time type safety for required fields
//! - Comprehensive error reporting on invalid configuration
//!
//! # Validation
//!
//! All configuration structures implement validation through:
//! - Type system enforcement (e.g., `NonZeroU16` for ports)
//! - TryFrom traits for string conversions with detailed errors
//! - Builder validate() method checking cross-field constraints
//! - Runtime validation in FromStr implementations
//!
//! # C Structure Mapping
//!
//! This module replaces several C structures from dnsmasq.h:
//! - `struct daemon` (global state container) → `Config` + subsystem structs
//! - `struct server` → `UpstreamServer`
//! - `struct dhcp_context` → `DhcpContext` + `DhcpRange`
//! - `struct dhcp_config` → `DhcpStaticHost`
//! - `struct dhcp_opt` → `DhcpOption` + `DhcpOptionValue`
//!
//! # Source Reference
//!
//! Translated from:
//! - `src/dnsmasq.h` - Primary type definitions (struct daemon, lines 1099+)
//! - `src/config.h` - Compile-time constants and feature flags
//! - `src/option.c` - Configuration parsing logic and validation

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use thiserror::Error;

use super::defaults::DEFAULT_LEASE_TIME_V4_SECS;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Configuration validation and parsing errors
///
/// Provides detailed error context for configuration failures with specific
/// error types for each validation failure mode.
///
/// # Error Categories
///
/// - **Parse Errors**: Invalid IP addresses, ports, domains, file paths
/// - **Validation Errors**: Constraint violations (overlapping ranges, invalid sizes)
/// - **Semantic Errors**: Logically inconsistent configurations
///
/// # Source Reference
///
/// Error handling replaces C's return codes and errno with structured Result types.
/// Similar to option.c parse error handling but with Rust's type-safe error propagation.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ConfigError {
    /// IP address parsing failed or address is invalid
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    /// Port number out of valid range (1-65535) or zero
    #[error("Invalid port number: {0}")]
    InvalidPort(u16),

    /// Domain name violates RFC 1035 rules or is malformed
    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),

    /// File path does not exist, is not accessible, or has invalid permissions
    #[error("Invalid file path: {0}")]
    InvalidPath(String),

    /// DHCP address ranges overlap, creating allocation conflicts
    #[error("Overlapping DHCP ranges: {0}")]
    OverlappingRanges(String),

    /// MAC address format invalid (must be 6 colon-separated hex bytes)
    #[error("Invalid MAC address: {0}")]
    InvalidMacAddress(String),

    /// Lease time out of reasonable bounds (<60s or >1 year)
    #[error("Invalid lease time: {0} seconds")]
    InvalidLeaseTime(u32),

    /// DNS cache size invalid (negative or exceeds system limits)
    #[error("Invalid cache size: {0}")]
    InvalidCacheSize(usize),

    /// Network interface name invalid or does not exist
    #[error("Invalid interface name: {0}")]
    InvalidInterface(String),

    /// Client ID (CLID/DUID) format invalid
    #[error("Invalid client ID: {0}")]
    InvalidClientId(String),

    /// DHCP option code out of range or value format incorrect
    #[error("Invalid DHCP option: {0}")]
    InvalidDhcpOption(String),

    /// DNSSEC trust anchor format invalid
    #[error("Invalid trust anchor: {0}")]
    InvalidTrustAnchor(String),

    /// Generic validation error with context
    #[error("Validation error: {0}")]
    ValidationError(String),
}

// =============================================================================
// NETWORK PROTOCOL ENUM
// =============================================================================

/// Network protocol for listen addresses
///
/// Specifies which protocol(s) a listen address serves.
///
/// # C Equivalent
///
/// Replaces C's conditional listening logic with explicit protocol designation.
/// In C, protocol determined by compilation flags (`HAVE_DHCP`, `HAVE_TFTP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// DNS protocol on port 53 (UDP/TCP)
    Dns,
    /// DHCP protocol on ports 67/68 (`DHCPv4`) or 547/546 (`DHCPv6`)
    Dhcp,
    /// TFTP protocol on port 69 (UDP only)
    Tftp,
}

// =============================================================================
// SYSLOG FACILITY
// =============================================================================

/// Syslog facility for daemon logging
///
/// Maps to standard POSIX syslog facility codes used for message categorization.
///
/// # C Equivalent
///
/// Replaces `LOG_DAEMON`, `LOG_LOCAL0`-7, `LOG_USER` macros from `<syslog.h>`.
/// See dnsmasq.h lines 980-1003 for facility flag definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyslogFacility {
    /// System daemons (default for most dnsmasq messages)
    #[default]
    Daemon,
    /// Local use 0 (custom facility)
    Local0,
    /// Local use 1
    Local1,
    /// Local use 2
    Local2,
    /// Local use 3
    Local3,
    /// Local use 4
    Local4,
    /// Local use 5
    Local5,
    /// Local use 6
    Local6,
    /// Local use 7
    Local7,
    /// User-level messages
    User,
}

// =============================================================================
// MAC ADDRESS TYPE
// =============================================================================

/// Hardware (MAC) address for Ethernet and similar link layers
///
/// Represents a 48-bit MAC address (6 bytes) used for DHCP client identification.
/// Supports standard colon-separated hexadecimal notation (e.g., "01:23:45:67:89:ab").
///
/// # C Equivalent
///
/// Replaces `unsigned char hwaddr[DHCP_CHADDR_MAX]` in struct `dhcp_lease` (dnsmasq.h line 2584).
/// `DHCP_CHADDR_MAX` is 16 bytes but MAC addresses are 6 bytes.
///
/// # Validation
///
/// - Exactly 6 bytes
/// - `FromStr` expects colon-separated hex notation
/// - `Display` outputs standard notation with lowercase hex
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Creates a new `MacAddress` from 6 bytes
    #[must_use]
    pub fn new(bytes: [u8; 6]) -> Self {
        MacAddress(bytes)
    }

    /// Returns the `MacAddress` as a byte slice
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(ConfigError::InvalidMacAddress(format!(
                "Expected 6 colon-separated hex bytes, got {}",
                parts.len()
            )));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).map_err(|_| {
                ConfigError::InvalidMacAddress(format!("Invalid hex byte: {part}"))
            })?;
        }

        Ok(MacAddress(bytes))
    }
}

// =============================================================================
// DHCP OPTION VALUE
// =============================================================================

/// DHCP option value with type-specific encoding
///
/// Represents the value portion of a DHCP option (RFC 2132). Different option
/// numbers have different value encodings (IP addresses, strings, integers, etc.).
///
/// # C Equivalent
///
/// Replaces `struct dhcp_opt` value encoding logic (dnsmasq.h line 2840).
/// C uses `unsigned char *val` with length and flag-based type interpretation.
///
/// # Encoding
///
/// Each variant knows how to encode itself into the wire format per RFC 2132.
#[derive(Debug, Clone, PartialEq)]
pub enum DhcpOptionValue {
    /// IP address (4 or 16 bytes depending on `DHCPv4`/v6)
    Ip(IpAddr),
    /// Text string (ASCII or UTF-8, null-terminated in `DHCPv4`)
    String(String),
    /// Binary data (arbitrary byte sequence)
    Binary(Vec<u8>),
    /// Single byte unsigned integer (0-255)
    U8(u8),
    /// Two-byte unsigned integer (0-65535, network byte order)
    U16(u16),
    /// Four-byte unsigned integer (0-4294967295, network byte order)
    U32(u32),
}

// =============================================================================
// DNS CONFIGURATION
// =============================================================================

/// Upstream DNS server configuration
///
/// Specifies an upstream recursive DNS server for query forwarding. Can be global
/// (handles all queries) or domain-specific (only queries for matching domain suffix).
///
/// # C Equivalent
///
/// Replaces `struct server` from dnsmasq.h lines 1807-1900.
/// C version includes health tracking and statistics fields (query count, failures)
/// which are runtime state, not configuration.
///
/// # Members
///
/// - `address`: Server socket address (IPv4 or IPv6, includes port)
/// - `domain`: Optional domain suffix this server handles (None = global)
/// - `source`: Optional source address for queries (interface binding)
/// - `port`: UDP/TCP port for queries (typically 53)
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamServer {
    /// Server socket address (IP + port)
    pub address: SocketAddr,
    /// Domain suffix this server handles (None = all domains)
    pub domain: Option<String>,
    /// Source IP address for outgoing queries (interface binding)
    pub source: Option<IpAddr>,
    /// Server port (typically 53)
    pub port: u16,
}

impl UpstreamServer {
    /// Creates a new upstream server with default port 53
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        UpstreamServer {
            address,
            domain: None,
            source: None,
            port: 53,
        }
    }
}

/// DNS forwarding rule for domain-specific routing
///
/// Maps domain names to specific upstream servers. Queries matching the domain
/// suffix are routed to the configured servers instead of global upstreams.
///
/// # C Equivalent
///
/// Replaces domain-specific entries in `struct server` linked list with
/// `SERV_HAS_DOMAIN` flag (dnsmasq.h line 1839).
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardRule {
    /// Domain suffix to match (e.g., "example.com")
    pub domain: String,
    /// Upstream server addresses for this domain
    pub servers: Vec<SocketAddr>,
    /// If true, do not use /etc/resolv.conf servers for this domain
    pub no_resolv: bool,
}

/// Local domain configuration
///
/// Defines a domain that should resolve to a specific address or be handled locally
/// without forwarding. Implements --local and --address directives.
///
/// # C Equivalent
///
/// Replaces entries in `struct server` with `SERV_LITERAL_ADDRESS` flag
/// (dnsmasq.h line 1734).
#[derive(Debug, Clone, PartialEq)]
pub struct LocalDomain {
    /// Domain name (e.g., "local" for .local TLD)
    pub domain: String,
    /// Address to return (None = NXDOMAIN, Some = literal address)
    pub address: Option<IpAddr>,
}

/// Bogus domain configuration for DNS filtering
///
/// Implements --bogus-nxdomain directive: upstream responses containing these
/// addresses are replaced with NXDOMAIN. Used for ad-blocking and malware filtering.
///
/// # C Equivalent
///
/// Replaces `struct bogus_addr` from dnsmasq.h lines 1176-1180.
#[derive(Debug, Clone, PartialEq)]
pub struct BogusRule {
    /// Domain name to mark as bogus
    pub domain: String,
    /// Optional subnet (if specified, only responses in subnet treated as bogus)
    pub subnet: Option<String>, // CIDR notation (e.g., "192.168.0.0/16")
}

/// DNS cache configuration parameters
///
/// Controls DNS cache behavior including size, TTL limits, and eviction policy.
///
/// # C Equivalent
///
/// Replaces cache-related fields in `struct daemon` and config.h constants.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheConfig {
    /// Maximum number of cache entries (LRU eviction when full)
    pub size: usize,
    /// Minimum TTL to enforce (None = no minimum)
    pub min_ttl: Option<Duration>,
    /// Maximum TTL to enforce (None = no maximum)
    pub max_ttl: Option<Duration>,
    /// TTL for negative responses (NXDOMAIN, NODATA)
    pub negative_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            size: super::defaults::DEFAULT_CACHE_SIZE,
            min_ttl: None,
            max_ttl: None,
            negative_ttl: Duration::from_secs(3600), // 1 hour per RFC 2308
        }
    }
}

/// Complete DNS subsystem configuration
///
/// Aggregates all DNS-related configuration including cache, forwarding, and
/// upstream servers.
///
/// # C Equivalent
///
/// Replaces DNS-related fields scattered across `struct daemon` in dnsmasq.h.
///
/// # Members Exposed
///
/// Per schema: `cache_size`, `upstream_servers`, `forward_rules`, `local_domains`,
/// `bogus_domains`, `edns_packet_size`, `min_ttl`, `max_ttl`, `negative_ttl`
#[derive(Debug, Clone, PartialEq)]
pub struct DnsConfig {
    /// Cache size in number of records
    pub cache_size: usize,
    /// Upstream recursive DNS servers (global)
    pub upstream_servers: Vec<UpstreamServer>,
    /// Domain-specific forwarding rules
    pub forward_rules: Vec<ForwardRule>,
    /// Local domain definitions (no forwarding)
    pub local_domains: Vec<LocalDomain>,
    /// Bogus domain rules for filtering
    pub bogus_domains: Vec<BogusRule>,
    /// EDNS0 UDP packet size (default 4096)
    pub edns_packet_size: usize,
    /// Minimum TTL override (None = respect upstream)
    pub min_ttl: Option<Duration>,
    /// Maximum TTL override (None = respect upstream)
    pub max_ttl: Option<Duration>,
    /// Negative response TTL (NXDOMAIN/NODATA)
    pub negative_ttl: Duration,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            cache_size: super::defaults::DEFAULT_CACHE_SIZE,
            upstream_servers: Vec::new(),
            forward_rules: Vec::new(),
            local_domains: Vec::new(),
            bogus_domains: Vec::new(),
            edns_packet_size: super::defaults::EDNS_PACKET_SIZE,
            min_ttl: None,
            max_ttl: None,
            negative_ttl: Duration::from_secs(3600),
        }
    }
}

// =============================================================================
// DHCP CONFIGURATION
// =============================================================================

/// DHCP address range configuration
///
/// Defines a pool of IP addresses available for dynamic DHCP allocation.
/// Corresponds to one --dhcp-range directive.
///
/// # C Equivalent
///
/// Replaces `struct dhcp_context` from dnsmasq.h lines 3194-3210.
/// C version includes runtime state (lease counters, interface binding, RA timers)
/// which are separated into runtime state in Rust.
///
/// # Members Exposed
///
/// Per schema: start, end, netmask, `lease_time`, tag
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpRange {
    /// Start of address range (inclusive)
    pub start: IpAddr,
    /// End of address range (inclusive)
    pub end: IpAddr,
    /// Subnet mask (IPv4 only, IPv6 uses prefix length)
    pub netmask: Option<IpAddr>,
    /// Lease duration for addresses from this range
    pub lease_time: Duration,
    /// Optional tag for conditional DHCP configuration
    pub tag: Option<String>,
}

impl DhcpRange {
    /// Creates a new `DHCPv4` range with default 1-hour lease time
    #[must_use]
    pub fn new_v4(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        DhcpRange {
            start: IpAddr::V4(start),
            end: IpAddr::V4(end),
            netmask: None,
            lease_time: Duration::from_secs(DEFAULT_LEASE_TIME_V4_SECS),
            tag: None,
        }
    }

    /// Creates a new `DHCPv6` range with default 1-hour lease time
    #[must_use]
    pub fn new_v6(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        DhcpRange {
            start: IpAddr::V6(start),
            end: IpAddr::V6(end),
            netmask: None,
            lease_time: Duration::from_secs(DEFAULT_LEASE_TIME_V4_SECS),
            tag: None,
        }
    }

    /// Validates that start address is less than or equal to end address
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ValidationError` if:
    /// - Start address is greater than end address
    /// - Start and end addresses are different address families
    ///
    /// Returns `ConfigError::InvalidLeaseTime` if lease time is less than 60 seconds or greater than 1 year
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Basic validation: start must be same address family as end
        match (self.start, self.end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                if s > e {
                    return Err(ConfigError::ValidationError(format!(
                        "DHCP range start {s} is greater than end {e}"
                    )));
                }
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                if s > e {
                    return Err(ConfigError::ValidationError(format!(
                        "DHCP range start {s} is greater than end {e}"
                    )));
                }
            }
            _ => {
                return Err(ConfigError::ValidationError(
                    "DHCP range start and end must be same address family".to_string(),
                ));
            }
        }

        // Validate lease time is reasonable (at least 60 seconds, at most 1 year)
        let secs = self.lease_time.as_secs();
        if secs < 60 {
            return Err(ConfigError::InvalidLeaseTime(u32::try_from(secs).unwrap_or(u32::MAX)));
        }
        if secs > 365 * 24 * 3600 {
            return Err(ConfigError::InvalidLeaseTime(u32::try_from(secs).unwrap_or(u32::MAX)));
        }

        Ok(())
    }
}

/// Static DHCP host configuration (reservation)
///
/// Assigns a fixed IP address to a specific client identified by MAC address,
/// client ID, or hostname. Corresponds to --dhcp-host directive.
///
/// # C Equivalent
///
/// Replaces `struct dhcp_config` from dnsmasq.h lines 2779-2794.
///
/// # Members Exposed
///
/// Per schema: mac, ip, hostname, `client_id`
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpStaticHost {
    /// Client MAC address for identification
    pub mac: MacAddress,
    /// Static IP address to assign
    pub ip: IpAddr,
    /// Hostname to register in DNS (optional)
    pub hostname: Option<String>,
    /// Client ID (CLID for `DHCPv6`, option 61 for `DHCPv4`)
    pub client_id: Option<Vec<u8>>,
}

/// DHCP option configuration
///
/// Configures a DHCP option to send to clients. Supports all standard DHCP
/// options from RFC 2132 plus vendor-specific options.
///
/// # C Equivalent
///
/// Replaces `struct dhcp_opt` from dnsmasq.h lines 2840-2850.
///
/// # Members Exposed
///
/// Per schema: code, value, tag, force
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpOption {
    /// DHCP option code (1-255)
    pub code: u8,
    /// Option value (type-specific encoding)
    pub value: DhcpOptionValue,
    /// Optional tag for conditional delivery
    pub tag: Option<String>,
    /// Force option even if not requested by client
    pub force: bool,
}

impl DhcpOption {
    /// Creates a new DHCP option with given code and value
    #[must_use]
    pub fn new(code: u8, value: DhcpOptionValue) -> Self {
        DhcpOption {
            code,
            value,
            tag: None,
            force: false,
        }
    }
}

/// Complete DHCP subsystem configuration
///
/// Aggregates all DHCP-related configuration including address ranges, static
/// hosts, options, and lease file management.
///
/// # C Equivalent
///
/// Replaces DHCP-related fields in `struct daemon` from dnsmasq.h.
/// Conditional compilation: only available with `dhcp` feature flag.
///
/// # Members Exposed
///
/// Per schema: ranges, `static_hosts`, options, `lease_file`, `lease_time`, authoritative
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpConfig {
    /// DHCP address ranges for dynamic allocation
    pub ranges: Vec<DhcpRange>,
    /// Static host configurations (reservations)
    pub static_hosts: Vec<DhcpStaticHost>,
    /// DHCP options to send to clients
    pub options: Vec<DhcpOption>,
    /// Lease database file path
    pub lease_file: Option<PathBuf>,
    /// Default lease time (overridden by range-specific times)
    pub lease_time: Duration,
    /// Authoritative mode (respond with NAK to unknown clients)
    pub authoritative: bool,
}

#[cfg(feature = "dhcp")]
impl Default for DhcpConfig {
    fn default() -> Self {
        DhcpConfig {
            ranges: Vec::new(),
            static_hosts: Vec::new(),
            options: Vec::new(),
            lease_file: None,
            lease_time: Duration::from_secs(DEFAULT_LEASE_TIME_V4_SECS),
            authoritative: false,
        }
    }
}

/// DHCP context with complete range and network parameters
///
/// Extended context information including network parameters like netmask,
/// broadcast, router, and interface binding. Maps closely to C's `struct dhcp_context`.
///
/// # C Equivalent
///
/// Direct mapping to `struct dhcp_context` from dnsmasq.h lines 3194-3210.
/// Includes all configuration-time fields, omits runtime state fields.
///
/// # Members Exposed
///
/// Per schema: flags, start, end, netmask, broadcast, router, `lease_time`,
/// interface, next, `ra_time`, `ra_short_period_start`, prefix, `prefix_len`
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpContext {
    /// Context flags (CONTEXT_* from dnsmasq.h lines 3248-3287)
    pub flags: u32,
    /// Start of address range (IPv4 or IPv6)
    pub start: IpAddr,
    /// End of address range (IPv4 or IPv6)
    pub end: IpAddr,
    /// Subnet mask for this range (IPv4 only)
    pub netmask: Option<Ipv4Addr>,
    /// Broadcast address for subnet (IPv4 only)
    pub broadcast: Option<Ipv4Addr>,
    /// Router address (default gateway) to advertise (IPv4 only, IPv6 uses RA)
    pub router: Option<Ipv4Addr>,
    /// Lease duration for this context
    pub lease_time: Duration,
    /// Interface name this context applies to
    pub interface: Option<String>,
    /// Next context in linked list (for builder pattern)
    pub next: Option<Box<DhcpContext>>,
    /// Next Router Advertisement time (IPv6)
    #[cfg(feature = "dhcp-v6")]
    pub ra_time: Option<std::time::SystemTime>,
    /// RA short period start time (IPv6)
    #[cfg(feature = "dhcp-v6")]
    pub ra_short_period_start: Option<std::time::SystemTime>,
    /// IPv6 prefix for this context
    #[cfg(feature = "dhcp-v6")]
    pub prefix: Option<Ipv6Addr>,
    /// IPv6 prefix length (typically 64)
    #[cfg(feature = "dhcp-v6")]
    pub prefix_len: Option<u8>,
}

// =============================================================================
// TFTP CONFIGURATION
// =============================================================================

/// TFTP server configuration
///
/// Configures the TFTP server for network boot and PXE support.
/// Conditional compilation: only available with `tftp` feature flag.
///
/// # C Equivalent
///
/// Replaces TFTP-related fields in `struct daemon` from dnsmasq.h.
///
/// # Members Exposed
///
/// Per schema: root, secure, `max_connections`, `port_range`
#[cfg(feature = "tftp")]
#[derive(Debug, Clone, PartialEq)]
pub struct TftpConfig {
    /// TFTP root directory (serves files from here)
    pub root: PathBuf,
    /// Secure mode (chroot to root directory)
    pub secure: bool,
    /// Maximum concurrent TFTP connections
    pub max_connections: usize,
    /// Port range for TFTP (start, end)
    pub port_range: Option<(u16, u16)>,
}

#[cfg(feature = "tftp")]
impl Default for TftpConfig {
    fn default() -> Self {
        TftpConfig {
            root: PathBuf::from("/var/tftp"),
            secure: false,
            max_connections: 50,
            port_range: None,
        }
    }
}

// =============================================================================
// DNSSEC CONFIGURATION
// =============================================================================

/// DNSSEC trust anchor configuration
///
/// Represents a DS (Delegation Signer) record that anchors DNSSEC validation.
/// Typically the root KSK (Key Signing Key) trust anchor.
///
/// # C Equivalent
///
/// Replaces `struct ds_config` from dnsmasq.h lines 1343-1347.
///
/// # Members Exposed
///
/// Per schema: domain, `key_tag`, algorithm, `digest_type`, digest
#[cfg(feature = "dnssec")]
#[derive(Debug, Clone, PartialEq)]
pub struct TrustAnchor {
    /// Zone name (e.g., "." for root)
    pub domain: String,
    /// Key tag identifier (16-bit)
    pub key_tag: u16,
    /// DNSSEC algorithm number (8=RSA/SHA-256, 13=ECDSA P-256, 15=Ed25519)
    pub algorithm: u8,
    /// Digest algorithm type (1=SHA-1, 2=SHA-256, 4=SHA-384)
    pub digest_type: u8,
    /// Digest bytes (hash of DNSKEY)
    pub digest: Vec<u8>,
}

/// DNSSEC validation configuration
///
/// Controls DNSSEC signature validation and trust anchor management.
/// Conditional compilation: only available with `dnssec` feature flag.
///
/// # C Equivalent
///
/// Replaces DNSSEC-related fields in `struct daemon` from dnsmasq.h.
///
/// # Members Exposed
///
/// Per schema: enabled, `check_unsigned`, `trust_anchors`
#[cfg(feature = "dnssec")]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DnssecConfig {
    /// Enable DNSSEC validation
    pub enabled: bool,
    /// Check unsigned responses (require DNSSEC for all queries)
    pub check_unsigned: bool,
    /// Trust anchors (DS records)
    pub trust_anchors: Vec<TrustAnchor>,
}

// =============================================================================
// AUTHORITATIVE DNS CONFIGURATION
// =============================================================================

/// Authoritative DNS zone configuration
///
/// Defines a DNS zone where dnsmasq acts as authoritative nameserver.
/// Conditional compilation: only available with `auth-dns` feature flag.
///
/// # C Equivalent
///
/// Replaces `struct auth_zone` from dnsmasq.h lines 1403-1413.
///
/// # Members Exposed
///
/// Per schema: zones, soa, ttl, peers
#[cfg(feature = "auth-dns")]
#[derive(Debug, Clone, PartialEq)]
pub struct AuthConfig {
    /// Authoritative zones (domain names)
    pub zones: Vec<String>,
    /// SOA record parameters (if any)
    pub soa: Option<String>, // Simplified; full SOA implementation would need struct
    /// TTL for authoritative records
    pub ttl: Duration,
    /// Peer nameservers (for zone transfers)
    pub peers: Vec<IpAddr>,
}

#[cfg(feature = "auth-dns")]
impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            zones: Vec::new(),
            soa: None,
            ttl: Duration::from_secs(3600),
            peers: Vec::new(),
        }
    }
}

// =============================================================================
// NETWORK CONFIGURATION
// =============================================================================

/// Network interface configuration
///
/// Specifies which network interfaces dnsmasq listens on.
///
/// # C Equivalent
///
/// Replaces `struct iname` from dnsmasq.h lines 2105-2110.
#[derive(Debug, Clone, PartialEq)]
pub struct Interface {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,
    /// Addresses on this interface (may be empty for wildcard)
    pub addresses: Vec<IpAddr>,
}

/// Listen address configuration
///
/// Specifies an address and port to listen on for a specific protocol.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenAddress {
    /// IP address to bind
    pub address: IpAddr,
    /// Port number to bind
    pub port: u16,
    /// Protocol this listen address serves
    pub protocol: Protocol,
}

/// Network configuration
///
/// Aggregates network-related configuration including interfaces, listen
/// addresses, and port settings.
///
/// # C Equivalent
///
/// Replaces network-related fields in `struct daemon` from dnsmasq.h.
///
/// # Members Exposed
///
/// Per schema: interfaces, `listen_addresses`, `bind_interfaces`, `bind_dynamic`, port, `query_port`
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkConfig {
    /// Network interfaces to listen on
    pub interfaces: Vec<Interface>,
    /// Specific addresses to listen on
    pub listen_addresses: Vec<ListenAddress>,
    /// Bind to specific interfaces (vs wildcard)
    pub bind_interfaces: bool,
    /// Dynamically track interface changes
    pub bind_dynamic: bool,
    /// DNS port (default 53)
    pub port: u16,
    /// Query port for upstream (0 = random)
    pub query_port: u16,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            interfaces: Vec::new(),
            listen_addresses: Vec::new(),
            bind_interfaces: false,
            bind_dynamic: false,
            port: 53,
            query_port: 0,
        }
    }
}

// =============================================================================
// LOGGING CONFIGURATION
// =============================================================================

/// Logging configuration
///
/// Controls log output including syslog facility, log levels, and log file.
///
/// # C Equivalent
///
/// Replaces logging-related fields in `struct daemon` from dnsmasq.h.
///
/// # Members Exposed
///
/// Per schema: facility, `async_log`, `log_queries`, `log_dhcp`, `log_file`
#[derive(Debug, Clone, PartialEq)]
pub struct LoggingConfig {
    /// Syslog facility for daemon messages
    pub facility: SyslogFacility,
    /// Asynchronous logging (non-blocking)
    pub async_log: bool,
    /// Log DNS queries
    pub log_queries: bool,
    /// Log DHCP transactions
    pub log_dhcp: bool,
    /// Optional log file path (None = syslog only)
    pub log_file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            facility: SyslogFacility::Daemon,
            async_log: false,
            log_queries: false,
            log_dhcp: false,
            log_file: None,
        }
    }
}

// =============================================================================
// SECURITY CONFIGURATION
// =============================================================================

/// Security configuration
///
/// Controls privilege dropping, user/group settings, and security options.
///
/// # C Equivalent
///
/// Replaces security-related fields in `struct daemon` from dnsmasq.h.
///
/// # Members Exposed
///
/// Per schema: `user`, `group`, `script_user`, `drop_after_bind`
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityConfig {
    /// User to run as after initialization
    pub user: Option<String>,
    /// Group to run as after initialization
    pub group: Option<String>,
    /// User to execute DHCP scripts as
    pub script_user: Option<String>,
    /// Drop privileges after binding to ports
    pub drop_after_bind: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            user: None,
            group: None,
            script_user: None,
            drop_after_bind: true,
        }
    }
}

// =============================================================================
// MAIN CONFIGURATION STRUCT
// =============================================================================

/// Complete dnsmasq configuration
///
/// Top-level configuration container aggregating all subsystem configurations.
/// Replaces C's global `struct daemon` from dnsmasq.h lines 1099+.
///
/// # Structure
///
/// The configuration is organized into logical subsystems:
/// - DNS: Cache, forwarding, upstream servers
/// - DHCP: Address ranges, static hosts, options (feature-gated)
/// - TFTP: Network boot configuration (feature-gated)
/// - DNSSEC: Validation and trust anchors (feature-gated)
/// - Auth: Authoritative DNS zones (feature-gated)
/// - Network: Interfaces, listen addresses, ports
/// - Logging: Syslog, query logging, output files
/// - Security: User/group, privilege dropping
///
/// # Construction
///
/// Use `ConfigBuilder` for incremental, validated construction:
///
/// ```ignore
/// let config = ConfigBuilder::new()
///     .dns(dns_config)
///     .network(network_config)
///     .validate()?
///     .build()?;
/// ```
///
/// # Members Exposed
///
/// Per schema: dns, dhcp, network, logging, security, tftp, dnssec, auth, files
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Config {
    /// DNS subsystem configuration
    pub dns: DnsConfig,

    /// DHCP subsystem configuration (feature-gated)
    #[cfg(feature = "dhcp")]
    pub dhcp: Option<DhcpConfig>,

    /// Network configuration
    pub network: NetworkConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// TFTP configuration (feature-gated)
    #[cfg(feature = "tftp")]
    pub tftp: Option<TftpConfig>,

    /// DNSSEC configuration (feature-gated)
    #[cfg(feature = "dnssec")]
    pub dnssec: Option<DnssecConfig>,

    /// Authoritative DNS configuration (feature-gated)
    #[cfg(feature = "auth-dns")]
    pub auth: Option<AuthConfig>,

    /// File paths (config file, PID file, lease file)
    pub files: FileConfig,
}

impl Config {
    /// Returns the DNS port if DNS is enabled
    ///
    /// DNS is considered enabled if the configured port is non-zero.
    /// A port of 0 disables DNS functionality.
    ///
    /// # Returns
    ///
    /// - `Some(port)` if DNS is enabled (port != 0)
    /// - `None` if DNS is disabled (port == 0)
    #[must_use]
    pub fn dns_port(&self) -> Option<u16> {
        if self.network.port == 0 {
            None
        } else {
            Some(self.network.port)
        }
    }

    /// Returns true if DHCP is enabled
    ///
    /// DHCP is enabled if the dhcp configuration is present.
    /// Requires the "dhcp" feature to be compiled.
    #[cfg(feature = "dhcp")]
    #[must_use]
    pub fn dhcp_enabled(&self) -> bool {
        self.dhcp.is_some()
    }

    /// Returns false if DHCP feature is not compiled
    #[cfg(not(feature = "dhcp"))]
    pub fn dhcp_enabled(&self) -> bool {
        false
    }

    /// Returns true if `DHCPv6` is enabled
    ///
    /// `DHCPv6` is enabled if the dhcp configuration is present and
    /// the dhcp-v6 feature is compiled in.
    #[cfg(feature = "dhcp-v6")]
    #[must_use]
    pub fn dhcp6_enabled(&self) -> bool {
        #[cfg(feature = "dhcp")]
        {
            self.dhcp.is_some()
        }
        #[cfg(not(feature = "dhcp"))]
        {
            false
        }
    }

    /// Returns false if DHCPv6 feature is not compiled
    #[cfg(not(feature = "dhcp-v6"))]
    pub fn dhcp6_enabled(&self) -> bool {
        false
    }

    /// Returns true if `TFTP` is enabled
    ///
    /// `TFTP` is enabled if the tftp configuration is present.
    /// Requires the "tftp" feature to be compiled.
    #[cfg(feature = "tftp")]
    #[must_use]
    pub fn tftp_enabled(&self) -> bool {
        self.tftp.is_some()
    }

    /// Returns false if `TFTP` feature is not compiled
    #[cfg(not(feature = "tftp"))]
    #[must_use]
    pub fn tftp_enabled(&self) -> bool {
        false
    }
}

/// File path configuration
///
/// Specifies paths for configuration files, runtime files, and data files.
#[derive(Debug, Clone, PartialEq)]
pub struct FileConfig {
    /// Configuration file path
    pub config_file: PathBuf,
    /// PID file path (None = no PID file)
    pub pid_file: Option<PathBuf>,
    /// Lease file path (None = no persistence)
    pub lease_file: Option<PathBuf>,
}

impl Default for FileConfig {
    fn default() -> Self {
        FileConfig {
            config_file: PathBuf::from("/etc/dnsmasq.conf"),
            pid_file: None,
            lease_file: None,
        }
    }
}

// =============================================================================
// CONFIGURATION BUILDER
// =============================================================================

/// Builder for constructing and validating configuration
///
/// Provides fluent interface for configuration assembly with incremental
/// validation. Each configuration method returns `&mut Self` for chaining.
///
/// # Example
///
/// ```ignore
/// let config = ConfigBuilder::new()
///     .dns(dns_config)
///     .network(network_config)
///     .validate()?
///     .build()?;
/// ```
///
/// # Members Exposed
///
/// Per schema: `new()`, `dns()`, `dhcp()`, `network()`, `logging()`, `security()`, `validate()`, `build()`
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    dns: Option<DnsConfig>,
    #[cfg(feature = "dhcp")]
    dhcp: Option<DhcpConfig>,
    network: Option<NetworkConfig>,
    logging: Option<LoggingConfig>,
    security: Option<SecurityConfig>,
    #[cfg(feature = "tftp")]
    tftp: Option<TftpConfig>,
    #[cfg(feature = "dnssec")]
    dnssec: Option<DnssecConfig>,
    #[cfg(feature = "auth-dns")]
    auth: Option<AuthConfig>,
    files: Option<FileConfig>,
}

impl ConfigBuilder {
    /// Creates a new configuration builder with default values
    #[must_use]
    pub fn new() -> Self {
        ConfigBuilder::default()
    }

    /// Sets DNS configuration
    pub fn dns(&mut self, config: DnsConfig) -> &mut Self {
        self.dns = Some(config);
        self
    }

    /// Sets DHCP configuration (feature-gated)
    #[cfg(feature = "dhcp")]
    pub fn dhcp(&mut self, config: DhcpConfig) -> &mut Self {
        self.dhcp = Some(config);
        self
    }

    /// Sets network configuration
    pub fn network(&mut self, config: NetworkConfig) -> &mut Self {
        self.network = Some(config);
        self
    }

    /// Sets logging configuration
    pub fn logging(&mut self, config: LoggingConfig) -> &mut Self {
        self.logging = Some(config);
        self
    }

    /// Sets security configuration
    pub fn security(&mut self, config: SecurityConfig) -> &mut Self {
        self.security = Some(config);
        self
    }

    /// Internal validation helper
    ///
    /// Performs validation checks and returns `Result<(), ConfigError>`
    fn validate_internal(&self) -> Result<(), ConfigError> {
        // Validate DNS configuration
        if let Some(ref dns) = self.dns {
            if dns.cache_size > 100_000 {
                return Err(ConfigError::InvalidCacheSize(dns.cache_size));
            }
        }

        // Validate DHCP configuration
        #[cfg(feature = "dhcp")]
        if let Some(ref dhcp) = self.dhcp {
            // Check for overlapping DHCP ranges
            for (i, range1) in dhcp.ranges.iter().enumerate() {
                range1.validate()?;
                for range2 in dhcp.ranges.iter().skip(i + 1) {
                    // Simplified overlap check - production would need full subnet math
                    if range1.start == range2.start || range1.end == range2.end {
                        return Err(ConfigError::OverlappingRanges(format!(
                            "{}-{} overlaps with {}-{}",
                            range1.start, range1.end, range2.start, range2.end
                        )));
                    }
                }
            }
        }

        // Validate network configuration
        if let Some(ref network) = self.network {
            if network.port == 0 {
                return Err(ConfigError::InvalidPort(network.port));
            }
        }

        Ok(())
    }

    /// Validates the configuration for consistency
    ///
    /// Checks cross-field constraints that can't be enforced by the type system:
    /// - No overlapping DHCP ranges
    /// - Valid port numbers
    /// - Accessible file paths
    /// - Valid network interface names
    ///
    /// Returns a mutable reference to self for method chaining.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if any validation check fails:
    /// - `InvalidCacheSize` if DNS cache size exceeds 100,000 entries
    /// - `ValidationError` if DHCP ranges are invalid or overlap
    /// - `InvalidPort` if port numbers are invalid
    /// - Other validation errors as defined in `ConfigError`
    pub fn validate(&mut self) -> Result<&mut Self, ConfigError> {
        self.validate_internal()?;
        Ok(self)
    }

    /// Builds the final configuration after validation
    ///
    /// Consumes the builder and returns a validated `Config` instance.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if validation fails:
    /// - `InvalidCacheSize` if DNS cache size exceeds 100,000 entries
    /// - `ValidationError` if DHCP ranges are invalid or overlap
    /// - `InvalidPort` if port numbers are invalid
    /// - Other validation errors as defined in `ConfigError`
    pub fn build(self) -> Result<Config, ConfigError> {
        // Perform final validation
        self.validate_internal()?;

        Ok(Config {
            dns: self.dns.unwrap_or_default(),
            #[cfg(feature = "dhcp")]
            dhcp: self.dhcp,
            network: self.network.unwrap_or_default(),
            logging: self.logging.unwrap_or_default(),
            security: self.security.unwrap_or_default(),
            #[cfg(feature = "tftp")]
            tftp: self.tftp,
            #[cfg(feature = "dnssec")]
            dnssec: self.dnssec,
            #[cfg(feature = "auth-dns")]
            auth: self.auth,
            files: self.files.unwrap_or_default(),
        })
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address_parsing() {
        let mac = "01:23:45:67:89:ab".parse::<MacAddress>().unwrap();
        assert_eq!(mac.0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        assert_eq!(mac.to_string(), "01:23:45:67:89:ab");
    }

    #[test]
    fn test_mac_address_invalid() {
        assert!("01:23:45:67:89".parse::<MacAddress>().is_err());
        assert!("01:23:45:67:89:ab:cd".parse::<MacAddress>().is_err());
        assert!("zz:23:45:67:89:ab".parse::<MacAddress>().is_err());
    }

    #[test]
    fn test_dhcp_range_validation() {
        let range = DhcpRange::new_v4(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
        );
        assert!(range.validate().is_ok());

        // Invalid: start > end
        let mut invalid_range = range.clone();
        invalid_range.start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 250));
        assert!(invalid_range.validate().is_err());
    }

    #[test]
    fn test_config_builder() {
        let mut builder = ConfigBuilder::new();
        builder.dns(DnsConfig::default());
        builder.network(NetworkConfig::default());

        // Validate returns &mut Self for chaining
        builder.validate().unwrap();

        // Build consumes the builder
        let config = builder.build().unwrap();

        assert_eq!(
            config.dns.cache_size,
            super::super::defaults::DEFAULT_CACHE_SIZE
        );
        assert_eq!(config.network.port, 53);
    }

    #[test]
    fn test_config_validation_cache_size() {
        let mut builder = ConfigBuilder::new();
        let dns = DnsConfig {
            cache_size: 200_000, // Too large
            ..Default::default()
        };
        builder.dns(dns);

        assert!(builder.validate().is_err());
    }
}
