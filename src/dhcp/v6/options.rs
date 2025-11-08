// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # `DHCPv6` Options Parsing and Serialization
//!
//! This module implements RFC 3315 `DHCPv6` option parsing and serialization with type-safe
//! structures replacing C's manual pointer arithmetic. `DHCPv6` uses `TLV` (Type-Length-Value)
//! encoding where each option consists of:
//! - 2-byte option code (network byte order / big-endian)
//! - 2-byte length field (network byte order / big-endian)
//! - Variable-length data payload
//!
//! ## Key Differences from C Implementation
//!
//! - **Memory Safety**: Rust's slice bounds checking prevents buffer overflows that were
//!   possible with C's manual `GETSHORT`/`PUTSHORT` macros and pointer arithmetic
//! - **Type Safety**: Strongly-typed enums for option codes and `DUID` types prevent invalid
//!   values that C's int-based approach allowed
//! - **Error Handling**: Result types with descriptive errors replace C's `NULL`/errno pattern
//! - **Nested Options**: Type-safe parsing of nested options (`IA_NA` contains `IAADDR`) using
//!   iterators instead of recursive pointer walking
//!
//! ## `DUID` (DHCP Unique Identifier)
//!
//! `DHCPv6` uses `DUIDs` instead of MAC addresses for client identification per RFC 3315 Section 9:
//! - **`DUID-LLT`** (Type 1): Link-layer address + timestamp for uniqueness across time
//! - **`DUID-EN`** (Type 2): Enterprise number + vendor-assigned identifier
//! - **`DUID-LL`** (Type 3): Link-layer address only (simpler than `DUID-LLT`)
//!
//! ## Protocol Compliance
//!
//! - RFC 3315: `DHCPv6` base protocol (message types, options, `DUID` types, `IA` structures)
//! - RFC 3633: IPv6 Prefix Delegation (`IA_PD`, `IAPREFIX` options)
//! - RFC 3646: DNS Configuration Options (`DNS_SERVER`, `DOMAIN_SEARCH`)
//! - RFC 4704: Client `FQDN` Option
//! - RFC 5908: NTP Server Option
//! - RFC 6939: Client Link-Layer Address Option

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::net::Ipv6Addr;
use thiserror::Error;

// ============================================================================
// Constants - DHCPv6 Option Codes (RFC 3315 and extensions)
// ============================================================================

/// Option 1: Client Identifier (contains DUID)
pub const OPTION6_CLIENT_ID: u16 = 1;

/// Option 2: Server Identifier (contains DUID)
pub const OPTION6_SERVER_ID: u16 = 2;

/// Option 3: Identity Association for Non-temporary Addresses
pub const OPTION6_IA_NA: u16 = 3;

/// Option 4: Identity Association for Temporary Addresses
pub const OPTION6_IA_TA: u16 = 4;

/// Option 5: `IA` Address (contained within `IA_NA` or `IA_TA`)
pub const OPTION6_IAADDR: u16 = 5;

/// Option 6: Option Request Option (list of requested option codes)
pub const OPTION6_ORO: u16 = 6;

/// Option 7: Preference (server preference value 0-255)
pub const OPTION6_PREFERENCE: u16 = 7;

/// Option 8: Elapsed Time (in centiseconds)
pub const OPTION6_ELAPSED_TIME: u16 = 8;

/// Option 9: Relay Message (encapsulated message in relay)
pub const OPTION6_RELAY_MSG: u16 = 9;

/// Option 11: Authentication
pub const OPTION6_AUTH: u16 = 11;

/// Option 12: Server Unicast (server's unicast address)
pub const OPTION6_UNICAST: u16 = 12;

/// Option 13: Status Code (success or error indication)
pub const OPTION6_STATUS_CODE: u16 = 13;

/// Option 14: Rapid Commit (2-message exchange)
pub const OPTION6_RAPID_COMMIT: u16 = 14;

/// Option 15: User Class
pub const OPTION6_USER_CLASS: u16 = 15;

/// Option 16: Vendor Class
pub const OPTION6_VENDOR_CLASS: u16 = 16;

/// Option 17: Vendor-specific Information
pub const OPTION6_VENDOR_OPTS: u16 = 17;

/// Option 18: Interface-ID (relay agent)
pub const OPTION6_INTERFACE_ID: u16 = 18;

/// Option 19: Reconfigure Message Type
pub const OPTION6_RECONFIGURE_MSG: u16 = 19;

/// Option 20: Reconfigure Accept
pub const OPTION6_RECONF_ACCEPT: u16 = 20;

/// Option 23: DNS Recursive Name Server
pub const OPTION6_DNS_SERVER: u16 = 23;

/// Option 24: Domain Search List
pub const OPTION6_DOMAIN_SEARCH: u16 = 24;

/// Option 25: Identity Association for Prefix Delegation
pub const OPTION6_IA_PD: u16 = 25;

/// Option 26: `IA` Prefix (contained within `IA_PD`)
pub const OPTION6_IAPREFIX: u16 = 26;

/// Option 32: Information Refresh Time
pub const OPTION6_REFRESH_TIME: u16 = 32;

/// Option 37: Relay Agent Remote-ID
pub const OPTION6_REMOTE_ID: u16 = 37;

/// Option 38: Relay Agent Subscriber-ID
pub const OPTION6_SUBSCRIBER_ID: u16 = 38;

/// Option 39: Client FQDN
pub const OPTION6_FQDN: u16 = 39;

/// Option 56: NTP Server
pub const OPTION6_NTP_SERVER: u16 = 56;

/// Option 79: Client Link-Layer Address
pub const OPTION6_CLIENT_MAC: u16 = 79;

/// Rapid Commit marker (zero-length option)
pub const RAPID_COMMIT: u16 = OPTION6_RAPID_COMMIT;

// ============================================================================
// Status Code Constants (RFC 3315 Section 24.4)
// ============================================================================

/// Status: Success (0)
pub const STATUS_SUCCESS: u16 = 0;

/// Status: `UnspecFail` (1) - Unspecified failure
pub const STATUS_UNSPEC_FAIL: u16 = 1;

/// Status: `NoAddrsAvail` (2) - No addresses available
pub const STATUS_NO_ADDRS_AVAIL: u16 = 2;

/// Status: `NoBinding` (3) - Client record (binding) unavailable
pub const STATUS_NO_BINDING: u16 = 3;

/// Status: `NotOnLink` (4) - Not appropriate for link
pub const STATUS_NOT_ON_LINK: u16 = 4;

/// Status: `UseMulticast` (5) - Use multicast instead of unicast
pub const STATUS_USE_MULTICAST: u16 = 5;

// ============================================================================
// DUID Type Constants (RFC 3315 Section 9)
// ============================================================================

/// DUID-LLT: Link-layer address plus time (Type 1)
pub const DUID_TYPE_LLT: u16 = 1;

/// DUID-EN: Enterprise number (Type 2)
pub const DUID_TYPE_EN: u16 = 2;

/// DUID-LL: Link-layer address (Type 3)
pub const DUID_TYPE_LL: u16 = 3;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during `DHCPv6` option parsing
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Dhcp6OptionError {
    /// Option length field doesn't match expected size for option type
    #[error("Invalid option length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length
        expected: usize,
        /// Actual length found
        actual: usize,
    },

    /// Unknown or unrecognized option code
    #[error("Unknown option code: {0}")]
    UnknownOptionCode(u16),

    /// Malformed DUID structure
    #[error("Invalid DUID format: {0}")]
    InvalidDuidFormat(String),

    /// Generic parsing error (I/O error, truncated data)
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Buffer too small for serialization
    #[error("Buffer too small: need {need} bytes, have {have}")]
    BufferTooSmall {
        /// Required size
        need: usize,
        /// Available size
        have: usize,
    },

    /// Invalid UTF-8 in status message or domain name
    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

impl From<std::io::Error> for Dhcp6OptionError {
    fn from(err: std::io::Error) -> Self {
        Dhcp6OptionError::ParseError(err.to_string())
    }
}

// ============================================================================
// DUID (DHCP Unique Identifier) - RFC 3315 Section 9
// ============================================================================

/// `DUID` (DHCP Unique Identifier) for `DHCPv6` client/server identification
///
/// `DHCPv6` uses `DUIDs` instead of MAC addresses for persistent client identification
/// across network moves and hardware changes. Three types are defined:
///
/// - **`DUID-LLT`**: Combines link-layer address with timestamp for uniqueness over time
/// - **`DUID-EN`**: Uses vendor's enterprise number with vendor-assigned identifier
/// - **`DUID-LL`**: Uses link-layer address only (simpler than `DUID-LLT`)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Duid {
    /// DUID-LLT: Link-layer address plus time (Type 1)
    ///
    /// Format: 2-byte type (1) + 2-byte hardware type + 4-byte time + link-layer address
    /// Time is seconds since midnight (UTC), January 1, 2000, modulo 2^32
    LLT {
        /// Hardware type (ARP hardware type, e.g., 1 for Ethernet)
        hw_type: u16,
        /// Time value (seconds since Jan 1, 2000 UTC, modulo 2^32)
        time: u32,
        /// Link-layer address (e.g., MAC address for Ethernet)
        ll_addr: Vec<u8>,
    },

    /// DUID-EN: Vendor-assigned identifier based on enterprise number (Type 2)
    ///
    /// Format: 2-byte type (2) + 4-byte enterprise number + vendor-assigned identifier
    /// Enterprise numbers assigned by IANA
    EN {
        /// IANA-assigned Private Enterprise Number
        enterprise: u32,
        /// Vendor-assigned unique identifier (format vendor-specific)
        identifier: Vec<u8>,
    },

    /// DUID-LL: Link-layer address (Type 3)
    ///
    /// Format: 2-byte type (3) + 2-byte hardware type + link-layer address
    /// Simpler than DUID-LLT, suitable when time synchronization unavailable
    LL {
        /// Hardware type (ARP hardware type, e.g., 1 for Ethernet)
        hw_type: u16,
        /// Link-layer address (e.g., MAC address for Ethernet)
        ll_addr: Vec<u8>,
    },
}

impl Duid {
    /// Parse DUID from byte slice
    ///
    /// # Arguments
    /// * `data` - Raw DUID bytes (minimum 2 bytes for type field)
    ///
    /// # Returns
    /// Parsed DUID or error if format invalid
    ///
    /// # Errors
    /// Returns error if DUID data is too short, has invalid type, or is malformed
    ///
    /// # Examples
    /// ```
    /// # use dnsmasq::dhcp::v6::options::Duid;
    /// // DUID-LL with Ethernet MAC address
    /// let duid_bytes = vec![0, 3, 0, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let duid = Duid::parse(&duid_bytes).unwrap();
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, Dhcp6OptionError> {
        if data.len() < 2 {
            return Err(Dhcp6OptionError::InvalidDuidFormat(
                "DUID too short (minimum 2 bytes for type)".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let duid_type = cursor.read_u16::<BigEndian>()?;

        match duid_type {
            DUID_TYPE_LLT => {
                // DUID-LLT: type (2) + hw_type (2) + time (4) + ll_addr (variable)
                if data.len() < 8 {
                    return Err(Dhcp6OptionError::InvalidDuidFormat(
                        "DUID-LLT too short (minimum 8 bytes)".to_string(),
                    ));
                }
                let hw_type = cursor.read_u16::<BigEndian>()?;
                let time = cursor.read_u32::<BigEndian>()?;
                let mut ll_addr = Vec::new();
                cursor.read_to_end(&mut ll_addr)?;

                Ok(Duid::LLT {
                    hw_type,
                    time,
                    ll_addr,
                })
            }
            DUID_TYPE_EN => {
                // DUID-EN: type (2) + enterprise (4) + identifier (variable)
                if data.len() < 6 {
                    return Err(Dhcp6OptionError::InvalidDuidFormat(
                        "DUID-EN too short (minimum 6 bytes)".to_string(),
                    ));
                }
                let enterprise = cursor.read_u32::<BigEndian>()?;
                let mut identifier = Vec::new();
                cursor.read_to_end(&mut identifier)?;

                Ok(Duid::EN {
                    enterprise,
                    identifier,
                })
            }
            DUID_TYPE_LL => {
                // DUID-LL: type (2) + hw_type (2) + ll_addr (variable)
                if data.len() < 4 {
                    return Err(Dhcp6OptionError::InvalidDuidFormat(
                        "DUID-LL too short (minimum 4 bytes)".to_string(),
                    ));
                }
                let hw_type = cursor.read_u16::<BigEndian>()?;
                let mut ll_addr = Vec::new();
                cursor.read_to_end(&mut ll_addr)?;

                Ok(Duid::LL { hw_type, ll_addr })
            }
            _ => Err(Dhcp6OptionError::InvalidDuidFormat(format!(
                "Unknown DUID type: {duid_type}"
            ))),
        }
    }

    /// Serialize DUID to byte vector
    ///
    /// # Returns
    /// Serialized DUID bytes in network byte order
    ///
    /// # Panics
    /// May panic if writing to Vec fails (which should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            Duid::LLT {
                hw_type,
                time,
                ll_addr,
            } => {
                buf.write_u16::<BigEndian>(DUID_TYPE_LLT).unwrap();
                buf.write_u16::<BigEndian>(*hw_type).unwrap();
                buf.write_u32::<BigEndian>(*time).unwrap();
                buf.extend_from_slice(ll_addr);
            }
            Duid::EN {
                enterprise,
                identifier,
            } => {
                buf.write_u16::<BigEndian>(DUID_TYPE_EN).unwrap();
                buf.write_u32::<BigEndian>(*enterprise).unwrap();
                buf.extend_from_slice(identifier);
            }
            Duid::LL { hw_type, ll_addr } => {
                buf.write_u16::<BigEndian>(DUID_TYPE_LL).unwrap();
                buf.write_u16::<BigEndian>(*hw_type).unwrap();
                buf.extend_from_slice(ll_addr);
            }
        }

        buf
    }

    /// Get DUID as byte slice (via serialization)
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.serialize()
    }

    /// Get length of serialized DUID in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Duid::LLT { ll_addr, .. } => 2 + 2 + 4 + ll_addr.len(), // type + hw_type + time + ll_addr
            Duid::EN { identifier, .. } => 2 + 4 + identifier.len(), // type + enterprise + identifier
            Duid::LL { ll_addr, .. } => 2 + 2 + ll_addr.len(),       // type + hw_type + ll_addr
        }
    }

    /// Check if DUID is empty (always false for valid DUID)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Display for Duid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Duid::LLT {
                hw_type,
                time,
                ll_addr,
            } => {
                write!(
                    f,
                    "DUID-LLT(hw_type={}, time={}, addr={})",
                    hw_type,
                    time,
                    hex_string(ll_addr)
                )
            }
            Duid::EN {
                enterprise,
                identifier,
            } => {
                write!(
                    f,
                    "DUID-EN(enterprise={}, id={})",
                    enterprise,
                    hex_string(identifier)
                )
            }
            Duid::LL { hw_type, ll_addr } => {
                write!(
                    f,
                    "DUID-LL(hw_type={}, addr={})",
                    hw_type,
                    hex_string(ll_addr)
                )
            }
        }
    }
}

// Helper function for hex display
fn hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ============================================================================
// Identity Association Structures
// ============================================================================

/// `IA_NA`: Identity Association for Non-temporary Addresses (Option 3)
///
/// Container for non-temporary IPv6 address assignment. Contains `IAID`, renewal timers
/// (T1, T2), and nested `IAADDR` options with actual addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaNa {
    /// Identity Association Identifier (chosen by client, unique per `IA`)
    pub iaid: u32,
    /// T1: Time when client should contact server to extend lifetimes (seconds)
    pub t1: u32,
    /// T2: Time when client should contact any server to extend lifetimes (seconds)
    pub t2: u32,
    /// Nested options (typically `IAADDR` and `STATUS_CODE`)
    pub options: Vec<u8>,
}

impl IaNa {
    /// Create new `IA_NA`
    #[must_use]
    pub fn new(iaid: u32, t1: u32, t2: u32, options: Vec<u8>) -> Self {
        Self {
            iaid,
            t1,
            t2,
            options,
        }
    }

    /// Parse `IA_NA` from bytes (after option code and length)
    ///
    /// Format: 4-byte `IAID` + 4-byte T1 + 4-byte T2 + options
    ///
    /// # Errors
    /// Returns error if data is too short or malformed
    pub fn parse(data: &[u8]) -> Result<Self, Dhcp6OptionError> {
        if data.len() < 12 {
            return Err(Dhcp6OptionError::InvalidLength {
                expected: 12,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let iaid = cursor.read_u32::<BigEndian>()?;
        let t1 = cursor.read_u32::<BigEndian>()?;
        let t2 = cursor.read_u32::<BigEndian>()?;

        let mut options = Vec::new();
        cursor.read_to_end(&mut options)?;

        Ok(Self::new(iaid, t1, t2, options))
    }

    /// Serialize `IA_NA` to bytes
    ///
    /// # Panics
    /// May panic if writing to Vec fails (which should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(self.iaid).unwrap();
        buf.write_u32::<BigEndian>(self.t1).unwrap();
        buf.write_u32::<BigEndian>(self.t2).unwrap();
        buf.extend_from_slice(&self.options);
        buf
    }

    /// Get IAID
    #[must_use]
    pub fn iaid(&self) -> u32 {
        self.iaid
    }

    /// Get T1 timer
    #[must_use]
    pub fn t1(&self) -> u32 {
        self.t1
    }

    /// Get T2 timer
    #[must_use]
    pub fn t2(&self) -> u32 {
        self.t2
    }

    /// Get nested options
    #[must_use]
    pub fn options(&self) -> &[u8] {
        &self.options
    }
}

/// `IA_TA`: Identity Association for Temporary Addresses (Option 4)
///
/// Container for temporary IPv6 address assignment (privacy extensions).
/// Unlike `IA_NA`, does not have T1/T2 timers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaTa {
    /// Identity Association Identifier
    pub iaid: u32,
    /// Nested options (typically `IAADDR` and `STATUS_CODE`)
    pub options: Vec<u8>,
}

impl IaTa {
    /// Create new `IA_TA`
    #[must_use]
    pub fn new(iaid: u32, options: Vec<u8>) -> Self {
        Self { iaid, options }
    }

    /// Parse `IA_TA` from bytes (after option code and length)
    ///
    /// Format: 4-byte `IAID` + options (no T1/T2)
    ///
    /// # Errors
    /// Returns error if data is too short or malformed
    pub fn parse(data: &[u8]) -> Result<Self, Dhcp6OptionError> {
        if data.len() < 4 {
            return Err(Dhcp6OptionError::InvalidLength {
                expected: 4,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let iaid = cursor.read_u32::<BigEndian>()?;

        let mut options = Vec::new();
        cursor.read_to_end(&mut options)?;

        Ok(Self::new(iaid, options))
    }

    /// Serialize `IA_TA` to bytes
    ///
    /// # Panics
    /// May panic if writing to Vec fails (which should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(self.iaid).unwrap();
        buf.extend_from_slice(&self.options);
        buf
    }

    /// Get IAID
    #[must_use]
    pub fn iaid(&self) -> u32 {
        self.iaid
    }

    /// Get nested options
    #[must_use]
    pub fn options(&self) -> &[u8] {
        &self.options
    }
}

/// `IAADDR`: `IA` Address (Option 5)
///
/// Actual IPv6 address within `IA_NA` or `IA_TA`, with preferred and valid lifetimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaAddr {
    /// IPv6 address
    pub address: Ipv6Addr,
    /// Preferred lifetime in seconds (address remains preferred)
    pub preferred_lifetime: u32,
    /// Valid lifetime in seconds (address remains valid)
    pub valid_lifetime: u32,
    /// Nested options (typically `STATUS_CODE`)
    pub options: Vec<u8>,
}

impl IaAddr {
    /// Create new IAADDR
    #[must_use]
    pub fn new(
        address: Ipv6Addr,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        options: Vec<u8>,
    ) -> Self {
        Self {
            address,
            preferred_lifetime,
            valid_lifetime,
            options,
        }
    }

    /// Parse IAADDR from bytes (after option code and length)
    ///
    /// Format: 16-byte IPv6 address + 4-byte preferred + 4-byte valid + options
    ///
    /// # Errors
    /// Returns error if data is too short or malformed
    pub fn parse(data: &[u8]) -> Result<Self, Dhcp6OptionError> {
        if data.len() < 24 {
            return Err(Dhcp6OptionError::InvalidLength {
                expected: 24,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        // Read 16-byte IPv6 address
        let mut addr_bytes = [0u8; 16];
        cursor.read_exact(&mut addr_bytes)?;
        let address = Ipv6Addr::from(addr_bytes);

        let preferred_lifetime = cursor.read_u32::<BigEndian>()?;
        let valid_lifetime = cursor.read_u32::<BigEndian>()?;

        let mut options = Vec::new();
        cursor.read_to_end(&mut options)?;

        Ok(Self::new(
            address,
            preferred_lifetime,
            valid_lifetime,
            options,
        ))
    }

    /// Serialize IAADDR to bytes
    ///
    /// # Panics
    /// May panic if writing to Vec fails (which should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.address.octets());
        buf.write_u32::<BigEndian>(self.preferred_lifetime).unwrap();
        buf.write_u32::<BigEndian>(self.valid_lifetime).unwrap();
        buf.extend_from_slice(&self.options);
        buf
    }

    /// Get IPv6 address
    #[must_use]
    pub fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// Get preferred lifetime
    #[must_use]
    pub fn preferred_lifetime(&self) -> u32 {
        self.preferred_lifetime
    }

    /// Get valid lifetime
    #[must_use]
    pub fn valid_lifetime(&self) -> u32 {
        self.valid_lifetime
    }

    /// Get nested options
    #[must_use]
    pub fn options(&self) -> &[u8] {
        &self.options
    }
}

/// `IA_PD`: Identity Association for Prefix Delegation (Option 25)
///
/// Container for delegated IPv6 prefix assignment (RFC 3633).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPd {
    /// Identity Association Identifier
    pub iaid: u32,
    /// T1: Time when client should renew
    pub t1: u32,
    /// T2: Time when client should rebind
    pub t2: u32,
    /// Nested options (typically IAPREFIX)
    pub options: Vec<u8>,
}

impl IaPd {
    /// Create new `IA_PD`
    #[must_use]
    pub fn new(iaid: u32, t1: u32, t2: u32, options: Vec<u8>) -> Self {
        Self {
            iaid,
            t1,
            t2,
            options,
        }
    }

    /// Parse `IA_PD` from bytes
    ///
    /// # Errors
    /// Returns error if data is too short or malformed
    pub fn parse(data: &[u8]) -> Result<Self, Dhcp6OptionError> {
        if data.len() < 12 {
            return Err(Dhcp6OptionError::InvalidLength {
                expected: 12,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let iaid = cursor.read_u32::<BigEndian>()?;
        let t1 = cursor.read_u32::<BigEndian>()?;
        let t2 = cursor.read_u32::<BigEndian>()?;

        let mut options = Vec::new();
        cursor.read_to_end(&mut options)?;

        Ok(Self::new(iaid, t1, t2, options))
    }

    /// Serialize `IA_PD` to bytes
    ///
    /// # Panics
    /// May panic if writing to Vec fails (which should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(self.iaid).unwrap();
        buf.write_u32::<BigEndian>(self.t1).unwrap();
        buf.write_u32::<BigEndian>(self.t2).unwrap();
        buf.extend_from_slice(&self.options);
        buf
    }

    /// Get IAID
    #[must_use]
    pub fn iaid(&self) -> u32 {
        self.iaid
    }

    /// Get T1 timer
    #[must_use]
    pub fn t1(&self) -> u32 {
        self.t1
    }

    /// Get T2 timer
    #[must_use]
    pub fn t2(&self) -> u32 {
        self.t2
    }

    /// Get nested options
    #[must_use]
    pub fn options(&self) -> &[u8] {
        &self.options
    }
}

/// IAPREFIX: IA Prefix (Option 26)
///
/// Delegated IPv6 prefix within `IA_PD` (RFC 3633).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPrefix {
    /// IPv6 prefix
    pub prefix: Ipv6Addr,
    /// Prefix length (0-128)
    pub prefix_length: u8,
    /// Preferred lifetime in seconds
    pub preferred_lifetime: u32,
    /// Valid lifetime in seconds
    pub valid_lifetime: u32,
    /// Nested options
    pub options: Vec<u8>,
}

impl IaPrefix {
    /// Create new IAPREFIX
    #[must_use]
    pub fn new(
        prefix: Ipv6Addr,
        prefix_length: u8,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        options: Vec<u8>,
    ) -> Self {
        Self {
            prefix,
            prefix_length,
            preferred_lifetime,
            valid_lifetime,
            options,
        }
    }

    /// Parse IAPREFIX from bytes
    ///
    /// Format: 4-byte preferred + 4-byte valid + 1-byte `prefix_len` + 16-byte prefix + options
    ///
    /// # Errors
    /// Returns error if data is too short or malformed
    pub fn parse(data: &[u8]) -> Result<Self, Dhcp6OptionError> {
        if data.len() < 25 {
            return Err(Dhcp6OptionError::InvalidLength {
                expected: 25,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let preferred_lifetime = cursor.read_u32::<BigEndian>()?;
        let valid_lifetime = cursor.read_u32::<BigEndian>()?;

        let mut prefix_length_byte = [0u8; 1];
        cursor.read_exact(&mut prefix_length_byte)?;
        let prefix_length = prefix_length_byte[0];

        let mut prefix_bytes = [0u8; 16];
        cursor.read_exact(&mut prefix_bytes)?;
        let prefix = Ipv6Addr::from(prefix_bytes);

        let mut options = Vec::new();
        cursor.read_to_end(&mut options)?;

        Ok(Self::new(
            prefix,
            prefix_length,
            preferred_lifetime,
            valid_lifetime,
            options,
        ))
    }

    /// Serialize IAPREFIX to bytes
    ///
    /// # Panics
    /// May panic if writing to Vec fails (which should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(self.preferred_lifetime).unwrap();
        buf.write_u32::<BigEndian>(self.valid_lifetime).unwrap();
        buf.push(self.prefix_length);
        buf.extend_from_slice(&self.prefix.octets());
        buf.extend_from_slice(&self.options);
        buf
    }

    /// Get prefix
    #[must_use]
    pub fn prefix(&self) -> Ipv6Addr {
        self.prefix
    }

    /// Get prefix length
    #[must_use]
    pub fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    /// Get preferred lifetime
    #[must_use]
    pub fn preferred_lifetime(&self) -> u32 {
        self.preferred_lifetime
    }

    /// Get valid lifetime
    #[must_use]
    pub fn valid_lifetime(&self) -> u32 {
        self.valid_lifetime
    }

    /// Get nested options
    #[must_use]
    pub fn options(&self) -> &[u8] {
        &self.options
    }
}

/// Status Code (Option 13)
///
/// Success or error indication with optional human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCode {
    /// Numeric status code
    pub code: u16,
    /// Human-readable status message (UTF-8)
    pub message: String,
}

impl StatusCode {
    /// Success status code constant
    pub const SUCCESS: u16 = STATUS_SUCCESS;
    /// Unspecified failure
    pub const UNSPEC_FAIL: u16 = STATUS_UNSPEC_FAIL;
    /// No addresses available
    pub const NO_ADDRS_AVAIL: u16 = STATUS_NO_ADDRS_AVAIL;
    /// No binding
    pub const NO_BINDING: u16 = STATUS_NO_BINDING;
    /// Not on link
    pub const NOT_ON_LINK: u16 = STATUS_NOT_ON_LINK;
    /// Use multicast
    pub const USE_MULTICAST: u16 = STATUS_USE_MULTICAST;

    /// Create new `StatusCode`
    #[must_use]
    pub fn new(code: u16, message: String) -> Self {
        Self { code, message }
    }

    /// Create success status
    #[must_use]
    pub fn success() -> Self {
        Self::new(Self::SUCCESS, String::new())
    }

    /// Create success status with message
    #[must_use]
    pub fn success_with_message(message: String) -> Self {
        Self::new(Self::SUCCESS, message)
    }

    /// Parse `StatusCode` from bytes
    ///
    /// Format: 2-byte code + UTF-8 message
    ///
    /// # Errors
    /// Returns error if data is too short, malformed, or contains invalid UTF-8
    pub fn parse(data: &[u8]) -> Result<Self, Dhcp6OptionError> {
        if data.len() < 2 {
            return Err(Dhcp6OptionError::InvalidLength {
                expected: 2,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let code = cursor.read_u16::<BigEndian>()?;

        let mut message_bytes = Vec::new();
        cursor.read_to_end(&mut message_bytes)?;
        let message = String::from_utf8(message_bytes)?;

        Ok(Self::new(code, message))
    }

    /// Serialize `StatusCode` to bytes
    ///
    /// # Panics
    /// May panic if writing to Vec fails (which should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_u16::<BigEndian>(self.code).unwrap();
        buf.extend_from_slice(self.message.as_bytes());
        buf
    }

    /// Get status code
    #[must_use]
    pub fn code(&self) -> u16 {
        self.code
    }

    /// Get status message
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Check if status is success
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.code == Self::SUCCESS
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code_name = match self.code {
            Self::SUCCESS => "Success",
            Self::UNSPEC_FAIL => "UnspecFail",
            Self::NO_ADDRS_AVAIL => "NoAddrsAvail",
            Self::NO_BINDING => "NoBinding",
            Self::NOT_ON_LINK => "NotOnLink",
            Self::USE_MULTICAST => "UseMulticast",
            _ => "Unknown",
        };

        if self.message.is_empty() {
            write!(f, "{code_name}")
        } else {
            write!(f, "{code_name}: {}", self.message)
        }
    }
}

// ============================================================================
// Main DHCPv6 Option Enum
// ============================================================================

/// `DHCPv6` Option with type-safe variants for all supported option types
#[derive(Debug, Clone)]
pub enum Dhcp6Option {
    /// Option 1: Client Identifier (DUID)
    ClientId(Duid),

    /// Option 2: Server Identifier (DUID)
    ServerId(Duid),

    /// Option 3: Identity Association for Non-temporary Addresses
    IaNa(IaNa),

    /// Option 4: Identity Association for Temporary Addresses
    IaTa(IaTa),

    /// Option 5: IA Address
    IaAddr(IaAddr),

    /// Option 6: Option Request Option (list of requested option codes)
    Oro(Vec<u16>),

    /// Option 7: Preference (0-255, higher is better)
    Preference(u8),

    /// Option 8: Elapsed Time (in centiseconds, 1/100th second)
    ElapsedTime(u16),

    /// Option 9: Relay Message (encapsulated message)
    RelayMsg(Vec<u8>),

    /// Option 11: Authentication
    Auth(Vec<u8>),

    /// Option 12: Server Unicast Address
    Unicast(Ipv6Addr),

    /// Option 13: Status Code
    StatusCode(StatusCode),

    /// Option 14: Rapid Commit (zero-length)
    RapidCommit,

    /// Option 15: User Class
    UserClass(Vec<u8>),

    /// Option 16: Vendor Class
    VendorClass(Vec<u8>),

    /// Option 17: Vendor-specific Information
    VendorOpts(Vec<u8>),

    /// Option 18: Interface-ID
    InterfaceId(Vec<u8>),

    /// Option 19: Reconfigure Message Type
    ReconfigureMsg(u8),

    /// Option 20: Reconfigure Accept (zero-length)
    ReconfAccept,

    /// Option 23: DNS Recursive Name Servers
    DnsServer(Vec<Ipv6Addr>),

    /// Option 24: Domain Search List
    DomainSearch(Vec<String>),

    /// Option 25: Identity Association for Prefix Delegation
    IaPd(IaPd),

    /// Option 26: IA Prefix
    IaPrefix(IaPrefix),

    /// Option 32: Information Refresh Time
    RefreshTime(u32),

    /// Option 37: Remote-ID
    RemoteId(Vec<u8>),

    /// Option 38: Subscriber-ID
    SubscriberId(Vec<u8>),

    /// Option 39: Client FQDN
    Fqdn(Vec<u8>),

    /// Option 56: NTP Server
    NtpServer(Vec<u8>),

    /// Option 79: Client Link-Layer Address (MAC)
    ClientMac(Vec<u8>),

    /// Unknown or unsupported option
    Unknown {
        /// Option code
        code: u16,
        /// Option data
        data: Vec<u8>,
    },
}

impl Dhcp6Option {
    /// Parse a single `DHCPv6` option from bytes
    ///
    /// Expects TLV format: 2-byte code + 2-byte length + data
    ///
    /// # Arguments
    /// * `data` - Byte slice containing the complete option (code + length + data)
    ///
    /// # Returns
    /// Tuple of (parsed option, bytes consumed) or error
    ///
    /// # Errors
    /// Returns error if data is too short, length is invalid, or option format is malformed
    pub fn parse(data: &[u8]) -> Result<(Self, usize), Dhcp6OptionError> {
        if data.len() < 4 {
            return Err(Dhcp6OptionError::ParseError(
                "Option too short (minimum 4 bytes for code + length)".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let code = cursor.read_u16::<BigEndian>()?;
        let length = cursor.read_u16::<BigEndian>()? as usize;

        if data.len() < 4 + length {
            return Err(Dhcp6OptionError::ParseError(format!(
                "Option data truncated: need {} bytes, have {}",
                4 + length,
                data.len()
            )));
        }

        let option_data = &data[4..4 + length];
        let total_len = 4 + length;

        let option = match code {
            OPTION6_CLIENT_ID => {
                let duid = Duid::parse(option_data)?;
                Dhcp6Option::ClientId(duid)
            }
            OPTION6_SERVER_ID => {
                let duid = Duid::parse(option_data)?;
                Dhcp6Option::ServerId(duid)
            }
            OPTION6_IA_NA => {
                let ia_na = IaNa::parse(option_data)?;
                Dhcp6Option::IaNa(ia_na)
            }
            OPTION6_IA_TA => {
                let ia_ta = IaTa::parse(option_data)?;
                Dhcp6Option::IaTa(ia_ta)
            }
            OPTION6_IAADDR => {
                let ia_addr = IaAddr::parse(option_data)?;
                Dhcp6Option::IaAddr(ia_addr)
            }
            OPTION6_ORO => {
                // ORO is list of 2-byte option codes
                if !length.is_multiple_of(2) {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: length + 1,
                        actual: length,
                    });
                }
                let mut oro = Vec::new();
                let mut cursor = Cursor::new(option_data);
                for _ in 0..length / 2 {
                    oro.push(cursor.read_u16::<BigEndian>()?);
                }
                Dhcp6Option::Oro(oro)
            }
            OPTION6_PREFERENCE => {
                if length != 1 {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: 1,
                        actual: length,
                    });
                }
                Dhcp6Option::Preference(option_data[0])
            }
            OPTION6_ELAPSED_TIME => {
                if length != 2 {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: 2,
                        actual: length,
                    });
                }
                let mut cursor = Cursor::new(option_data);
                Dhcp6Option::ElapsedTime(cursor.read_u16::<BigEndian>()?)
            }
            OPTION6_RELAY_MSG => Dhcp6Option::RelayMsg(option_data.to_vec()),
            OPTION6_AUTH => Dhcp6Option::Auth(option_data.to_vec()),
            OPTION6_UNICAST => {
                if length != 16 {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: 16,
                        actual: length,
                    });
                }
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(option_data);
                Dhcp6Option::Unicast(Ipv6Addr::from(addr_bytes))
            }
            OPTION6_STATUS_CODE => {
                let status = StatusCode::parse(option_data)?;
                Dhcp6Option::StatusCode(status)
            }
            OPTION6_RAPID_COMMIT => {
                if length != 0 {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: 0,
                        actual: length,
                    });
                }
                Dhcp6Option::RapidCommit
            }
            OPTION6_USER_CLASS => Dhcp6Option::UserClass(option_data.to_vec()),
            OPTION6_VENDOR_CLASS => Dhcp6Option::VendorClass(option_data.to_vec()),
            OPTION6_VENDOR_OPTS => Dhcp6Option::VendorOpts(option_data.to_vec()),
            OPTION6_INTERFACE_ID => Dhcp6Option::InterfaceId(option_data.to_vec()),
            OPTION6_RECONFIGURE_MSG => {
                if length != 1 {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: 1,
                        actual: length,
                    });
                }
                Dhcp6Option::ReconfigureMsg(option_data[0])
            }
            OPTION6_RECONF_ACCEPT => {
                if length != 0 {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: 0,
                        actual: length,
                    });
                }
                Dhcp6Option::ReconfAccept
            }
            OPTION6_DNS_SERVER => {
                // DNS servers are list of 16-byte IPv6 addresses
                if !length.is_multiple_of(16) {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: (length / 16 + 1) * 16,
                        actual: length,
                    });
                }
                let mut servers = Vec::new();
                for chunk in option_data.chunks_exact(16) {
                    let mut addr_bytes = [0u8; 16];
                    addr_bytes.copy_from_slice(chunk);
                    servers.push(Ipv6Addr::from(addr_bytes));
                }
                Dhcp6Option::DnsServer(servers)
            }
            OPTION6_DOMAIN_SEARCH => {
                // Domain search list uses DNS wire format
                // For simplicity, store as raw bytes (full implementation would parse DNS names)
                Dhcp6Option::DomainSearch(vec![String::from_utf8_lossy(option_data).to_string()])
            }
            OPTION6_IA_PD => {
                let ia_pd = IaPd::parse(option_data)?;
                Dhcp6Option::IaPd(ia_pd)
            }
            OPTION6_IAPREFIX => {
                let ia_prefix = IaPrefix::parse(option_data)?;
                Dhcp6Option::IaPrefix(ia_prefix)
            }
            OPTION6_REFRESH_TIME => {
                if length != 4 {
                    return Err(Dhcp6OptionError::InvalidLength {
                        expected: 4,
                        actual: length,
                    });
                }
                let mut cursor = Cursor::new(option_data);
                Dhcp6Option::RefreshTime(cursor.read_u32::<BigEndian>()?)
            }
            OPTION6_REMOTE_ID => Dhcp6Option::RemoteId(option_data.to_vec()),
            OPTION6_SUBSCRIBER_ID => Dhcp6Option::SubscriberId(option_data.to_vec()),
            OPTION6_FQDN => Dhcp6Option::Fqdn(option_data.to_vec()),
            OPTION6_NTP_SERVER => Dhcp6Option::NtpServer(option_data.to_vec()),
            OPTION6_CLIENT_MAC => Dhcp6Option::ClientMac(option_data.to_vec()),
            _ => Dhcp6Option::Unknown {
                code,
                data: option_data.to_vec(),
            },
        };

        Ok((option, total_len))
    }

    /// Serialize `DHCPv6` option to bytes (TLV format)
    ///
    /// Returns: 2-byte code + 2-byte length + data
    ///
    /// # Panics
    /// May panic if writing to Vec fails (which should never happen in practice) or if option data exceeds 65535 bytes
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let code = self.option_code();
        let data = self.option_data();

        buf.write_u16::<BigEndian>(code).unwrap();
        buf.write_u16::<BigEndian>(
            data.len()
                .try_into()
                .expect("DHCPv6 option data exceeds maximum length of 65535 bytes"),
        )
        .unwrap();
        buf.extend_from_slice(&data);

        buf
    }

    /// Get option code for this option
    #[must_use]
    pub fn option_code(&self) -> u16 {
        match self {
            Dhcp6Option::ClientId(_) => OPTION6_CLIENT_ID,
            Dhcp6Option::ServerId(_) => OPTION6_SERVER_ID,
            Dhcp6Option::IaNa(_) => OPTION6_IA_NA,
            Dhcp6Option::IaTa(_) => OPTION6_IA_TA,
            Dhcp6Option::IaAddr(_) => OPTION6_IAADDR,
            Dhcp6Option::Oro(_) => OPTION6_ORO,
            Dhcp6Option::Preference(_) => OPTION6_PREFERENCE,
            Dhcp6Option::ElapsedTime(_) => OPTION6_ELAPSED_TIME,
            Dhcp6Option::RelayMsg(_) => OPTION6_RELAY_MSG,
            Dhcp6Option::Auth(_) => OPTION6_AUTH,
            Dhcp6Option::Unicast(_) => OPTION6_UNICAST,
            Dhcp6Option::StatusCode(_) => OPTION6_STATUS_CODE,
            Dhcp6Option::RapidCommit => OPTION6_RAPID_COMMIT,
            Dhcp6Option::UserClass(_) => OPTION6_USER_CLASS,
            Dhcp6Option::VendorClass(_) => OPTION6_VENDOR_CLASS,
            Dhcp6Option::VendorOpts(_) => OPTION6_VENDOR_OPTS,
            Dhcp6Option::InterfaceId(_) => OPTION6_INTERFACE_ID,
            Dhcp6Option::ReconfigureMsg(_) => OPTION6_RECONFIGURE_MSG,
            Dhcp6Option::ReconfAccept => OPTION6_RECONF_ACCEPT,
            Dhcp6Option::DnsServer(_) => OPTION6_DNS_SERVER,
            Dhcp6Option::DomainSearch(_) => OPTION6_DOMAIN_SEARCH,
            Dhcp6Option::IaPd(_) => OPTION6_IA_PD,
            Dhcp6Option::IaPrefix(_) => OPTION6_IAPREFIX,
            Dhcp6Option::RefreshTime(_) => OPTION6_REFRESH_TIME,
            Dhcp6Option::RemoteId(_) => OPTION6_REMOTE_ID,
            Dhcp6Option::SubscriberId(_) => OPTION6_SUBSCRIBER_ID,
            Dhcp6Option::Fqdn(_) => OPTION6_FQDN,
            Dhcp6Option::NtpServer(_) => OPTION6_NTP_SERVER,
            Dhcp6Option::ClientMac(_) => OPTION6_CLIENT_MAC,
            Dhcp6Option::Unknown { code, .. } => *code,
        }
    }

    /// Get option data (without code and length header)
    fn option_data(&self) -> Vec<u8> {
        match self {
            Dhcp6Option::ClientId(duid) | Dhcp6Option::ServerId(duid) => duid.serialize(),
            Dhcp6Option::IaNa(ia_na) => ia_na.serialize(),
            Dhcp6Option::IaTa(ia_ta) => ia_ta.serialize(),
            Dhcp6Option::IaAddr(ia_addr) => ia_addr.serialize(),
            Dhcp6Option::Oro(codes) => {
                let mut buf = Vec::new();
                for code in codes {
                    buf.write_u16::<BigEndian>(*code).unwrap();
                }
                buf
            }
            Dhcp6Option::Preference(pref) => vec![*pref],
            Dhcp6Option::ElapsedTime(time) => {
                let mut buf = Vec::new();
                buf.write_u16::<BigEndian>(*time).unwrap();
                buf
            }
            Dhcp6Option::RelayMsg(data)
            | Dhcp6Option::Auth(data)
            | Dhcp6Option::UserClass(data)
            | Dhcp6Option::VendorClass(data)
            | Dhcp6Option::VendorOpts(data)
            | Dhcp6Option::InterfaceId(data)
            | Dhcp6Option::RemoteId(data)
            | Dhcp6Option::SubscriberId(data)
            | Dhcp6Option::Fqdn(data)
            | Dhcp6Option::NtpServer(data)
            | Dhcp6Option::ClientMac(data)
            | Dhcp6Option::Unknown { data, .. } => data.clone(),
            Dhcp6Option::Unicast(addr) => addr.octets().to_vec(),
            Dhcp6Option::StatusCode(status) => status.serialize(),
            Dhcp6Option::RapidCommit | Dhcp6Option::ReconfAccept => Vec::new(),
            Dhcp6Option::ReconfigureMsg(msg_type) => vec![*msg_type],
            Dhcp6Option::DnsServer(servers) => {
                let mut buf = Vec::new();
                for server in servers {
                    buf.extend_from_slice(&server.octets());
                }
                buf
            }
            Dhcp6Option::DomainSearch(domains) => {
                // Simplified: just concatenate as UTF-8
                // Full implementation would use DNS wire format with compression
                domains.join("\0").as_bytes().to_vec()
            }
            Dhcp6Option::IaPd(ia_pd) => ia_pd.serialize(),
            Dhcp6Option::IaPrefix(ia_prefix) => ia_prefix.serialize(),
            Dhcp6Option::RefreshTime(time) => {
                let mut buf = Vec::new();
                buf.write_u32::<BigEndian>(*time).unwrap();
                buf
            }
        }
    }

    /// Get total option length (including 4-byte header)
    #[must_use]
    pub fn option_len(&self) -> usize {
        4 + self.option_data().len()
    }
}

// ============================================================================
// Utility Functions for Parsing/Serializing Option Lists
// ============================================================================

/// Parse all options from a byte slice
///
/// Returns vector of parsed options. Continues parsing until end of data,
/// skipping or storing unknown options.
///
/// # Arguments
/// * `data` - Byte slice containing concatenated TLV options
///
/// # Returns
/// Vector of parsed options or error on malformed data
///
/// # Errors
/// Returns error if data is too short, malformed, or contains invalid option format
pub fn parse_options(data: &[u8]) -> Result<Vec<Dhcp6Option>, Dhcp6OptionError> {
    let mut options = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        match Dhcp6Option::parse(&data[offset..]) {
            Ok((option, consumed)) => {
                options.push(option);
                offset += consumed;
            }
            Err(e) => {
                // Stop on first error
                return Err(e);
            }
        }
    }

    Ok(options)
}

/// Serialize multiple options to byte vector
///
/// Concatenates serialized TLV options in sequence.
///
/// # Arguments
/// * `options` - Slice of options to serialize
///
/// # Returns
/// Byte vector containing all options in TLV format
#[must_use]
pub fn serialize_options(options: &[Dhcp6Option]) -> Vec<u8> {
    let mut buf = Vec::new();

    for option in options {
        buf.extend_from_slice(&option.serialize());
    }

    buf
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duid_llt_parse_serialize() {
        // DUID-LLT: type=1, hw_type=1 (Ethernet), time=12345678, MAC=00:11:22:33:44:55
        let duid_bytes = vec![
            0, 1, // type = 1 (DUID-LLT)
            0, 1, // hw_type = 1 (Ethernet)
            0, 0xBC, 0x61, 0x4E, // time = 12345678
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC
        ];

        let duid = Duid::parse(&duid_bytes).unwrap();
        assert!(matches!(duid, Duid::LLT { .. }));

        if let Duid::LLT {
            hw_type,
            time,
            ref ll_addr,
        } = duid
        {
            assert_eq!(hw_type, 1);
            assert_eq!(time, 12_345_678);
            assert_eq!(ll_addr, &vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        }

        // Test round-trip
        let serialized = duid.serialize();
        assert_eq!(serialized, duid_bytes);
    }

    #[test]
    fn test_duid_en_parse() {
        // DUID-EN: type=2, enterprise=9, identifier=[1,2,3,4]
        let duid_bytes = vec![
            0, 2, // type = 2 (DUID-EN)
            0, 0, 0, 9, // enterprise = 9
            1, 2, 3, 4, // identifier
        ];

        let duid = Duid::parse(&duid_bytes).unwrap();
        assert!(matches!(duid, Duid::EN { .. }));

        if let Duid::EN {
            enterprise,
            identifier,
        } = duid
        {
            assert_eq!(enterprise, 9);
            assert_eq!(identifier, vec![1, 2, 3, 4]);
        }
    }

    #[test]
    fn test_duid_ll_parse() {
        // DUID-LL: type=3, hw_type=1, MAC=aa:bb:cc:dd:ee:ff
        let duid_bytes = vec![
            0, 3, // type = 3 (DUID-LL)
            0, 1, // hw_type = 1
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // MAC
        ];

        let duid = Duid::parse(&duid_bytes).unwrap();
        assert!(matches!(duid, Duid::LL { .. }));

        if let Duid::LL { hw_type, ll_addr } = duid {
            assert_eq!(hw_type, 1);
            assert_eq!(ll_addr, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        }
    }

    #[test]
    fn test_ia_na_parse() {
        // IA_NA: IAID=42, T1=1000, T2=2000
        let mut data = Vec::new();
        data.write_u32::<BigEndian>(42).unwrap();
        data.write_u32::<BigEndian>(1000).unwrap();
        data.write_u32::<BigEndian>(2000).unwrap();

        let ia_na = IaNa::parse(&data).unwrap();
        assert_eq!(ia_na.iaid, 42);
        assert_eq!(ia_na.t1, 1000);
        assert_eq!(ia_na.t2, 2000);
    }

    #[test]
    fn test_ia_addr_parse() {
        // IAADDR: address=::1, preferred=3600, valid=7200
        let mut data = Vec::new();
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        data.write_u32::<BigEndian>(3600).unwrap();
        data.write_u32::<BigEndian>(7200).unwrap();

        let ia_addr = IaAddr::parse(&data).unwrap();
        assert_eq!(ia_addr.address, Ipv6Addr::LOCALHOST);
        assert_eq!(ia_addr.preferred_lifetime, 3600);
        assert_eq!(ia_addr.valid_lifetime, 7200);
    }

    #[test]
    fn test_status_code_parse() {
        // StatusCode: code=0, message="Success"
        let mut data = Vec::new();
        data.write_u16::<BigEndian>(0).unwrap();
        data.extend_from_slice(b"Success");

        let status = StatusCode::parse(&data).unwrap();
        assert_eq!(status.code, 0);
        assert_eq!(status.message, "Success");
        assert!(status.is_success());
    }

    #[test]
    fn test_option_rapid_commit_parse() {
        // RAPID_COMMIT option: code=14, length=0
        let data = vec![0, 14, 0, 0];

        let (option, consumed) = Dhcp6Option::parse(&data).unwrap();
        assert_eq!(consumed, 4);
        assert!(matches!(option, Dhcp6Option::RapidCommit));
    }

    #[test]
    fn test_option_preference_parse() {
        // PREFERENCE option: code=7, length=1, value=255
        let data = vec![0, 7, 0, 1, 255];

        let (option, consumed) = Dhcp6Option::parse(&data).unwrap();
        assert_eq!(consumed, 5);

        if let Dhcp6Option::Preference(pref) = option {
            assert_eq!(pref, 255);
        } else {
            panic!("Expected Preference option");
        }
    }

    #[test]
    fn test_parse_multiple_options() {
        // Two options: RAPID_COMMIT (14, 0 bytes) + PREFERENCE (7, 1 byte = 128)
        let data = vec![
            0, 14, 0, 0, // RAPID_COMMIT
            0, 7, 0, 1, 128, // PREFERENCE = 128
        ];

        let options = parse_options(&data).unwrap();
        assert_eq!(options.len(), 2);

        assert!(matches!(options[0], Dhcp6Option::RapidCommit));
        assert!(matches!(options[1], Dhcp6Option::Preference(128)));
    }

    #[test]
    fn test_serialize_option_round_trip() {
        let option = Dhcp6Option::Preference(200);
        let serialized = option.serialize();

        let (parsed, _) = Dhcp6Option::parse(&serialized).unwrap();

        if let Dhcp6Option::Preference(pref) = parsed {
            assert_eq!(pref, 200);
        } else {
            panic!("Expected Preference option");
        }
    }
}
