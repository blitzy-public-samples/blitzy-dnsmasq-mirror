// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// EDNS0 (Extension Mechanisms for DNS) support
//
// Translated from: src/edns0.c

//! EDNS0 extension mechanisms for DNS (RFC 6891)
//!
//! This module implements comprehensive support for DNS Extension Mechanisms (EDNS0) as defined
//! in RFC 6891. EDNS0 extends the DNS protocol to support:
//! - Larger UDP payloads beyond the original 512-byte limit
//! - Extended response codes (16-bit instead of 4-bit)
//! - DNSSEC OK (DO) bit for signaling DNSSEC support
//! - Arbitrary extension options in OPT pseudo-records
//!
//! # EDNS0 OPT Record Format
//!
//! The OPT pseudo-resource record uses the DNS RR format with special semantics:
//! - NAME: Root domain (empty)
//! - TYPE: OPT (41)
//! - CLASS: UDP payload size (instead of record class)
//! - TTL: Extended RCODE and flags (instead of time-to-live)
//! - RDATA: EDNS options as TLV (Type-Length-Value) tuples
//!
//! # Supported EDNS Options
//!
//! - **Client Subnet (RFC 7871, code 8)**: IP address prefix for geographic DNS responses
//! - **DNS Cookies (RFC 7873, code 10)**: Lightweight transaction security
//! - **Padding (RFC 7830, code 12)**: DNS message padding for privacy
//! - **Extended Errors (RFC 8914, code 15)**: Enhanced error reporting
//! - **Device ID options**: Cisco Umbrella and NOM device identification
//!
//! # Memory Safety
//!
//! The C implementation in edns0.c uses manual buffer manipulation with pointer arithmetic
//! and explicit bounds checking. This Rust implementation provides compile-time safety through:
//! - Slice bounds checking preventing buffer overflows
//! - Type-safe option parsing with validated enums
//! - UTF-8 validation for text fields
//! - Automatic memory management eliminating use-after-free bugs
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use crate::dns::edns::{OptRecord, EdnsOption, ClientSubnetInfo};
//! use std::net::IpAddr;
//!
//! // Create an OPT record with client subnet option
//! let client_subnet = ClientSubnetInfo {
//!     family: 1, // IPv4
//!     source_prefix: 24,
//!     scope_prefix: 0,
//!     address: IpAddr::from([192, 168, 1, 0]),
//! };
//!
//! let opt = OptRecord::new()
//!     .with_udp_size(4096)
//!     .with_dnssec_ok(true)
//!     .with_option(EdnsOption::ClientSubnet(client_subnet));
//!
//! // Check if DNSSEC is supported
//! if supports_dnssec(Some(&opt)) {
//!     // Handle DNSSEC validation
//! }
//!
//! // Get maximum UDP payload size
//! let max_size = max_udp_payload(Some(&opt)); // Returns 4096
//! ```

use crate::constants::DNS_PACKET_SIZE;
use crate::dns::protocol::ResourceRecord;
use crate::types::errors::{DnsError, DnsmasqError};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use tracing::{debug, error, warn};

// =============================================================================
// Error Types
// =============================================================================

/// EDNS0-specific errors
///
/// Errors that can occur during EDNS0 OPT record parsing, option processing,
/// and validation. These errors are distinct from general DNS protocol errors
/// and provide detailed context for EDNS0 extension failures.
#[derive(Debug, Error)]
pub enum EdnsError {
    /// Malformed EDNS option data (invalid length or format)
    #[error("Malformed EDNS option: {0}")]
    MalformedOption(String),

    /// Invalid UDP payload size (too small or too large)
    #[error("Invalid payload size: {size} (must be between {min} and {max})")]
    InvalidPayloadSize {
        /// The invalid size value
        size: u16,
        /// Minimum acceptable size
        min: u16,
        /// Maximum acceptable size
        max: u16,
    },

    /// Unsupported EDNS version
    #[error("Unsupported EDNS version: {0} (only version 0 is supported)")]
    UnsupportedVersion(u8),

    /// Invalid IP address in client subnet option
    #[error("Invalid IP address in client subnet: {0}")]
    InvalidAddress(String),

    /// DNS packet too short to contain valid EDNS data
    #[error("Packet too short: need {needed} bytes, have {available}")]
    PacketTooShort {
        /// Number of bytes needed
        needed: usize,
        /// Number of bytes available
        available: usize,
    },

    /// DNS cookie validation failed
    #[error("Cookie validation failed: {0}")]
    CookieValidationFailed(String),

    /// Extended error information from upstream
    #[error("Extended DNS error {info_code}: {extra_text}")]
    ExtendedDnsError {
        /// RFC 8914 extended error code
        info_code: u16,
        /// Human-readable error description
        extra_text: String,
    },
}

/// Result type for EDNS operations
pub type EdnsResult<T> = Result<T, EdnsError>;

// =============================================================================
// Data Structures
// =============================================================================

/// Client Subnet information (RFC 7871)
///
/// The EDNS Client Subnet (ECS) option carries a portion of the client's IP address
/// in DNS queries, allowing authoritative servers to provide geographically relevant
/// responses. This is commonly used for CDN selection and geographic load balancing.
///
/// # Wire Format
///
/// ```text
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// |                            FAMILY                             |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// | SOURCE PREFIX-LENGTH  | SCOPE PREFIX-LENGTH   |               |
/// +---+---+---+---+---+---+---+---+---+---+---+---+               /
/// /                          ADDRESS...                           /
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// ```
///
/// # Privacy Considerations
///
/// The source prefix length allows truncating the client address for privacy.
/// Typical values: 24 bits for IPv4, 56 bits for IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubnetInfo {
    /// Address family (1 = IPv4, 2 = IPv6)
    pub family: u16,
    /// Number of significant bits in source address (for privacy)
    pub source_prefix: u8,
    /// Number of significant bits in scope (response from server)
    pub scope_prefix: u8,
    /// Client IP address (truncated to `source_prefix` bits)
    pub address: IpAddr,
}

impl ClientSubnetInfo {
    /// Create new client subnet info for IPv4 address
    #[must_use]
    pub fn new_v4(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            family: 1,
            source_prefix: prefix_len.min(32),
            scope_prefix: 0,
            address: IpAddr::V4(addr),
        }
    }

    /// Create new client subnet info for IPv6 address
    #[must_use]
    pub fn new_v6(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            family: 2,
            source_prefix: prefix_len.min(128),
            scope_prefix: 0,
            address: IpAddr::V6(addr),
        }
    }

    /// Parse client subnet info from wire format
    ///
    /// # Errors
    ///
    /// Returns `EdnsError` if the data is malformed or too short.
    pub fn from_bytes(data: &[u8]) -> EdnsResult<Self> {
        if data.len() < 4 {
            return Err(EdnsError::PacketTooShort {
                needed: 4,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let family = cursor
            .read_u16::<NetworkEndian>()
            .map_err(|e| EdnsError::MalformedOption(format!("Failed to read family: {e}")))?;
        let source_prefix = cursor.read_u8().map_err(|e| {
            EdnsError::MalformedOption(format!("Failed to read source prefix: {e}"))
        })?;
        let scope_prefix = cursor
            .read_u8()
            .map_err(|e| EdnsError::MalformedOption(format!("Failed to read scope prefix: {e}")))?;

        let address = match family {
            1 => {
                // IPv4
                let addr_len = source_prefix.div_ceil(8) as usize;
                if data.len() < 4 + addr_len {
                    return Err(EdnsError::PacketTooShort {
                        needed: 4 + addr_len,
                        available: data.len(),
                    });
                }
                let mut addr_bytes = [0u8; 4];
                addr_bytes[..addr_len].copy_from_slice(&data[4..4 + addr_len]);
                IpAddr::V4(Ipv4Addr::from(addr_bytes))
            }
            2 => {
                // IPv6
                let addr_len = source_prefix.div_ceil(8) as usize;
                if data.len() < 4 + addr_len {
                    return Err(EdnsError::PacketTooShort {
                        needed: 4 + addr_len,
                        available: data.len(),
                    });
                }
                let mut addr_bytes = [0u8; 16];
                addr_bytes[..addr_len].copy_from_slice(&data[4..4 + addr_len]);
                IpAddr::V6(Ipv6Addr::from(addr_bytes))
            }
            _ => {
                return Err(EdnsError::InvalidAddress(format!(
                    "Unsupported address family: {family}"
                )));
            }
        };

        Ok(Self {
            family,
            source_prefix,
            scope_prefix,
            address,
        })
    }

    /// Serialize client subnet info to wire format
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u16(self.family);
        buf.put_u8(self.source_prefix);
        buf.put_u8(self.scope_prefix);

        // Truncate address to source_prefix bits
        let addr_len = self.source_prefix.div_ceil(8) as usize;
        match self.address {
            IpAddr::V4(addr) => {
                let bytes = addr.octets();
                buf.extend_from_slice(&bytes[..addr_len.min(4)]);
            }
            IpAddr::V6(addr) => {
                let bytes = addr.octets();
                buf.extend_from_slice(&bytes[..addr_len.min(16)]);
            }
        }

        buf.to_vec()
    }
}

/// Extended DNS Error information (RFC 8914)
///
/// Provides detailed error information beyond traditional DNS RCODEs.
/// This allows servers to communicate specific reasons for query failures.
///
/// # Common Error Codes
///
/// - 0: Other Error
/// - 1: Unsupported DNSKEY Algorithm
/// - 2: Unsupported DS Digest Type
/// - 6: DNSSEC Bogus
/// - 9: DNSSEC Indeterminate
/// - 18: Prohibited
/// - 22: Not Authoritative
/// - 23: Not Supported
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedErrorInfo {
    /// RFC 8914 error information code
    pub info_code: u16,
    /// Extra textual explanation (UTF-8)
    pub extra_text: String,
}

impl ExtendedErrorInfo {
    /// Create new extended error info
    #[must_use]
    pub fn new(info_code: u16, extra_text: String) -> Self {
        Self {
            info_code,
            extra_text,
        }
    }

    /// Parse extended error info from wire format
    ///
    /// # Errors
    ///
    /// Returns `EdnsError` if the data is malformed or too short.
    pub fn from_bytes(data: &[u8]) -> EdnsResult<Self> {
        if data.len() < 2 {
            return Err(EdnsError::PacketTooShort {
                needed: 2,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let info_code = cursor
            .read_u16::<NetworkEndian>()
            .map_err(|e| EdnsError::MalformedOption(format!("Failed to read info code: {e}")))?;

        let extra_text = if data.len() > 2 {
            String::from_utf8(data[2..].to_vec()).map_err(|e| {
                EdnsError::MalformedOption(format!("Invalid UTF-8 in extra text: {e}"))
            })?
        } else {
            String::new()
        };

        Ok(Self {
            info_code,
            extra_text,
        })
    }

    /// Serialize extended error info to wire format
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u16(self.info_code);
        buf.extend_from_slice(self.extra_text.as_bytes());
        buf.to_vec()
    }
}

/// EDNS OPT pseudo-record (RFC 6891)
///
/// The OPT record uses the DNS resource record format but with special semantics:
/// - NAME is the root domain (empty)
/// - TYPE is OPT (41)
/// - CLASS field contains the UDP payload size
/// - TTL field contains extended RCODE, version, and flags
/// - RDATA contains EDNS options
///
/// # Builder Pattern
///
/// The OPT record uses a builder pattern for construction:
///
/// ```rust,ignore
/// let opt = OptRecord::new()
///     .with_udp_size(4096)
///     .with_dnssec_ok(true)
///     .with_option(EdnsOption::Padding { length: 100 });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptRecord {
    /// Sender's UDP payload size (advertises maximum UDP response size)
    pub udp_payload_size: u16,
    /// Extended RCODE (upper 8 bits of 12-bit extended RCODE)
    pub extended_rcode: u8,
    /// EDNS version (must be 0 per RFC 6891)
    pub version: u8,
    /// DNSSEC OK and other flags
    pub dnssec_ok: bool,
    /// EDNS options (variable-length)
    pub options: Vec<EdnsOption>,
}

impl OptRecord {
    /// Create a new OPT record with default values
    ///
    /// Default values per RFC 6891:
    /// - UDP payload size: 1232 bytes (DNS Flag Day 2020 recommendation)
    /// - Extended RCODE: 0
    /// - Version: 0 (only supported version)
    /// - DNSSEC OK: false
    /// - No options
    #[must_use]
    pub fn new() -> Self {
        Self {
            udp_payload_size: 1232, // RFC 6891 recommended minimum for IPv6
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }

    /// Set the UDP payload size (builder pattern)
    #[must_use]
    pub fn with_udp_size(mut self, size: u16) -> Self {
        self.udp_payload_size = size;
        self
    }

    /// Set DNSSEC OK flag (builder pattern)
    #[must_use]
    pub fn with_dnssec_ok(mut self, value: bool) -> Self {
        self.dnssec_ok = value;
        self
    }

    /// Add an EDNS option (builder pattern)
    #[must_use]
    pub fn with_option(mut self, option: EdnsOption) -> Self {
        self.options.push(option);
        self
    }

    /// Parse OPT record from wire format
    ///
    /// Expects the RDATA section of an OPT record (after NAME, TYPE, CLASS, TTL, RDLEN).
    /// The CLASS and TTL fields should be parsed externally and passed to construct the
    /// `OptRecord` structure.
    ///
    /// # Errors
    ///
    /// Returns `EdnsError` if the version is unsupported or the RDATA is malformed.
    pub fn from_bytes(udp_payload_size: u16, ttl_bytes: u32, rdata: &[u8]) -> EdnsResult<Self> {
        // Extract extended RCODE, version, and flags from TTL field
        let extended_rcode = ((ttl_bytes >> 24) & 0xFF) as u8;
        let version = ((ttl_bytes >> 16) & 0xFF) as u8;
        let flags = (ttl_bytes & 0xFFFF) as u16;
        let dnssec_ok = (flags & 0x8000) != 0;

        // Version must be 0
        if version != 0 {
            return Err(EdnsError::UnsupportedVersion(version));
        }

        // Parse EDNS options from RDATA
        let options = Self::parse_options(rdata)?;

        Ok(Self {
            udp_payload_size,
            extended_rcode,
            version,
            dnssec_ok,
            options,
        })
    }

    /// Serialize OPT record to wire format
    ///
    /// Returns `(udp_payload_size` for CLASS, `ttl_bytes`, `rdata)`
    #[must_use]
    pub fn to_bytes(&self) -> (u16, u32, Vec<u8>) {
        // Construct TTL field: extended_rcode | version | flags
        let flags = if self.dnssec_ok { 0x8000u16 } else { 0u16 };
        let ttl_bytes = (u32::from(self.extended_rcode) << 24)
            | (u32::from(self.version) << 16)
            | u32::from(flags);

        // Serialize all options
        let mut rdata = BytesMut::new();
        for option in &self.options {
            let option_data = option.to_bytes();
            rdata.put_u16(option.code());
            rdata.put_u16(u16::try_from(option_data.len()).unwrap_or(u16::MAX));
            rdata.extend_from_slice(&option_data);
        }

        (self.udp_payload_size, ttl_bytes, rdata.to_vec())
    }

    /// Parse EDNS options from RDATA
    ///
    /// # Errors
    ///
    /// Returns `EdnsError` if the RDATA is malformed or too short.
    fn parse_options(mut rdata: &[u8]) -> EdnsResult<Vec<EdnsOption>> {
        let mut options = Vec::new();

        while rdata.len() >= 4 {
            let mut cursor = Cursor::new(rdata);
            let code = cursor.read_u16::<NetworkEndian>().map_err(|e| {
                EdnsError::MalformedOption(format!("Failed to read option code: {e}"))
            })?;
            let length = cursor.read_u16::<NetworkEndian>().map_err(|e| {
                EdnsError::MalformedOption(format!("Failed to read option length: {e}"))
            })?;

            if rdata.len() < 4 + length as usize {
                return Err(EdnsError::PacketTooShort {
                    needed: 4 + length as usize,
                    available: rdata.len(),
                });
            }

            let option_data = &rdata[4..4 + length as usize];
            let option = EdnsOption::from_code_and_data(code, option_data)?;
            options.push(option);

            rdata = &rdata[4 + length as usize..];
        }

        Ok(options)
    }
}

impl Default for OptRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// EDNS option codes (RFC 6891 and extensions)
///
/// Standard EDNS option codes as assigned by IANA.
pub mod option_codes {
    /// EDNS Client Subnet (RFC 7871)
    pub const CLIENT_SUBNET: u16 = 8;
    /// DNS Cookie (RFC 7873)
    pub const COOKIE: u16 = 10;
    /// Padding (RFC 7830)
    pub const PADDING: u16 = 12;
    /// Chain Query (RFC 7901)
    pub const CHAIN: u16 = 13;
    /// Key Tag (RFC 8145)
    pub const KEY_TAG: u16 = 14;
    /// Extended DNS Error (RFC 8914)
    pub const EXTENDED_ERROR: u16 = 15;
    /// Cisco Umbrella device identification
    pub const UMBRELLA: u16 = 20292;
    /// NOM device ID (Apple)
    pub const NOM_DEVICE_ID: u16 = 65073;
    /// NOM CPE ID
    pub const NOM_CPE_ID: u16 = 65074;
}

/// EDNS option types
///
/// Represents the various EDNS options that can be included in an OPT record.
/// Each option has a specific wire format defined by its corresponding RFC.
///
/// # Option Categories
///
/// - **Geographic**: `ClientSubnet` for location-aware responses
/// - **Security**: Cookie for transaction authentication, `ExtendedError` for detailed diagnostics
/// - **Privacy**: Padding for traffic analysis resistance
/// - **DNSSEC**: `KeyTag` for algorithm signaling
/// - **Device Tracking**: Umbrella and NOM options for device identification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdnsOption {
    /// Client Subnet (RFC 7871, code 8)
    ///
    /// Carries client IP address prefix for geographic DNS responses.
    /// Enables CDN selection and geographically relevant answers.
    ClientSubnet(ClientSubnetInfo),

    /// DNS Cookie (RFC 7873, code 10)
    ///
    /// Provides lightweight transaction security against off-path attacks.
    /// Client cookie: 8 bytes (required)
    /// Server cookie: 8-32 bytes (optional, provided by server)
    Cookie {
        /// Client cookie (8 bytes)
        client: [u8; 8],
        /// Optional server cookie (8-32 bytes)
        server: Option<Vec<u8>>,
    },

    /// Padding (RFC 7830, code 12)
    ///
    /// Adds padding to DNS messages for traffic analysis resistance.
    /// Used primarily with DNS-over-TLS/HTTPS for privacy.
    Padding {
        /// Padding length in bytes
        length: usize,
    },

    /// Extended DNS Error (RFC 8914, code 15)
    ///
    /// Provides detailed error information beyond traditional RCODEs.
    /// Helps diagnose DNSSEC validation failures and other issues.
    ExtendedError(ExtendedErrorInfo),

    /// Cisco Umbrella device identification (code 20292)
    ///
    /// Device ID for Umbrella security filtering.
    /// Format: 4-byte device ID + optional org ID
    Umbrella {
        /// Device identifier
        device_id: Vec<u8>,
        /// Optional organization identifier
        org_id: Option<Vec<u8>>,
    },

    /// Unknown or unsupported option (pass-through)
    ///
    /// Preserves options we don't explicitly handle.
    /// RFC 6891 requires forwarding unknown options unchanged.
    Unknown {
        /// Option code
        code: u16,
        /// Option data
        data: Vec<u8>,
    },
}

impl EdnsOption {
    /// Get the option code for this option
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            EdnsOption::ClientSubnet(_) => option_codes::CLIENT_SUBNET,
            EdnsOption::Cookie { .. } => option_codes::COOKIE,
            EdnsOption::Padding { .. } => option_codes::PADDING,
            EdnsOption::ExtendedError(_) => option_codes::EXTENDED_ERROR,
            EdnsOption::Umbrella { .. } => option_codes::UMBRELLA,
            EdnsOption::Unknown { code, .. } => *code,
        }
    }

    /// Parse EDNS option from option code and data
    ///
    /// # Errors
    ///
    /// Returns `EdnsError` if the data is malformed or too short for the specified option type.
    pub fn from_code_and_data(code: u16, data: &[u8]) -> EdnsResult<Self> {
        match code {
            option_codes::CLIENT_SUBNET => {
                let info = ClientSubnetInfo::from_bytes(data)?;
                Ok(EdnsOption::ClientSubnet(info))
            }
            option_codes::COOKIE => {
                if data.len() < 8 {
                    let len = data.len();
                    return Err(EdnsError::MalformedOption(format!(
                        "Cookie too short: {len} bytes (need at least 8)"
                    )));
                }
                let mut client = [0u8; 8];
                client.copy_from_slice(&data[0..8]);
                let server = if data.len() > 8 {
                    Some(data[8..].to_vec())
                } else {
                    None
                };
                Ok(EdnsOption::Cookie { client, server })
            }
            option_codes::PADDING => Ok(EdnsOption::Padding { length: data.len() }),
            option_codes::EXTENDED_ERROR => {
                let info = ExtendedErrorInfo::from_bytes(data)?;
                Ok(EdnsOption::ExtendedError(info))
            }
            option_codes::UMBRELLA => {
                if data.len() < 4 {
                    let len = data.len();
                    return Err(EdnsError::MalformedOption(format!(
                        "Umbrella option too short: {len} bytes (need at least 4)"
                    )));
                }
                let device_id = data[0..4].to_vec();
                let org_id = if data.len() > 4 {
                    Some(data[4..].to_vec())
                } else {
                    None
                };
                Ok(EdnsOption::Umbrella { device_id, org_id })
            }
            _ => {
                // Unknown option - preserve as-is for forwarding
                debug!(
                    "Unknown EDNS option code {code}, preserving {} bytes",
                    data.len()
                );
                Ok(EdnsOption::Unknown {
                    code,
                    data: data.to_vec(),
                })
            }
        }
    }

    /// Serialize EDNS option to wire format (without code and length headers)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            EdnsOption::ClientSubnet(info) => info.to_bytes(),
            EdnsOption::Cookie { client, server } => {
                let mut buf = BytesMut::new();
                buf.extend_from_slice(client);
                if let Some(server_cookie) = server {
                    buf.extend_from_slice(server_cookie);
                }
                buf.to_vec()
            }
            EdnsOption::Padding { length } => vec![0u8; *length],
            EdnsOption::ExtendedError(info) => info.to_bytes(),
            EdnsOption::Umbrella { device_id, org_id } => {
                let mut buf = BytesMut::new();
                buf.extend_from_slice(device_id);
                if let Some(org) = org_id {
                    buf.extend_from_slice(org);
                }
                buf.to_vec()
            }
            EdnsOption::Unknown { data, .. } => data.clone(),
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Find OPT record in a DNS message
///
/// Searches the additional section of a DNS message for an EDNS0 OPT record.
/// Per RFC 6891, there must be at most one OPT record in a DNS message, and it
/// should be placed in the additional section.
///
/// # Arguments
///
/// * `additional` - Slice of resource records from the additional section
///
/// # Returns
///
/// Reference to the OPT record if found, None otherwise
///
/// # Example
///
/// ```rust,ignore
/// use crate::dns::edns::find_opt_record;
/// use crate::dns::protocol::DnsMessage;
///
/// let message = DnsMessage::parse(&packet)?;
/// if let Some(opt) = find_opt_record(&message.additional) {
///     println!("UDP payload size: {}", opt.udp_payload_size);
/// }
/// ```
#[must_use]
pub fn find_opt_record(additional: &[ResourceRecord]) -> Option<&ResourceRecord> {
    additional
        .iter()
        .find(|rr| matches!(rr, ResourceRecord::OPT { .. }))
}

/// Add OPT record to a DNS message
///
/// Adds or replaces an EDNS0 OPT record in the additional section of a DNS message.
/// If an OPT record already exists, it is replaced. Otherwise, a new OPT record is
/// appended to the additional section.
///
/// # Arguments
///
/// * `additional` - Mutable reference to additional section records
/// * `udp_payload_size` - Sender's UDP payload size (typically 4096)
/// * `dnssec_ok` - Whether to set the DNSSEC OK (DO) bit
/// * `options` - EDNS options to include in the OPT record
///
/// # Example
///
/// ```rust,ignore
/// use crate::dns::edns::{add_opt_record, EdnsOption};
/// use crate::dns::protocol::DnsMessage;
///
/// let mut message = DnsMessage::new();
/// add_opt_record(&mut message.additional, 4096, true, vec![
///     EdnsOption::Padding { length: 100 }
/// ]);
/// ```
pub fn add_opt_record(
    additional: &mut Vec<ResourceRecord>,
    udp_payload_size: u16,
    dnssec_ok: bool,
    options: &[EdnsOption],
) {
    // Remove existing OPT record if present
    additional.retain(|rr| !matches!(rr, ResourceRecord::OPT { .. }));

    // Create new OPT record
    let opt_record = ResourceRecord::OPT {
        udp_payload_size,
        extended_rcode: 0,
        version: 0,
        dnssec_ok,
        data: {
            // Serialize options
            let mut buf = BytesMut::new();
            for option in options {
                let option_data = option.to_bytes();
                buf.put_u16(option.code());
                buf.put_u16(u16::try_from(option_data.len()).unwrap_or(0));
                buf.extend_from_slice(&option_data);
            }
            buf.to_vec()
        },
    };

    additional.push(opt_record);
    debug!(
        "Added OPT record: UDP size {}, DNSSEC {}, {} options",
        udp_payload_size,
        dnssec_ok,
        options.len()
    );
}

/// Get maximum UDP payload size from OPT record
///
/// Returns the maximum UDP payload size advertised in the OPT record, or the
/// standard DNS packet size (512 bytes) if no OPT record is present.
///
/// # Arguments
///
/// * `opt` - Optional reference to OPT record
///
/// # Returns
///
/// Maximum UDP payload size in bytes
///
/// # Example
///
/// ```rust,ignore
/// use crate::dns::edns::{find_opt_record, max_udp_payload};
/// use crate::dns::protocol::DnsMessage;
///
/// let message = DnsMessage::parse(&packet)?;
/// let opt = find_opt_record(&message.additional);
/// let max_size = max_udp_payload(opt.and_then(|rr| {
///     if let ResourceRecord::OPT { udp_payload_size, .. } = rr {
///         Some(*udp_payload_size)
///     } else {
///         None
///     }
/// }));
/// ```
#[must_use]
pub fn max_udp_payload(opt_payload_size: Option<u16>) -> usize {
    if let Some(size) = opt_payload_size {
        // Cap at reasonable maximum to prevent abuse
        size.min(16384) as usize
    } else {
        // Standard DNS packet size without EDNS0
        DNS_PACKET_SIZE
    }
}

/// Check if DNSSEC is supported based on OPT record
///
/// Returns true if an OPT record is present and the DNSSEC OK (DO) bit is set.
/// The DO bit indicates that the sender is interested in receiving DNSSEC records
/// and can perform DNSSEC validation.
///
/// # Arguments
///
/// * `dnssec_ok` - Optional DNSSEC OK flag from OPT record
///
/// # Returns
///
/// true if DNSSEC is supported, false otherwise
///
/// # Example
///
/// ```rust,ignore
/// use crate::dns::edns::{find_opt_record, supports_dnssec};
/// use crate::dns::protocol::{DnsMessage, ResourceRecord};
///
/// let message = DnsMessage::parse(&packet)?;
/// let opt = find_opt_record(&message.additional);
/// let dnssec_flag = opt.and_then(|rr| {
///     if let ResourceRecord::OPT { dnssec_ok, .. } = rr {
///         Some(*dnssec_ok)
///     } else {
///         None
///     }
/// });
///
/// if supports_dnssec(dnssec_flag) {
///     // Include DNSSEC records in response
/// }
/// ```
#[must_use]
pub fn supports_dnssec(dnssec_ok: Option<bool>) -> bool {
    dnssec_ok.unwrap_or(false)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opt_record_default() {
        let opt = OptRecord::new();
        assert_eq!(opt.udp_payload_size, 1232);
        assert_eq!(opt.version, 0);
        assert_eq!(opt.extended_rcode, 0);
        assert!(!opt.dnssec_ok);
        assert!(opt.options.is_empty());
    }

    #[test]
    fn test_opt_record_builder() {
        let opt = OptRecord::new()
            .with_udp_size(4096)
            .with_dnssec_ok(true)
            .with_option(EdnsOption::Padding { length: 100 });

        assert_eq!(opt.udp_payload_size, 4096);
        assert!(opt.dnssec_ok);
        assert_eq!(opt.options.len(), 1);
    }

    #[test]
    fn test_opt_record_serialization() {
        let opt = OptRecord::new().with_udp_size(4096).with_dnssec_ok(true);

        let (udp_size, ttl_bytes, rdata) = opt.to_bytes();
        assert_eq!(udp_size, 4096);
        // Check DO bit is set in flags (lower 16 bits of TTL)
        assert_eq!(ttl_bytes & 0xFFFF, 0x8000);
        assert!(rdata.is_empty()); // No options
    }

    #[test]
    fn test_client_subnet_ipv4() {
        let info = ClientSubnetInfo::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24);
        assert_eq!(info.family, 1);
        assert_eq!(info.source_prefix, 24);
        assert_eq!(info.scope_prefix, 0);

        let bytes = info.to_bytes();
        assert_eq!(bytes[0..2], [0, 1]); // Family
        assert_eq!(bytes[2], 24); // Source prefix
        assert_eq!(bytes[3], 0); // Scope prefix
        assert_eq!(bytes[4..7], [192, 168, 1]); // Address (truncated to 3 bytes)

        let parsed = ClientSubnetInfo::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.family, info.family);
        assert_eq!(parsed.source_prefix, info.source_prefix);
    }

    #[test]
    fn test_client_subnet_ipv6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let info = ClientSubnetInfo::new_v6(addr, 48);
        assert_eq!(info.family, 2);
        assert_eq!(info.source_prefix, 48);

        let bytes = info.to_bytes();
        assert_eq!(bytes[0..2], [0, 2]); // Family IPv6
        assert_eq!(bytes[2], 48); // Source prefix
        assert_eq!(bytes.len(), 4 + 6); // Header + 6 bytes for /48

        let parsed = ClientSubnetInfo::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.family, 2);
        assert_eq!(parsed.source_prefix, 48);
    }

    #[test]
    fn test_extended_error_info() {
        let info = ExtendedErrorInfo::new(6, "DNSSEC Bogus".to_string());
        assert_eq!(info.info_code, 6);
        assert_eq!(info.extra_text, "DNSSEC Bogus");

        let bytes = info.to_bytes();
        assert_eq!(bytes[0..2], [0, 6]); // Info code

        let parsed = ExtendedErrorInfo::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.info_code, 6);
        assert_eq!(parsed.extra_text, "DNSSEC Bogus");
    }

    #[test]
    fn test_edns_option_codes() {
        let client_subnet =
            EdnsOption::ClientSubnet(ClientSubnetInfo::new_v4(Ipv4Addr::new(192, 168, 1, 0), 24));
        assert_eq!(client_subnet.code(), option_codes::CLIENT_SUBNET);

        let cookie = EdnsOption::Cookie {
            client: [0u8; 8],
            server: None,
        };
        assert_eq!(cookie.code(), option_codes::COOKIE);

        let padding = EdnsOption::Padding { length: 100 };
        assert_eq!(padding.code(), option_codes::PADDING);

        let ext_error = EdnsOption::ExtendedError(ExtendedErrorInfo::new(0, String::new()));
        assert_eq!(ext_error.code(), option_codes::EXTENDED_ERROR);
    }

    #[test]
    fn test_edns_option_cookie_parsing() {
        let client_cookie = [1, 2, 3, 4, 5, 6, 7, 8];
        let server_cookie = vec![9, 10, 11, 12, 13, 14, 15, 16];
        let mut data = Vec::new();
        data.extend_from_slice(&client_cookie);
        data.extend_from_slice(&server_cookie);

        let option = EdnsOption::from_code_and_data(option_codes::COOKIE, &data).unwrap();
        match option {
            EdnsOption::Cookie { client, server } => {
                assert_eq!(client, client_cookie);
                assert_eq!(server, Some(server_cookie));
            }
            _ => panic!("Expected Cookie option"),
        }
    }

    #[test]
    fn test_edns_option_padding() {
        let option = EdnsOption::from_code_and_data(option_codes::PADDING, &[0; 100]).unwrap();
        match option {
            EdnsOption::Padding { length } => {
                assert_eq!(length, 100);
            }
            _ => panic!("Expected Padding option"),
        }

        let bytes = option.to_bytes();
        assert_eq!(bytes.len(), 100);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_edns_option_unknown() {
        let data = vec![1, 2, 3, 4, 5];
        let option = EdnsOption::from_code_and_data(9999, &data).unwrap();
        match option {
            EdnsOption::Unknown {
                code,
                data: parsed_data,
            } => {
                assert_eq!(code, 9999);
                assert_eq!(parsed_data, data);
            }
            _ => panic!("Expected Unknown option"),
        }
    }

    #[test]
    fn test_opt_record_parse_with_options() {
        // Create OPT record with padding option
        let mut opt = OptRecord::new()
            .with_udp_size(4096)
            .with_dnssec_ok(true)
            .with_option(EdnsOption::Padding { length: 50 });

        let (udp_size, ttl_bytes, rdata) = opt.to_bytes();

        // Parse it back
        let parsed = OptRecord::from_bytes(udp_size, ttl_bytes, &rdata).unwrap();
        assert_eq!(parsed.udp_payload_size, 4096);
        assert!(parsed.dnssec_ok);
        assert_eq!(parsed.options.len(), 1);

        match &parsed.options[0] {
            EdnsOption::Padding { length } => assert_eq!(*length, 50),
            _ => panic!("Expected Padding option"),
        }
    }

    #[test]
    fn test_max_udp_payload() {
        // Without EDNS0
        assert_eq!(max_udp_payload(None), DNS_PACKET_SIZE);

        // With EDNS0
        assert_eq!(max_udp_payload(Some(4096)), 4096);

        // Cap at maximum
        assert_eq!(max_udp_payload(Some(32000)), 16384);
    }

    #[test]
    fn test_supports_dnssec() {
        assert!(!supports_dnssec(None));
        assert!(!supports_dnssec(Some(false)));
        assert!(supports_dnssec(Some(true)));
    }

    #[test]
    fn test_add_opt_record() {
        use crate::dns::protocol::ResourceRecord;

        let mut additional = Vec::new();

        // Add OPT record
        add_opt_record(&mut additional, 4096, true, &[]);
        assert_eq!(additional.len(), 1);
        match &additional[0] {
            ResourceRecord::OPT {
                udp_payload_size,
                dnssec_ok,
                ..
            } => {
                assert_eq!(*udp_payload_size, 4096);
                assert!(*dnssec_ok);
            }
            _ => panic!("Expected OPT record"),
        }

        // Replace existing OPT record
        add_opt_record(&mut additional, 1232, false, &[]);
        assert_eq!(additional.len(), 1);
        match &additional[0] {
            ResourceRecord::OPT {
                udp_payload_size,
                dnssec_ok,
                ..
            } => {
                assert_eq!(*udp_payload_size, 1232);
                assert!(!*dnssec_ok);
            }
            _ => panic!("Expected OPT record"),
        }
    }

    #[test]
    fn test_find_opt_record() {
        use crate::dns::protocol::ResourceRecord;

        let mut additional = vec![
            ResourceRecord::A {
                name: "example.com".to_string(),
                class: crate::dns::protocol::RecordClass::IN,
                ttl: 300,
                address: Ipv4Addr::new(192, 0, 2, 1),
            },
            ResourceRecord::OPT {
                udp_payload_size: 4096,
                extended_rcode: 0,
                version: 0,
                dnssec_ok: true,
                data: vec![],
            },
        ];

        let opt = find_opt_record(&additional);
        assert!(opt.is_some());
        match opt.unwrap() {
            ResourceRecord::OPT {
                udp_payload_size, ..
            } => {
                assert_eq!(*udp_payload_size, 4096);
            }
            _ => panic!("Expected OPT record"),
        }

        // Test with no OPT record
        additional.retain(|rr| !matches!(rr, ResourceRecord::OPT { .. }));
        assert!(find_opt_record(&additional).is_none());
    }

    #[test]
    fn test_edns_error_unsupported_version() {
        let result = OptRecord::from_bytes(4096, 0x0001_0000, &[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            EdnsError::UnsupportedVersion(v) => assert_eq!(v, 1),
            _ => panic!("Expected UnsupportedVersion error"),
        }
    }

    #[test]
    fn test_client_subnet_invalid_family() {
        let data = vec![0, 99, 24, 0]; // Invalid family 99
        let result = ClientSubnetInfo::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_cookie_too_short() {
        let data = vec![1, 2, 3]; // Only 3 bytes, need at least 8
        let result = EdnsOption::from_code_and_data(option_codes::COOKIE, &data);
        assert!(result.is_err());
    }
}
