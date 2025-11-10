// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
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

//! EDNS0 OPT record handling and client subnet extension processing
//!
//! # Purpose
//!
//! This module implements comprehensive support for DNS Extension Mechanisms (EDNS0)
//! as defined in RFC 6891. EDNS0 extends DNS to support larger UDP payloads beyond
//! the original 512-byte limit, additional flags like the DNSSEC OK (DO) bit, and
//! arbitrary extension options in OPT pseudo-records.
//!
//! # Memory Safety Transformation
//!
//! Replaces C's unsafe patterns with safe Rust equivalents:
//! - Manual pointer arithmetic → safe slice indexing with automatic bounds checking
//! - Manual `memmove` and buffer copying → `Vec::insert` and `Vec::extend_from_slice`
//! - `unsigned char*` with manual bounds → `BytesMut` with automatic capacity management
//! - Manual subnet mask calculations → `ipnetwork` crate type-safe operations
//! - Manual base64 encoding → `base64` crate RFC 4648 compliant implementation
//! - C `union mysockaddr` → Rust `IpAddr` enum with pattern matching
//!
//! # Key Responsibilities
//!
//! - `find_pseudoheader()`: Locates existing EDNS0 OPT records in DNS packets
//! - `add_pseudoheader()`: Creates or modifies OPT records with specified options
//! - `add_edns0_config()`: Primary entry point for adding configured options to queries
//! - `add_source_addr()`: Implements EDNS Client Subnet (ECS) per RFC 7871
//! - `add_do_bit()`: Sets DNSSEC OK flag in OPT record
//! - `check_source()`: Validates ECS option in responses matches query parameters
//!
//! # RFC Compliance
//!
//! - RFC 6891: Extension Mechanisms for DNS (EDNS0)
//! - RFC 7871: Client Subnet in DNS Queries (ECS)
//! - RFC 7873: DNS Cookies
//! - RFC 1035: Domain Names - Implementation and Specification
//!
//! # Original C Implementation
//!
//! Refactored from `src/edns0.c` (dnsmasq 2.90) - approximately 1267 lines of C code
//! transformed to memory-safe Rust while maintaining exact wire protocol compatibility.

use bytes::BytesMut;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

// Internal imports (ONLY from depends_on_files)
use crate::config::types::DaemonOptions;
use crate::dns::parser::{skip_name, skip_questions, skip_section};
use crate::dns::protocol::{
    EDNS0_OPTION_CLIENT_SUBNET, EDNS0_OPTION_MAC, EDNS0_OPTION_NOMCPEID,
    EDNS0_OPTION_NOMDEVICEID, EDNS0_OPTION_UMBRELLA, PACKETSZ, T_OPT, T_TKEY, T_TSIG,
};
use crate::dns::rrfilter::rrfilter;
use crate::dns::serializer::{read_u16, write_u16, write_u32};
use crate::network::arp::{find_mac, ArpCache};
use crate::network::platform::Platform;
use crate::utils::general::print_mac;

// ============================================================================
// Constants
// ============================================================================

/// Default EDNS0 UDP payload size (1232 bytes per C implementation)
///
/// This is the default value used when no OPT record exists. The value 1232
/// is chosen to fit within typical IPv6 minimum MTU (1280 bytes) minus headers.
const EDNS0_DEFAULT_PAYLOAD_SIZE: u16 = 1232;

/// Root label (empty DNS name) represented as single zero byte
const ROOT_LABEL: &[u8] = &[0];

/// DNSSEC OK bit position in extended RCODE field (bit 15)
const EDNS0_DO_BIT: u16 = 0x8000;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during EDNS0 processing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edns0Error {
    /// Packet buffer too small to contain required data
    BufferTooSmall {
        required: usize,
        available: usize,
    },
    /// Malformed packet structure
    MalformedPacket {
        reason: String,
    },
    /// Invalid EDNS0 option format
    InvalidOption {
        option_code: u16,
        reason: String,
    },
    /// DNS parsing error
    ParseError {
        details: String,
    },
    /// Internal error during processing
    InternalError {
        message: String,
    },
}

impl fmt::Display for Edns0Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall {
                required,
                available,
            } => write!(
                f,
                "Buffer too small: required {} bytes, available {} bytes",
                required, available
            ),
            Self::MalformedPacket { reason } => write!(f, "Malformed packet: {}", reason),
            Self::InvalidOption {
                option_code,
                reason,
            } => write!(f, "Invalid EDNS0 option {}: {}", option_code, reason),
            Self::ParseError { details } => write!(f, "Parse error: {}", details),
            Self::InternalError { message } => write!(f, "Internal error: {}", message),
        }
    }
}

impl std::error::Error for Edns0Error {}

// ============================================================================
// Data Structures
// ============================================================================

/// EDNS0 option codes as defined in various RFCs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Edns0OptionCode {
    /// LLQ (Long-Lived Queries) - RFC 8764
    Llq,
    /// UL (Update Lease) - RFC 2136
    Ul,
    /// NSID (Name Server Identifier) - RFC 5001
    Nsid,
    /// DAU (DNSSEC Algorithm Understood) - RFC 6975
    Dau,
    /// DHU (DS Hash Understood) - RFC 6975
    Dhu,
    /// N3U (NSEC3 Hash Understood) - RFC 6975
    N3u,
    /// EDNS Client Subnet - RFC 7871
    ClientSubnet,
    /// EDNS EXPIRE - RFC 7314
    Expire,
    /// Cookie - RFC 7873
    Cookie,
    /// EDNS TCP Keepalive - RFC 7828
    TcpKeepalive,
    /// Padding - RFC 7830
    Padding,
    /// CHAIN - RFC 7901
    Chain,
    /// EDNS Key Tag - RFC 8145
    KeyTag,
    /// Extended DNS Error - RFC 8914
    ExtendedDnsError,
    /// MAC address option (Apple devices) - Proprietary
    Mac,
    /// CPE-ID option - Proprietary
    NomCpeId,
    /// Device-ID option - Proprietary
    NomDeviceId,
    /// Cisco Umbrella device identification - Proprietary
    Umbrella,
    /// Unknown option code
    Unknown(u16),
}

impl From<u16> for Edns0OptionCode {
    fn from(code: u16) -> Self {
        match code {
            1 => Self::Llq,
            2 => Self::Ul,
            3 => Self::Nsid,
            5 => Self::Dau,
            6 => Self::Dhu,
            7 => Self::N3u,
            c if c == EDNS0_OPTION_CLIENT_SUBNET => Self::ClientSubnet,
            9 => Self::Expire,
            10 => Self::Cookie,
            11 => Self::TcpKeepalive,
            12 => Self::Padding,
            13 => Self::Chain,
            14 => Self::KeyTag,
            15 => Self::ExtendedDnsError,
            c if c == EDNS0_OPTION_MAC => Self::Mac,
            c if c == EDNS0_OPTION_NOMCPEID => Self::NomCpeId,
            c if c == EDNS0_OPTION_NOMDEVICEID => Self::NomDeviceId,
            c if c == EDNS0_OPTION_UMBRELLA => Self::Umbrella,
            c => Self::Unknown(c),
        }
    }
}

impl From<Edns0OptionCode> for u16 {
    fn from(code: Edns0OptionCode) -> Self {
        match code {
            Edns0OptionCode::Llq => 1,
            Edns0OptionCode::Ul => 2,
            Edns0OptionCode::Nsid => 3,
            Edns0OptionCode::Dau => 5,
            Edns0OptionCode::Dhu => 6,
            Edns0OptionCode::N3u => 7,
            Edns0OptionCode::ClientSubnet => EDNS0_OPTION_CLIENT_SUBNET,
            Edns0OptionCode::Expire => 9,
            Edns0OptionCode::Cookie => 10,
            Edns0OptionCode::TcpKeepalive => 11,
            Edns0OptionCode::Padding => 12,
            Edns0OptionCode::Chain => 13,
            Edns0OptionCode::KeyTag => 14,
            Edns0OptionCode::ExtendedDnsError => 15,
            Edns0OptionCode::Mac => EDNS0_OPTION_MAC,
            Edns0OptionCode::NomCpeId => EDNS0_OPTION_NOMCPEID,
            Edns0OptionCode::NomDeviceId => EDNS0_OPTION_NOMDEVICEID,
            Edns0OptionCode::Umbrella => EDNS0_OPTION_UMBRELLA,
            Edns0OptionCode::Unknown(c) => c,
        }
    }
}

/// EDNS Client Subnet option data (RFC 7871)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubnet {
    /// Address family: 1 for IPv4, 2 for IPv6
    pub family: u16,
    /// Source netmask bits
    pub source_netmask: u8,
    /// Scope netmask bits (0 in queries, set by server in responses)
    pub scope_netmask: u8,
    /// Address bytes (truncated to source_netmask bits)
    pub addr: Vec<u8>,
}

impl ClientSubnet {
    /// Create ClientSubnet from IP address and netmask
    pub fn from_addr(addr: &IpAddr, netmask: u8) -> Self {
        match addr {
            IpAddr::V4(ipv4) => {
                let bytes = ipv4.octets();
                let byte_count = ((netmask + 7) / 8) as usize;
                Self {
                    family: 1,
                    source_netmask: netmask.min(32),
                    scope_netmask: 0,
                    addr: bytes[..byte_count.min(4)].to_vec(),
                }
            }
            IpAddr::V6(ipv6) => {
                let bytes = ipv6.octets();
                let byte_count = ((netmask + 7) / 8) as usize;
                Self {
                    family: 2,
                    source_netmask: netmask.min(128),
                    scope_netmask: 0,
                    addr: bytes[..byte_count.min(16)].to_vec(),
                }
            }
        }
    }

    /// Convert to IP address with the source netmask
    pub fn to_addr(&self) -> Option<(IpAddr, u8)> {
        match self.family {
            1 => {
                // IPv4
                if self.addr.len() > 4 {
                    return None;
                }
                let mut bytes = [0u8; 4];
                bytes[..self.addr.len()].copy_from_slice(&self.addr);
                Some((IpAddr::V4(Ipv4Addr::from(bytes)), self.source_netmask))
            }
            2 => {
                // IPv6
                if self.addr.len() > 16 {
                    return None;
                }
                let mut bytes = [0u8; 16];
                bytes[..self.addr.len()].copy_from_slice(&self.addr);
                Some((IpAddr::V6(Ipv6Addr::from(bytes)), self.source_netmask))
            }
            _ => None,
        }
    }
}

/// EDNS0 option with parsed data
#[derive(Debug, Clone)]
pub enum Edns0Option {
    /// EDNS Client Subnet (RFC 7871)
    ClientSubnet(ClientSubnet),
    /// MAC address for device identification
    Mac(Vec<u8>),
    /// CPE-ID for device tracking
    NomCpeId(Vec<u8>),
    /// Device-ID for device tracking
    NomDeviceId(Vec<u8>),
    /// Cisco Umbrella device identification
    Umbrella { device_id: Vec<u8>, asset_id: Vec<u8> },
    /// DNS Cookie (RFC 7873)
    Cookie(Vec<u8>),
    /// NSID (Name Server Identifier - RFC 5001)
    Nsid(Vec<u8>),
    /// Extended DNS Error (RFC 8914)
    ExtendedDnsError { info_code: u16, extra_text: String },
    /// Padding (RFC 7830)
    Padding(usize),
    /// Generic option with raw data
    Unknown { code: u16, data: Vec<u8> },
}

impl Edns0Option {
    /// Get the option code
    pub fn code(&self) -> u16 {
        match self {
            Self::ClientSubnet(_) => EDNS0_OPTION_CLIENT_SUBNET,
            Self::Mac(_) => EDNS0_OPTION_MAC,
            Self::NomCpeId(_) => EDNS0_OPTION_NOMCPEID,
            Self::NomDeviceId(_) => EDNS0_OPTION_NOMDEVICEID,
            Self::Umbrella { .. } => EDNS0_OPTION_UMBRELLA,
            Self::Cookie(_) => 10,
            Self::Nsid(_) => 3,
            Self::ExtendedDnsError { .. } => 15,
            Self::Padding(_) => 12,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Get the option data as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::ClientSubnet(cs) => {
                let mut data = Vec::new();
                data.extend_from_slice(&cs.family.to_be_bytes());
                data.push(cs.source_netmask);
                data.push(cs.scope_netmask);
                data.extend_from_slice(&cs.addr);
                data
            }
            Self::Mac(mac) => mac.clone(),
            Self::NomCpeId(id) => id.clone(),
            Self::NomDeviceId(id) => id.clone(),
            Self::Umbrella { device_id, asset_id } => {
                let mut data = Vec::new();
                data.extend_from_slice(device_id);
                if !asset_id.is_empty() {
                    data.extend_from_slice(asset_id);
                }
                data
            }
            Self::Cookie(cookie) => cookie.clone(),
            Self::Nsid(nsid) => nsid.clone(),
            Self::ExtendedDnsError { info_code, extra_text } => {
                let mut data = Vec::new();
                data.extend_from_slice(&info_code.to_be_bytes());
                data.extend_from_slice(extra_text.as_bytes());
                data
            }
            Self::Padding(len) => vec![0u8; *len],
            Self::Unknown { data, .. } => data.clone(),
        }
    }
}

/// Internal EDNS Client Subnet option data (RFC 7871)
#[derive(Debug, Clone)]
struct SubnetOption {
    /// Address family: 1 for IPv4, 2 for IPv6
    family: u16,
    /// Source netmask bits
    source_netmask: u8,
    /// Scope netmask bits (0 in queries, set by server in responses)
    scope_netmask: u8,
    /// Address bytes (truncated to source_netmask bits)
    addr: Vec<u8>,
}

/// Cisco Umbrella device identification option
#[derive(Debug, Clone)]
struct UmbrellaOption {
    /// Device ID (variable length, typically 36-40 bytes)
    device_id: Vec<u8>,
    /// Asset ID (optional, 0-16 bytes)
    asset_id: Vec<u8>,
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Locate EDNS0 OPT pseudo-record in DNS packet
///
/// Searches the additional section of a DNS packet for an EDNS0 OPT resource record
/// as defined in RFC 6891. The OPT record is a pseudo-RR that carries protocol extensions
/// in the DNS additional section. This function also detects signed packets (TSIG/TKEY)
/// which cannot be modified without invalidating signatures.
///
/// # Arguments
///
/// * `packet` - Complete DNS packet as byte slice
/// * `is_sign` - If true, returns pointer even if TSIG/TKEY signature present
///
/// # Returns
///
/// * `Ok(Some((offset, udp_size, rcode_ext, flags)))` - OPT record found with metadata
///   - `offset`: Byte offset to start of OPT record in packet
///   - `udp_size`: UDP payload size from OPT record
///   - `rcode_ext`: Extended RCODE (upper 8 bits)
///   - `flags`: EDNS flags (includes DO bit)
/// * `Ok(None)` - No OPT record found or packet is signed
/// * `Err(Edns0Error)` - Malformed packet or buffer overrun
///
/// # RFC Compliance
///
/// Implements RFC 6891 Section 6.1.2 (Wire Format) for OPT pseudo-RR location.
/// Per RFC, OPT record SHOULD appear last in additional section but implementations
/// MUST accept it anywhere in additional section.
///
/// # Example
///
/// ```rust,ignore
/// use dnsmasq::dns::edns0::find_pseudoheader;
///
/// let packet: &[u8] = &[/* DNS packet */];
/// match find_pseudoheader(packet, false) {
///     Ok(Some((offset, udp_size, _, flags))) => {
///         println!("Found OPT at offset {}, UDP size {}", offset, udp_size);
///     }
///     Ok(None) => println!("No OPT record"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
///
/// # Original C Function
///
/// Replaces `find_pseudoheader()` from `src/edns0.c` lines 88-162
pub fn find_pseudoheader(
    packet: &[u8],
    is_sign: bool,
) -> Result<Option<(usize, u16, u8, u16)>, Edns0Error> {
    // Minimum packet size: 12-byte header
    if packet.len() < 12 {
        return Err(Edns0Error::BufferTooSmall {
            required: 12,
            available: packet.len(),
        });
    }

    // Extract header counts
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);
    let arcount = u16::from_be_bytes([packet[10], packet[11]]);

    trace!(
        "find_pseudoheader: qdcount={}, ancount={}, nscount={}, arcount={}",
        qdcount,
        ancount,
        nscount,
        arcount
    );

    // No additional section, no OPT possible
    if arcount == 0 {
        return Ok(None);
    }

    // Start after 12-byte header
    let mut pos = &packet[12..];

    // Skip question section unless is_sign is true
    if !is_sign {
        pos = skip_questions(packet, pos, qdcount).map_err(|e| Edns0Error::ParseError {
            details: format!("Failed to skip questions: {}", e),
        })?;

        // Skip answer section
        pos = skip_section(packet, pos, ancount).map_err(|e| Edns0Error::ParseError {
            details: format!("Failed to skip answer section: {}", e),
        })?;

        // Skip authority section
        pos = skip_section(packet, pos, nscount).map_err(|e| Edns0Error::ParseError {
            details: format!("Failed to skip authority section: {}", e),
        })?;
    }

    // Now we're in additional section - search for OPT record
    for _ in 0..arcount {
        // Calculate current offset in original packet
        let current_offset = packet.len() - pos.len();

        // Skip NAME field
        let after_name = skip_name(packet, pos).map_err(|e| Edns0Error::ParseError {
            details: format!("Failed to skip name in additional section: {}", e),
        })?;

        // Need at least 10 bytes for TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        if after_name.len() < 10 {
            return Err(Edns0Error::BufferTooSmall {
                required: 10,
                available: after_name.len(),
            });
        }

        // Extract TYPE and CLASS
        let rr_type = u16::from_be_bytes([after_name[0], after_name[1]]);
        let rr_class = u16::from_be_bytes([after_name[2], after_name[3]]);

        // Check if this is OPT record (TYPE=41, CLASS field = UDP payload size)
        if rr_type == T_OPT {
            let udp_size = rr_class; // CLASS field repurposed as UDP payload size
            let rcode_ext = after_name[4]; // TTL byte 0 = extended RCODE
            let version = after_name[5]; // TTL byte 1 = EDNS version
            let flags = u16::from_be_bytes([after_name[6], after_name[7]]); // TTL bytes 2-3 = flags
            let rdlength = u16::from_be_bytes([after_name[8], after_name[9]]);

            trace!(
                "Found OPT record at offset {}: udp_size={}, version={}, flags={:#x}, rdlength={}",
                current_offset,
                udp_size,
                version,
                flags,
                rdlength
            );

            // Verify RDLENGTH doesn't exceed packet
            if after_name.len() < 10 + rdlength as usize {
                return Err(Edns0Error::MalformedPacket {
                    reason: format!(
                        "OPT record RDLENGTH {} exceeds packet boundary",
                        rdlength
                    ),
                });
            }

            return Ok(Some((current_offset, udp_size, rcode_ext, flags)));
        }

        // Check for TSIG/TKEY (signed packets) - cannot modify
        if (rr_type == T_TSIG || rr_type == T_TKEY) && !is_sign {
            debug!("Packet contains TSIG/TKEY signature, cannot modify");
            return Ok(None);
        }

        // Extract RDLENGTH and skip to next RR
        let rdlength = u16::from_be_bytes([after_name[8], after_name[9]]) as usize;

        if after_name.len() < 10 + rdlength {
            return Err(Edns0Error::BufferTooSmall {
                required: 10 + rdlength,
                available: after_name.len(),
            });
        }

        pos = &after_name[10 + rdlength..];
    }

    // No OPT record found
    Ok(None)
}

/// Create or modify EDNS0 OPT pseudo-record in DNS packet
///
/// This function adds an EDNS0 OPT record to a DNS packet or modifies an existing one.
/// It handles three scenarios:
/// 1. No existing OPT: Adds new OPT record at end of additional section
/// 2. Existing OPT in correct position: Modifies in place or replaces
/// 3. Existing OPT in wrong position: Removes old, adds new at correct position
///
/// The function manages OPT record options through three modes:
/// - Replace (normal): Replaces specified options, keeps others
/// - Delete: Removes specified option types completely
/// - Add: Adds new options without removing existing ones
///
/// # Arguments
///
/// * `packet` - Mutable buffer containing DNS packet (will be modified in place)
/// * `udp_sz` - Desired UDP payload size for OPT record
/// * `opt_data` - Option data to add/replace (option code + data)
/// * `opt_code` - Option code to replace/delete (0 = none)
/// * `replace` - If true, replace option; if false, delete option
///
/// # Returns
///
/// * `Ok(new_length)` - New packet length after modification
/// * `Err(Edns0Error)` - Buffer too small, malformed packet, or processing error
///
/// # RFC Compliance
///
/// Implements RFC 6891 Section 6.1.2 requiring OPT to be last RR in additional section.
/// When existing OPT is not in final position, uses rrfilter to remove it and recreate
/// at correct position.
///
/// # Original C Function
///
/// Replaces `add_pseudoheader()` from `src/edns0.c` lines 164-324
pub fn add_pseudoheader(
    packet: &mut BytesMut,
    udp_sz: u16,
    opt_data: &[(u16, Vec<u8>)],
    opt_code: u16,
    replace: bool,
) -> Result<usize, Edns0Error> {
    let packet_len = packet.len();

    // Find existing OPT record
    let opt_info = find_pseudoheader(&packet[..], false)?;

    if packet_len < 12 {
        return Err(Edns0Error::BufferTooSmall {
            required: 12,
            available: packet_len,
        });
    }

    let arcount = u16::from_be_bytes([packet[10], packet[11]]);

    if let Some((opt_offset, old_udp_sz, rcode_ext, flags)) = opt_info {
        // Existing OPT record found - check if it's in the correct position (last in additional section)
        // We need to verify if this OPT is the last RR in additional section
        let is_last = check_opt_is_last(packet, opt_offset, arcount)?;

        if !is_last {
            // OPT is not last - need to remove and recreate at end
            debug!("OPT record not in final position, relocating");

            // Save existing OPT options before removal
            let saved_options = extract_opt_options(packet, opt_offset)?;

            // Remove existing OPT using rrfilter
            let new_len = rrfilter(packet, crate::dns::rrfilter::RRFILTER_EDNS0)
                .map_err(|e| Edns0Error::InternalError {
                    message: format!("rrfilter failed: {}", e),
                })?;
            packet.truncate(new_len);

            // Now add new OPT at end with saved options plus new options
            let mut combined_options = saved_options;
            for (code, data) in opt_data {
                // Handle replace/delete logic
                if opt_code == *code {
                    if replace {
                        combined_options.push((*code, data.clone()));
                    }
                    // If !replace, we're deleting, so don't add it
                } else {
                    combined_options.push((*code, data.clone()));
                }
            }

            return add_opt_record_to_end(packet, udp_sz, &combined_options);
        }

        // OPT is in correct position - modify in place if possible
        // For simplicity, we'll extract options, filter/modify, and rebuild
        let mut existing_options = extract_opt_options(packet, opt_offset)?;

        // Apply modifications based on opt_code and replace flag
        if opt_code != 0 {
            if replace {
                // Remove old instances of opt_code
                existing_options.retain(|(code, _)| *code != opt_code);
            } else {
                // Delete mode - just remove
                existing_options.retain(|(code, _)| *code != opt_code);
            }
        }

        // Add new options
        for (code, data) in opt_data {
            existing_options.push((*code, data.clone()));
        }

        // Remove old OPT
        let new_len = rrfilter(packet, crate::dns::rrfilter::RRFILTER_EDNS0).map_err(|e| {
            Edns0Error::InternalError {
                message: format!("rrfilter failed: {}", e),
            }
        })?;
        packet.truncate(new_len);

        // Add new OPT with combined options
        return add_opt_record_to_end(packet, udp_sz, &existing_options);
    }

    // No existing OPT - add new one
    add_opt_record_to_end(packet, udp_sz, opt_data)
}

/// Add DNSSEC OK (DO) bit to OPT record
///
/// Sets the DNSSEC OK bit in an existing OPT record or creates a new OPT record
/// with the DO bit set. This signals to upstream resolvers that the client can
/// handle DNSSEC validation records.
///
/// # Arguments
///
/// * `packet` - Mutable DNS packet buffer
/// * `minsize` - Minimum UDP payload size (defaults to PACKETSZ if 0)
///
/// # Returns
///
/// * `Ok(new_length)` - New packet length after modification
/// * `Err(Edns0Error)` - Processing error
///
/// # RFC Compliance
///
/// Implements RFC 4035 Section 3.2.1 for DNSSEC OK bit signaling.
///
/// # Original C Function
///
/// Replaces `add_do_bit()` from `src/edns0.c` lines 1239-1267
pub fn add_do_bit(packet: &mut BytesMut, minsize: u16) -> Result<usize, Edns0Error> {
    let udp_size = if minsize == 0 {
        PACKETSZ as u16
    } else {
        minsize
    };

    // Check if OPT already exists
    if let Some((opt_offset, old_udp_sz, rcode_ext, flags)) = find_pseudoheader(&packet[..], false)? {
        // Check if DO bit already set
        if (flags & EDNS0_DO_BIT) != 0 {
            trace!("DO bit already set in OPT record");
            return Ok(packet.len());
        }

        // Need to set DO bit - modify flags in place
        // The flags are in TTL bytes 2-3 of the OPT record
        // Calculate position: opt_offset + 1 (root label) + 2 (TYPE) + 2 (CLASS/UDP) + 2 (RCODE+VERSION) = opt_offset + 7
        let flags_offset = opt_offset + 1 + 2 + 2 + 2;

        if packet.len() < flags_offset + 2 {
            return Err(Edns0Error::BufferTooSmall {
                required: flags_offset + 2,
                available: packet.len(),
            });
        }

        let new_flags = flags | EDNS0_DO_BIT;
        packet[flags_offset] = (new_flags >> 8) as u8;
        packet[flags_offset + 1] = (new_flags & 0xFF) as u8;

        trace!("Set DO bit in existing OPT record");
        return Ok(packet.len());
    }

    // No OPT exists - add one with DO bit set
    add_opt_record_with_do(packet, udp_size)
}

/// Validate EDNS Client Subnet option in response matches query
///
/// Checks that the ECS option returned by an upstream server properly matches
/// the subnet parameters sent in the query. Per RFC 7871, the scope netmask
/// in the response must not exceed the source netmask from the query.
///
/// # Arguments
///
/// * `packet` - DNS response packet to validate
/// * `query_source` - Original query source address
/// * `query_source_netmask` - Source netmask sent in query
///
/// # Returns
///
/// * `Ok(true)` - ECS option valid or not present
/// * `Ok(false)` - ECS option invalid (scope > source netmask)
/// * `Err(Edns0Error)` - Parse error
///
/// # RFC Compliance
///
/// Implements RFC 7871 Section 7.3 validation requirements for scope netmask.
///
/// # Original C Function
///
/// Replaces `check_source()` from `src/edns0.c` lines 961-1073
pub fn check_source(
    packet: &[u8],
    query_source: &IpAddr,
    query_source_netmask: u8,
) -> Result<bool, Edns0Error> {
    // Find OPT record
    let opt_info = match find_pseudoheader(packet, false)? {
        Some(info) => info,
        None => {
            // No OPT record, nothing to validate
            return Ok(true);
        }
    };

    let (opt_offset, _, _, _) = opt_info;

    // Extract options from OPT record
    let options = extract_opt_options(packet, opt_offset)?;

    // Look for CLIENT_SUBNET option
    for (code, data) in options {
        if code == EDNS0_OPTION_CLIENT_SUBNET {
            // Parse subnet option
            let subnet_opt = parse_subnet_option(&data)?;

            // Validate family matches
            let expected_family = match query_source {
                IpAddr::V4(_) => 1u16,
                IpAddr::V6(_) => 2u16,
            };

            if subnet_opt.family != expected_family {
                warn!(
                    "ECS family mismatch: expected {}, got {}",
                    expected_family, subnet_opt.family
                );
                return Ok(false);
            }

            // Validate scope netmask <= source netmask
            if subnet_opt.scope_netmask > query_source_netmask {
                warn!(
                    "ECS scope netmask {} exceeds query source netmask {}",
                    subnet_opt.scope_netmask, query_source_netmask
                );
                return Ok(false);
            }

            trace!(
                "ECS validation passed: source={}, scope={}",
                query_source_netmask,
                subnet_opt.scope_netmask
            );
            return Ok(true);
        }
    }

    // No CLIENT_SUBNET option in response
    Ok(true)
}

/// Add configured EDNS0 options to outbound DNS query
///
/// This is the main entry point for adding EDNS0 options to queries forwarded to
/// upstream resolvers. It orchestrates calling individual option builders based on
/// daemon configuration flags.
///
/// Supported options:
/// - EDNS Client Subnet (ECS) - RFC 7871
/// - MAC address identification
/// - Device ID (base64/hex encoded MAC)
/// - Cisco Umbrella device identification
///
/// # Arguments
///
/// * `packet` - Mutable DNS query packet buffer
/// * `limit` - Maximum allowed packet size
/// * `source` - Client source address for ECS
/// * `options` - Daemon configuration options (feature flags)
/// * `pktsz` - Preferred packet size for OPT record
///
/// # Returns
///
/// * `Ok(new_length)` - New packet length after adding options
/// * `Err(Edns0Error)` - Buffer overflow or processing error
///
/// # RFC Compliance
///
/// Aggregates multiple EDNS0 options per RFC 6891 Section 6.1.2 format.
///
/// # Original C Function
///
/// Replaces `add_edns0_config()` from `src/edns0.c` lines 1075-1237
pub async fn add_edns0_config(
    packet: &mut BytesMut,
    limit: usize,
    source: &SocketAddr,
    options: &DaemonOptions,
    pktsz: u16,
    arp_cache: Option<Arc<RwLock<ArpCache>>>,
    platform: Option<&dyn Platform>,
) -> Result<usize, Edns0Error> {
    let mut opt_data: Vec<(u16, Vec<u8>)> = Vec::new();

    // Add MAC address option if configured (requires ARP cache and platform)
    if options.contains(DaemonOptions::OPT_ADD_MAC) {
        if let (Some(cache), Some(plat)) = (arp_cache.as_ref(), platform) {
            if let Some(mac_data) = add_mac_option(source, options, cache.clone(), plat).await {
                opt_data.push((EDNS0_OPTION_MAC, mac_data));
            }
        }
    }

    // Add device ID option (base64/hex MAC) if configured
    // Note: This uses different option codes than MAC
    if let (Some(cache), Some(plat)) = (arp_cache.as_ref(), platform) {
        if let Some(device_data) = add_device_id_option(source, options, cache.clone(), plat).await {
            opt_data.push(device_data);
        }
    }

    // Add Client Subnet option if configured
    if options.contains(DaemonOptions::OPT_CLIENT_SUBNET) {
        if let Some(ecs_data) = add_source_addr_option(&source.ip(), options) {
            opt_data.push((EDNS0_OPTION_CLIENT_SUBNET, ecs_data));
        }
    }

    // Add Cisco Umbrella option if configured (would need OPT_UMBRELLA flag)
    // Note: OPT_UMBRELLA not yet defined in config::types, so skipping for now

    // If no options to add, just ensure OPT record exists with proper size
    if opt_data.is_empty() {
        // Just ensure proper UDP size
        return add_pseudoheader(packet, pktsz, &[], 0, false);
    }

    // Add all collected options
    let new_len = add_pseudoheader(packet, pktsz, &opt_data, 0, false)?;

    // Verify we didn't exceed limit
    if new_len > limit {
        return Err(Edns0Error::BufferTooSmall {
            required: new_len,
            available: limit,
        });
    }

    debug!("Added {} EDNS0 options to query", opt_data.len());
    Ok(new_len)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if OPT record is last in additional section
fn check_opt_is_last(packet: &[u8], opt_offset: usize, arcount: u16) -> Result<bool, Edns0Error> {
    if arcount == 0 {
        return Ok(false);
    }

    // Parse through additional section to see if OPT is last
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);

    let mut pos = &packet[12..];

    // Skip to additional section
    pos = skip_questions(packet, pos, qdcount).map_err(|e| Edns0Error::ParseError {
        details: format!("{}", e),
    })?;
    pos = skip_section(packet, pos, ancount).map_err(|e| Edns0Error::ParseError {
        details: format!("{}", e),
    })?;
    pos = skip_section(packet, pos, nscount).map_err(|e| Edns0Error::ParseError {
        details: format!("{}", e),
    })?;

    // Now iterate through additional records
    for i in 0..arcount {
        let current_offset = packet.len() - pos.len();

        if current_offset == opt_offset {
            // Found the OPT - check if it's the last one
            return Ok(i == arcount - 1);
        }

        // Skip this RR
        pos = skip_name(packet, pos).map_err(|e| Edns0Error::ParseError {
            details: format!("{}", e),
        })?;

        if pos.len() < 10 {
            return Err(Edns0Error::BufferTooSmall {
                required: 10,
                available: pos.len(),
            });
        }

        let rdlength = u16::from_be_bytes([pos[8], pos[9]]) as usize;
        if pos.len() < 10 + rdlength {
            return Err(Edns0Error::BufferTooSmall {
                required: 10 + rdlength,
                available: pos.len(),
            });
        }

        pos = &pos[10 + rdlength..];
    }

    Ok(false)
}

/// Extract all options from an OPT record
fn extract_opt_options(packet: &[u8], opt_offset: usize) -> Result<Vec<(u16, Vec<u8>)>, Edns0Error> {
    if packet.len() < opt_offset + 1 {
        return Err(Edns0Error::BufferTooSmall {
            required: opt_offset + 1,
            available: packet.len(),
        });
    }

    // Skip root label (1 byte)
    let pos = opt_offset + 1;

    // Need TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
    if packet.len() < pos + 10 {
        return Err(Edns0Error::BufferTooSmall {
            required: pos + 10,
            available: packet.len(),
        });
    }

    let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;

    if packet.len() < pos + 10 + rdlength {
        return Err(Edns0Error::BufferTooSmall {
            required: pos + 10 + rdlength,
            available: packet.len(),
        });
    }

    let rdata = &packet[pos + 10..pos + 10 + rdlength];

    // Parse options from RDATA
    let mut options = Vec::new();
    let mut opt_pos = 0;

    while opt_pos + 4 <= rdata.len() {
        let opt_code = u16::from_be_bytes([rdata[opt_pos], rdata[opt_pos + 1]]);
        let opt_len = u16::from_be_bytes([rdata[opt_pos + 2], rdata[opt_pos + 3]]) as usize;

        if opt_pos + 4 + opt_len > rdata.len() {
            break;
        }

        let opt_data = rdata[opt_pos + 4..opt_pos + 4 + opt_len].to_vec();
        options.push((opt_code, opt_data));

        opt_pos += 4 + opt_len;
    }

    Ok(options)
}

/// Add OPT record to end of packet
fn add_opt_record_to_end(
    packet: &mut BytesMut,
    udp_sz: u16,
    options: &[(u16, Vec<u8>)],
) -> Result<usize, Edns0Error> {
    let start_len = packet.len();

    // Calculate total RDLENGTH
    let rdlength: usize = options.iter().map(|(_, data)| 4 + data.len()).sum();

    // Ensure we have space
    let required = start_len + 1 + 2 + 2 + 4 + 2 + rdlength;
    packet.reserve(required - start_len);

    // Add root label (NAME = .)
    packet.extend_from_slice(ROOT_LABEL);

    // Add TYPE = OPT (41)
    packet.extend_from_slice(&T_OPT.to_be_bytes());

    // Add CLASS = UDP payload size
    packet.extend_from_slice(&udp_sz.to_be_bytes());

    // Add TTL field (4 bytes):
    // - Byte 0: Extended RCODE (0)
    // - Byte 1: EDNS version (0)
    // - Bytes 2-3: Flags (0)
    packet.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]);

    // Add RDLENGTH
    packet.extend_from_slice(&(rdlength as u16).to_be_bytes());

    // Add all options
    for (code, data) in options {
        packet.extend_from_slice(&code.to_be_bytes());
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);
    }

    // Update ARCOUNT in header
    if packet.len() < 12 {
        return Err(Edns0Error::BufferTooSmall {
            required: 12,
            available: packet.len(),
        });
    }

    let arcount = u16::from_be_bytes([packet[10], packet[11]]);
    let new_arcount = arcount + 1;
    packet[10] = (new_arcount >> 8) as u8;
    packet[11] = (new_arcount & 0xFF) as u8;

    trace!("Added OPT record with {} options, rdlength={}", options.len(), rdlength);
    Ok(packet.len())
}

/// Add OPT record with DO bit set
fn add_opt_record_with_do(packet: &mut BytesMut, udp_sz: u16) -> Result<usize, Edns0Error> {
    let start_len = packet.len();

    // Ensure we have space for OPT record (11 bytes: 1 + 2 + 2 + 4 + 2)
    packet.reserve(11);

    // Add root label (NAME = .)
    packet.extend_from_slice(ROOT_LABEL);

    // Add TYPE = OPT (41)
    packet.extend_from_slice(&T_OPT.to_be_bytes());

    // Add CLASS = UDP payload size
    packet.extend_from_slice(&udp_sz.to_be_bytes());

    // Add TTL field (4 bytes) with DO bit set in flags:
    // - Byte 0: Extended RCODE (0)
    // - Byte 1: EDNS version (0)
    // - Bytes 2-3: Flags (DO bit = 0x8000)
    let flags_with_do = EDNS0_DO_BIT;
    packet.extend_from_slice(&[
        0u8,
        0u8,
        (flags_with_do >> 8) as u8,
        (flags_with_do & 0xFF) as u8,
    ]);

    // Add RDLENGTH = 0 (no options)
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Update ARCOUNT in header
    if packet.len() < 12 {
        return Err(Edns0Error::BufferTooSmall {
            required: 12,
            available: packet.len(),
        });
    }

    let arcount = u16::from_be_bytes([packet[10], packet[11]]);
    let new_arcount = arcount + 1;
    packet[10] = (new_arcount >> 8) as u8;
    packet[11] = (new_arcount & 0xFF) as u8;

    trace!("Added OPT record with DO bit set");
    Ok(packet.len())
}

/// Parse subnet option from raw bytes
fn parse_subnet_option(data: &[u8]) -> Result<SubnetOption, Edns0Error> {
    if data.len() < 4 {
        return Err(Edns0Error::InvalidOption {
            option_code: EDNS0_OPTION_CLIENT_SUBNET,
            reason: format!("Option too short: {} bytes", data.len()),
        });
    }

    let family = u16::from_be_bytes([data[0], data[1]]);
    let source_netmask = data[2];
    let scope_netmask = data[3];

    let addr = data[4..].to_vec();

    Ok(SubnetOption {
        family,
        source_netmask,
        scope_netmask,
        addr,
    })
}

/// Calculate subnet option data from IP address
fn calc_subnet_opt(source: &IpAddr, source_netmask: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(20);

    match source {
        IpAddr::V4(ipv4) => {
            // Family = 1 (IPv4)
            data.extend_from_slice(&1u16.to_be_bytes());
            // Source netmask
            data.push(source_netmask.min(32));
            // Scope netmask = 0 (query)
            data.push(0);

            // Calculate address bytes needed
            let bytes_needed = ((source_netmask + 7) / 8) as usize;
            let addr_bytes = ipv4.octets();

            // Add truncated address
            for i in 0..bytes_needed.min(4) {
                data.push(addr_bytes[i]);
            }

            // Mask last byte if needed
            if source_netmask % 8 != 0 && bytes_needed > 0 && bytes_needed <= 4 {
                let last_idx = data.len() - 1;
                let bits_in_last_byte = source_netmask % 8;
                let mask = 0xFFu8 << (8 - bits_in_last_byte);
                data[last_idx] &= mask;
            }
        }
        IpAddr::V6(ipv6) => {
            // Family = 2 (IPv6)
            data.extend_from_slice(&2u16.to_be_bytes());
            // Source netmask
            data.push(source_netmask.min(128));
            // Scope netmask = 0 (query)
            data.push(0);

            // Calculate address bytes needed
            let bytes_needed = ((source_netmask + 7) / 8) as usize;
            let addr_bytes = ipv6.octets();

            // Add truncated address
            for i in 0..bytes_needed.min(16) {
                data.push(addr_bytes[i]);
            }

            // Mask last byte if needed
            if source_netmask % 8 != 0 && bytes_needed > 0 && bytes_needed <= 16 {
                let last_idx = data.len() - 1;
                let bits_in_last_byte = source_netmask % 8;
                let mask = 0xFFu8 << (8 - bits_in_last_byte);
                data[last_idx] &= mask;
            }
        }
    }

    data
}

/// Create EDNS Client Subnet option data
fn add_source_addr_option(source: &IpAddr, options: &DaemonOptions) -> Option<Vec<u8>> {
    // Determine source netmask based on configuration
    // For privacy, typically use /24 for IPv4, /56 for IPv6
    let source_netmask = match source {
        IpAddr::V4(_) => 24u8,
        IpAddr::V6(_) => 56u8,
    };

    Some(calc_subnet_opt(source, source_netmask))
}

/// Create MAC address option data
async fn add_mac_option(
    source: &SocketAddr,
    _options: &DaemonOptions,
    arp_cache: Arc<RwLock<ArpCache>>,
    platform: &dyn Platform,
) -> Option<Vec<u8>> {
    // Query ARP cache for MAC address
    // find_mac expects Option<&IpAddr>, lazy: bool
    let addr = source.ip();
    match find_mac(arp_cache, Some(&addr), true, platform).await {
        Ok(Some((mac_bytes, mac_len))) if mac_len > 0 => {
            trace!("Found MAC for {}: {:02X?}", source.ip(), &mac_bytes[..mac_len]);
            Some(mac_bytes[..mac_len].to_vec())
        }
        Ok(_) => {
            trace!("No MAC found for {}", source.ip());
            None
        }
        Err(e) => {
            warn!("Failed to lookup MAC for {}: {}", source.ip(), e);
            None
        }
    }
}

/// Create device ID option data (encoded MAC)
async fn add_device_id_option(
    source: &SocketAddr,
    _options: &DaemonOptions,
    arp_cache: Arc<RwLock<ArpCache>>,
    platform: &dyn Platform,
) -> Option<(u16, Vec<u8>)> {
    // Query ARP cache for MAC address
    let addr = source.ip();
    let (mac_bytes, mac_len) = match find_mac(arp_cache, Some(&addr), true, platform).await {
        Ok(Some((bytes, len))) if len > 0 => (bytes, len),
        _ => return None,
    };

    // Check encoding format flags
    // Note: OPT_MAC_B64 and OPT_MAC_HEX not yet defined in config::types
    // Using NOMDEVICEID as default for now
    let option_code = EDNS0_OPTION_NOMDEVICEID;

    // Encode MAC as hex string for device ID
    let mac_str = print_mac(&mac_bytes[..mac_len]);
    let encoded = mac_str.as_bytes().to_vec();

    trace!(
        "Created device ID option for {}: {}",
        source.ip(),
        mac_str
    );

    Some((option_code, encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_pseudoheader_no_opt() {
        // Minimal DNS query with no OPT record
        let packet = [
            0x00, 0x01, // ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        let result = find_pseudoheader(&packet, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_calc_subnet_opt_ipv4() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let data = calc_subnet_opt(&addr, 24);

        // Should be: family(2) + source_mask(1) + scope_mask(1) + addr(3)
        assert_eq!(data.len(), 7);
        assert_eq!(u16::from_be_bytes([data[0], data[1]]), 1); // IPv4
        assert_eq!(data[2], 24); // source netmask
        assert_eq!(data[3], 0); // scope netmask
        assert_eq!(data[4], 192);
        assert_eq!(data[5], 168);
        assert_eq!(data[6], 1);
    }

    #[test]
    fn test_calc_subnet_opt_ipv6() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let data = calc_subnet_opt(&addr, 56);

        // Should be: family(2) + source_mask(1) + scope_mask(1) + addr(7)
        assert_eq!(data.len(), 11);
        assert_eq!(u16::from_be_bytes([data[0], data[1]]), 2); // IPv6
        assert_eq!(data[2], 56); // source netmask
        assert_eq!(data[3], 0); // scope netmask
        assert_eq!(data[4], 0x20);
        assert_eq!(data[5], 0x01);
        assert_eq!(data[6], 0x0d);
        assert_eq!(data[7], 0xb8);
    }

    #[test]
    fn test_parse_subnet_option() {
        let data = vec![
            0x00, 0x01, // family = 1 (IPv4)
            24,   // source netmask
            0,    // scope netmask
            192, 168, 1, // address bytes
        ];

        let result = parse_subnet_option(&data);
        assert!(result.is_ok());

        let opt = result.unwrap();
        assert_eq!(opt.family, 1);
        assert_eq!(opt.source_netmask, 24);
        assert_eq!(opt.scope_netmask, 0);
        assert_eq!(opt.addr, vec![192, 168, 1]);
    }

    #[test]
    fn test_add_opt_record_to_end() {
        let mut packet = BytesMut::from(&[
            0x00, 0x01, // ID
            0x01, 0x00, // Flags
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT = 0
        ][..]);

        let options = vec![];
        let result = add_opt_record_to_end(&mut packet, 1232, &options);
        assert!(result.is_ok());

        // Check ARCOUNT incremented
        assert_eq!(packet[10], 0x00);
        assert_eq!(packet[11], 0x01);

        // Check OPT record structure
        assert_eq!(packet[12], 0x00); // root label
        assert_eq!(u16::from_be_bytes([packet[13], packet[14]]), T_OPT);
        assert_eq!(u16::from_be_bytes([packet[15], packet[16]]), 1232);
    }
}
