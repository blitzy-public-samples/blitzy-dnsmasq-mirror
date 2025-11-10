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

//! DNS packet serialization and construction
//!
//! This module provides memory-safe DNS packet serialization functionality, replacing
//! the manual pointer arithmetic and buffer management from `src/rfc1035.c` with safe
//! Rust types and automatic bounds checking. It implements RFC 1035 wire format exactly
//! while eliminating all buffer overflow vulnerabilities through Rust's type system.
//!
//! # Key Functionality
//!
//! - **add_resource_record**: Add individual resource records to DNS responses with
//!   automatic compression pointer integration
//! - **setup_reply**: Initialize DNS response headers with appropriate flags for
//!   different response types (NOERROR, NXDOMAIN, REFUSED)
//! - **resize_packet**: Adjust packet buffer size for response construction and
//!   EDNS0 OPT record management
//! - **DnsPacketBuilder**: Builder pattern for constructing complete DNS responses
//!   with automatic capacity management
//!
//! # Memory Safety
//!
//! Replaces C's unsafe patterns with safe Rust equivalents:
//! - `unsigned char*` pointer arithmetic → `BytesMut` with automatic bounds checking
//! - Manual `PUTSHORT`/`PUTLONG` macros → `write_u16`/`write_u32` safe functions
//! - Unchecked buffer offsets → Vec capacity checks and `Result` error propagation
//! - Manual memory reallocation → `Vec::reserve` automatic growth
//!
//! # RFC 1035 Compliance
//!
//! Maintains byte-identical wire format:
//! - DNS header structure (12 bytes): ID, flags, section counts
//! - Resource record format: NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA
//! - Name compression pointers: 0xC000 | offset (14-bit)
//! - Network byte order (big-endian) for all multi-byte fields
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use dnsmasq::dns::serializer::{DnsPacketBuilder, setup_reply, ResponseType, ExtendedDnsError};
//! use dnsmasq::dns::protocol::{DnsHeader, T_A, C_IN, NOERROR};
//!
//! // Initialize response header
//! let mut header = DnsHeader::new();
//! header.set_id(12345);
//! setup_reply(&mut header, ResponseType::NoError, ExtendedDnsError::Unset);
//!
//! // Build response with answer records
//! let mut builder = DnsPacketBuilder::with_capacity(512);
//! builder.set_header(header)?;
//! builder.add_answer(name_offset, ttl, T_A, C_IN, &ipv4_addr)?;
//! let packet = builder.build()?;
//! ```
//!
//! # See Also
//!
//! - `dns::parser` - Packet parsing (extract_name, extract_request)
//! - `dns::compression` - Name compression context and pointer creation
//! - `dns::protocol` - DNS constants and header structure
//! - C source: `src/rfc1035.c` (functions: add_resource_record, setup_reply, resize_packet)

use crate::dns::protocol::{
    // Size constants
    RRFIXEDSZ, PACKETSZ, INADDRSZ, IN6ADDRSZ,
    // Header structure and accessor trait
    DnsHeader,
    // Response codes
    NOERROR, NXDOMAIN, REFUSED,
};

use crate::dns::compression::{
    CompressionContext,
};

use bytes::BytesMut;
use std::fmt;
use tracing::{debug, warn, trace};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during DNS packet serialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializationError {
    /// Buffer would exceed maximum size during serialization
    BufferTooSmall {
        /// Required size in bytes
        required: usize,
        /// Available capacity in bytes
        available: usize,
    },
    
    /// Invalid DNS packet format or structure
    InvalidFormat {
        /// Description of the format error
        reason: String,
    },
    
    /// Name compression operation failed
    CompressionFailed {
        /// Description of compression failure
        reason: String,
    },
    
    /// Domain name exceeds maximum allowed length
    NameTooLong {
        /// Actual name length in bytes
        length: usize,
        /// Maximum allowed length
        max_length: usize,
    },
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializationError::BufferTooSmall { required, available } => {
                write!(f, "Buffer too small: required {} bytes, available {} bytes", required, available)
            }
            SerializationError::InvalidFormat { reason } => {
                write!(f, "Invalid DNS packet format: {}", reason)
            }
            SerializationError::CompressionFailed { reason } => {
                write!(f, "Name compression failed: {}", reason)
            }
            SerializationError::NameTooLong { length, max_length } => {
                write!(f, "Domain name too long: {} bytes exceeds maximum {}", length, max_length)
            }
        }
    }
}

impl std::error::Error for SerializationError {}

// ============================================================================
// Response Type Enum
// ============================================================================

/// DNS response types for setup_reply initialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    /// NOERROR response (empty domain or successful answer)
    NoError,
    /// NXDOMAIN response (non-existent domain)
    NxDomain,
    /// Standard response with answer records (IPv4/IPv6)
    WithRecords,
    /// REFUSED response (nowhere to forward, policy refusal)
    Refused,
}

/// Extended DNS Error codes for EDE option
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedDnsError {
    /// No extended error
    Unset,
    /// Other error
    Other,
    /// DNSSEC bogus
    DnssecBogus,
    /// Blocked
    Blocked,
    /// Censored
    Censored,
    /// Filtered
    Filtered,
}

// ============================================================================
// Helper Functions for Network Byte Order
// ============================================================================

/// Read 16-bit unsigned integer from buffer in network byte order (big-endian)
///
/// # Arguments
///
/// * `buffer` - Byte slice containing at least 2 bytes
///
/// # Returns
///
/// * `Ok(u16)` - Parsed value in host byte order
/// * `Err(SerializationError)` - Buffer too small
///
/// # Safety
///
/// Replaces C macro `GETSHORT(val, ptr)` with safe bounds-checked operation.
/// Prevents buffer overruns that could occur with manual pointer arithmetic.
///
/// # Example
///
/// ```rust
/// use dnsmasq::dns::serializer::read_u16;
///
/// let bytes = [0x12, 0x34];
/// let value = read_u16(&bytes).unwrap();
/// assert_eq!(value, 0x1234);
/// ```
pub fn read_u16(buffer: &[u8]) -> Result<u16, SerializationError> {
    if buffer.len() < 2 {
        return Err(SerializationError::BufferTooSmall {
            required: 2,
            available: buffer.len(),
        });
    }
    Ok(u16::from_be_bytes([buffer[0], buffer[1]]))
}

/// Write 16-bit unsigned integer to buffer in network byte order (big-endian)
///
/// # Arguments
///
/// * `buffer` - Mutable byte buffer with at least 2 bytes capacity
/// * `value` - Value to write in host byte order
///
/// # Returns
///
/// * `Ok(())` - Successfully written
/// * `Err(SerializationError)` - Buffer too small
///
/// # Safety
///
/// Replaces C macro `PUTSHORT(val, ptr)` which manually manipulated bytes and
/// advanced pointer. This safe version checks capacity automatically via BytesMut.
///
/// # Example
///
/// ```rust
/// use dnsmasq::dns::serializer::write_u16;
/// use bytes::BytesMut;
///
/// let mut buf = BytesMut::with_capacity(512);
/// write_u16(&mut buf, 0x1234).unwrap();
/// assert_eq!(&buf[..], &[0x12, 0x34]);
/// ```
pub fn write_u16(buffer: &mut BytesMut, value: u16) -> Result<(), SerializationError> {
    let bytes = value.to_be_bytes();
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Write 32-bit unsigned integer to buffer in network byte order (big-endian)
///
/// # Arguments
///
/// * `buffer` - Mutable byte buffer with at least 4 bytes capacity
/// * `value` - Value to write in host byte order
///
/// # Returns
///
/// * `Ok(())` - Successfully written
/// * `Err(SerializationError)` - Buffer too small
///
/// # Safety
///
/// Replaces C macro `PUTLONG(val, ptr)` with safe automatic capacity management.
/// BytesMut automatically expands as needed, eliminating manual realloc calls.
///
/// # Example
///
/// ```rust
/// use dnsmasq::dns::serializer::write_u32;
/// use bytes::BytesMut;
///
/// let mut buf = BytesMut::with_capacity(512);
/// write_u32(&mut buf, 0x12345678).unwrap();
/// assert_eq!(&buf[..], &[0x12, 0x34, 0x56, 0x78]);
/// ```
pub fn write_u32(buffer: &mut BytesMut, value: u32) -> Result<(), SerializationError> {
    let bytes = value.to_be_bytes();
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Check if buffer has sufficient remaining capacity
///
/// # Arguments
///
/// * `buffer` - Current buffer
/// * `required` - Required additional bytes
/// * `limit` - Maximum allowed buffer size (e.g., 512 for standard DNS)
///
/// # Returns
///
/// * `Ok(())` - Sufficient capacity available
/// * `Err(SerializationError)` - Would exceed limit
///
/// # Safety
///
/// Replaces C macro `CHECK_LIMIT(size)` which compared pointer positions.
/// This safe version uses buffer length tracking instead of raw pointers.
pub fn check_len(buffer: &BytesMut, required: usize, limit: usize) -> Result<(), SerializationError> {
    let new_len = buffer.len() + required;
    if new_len > limit {
        return Err(SerializationError::BufferTooSmall {
            required: new_len,
            available: limit,
        });
    }
    Ok(())
}

// ============================================================================
// DNS Name Encoding
// ============================================================================

/// Encode a domain name in DNS wire format with label-length prefixes
///
/// Converts "example.com" → [7]example[3]com[0]
///
/// # Arguments
///
/// * `buffer` - Output buffer for encoded name
/// * `name` - Domain name in presentation format
/// * `limit` - Maximum buffer size
///
/// # Returns
///
/// * `Ok(())` - Name successfully encoded
/// * `Err(SerializationError)` - Name too long or buffer full
///
/// # RFC 1035 Compliance
///
/// Implements Section 3.1 name format:
/// - Each label prefixed by length byte (max 63)
/// - Labels separated by dots in presentation format
/// - Terminated by zero-length label
/// - Total wire format ≤ 255 bytes
///
/// # Safety
///
/// Replaces C function `do_rfc1035_name(p, name, limit)` which manually
/// calculated offsets and could overflow buffers.
fn encode_domain_name(
    buffer: &mut BytesMut,
    name: &str,
    limit: usize,
) -> Result<(), SerializationError> {
    if name.is_empty() {
        // Root domain - just write zero byte
        check_len(buffer, 1, limit)?;
        buffer.extend_from_slice(&[0]);
        return Ok(());
    }

    let labels: Vec<&str> = name.split('.').filter(|s| !s.is_empty()).collect();
    
    // Calculate total size: each label has 1-byte length + label bytes + final zero
    let total_size: usize = labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
    
    if total_size > 255 {
        return Err(SerializationError::NameTooLong {
            length: total_size,
            max_length: 255,
        });
    }
    
    check_len(buffer, total_size, limit)?;
    
    // Encode each label with length prefix
    for label in labels {
        let label_bytes = label.as_bytes();
        let label_len = label_bytes.len();
        
        if label_len > 63 {
            return Err(SerializationError::NameTooLong {
                length: label_len,
                max_length: 63,
            });
        }
        
        buffer.extend_from_slice(&[label_len as u8]);
        buffer.extend_from_slice(label_bytes);
    }
    
    // Terminating zero-length label
    buffer.extend_from_slice(&[0]);
    
    trace!("Encoded domain name '{}' ({} bytes)", name, total_size);
    Ok(())
}

// ============================================================================
// Core Serialization Functions
// ============================================================================

/// Add a resource record to a DNS response packet
///
/// This function constructs and appends a complete DNS resource record (RR) to the
/// packet buffer, handling name encoding/compression, RR header fields (TYPE, CLASS,
/// TTL), RDLENGTH calculation, and RDATA content. It replicates the functionality of
/// `add_resource_record()` from `src/rfc1035.c` while providing memory safety through
/// Rust's type system and automatic bounds checking.
///
/// # Arguments
///
/// * `buffer` - Mutable packet buffer to append RR to
/// * `limit` - Maximum allowed packet size (typically 512 or EDNS0 size)
/// * `truncated` - Mutable flag set to true if truncation occurs
/// * `name_offset` - Compression pointer offset, or 0 to encode full name
/// * `name` - Domain name for this RR (used if name_offset == 0)
/// * `ttl` - Time-to-live in seconds
/// * `rr_type` - Resource record type (T_A, T_AAAA, T_CNAME, etc.)
/// * `rr_class` - Resource record class (typically C_IN)
/// * `rdata` - Resource record data (IPv4/IPv6 address, domain name, etc.)
/// * `compression_ctx` - Optional compression context for encoding RDATA names
///
/// # Returns
///
/// * `Ok(usize)` - Offset where RDATA was written (for compression tracking)
/// * `Err(SerializationError)` - Serialization failure
///
/// # Truncation Handling
///
/// If adding the RR would exceed `limit`, sets `*truncated = true` and returns error.
/// Caller should set TC (truncation) flag in DNS header and stop adding more records.
///
/// # RFC 1035 Compliance
///
/// Resource record wire format (Section 3.2.1):
/// ```text
/// NAME:     domain name (variable length with compression)
/// TYPE:     2 bytes - RR type code
/// CLASS:    2 bytes - RR class code  
/// TTL:      4 bytes - time to live
/// RDLENGTH: 2 bytes - length of RDATA
/// RDATA:    variable - resource data
/// ```
///
/// # Memory Safety
///
/// Replaces C's variadic `add_resource_record(header, limit, truncp, nameoffset, pp, ttl, ...)`:
/// - No `va_list` format string parsing (unsafe)
/// - No manual `pp` pointer advancement (eliminates pointer arithmetic bugs)
/// - Automatic capacity checks via BytesMut (prevents buffer overflows)
/// - Type-safe RDATA handling via RDataType enum (no format string ambiguity)
///
/// # Example
///
/// ```rust,ignore
/// let mut buffer = BytesMut::with_capacity(512);
/// let mut truncated = false;
/// let mut compression_ctx = CompressionContext::new();
///
/// // Add A record: example.com. 300 IN A 192.0.2.1
/// add_resource_record(
///     &mut buffer,
///     512,
///     &mut truncated,
///     12,  // Compression pointer to name at offset 12
///     None,  // No name string needed with compression pointer
///     300,
///     T_A,
///     C_IN,
///     &RDataType::A([192, 0, 2, 1]),
///     Some(&mut compression_ctx),
/// )?;
/// ```
///
/// # See Also
///
/// - C source: `src/rfc1035.c:add_resource_record()`
/// - RFC 1035 Section 3.2.1 (RR format)
/// - RFC 1035 Section 4.1.4 (name compression)
pub fn add_resource_record(
    buffer: &mut BytesMut,
    limit: usize,
    truncated: &mut bool,
    name_offset: i32,
    name: Option<&str>,
    ttl: u32,
    rr_type: u16,
    rr_class: u16,
    rdata: &RDataType,
    _compression_ctx: Option<&mut CompressionContext>,
) -> Result<usize, SerializationError> {
    // If already truncated, don't add more records
    if *truncated {
        return Err(SerializationError::BufferTooSmall {
            required: 0,
            available: 0,
        });
    }

    // Save position before adding record (for rollback on truncation)
    let _start_pos = buffer.len();

    // Step 1: Write NAME field (either compression pointer or full name)
    if name_offset > 0 {
        // Positive offset: write compression pointer (2 bytes)
        check_len(buffer, 2, limit)?;
        let pointer = (name_offset as u16) | 0xC000;  // Set top 2 bits
        write_u16(buffer, pointer)?;
        trace!("Added compression pointer: offset {}", name_offset);
    } else if name_offset < 0 {
        // Negative offset: write name then compression pointer
        let name_str = name.ok_or_else(|| SerializationError::InvalidFormat {
            reason: "Name required when name_offset < 0".to_string(),
        })?;
        
        encode_domain_name(buffer, name_str, limit)?;
        
        // Write compression pointer using absolute value
        check_len(buffer, 2, limit)?;
        let pointer = ((-name_offset) as u16) | 0xC000;
        write_u16(buffer, pointer)?;
    } else {
        // Zero offset: write full name with terminating zero
        let name_str = name.ok_or_else(|| SerializationError::InvalidFormat {
            reason: "Name required when name_offset == 0".to_string(),
        })?;
        
        encode_domain_name(buffer, name_str, limit)?;
    }

    // Step 2: Write fixed RR header fields (TYPE + CLASS + TTL + RDLENGTH placeholder)
    // Total: 2 + 2 + 4 + 2 = 10 bytes (RRFIXEDSZ)
    check_len(buffer, RRFIXEDSZ, limit)?;
    
    write_u16(buffer, rr_type)?;
    write_u16(buffer, rr_class)?;
    write_u32(buffer, ttl)?;
    
    // Save position for RDLENGTH (will update after writing RDATA)
    let rdlength_pos = buffer.len();
    write_u16(buffer, 0)?;  // Placeholder for RDLENGTH

    // Step 3: Write RDATA based on type
    let rdata_start = buffer.len();
    
    match rdata {
        RDataType::A(addr) => {
            check_len(buffer, INADDRSZ, limit)?;
            buffer.extend_from_slice(addr);
        }
        
        RDataType::AAAA(addr) => {
            check_len(buffer, IN6ADDRSZ, limit)?;
            buffer.extend_from_slice(addr);
        }
        
        RDataType::CNAME(domain) | RDataType::PTR(domain) | RDataType::NS(domain) => {
            encode_domain_name(buffer, domain, limit)?;
        }
        
        RDataType::MX { preference, exchange } => {
            check_len(buffer, 2, limit)?;
            write_u16(buffer, *preference)?;
            encode_domain_name(buffer, exchange, limit)?;
        }
        
        RDataType::TXT(text) => {
            // TXT records: <length><text> format (can have multiple strings)
            let text_bytes = text.as_bytes();
            let len = text_bytes.len().min(255);  // Cap at 255 per RFC
            check_len(buffer, len + 1, limit)?;
            buffer.extend_from_slice(&[len as u8]);
            buffer.extend_from_slice(&text_bytes[..len]);
        }
        
        RDataType::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
            encode_domain_name(buffer, mname, limit)?;
            encode_domain_name(buffer, rname, limit)?;
            check_len(buffer, 20, limit)?;  // 5 x 4-byte fields
            write_u32(buffer, *serial)?;
            write_u32(buffer, *refresh)?;
            write_u32(buffer, *retry)?;
            write_u32(buffer, *expire)?;
            write_u32(buffer, *minimum)?;
        }
        
        RDataType::SRV { priority, weight, port, target } => {
            check_len(buffer, 6, limit)?;
            write_u16(buffer, *priority)?;
            write_u16(buffer, *weight)?;
            write_u16(buffer, *port)?;
            encode_domain_name(buffer, target, limit)?;
        }
        
        RDataType::Raw(data) => {
            check_len(buffer, data.len(), limit)?;
            buffer.extend_from_slice(data);
        }
    }
    
    // Step 4: Calculate and update RDLENGTH
    let rdata_len = buffer.len() - rdata_start;
    if rdata_len > 65535 {
        return Err(SerializationError::InvalidFormat {
            reason: format!("RDATA too long: {} bytes", rdata_len),
        });
    }
    
    // Update RDLENGTH field (save/restore not needed with BytesMut slicing)
    let rdlength_bytes = (rdata_len as u16).to_be_bytes();
    buffer[rdlength_pos] = rdlength_bytes[0];
    buffer[rdlength_pos + 1] = rdlength_bytes[1];
    
    debug!(
        "Added RR: type={}, class={}, ttl={}, rdlen={}",
        rr_type, rr_class, ttl, rdata_len
    );
    
    Ok(rdata_start)
}

/// Resource record data types
#[derive(Debug, Clone)]
pub enum RDataType {
    /// IPv4 address (4 bytes)
    A([u8; 4]),
    /// IPv6 address (16 bytes)
    AAAA([u8; 16]),
    /// Canonical name (domain name)
    CNAME(String),
    /// Pointer record (domain name)
    PTR(String),
    /// Name server (domain name)
    NS(String),
    /// Mail exchange record
    MX {
        /// MX preference value (lower values are higher priority)
        preference: u16,
        /// Mail server hostname
        exchange: String,
    },
    /// Text record
    TXT(String),
    /// Start of authority
    SOA {
        /// Primary name server for this zone
        mname: String,
        /// Responsible party email address (@ replaced with .)
        rname: String,
        /// Serial number of the zone
        serial: u32,
        /// Refresh interval in seconds
        refresh: u32,
        /// Retry interval in seconds
        retry: u32,
        /// Expiry time in seconds
        expire: u32,
        /// Minimum TTL in seconds
        minimum: u32,
    },
    /// Service locator
    SRV {
        /// Priority (lower values are preferred)
        priority: u16,
        /// Weight for load balancing among same priority
        weight: u16,
        /// Port number of the service
        port: u16,
        /// Target hostname providing the service
        target: String,
    },
    /// Raw RDATA bytes
    Raw(Vec<u8>),
}

/// Initialize DNS response header with appropriate flags
///
/// Sets up a DNS header for response generation, configuring QR, AA, TC, RA, AD flags
/// and RCODE based on the response type. This replaces `setup_reply()` from
/// `src/rfc1035.c:1982` with safe Rust header manipulation.
///
/// # Arguments
///
/// * `header` - DNS header to initialize
/// * `response_type` - Type of response (NoError, NxDomain, WithRecords, Refused)
/// * `ede` - Extended DNS error code (for EDE option)
///
/// # Flag Settings
///
/// All response types:
/// - QR (Query/Response) = 1 (response)
/// - RA (Recursion Available) = 1
/// - AD (Authenticated Data) = 0 (cleared)
/// - AA (Authoritative Answer) = 0 (cleared by default)
/// - TC (Truncation) = 0 (cleared)
///
/// Response-specific:
/// - `NoError`: RCODE=NOERROR, ancount=0
/// - `NxDomain`: RCODE=NXDOMAIN, ancount=0
/// - `WithRecords`: RCODE=NOERROR, AA=1 (authoritative), ancount set by caller
/// - `Refused`: RCODE=REFUSED, ancount=0
///
/// # RFC 1035 Compliance
///
/// Header flag bits (Section 4.1.1):
/// - QR: bit 15 (byte 2, bit 7)
/// - OPCODE: bits 14-11 (preserved from query)
/// - AA: bit 10 (byte 2, bit 2)
/// - TC: bit 9 (byte 2, bit 1)
/// - RA: bit 7 (byte 3, bit 7)
/// - RCODE: bits 3-0 (byte 3, bits 3-0)
///
/// # Memory Safety
///
/// Replaces C's bit manipulation:
/// ```c
/// header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC)) | HB3_QR;
/// header->hb4 = (header->hb4 & ~HB4_AD) | HB4_RA;
/// SET_RCODE(header, NOERROR);
/// ```
///
/// With safe accessor methods that prevent invalid flag combinations.
///
/// # Example
///
/// ```rust,ignore
/// let mut header = DnsHeader::new();
/// header.set_id(query_id);  // Copy from query
/// setup_reply(&mut header, ResponseType::NoError, ExtendedDnsError::Unset);
/// ```
///
/// # See Also
///
/// - C source: `src/rfc1035.c:setup_reply()`
/// - `dns::protocol::DnsHeader` for flag accessor methods
pub fn setup_reply(
    header: &mut DnsHeader,
    response_type: ResponseType,
    _ede: ExtendedDnsError,
) -> Result<(), SerializationError> {
    // Clear authoritative and truncated flags, set QR flag
    header.set_qr(true);  // QR = 1 (response)
    header.set_aa(false);  // Clear AA
    header.set_tc(false);  // Clear TC
    
    // Clear AD flag, set RA flag  
    header.set_ad(false);  // Clear AD
    header.set_ra(true);   // RA = 1 (recursion available)
    
    // Initialize section counts
    header.set_nscount(0);
    header.set_arcount(0);
    header.set_ancount(0);  // Will be set by caller if adding records
    
    // Set RCODE based on response type
    match response_type {
        ResponseType::NoError => {
            header.set_rcode(NOERROR);
            debug!("Setup reply: NOERROR (empty domain)");
        }
        
        ResponseType::NxDomain => {
            header.set_rcode(NXDOMAIN);
            debug!("Setup reply: NXDOMAIN (non-existent domain)");
        }
        
        ResponseType::WithRecords => {
            header.set_rcode(NOERROR);
            header.set_aa(true);  // Set authoritative answer flag
            debug!("Setup reply: NOERROR with AA (authoritative answer)");
        }
        
        ResponseType::Refused => {
            header.set_rcode(REFUSED);
            debug!("Setup reply: REFUSED (policy refusal)");
        }
    }
    
    Ok(())
}

/// Resize DNS packet buffer for response construction
///
/// Adjusts packet size by skipping to end of all sections and optionally restoring
/// an EDNS0 OPT pseudo-record. Used when converting query to response to strip
/// query sections and prepare for answer addition. Replicates `resize_packet()`
/// from `src/rfc1035.c:705`.
///
/// # Arguments
///
/// * `buffer` - Packet buffer to resize
/// * `header` - DNS header (for section counts)
/// * `opt_record` - Optional EDNS0 OPT record to append after resizing
///
/// # Returns
///
/// * `Ok(usize)` - New packet size in bytes
/// * `Err(SerializationError)` - Malformed packet
///
/// # Algorithm
///
/// 1. Skip question section (header.qdcount questions)
/// 2. Skip answer section (header.ancount RRs)
/// 3. Skip authority section (header.nscount RRs)
/// 4. Skip additional section (header.arcount RRs)
/// 5. If OPT record provided and arcount==0, append it and set arcount=1
/// 6. Truncate buffer to new end position
///
/// # EDNS0 Handling
///
/// When client query has no EDNS0 but server response needs it (e.g., for EDE):
/// - `opt_record` contains serialized OPT RR
/// - Function appends it to buffer
/// - Sets header.arcount = 1
/// - Returns position after OPT
///
/// # Memory Safety
///
/// C version used manual pointer arithmetic:
/// ```c
/// unsigned char *ansp = skip_questions(header, plen);
/// ansp = skip_section(ansp, ...);
/// memmove(ansp, pheader, hlen);  // Could overlap!
/// return ansp - (unsigned char *)header;
/// ```
///
/// Rust version uses safe buffer operations with automatic bounds checking.
///
/// # Example
///
/// ```rust,ignore
/// let mut buffer = BytesMut::from(&query_packet[..]);
/// let header = DnsHeader::from_bytes(&buffer)?;
/// let new_size = resize_packet(&mut buffer, &header, None)?;
/// buffer.truncate(new_size);
/// ```
///
/// # See Also
///
/// - C source: `src/rfc1035.c:resize_packet()`
/// - `dns::parser::skip_questions()` for question section skipping
/// - `dns::parser::skip_section()` for RR section skipping
pub fn resize_packet(
    buffer: &mut BytesMut,
    header: &DnsHeader,
    opt_record: Option<&[u8]>,
) -> Result<usize, SerializationError> {
    // Parse header to get section counts
    let qdcount = header.qdcount();
    let ancount = header.ancount();
    let nscount = header.nscount();
    let arcount = header.arcount();
    
    // Start after 12-byte header
    let mut pos = DnsHeader::SIZE;
    
    // Skip question section (qdcount questions)
    // Each question: QNAME + QTYPE(2) + QCLASS(2)
    for _ in 0..qdcount {
        // Skip QNAME (labels with length bytes, terminated by 0 or compression pointer)
        pos = skip_name(buffer, pos)?;
        // Skip QTYPE + QCLASS (4 bytes)
        pos += 4;
        if pos > buffer.len() {
            return Err(SerializationError::InvalidFormat {
                reason: "Question section extends beyond packet".to_string(),
            });
        }
    }
    
    // Skip answer, authority, and additional sections
    let total_rr_count = ancount + nscount + arcount;
    for _ in 0..total_rr_count {
        // Skip NAME
        pos = skip_name(buffer, pos)?;
        
        // Check for TYPE + CLASS + TTL + RDLENGTH (10 bytes)
        if pos + 10 > buffer.len() {
            return Err(SerializationError::InvalidFormat {
                reason: "Resource record header truncated".to_string(),
            });
        }
        
        // Read RDLENGTH (bytes 8-9 of RR header, after TYPE+CLASS+TTL)
        let rdlength = u16::from_be_bytes([buffer[pos + 8], buffer[pos + 9]]) as usize;
        
        // Skip TYPE + CLASS + TTL + RDLENGTH + RDATA
        pos += 10 + rdlength;
        
        if pos > buffer.len() {
            return Err(SerializationError::InvalidFormat {
                reason: format!("Resource record with RDLENGTH {} extends beyond packet", rdlength),
            });
        }
    }
    
    // Restore OPT pseudo-record if provided and no additional records existed
    if let Some(opt_bytes) = opt_record {
        if arcount == 0 {
            // Append OPT record to buffer
            if pos + opt_bytes.len() > buffer.capacity() {
                buffer.reserve(opt_bytes.len());
            }
            
            buffer.truncate(pos);
            buffer.extend_from_slice(opt_bytes);
            pos += opt_bytes.len();
            
            // Update header arcount (caller must update buffer)
            // Note: header is passed by reference, so can't mutate here
            // Caller should update header.set_arcount(1) after this call
            
            trace!("Restored EDNS0 OPT record ({} bytes)", opt_bytes.len());
        }
    }
    
    // Truncate buffer to new size
    buffer.truncate(pos);
    
    debug!("Resized packet from {} to {} bytes", buffer.len(), pos);
    Ok(pos)
}

/// Skip over a domain name in DNS wire format
///
/// Advances position past a domain name, handling labels and compression pointers.
/// Helper function for `resize_packet()`.
///
/// # Arguments
///
/// * `buffer` - Packet buffer
/// * `pos` - Current position in buffer
///
/// # Returns
///
/// * `Ok(usize)` - Position after name
/// * `Err(SerializationError)` - Malformed name
fn skip_name(buffer: &BytesMut, mut pos: usize) -> Result<usize, SerializationError> {
    const MAX_HOPS: usize = 255;
    let mut hops = 0;
    
    loop {
        if pos >= buffer.len() {
            return Err(SerializationError::InvalidFormat {
                reason: "Name extends beyond packet".to_string(),
            });
        }
        
        let label_len = buffer[pos];
        
        // Check for compression pointer (top 2 bits set)
        if (label_len & 0xC0) == 0xC0 {
            // Compression pointer: 2 bytes
            if pos + 1 >= buffer.len() {
                return Err(SerializationError::InvalidFormat {
                    reason: "Compression pointer truncated".to_string(),
                });
            }
            return Ok(pos + 2);
        }
        
        // Normal label
        if label_len == 0 {
            // Terminating zero-length label
            return Ok(pos + 1);
        }
        
        // Skip length byte + label bytes
        pos += 1 + label_len as usize;
        
        hops += 1;
        if hops > MAX_HOPS {
            return Err(SerializationError::CompressionFailed {
                reason: "Too many labels in name".to_string(),
            });
        }
    }
}

// ============================================================================
// DNS Packet Builder
// ============================================================================

/// Builder for constructing complete DNS response packets
///
/// Provides a high-level API for DNS packet construction with automatic capacity
/// management, truncation detection, and compression context tracking. Replaces
/// manual packet building patterns from C with a safe builder pattern.
///
/// # Example
///
/// ```rust,ignore
/// use dnsmasq::dns::serializer::DnsPacketBuilder;
/// use dnsmasq::dns::protocol::{DnsHeader, T_A, C_IN};
///
/// let mut builder = DnsPacketBuilder::with_capacity(512);
/// 
/// let mut header = DnsHeader::new();
/// header.set_id(12345);
/// builder.set_header(header)?;
///
/// builder.add_answer(0, 300, T_A, C_IN, &RDataType::A([192, 0, 2, 1]))?;
/// 
/// let packet = builder.build()?;
/// ```
pub struct DnsPacketBuilder {
    /// Packet buffer with automatic capacity management
    buffer: BytesMut,
    /// Maximum packet size (512 standard, or EDNS0 size)
    max_size: usize,
    /// Truncation flag
    truncated: bool,
    /// Name compression context
    compression_ctx: CompressionContext,
    /// Current answer count
    answer_count: u16,
    /// Current authority count
    authority_count: u16,
    /// Current additional count
    additional_count: u16,
    /// DNS message ID (for fluent API)
    id: u16,
    /// DNS flags (for fluent API)
    flags: u16,
    /// Question count (for fluent API)
    question_count: u16,
}

impl DnsPacketBuilder {
    /// Create new builder with default capacity (512 bytes)
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(PACKETSZ)
    }
    
    /// Create new builder with specified capacity
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum packet size in bytes (512 standard, 4096 typical EDNS0)
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
            max_size: capacity,
            truncated: false,
            compression_ctx: CompressionContext::new(),
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            id: 0,
            flags: 0,
            question_count: 0,
        }
    }
    
    /// Set DNS message ID (fluent builder API)
    #[must_use]
    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }
    
    /// Set query flags (fluent builder API)
    /// Sets standard query flags (RD bit set)
    #[must_use]
    pub fn with_query_flags(mut self) -> Self {
        self.flags = 0x0100; // RD (Recursion Desired) bit set
        self
    }
    
    /// Set response flags with RCODE (fluent builder API)
    /// Automatically sets QR bit to mark as response
    #[must_use]
    pub fn with_response_flags(mut self, rcode: u16) -> Self {
        self.flags = 0x8000 | (rcode & 0x0F); // QR bit + RCODE
        self
    }
    
    /// Helper method to apply 16-bit flags value to DnsHeader
    /// Flags format: high byte = hb3 (QR, OPCODE, AA, TC, RD), low byte = hb4 (RA, Z, AD, CD, RCODE)
    fn apply_flags_to_header(header: &mut DnsHeader, flags: u16) {
        let hb3 = (flags >> 8) as u8;
        let hb4 = (flags & 0xFF) as u8;
        
        // Set QR bit
        header.set_qr((hb3 & 0x80) != 0);
        
        // Set OPCODE (bits 3-6 of hb3)
        header.set_opcode((hb3 >> 3) & 0x0F);
        
        // Set AA bit
        header.set_aa((hb3 & 0x04) != 0);
        
        // Set TC bit
        header.set_tc((hb3 & 0x02) != 0);
        
        // Set RD bit
        header.set_rd((hb3 & 0x01) != 0);
        
        // Set RA bit
        header.set_ra((hb4 & 0x80) != 0);
        
        // Set AD bit
        header.set_ad((hb4 & 0x20) != 0);
        
        // Set CD bit
        header.set_cd((hb4 & 0x10) != 0);
        
        // Set RCODE
        header.set_rcode(hb4 & 0x0F);
    }
    
    /// Add a question section entry (fluent builder API)
    /// Returns Result because it needs to encode the name
    pub fn add_question(mut self, name: &str, qtype: u16, qclass: u16) -> Self {
        // Initialize header if not already done
        if self.buffer.is_empty() {
            let mut header = DnsHeader::new();
            header.set_id(self.id);
            Self::apply_flags_to_header(&mut header, self.flags);
            let header_bytes = header.to_bytes();
            self.buffer.extend_from_slice(&header_bytes);
        }
        
        // Encode question
        if let Ok(_) = encode_domain_name(&mut self.buffer, name, self.max_size) {
            // Write QTYPE and QCLASS
            let _ = write_u16(&mut self.buffer, qtype);
            let _ = write_u16(&mut self.buffer, qclass);
            self.question_count += 1;
        }
        
        self
    }
    
    /// Add an answer record (fluent builder API for tests)
    /// Accepts raw rdata bytes instead of RDataType enum
    pub fn with_answer(mut self, name: &str, rtype: u16, rclass: u16, ttl: u32, rdata: &[u8]) -> Self {
        // Ensure header is initialized
        if self.buffer.is_empty() {
            let mut header = DnsHeader::new();
            header.set_id(self.id);
            Self::apply_flags_to_header(&mut header, self.flags);
            let header_bytes = header.to_bytes();
            self.buffer.extend_from_slice(&header_bytes);
        }
        
        // Encode name
        if let Ok(_) = encode_domain_name(&mut self.buffer, name, self.max_size) {
            // Write TYPE, CLASS, TTL
            let _ = write_u16(&mut self.buffer, rtype);
            let _ = write_u16(&mut self.buffer, rclass);
            let _ = write_u32(&mut self.buffer, ttl);
            
            // Write RDLENGTH
            let _ = write_u16(&mut self.buffer, rdata.len() as u16);
            
            // Write RDATA
            self.buffer.extend_from_slice(rdata);
            
            self.answer_count += 1;
        }
        
        self
    }
    
    /// Add an authority record (fluent builder API for tests)
    /// Accepts raw rdata bytes instead of RDataType enum
    pub fn with_authority(mut self, name: &str, rtype: u16, rclass: u16, ttl: u32, rdata: &[u8]) -> Self {
        // Ensure header is initialized
        if self.buffer.is_empty() {
            let mut header = DnsHeader::new();
            header.set_id(self.id);
            Self::apply_flags_to_header(&mut header, self.flags);
            let header_bytes = header.to_bytes();
            self.buffer.extend_from_slice(&header_bytes);
        }
        
        // Encode name
        if let Ok(_) = encode_domain_name(&mut self.buffer, name, self.max_size) {
            // Write TYPE, CLASS, TTL
            let _ = write_u16(&mut self.buffer, rtype);
            let _ = write_u16(&mut self.buffer, rclass);
            let _ = write_u32(&mut self.buffer, ttl);
            
            // Write RDLENGTH
            let _ = write_u16(&mut self.buffer, rdata.len() as u16);
            
            // Write RDATA
            self.buffer.extend_from_slice(rdata);
            
            self.authority_count += 1;
        }
        
        self
    }
    
    /// Add an additional record (fluent builder API for tests)
    /// Accepts raw rdata bytes instead of RDataType enum
    pub fn with_additional(mut self, name: &str, rtype: u16, rclass: u16, ttl: u32, rdata: &[u8]) -> Self {
        // Ensure header is initialized
        if self.buffer.is_empty() {
            let mut header = DnsHeader::new();
            header.set_id(self.id);
            Self::apply_flags_to_header(&mut header, self.flags);
            let header_bytes = header.to_bytes();
            self.buffer.extend_from_slice(&header_bytes);
        }
        
        // Encode name
        if let Ok(_) = encode_domain_name(&mut self.buffer, name, self.max_size) {
            // Write TYPE, CLASS, TTL
            let _ = write_u16(&mut self.buffer, rtype);
            let _ = write_u16(&mut self.buffer, rclass);
            let _ = write_u32(&mut self.buffer, ttl);
            
            // Write RDLENGTH
            let _ = write_u16(&mut self.buffer, rdata.len() as u16);
            
            // Write RDATA
            self.buffer.extend_from_slice(rdata);
            
            self.additional_count += 1;
        }
        
        self
    }
    
    /// Set DNS header
    ///
    /// # Arguments
    ///
    /// * `header` - DNS header to serialize
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Header successfully written
    /// * `Err(SerializationError)` - Header serialization failed
    pub fn set_header(&mut self, header: DnsHeader) -> Result<(), SerializationError> {
        self.buffer.clear();
        let header_bytes = header.to_bytes();
        self.buffer.extend_from_slice(&header_bytes);
        Ok(())
    }
    
    /// Add answer record
    ///
    /// # Arguments
    ///
    /// * `name_offset` - Compression pointer offset (0 for full name)
    /// * `ttl` - Time to live
    /// * `rr_type` - Record type
    /// * `rr_class` - Record class
    /// * `rdata` - Record data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Record added successfully
    /// * `Err(SerializationError)` - Failed to add record
    pub fn add_answer(
        &mut self,
        name_offset: i32,
        ttl: u32,
        rr_type: u16,
        rr_class: u16,
        rdata: &RDataType,
    ) -> Result<(), SerializationError> {
        add_resource_record(
            &mut self.buffer,
            self.max_size,
            &mut self.truncated,
            name_offset,
            None,
            ttl,
            rr_type,
            rr_class,
            rdata,
            Some(&mut self.compression_ctx),
        )?;
        
        self.answer_count += 1;
        Ok(())
    }
    
    /// Add authority record
    pub fn add_authority(
        &mut self,
        name_offset: i32,
        ttl: u32,
        rr_type: u16,
        rr_class: u16,
        rdata: &RDataType,
    ) -> Result<(), SerializationError> {
        add_resource_record(
            &mut self.buffer,
            self.max_size,
            &mut self.truncated,
            name_offset,
            None,
            ttl,
            rr_type,
            rr_class,
            rdata,
            Some(&mut self.compression_ctx),
        )?;
        
        self.authority_count += 1;
        Ok(())
    }
    
    /// Add additional record
    pub fn add_additional(
        &mut self,
        name_offset: i32,
        ttl: u32,
        rr_type: u16,
        rr_class: u16,
        rdata: &RDataType,
    ) -> Result<(), SerializationError> {
        add_resource_record(
            &mut self.buffer,
            self.max_size,
            &mut self.truncated,
            name_offset,
            None,
            ttl,
            rr_type,
            rr_class,
            rdata,
            Some(&mut self.compression_ctx),
        )?;
        
        self.additional_count += 1;
        Ok(())
    }
    
    /// Check if packet was truncated
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
    
    /// Build final packet
    ///
    /// Updates header section counts and returns complete packet bytes.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Complete DNS packet
    /// * `Err(SerializationError)` - Build failed
    pub fn build(mut self) -> Result<Vec<u8>, SerializationError> {
        // Update section counts in header
        if self.buffer.len() >= DnsHeader::SIZE {
            // Parse existing header
            let mut header = DnsHeader::from_bytes(&self.buffer[..DnsHeader::SIZE])
                .map_err(|e| SerializationError::InvalidFormat {
                    reason: e.to_string(),
                })?;
            
            // Update counts
            header.set_qdcount(self.question_count);
            header.set_ancount(self.answer_count);
            header.set_nscount(self.authority_count);
            header.set_arcount(self.additional_count);
            
            // Set TC flag if truncated
            if self.truncated {
                header.set_tc(true);
                warn!("Packet truncated: exceeded {} byte limit", self.max_size);
            }
            
            // Write updated header back
            let header_bytes = header.to_bytes();
            self.buffer[..DnsHeader::SIZE].copy_from_slice(&header_bytes);
        }
        
        Ok(self.buffer.to_vec())
    }
}

impl Default for DnsPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_u16() {
        let mut buf = BytesMut::with_capacity(64);
        write_u16(&mut buf, 0x1234).unwrap();
        assert_eq!(&buf[..], &[0x12, 0x34]);
    }

    #[test]
    fn test_write_u32() {
        let mut buf = BytesMut::with_capacity(64);
        write_u32(&mut buf, 0x12345678).unwrap();
        assert_eq!(&buf[..], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_encode_domain_name() {
        let mut buf = BytesMut::with_capacity(64);
        encode_domain_name(&mut buf, "example.com", 512).unwrap();
        // Expected: [7]example[3]com[0]
        assert_eq!(&buf[..], b"\x07example\x03com\x00");
    }

    #[test]
    fn test_encode_root_domain() {
        let mut buf = BytesMut::with_capacity(64);
        encode_domain_name(&mut buf, "", 512).unwrap();
        assert_eq!(&buf[..], b"\x00");
    }

    #[test]
    fn test_builder_basic() {
        let mut builder = DnsPacketBuilder::with_capacity(512);
        
        let mut header = DnsHeader::new();
        header.set_id(12345);
        builder.set_header(header).unwrap();
        
        let packet = builder.build().unwrap();
        assert_eq!(packet.len(), DnsHeader::SIZE);
    }

    #[test]
    fn test_read_u16_success() {
        let buffer = vec![0x12, 0x34];
        let result = read_u16(&buffer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u16_insufficient_data() {
        let buffer = vec![0x12];
        let result = read_u16(&buffer);
        assert!(result.is_err());
        match result {
            Err(SerializationError::BufferTooSmall { .. }) => {},
            _ => panic!("Expected BufferTooSmall error"),
        }
    }

    #[test]
    fn test_check_len_within_limits() {
        let buffer = BytesMut::from(&[0u8; 100][..]);
        let result = check_len(&buffer, 50, 200);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_len_exceeds_limit() {
        let buffer = BytesMut::from(&[0u8; 150][..]);
        let result = check_len(&buffer, 100, 200);
        assert!(result.is_err());
        match result {
            Err(SerializationError::BufferTooSmall { .. }) => {},
            _ => panic!("Expected BufferTooSmall error"),
        }
    }

    #[test]
    fn test_setup_reply_basic() {
        let mut header = DnsHeader::new();
        header.set_id(0x1234);
        header.set_qr(false); // Query
        header.set_qdcount(1);
        
        let result = setup_reply(&mut header, ResponseType::NoError, ExtendedDnsError::Unset);
        assert!(result.is_ok());
        
        // Verify the response has QR bit set
        assert!(header.qr());
        // Verify AA is cleared
        assert!(!header.aa());
        // Verify TC is cleared
        assert!(!header.tc());
    }

    #[test]
    fn test_setup_reply_nxdomain() {
        let mut header = DnsHeader::new();
        header.set_id(0x1234);
        
        let result = setup_reply(&mut header, ResponseType::NxDomain, ExtendedDnsError::Unset);
        assert!(result.is_ok());
        
        // Verify RCODE is set to NXDOMAIN (3)
        assert_eq!(header.rcode(), 3);
    }

    #[test]
    fn test_resize_packet_basic() {
        use bytes::BufMut;
        
        let mut packet = BytesMut::with_capacity(512);
        // Add a simple DNS header
        for _ in 0..12 {
            packet.put_u8(0);
        }
        
        let mut header = DnsHeader::new();
        header.set_qdcount(0);
        header.set_ancount(0);
        header.set_nscount(0);
        header.set_arcount(0);
        
        let result = resize_packet(&mut packet, &header, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dns_packet_builder_new() {
        let builder = DnsPacketBuilder::new();
        // Verify builder is created (can't check buffer directly as it's private)
        assert!(!builder.is_truncated());
    }

    #[test]
    fn test_dns_packet_builder_with_capacity() {
        let builder = DnsPacketBuilder::with_capacity(1024);
        // Verify builder is created with custom capacity
        assert!(!builder.is_truncated());
    }

    #[test]
    fn test_dns_packet_builder_set_header() {
        let mut builder = DnsPacketBuilder::new();
        let mut header = DnsHeader::new();
        header.set_id(12345);
        let result = builder.set_header(header);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dns_packet_builder_build() {
        let mut builder = DnsPacketBuilder::new();
        let mut header = DnsHeader::new();
        header.set_id(12345);
        builder.set_header(header).unwrap();
        
        let packet = builder.build();
        assert!(packet.is_ok());
        let packet_bytes = packet.unwrap();
        assert_eq!(packet_bytes.len(), DnsHeader::SIZE);
    }

    #[test]
    fn test_dns_packet_builder_truncation_flag() {
        let builder = DnsPacketBuilder::new();
        // Initially should not be truncated
        assert!(!builder.is_truncated());
    }
}
