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

//! DNS resource record filtering for safe RR removal from response packets
//!
//! This module provides safe removal of DNS resource records (RRs) from DNS response
//! packets while maintaining packet validity and DNS name compression integrity. The
//! primary challenge in RR removal is handling DNS name compression pointers that may
//! reference removed records. The implementation performs multi-pass processing to
//! detect invalid pointer references, adjust compression offsets, and physically
//! remove records while preserving packet structure per RFC 1035.
//!
//! # Purpose
//!
//! The filtering is used for multiple purposes:
//! - Removing DNSSEC validation records (RRSIG, NSEC, NSEC3) when not requested
//! - Stripping EDNS0 OPT pseudo-records
//! - Filtering A or AAAA records for policy enforcement
//!
//! All operations maintain DNS packet validity by updating section counts and ensuring
//! name compression pointers remain valid after record removal.
//!
//! # Key Responsibilities
//!
//! - `rrfilter()` - Main entry point for selective RR removal with four-pass algorithm
//! - `rrfilter_desc()` - Returns descriptor array for RR types containing domain names
//! - `check_name()` - Validates and adjusts DNS name compression pointers
//! - `check_rrs()` - Validates domain names in RR data sections
//!
//! # RFC Compliance
//!
//! - RFC 1035 Section 4.1.4: Domain Name Compression
//! - RFC 1035 Section 4.1: Message Format
//! - RFC 6891: Extension Mechanisms for DNS (EDNS0)
//! - RFC 4034: Resource Records for DNSSEC
//!
//! # Memory Safety
//!
//! Replaces C's manual memory management with:
//! - `Vec<(usize, usize)>` for tracking removed RR positions (replaces static unsigned char **rrs)
//! - Safe slice indexing with automatic bounds checking (replaces CHECK_LEN macros)
//! - `Vec::drain()` and `Vec::splice()` for safe record removal (replaces memmove)
//! - Rust's borrow checker prevents use-after-free and double-free vulnerabilities
//!
//! # Example Usage
//!
//! ```rust
//! use dnsmasq::dns::rrfilter::{rrfilter, RRFILTER_DNSSEC};
//!
//! let mut packet = vec![/* DNS packet bytes */];
//! let new_len = rrfilter(&mut packet, RRFILTER_DNSSEC)?;
//! // DNSSEC records removed, packet shrunk
//! packet.truncate(new_len);
//! ```

use crate::dns::protocol::{
    T_A, T_AAAA, T_AFSDB, T_CNAME, T_DNAME, T_KX, T_MB, T_MD, T_MF, T_MG, T_MINFO, T_MR, T_MX,
    T_NS, T_NSEC, T_NSEC3, T_NXT, T_OPT, T_PTR, T_PX, T_RP, T_RRSIG, T_RT, T_SIG, T_SOA, T_SRV,
    C_IN,
};
use crate::dns::parser::skip_name;
use crate::dns::compression::{
    COMPRESSION_POINTER_FLAG, COMPRESSION_OFFSET_MASK,
};
use std::fmt;
use tracing::{debug, warn, trace};

// Note on unused imports:
// - MAX_COMPRESSION_HOPS: Not applicable for this implementation since check_name()
//   validates and adjusts pointers without recursive pointer following
// - serializer::read_u16/write_u16/check_len: These are designed for BytesMut buffers
//   and are not suitable for in-place modification of &mut [u8] slices. We use direct
//   byte manipulation with manual bounds checking instead, which is equally safe.

// ============================================================================
// Constants
// ============================================================================

/// Filter mode: Remove EDNS0 OPT records from additional section
pub const RRFILTER_EDNS0: i32 = 1;

/// Filter mode: Remove DNSSEC validation records (RRSIG, NSEC, NSEC3)
pub const RRFILTER_DNSSEC: i32 = 2;

/// Filter mode: Remove A records from answer section
pub const RRFILTER_A: i32 = 3;

/// Filter mode: Remove AAAA records from answer section
pub const RRFILTER_AAAA: i32 = 4;

/// Descriptor array terminator
const DESC_END: u16 = 0xFFFF;

/// Hard limit on workspace expansion to prevent excessive allocation
const MAX_WORKSPACE_ENTRIES: usize = 100;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during RR filtering
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RRFilterError {
    /// Packet length insufficient for parsing
    InvalidLength {
        /// Expected minimum length in bytes
        expected: usize,
        /// Actual packet length in bytes
        actual: usize,
    },
    
    /// Invalid compression pointer detected
    InvalidCompressionPointer {
        /// Offset value from compression pointer
        offset: usize,
    },
    
    /// Compression pointer points into removed section
    PointerIntoRemovedSection {
        /// Offset value that points into removed section
        offset: usize,
    },
    
    /// Invalid label type encountered
    InvalidLabelType {
        /// Label type byte that was invalid
        label_type: u8,
    },
    
    /// Workspace expansion limit exceeded
    WorkspaceLimit,
}

impl fmt::Display for RRFilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RRFilterError::InvalidLength { expected, actual } => {
                write!(f, "Invalid packet length: expected {}, got {}", expected, actual)
            }
            RRFilterError::InvalidCompressionPointer { offset } => {
                write!(f, "Invalid compression pointer at offset {}", offset)
            }
            RRFilterError::PointerIntoRemovedSection { offset } => {
                write!(f, "Compression pointer at {} points into removed section", offset)
            }
            RRFilterError::InvalidLabelType { label_type } => {
                write!(f, "Invalid label type: 0x{:02X}", label_type)
            }
            RRFilterError::WorkspaceLimit => {
                write!(f, "Workspace expansion limit exceeded")
            }
        }
    }
}

impl std::error::Error for RRFilterError {}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate and adjust DNS name compression pointers after RR removal
///
/// Traverses a DNS domain name to validate or fix compression pointers after resource
/// records have been removed from a packet. DNS names use compression where repeated
/// domain components are replaced with two-byte pointers to earlier occurrences (RFC 1035
/// Section 4.1.4). When RRs are removed, pointers must be adjusted to account for the
/// removed bytes, and pointers targeting removed sections must be detected as invalid.
///
/// # Arguments
///
/// * `packet` - Complete DNS packet bytes (mutable for fixup)
/// * `pos` - Position of domain name to check
/// * `fixup` - If true, rewrite compression pointers; if false, only validate
/// * `rrs` - Array of removed RR position pairs [start, end, start, end, ...]
///
/// # Returns
///
/// * `Ok(next_pos)` - Position after the name on success
/// * `Err(RRFilterError)` - Invalid pointer or packet truncation
///
/// # RFC Compliance
///
/// Implements RFC 1035 Section 4.1.4 (Domain Name Compression) validation and adjustment.
/// Handles RFC 2673 binary labels (extended label type 0x41 for bitstrings).
fn check_name(
    packet: &mut [u8],
    mut pos: usize,
    fixup: bool,
    rrs: &[usize],
) -> Result<usize, RRFilterError> {
    loop {
        // Check we have at least 1 byte for label length/type
        if pos >= packet.len() {
            return Err(RRFilterError::InvalidLength {
                expected: pos + 1,
                actual: packet.len(),
            });
        }
        
        let label_byte = packet[pos];
        let label_type = label_byte & COMPRESSION_POINTER_FLAG;
        
        match label_type {
            // Compression pointer - uses COMPRESSION_POINTER_FLAG (0xC0)
            _ if label_type == COMPRESSION_POINTER_FLAG => {
                // Check we have 2 bytes for pointer
                if pos + 1 >= packet.len() {
                    return Err(RRFilterError::InvalidLength {
                        expected: pos + 2,
                        actual: packet.len(),
                    });
                }
                
                // Extract 14-bit offset (max value is COMPRESSION_OFFSET_MASK = 0x3FFF)
                let mut offset = ((packet[pos] & 0x3F) as usize) << 8;
                offset |= packet[pos + 1] as usize;
                let original_offset = offset;
                
                // Sanity check: offset should never exceed COMPRESSION_OFFSET_MASK due to bit masking
                debug_assert!(offset <= COMPRESSION_OFFSET_MASK as usize);
                
                // Adjust offset based on removed sections
                // rrs array is structured as: [start0, end0, start1, end1, ...]
                // Algorithm from C rrfilter.c lines 173-182:
                // - At each rrs[i], check if offset < rrs[i]
                // - If yes, break
                // - If no and i is odd (end marker), subtract the previous removed section size
                // - After loop, if i is odd, offset was inside a removed section (error)
                let mut i = 0;
                while i < rrs.len() {
                    if offset < rrs[i] {
                        break;
                    }
                    
                    // Only adjust at odd indices (after passing an end marker)
                    if i % 2 == 1 && i > 0 {
                        offset -= rrs[i] - rrs[i - 1];
                    }
                    
                    i += 1;
                }
                
                // Check if we stopped at an odd index (inside a removed section)
                if i > 0 && i % 2 == 1 {
                    trace!("Compression pointer at {} (offset {}) points into removed section [{}, {})",
                           pos, original_offset, rrs[i - 1], rrs[i]);
                    return Err(RRFilterError::PointerIntoRemovedSection { offset: original_offset });
                }
                
                // Fix up the pointer if requested
                if fixup {
                    packet[pos] = ((offset >> 8) as u8) | COMPRESSION_POINTER_FLAG;
                    packet[pos + 1] = (offset & 0xFF) as u8;
                    trace!("Fixed compression pointer at {} from {} to {}", pos, original_offset, offset);
                }
                
                return Ok(pos + 2);
            }
            
            // Reserved label type (0x80)
            0x80 => {
                debug!("Reserved label type 0x80 at position {}", pos);
                return Err(RRFilterError::InvalidLabelType { label_type });
            }
            
            // Extended label type (0x40) for bitstrings
            0x40 => {
                // Check we have at least 2 bytes
                if pos + 1 >= packet.len() {
                    return Err(RRFilterError::InvalidLength {
                        expected: pos + 2,
                        actual: packet.len(),
                    });
                }
                
                // We only understand bitstrings (type 1)
                if (packet[pos] & 0x3F) != 1 {
                    return Err(RRFilterError::InvalidLabelType { label_type });
                }
                
                pos += 1;
                let count = packet[pos] as usize;
                pos += 1;
                
                // count == 0 means 256 bits
                let byte_count = if count == 0 { 32 } else { ((count - 1) >> 3) + 1 };
                
                // Check bounds
                if pos + byte_count > packet.len() {
                    return Err(RRFilterError::InvalidLength {
                        expected: pos + byte_count,
                        actual: packet.len(),
                    });
                }
                
                pos += byte_count;
            }
            
            // Normal label (0x00)
            _ => {
                let label_len = (label_byte & 0x3F) as usize;
                
                // Zero-length label marks the end
                if label_len == 0 {
                    return Ok(pos + 1);
                }
                
                // Check bounds for label data
                if pos + 1 + label_len > packet.len() {
                    return Err(RRFilterError::InvalidLength {
                        expected: pos + 1 + label_len,
                        actual: packet.len(),
                    });
                }
                
                pos += 1 + label_len;
            }
        }
    }
}

/// Validate and adjust domain names within DNS resource record data sections
///
/// Iterates through all resource records in answer, authority, and additional sections
/// to validate or fix domain names embedded in RR RDATA fields. Many RR types contain
/// domain names as part of their data (NS, CNAME, MX, SOA, etc.), and these names may
/// use compression pointers that require adjustment after RR removal.
///
/// # Arguments
///
/// * `packet` - Complete DNS packet bytes (mutable for fixup)
/// * `pos` - Position of first RR after question section
/// * `rr_count` - Total number of RRs to process (ancount + nscount + arcount)
/// * `fixup` - If true, fix compression pointers; if false, only validate
/// * `rrs` - Flat array of removed RR positions [start, end, start, end, ...]
///
/// # Returns
///
/// * `Ok(())` - All names valid or successfully fixed
/// * `Err(RRFilterError)` - Invalid pointer or truncation
fn check_rrs(
    packet: &mut [u8],
    mut pos: usize,
    rr_count: usize,
    fixup: bool,
    rrs: &[usize],
) -> Result<(), RRFilterError> {
    for _ in 0..rr_count {
        let rr_start = pos;
        
        // Skip RR owner name
        let after_name = skip_name(packet, &packet[pos..])
            .map_err(|_| RRFilterError::InvalidLength {
                expected: pos + 10,
                actual: packet.len(),
            })?;
        pos = after_name.as_ptr() as usize - packet.as_ptr() as usize;
        
        // Check we have type, class, TTL, rdlen
        if pos + 10 > packet.len() {
            return Err(RRFilterError::InvalidLength {
                expected: pos + 10,
                actual: packet.len(),
            });
        }
        
        let rr_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let class = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        pos += 4; // Skip type and class
        pos += 4; // Skip TTL
        let rdlen = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
        pos += 2; // Skip rdlen
        
        // Check if this RR is marked for removal (in pairs in rrs array)
        let mut is_removed = false;
        let mut i = 0;
        while i + 1 < rrs.len() {
            if rr_start == rrs[i] {
                is_removed = true;
                break;
            }
            i += 2; // Skip to next start/end pair
        }
        
        // If not removed, validate/fix the RR
        if !is_removed {
            // Validate RR owner name
            check_name(packet, rr_start, fixup, rrs)?;
            
            // For class IN, check names in RDATA
            if class == C_IN {
                let desc = rrfilter_desc(rr_type);
                let mut rdata_pos = pos;
                
                for &desc_val in desc.iter() {
                    if desc_val == DESC_END {
                        break;
                    }
                    
                    if desc_val == 0 {
                        // Domain name at this position
                        rdata_pos = check_name(packet, rdata_pos, fixup, rrs)?;
                    } else {
                        // Skip fixed-length field
                        rdata_pos += desc_val as usize;
                        if rdata_pos > pos + rdlen {
                            return Err(RRFilterError::InvalidLength {
                                expected: rdata_pos,
                                actual: pos + rdlen,
                            });
                        }
                    }
                }
            }
        }
        
        // Advance to next RR
        if pos + rdlen > packet.len() {
            return Err(RRFilterError::InvalidLength {
                expected: pos + rdlen,
                actual: packet.len(),
            });
        }
        pos += rdlen;
    }
    
    Ok(())
}

// ============================================================================
// Public API
// ============================================================================

/// Return descriptor array for RR type indicating domain name locations in RDATA
///
/// Provides a descriptor array that maps a DNS resource record type to the structure
/// of its RDATA, specifically indicating where domain names appear. The descriptor is
/// an array of u16 values where 0 indicates a domain name at that position, positive
/// integers indicate that many bytes of fixed data to skip, and 0xFFFF marks the end.
///
/// # Arguments
///
/// * `rr_type` - DNS RR type (T_NS, T_CNAME, T_MX, T_SOA, etc.)
///
/// # Returns
///
/// Slice of descriptor values for this RR type. Format:
/// - 0 = domain name at this position
/// - N>0 = skip N bytes of fixed data
/// - 0xFFFF = end of descriptor
///
/// # Examples
///
/// - NS, CNAME, PTR: [0, 0xFFFF] (single domain name)
/// - MX: [2, 0, 0xFFFF] (2-byte preference + domain name)
/// - SOA: [0, 0, 0xFFFF] (primary NS + responsible person)
///
/// # RFC Compliance
///
/// Descriptor content matches RDATA formats defined in:
/// - RFC 1035 Section 3.3 (Standard RRs)
/// - RFC 2535 Section 4.1 (SIG record)
/// - RFC 2782 (SRV record)
/// - RFC 2672 (DNAME record)
pub fn rrfilter_desc(rr_type: u16) -> &'static [u16] {
    // Descriptor array: type identifier followed by RDATA structure descriptor
    // 0 = domain name, N>0 = skip N bytes, 0xFFFF = end
    #[allow(clippy::match_same_arms)]
    match rr_type {
        T_NS => &[0, DESC_END],
        T_MD => &[0, DESC_END],
        T_MF => &[0, DESC_END],
        T_CNAME => &[0, DESC_END],
        T_SOA => &[0, 0, DESC_END],
        T_MB => &[0, DESC_END],
        T_MG => &[0, DESC_END],
        T_MR => &[0, DESC_END],
        T_PTR => &[0, DESC_END],
        T_MINFO => &[0, 0, DESC_END],
        T_MX => &[2, 0, DESC_END],
        T_RP => &[0, 0, DESC_END],
        T_AFSDB => &[2, 0, DESC_END],
        T_RT => &[2, 0, DESC_END],
        T_SIG => &[18, 0, DESC_END],
        T_PX => &[2, 0, 0, DESC_END],
        T_NXT => &[0, DESC_END],
        T_KX => &[2, 0, DESC_END],
        T_SRV => &[6, 0, DESC_END],
        T_DNAME => &[0, DESC_END],
        _ => &[DESC_END], // Wildcard: no domain names in RDATA
    }
}

/// Remove resource records matching filter criteria from DNS response packet
///
/// Performs selective removal of DNS resource records from a response packet using a
/// safe four-pass algorithm that handles DNS name compression correctly. The function
/// can filter EDNS0 OPT pseudo-RRs, DNSSEC validation records (RRSIG/NSEC/NSEC3), or
/// specific address record types (A or AAAA) based on the mode parameter.
///
/// # Four-Pass Algorithm
///
/// 1. **Mark Pass**: Scan all RRs and identify those matching filter criteria
/// 2. **Validate Pass**: Ensure no compression pointers in kept records point into removed sections
/// 3. **Adjust Pass**: Fix compression pointer offsets to account for removed bytes
/// 4. **Remove Pass**: Physically remove RRs and update DNS header section counts
///
/// # Arguments
///
/// * `packet` - Mutable DNS packet bytes (modified in-place on success)
/// * `mode` - Filter mode (RRFILTER_EDNS0, RRFILTER_DNSSEC, RRFILTER_A, RRFILTER_AAAA)
///
/// # Returns
///
/// * `Ok(new_len)` - New packet length after removal (<= original)
/// * `Err(RRFilterError)` - Validation failed or packet malformed
///
/// Returns original packet unchanged if:
/// - qdcount != 1 (invalid packet structure)
/// - Packet truncated (cannot parse)
/// - Validation fails (compression pointers would be invalid)
/// - No records match filter criteria
///
/// # Filter Modes
///
/// - `RRFILTER_EDNS0`: Remove T_OPT from additional section only
/// - `RRFILTER_DNSSEC`: Remove RRSIG/NSEC/NSEC3 (except when explicitly queried)
/// - `RRFILTER_A`: Remove A records from answer section
/// - `RRFILTER_AAAA`: Remove AAAA records from answer section
///
/// # Safety
///
/// - Modifies packet in-place with safe memmove-like operations
/// - Updates header section counts atomically
/// - Preserves packet validity throughout operation
/// - Uses safe slice operations and bounds checking
///
/// # RFC Compliance
///
/// - RFC 1035 Section 4.1.4 (Message Compression)
/// - RFC 1035 Section 4.1 (Format)
/// - RFC 6891 (EDNS0)
/// - RFC 4034 (DNSSEC)
///
/// # Example
///
/// ```rust
/// use dnsmasq::dns::rrfilter::{rrfilter, RRFILTER_DNSSEC};
///
/// let mut packet = vec![/* DNS packet */];
/// match rrfilter(&mut packet, RRFILTER_DNSSEC) {
///     Ok(new_len) => {
///         // DNSSEC records removed, packet shrunk to new_len
///     }
///     Err(e) => {
///         // Keep original packet
///     }
/// }
/// ```
pub fn rrfilter(packet: &mut [u8], mode: i32) -> Result<usize, RRFilterError> {
    let original_len = packet.len();
    
    // Validate DNS header structure
    if packet.len() < 12 {
        return Err(RRFilterError::InvalidLength {
            expected: 12,
            actual: packet.len(),
        });
    }
    
    // Extract header fields
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);
    let arcount = u16::from_be_bytes([packet[10], packet[11]]);
    
    // Only handle packets with exactly 1 question
    if qdcount != 1 {
        debug!("rrfilter: qdcount={}, expected 1, returning original packet", qdcount);
        return Ok(original_len);
    }
    
    // Skip question section
    let mut pos = 12;
    let after_qname = skip_name(packet, &packet[pos..])
        .map_err(|_| {
            debug!("Failed to skip question name, returning original packet");
            RRFilterError::InvalidLength {
                expected: pos + 4,
                actual: packet.len(),
            }
        })?;
    pos = after_qname.as_ptr() as usize - packet.as_ptr() as usize;
    
    // Extract qtype and qclass
    if pos + 4 > packet.len() {
        debug!("Packet truncated after question name, returning original");
        return Ok(original_len);
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    pos += 4;
    
    // Pass 1: Mark records for removal
    // Store as flat array: [start0, end0, start1, end1, ...]
    let mut rrs: Vec<usize> = Vec::new();
    let mut chop_an = 0u16;
    let mut chop_ns = 0u16;
    let mut chop_ar = 0u16;
    
    let total_rrs = ancount as usize + nscount as usize + arcount as usize;
    let mut rr_index = 0usize;
    
    while rr_index < total_rrs {
        let rr_start = pos;
        
        // Skip RR owner name
        let after_name = skip_name(packet, &packet[pos..])
            .map_err(|_| {
                debug!("Failed to skip RR name, returning original packet");
                RRFilterError::InvalidLength {
                    expected: pos + 10,
                    actual: packet.len(),
                }
            })?;
        pos = after_name.as_ptr() as usize - packet.as_ptr() as usize;
        
        // Check we have type, class, TTL, rdlen
        if pos + 10 > packet.len() {
            debug!("Packet truncated in RR header, returning original");
            return Ok(original_len);
        }
        
        let rr_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let class = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        pos += 8; // Skip type, class, TTL
        let rdlen = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
        pos += 2;
        
        // Check rdlen bounds
        if pos + rdlen > packet.len() {
            debug!("Packet truncated in RDATA, returning original");
            return Ok(original_len);
        }
        
        let rr_end = pos + rdlen;
        
        // Determine if this RR should be removed
        let mut should_remove = false;
        
        match mode {
            RRFILTER_EDNS0 => {
                // Remove T_OPT from additional section only
                if rr_index >= (ancount + nscount) as usize && rr_type == T_OPT {
                    should_remove = true;
                }
            }
            RRFILTER_DNSSEC => {
                // Remove DNSSEC RRs (RRSIG, NSEC, NSEC3)
                if rr_type == T_RRSIG || rr_type == T_NSEC || rr_type == T_NSEC3 {
                    // Don't remove if this is the answer to the query
                    if !(rr_index < ancount as usize && rr_type == qtype && class == qclass) {
                        should_remove = true;
                    }
                }
            }
            RRFILTER_A => {
                // Remove A records from answer section
                if rr_index >= ancount as usize {
                    // Past answer section, done
                    break;
                }
                if class == C_IN && rr_type == T_A {
                    should_remove = true;
                }
            }
            RRFILTER_AAAA => {
                // Remove AAAA records from answer section
                if rr_index >= ancount as usize {
                    // Past answer section, done
                    break;
                }
                if class == C_IN && rr_type == T_AAAA {
                    should_remove = true;
                }
            }
            _ => {}
        }
        
        if should_remove {
            // Check workspace limit
            if rrs.len() >= MAX_WORKSPACE_ENTRIES * 2 {
                warn!("Workspace limit exceeded, returning original packet");
                return Ok(original_len);
            }
            
            rrs.push(rr_start);
            rrs.push(rr_end);
            trace!("Marked RR at {}-{} for removal (type={})", rr_start, rr_end, rr_type);
            
            // Track which section this RR is in
            if rr_index < ancount as usize {
                chop_an += 1;
            } else if rr_index < (ancount + nscount) as usize {
                chop_ns += 1;
            } else {
                chop_ar += 1;
            }
        }
        
        pos = rr_end;
        rr_index += 1;
    }
    
    // Nothing to do if no RRs marked for removal
    if rrs.is_empty() {
        debug!("No RRs matched filter criteria, returning original packet");
        return Ok(original_len);
    }
    
    debug!("Pass 1 complete: {} RRs marked for removal", rrs.len() / 2);
    
    // Pass 2: Validate that no compression pointers in kept records point into removed sections
    pos = 12;
    
    // Validate question name
    pos = check_name(packet, pos, false, &rrs).map_err(|e| {
        debug!("Validation failed in question name, returning original packet");
        e
    })?;
    pos += 4; // Skip qtype, qclass
    
    // Validate RRs
    check_rrs(packet, pos, total_rrs, false, &rrs).map_err(|e| {
        debug!("Validation failed in RRs, returning original packet");
        e
    })?;
    
    debug!("Pass 2 complete: All compression pointers valid");
    
    // Pass 3: Adjust compression pointers
    pos = 12;
    
    // Fix question name
    pos = check_name(packet, pos, true, &rrs)?;
    pos += 4; // Skip qtype, qclass
    
    // Fix RRs
    check_rrs(packet, pos, total_rrs, true, &rrs)?;
    
    debug!("Pass 3 complete: Compression pointers adjusted");
    
    // Pass 4: Physically remove RRs using memmove-like logic
    // Copy from end of first removed RR to start of next removed RR, etc.
    let mut write_pos = rrs[0]; // Start writing at first removed RR
    let mut i = 1;
    
    while i < rrs.len() {
        let copy_start = rrs[i]; // End of previous removed section
        let copy_end = if i + 1 < rrs.len() {
            rrs[i + 1] // Start of next removed section
        } else {
            original_len // End of packet
        };
        
        let copy_len = copy_end - copy_start;
        
        // Use safe copy_within for overlapping memory regions
        if copy_len > 0 {
            packet.copy_within(copy_start..copy_end, write_pos);
            write_pos += copy_len;
        }
        
        i += 2; // Move to next start/end pair
    }
    
    let new_len = write_pos;
    
    // Update header counts
    let new_ancount = ancount - chop_an;
    let new_nscount = nscount - chop_ns;
    let new_arcount = arcount - chop_ar;
    
    packet[6..8].copy_from_slice(&new_ancount.to_be_bytes());
    packet[8..10].copy_from_slice(&new_nscount.to_be_bytes());
    packet[10..12].copy_from_slice(&new_arcount.to_be_bytes());
    
    debug!(
        "Pass 4 complete: Removed {} bytes (an-{}, ns-{}, ar-{})",
        original_len - new_len, chop_an, chop_ns, chop_ar
    );
    
    Ok(new_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rrfilter_desc_ns() {
        let desc = rrfilter_desc(T_NS);
        assert_eq!(desc, &[0, DESC_END]);
    }
    
    #[test]
    fn test_rrfilter_desc_mx() {
        let desc = rrfilter_desc(T_MX);
        assert_eq!(desc, &[2, 0, DESC_END]);
    }
    
    #[test]
    fn test_rrfilter_desc_soa() {
        let desc = rrfilter_desc(T_SOA);
        assert_eq!(desc, &[0, 0, DESC_END]);
    }
    
    #[test]
    fn test_rrfilter_desc_unknown() {
        let desc = rrfilter_desc(9999);
        assert_eq!(desc, &[DESC_END]);
    }
    
    #[test]
    fn test_rrfilter_invalid_qdcount() {
        let mut packet = vec![
            0, 0, // ID
            0, 0, // Flags
            0, 2, // qdcount = 2 (invalid, not 1)
            0, 0, // ancount
            0, 0, // nscount
            0, 0, // arcount
        ];
        
        let original_len = packet.len();
        // Per C rrfilter.c lines 419-421: when qdcount != 1, return plen unchanged
        // This is not an error, just "do nothing" behavior
        let result = rrfilter(&mut packet, RRFILTER_EDNS0);
        assert_eq!(result, Ok(original_len));
    }
    
    #[test]
    fn test_rrfilter_no_matches() {
        // Simple DNS query response with A record
        let mut packet = vec![
            0, 0, // ID
            0x81, 0x80, // Flags (response)
            0, 1, // qdcount = 1
            0, 1, // ancount = 1
            0, 0, // nscount = 0
            0, 0, // arcount = 0
            // Question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0, // End of name
            0, 1, // qtype = A
            0, 1, // qclass = IN
            // Answer: example.com A IN 3600 192.0.2.1
            0xC0, 0x0C, // Compression pointer to question name
            0, 1, // type = A
            0, 1, // class = IN
            0, 0, 0, 3, // TTL = 3
            0, 4, // rdlen = 4
            192, 0, 2, 1, // IPv4 address
        ];
        
        let original_len = packet.len();
        
        // Try to filter AAAA records (none present)
        let result = rrfilter(&mut packet, RRFILTER_AAAA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), original_len);
    }
}
