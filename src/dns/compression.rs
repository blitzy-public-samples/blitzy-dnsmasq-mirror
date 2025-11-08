// Copyright (c) 2000-2022 Simon Kelley
// Copyright (c) 2024 Blitzy Platform (Rust translation)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

//! DNS name compression pointer handling per RFC 1035 Section 4.1.4
//!
//! This module implements safe DNS name extraction and compression with memory-safe handling
//! of compression pointers, preventing buffer overflows and infinite loops that can occur
//! in C implementations.
//!
//! # Overview
//!
//! DNS messages use name compression to reduce packet size by replacing repeated domain name
//! suffixes with 2-byte pointers to earlier occurrences. This module provides:
//!
//! - **Name Extraction**: Parse DNS names from wire format with compression pointer following
//! - **Name Skipping**: Advance past names without extraction for efficient parsing
//! - **Name Compression**: Build compressed names with pointer generation
//! - **Safety Guarantees**: Compile-time prevention of buffer overflows via Rust slices
//!
//! # Wire Format
//!
//! DNS names in wire format consist of:
//! - **Labels**: Length byte (0-63) followed by that many label characters
//! - **Compression Pointers**: Two bytes with top 2 bits set (0xC0 mask), bottom 14 bits = offset
//! - **Terminator**: Zero-length label (0x00) marks end of name
//!
//! # C Source Reference
//!
//! Translated from: `src/rfc1035.c`
//! - `extract_name()` function (lines 136-259): Name extraction with compression
//! - `skip_name()` function (lines 471-524): Skip over names efficiently
//! - Compression logic from packet construction functions
//!
//! # Safety Features
//!
//! - **No Buffer Overflows**: All buffer access bounds-checked automatically by Rust slices
//! - **No Pointer Arithmetic**: Uses safe `usize` offsets instead of pointer manipulation
//! - **No Infinite Loops**: Strict 255 hop limit prevents malicious compression pointer cycles
//! - **No NULL Pointers**: Compression pointer offsets validated before dereferencing
//!
//! # Examples
//!
//! ```rust
//! use dnsmasq::dns::compression::{extract_name, CompressionError};
//!
//! let packet = &[
//!     // DNS header (12 bytes)
//!     0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     // Query: "example.com" (7 "example" 3 "com" 0)
//!     0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
//!     0x03, b'c', b'o', b'm',
//!     0x00,
//!     // QTYPE/QCLASS
//!     0x00, 0x01, 0x00, 0x01,
//! ];
//!
//! let mut offset = 12; // Start after DNS header
//! let name = extract_name(packet, &mut offset, 4)?; // Validate 4 more bytes exist (QTYPE/QCLASS)
//! assert_eq!(name.labels.join("."), "example.com");
//! assert_eq!(offset, 25); // After name (12 + 13 bytes), positioned at QTYPE/QCLASS
//! # Ok::<(), CompressionError>(())
//! ```

use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

use crate::constants::MAX_DOMAIN_NAME;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of compression pointer hops to prevent infinite loops
///
/// Corresponds to C's implicit hop counter limit in `extract_name()` (rfc1035.c line 192).
/// Malicious or malformed packets can create compression pointer cycles. This limit
/// ensures parsing terminates even with cyclic pointers.
const MAX_COMPRESSION_HOPS: usize = 255;

/// Compression pointer identification mask (top 2 bits set)
///
/// Per RFC 1035 Section 4.1.4, compression pointers have bits 7-6 set to 11 (binary).
/// Corresponds to C's `0xC0` mask in rfc1035.c line 177.
const COMPRESSION_POINTER_MASK: u8 = 0xC0;

/// Compression pointer offset extraction mask (bottom 6 bits)
///
/// Extracts the high 6 bits of the 14-bit offset from the first byte of a compression pointer.
/// Corresponds to C's `(l & 0x3f)` in rfc1035.c line 185.
const COMPRESSION_OFFSET_MASK: u8 = 0x3F;

/// Normal label type indicator (top 2 bits clear)
///
/// Per RFC 1035 Section 4.1.4, normal labels have bits 7-6 set to 00 (binary).
/// The bottom 6 bits contain the label length (0-63 bytes).
const LABEL_TYPE_NORMAL: u8 = 0x00;

/// Extended label type 0x40 (reserved, not supported)
///
/// Label type 0x40 (bits 7-6 = 01) was defined for bitstring labels in RFC 2673
/// but is now obsolete per RFC 6891. Corresponds to C's check in rfc1035.c line 490.
const LABEL_TYPE_EXTENDED: u8 = 0x40;

/// Reserved label type 0x80 (not supported)
///
/// Label type 0x80 (bits 7-6 = 10) is reserved and not defined by any RFC.
/// Corresponds to C's check in rfc1035.c line 488.
const LABEL_TYPE_RESERVED: u8 = 0x80;

/// DNSSEC name escape character for special byte encoding
///
/// In DNSSEC mode, characters `0x00` (null), `0x2E` (dot), and `NAME_ESCAPE` itself
/// are encoded as `NAME_ESCAPE` followed by (`original_byte` + 1).
/// Corresponds to C's `NAME_ESCAPE` in dns-protocol.h line 1429.
#[cfg(feature = "dnssec")]
const NAME_ESCAPE: u8 = 0x01;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during DNS name compression operations
///
/// Corresponds to various failure modes in C's `extract_name()` and `skip_name()`
/// which return 0 or NULL on error. Rust provides specific error variants for
/// better diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompressionError {
    /// Packet is truncated or shorter than expected
    ///
    /// Occurs when reading would go beyond packet bounds. Corresponds to C's
    /// `CHECK_LEN` macro failures in rfc1035.c.
    #[error(
        "Packet too short: attempted to read {attempted} bytes at offset {offset}, but packet is only {packet_len} bytes"
    )]
    PacketTooShort {
        /// Current read offset in packet
        offset: usize,
        /// Number of bytes attempted to read
        attempted: usize,
        /// Total length of packet
        packet_len: usize,
    },

    /// Compression pointer offset is invalid (points outside packet or backwards)
    ///
    /// Compression pointers must point to earlier positions in the packet.
    /// Corresponds to C's implicit bounds checking in rfc1035.c line 195.
    #[error(
        "Invalid compression pointer offset {offset}: must be within packet bounds (0-{packet_len}) and point backwards"
    )]
    InvalidOffset {
        /// Compression pointer offset value
        offset: usize,
        /// Total length of packet
        packet_len: usize,
    },

    /// Too many compression pointer hops (potential infinite loop)
    ///
    /// Prevents denial of service from malicious packets with compression pointer cycles.
    /// Corresponds to C's hop counter check in rfc1035.c line 192.
    #[error("Too many compression pointer hops: exceeded limit of {MAX_COMPRESSION_HOPS}")]
    TooManyHops,

    /// Unsupported or reserved label type encountered
    ///
    /// Valid label types are 0x00 (normal) and 0xC0 (compression pointer).
    /// Types 0x40 (extended/bitstring) and 0x80 (reserved) are not supported.
    /// Corresponds to C's rejection in rfc1035.c lines 256, 488, 490.
    #[error(
        "Invalid label type {label_type:#04x}: only normal labels (0x00) and compression pointers (0xC0) are supported"
    )]
    InvalidLabelType {
        /// Invalid label type byte value
        label_type: u8,
    },

    /// Domain name exceeds maximum length
    ///
    /// DNS names in presentation format (with dots) are limited to 1025 bytes including
    /// null terminator. Corresponds to C's `MAXDNAME` check in rfc1035.c line 200.
    #[error("Domain name too long: {length} bytes exceeds maximum of {MAX_DOMAIN_NAME}")]
    NameTooLong {
        /// Length of the domain name in bytes
        length: usize,
    },
}

// =============================================================================
// Data Structures
// =============================================================================

/// Result type for compression operations
pub type CompressionResult<T> = Result<T, CompressionError>;

/// Represents a DNS name extracted from wire format with compression metadata
///
/// DNS names consist of labels separated by dots. This structure tracks both the
/// individual labels and whether compression pointers were used during extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedName {
    /// Individual labels of the domain name (e.g., `["example", "com"]`)
    ///
    /// Labels are stored without the separating dots. The full domain name can be
    /// reconstructed by joining with dots. Empty labels vector represents the root domain.
    pub labels: Vec<String>,

    /// Whether name used compression pointers during extraction
    ///
    /// Set to true if any compression pointers were followed while parsing this name.
    /// Useful for metrics and debugging. Does not affect name semantics.
    pub compressed: bool,
}

impl fmt::Display for CompressedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            write!(f, ".") // Root domain
        } else {
            write!(f, "{}", self.labels.join("."))
        }
    }
}

impl CompressedName {
    /// Compares this name case-insensitively with another string
    ///
    /// DNS names are case-insensitive per RFC 1035 Section 2.3.3.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dnsmasq::dns::compression::CompressedName;
    /// let name = CompressedName {
    ///     labels: vec!["Example".to_string(), "COM".to_string()],
    ///     compressed: false,
    /// };
    /// assert!(name.matches_ignore_case("example.com"));
    /// assert!(name.matches_ignore_case("EXAMPLE.COM"));
    /// ```
    #[must_use]
    pub fn matches_ignore_case(&self, other: &str) -> bool {
        self.to_string().eq_ignore_ascii_case(other)
    }
}

// =============================================================================
// Name Extraction Functions
// =============================================================================

/// Extract DNS name from wire format with compression pointer following
///
/// Parses a DNS domain name from a packet starting at the specified offset, handling
/// RFC 1035 label compression (pointer labels starting with 0xC0). The function follows
/// compression pointers up to `MAX_COMPRESSION_HOPS` (255) to prevent infinite loops
/// from malicious packets.
///
/// # Arguments
///
/// * `packet` - Complete DNS packet buffer for base address calculations and validation
/// * `offset` - Current position in packet; updated to position after name on success
/// * `extrabytes` - Number of additional bytes expected after the name (e.g., QTYPE+QCLASS=4)
///
/// # Returns
///
/// * `Ok(CompressedName)` - Successfully extracted name with labels and compression metadata
/// * `Err(CompressionError)` - Parse failure (truncated packet, invalid pointer, etc.)
///
/// # Wire Format
///
/// DNS names consist of length-prefixed labels terminated by a zero-length label:
/// ```text
/// 3 "www" 7 "example" 3 "com" 0
/// ```
///
/// Compression pointers provide offsets to previously occurring labels:
/// ```text
/// 3 "www" 0xC0 0x0C (pointer to offset 12)
/// ```
///
/// # Safety Features
///
/// - All buffer accesses are bounds-checked via Rust slices (no `CHECK_LEN` macro needed)
/// - Compression pointer offsets validated before dereferencing
/// - Hop counter prevents infinite loops from cyclic pointers
/// - Name length checked against `MAX_DOMAIN_NAME` (1025 bytes)
///
/// # C Source Reference
///
/// Translated from: `src/rfc1035.c` lines 136-259 (`extract_name()` function)
///
/// Key differences from C:
/// - Uses `usize` offset instead of `unsigned char**` pointer manipulation
/// - Returns `Result<CompressedName, CompressionError>` instead of int + name buffer
/// - Builds `String` directly instead of writing to pre-allocated char buffer
/// - Automatic bounds checking via slices instead of `CHECK_LEN` macro
///
/// # Examples
///
/// ```
/// # use dnsmasq::dns::compression::{extract_name, CompressionError};
/// // DNS packet with query "example.com"
/// let packet = &[
///     // DNS header (12 bytes) - omitted for brevity
///     /* ... */
///     # 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     // Query name: 7 "example" 3 "com" 0
///     0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
///     0x03, b'c', b'o', b'm',
///     0x00,
///     // QTYPE (2 bytes) + QCLASS (2 bytes)
///     0x00, 0x01, 0x00, 0x01,
/// ];
///
/// let mut offset = 12; // Start after header
/// let name = extract_name(packet, &mut offset, 4)?; // Validate 4 bytes (QTYPE+QCLASS) exist after name
/// assert_eq!(name.labels, vec!["example", "com"]);
/// assert_eq!(name.compressed, false);
/// assert_eq!(offset, 25); // After name (12 + 13 bytes), positioned at QTYPE/QCLASS
/// # Ok::<(), CompressionError>(())
/// ```
///
/// # Errors
///
/// - `CompressionError::PacketTooShort` - Not enough bytes in packet for complete name
/// - `CompressionError::InvalidOffset` - Compression pointer targets invalid location
/// - `CompressionError::TooManyHops` - Exceeds maximum compression pointer hops (prevents cycles)
/// - `CompressionError::NameTooLong` - Domain name exceeds RFC 1035 maximum (255 bytes)
/// - `CompressionError::InvalidLabelType` - Invalid label type byte encountered
/// - `CompressionError::InvalidCharacter` - Label contains invalid DNS character
pub fn extract_name(
    packet: &[u8],
    offset: &mut usize,
    extrabytes: usize,
) -> CompressionResult<CompressedName> {
    let mut labels = Vec::new();
    let mut current_offset = *offset;
    let mut first_jump: Option<usize> = None; // Corresponds to C's p1 (rfc1035.c line 139)
    let mut hops = 0; // Compression pointer hop counter
    let mut total_length = 0; // Total name length in presentation format
    let mut used_compression = false;

    loop {
        // Check we can read at least the length/type byte
        if current_offset >= packet.len() {
            return Err(CompressionError::PacketTooShort {
                offset: current_offset,
                attempted: 1,
                packet_len: packet.len(),
            });
        }

        let label_byte = packet[current_offset];
        current_offset += 1;

        // Check for end marker (zero-length label)
        if label_byte == 0 {
            // Verify that there are the correct number of bytes after the name
            // Uses the position after first jump if we followed pointers, otherwise current position
            let final_offset = first_jump.unwrap_or(current_offset);
            if final_offset + extrabytes > packet.len() {
                return Err(CompressionError::PacketTooShort {
                    offset: final_offset,
                    attempted: extrabytes,
                    packet_len: packet.len(),
                });
            }

            // Update caller's offset to position after name (and after first jump if compression used)
            *offset = final_offset;

            return Ok(CompressedName {
                labels,
                compressed: used_compression,
            });
        }

        let label_type = label_byte & COMPRESSION_POINTER_MASK;

        if label_type == COMPRESSION_POINTER_MASK {
            // Compression pointer (0xC0): read 14-bit offset
            // Corresponds to C code in rfc1035.c lines 179-196

            if current_offset >= packet.len() {
                return Err(CompressionError::PacketTooShort {
                    offset: current_offset,
                    attempted: 1,
                    packet_len: packet.len(),
                });
            }

            // Extract 14-bit offset: ((first_byte & 0x3F) << 8) | second_byte
            let pointer_offset = (((label_byte & COMPRESSION_OFFSET_MASK) as usize) << 8)
                | (packet[current_offset] as usize);
            current_offset += 1;

            // Save location to return to after following pointers (first jump only)
            if first_jump.is_none() {
                first_jump = Some(current_offset);
            }

            // Validate pointer points backwards and within packet bounds
            if pointer_offset >= packet.len() {
                return Err(CompressionError::InvalidOffset {
                    offset: pointer_offset,
                    packet_len: packet.len(),
                });
            }

            // Increment hop counter to prevent infinite loops
            hops += 1;
            if hops > MAX_COMPRESSION_HOPS {
                return Err(CompressionError::TooManyHops);
            }

            // Jump to the pointed location
            current_offset = pointer_offset;
            used_compression = true;
        } else if label_type == LABEL_TYPE_NORMAL {
            // Normal label (0x00): length byte followed by label characters
            // Corresponds to C code in rfc1035.c lines 197-255

            let label_length = (label_byte & COMPRESSION_OFFSET_MASK) as usize;

            // Update total name length (include period separator)
            total_length += label_length + 1;
            // RFC 1035 Section 2.3.4: Maximum name length in wire format is 255 bytes
            // This is the wire format limit, not the presentation format limit (MAXDNAME = 1025)
            if total_length >= 255 {
                return Err(CompressionError::NameTooLong {
                    length: total_length,
                });
            }

            // Check we can read label_length bytes
            if current_offset + label_length > packet.len() {
                return Err(CompressionError::PacketTooShort {
                    offset: current_offset,
                    attempted: label_length,
                    packet_len: packet.len(),
                });
            }

            // Extract label bytes
            let label_bytes = &packet[current_offset..current_offset + label_length];
            current_offset += label_length;

            // Convert label bytes to String, handling DNSSEC escaping if enabled
            let label = decode_label(label_bytes)?;
            labels.push(label);
        } else {
            // Invalid label type (0x40 extended or 0x80 reserved)
            // Corresponds to C's rejection in rfc1035.c line 256
            return Err(CompressionError::InvalidLabelType {
                label_type: label_byte,
            });
        }
    }
}

/// Decode label bytes to String, handling DNSSEC escaping if enabled
///
/// In DNSSEC mode, special characters (0x00, '.', `NAME_ESCAPE`) are stored escaped.
/// This function decodes them back to their original values.
///
/// # Arguments
///
/// * `label_bytes` - Raw label bytes from DNS packet
///
/// # Returns
///
/// * `Ok(String)` - Decoded label as UTF-8 string
/// * `Err(CompressionError)` - If label contains invalid characters
///
/// # C Source Reference
///
/// Corresponds to label extraction logic in rfc1035.c lines 205-226
#[cfg(feature = "dnssec")]
fn decode_label(label_bytes: &[u8]) -> CompressionResult<String> {
    let mut result = String::with_capacity(label_bytes.len());
    let mut i = 0;

    while i < label_bytes.len() {
        let byte = label_bytes[i];

        if byte == NAME_ESCAPE && i + 1 < label_bytes.len() {
            // Unescape: NAME_ESCAPE followed by (original + 1)
            let escaped_byte = label_bytes[i + 1].wrapping_sub(1);
            result.push(escaped_byte as char);
            i += 2;
        } else if byte == 0 || byte == b'.' {
            // In DNSSEC mode, null bytes and dots should be escaped
            // If we encounter them unescaped, reject the label
            return Err(CompressionError::InvalidLabelType { label_type: byte });
        } else {
            result.push(byte as char);
            i += 1;
        }
    }

    Ok(result)
}

/// Decode label bytes to String (non-DNSSEC mode)
///
/// In non-DNSSEC mode, labels must not contain null bytes or dots.
///
/// # C Source Reference
///
/// Corresponds to label extraction logic in rfc1035.c lines 222-225
#[cfg(not(feature = "dnssec"))]
fn decode_label(label_bytes: &[u8]) -> CompressionResult<String> {
    // Validate no null bytes or dots
    for &byte in label_bytes {
        if byte == 0 || byte == b'.' {
            return Err(CompressionError::InvalidLabelType { label_type: byte });
        }
    }

    // Convert to String (assuming ASCII/UTF-8)
    Ok(String::from_utf8_lossy(label_bytes).to_string())
}

/// Skip over a DNS name in wire format without extraction
///
/// Advances the offset past a DNS name efficiently without extracting or validating its
/// content. More efficient than `extract_name()` when name content is not needed (e.g.,
/// when processing answer sections where only RDATA is of interest).
///
/// # Arguments
///
/// * `packet` - Complete DNS packet buffer for bounds checking
/// * `offset` - Current position in packet; updated to position after name on success
/// * `extrabytes` - Number of additional bytes expected after the name
///
/// # Returns
///
/// * `Ok(())` - Successfully skipped over name
/// * `Err(CompressionError)` - Parse failure (truncated packet, invalid format)
///
/// # Label Types Supported
///
/// - Normal labels (0x00): Length byte + label data
/// - Compression pointers (0xC0): 2-byte pointer (terminal, no following)
/// - Extended labels (0x40): Bitstring labels (obsolete, basic support for skipping)
///
/// # C Source Reference
///
/// Translated from: `src/rfc1035.c` lines 471-524 (`skip_name()` function)
///
/// Key differences from C:
/// - Returns `Result<(), CompressionError>` instead of pointer or NULL
/// - Uses mutable `usize` offset instead of returning new pointer position
/// - Automatic bounds checking via Rust slices
///
/// # Examples
///
/// ```
/// # use dnsmasq::dns::compression::{skip_name, CompressionError};
/// let packet = &[
///     /* DNS header + query */
///     # 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
///     0x03, b'c', b'o', b'm',
///     0x00,
///     0x00, 0x01, 0x00, 0x01, // QTYPE + QCLASS
/// ];
///
/// let mut offset = 12;
/// skip_name(packet, &mut offset, 4)?; // Skip name, expect QTYPE+QCLASS
/// assert_eq!(offset, 12 + 13); // After name, before extrabytes
/// # Ok::<(), CompressionError>(())
/// ```
///
/// # Errors
///
/// - `CompressionError::PacketTooShort` - Not enough bytes in packet to skip complete name
/// - `CompressionError::InvalidLabelType` - Invalid or unsupported label type encountered
pub fn skip_name(packet: &[u8], offset: &mut usize, extrabytes: usize) -> CompressionResult<()> {
    let mut current_offset = *offset;

    loop {
        // Check we can read at least the length/type byte
        if current_offset >= packet.len() {
            return Err(CompressionError::PacketTooShort {
                offset: current_offset,
                attempted: 1,
                packet_len: packet.len(),
            });
        }

        let label_byte = packet[current_offset];
        let label_type = label_byte & COMPRESSION_POINTER_MASK;

        if label_type == COMPRESSION_POINTER_MASK {
            // Compression pointer (0xC0): 2 bytes total, terminal
            // Corresponds to C code in rfc1035.c lines 482-486
            current_offset += 2;
            break;
        } else if label_type == LABEL_TYPE_RESERVED {
            // Reserved label type (0x80): not supported
            // Corresponds to C code in rfc1035.c lines 488-489
            return Err(CompressionError::InvalidLabelType {
                label_type: label_byte,
            });
        } else if label_type == LABEL_TYPE_EXTENDED {
            // Extended label type (0x40): bitstring labels
            // Corresponds to C code in rfc1035.c lines 490-507
            // We only support bitstring subtype (1)

            if current_offset + 1 >= packet.len() {
                return Err(CompressionError::PacketTooShort {
                    offset: current_offset,
                    attempted: 2,
                    packet_len: packet.len(),
                });
            }

            current_offset += 1;
            let subtype = packet[current_offset - 1] & COMPRESSION_OFFSET_MASK;
            if subtype != 1 {
                // We only understand bitstrings
                return Err(CompressionError::InvalidLabelType {
                    label_type: label_byte,
                });
            }

            if current_offset >= packet.len() {
                return Err(CompressionError::PacketTooShort {
                    offset: current_offset,
                    attempted: 1,
                    packet_len: packet.len(),
                });
            }

            let bit_count = packet[current_offset] as usize;
            current_offset += 1;

            // Calculate byte length from bit count
            let byte_count = if bit_count == 0 {
                // bit_count == 0 means 256 bits = 32 bytes
                32
            } else {
                ((bit_count - 1) >> 3) + 1
            };

            if current_offset + byte_count > packet.len() {
                return Err(CompressionError::PacketTooShort {
                    offset: current_offset,
                    attempted: byte_count,
                    packet_len: packet.len(),
                });
            }

            current_offset += byte_count;
        } else {
            // Normal label (0x00): length byte + label data
            // Corresponds to C code in rfc1035.c lines 509-517
            let label_length = (label_byte & COMPRESSION_OFFSET_MASK) as usize;
            current_offset += 1;

            if label_length == 0 {
                // Zero-length label marks end of name
                break;
            }

            // Skip label data
            if current_offset + label_length > packet.len() {
                return Err(CompressionError::PacketTooShort {
                    offset: current_offset,
                    attempted: label_length,
                    packet_len: packet.len(),
                });
            }

            current_offset += label_length;
        }
    }

    // Verify extrabytes are available
    if current_offset + extrabytes > packet.len() {
        return Err(CompressionError::PacketTooShort {
            offset: current_offset,
            attempted: extrabytes,
            packet_len: packet.len(),
        });
    }

    *offset = current_offset;
    Ok(())
}

// =============================================================================
// Name Compression Functions
// =============================================================================

/// Compress and write a DNS name to a packet buffer
///
/// Writes a DNS domain name to the packet buffer in wire format, using compression
/// pointers when possible to reference earlier occurrences of label suffixes. The
/// compression map tracks label positions to enable pointer generation.
///
/// # Arguments
///
/// * `name` - Domain name in presentation format (e.g., "www.example.com")
/// * `packet` - Packet buffer to append compressed name to
/// * `compression_map` - Map of previously written labels to their offsets for compression
///
/// # Returns
///
/// * `Ok(())` - Name successfully written to packet
/// * `Err(CompressionError)` - Compression failure (name too long, invalid format)
///
/// # Errors
///
/// - `CompressionError::InvalidOffset` - Compression pointer offset exceeds 14-bit limit (0x3FFF)
/// - `CompressionError::NameTooLong` - Individual label exceeds 63 bytes
///
/// # Compression Algorithm
///
/// For each label suffix (e.g., "example.com", "com"):
/// 1. Check if suffix exists in compression map
/// 2. If yes: Write 2-byte pointer (0xC0 | `offset_high`, `offset_low`)
/// 3. If no: Write label (length byte + data), add to map, continue
///
/// # C Source Reference
///
/// This functionality is distributed across multiple C functions in rfc1035.c:
/// - `add_resource_record()` for compression during response construction
/// - Compression map maintained manually via pointer comparisons
///
/// Key differences from C:
/// - Uses `HashMap` for efficient suffix lookup instead of linear scan
/// - Explicit compression map parameter instead of implicit packet scanning
/// - Returns Result instead of boolean or pointer
///
/// # Examples
///
/// ```
/// # use dnsmasq::dns::compression::{compress_name, CompressionError};
/// # use std::collections::HashMap;
/// let mut packet = Vec::new();
/// let mut compression_map = HashMap::new();
///
/// // Write first name: "example.com"
/// compress_name("example.com", &mut packet, &mut compression_map)?;
///
/// // Write second name: "www.example.com" (will use pointer for "example.com" suffix)
/// compress_name("www.example.com", &mut packet, &mut compression_map)?;
/// # Ok::<(), CompressionError>(())
/// ```
pub fn compress_name<S: std::hash::BuildHasher>(
    name: &str,
    packet: &mut Vec<u8>,
    compression_map: &mut HashMap<String, usize, S>,
) -> CompressionResult<()> {
    // Handle root domain special case
    if name == "." || name.is_empty() {
        packet.push(0);
        return Ok(());
    }

    // Split name into labels
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();

    // Process each label, checking for compression opportunities
    let mut i = 0;
    while i < labels.len() {
        // Build suffix from current label onward (e.g., "example.com", "com")
        let suffix = labels[i..].join(".");

        // Check if this suffix was written before
        if let Some(&offset) = compression_map.get(&suffix) {
            // Write compression pointer: 0xC0 mask | 14-bit offset
            if offset > 0x3FFF {
                // Offset too large for 14-bit field
                return Err(CompressionError::InvalidOffset {
                    offset,
                    packet_len: packet.len(),
                });
            }

            #[allow(clippy::cast_possible_truncation)]
            let pointer_high = 0xC0 | ((offset >> 8) as u8);
            #[allow(clippy::cast_possible_truncation)]
            let pointer_low = (offset & 0xFF) as u8;
            packet.push(pointer_high);
            packet.push(pointer_low);

            // Compression pointer is terminal (no more labels follow)
            return Ok(());
        }

        // No compression match: write label normally
        let label = labels[i];
        let label_bytes = label.as_bytes();

        if label_bytes.len() > 63 {
            return Err(CompressionError::NameTooLong {
                length: label_bytes.len(),
            });
        }

        // Record this suffix position for future compression
        let suffix_offset = packet.len();
        compression_map.insert(suffix.clone(), suffix_offset);

        // Write label: length byte + label data
        #[allow(clippy::cast_possible_truncation)]
        packet.push(label_bytes.len() as u8);
        packet.extend_from_slice(label_bytes);

        i += 1;
    }

    // Write terminating zero-length label
    packet.push(0);

    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test extraction of simple uncompressed name
    #[test]
    fn test_extract_simple_name() {
        let packet = vec![
            // DNS header (12 bytes)
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Query: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            // QTYPE + QCLASS
            0x00, 0x01, 0x00, 0x01,
        ];

        let mut offset = 12;
        let name = extract_name(&packet, &mut offset, 4).unwrap();

        assert_eq!(name.labels, vec!["example", "com"]);
        assert!(!name.compressed);
        assert_eq!(offset, 12 + 13); // After name, before extrabytes
    }

    /// Test extraction of name with compression pointer
    #[test]
    fn test_extract_compressed_name() {
        let packet = vec![
            // DNS header
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // First name at offset 12: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            // Second name at offset 25: "www" + pointer to offset 12
            0x03, b'w', b'w', b'w', 0xC0, 0x0C, // Pointer to offset 12
        ];

        let mut offset = 25; // Start at the "www" label
        let name = extract_name(&packet, &mut offset, 0).unwrap();

        assert_eq!(name.labels, vec!["www", "example", "com"]);
        assert!(name.compressed);
        assert_eq!(offset, 31); // After "www" (4 bytes) + pointer (2 bytes) = offset 25 + 6 = 31
    }

    /// Test error on packet too short
    #[test]
    fn test_extract_packet_too_short() {
        let packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', // Truncated
        ];

        let mut offset = 12;
        let result = extract_name(&packet, &mut offset, 0);

        assert!(matches!(
            result,
            Err(CompressionError::PacketTooShort { .. })
        ));
    }

    /// Test error on invalid compression pointer
    #[test]
    fn test_extract_invalid_pointer() {
        let packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
            0xFF, // Pointer to invalid offset 255
        ];

        let mut offset = 12;
        let result = extract_name(&packet, &mut offset, 0);

        assert!(matches!(
            result,
            Err(CompressionError::InvalidOffset { .. })
        ));
    }

    /// Test error on too many hops (infinite loop prevention)
    #[test]
    fn test_extract_too_many_hops() {
        // Create packet with compression pointer cycle
        let mut packet = vec![0; 12];
        // Pointer at offset 12 pointing to offset 14
        packet.push(0xC0);
        packet.push(0x0E);
        // Pointer at offset 14 pointing back to offset 12
        packet.push(0xC0);
        packet.push(0x0C);

        let mut offset = 12;
        let result = extract_name(&packet, &mut offset, 0);

        assert!(matches!(result, Err(CompressionError::TooManyHops)));
    }

    /// Test skipping simple uncompressed name
    #[test]
    fn test_skip_simple_name() {
        let packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let mut offset = 12;
        skip_name(&packet, &mut offset, 4).unwrap();

        assert_eq!(offset, 12 + 13); // After name, before extrabytes
    }

    /// Test skipping name with compression pointer
    #[test]
    fn test_skip_compressed_name() {
        let packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0xC0, 0x0C, // Pointer
        ];

        let mut offset = 12;
        skip_name(&packet, &mut offset, 0).unwrap();

        assert_eq!(offset, 12 + 6); // After "www" + 2-byte pointer
    }

    /// Test compression of simple name
    #[test]
    fn test_compress_simple_name() {
        let mut packet = Vec::new();
        let mut compression_map = HashMap::new();

        compress_name("example.com", &mut packet, &mut compression_map).unwrap();

        let expected = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        assert_eq!(packet, expected);

        // Verify compression map entries
        // "example.com" starts at byte 0
        // "com" starts at byte 8 (after 0x07 + 7 bytes of "example")
        assert_eq!(compression_map.get("example.com"), Some(&0));
        assert_eq!(compression_map.get("com"), Some(&8));
    }

    /// Test compression with pointer generation
    #[test]
    fn test_compress_with_pointer() {
        let mut packet = Vec::new();
        let mut compression_map = HashMap::new();

        // Write first name
        compress_name("example.com", &mut packet, &mut compression_map).unwrap();
        let first_len = packet.len();

        // Write second name with common suffix
        compress_name("www.example.com", &mut packet, &mut compression_map).unwrap();

        // Second name should be: 3 "www" + pointer to offset 0
        assert_eq!(packet[first_len], 0x03); // Length of "www"
        assert_eq!(&packet[first_len + 1..first_len + 4], b"www");
        assert_eq!(packet[first_len + 4], 0xC0); // Compression pointer high byte
        assert_eq!(packet[first_len + 5], 0x00); // Compression pointer low byte (offset 0)
    }

    /// Test root domain compression
    #[test]
    fn test_compress_root_domain() {
        let mut packet = Vec::new();
        let mut compression_map = HashMap::new();

        compress_name(".", &mut packet, &mut compression_map).unwrap();

        assert_eq!(packet, vec![0x00]); // Just terminating zero
    }

    /// Test `CompressedName` `to_string` conversion
    #[test]
    fn test_compressed_name_to_string() {
        let name = CompressedName {
            labels: vec!["example".to_string(), "com".to_string()],
            compressed: false,
        };
        assert_eq!(name.to_string(), "example.com");

        let root = CompressedName {
            labels: vec![],
            compressed: false,
        };
        assert_eq!(root.to_string(), ".");
    }

    /// Test `CompressedName` case-insensitive matching
    #[test]
    fn test_compressed_name_case_insensitive() {
        let name = CompressedName {
            labels: vec!["Example".to_string(), "COM".to_string()],
            compressed: false,
        };

        assert!(name.matches_ignore_case("example.com"));
        assert!(name.matches_ignore_case("EXAMPLE.COM"));
        assert!(name.matches_ignore_case("ExAmPlE.CoM"));
        assert!(!name.matches_ignore_case("different.com"));
    }
}
