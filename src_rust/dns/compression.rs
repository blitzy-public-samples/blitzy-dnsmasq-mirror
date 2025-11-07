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

//! DNS name compression implementation per RFC 1035 Section 4.1.4
//!
//! This module provides safe Rust implementations for DNS name compression, replacing
//! manual pointer manipulation and offset tracking from the C implementation with
//! HashMap-based tracking and type-safe operations.
//!
//! DNS name compression reduces packet size by replacing repeated domain name components
//! with two-byte pointers to earlier occurrences in the packet. The compression pointer
//! format uses the top 2 bits (0xC0) as a flag, with the remaining 14 bits encoding the
//! byte offset within the packet.
//!
//! # Key Features
//!
//! - **Memory Safety**: Replaces manual compression offset calculation with HashMap tracking
//! - **Cycle Detection**: Uses HashSet to prevent infinite loops from malicious packets
//! - **Type-Safe Label Handling**: Enums replace manual bit masking for label types
//! - **RFC Compliance**: Implements RFC 1035 Section 4.1.4 precisely
//!
//! # RFC 1035 Compliance
//!
//! Per RFC 1035 Section 4.1.4:
//! - Compression pointers have top 2 bits = 11 (0xC0)
//! - Bottom 14 bits encode offset (0x3FFF mask)
//! - Pointers must only reference backward (earlier labels)
//! - Maximum 255 hops when following pointer chains
//! - Label types: 0x00 (normal), 0xC0 (pointer), 0x40/0x80 (extended/reserved)
//!
//! # Example Usage
//!
//! ```rust
//! use dnsmasq::dns::compression::{CompressionContext, encode_compression_pointer};
//!
//! let mut ctx = CompressionContext::new();
//! 
//! // Add a label at position 12 in the packet
//! ctx.add_label("example.com".to_string(), 12);
//!
//! // Later, check if we can compress a reference to this label
//! if let Some(offset) = ctx.find_suffix("example.com") {
//!     let pointer_bytes = encode_compression_pointer(offset)?;
//!     // pointer_bytes contains [0xC0, 0x0C] for offset 12
//! }
//! ```

use crate::dns::protocol::{MAXDNAME, MAXLABEL};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Debug};

// ============================================================================
// Constants
// ============================================================================

/// Compression pointer flag (top 2 bits = 11, value 0xC0)
/// Used to identify compression pointers in DNS wire format
pub const COMPRESSION_POINTER_FLAG: u8 = 0xC0;

/// Compression offset mask (bottom 14 bits, value 0x3FFF)
/// Masks out the flag bits to extract the actual offset value
pub const COMPRESSION_OFFSET_MASK: u16 = 0x3FFF;

/// Maximum compression pointer hops (255) per RFC 1035
/// Prevents infinite loops from malicious or malformed packets
pub const MAX_COMPRESSION_HOPS: usize = 255;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during DNS name compression/decompression
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionError {
    /// Cyclic pointer chain detected (would cause infinite loop)
    CyclicPointer {
        /// The offset where the cycle was detected
        offset: usize,
    },
    
    /// Invalid label type encountered (only 0x00 and 0xC0 are valid)
    InvalidLabelType {
        /// The invalid label type byte value
        label_type: u8,
    },
    
    /// Exceeded maximum compression hops (255) while following pointers
    ExceededMaxHops {
        /// Number of hops attempted
        hops: usize,
    },
    
    /// Offset out of packet bounds
    OffsetOutOfBounds {
        /// The invalid offset value
        offset: usize,
        /// The packet length
        packet_len: usize,
    },
    
    /// Decompressed name exceeds MAXDNAME (1025 bytes)
    NameTooLong {
        /// The length that was exceeded
        length: usize,
    },
    
    /// Label length exceeds MAXLABEL (63 bytes)
    LabelTooLong {
        /// The invalid label length
        length: usize,
    },
}

impl Display for CompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionError::CyclicPointer { offset } => {
                write!(f, "Cyclic compression pointer detected at offset {}", offset)
            }
            CompressionError::InvalidLabelType { label_type } => {
                write!(f, "Invalid DNS label type: 0x{:02X}", label_type)
            }
            CompressionError::ExceededMaxHops { hops } => {
                write!(f, "Exceeded maximum compression hops: {} > {}", hops, MAX_COMPRESSION_HOPS)
            }
            CompressionError::OffsetOutOfBounds { offset, packet_len } => {
                write!(f, "Compression pointer offset {} exceeds packet length {}", offset, packet_len)
            }
            CompressionError::NameTooLong { length } => {
                write!(f, "Decompressed name length {} exceeds MAXDNAME {}", length, MAXDNAME)
            }
            CompressionError::LabelTooLong { length } => {
                write!(f, "Label length {} exceeds MAXLABEL {}", length, MAXLABEL)
            }
        }
    }
}

impl Error for CompressionError {}

// ============================================================================
// Label Type Enumeration
// ============================================================================

/// DNS label type encoding per RFC 1035
///
/// The top 2 bits of the first byte of a label indicate its type:
/// - 0x00 (00): Normal label with length in lower 6 bits
/// - 0xC0 (11): Compression pointer with 14-bit offset
/// - 0x40 (01): Extended label type (RFC 2671, not supported)
/// - 0x80 (10): Reserved for future use
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelType {
    /// Normal label (0x00-0x3F): length byte + label data
    Normal,
    
    /// Compression pointer (0xC0-0xFF): 2-byte pointer to earlier label
    Pointer,
    
    /// Extended label type (0x40-0x7F): RFC 2671, not supported by dnsmasq
    Extended,
    
    /// Reserved (0x80-0xBF): reserved for future use
    Reserved,
}

impl LabelType {
    /// Determine label type from the first byte
    ///
    /// # Arguments
    ///
    /// * `byte` - The first byte of the label
    ///
    /// # Returns
    ///
    /// The corresponding `LabelType` enum variant
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte & 0xC0 {
            0x00 => LabelType::Normal,
            0xC0 => LabelType::Pointer,
            0x40 => LabelType::Extended,
            0x80 => LabelType::Reserved,
            _ => unreachable!("Bit mask 0xC0 can only produce 4 values"),
        }
    }
    
    /// Check if this label type is valid for dnsmasq (Normal or Pointer only)
    ///
    /// # Returns
    ///
    /// `true` if the label type is Normal or Pointer, `false` otherwise
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, LabelType::Normal | LabelType::Pointer)
    }
}

// ============================================================================
// Compression Pointer Encoding/Decoding Functions
// ============================================================================

/// Decode a compression pointer from two bytes
///
/// Extracts the 14-bit offset from a compression pointer by masking out the
/// flag bits (0xC0) and combining the two bytes in network byte order.
///
/// # Arguments
///
/// * `byte1` - First byte of pointer (contains 0xC0 flag + high 6 bits of offset)
/// * `byte2` - Second byte of pointer (contains low 8 bits of offset)
///
/// # Returns
///
/// The 14-bit offset value (0-16383)
///
/// # Example
///
/// ```rust
/// use dnsmasq::dns::compression::decode_compression_pointer;
///
/// // Pointer to offset 12: [0xC0, 0x0C]
/// let offset = decode_compression_pointer(0xC0, 0x0C)?;
/// assert_eq!(offset, 12);
/// ```
#[must_use]
pub fn decode_compression_pointer(byte1: u8, byte2: u8) -> u16 {
    // Extract lower 6 bits from first byte and shift left 8 bits
    let high_bits = ((byte1 & 0x3F) as u16) << 8;
    // Combine with second byte
    let low_bits = byte2 as u16;
    high_bits | low_bits
}

/// Encode a compression pointer to two bytes
///
/// Creates a compression pointer by setting the flag bits (0xC0) and encoding
/// the 14-bit offset in network byte order.
///
/// # Arguments
///
/// * `offset` - The byte offset to encode (must be < 0x4000 = 16384)
///
/// # Returns
///
/// * `Ok([byte1, byte2])` - The two-byte compression pointer
/// * `Err(CompressionError::OffsetOutOfBounds)` - If offset >= 0x4000
///
/// # Example
///
/// ```rust
/// use dnsmasq::dns::compression::encode_compression_pointer;
///
/// let pointer_bytes = encode_compression_pointer(12)?;
/// assert_eq!(pointer_bytes, [0xC0, 0x0C]);
/// ```
pub fn encode_compression_pointer(offset: u16) -> Result<[u8; 2], CompressionError> {
    // Validate offset fits in 14 bits
    if offset > COMPRESSION_OFFSET_MASK {
        return Err(CompressionError::OffsetOutOfBounds {
            offset: offset as usize,
            packet_len: COMPRESSION_OFFSET_MASK as usize,
        });
    }
    
    // First byte: 0xC0 flag | high 6 bits of offset
    let byte1 = COMPRESSION_POINTER_FLAG | ((offset >> 8) as u8);
    // Second byte: low 8 bits of offset
    let byte2 = (offset & 0xFF) as u8;
    
    Ok([byte1, byte2])
}

// ============================================================================
// Compression Context
// ============================================================================

/// DNS name compression context for packet building
///
/// Tracks domain name positions in a DNS packet for compression purposes.
/// Replaces C's manual compression offset tracking with safe HashMap-based
/// approach using O(1) lookup for compression pointer creation.
///
/// The context maintains a mapping from domain name suffixes to their first
/// occurrence position in the packet, enabling compression of repeated names
/// and partial matches (e.g., "mail.example.com" can use a pointer for
/// "example.com" if it appeared earlier).
///
/// # Memory Safety
///
/// - No manual pointer arithmetic (replaced with safe offset tracking)
/// - HashMap provides automatic memory management
/// - Offset validation prevents out-of-bounds pointer creation
/// - Type-safe operations eliminate buffer overflows
///
/// # RFC Compliance
///
/// Per RFC 1035 Section 4.1.4:
/// - Only records first occurrence (preserves backward-only pointer requirement)
/// - Validates offsets fit in 14 bits (0x3FFF maximum)
/// - Supports suffix matching for optimal compression
pub struct CompressionContext {
    /// Map from domain name suffix to byte offset in packet
    /// Key: domain name (e.g., "example.com", "com")
    /// Value: byte offset where this suffix first appears
    label_positions: HashMap<String, u16>,
}

impl CompressionContext {
    /// Create a new empty compression context
    ///
    /// # Returns
    ///
    /// A new `CompressionContext` with no labels recorded
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dns::compression::CompressionContext;
    ///
    /// let ctx = CompressionContext::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            label_positions: HashMap::new(),
        }
    }
    
    /// Add a label at a specific offset in the packet
    ///
    /// Records the domain name and all its suffixes at the given offset for
    /// later compression. For example, "mail.example.com" will record:
    /// - "mail.example.com" at offset
    /// - "example.com" at offset + length("mail.")
    /// - "com" at offset + length("mail.example.")
    ///
    /// Only the first occurrence of each suffix is recorded to maintain
    /// backward-only pointer references.
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name to record
    /// * `offset` - Byte offset in the packet where this name appears
    ///
    /// # Returns
    ///
    /// `true` if the name was recorded, `false` if offset is too large (>= 0x4000)
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dns::compression::CompressionContext;
    ///
    /// let mut ctx = CompressionContext::new();
    /// ctx.add_label("example.com".to_string(), 12);
    /// ctx.add_label("mail.example.com".to_string(), 50);
    /// ```
    pub fn add_label(&mut self, name: String, offset: u16) -> bool {
        // Validate offset fits in 14 bits
        if offset > COMPRESSION_OFFSET_MASK {
            return false;
        }
        
        // Record all suffixes of the domain name
        // For "mail.example.com", record:
        // - "mail.example.com" at offset
        // - "example.com" at offset + length("mail.")
        // - "com" at offset + length("mail.example.")
        
        let parts: Vec<&str> = name.split('.').collect();
        let mut current_offset = offset;
        
        for i in 0..parts.len() {
            // Build suffix from remaining parts
            let suffix = parts[i..].join(".");
            
            if !suffix.is_empty() {
                // Only insert if not already present (preserve first occurrence)
                self.label_positions.entry(suffix.clone()).or_insert(current_offset);
            }
            
            // Advance offset by this label's size (length byte + label data)
            if i < parts.len() {
                current_offset += parts[i].len() as u16 + 1;
            }
        }
        
        true
    }
    
    /// Find the best compression pointer for a domain name suffix
    ///
    /// Searches for the longest matching suffix that has been previously
    /// recorded. For example, if "example.com" and "com" have both been seen,
    /// and we're looking up "mail.example.com", this returns the offset of
    /// "example.com" (the longest match).
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name to search for
    ///
    /// # Returns
    ///
    /// * `Some(offset)` - The offset of the longest matching suffix
    /// * `None` - If no matching suffix has been recorded
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dns::compression::CompressionContext;
    ///
    /// let mut ctx = CompressionContext::new();
    /// ctx.add_label("example.com".to_string(), 12);
    ///
    /// // Exact match
    /// assert_eq!(ctx.find_suffix("example.com"), Some(12));
    ///
    /// // Suffix match (would return offset of "com" if recorded)
    /// ```
    #[must_use]
    pub fn find_suffix(&self, name: &str) -> Option<u16> {
        // Try full name first
        if let Some(&offset) = self.label_positions.get(name) {
            return Some(offset);
        }
        
        // Try progressively shorter suffixes
        let parts: Vec<&str> = name.split('.').collect();
        for i in 1..parts.len() {
            let suffix = parts[i..].join(".");
            if let Some(&offset) = self.label_positions.get(&suffix) {
                return Some(offset);
            }
        }
        
        None
    }
    
    /// Create a compression pointer for a domain name
    ///
    /// Convenience method that combines `find_suffix` and `encode_compression_pointer`.
    /// Searches for a matching suffix and, if found, encodes it as a compression pointer.
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name to compress
    ///
    /// # Returns
    ///
    /// * `Some(Ok([byte1, byte2]))` - Compression pointer bytes if match found
    /// * `Some(Err(error))` - If match found but encoding failed
    /// * `None` - If no matching suffix exists
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dns::compression::CompressionContext;
    ///
    /// let mut ctx = CompressionContext::new();
    /// ctx.add_label("example.com".to_string(), 12);
    ///
    /// if let Some(Ok(pointer)) = ctx.create_pointer("example.com") {
    ///     // pointer contains [0xC0, 0x0C]
    /// }
    /// ```
    pub fn create_pointer(&self, name: &str) -> Option<Result<[u8; 2], CompressionError>> {
        self.find_suffix(name).map(encode_compression_pointer)
    }
    
    /// Follow a compression pointer chain in a DNS packet
    ///
    /// Dereferences compression pointers to extract the complete domain name.
    /// Implements cycle detection using HashSet to prevent infinite loops from
    /// malicious packets. Enforces maximum 255 hops per RFC 1035.
    ///
    /// # Arguments
    ///
    /// * `packet` - The complete DNS packet buffer
    /// * `start_offset` - Byte offset where the name begins
    ///
    /// # Returns
    ///
    /// * `Ok(name)` - The fully decompressed domain name
    /// * `Err(CompressionError)` - If cycle, invalid pointer, or limit exceeded
    ///
    /// # Errors
    ///
    /// - `CyclicPointer`: Pointer chain contains a cycle
    /// - `ExceededMaxHops`: More than 255 pointer hops
    /// - `OffsetOutOfBounds`: Pointer references invalid offset
    /// - `InvalidLabelType`: Unsupported label type encountered
    /// - `NameTooLong`: Decompressed name exceeds MAXDNAME
    /// - `LabelTooLong`: Individual label exceeds MAXLABEL
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dns::compression::CompressionContext;
    ///
    /// let packet = vec![/* DNS packet bytes */];
    /// let ctx = CompressionContext::new();
    ///
    /// match ctx.follow_pointer(&packet, 12) {
    ///     Ok(name) => println!("Domain: {}", name),
    ///     Err(e) => eprintln!("Decompression error: {}", e),
    /// }
    /// ```
    pub fn follow_pointer(&self, packet: &[u8], start_offset: usize) -> Result<String, CompressionError> {
        let mut result = String::new();
        let mut offset = start_offset;
        let mut visited_offsets = HashSet::new();
        let mut hops = 0;
        let mut name_length = 0;
        
        loop {
            // Check bounds
            if offset >= packet.len() {
                return Err(CompressionError::OffsetOutOfBounds {
                    offset,
                    packet_len: packet.len(),
                });
            }
            
            let byte = packet[offset];
            
            // Check for end of name (zero-length label)
            if byte == 0 {
                // Remove trailing dot if present
                if result.ends_with('.') {
                    result.pop();
                }
                return Ok(result);
            }
            
            let label_type = LabelType::from_byte(byte);
            
            match label_type {
                LabelType::Normal => {
                    let label_len = (byte & 0x3F) as usize;
                    
                    // Validate label length
                    if label_len > MAXLABEL {
                        return Err(CompressionError::LabelTooLong { length: label_len });
                    }
                    
                    // Check bounds for label data
                    if offset + 1 + label_len > packet.len() {
                        return Err(CompressionError::OffsetOutOfBounds {
                            offset: offset + 1 + label_len,
                            packet_len: packet.len(),
                        });
                    }
                    
                    // Extract label data
                    let label_data = &packet[offset + 1..offset + 1 + label_len];
                    let label_str = String::from_utf8_lossy(label_data);
                    
                    result.push_str(&label_str);
                    result.push('.');
                    
                    name_length += label_len + 1; // +1 for length byte or dot
                    
                    // Check total name length
                    if name_length >= MAXDNAME {
                        return Err(CompressionError::NameTooLong { length: name_length });
                    }
                    
                    // Advance past label length + data
                    offset += 1 + label_len;
                }
                
                LabelType::Pointer => {
                    // Cycle detection
                    if !visited_offsets.insert(offset) {
                        return Err(CompressionError::CyclicPointer { offset });
                    }
                    
                    // Hop limit
                    hops += 1;
                    if hops > MAX_COMPRESSION_HOPS {
                        return Err(CompressionError::ExceededMaxHops { hops });
                    }
                    
                    // Check bounds for second byte
                    if offset + 1 >= packet.len() {
                        return Err(CompressionError::OffsetOutOfBounds {
                            offset: offset + 1,
                            packet_len: packet.len(),
                        });
                    }
                    
                    // Decode pointer
                    let pointer_offset = decode_compression_pointer(packet[offset], packet[offset + 1]);
                    
                    // Validate pointer points backward (RFC 1035 requirement)
                    if pointer_offset as usize >= offset {
                        return Err(CompressionError::OffsetOutOfBounds {
                            offset: pointer_offset as usize,
                            packet_len: offset,
                        });
                    }
                    
                    // Follow pointer
                    offset = pointer_offset as usize;
                }
                
                LabelType::Extended | LabelType::Reserved => {
                    return Err(CompressionError::InvalidLabelType { label_type: byte });
                }
            }
        }
    }
    
    /// Clear all compression state
    ///
    /// Removes all recorded label positions. Useful for processing multiple
    /// independent DNS packets with the same context object.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dns::compression::CompressionContext;
    ///
    /// let mut ctx = CompressionContext::new();
    /// ctx.add_label("example.com".to_string(), 12);
    ///
    /// ctx.clear();
    /// assert!(ctx.find_suffix("example.com").is_none());
    /// ```
    pub fn clear(&mut self) {
        self.label_positions.clear();
    }
}

impl Default for CompressionContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_type_from_byte() {
        assert_eq!(LabelType::from_byte(0x00), LabelType::Normal);
        assert_eq!(LabelType::from_byte(0x3F), LabelType::Normal);
        assert_eq!(LabelType::from_byte(0xC0), LabelType::Pointer);
        assert_eq!(LabelType::from_byte(0xFF), LabelType::Pointer);
        assert_eq!(LabelType::from_byte(0x40), LabelType::Extended);
        assert_eq!(LabelType::from_byte(0x7F), LabelType::Extended);
        assert_eq!(LabelType::from_byte(0x80), LabelType::Reserved);
        assert_eq!(LabelType::from_byte(0xBF), LabelType::Reserved);
    }

    #[test]
    fn test_label_type_is_valid() {
        assert!(LabelType::Normal.is_valid());
        assert!(LabelType::Pointer.is_valid());
        assert!(!LabelType::Extended.is_valid());
        assert!(!LabelType::Reserved.is_valid());
    }

    #[test]
    fn test_decode_compression_pointer() {
        // Offset 12: 0xC0 0x0C
        assert_eq!(decode_compression_pointer(0xC0, 0x0C), 12);
        
        // Offset 255: 0xC0 0xFF
        assert_eq!(decode_compression_pointer(0xC0, 0xFF), 255);
        
        // Offset 16383 (max 14-bit): 0xFF 0xFF
        assert_eq!(decode_compression_pointer(0xFF, 0xFF), 0x3FFF);
        
        // Offset 4096: 0xD0 0x00
        assert_eq!(decode_compression_pointer(0xD0, 0x00), 4096);
    }

    #[test]
    fn test_encode_compression_pointer() {
        // Offset 12
        assert_eq!(encode_compression_pointer(12).unwrap(), [0xC0, 0x0C]);
        
        // Offset 255
        assert_eq!(encode_compression_pointer(255).unwrap(), [0xC0, 0xFF]);
        
        // Offset 16383 (max 14-bit)
        assert_eq!(encode_compression_pointer(0x3FFF).unwrap(), [0xFF, 0xFF]);
        
        // Offset too large
        assert!(encode_compression_pointer(0x4000).is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for offset in [0, 12, 255, 1000, 16383] {
            let encoded = encode_compression_pointer(offset).unwrap();
            let decoded = decode_compression_pointer(encoded[0], encoded[1]);
            assert_eq!(decoded, offset);
        }
    }

    #[test]
    fn test_compression_context_add_label() {
        let mut ctx = CompressionContext::new();
        
        assert!(ctx.add_label("example.com".to_string(), 12));
        assert!(ctx.add_label("test.com".to_string(), 50));
        
        // Offset too large
        assert!(!ctx.add_label("toolarge.com".to_string(), 0x4000));
    }

    #[test]
    fn test_compression_context_find_suffix() {
        let mut ctx = CompressionContext::new();
        
        ctx.add_label("example.com".to_string(), 12);
        
        // Exact match
        assert_eq!(ctx.find_suffix("example.com"), Some(12));
        
        // Suffix match - "com" should be recorded at offset 12 + length("example.")
        // "example" = 7 chars, + 1 for length byte = 8
        assert_eq!(ctx.find_suffix("com"), Some(20));
        
        // No match
        assert_eq!(ctx.find_suffix("notfound.com"), None);
    }

    #[test]
    fn test_compression_context_suffix_matching() {
        let mut ctx = CompressionContext::new();
        
        ctx.add_label("mail.example.com".to_string(), 12);
        
        // "mail.example.com" at 12
        assert_eq!(ctx.find_suffix("mail.example.com"), Some(12));
        
        // "example.com" at 12 + len("mail") + 1 = 12 + 4 + 1 = 17
        assert_eq!(ctx.find_suffix("example.com"), Some(17));
        
        // "com" at 17 + len("example") + 1 = 17 + 7 + 1 = 25
        assert_eq!(ctx.find_suffix("com"), Some(25));
        
        // Suffix matching for new name "www.example.com" should find "example.com"
        assert_eq!(ctx.find_suffix("www.example.com"), Some(17));
    }

    #[test]
    fn test_compression_context_create_pointer() {
        let mut ctx = CompressionContext::new();
        
        ctx.add_label("example.com".to_string(), 12);
        
        // Create pointer to "example.com"
        match ctx.create_pointer("example.com") {
            Some(Ok(pointer)) => {
                assert_eq!(pointer, [0xC0, 0x0C]);
            }
            _ => panic!("Expected successful pointer creation"),
        }
        
        // No match returns None
        assert!(ctx.create_pointer("notfound.com").is_none());
    }

    #[test]
    fn test_compression_context_clear() {
        let mut ctx = CompressionContext::new();
        
        ctx.add_label("example.com".to_string(), 12);
        assert!(ctx.find_suffix("example.com").is_some());
        
        ctx.clear();
        assert!(ctx.find_suffix("example.com").is_none());
    }

    #[test]
    fn test_follow_pointer_simple() {
        let mut ctx = CompressionContext::new();
        
        // Create a simple DNS packet with one name at offset 12
        // Format: [12 bytes header] [7 'example' 3 'com' 0]
        let mut packet = vec![0u8; 12]; // Header
        packet.extend_from_slice(&[7]); // length of "example"
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[3]); // length of "com"
        packet.extend_from_slice(b"com");
        packet.extend_from_slice(&[0]); // end of name
        
        let name = ctx.follow_pointer(&packet, 12).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn test_follow_pointer_with_compression() {
        let mut ctx = CompressionContext::new();
        
        // Packet with compression pointer
        // [12 bytes header]
        // Offset 12: [7 'example' 3 'com' 0]  = "example.com"
        // Offset 24: [3 'www' 0xC0 0x0C]      = "www" + pointer to offset 12
        let mut packet = vec![0u8; 12]; // Header
        
        // First name at offset 12: "example.com"
        packet.extend_from_slice(&[7]); // length of "example"
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[3]); // length of "com"
        packet.extend_from_slice(b"com");
        packet.extend_from_slice(&[0]); // end of name
        
        // Second name at offset 24: "www" + pointer
        packet.extend_from_slice(&[3]); // length of "www"
        packet.extend_from_slice(b"www");
        packet.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        
        let name = ctx.follow_pointer(&packet, 24).unwrap();
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn test_follow_pointer_cycle_detection() {
        let ctx = CompressionContext::new();
        
        // Create a malicious packet with cyclic pointer
        // Offset 12: [0xC0 0x0C] = pointer to itself
        let mut packet = vec![0u8; 12]; // Header
        packet.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12 (itself)
        
        let result = ctx.follow_pointer(&packet, 12);
        assert!(matches!(result, Err(CompressionError::CyclicPointer { .. })));
    }

    #[test]
    fn test_follow_pointer_max_hops() {
        let ctx = CompressionContext::new();
        
        // Create packet with long pointer chain
        let mut packet = vec![0u8; 12]; // Header
        
        // Create chain of 256 pointers, each pointing to the next
        for i in 0..256 {
            let offset = 12 + i * 2;
            let next_offset = offset + 2;
            packet.extend_from_slice(&encode_compression_pointer(next_offset as u16).unwrap());
        }
        // Final pointer points to a valid name
        packet.extend_from_slice(&[7]); // length
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[0]); // end
        
        let result = ctx.follow_pointer(&packet, 12);
        assert!(matches!(result, Err(CompressionError::ExceededMaxHops { .. })));
    }

    #[test]
    fn test_follow_pointer_out_of_bounds() {
        let ctx = CompressionContext::new();
        
        let packet = vec![0u8; 20]; // Small packet
        
        // Start offset beyond packet
        let result = ctx.follow_pointer(&packet, 100);
        assert!(matches!(result, Err(CompressionError::OffsetOutOfBounds { .. })));
    }

    #[test]
    fn test_follow_pointer_invalid_label_type() {
        let ctx = CompressionContext::new();
        
        // Packet with extended label type (0x40)
        let mut packet = vec![0u8; 12];
        packet.extend_from_slice(&[0x41]); // Extended label type
        
        let result = ctx.follow_pointer(&packet, 12);
        assert!(matches!(result, Err(CompressionError::InvalidLabelType { .. })));
    }

    #[test]
    fn test_follow_pointer_label_too_long() {
        let ctx = CompressionContext::new();
        
        // Packet with label length > 63
        let mut packet = vec![0u8; 12];
        packet.extend_from_slice(&[64]); // Invalid: exceeds MAXLABEL (63)
        
        let result = ctx.follow_pointer(&packet, 12);
        assert!(matches!(result, Err(CompressionError::LabelTooLong { .. })));
    }

    #[test]
    fn test_compression_error_display() {
        let err = CompressionError::CyclicPointer { offset: 12 };
        assert!(err.to_string().contains("Cyclic"));
        
        let err = CompressionError::InvalidLabelType { label_type: 0x40 };
        assert!(err.to_string().contains("Invalid"));
        
        let err = CompressionError::ExceededMaxHops { hops: 256 };
        assert!(err.to_string().contains("Exceeded"));
        
        let err = CompressionError::OffsetOutOfBounds { offset: 100, packet_len: 50 };
        assert!(err.to_string().contains("exceeds"));
        
        let err = CompressionError::NameTooLong { length: 2000 };
        assert!(err.to_string().contains("MAXDNAME"));
        
        let err = CompressionError::LabelTooLong { length: 100 };
        assert!(err.to_string().contains("MAXLABEL"));
    }
}
