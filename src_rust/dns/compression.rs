//! DNS name compression
//!
//! Implements DNS name compression per RFC 1035 Section 4.1.4.
//! Replaces manual pointer manipulation from C with safe Rust implementation.

use std::collections::HashMap;

/// DNS name compression state
///
/// Tracks domain name offsets in a DNS packet for compression purposes.
/// Replaces C's manual pointer tracking with safe HashMap-based approach.
pub struct CompressionMap {
    /// Map from domain name to byte offset in packet
    name_offsets: HashMap<String, u16>,
}

impl CompressionMap {
    /// Create a new compression map
    #[must_use] 
    pub fn new() -> Self {
        Self {
            name_offsets: HashMap::new(),
        }
    }

    /// Record a domain name at a specific offset
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name (e.g., "example.com")
    /// * `offset` - Byte offset in the DNS packet where this name appears
    ///
    /// # Returns
    ///
    /// Returns true if the name was newly recorded, false if it already existed.
    pub fn insert(&mut self, name: String, offset: u16) -> bool {
        if offset >= 0x4000 {
            // Offset too large for compression pointer (14-bit limit)
            return false;
        }
        
        // Only insert if name doesn't already exist (preserve first occurrence)
        if let std::collections::hash_map::Entry::Vacant(e) = self.name_offsets.entry(name) {
            e.insert(offset);
            true
        } else {
            false
        }
    }

    /// Look up a domain name's offset
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name to look up
    ///
    /// # Returns
    ///
    /// Returns Some(offset) if the name has been seen before, None otherwise.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<u16> {
        self.name_offsets.get(name).copied()
    }

    /// Check if compression is available for a name
    ///
    /// # Arguments
    ///
    /// * `name` - The domain name to check
    ///
    /// # Returns
    ///
    /// Returns true if the name can be compressed (has been seen before).
    #[must_use] 
    pub fn can_compress(&self, name: &str) -> bool {
        self.name_offsets.contains_key(name)
    }

    /// Clear all compression state
    pub fn clear(&mut self) {
        self.name_offsets.clear();
    }

    /// Get the number of names tracked
    #[must_use] 
    pub fn len(&self) -> usize {
        self.name_offsets.len()
    }

    /// Check if the compression map is empty
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.name_offsets.is_empty()
    }
}

impl Default for CompressionMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Compression context for DNS packet serialization
///
/// Provides high-level compression management during packet building.
pub struct CompressionContext {
    /// The compression map
    map: CompressionMap,
    /// Current write offset in packet
    current_offset: u16,
}

impl CompressionContext {
    /// Create a new compression context
    ///
    /// # Arguments
    ///
    /// * `initial_offset` - Starting offset (typically 12 for after DNS header)
    #[must_use] 
    pub fn new(initial_offset: u16) -> Self {
        Self {
            map: CompressionMap::new(),
            current_offset: initial_offset,
        }
    }

    /// Advance the current offset
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes written
    pub fn advance(&mut self, bytes: u16) {
        self.current_offset = self.current_offset.saturating_add(bytes);
    }

    /// Record a name at the current offset and advance
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name being written
    /// * `name_length` - Length of the name in bytes
    pub fn record_name(&mut self, name: String, name_length: u16) {
        self.map.insert(name, self.current_offset);
        self.advance(name_length);
    }

    /// Get a reference to the compression map
    #[must_use] 
    pub fn map(&self) -> &CompressionMap {
        &self.map
    }

    /// Get the current write offset
    #[must_use] 
    pub fn current_offset(&self) -> u16 {
        self.current_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_map_basic() {
        let mut map = CompressionMap::new();
        
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        
        map.insert("example.com".to_string(), 12);
        assert!(!map.is_empty());
        assert_eq!(map.len(), 1);
        
        assert_eq!(map.get("example.com"), Some(12));
        assert_eq!(map.get("notfound.com"), None);
        
        assert!(map.can_compress("example.com"));
        assert!(!map.can_compress("notfound.com"));
    }

    #[test]
    fn test_compression_map_offset_limit() {
        let mut map = CompressionMap::new();
        
        // Valid offset
        assert!(map.insert("valid.com".to_string(), 0x3FFF));
        
        // Offset too large (14-bit limit is 0x3FFF)
        assert!(!map.insert("toolarge.com".to_string(), 0x4000));
    }

    #[test]
    fn test_compression_context() {
        let mut ctx = CompressionContext::new(12);
        
        assert_eq!(ctx.current_offset(), 12);
        
        ctx.record_name("example.com".to_string(), 13); // "example.com" + null = 13 bytes
        assert_eq!(ctx.current_offset(), 25);
        
        assert!(ctx.map().can_compress("example.com"));
    }

    #[test]
    fn test_compression_map_duplicate_insert() {
        let mut map = CompressionMap::new();
        
        // First insert returns true (newly added)
        assert!(map.insert("example.com".to_string(), 12));
        
        // Second insert returns false (already exists)
        assert!(!map.insert("example.com".to_string(), 20));
        
        // Original offset is preserved
        assert_eq!(map.get("example.com"), Some(12));
    }
}
