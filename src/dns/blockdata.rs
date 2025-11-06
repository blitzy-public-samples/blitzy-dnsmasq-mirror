// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// Block-chained buffer management for large DNS records
//
// Translated from: src/blockdata.c

//! Efficient storage for large DNS records using chained blocks
//!
//! Implements efficient storage for large DNS records (like TXT or RRSIG)
//! that exceed typical buffer sizes, using a chain of fixed-size blocks.

const BLOCK_SIZE: usize = 256;

/// Block-chained buffer for large DNS data
#[derive(Debug, Clone)]
pub struct BlockData {
    blocks: Vec<Vec<u8>>,
    total_size: usize,
}

impl BlockData {
    /// Create a new empty BlockData
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            total_size: 0,
        }
    }

    /// Create BlockData from a byte slice
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut blocks = Vec::new();
        let mut remaining = data;

        while !remaining.is_empty() {
            let chunk_size = remaining.len().min(BLOCK_SIZE);
            blocks.push(remaining[..chunk_size].to_vec());
            remaining = &remaining[chunk_size..];
        }

        Self {
            blocks,
            total_size: data.len(),
        }
    }

    /// Get the total size of the data
    pub fn len(&self) -> usize {
        self.total_size
    }

    /// Check if the BlockData is empty
    pub fn is_empty(&self) -> bool {
        self.total_size == 0
    }

    /// Convert BlockData to a contiguous byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size);
        for block in &self.blocks {
            result.extend_from_slice(block);
        }
        result
    }

    /// Append data to the BlockData
    pub fn append(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let new_data = BlockData::from_bytes(data);
        self.blocks.extend(new_data.blocks);
        self.total_size += data.len();
    }

    /// Get a specific byte at an index
    pub fn get(&self, index: usize) -> Option<u8> {
        if index >= self.total_size {
            return None;
        }

        let block_index = index / BLOCK_SIZE;
        let byte_index = index % BLOCK_SIZE;

        self.blocks.get(block_index).and_then(|block| block.get(byte_index).copied())
    }
}

impl Default for BlockData {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for BlockData {
    fn from(data: Vec<u8>) -> Self {
        Self::from_bytes(&data)
    }
}

impl From<&[u8]> for BlockData {
    fn from(data: &[u8]) -> Self {
        Self::from_bytes(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockdata_new() {
        let bd = BlockData::new();
        assert_eq!(bd.len(), 0);
        assert!(bd.is_empty());
    }

    #[test]
    fn test_blockdata_from_small_data() {
        let data = b"Hello, World!";
        let bd = BlockData::from_bytes(data);
        
        assert_eq!(bd.len(), data.len());
        assert_eq!(bd.to_bytes(), data);
    }

    #[test]
    fn test_blockdata_from_large_data() {
        let data = vec![0u8; 1000]; // 1000 bytes, spans multiple blocks
        let bd = BlockData::from_bytes(&data);
        
        assert_eq!(bd.len(), 1000);
        assert_eq!(bd.blocks.len(), 4); // ceil(1000 / 256) = 4 blocks
        assert_eq!(bd.to_bytes(), data);
    }

    #[test]
    fn test_blockdata_append() {
        let mut bd = BlockData::from_bytes(b"Hello");
        bd.append(b", World!");
        
        assert_eq!(bd.len(), 13);
        assert_eq!(bd.to_bytes(), b"Hello, World!");
    }

    #[test]
    fn test_blockdata_get() {
        let bd = BlockData::from_bytes(b"Hello");
        
        assert_eq!(bd.get(0), Some(b'H'));
        assert_eq!(bd.get(4), Some(b'o'));
        assert_eq!(bd.get(5), None);
    }

    #[test]
    fn test_blockdata_get_across_blocks() {
        let data = vec![0u8; 300]; // Spans 2 blocks
        let bd = BlockData::from_bytes(&data);
        
        assert_eq!(bd.get(0), Some(0));
        assert_eq!(bd.get(255), Some(0));
        assert_eq!(bd.get(256), Some(0));
        assert_eq!(bd.get(299), Some(0));
        assert_eq!(bd.get(300), None);
    }
}
