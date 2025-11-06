//! Block-chained storage for variable-length DNS data
//!
//! Provides efficient storage for variable-length data such as DNS names,
//! TXT records, and DNSSEC signatures using a block-chained approach.
//! Replaces C implementation from blockdata.c.

use std::sync::Arc;

/// Block size for storage (matches C implementation)
const BLOCK_SIZE: usize = 128;

/// A block of data
#[derive(Debug, Clone)]
struct Block {
    /// Data stored in this block
    data: Vec<u8>,
    
    /// Next block in chain, if any
    next: Option<Arc<Block>>,
}

impl Block {
    /// Create a new block with the given data
    fn new(data: Vec<u8>) -> Self {
        Self { data, next: None }
    }

    /// Create a new block with data and a next pointer
    fn with_next(data: Vec<u8>, next: Arc<Block>) -> Self {
        Self {
            data,
            next: Some(next),
        }
    }
}

/// Block-chained data storage
///
/// Stores variable-length data as a chain of fixed-size blocks.
/// Optimized for DNS name compression and DNSSEC signature storage.
#[derive(Debug, Clone)]
pub struct BlockData {
    /// Head block (most recent)
    head: Option<Arc<Block>>,
    
    /// Total size of data stored
    total_size: usize,
}

impl BlockData {
    /// Create a new empty BlockData
    pub fn new() -> Self {
        Self {
            head: None,
            total_size: 0,
        }
    }

    /// Create BlockData from a slice of bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice to store
    ///
    /// # Returns
    ///
    /// Returns a new BlockData containing the data split into blocks.
    pub fn from_slice(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::new();
        }

        let mut chunks: Vec<&[u8]> = data.chunks(BLOCK_SIZE).collect();
        chunks.reverse(); // Reverse to build chain from tail to head

        let mut head: Option<Arc<Block>> = None;

        for chunk in chunks {
            let block = if let Some(next) = head {
                Arc::new(Block::with_next(chunk.to_vec(), next))
            } else {
                Arc::new(Block::new(chunk.to_vec()))
            };
            head = Some(block);
        }

        Self {
            head,
            total_size: data.len(),
        }
    }

    /// Get the total size of stored data
    pub fn len(&self) -> usize {
        self.total_size
    }

    /// Check if the BlockData is empty
    pub fn is_empty(&self) -> bool {
        self.total_size == 0
    }

    /// Convert BlockData back to a contiguous Vec<u8>
    ///
    /// # Returns
    ///
    /// Returns a Vec<u8> containing all data from all blocks.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size);
        
        let mut current = self.head.as_ref();
        while let Some(block) = current {
            result.extend_from_slice(&block.data);
            current = block.next.as_ref();
        }

        result
    }

    /// Read data from the BlockData at a specific offset
    ///
    /// # Arguments
    ///
    /// * `offset` - Starting offset to read from
    /// * `buf` - Buffer to read into
    ///
    /// # Returns
    ///
    /// Returns the number of bytes read.
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        if offset >= self.total_size || buf.is_empty() {
            return 0;
        }

        let max_read = std::cmp::min(buf.len(), self.total_size - offset);
        let mut bytes_read = 0;
        let mut current_offset = 0;

        let mut current = self.head.as_ref();
        while let Some(block) = current {
            let block_end = current_offset + block.data.len();
            
            if offset < block_end && bytes_read < max_read {
                let block_offset = if offset > current_offset {
                    offset - current_offset
                } else {
                    0
                };
                
                let available = block.data.len() - block_offset;
                let to_read = std::cmp::min(available, max_read - bytes_read);
                
                buf[bytes_read..bytes_read + to_read]
                    .copy_from_slice(&block.data[block_offset..block_offset + to_read]);
                
                bytes_read += to_read;
            }

            current_offset = block_end;
            current = block.next.as_ref();

            if bytes_read >= max_read {
                break;
            }
        }

        bytes_read
    }

    /// Get a slice of data from the BlockData
    ///
    /// # Arguments
    ///
    /// * `offset` - Starting offset
    /// * `len` - Length to extract
    ///
    /// # Returns
    ///
    /// Returns Some(Vec<u8>) if the range is valid, None otherwise.
    pub fn slice(&self, offset: usize, len: usize) -> Option<Vec<u8>> {
        if offset + len > self.total_size {
            return None;
        }

        let mut buf = vec![0u8; len];
        let bytes_read = self.read_at(offset, &mut buf);
        
        if bytes_read == len {
            Some(buf)
        } else {
            None
        }
    }

    /// Compare BlockData with a byte slice
    ///
    /// # Arguments
    ///
    /// * `other` - Byte slice to compare with
    ///
    /// # Returns
    ///
    /// Returns true if the BlockData contains the same data as the slice.
    pub fn equals(&self, other: &[u8]) -> bool {
        if self.total_size != other.len() {
            return false;
        }

        let self_data = self.to_vec();
        self_data == other
    }
}

impl Default for BlockData {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for BlockData {
    fn eq(&self, other: &Self) -> bool {
        if self.total_size != other.total_size {
            return false;
        }
        self.to_vec() == other.to_vec()
    }
}

impl Eq for BlockData {}

impl From<Vec<u8>> for BlockData {
    fn from(data: Vec<u8>) -> Self {
        Self::from_slice(&data)
    }
}

impl From<&[u8]> for BlockData {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

impl From<String> for BlockData {
    fn from(data: String) -> Self {
        Self::from_slice(data.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_blockdata() {
        let bd = BlockData::new();
        assert!(bd.is_empty());
        assert_eq!(bd.len(), 0);
        assert_eq!(bd.to_vec(), Vec::<u8>::new());
    }

    #[test]
    fn test_small_data() {
        let data = b"Hello, World!";
        let bd = BlockData::from_slice(data);
        
        assert_eq!(bd.len(), data.len());
        assert!(!bd.is_empty());
        assert_eq!(bd.to_vec(), data);
    }

    #[test]
    fn test_large_data() {
        // Create data larger than one block
        let data: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let bd = BlockData::from_slice(&data);
        
        assert_eq!(bd.len(), data.len());
        assert_eq!(bd.to_vec(), data);
    }

    #[test]
    fn test_read_at() {
        let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let bd = BlockData::from_slice(data);
        
        let mut buf = [0u8; 5];
        let bytes_read = bd.read_at(0, &mut buf);
        
        assert_eq!(bytes_read, 5);
        assert_eq!(&buf, b"ABCDE");
        
        let bytes_read = bd.read_at(10, &mut buf);
        assert_eq!(bytes_read, 5);
        assert_eq!(&buf, b"KLMNO");
    }

    #[test]
    fn test_read_at_partial() {
        let data = b"SHORT";
        let bd = BlockData::from_slice(data);
        
        let mut buf = [0u8; 10];
        let bytes_read = bd.read_at(0, &mut buf);
        
        assert_eq!(bytes_read, 5);
        assert_eq!(&buf[..5], b"SHORT");
    }

    #[test]
    fn test_read_at_out_of_bounds() {
        let data = b"TEST";
        let bd = BlockData::from_slice(data);
        
        let mut buf = [0u8; 5];
        let bytes_read = bd.read_at(10, &mut buf);
        
        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn test_slice() {
        let data = b"0123456789ABCDEFGHIJ";
        let bd = BlockData::from_slice(data);
        
        let slice = bd.slice(5, 5);
        assert!(slice.is_some());
        assert_eq!(slice.unwrap(), b"56789");
        
        let invalid_slice = bd.slice(15, 10);
        assert!(invalid_slice.is_none());
    }

    #[test]
    fn test_equals() {
        let data1 = b"Hello, World!";
        let bd = BlockData::from_slice(data1);
        
        assert!(bd.equals(data1));
        assert!(!bd.equals(b"Different data"));
    }

    #[test]
    fn test_blockdata_equality() {
        let data = b"Test data for equality";
        let bd1 = BlockData::from_slice(data);
        let bd2 = BlockData::from_slice(data);
        
        assert_eq!(bd1, bd2);
    }

    #[test]
    fn test_from_vec() {
        let vec = vec![1, 2, 3, 4, 5];
        let bd: BlockData = vec.clone().into();
        
        assert_eq!(bd.to_vec(), vec);
    }

    #[test]
    fn test_from_string() {
        let s = String::from("Test string");
        let bd: BlockData = s.clone().into();
        
        assert_eq!(bd.to_vec(), s.as_bytes());
    }

    #[test]
    fn test_block_size_boundary() {
        // Test data exactly at block boundary
        let data: Vec<u8> = vec![42; BLOCK_SIZE];
        let bd = BlockData::from_slice(&data);
        
        assert_eq!(bd.len(), BLOCK_SIZE);
        assert_eq!(bd.to_vec(), data);
    }

    #[test]
    fn test_multiple_blocks() {
        // Test data spanning multiple blocks
        let data: Vec<u8> = vec![17; BLOCK_SIZE * 3 + 50];
        let bd = BlockData::from_slice(&data);
        
        assert_eq!(bd.len(), BLOCK_SIZE * 3 + 50);
        assert_eq!(bd.to_vec(), data);
    }
}
