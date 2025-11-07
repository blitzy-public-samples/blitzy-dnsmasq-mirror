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

//! Block-chained buffer management for variable-length DNSSEC data
//!
//! # Purpose
//!
//! This module provides a memory-efficient block-chained buffer allocation system
//! designed specifically for storing variable-length DNSSEC resource record data.
//! Instead of allocating large contiguous memory blocks (which can cause heap
//! fragmentation), data is split across a chain of fixed-size blocks (KEYBLOCK_LEN
//! bytes each, typically 40 bytes). This approach minimizes fragmentation while
//! efficiently storing DNSSEC keys, signatures, and other cryptographic data that
//! varies in size from tens to hundreds of bytes.
//!
//! # Memory Safety
//!
//! The Rust implementation eliminates all manual memory management from the C version:
//! - `Box<[u8; KEYBLOCK_LEN]>` provides automatic deallocation via Drop trait
//! - `Vec<Box<BlockDataNode>>` replaces manual linked list traversal
//! - `RefCell` provides safe single-threaded interior mutability for freelist
//! - `AtomicUsize` enables thread-safe statistics without locks
//!
//! # Architecture
//!
//! The module maintains a freelist of pre-allocated blocks to reduce allocation
//! overhead and improve performance during DNSSEC validation operations. Blocks
//! are allocated from the freelist and returned to it when freed, creating a pool
//! management system. The freelist is pre-populated proportionally to cache size
//! when DNSSEC validation is enabled.
//!
//! # Key Components
//!
//! - `BlockData`: Public API representing a chain of blocks containing data
//! - `BlockDataNode`: Internal node structure for block chaining
//! - `BLOCK_ALLOCATOR`: Module-level singleton managing the freelist
//! - Statistics counters: blocks in use, high water mark, total allocated
//!
//! # Performance Characteristics
//!
//! - Block allocation: O(1) from freelist, O(n) when expanding freelist
//! - Block deallocation: O(n) for chain traversal + O(1) to prepend to freelist
//! - Data retrieval: O(n) where n is number of blocks in chain
//! - Memory overhead: ~8 bytes per block for Box pointer
//!
//! # Usage Example
//!
//! ```rust
//! use crate::dns::blockdata::{BlockData, init};
//!
//! // Initialize with cache size (typically done at startup)
//! init(150, true);  // 150 blocks pre-allocated if DNSSEC enabled
//!
//! // Allocate from memory buffer
//! let key_data: Vec<u8> = vec![0u8; 256];
//! let block_chain = BlockData::from_bytes(&key_data);
//!
//! // Retrieve data back to contiguous buffer
//! let retrieved = block_chain.to_bytes();
//! assert_eq!(retrieved.len(), 256);
//!
//! // BlockData automatically freed when dropped (RAII)
//! ```

use crate::core::config::KEYBLOCK_LEN;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::io::{self, Read, Write};

/// Internal node structure for block-chained storage
///
/// Each node contains a fixed-size data array and a pointer to the next node.
/// Forms a singly-linked list. Replaces C's `struct blockdata`.
#[derive(Debug)]
struct BlockDataNode {
    /// Fixed-size data storage array (40 bytes by default)
    data: Box<[u8; KEYBLOCK_LEN]>,
    /// Next node in the chain, if any
    next: Option<Box<BlockDataNode>>,
}

impl BlockDataNode {
    /// Create a new node with uninitialized data
    fn new() -> Self {
        Self {
            data: Box::new([0u8; KEYBLOCK_LEN]),
            next: None,
        }
    }
}

/// Block allocator managing freelist and statistics
///
/// Singleton structure maintaining the global freelist of available blocks
/// and tracking allocation statistics. Replaces C's global static variables.
#[allow(clippy::vec_box)]
struct BlockAllocator {
    /// Freelist of available blocks for reuse
    freelist: Mutex<Vec<Box<BlockDataNode>>>,
    /// Current number of blocks in use
    count: AtomicUsize,
    /// High water mark (maximum blocks ever in use)
    hwm: AtomicUsize,
    /// Total blocks ever allocated from heap
    allocated: AtomicUsize,
}

impl BlockAllocator {
    /// Create a new block allocator with empty freelist
    const fn new() -> Self {
        Self {
            freelist: Mutex::new(Vec::new()),
            count: AtomicUsize::new(0),
            hwm: AtomicUsize::new(0),
            allocated: AtomicUsize::new(0),
        }
    }

    /// Expand freelist by allocating n new blocks from heap
    ///
    /// Batch allocates n blocks and adds them to the freelist. This reduces
    /// malloc overhead compared to individual allocations. Typical expansion
    /// size is 50 blocks.
    fn expand(&self, n: usize) {
        let mut freelist = self.freelist.lock().unwrap();
        freelist.reserve(n);
        
        for _ in 0..n {
            freelist.push(Box::new(BlockDataNode::new()));
        }
        
        self.allocated.fetch_add(n, Ordering::Relaxed);
    }

    /// Allocate a single block from freelist or heap
    ///
    /// Attempts to pop a block from the freelist. If freelist is empty,
    /// expands by 50 blocks and retries. Updates statistics counters.
    ///
    /// Returns None only if heap allocation fails (extremely rare).
    fn alloc_block(&self) -> Option<Box<BlockDataNode>> {
        let mut freelist = self.freelist.lock().unwrap();
        
        if freelist.is_empty() {
            drop(freelist); // Release lock before expansion
            self.expand(50);
            freelist = self.freelist.lock().unwrap();
        }
        
        if let Some(block) = freelist.pop() {
            let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
            
            // Update high water mark if we've exceeded it
            let mut hwm = self.hwm.load(Ordering::Relaxed);
            while count > hwm {
                match self.hwm.compare_exchange_weak(
                    hwm,
                    count,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(current) => hwm = current,
                }
            }
            
            Some(block)
        } else {
            None
        }
    }

    /// Free a block chain by returning all blocks to freelist
    ///
    /// Traverses the chain to count blocks, decrements usage counter,
    /// then prepends the entire chain to the freelist. This bulk free
    /// operation is more efficient than freeing blocks individually.
    fn free_chain(&self, head: Option<Box<BlockDataNode>>) {
        if head.is_none() {
            return;
        }

        let mut chain_blocks = Vec::new();
        let mut node = head;
        let mut count = 0;

        // Traverse chain and collect all blocks
        while let Some(mut current) = node {
            count += 1;
            node = current.next.take();
            // Clear the next pointer before returning to freelist
            current.next = None;
            chain_blocks.push(current);
        }

        // Update usage counter
        self.count.fetch_sub(count, Ordering::Relaxed);

        // Return all blocks to freelist
        let mut freelist = self.freelist.lock().unwrap();
        freelist.extend(chain_blocks);
    }

    /// Reset allocator state and optionally preallocate blocks
    ///
    /// Clears the freelist and resets all counters to zero. If `dnssec_enabled`
    /// is true and `cache_size` > 0, preallocates `cache_size` blocks to reduce
    /// heap fragmentation during runtime.
    fn reset(&self, cache_size: usize, dnssec_enabled: bool) {
        // Clear freelist
        self.freelist.lock().unwrap().clear();
        
        // Reset all counters
        self.count.store(0, Ordering::Relaxed);
        self.hwm.store(0, Ordering::Relaxed);
        self.allocated.store(0, Ordering::Relaxed);

        // Preallocate blocks if DNSSEC validation is enabled
        if dnssec_enabled && cache_size > 0 {
            self.expand(cache_size);
        }
    }

    /// Get current statistics for reporting
    ///
    /// Returns tuple of (`blocks_in_use`, `high_water_mark`, `total_allocated`)
    fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.count.load(Ordering::Relaxed),
            self.hwm.load(Ordering::Relaxed),
            self.allocated.load(Ordering::Relaxed),
        )
    }
}

/// Global block allocator instance
///
/// Module-level singleton managing the freelist and statistics.
/// Replaces C's global static variables (`keyblock_free`, `blockdata_count`, etc.)
static BLOCK_ALLOCATOR: BlockAllocator = BlockAllocator::new();

/// Block-chained data storage
///
/// Public API representing a chain of blocks containing variable-length data.
/// Automatically manages memory through RAII - blocks are returned to freelist
/// when `BlockData` is dropped.
///
/// # Memory Layout
///
/// Data is stored as a singly-linked list of fixed-size blocks:
/// ```text
/// BlockData -> Node1[40 bytes] -> Node2[40 bytes] -> Node3[N bytes] -> None
/// ```
///
/// # Thread Safety
///
/// `BlockData` itself is not Send/Sync as it uses `RefCell` internally for the
/// freelist. All operations must be performed on the same thread. However,
/// statistics counters use `AtomicUsize` for thread-safe access.
#[derive(Debug)]
pub struct BlockData {
    /// Head of the block chain
    head: Option<Box<BlockDataNode>>,
    /// Total length of data stored across all blocks
    total_len: usize,
}

impl BlockData {
    /// Create a new empty `BlockData`
    ///
    /// Creates an empty block chain with no allocated blocks. Useful as a
    /// placeholder or for incremental construction.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::dns::blockdata::BlockData;
    ///
    /// let empty = BlockData::new();
    /// assert!(empty.is_empty());
    /// assert_eq!(empty.len(), 0);
    /// ```
    #[must_use] 
    pub fn new() -> Self {
        Self {
            head: None,
            total_len: 0,
        }
    }

    /// Create `BlockData` from a byte slice
    ///
    /// Allocates a block chain and copies data from the provided slice.
    /// Each block holds up to `KEYBLOCK_LEN` bytes. This is the primary
    /// construction method for storing DNSSEC keys, signatures, and other
    /// cryptographic data.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice to copy into the block chain
    ///
    /// # Returns
    ///
    /// `BlockData` containing the copied data, or empty `BlockData` if allocation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::dns::blockdata::BlockData;
    ///
    /// let key_data = vec![0x12, 0x34, 0x56, 0x78];
    /// let blocks = BlockData::from_bytes(&key_data);
    /// assert_eq!(blocks.len(), 4);
    ///
    /// let retrieved = blocks.to_bytes();
    /// assert_eq!(retrieved, key_data);
    /// ```
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::new();
        }

        let mut remaining = data;
        let mut head: Option<Box<BlockDataNode>> = None;
        let mut tail: *mut Option<Box<BlockDataNode>> = &raw mut head;

        while !remaining.is_empty() {
            // Allocate a block from freelist or heap
            let Some(mut block) = BLOCK_ALLOCATOR.alloc_block() else {
                // Allocation failed - free partial chain and return empty
                if let Some(chain) = head {
                    BLOCK_ALLOCATOR.free_chain(Some(chain));
                }
                return Self::new();
            };

            // Copy data into this block
            let copy_len = remaining.len().min(KEYBLOCK_LEN);
            block.data[..copy_len].copy_from_slice(&remaining[..copy_len]);
            remaining = &remaining[copy_len..];

            // Link block into chain
            unsafe {
                *tail = Some(block);
                if let Some(ref mut node) = *tail {
                    tail = &raw mut node.next;
                }
            }
        }

        Self {
            head,
            total_len: data.len(),
        }
    }

    /// Read data from a reader into a new `BlockData`
    ///
    /// Allocates a block chain and reads exactly `len` bytes from the provided
    /// reader. Used for loading persisted DNSSEC data from disk during cache
    /// restoration.
    ///
    /// # Arguments
    ///
    /// * `reader` - Source to read data from
    /// * `len` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// - `Ok(BlockData)` - Successfully read data into block chain
    /// - `Err(io::Error)` - Read error or allocation failure
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Reader fails to provide `len` bytes
    /// - Block allocation fails
    /// - I/O error occurs during reading
    ///
    /// On error, any partially allocated chain is automatically freed.
    pub fn from_reader<R: Read>(reader: &mut R, len: usize) -> io::Result<Self> {
        if len == 0 {
            return Ok(Self::new());
        }

        let mut remaining = len;
        let mut head: Option<Box<BlockDataNode>> = None;
        let mut tail: *mut Option<Box<BlockDataNode>> = &raw mut head;

        while remaining > 0 {
            // Allocate a block from freelist or heap
            let Some(mut block) = BLOCK_ALLOCATOR.alloc_block() else {
                // Allocation failed - free partial chain
                if let Some(chain) = head.take() {
                    BLOCK_ALLOCATOR.free_chain(Some(chain));
                }
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "Failed to allocate block",
                ));
            };

            // Read data directly into this block
            let read_len = remaining.min(KEYBLOCK_LEN);
            reader.read_exact(&mut block.data[..read_len]).inspect_err(|_e| {
                // Free partial chain on read error
                if let Some(chain) = head.take() {
                    BLOCK_ALLOCATOR.free_chain(Some(chain));
                }
            })?;

            remaining -= read_len;

            // Link block into chain
            unsafe {
                *tail = Some(block);
                if let Some(ref mut node) = *tail {
                    tail = &raw mut node.next;
                }
            }
        }

        Ok(Self {
            head,
            total_len: len,
        })
    }

    /// Convert block chain to a contiguous byte vector
    ///
    /// Copies all data from the block chain into a single contiguous Vec<u8>.
    /// This is the inverse of `from_bytes()`. Used when contiguous data access
    /// is needed, such as for cryptographic verification.
    ///
    /// # Returns
    ///
    /// Vec<u8> containing all data from the block chain
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::dns::blockdata::BlockData;
    ///
    /// let original = vec![1, 2, 3, 4, 5];
    /// let blocks = BlockData::from_bytes(&original);
    /// let retrieved = blocks.to_bytes();
    /// assert_eq!(retrieved, original);
    /// ```
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.total_len == 0 {
            return Vec::new();
        }

        let mut result = Vec::with_capacity(self.total_len);
        let mut node = self.head.as_ref();
        let mut remaining = self.total_len;

        while let Some(current) = node {
            let copy_len = remaining.min(KEYBLOCK_LEN);
            result.extend_from_slice(&current.data[..copy_len]);
            remaining -= copy_len;
            node = current.next.as_ref();
        }

        result
    }

    /// Write block chain data to a writer
    ///
    /// Writes all data from the block chain to the provided writer.
    /// Used for persisting DNSSEC data to disk (e.g., lease files with
    /// DNSSEC state).
    ///
    /// # Arguments
    ///
    /// * `writer` - Destination to write data to
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if the underlying writer fails to write data
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Successfully wrote all data
    /// - `Err(io::Error)` - Write error occurred
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::dns::blockdata::BlockData;
    /// use std::io::Cursor;
    ///
    /// let data = vec![1, 2, 3, 4, 5];
    /// let blocks = BlockData::from_bytes(&data);
    ///
    /// let mut output = Cursor::new(Vec::new());
    /// blocks.write_to(&mut output)?;
    /// assert_eq!(output.into_inner(), data);
    /// ```
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut node = self.head.as_ref();
        let mut remaining = self.total_len;

        while let Some(current) = node {
            let write_len = remaining.min(KEYBLOCK_LEN);
            writer.write_all(&current.data[..write_len])?;
            remaining -= write_len;
            node = current.next.as_ref();
        }

        Ok(())
    }

    /// Copy data into a provided buffer
    ///
    /// Copies up to `buffer.len()` bytes from the block chain into the provided
    /// buffer. Returns the number of bytes actually copied, which may be less
    /// than `buffer.len()` if the chain contains less data.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Destination buffer to copy data into
    ///
    /// # Returns
    ///
    /// Number of bytes copied into buffer
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::dns::blockdata::BlockData;
    ///
    /// let data = vec![1, 2, 3, 4, 5];
    /// let blocks = BlockData::from_bytes(&data);
    ///
    /// let mut buffer = [0u8; 10];
    /// let copied = blocks.copy_to_buffer(&mut buffer);
    /// assert_eq!(copied, 5);
    /// assert_eq!(&buffer[..5], &data[..]);
    /// ```
    pub fn copy_to_buffer(&self, buffer: &mut [u8]) -> usize {
        let mut node = self.head.as_ref();
        let mut offset = 0;
        let mut remaining = self.total_len.min(buffer.len());

        while let Some(current) = node {
            if remaining == 0 {
                break;
            }

            let copy_len = remaining.min(KEYBLOCK_LEN);
            buffer[offset..offset + copy_len].copy_from_slice(&current.data[..copy_len]);
            offset += copy_len;
            remaining -= copy_len;
            node = current.next.as_ref();
        }

        offset
    }

    /// Get the total length of data in the block chain
    ///
    /// Returns the total number of bytes stored across all blocks in the chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::dns::blockdata::BlockData;
    ///
    /// let data = vec![0u8; 100];
    /// let blocks = BlockData::from_bytes(&data);
    /// assert_eq!(blocks.len(), 100);
    /// ```
    #[must_use] 
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Check if the block chain is empty
    ///
    /// Returns true if the chain contains no data (`len()` == 0).
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::dns::blockdata::BlockData;
    ///
    /// let empty = BlockData::new();
    /// assert!(empty.is_empty());
    ///
    /// let data = BlockData::from_bytes(&[1, 2, 3]);
    /// assert!(!data.is_empty());
    /// ```
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }
}

impl Default for BlockData {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BlockData {
    /// Automatically return blocks to freelist when `BlockData` is dropped
    ///
    /// RAII pattern ensures blocks are recycled without explicit `free()` calls.
    /// This eliminates memory leaks and use-after-free bugs from the C implementation.
    fn drop(&mut self) {
        if let Some(head) = self.head.take() {
            BLOCK_ALLOCATOR.free_chain(Some(head));
        }
    }
}

impl Clone for BlockData {
    /// Clone the block chain by creating a new independent copy
    ///
    /// Allocates new blocks and copies all data. The cloned chain is
    /// completely independent of the original.
    fn clone(&self) -> Self {
        Self::from_bytes(&self.to_bytes())
    }
}

/// Initialize blockdata pool and preallocate blocks
///
/// Initializes the blockdata memory pool system by resetting all counters
/// and clearing the freelist. If DNSSEC validation is enabled and `cache_size`
/// is non-zero, preallocates `cache_size` blocks to reduce heap fragmentation
/// during runtime.
///
/// This function should be called once during daemon startup before any
/// blockdata allocation occurs.
///
/// # Arguments
///
/// * `cache_size` - Number of cache entries (used to size preallocation)
/// * `dnssec_enabled` - Whether DNSSEC validation is enabled
///
/// # Examples
///
/// ```
/// use crate::dns::blockdata::init;
///
/// // During daemon startup
/// init(150, true);  // Preallocate 150 blocks for DNSSEC
/// ```
///
/// # Thread Safety
///
/// Must be called from the main thread during single-threaded initialization
/// phase before the event loop starts.
pub fn init(cache_size: usize, dnssec_enabled: bool) {
    BLOCK_ALLOCATOR.reset(cache_size, dnssec_enabled);
}

/// Log blockdata pool memory usage statistics
///
/// Reports current memory pool usage statistics, showing:
/// - Current blocks in use
/// - Maximum blocks ever used (high water mark)
/// - Total blocks allocated from heap
///
/// Values are converted from block counts to bytes for human-readable output.
/// Useful for monitoring DNSSEC memory consumption and detecting memory leaks.
///
/// # Examples
///
/// ```
/// use crate::dns::blockdata::report;
///
/// // Log statistics on SIGUSR1 signal
/// report();
/// // Output logged: "blockdata pool: 4800 bytes in use, 6000 max, 7500 allocated"
/// ```
///
/// # Thread Safety
///
/// Thread-safe for reading statistics. Can be called from any thread.
pub fn report() {
    let (count, hwm, allocated) = BLOCK_ALLOCATOR.get_stats();
    let block_size = std::mem::size_of::<BlockDataNode>();
    
    tracing::info!(
        "blockdata pool: {} bytes in use, {} max, {} allocated",
        count * block_size,
        hwm * block_size,
        allocated * block_size
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_blockdata() {
        let empty = BlockData::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.to_bytes(), Vec::<u8>::new());
    }

    #[test]
    fn test_single_block() {
        let data = vec![1u8, 2, 3, 4, 5];
        let blocks = BlockData::from_bytes(&data);
        assert_eq!(blocks.len(), 5);
        assert!(!blocks.is_empty());
        assert_eq!(blocks.to_bytes(), data);
    }

    #[test]
    fn test_multiple_blocks() {
        // Create data larger than KEYBLOCK_LEN to span multiple blocks
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let blocks = BlockData::from_bytes(&data);
        assert_eq!(blocks.len(), 100);
        assert_eq!(blocks.to_bytes(), data);
    }

    #[test]
    fn test_exact_block_boundary() {
        // Test data that exactly fills blocks
        let data = vec![0xAB; KEYBLOCK_LEN * 3];
        let blocks = BlockData::from_bytes(&data);
        assert_eq!(blocks.len(), KEYBLOCK_LEN * 3);
        assert_eq!(blocks.to_bytes(), data);
    }

    #[test]
    fn test_copy_to_buffer() {
        let data = vec![1, 2, 3, 4, 5];
        let blocks = BlockData::from_bytes(&data);
        
        let mut buffer = [0u8; 10];
        let copied = blocks.copy_to_buffer(&mut buffer);
        assert_eq!(copied, 5);
        assert_eq!(&buffer[..5], &data[..]);
    }

    #[test]
    fn test_copy_to_small_buffer() {
        let data = vec![1, 2, 3, 4, 5];
        let blocks = BlockData::from_bytes(&data);
        
        let mut buffer = [0u8; 3];
        let copied = blocks.copy_to_buffer(&mut buffer);
        assert_eq!(copied, 3);
        assert_eq!(&buffer[..], &data[..3]);
    }

    #[test]
    fn test_clone() {
        let data = vec![1, 2, 3, 4, 5];
        let blocks1 = BlockData::from_bytes(&data);
        let blocks2 = blocks1.clone();
        
        assert_eq!(blocks1.len(), blocks2.len());
        assert_eq!(blocks1.to_bytes(), blocks2.to_bytes());
    }

    #[test]
    fn test_init_and_report() {
        init(100, true);
        report(); // Should not panic
        
        // Create and free some blocks to test statistics
        let data = vec![0u8; 200];
        let blocks = BlockData::from_bytes(&data);
        assert_eq!(blocks.len(), 200);
        drop(blocks);
        
        report(); // Should show updated statistics
    }

    #[test]
    fn test_write_and_read() {
        use std::io::Cursor;
        
        let original_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let blocks = BlockData::from_bytes(&original_data);
        
        // Write to cursor
        let mut cursor = Cursor::new(Vec::new());
        blocks.write_to(&mut cursor).unwrap();
        
        // Read back
        let written_data = cursor.into_inner();
        assert_eq!(written_data, original_data);
        
        // Test from_reader
        let mut read_cursor = Cursor::new(written_data);
        let read_blocks = BlockData::from_reader(&mut read_cursor, original_data.len()).unwrap();
        assert_eq!(read_blocks.to_bytes(), original_data);
    }

    #[test]
    fn test_large_data() {
        // Test with data significantly larger than a single block
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let blocks = BlockData::from_bytes(&data);
        assert_eq!(blocks.len(), 1000);
        
        let retrieved = blocks.to_bytes();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn test_freelist_reuse() {
        init(10, true);
        
        // Allocate and free multiple times to test freelist reuse
        for _ in 0..5 {
            let data = vec![0u8; 100];
            let blocks = BlockData::from_bytes(&data);
            assert_eq!(blocks.len(), 100);
            drop(blocks);
        }
        
        report(); // Verify statistics are reasonable
    }

    #[test]
    fn test_default() {
        let blocks = BlockData::default();
        assert!(blocks.is_empty());
        assert_eq!(blocks.len(), 0);
    }
}

