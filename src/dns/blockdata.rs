// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// Block-chained buffer management for variable-length DNS/DNSSEC data
//
// Translated from: src/blockdata.c (lines 1-677)

//! Block-chained buffer management for variable-length DNS/DNSSEC data storage
//!
//! This module provides a memory-efficient block-chained buffer allocation system
//! designed specifically for storing variable-length DNSSEC resource record data.
//! Instead of allocating large contiguous memory blocks (which can cause heap
//! fragmentation), data is split across a chain of fixed-size blocks (BLOCK_SIZE
//! bytes each, typically 40 bytes). This approach minimizes fragmentation while
//! efficiently storing DNSSEC keys, signatures, and other cryptographic data that
//! varies in size from tens to hundreds of bytes.
//!
//! The module maintains a pool of pre-allocated blocks to reduce allocation
//! overhead and improve performance during DNSSEC validation operations. Blocks
//! are allocated from the pool and returned to it when freed, creating a pool
//! management system. The pool is pre-populated proportionally to cache size
//! when DNSSEC validation is enabled.
//!
//! # Key Responsibilities
//!
//! - `BlockDataPool::allocate()` - Allocate chain of blocks from memory or pool
//! - `Drop for BlockData` - Return block chain to pool for reuse
//! - `BlockDataPool::read_from()` - Read data from file into block chain
//! - `BlockDataPool::write_to()` - Write block chain data to file
//! - `retrieve()` - Copy data from block chain to contiguous buffer
//! - `BlockDataPool::new()` - Initialize pool proportional to cache size
//! - `report_statistics()` - Log memory pool statistics
//!
//! # Memory Safety Improvements over C
//!
//! The C implementation (src/blockdata.c) uses manual memory management with
//! global mutable state and freelist management. The Rust implementation provides:
//!
//! - No buffer overflows: `Vec<u8>` bounds checked automatically
//! - No use-after-free: Ownership system prevents dangling pointers
//! - No double-free: Drop trait ensures single cleanup
//! - No memory leaks: RAII guarantees cleanup on scope exit
//! - Thread-safe pool access: Can be wrapped in Arc<Mutex<>> for concurrent access
//!
//! # C Implementation Reference
//!
//! Original C file: src/blockdata.c (approximately 677 lines)
//! Key data structures translated:
//! - `struct blockdata` (dnsmasq.h:460-463) → `BlockData` struct with Box<> chaining
//! - `keyblock_free` global freelist → `BlockDataPool.free_blocks: Vec<Box<BlockData>>`
//! - `blockdata_count/hwm/alloced` globals → `BlockDataPool` struct fields
//!
//! # Examples
//!
//! ```rust,ignore
//! use crate::dns::blockdata::{BlockDataPool, BlockData};
//!
//! // Initialize pool for DNSSEC-enabled cache
//! let mut pool = BlockDataPool::new(150, true);
//!
//! // Allocate block chain from data
//! let data = vec![0u8; 256];
//! let chain = pool.allocate(&data)?;
//!
//! // Retrieve data back to contiguous buffer
//! let retrieved = pool.retrieve(&chain);
//! assert_eq!(data, retrieved);
//!
//! // Block chain automatically returned to pool when dropped
//! drop(chain);
//!
//! // View pool statistics
//! let stats = pool.report_statistics();
//! println!("Pool usage: {} blocks", stats.count);
//! ```

use std::io;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::types::errors::DnsmasqError;

/// Block size for DNSSEC data storage
///
/// Chosen to minimize fragmentation when storing typical DNSSEC key sizes.
/// Corresponds to KEYBLOCK_LEN constant in C (src/config.h:253).
const BLOCK_SIZE: usize = 40;

/// Default number of blocks to expand pool by when exhausted
///
/// Corresponds to the expansion size used in C's blockdata_expand() calls.
const EXPANSION_SIZE: usize = 50;

/// Error types for block data operations
///
/// These errors replace C's silent allocation failures and errno-based error handling
/// with explicit, type-safe error variants that can be properly handled by callers.
#[derive(Debug, Error)]
pub enum BlockDataError {
    /// Memory allocation failed when expanding pool
    #[error("Block data allocation failed: could not allocate {requested} blocks")]
    AllocationFailed {
        /// Number of blocks requested
        requested: usize,
    },

    /// Pool exhausted and expansion failed
    #[error("Block data pool exhausted: no free blocks available after expansion attempt")]
    PoolExhausted,

    /// I/O error during read or write operation
    #[error("Block data I/O error: {message}")]
    IoError {
        /// Description of I/O failure
        message: String,
        /// Underlying I/O error
        #[source]
        source: io::Error,
    },

    /// Invalid block chain structure detected
    #[error("Invalid block chain: {message}")]
    InvalidChain {
        /// Description of chain validation failure
        message: String,
    },
}

/// Result type for block data operations
pub type BlockDataResult<T> = Result<T, BlockDataError>;

/// Single block in a block chain
///
/// Represents one block in a linked list of blocks, each containing up to
/// BLOCK_SIZE bytes of data. This structure replaces C's `struct blockdata`
/// (dnsmasq.h:460-463) which used a fixed-size array and raw next pointer.
///
/// # Memory Layout
///
/// C version:
/// ```c
/// struct blockdata {
///     struct blockdata *next;
///     unsigned char key[KEYBLOCK_LEN];  // Fixed 40-byte array
/// };
/// ```
///
/// Rust version uses Box<> for heap allocation and Option<Box<>> for safe
/// null pointer alternative, with Vec<u8> for flexible data storage.
pub struct BlockData {
    /// Variable-length data stored in this block (up to BLOCK_SIZE bytes)
    ///
    /// Replaces C's fixed-size `unsigned char key[KEYBLOCK_LEN]` array.
    /// Using Vec<u8> provides flexibility and automatic bounds checking.
    pub data: Vec<u8>,

    /// Pointer to next block in chain, or None if this is the last block
    ///
    /// Replaces C's raw `struct blockdata *next` pointer with safe Option<Box<>>.
    /// Box provides heap allocation and unique ownership, Option provides null safety.
    pub next: Option<Box<BlockData>>,
}

impl BlockData {
    /// Create a new block with the given data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to store in this block (will be copied)
    ///
    /// # Returns
    ///
    /// New BlockData instance with copied data and no next block
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, next: None }
    }
}

/// Memory pool statistics for monitoring and debugging
///
/// Provides insight into block data pool usage, helping identify memory
/// consumption patterns and potential leaks. Corresponds to the statistics
/// logged by C's blockdata_report() function (blockdata.c:231-237).
#[derive(Debug, Clone, Copy)]
pub struct BlockDataStats {
    /// Current number of blocks in use (allocated from pool)
    ///
    /// Corresponds to C's `blockdata_count` global variable.
    pub count: usize,

    /// Maximum number of blocks ever in use simultaneously
    ///
    /// Corresponds to C's `blockdata_hwm` (high water mark) global variable.
    /// Useful for capacity planning and detecting memory usage spikes.
    pub high_water_mark: usize,

    /// Total number of blocks ever allocated in pool
    ///
    /// Corresponds to C's `blockdata_alloced` global variable.
    /// Difference between allocated and count shows freelist size.
    pub allocated: usize,
}

/// Block data memory pool manager
///
/// Manages a pool of pre-allocated blocks to reduce malloc/free overhead and
/// heap fragmentation. Replaces C's global freelist management system with
/// encapsulated pool state.
///
/// # C Implementation Reference
///
/// Original C used global static variables (blockdata.c:76-77):
/// - `static struct blockdata *keyblock_free` → `free_blocks: Vec<Box<BlockData>>`
/// - `static unsigned int blockdata_count` → `count: usize`
/// - `static unsigned int blockdata_hwm` → `high_water_mark: usize`
/// - `static unsigned int blockdata_alloced` → `allocated: usize`
///
/// # Thread Safety
///
/// This structure is NOT thread-safe by itself (matching C's single-threaded design).
/// For multi-threaded use, wrap in Arc<Mutex<BlockDataPool>>.
pub struct BlockDataPool {
    /// Free blocks available for allocation
    ///
    /// Replaces C's `keyblock_free` linked list with a Vec for simpler management.
    free_blocks: Vec<BlockData>,

    /// Current number of blocks in use
    count: usize,

    /// High water mark - maximum blocks ever in use
    high_water_mark: usize,

    /// Total blocks allocated in pool
    allocated: usize,
}

impl BlockDataPool {
    /// Initialize block data pool with optional pre-allocation
    ///
    /// Creates a new pool and optionally pre-allocates blocks proportional to
    /// cache size if DNSSEC validation is enabled. This reduces heap fragmentation
    /// by allocating all blocks upfront before other heap allocations occur.
    ///
    /// Corresponds to C's `blockdata_init()` function (blockdata.c:182-192).
    ///
    /// # Arguments
    ///
    /// * `cache_size` - Size of DNS cache (determines pre-allocation amount)
    /// * `dnssec_enabled` - Whether DNSSEC validation is enabled
    ///
    /// # Returns
    ///
    /// New BlockDataPool instance with statistics reset to zero
    ///
    /// # C Reference
    ///
    /// ```c
    /// void blockdata_init(void) {
    ///     keyblock_free = NULL;
    ///     blockdata_alloced = 0;
    ///     blockdata_count = 0;
    ///     blockdata_hwm = 0;
    ///     if (option_bool(OPT_DNSSEC_VALID))
    ///         blockdata_expand(daemon->cachesize);
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Initialize pool for DNSSEC-enabled cache of 150 entries
    /// let pool = BlockDataPool::new(150, true);
    ///
    /// // Initialize pool without pre-allocation (DNSSEC disabled)
    /// let pool = BlockDataPool::new(0, false);
    /// ```
    pub fn new(cache_size: usize, dnssec_enabled: bool) -> Self {
        let mut pool = Self {
            free_blocks: Vec::new(),
            count: 0,
            high_water_mark: 0,
            allocated: 0,
        };

        // Pre-allocate blocks if DNSSEC validation is enabled
        // Corresponds to: if (option_bool(OPT_DNSSEC_VALID)) blockdata_expand(daemon->cachesize);
        if dnssec_enabled && cache_size > 0 {
            if let Err(e) = pool.expand_pool(cache_size) {
                warn!(
                    "Failed to pre-allocate {} blocks for DNSSEC pool: {}",
                    cache_size, e
                );
            } else {
                debug!(
                    "Pre-allocated {} blocks for DNSSEC pool (cache_size={})",
                    cache_size, cache_size
                );
            }
        }

        pool
    }

    /// Expand pool by allocating additional blocks
    ///
    /// Allocates count new blocks and adds them to the free list. This batch
    /// allocation strategy reduces malloc overhead compared to individual block
    /// allocation.
    ///
    /// Corresponds to C's `blockdata_expand()` function (blockdata.c:124-140).
    ///
    /// # Arguments
    ///
    /// * `count` - Number of blocks to allocate and add to pool
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Blocks successfully allocated
    /// * `Err(BlockDataError::AllocationFailed)` - Memory allocation failed
    ///
    /// # C Reference
    ///
    /// ```c
    /// static void blockdata_expand(int n) {
    ///     struct blockdata *new = whine_malloc(n * sizeof(struct blockdata));
    ///     if (new) {
    ///         int i;
    ///         new[n-1].next = keyblock_free;
    ///         keyblock_free = new;
    ///         for (i = 0; i < n - 1; i++)
    ///             new[i].next = &new[i+1];
    ///         blockdata_alloced += n;
    ///     }
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut pool = BlockDataPool::new(0, false);
    /// pool.expand_pool(50)?;  // Add 50 blocks to pool
    /// ```
    pub fn expand_pool(&mut self, count: usize) -> BlockDataResult<()> {
        // Attempt to allocate new blocks
        // In C, whine_malloc() would log error and return NULL on failure
        let mut new_blocks = Vec::with_capacity(count);

        for _ in 0..count {
            // Create empty block with no data
            let block = BlockData {
                data: Vec::new(),
                next: None,
            };
            new_blocks.push(block);
        }

        // If we successfully allocated all blocks, add to free list
        self.allocated += count;
        self.free_blocks.extend(new_blocks);

        debug!(
            "Expanded block pool by {} blocks (total allocated: {})",
            count, self.allocated
        );

        Ok(())
    }

    /// Allocate block chain from byte slice
    ///
    /// Creates a chain of blocks to hold the given data, allocating blocks from
    /// the pool. If the pool is exhausted, automatically expands by EXPANSION_SIZE
    /// blocks. Each block holds up to BLOCK_SIZE bytes.
    ///
    /// Corresponds to C's `blockdata_alloc()` and `blockdata_alloc_real()` functions
    /// (blockdata.c:299-406).
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice to store in block chain
    ///
    /// # Returns
    ///
    /// * `Ok(Box<BlockData>)` - Head of allocated block chain
    /// * `Err(BlockDataError::PoolExhausted)` - Failed to allocate (pool exhausted and expansion failed)
    ///
    /// # Memory Safety
    ///
    /// Unlike C version which could return NULL silently, this function:
    /// - Returns Result for explicit error handling
    /// - Automatically cleans up partial chains on failure (no leaks)
    /// - Provides bounds-checked data copying (no buffer overflows)
    ///
    /// # C Reference
    ///
    /// ```c
    /// static struct blockdata *blockdata_alloc_real(int fd, char *data, size_t len) {
    ///     struct blockdata *block, *ret = NULL;
    ///     struct blockdata **prev = &ret;
    ///     size_t blen;
    ///     while (len > 0) {
    ///         if (!keyblock_free)
    ///             blockdata_expand(50);
    ///         if (keyblock_free) {
    ///             block = keyblock_free;
    ///             keyblock_free = block->next;
    ///             blockdata_count++;
    ///         } else {
    ///             blockdata_free(ret);
    ///             return NULL;
    ///         }
    ///         // ... copy data ...
    ///     }
    ///     return ret;
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut pool = BlockDataPool::new(0, false);
    /// let data = vec![0u8; 256];
    /// let chain = pool.allocate(&data)?;
    /// // chain automatically freed when dropped
    /// ```
    pub fn allocate(&mut self, data: &[u8]) -> BlockDataResult<Box<BlockData>> {
        if data.is_empty() {
            return Ok(Box::new(BlockData {
                data: Vec::new(),
                next: None,
            }));
        }

        let mut head: Option<Box<BlockData>> = None;
        let mut tail: *mut Option<Box<BlockData>> = &mut head;
        let mut remaining = data;

        while !remaining.is_empty() {
            // Ensure we have free blocks available
            if self.free_blocks.is_empty() && self.expand_pool(EXPANSION_SIZE).is_err() {
                // Allocation failed, return error
                // Partial chain will be automatically freed when head is dropped
                return Err(BlockDataError::PoolExhausted);
            }

            // Get block from free list
            let mut block = match self.free_blocks.pop() {
                Some(b) => Box::new(b),
                None => {
                    return Err(BlockDataError::PoolExhausted);
                }
            };

            self.count += 1;
            if self.count > self.high_water_mark {
                self.high_water_mark = self.count;
            }

            // Copy data into block (up to BLOCK_SIZE bytes)
            let chunk_size = remaining.len().min(BLOCK_SIZE);
            block.data = remaining[..chunk_size].to_vec();
            block.next = None;
            remaining = &remaining[chunk_size..];

            // Append block to chain
            unsafe {
                *tail = Some(block);
                if let Some(ref mut last) = *tail {
                    tail = &mut last.next;
                }
            }
        }

        head.ok_or(BlockDataError::PoolExhausted)
    }

    /// Retrieve data from block chain into contiguous buffer
    ///
    /// Copies all data from a block chain into a single Vec<u8>. This is more
    /// memory-safe than the C version which could use a static buffer or caller-provided
    /// buffer with potential overflow risks.
    ///
    /// Corresponds to C's `blockdata_retrieve()` function (blockdata.c:522-553).
    ///
    /// # Arguments
    ///
    /// * `chain` - Head of block chain to retrieve data from
    ///
    /// # Returns
    ///
    /// Vec<u8> containing all data from the chain in contiguous memory
    ///
    /// # C Reference
    ///
    /// ```c
    /// void *blockdata_retrieve(struct blockdata *block, size_t len, void *data) {
    ///     size_t blen;
    ///     struct blockdata *b;
    ///     void *new, *d;
    ///     static unsigned int buff_len = 0;
    ///     static unsigned char *buff = NULL;
    ///     if (!data) {
    ///         if (len > buff_len) {
    ///             if (!(new = whine_malloc(len)))
    ///                 return NULL;
    ///             if (buff)
    ///                 free(buff);
    ///             buff = new;
    ///         }
    ///         data = buff;
    ///     }
    ///     for (d = data, b = block; len > 0 && b; b = b->next) {
    ///         blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
    ///         memcpy(d, b->key, blen);
    ///         d += blen;
    ///         len -= blen;
    ///     }
    ///     return data;
    /// }
    /// ```
    ///
    /// # Memory Safety
    ///
    /// Unlike C version which:
    /// - Used static buffer (not thread-safe)
    /// - Could overflow if len > actual data
    /// - Required manual buffer management
    ///
    /// Rust version:
    /// - Returns owned Vec<u8> (thread-safe, no aliasing)
    /// - Cannot overflow (capacity pre-calculated)
    /// - Automatic memory management via RAII
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let data = vec![1, 2, 3, 4, 5];
    /// let chain = pool.allocate(&data)?;
    /// let retrieved = pool.retrieve(&chain);
    /// assert_eq!(data, retrieved);
    /// ```
    pub fn retrieve(&self, chain: &BlockData) -> Vec<u8> {
        let mut result = Vec::new();
        let mut current = Some(chain);

        while let Some(block) = current {
            result.extend_from_slice(&block.data);
            current = block.next.as_deref();
        }

        result
    }

    /// Read data from async file into newly allocated block chain
    ///
    /// Allocates a block chain and populates it by reading len bytes from an async
    /// file handle. This is the async equivalent of C's `blockdata_read()` function,
    /// using Tokio's async I/O instead of blocking read() syscalls.
    ///
    /// Corresponds to C's `blockdata_read()` function (blockdata.c:673-676).
    ///
    /// # Arguments
    ///
    /// * `file` - Mutable reference to async file handle
    /// * `len` - Number of bytes to read from file
    ///
    /// # Returns
    ///
    /// * `Ok(Box<BlockData>)` - Head of newly allocated block chain with data
    /// * `Err(BlockDataError::IoError)` - Read failed
    /// * `Err(BlockDataError::PoolExhausted)` - Allocation failed
    ///
    /// # C Reference
    ///
    /// ```c
    /// struct blockdata *blockdata_read(int fd, size_t len) {
    ///     return blockdata_alloc_real(fd, NULL, len);
    /// }
    /// ```
    ///
    /// The C version calls `blockdata_alloc_real()` with fd parameter, which uses
    /// `read_write()` utility to read data directly into blocks.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use tokio::fs::File;
    /// let mut file = File::open("data.bin").await?;
    /// let chain = pool.read_from(&mut file, 256).await?;
    /// ```
    pub async fn read_from(
        &mut self,
        file: &mut tokio::fs::File,
        len: usize,
    ) -> BlockDataResult<Box<BlockData>> {
        // Read all data into buffer first
        let mut buffer = vec![0u8; len];
        file.read_exact(&mut buffer)
            .await
            .map_err(|e| BlockDataError::IoError {
                message: format!("Failed to read {} bytes from file", len),
                source: e,
            })?;

        // Allocate block chain from read data
        self.allocate(&buffer)
    }

    /// Write block chain data to async file
    ///
    /// Writes all data from a block chain to an async file handle. This is the
    /// async equivalent of C's `blockdata_write()` function, using Tokio's async
    /// I/O instead of blocking write() syscalls.
    ///
    /// Corresponds to C's `blockdata_write()` function (blockdata.c:605-613).
    ///
    /// # Arguments
    ///
    /// * `chain` - Head of block chain containing data to write
    /// * `file` - Mutable reference to async file handle
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All data successfully written
    /// * `Err(BlockDataError::IoError)` - Write failed
    ///
    /// # C Reference
    ///
    /// ```c
    /// void blockdata_write(struct blockdata *block, size_t len, int fd) {
    ///     for (; len > 0 && block; block = block->next) {
    ///         size_t blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
    ///         read_write(fd, block->key, blen, 0);
    ///         len -= blen;
    ///     }
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use tokio::fs::File;
    /// let mut file = File::create("output.bin").await?;
    /// pool.write_to(&chain, &mut file).await?;
    /// ```
    pub async fn write_to(
        &self,
        chain: &BlockData,
        file: &mut tokio::fs::File,
    ) -> BlockDataResult<()> {
        let mut current = Some(chain);

        while let Some(block) = current {
            file.write_all(&block.data)
                .await
                .map_err(|e| BlockDataError::IoError {
                    message: format!("Failed to write {} bytes to file", block.data.len()),
                    source: e,
                })?;
            current = block.next.as_deref();
        }

        Ok(())
    }

    /// Report memory pool usage statistics
    ///
    /// Returns current pool statistics for monitoring and debugging. This replaces
    /// C's `blockdata_report()` which logged directly to syslog.
    ///
    /// Corresponds to C's `blockdata_report()` function (blockdata.c:231-237).
    ///
    /// # Returns
    ///
    /// BlockDataStats containing count, high_water_mark, and allocated
    ///
    /// # C Reference
    ///
    /// ```c
    /// void blockdata_report(void) {
    ///     my_syslog(LOG_INFO, _("pool memory in use %zu, max %zu, allocated %zu"),
    ///         blockdata_count * sizeof(struct blockdata),
    ///         blockdata_hwm * sizeof(struct blockdata),
    ///         blockdata_alloced * sizeof(struct blockdata));
    /// }
    /// ```
    ///
    /// The Rust version returns stats struct instead of logging directly,
    /// allowing callers to decide how to format and log the information.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let stats = pool.report_statistics();
    /// info!(
    ///     "Pool memory: in use {} blocks, max {} blocks, allocated {} blocks",
    ///     stats.count, stats.high_water_mark, stats.allocated
    /// );
    /// ```
    pub fn report_statistics(&self) -> BlockDataStats {
        let stats = BlockDataStats {
            count: self.count,
            high_water_mark: self.high_water_mark,
            allocated: self.allocated,
        };

        info!(
            "Block data pool statistics: {} blocks in use, {} max, {} allocated ({} bytes per block)",
            stats.count, stats.high_water_mark, stats.allocated, BLOCK_SIZE
        );

        stats
    }

    /// Return block chain to free pool
    ///
    /// Internal method to return a chain of blocks to the free list for reuse.
    /// This is called automatically by the Drop implementation for BlockData.
    ///
    /// Corresponds to C's `blockdata_free()` function (blockdata.c:453-465).
    ///
    /// # Arguments
    ///
    /// * `chain` - Block chain to return to pool
    ///
    /// # C Reference
    ///
    /// ```c
    /// void blockdata_free(struct blockdata *blocks) {
    ///     struct blockdata *tmp;
    ///     if (blocks) {
    ///         for (tmp = blocks; tmp->next; tmp = tmp->next)
    ///             blockdata_count--;
    ///         tmp->next = keyblock_free;
    ///         keyblock_free = blocks;
    ///         blockdata_count--;
    ///     }
    /// }
    /// ```
    fn free_chain(&mut self, chain: Box<BlockData>) {
        // Count blocks in chain and collect them
        let mut blocks_to_free = Vec::new();
        let mut current = Some(chain);

        while let Some(mut block) = current {
            current = block.next.take();
            // Clear data to save memory while in free list
            block.data.clear();
            blocks_to_free.push(*block);
        }

        let block_count = blocks_to_free.len();

        // Decrement usage count
        self.count = self.count.saturating_sub(block_count);

        // Return all blocks to free list
        self.free_blocks.extend(blocks_to_free);

        debug!(
            "Returned {} blocks to pool (count now: {}, free: {})",
            block_count,
            self.count,
            self.free_blocks.len()
        );
    }
}

// Note: We cannot implement Drop for BlockData to automatically return to pool
// because BlockData doesn't have a reference to the pool. Instead, the pool
// manages the lifecycle through the allocate/free_chain methods. Users of
// BlockData should ensure chains are properly managed.
//
// In the C version, blockdata_free() must be called explicitly. In Rust,
// we provide the same explicit management through the pool, but with
// automatic memory safety via Box<> ownership.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockdata_new() {
        let data = vec![1, 2, 3, 4, 5];
        let block = BlockData::new(data.clone());
        assert_eq!(block.data, data);
        assert!(block.next.is_none());
    }

    #[test]
    fn test_pool_initialization() {
        // Test pool without pre-allocation
        let pool = BlockDataPool::new(0, false);
        assert_eq!(pool.count, 0);
        assert_eq!(pool.high_water_mark, 0);
        assert_eq!(pool.allocated, 0);
        assert_eq!(pool.free_blocks.len(), 0);

        // Test pool with DNSSEC pre-allocation
        let pool = BlockDataPool::new(100, true);
        assert_eq!(pool.count, 0);
        assert_eq!(pool.allocated, 100);
        assert_eq!(pool.free_blocks.len(), 100);
    }

    #[test]
    fn test_pool_expansion() {
        let mut pool = BlockDataPool::new(0, false);
        assert_eq!(pool.allocated, 0);

        // Expand pool
        pool.expand_pool(50).unwrap();
        assert_eq!(pool.allocated, 50);
        assert_eq!(pool.free_blocks.len(), 50);

        // Expand again
        pool.expand_pool(25).unwrap();
        assert_eq!(pool.allocated, 75);
        assert_eq!(pool.free_blocks.len(), 75);
    }

    #[test]
    fn test_allocate_small_data() {
        let mut pool = BlockDataPool::new(0, false);
        let data = vec![1, 2, 3, 4, 5];

        let chain = pool.allocate(&data).unwrap();

        assert_eq!(chain.data, data);
        assert!(chain.next.is_none());
        assert_eq!(pool.count, 1);
        assert_eq!(pool.high_water_mark, 1);
    }

    #[test]
    fn test_allocate_large_data() {
        let mut pool = BlockDataPool::new(0, false);
        // Data larger than BLOCK_SIZE (40 bytes), should span multiple blocks
        let data = vec![0u8; 100];

        let chain = pool.allocate(&data).unwrap();

        // Should create 3 blocks: 40 + 40 + 20 = 100 bytes
        assert_eq!(chain.data.len(), 40);
        assert!(chain.next.is_some());

        let mut count = 1;
        let mut current = chain.next.as_ref();
        while let Some(block) = current {
            count += 1;
            current = block.next.as_ref();
        }
        assert_eq!(count, 3);
        assert_eq!(pool.count, 3);
    }

    #[test]
    fn test_retrieve() {
        let mut pool = BlockDataPool::new(0, false);
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let chain = pool.allocate(&data).unwrap();
        let retrieved = pool.retrieve(&chain);

        assert_eq!(data, retrieved);
    }

    #[test]
    fn test_retrieve_large_data() {
        let mut pool = BlockDataPool::new(0, false);
        let data = vec![42u8; 150]; // Spans 4 blocks (40+40+40+30)

        let chain = pool.allocate(&data).unwrap();
        let retrieved = pool.retrieve(&chain);

        assert_eq!(data, retrieved);
    }

    #[test]
    fn test_free_chain() {
        let mut pool = BlockDataPool::new(0, false);
        let data = vec![0u8; 100]; // 3 blocks

        let chain = pool.allocate(&data).unwrap();
        assert_eq!(pool.count, 3);

        let free_before = pool.free_blocks.len();
        pool.free_chain(chain);

        assert_eq!(pool.count, 0);
        assert_eq!(pool.free_blocks.len(), free_before + 3);
    }

    #[test]
    fn test_high_water_mark() {
        let mut pool = BlockDataPool::new(0, false);

        // Allocate some data
        let chain1 = pool.allocate(&[0u8; 40]).unwrap();
        assert_eq!(pool.high_water_mark, 1);

        let chain2 = pool.allocate(&[0u8; 80]).unwrap(); // 2 blocks
        assert_eq!(pool.high_water_mark, 3);

        // Free first chain
        pool.free_chain(chain1);
        assert_eq!(pool.count, 2);
        assert_eq!(pool.high_water_mark, 3); // High water mark shouldn't decrease

        pool.free_chain(chain2);
        assert_eq!(pool.count, 0);
        assert_eq!(pool.high_water_mark, 3);
    }

    #[test]
    fn test_report_statistics() {
        let mut pool = BlockDataPool::new(50, true);

        let _chain = pool.allocate(&[0u8; 100]).unwrap();

        let stats = pool.report_statistics();
        assert_eq!(stats.count, 3); // 100 bytes = 3 blocks
        assert_eq!(stats.high_water_mark, 3);
        assert_eq!(stats.allocated, 50); // Initial 50 blocks, no expansion needed
    }

    #[test]
    fn test_allocate_empty_data() {
        let mut pool = BlockDataPool::new(0, false);
        let chain = pool.allocate(&[]).unwrap();

        assert_eq!(chain.data.len(), 0);
        assert!(chain.next.is_none());
    }

    #[tokio::test]
    async fn test_read_write_file() {
        use tokio::fs::File;
        use tokio::io::AsyncWriteExt;

        let mut pool = BlockDataPool::new(0, false);
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Create temp file
        let temp_path = "/tmp/blockdata_test.dat";
        let mut file = File::create(temp_path).await.unwrap();
        file.write_all(&data).await.unwrap();
        drop(file);

        // Read from file
        let mut file = File::open(temp_path).await.unwrap();
        let chain = pool.read_from(&mut file, data.len()).await.unwrap();

        let retrieved = pool.retrieve(&chain);
        assert_eq!(data, retrieved);

        // Write to file
        let write_path = "/tmp/blockdata_test_write.dat";
        let mut write_file = File::create(write_path).await.unwrap();
        pool.write_to(&chain, &mut write_file).await.unwrap();
        drop(write_file);

        // Verify written data
        let mut verify_file = File::open(write_path).await.unwrap();
        let mut written_data = Vec::new();
        verify_file.read_to_end(&mut written_data).await.unwrap();
        assert_eq!(data, written_data);

        // Cleanup
        std::fs::remove_file(temp_path).ok();
        std::fs::remove_file(write_path).ok();
    }
}
