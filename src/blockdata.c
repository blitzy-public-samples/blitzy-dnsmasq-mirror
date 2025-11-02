/* dnsmasq is Copyright (c) 2000-2022 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file blockdata.c
 * @brief Block-chained buffer management for variable-length DNS/DNSSEC data
 * 
 * DETAILED PURPOSE:
 * This module provides a memory-efficient block-chained buffer allocation system
 * designed specifically for storing variable-length DNSSEC resource record data.
 * Instead of allocating large contiguous memory blocks (which can cause heap
 * fragmentation), data is split across a chain of fixed-size blocks (KEYBLOCK_LEN
 * bytes each, typically 40 bytes). This approach minimizes fragmentation while
 * efficiently storing DNSSEC keys, signatures, and other cryptographic data that
 * varies in size from tens to hundreds of bytes.
 * 
 * The module maintains a freelist of pre-allocated blocks to reduce allocation
 * overhead and improve performance during DNSSEC validation operations. Blocks
 * are allocated from the freelist and returned to it when freed, creating a pool
 * management system. The freelist is pre-populated proportionally to cache size
 * when DNSSEC validation is enabled.
 * 
 * KEY RESPONSIBILITIES:
 * - blockdata_alloc() - Allocate chain of blocks from memory or freelist
 * - blockdata_free() - Return block chain to freelist for reuse
 * - blockdata_read() - Read data from file descriptor into block chain
 * - blockdata_write() - Write block chain data to file descriptor
 * - blockdata_retrieve() - Copy data from block chain to contiguous buffer
 * - blockdata_init() - Initialize freelist proportional to cache size
 * - blockdata_report() - Log memory pool statistics to syslog
 * 
 * DEPENDENCIES:
 * - dnsmasq.h: Provides struct blockdata definition, KEYBLOCK_LEN constant,
 *              whine_malloc(), read_write() utility functions
 * - Used by: dnssec.c (DNSSEC record storage), cache.c (cached DNSSEC data)
 * - Calls: whine_malloc() for allocation, read_write() for I/O, memcpy() for data
 * 
 * DATA STRUCTURES:
 * - struct blockdata (dnsmasq.h:460-463): Single block with next pointer and
 *   KEYBLOCK_LEN-byte data array, forms linked list for chaining
 * - keyblock_free (line 19): Global freelist head pointer for available blocks
 * - blockdata_count (line 20): Current number of blocks in use
 * - blockdata_hwm (line 20): High water mark (maximum blocks ever in use)
 * - blockdata_alloced (line 20): Total blocks ever allocated
 * 
 * COMPILE-TIME OPTIONS:
 * - KEYBLOCK_LEN (config.h:24): Block data size, default 40 bytes to minimize
 *   fragmentation for typical DNSSEC key sizes
 * - OPT_DNSSEC_VALID: When set, triggers freelist pre-allocation in blockdata_init()
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Not thread-safe - uses global static
 * variables (keyblock_free, blockdata_count, blockdata_hwm, blockdata_alloced)
 * without locking. All blockdata operations must be called from the main event
 * loop thread only. Re-entrant only if freelist has available blocks.
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

static struct blockdata *keyblock_free;
static unsigned int blockdata_count, blockdata_hwm, blockdata_alloced;

/**
 * @brief Expand the blockdata freelist by allocating n new blocks
 * 
 * @detailed
 * Allocates a contiguous array of n blockdata structures using whine_malloc()
 * and links them into the global freelist (keyblock_free). The new blocks are
 * chained together using their next pointers, with the last block's next pointing
 * to the existing freelist head. This batch allocation strategy reduces malloc()
 * overhead compared to individual block allocation. Updates blockdata_alloced
 * counter to track total allocated blocks. Called automatically when freelist
 * is exhausted during allocation.
 * 
 * @param n Number of blocks to allocate and add to freelist (typically 50)
 * 
 * @return void (no return value)
 * 
 * @note If malloc fails, whine_malloc() logs error to syslog and expansion is
 *       silently skipped. Caller must check if keyblock_free is still NULL after
 *       calling to detect allocation failure. Typical expansion size is 50 blocks.
 * 
 * @warning Memory allocation failure is not explicitly signaled to caller. After
 *          calling blockdata_expand(), caller MUST check keyblock_free != NULL.
 *          Modifies global state (keyblock_free, blockdata_alloced).
 * 
 * @see blockdata_alloc_real() calls this when freelist is empty
 * @see blockdata_init() calls this during initialization
 * 
 * EXAMPLE USAGE:
 * @code
 * if (!keyblock_free)
 *     blockdata_expand(50);
 * if (keyblock_free)
 *     block = keyblock_free; // Allocation succeeded
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Allocates n * sizeof(struct blockdata) bytes from heap
 * - Modifies keyblock_free global (prepends new blocks to freelist)
 * - Increments blockdata_alloced by n
 * - May log error to syslog if allocation fails (via whine_malloc)
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global static variables without locking.
 * Must be called from main event loop thread only.
 */
static void blockdata_expand(int n)
{
  struct blockdata *new = whine_malloc(n * sizeof(struct blockdata));
  
  if (new)
    {
      int i;
      
      new[n-1].next = keyblock_free;
      keyblock_free = new;

      for (i = 0; i < n - 1; i++)
	new[i].next = &new[i+1];

      blockdata_alloced += n;
    }
}

/**
 * @brief Initialize blockdata pool and preallocate blocks proportional to cache size
 * 
 * @detailed
 * Initializes the blockdata memory pool system by resetting all global counters
 * (blockdata_count, blockdata_hwm, blockdata_alloced) to zero and clearing the
 * freelist. If DNSSEC validation is enabled (OPT_DNSSEC_VALID), preallocates a
 * number of blocks equal to daemon->cachesize to reduce heap fragmentation during
 * runtime. This preallocation strategy minimizes malloc() calls during DNSSEC
 * validation operations, improving performance. Called once during daemon startup.
 * 
 * @return void (no return value)
 * 
 * @note daemon->cachesize is guaranteed non-zero if OPT_DNSSEC_VALID is set (enforced
 *       by configuration parser). Preallocation reduces fragmentation by allocating
 *       all blocks upfront before other heap allocations occur.
 * 
 * @warning Must be called before any blockdata_alloc() calls. Typically called during
 *          daemon initialization sequence. Assumes daemon->cachesize is already set.
 * 
 * @see blockdata_expand() performs the actual allocation
 * @see blockdata_report() shows statistics after initialization
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon startup
 * daemon->cachesize = 150; // Configure cache size
 * blockdata_init();        // Preallocate 150 blocks if DNSSEC enabled
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Resets keyblock_free to NULL
 * - Resets blockdata_count, blockdata_hwm, blockdata_alloced to 0
 * - If OPT_DNSSEC_VALID enabled, allocates daemon->cachesize blocks via blockdata_expand()
 * - May allocate significant memory (cachesize * sizeof(struct blockdata) bytes)
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main thread during single-threaded
 * initialization phase before event loop starts.
 */
void blockdata_init(void)
{
  keyblock_free = NULL;
  blockdata_alloced = 0;
  blockdata_count = 0;
  blockdata_hwm = 0;

  /* Note that daemon->cachesize is enforced to have non-zero size if OPT_DNSSEC_VALID is set */  
  if (option_bool(OPT_DNSSEC_VALID))
    blockdata_expand(daemon->cachesize);
}

/**
 * @brief Log blockdata pool memory usage statistics to syslog
 * 
 * @detailed
 * Reports current memory pool usage statistics to syslog at LOG_INFO level,
 * showing current blocks in use, maximum blocks ever used (high water mark),
 * and total blocks allocated. Values are converted from block counts to bytes
 * by multiplying by sizeof(struct blockdata) for human-readable size reporting.
 * Useful for monitoring DNSSEC memory consumption and detecting memory leaks.
 * 
 * @return void (no return value)
 * 
 * @note Output format: "pool memory in use X, max Y, allocated Z" where X, Y, Z
 *       are byte counts. High water mark (max) indicates peak memory usage.
 *       Difference between allocated and in-use shows freelist size.
 * 
 * @warning Logged at LOG_INFO level, may be filtered by syslog configuration.
 *          Does not reset statistics - reports cumulative values since init.
 * 
 * @see blockdata_init() for counter initialization
 * @see my_syslog() for syslog wrapper with localization
 * 
 * EXAMPLE USAGE:
 * @code
 * // Log statistics on SIGUSR1 signal
 * blockdata_report();
 * // Output: "pool memory in use 4800, max 6000, allocated 7500"
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Writes log message to syslog at LOG_INFO priority
 * - No modification of global state (read-only operation)
 * 
 * THREAD SAFETY:
 * Thread-safe for reading. Can be called from signal handler context if
 * my_syslog() is async-signal-safe (implementation-dependent).
 */
void blockdata_report(void)
{
  my_syslog(LOG_INFO, _("pool memory in use %zu, max %zu, allocated %zu"), 
	    blockdata_count * sizeof(struct blockdata),  
	    blockdata_hwm * sizeof(struct blockdata),  
	    blockdata_alloced * sizeof(struct blockdata));
}

/**
 * @brief Internal function to allocate block chain from memory buffer or file descriptor
 * 
 * @detailed
 * Core allocation routine that creates a chain of blockdata structures to hold len
 * bytes of data. Data source is either a memory buffer (data != NULL) or a file
 * descriptor (fd used with data == NULL). Allocates blocks from freelist, expanding
 * by 50 blocks if freelist is empty. Each block holds up to KEYBLOCK_LEN bytes.
 * Forms singly-linked list via next pointers. On allocation failure (malloc or read
 * error), frees partial chain and returns NULL. Updates blockdata_count and
 * blockdata_hwm counters.
 * 
 * @param fd File descriptor to read from if data is NULL, ignored otherwise
 * @param data Pointer to source data buffer to copy from, or NULL to read from fd
 * @param len Number of bytes to store in the block chain
 * 
 * @return struct blockdata* Pointer to head of allocated block chain, or NULL on failure
 * @retval non-NULL Successfully allocated chain containing len bytes of data
 * @retval NULL Allocation failed (malloc failure or read error), no memory leaked
 * 
 * @note Automatically expands freelist by 50 blocks when empty. Partial chain freed
 *       on any failure to prevent memory leaks. High water mark updated if current
 *       count exceeds previous maximum.
 * 
 * @warning Returns NULL on failure without logging error details. Caller must handle
 *          NULL return. If data and fd are both invalid, behavior is undefined. On
 *          read error from fd, partial chain is freed but errno is preserved.
 * 
 * @see blockdata_alloc() public wrapper for memory buffer allocation
 * @see blockdata_read() public wrapper for file descriptor reading
 * @see blockdata_free() must be called to release returned chain
 * @see blockdata_expand() called if freelist exhausted
 * 
 * EXAMPLE USAGE:
 * @code
 * // Allocate from memory buffer
 * char key_data[256];
 * struct blockdata *chain = blockdata_alloc_real(0, key_data, 256);
 * if (chain) {
 *     // Use chain...
 *     blockdata_free(chain);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * N/A - Internal memory management function, not protocol-specific
 * 
 * SIDE EFFECTS:
 * - Removes blocks from keyblock_free (freelist consumption)
 * - Increments blockdata_count by number of allocated blocks
 * - Updates blockdata_hwm if new high water mark reached
 * - May call blockdata_expand() triggering heap allocation
 * - If data != NULL: Copies len bytes from data buffer using memcpy()
 * - If data == NULL: Reads len bytes from fd using read_write()
 * - On failure: Calls blockdata_free() on partial chain
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global freelist and counters without locking.
 * Must be called from main event loop thread only.
 */
static struct blockdata *blockdata_alloc_real(int fd, char *data, size_t len)
{
  struct blockdata *block, *ret = NULL;
  struct blockdata **prev = &ret;
  size_t blen;

  while (len > 0)
    {
      if (!keyblock_free)
	blockdata_expand(50);
      
      if (keyblock_free)
	{
	  block = keyblock_free;
	  keyblock_free = block->next;
	  blockdata_count++; 
	}
      else
	{
	  /* failed to alloc, free partial chain */
	  blockdata_free(ret);
	  return NULL;
	}
       
      if (blockdata_hwm < blockdata_count)
	blockdata_hwm = blockdata_count; 
      
      blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
      if (data)
	{
	  memcpy(block->key, data, blen);
	  data += blen;
	}
      else if (!read_write(fd, block->key, blen, 1))
	{
	  /* failed read free partial chain */
	  blockdata_free(ret);
	  return NULL;
	}
      len -= blen;
      *prev = block;
      prev = &block->next;
      block->next = NULL;
    }
  
  return ret;
}

/**
 * @brief Allocate block chain and copy data from memory buffer
 * 
 * @detailed
 * Public interface for allocating a block chain to store len bytes from a memory
 * buffer. Wrapper around blockdata_alloc_real() that specifies memory buffer as
 * data source. Creates linked list of blocks, each containing up to KEYBLOCK_LEN
 * bytes, totaling len bytes. Used primarily by DNSSEC code to store cryptographic
 * keys, signatures, and other variable-length DNSSEC resource record data.
 * 
 * @param data Pointer to source data buffer to copy from (must not be NULL)
 * @param len Number of bytes to copy from data buffer into block chain
 * 
 * @return struct blockdata* Pointer to head of block chain containing copied data, or NULL on failure
 * @retval non-NULL Successfully allocated and populated block chain
 * @retval NULL Memory allocation failed, no partial chain exists (cleaned up)
 * 
 * @note Caller owns returned block chain and must call blockdata_free() when done.
 *       Data is copied into blocks, so source buffer can be freed immediately after
 *       return. Typical usage stores DNSSEC RRSIG, DNSKEY, DS records.
 * 
 * @warning data parameter must point to valid memory of at least len bytes. Passing
 *          NULL or invalid pointer causes undefined behavior. Returns NULL on malloc
 *          failure - caller must handle NULL return to avoid dereferencing.
 * 
 * @see blockdata_alloc_real() internal implementation
 * @see blockdata_free() to release allocated chain
 * @see blockdata_retrieve() to extract data back from chain
 * @see blockdata_read() alternative that reads from file descriptor
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char dnskey_data[512];
 * size_t dnskey_len = 256;
 * // ... populate dnskey_data ...
 * struct blockdata *key_chain = blockdata_alloc(dnskey_data, dnskey_len);
 * if (key_chain) {
 *     cache_entry->keydata = key_chain; // Store in cache
 * } else {
 *     return 0; // Allocation failed
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * N/A - Memory management utility for DNSSEC data storage (RFCs 4033-4035)
 * 
 * SIDE EFFECTS:
 * - Allocates blocks from freelist (may trigger heap allocation)
 * - Copies len bytes from data buffer into newly allocated blocks
 * - Increments blockdata_count global counter
 * - May update blockdata_hwm if new high water mark
 * 
 * THREAD SAFETY:
 * Not thread-safe due to global freelist manipulation. Must be called from
 * main event loop thread only.
 */
struct blockdata *blockdata_alloc(char *data, size_t len)
{
  return blockdata_alloc_real(0, data, len);
}

/**
 * @brief Free block chain by returning all blocks to the freelist
 * 
 * @detailed
 * Returns an entire block chain to the global freelist (keyblock_free) for reuse.
 * Traverses the chain to count blocks, decrements blockdata_count accordingly, then
 * prepends the entire chain to the freelist by linking the last block's next pointer
 * to the current freelist head. This bulk free operation is more efficient than
 * freeing blocks individually. Handles NULL safely by doing nothing.
 * 
 * @param blocks Pointer to head of block chain to free, or NULL (safe to pass NULL)
 * 
 * @return void (no return value)
 * 
 * @note Does NOT call free() - blocks are returned to freelist pool for reuse, not
 *       released to OS. This pool management strategy reduces malloc/free overhead.
 *       NULL blocks parameter is safe and results in no-op. Chain must have been
 *       allocated by blockdata_alloc() or blockdata_read().
 * 
 * @warning After calling blockdata_free(), blocks pointer is invalid and must not be
 *          dereferenced. Chain must be properly formed (NULL-terminated) or traversal
 *          will read invalid memory. Does not check for double-free - caller
 *          responsible for not freeing same chain twice.
 * 
 * @see blockdata_alloc() allocates chains that must be freed with this function
 * @see blockdata_read() allocates chains that must be freed with this function
 * 
 * EXAMPLE USAGE:
 * @code
 * struct blockdata *chain = blockdata_alloc(data, 256);
 * // ... use chain ...
 * blockdata_free(chain);
 * chain = NULL; // Good practice: nullify pointer after free
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Prepends entire chain to keyblock_free (freelist)
 * - Decrements blockdata_count by number of blocks in chain
 * - Traverses chain to count blocks (O(n) operation)
 * - No heap deallocation (blocks retained in pool)
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies global freelist (keyblock_free) and blockdata_count
 * without locking. Must be called from main event loop thread only.
 */
void blockdata_free(struct blockdata *blocks)
{
  struct blockdata *tmp;
  
  if (blocks)
    {
      for (tmp = blocks; tmp->next; tmp = tmp->next)
	blockdata_count--;
      tmp->next = keyblock_free;
      keyblock_free = blocks; 
      blockdata_count--;
    }
}

/**
 * @brief Retrieve data from block chain into contiguous buffer
 * 
 * @detailed
 * Copies len bytes from a block chain into a contiguous memory buffer. If data is
 * NULL, allocates a static internal buffer of sufficient size and returns pointer
 * to it (useful for temporary access without caller-managed allocation). If data
 * is non-NULL, copies into caller-provided buffer. Traverses block chain, copying
 * up to KEYBLOCK_LEN bytes from each block until len bytes copied or chain ends.
 * Static buffer is reused across calls, growing as needed but never shrinking.
 * 
 * @param block Pointer to head of block chain containing data to retrieve
 * @param len Number of bytes to retrieve from block chain
 * @param data Destination buffer pointer, or NULL to use internal static buffer
 * 
 * @return void* Pointer to buffer containing retrieved data (static or caller-provided)
 * @retval non-NULL Pointer to buffer with data (static internal buffer if data was NULL)
 * @retval NULL Only if data was NULL and static buffer allocation failed (rare)
 * 
 * @note If data is NULL, returned pointer is to static storage that persists until
 *       next blockdata_retrieve(NULL, ...) call - caller must not free it. Static
 *       buffer grows but never shrinks. If len exceeds data in chain, only available
 *       bytes are copied (short read possible if chain shorter than len).
 * 
 * @warning Static buffer mode (data == NULL): Returned pointer is valid only until
 *          next call with data == NULL. Not thread-safe even for reads due to static
 *          buffer. If len > data available in chain, reads less than len bytes without
 *          error indication. Caller must ensure chain contains at least len bytes.
 * 
 * @see blockdata_alloc() creates chains that this function reads from
 * @see blockdata_read() alternative that reads chain directly from file
 * @see blockdata_write() inverse operation that writes chain to file
 * 
 * EXAMPLE USAGE:
 * @code
 * // Using static buffer (temporary access)
 * struct blockdata *chain = cache_entry->keydata;
 * unsigned char *key = blockdata_retrieve(chain, 256, NULL);
 * verify_signature(key, 256, ...); // Use immediately
 * 
 * // Using caller-provided buffer (persistent access)
 * unsigned char key_buffer[512];
 * blockdata_retrieve(chain, 256, key_buffer);
 * @endcode
 * 
 * SIDE EFFECTS:
 * - If data == NULL: May allocate/reallocate static buffer if len > previous max
 * - Reads from block chain (does not modify chain)
 * - Static buffer persists between calls (never freed until process exit)
 * 
 * THREAD SAFETY:
 * Not thread-safe. Uses static variables (buff, buff_len) without locking.
 * Multiple concurrent calls with data == NULL will corrupt static buffer.
 * Must be called from main event loop thread only.
 */
void *blockdata_retrieve(struct blockdata *block, size_t len, void *data)
{
  size_t blen;
  struct  blockdata *b;
  void *new, *d;
  
  static unsigned int buff_len = 0;
  static unsigned char *buff = NULL;
   
  if (!data)
    {
      if (len > buff_len)
	{
	  if (!(new = whine_malloc(len)))
	    return NULL;
	  if (buff)
	    free(buff);
	  buff = new;
	}
      data = buff;
    }
  
  for (d = data, b = block; len > 0 && b;  b = b->next)
    {
      blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
      memcpy(d, b->key, blen);
      d += blen;
      len -= blen;
    }

  return data;
}

/**
 * @brief Write data from block chain to file descriptor
 * 
 * @detailed
 * Writes len bytes from a block chain to a file descriptor. Traverses the block
 * chain, writing up to KEYBLOCK_LEN bytes from each block via read_write() utility
 * function until len bytes written or chain ends. Used for persisting DNSSEC data
 * to disk (e.g., lease files with DNSSEC state). Each block contributes min(len,
 * KEYBLOCK_LEN) bytes. Write errors are handled by read_write() which may log errors.
 * 
 * @param block Pointer to head of block chain containing data to write
 * @param len Number of bytes to write from block chain to file descriptor
 * @param fd File descriptor to write to (must be open for writing)
 * 
 * @return void (no return value, errors handled by read_write)
 * 
 * @note Writes up to len bytes - if chain shorter than len, writes only available
 *       data (short write possible). read_write() wrapper handles EINTR and partial
 *       writes. File descriptor must be open and writable. Typically used for lease
 *       file persistence or DNSSEC cache serialization.
 * 
 * @warning No return value to indicate write errors - errors logged by read_write().
 *          If len exceeds data in chain, writes less than len bytes without indication.
 *          fd must be valid open file descriptor. Does not close fd. Caller must
 *          ensure chain contains at least len bytes for complete write.
 * 
 * @see blockdata_read() inverse operation that reads from fd into chain
 * @see blockdata_retrieve() alternative that copies to memory buffer
 * @see read_write() utility in util.c handles actual I/O with error recovery
 * 
 * EXAMPLE USAGE:
 * @code
 * int fd = open("/var/lib/dnsmasq/dnssec.dat", O_WRONLY | O_CREAT, 0644);
 * if (fd >= 0) {
 *     blockdata_write(cache_entry->keydata, 256, fd);
 *     close(fd);
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Writes len bytes (or less if chain shorter) to file descriptor fd
 * - Advances file position in fd by number of bytes written
 * - May trigger disk I/O and block briefly (non-async operation)
 * - Errors logged by read_write() to syslog
 * 
 * THREAD SAFETY:
 * Safe to call concurrently with different file descriptors. Block chain should
 * not be modified during write operation. Single-threaded event loop ensures no
 * concurrent access to same chain.
 */
void blockdata_write(struct blockdata *block, size_t len, int fd)
{
  for (; len > 0 && block; block = block->next)
    {
      size_t blen = len > KEYBLOCK_LEN ? KEYBLOCK_LEN : len;
      read_write(fd, block->key, blen, 0);
      len -= blen;
    }
}

/**
 * @brief Read data from file descriptor into newly allocated block chain
 * 
 * @detailed
 * Allocates a block chain and populates it by reading len bytes from a file
 * descriptor. Wrapper around blockdata_alloc_real() that specifies file descriptor
 * as data source. Creates linked list of blocks containing up to KEYBLOCK_LEN bytes
 * each, reading data directly into blocks without intermediate buffering. Used for
 * loading persisted DNSSEC data from disk during cache restoration or lease file
 * reading. Returns NULL if allocation or read fails.
 * 
 * @param fd File descriptor to read from (must be open for reading)
 * @param len Number of bytes to read from file descriptor into block chain
 * 
 * @return struct blockdata* Pointer to head of newly allocated block chain containing read data, or NULL on failure
 * @retval non-NULL Successfully allocated chain and read len bytes from fd
 * @retval NULL Allocation failed or read error occurred, no partial chain exists
 * 
 * @note Caller owns returned chain and must call blockdata_free() when done. On read
 *       error, partial chain is automatically freed (no leak). read_write() utility
 *       handles EINTR and partial reads. File position advanced by len bytes on success.
 *       Typical usage: restore DNSSEC cache from disk at startup.
 * 
 * @warning Returns NULL on any failure (malloc or read error) without distinguishing
 *          cause. errno preserved from read_write() on read errors. fd must be valid
 *          and readable. Caller must check for NULL return. Does not close fd.
 * 
 * @see blockdata_alloc_real() internal implementation
 * @see blockdata_alloc() alternative that copies from memory buffer
 * @see blockdata_write() inverse operation that writes chain to fd
 * @see blockdata_free() to release allocated chain
 * @see read_write() utility in util.c handles actual I/O
 * 
 * EXAMPLE USAGE:
 * @code
 * int fd = open("/var/lib/dnsmasq/dnssec.dat", O_RDONLY);
 * if (fd >= 0) {
 *     struct blockdata *chain = blockdata_read(fd, 256);
 *     if (chain) {
 *         cache_entry->keydata = chain;
 *     }
 *     close(fd);
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Allocates blocks from freelist (may trigger heap allocation)
 * - Reads len bytes from file descriptor fd
 * - Advances file position in fd by len bytes on success
 * - Increments blockdata_count global counter
 * - May update blockdata_hwm if new high water mark
 * - On failure: Frees partial chain automatically
 * 
 * THREAD SAFETY:
 * Not thread-safe due to global freelist manipulation. Must be called from
 * main event loop thread only. File descriptor should not be accessed
 * concurrently from other threads.
 */
struct blockdata *blockdata_read(int fd, size_t len)
{
  return blockdata_alloc_real(fd, NULL, len);
}
