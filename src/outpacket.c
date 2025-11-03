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
 * @file outpacket.c
 * @brief DHCPv6 option assembly and packet construction utilities.
 *
 * DETAILED PURPOSE:
 * This file provides the core functionality for building DHCPv6 response packets
 * using the Type-Length-Value (TLV) option encoding format specified in RFC 3315.
 * Unlike DHCPv4 which uses a single-byte option code followed by length and value,
 * DHCPv6 uses 16-bit option codes and 16-bit lengths in network byte order (big-endian).
 * 
 * The outpacket buffer (daemon->outpacket.iov_base) serves as the working memory
 * for constructing DHCPv6 REPLY, ADVERTISE, and other message types. Functions here
 * manage sequential assembly of nested options (e.g., IA_NA containing IAADDR suboptions)
 * and automatic buffer expansion when needed. The counter-based design allows marking
 * positions for later length field updates when option content size is not known upfront.
 * 
 * This approach differs from DHCPv4's fixed-format packet construction and provides
 * the flexibility required for DHCPv6's variable-length, nested option structure including
 * Identity Associations (IA_NA, IA_TA, IA_PD), status codes, and vendor-specific options.
 *
 * KEY RESPONSIBILITIES:
 * - new_opt6() - Begin new DHCPv6 option with 16-bit code and reserve space for length
 * - end_opt6() - Finalize option by calculating and writing 16-bit length field
 * - put_opt6_char/short/long() - Append 8-bit, 16-bit, and 32-bit values in big-endian
 * - put_opt6() - Append arbitrary binary data to current option
 * - put_opt6_string() - Append null-terminated string (without null terminator)
 * - expand() - Dynamically grow outpacket buffer using expand_buf() when needed
 * - save_counter() - Save and restore buffer position for nested option construction
 * - reset_counter() - Initialize buffer for new packet construction
 *
 * DEPENDENCIES:
 * - Includes: dnsmasq.h (primary header with struct daemon definition)
 * - Requires: HAVE_DHCP6 compile-time option (entire file conditional)
 * - Uses: daemon->outpacket (struct iovec) for buffer management
 * - Uses: expand_buf() from util.c for dynamic buffer growth
 * - Uses: PUTSHORT, PUTLONG macros for network byte order encoding
 * - Called by: rfc3315.c (DHCPv6 message construction), dhcp6.c (address assignment)
 * - Calls: expand_buf() for buffer allocation, memcpy() and memset() for data operations
 *
 * DATA STRUCTURES:
 * - static size_t outpacket_counter - Current write position in outpacket buffer (line 22)
 * - daemon->outpacket (struct iovec) - Buffer for packet assembly (defined in dnsmasq.h)
 *   .iov_base points to allocated memory, .iov_len tracks current allocation size
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP6 - Must be defined for entire file to compile (lines 20-118)
 *   When undefined, DHCPv6 server functionality is disabled
 *   Affects: All functions in this file become unavailable
 *
 * THREADING/CONCURRENCY:
 * Single-process, event-driven architecture. The outpacket buffer is global state
 * accessed sequentially during DHCPv6 message construction. Each message is built
 * completely before transmission, so no concurrent access occurs. The static
 * outpacket_counter maintains position between function calls within a single
 * packet construction sequence. Not thread-safe, but dnsmasq's event loop model
 * ensures sequential execution.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"
 
#ifdef HAVE_DHCP6

static size_t outpacket_counter;

/**
 * @brief Finalize DHCPv6 option by calculating and writing its length field.
 *
 * @detailed Completes a DHCPv6 option started with new_opt6() by computing the
 * option's data length (excluding the 4-byte option header) and writing the
 * 16-bit length value in network byte order (big-endian) to the length field
 * position reserved during new_opt6(). The length is calculated as the difference
 * between the current buffer position and the container position, minus 4 bytes
 * for the option code (2 bytes) and length field itself (2 bytes). This function
 * must be called after all option data has been written with put_opt6_*() functions.
 *
 * @param container Position returned by new_opt6(), marking the start of this option's
 *        4-byte header in the outpacket buffer. The length field to update is at
 *        container+2. Valid range: 0 to (current buffer size - 4).
 *
 * @return void (no return value)
 *
 * @note The 16-bit length field does NOT include the 4-byte option header itself,
 *       only the option data that follows. This matches RFC 3315 Section 22.1
 *       option format: option-code (2 bytes) + option-len (2 bytes) + option-data.
 * @note For nested options (e.g., IAADDR inside IA_NA), call end_opt6() for inner
 *       options before calling end_opt6() for the outer container option.
 *
 * @warning Assumes container parameter points to a valid option header previously
 *          created by new_opt6(). Passing an incorrect position will corrupt the
 *          packet. No bounds checking performed for performance.
 *
 * @see new_opt6() to begin an option and obtain the container position
 * @see put_opt6() for writing option data between new_opt6() and end_opt6()
 *
 * EXAMPLE USAGE:
 * @code
 * int ia_na_pos = new_opt6(OPTION6_IA_NA);
 * put_opt6_long(iaid);  // IA_NA IAID (4 bytes)
 * put_opt6_long(t1);    // T1 renewal time
 * put_opt6_long(t2);    // T2 rebind time
 * // Add IAADDR suboption
 * int iaaddr_pos = new_opt6(OPTION6_IAADDR);
 * put_opt6(&lease_addr, 16);  // IPv6 address
 * put_opt6_long(preferred);
 * put_opt6_long(valid);
 * end_opt6(iaaddr_pos);  // Finalize IAADDR first
 * end_opt6(ia_na_pos);   // Then finalize IA_NA container
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 3315 Section 22.1 "Format of DHCP Options" - The option-len
 * field contains the length in octets of the option-data field, stored as
 * unsigned 16-bit integer in network byte order. The length does not include
 * the option-code and option-len fields.
 *
 * SIDE EFFECTS:
 * Modifies 2 bytes at daemon->outpacket.iov_base + container + 2 to store
 * the computed length value. Does not modify outpacket_counter.
 *
 * THREAD SAFETY:
 * Not thread-safe. Assumes sequential packet construction in single-threaded
 * event loop model. Accesses global daemon->outpacket and static outpacket_counter.
 */
void end_opt6(int container)
{
   void *p = daemon->outpacket.iov_base + container + 2;
   u16 len = outpacket_counter - container - 4 ;
   
   PUTSHORT(len, p);
}

/**
 * @brief Initialize outpacket buffer for new DHCPv6 message construction.
 *
 * @detailed Prepares the global outpacket buffer for building a new DHCPv6 message
 * by clearing any previous content and resetting the write position counter to zero.
 * If the buffer has been allocated (iov_base is non-NULL), the entire buffer is
 * zeroed using memset() to ensure no stale data from previous packets remains.
 * The outpacket_counter is then reset to 0 via save_counter(), positioning writes
 * at the start of the buffer. This function should be called before constructing
 * each new DHCPv6 reply message.
 *
 * @param None
 *
 * @return void (no return value)
 *
 * @note Buffer clearing is conditional on iov_base being non-NULL. On first use
 *       before any allocation, only the counter is reset and no memset() occurs.
 * @note The buffer size (iov_len) is preserved; only the content and write position
 *       are reset. If the buffer is too small for subsequent writes, expand() will
 *       grow it automatically.
 *
 * @warning Must be called before starting construction of each new DHCPv6 message.
 *          Failing to reset may result in corrupted packets with data from previous
 *          messages. However, if expand() reallocates the buffer, old data is lost.
 *
 * @see save_counter() for counter manipulation
 * @see expand() for buffer allocation and growth
 * @see new_opt6() typically called after reset_counter() to begin first option
 *
 * EXAMPLE USAGE:
 * @code
 * reset_counter();  // Clear buffer, start new message
 * // Build DHCPv6 message header (done by caller)
 * int opt_pos = new_opt6(OPTION6_SERVER_ID);
 * put_opt6(server_duid, duid_len);
 * end_opt6(opt_pos);
 * // Continue building message...
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supporting function for RFC 3315 message construction. Ensures clean buffer
 * state before assembling ADVERTISE, REPLY, or other DHCPv6 messages. While not
 * directly specified in RFC 3315, buffer initialization is essential for correct
 * packet formation.
 *
 * SIDE EFFECTS:
 * - Writes zeros to entire daemon->outpacket.iov_base buffer (if allocated)
 * - Resets static outpacket_counter to 0 via save_counter(0)
 * - Does not deallocate or reallocate buffer memory
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->outpacket buffer and static
 * outpacket_counter. Assumes sequential execution in dnsmasq's event loop.
 */
void reset_counter(void)
{
  /* Clear out buffer when starting from beginning */
  if (daemon->outpacket.iov_base)
    memset(daemon->outpacket.iov_base, 0, daemon->outpacket.iov_len);
 
  save_counter(0);
}

/**
 * @brief Save current buffer position and optionally set new position.
 *
 * @detailed Provides atomic save-and-optionally-set operation on the static
 * outpacket_counter, enabling both position retrieval and position restoration.
 * Always returns the counter's value BEFORE any modification. If newval is not -1,
 * the counter is updated to newval. If newval is -1, the counter is unchanged
 * (read-only operation). This function is critical for nested option construction
 * where the caller needs to save the current position, build inner options, then
 * restore the saved position or set a specific position for subsequent operations.
 *
 * @param newval New value for outpacket_counter. Special values:
 *        -1: Read-only mode, counter is not modified (just return current value)
 *        0: Reset counter to start of buffer (used by reset_counter())
 *        Other: Set counter to specific position (e.g., restoring saved position)
 *        Valid range when setting: 0 to daemon->outpacket.iov_len
 *
 * @return Previous value of outpacket_counter before any modification. Caller can
 *         use this to restore position later by calling save_counter(returned_value).
 *
 * @note The -1 special value for read-only access allows querying current position
 *       without side effects: current_pos = save_counter(-1);
 * @note Setting counter beyond allocated buffer size is permitted but will cause
 *       expand() to allocate more memory on next write operation.
 *
 * @warning No bounds checking is performed on newval. Setting counter to invalid
 *          position (e.g., beyond physical memory) will cause segfault on next
 *          buffer access. Caller must ensure validity.
 *
 * @see reset_counter() which uses save_counter(0) to reset position
 * @see expand() which advances counter after expanding buffer
 * @see end_opt6() which uses counter to calculate option lengths
 *
 * EXAMPLE USAGE:
 * @code
 * // Save position before nested option
 * int saved_pos = save_counter(-1);  // Read current position
 * // Build inner option at current position
 * int inner = new_opt6(OPTION6_STATUS_CODE);
 * put_opt6_short(DHCP6SUCCESS);
 * end_opt6(inner);
 * // Restore saved position if needed, or continue from current
 * // (In practice, usually just continue forward)
 * @endcode
 *
 * @code
 * // Reset to beginning
 * save_counter(0);  // Equivalent to setting outpacket_counter = 0
 * @endcode
 *
 * RFC COMPLIANCE:
 * Utility function supporting RFC 3315 nested option construction. While not
 * directly specified in RFC, position tracking is necessary for correct TLV
 * encoding where option lengths must be calculated after content is written.
 *
 * SIDE EFFECTS:
 * Modifies static outpacket_counter if newval != -1. No other side effects.
 * Does not access daemon->outpacket buffer.
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies static outpacket_counter without locking.
 * Assumes sequential execution in single-threaded event loop.
 */
int save_counter(int newval)
{
  int ret = outpacket_counter;
  
  if (newval != -1)
    outpacket_counter = newval;

  return ret;
}

/**
 * @brief Expand outpacket buffer if needed and return pointer for writing.
 *
 * @detailed Ensures the outpacket buffer has sufficient space for writing headroom
 * additional bytes at the current counter position, automatically growing the buffer
 * via expand_buf() if necessary. On success, returns a pointer to the current write
 * position (daemon->outpacket.iov_base + outpacket_counter) and advances the counter
 * by headroom bytes, reserving that space for the caller. On failure (memory allocation
 * error), returns NULL without modifying the counter. This function is the core
 * mechanism for dynamic packet buffer growth, eliminating need for pre-calculated
 * maximum packet sizes.
 *
 * @param headroom Number of bytes to reserve starting at current counter position.
 *        Must be greater than 0 for meaningful operation. Common values: 1 (char),
 *        2 (short), 4 (long/int), 16 (IPv6 address), variable (string/data length).
 *        Maximum: Limited only by available system memory.
 *
 * @return Pointer to reserved space at daemon->outpacket.iov_base + outpacket_counter
 *         (before counter advance) on success, allowing caller to write headroom bytes.
 *         Returns NULL if expand_buf() fails due to memory allocation error.
 *
 * @note expand_buf() intelligently grows the buffer only when needed. If current
 *       iov_len is already sufficient for outpacket_counter + headroom, no
 *       reallocation occurs and the existing buffer pointer is used.
 * @note After successful return, caller MUST write exactly headroom bytes to the
 *       returned pointer to maintain packet integrity. Writing less leaves garbage,
 *       writing more causes buffer overflow.
 * @note Counter is advanced BEFORE returning, so outpacket_counter points past
 *       the reserved space after this function returns.
 *
 * @warning If expand_buf() reallocates the buffer (grows memory), any previously
 *          obtained pointers into the old buffer become INVALID. Callers must not
 *          cache pointers across expand() calls for different options.
 * @warning NULL return indicates memory exhaustion. Caller must check return value
 *          and handle failure (typically by aborting message construction).
 *
 * @see expand_buf() in util.c for buffer allocation/reallocation implementation
 * @see new_opt6() which uses expand(4) for option header
 * @see put_opt6_long() which uses expand(4) for 32-bit value
 * @see put_opt6_short() which uses expand(2) for 16-bit value
 * @see put_opt6_char() which uses expand(1) for 8-bit value
 *
 * EXAMPLE USAGE:
 * @code
 * void *p = expand(16);  // Reserve 16 bytes for IPv6 address
 * if (p) {
 *   memcpy(p, &ipv6_addr, 16);  // Write address to reserved space
 * } else {
 *   // Handle allocation failure
 *   return 0;
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supporting function for RFC 3315 variable-length option encoding. DHCPv6 options
 * can be arbitrary length (up to 65535 bytes per option), requiring dynamic buffer
 * management. This function enables unlimited option nesting and data sizes.
 *
 * SIDE EFFECTS:
 * - May reallocate daemon->outpacket.iov_base via expand_buf() (invalidates old pointers)
 * - Updates daemon->outpacket.iov_len if buffer grows
 * - Advances outpacket_counter by headroom on success
 * - No effect on counter if expand_buf() fails
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->outpacket and static outpacket_counter.
 * Assumes sequential execution without concurrent buffer access.
 */
void *expand(size_t headroom)
{
  void *ret;

  if (expand_buf(&daemon->outpacket, outpacket_counter + headroom))
    {
      ret = daemon->outpacket.iov_base + outpacket_counter;
      outpacket_counter += headroom;
      return ret;
    }
  
  return NULL;
}
    
/**
 * @brief Begin a new DHCPv6 option with 16-bit option code and length placeholder.
 *
 * @detailed Starts construction of a DHCPv6 option by writing the 4-byte option header
 * consisting of a 16-bit option code followed by a 16-bit length field (initially zero)
 * in network byte order (big-endian). Returns the buffer position of this header so
 * end_opt6() can later calculate and update the length field. After calling new_opt6(),
 * use put_opt6_*() functions to append option data, then call end_opt6(returned_position)
 * to finalize. The PUTSHORT macro handles conversion to network byte order.
 *
 * @param opt DHCPv6 option code (16-bit unsigned). Standard option codes defined in
 *        dhcp6-protocol.h include OPTION6_CLIENT_ID (1), OPTION6_SERVER_ID (2),
 *        OPTION6_IA_NA (3), OPTION6_IA_TA (4), OPTION6_IAADDR (5), OPTION6_ORO (6),
 *        OPTION6_STATUS_CODE (13), OPTION6_DNS_SERVER (23), and others per RFC 3315.
 *        Valid range: 0-65535, though values 0 and 65535 are typically reserved.
 *
 * @return Position (offset) in outpacket buffer where this option's header begins.
 *         This value must be passed to end_opt6() to finalize the option. Returns the
 *         position BEFORE expand(4), so return value marks the option-code field start.
 *         Returns current counter value even if expand() fails, but option is incomplete.
 *
 * @note The initial length field is set to 0 and must be updated by end_opt6() after
 *       all option data is written. Length does not include the 4-byte header itself.
 * @note For nested options (e.g., OPTION6_IAADDR inside OPTION6_IA_NA), call new_opt6()
 *       for the inner option after partially filling the outer option, then end_opt6()
 *       the inner option before finalizing the outer option.
 *
 * @warning If expand(4) fails (returns NULL), the option header is not written and
 *          the buffer is in inconsistent state. Caller should check if subsequent
 *          put_opt6_*() calls succeed. However, typical usage pattern assumes success.
 * @warning Caller MUST call end_opt6(returned_value) to finalize the option. Forgetting
 *          this leaves the length field at zero, creating invalid DHCPv6 packet.
 *
 * @see end_opt6() to finalize the option by writing correct length
 * @see put_opt6() to append arbitrary data to option
 * @see put_opt6_long() to append 32-bit value
 * @see put_opt6_short() to append 16-bit value
 *
 * EXAMPLE USAGE:
 * @code
 * // Create IA_NA option with IAID and timers
 * int ia_pos = new_opt6(OPTION6_IA_NA);
 * put_opt6_long(0x12345678);  // IAID
 * put_opt6_long(3600);        // T1
 * put_opt6_long(7200);        // T2
 * // Nested IAADDR suboption
 * int addr_pos = new_opt6(OPTION6_IAADDR);
 * put_opt6(&ipv6_address, 16);
 * put_opt6_long(7200);   // Preferred lifetime
 * put_opt6_long(14400);  // Valid lifetime
 * end_opt6(addr_pos);
 * end_opt6(ia_pos);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 3315 Section 22.1 "Format of DHCP Options":
 * - option-code: 16-bit identifier of the option type (0-65535)
 * - option-len: 16-bit unsigned integer giving length of option-data in octets
 * - option-data: Option payload (added by put_opt6_*() functions)
 * Both option-code and option-len are in network byte order (big-endian).
 *
 * SIDE EFFECTS:
 * - Calls expand(4) which may reallocate daemon->outpacket.iov_base
 * - Writes 4 bytes to buffer: 2-byte option code + 2-byte length (initially 0)
 * - Advances outpacket_counter by 4 bytes via expand()
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->outpacket and advances outpacket_counter
 * via expand(). Assumes sequential execution in dnsmasq event loop.
 */
int new_opt6(int opt)
{
  int ret = outpacket_counter;
  void *p;

  if ((p = expand(4)))
    {
      PUTSHORT(opt, p);
      PUTSHORT(0, p);
    }

  return ret;
}

/**
 * @brief Append arbitrary binary data to current DHCPv6 option.
 *
 * @detailed Writes len bytes of binary data from the data pointer into the outpacket
 * buffer at the current counter position, expanding the buffer if necessary. This is
 * the general-purpose function for appending option data of any type: IPv6 addresses
 * (16 bytes), DUIDs (variable length), domain names (DNS encoding), or any other
 * binary payloads required by DHCPv6 options. The data is copied as-is without byte
 * order conversion, so caller must ensure multi-byte values are in network byte order
 * if required. Returns pointer to the written data in the buffer.
 *
 * @param data Pointer to binary data to copy into option. If NULL, space is reserved
 *        via expand(len) but no memcpy() occurs, leaving the reserved space uninitialized
 *        (potentially garbage). Typically non-NULL; NULL is used when caller will fill
 *        the space directly using the returned pointer.
 * @param len Number of bytes to copy from data pointer. Must match actual data size.
 *        Common values: 16 (IPv6 address), 4 (32-bit value), 2 (16-bit value), or
 *        variable for strings and DUIDs. Zero length is valid (reserves no space).
 *
 * @return Pointer to the written data in daemon->outpacket.iov_base buffer on success.
 *         Returns NULL if expand(len) fails due to memory allocation error. If data
 *         parameter is NULL, returns pointer to uninitialized reserved space (or NULL
 *         on expand failure).
 *
 * @note For multi-byte numeric values, consider put_opt6_short() or put_opt6_long()
 *       which handle network byte order conversion automatically. Use put_opt6() for
 *       binary data that doesn't need byte swapping (addresses, strings, DUIDs).
 * @note If data is NULL, caller can use returned pointer to write data manually:
 *       void *p = put_opt6(NULL, 16); if (p) memcpy(p, &addr, 16);
 *
 * @warning If data is NULL, reserved space contains undefined content (garbage).
 *          Caller MUST initialize it to avoid sending uninitialized memory in packets.
 * @warning No bounds checking on data pointer. If data points to less than len bytes
 *          of valid memory, memcpy() will read past buffer end (undefined behavior).
 *
 * @see put_opt6_long() for 32-bit values with automatic byte order conversion
 * @see put_opt6_short() for 16-bit values with automatic byte order conversion
 * @see put_opt6_string() for null-terminated strings (convenience wrapper)
 * @see expand() for buffer expansion mechanism
 *
 * EXAMPLE USAGE:
 * @code
 * // Write IPv6 address (16 bytes, no byte swapping needed)
 * struct in6_addr addr = { ... };
 * put_opt6(&addr, sizeof(addr));
 * @endcode
 *
 * @code
 * // Write DUID (variable length)
 * unsigned char duid[] = { 0x00, 0x01, 0x00, 0x01, ... };
 * put_opt6(duid, sizeof(duid));
 * @endcode
 *
 * @code
 * // Reserve space and fill manually
 * void *p = put_opt6(NULL, 16);
 * if (p) {
 *   inet_pton(AF_INET6, "2001:db8::1", p);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Generic function supporting all RFC 3315 option data formats. Used for option
 * payloads that don't require endianness conversion, including IPv6 addresses
 * (Section 22.6 - OPTION_IAADDR), DUIDs (Section 9), and vendor-specific data.
 *
 * SIDE EFFECTS:
 * - Calls expand(len) which may reallocate daemon->outpacket.iov_base
 * - Copies len bytes from data to buffer via memcpy() (if data is non-NULL)
 * - Advances outpacket_counter by len via expand()
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->outpacket buffer and advances counter.
 * Assumes sequential execution without concurrent access.
 */
void *put_opt6(void *data, size_t len)
{
  void *p;

  if ((p = expand(len)) && data)
    memcpy(p, data, len);   
  
  return p;
}
  
/**
 * @brief Append 32-bit unsigned integer to DHCPv6 option in network byte order.
 *
 * @detailed Writes a 4-byte (32-bit) unsigned integer value to the outpacket buffer
 * at the current counter position, automatically converting from host byte order to
 * network byte order (big-endian) using the PUTLONG macro. This function is used for
 * DHCPv6 option fields that require 32-bit values such as IAID (Identity Association
 * Identifier), T1 renewal time, T2 rebinding time, preferred lifetime, valid lifetime,
 * and various numeric option parameters. Expands the buffer by 4 bytes if needed.
 *
 * @param val 32-bit unsigned integer value in host byte order. Will be converted to
 *        big-endian (network byte order) before writing. Common values include:
 *        - IAID: Unique 32-bit identifier for IA_NA/IA_TA (typically derived from MAC)
 *        - T1: Time until client should renew (seconds, typically 1/2 of valid lifetime)
 *        - T2: Time until client should rebind (seconds, typically 4/5 of valid lifetime)
 *        - Lifetimes: preferred-lifetime and valid-lifetime in seconds (0 = infinite)
 *        Valid range: 0x00000000 to 0xFFFFFFFF
 *
 * @return void (no return value, unlike put_opt6() which returns pointer)
 *
 * @note If expand(4) fails, PUTLONG is not called and no data is written. The buffer
 *       remains in potentially inconsistent state. Typical usage assumes success.
 * @note PUTLONG macro advances the pointer p internally, so the pointer is not usable
 *       after this call (which is why function returns void, not the advanced pointer).
 *
 * @warning Silent failure if expand(4) returns NULL (memory allocation error). No
 *          error indication to caller. In practice, dnsmasq terminates on allocation
 *          failures, so this is acceptable.
 *
 * @see put_opt6_short() for 16-bit values
 * @see put_opt6_char() for 8-bit values
 * @see put_opt6() for arbitrary length binary data without byte order conversion
 * @see expand() for buffer expansion mechanism
 *
 * EXAMPLE USAGE:
 * @code
 * // Build IA_NA option with IAID and timers
 * int pos = new_opt6(OPTION6_IA_NA);
 * put_opt6_long(0x11223344);  // IAID (4 bytes)
 * put_opt6_long(3600);        // T1 renewal time (1 hour)
 * put_opt6_long(5400);        // T2 rebind time (1.5 hours)
 * end_opt6(pos);
 * @endcode
 *
 * @code
 * // Write IAADDR lifetimes
 * int addr_pos = new_opt6(OPTION6_IAADDR);
 * put_opt6(&ipv6_addr, 16);   // IPv6 address
 * put_opt6_long(7200);        // Preferred lifetime (2 hours)
 * put_opt6_long(86400);       // Valid lifetime (24 hours)
 * end_opt6(addr_pos);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements 32-bit field encoding for RFC 3315 options including:
 * - Section 22.4 OPTION_IA_NA: IAID (4 octets), T1 (4 octets), T2 (4 octets)
 * - Section 22.5 OPTION_IA_TA: IAID (4 octets)
 * - Section 22.6 OPTION_IAADDR: preferred-lifetime (4 octets), valid-lifetime (4 octets)
 * All 32-bit fields must be in network byte order per RFC 3315 Section 5.2.
 *
 * SIDE EFFECTS:
 * - Calls expand(4) which may reallocate daemon->outpacket.iov_base
 * - Writes 4 bytes to buffer in big-endian byte order
 * - Advances outpacket_counter by 4 via expand()
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->outpacket buffer via expand().
 * Assumes sequential execution in single-threaded event loop.
 */
void put_opt6_long(unsigned int val)
{
  void *p;
  
  if ((p = expand(4)))  
    PUTLONG(val, p);
}

/**
 * @brief Append 16-bit unsigned integer to DHCPv6 option in network byte order.
 *
 * @detailed Writes a 2-byte (16-bit) unsigned integer value to the outpacket buffer
 * at the current counter position, automatically converting from host byte order to
 * network byte order (big-endian) using the PUTSHORT macro. This function is used for
 * DHCPv6 option fields requiring 16-bit values such as status codes, preference values,
 * elapsed time, option request list entries, and various protocol enumerations defined
 * in RFC 3315. Expands the buffer by 2 bytes if needed.
 *
 * @param val 16-bit unsigned integer value in host byte order. Will be converted to
 *        big-endian (network byte order) before writing. Common values include:
 *        - Status codes: DHCP6SUCCESS (0), DHCP6UNSPEC (1), DHCP6NOADDRS (2), etc.
 *        - Preference: 0-255 for server preference (Section 22.8)
 *        - Elapsed time: 0-65535 centiseconds (Section 22.9)
 *        - Requested options: Option codes in Option Request Option (Section 22.7)
 *        Valid range: 0x0000 to 0xFFFF (though parameter is unsigned int, only lower
 *        16 bits are used; upper bits are ignored by PUTSHORT).
 *
 * @return void (no return value)
 *
 * @note If expand(2) fails, PUTSHORT is not called and no data is written. Silent
 *       failure with no error indication (consistent with other put_opt6_* functions).
 * @note PUTSHORT macro advances pointer p internally, consuming it.
 * @note Upper 16 bits of val parameter are ignored by PUTSHORT; only lower 16 bits
 *       written. Caller should ensure val fits in 16 bits (0-65535).
 *
 * @warning Silent failure if expand(2) returns NULL. In practice, dnsmasq's memory
 *          allocation failures are fatal, so this is acceptable.
 * @warning If val > 65535, value will be truncated to lower 16 bits (modulo 65536).
 *
 * @see put_opt6_long() for 32-bit values
 * @see put_opt6_char() for 8-bit values
 * @see put_opt6() for arbitrary binary data
 * @see new_opt6() which uses PUTSHORT to write option code and initial length
 *
 * EXAMPLE USAGE:
 * @code
 * // Write status code option
 * int status_pos = new_opt6(OPTION6_STATUS_CODE);
 * put_opt6_short(DHCP6SUCCESS);  // Status code (2 bytes)
 * put_opt6_string("Success");     // Optional status message
 * end_opt6(status_pos);
 * @endcode
 *
 * @code
 * // Write preference option
 * int pref_pos = new_opt6(OPTION6_PREFERENCE);
 * put_opt6_short(255);  // Maximum preference
 * end_opt6(pref_pos);
 * @endcode
 *
 * @code
 * // Write elapsed time (e.g., 123 centiseconds = 1.23 seconds)
 * int elapsed_pos = new_opt6(OPTION6_ELAPSED_TIME);
 * put_opt6_short(123);
 * end_opt6(elapsed_pos);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements 16-bit field encoding for multiple RFC 3315 options:
 * - Section 22.3 OPTION_STATUS_CODE: status-code (2 octets unsigned integer)
 * - Section 22.8 OPTION_PREFERENCE: pref-value (1 octet, but typically encoded as 2)
 * - Section 22.9 OPTION_ELAPSED_TIME: elapsed-time (2 octets, 1/100 sec units)
 * - Section 22.7 OPTION_ORO: requested-option-code (2 octets per entry)
 * All 16-bit fields must be in network byte order per RFC 3315 Section 5.2.
 *
 * SIDE EFFECTS:
 * - Calls expand(2) which may reallocate daemon->outpacket.iov_base
 * - Writes 2 bytes to buffer in big-endian byte order
 * - Advances outpacket_counter by 2 via expand()
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->outpacket buffer via expand().
 * Assumes sequential execution in single-threaded event loop model.
 */
void put_opt6_short(unsigned int val)
{
  void *p;

  if ((p = expand(2)))
    PUTSHORT(val, p);   
}

/**
 * @brief Append 8-bit unsigned integer (single byte) to DHCPv6 option.
 *
 * @detailed Writes a single byte (8-bit) unsigned integer value to the outpacket buffer
 * at the current counter position. No byte order conversion is needed for single-byte
 * values. This function is used for DHCPv6 option fields requiring 8-bit values such as
 * preference values (when encoded as single byte rather than 16-bit), message type codes
 * in some contexts, flags, and single-byte enumeration values. Expands the buffer by 1
 * byte if needed. This is the most basic data writing function, simply storing one byte.
 *
 * @param val 8-bit unsigned integer value (0-255). Upper 24 bits of the unsigned int
 *        parameter are ignored; only the lowest 8 bits are written to the buffer.
 *        Common values include:
 *        - Preference: 0-255 for server preference (OPTION_PREFERENCE, RFC 3315 Sec 22.8)
 *        - Flags: Single-bit flags packed into one byte
 *        - Enumeration values: Small enum constants
 *        Valid range: 0x00 to 0xFF (0-255 decimal)
 *
 * @return void (no return value)
 *
 * @note Single-byte values don't require byte order conversion (endianness doesn't apply).
 * @note If expand(1) fails, assignment *p = val doesn't occur and no data is written.
 *       Silent failure consistent with other put_opt6_* functions.
 * @note If val > 255, only the lowest 8 bits are stored (val & 0xFF). Upper bits
 *       discarded without warning.
 *
 * @warning If val exceeds 255, truncation occurs silently (modulo 256).
 * @warning Silent failure if expand(1) returns NULL (memory allocation failure).
 *
 * @see put_opt6_short() for 16-bit values requiring byte order conversion
 * @see put_opt6_long() for 32-bit values requiring byte order conversion
 * @see put_opt6() for multi-byte binary data
 *
 * EXAMPLE USAGE:
 * @code
 * // Write preference value (OPTION_PREFERENCE expects 1 byte per RFC 3315)
 * int pref_pos = new_opt6(OPTION6_PREFERENCE);
 * put_opt6_char(200);  // Preference value 200 (high preference)
 * end_opt6(pref_pos);
 * @endcode
 *
 * @code
 * // Write single-byte flag field (hypothetical custom option)
 * int custom_pos = new_opt6(CUSTOM_OPTION);
 * put_opt6_char(0x01);  // Flag bit 0 set
 * end_opt6(custom_pos);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements 8-bit field encoding for RFC 3315 options. Primary use case is
 * OPTION_PREFERENCE (Section 22.8) where pref-value is defined as 1 octet
 * unsigned integer (though some implementations may use 2 bytes via put_opt6_short()).
 * Single-byte fields are less common in DHCPv6 than in DHCPv4, but this function
 * provides completeness for all possible data widths.
 *
 * SIDE EFFECTS:
 * - Calls expand(1) which may reallocate daemon->outpacket.iov_base
 * - Writes 1 byte to buffer (no byte order conversion needed)
 * - Advances outpacket_counter by 1 via expand()
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->outpacket buffer via expand().
 * Assumes sequential execution in single-threaded event loop.
 */
void put_opt6_char(unsigned int val)
{
  unsigned char *p;

  if ((p = expand(1)))
    *p = val;   
}

/**
 * @brief Append null-terminated string to DHCPv6 option without null terminator.
 *
 * @detailed Convenience wrapper around put_opt6() for writing null-terminated C strings
 * to DHCPv6 options. Calculates the string length using strlen() and copies only the
 * string content (excluding the null terminator) to the buffer. DHCPv6 option strings
 * are typically NOT null-terminated on the wire (length is explicit via option-len field),
 * matching network protocol conventions. Used for text fields like status messages in
 * STATUS_CODE options, domain names, and other string data.
 *
 * @param s Pointer to null-terminated C string to append. Must not be NULL (strlen(NULL)
 *        is undefined behavior). String is copied up to but NOT including the '\0' null
 *        terminator. Empty string (s[0] == '\0') results in zero-length write (valid).
 *        Common values:
 *        - Status messages: "Success", "No addresses available", etc.
 *        - Domain names: "example.com" (though DNS encoding may be required instead)
 *        - Server names: "dhcp-server-1"
 *        Maximum practical length: 65535 bytes (limited by DHCPv6 option-len field)
 *
 * @return void (no return value, unlike put_opt6() which returns pointer)
 *
 * @note The null terminator '\0' is NOT copied to the buffer. DHCPv6 uses explicit
 *       length fields, so null terminators are redundant and excluded per protocol.
 * @note For empty strings (strlen(s) == 0), this is equivalent to put_opt6(s, 0)
 *       which reserves no space and performs no memcpy().
 * @note For domain names requiring DNS wire format (length-prefixed labels), this
 *       function is insufficient. Use custom encoding with put_opt6() instead.
 *
 * @warning s must not be NULL. Passing NULL causes strlen(NULL) undefined behavior
 *          (likely segmentation fault). No NULL check performed for efficiency.
 * @warning String length is calculated using strlen(), which scans for '\0'. For very
 *          long strings, this may be inefficient. If length is known, prefer put_opt6()
 *          directly to avoid redundant strlen() call.
 *
 * @see put_opt6() for arbitrary binary data (this function wraps put_opt6)
 * @see strlen() for length calculation
 *
 * EXAMPLE USAGE:
 * @code
 * // Write status code with message
 * int status_pos = new_opt6(OPTION6_STATUS_CODE);
 * put_opt6_short(DHCP6NOADDRS);  // Status code 2
 * put_opt6_string("No addresses available in pool");
 * end_opt6(status_pos);
 * @endcode
 *
 * @code
 * // Write empty status message (just code, no text)
 * int status_pos = new_opt6(OPTION6_STATUS_CODE);
 * put_opt6_short(DHCP6SUCCESS);
 * put_opt6_string("");  // Zero-length string (strlen returns 0)
 * end_opt6(status_pos);
 * @endcode
 *
 * @code
 * // Write server identifier string (hypothetical text-based use case)
 * int custom_pos = new_opt6(CUSTOM_SERVER_NAME_OPTION);
 * put_opt6_string("dhcp-server.example.com");
 * end_opt6(custom_pos);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 3315 Section 22.3 OPTION_STATUS_CODE where status-message is
 * defined as UTF-8 encoded text without null termination (length determined by
 * option-len field). Also applicable to any DHCPv6 option containing human-readable
 * text strings. Note that domain names in options like OPTION_DOMAIN_SEARCH typically
 * require DNS wire format encoding (RFC 1035 compressed names), not plain strings.
 *
 * SIDE EFFECTS:
 * - Calls put_opt6(s, strlen(s)) which in turn calls expand() potentially reallocating
 *   daemon->outpacket.iov_base
 * - Copies strlen(s) bytes to buffer (null terminator excluded)
 * - Advances outpacket_counter by strlen(s) via expand()
 *
 * THREAD SAFETY:
 * Not thread-safe. Calls put_opt6() which modifies global daemon->outpacket buffer.
 * Assumes sequential execution in single-threaded event loop model.
 */
void put_opt6_string(char *s)
{
  put_opt6(s, strlen(s));
}

#endif
