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
 * @file poll.c
 * @brief Poll-based event loop wrapper for socket and timer multiplexing
 *
 * DETAILED PURPOSE:
 * This file provides a thin abstraction layer over the poll(2) system call,
 * offering portable event multiplexing capabilities for dnsmasq's single-process
 * event-driven architecture. It manages a dynamically-sized array of pollfd
 * structures, maintaining them in sorted order by file descriptor for efficient
 * binary search operations. The implementation calculates appropriate timeouts
 * for timer expiry events (lease expiry, cache TTL countdown, query retry timing,
 * and periodic maintenance tasks) and returns ready file descriptors to the main
 * event loop.
 *
 * This wrapper abstracts platform differences while leveraging poll(2)'s superior
 * scalability compared to select(2) for handling many simultaneous file descriptors.
 * All major platforms (Linux, BSD variants, Solaris) provide robust poll(2)
 * implementations. The design supports dnsmasq's single-threaded cooperative
 * multitasking model where the event loop processes all I/O operations sequentially.
 *
 * KEY RESPONSIBILITIES:
 * - poll_reset() - Initialize poll context for new event loop iteration
 * - poll_listen() - Register file descriptor with event mask for monitoring
 * - do_poll() - Execute poll(2) system call with calculated timeout
 * - poll_check() - Query whether specific file descriptor is ready
 * - fd_search() - Perform binary search to locate pollfd entries efficiently
 *
 * DEPENDENCIES:
 * - Called exclusively by dnsmasq.c event_loop() function
 * - Includes: dnsmasq.h for type definitions and system headers
 * - Uses: poll(2) POSIX system call (via <poll.h>)
 * - Memory: whine_malloc() for dynamic array allocation with error reporting
 *
 * DATA STRUCTURES:
 * - pollfds (line 42) - Dynamic array of struct pollfd sorted by fd
 * - nfds (line 43) - Current number of active pollfd entries
 * - arrsize (line 43) - Allocated array capacity (grows geometrically)
 *
 * COMPILE-TIME OPTIONS:
 * - No conditional compilation - universal poll(2) support assumed
 * - Platform detection handled by dnsmasq.h system includes
 *
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. All functions assume single-threaded
 * access with no locking required. The poll(2) call blocks until events occur or
 * timeout expires, enabling cooperative multitasking. Not thread-safe - must only
 * be called from main event loop thread.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/ARCHITECTURE.md for event-driven architecture explanation
 */

#include "dnsmasq.h"

/* Wrapper for poll(). Allocates and extends array of struct pollfds,
   keeps them in fd order so that we can set and test conditions on
   fd using a simple but efficient binary chop. */

/* poll_reset()
   poll_listen(fd, event)
   .
   .
   poll_listen(fd, event);

   hits = do_poll(timeout);

   if (poll_check(fd, event)
    .
    .

   if (poll_check(fd, event)
    .
    .

    event is OR of POLLIN, POLLOUT, POLLERR, etc
*/

static struct pollfd *pollfds = NULL;
static nfds_t nfds, arrsize = 0;

/**
 * @brief Perform binary search to locate file descriptor in sorted pollfd array
 *
 * @detailed
 * Executes an efficient binary search algorithm to locate a file descriptor within
 * the sorted pollfds array. If an exact match is found, returns the index of that
 * pollfd entry. If no match exists, returns the insertion point where a new entry
 * for this fd should be inserted to maintain sorted order. This dual-purpose return
 * value enables both lookup and insertion operations using a single search pass.
 * The array is maintained in ascending fd order to guarantee O(log n) search complexity.
 *
 * @param fd File descriptor to search for in the pollfds array
 * 
 * @return Index of matching pollfd entry if found, or insertion point for new entry.
 *         If return value equals nfds, fd should be appended to end of array.
 *         If pollfds[return_value].fd == fd, exact match found at that index.
 *         Otherwise, new entry should be inserted at return_value position.
 *
 * @retval 0 If array is empty (nfds == 0) or fd should be inserted at beginning
 * @retval nfds If fd is larger than all existing entries (insert at end)
 *
 * @note Time complexity is O(log n) for n file descriptors. Search converges
 *       when left and right pointers differ by exactly one position.
 *
 * @warning Assumes pollfds array is maintained in strict ascending fd order.
 *          Breaks sorting invariant will cause incorrect search results.
 *
 * @see poll_listen() uses this function to locate insertion point for new fds
 * @see poll_check() uses this function to locate fd for event readiness testing
 *
 * EXAMPLE USAGE:
 * @code
 * nfds_t idx = fd_search(listen_fd);
 * if (idx < nfds && pollfds[idx].fd == listen_fd) {
 *   // Found existing entry
 *   pollfds[idx].events |= POLLIN;
 * } else {
 *   // Insert new entry at position idx
 * }
 * @endcode
 *
 * ALGORITHM DETAILS:
 * Uses classic binary search with mid = (left + right) / 2 splitting strategy.
 * Terminates when search space narrows to single position (right == left + 1).
 * Returns left if pollfds[left].fd >= fd, otherwise returns right for insertion.
 *
 * SIDE EFFECTS: None - read-only operation
 *
 * THREAD SAFETY: Not thread-safe. Reads shared pollfds array without locking.
 *                Safe only in single-threaded event loop context.
 */
static nfds_t fd_search(int fd)
{
  nfds_t left, right, mid;
  
  if ((right = nfds) == 0)
    return 0;
  
  left = 0;
  
  while (1)
    {
      if (right == left + 1)
	return (pollfds[left].fd >= fd) ? left : right;
      
      mid = (left + right)/2;
      
      if (pollfds[mid].fd > fd)
	right = mid;
      else 
	left = mid;
    }
}

/**
 * @brief Reset poll context for new event loop iteration
 *
 * @detailed
 * Clears the active file descriptor count to reset the poll context for a new
 * event loop iteration. This function must be called at the start of each pass
 * through the main event loop before registering file descriptors with poll_listen().
 * The pollfds array memory remains allocated for reuse, only the active entry
 * count (nfds) is reset to zero. This approach avoids repeated malloc/free cycles
 * and maintains the allocated array capacity for subsequent iterations.
 *
 * @return void
 *
 * @note Does not deallocate pollfds array memory - reuses allocation across iterations.
 *       Array capacity (arrsize) remains unchanged for performance optimization.
 *
 * @warning Must be called before poll_listen() in each event loop iteration.
 *          Failure to reset will accumulate stale fd registrations from prior iterations.
 *
 * @see dnsmasq.c event_loop() calls this at the start of each iteration
 * @see poll_listen() registers fds after poll_reset() clears active count
 *
 * EXAMPLE USAGE:
 * @code
 * while (1) {
 *   poll_reset();
 *   poll_listen(dns_fd, POLLIN);
 *   poll_listen(dhcp_fd, POLLIN);
 *   int ready = do_poll(timeout);
 *   if (ready > 0) {
 *     if (poll_check(dns_fd, POLLIN)) handle_dns();
 *   }
 * }
 * @endcode
 *
 * MEMORY MANAGEMENT:
 * Preserves allocated pollfds array across iterations to minimize heap operations.
 * Array grows geometrically in poll_listen() when capacity exceeded but never shrinks.
 * This trades memory for performance in steady-state operation.
 *
 * SIDE EFFECTS:
 * Modifies global nfds counter to zero, effectively invalidating all prior poll_listen()
 * registrations. Pollfds array contents become logically invalid until repopulated.
 *
 * THREAD SAFETY: Not thread-safe. Modifies shared nfds without locking.
 *                Safe only in single-threaded event loop context.
 */
void poll_reset(void)
{
  nfds = 0;
}

/**
 * @brief Execute poll system call with timeout for event multiplexing
 *
 * @detailed
 * Invokes the POSIX poll(2) system call to monitor all registered file descriptors
 * for readiness events. Blocks until one or more file descriptors become ready for
 * I/O, the timeout expires, or a signal interrupts the call. Upon return, the revents
 * field of each pollfd entry is populated with triggered events, which can be queried
 * using poll_check(). The timeout parameter controls maximum blocking duration,
 * calculated by the event loop based on next timer expiry (lease expiry, cache TTL,
 * query retry, or periodic maintenance).
 *
 * @param timeout Maximum wait time in milliseconds. Negative value causes infinite
 *                blocking until events occur. Zero value causes immediate return
 *                (non-blocking poll). Positive value blocks for at most timeout
 *                milliseconds. Typical values range from 0 (immediate) to several
 *                seconds for periodic tasks.
 *
 * @return Number of file descriptors with ready events (positive integer),
 *         zero if timeout expired with no ready fds, or -1 on error with errno set.
 *
 * @retval >0 Number of file descriptors with events in revents fields
 * @retval 0 Timeout expired with no ready file descriptors
 * @retval -1 Error occurred (check errno). EINTR indicates signal interruption.
 *
 * @note Handles EINTR signal interruption by returning -1. Event loop should check
 *       errno and retry or process pending signals. Dnsmasq uses self-pipe pattern
 *       for async-signal-safe signal handling, converting signals to fd events.
 *
 * @warning Return value of -1 does not always indicate fatal error. EINTR is normal
 *          when signals arrive during poll(). Caller must check errno to distinguish
 *          signal interruption from actual I/O errors.
 *
 * @see poll_reset() must be called before registering fds for new iteration
 * @see poll_listen() registers fds before calling do_poll()
 * @see poll_check() queries specific fd readiness after do_poll() returns
 * @see dnsmasq.c event_loop() calculates timeout based on next timer expiry
 *
 * EXAMPLE USAGE:
 * @code
 * poll_reset();
 * poll_listen(dns_fd, POLLIN);
 * poll_listen(signal_pipe[0], POLLIN);
 * int timeout_ms = calculate_next_timeout();
 * int ready = do_poll(timeout_ms);
 * if (ready > 0) {
 *   if (poll_check(dns_fd, POLLIN)) process_dns_query();
 *   if (poll_check(signal_pipe[0], POLLIN)) process_signals();
 * } else if (ready == 0) {
 *   handle_timeout_event();
 * }
 * @endcode
 *
 * POSIX COMPLIANCE:
 * Thin wrapper around poll(2) POSIX system call. Behavior strictly follows
 * POSIX.1-2001 specification for poll(). Supported on all target platforms
 * including Linux, BSD variants (FreeBSD, OpenBSD, NetBSD), macOS, and Solaris.
 *
 * PERFORMANCE:
 * Poll(2) scales better than select(2) for large fd sets. No recomputation of
 * fd_set required on each call. Kernel maintains internal structures across calls.
 * Typical dnsmasq deployments monitor 3-20 fds (DNS, DHCP, control sockets, signal pipe).
 *
 * SIDE EFFECTS:
 * Modifies revents field of all pollfd entries in pollfds array to reflect triggered
 * events. Prior revents values are overwritten. Blocks calling thread until events
 * occur, timeout expires, or signal arrives.
 *
 * THREAD SAFETY: Not thread-safe. Operates on shared pollfds array without locking.
 *                Poll(2) system call itself is thread-safe but this wrapper assumes
 *                single-threaded access to pollfds global state.
 */
int do_poll(int timeout)
{
  return poll(pollfds, nfds, timeout);
}

/**
 * @brief Check if file descriptor has ready events after poll
 *
 * @detailed
 * Queries whether a specific file descriptor has triggered events of interest after
 * do_poll() returns. Performs efficient binary search via fd_search() to locate the
 * pollfd entry, then tests if the requested event mask matches any events in the
 * revents field. This function should only be called after do_poll() completes,
 * as revents fields are only valid after poll(2) returns. Multiple event types can
 * be tested by bitwise OR of POLLIN, POLLOUT, POLLERR, POLLHUP, and POLLNVAL.
 *
 * @param fd File descriptor to check for ready events. Must have been previously
 *           registered with poll_listen(). Checking unregistered fd safely returns 0.
 * @param event Event mask to test against revents. Use POLLIN for read readiness,
 *              POLLOUT for write readiness, POLLERR for error conditions, POLLHUP
 *              for hangup, POLLNVAL for invalid fd. Combine with bitwise OR for
 *              multiple simultaneous event tests.
 *
 * @return Bitwise AND of requested event mask and actual revents. Non-zero indicates
 *         at least one requested event occurred. Zero indicates no matching events
 *         or fd was not registered.
 *
 * @retval 0 No matching events, fd not registered, or fd not found in pollfds array
 * @retval non-zero Bitwise AND of event mask and revents showing which requested events occurred
 *
 * @note Returns zero for unregistered fds rather than error. Caller can safely query
 *       any fd without pre-checking registration status. Binary search ensures O(log n)
 *       lookup performance.
 *
 * @warning Only valid to call after do_poll() returns positive value. Revents fields
 *          are undefined before poll() executes. Checking events before do_poll() or
 *          after poll_reset() produces meaningless results.
 *
 * @see do_poll() populates revents fields that poll_check() queries
 * @see poll_listen() must be called to register fd before checking events
 * @see fd_search() performs binary search to locate fd efficiently
 *
 * EXAMPLE USAGE:
 * @code
 * int ready = do_poll(1000);
 * if (ready > 0) {
 *   if (poll_check(dns_fd, POLLIN)) {
 *     // DNS socket has data ready to read
 *     handle_dns_query();
 *   }
 *   if (poll_check(dhcp_fd, POLLIN | POLLERR)) {
 *     // DHCP socket ready or has error
 *     if (poll_check(dhcp_fd, POLLERR))
 *       handle_dhcp_error();
 *     else
 *       handle_dhcp_request();
 *   }
 * }
 * @endcode
 *
 * EVENT MASK INTERPRETATION:
 * - POLLIN: Data available for reading without blocking
 * - POLLOUT: Socket buffer space available for writing without blocking
 * - POLLERR: Error condition detected (socket error, connection reset)
 * - POLLHUP: Peer closed connection (hangup)
 * - POLLNVAL: File descriptor is invalid (not open)
 * Returned value is bitwise AND, so check specific bits to determine exact condition.
 *
 * SIDE EFFECTS: None - read-only operation on pollfds array
 *
 * THREAD SAFETY: Not thread-safe. Reads shared pollfds and nfds without locking.
 *                Safe only in single-threaded event loop context.
 */
int poll_check(int fd, short event)
{
  nfds_t i = fd_search(fd);
  
  if (i < nfds && pollfds[i].fd == fd)
    return pollfds[i].revents & event;

  return 0;
}

/**
 * @brief Register file descriptor with event mask for monitoring
 *
 * @detailed
 * Registers a file descriptor for event monitoring with the specified event mask,
 * or updates the event mask for an already-registered fd. Uses binary search to
 * locate existing entry or determine insertion point, then either updates the events
 * field or inserts a new pollfd entry while maintaining sorted order by file descriptor.
 * The pollfds array grows geometrically (doubling) when capacity is exceeded, starting
 * from initial size 64. Array memory is preserved across poll_reset() calls for
 * performance, only growing when necessary and never shrinking.
 *
 * @param fd File descriptor to monitor. Must be valid open file descriptor for socket,
 *           pipe, or other pollable resource. Invalid fd will be detected by poll(2)
 *           which sets POLLNVAL in revents.
 * @param event Event mask specifying conditions to monitor. Use POLLIN for read
 *              readiness, POLLOUT for write readiness. Multiple events can be combined
 *              with bitwise OR. For existing registrations, this is OR'd with current
 *              events to enable cumulative registration of multiple event types.
 *
 * @return void
 *
 * @note If fd already registered, event mask is OR'd with existing events rather than
 *       replaced. This allows multiple poll_listen() calls for same fd to accumulate
 *       event interests (e.g., first register POLLIN, later add POLLOUT).
 *
 * @note Array grows geometrically (×2) starting from 64 entries to minimize reallocation
 *       overhead. Typical dnsmasq usage registers 3-20 fds per iteration. Growth strategy
 *       provides amortized O(1) insertion cost.
 *
 * @warning Silently returns on whine_malloc() failure, leaving fd unregistered. Caller
 *          has no indication of failure. This matches dnsmasq's general philosophy of
 *          continuing degraded operation rather than fatal exit on allocation failure.
 *
 * @warning Maintains sorted order by fd using memmove() for insertion. Insertion cost
 *          is O(n) for array shift but amortized with infrequent reallocations. Binary
 *          search provides O(log n) lookup to find insertion point.
 *
 * @see poll_reset() clears registrations at start of each event loop iteration
 * @see do_poll() monitors all registered fds for events
 * @see poll_check() queries results after do_poll() completes
 * @see fd_search() locates insertion point or existing entry via binary search
 *
 * EXAMPLE USAGE:
 * @code
 * poll_reset();
 * // Register DNS listener sockets
 * poll_listen(dns_udp_fd, POLLIN);
 * poll_listen(dns_tcp_listener, POLLIN);
 * // Register DHCP sockets
 * poll_listen(dhcp_fd, POLLIN);
 * poll_listen(dhcp6_fd, POLLIN);
 * // Register signal self-pipe for async-signal-safe handling
 * poll_listen(signal_pipe[0], POLLIN);
 * int ready = do_poll(timeout_ms);
 * @endcode
 *
 * MEMORY ALLOCATION STRATEGY:
 * Initial allocation: 64 entries (arrsize = 64)
 * Growth: Doubles on each expansion (64 → 128 → 256 → ...)
 * Memory persists: Array never deallocated or shrunk during daemon lifetime
 * Reuse: poll_reset() zeros nfds but preserves allocated array
 * This provides O(1) amortized insertion cost with minimal memory overhead.
 *
 * ARRAY MAINTENANCE INVARIANT:
 * Pollfds array is always sorted in ascending order by fd field. Binary search
 * and event loop correctness depend on this invariant. New entries are inserted
 * at correct position via memmove() to shift higher fds rightward.
 *
 * SIDE EFFECTS:
 * - May allocate or reallocate pollfds array via whine_malloc() on capacity exhaustion
 * - Increments nfds counter on successful new registration
 * - Modifies pollfds[].events field for existing registrations (OR's with event param)
 * - May free() old pollfds array during reallocation (line 115)
 * - Shifts array contents via memmove() to maintain sorted order (lines 100, 114)
 *
 * THREAD SAFETY: Not thread-safe. Modifies shared pollfds, nfds, and arrsize without
 *                locking. Safe only in single-threaded event loop context.
 */
void poll_listen(int fd, short event)
{
   nfds_t i = fd_search(fd);
  
   if (i < nfds && pollfds[i].fd == fd)
     pollfds[i].events |= event;
   else
     {
       if (arrsize != nfds)
	 memmove(&pollfds[i+1], &pollfds[i], (nfds - i) * sizeof(struct pollfd));
       else
	 {
	   /* Array too small, extend. */
	   struct pollfd *new;

	   arrsize = (arrsize == 0) ? 64 : arrsize * 2;

	   if (!(new = whine_malloc(arrsize * sizeof(struct pollfd))))
	     return;

	   if (pollfds)
	     {
	       memcpy(new, pollfds, i * sizeof(struct pollfd));
	       memcpy(&new[i+1], &pollfds[i], (nfds - i) * sizeof(struct pollfd));
	       free(pollfds);
	     }
	   
	   pollfds = new;
	 }
       
       pollfds[i].fd = fd;
       pollfds[i].events = event;
       nfds++;
     }
}
