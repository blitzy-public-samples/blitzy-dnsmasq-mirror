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
 * @file arp.c
 * @brief ARP table access for DHCP address conflict detection.
 *
 * DETAILED PURPOSE:
 * This file provides platform-independent ARP cache querying functionality used by 
 * the DHCP server to implement ping-before-offer address conflict detection. Before 
 * allocating an IP address from the DHCP pool, dnsmasq queries the ARP cache to 
 * determine if the address is already in use on the local network. This prevents 
 * duplicate IP address assignments and conflicts with existing hosts.
 *
 * The implementation maintains an in-memory cache of ARP entries to minimize expensive
 * kernel queries. The cache is refreshed at configurable intervals (90 seconds by 
 * default) and supports both positive entries (IP→MAC mappings) and negative entries 
 * (addresses known to be absent from ARP table). Platform-specific code handles 
 * differences between Linux (/proc/net/arp parsing), BSD (routing socket queries), 
 * and other UNIX variants.
 *
 * This module is critical for DHCP server reliability, as it ensures addresses are 
 * not assigned while already in use by another host, which could cause network 
 * connectivity issues for both the DHCP client and the existing host.
 *
 * KEY RESPONSIBILITIES:
 * - find_mac() - Primary public API: search ARP cache for MAC address of given IP
 * - filter_mac() - Internal callback: process ARP entries from kernel enumeration
 * - do_arp_script_run() - Script notification: queue ARP events for external scripts
 *
 * DEPENDENCIES:
 * - dnsmasq.h: Core type definitions including union mysockaddr, union all_addr
 * - iface_enumerate(): Platform-specific interface enumeration function
 * - whine_malloc(): Memory allocator with logging on failure
 * - queue_arp(): Script notification queue (when HAVE_SCRIPT defined)
 * - option_bool(OPT_SCRIPT_ARP): Configuration option check
 *
 * Platform-specific implementations:
 * - Linux: Reads /proc/net/arp, parses text format ARP entries
 * - BSD: Uses RTM_GET routing socket messages to query ARP cache
 * - Solaris/others: Platform-specific iface_enumerate() implementations
 *
 * DATA STRUCTURES:
 * - struct arp_record (lines 27-33): Cached ARP entry with IP, MAC, status, and aging
 * - Static freelists (line 35): Memory pool management for arp_record recycling
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_SCRIPT: Enables external script notification of ARP events (add/delete)
 * - HAVE_LINUX_NETWORK: Linux-specific /proc/net/arp parsing path
 * - HAVE_BSD_NETWORK: BSD-specific routing socket path
 * - Platform detection influences iface_enumerate() behavior in network.c
 *
 * THREADING/CONCURRENCY:
 * This module operates in dnsmasq's single-process, event-driven architecture. All 
 * functions are called from the main event loop and are not thread-safe. The static 
 * cache variables (arps, old, freelist, last) maintain state across invocations but 
 * are protected by the single-threaded execution model. Re-entrancy is not supported.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DHCP_V4.md for DHCP server architecture and ping-before-offer mechanism
 * @see network.c for iface_enumerate() platform-specific implementations
 */

#include "dnsmasq.h"

/**
 * @def INTERVAL
 * @brief Time interval in seconds between forced ARP cache reloads from kernel.
 *
 * The ARP cache is refreshed from the kernel at most once every INTERVAL seconds
 * (90 seconds) to minimize expensive system calls while keeping the cache reasonably
 * current. Queries within this window are served from the in-memory cache.
 */
#define INTERVAL 90

/**
 * @def ARP_MARK
 * @brief Temporary marker status during cache refresh sweep.
 *
 * Entries are marked with ARP_MARK at the start of a kernel query, then confirmed
 * as ARP_FOUND if still present, or moved to old list if not reconfirmed.
 */
#define ARP_MARK  0

/**
 * @def ARP_FOUND
 * @brief Status indicating ARP entry confirmed present in kernel cache.
 *
 * Entry has been verified to exist in the kernel ARP table during the most recent
 * refresh cycle. This is a positive, confirmed IP→MAC mapping.
 */
#define ARP_FOUND 1  /* Confirmed */

/**
 * @def ARP_NEW
 * @brief Status indicating newly discovered ARP entry.
 *
 * Entry was just added to cache during current refresh cycle. Used to trigger
 * script notifications (ACTION_ARP event) for new IP→MAC mappings.
 */
#define ARP_NEW   2  /* Newly created */

/**
 * @def ARP_EMPTY
 * @brief Status indicating negative cache entry (no MAC address).
 *
 * This entry records that an IP address was queried but not found in the ARP table.
 * Negative caching prevents repeated kernel queries for non-existent entries in lazy
 * mode. hwlen is 0 for these entries.
 */
#define ARP_EMPTY 3  /* No MAC addr */

/**
 * @struct arp_record
 * @brief Cached ARP table entry recording IP→MAC address mapping.
 *
 * DETAILED PURPOSE:
 * Each arp_record represents one entry from the system ARP cache, storing the IP address,
 * corresponding hardware (MAC) address, address family (IPv4 or IPv6), and current status.
 * Records are organized in a singly-linked list with separate lists for active entries
 * (arps), old/expired entries (old), and free entries available for reuse (freelist).
 *
 * LIFECYCLE:
 * - Allocation: From freelist if available, otherwise via whine_malloc()
 * - Initialization: Populated during iface_enumerate() callback with filter_mac()
 * - Usage: Queried by find_mac() for DHCP address conflict detection
 * - Expiry: Moved to old list if not reconfirmed during cache refresh
 * - Deallocation: Moved to freelist for recycling, not freed to reduce malloc overhead
 *
 * MEMORY LAYOUT:
 * Total size approximately 32-48 bytes depending on platform (union all_addr size varies).
 * Structure packing is compiler-dependent; no explicit alignment requirements.
 * hwaddr uses DHCP_CHADDR_MAX (16 bytes) to accommodate largest hardware address formats.
 *
 * USAGE PATTERNS:
 * - find_mac() searches arps list linearly for matching IP address
 * - filter_mac() updates existing entries or creates new ones during kernel enumeration
 * - do_arp_script_run() iterates lists to notify external scripts of changes
 * - Three separate lists maintained: arps (active), old (expired), freelist (recycled)
 */
struct arp_record {
  unsigned short hwlen;    /**< Hardware address length in bytes (typically 6 for Ethernet, 0 for negative entries) */
  unsigned short status;   /**< Entry status: ARP_MARK, ARP_FOUND, ARP_NEW, or ARP_EMPTY */
  int family;              /**< Address family: AF_INET for IPv4, AF_INET6 for IPv6 */
  unsigned char hwaddr[DHCP_CHADDR_MAX]; /**< Hardware (MAC) address, up to DHCP_CHADDR_MAX (16) bytes */
  union all_addr addr;     /**< IP address: addr.addr4 for IPv4, addr.addr6 for IPv6 */
  struct arp_record *next; /**< Next entry in linked list (arps, old, or freelist) */
};

static struct arp_record *arps = NULL, *old = NULL, *freelist = NULL;
static time_t last = 0;

/**
 * @brief Process ARP entry from kernel enumeration and update cache.
 *
 * @detailed
 * Callback function invoked by iface_enumerate() for each ARP entry discovered in
 * the kernel ARP table. Searches the current cache for matching IP address and either
 * updates existing entry status or creates new entry. Implements intelligent cache
 * update logic: existing entries are confirmed (ARP_FOUND), negative entries become
 * positive (ARP_EMPTY→ARP_NEW), mismatched MAC addresses are skipped to preserve
 * existing data, and new IP addresses trigger fresh arp_record allocation from
 * freelist or heap.
 *
 * @param family Address family (AF_INET or AF_INET6) of the ARP entry.
 * @param addrp Pointer to IP address structure (struct in_addr* for IPv4, struct in6_addr* for IPv6).
 *        Must not be NULL. Ownership remains with caller.
 * @param mac Pointer to hardware (MAC) address bytes. Must not be NULL. Ownership remains with caller.
 * @param maclen Length of hardware address in bytes. Typically 6 for Ethernet. If exceeds
 *        DHCP_CHADDR_MAX (16), entry is rejected.
 * @param parmv Unused parameter required by iface_enumerate() callback signature. Always NULL.
 *
 * @return Always returns 1 to continue enumeration (iface_enumerate() API requirement).
 *
 * @note
 * This function is called from iface_enumerate() context during find_mac() cache refresh.
 * The family parameter determines structure interpretation: AF_INET treats addrp as
 * struct in_addr*, AF_INET6 as struct in6_addr*. Matching logic uses byte-wise address
 * comparison appropriate for each family (s_addr equality for IPv4, IN6_ARE_ADDR_EQUAL
 * macro for IPv6).
 *
 * @warning
 * Memory allocation failure (whine_malloc() returns NULL) is tolerated but logged; the
 * failing entry is silently dropped. Caller must handle possibility of incomplete cache
 * updates. MAC address comparison is byte-wise memcmp(); different MAC for same IP
 * causes entry to be skipped rather than updated, preserving historical behavior.
 *
 * @see find_mac() for the caller that invokes iface_enumerate() with this callback
 * @see iface_enumerate() in network.c for platform-specific ARP enumeration
 * @see whine_malloc() in util.c for logging memory allocator
 *
 * EXAMPLE USAGE:
 * @code
 * // Called internally by iface_enumerate() during cache refresh:
 * // iface_enumerate(AF_UNSPEC, NULL, filter_mac);
 * // For each ARP entry found, kernel calls:
 * // filter_mac(AF_INET, &ipv4_addr, mac_bytes, 6, NULL);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies global arps list (adds new entries, updates entry status)
 * - Allocates memory from freelist or heap (via whine_malloc())
 * - Updates status fields of existing arp_record entries
 * - No I/O operations; purely in-memory cache manipulation
 *
 * THREAD SAFETY:
 * Not thread-safe. Relies on single-threaded event loop execution. Modifies static
 * global variables (arps, freelist) without locking. Must only be called from main
 * thread during iface_enumerate() invocation.
 */
static int filter_mac(int family, char *addrp, char *mac, size_t maclen, void *parmv)
{
  struct arp_record *arp;

  (void)parmv;

  if (maclen > DHCP_CHADDR_MAX)
    return 1;

  /* Look for existing entry */
  for (arp = arps; arp; arp = arp->next)
    {
      if (family != arp->family || arp->status == ARP_NEW)
	continue;
      
      if (family == AF_INET)
	{
	  if (arp->addr.addr4.s_addr != ((struct in_addr *)addrp)->s_addr)
	    continue;
	}
      else
	{
	  if (!IN6_ARE_ADDR_EQUAL(&arp->addr.addr6, (struct in6_addr *)addrp))
	    continue;
	}

      if (arp->status == ARP_EMPTY)
	{
	  /* existing address, was negative. */
	  arp->status = ARP_NEW;
	  arp->hwlen = maclen;
	  memcpy(arp->hwaddr, mac, maclen);
	}
      else if (arp->hwlen == maclen && memcmp(arp->hwaddr, mac, maclen) == 0)
	/* Existing entry matches - confirm. */
	arp->status = ARP_FOUND;
      else
	continue;
      
      break;
    }

  if (!arp)
    {
      /* New entry */
      if (freelist)
	{
	  arp = freelist;
	  freelist = freelist->next;
	}
      else if (!(arp = whine_malloc(sizeof(struct arp_record))))
	return 1;
      
      arp->next = arps;
      arps = arp;
      arp->status = ARP_NEW;
      arp->hwlen = maclen;
      arp->family = family;
      memcpy(arp->hwaddr, mac, maclen);
      if (family == AF_INET)
	arp->addr.addr4.s_addr = ((struct in_addr *)addrp)->s_addr;
      else
	memcpy(&arp->addr.addr6, addrp, IN6ADDRSZ);
    }
  
  return 1;
}

/**
 * @brief Search ARP cache for MAC address of given IP address.
 *
 * @detailed
 * Primary public API for ARP cache lookups. Searches the in-memory ARP cache for the
 * MAC address corresponding to the specified IP address, refreshing from kernel if cache
 * is stale (older than INTERVAL seconds). Used by DHCP server to implement ping-before-offer
 * address conflict detection. Supports both immediate lookups (non-lazy mode returns only
 * confirmed entries) and lazy mode (returns cached negative entries to avoid repeated
 * kernel queries). The function automatically triggers cache refresh when needed and
 * maintains negative cache entries to record addresses known to be absent from ARP table.
 *
 * Cache refresh algorithm: marks existing entries, enumerates kernel ARP table via
 * iface_enumerate() with filter_mac() callback, moves unconfirmed entries to old list,
 * and retries lookup after refresh completes. This ensures at-most-once kernel query
 * per INTERVAL (90 seconds) regardless of query frequency.
 *
 * @param addr Pointer to socket address structure containing IP address to look up. If NULL,
 *        function performs cache refresh only without lookup (maintenance mode). For IPv4
 *        queries, addr->in.sin_addr contains target; for IPv6, addr->in6.sin6_addr contains
 *        target. Family determined by addr->sa.sa_family (AF_INET or AF_INET6). Must remain
 *        valid for function duration; not modified.
 * @param mac Output buffer for MAC address. If non-NULL and entry found with MAC, receives
 *        hardware address bytes (typically 6 bytes for Ethernet). Caller must provide buffer
 *        of at least DHCP_CHADDR_MAX (16) bytes. If NULL, function performs existence check
 *        only. Ownership remains with caller.
 * @param lazy If non-zero, function returns negative cache entries (ARP_EMPTY status with
 *        hwlen=0) to indicate address is known absent from ARP table. If zero, only positive
 *        entries with confirmed MAC addresses are returned. Lazy mode reduces kernel queries
 *        by accepting cached negative results.
 * @param now Current time (seconds since epoch) used for cache aging and refresh decisions.
 *        Typically obtained from time(NULL). If difftime(now, last) >= INTERVAL, triggers
 *        cache refresh from kernel before lookup.
 *
 * @return Hardware address length in bytes (typically 6 for Ethernet) if entry found with
 *         MAC address. Returns 0 if address not found in ARP table or entry is negative
 *         (ARP_EMPTY) and lazy mode disabled. Zero return does NOT indicate error; it means
 *         "address not present in ARP cache." Distinguish from error by checking errno if
 *         needed (though this function generally does not set errno).
 *
 * @retval 6 Typical return for found IPv4/Ethernet entry (48-bit MAC address).
 * @retval 0 Address not in ARP table, or negative cache entry in non-lazy mode.
 * @retval >0 Hardware address length for non-Ethernet media (rare).
 *
 * @note
 * Function uses goto-based retry logic: after cache refresh, jumps back to "again:" label
 * to retry lookup with updated cache. This ensures single code path for lookup logic while
 * handling refresh-then-retry pattern. The updated flag prevents infinite loops by allowing
 * only one kernel refresh per invocation.
 *
 * Special case: addr==NULL acts as cache maintenance trigger, refreshing from kernel without
 * performing lookup. Used by DHCP server to proactively update cache before address allocation.
 *
 * @warning
 * Function may block briefly during iface_enumerate() kernel query (reads /proc/net/arp on
 * Linux or performs routing socket query on BSD). Typical duration <10ms but could be longer
 * under heavy kernel load. Not suitable for hard real-time contexts.
 *
 * Negative cache entries (ARP_EMPTY) are created for lookup misses and persist until next
 * INTERVAL refresh. This prevents cache pollution but means failed lookups are remembered
 * even if address becomes available before next refresh window.
 *
 * @see filter_mac() for the callback that populates cache during refresh
 * @see do_arp_script_run() for script notification of ARP changes
 * @see docs/DHCP_V4.md for ping-before-offer algorithm description
 *
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr;
 * unsigned char mac_buf[DHCP_CHADDR_MAX];
 * time_t now = time(NULL);
 * 
 * client_addr.sa.sa_family = AF_INET;
 * client_addr.in.sin_addr.s_addr = inet_addr("192.168.1.100");
 * 
 * int mac_len = find_mac(&client_addr, mac_buf, 0, now);
 * if (mac_len > 0) {
 *   // Address in use: MAC found in ARP table, do not allocate
 * } else {
 *   // Address available: safe to allocate from DHCP pool
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 2131 Section 3.1 requirement that DHCP servers "SHOULD" probe addresses
 * before allocation to detect conflicts. ARP cache checking is faster alternative to
 * ICMP ping (ping-before-offer) for local subnet conflict detection.
 *
 * SIDE EFFECTS:
 * - Reads kernel ARP table via iface_enumerate() if cache stale (> INTERVAL seconds old)
 * - Updates global arps, old, freelist linked lists
 * - Modifies arp_record status fields during refresh sweep
 * - Updates last timestamp on cache refresh
 * - Creates negative cache entries (ARP_EMPTY) for lookup misses
 * - May allocate memory via whine_malloc() for new arp_record entries
 * - On Linux: reads /proc/net/arp file
 * - On BSD: performs RTM_GET routing socket query
 *
 * THREAD SAFETY:
 * Not thread-safe. Function modifies static global state (arps, old, freelist, last)
 * without synchronization. Must be called only from dnsmasq main event loop thread.
 * Re-entrancy NOT supported: calling find_mac() during iface_enumerate() callback
 * would corrupt linked lists.
 */
/* If in lazy mode, we cache absence of ARP entries. */
int find_mac(union mysockaddr *addr, unsigned char *mac, int lazy, time_t now)
{
  struct arp_record *arp, *tmp, **up;
  int updated = 0;

 again:
  
  /* If the database is less then INTERVAL old, look in there */
  if (difftime(now, last) < INTERVAL)
    {
      /* addr == NULL -> just make cache up-to-date */
      if (!addr)
	return 0;

      for (arp = arps; arp; arp = arp->next)
	{
	  if (addr->sa.sa_family != arp->family)
	    continue;
	    
	  if (arp->family == AF_INET &&
	      arp->addr.addr4.s_addr != addr->in.sin_addr.s_addr)
	    continue;
	    
	  if (arp->family == AF_INET6 && 
	      !IN6_ARE_ADDR_EQUAL(&arp->addr.addr6, &addr->in6.sin6_addr))
	    continue;
	  
	  /* Only accept positive entries unless in lazy mode. */
	  if (arp->status != ARP_EMPTY || lazy || updated)
	    {
	      if (mac && arp->hwlen != 0)
		memcpy(mac, arp->hwaddr, arp->hwlen);
	      return arp->hwlen;
	    }
	}
    }

  /* Not found, try the kernel */
  if (!updated)
     {
       updated = 1;
       last = now;

       /* Mark all non-negative entries */
       for (arp = arps; arp; arp = arp->next)
	 if (arp->status != ARP_EMPTY)
	   arp->status = ARP_MARK;
       
       iface_enumerate(AF_UNSPEC, NULL, filter_mac);
       
       /* Remove all unconfirmed entries to old list. */
       for (arp = arps, up = &arps; arp; arp = tmp)
	 {
	   tmp = arp->next;
	   
	   if (arp->status == ARP_MARK)
	     {
	       *up = arp->next;
	       arp->next = old;
	       old = arp;
	     }
	   else
	     up = &arp->next;
	 }

       goto again;
     }

  /* record failure, so we don't consult the kernel each time
     we're asked for this address */
  if (freelist)
    {
      arp = freelist;
      freelist = freelist->next;
    }
  else
    arp = whine_malloc(sizeof(struct arp_record));
  
  if (arp)
    {      
      arp->next = arps;
      arps = arp;
      arp->status = ARP_EMPTY;
      arp->family = addr->sa.sa_family;
      arp->hwlen = 0;

      if (addr->sa.sa_family == AF_INET)
	arp->addr.addr4.s_addr = addr->in.sin_addr.s_addr;
      else
	memcpy(&arp->addr.addr6, &addr->in6.sin6_addr, IN6ADDRSZ);
    }
	  
   return 0;
}

/**
 * @brief Queue ARP change events for external script notification.
 *
 * @detailed
 * Iterates through ARP cache lists to identify changes (additions and deletions) and
 * queues corresponding script notification events. Processes one entry per invocation
 * to spread notification load across event loop iterations, preventing script execution
 * backlog. Expired entries (from old list) trigger ACTION_ARP_DEL events and are moved
 * to freelist for recycling. New entries (ARP_NEW status) trigger ACTION_ARP events and
 * are promoted to confirmed (ARP_FOUND) status. Function is designed to be called
 * repeatedly from main event loop until it returns 0, indicating all pending events
 * have been queued.
 *
 * Script notification requires HAVE_SCRIPT compile-time option and OPT_SCRIPT_ARP runtime
 * configuration. If either is disabled, function still performs list maintenance (moving
 * old entries to freelist, promoting new to found) but skips queue_arp() calls.
 *
 * @return 1 if an event was queued (or would have been queued if scripts enabled), indicating
 *         caller should invoke function again to process remaining changes.
 *         0 if no pending events remain, indicating completion of current notification cycle.
 *
 * @retval 1 Event processed, more events may be pending (call again).
 * @retval 0 No events pending, notification cycle complete.
 *
 * @note
 * Function processes exactly one event per call to avoid blocking main event loop with
 * batch notification processing. Caller (typically main event loop in dnsmasq.c) should
 * call repeatedly in a loop until return value is 0.
 *
 * Old list is processed with FIFO semantics: oldest expired entries notified first.
 * New entries are processed in list order (effectively LIFO since new entries are
 * prepended to arps list).
 *
 * @warning
 * Function modifies global linked lists (old, freelist, arps) and entry status fields.
 * Not thread-safe and not re-entrant. Must be called only from main event loop thread.
 * Do not call during iface_enumerate() or find_mac() execution.
 *
 * Script notification is asynchronous: queue_arp() adds to notification queue but does
 * not execute script immediately. Actual script invocation occurs later in event loop.
 * Script execution failures are logged but do not affect ARP cache state.
 *
 * @see queue_arp() in helper.c for script notification queue management
 * @see find_mac() for ARP cache lookup that creates entries processed here
 * @see docs/DHCP_V4.md for DHCP server event notification architecture
 *
 * EXAMPLE USAGE:
 * @code
 * // From main event loop in dnsmasq.c:
 * if (option_bool(OPT_SCRIPT_ARP)) {
 *   while (do_arp_script_run()) {
 *     // Process one ARP event per iteration
 *     // Loop continues until all events queued
 *   }
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies old list: removes one entry, moves to freelist
 * - Modifies arps list: changes ARP_NEW entries to ARP_FOUND status
 * - Calls queue_arp() to add script notification events (if HAVE_SCRIPT enabled)
 * - Maintains freelist: recycled entries added for future allocation
 * - No I/O operations directly (queue_arp() may perform I/O later)
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies static global variables (old, arps, freelist) without
 * synchronization. Must be called only from dnsmasq main event loop thread. Re-entrancy
 * not supported.
 */
int do_arp_script_run(void)
{
  struct arp_record *arp;
  
  /* Notify any which went, then move to free list */
  if (old)
    {
#ifdef HAVE_SCRIPT
      if (option_bool(OPT_SCRIPT_ARP))
	queue_arp(ACTION_ARP_DEL, old->hwaddr, old->hwlen, old->family, &old->addr);
#endif
      arp = old;
      old = arp->next;
      arp->next = freelist;
      freelist = arp;
      return 1;
    }

  for (arp = arps; arp; arp = arp->next)
    if (arp->status == ARP_NEW)
      {
#ifdef HAVE_SCRIPT
	if (option_bool(OPT_SCRIPT_ARP))
	  queue_arp(ACTION_ARP, arp->hwaddr, arp->hwlen, arp->family, &arp->addr);
#endif
	arp->status = ARP_FOUND;
	return 1;
      }

  return 0;
}
