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
 * @file loop.c
 * @brief DNS forwarding loop detection
 *
 * DETAILED PURPOSE:
 * This module implements DNS forwarding loop detection to prevent infinite recursion
 * when an upstream DNS server is misconfigured to point back to dnsmasq itself. Without
 * loop detection, dnsmasq could receive its own queries forwarded by an upstream server,
 * creating an infinite forwarding loop that exhausts resources and prevents proper DNS
 * resolution. The implementation uses a probe-based mechanism where dnsmasq sends unique
 * TXT queries to upstream servers and watches for those same queries to return, indicating
 * a forwarding loop.
 *
 * KEY RESPONSIBILITIES:
 * - loop_send_probes() - Send loop detection probe queries to all upstream servers
 * - detect_loop() - Identify incoming queries as loop detection probes
 * - loop_make_probe() - Construct DNS TXT query packets with unique identifiers
 * - Mark servers with SERV_LOOP flag to prevent using looped servers
 *
 * DEPENDENCIES:
 * Includes: dnsmasq.h
 * Called by: Main daemon initialization and server checking routines
 * Calls: allocate_rfd(), free_rfds(), sendto(), check_servers()
 *
 * DATA STRUCTURES:
 * - struct server (dnsmasq.h:575-593) - Upstream server tracking with uid field
 * - struct dns_header (dns-protocol.h) - DNS packet header structure
 * - struct randfd_list - Random file descriptor list for socket management
 *
 * COMPILE-TIME OPTIONS:
 * HAVE_LOOP - Enables loop detection feature (config.h:182). When undefined, this
 *             entire module is excluded from compilation. The feature can be disabled
 *             with --no-loop-detect command line option at runtime via OPT_LOOP_DETECT.
 *
 * ALGORITHM:
 * 1. Periodically send TXT queries to "XXXXXXXX.test" (where XXXXXXXX is server's uid)
 * 2. If dnsmasq receives its own probe query back, the upstream server is looping
 * 3. Mark the offending server with SERV_LOOP flag to exclude it from query forwarding
 * 4. Log the loop detection event via check_servers() for administrator notification
 *
 * THREADING/CONCURRENCY:
 * This module operates within dnsmasq's single-process event-driven architecture.
 * Loop probes are sent synchronously during server health checks. The detect_loop()
 * function is called during normal query processing to check incoming requests.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/ARCHITECTURE.md for event-driven architecture explanation
 * @see docs/DNS_FORWARDING.md for upstream server selection details
 */

#include "dnsmasq.h"

#ifdef HAVE_LOOP
static ssize_t loop_make_probe(u32 uid);

/**
 * @brief Send loop detection probe queries to all upstream DNS servers
 *
 * @detailed
 * Iterates through all configured upstream DNS servers and sends a unique TXT query
 * to each one. The query contains a hex-encoded unique identifier (UID) specific to
 * each server. If dnsmasq later receives this same query back, it indicates that the
 * upstream server is forwarding queries back to dnsmasq, creating a forwarding loop.
 * Servers are marked with SERV_LOOP flag when loops are detected by detect_loop().
 * This function clears the SERV_LOOP flag before sending probes to allow recovery if
 * the upstream configuration has been corrected.
 *
 * @note This function only sends probes if OPT_LOOP_DETECT option is enabled via
 *       --loop-detect command line option. Returns immediately if disabled.
 *
 * @note Only probes "default" upstream servers (servers without specific domain
 *       restrictions and not marked SERV_FOR_NODOTS). Domain-specific servers
 *       are not probed since they only receive queries for specific domains.
 *
 * @note Uses loop_make_probe() to construct the DNS TXT query packet with format:
 *       "XXXXXXXX.test" where XXXXXXXX is the server's uid in hexadecimal.
 *
 * @warning Clears SERV_LOOP flag on all probed servers before sending, allowing
 *          previously detected looped servers to be re-tested.
 *
 * @see detect_loop() - Companion function that detects returning probe queries
 * @see loop_make_probe() - Constructs the probe query packet (lines 51-77)
 * @see check_servers() - Called when loop is detected to log server state
 *
 * EXAMPLE USAGE:
 * @code
 * // Called periodically by main daemon to check server health
 * loop_send_probes();
 * // If loops detected, servers marked SERV_LOOP will be excluded from forwarding
 * @endcode
 *
 * RFC COMPLIANCE:
 * Uses RFC 2606 reserved domain "test" to avoid conflicts with real DNS queries.
 * Constructs valid DNS TXT queries per RFC 1035 Section 4.1.
 *
 * SIDE EFFECTS:
 * - Clears SERV_LOOP flag on all default upstream servers
 * - Allocates temporary random file descriptors via allocate_rfd()
 * - Sends UDP packets to all default upstream servers
 * - Modifies daemon->packet buffer with probe query
 * - Sets daemon->srv_save to NULL in loop_make_probe()
 *
 * THREAD SAFETY:
 * Not reentrant. Modifies global daemon structure. Must be called from main event loop.
 */
void loop_send_probes()
{
   struct server *serv;
   struct randfd_list *rfds = NULL;
   
   if (!option_bool(OPT_LOOP_DETECT))
     return;

   /* Loop through all upstream servers not for particular domains, and send a query to that server which is
      identifiable, via the uid. If we see that query back again, then the server is looping, and we should not use it. */
   for (serv = daemon->servers; serv; serv = serv->next)
     if (strlen(serv->domain) == 0 &&
	 !(serv->flags & (SERV_FOR_NODOTS)))
       {
	 ssize_t len = loop_make_probe(serv->uid);
	 int fd;
	 
	 serv->flags &= ~SERV_LOOP;

	 if ((fd = allocate_rfd(&rfds, serv)) == -1)
	   continue;
	 
	 while (retry_send(sendto(fd, daemon->packet, len, 0, 
				  &serv->addr.sa, sa_len(&serv->addr))));
       }

   free_rfds(&rfds);
}

/**
 * @brief Construct DNS TXT query packet for loop detection probe
 *
 * @detailed
 * Creates a DNS query packet in daemon->packet buffer with a TXT record request
 * for a hostname encoding the provided UID. The query format is "XXXXXXXX.test"
 * where XXXXXXXX is the 32-bit uid parameter formatted as 8 hexadecimal digits,
 * and "test" is the RFC 2606 reserved domain. This unique query allows dnsmasq
 * to identify its own probe if it returns from an upstream server, indicating
 * a forwarding loop.
 *
 * @param uid Unique identifier (32-bit) assigned to the target server. This value
 *            is stored in struct server.uid (dnsmasq.h:591) and uniquely identifies
 *            each upstream server for loop detection purposes.
 *
 * @return Length of the constructed DNS query packet in bytes, suitable for sendto().
 *         Typical return value is approximately 30-40 bytes depending on domain length.
 *
 * @note Sets daemon->srv_save to NULL because this function overwrites the daemon->packet
 *       buffer, invalidating any saved state.
 *
 * @note The constructed query uses:
 *       - Random query ID (rand16()) to match DNS protocol requirements
 *       - RD (Recursion Desired) flag set (HB3_RD)
 *       - Standard QUERY opcode
 *       - Question count = 1, Answer/Authority/Additional counts = 0
 *       - Class IN (Internet), Type TXT (LOOP_TEST_TYPE from config.h:60)
 *
 * @warning This function overwrites daemon->packet buffer. Any previous packet
 *          data is lost. Not safe to call during active query processing.
 *
 * @see loop_send_probes() - Calls this function to generate probes (line 137)
 * @see detect_loop() - Parses queries in reverse to detect probes (lines 181-212)
 *
 * EXAMPLE USAGE:
 * @code
 * u32 server_uid = 0x12345678;
 * ssize_t probe_len = loop_make_probe(server_uid);
 * // probe_len contains size of packet in daemon->packet
 * // Query will be for "12345678.test" TXT record
 * sendto(fd, daemon->packet, probe_len, 0, &addr, addrlen);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 1035 Section 4.1.1 - DNS header format
 * - RFC 1035 Section 4.1.2 - DNS question section format
 * - RFC 2606 - Reserved domain "test" used to avoid conflicts
 *
 * SIDE EFFECTS:
 * - Overwrites daemon->packet buffer with new query
 * - Sets daemon->srv_save = NULL
 * - Does not modify any server structures
 *
 * THREAD SAFETY:
 * Not reentrant. Modifies global daemon->packet buffer. Must be called from main
 * event loop only, not from signal handlers or callbacks.
 */
static ssize_t loop_make_probe(u32 uid)
{
  struct dns_header *header = (struct dns_header *)daemon->packet;
  unsigned char *p = (unsigned char *)(header+1);
  
  /* packet buffer overwritten */
  daemon->srv_save = NULL;
  
  header->id = rand16();
  header->ancount = header->nscount = header->arcount = htons(0);
  header->qdcount = htons(1);
  header->hb3 = HB3_RD;
  header->hb4 = 0;
  SET_OPCODE(header, QUERY);

  *p++ = 8;
  sprintf((char *)p, "%.8x", uid);
  p += 8;
  *p++ = strlen(LOOP_TEST_DOMAIN);
  strcpy((char *)p, LOOP_TEST_DOMAIN); /* Add terminating zero */
  p += strlen(LOOP_TEST_DOMAIN) + 1;

  PUTSHORT(LOOP_TEST_TYPE, p);
  PUTSHORT(C_IN, p);

  return p - (unsigned char *)header;
}

/**
 * @brief Detect if an incoming DNS query is a loop detection probe
 *
 * @detailed
 * Examines an incoming DNS query to determine if it matches a loop detection probe
 * previously sent by loop_send_probes(). If the query is for a TXT record matching
 * the pattern "XXXXXXXX.test" (where XXXXXXXX is a hex-encoded UID), this function
 * extracts the UID and searches for a matching upstream server. If found, the server
 * is marked with SERV_LOOP flag to prevent forwarding queries to it, and check_servers()
 * is called to log the loop detection event. This mechanism prevents infinite forwarding
 * loops when an upstream server is misconfigured to point back to dnsmasq.
 *
 * @param query NULL-terminated string containing the DNS query name (domain name).
 *              Expected format for probe detection: "XXXXXXXX.test" where XXXXXXXX
 *              is exactly 8 hexadecimal digits. Must not be NULL.
 *
 * @param type DNS query type (e.g., T_A, T_AAAA, T_TXT). Only LOOP_TEST_TYPE (T_TXT)
 *             queries are examined for loop detection. Other types return 0 immediately.
 *
 * @return 1 if a forwarding loop was detected and the server was marked with SERV_LOOP flag.
 * @retval 0 Query is not a loop detection probe, or OPT_LOOP_DETECT is disabled, or
 *           query format doesn't match probe pattern, or no matching server UID found.
 * @retval 1 Loop detected: query matched a probe UID, server marked SERV_LOOP.
 *
 * @note Only operates if OPT_LOOP_DETECT option is enabled. Returns 0 immediately if disabled.
 *
 * @note Validation steps performed:
 *       1. Check if type == LOOP_TEST_TYPE (TXT record)
 *       2. Verify query length matches expected pattern (LOOP_TEST_DOMAIN + 9 chars)
 *       3. Confirm LOOP_TEST_DOMAIN appears at correct position (after 8 hex digits)
 *       4. Validate first 8 characters are hexadecimal digits
 *       5. Extract UID and search for matching server
 *
 * @note When loop detected, sets SERV_LOOP flag (dnsmasq.h:551) on the offending server
 *       and calls check_servers(1) to log the state change without sending more probes.
 *
 * @warning Does not validate that query pointer is non-NULL. Caller must ensure valid pointer.
 *
 * @see loop_send_probes() - Sends the probe queries that this function detects (lines 73-150)
 * @see loop_make_probe() - Constructs the probe packets (lines 152-235)
 * @see check_servers() - Called to log server state when loop detected (dnsmasq.h:1470)
 *
 * EXAMPLE USAGE:
 * @code
 * // In query processing pipeline:
 * char *query_name = "12345678.test";
 * int query_type = T_TXT;
 * if (detect_loop(query_name, query_type)) {
 *     // Loop detected, query should not be processed further
 *     // Offending server is now marked SERV_LOOP
 *     return;
 * }
 * // Normal query processing continues...
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 2606 - Uses reserved domain "test" for loop detection
 * - RFC 1035 Section 3.1 - Domain name format validation
 *
 * SIDE EFFECTS:
 * - Sets SERV_LOOP flag on matching server (struct server.flags |= SERV_LOOP)
 * - Calls check_servers(1) which logs server state changes
 * - Does not modify query string or type parameter
 *
 * THREAD SAFETY:
 * Not fully reentrant. Modifies server flags and calls check_servers(). Must be called
 * from main event loop during query processing. Safe for single-threaded event model.
 */
int detect_loop(char *query, int type)
{
  int i;
  u32 uid;
  struct server *serv;
  
  if (!option_bool(OPT_LOOP_DETECT))
    return 0;

  if (type != LOOP_TEST_TYPE ||
      strlen(LOOP_TEST_DOMAIN) + 9 != strlen(query) ||
      strstr(query, LOOP_TEST_DOMAIN) != query + 9)
    return 0;

  for (i = 0; i < 8; i++)
    if (!isxdigit(query[i]))
      return 0;

  uid = strtol(query, NULL, 16);

  for (serv = daemon->servers; serv; serv = serv->next)
    if (strlen(serv->domain) == 0 &&
	!(serv->flags & SERV_LOOP) &&
	uid == serv->uid)
      {
	serv->flags |= SERV_LOOP;
	check_servers(1); /* log new state - don't send more probes. */
	return 1;
      }
  
  return 0;
}

#endif
