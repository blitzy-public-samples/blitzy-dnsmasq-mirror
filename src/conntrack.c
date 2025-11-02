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
 * @file conntrack.c
 * @brief Linux connection tracking (conntrack) mark propagation integration
 *
 * DETAILED PURPOSE:
 * This file implements integration with the Linux netfilter connection tracking
 * (conntrack) subsystem to enable firewall mark propagation from incoming DNS
 * query packets to outgoing upstream DNS queries. This allows network administrators
 * to implement policy-based routing where DNS queries inherit the firewall marks
 * of the original client connections, enabling routing decisions based on the
 * source of the DNS query rather than just the dnsmasq process itself.
 *
 * The primary use case is in complex network environments where different client
 * networks need their DNS queries routed through different upstream paths, with
 * routing controlled by iptables MARK targets and ip rule fwmark-based routing
 * policies. By querying conntrack for the mark associated with the incoming
 * connection, dnsmasq can copy that mark to its upstream queries.
 *
 * KEY RESPONSIBILITIES:
 * - get_incoming_mark() queries netfilter conntrack to retrieve the firewall mark
 *   associated with an incoming DNS query connection based on source/destination
 *   addresses and ports
 * - callback() processes conntrack query results and extracts the ATTR_MARK value
 * - Integration with libnetfilter_conntrack library for conntrack table access
 * - Support for both IPv4 and IPv6 connection tracking entries
 * - Error handling and logging for conntrack access failures
 *
 * DEPENDENCIES:
 * - dnsmasq.h: Core type definitions (union mysockaddr, union all_addr, daemon global)
 * - libnetfilter_conntrack: External library for netfilter conntrack table access
 * - Linux kernel netfilter conntrack module must be loaded and active
 * - Requires CAP_NET_ADMIN capability for conntrack table access
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_CONNTRACK: Entire file is conditionally compiled only when this macro is
 *   defined. When undefined, no conntrack integration is available and the
 *   get_incoming_mark() function is not provided.
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. Functions are re-entrant as each invocation
 * creates its own nfct_handle and nf_conntrack structures. The static gotit variable
 * is used as a callback result indicator and is set/read within a single function
 * call context (not across concurrent invocations). Not thread-safe due to static
 * gotit variable, but dnsmasq is single-threaded so this is acceptable.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_CONNTRACK

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

/**
 * @var gotit
 * @brief Callback completion flag indicating conntrack query result availability
 *
 * Static flag set by callback() to indicate successful retrieval of conntrack
 * mark value. Reset to 0 before each conntrack query, set to 1 by callback()
 * when mark is successfully extracted. Used as return value from get_incoming_mark()
 * to indicate query success/failure.
 *
 * Note: Original code comment "yuck" reflects that this is a simple but effective
 * mechanism for communicating callback result status back to the caller in the
 * single-threaded dnsmasq event loop context.
 */
static int gotit = 0; /* yuck */

static int callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data);

/**
 * @brief Query netfilter conntrack for firewall mark associated with incoming connection
 *
 * @detailed
 * Queries the Linux netfilter connection tracking table to retrieve the firewall
 * mark (set by iptables MARK target) associated with an incoming DNS query connection.
 * Constructs a conntrack query based on the source address (peer), destination address
 * (local), port (daemon->port), and protocol (TCP/UDP), then retrieves the ATTR_MARK
 * value if a matching conntrack entry exists. This mark can then be applied to upstream
 * DNS queries to enable policy-based routing where queries inherit the routing policy
 * of the originating client network.
 *
 * The function handles both IPv4 (AF_INET) and IPv6 (AF_INET6) connections, setting
 * appropriate conntrack attributes for each protocol family. Creates a temporary
 * conntrack handle, registers a callback to extract the mark, performs the query,
 * and cleans up resources before returning.
 *
 * @param peer_addr Pointer to union mysockaddr containing the source address and port
 *                  of the incoming DNS query (client address). Must be valid IPv4
 *                  (AF_INET with sin_addr/sin_port) or IPv6 (AF_INET6 with
 *                  sin6_addr/sin6_port). Cannot be NULL.
 *
 * @param local_addr Pointer to union all_addr containing the destination address where
 *                   dnsmasq received the query (local interface address). Must contain
 *                   valid addr4 (IPv4) or addr6 (IPv6) matching the family in peer_addr.
 *                   Cannot be NULL.
 *
 * @param istcp Integer flag indicating protocol: non-zero for TCP connections (IPPROTO_TCP),
 *              zero for UDP connections (IPPROTO_UDP). Used to set ATTR_L4PROTO in
 *              conntrack query.
 *
 * @param markp Pointer to unsigned int where the retrieved firewall mark will be stored.
 *              If conntrack entry is found and contains a mark, the ATTR_MARK value is
 *              written to *markp via the callback function. If query fails or no entry
 *              found, value is unchanged. Cannot be NULL.
 *
 * @return Integer indicating success/failure of conntrack mark retrieval:
 * @retval 1 Success - conntrack entry found and mark retrieved to *markp
 * @retval 0 Failure - no conntrack entry found, conntrack access error, or resource
 *           allocation failure (nfct_new() or nfct_open() failed)
 *
 * @note Requires CAP_NET_ADMIN capability to access netfilter conntrack table. Without
 *       this capability, nfct_open() or nfct_query() will fail with permission denied.
 *       Typically dnsmasq drops to unprivileged user after initialization, so conntrack
 *       functionality may only be available if dnsmasq retains CAP_NET_ADMIN or runs
 *       as root (not recommended for security).
 *
 * @warning First failure to access conntrack logs error message via my_syslog(), but
 *          subsequent failures are silently ignored (warned flag prevents log spam).
 *          Memory allocation failures (nfct_new() returns NULL) are silent.
 *
 * @see callback() for conntrack query result processing and mark extraction
 * @see forward.c reply_query() which calls get_incoming_mark() to retrieve mark before
 *      forwarding queries upstream
 *
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr;
 * union all_addr dest_addr;
 * unsigned int conntrack_mark = 0;
 * int tcp_query = 0;
 * 
 * if (get_incoming_mark(&client_addr, &dest_addr, tcp_query, &conntrack_mark))
 *   setsockopt(upstream_fd, SOL_SOCKET, SO_MARK, &conntrack_mark, sizeof(conntrack_mark));
 * @endcode
 *
 * RFC COMPLIANCE:
 * Linux Netfilter conntrack API (libnetfilter_conntrack library). Not based on IETF
 * RFC but follows Linux kernel netfilter conntrack subsystem API conventions.
 *
 * SIDE EFFECTS:
 * - Netlink socket I/O to kernel conntrack subsystem via nfct_query()
 * - Allocates and frees nf_conntrack structure and nfct_handle
 * - May log error message to syslog on first conntrack access failure
 * - Sets global static variable gotit (reset at start, set by callback)
 *
 * THREAD SAFETY:
 * Re-entrant with respect to conntrack handle creation (each call creates separate
 * handle). NOT thread-safe due to static gotit variable used for callback signaling.
 * Safe in dnsmasq's single-threaded event-driven architecture.
 */
int get_incoming_mark(union mysockaddr *peer_addr, union all_addr *local_addr, int istcp, unsigned int *markp)
{
  struct nf_conntrack *ct;
  struct nfct_handle *h;
  
  gotit = 0;
  
  if ((ct = nfct_new())) 
    {
      nfct_set_attr_u8(ct, ATTR_L4PROTO, istcp ? IPPROTO_TCP : IPPROTO_UDP);
      nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(daemon->port));
      
      if (peer_addr->sa.sa_family == AF_INET6)
	{
	  nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
	  nfct_set_attr(ct, ATTR_IPV6_SRC, peer_addr->in6.sin6_addr.s6_addr);
	  nfct_set_attr_u16(ct, ATTR_PORT_SRC, peer_addr->in6.sin6_port);
	  nfct_set_attr(ct, ATTR_IPV6_DST, local_addr->addr6.s6_addr);
	}
      else
	{
	  nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
	  nfct_set_attr_u32(ct, ATTR_IPV4_SRC, peer_addr->in.sin_addr.s_addr);
	  nfct_set_attr_u16(ct, ATTR_PORT_SRC, peer_addr->in.sin_port);
	  nfct_set_attr_u32(ct, ATTR_IPV4_DST, local_addr->addr4.s_addr);
	}
      
      
      if ((h = nfct_open(CONNTRACK, 0))) 
	{
	  nfct_callback_register(h, NFCT_T_ALL, callback, (void *)markp);  
	  if (nfct_query(h, NFCT_Q_GET, ct) == -1)
	    {
	      static int warned = 0;
	      if (!warned)
		{
		  my_syslog(LOG_ERR, _("Conntrack connection mark retrieval failed: %s"), strerror(errno));
		  warned = 1;
		}
	    }
	  nfct_close(h);  
	}
      nfct_destroy(ct);
    }

  return gotit;
}

/**
 * @brief Conntrack query callback to extract firewall mark from conntrack entry
 *
 * @detailed
 * Callback function registered with nfct_callback_register() and invoked by
 * libnetfilter_conntrack library when a matching conntrack entry is found during
 * nfct_query(NFCT_Q_GET) operation. Extracts the ATTR_MARK (firewall mark) value
 * from the conntrack entry and stores it in the caller-provided location, then
 * sets the gotit flag to signal successful retrieval to get_incoming_mark().
 *
 * The callback signature is defined by libnetfilter_conntrack API requirements
 * (nfct_callback type). The type parameter is required by the API but unused in
 * this implementation since we only handle NFCT_Q_GET queries which return a
 * single result.
 *
 * @param type Message type from enum nf_conntrack_msg_type (e.g., NFCT_T_NEW,
 *             NFCT_T_UPDATE, NFCT_T_DESTROY). Parameter required by API but unused
 *             in this implementation (explicitly voided to eliminate compiler warnings).
 *
 * @param ct Pointer to struct nf_conntrack representing the conntrack table entry
 *           found by nfct_query(). Contains all conntrack attributes including
 *           ATTR_MARK. Managed by libnetfilter_conntrack library, must not be freed
 *           by callback. Cannot be NULL when callback is invoked.
 *
 * @param data Opaque user data pointer passed through from nfct_callback_register().
 *             Expected to be pointer to unsigned int (unsigned int *) where the
 *             extracted mark should be stored. Cast from void* to unsigned int*
 *             within function. Cannot be NULL.
 *
 * @return Return value for libnetfilter_conntrack callback API:
 * @retval NFCT_CB_CONTINUE Always returned. Instructs library to continue processing
 *                          (though for NFCT_Q_GET single-entry queries, no further
 *                          processing occurs after first callback).
 *
 * @note Callback is invoked in the context of nfct_query() call from get_incoming_mark().
 *       Not invoked directly by user code.
 *
 * @warning Assumes data pointer is valid unsigned int* as passed from get_incoming_mark().
 *          No NULL checking or type validation performed (safe because caller controls
 *          the data pointer).
 *
 * @see get_incoming_mark() which registers this callback and provides the markp pointer
 *      as the data parameter
 *
 * EXAMPLE USAGE:
 * @code
 * // Called internally by libnetfilter_conntrack, not directly invoked
 * unsigned int mark_storage;
 * nfct_callback_register(handle, NFCT_T_ALL, callback, (void *)&mark_storage);
 * nfct_query(handle, NFCT_Q_GET, conntrack_entry);
 * // callback extracts mark to mark_storage
 * @endcode
 *
 * RFC COMPLIANCE:
 * Linux libnetfilter_conntrack callback API. Follows callback signature requirements
 * defined by libnetfilter_conntrack library documentation.
 *
 * SIDE EFFECTS:
 * - Writes firewall mark value to caller-provided unsigned int via data pointer
 * - Sets global static variable gotit to 1 to signal successful extraction
 * - No dynamic memory allocation or I/O operations
 *
 * THREAD SAFETY:
 * Not thread-safe due to modification of static gotit variable. Safe in single-threaded
 * dnsmasq event loop. Invoked synchronously within get_incoming_mark() call context.
 */
static int callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
  unsigned int *ret = (unsigned int *)data;
  *ret = nfct_get_attr_u32(ct, ATTR_MARK);
  (void)type; /* eliminate warning */
  gotit = 1;

  return NFCT_CB_CONTINUE;
}

#endif /* HAVE_CONNTRACK */
