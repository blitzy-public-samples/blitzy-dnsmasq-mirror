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
 * @file forward.c
 * @brief DNS query forwarding and upstream server management
 *
 * DETAILED PURPOSE:
 * This module implements the complete DNS query forwarding pipeline for dnsmasq,
 * handling query reception from network listeners, cache integration, upstream 
 * server selection with health tracking, and response processing. It manages the
 * lifecycle of forward records (frec) that track DNS transaction state from query
 * reception through upstream transmission to response delivery. The module implements
 * critical security features including query ID and source port randomization to
 * prevent cache poisoning attacks, EDNS0 extension handling, DNSSEC DO bit propagation,
 * and TCP fallback on truncation. Query retry logic with exponential backoff and
 * server rotation ensures reliability when upstream servers fail or timeout.
 *
 * KEY RESPONSIBILITIES:
 * - receive_query() - Main DNS query entry point from network layer listeners
 * - forward_query() - Upstream server selection and query transmission with randomization
 * - reply_query() - Process upstream responses, cache results, forward to clients
 * - retry_send() - Implement query retry with server rotation on failures
 * - get_new_frec() - Allocate forward records from freelist for transaction tracking
 * - free_frec() - Return forward records to freelist after transaction completion
 * - tcp_request() - Handle TCP-based DNS queries for responses exceeding UDP limits
 * - send_from() - Send UDP packets with explicit source address for multi-homed hosts
 *
 * DEPENDENCIES:
 * - Includes: dnsmasq.h (core type definitions: struct frec, struct server, struct dns_header)
 * - Called by: Event loop in dnsmasq.c when DNS socket becomes readable
 * - Calls: cache.c (cache_lookup, cache_insert), rfc1035.c (extract_request, setup_reply),
 *          network.c (socket management), dnssec.c (dnssec_validate when HAVE_DNSSEC)
 *
 * DATA STRUCTURES:
 * - struct frec (dnsmasq.h:~350-400) - Forward record tracking transaction state: source/dest
 *   addresses, original/randomized query IDs, upstream server pointer, DNSSEC flags, hash
 * - struct server (dnsmasq.h:~400-450) - Upstream DNS server with address, query counters,
 *   failure tracking, health metrics for server selection
 * - struct randfd_list - Random file descriptor pool for source port randomization
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC: Enables dependent query handling for DNSSEC validation, trust anchor
 *   validation, DS record lookups (affects forward_query, dnssec_validate functions)
 * - HAVE_CONNTRACK: Enables connection mark propagation for netfilter integration
 * - HAVE_IPSET/HAVE_NFTSET: Enables domain-based ipset/nftables set population on response
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture using poll(). All DNS query processing occurs
 * in the main event loop thread. No multi-threading or concurrent access to forward records.
 * Forward record allocation is not thread-safe but this is acceptable in single-threaded
 * model. Signal handlers use self-pipe pattern to queue events safely.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DNS_FORWARDING.md for complete DNS forwarding pipeline documentation
 * @see docs/ARCHITECTURE.md for event-driven architecture explanation
 */

#include "dnsmasq.h"

static struct frec *get_new_frec(time_t now, struct server *serv, int force);
static struct frec *lookup_frec(unsigned short id, int fd, void *hash, int *firstp, int *lastp);
static struct frec *lookup_frec_by_query(void *hash, unsigned int flags, unsigned int flagmask);
#ifdef HAVE_DNSSEC
static struct frec *lookup_frec_dnssec(char *target, int class, int flags, struct dns_header *header);
#endif

static unsigned short get_id(void);
static void free_frec(struct frec *f);
static void query_full(time_t now, char *domain);

static void return_reply(time_t now, struct frec *forward, struct dns_header *header, ssize_t n, int status);

/**
 * @brief Send UDP packet with explicit source address for multi-homed hosts
 *
 * @detailed Transmits a UDP packet using sendmsg() with ancillary data to specify
 * the source IP address, enabling dnsmasq to respond from the same address that
 * received the query on multi-homed systems. Platform-specific handling for Linux
 * (IP_PKTINFO), BSD (IP_SENDSRCADDR), and IPv6 (IPV6_PKTINFO). Implements retry
 * logic for EINTR via retry_send() macro.
 *
 * @param fd File descriptor of UDP socket to send on
 * @param nowild If true, use kernel default source address; if false, set explicit source
 * @param packet Pointer to DNS packet buffer to transmit
 * @param len Length of packet data in bytes
 * @param to Destination socket address (includes IP and port)
 * @param source Source IP address to use (union all_addr with addr4/addr6)
 * @param iface Interface index for IPv6 link-local addresses (0 for IPv4)
 *
 * @return 1 on successful transmission, 0 on error
 *
 * @note Uses platform-specific control message formats: Linux IP_PKTINFO with
 * ipi_spec_dst, BSD IP_SENDSRCADDR, IPv6 IPV6_PKTINFO with ipi6_addr and ipi6_ifindex
 * @warning On Linux, EINVAL errors during interface DAD (Duplicate Address Detection)
 * are suppressed; other sendmsg errors are logged
 * @see receive_query() which determines source address from listener configuration
 *
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr dest;
 * union all_addr src_addr;
 * char dns_packet[512];
 * int sent = send_from(udp_fd, 0, dns_packet, packet_len, &dest, &src_addr, 0);
 * if (!sent) handle_send_error();
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies errno on sendmsg() failure
 * - Logs error messages via my_syslog() on non-EINVAL errors (Linux only)
 *
 * THREAD SAFETY:
 * Not thread-safe (modifies shared errno). Safe in single-threaded event loop.
 */
/* Send a UDP packet with its source address set as "source" 
   unless nowild is true, when we just send it with the kernel default */
int send_from(int fd, int nowild, char *packet, size_t len, 
	      union mysockaddr *to, union all_addr *source,
	      unsigned int iface)
{
  struct msghdr msg;
  struct iovec iov[1]; 
  union {
    struct cmsghdr align; /* this ensures alignment */
#if defined(HAVE_LINUX_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(IP_SENDSRCADDR)
    char control[CMSG_SPACE(sizeof(struct in_addr))];
#endif
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_u;
  
  iov[0].iov_base = packet;
  iov[0].iov_len = len;

  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  msg.msg_name = to;
  msg.msg_namelen = sa_len(to);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  if (!nowild)
    {
      struct cmsghdr *cmptr;
      msg.msg_control = &control_u;
      msg.msg_controllen = sizeof(control_u);
      cmptr = CMSG_FIRSTHDR(&msg);

      if (to->sa.sa_family == AF_INET)
	{
#if defined(HAVE_LINUX_NETWORK)
	  struct in_pktinfo p;
	  p.ipi_ifindex = 0;
	  p.ipi_spec_dst = source->addr4;
	  msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
	  memcpy(CMSG_DATA(cmptr), &p, sizeof(p));
	  cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	  cmptr->cmsg_level = IPPROTO_IP;
	  cmptr->cmsg_type = IP_PKTINFO;
#elif defined(IP_SENDSRCADDR)
	  msg.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
	  memcpy(CMSG_DATA(cmptr), &(source->addr4), sizeof(source->addr4));
	  cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
	  cmptr->cmsg_level = IPPROTO_IP;
	  cmptr->cmsg_type = IP_SENDSRCADDR;
#endif
	}
      else
	{
	  struct in6_pktinfo p;
	  p.ipi6_ifindex = iface; /* Need iface for IPv6 to handle link-local addrs */
	  p.ipi6_addr = source->addr6;
	  msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	  memcpy(CMSG_DATA(cmptr), &p, sizeof(p));
	  cmptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	  cmptr->cmsg_type = daemon->v6pktinfo;
	  cmptr->cmsg_level = IPPROTO_IPV6;
	}
    }
  
  while (retry_send(sendmsg(fd, &msg, 0)));

  if (errno != 0)
    {
#ifdef HAVE_LINUX_NETWORK
      /* If interface is still in DAD, EINVAL results - ignore that. */
      if (errno != EINVAL)
	my_syslog(LOG_ERR, _("failed to send packet: %s"), strerror(errno));
#endif
      return 0;
    }
  
  return 1;
}
          
#ifdef HAVE_CONNTRACK
/**
 * @brief Copy netfilter connection mark from incoming query to outgoing connection
 *
 * @detailed Propagates connection tracking marks from client queries to upstream
 * server connections, enabling firewall rules and traffic shaping policies to apply
 * consistently through the DNS forwarding path. Only compiled when HAVE_CONNTRACK
 * is defined for Linux netfilter integration.
 *
 * @param forward Forward record containing source/dest addresses of original query
 * @param fd File descriptor of socket for outgoing upstream query
 *
 * @note Requires CAP_NET_ADMIN capability to set SO_MARK socket option
 * @note Silent failure if get_incoming_mark() returns false (no mark found)
 * @warning Linux-specific, depends on netfilter conntrack kernel module
 * @see allocate_rfd() where this is called during socket setup for upstream queries
 *
 * EXAMPLE USAGE:
 * @code
 * int upstream_fd = socket(AF_INET, SOCK_DGRAM, 0);
 * set_outgoing_mark(forward, upstream_fd);
 * // Now upstream_fd inherits connection mark from client query
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies socket option SO_MARK on fd (persistent until socket close)
 * - No effect if get_incoming_mark() fails to retrieve mark
 *
 * THREAD SAFETY:
 * Thread-safe (no shared state modified), safe in single-threaded model.
 */
static void set_outgoing_mark(struct frec *forward, int fd)
{
  /* Copy connection mark of incoming query to outgoing connection. */
  unsigned int mark;
  if (get_incoming_mark(&forward->frec_src.source, &forward->frec_src.dest, 0, &mark))
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(unsigned int));
}
#endif

/**
 * @brief Log DNS query or response with socket address extraction
 *
 * @detailed Wrapper around log_query() that extracts IP address and port from
 * union mysockaddr, handling both IPv4 and IPv6 address families. Automatically
 * sets F_IPV4 or F_IPV6 flag based on sa_family. For server logging (F_SERVER flag),
 * extracts port number and uses as type parameter for server identification.
 *
 * @param flags Logging flags (F_SERVER, F_FORWARD, F_REVERSE, etc.)
 * @param name Domain name being queried (null-terminated string)
 * @param addr Socket address containing IP and port (AF_INET or AF_INET6)
 * @param arg Additional argument string for logging context (may be NULL)
 * @param type DNS query type (A, AAAA, etc.) or port if flags & F_SERVER
 *
 * @note For F_SERVER logging, type parameter is replaced with port from addr
 * @note Automatically adds F_IPV4 or F_IPV6 to flags based on address family
 * @see log_query() in log.c for actual logging implementation
 * @see forward_query() which uses this to log upstream server selection
 *
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr upstream_addr;
 * log_query_mysockaddr(F_SERVER | F_FORWARD, "example.com", &upstream_addr, NULL, T_A);
 * // Logs query forwarded to server at upstream_addr
 * @endcode
 *
 * SIDE EFFECTS:
 * - Writes to query log if query logging enabled
 * - No state modifications
 *
 * THREAD SAFETY:
 * Thread-safe (read-only access to addr), safe in single-threaded model.
 */
static void log_query_mysockaddr(unsigned int flags, char *name, union mysockaddr *addr, char *arg, unsigned short type)
{
  if (addr->sa.sa_family == AF_INET)
    {
      if (flags & F_SERVER)
	type = ntohs(addr->in.sin_port);
      log_query(flags | F_IPV4, name, (union all_addr *)&addr->in.sin_addr, arg, type);
    }
  else
    {
      if (flags & F_SERVER)
	type = ntohs(addr->in6.sin6_port);
      log_query(flags | F_IPV6, name, (union all_addr *)&addr->in6.sin6_addr, arg, type);
    }
}

/**
 * @brief Send DNS query packet to upstream server with retry on EINTR
 *
 * @detailed Transmits DNS packet to upstream server using sendto() with automatic
 * retry on EINTR (interrupted system call). Wrapper function providing consistent
 * transmission interface for upstream server communication. Uses server's configured
 * address from struct server.
 *
 * @param server Upstream DNS server containing destination address
 * @param fd Socket file descriptor to send on (UDP or TCP)
 * @param header Pointer to DNS packet header and data
 * @param plen Packet length in bytes including DNS header
 * @param flags sendto() flags parameter (typically 0 for UDP, MSG_NOSIGNAL for TCP)
 *
 * @note Blocks until sendto() succeeds or fails with non-EINTR error
 * @note Does not check return value; assumes sendto() will eventually succeed
 * @warning Silent on sendto() errors other than EINTR; caller should check errno
 * @see retry_send() macro which implements EINTR retry logic
 * @see forward_query() which calls this for upstream transmission
 *
 * EXAMPLE USAGE:
 * @code
 * struct server *upstream = select_server();
 * struct dns_header *header = build_query();
 * server_send(upstream, udp_fd, header, query_len, 0);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Transmits packet on network (UDP datagram or TCP segment)
 * - Modifies errno on sendto() failure
 *
 * THREAD SAFETY:
 * Not thread-safe (uses errno). Safe in single-threaded event loop.
 */
static void server_send(struct server *server, int fd,
			const void *header, size_t plen, int flags)
{
  while (retry_send(sendto(fd, header, plen, flags,
			   &server->addr.sa,
			   sa_len(&server->addr))));
}

/**
 * @brief Check if domain is exempt from DNS rebinding protection
 *
 * @detailed Tests whether a domain name matches any entry in the no-rebind exception
 * list (--rebind-domain-ok configuration option). DNS rebinding protection blocks
 * responses containing private IP addresses to prevent rebinding attacks. This function
 * identifies domains that should bypass this protection. Matches whole DNS labels only
 * using suffix comparison. Empty domain in list matches any single-label name (no dots).
 *
 * @param domain Null-terminated domain name to check (e.g., "example.com")
 *
 * @return 1 if domain is exempt from rebinding protection, 0 otherwise
 *
 * @note Matches domain suffixes: "example.com" matches "www.example.com" and "example.com"
 * @note Empty domain in list matches single-label names like "localhost" or "router"
 * @note Uses case-insensitive comparison via hostname_isequal()
 * @see process_reply() which calls this to check rebinding protection applicability
 * @see struct rebind_domain in daemon->no_rebind list
 *
 * EXAMPLE USAGE:
 * @code
 * if (is_private_address(&reply_addr) && !domain_no_rebind("internal.example.com"))
 *   block_response(); // Apply rebinding protection
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements DNS rebinding attack mitigation, not defined by specific RFC but
 * widely recognized security practice for DNS forwarders.
 *
 * SIDE EFFECTS:
 * - Read-only access to daemon->no_rebind list
 * - No modifications to state
 *
 * THREAD SAFETY:
 * Thread-safe (read-only), safe in single-threaded model.
 */
static int domain_no_rebind(char *domain)
{
  struct rebind_domain *rbd;
  size_t tlen, dlen = strlen(domain);
  char *dots = strchr(domain, '.');

  /* Match whole labels only. Empty domain matches no dots (any single label) */
  for (rbd = daemon->no_rebind; rbd; rbd = rbd->next)
    {
      if (dlen >= (tlen = strlen(rbd->domain)) &&
	hostname_isequal(rbd->domain, &domain[dlen - tlen]) &&
	(dlen == tlen || domain[dlen - tlen - 1] == '.'))
      return 1;

      if (tlen == 0 && !dots)
	return 1;
    }
  
  return 0;
}

/**
 * @brief Forward DNS query to upstream server with server selection and randomization
 *
 * @detailed Core DNS forwarding function implementing upstream server selection algorithm,
 * query ID randomization for cache poisoning prevention, source port randomization, EDNS0
 * handling, and DNSSEC DO bit propagation. Manages forward record (frec) allocation or
 * reuse for existing queries, handles duplicate queries from multiple clients, implements
 * server filtering based on domain rules, and supports TCP fallback. Integrates with cache
 * to check for local answers before forwarding. Implements retry detection and query
 * aggregation where multiple clients asking same question share single upstream query.
 *
 * @param udpfd UDP socket file descriptor for sending to upstream
 * @param udpaddr Socket address of client that sent query
 * @param dst_addr Destination address where query was received (for multi-homed)
 * @param dst_iface Interface index where query was received
 * @param header DNS packet header containing query
 * @param plen Packet length in bytes
 * @param limit Pointer to end of packet buffer (for bounds checking)
 * @param now Current time for timestamp tracking
 * @param forward Existing forward record if retry, NULL for new query
 * @param ad_reqd Client requested Authenticated Data (AD bit)
 * @param do_bit Client set DNSSEC OK (DO bit) in EDNS0
 *
 * @return 1 if query was forwarded or answered locally, 0 on error
 *
 * @retval 1 Query forwarded to upstream or answered from cache/local
 * @retval 0 Forward record allocation failed or query should be dropped
 *
 * @note Randomizes query ID (original stored in frec->orig_id) to prevent cache poisoning
 * @note Aggregates duplicate queries: multiple clients with same question wait for one upstream query
 * @note Applies server selection filters based on --server=domain configuration
 * @note Preserves CD (Checking Disabled) and AD (Authentic Data) request flags
 * @warning Silently drops queries when forward record table exhausted (logs "Maximum number of concurrent DNS queries reached")
 * @warning Blocks private IP responses unless domain in rebind exception list
 *
 * @see receive_query() which calls this after cache miss
 * @see reply_query() which processes upstream responses
 * @see get_new_frec() for forward record allocation
 * @see lookup_frec_by_query() for duplicate query detection
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * int result = forward_query(udp_fd, &client_addr, &listen_addr, if_index,
 *                            header, packet_len, packet + packet_len, time(NULL),
 *                            NULL, ad_requested, do_bit_set);
 * if (result) query_forwarded_successfully();
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 1035: DNS query forwarding with ID randomization
 * - RFC 2671: EDNS0 extension handling (OPT record preservation)
 * - RFC 3225: DO bit (DNSSEC OK) propagation when HAVE_DNSSEC enabled
 * - RFC 6891: EDNS0 extensions including client subnet
 *
 * SIDE EFFECTS:
 * - Allocates forward record from freelist via get_new_frec()
 * - Randomizes query ID in header (modifies header->id)
 * - May send REFUSED response directly to client if table full
 * - Updates server query statistics (server->queries_sent)
 * - Logs query forwarding via log_query()
 *
 * THREAD SAFETY:
 * Not thread-safe (modifies shared daemon state, forward record table).
 * Safe in single-threaded event loop model.
 */
static int forward_query(int udpfd, union mysockaddr *udpaddr,
			 union all_addr *dst_addr, unsigned int dst_iface,
			 struct dns_header *header, size_t plen,  char *limit, time_t now, 
			 struct frec *forward, int ad_reqd, int do_bit)
{
  unsigned int flags = 0;
  unsigned int fwd_flags = 0;
  int is_dnssec = forward && (forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY));
  struct server *master;
  void *hash = hash_questions(header, plen, daemon->namebuff);
  unsigned int gotname = extract_request(header, plen, daemon->namebuff, NULL);
  unsigned char *oph = find_pseudoheader(header, plen, NULL, NULL, NULL, NULL);
  int old_src = 0, old_reply = 0;
  int first, last, start = 0;
  int cacheable, forwarded = 0;
  size_t edns0_len;
  unsigned char *pheader;
  int ede = EDE_UNSET;
  (void)do_bit;
  
  if (header->hb4 & HB4_CD)
    fwd_flags |= FREC_CHECKING_DISABLED;
  if (ad_reqd)
    fwd_flags |= FREC_AD_QUESTION;
  if (oph)
    fwd_flags |= FREC_HAS_PHEADER;
#ifdef HAVE_DNSSEC
  if (do_bit)
    fwd_flags |= FREC_DO_QUESTION;
#endif
  
  /* Check for retry on existing query.
     FREC_DNSKEY and FREC_DS_QUERY are never set in flags, so the test below 
     ensures that no frec created for internal DNSSEC query can be returned here.
     
     Similarly FREC_NO_CACHE is never set in flags, so a query which is
     contigent on a particular source address EDNS0 option will never be matched. */
  if (forward)
    {
      old_src = 1;
      old_reply = 1;
    }
  else if ((forward = lookup_frec_by_query(hash, fwd_flags,
					   FREC_CHECKING_DISABLED | FREC_AD_QUESTION | FREC_DO_QUESTION |
					   FREC_HAS_PHEADER | FREC_DNSKEY_QUERY | FREC_DS_QUERY | FREC_NO_CACHE)))
    {
      struct frec_src *src;
      
      for (src = &forward->frec_src; src; src = src->next)
	if (src->orig_id == ntohs(header->id) && 
	    sockaddr_isequal(&src->source, udpaddr))
	  break;
      
      if (src)
	{
	  old_src = 1;
	  /* If a query is retried, use the log_id for the retry when logging the answer. */
	  src->log_id = daemon->log_id;
	}
      else
	{
	  /* Existing query, but from new source, just add this 
	     client to the list that will get the reply.*/
	  
	  /* Note whine_malloc() zeros memory. */
	  if (!daemon->free_frec_src &&
	      daemon->frec_src_count < daemon->ftabsize &&
	      (daemon->free_frec_src = whine_malloc(sizeof(struct frec_src))))
	    {
	      daemon->frec_src_count++;
	      daemon->free_frec_src->next = NULL;
	    }
	  
	  /* If we've been spammed with many duplicates, return REFUSED. */
	  if (!daemon->free_frec_src)
	    {
	      query_full(now, NULL);
	      goto reply;
	    }
	  
	  src = daemon->free_frec_src;
	  daemon->free_frec_src = src->next;
	  src->next = forward->frec_src.next;
	  forward->frec_src.next = src;
	  src->orig_id = ntohs(header->id);
	  src->source = *udpaddr;
	  src->dest = *dst_addr;
	  src->log_id = daemon->log_id;
	  src->iface = dst_iface;
	  src->fd = udpfd;

	  /* closely spaced identical queries cannot be a try and a retry, so
	     it's safe to wait for the reply from the first without
	     forwarding the second. */
	  if (difftime(now, forward->time) < 2)
	    return 0;
	}
    }

  /* new query */
  if (!forward)
    {
      /* If the query is malformed, we can't forward it because
	 we can't get a reliable hash to recognise the answer. */
      if (!hash)
	{
	  flags = 0;
	  ede = EDE_INVALID_DATA;
	  goto reply;
	}
      
      if (lookup_domain(daemon->namebuff, gotname, &first, &last))
	flags = is_local_answer(now, first, daemon->namebuff);
      else
	{
	  /* no available server. */
	  ede = EDE_NOT_READY;
	  flags = 0;
	}
       
      /* don't forward A or AAAA queries for simple names, except the empty name */
      if (!flags &&
	  option_bool(OPT_NODOTS_LOCAL) &&
	  (gotname & (F_IPV4 | F_IPV6)) &&
	  !strchr(daemon->namebuff, '.') &&
	  strlen(daemon->namebuff) != 0)
	flags = check_for_local_domain(daemon->namebuff, now) ? F_NOERR : F_NXDOMAIN;
      
      /* Configured answer. */
      if (flags || ede == EDE_NOT_READY)
	goto reply;
      
      master = daemon->serverarray[first];
      
      if (!(forward = get_new_frec(now, master, 0)))
	goto reply;
      /* table full - flags == 0, return REFUSED */
      
      forward->frec_src.log_id = daemon->log_id;
      forward->frec_src.source = *udpaddr;
      forward->frec_src.orig_id = ntohs(header->id);
      forward->frec_src.dest = *dst_addr;
      forward->frec_src.iface = dst_iface;
      forward->frec_src.next = NULL;
      forward->frec_src.fd = udpfd;
      forward->new_id = get_id();
      memcpy(forward->hash, hash, HASH_SIZE);
      forward->forwardall = 0;
      forward->flags = fwd_flags;
      if (domain_no_rebind(daemon->namebuff))
	forward->flags |= FREC_NOREBIND;
      if (header->hb4 & HB4_CD)
	forward->flags |= FREC_CHECKING_DISABLED;
      if (ad_reqd)
	forward->flags |= FREC_AD_QUESTION;
#ifdef HAVE_DNSSEC
      forward->work_counter = DNSSEC_WORK;
      if (do_bit)
	forward->flags |= FREC_DO_QUESTION;
#endif
      
      start = first;

      if (option_bool(OPT_ALL_SERVERS))
	forward->forwardall = 1;

      if (!option_bool(OPT_ORDER))
	{
	  if (master->forwardcount++ > FORWARD_TEST ||
	      difftime(now, master->forwardtime) > FORWARD_TIME ||
	      master->last_server == -1)
	    {
	      master->forwardtime = now;
	      master->forwardcount = 0;
	      forward->forwardall = 1;
	    }
	  else
	    start = master->last_server;
	}
    }
  else
    {
#ifdef HAVE_DNSSEC
      /* If we've already got an answer to this query, but we're awaiting keys for validation,
	 there's no point retrying the query, retry the key query instead...... */
      if (forward->blocking_query)
	{
	  int is_sign;
	  unsigned char *pheader;
	  
	  while (forward->blocking_query)
	    forward = forward->blocking_query;

	  /* log_id should match previous DNSSEC query. */
	  daemon->log_display_id = forward->frec_src.log_id;
	  
	  blockdata_retrieve(forward->stash, forward->stash_len, (void *)header);
	  plen = forward->stash_len;
	  /* get query for logging. */
	  extract_request(header, plen, daemon->namebuff, NULL);
	  
	  if (find_pseudoheader(header, plen, NULL, &pheader, &is_sign, NULL) && !is_sign)
	    PUTSHORT(SAFE_PKTSZ, pheader);
	  
	  /* Find suitable servers: should never fail. */
	  if (!filter_servers(forward->sentto->arrayposn, F_DNSSECOK, &first, &last))
	    return 0;
	  
	  is_dnssec = 1;
	  forward->forwardall = 1;
	}
      else
#endif
	{
	  /* retry on existing query, from original source. Send to all available servers  */
	  forward->sentto->failed_queries++;
	  
	  if (!filter_servers(forward->sentto->arrayposn, F_SERVER, &first, &last))
	    goto reply;
	  
	  master = daemon->serverarray[first];
	  
	  /* Forward to all available servers on retry of query from same host. */
	  if (!option_bool(OPT_ORDER) && old_src)
	    forward->forwardall = 1;
	  else
	    {
	      start = forward->sentto->arrayposn;
	      
	      if (option_bool(OPT_ORDER))
		{
		  /* In strict order mode, there must be a server later in the list
		     left to send to, otherwise without the forwardall mechanism,
		     code further on will cycle around the list forwever if they
		     all return REFUSED. If at the last, give up.
		     Note that we can get here EITHER because a client retried,
		     or an upstream server returned REFUSED. The above only
		     applied in the later case. For client retries,
		     keep trying the last server.. */
		  if (++start == last)
		    {
		      if (old_reply)
			goto reply;
		      else
			start--;
		    }
		}
	    }	  
	}
      
      /* If we didn't get an answer advertising a maximal packet in EDNS,
	 fall back to 1280, which should work everywhere on IPv6.
	 If that generates an answer, it will become the new default
	 for this server */
      forward->flags |= FREC_TEST_PKTSZ;
    }

  /* We may be resending a DNSSEC query here, for which the below processing is not necessary. */
  if (!is_dnssec)
    {
      header->id = htons(forward->new_id);
      
      plen = add_edns0_config(header, plen, ((unsigned char *)header) + PACKETSZ, &forward->frec_src.source, now, &cacheable);
      
      if (!cacheable)
	forward->flags |= FREC_NO_CACHE;
      
#ifdef HAVE_DNSSEC
      if (option_bool(OPT_DNSSEC_VALID) && (master->flags & SERV_DO_DNSSEC))
	{
	  plen = add_do_bit(header, plen, ((unsigned char *) header) + PACKETSZ);
	  
	  /* For debugging, set Checking Disabled, otherwise, have the upstream check too,
	     this allows it to select auth servers when one is returning bad data. */
	  if (option_bool(OPT_DNSSEC_DEBUG))
	    header->hb4 |= HB4_CD;
	  
	}
#endif
      
      if (find_pseudoheader(header, plen, &edns0_len, &pheader, NULL, NULL))
	{
	  /* If there wasn't a PH before, and there is now, we added it. */
	  if (!oph)
	    forward->flags |= FREC_ADDED_PHEADER;
	  
	  /* If we're sending an EDNS0 with any options, we can't recreate the query from a reply. */
	  if (edns0_len > 11)
	    forward->flags |= FREC_HAS_EXTRADATA;
	  
	  /* Reduce udp size on retransmits. */
	  if (forward->flags & FREC_TEST_PKTSZ)
	    PUTSHORT(SAFE_PKTSZ, pheader);
	}
    }
  
  if (forward->forwardall)
    start = first;

  forwarded = 0;
  
  /* check for send errors here (no route to host) 
     if we fail to send to all nameservers, send back an error
     packet straight away (helps modem users when offline)  */

  while (1)
    { 
      int fd;
      struct server *srv = daemon->serverarray[start];
      
      if ((fd = allocate_rfd(&forward->rfds, srv)) != -1)
	{
	  
#ifdef HAVE_CONNTRACK
	  /* Copy connection mark of incoming query to outgoing connection. */
	  if (option_bool(OPT_CONNTRACK))
	    set_outgoing_mark(forward, fd);
#endif
	  
#ifdef HAVE_DNSSEC
	  if (option_bool(OPT_DNSSEC_VALID) && (forward->flags & FREC_ADDED_PHEADER))
	    {
	      /* Difficult one here. If our client didn't send EDNS0, we will have set the UDP
		 packet size to 512. But that won't provide space for the RRSIGS in many cases.
		 The RRSIGS will be stripped out before the answer goes back, so the packet should
		 shrink again. So, if we added a do-bit, bump the udp packet size to the value
		 known to be OK for this server. We check returned size after stripping and set
		 the truncated bit if it's still too big. */		  
	      unsigned char *pheader;
	      int is_sign;
	      if (find_pseudoheader(header, plen, NULL, &pheader, &is_sign, NULL) && !is_sign)
		PUTSHORT(srv->edns_pktsz, pheader);
	    }
#endif
	  
	  if (retry_send(sendto(fd, (char *)header, plen, 0,
				&srv->addr.sa,
				sa_len(&srv->addr))))
	    continue;
	  
	  if (errno == 0)
	    {
#ifdef HAVE_DUMPFILE
	      dump_packet(DUMP_UP_QUERY, (void *)header, plen, NULL, &srv->addr, daemon->port);
#endif
	      
	      /* Keep info in case we want to re-send this packet */
	      daemon->srv_save = srv;
	      daemon->packet_len = plen;
	      daemon->fd_save = fd;
	      
	      if (!(forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)))
		{
		  if (!gotname)
		    strcpy(daemon->namebuff, "query");
		  log_query_mysockaddr(F_SERVER | F_FORWARD, daemon->namebuff,
				       &srv->addr, NULL, 0);
		}
#ifdef HAVE_DNSSEC
	      else
		log_query_mysockaddr(F_NOEXTRA | F_DNSSEC | F_SERVER, daemon->namebuff, &srv->addr,
				     (forward->flags & FREC_DNSKEY_QUERY) ? "dnssec-retry[DNSKEY]" : "dnssec-retry[DS]", 0);
#endif

	      srv->queries++;
	      forwarded = 1;
	      forward->sentto = srv;
	      if (!forward->forwardall) 
		break;
	      forward->forwardall++;
	    }
	}
      
      if (++start == last)
	break;
    }
  
  if (forwarded || is_dnssec)
    return 1;
  
  /* could not send on, prepare to return */ 
  header->id = htons(forward->frec_src.orig_id);
  free_frec(forward); /* cancel */
  ede = EDE_NETERR;
  
 reply:
  if (udpfd != -1)
    {
      if (!(plen = make_local_answer(flags, gotname, plen, header, daemon->namebuff, limit, first, last, ede)))
	return 0;
      
      if (oph)
	{
	  u16 swap = htons((u16)ede);

	  if (ede != EDE_UNSET)
	    plen = add_pseudoheader(header, plen, (unsigned char *)limit, daemon->edns_pktsz, EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, do_bit, 0);
	  else
	    plen = add_pseudoheader(header, plen, (unsigned char *)limit, daemon->edns_pktsz, 0, NULL, 0, do_bit, 0);
	}
      
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
      if (option_bool(OPT_CMARK_ALST_EN))
	{
	  unsigned int mark;
	  int have_mark = get_incoming_mark(udpaddr, dst_addr, /* istcp: */ 0, &mark);
	  if (have_mark && ((u32)mark & daemon->allowlist_mask))
	    report_addresses(header, plen, mark);
	}
#endif
      
      send_from(udpfd, option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND), (char *)header, plen, udpaddr, dst_addr, dst_iface);
    }
	  
  return 0;
}

/**
 * @brief Find longest matching ipset/nftset configuration for domain
 *
 * @detailed Searches ipset/nftset configuration list for most specific domain match
 * using suffix matching algorithm. Returns ipset entry with longest matching domain
 * suffix, enabling resolved IP addresses to be added to Linux ipset or nftables sets
 * for firewall rules. Empty domain (domainlen==0) matches all domains. Algorithm
 * matches whole DNS labels only (checks for dot separator).
 *
 * @param setlist Head of ipset configuration list to search
 * @param domain Domain name to match (null-terminated, e.g., "www.example.com")
 *
 * @return Pointer to matching struct ipsets with longest suffix match, NULL if no match
 *
 * @note Matches domain suffixes: "example.com" in config matches "www.example.com"
 * @note Uses case-insensitive comparison via hostname_isequal()
 * @note Returns most specific match when multiple entries match
 * @see process_reply() which calls this to determine ipset population on response
 * @see struct ipsets in dnsmasq.h for ipset configuration structure
 *
 * EXAMPLE USAGE:
 * @code
 * struct ipsets *matched = domain_find_sets(daemon->ipsets, "www.example.com");
 * if (matched) add_to_ipset(matched->sets, &resolved_addr);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Read-only traversal of setlist
 * - No state modifications
 *
 * THREAD SAFETY:
 * Thread-safe (read-only), safe in single-threaded model.
 */
static struct ipsets *domain_find_sets(struct ipsets *setlist, const char *domain) {
  /* Similar algorithm to search_servers. */
  struct ipsets *ipset_pos, *ret = NULL;
  unsigned int namelen = strlen(domain);
  unsigned int matchlen = 0;
  for (ipset_pos = setlist; ipset_pos; ipset_pos = ipset_pos->next) 
    {
      unsigned int domainlen = strlen(ipset_pos->domain);
      const char *matchstart = domain + namelen - domainlen;
      if (namelen >= domainlen && hostname_isequal(matchstart, ipset_pos->domain) &&
          (domainlen == 0 || namelen == domainlen || *(matchstart - 1) == '.' ) &&
          domainlen >= matchlen) 
        {
          matchlen = domainlen;
          ret = ipset_pos;
        }
    }

  return ret;
}

/**
 * @brief Process upstream DNS response for caching and client forwarding
 *
 * @detailed Complex response processing pipeline handling EDNS0 stripping/preservation,
 * DNS rebinding protection (blocks private IPs unless domain exempt), ipset/nftset
 * population with resolved addresses, cache insertion with security status, DNSSEC
 * validation integration, response munging (CNAME rewriting), and EDE (Extended DNS
 * Error) code handling. Validates EDNS0 client subnet options match query. Applies
 * filters for bogus responses, truncation, and security status.
 *
 * @param header DNS response packet header
 * @param now Current timestamp for cache TTL calculation
 * @param server Upstream server that provided response
 * @param n Response packet size in bytes
 * @param check_rebind If true, apply DNS rebinding protection to response addresses
 * @param no_cache If true, do not cache this response
 * @param cache_secure Mark cached entry as DNSSEC-validated secure
 * @param bogusanswer Response failed DNSSEC validation (mark as bogus)
 * @param ad_reqd Client requested Authenticated Data bit
 * @param do_bit Client set DNSSEC OK bit in EDNS0
 * @param added_pheader dnsmasq added EDNS0 OPT record not in original query
 * @param query_source Original query source address for EDNS0 client subnet validation
 * @param limit Pointer to end of packet buffer for bounds checking
 * @param ede Extended DNS Error code to add to response (EDE_UNSET if none)
 *
 * @return Modified packet size after processing, 0 if response should be dropped
 *
 * @retval 0 Response invalid or should be dropped (rebinding block, subnet mismatch, munging failed)
 * @retval >0 Processed packet size ready for forwarding to client
 *
 * @note Strips EDNS0 if added_pheader is true and client didn't send EDNS0
 * @note Blocks responses with private IP addresses unless domain in rebind exception list
 * @note Populates Linux ipset/nftables sets with resolved addresses if configured
 * @warning Drops responses with mismatched EDNS0 client subnet options (security)
 * @warning May modify packet (munge CNAMEs, strip EDNS0, add EDE codes)
 *
 * @see reply_query() which calls this to process upstream server responses
 * @see cache_insert() called to cache processed responses
 * @see domain_find_sets() to find ipset/nftset configuration
 * @see domain_no_rebind() to check rebinding protection exemptions
 *
 * EXAMPLE USAGE:
 * @code
 * size_t reply_len = process_reply(header, time(NULL), upstream_server, packet_len,
 *                                  1, 0, 0, 0, ad_req, do_bit, added_edns0,
 *                                  &client_addr, packet + packet_len, EDE_UNSET);
 * if (reply_len > 0) forward_to_client(header, reply_len);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 1918: Private address detection for rebinding protection
 * - RFC 6891: EDNS0 extension handling
 * - RFC 8914: Extended DNS Error codes
 * - RFC 7871: EDNS0 client subnet option validation
 *
 * SIDE EFFECTS:
 * - Modifies packet (may strip EDNS0, add EDE, munge CNAMEs)
 * - Inserts entries into DNS cache via cache_insert()
 * - Populates ipset/nftables sets with resolved addresses
 * - Logs warnings for subnet option mismatches and rebinding blocks
 *
 * THREAD SAFETY:
 * Not thread-safe (modifies packet, cache, logs). Safe in single-threaded model.
 */
static size_t process_reply(struct dns_header *header, time_t now, struct server *server, size_t n, int check_rebind, 
			    int no_cache, int cache_secure, int bogusanswer, int ad_reqd, int do_bit, int added_pheader, 
			    union mysockaddr *query_source, unsigned char *limit, int ede)
{
  unsigned char *pheader, *sizep;
  struct ipsets *ipsets = NULL, *nftsets = NULL;
  int munged = 0, is_sign;
  unsigned int rcode = RCODE(header);
  size_t plen; 
    
  (void)ad_reqd;
  (void)do_bit;
  (void)bogusanswer;

#ifdef HAVE_IPSET
  if (daemon->ipsets && extract_request(header, n, daemon->namebuff, NULL))
    ipsets = domain_find_sets(daemon->ipsets, daemon->namebuff);
#endif

#ifdef HAVE_NFTSET
  if (daemon->nftsets && extract_request(header, n, daemon->namebuff, NULL))
    nftsets = domain_find_sets(daemon->nftsets, daemon->namebuff);
#endif

  if ((pheader = find_pseudoheader(header, n, &plen, &sizep, &is_sign, NULL)))
    {
      /* Get extended RCODE. */
      rcode |= sizep[2] << 4;

      if (option_bool(OPT_CLIENT_SUBNET) && !check_source(header, plen, pheader, query_source))
	{
	  my_syslog(LOG_WARNING, _("discarding DNS reply: subnet option mismatch"));
	  return 0;
	}
      
      if (!is_sign)
	{
	  if (added_pheader)
	    {
	      /* client didn't send EDNS0, we added one, strip it off before returning answer. */
	      n = rrfilter(header, n, RRFILTER_EDNS0);
	      pheader = NULL;
	    }
	  else
	    {
	      /* If upstream is advertising a larger UDP packet size
		 than we allow, trim it so that we don't get overlarge
		 requests for the client. We can't do this for signed packets. */
	      unsigned short udpsz;
	      GETSHORT(udpsz, sizep);
	      if (udpsz > daemon->edns_pktsz)
		{
		  sizep -= 2;
		  PUTSHORT(daemon->edns_pktsz, sizep);
		}

#ifdef HAVE_DNSSEC
	      /* If the client didn't set the do bit, but we did, reset it. */
	      if (option_bool(OPT_DNSSEC_VALID) && !do_bit)
		{
		  unsigned short flags;
		  sizep += 2; /* skip RCODE */
		  GETSHORT(flags, sizep);
		  flags &= ~0x8000;
		  sizep -= 2;
		  PUTSHORT(flags, sizep);
		}
#endif
	    }
	}
    }
  
  /* RFC 4035 sect 4.6 para 3 */
  if (!is_sign && !option_bool(OPT_DNSSEC_PROXY))
     header->hb4 &= ~HB4_AD;

  header->hb4 |= HB4_RA; /* recursion if available */

  if (OPCODE(header) != QUERY)
    return resize_packet(header, n, pheader, plen);

  if (rcode != NOERROR && rcode != NXDOMAIN)
    {
      union all_addr a;
      a.log.rcode = rcode;
      a.log.ede = ede;
      log_query(F_UPSTREAM | F_RCODE, "error", &a, NULL, 0);
      
      return resize_packet(header, n, pheader, plen);
    }
  
  /* Complain loudly if the upstream server is non-recursive. */
  if (!(header->hb4 & HB4_RA) && rcode == NOERROR &&
      server && !(server->flags & SERV_WARNED_RECURSIVE))
    {
      (void)prettyprint_addr(&server->addr, daemon->namebuff);
      my_syslog(LOG_WARNING, _("nameserver %s refused to do a recursive query"), daemon->namebuff);
      if (!option_bool(OPT_LOG))
	server->flags |= SERV_WARNED_RECURSIVE;
    }  

  if (daemon->bogus_addr && rcode != NXDOMAIN &&
      check_for_bogus_wildcard(header, n, daemon->namebuff, now))
    {
      munged = 1;
      SET_RCODE(header, NXDOMAIN);
      header->hb3 &= ~HB3_AA;
      cache_secure = 0;
      ede = EDE_BLOCKED;
    }
  else 
    {
      int doctored = 0;
      
      if (rcode == NXDOMAIN && 
	  extract_request(header, n, daemon->namebuff, NULL))
	{
	  if (check_for_local_domain(daemon->namebuff, now) ||
	      lookup_domain(daemon->namebuff, F_CONFIG, NULL, NULL))
	    {
	      /* if we forwarded a query for a locally known name (because it was for 
		 an unknown type) and the answer is NXDOMAIN, convert that to NODATA,
		 since we know that the domain exists, even if upstream doesn't */
	      munged = 1;
	      header->hb3 |= HB3_AA;
	      SET_RCODE(header, NOERROR);
	      cache_secure = 0;
	    }
	}

      /* Before extract_addresses() */
      if (rcode == NOERROR)
	{
	  if (option_bool(OPT_FILTER_A))
	    n = rrfilter(header, n, RRFILTER_A);

	  if (option_bool(OPT_FILTER_AAAA))
	    n = rrfilter(header, n, RRFILTER_AAAA);
	}

      if (extract_addresses(header, n, daemon->namebuff, now, ipsets, nftsets, is_sign, check_rebind, no_cache, cache_secure, &doctored))
	{
	  my_syslog(LOG_WARNING, _("possible DNS-rebind attack detected: %s"), daemon->namebuff);
	  munged = 1;
	  cache_secure = 0;
	  ede = EDE_BLOCKED;
	}

      if (doctored)
	cache_secure = 0;
    }
  
#ifdef HAVE_DNSSEC
  if (bogusanswer && !(header->hb4 & HB4_CD) && !option_bool(OPT_DNSSEC_DEBUG))
    {
      /* Bogus reply, turn into SERVFAIL */
      SET_RCODE(header, SERVFAIL);
      munged = 1;
    }

  if (option_bool(OPT_DNSSEC_VALID))
    {
      header->hb4 &= ~HB4_AD;
      
      if (!(header->hb4 & HB4_CD) && ad_reqd && cache_secure)
	header->hb4 |= HB4_AD;
      
      /* If the requestor didn't set the DO bit, don't return DNSSEC info. */
      if (!do_bit)
	n = rrfilter(header, n, RRFILTER_DNSSEC);
    }
#endif

  /* do this after extract_addresses. Ensure NODATA reply and remove
     nameserver info. */
  if (munged)
    {
      header->ancount = htons(0);
      header->nscount = htons(0);
      header->arcount = htons(0);
      header->hb3 &= ~HB3_TC;
    }
  
  /* the bogus-nxdomain stuff, doctor and NXDOMAIN->NODATA munging can all elide
     sections of the packet. Find the new length here and put back pseudoheader
     if it was removed. */
  n = resize_packet(header, n, pheader, plen);

  if (pheader && ede != EDE_UNSET)
    {
      u16 swap = htons((u16)ede);
      n = add_pseudoheader(header, n, limit, daemon->edns_pktsz, EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, do_bit, 1);
    }

  return n;
}

#ifdef HAVE_DNSSEC
/**
 * @brief Perform DNSSEC validation on DNS response and handle dependent queries
 *
 * @detailed
 * Orchestrates DNSSEC validation for DNS responses, handling the complete validation
 * chain including DNSKEY and DS record lookups when needed. Validates responses using
 * dnssec_validate_reply(), dnssec_validate_by_ds(), or dnssec_validate_ds() depending
 * on query type. When validation requires additional key data (STAT_NEED_DS or STAT_NEED_KEY),
 * creates dependent queries and stashes the current response using blockdata. Detects and
 * breaks validation dependency cycles to prevent infinite loops. Handles truncated answers
 * by forcing TCP retry, and abandons validation on REFUSED responses.
 *
 * @param forward Forward record for the query being validated
 * @param header DNS response header to validate
 * @param plen Length of DNS response packet in bytes
 * @param status Initial validation status (STAT_SECURE, STAT_BOGUS, STAT_NEED_DS, etc.)
 * @param now Current time for cache operations and logging
 * @return void (updates forward->blocking_query and validation chain)
 *
 * @note Sets daemon->log_display_id for consistent logging across validation chain
 * @note Stashes response in blockdata when awaiting key data (prevents response loss)
 * @note Only available when compiled with HAVE_DNSSEC
 * @warning Ignores duplicate responses when forward->blocking_query already set
 * @warning Returns immediately if validation already in progress (avoids re-entrancy)
 * @warning Detects and breaks dependency cycles to prevent infinite validation loops
 *
 * @see dnssec_validate_reply() in dnssec.c for main validation logic
 * @see dnssec_validate_by_ds() in dnssec.c for DNSKEY validation
 * @see dnssec_validate_ds() in dnssec.c for DS record validation
 * @see blockdata_alloc() in blockdata.c for response stashing
 * @see lookup_frec_dnssec() for finding existing dependent queries
 *
 * EXAMPLE USAGE:
 * @code
 * int status = STAT_OK;
 * struct frec *forward = lookup_frec(header->id, fd, NULL, NULL, NULL);
 * if (forward && (forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)))
 *   dnssec_validate(forward, header, n, status, now);
 * @endcode
 *
 * RFC COMPLIANCE: Implements DNSSEC validation per RFC 4033-4035 (DNSSEC introduction,
 * resource records, and protocol modifications)
 *
 * SIDE EFFECTS:
 * - Sets daemon->log_display_id for logging context
 * - May allocate blockdata stash via blockdata_alloc()
 * - May create new dependent forward records via get_new_frec()
 * - Modifies forward->blocking_query, forward->dependent chains
 * - May free blockdata via blockdata_free() if stash already exists
 * - Sends dependent DNSKEY/DS queries via server_send()
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static void dnssec_validate(struct frec *forward, struct dns_header *header,
			    ssize_t plen, int status, time_t now)
{
  daemon->log_display_id = forward->frec_src.log_id;
  
  /* We've had a reply already, which we're validating. Ignore this duplicate */
  if (forward->blocking_query)
    return;
  
  /* Truncated answer can't be validated.
     If this is an answer to a DNSSEC-generated query, we still
     need to get the client to retry over TCP, so return
     an answer with the TC bit set, even if the actual answer fits.
  */
  if (header->hb3 & HB3_TC)
    status = STAT_TRUNCATED;

  /* If all replies to a query are REFUSED, give up. */
  if (RCODE(header) == REFUSED)
    status = STAT_ABANDONED;
  
  /* As soon as anything returns BOGUS, we stop and unwind, to do otherwise
     would invite infinite loops, since the answers to DNSKEY and DS queries
     will not be cached, so they'll be repeated. */
  if (!STAT_ISEQUAL(status, STAT_BOGUS) && !STAT_ISEQUAL(status, STAT_TRUNCATED) && !STAT_ISEQUAL(status, STAT_ABANDONED))
    {
      if (forward->flags & FREC_DNSKEY_QUERY)
	status = dnssec_validate_by_ds(now, header, plen, daemon->namebuff, daemon->keyname, forward->class);
      else if (forward->flags & FREC_DS_QUERY)
	status = dnssec_validate_ds(now, header, plen, daemon->namebuff, daemon->keyname, forward->class);
      else
	status = dnssec_validate_reply(now, header, plen, daemon->namebuff, daemon->keyname, &forward->class, 
				       !option_bool(OPT_DNSSEC_IGN_NS) && (forward->sentto->flags & SERV_DO_DNSSEC),
				       NULL, NULL, NULL);
#ifdef HAVE_DUMPFILE
      if (STAT_ISEQUAL(status, STAT_BOGUS))
	dump_packet((forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)) ? DUMP_SEC_BOGUS : DUMP_BOGUS,
		    header, (size_t)plen, &forward->sentto->addr, NULL, daemon->port);
#endif
    }
  
  /* Can't validate, as we're missing key data. Put this
     answer aside, whilst we get that. */     
  if (STAT_ISEQUAL(status, STAT_NEED_DS) || STAT_ISEQUAL(status, STAT_NEED_KEY))
    {
      struct frec *new = NULL;
      struct blockdata *stash;
      
      /* Now save reply pending receipt of key data */
      if ((stash = blockdata_alloc((char *)header, plen)))
	{
	  /* validate routines leave name of required record in daemon->keyname */
	  unsigned int flags = STAT_ISEQUAL(status, STAT_NEED_KEY) ? FREC_DNSKEY_QUERY : FREC_DS_QUERY;

	  if ((new = lookup_frec_dnssec(daemon->keyname, forward->class, flags, header)))
	    {
	      /* This is tricky; it detects loops in the dependency
		 graph for DNSSEC validation, say validating A requires DS B
		 and validating DS B requires DNSKEY C and validating DNSKEY C requires DS B.
		 This should never happen in correctly signed records, but it's
		 likely the case that sufficiently broken ones can cause our validation
		 code requests to exhibit cycles. The result is that the ->blocking_query list
		 can form a cycle, and under certain circumstances that can lock us in 
		 an infinite loop. Here we transform the situation into ABANDONED. */
	      struct frec *f;
	      for (f = new; f; f = f->blocking_query)
		if (f == forward)
		  break;

	      if (!f)
		{
		  forward->next_dependent = new->dependent;
		  new->dependent = forward;
		  /* Make consistent, only replace query copy with unvalidated answer
		     when we set ->blocking_query. */
		  if (forward->stash)
		    blockdata_free(forward->stash);
		  forward->blocking_query = new;
		  forward->stash_len = plen;
		  forward->stash = stash;
		  return;
		}
	    }
	  else
	    {
	      struct server *server;
	      struct frec *orig;
	      void *hash;
	      size_t nn;
	      int serverind, fd;
	      struct randfd_list *rfds = NULL;
	      
	      /* Find the original query that started it all.... */
	      for (orig = forward; orig->dependent; orig = orig->dependent);
	      
	      /* Make sure we don't expire and free the orig frec during the
		 allocation of a new one: third arg of get_new_frec() does that. */
	      if ((serverind = dnssec_server(forward->sentto, daemon->keyname, NULL, NULL)) != -1 &&
		  (server = daemon->serverarray[serverind]) &&
		  (nn = dnssec_generate_query(header, ((unsigned char *) header) + server->edns_pktsz,
					      daemon->keyname, forward->class,
					      STAT_ISEQUAL(status, STAT_NEED_KEY) ? T_DNSKEY : T_DS, server->edns_pktsz)) && 
		  (hash = hash_questions(header, nn, daemon->namebuff)) &&
		  --orig->work_counter != 0 &&
		  (fd = allocate_rfd(&rfds, server)) != -1 &&
		  (new = get_new_frec(now, server, 1)))
		{
		  struct frec *next = new->next;
		  
		  *new = *forward; /* copy everything, then overwrite */
		  new->next = next;
		  new->blocking_query = NULL;
		  
		  new->frec_src.log_id = daemon->log_display_id = ++daemon->log_id;
		  new->sentto = server;
		  new->rfds = rfds;
		  new->frec_src.next = NULL;
		  new->flags &= ~(FREC_DNSKEY_QUERY | FREC_DS_QUERY | FREC_HAS_EXTRADATA);
		  new->flags |= flags;
		  new->forwardall = 0;
		  
		  forward->next_dependent = NULL;
		  new->dependent = forward; /* to find query awaiting new one. */
		  
		  /* Make consistent, only replace query copy with unvalidated answer
		     when we set ->blocking_query. */
		  forward->blocking_query = new; 
		  if (forward->stash)
		    blockdata_free(forward->stash);
		  forward->stash_len = plen;
		  forward->stash = stash;
		  
		  memcpy(new->hash, hash, HASH_SIZE);
		  new->new_id = get_id();
		  header->id = htons(new->new_id);
		  /* Save query for retransmission and de-dup */
		  new->stash = blockdata_alloc((char *)header, nn);
		  new->stash_len = nn;
		  
		  /* Don't resend this. */
		  daemon->srv_save = NULL;
		  
#ifdef HAVE_CONNTRACK
		  if (option_bool(OPT_CONNTRACK))
		    set_outgoing_mark(orig, fd);
#endif
		  
#ifdef HAVE_DUMPFILE
		  dump_packet(DUMP_SEC_QUERY, (void *)header, (size_t)nn, NULL, &server->addr, daemon->port);
#endif
		  log_query_mysockaddr(F_NOEXTRA | F_DNSSEC | F_SERVER, daemon->keyname, &server->addr,
				       STAT_ISEQUAL(status, STAT_NEED_KEY) ? "dnssec-query[DNSKEY]" : "dnssec-query[DS]", 0);
		  server_send(server, fd, header, nn, 0);
		  server->queries++;
		  return;
		}
	      
	      free_rfds(&rfds); /* error unwind */
	    }
	  
	  blockdata_free(stash); /* don't leak this on failure. */
	}

      /* sending DNSSEC query failed or loop detected. */
      status = STAT_ABANDONED;
    }

  /* Validated original answer, all done. */
  if (!forward->dependent)
    return_reply(now, forward, header, plen, status);
  else
    {
      /* validated subsidiary query/queries, (and cached result)
	 pop that and return to the previous query/queries we were working on. */
      struct frec *prev, *nxt = forward->dependent;
      
      free_frec(forward);
      
      while ((prev = nxt))
	{
	  /* ->next_dependent will have changed after return from recursive call below. */
	  nxt = prev->next_dependent;
	  prev->blocking_query = NULL; /* already gone */
	  blockdata_retrieve(prev->stash, prev->stash_len, (void *)header);
	  dnssec_validate(prev, header, prev->stash_len, status, now);
	}
    }
}
#endif

/* sets new last_server */
/**
 * @brief Process DNS response from upstream server and forward to client
 *
 * @detailed Main upstream response handler called when upstream DNS server socket
 * becomes readable in event loop. Receives response packet, validates it matches a
 * pending forward record, verifies response came from expected server (spoof protection),
 * updates server health metrics, processes response through caching pipeline, and
 * forwards to all clients waiting for this query. Implements server selection learning
 * by tracking which servers respond successfully vs REFUSED. Handles DNSSEC validation
 * when enabled. Manages forward record cleanup after response delivery.
 *
 * @param fd File descriptor of socket that received response (UDP or TCP)
 * @param now Current timestamp for cache TTL and server health tracking
 *
 * @note Called from event loop when upstream server socket readable
 * @note Handles responses for both regular queries and DNSSEC-related queries (DNSKEY, DS)
 * @note Updates server->last_server for intelligent server selection on future queries
 * @note Silently drops invalid responses (too small, wrong QR bit, no matching frec, wrong server)
 * @warning Relies on query ID + hash for frec lookup; randomized IDs prevent spoofing
 * @warning Validates response source address matches expected server (critical security check)
 *
 * @see forward_query() which sends queries to upstream and creates forward records
 * @see process_reply() which handles response caching and filtering
 * @see return_reply() which forwards processed response to clients
 * @see lookup_frec() to find forward record matching response
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from event loop when upstream socket readable:
 * struct pollfd *pfd = &pollfds[upstream_socket_index];
 * if (pfd->revents & POLLIN)
 *   reply_query(pfd->fd, time(NULL));
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 1035: DNS response processing and forwarding
 * - RFC 2181: Response validation and cache behavior
 * - RFC 4035: DNSSEC response processing when HAVE_DNSSEC enabled
 *
 * SIDE EFFECTS:
 * - Receives packet into daemon->packet buffer (overwrites previous content)
 * - Updates server health metrics (queries, failed_queries, replyto, last_server)
 * - Inserts responses into DNS cache via process_reply()
 * - Forwards responses to clients via return_reply()
 * - Frees forward record after delivery
 * - May trigger DNSSEC validation queries
 * - Logs query responses if query logging enabled
 *
 * THREAD SAFETY:
 * Not thread-safe (uses shared daemon->packet buffer, modifies server state).
 * Safe in single-threaded event loop model.
 */
void reply_query(int fd, time_t now)
{
  /* packet from peer server, extract data for cache, and send to
     original requester */
  struct dns_header *header;
  union mysockaddr serveraddr;
  struct frec *forward;
  socklen_t addrlen = sizeof(serveraddr);
  ssize_t n = recvfrom(fd, daemon->packet, daemon->packet_buff_sz, 0, &serveraddr.sa, &addrlen);
  struct server *server;
  void *hash;
  int first, last, c;
    
  /* packet buffer overwritten */
  daemon->srv_save = NULL;

  /* Determine the address of the server replying  so that we can mark that as good */
  if (serveraddr.sa.sa_family == AF_INET6)
    serveraddr.in6.sin6_flowinfo = 0;
  
  header = (struct dns_header *)daemon->packet;

  if (n < (int)sizeof(struct dns_header) || !(header->hb3 & HB3_QR))
    return;

  hash = hash_questions(header, n, daemon->namebuff);
  
  if (!(forward = lookup_frec(ntohs(header->id), fd, hash, &first, &last)))
    return;
  
  /* spoof check: answer must come from known server, also
     we may have sent the same query to multiple servers from
     the same local socket, and would like to know which one has answered. */
  for (c = first; c != last; c++)
    if (sockaddr_isequal(&daemon->serverarray[c]->addr, &serveraddr))
      break;
  
  if (c == last)
    return;

  server = daemon->serverarray[c];

  if (RCODE(header) != REFUSED)
    daemon->serverarray[first]->last_server = c;
  else if (daemon->serverarray[first]->last_server == c)
    daemon->serverarray[first]->last_server = -1;

  /* If sufficient time has elapsed, try and expand UDP buffer size again. */
  if (difftime(now, server->pktsz_reduced) > UDP_TEST_TIME)
    server->edns_pktsz = daemon->edns_pktsz;

#ifdef HAVE_DUMPFILE
  dump_packet((forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)) ? DUMP_SEC_REPLY : DUMP_UP_REPLY,
	      (void *)header, n, &serveraddr, NULL, daemon->port);
#endif

  /* log_query gets called indirectly all over the place, so 
     pass these in global variables - sorry. */
  daemon->log_display_id = forward->frec_src.log_id;
  daemon->log_source_addr = &forward->frec_src.source;
  
  if (daemon->ignore_addr && RCODE(header) == NOERROR &&
      check_for_ignored_address(header, n))
    return;

  /* Note: if we send extra options in the EDNS0 header, we can't recreate
     the query from the reply. */
  if ((RCODE(header) == REFUSED || RCODE(header) == SERVFAIL) &&
      forward->forwardall == 0 &&
      !(forward->flags & FREC_HAS_EXTRADATA))
    /* for broken servers, attempt to send to another one. */
    {
      unsigned char *pheader, *udpsz;
      unsigned short udp_size =  PACKETSZ; /* default if no EDNS0 */
      size_t plen;
      int is_sign;
      size_t nn = 0;
      
#ifdef HAVE_DNSSEC
      /* DNSSEC queries have a copy of the original query stashed. 
	 The query MAY have got a good answer, and be awaiting
	 the results of further queries, in which case
	 The Stash contains something else and we don't need to retry anyway. */
      if ((forward->flags & (FREC_DNSKEY_QUERY | FREC_DS_QUERY)) && !forward->blocking_query)
	{
	  blockdata_retrieve(forward->stash, forward->stash_len, (void *)header);
	  nn = forward->stash_len;
	  udp_size = daemon->edns_pktsz;
	}
      else
#endif
	{
	  /* recreate query from reply */
	  if ((pheader = find_pseudoheader(header, (size_t)n, &plen, &udpsz, &is_sign, NULL)))
	    GETSHORT(udp_size, udpsz);
	  
	  /* If the client provides an EDNS0 UDP size, use that to limit our reply.
	     (bounded by the maximum configured). If no EDNS0, then it
	     defaults to 512 */
	  if (udp_size > daemon->edns_pktsz)
	    udp_size = daemon->edns_pktsz;
	  else if (udp_size < PACKETSZ)
	    udp_size = PACKETSZ; /* Sanity check - can't reduce below default. RFC 6891 6.2.3 */
	  
	  if (!is_sign &&
	      (nn = resize_packet(header, (size_t)n, pheader, plen)) &&
	      (forward->flags & FREC_DO_QUESTION))
	    add_do_bit(header, nn,  (unsigned char *)pheader + plen);

	  header->ancount = htons(0);
	  header->nscount = htons(0);
	  header->arcount = htons(0);
	  header->hb3 &= ~(HB3_QR | HB3_AA | HB3_TC);
	  header->hb4 &= ~(HB4_RA | HB4_RCODE | HB4_CD | HB4_AD);
	  if (forward->flags & FREC_CHECKING_DISABLED)
	    header->hb4 |= HB4_CD;
	  if (forward->flags & FREC_AD_QUESTION)
	    header->hb4 |= HB4_AD;
	}

      if (nn)
	{
	  forward_query(-1, NULL, NULL, 0, header, nn, ((char *) header) + udp_size, now, forward,
			forward->flags & FREC_AD_QUESTION, forward->flags & FREC_DO_QUESTION);
	  return;
	}
    }

  /* If the answer is an error, keep the forward record in place in case
     we get a good reply from another server. Kill it when we've
     had replies from all to avoid filling the forwarding table when
     everything is broken */

  /* decrement count of replies recieved if we sent to more than one server. */
  if (forward->forwardall && (--forward->forwardall > 1) && RCODE(header) == REFUSED)
    return;

  /* We tried resending to this server with a smaller maximum size and got an answer.
     Make that permanent. To avoid reduxing the packet size for a single dropped packet,
     only do this when we get a truncated answer, or one larger than the safe size. */
  if (server->edns_pktsz > SAFE_PKTSZ && (forward->flags & FREC_TEST_PKTSZ) && 
      ((header->hb3 & HB3_TC) || n >= SAFE_PKTSZ))
    {
      server->edns_pktsz = SAFE_PKTSZ;
      server->pktsz_reduced = now;
      (void)prettyprint_addr(&server->addr, daemon->addrbuff);
      my_syslog(LOG_WARNING, _("reducing DNS packet size for nameserver %s to %d"), daemon->addrbuff, SAFE_PKTSZ);
    }

  forward->sentto = server;
  
#ifdef HAVE_DNSSEC
  if ((forward->sentto->flags & SERV_DO_DNSSEC) && 
      option_bool(OPT_DNSSEC_VALID) &&
      !(forward->flags & FREC_CHECKING_DISABLED))
    dnssec_validate(forward, header, n, STAT_OK, now);
  else
#endif
    return_reply(now, forward, header, n, STAT_OK); 
}

/**
 * @brief Forward processed DNS response to all waiting clients
 *
 * @detailed Sends DNS response to all clients that requested this query (handles query
 * aggregation where multiple clients share single upstream query). Processes DNSSEC
 * validation status, applies rebinding protection, invokes process_reply() for caching
 * and filtering, and transmits response to each client via send_from(). Handles DNSSEC
 * validation results (SECURE, INSECURE, BOGUS) with appropriate logging and cache flags.
 * Sets Extended DNS Error (EDE) codes for DNSSEC failures. Manages forward record cleanup.
 *
 * @param now Current timestamp for cache insertion
 * @param forward Forward record containing all clients waiting for this query
 * @param header DNS response packet header
 * @param n Response packet size in bytes
 * @param status DNSSEC validation status (STAT_OK, STAT_SECURE, STAT_INSECURE, STAT_BOGUS, etc.)
 *
 * @note Handles CD (Checking Disabled) bit: if set, DNSSEC validation not cached
 * @note Iterates through forward->frec_src list to deliver response to all waiting clients
 * @note Applies rebinding protection unless domain is in exception list
 * @note Logs DNSSEC validation results (SECURE/INSECURE/BOGUS/ABANDONED)
 * @warning Sets TC (Truncated) bit if DNSSEC validation status is STAT_TRUNCATED
 * @warning Modifies header to add EDE codes for DNSSEC validation failures
 *
 * @see reply_query() which calls this after receiving upstream response
 * @see process_reply() for response caching and filtering pipeline
 * @see send_from() to transmit response to each client
 * @see free_frec() called after all clients receive response
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal call from reply_query after upstream response:
 * return_reply(time(NULL), forward_rec, response_header, response_len, validation_status);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4035: DNSSEC validation status handling
 * - RFC 8914: Extended DNS Error (EDE) codes for DNSSEC failures
 * - RFC 1918: Rebinding protection for private address responses
 *
 * SIDE EFFECTS:
 * - Sends response packets to all clients in forward->frec_src list
 * - Calls process_reply() which caches response and populates ipsets
 * - Sets daemon->log_display_id and daemon->log_source_addr for logging context
 * - Logs DNSSEC validation results
 * - Modifies header to add EDE codes or TC bit
 * - Frees forward record after delivery
 *
 * THREAD SAFETY:
 * Not thread-safe (modifies header, uses daemon globals, frees frec).
 * Safe in single-threaded event loop model.
 */
static void return_reply(time_t now, struct frec *forward, struct dns_header *header, ssize_t n, int status)
{
  int check_rebind = 0, no_cache_dnssec = 0, cache_secure = 0, bogusanswer = 0;
  size_t nn;
  int ede = EDE_UNSET;

  (void)status;

  daemon->log_display_id = forward->frec_src.log_id;
  daemon->log_source_addr = &forward->frec_src.source;
  
  /* Don't cache replies where DNSSEC validation was turned off, either
     the upstream server told us so, or the original query specified it.  */
  if ((header->hb4 & HB4_CD) || (forward->flags & FREC_CHECKING_DISABLED))
    no_cache_dnssec = 1;

#ifdef HAVE_DNSSEC
  if (!STAT_ISEQUAL(status, STAT_OK))
    {
      /* status is STAT_OK when validation not turned on. */
      no_cache_dnssec = 0;
      
      if (STAT_ISEQUAL(status, STAT_TRUNCATED))
	header->hb3 |= HB3_TC;
      else
	{
	  char *result, *domain = "result";
	  union all_addr a;

	  a.log.ede = ede = errflags_to_ede(status);

	  if (STAT_ISEQUAL(status, STAT_ABANDONED))
	    {
	      result = "ABANDONED";
	      status = STAT_BOGUS;
	    }
	  else
	    result = (STAT_ISEQUAL(status, STAT_SECURE) ? "SECURE" : (STAT_ISEQUAL(status, STAT_INSECURE) ? "INSECURE" : "BOGUS"));
	  
	  if (STAT_ISEQUAL(status, STAT_SECURE))
	    cache_secure = 1;
	  else if (STAT_ISEQUAL(status, STAT_BOGUS))
	    {
	      no_cache_dnssec = 1;
	      bogusanswer = 1;
	      
	      if (extract_request(header, n, daemon->namebuff, NULL))
		domain = daemon->namebuff;
	    }
	  
	  log_query(F_SECSTAT, domain, &a, result, 0);
	}
    }
#endif
  
  if (option_bool(OPT_NO_REBIND))
    check_rebind = !(forward->flags & FREC_NOREBIND);
  
  /* restore CD bit to the value in the query */
  if (forward->flags & FREC_CHECKING_DISABLED)
    header->hb4 |= HB4_CD;
  else
    header->hb4 &= ~HB4_CD;
  
  /* Never cache answers which are contingent on the source or MAC address EDSN0 option,
     since the cache is ignorant of such things. */
  if (forward->flags & FREC_NO_CACHE)
    no_cache_dnssec = 1;
  
  if ((nn = process_reply(header, now, forward->sentto, (size_t)n, check_rebind, no_cache_dnssec, cache_secure, bogusanswer, 
			  forward->flags & FREC_AD_QUESTION, forward->flags & FREC_DO_QUESTION, 
			  forward->flags & FREC_ADDED_PHEADER, &forward->frec_src.source,
			  ((unsigned char *)header) + daemon->edns_pktsz, ede)))
    {
      struct frec_src *src;
      
      header->id = htons(forward->frec_src.orig_id);
#ifdef HAVE_DNSSEC
      /* We added an EDNSO header for the purpose of getting DNSSEC RRs, and set the value of the UDP payload size
	 greater than the no-EDNS0-implied 512 to have space for the RRSIGS. If, having stripped them and the EDNS0
	 header, the answer is still bigger than 512, truncate it and mark it so. The client then retries with TCP. */
      if (option_bool(OPT_DNSSEC_VALID) && (forward->flags & FREC_ADDED_PHEADER) && (nn > PACKETSZ))
	{
	  header->ancount = htons(0);
	  header->nscount = htons(0);
	  header->arcount = htons(0);
	  header->hb3 |= HB3_TC;
	  nn = resize_packet(header, nn, NULL, 0);
	}
#endif
      
      for (src = &forward->frec_src; src; src = src->next)
	{
	  header->id = htons(src->orig_id);
	  
#ifdef HAVE_DUMPFILE
	  dump_packet(DUMP_REPLY, daemon->packet, (size_t)nn, NULL, &src->source, daemon->port);
#endif
	  
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
	  if (option_bool(OPT_CMARK_ALST_EN))
	    {
	      unsigned int mark;
	      int have_mark = get_incoming_mark(&src->source, &src->dest, /* istcp: */ 0, &mark);
	      if (have_mark && ((u32)mark & daemon->allowlist_mask))
		report_addresses(header, nn, mark);
	    }
#endif
	  
	  send_from(src->fd, option_bool(OPT_NOWILD) || option_bool (OPT_CLEVERBIND), daemon->packet, nn, 
		    &src->source, &src->dest, src->iface);
	  
	  if (option_bool(OPT_EXTRALOG) && src != &forward->frec_src)
	    {
	      daemon->log_display_id = src->log_id;
	      daemon->log_source_addr = &src->source;
	      log_query(F_UPSTREAM, "query", NULL, "duplicate", 0);
	    }
	}
    }

  free_frec(forward); /* cancel */
}


#ifdef HAVE_CONNTRACK
/**
 * @brief Check if DNS query is allowed based on connection mark and allowlist patterns
 *
 * @detailed
 * Implements connection mark-based query filtering by checking if the query's domain name
 * matches any allowlist pattern associated with the packet's connection mark. Iterates
 * through daemon->allowlists comparing the masked connection mark, then checks domain name
 * against patterns in matching allowlists. Wildcard pattern "*" allows all queries for that
 * mark. Domain name validation is lazy (only performed once if needed) for efficiency. Used
 * to restrict DNS resolution based on application identity in containerized environments.
 *
 * @param mark Connection mark from SO_MARK socket option (netfilter conntrack mark)
 * @param name Domain name being queried (e.g., "example.com"), or NULL if extraction failed
 * @return 1 if query allowed (mark matches allowlist with matching pattern), 0 if disallowed
 *
 * @note Requires HAVE_CONNTRACK to enable connection mark support
 * @note Wildcard "*" pattern matches all domains for that mark
 * @note Domain validation skipped if name is NULL (returns 0 for safety)
 * @note Mark comparison uses daemon->allowlist_mask and per-allowlist mask for flexibility
 * @warning Returns 0 (disallowed) if name is NULL or invalid DNS name
 *
 * @see answer_disallowed() for generating REFUSED response to disallowed queries
 * @see is_valid_dns_name() for domain name validation
 * @see is_dns_name_matching_pattern() for wildcard pattern matching
 *
 * EXAMPLE USAGE:
 * @code
 * u32 mark = get_connection_mark(fd);
 * if (!is_query_allowed_for_mark(mark, "example.com")) {
 *   return answer_disallowed(header, qlen, mark, "example.com");
 * }
 * @endcode
 *
 * SIDE EFFECTS: None - read-only check operation
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static int is_query_allowed_for_mark(u32 mark, const char *name)
{
  int is_allowable_name, did_validate_name = 0;
  struct allowlist *allowlists;
  char **patterns_pos;
  
  for (allowlists = daemon->allowlists; allowlists; allowlists = allowlists->next)
    if (allowlists->mark == (mark & daemon->allowlist_mask & allowlists->mask))
      for (patterns_pos = allowlists->patterns; *patterns_pos; patterns_pos++)
	{
	  if (!strcmp(*patterns_pos, "*"))
	    return 1;
	  if (!did_validate_name)
	    {
	      is_allowable_name = name ? is_valid_dns_name(name) : 0;
	      did_validate_name = 1;
	    }
	  if (is_allowable_name && is_dns_name_matching_pattern(name, *patterns_pos))
	    return 1;
	}
  return 0;
}

/**
 * @brief Generate REFUSED response for disallowed query with EDE (Extended DNS Error)
 *
 * @detailed
 * Constructs a DNS REFUSED response for queries blocked by connection mark allowlist filtering,
 * using Extended DNS Error (EDE) code BLOCKED to inform clients why the query was denied.
 * Broadcasts ubus event on OpenWrt for logging/monitoring disallowed queries. Sets up response
 * header with REFUSED rcode and EDE_BLOCKED extended error, skips question section, and returns
 * response length for transmission. No answer/authority/additional sections added (minimal response).
 *
 * @param header DNS query header to be transformed into REFUSED response
 * @param qlen Original query length in bytes (for question section parsing)
 * @param mark Connection mark that caused query to be disallowed (for ubus event)
 * @param name Domain name that was queried (for ubus event), or NULL
 * @return Length of response packet in bytes, or 0 if question section parsing failed
 *
 * @note Requires HAVE_CONNTRACK for connection mark-based filtering
 * @note Broadcasts ubus event if HAVE_UBUS enabled and name != NULL
 * @note Sets EDE_BLOCKED (Extended DNS Error for filtered query)
 * @note Parameters mark and name unused if HAVE_UBUS not defined (hence (void) casts)
 * @warning Returns 0 if skip_questions() fails (malformed query)
 *
 * @see is_query_allowed_for_mark() which determines if answer_disallowed should be called
 * @see setup_reply() in rfc1035.c for response header construction
 * @see skip_questions() in rfc1035.c for question section parsing
 *
 * EXAMPLE USAGE:
 * @code
 * u32 mark = get_connection_mark(fd);
 * if (!is_query_allowed_for_mark(mark, "example.com")) {
 *   size_t response_len = answer_disallowed(header, qlen, mark, "example.com");
 *   sendto(fd, header, response_len, 0, &source, sa_len(&source));
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Uses RFC 8914 Extended DNS Errors (EDE) with BLOCKED code
 *
 * SIDE EFFECTS:
 * - Modifies header in-place (transforms query into response)
 * - Broadcasts ubus event if HAVE_UBUS (external notification)
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static size_t answer_disallowed(struct dns_header *header, size_t qlen, u32 mark, const char *name)
{
  unsigned char *p;
  (void)name;
  (void)mark;
  
#ifdef HAVE_UBUS
  if (name)
    ubus_event_bcast_connmark_allowlist_refused(mark, name);
#endif
  
  setup_reply(header, /* flags: */ 0, EDE_BLOCKED);
  
  if (!(p = skip_questions(header, qlen)))
    return 0;
  return p - (unsigned char *)header;
}
#endif

/**
 * @brief Main DNS query entry point from network listeners
 *
 * @detailed Primary DNS query reception handler called when DNS listener socket becomes
 * readable. Receives query packet with ancillary data (interface, destination address),
 * extracts EDNS0 extensions, validates query format, checks connection tracking marks
 * for filtering, determines if query is for authoritative zone, performs cache lookup,
 * and either answers from cache/local data or forwards to upstream via forward_query().
 * Handles CHAOS class queries for version binding. Implements query filtering based on
 * marks (--filter-A, --filter-AAAA). Routes to authoritative DNS handler if applicable.
 *
 * @param listen Listener structure containing socket, interface, and bind address info
 * @param now Current timestamp for cache lookup and forwarding
 *
 * @note Called from main event loop when DNS listener socket readable
 * @note Handles both UDP and TCP queries (TCP via separate tcp_request path)
 * @note Extracts destination address from ancillary data for multi-homed response addressing
 * @note Performs cache lookup before forwarding (cache_find_by_query)
 * @warning Silently drops malformed queries (too small, invalid format)
 * @warning Drops queries with disallowed marks if connection tracking filtering enabled
 * @warning Returns REFUSED for blocked query types (filtered by mark)
 *
 * @see forward_query() called when cache miss requires upstream forwarding
 * @see answer_request() to generate responses from cache or local data
 * @see extract_addresses() to parse authoritative zone queries
 * @see tcp_request() for TCP query handling
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from event loop when DNS listener socket readable:
 * struct pollfd *pfd = &pollfds[listener_index];
 * if (pfd->revents & POLLIN)
 *   receive_query(listeners[listener_index], time(NULL));
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 1035: DNS query processing, cache lookup, response generation
 * - RFC 2671: EDNS0 extension parsing (OPT record, UDP size, flags)
 * - RFC 3225: DNSSEC OK (DO) bit handling in EDNS0
 * - RFC 4892: CHAOS class queries for version.bind and id.server.bind
 * - RFC 7871: EDNS0 client subnet option extraction
 *
 * SIDE EFFECTS:
 * - Receives packet into daemon->packet buffer via recvmsg()
 * - May send response directly to client (cache hit, local answer, REFUSED)
 * - Creates forward record and sends upstream query on cache miss
 * - Logs queries if query logging enabled
 * - Updates cache statistics
 * - May trigger authoritative DNS processing
 *
 * THREAD SAFETY:
 * Not thread-safe (uses shared daemon->packet buffer, modifies cache).
 * Safe in single-threaded event loop model.
 */
void receive_query(struct listener *listen, time_t now)
{
  struct dns_header *header = (struct dns_header *)daemon->packet;
  union mysockaddr source_addr;
  unsigned char *pheader;
  unsigned short type, udp_size = PACKETSZ; /* default if no EDNS0 */
  union all_addr dst_addr;
  struct in_addr netmask, dst_addr_4;
  size_t m;
  ssize_t n;
  int if_index = 0, auth_dns = 0, do_bit = 0, have_pseudoheader = 0;
#ifdef HAVE_CONNTRACK
  unsigned int mark = 0;
  int have_mark = 0;
  int is_single_query = 0, allowed = 1;
#endif
#ifdef HAVE_AUTH
  int local_auth = 0;
#endif
  struct iovec iov[1];
  struct msghdr msg;
  struct cmsghdr *cmptr;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#if defined(HAVE_LINUX_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(IP_RECVDSTADDR) && defined(HAVE_SOLARIS_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(unsigned int))];
#elif defined(IP_RECVDSTADDR)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
  } control_u;
  int family = listen->addr.sa.sa_family;
   /* Can always get recvd interface for IPv6 */
  int check_dst = !option_bool(OPT_NOWILD) || family == AF_INET6;

  /* packet buffer overwritten */
  daemon->srv_save = NULL;

  dst_addr_4.s_addr = dst_addr.addr4.s_addr = 0;
  netmask.s_addr = 0;
  
  if (option_bool(OPT_NOWILD) && listen->iface)
    {
      auth_dns = listen->iface->dns_auth;
     
      if (family == AF_INET)
	{
	  dst_addr_4 = dst_addr.addr4 = listen->iface->addr.in.sin_addr;
	  netmask = listen->iface->netmask;
	}
    }
  
  iov[0].iov_base = daemon->packet;
  iov[0].iov_len = daemon->edns_pktsz;
    
  msg.msg_control = control_u.control;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &source_addr;
  msg.msg_namelen = sizeof(source_addr);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  
  if ((n = recvmsg(listen->fd, &msg, 0)) == -1)
    return;
  
  if (n < (int)sizeof(struct dns_header) || 
      (msg.msg_flags & MSG_TRUNC) ||
      (header->hb3 & HB3_QR))
    return;

  /* Clear buffer beyond request to avoid risk of
     information disclosure. */
  memset(daemon->packet + n, 0, daemon->edns_pktsz - n);
  
  source_addr.sa.sa_family = family;
  
  if (family == AF_INET)
    {
       /* Source-port == 0 is an error, we can't send back to that. 
	  http://www.ietf.org/mail-archive/web/dnsop/current/msg11441.html */
      if (source_addr.in.sin_port == 0)
	return;
    }
  else
    {
      /* Source-port == 0 is an error, we can't send back to that. */
      if (source_addr.in6.sin6_port == 0)
	return;
      source_addr.in6.sin6_flowinfo = 0;
    }
  
  /* We can be configured to only accept queries from at-most-one-hop-away addresses. */
  if (option_bool(OPT_LOCAL_SERVICE))
    {
      struct addrlist *addr;

      if (family == AF_INET6) 
	{
	  for (addr = daemon->interface_addrs; addr; addr = addr->next)
	    if ((addr->flags & ADDRLIST_IPV6) &&
		is_same_net6(&addr->addr.addr6, &source_addr.in6.sin6_addr, addr->prefixlen))
	      break;
	}
      else
	{
	  struct in_addr netmask;
	  for (addr = daemon->interface_addrs; addr; addr = addr->next)
	    {
	      netmask.s_addr = htonl(~(in_addr_t)0 << (32 - addr->prefixlen));
	      if (!(addr->flags & ADDRLIST_IPV6) &&
		  is_same_net(addr->addr.addr4, source_addr.in.sin_addr, netmask))
		break;
	    }
	}
      if (!addr)
	{
	  static int warned = 0;
	  if (!warned)
	    {
	      prettyprint_addr(&source_addr, daemon->addrbuff);
	      my_syslog(LOG_WARNING, _("ignoring query from non-local network %s (logged only once)"), daemon->addrbuff);
	      warned = 1;
	    }
	  return;
	}
    }
		
  if (check_dst)
    {
      struct ifreq ifr;

      if (msg.msg_controllen < sizeof(struct cmsghdr))
	return;

#if defined(HAVE_LINUX_NETWORK)
      if (family == AF_INET)
	for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	  if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO)
	    {
	      union {
		unsigned char *c;
		struct in_pktinfo *p;
	      } p;
	      p.c = CMSG_DATA(cmptr);
	      dst_addr_4 = dst_addr.addr4 = p.p->ipi_spec_dst;
	      if_index = p.p->ipi_ifindex;
	    }
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
      if (family == AF_INET)
	{
	  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	    {
	      union {
		unsigned char *c;
		unsigned int *i;
		struct in_addr *a;
#ifndef HAVE_SOLARIS_NETWORK
		struct sockaddr_dl *s;
#endif
	      } p;
	       p.c = CMSG_DATA(cmptr);
	       if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVDSTADDR)
		 dst_addr_4 = dst_addr.addr4 = *(p.a);
	       else if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
#ifdef HAVE_SOLARIS_NETWORK
		 if_index = *(p.i);
#else
  	         if_index = p.s->sdl_index;
#endif
	    }
	}
#endif
      
      if (family == AF_INET6)
	{
	  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	    if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == daemon->v6pktinfo)
	      {
		union {
		  unsigned char *c;
		  struct in6_pktinfo *p;
		} p;
		p.c = CMSG_DATA(cmptr);
		  
		dst_addr.addr6 = p.p->ipi6_addr;
		if_index = p.p->ipi6_ifindex;
	      }
	}
      
      /* enforce available interface configuration */
      
      if (!indextoname(listen->fd, if_index, ifr.ifr_name))
	return;
      
      if (!iface_check(family, &dst_addr, ifr.ifr_name, &auth_dns))
	{
	   if (!option_bool(OPT_CLEVERBIND))
	     enumerate_interfaces(0); 
	   if (!loopback_exception(listen->fd, family, &dst_addr, ifr.ifr_name) &&
	       !label_exception(if_index, family, &dst_addr))
	     return;
	}

      if (family == AF_INET && option_bool(OPT_LOCALISE))
	{
	  struct irec *iface;
	  
	  /* get the netmask of the interface which has the address we were sent to.
	     This is no necessarily the interface we arrived on. */
	  
	  for (iface = daemon->interfaces; iface; iface = iface->next)
	    if (iface->addr.sa.sa_family == AF_INET &&
		iface->addr.in.sin_addr.s_addr == dst_addr_4.s_addr)
	      break;
	  
	  /* interface may be new */
	  if (!iface && !option_bool(OPT_CLEVERBIND))
	    enumerate_interfaces(0); 
	  
	  for (iface = daemon->interfaces; iface; iface = iface->next)
	    if (iface->addr.sa.sa_family == AF_INET &&
		iface->addr.in.sin_addr.s_addr == dst_addr_4.s_addr)
	      break;
	  
	  /* If we failed, abandon localisation */
	  if (iface)
	    netmask = iface->netmask;
	  else
	    dst_addr_4.s_addr = 0;
	}
    }
   
  /* log_query gets called indirectly all over the place, so 
     pass these in global variables - sorry. */
  daemon->log_display_id = ++daemon->log_id;
  daemon->log_source_addr = &source_addr;

#ifdef HAVE_DUMPFILE
  dump_packet(DUMP_QUERY, daemon->packet, (size_t)n, &source_addr, NULL, daemon->port);
#endif
  
#ifdef HAVE_CONNTRACK
  if (option_bool(OPT_CMARK_ALST_EN))
    have_mark = get_incoming_mark(&source_addr, &dst_addr, /* istcp: */ 0, &mark);
#endif
	  
  if (extract_request(header, (size_t)n, daemon->namebuff, &type))
    {
#ifdef HAVE_AUTH
      struct auth_zone *zone;
#endif
      log_query_mysockaddr(F_QUERY | F_FORWARD, daemon->namebuff,
			   &source_addr, auth_dns ? "auth" : "query", type);
      
#ifdef HAVE_CONNTRACK
      is_single_query = 1;
#endif

#ifdef HAVE_AUTH
      /* find queries for zones we're authoritative for, and answer them directly */
      if (!auth_dns && !option_bool(OPT_LOCALISE))
	for (zone = daemon->auth_zones; zone; zone = zone->next)
	  if (in_zone(zone, daemon->namebuff, NULL))
	    {
	      auth_dns = 1;
	      local_auth = 1;
	      break;
	    }
#endif
      
#ifdef HAVE_LOOP
      /* Check for forwarding loop */
      if (detect_loop(daemon->namebuff, type))
	return;
#endif
    }
  
  if (find_pseudoheader(header, (size_t)n, NULL, &pheader, NULL, NULL))
    { 
      unsigned short flags;
      
      have_pseudoheader = 1;
      GETSHORT(udp_size, pheader);
      pheader += 2; /* ext_rcode */
      GETSHORT(flags, pheader);
      
      if (flags & 0x8000)
	do_bit = 1;/* do bit */ 
	
      /* If the client provides an EDNS0 UDP size, use that to limit our reply.
	 (bounded by the maximum configured). If no EDNS0, then it
	 defaults to 512 */
      if (udp_size > daemon->edns_pktsz)
	udp_size = daemon->edns_pktsz;
      else if (udp_size < PACKETSZ)
	udp_size = PACKETSZ; /* Sanity check - can't reduce below default. RFC 6891 6.2.3 */
    }

#ifdef HAVE_CONNTRACK
#ifdef HAVE_AUTH
  if (!auth_dns || local_auth)
#endif
    if (option_bool(OPT_CMARK_ALST_EN) && have_mark && ((u32)mark & daemon->allowlist_mask))
      allowed = is_query_allowed_for_mark((u32)mark, is_single_query ? daemon->namebuff : NULL);
#endif
  
  if (0);
#ifdef HAVE_CONNTRACK
  else if (!allowed)
    {
      u16 swap = htons(EDE_BLOCKED);

      m = answer_disallowed(header, (size_t)n, (u32)mark, is_single_query ? daemon->namebuff : NULL);
      
      if (have_pseudoheader && m != 0)
	m = add_pseudoheader(header,  m,  ((unsigned char *) header) + udp_size, daemon->edns_pktsz,
			     EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, do_bit, 0);
      
      if (m >= 1)
	{
#ifdef HAVE_DUMPFILE
	  dump_packet(DUMP_REPLY, daemon->packet, m, NULL, &source_addr, daemon->port);
#endif
	  send_from(listen->fd, option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND),
		    (char *)header, m, &source_addr, &dst_addr, if_index);
	  daemon->metrics[METRIC_DNS_LOCAL_ANSWERED]++;
	}
    }
#endif
#ifdef HAVE_AUTH
  else if (auth_dns)
    {
      m = answer_auth(header, ((char *) header) + udp_size, (size_t)n, now, &source_addr, 
		      local_auth, do_bit, have_pseudoheader);
      if (m >= 1)
	{
#ifdef HAVE_DUMPFILE
	  dump_packet(DUMP_REPLY, daemon->packet, m, NULL, &source_addr, daemon->port);
#endif
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
	  if (local_auth)
	    if (option_bool(OPT_CMARK_ALST_EN) && have_mark && ((u32)mark & daemon->allowlist_mask))
	      report_addresses(header, m, mark);
#endif
	  send_from(listen->fd, option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND),
		    (char *)header, m, &source_addr, &dst_addr, if_index);
	  daemon->metrics[METRIC_DNS_AUTH_ANSWERED]++;
	}
    }
#endif
  else
    {
      int ad_reqd = do_bit;
      /* RFC 6840 5.7 */
      if (header->hb4 & HB4_AD)
	ad_reqd = 1;
      
      m = answer_request(header, ((char *) header) + udp_size, (size_t)n, 
			 dst_addr_4, netmask, now, ad_reqd, do_bit, have_pseudoheader);
      
      if (m >= 1)
	{
#ifdef HAVE_DUMPFILE
	  dump_packet(DUMP_REPLY, daemon->packet, m, NULL, &source_addr, daemon->port);
#endif
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
	  if (option_bool(OPT_CMARK_ALST_EN) && have_mark && ((u32)mark & daemon->allowlist_mask))
	    report_addresses(header, m, mark);
#endif
	  send_from(listen->fd, option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND),
		    (char *)header, m, &source_addr, &dst_addr, if_index);
	  daemon->metrics[METRIC_DNS_LOCAL_ANSWERED]++;
	}
      else if (forward_query(listen->fd, &source_addr, &dst_addr, if_index,
			     header, (size_t)n,  ((char *) header) + udp_size, now, NULL, ad_reqd, do_bit))
	daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]++;
      else
	daemon->metrics[METRIC_DNS_LOCAL_ANSWERED]++;
    }
}

/* Send query in packet, qsize to a server determined by first,last,start and
   get the reply. return reply size. */
/**
 * @brief Send DNS query via TCP to upstream servers with automatic failover
 *
 * @detailed
 * Establishes TCP connections to upstream DNS servers and performs query/response transaction
 * over TCP (RFC 1035 Section 4.2.2 TCP usage). Iterates through server range [first, last)
 * starting at 'start' index, trying each server until successful response received. Creates
 * TCP socket per server (cached in serv->tcpfd), attempts MSG_FASTOPEN when available, validates
 * response by comparing question section hash to prevent cache poisoning via bogus TCP responses.
 * Retries same server once if data received then EOF (SERV_GOT_TCP), to avoid DoS from servers
 * that accept connections then immediately close. Copies connection mark for netfilter integration.
 *
 * @param first First index in daemon->serverarray to try
 * @param last One past last index in daemon->serverarray to try (exclusive upper bound)
 * @param start Starting index for first attempt (rotates for load balancing)
 * @param packet Buffer containing 2-byte length prefix + DNS query packet
 * @param qsize DNS query size in bytes (excluding 2-byte length prefix)
 * @param have_mark Whether connection mark is valid (HAVE_CONNTRACK)
 * @param mark Connection mark to propagate to outgoing TCP connection
 * @param servp Output parameter receiving pointer to server that responded successfully
 * @return Response size in bytes (excluding length prefix) on success, 0 on all servers failed
 *
 * @note Requires TCP for responses exceeding UDP limit or when TC bit set in UDP response
 * @note Validates response question hash to prevent TCP-based cache poisoning
 * @note Caches TCP connections in server->tcpfd for connection reuse
 * @warning Returns 0 if all servers fail or response hash doesn't match query hash
 * @warning Closes and clears serv->tcpfd on any I/O error (forces reconnect on retry)
 *
 * @see read_write() in util.c for reliable TCP I/O with retries
 * @see hash_questions() for question section hashing
 * @see tcp_request() which uses tcp_talk for client TCP queries
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char packet[MAXDNAME];
 * *(u16*)packet = 0; // Length filled by tcp_talk
 * memcpy(&packet[2], query, query_len);
 * struct server *server_used;
 * ssize_t n = tcp_talk(0, daemon->numservers, 0, packet, query_len, 0, 0, &server_used);
 * @endcode
 *
 * RFC COMPLIANCE: Implements TCP transport per RFC 1035 Section 4.2.2 (length-prefixed messages)
 *
 * SIDE EFFECTS:
 * - Opens TCP sockets via socket() and stores in server->tcpfd
 * - Closes sockets on I/O errors via close()
 * - Sets SO_MARK on outgoing connections if have_mark (HAVE_CONNTRACK)
 * - Updates daemon->serverarray[first]->last_server for round-robin
 * - Sets SERV_GOT_TCP flag on successful data receipt
 * - Sends/receives data via read_write() and server_send()
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static ssize_t tcp_talk(int first, int last, int start, unsigned char *packet,  size_t qsize,
			int have_mark, unsigned int mark, struct server **servp)
{
  int firstsendto = -1;
  u16 *length = (u16 *)packet;
  unsigned char *payload = &packet[2];
  struct dns_header *header = (struct dns_header *)payload;
  unsigned char c1, c2;
  unsigned char hash[HASH_SIZE], *hashp;
  unsigned int rsize;
  
  (void)mark;
  (void)have_mark;

  if (!(hashp = hash_questions(header, (unsigned int)qsize, daemon->namebuff)))
    return 0;

  memcpy(hash, hashp, HASH_SIZE);
  
  while (1) 
    {
      int data_sent = 0;
      struct server *serv;
      
      if (firstsendto == -1)
	firstsendto = start;
      else
	{
	  start++;
	  
	  if (start == last)
	    start = first;
	  
	  if (start == firstsendto)
	    break;
	}
      
      serv = daemon->serverarray[start];
      
    retry:
      *length = htons(qsize);
      
      if (serv->tcpfd == -1)
	{
	  if ((serv->tcpfd = socket(serv->addr.sa.sa_family, SOCK_STREAM, 0)) == -1)
	    continue;
	  
#ifdef HAVE_CONNTRACK
	  /* Copy connection mark of incoming query to outgoing connection. */
	  if (have_mark)
	    setsockopt(serv->tcpfd, SOL_SOCKET, SO_MARK, &mark, sizeof(unsigned int));
#endif			  
	  
	  if ((!local_bind(serv->tcpfd,  &serv->source_addr, serv->interface, 0, 1)))
	    {
	      close(serv->tcpfd);
	      serv->tcpfd = -1;
	      continue;
	    }
	  
#ifdef MSG_FASTOPEN
	  server_send(serv, serv->tcpfd, packet, qsize + sizeof(u16), MSG_FASTOPEN);
	  
	  if (errno == 0)
	    data_sent = 1;
#endif
	  
	  if (!data_sent && connect(serv->tcpfd, &serv->addr.sa, sa_len(&serv->addr)) == -1)
	    {
	      close(serv->tcpfd);
	      serv->tcpfd = -1;
	      continue;
	    }
	  
	  daemon->serverarray[first]->last_server = start;
	  serv->flags &= ~SERV_GOT_TCP;
	}
      
      if ((!data_sent && !read_write(serv->tcpfd, packet, qsize + sizeof(u16), 0)) ||
	  !read_write(serv->tcpfd, &c1, 1, 1) ||
	  !read_write(serv->tcpfd, &c2, 1, 1) ||
	  !read_write(serv->tcpfd, payload, (rsize = (c1 << 8) | c2), 1))
	{
	  close(serv->tcpfd);
	  serv->tcpfd = -1;
	  /* We get data then EOF, reopen connection to same server,
	     else try next. This avoids DoS from a server which accepts
	     connections and then closes them. */
	  if (serv->flags & SERV_GOT_TCP)
	    goto retry;
	  else
	    continue;
	}

      /* If the hash of the question section doesn't match the crc we sent, then
	 someone might be attempting to insert bogus values into the cache by 
	 sending replies containing questions and bogus answers. 
	 Try another server, or give up */
      if (!(hashp = hash_questions(header, rsize, daemon->namebuff)) || memcmp(hash, hashp, HASH_SIZE) != 0)
	continue;
      
      serv->flags |= SERV_GOT_TCP;
      
      *servp = serv;
      return rsize;
    }

  return 0;
}
		  
#ifdef HAVE_DNSSEC
/**
 * @brief Recursively validate DNSSEC chain by fetching needed DNSKEY/DS records via TCP
 *
 * @detailed
 * Implements recursive DNSSEC validation over TCP by traversing the trust chain from the
 * current response up to trust anchors. When validation returns STAT_NEED_KEY or STAT_NEED_DS,
 * generates queries for the missing DNSKEY or DS records, sends them via tcp_talk(), and
 * recursively validates the responses. Limits recursion depth via keycount to prevent infinite
 * loops on broken DNSSEC. Used by tcp_request() to validate responses when client requests
 * DNSSEC validation over TCP. Updates keyname with next required key on each iteration.
 *
 * @param now Current time for validation and cache operations
 * @param status Current validation status (STAT_NEED_KEY, STAT_NEED_DS, or STAT_OK)
 * @param header DNS response header being validated
 * @param n Length of DNS response in bytes
 * @param class DNS class (typically C_IN = 1 for Internet)
 * @param name Domain name being validated (original query target)
 * @param keyname Buffer receiving name of next required DNSKEY/DS record (updated by validators)
 * @param server Upstream server used for dependent queries
 * @param have_mark Whether connection mark is valid for marking outgoing queries
 * @param mark Connection mark to propagate to dependent TCP queries
 * @param keycount Pointer to remaining recursion limit counter (decremented each iteration)
 * @return Final validation status (STAT_OK, STAT_SECURE, STAT_BOGUS, or STAT_ABANDONED)
 *
 * @note Only available when compiled with HAVE_DNSSEC
 * @note Allocates 65536-byte packet buffer for dependent queries (freed on return)
 * @note Recursion limit enforced via *keycount to prevent DNSSEC validation cycles
 * @warning Returns STAT_ABANDONED if keycount reaches zero (recursion limit exceeded)
 * @warning Returns STAT_ABANDONED if packet allocation fails or tcp_talk fails
 *
 * @see dnssec_validate_by_ds() in dnssec.c for DNSKEY validation
 * @see dnssec_validate_ds() in dnssec.c for DS validation
 * @see dnssec_validate_reply() in dnssec.c for general DNSSEC validation
 * @see tcp_talk() for sending dependent queries via TCP
 * @see tcp_request() which initiates tcp_key_recurse for DNSSEC validation
 *
 * EXAMPLE USAGE:
 * @code
 * int keycount = DNSSEC_WORK; // Maximum recursion depth
 * int status = dnssec_validate_reply(now, header, n, name, keyname, &class, 1, NULL, NULL, NULL);
 * if (status == STAT_NEED_KEY || status == STAT_NEED_DS)
 *   status = tcp_key_recurse(now, status, header, n, class, name, keyname, server, 0, 0, &keycount);
 * @endcode
 *
 * RFC COMPLIANCE: Implements DNSSEC trust chain validation per RFC 4033-4035
 *
 * SIDE EFFECTS:
 * - Allocates and frees 65536-byte packet buffer via whine_malloc/free
 * - Sends dependent DNSKEY/DS queries via tcp_talk()
 * - Modifies daemon->log_display_id for dependent query logging
 * - Decrements *keycount on each recursive iteration
 * - Updates keyname with next required key name (via validation functions)
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static int tcp_key_recurse(time_t now, int status, struct dns_header *header, size_t n, 
			   int class, char *name, char *keyname, struct server *server, 
			   int have_mark, unsigned int mark, int *keycount)
{
  int first, last, start, new_status;
  unsigned char *packet = NULL;
  struct dns_header *new_header = NULL;
  
  while (1)
    {
      size_t m;
      int log_save;
            
      /* limit the amount of work we do, to avoid cycling forever on loops in the DNS */
      if (--(*keycount) == 0)
	new_status = STAT_ABANDONED;
      else if (STAT_ISEQUAL(status, STAT_NEED_KEY))
	new_status = dnssec_validate_by_ds(now, header, n, name, keyname, class);
      else if (STAT_ISEQUAL(status, STAT_NEED_DS))
	new_status = dnssec_validate_ds(now, header, n, name, keyname, class);
      else 
	new_status = dnssec_validate_reply(now, header, n, name, keyname, &class,
					   !option_bool(OPT_DNSSEC_IGN_NS) && (server->flags & SERV_DO_DNSSEC),
					   NULL, NULL, NULL);
      
      if (!STAT_ISEQUAL(new_status, STAT_NEED_DS) && !STAT_ISEQUAL(new_status, STAT_NEED_KEY))
	break;

      /* Can't validate because we need a key/DS whose name now in keyname.
	 Make query for same, and recurse to validate */
      if (!packet)
	{
	  packet = whine_malloc(65536 + MAXDNAME + RRFIXEDSZ + sizeof(u16));
	  new_header = (struct dns_header *)&packet[2];
	}
      
      if (!packet)
	{
	  new_status = STAT_ABANDONED;
	  break;
	}

      m = dnssec_generate_query(new_header, ((unsigned char *) new_header) + 65536, keyname, class, 
				STAT_ISEQUAL(new_status, STAT_NEED_KEY) ? T_DNSKEY : T_DS, server->edns_pktsz);
      
      if ((start = dnssec_server(server, daemon->keyname, &first, &last)) == -1 ||
	  (m = tcp_talk(first, last, start, packet, m, have_mark, mark, &server)) == 0)
	{
	  new_status = STAT_ABANDONED;
	  break;
	}

      log_save = daemon->log_display_id;
      daemon->log_display_id = ++daemon->log_id;
      
      log_query_mysockaddr(F_NOEXTRA | F_DNSSEC | F_SERVER, keyname, &server->addr,
			    STAT_ISEQUAL(status, STAT_NEED_KEY) ? "dnssec-query[DNSKEY]" : "dnssec-query[DS]", 0);
            
      new_status = tcp_key_recurse(now, new_status, new_header, m, class, name, keyname, server, have_mark, mark, keycount);

      daemon->log_display_id = log_save;
      
      if (!STAT_ISEQUAL(new_status, STAT_OK))
	break;
    }
    
  if (packet)
    free(packet);
    
  return new_status;
}
#endif


/* The daemon forks before calling this: it should deal with one connection,
   blocking as necessary, and then return. Note, need to be a bit careful
   about resources for debug mode, when the fork is suppressed: that's
   done by the caller. */
/**
 * @brief Handle TCP-based DNS queries from connected client
 *
 * @detailed Processes one or more DNS queries over established TCP connection,
 * handling TCP length-prefixed message format (2-byte length + DNS packet). Supports
 * query pipelining where multiple queries arrive on same connection. Performs cache
 * lookup, forwards to upstream via TCP if needed, processes responses, and sends
 * length-prefixed responses back to client. Handles EDNS0, DNSSEC, authoritative
 * zones, connection tracking marks, and local service restrictions. Implements
 * TCP-specific timeout handling and connection cleanup.
 *
 * @param confd Connected TCP socket file descriptor
 * @param now Current timestamp for cache operations
 * @param local_addr Local address where connection was accepted
 * @param netmask Network mask for local address (for local service check)
 * @param auth_dns True if this listener is for authoritative DNS zone
 *
 * @return Pointer to allocated packet buffer (caller must free), NULL on allocation failure
 *
 * @note TCP DNS uses 2-byte length prefix before each query/response packet
 * @note Supports query pipelining: processes up to query_count queries per connection
 * @note Allocates buffer of 65536 + MAXDNAME + RRFIXEDSZ + 2 bytes for maximum TCP packet
 * @note Connection mark propagation via HAVE_CONNTRACK if enabled
 * @warning Closes connection and returns NULL on protocol violations or resource exhaustion
 * @warning Enforces --local-service restriction if enabled (one-hop-away addresses only)
 *
 * @see receive_query() which handles UDP queries
 * @see tcp_talk() helper for upstream TCP communication
 * @see forward_query() for upstream forwarding logic
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from daemon when TCP client connects:
 * int tcp_fd = accept(listener_fd, &client_addr, &addrlen);
 * unsigned char *buffer = tcp_request(tcp_fd, time(NULL), &local, netmask, is_auth);
 * if (buffer) free(buffer);
 * close(tcp_fd);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 1035 Section 4.2.2: TCP DNS message format with 2-byte length prefix
 * - RFC 7766: TCP implementation recommendations for DNS
 * - RFC 7828: EDNS0 TCP keepalive option (if supported)
 *
 * SIDE EFFECTS:
 * - Reads queries from TCP socket confd
 * - Writes responses to TCP socket confd
 * - May forward queries to upstream servers via TCP
 * - Performs cache lookups and insertions
 * - Logs queries if logging enabled
 * - Allocates packet buffer via whine_malloc() (caller must free)
 * - May close connection on errors
 *
 * THREAD SAFETY:
 * Not thread-safe (uses daemon globals, cache operations).
 * Safe in single-threaded event loop with one connection per call.
 */
unsigned char *tcp_request(int confd, time_t now,
			   union mysockaddr *local_addr, struct in_addr netmask, int auth_dns)
{
  size_t size = 0;
  int norebind;
#ifdef HAVE_CONNTRACK
  int is_single_query = 0, allowed = 1;
#endif
#ifdef HAVE_AUTH
  int local_auth = 0;
#endif
  int checking_disabled, do_bit, added_pheader = 0, have_pseudoheader = 0;
  int cacheable, no_cache_dnssec = 0, cache_secure = 0, bogusanswer = 0;
  size_t m;
  unsigned short qtype;
  unsigned int gotname;
  /* Max TCP packet + slop + size */
  unsigned char *packet = whine_malloc(65536 + MAXDNAME + RRFIXEDSZ + sizeof(u16));
  unsigned char *payload = &packet[2];
  unsigned char c1, c2;
  /* largest field in header is 16-bits, so this is still sufficiently aligned */
  struct dns_header *header = (struct dns_header *)payload;
  u16 *length = (u16 *)packet;
  struct server *serv;
  struct in_addr dst_addr_4;
  union mysockaddr peer_addr;
  socklen_t peer_len = sizeof(union mysockaddr);
  int query_count = 0;
  unsigned char *pheader;
  unsigned int mark = 0;
  int have_mark = 0;
  int first, last;
  unsigned int flags = 0;
    
  if (!packet || getpeername(confd, (struct sockaddr *)&peer_addr, &peer_len) == -1)
    return packet;

#ifdef HAVE_CONNTRACK
  /* Get connection mark of incoming query to set on outgoing connections. */
  if (option_bool(OPT_CONNTRACK) || option_bool(OPT_CMARK_ALST_EN))
    {
      union all_addr local;
		      
      if (local_addr->sa.sa_family == AF_INET6)
	local.addr6 = local_addr->in6.sin6_addr;
      else
	local.addr4 = local_addr->in.sin_addr;
      
      have_mark = get_incoming_mark(&peer_addr, &local, 1, &mark);
    }
#endif	

  /* We can be configured to only accept queries from at-most-one-hop-away addresses. */
  if (option_bool(OPT_LOCAL_SERVICE))
    {
      struct addrlist *addr;

      if (peer_addr.sa.sa_family == AF_INET6) 
	{
	  for (addr = daemon->interface_addrs; addr; addr = addr->next)
	    if ((addr->flags & ADDRLIST_IPV6) &&
		is_same_net6(&addr->addr.addr6, &peer_addr.in6.sin6_addr, addr->prefixlen))
	      break;
	}
      else
	{
	  struct in_addr netmask;
	  for (addr = daemon->interface_addrs; addr; addr = addr->next)
	    {
	      netmask.s_addr = htonl(~(in_addr_t)0 << (32 - addr->prefixlen));
	      if (!(addr->flags & ADDRLIST_IPV6) && 
		  is_same_net(addr->addr.addr4, peer_addr.in.sin_addr, netmask))
		break;
	    }
	}
      if (!addr)
	{
	  prettyprint_addr(&peer_addr, daemon->addrbuff);
	  my_syslog(LOG_WARNING, _("ignoring query from non-local network %s"), daemon->addrbuff);
	  return packet;
	}
    }

  while (1)
    {
      int ede = EDE_UNSET;

      if (query_count == TCP_MAX_QUERIES ||
	  !packet ||
	  !read_write(confd, &c1, 1, 1) || !read_write(confd, &c2, 1, 1) ||
	  !(size = c1 << 8 | c2) ||
	  !read_write(confd, payload, size, 1))
       	return packet; 
  
      if (size < (int)sizeof(struct dns_header))
	continue;

      /* Clear buffer beyond request to avoid risk of
	 information disclosure. */
      memset(payload + size, 0, 65536 - size);
      
      query_count++;

      /* log_query gets called indirectly all over the place, so 
	 pass these in global variables - sorry. */
      daemon->log_display_id = ++daemon->log_id;
      daemon->log_source_addr = &peer_addr;
      
      /* save state of "cd" flag in query */
      if ((checking_disabled = header->hb4 & HB4_CD))
	no_cache_dnssec = 1;
       
      if ((gotname = extract_request(header, (unsigned int)size, daemon->namebuff, &qtype)))
	{
#ifdef HAVE_AUTH
	  struct auth_zone *zone;
#endif

	  log_query_mysockaddr(F_QUERY | F_FORWARD, daemon->namebuff,
			       &peer_addr, auth_dns ? "auth" : "query", qtype);

#ifdef HAVE_CONNTRACK
	  is_single_query = 1;
#endif
	  
#ifdef HAVE_AUTH
	  /* find queries for zones we're authoritative for, and answer them directly */
	  if (!auth_dns && !option_bool(OPT_LOCALISE))
	    for (zone = daemon->auth_zones; zone; zone = zone->next)
	      if (in_zone(zone, daemon->namebuff, NULL))
		{
		  auth_dns = 1;
		  local_auth = 1;
		  break;
		}
#endif
	}
      
      norebind = domain_no_rebind(daemon->namebuff);
      
      if (local_addr->sa.sa_family == AF_INET)
	dst_addr_4 = local_addr->in.sin_addr;
      else
	dst_addr_4.s_addr = 0;
      
      do_bit = 0;

      if (find_pseudoheader(header, (size_t)size, NULL, &pheader, NULL, NULL))
	{ 
	  unsigned short flags;
	  
	  have_pseudoheader = 1;
	  pheader += 4; /* udp_size, ext_rcode */
	  GETSHORT(flags, pheader);
      
	  if (flags & 0x8000)
	    do_bit = 1; /* do bit */ 
	}
      
#ifdef HAVE_CONNTRACK
#ifdef HAVE_AUTH
      if (!auth_dns || local_auth)
#endif
	if (option_bool(OPT_CMARK_ALST_EN) && have_mark && ((u32)mark & daemon->allowlist_mask))
	  allowed = is_query_allowed_for_mark((u32)mark, is_single_query ? daemon->namebuff : NULL);
#endif

      if (0);
#ifdef HAVE_CONNTRACK
      else if (!allowed)
	{
	  u16 swap = htons(EDE_BLOCKED);

	  m = answer_disallowed(header, size, (u32)mark, is_single_query ? daemon->namebuff : NULL);
	  
	  if (have_pseudoheader && m != 0)
	    m = add_pseudoheader(header,  m, ((unsigned char *) header) + 65536, daemon->edns_pktsz,
				 EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, do_bit, 0);
	}
#endif
#ifdef HAVE_AUTH
      else if (auth_dns)
	m = answer_auth(header, ((char *) header) + 65536, (size_t)size, now, &peer_addr, 
			local_auth, do_bit, have_pseudoheader);
#endif
      else
	{
	   int ad_reqd = do_bit;
	   /* RFC 6840 5.7 */
	   if (header->hb4 & HB4_AD)
	     ad_reqd = 1;
	   
	   /* m > 0 if answered from cache */
	   m = answer_request(header, ((char *) header) + 65536, (size_t)size, 
			      dst_addr_4, netmask, now, ad_reqd, do_bit, have_pseudoheader);
	  
	  /* Do this by steam now we're not in the select() loop */
	  check_log_writer(1); 
	  
	  if (m == 0)
	    {
	      struct server *master;
	      int start;

	      if (lookup_domain(daemon->namebuff, gotname, &first, &last))
		flags = is_local_answer(now, first, daemon->namebuff);
	      else
		{
		  /* No configured servers */
		  ede = EDE_NOT_READY;
		  flags = 0;
		}
	      
	      /* don't forward A or AAAA queries for simple names, except the empty name */
	      if (!flags &&
		  option_bool(OPT_NODOTS_LOCAL) &&
		  (gotname & (F_IPV4 | F_IPV6)) &&
		  !strchr(daemon->namebuff, '.') &&
		  strlen(daemon->namebuff) != 0)
		flags = check_for_local_domain(daemon->namebuff, now) ? F_NOERR : F_NXDOMAIN;
		
	      if (!flags && ede != EDE_NOT_READY)
		{
		  master = daemon->serverarray[first];
		  
		  if (option_bool(OPT_ORDER) || master->last_server == -1)
		    start = first;
		  else
		    start = master->last_server;
		  
		  size = add_edns0_config(header, size, ((unsigned char *) header) + 65536, &peer_addr, now, &cacheable);
		  
#ifdef HAVE_DNSSEC
		  if (option_bool(OPT_DNSSEC_VALID) && (master->flags & SERV_DO_DNSSEC))
		    {
		      size = add_do_bit(header, size, ((unsigned char *) header) + 65536);
		      
		      /* For debugging, set Checking Disabled, otherwise, have the upstream check too,
			 this allows it to select auth servers when one is returning bad data. */
		      if (option_bool(OPT_DNSSEC_DEBUG))
			header->hb4 |= HB4_CD;
		    }
#endif
		  
		  /* Check if we added a pheader on forwarding - may need to
		     strip it from the reply. */
		  if (!have_pseudoheader && find_pseudoheader(header, size, NULL, NULL, NULL, NULL))
		    added_pheader = 1;
		  
		  /* Loop round available servers until we succeed in connecting to one. */
		  if ((m = tcp_talk(first, last, start, packet, size, have_mark, mark, &serv)) == 0)
		    {
		      ede = EDE_NETERR;
		      break;
		    }
		  
		  /* get query name again for logging - may have been overwritten */
		  if (!(gotname = extract_request(header, (unsigned int)size, daemon->namebuff, &qtype)))
		    strcpy(daemon->namebuff, "query");
		  log_query_mysockaddr(F_SERVER | F_FORWARD, daemon->namebuff, &serv->addr, NULL, 0);
		  
#ifdef HAVE_DNSSEC
		  if (option_bool(OPT_DNSSEC_VALID) && !checking_disabled && (master->flags & SERV_DO_DNSSEC))
		    {
		      int keycount = DNSSEC_WORK; /* Limit to number of DNSSEC questions, to catch loops and avoid filling cache. */
		      int status = tcp_key_recurse(now, STAT_OK, header, m, 0, daemon->namebuff, daemon->keyname, 
						   serv, have_mark, mark, &keycount);
		      char *result, *domain = "result";
		      
		      union all_addr a;
		      a.log.ede = ede = errflags_to_ede(status);
		      
		      if (STAT_ISEQUAL(status, STAT_ABANDONED))
			{
			  result = "ABANDONED";
			  status = STAT_BOGUS;
			}
		      else
			result = (STAT_ISEQUAL(status, STAT_SECURE) ? "SECURE" : (STAT_ISEQUAL(status, STAT_INSECURE) ? "INSECURE" : "BOGUS"));
		      
		      if (STAT_ISEQUAL(status, STAT_SECURE))
			cache_secure = 1;
		      else if (STAT_ISEQUAL(status, STAT_BOGUS))
			{
			  no_cache_dnssec = 1;
			  bogusanswer = 1;
			  
			  if (extract_request(header, m, daemon->namebuff, NULL))
			    domain = daemon->namebuff;
			}
		      
		      log_query(F_SECSTAT, domain, &a, result, 0);
		    }
#endif
		  
		  /* restore CD bit to the value in the query */
		  if (checking_disabled)
		    header->hb4 |= HB4_CD;
		  else
		    header->hb4 &= ~HB4_CD;
		  
		  /* Never cache answers which are contingent on the source or MAC address EDSN0 option,
		     since the cache is ignorant of such things. */
		  if (!cacheable)
		    no_cache_dnssec = 1;
		  
		  m = process_reply(header, now, serv, (unsigned int)m, 
				    option_bool(OPT_NO_REBIND) && !norebind, no_cache_dnssec, cache_secure, bogusanswer,
				    ad_reqd, do_bit, added_pheader, &peer_addr, ((unsigned char *)header) + 65536, ede); 
		}
	    }
	}
	
      /* In case of local answer or no connections made. */
      if (m == 0)
	{
	  if (!(m = make_local_answer(flags, gotname, size, header, daemon->namebuff,
				      ((char *) header) + 65536, first, last, ede)))
	    break;
	  
	  if (have_pseudoheader)
	    {
	      u16 swap = htons((u16)ede);

	       if (ede != EDE_UNSET)
		 m = add_pseudoheader(header, m, ((unsigned char *) header) + 65536, daemon->edns_pktsz, EDNS0_OPTION_EDE, (unsigned char *)&swap, 2, do_bit, 0);
	       else
		 m = add_pseudoheader(header, m, ((unsigned char *) header) + 65536, daemon->edns_pktsz, 0, NULL, 0, do_bit, 0);
	    }
	}
      
      check_log_writer(1);
      
      *length = htons(m);
      
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
#ifdef HAVE_AUTH
      if (!auth_dns || local_auth)
#endif
	if (option_bool(OPT_CMARK_ALST_EN) && have_mark && ((u32)mark & daemon->allowlist_mask))
	  report_addresses(header, m, mark);
#endif
      if (!read_write(confd, packet, m + sizeof(u16), 0))
	break;
    }
  
  return packet;
}

/* return a UDP socket bound to a random port, have to cope with straying into
   occupied port nos and reserved ones. */
/**
 * @brief Create UDP socket bound to server's source address and interface
 *
 * @detailed
 * Allocates a new UDP socket (SOCK_DGRAM) for the address family of the upstream server's
 * source address, then binds it to the server's configured source address and network interface.
 * Used for creating randomized source port sockets for DNS queries to prevent cache poisoning.
 * Logs error and closes socket on bind failure. The bound socket provides explicit source
 * address control required for multi-homed hosts and policy routing.
 *
 * @param s Upstream server containing source_addr, interface, and ifindex for binding
 * @return File descriptor of bound UDP socket on success, -1 on socket creation or bind failure
 *
 * @note Socket family (AF_INET or AF_INET6) determined from s->source_addr.sa.sa_family
 * @note Binds to specific interface if s->interface is non-empty
 * @warning Logs error via my_syslog on bind failure (includes interface name or source address)
 * @warning Returns -1 and does not leak socket fd on bind failure
 *
 * @see local_bind() in network.c for interface and address binding
 * @see allocate_rfd() which uses random_sock to create socket pool
 *
 * EXAMPLE USAGE:
 * @code
 * struct server *upstream = daemon->servers;
 * int fd = random_sock(upstream);
 * if (fd != -1) {
 *   sendto(fd, query, query_len, 0, &upstream->addr.sa, sa_len(&upstream->addr));
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Creates UDP socket via socket()
 * - Binds socket to source address and interface via local_bind()
 * - Logs error via my_syslog on bind failure
 * - Closes socket via close() on bind failure
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static int random_sock(struct server *s)
{
  int fd;

  if ((fd = socket(s->source_addr.sa.sa_family, SOCK_DGRAM, 0)) != -1)
    {
      if (local_bind(fd, &s->source_addr, s->interface, s->ifindex, 0))
	return fd;

      if (s->interface[0] == 0)
	(void)prettyprint_addr(&s->source_addr, daemon->namebuff);
      else
	strcpy(daemon->namebuff, s->interface);

      my_syslog(LOG_ERR, _("failed to bind server socket to %s: %s"),
		daemon->namebuff, strerror(errno));
      close(fd);
    }
  
  return -1;
}

/**
 * @brief Compare two server records for source address and interface equality
 *
 * @detailed
 * Determines if two upstream server records are equivalent in terms of network binding
 * (source address, interface index, and interface name). Used by allocate_rfd() to find
 * existing randomized sockets that can be reused for queries to the same logical upstream
 * when multiple server records exist for the same destination. Compares interface index
 * (kernel interface ID), source address (IP and port), and interface name string. Returns
 * false if serv2 is NULL (allows safe comparison with potentially cleared server pointers).
 *
 * @param serv1 First server record to compare (must not be NULL)
 * @param serv2 Second server record to compare (may be NULL)
 * @return 1 if servers are equivalent (same source binding), 0 if different or serv2 is NULL
 *
 * @note NULL-safe: Returns 0 if serv2 is NULL
 * @note Compares interface index, source address (via sockaddr_isequal), and interface name
 * @note Interface name comparison limited to IF_NAMESIZE (typically 16 bytes on Linux)
 * @warning Does not compare destination address (only source binding parameters)
 *
 * @see sockaddr_isequal() for address comparison logic
 * @see allocate_rfd() which uses server_isequal for socket reuse detection
 *
 * EXAMPLE USAGE:
 * @code
 * struct server *serv_a = daemon->servers;
 * struct server *serv_b = serv_a->next;
 * if (server_isequal(serv_a, serv_b)) {
 *   // Can reuse same randomized socket for both servers
 *   fd = serv_a->sfd->fd;
 * }
 * @endcode
 *
 * SIDE EFFECTS: None - pure comparison function (read-only)
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static int server_isequal(const struct server *serv1,
			 const struct server *serv2)
{
  return (serv2 &&
    serv2->ifindex == serv1->ifindex &&
    sockaddr_isequal(&serv2->source_addr, &serv1->source_addr) &&
    strncmp(serv2->interface, serv1->interface, IF_NAMESIZE) == 0);
}

/* fdlp points to chain of randomfds already in use by transaction.
   If there's already a suitable one, return it, else allocate a 
   new one and add it to the list. 

   Not leaking any resources in the face of allocation failures
   is rather convoluted here.
   
   Note that rfd->serv may be NULL, when a server goes away.
*/
/**
 * @brief Allocate randomized source port socket for upstream query
 *
 * @detailed Manages pool of random source port sockets to prevent DNS cache poisoning
 * by making source ports unpredictable. Returns existing socket if transaction already
 * has one for this server, otherwise allocates new socket with random port or reuses
 * existing socket from pool (with refcount tracking). Prefers server pre-allocated
 * socket (serv->sfd) if available. Implements round-robin socket reuse when pool
 * exhausted. Limits total socket count to avoid resource starvation.
 *
 * @param fdlp Pointer to list head of randfd_list for this transaction (modified)
 * @param serv Upstream server for socket allocation (determines AF_INET vs AF_INET6)
 *
 * @return File descriptor of allocated socket, -1 on allocation failure
 *
 * @retval >=0 Valid file descriptor for upstream query transmission
 * @retval -1 Resource allocation failed (malloc failure or too many open sockets)
 *
 * @note Randomized source ports critical security feature to prevent cache poisoning
 * @note Reuses sockets when possible to limit resource consumption (daemon->numrrand limit)
 * @note Reference counting allows socket sharing between multiple transactions
 * @warning Socket pool size daemon->numrrand limits concurrent queries to same server
 * @warning Static finger variable maintains round-robin state across calls (not thread-safe)
 *
 * @see forward_query() which calls this to get socket for upstream transmission
 * @see random_sock() which creates new socket with random port binding
 * @see free_rfds() to release sockets and decrement refcounts after transaction completes
 * @see server_isequal() for server comparison to enable socket reuse
 *
 * EXAMPLE USAGE:
 * @code
 * struct randfd_list *rfd_list = NULL;
 * int upstream_fd = allocate_rfd(&rfd_list, upstream_server);
 * if (upstream_fd >= 0)
 *   sendto(upstream_fd, query, query_len, 0, &server->addr, sizeof(server->addr));
 * free_rfds(&rfd_list); // Clean up after transaction
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 5452: Source port randomization for DNS poisoning prevention
 *
 * SIDE EFFECTS:
 * - Allocates randfd_list entry via whine_malloc() or daemon->rfl_spare pool
 * - Creates new socket via random_sock() if pool has capacity
 * - Increments refcount on reused sockets (daemon->randomsocks[].refcount)
 * - Modifies *fdlp to prepend allocated randfd_list entry
 * - May call set_outgoing_mark() if HAVE_CONNTRACK enabled
 *
 * THREAD SAFETY:
 * Not thread-safe (modifies static finger, daemon globals, shared socket pool).
 * Safe in single-threaded event loop model.
 */
int allocate_rfd(struct randfd_list **fdlp, struct server *serv)
{
  static int finger = 0;
  int i, j = 0;
  struct randfd_list *rfl;
  struct randfd *rfd = NULL;
  int fd = 0;
  
  /* If server has a pre-allocated fd, use that. */
  if (serv->sfd)
    return serv->sfd->fd;
  
  /* existing suitable random port socket linked to this transaction? */
  for (rfl = *fdlp; rfl; rfl = rfl->next)
    if (server_isequal(serv, rfl->rfd->serv))
      return rfl->rfd->fd;

  /* No. need new link. */
  if ((rfl = daemon->rfl_spare))
    daemon->rfl_spare = rfl->next;
  else if (!(rfl = whine_malloc(sizeof(struct randfd_list))))
    return -1;
   
  /* limit the number of sockets we have open to avoid starvation of 
     (eg) TFTP. Once we have a reasonable number, randomness should be OK */
  for (i = 0; i < daemon->numrrand; i++)
    if (daemon->randomsocks[i].refcount == 0)
      {
	if ((fd = random_sock(serv)) != -1)
    	  {
	    rfd = &daemon->randomsocks[i];
	    rfd->serv = serv;
	    rfd->fd = fd;
	    rfd->refcount = 1;
	  }
	break;
      }
  
  /* No free ones or cannot get new socket, grab an existing one */
  if (!rfd)
    for (j = 0; j < daemon->numrrand; j++)
      {
	i = (j + finger) % daemon->numrrand;
	if (daemon->randomsocks[i].refcount != 0 &&
	    server_isequal(serv, daemon->randomsocks[i].serv) &&
	    daemon->randomsocks[i].refcount != 0xfffe)
	  {
	    finger = i + 1;
	    rfd = &daemon->randomsocks[i];
	    rfd->refcount++;
	    break;
	  }
      }

  if (!rfd) /* should be when j == daemon->numrrand */
    {
      struct randfd_list *rfl_poll;

      /* there are no free slots, and non with the same parameters we can piggy-back on. 
	 We're going to have to allocate a new temporary record, distinguished by
	 refcount == 0xffff. This will exist in the frec randfd list, never be shared,
	 and be freed when no longer in use. It will also be held on 
	 the daemon->rfl_poll list so the poll system can find it. */

      if ((rfl_poll = daemon->rfl_spare))
	daemon->rfl_spare = rfl_poll->next;
      else
	rfl_poll = whine_malloc(sizeof(struct randfd_list));
      
      if (!rfl_poll ||
	  !(rfd = whine_malloc(sizeof(struct randfd))) ||
	  (fd = random_sock(serv)) == -1)
	{
	  
	  /* Don't leak anything we may already have */
	  rfl->next = daemon->rfl_spare;
	  daemon->rfl_spare = rfl;

	  if (rfl_poll)
	    {
	      rfl_poll->next = daemon->rfl_spare;
	      daemon->rfl_spare = rfl_poll;
	    }
	  
	  if (rfd)
	    free(rfd);
	  
	  return -1; /* doom */
	}

      /* Note rfd->serv not set here, since it's not reused */
      rfd->fd = fd;
      rfd->refcount = 0xffff; /* marker for temp record */

      rfl_poll->rfd = rfd;
      rfl_poll->next = daemon->rfl_poll;
      daemon->rfl_poll = rfl_poll;
    }
  
  rfl->rfd = rfd;
  rfl->next = *fdlp;
  *fdlp = rfl;
  
  return rfl->rfd->fd;
}

/**
 * @brief Release randomized source port sockets after query completion
 *
 * @detailed Decrements reference counts on all random port sockets in transaction list,
 * closes sockets when refcount reaches zero, and returns randfd_list entries to spare
 * pool for reuse. Handles special overflow records (refcount 0xffff) which are temporary
 * allocations needing full cleanup. Iterates through transaction socket list and updates
 * global daemon socket structures.
 *
 * @param fdlp Pointer to head of randfd_list chain (set to NULL on return)
 *
 * @note Called after query transaction completes to release socket resources
 * @note Closes socket only when refcount decrements to zero (may be shared by other transactions)
 * @note Returns randfd_list entries to daemon->rfl_spare pool for memory efficiency
 * @note Overflow records (refcount 0xffff) are fully freed including socket and structure
 * @warning Must be called for every transaction that called allocate_rfd() to prevent socket leaks
 *
 * @see allocate_rfd() which allocates sockets and increments refcounts
 * @see reply_query() which calls this after forwarding response to client
 * @see forward_query() for transaction lifecycle context
 *
 * EXAMPLE USAGE:
 * @code
 * struct randfd_list *rfd_list = NULL;
 * int fd = allocate_rfd(&rfd_list, server);
 * // ... use fd for query ...
 * free_rfds(&rfd_list); // Release after query completes
 * @endcode
 *
 * SIDE EFFECTS:
 * - Decrements refcount on daemon->randomsocks[] entries
 * - Closes sockets when refcount reaches zero
 * - Frees overflow randfd structures (refcount 0xffff)
 * - Returns randfd_list entries to daemon->rfl_spare pool
 * - Sets *fdlp to NULL
 * - Modifies daemon->rfl_poll list for overflow cleanup
 *
 * THREAD SAFETY:
 * Not thread-safe (modifies shared daemon socket pool and freelists).
 * Safe in single-threaded event loop model.
 */
void free_rfds(struct randfd_list **fdlp)
{
  struct randfd_list *tmp, *rfl, *poll, *next, **up;
  
  for (rfl = *fdlp; rfl; rfl = tmp)
    {
      if (rfl->rfd->refcount == 0xffff || --(rfl->rfd->refcount) == 0)
	close(rfl->rfd->fd);

      /* temporary overflow record */
      if (rfl->rfd->refcount == 0xffff)
	{
	  free(rfl->rfd);
	  
	  /* go through the link of all these by steam to delete.
	     This list is expected to be almost always empty. */
	  for (poll = daemon->rfl_poll, up = &daemon->rfl_poll; poll; poll = next)
	    {
	      next = poll->next;
	      
	      if (poll->rfd == rfl->rfd)
		{
		  *up = poll->next;
		  poll->next = daemon->rfl_spare;
		  daemon->rfl_spare = poll;
		}
	      else
		up = &poll->next;
	    }
	}

      tmp = rfl->next;
      rfl->next = daemon->rfl_spare;
      daemon->rfl_spare = rfl;
    }

  *fdlp = NULL;
}

/**
 * @brief Release forward record after query transaction completes
 *
 * @detailed Returns forward record to available state for reuse, clearing all transaction
 * data. Releases random port sockets via free_rfds(), returns frec_src entries (for
 * multiple clients sharing query) to freelist, clears DNSSEC blockdata and dependency
 * chains. Implements recursive freeing: if this frec was dependent on blocking DNSSEC
 * query and was last dependent, frees blocking query too. Does not deallocate frec
 * structure itself (statically allocated pool).
 *
 * @param f Forward record to free (from daemon->frec_list pool)
 *
 * @note Forward records are never deallocated, only marked available via sentto=NULL
 * @note Handles query aggregation: multiple frec_src entries for duplicate client queries
 * @note DNSSEC support: frees blockdata stash and manages blocking query dependencies
 * @note Recursive: may free blocking_query if this was last dependent
 * @warning Must be called for every allocated forward record to prevent resource exhaustion
 * @warning Recursive calls can free multiple frecs in DNSSEC validation chains
 *
 * @see get_new_frec() which allocates forward records from pool
 * @see return_reply() which calls this after delivering response to clients
 * @see free_rfds() to release random port sockets
 *
 * EXAMPLE USAGE:
 * @code
 * // After sending response to all clients:
 * return_reply(now, forward, header, packet_len, status);
 * free_frec(forward); // Release forward record for reuse
 * @endcode
 *
 * SIDE EFFECTS:
 * - Releases random port sockets via free_rfds(&f->rfds)
 * - Returns frec_src entries to daemon->free_frec_src pool
 * - Frees DNSSEC blockdata via blockdata_free(f->stash) if HAVE_DNSSEC
 * - Unlinks from blocking_query dependency chain if HAVE_DNSSEC
 * - May recursively free blocking_query if this was last dependent
 * - Clears f->sentto, f->flags, f->frec_src.next, f->stash, f->blocking_query, f->dependent
 *
 * THREAD SAFETY:
 * Not thread-safe (modifies shared frec pool and freelists).
 * Safe in single-threaded event loop model.
 */
static void free_frec(struct frec *f)
{
  struct frec_src *last;
  
  /* add back to freelist if not the record builtin to every frec. */
  for (last = f->frec_src.next; last && last->next; last = last->next) ;
  if (last)
    {
      last->next = daemon->free_frec_src;
      daemon->free_frec_src = f->frec_src.next;
    }
    
  f->frec_src.next = NULL;    
  free_rfds(&f->rfds);
  f->sentto = NULL;
  f->flags = 0;

#ifdef HAVE_DNSSEC
  if (f->stash)
    {
      blockdata_free(f->stash);
      f->stash = NULL;
    }

  /* Anything we're waiting on is pointless now, too */
  if (f->blocking_query)
    {
      struct frec *n, **up;

      /* unlink outselves from the blocking query's dependents list. */
      for (n = f->blocking_query->dependent, up = &f->blocking_query->dependent; n; n = n->next_dependent)
	if (n == f)
	  {
	    *up = n->next_dependent;
	    break;
	  }
	else
	  up = &n->next_dependent;

      /* If we were the only/last dependent, free the blocking query too. */
      if (!f->blocking_query->dependent)
	free_frec(f->blocking_query);
    }
  
  f->blocking_query = NULL;
  f->dependent = NULL;
  f->next_dependent = NULL;
#endif
}



/**
 * @brief Allocate forward record from pool for new DNS transaction
 *
 * @detailed Finds available forward record from daemon->frec_list pool, implementing
 * garbage collection of expired records (4*TIMEOUT age limit), per-server-group quotas
 * to prevent single server monopolizing pool, and resource exhaustion detection. Returns
 * free record if available, oldest expired record if garbage collection needed, or forces
 * allocation beyond limits for DNSSEC queries. Logs "Maximum number of concurrent DNS
 * queries reached" when pool exhausted.
 *
 * @param now Current timestamp for age comparison (garbage collection threshold)
 * @param master Upstream server for this query (used for per-server-group counting)
 * @param force If true, bypass limits and return record even if pool exhausted (DNSSEC)
 *
 * @return Pointer to allocated forward record, NULL if exhausted and force=false
 *
 * @retval non-NULL Available forward record ready for transaction use
 * @retval NULL Pool exhausted, cannot allocate (only if force=false)
 *
 * @note Forward record pool size set by --dns-forward-max (default FTABSIZ=150)
 * @note Garbage collection: records older than 4*TIMEOUT seconds are reclaimed
 * @note Per-server-group limit: prevents single server consuming entire pool
 * @note Force mode for DNSSEC: prevents freeing records in active validation chains
 * @warning Pool exhaustion causes query drops until existing transactions complete
 * @warning Force mode bypasses safety limits: used only for DNSSEC internal queries
 *
 * @see free_frec() to return records to pool after transaction completes
 * @see forward_query() which calls this to allocate frec for new queries
 * @see query_full() logging function called when pool exhausted
 *
 * EXAMPLE USAGE:
 * @code
 * struct frec *forward = get_new_frec(time(NULL), upstream_server, 0);
 * if (!forward) {
 *   // Pool exhausted, cannot forward query
 *   return send_refused_response(client);
 * }
 * forward->sentto = upstream_server;
 * // ... configure forward record and send query ...
 * @endcode
 *
 * RFC COMPLIANCE:
 * - No specific RFC, implementation-defined resource management
 *
 * SIDE EFFECTS:
 * - May call free_frec() on expired records (garbage collection)
 * - Logs warning via query_full() when pool exhausted
 * - Returns record with cleared state (sentto=NULL becomes non-NULL after allocation)
 *
 * THREAD SAFETY:
 * Not thread-safe (modifies shared daemon->frec_list pool).
 * Safe in single-threaded event loop model.
 */
/* Impose an absolute
   limit of 4*TIMEOUT before we wipe things (for random sockets).
   If force is set, always return a result, even if we have
   to allocate above the limit, and don'y free any records.
   This is set when allocating for DNSSEC to avoid cutting off
   the branch we are sitting on. */
static struct frec *get_new_frec(time_t now, struct server *master, int force)
{
  struct frec *f, *oldest, *target;
  int count;
  
  /* look for free records, garbage collect old records and count number in use by our server-group. */
  for (f = daemon->frec_list, oldest = NULL, target =  NULL, count = 0; f; f = f->next)
    {
      if (!f->sentto)
	target = f;
      else
	{
#ifdef HAVE_DNSSEC
	  /* Don't free DNSSEC sub-queries here, as we may end up with
	     dangling references to them. They'll go when their "real" query 
	     is freed. */
	  if (!f->dependent && !force)
#endif
	    {
	      if (difftime(now, f->time) >= 4*TIMEOUT)
		{
		  free_frec(f);
		  target = f;
		}
	      else if (!oldest || difftime(f->time, oldest->time) <= 0)
		oldest = f;
	    }
	}
      
      if (f->sentto && ((int)difftime(now, f->time)) < TIMEOUT && server_samegroup(f->sentto, master))
	count++;
    }

  if (!force && count >= daemon->ftabsize)
    {
      query_full(now, master->domain);
      return NULL;
    }
  
  if (!target && oldest && ((int)difftime(now, oldest->time)) >= TIMEOUT)
    { 
      /* can't find empty one, use oldest if there is one and it's older than timeout */
      free_frec(oldest);
      target = oldest;
    }
  
  if (!target && (target = (struct frec *)whine_malloc(sizeof(struct frec))))
    {
      target->next = daemon->frec_list;
      daemon->frec_list = target;
    }

  if (target)
    target->time = now;

  return target;
}

/**
 * @brief Log warning when forward record pool exhausted
 *
 * @detailed Rate-limited logging function (maximum once per 5 seconds) to warn when
 * daemon->frec_list pool is exhausted, preventing new queries from being forwarded.
 * Provides different messages for global exhaustion vs per-domain exhaustion. Static
 * last_log variable implements rate limiting to avoid log flooding during sustained
 * overload conditions.
 *
 * @param now Current timestamp for rate limiting comparison
 * @param domain Domain name causing exhaustion (NULL or empty for global limit)
 *
 * @note Rate limited to one log message per 5 seconds regardless of call frequency
 * @note Message includes daemon->ftabsize (max concurrent queries, default 150)
 * @warning Static last_log makes this function not thread-safe
 *
 * @see get_new_frec() which calls this when pool exhausted
 * @see forward_query() which may trigger this on high query load
 *
 * EXAMPLE USAGE:
 * @code
 * if (!get_new_frec(now, server, 0))
 *   query_full(now, NULL); // Log global pool exhaustion
 * @endcode
 *
 * SIDE EFFECTS:
 * - Logs warning message via my_syslog(LOG_WARNING)
 * - Updates static last_log timestamp
 *
 * THREAD SAFETY:
 * Not thread-safe (static last_log variable).
 * Safe in single-threaded event loop model.
 */
static void query_full(time_t now, char *domain)
{
  static time_t last_log = 0;
  
  if ((int)difftime(now, last_log) > 5)
    {
      last_log = now;
      if (!domain || strlen(domain) == 0)
	my_syslog(LOG_WARNING, _("Maximum number of concurrent DNS queries reached (max: %d)"), daemon->ftabsize);
      else
	my_syslog(LOG_WARNING, _("Maximum number of concurrent DNS queries to %s reached (max: %d)"), domain, daemon->ftabsize);
    }
}


/**
 * @brief Find forward record matching response ID, hash, and socket
 *
 * @detailed Searches daemon->frec_list for forward record matching upstream response,
 * using query ID (randomized by forward_query), question hash (SHA-256 digest), and
 * receiving socket file descriptor. Triple-key matching provides spoof protection:
 * attacker must guess randomized ID, know question hash, and match socket. Handles
 * both random port sockets (f->rfds list) and server-bound sockets (s->sfd).
 *
 * @param id Randomized query ID from DNS response header (f->new_id)
 * @param fd File descriptor that received response (random port or server socket)
 * @param hash SHA-256 hash of question section from response (HASH_SIZE bytes)
 * @param firstp Output: first index in serverarray for matched server group
 * @param lastp Output: last index in serverarray for matched server group
 *
 * @return Pointer to matching forward record, NULL if no match found
 *
 * @retval non-NULL Forward record for this query
 * @retval NULL No matching record (possible spoof attempt or late response)
 *
 * @note Requires all three of ID, hash, and socket FD to match for security
 * @note Populates firstp/lastp via filter_servers() for server group iteration
 * @note Used by reply_query() to find forward record for upstream response
 * @warning Returns NULL for spoofed responses with wrong ID, hash, or socket
 *
 * @see reply_query() which calls this to match responses to queries
 * @see hash_questions() which generates question hash
 * @see forward_query() which sets f->new_id to randomized value
 *
 * EXAMPLE USAGE:
 * @code
 * void *hash = hash_questions(header, packet_len, namebuff);
 * int first, last;
 * struct frec *forward = lookup_frec(ntohs(header->id), recv_fd, hash, &first, &last);
 * if (forward) process_response(forward); // Legitimate response
 * else drop_packet(); // Spoof or late response
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 5452: DNS cache poisoning prevention via ID/port randomization
 *
 * SIDE EFFECTS:
 * - Sets *firstp and *lastp via filter_servers() if match found
 * - Read-only traversal of daemon->frec_list and socket lists
 *
 * THREAD SAFETY:
 * Thread-safe (read-only access).
 * Safe in single-threaded event loop model.
 */
static struct frec *lookup_frec(unsigned short id, int fd, void *hash, int *firstp, int *lastp)
{
  struct frec *f;
  struct server *s;
  int first, last;
  struct randfd_list *fdl;

  if (hash)
    for (f = daemon->frec_list; f; f = f->next)
      if (f->sentto && f->new_id == id && 
	  (memcmp(hash, f->hash, HASH_SIZE) == 0))
	{
	  filter_servers(f->sentto->arrayposn, F_SERVER, firstp, lastp);
	  
	  /* sent from random port */
	  for (fdl = f->rfds; fdl; fdl = fdl->next)
	    if (fdl->rfd->fd == fd)
	      return f;
	  
	  /* Sent to upstream from socket associated with a server. 
	     Note we have to iterate over all the possible servers, since they may
	     have different bound sockets. */
	  for (first = *firstp, last = *lastp; first != last; first++)
	    {
	      s = daemon->serverarray[first];
	      if (s->sfd && s->sfd->fd == fd)
		return f;
	    }
	}
  
  return NULL;
}

/**
 * @brief Lookup forward record by query hash and flags
 *
 * @detailed
 * Searches the active forward record list for a transaction matching the provided
 * query hash and flag criteria. Uses the SHA-256 hash of the DNS query question
 * section for matching, enabling duplicate query detection and coalescing. The
 * flagmask parameter allows selective flag matching (e.g., match DNSSEC queries only).
 * Returns NULL if no matching forward record exists or if hash is NULL.
 *
 * @param hash Pointer to HASH_SIZE byte SHA-256 digest of query question section, or NULL
 * @param flags Required flag bits that must be set (after masking)
 * @param flagmask Mask selecting which flag bits to compare
 * @return Pointer to matching frec if found, NULL if no match or hash is NULL
 *
 * @note Only searches forward records with sentto != NULL (active queries)
 * @note Hash comparison uses constant-time memcmp for HASH_SIZE bytes
 * @warning Caller must validate returned frec is still valid before use
 *
 * @see lookup_frec() for ID/socket-based lookup
 * @see lookup_frec_dnssec() for DNSSEC-specific lookup using blockdata stash
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char query_hash[HASH_SIZE];
 * hash_questions(header, plen, query_hash);
 * struct frec *existing = lookup_frec_by_query(query_hash, F_DNSSEC, F_DNSSEC);
 * if (existing)
 *   return existing; // Coalesce duplicate DNSSEC query
 * @endcode
 *
 * SIDE EFFECTS: None - read-only search operation
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static struct frec *lookup_frec_by_query(void *hash, unsigned int flags, unsigned int flagmask)
{
  struct frec *f;

  if (hash)
    for (f = daemon->frec_list; f; f = f->next)
      if (f->sentto &&
	  (f->flags & flagmask) == flags &&
	  memcmp(hash, f->hash, HASH_SIZE) == 0)
	return f;
  
  return NULL;
}

#ifdef HAVE_DNSSEC
/**
 * @brief Lookup forward record for DNSSEC query by target name and class
 *
 * @detailed
 * DNSSEC-specific forward record lookup that searches by reconstructing the query
 * from the blockdata stash and comparing target domain name and class. DNSSEC queries
 * store the complete original query in f->stash via blockdata_save(), enabling exact
 * query matching even when query IDs are rewritten. Retrieves the stashed query into
 * the provided header buffer, extracts the question name, skips the type field (known
 * from flags), and compares the class field. Used for dependent query coalescing in
 * DNSSEC validation chains.
 *
 * @param target Target domain name buffer to match (e.g., "example.com" for DS lookup)
 * @param class DNS class to match (typically C_IN = 1 for Internet class)
 * @param flags Required flag bits (e.g., F_DNSSEC) that must be set
 * @param header DNS header buffer for temporary query reconstruction from stash
 * @return Pointer to matching frec if found, NULL if no DNSSEC query matches
 *
 * @note Only available when compiled with HAVE_DNSSEC
 * @note Requires blockdata stash to be populated (f->stash != NULL)
 * @note Only searches forward records with sentto != NULL (active queries)
 * @warning blockdata_retrieve modifies header buffer as side effect
 *
 * @see lookup_frec() for standard ID-based lookup
 * @see lookup_frec_by_query() for hash-based lookup
 * @see blockdata_retrieve() in blockdata.c for stash retrieval
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *temp_header = whine_malloc(DNSSEC_WORK * sizeof(struct dns_header));
 * struct frec *existing = lookup_frec_dnssec("example.com", C_IN, F_DNSSEC, temp_header);
 * if (existing)
 *   return existing; // Coalesce duplicate DNSSEC dependent query
 * @endcode
 *
 * RFC COMPLIANCE: Supports DNSSEC validation per RFC 4033-4035
 *
 * SIDE EFFECTS: Writes to header buffer during blockdata_retrieve and extract_name
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static struct frec *lookup_frec_dnssec(char *target, int class, int flags, struct dns_header *header)
{
   struct frec *f;

   for (f = daemon->frec_list; f; f = f->next)
     if (f->sentto &&
	 (f->flags & flags) &&
	 blockdata_retrieve(f->stash, f->stash_len, (void *)header))
       {
	 unsigned char *p = (unsigned char *)(header+1);
	 int hclass;

	 if (extract_name(header, f->stash_len, &p, target, 0, 4) != 1)
	   continue;

	 p += 2;  /* type, known from flags */ 
	 GETSHORT(hclass, p);

	 if (class != hclass)
	   continue;

	 return f;
       }

   return NULL;
}
#endif

/**
 * @brief Resend last query packet to saved upstream server
 *
 * @detailed
 * Re-transmits the most recently saved DNS query packet to the previously selected
 * upstream server. Used by DNSSEC validation to resend queries after trust anchor
 * updates or configuration changes. The query packet and destination server are stored
 * in daemon->packet, daemon->packet_len, daemon->srv_save, and daemon->fd_save by
 * previous query operations. No-op if srv_save is NULL (no saved query exists).
 *
 * @return void
 *
 * @note Requires daemon->srv_save to be set by prior server_send() call
 * @note Global state dependency: daemon->packet, daemon->packet_len, daemon->fd_save
 * @warning No validation that saved query is still valid or recent
 *
 * @see server_send() which populates daemon->srv_save for resend capability
 *
 * EXAMPLE USAGE:
 * @code
 * // After trust anchor update in DNSSEC validation
 * reload_trust_anchors();
 * resend_query(); // Re-validate with updated anchors
 * @endcode
 *
 * SIDE EFFECTS: Sends UDP packet via server_send() if srv_save != NULL
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
void resend_query()
{
  if (daemon->srv_save)
    server_send(daemon->srv_save, daemon->fd_save,
		daemon->packet, daemon->packet_len, 0);
}

/**
 * @brief Cleanup all references to upstream server being removed
 *
 * @detailed
 * Called when an upstream server record is being deleted (e.g., configuration reload,
 * server failure threshold exceeded). Iterates through all active forward records and
 * frees any queries awaiting responses from the departing server. Clears server references
 * in the random socket pool to prevent use-after-free errors. Nulls the global saved server
 * pointer if it references the departing server. Ensures clean removal of server without
 * dangling pointers or resource leaks.
 *
 * @param server Pointer to struct server being removed from upstream server list
 * @return void
 *
 * @note Iterates entire forward record list (potentially expensive for many queries)
 * @note Frees forward records immediately without attempting retry to other servers
 * @warning Must be called before server struct is deallocated to prevent use-after-free
 * @warning Drops any queries awaiting responses from this server (clients timeout)
 *
 * @see free_frec() for forward record cleanup
 * @see option.c for server configuration and removal triggers
 *
 * EXAMPLE USAGE:
 * @code
 * struct server *failing_server = find_server_by_addr(&addr);
 * if (failing_server->failed_queries > FAILURE_THRESHOLD) {
 *   server_gone(failing_server); // Clean references
 *   free(failing_server); // Safe to deallocate
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Frees forward records via free_frec() (returns to freelist)
 * - Modifies daemon->randomsocks[] array (NULLs server pointers)
 * - May modify daemon->srv_save (sets to NULL if matches)
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
void server_gone(struct server *server)
{
  struct frec *f;
  int i;
  
  for (f = daemon->frec_list; f; f = f->next)
    if (f->sentto && f->sentto == server)
      free_frec(f);

  /* If any random socket refers to this server, NULL the reference.
     No more references to the socket will be created in the future. */
  for (i = 0; i < daemon->numrrand; i++)
    if (daemon->randomsocks[i].refcount != 0 && daemon->randomsocks[i].serv == server)
      daemon->randomsocks[i].serv = NULL;
  
  if (daemon->srv_save == server)
    daemon->srv_save = NULL;
}

/**
 * @brief Generate unique random DNS query ID for cache poisoning prevention
 *
 * @detailed
 * Generates a cryptographically random 16-bit DNS query ID using rand16() SURF random
 * number generator, ensuring uniqueness across all active forward records. Loops until
 * finding an ID not currently in use by any pending query (checks f->new_id in all frecs
 * with sentto != NULL). The unique randomized ID prevents DNS cache poisoning attacks by
 * making query ID prediction infeasible. Combined with source port randomization, this
 * provides ~32 bits of entropy for query identification.
 *
 * @return Unique random 16-bit query ID not in use by any active forward record
 *
 * @note Uses rand16() from util.c (SURF RNG from djbdns, cryptographically strong)
 * @note Loops until unique ID found (worst case ~65536 iterations if all IDs in use)
 * @note Collision probability increases with number of concurrent queries (birthday paradox)
 * @warning Infinite loop if all 65536 possible IDs are in use (effectively impossible)
 *
 * @see rand16() in util.c for random number generation
 * @see forward_query() which uses get_id() to randomize outgoing query IDs
 *
 * EXAMPLE USAGE:
 * @code
 * struct frec *forward = get_new_frec(now, NULL, 0);
 * forward->new_id = get_id(); // Randomize ID for cache poisoning prevention
 * header->id = htons(forward->new_id);
 * @endcode
 *
 * RFC COMPLIANCE: Implements DNS ID randomization per RFC 5452 (cache poisoning prevention)
 *
 * SIDE EFFECTS: None - pure function returning random unique value
 *
 * THREAD SAFETY: Safe in single-threaded event loop model (not thread-safe for concurrent access)
 */
static unsigned short get_id(void)
{
  unsigned short ret = 0;
  struct frec *f;
  
  while (1)
    {
      ret = rand16();

      /* ensure id is unique. */
      for (f = daemon->frec_list; f; f = f->next)
	if (f->sentto && f->new_id == ret)
	  break;

      if (!f)
	return ret;
    }
}
