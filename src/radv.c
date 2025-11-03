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
 * @file radv.c
 * @brief IPv6 Router Advertisement transmission per RFC 4861
 * 
 * DETAILED PURPOSE:
 * This module implements IPv6 Router Advertisement (RA) functionality as specified in
 * RFC 4861 Section 6. It handles periodic ICMPv6 Router Advertisement broadcasts that
 * inform IPv6 clients about network prefixes, router lifetime, MTU, and DNS configuration.
 * The implementation supports both solicited and unsolicited RAs, includes prefix information
 * options with valid/preferred lifetimes, sets Managed (M) and Other (O) configuration flags
 * for DHCPv6 coordination, and handles router priority and advertisement interval options.
 * 
 * The code supports interface aliasing via --bridge-interface, allowing a single RA to be
 * transmitted on multiple physical interfaces with the same configuration context. It integrates
 * with the DHCPv6 subsystem to determine prefix lifetimes and configuration flags, and handles
 * both stateful and stateless address autoconfiguration (SLAAC) signaling.
 * 
 * KEY RESPONSIBILITIES:
 * - ra_init(): Initialize ICMPv6 raw socket with packet filters for Router Solicitation and Echo Reply
 * - send_ra()/send_ra_alias(): Construct and transmit Router Advertisement packets with prefix options
 * - icmp6_packet(): Process incoming Router Solicitation messages and respond with solicited RAs
 * - periodic_ra(): Schedule and execute periodic unsolicited Router Advertisements per RFC 4861 timing
 * - add_prefixes(): Enumerate interface addresses and construct prefix information options
 * 
 * DEPENDENCIES:
 * Internal includes: dnsmasq.h (daemon structures, DHCPv6 contexts), radv-protocol.h (RA packet formats)
 * External includes: netinet/icmp6.h (ICMPv6 constants and structures)
 * Called by: dnsmasq.c main loop for initialization, DHCPv6 code on address changes
 * Calls: Network layer (iface_enumerate(), indextoname()), DHCPv6 context management, outpacket buffer
 * 
 * DATA STRUCTURES:
 * - struct ra_param (lines 29-37): Parameter block for RA construction with context and timing
 * - struct search_param (lines 39-42): Search parameters for finding overdue RA contexts
 * - struct alias_param (lines 44-50): Parameters for handling interface aliases
 * - struct ra_packet (radv-protocol.h:27-34): ICMPv6 Router Advertisement packet header
 * - struct prefix_opt (radv-protocol.h:43-47): Prefix Information option (RFC 4861 Section 4.6.2)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP6: Required - entire file conditionally compiled only when DHCPv6 support enabled
 * - HAVE_LINUX_NETWORK: Linux-specific MTU retrieval from /proc/sys/net/ipv6/conf/*/mtu
 * - HAVE_DUMPFILE: Optional packet dumping for debugging
 * - IPV6_TCLASS, IPTOS_CLASS_CS6: Traffic class for router-to-router communication priority
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. Functions are called from main event loop in response to
 * timer expirations (periodic_ra()) or incoming ICMPv6 packets (icmp6_packet()). No thread
 * safety concerns. Uses daemon->outpacket buffer which is explicitly documented as safe for
 * concurrent RA transmission even during DHCPv4 ping-wait states.
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

/* NB. This code may be called during a DHCPv4 or transaction which is in ping-wait
   It therefore cannot use any DHCP buffer resources except outpacket, which is
   not used by DHCPv4 code. This code may also be called when DHCP 4 or 6 isn't
   active, so we ensure that outpacket is allocated here too */

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

#include <netinet/icmp6.h>

struct ra_param {
  time_t now;
  int ind, managed, other, first, adv_router;
  char *if_name;
  struct dhcp_netid *tags;
  struct in6_addr link_local, link_global, ula;
  unsigned int glob_pref_time, link_pref_time, ula_pref_time, adv_interval, prio;
  struct dhcp_context *found_context;
};

struct search_param {
  time_t now; int iface;
  char name[IF_NAMESIZE+1];
};

struct alias_param {
  int iface;
  struct dhcp_bridge *bridge;
  int num_alias_ifs;
  int max_alias_ifs;
  int *alias_ifs;
};

static void send_ra(time_t now, int iface, char *iface_name, struct in6_addr *dest);
static void send_ra_alias(time_t now, int iface, char *iface_name, struct in6_addr *dest,
                    int send_iface);
static int send_ra_to_aliases(int index, unsigned int type, char *mac, size_t maclen, void *parm);
static int add_prefixes(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			unsigned int preferred, unsigned int valid, void *vparam);
static int iface_search(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			int prefered, int valid, void *vparam);
static int add_lla(int index, unsigned int type, char *mac, size_t maclen, void *parm);
static void new_timeout(struct dhcp_context *context, char *iface_name, time_t now);
static unsigned int calc_lifetime(struct ra_interface *ra);
static unsigned int calc_interval(struct ra_interface *ra);
static unsigned int calc_prio(struct ra_interface *ra);
static struct ra_interface *find_iface_param(char *iface);

static int hop_limit;

/**
 * @brief Initialize ICMPv6 socket for Router Advertisement transmission
 * 
 * @detailed Creates and configures an ICMPv6 raw socket with appropriate packet filters for
 * receiving Router Solicitation messages and optionally Echo Reply messages (for SLAAC address
 * verification). Sets socket options for hop limit (255 per RFC 4861), traffic class priority,
 * and packet info retrieval. Stores the socket descriptor in daemon->icmp6fd for use by RA
 * transmission functions. Initiates unsolicited RA transmission schedule if --enable-ra is active.
 * 
 * @param now Current time for scheduling initial RA transmission
 * 
 * @return void (dies with EC_BADNET error if socket creation fails)
 * 
 * @note Must be called during daemon initialization after network interfaces are available
 * @note Requires CAP_NET_RAW capability for raw ICMP socket creation
 * @note Sets ICMP6 packet filter to pass ND_ROUTER_SOLICIT and optionally ICMP6_ECHO_REPLY
 * 
 * @warning Dies with error message if socket creation or option setting fails - not recoverable
 * 
 * @see ra_start_unsolicited() for initial RA scheduling
 * @see icmp6_packet() for processing received ICMPv6 packets on this socket
 * @see periodic_ra() for ongoing RA transmission
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t startup_time = time(NULL);
 * ra_init(startup_time);
 * // daemon->icmp6fd now ready for RA transmission
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 6.1.2 (Router Advertisement format) requirements:
 * - Source address must be link-local (enforced by kernel routing)
 * - Hop limit set to 255 (RFC 4861 Section 6.1.2)
 * - Responds to Router Solicitations (ICMPv6 type 133)
 * 
 * SIDE EFFECTS:
 * - Creates ICMPv6 raw socket and stores in daemon->icmp6fd
 * - Reads current hop limit from kernel via getsockopt IPV6_UNICAST_HOPS
 * - Allocates daemon->outpacket buffer if not already present
 * - Calls ra_start_unsolicited() if daemon->doing_ra is true
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main thread during initialization.
 */
void ra_init(time_t now)
{
  struct icmp6_filter filter;
  int fd;
#if defined(IPV6_TCLASS) && defined(IPTOS_CLASS_CS6)
  int class = IPTOS_CLASS_CS6;
#endif
  int val = 255; /* radvd uses this value */
  socklen_t len = sizeof(int);
  struct dhcp_context *context;
  
  /* ensure this is around even if we're not doing DHCPv6 */
  expand_buf(&daemon->outpacket, sizeof(struct dhcp_packet));
 
  /* See if we're guessing SLAAC addresses, if so we need to receive ping replies */
  for (context = daemon->dhcp6; context; context = context->next)
    if ((context->flags & CONTEXT_RA_NAME))
      break;
  
  /* Need ICMP6 socket for transmission for DHCPv6 even when not doing RA. */

  ICMP6_FILTER_SETBLOCKALL(&filter);
  if (daemon->doing_ra)
    {
      ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
      if (context)
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
    }
  
  if ((fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1 ||
      getsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hop_limit, &len) ||
#if defined(IPV6_TCLASS) && defined(IPTOS_CLASS_CS6)
      setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &class, sizeof(class)) == -1 ||
#endif
      !fix_fd(fd) ||
      !set_ipv6pktinfo(fd) ||
      setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val)) ||
      setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val)) ||
      setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) == -1)
    die (_("cannot create ICMPv6 socket: %s"), NULL, EC_BADNET);
  
   daemon->icmp6fd = fd;
   
   if (daemon->doing_ra)
     ra_start_unsolicited(now, NULL);
}

/**
 * @brief Schedule unsolicited Router Advertisement transmission
 * 
 * @detailed Initializes or resets RA transmission timers for DHCPv6 contexts to trigger periodic
 * unsolicited Router Advertisements per RFC 4861 Section 6.2.4. When called with a specific context,
 * schedules RA for that context only (used after address changes). When called with NULL context,
 * schedules RAs for all active DHCPv6 contexts with randomized initial delays (0-5 seconds) to avoid
 * thundering herd. Sets short period start time to trigger frequent RAs (every 5-20 seconds) for the
 * first minute, then transitions to normal interval (per calc_interval()).
 * 
 * @param now Current timestamp for calculating RA transmission times
 * @param context Specific DHCPv6 context to schedule, or NULL for all contexts
 * 
 * @return void
 * 
 * @note Called on daemon startup, netlink route changes, and DHCPv6 context updates
 * @note Short period (first 60 seconds) sends frequent RAs per RFC 4861 Section 6.2.4
 * @note Skips CONTEXT_TEMPLATE contexts which are configuration templates only
 * 
 * @see periodic_ra() for actual RA transmission when timers expire
 * @see new_timeout() for timeout calculation algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * // Schedule RAs for all contexts at startup
 * ra_start_unsolicited(time(NULL), NULL);
 * 
 * // Re-schedule RA after address change on specific context
 * ra_start_unsolicited(time(NULL), changed_context);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 6.2.4 timing requirements:
 * - Initial RAs sent at 5-20 second intervals for reliability
 * - Transitions to normal intervals after short period
 * - Randomized delays prevent synchronization across routers
 * 
 * SIDE EFFECTS:
 * - Modifies context->ra_time for scheduled contexts
 * - Sets context->ra_short_period_start to enable fast initial RAs
 * - Uses rand16() for randomization of initial delays
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop thread.
 */
void ra_start_unsolicited(time_t now, struct dhcp_context *context)
{   
   /* init timers so that we do ra's for some/all soon. some ra_times will end up zeroed
     if it's not appropriate to advertise those contexts.
     This gets re-called on a netlink route-change to re-do the advertisement
     and pick up new interfaces */
  
  if (context)
    {
      context->ra_short_period_start = now;
      /* start after 1 second to get logging right at startup. */
      context->ra_time = now + 1;
    }
  else
    for (context = daemon->dhcp6; context; context = context->next)
      if (!(context->flags & CONTEXT_TEMPLATE))
	{
	  context->ra_time = now + (rand16()/13000); /* range 0 - 5 */
	  /* re-do frequently for a minute or so, in case the first gets lost. */
	  context->ra_short_period_start = now;
	}
}

/**
 * @brief Process incoming ICMPv6 Router Solicitation and Echo Reply packets
 * 
 * @detailed Receives and handles ICMPv6 packets on daemon->icmp6fd, processing Router Solicitation
 * (RS) messages by sending solicited Router Advertisements, and Echo Reply messages for SLAAC
 * address verification. Extracts source address and interface index from ancillary data, validates
 * interface is configured for RA, checks against dhcp-except exclusions, and optionally extracts
 * source MAC address from RS for logging. Supports interface aliasing via --bridge-interface by
 * detecting alias interfaces and sending RAs with the bridge interface's context.
 * 
 * @param now Current timestamp passed to send_ra() for RA construction
 * 
 * @return void
 * 
 * @note Uses daemon->outpacket.iov_base as receive buffer (safe per file header comment)
 * @note Requires minimum 8-byte packet for valid ICMP header
 * @note Validates ICMP code field is 0 per RFC 4861
 * 
 * @warning Returns silently on receive errors, short packets, or invalid interfaces
 * 
 * @see send_ra() for solicited RA transmission
 * @see send_ra_alias() for aliased interface RA transmission
 * @see lease_ping_reply() for Echo Reply processing (SLAAC verification)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Main event loop calls on ICMPv6 socket readable
 * if (poll_check(daemon->icmp6fd, POLLIN))
 *   icmp6_packet(time(NULL));
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 6.2.6 (Processing Router Solicitations):
 * - Validates source address (may be unspecified during DAD)
 * - Sends unicast RA to specified source or multicast to all-nodes
 * - Extracts source link-layer address from RS options (type 1)
 * - Processes Router Solicitation (ICMPv6 type 133)
 * 
 * SIDE EFFECTS:
 * - Calls send_ra() or send_ra_alias() which transmit RA packets
 * - Logs RS reception with interface name and source MAC if !OPT_QUIET_RA
 * - May dump packet if HAVE_DUMPFILE enabled
 * - Updates lease state via lease_ping_reply() for Echo Reply packets
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop on socket ready event.
 */
void icmp6_packet(time_t now)
{
  char interface[IF_NAMESIZE+1];
  ssize_t sz; 
  int if_index = 0;
  struct cmsghdr *cmptr;
  struct msghdr msg;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_u;
  struct sockaddr_in6 from;
  unsigned char *packet;
  struct iname *tmp;

  /* Note: use outpacket for input buffer */
  msg.msg_control = control_u.control6;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_iov = &daemon->outpacket;
  msg.msg_iovlen = 1;
  
  if ((sz = recv_dhcp_packet(daemon->icmp6fd, &msg)) == -1 || sz < 8)
    return;
   
  packet = (unsigned char *)daemon->outpacket.iov_base;

  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
    if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == daemon->v6pktinfo)
      {
	union {
	  unsigned char *c;
	  struct in6_pktinfo *p;
	} p;
	p.c = CMSG_DATA(cmptr);
        
	if_index = p.p->ipi6_ifindex;
      }
  
  if (!indextoname(daemon->icmp6fd, if_index, interface))
    return;
    
  if (!iface_check(AF_LOCAL, NULL, interface, NULL))
    return;
  
  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && wildcard_match(tmp->name, interface))
      return;
 
  if (packet[1] != 0)
    return;

  if (packet[0] == ICMP6_ECHO_REPLY)
    lease_ping_reply(&from.sin6_addr, packet, interface); 
  else if (packet[0] == ND_ROUTER_SOLICIT)
    {
      char *mac = "";
      struct dhcp_bridge *bridge, *alias;
      ssize_t rem;
      unsigned char *p;
      int opt_sz;
      
#ifdef HAVE_DUMPFILE
      dump_packet(DUMP_RA, (void *)packet, sz, (union mysockaddr *)&from, NULL, -1);
#endif           
      
      /* look for link-layer address option for logging */
      for (rem = sz - 8, p = &packet[8]; rem >= 2; rem -= opt_sz, p += opt_sz)
	{
	  opt_sz = p[1] * 8;
	  
	  if (opt_sz == 0 || opt_sz > rem)
	    return; /* Bad packet */
	  
	  if (p[0] == ICMP6_OPT_SOURCE_MAC && ((opt_sz - 2) * 3 - 1 < MAXDNAME))
	    {
	      print_mac(daemon->namebuff, &p[2], opt_sz - 2);
	      mac = daemon->namebuff;
	    }
	}
      
      if (!option_bool(OPT_QUIET_RA))
	my_syslog(MS_DHCP | LOG_INFO, "RTR-SOLICIT(%s) %s", interface, mac);

      /* If the incoming interface is an alias of some other one (as
         specified by the --bridge-interface option), send an RA using
         the context of the aliased interface. */
      for (bridge = daemon->bridges; bridge; bridge = bridge->next)
        {
          int bridge_index = if_nametoindex(bridge->iface);
          if (bridge_index)
	    {
	      for (alias = bridge->alias; alias; alias = alias->next)
		if (wildcard_matchn(alias->iface, interface, IF_NAMESIZE))
		  {
		    /* Send an RA on if_index with information from
		       bridge_index. */
		    send_ra_alias(now, bridge_index, bridge->iface, NULL, if_index);
		    break;
		  }
	      if (alias)
		break;
	    }
        }

      /* If the incoming interface wasn't an alias, send an RA using
	 the context of the incoming interface. */
      if (!bridge)
	/* source address may not be valid in solicit request. */
	send_ra(now, if_index, interface, !IN6_IS_ADDR_UNSPECIFIED(&from.sin6_addr) ? &from.sin6_addr : NULL);
    }
}

/**
 * @brief Construct and transmit Router Advertisement with interface aliasing support
 * 
 * @detailed Builds complete ICMPv6 Router Advertisement packet with prefix information options,
 * router lifetime, M/O flags for DHCPv6 coordination, MTU option, RDNSS (Recursive DNS Server)
 * options, and DNSSL (DNS Search List) options. Enumerates interface addresses to construct prefix
 * options with appropriate autonomous/managed flags, valid/preferred lifetimes from DHCPv6 contexts.
 * Handles old prefixes being phased out (advertised with preferred lifetime 0 per RFC 6204).
 * Supports sending RA using one interface's configuration (iface) but transmitting on a different
 * physical interface (send_iface) for bridge/alias scenarios.
 * 
 * @param now Current timestamp for lifetime calculations and context timeout scheduling
 * @param iface Interface index providing RA configuration context (prefix sources)
 * @param iface_name Interface name for logging and parameter lookup
 * @param dest Destination IPv6 address for solicited RA (unicast), or NULL for unsolicited multicast
 * @param send_iface Physical interface index for actual packet transmission
 * 
 * @return void (returns silently if no link-local address or no contexts to advertise)
 * 
 * @note Uses daemon->outpacket buffer built incrementally via expand() and put_opt6_*()
 * @note Sets M (Managed) flag (0x80) if DHCPv6 address assignment enabled
 * @note Sets O (Other) flag (0x40) if DHCPv6 other configuration enabled
 * @note Autonomous flag (0x40 in prefix opt) set only for SLAAC, not pure DHCPv6
 * @note On-link flag (0x80 in prefix opt) set unless CONTEXT_RA_OFF_LINK specified
 * 
 * @warning Requires CAP_NET_RAW capability for ICMPv6 transmission
 * @warning Returns early if no link-local address found (RFC 4861 requirement)
 * @warning May modify/free CONTEXT_OLD contexts that have expired
 * 
 * @see send_ra() for wrapper without interface aliasing
 * @see add_prefixes() for prefix enumeration and option construction
 * @see calc_interval(), calc_lifetime(), calc_prio() for RA parameter calculation
 * @see find_iface_param() for per-interface RA configuration
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr solicitor;
 * inet_pton(AF_INET6, "fe80::1", &solicitor);
 * // Send solicited RA on interface 2, using config from interface 2
 * send_ra_alias(time(NULL), 2, "eth0", &solicitor, 2);
 * 
 * // Send unsolicited multicast RA
 * send_ra_alias(time(NULL), 2, "eth0", NULL, 2);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Sections 4.2 (Router Advertisement Message Format) and 6.2.3 (Router Advertisement):
 * - Hop limit 255, Router Lifetime in seconds (RFC 4861 Section 4.2)
 * - Prefix Information Option format (RFC 4861 Section 4.6.2)
 * - M and O flags for DHCPv6 coordination (RFC 4861 Section 4.2)
 * - Advertisement Interval Option (RFC 6275 Section 7.3)
 * - RDNSS Option (RFC 6106) for DNS server advertisement
 * - DNSSL Option (RFC 6106) for DNS search list
 * - MTU Option (RFC 4861 Section 4.6.4)
 * Also implements RFC 6204 Section 4.3 L-13 for old prefix deprecation
 * 
 * SIDE EFFECTS:
 * - Transmits ICMPv6 RA packet via sendto() on daemon->icmp6fd
 * - Modifies daemon->outpacket buffer with RA content
 * - May free CONTEXT_OLD contexts that have exceeded valid lifetime
 * - Logs RTR-ADVERT messages per prefix unless OPT_QUIET_RA set
 * - Calls option_filter() which modifies DHOPT_TAGOK flags
 * - May read /proc/sys/net/ipv6/conf/*/mtu on Linux for MTU option
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop thread.
 */
static void send_ra_alias(time_t now, int iface, char *iface_name, struct in6_addr *dest, int send_iface)
{
  struct ra_packet *ra;
  struct ra_param parm;
  struct sockaddr_in6 addr;
  struct dhcp_context *context, *tmp,  **up;
  struct dhcp_netid iface_id;
  struct dhcp_opt *opt_cfg;
  struct ra_interface *ra_param = find_iface_param(iface_name);
  int done_dns = 0, old_prefix = 0, mtu = 0;
  unsigned int min_pref_time;
#ifdef HAVE_LINUX_NETWORK
  FILE *f;
#endif
  
  parm.ind = iface;
  parm.managed = 0;
  parm.other = 0;
  parm.found_context = NULL;
  parm.adv_router = 0;
  parm.if_name = iface_name;
  parm.first = 1;
  parm.now = now;
  parm.glob_pref_time = parm.link_pref_time = parm.ula_pref_time = 0;
  parm.adv_interval = calc_interval(ra_param);
  parm.prio = calc_prio(ra_param);
  
  reset_counter();
  
  if (!(ra = expand(sizeof(struct ra_packet))))
    return;
  
  ra->type = ND_ROUTER_ADVERT;
  ra->code = 0;
  ra->hop_limit = hop_limit;
  ra->flags = parm.prio;
  ra->lifetime = htons(calc_lifetime(ra_param));
  ra->reachable_time = 0;
  ra->retrans_time = 0;

  /* set tag with name == interface */
  iface_id.net = iface_name;
  iface_id.next = NULL;
  parm.tags = &iface_id; 
  
  for (context = daemon->dhcp6; context; context = context->next)
    {
      context->flags &= ~CONTEXT_RA_DONE;
      context->netid.next = &context->netid;
    }

  /* If no link-local address then we can't advertise since source address of
     advertisement must be link local address: RFC 4861 para 6.1.2. */
  if (!iface_enumerate(AF_INET6, &parm, add_prefixes) ||
      parm.link_pref_time == 0)
    return;

  /* Find smallest preferred time within address classes,
     to use as lifetime for options. This is a rather arbitrary choice. */
  min_pref_time = 0xffffffff;
  if (parm.glob_pref_time != 0 && parm.glob_pref_time < min_pref_time)
    min_pref_time = parm.glob_pref_time;
  
  if (parm.ula_pref_time != 0 && parm.ula_pref_time < min_pref_time)
    min_pref_time = parm.ula_pref_time;

  if (parm.link_pref_time != 0 && parm.link_pref_time < min_pref_time)
    min_pref_time = parm.link_pref_time;

  /* Look for constructed contexts associated with addresses which have gone, 
     and advertise them with preferred_time == 0  RFC 6204 4.3 L-13 */
  for (up = &daemon->dhcp6, context = daemon->dhcp6; context; context = tmp)
    {
      tmp = context->next;

      if (context->if_index == iface && (context->flags & CONTEXT_OLD))
	{
	  unsigned int old = difftime(now, context->address_lost_time);
	  
	  if (old > context->saved_valid)
	    { 
	      /* We've advertised this enough, time to go */
	     
	      /* If this context held the timeout, and there's another context in use
		 transfer the timeout there. */
	      if (context->ra_time != 0 && parm.found_context && parm.found_context->ra_time == 0)
		new_timeout(parm.found_context, iface_name, now);
	      
	      *up = context->next;
	      free(context);
	    }
	  else
	    {
	      struct prefix_opt *opt;
	      struct in6_addr local = context->start6;
	      int do_slaac = 0;

	      old_prefix = 1;

	      /* zero net part of address */
	      setaddr6part(&local, addr6part(&local) & ~((context->prefix == 64) ? (u64)-1LL : (1LLU << (128 - context->prefix)) - 1LLU));
	     
	      
	      if (context->flags & CONTEXT_RA)
		{
		  do_slaac = 1;
		  if (context->flags & CONTEXT_DHCP)
		    {
		      parm.other = 1; 
		      if (!(context->flags & CONTEXT_RA_STATELESS))
			parm.managed = 1;
		    }
		}
	      else
		{
		  /* don't do RA for non-ra-only unless --enable-ra is set */
		  if (option_bool(OPT_RA))
		    {
		      parm.managed = 1;
		      parm.other = 1;
		    }
		}

	      if ((opt = expand(sizeof(struct prefix_opt))))
		{
		  opt->type = ICMP6_OPT_PREFIX;
		  opt->len = 4;
		  opt->prefix_len = context->prefix;
		  /* autonomous only if we're not doing dhcp, set
                     "on-link" unless "off-link" was specified */
		  opt->flags = (do_slaac ? 0x40 : 0) |
                    ((context->flags & CONTEXT_RA_OFF_LINK) ? 0 : 0x80);
		  opt->valid_lifetime = htonl(context->saved_valid - old);
		  opt->preferred_lifetime = htonl(0);
		  opt->reserved = 0; 
		  opt->prefix = local;
		  
		  inet_ntop(AF_INET6, &local, daemon->addrbuff, ADDRSTRLEN);
		  if (!option_bool(OPT_QUIET_RA))
		    my_syslog(MS_DHCP | LOG_INFO, "RTR-ADVERT(%s) %s old prefix", iface_name, daemon->addrbuff); 		    
		}
	   
	      up = &context->next;
	    }
	}
      else
	up = &context->next;
    }
    
  /* If we're advertising only old prefixes, set router lifetime to zero. */
  if (old_prefix && !parm.found_context)
    ra->lifetime = htons(0);

  /* No prefixes to advertise. */
  if (!old_prefix && !parm.found_context)
    return; 
  
  /* If we're sending router address instead of prefix in at least on prefix,
     include the advertisement interval option. */
  if (parm.adv_router)
    {
      put_opt6_char(ICMP6_OPT_ADV_INTERVAL);
      put_opt6_char(1);
      put_opt6_short(0);
      /* interval value is in milliseconds */
      put_opt6_long(1000 * calc_interval(find_iface_param(iface_name)));
    }

  /* Set the MTU from ra_param if any, an MTU of 0 mean automatic for linux, */
  /* an MTU of -1 prevents the option from being sent. */
  if (ra_param)
    mtu = ra_param->mtu;
#ifdef HAVE_LINUX_NETWORK
  /* Note that IPv6 MTU is not necessarily the same as the IPv4 MTU
     available from SIOCGIFMTU */
  if (mtu == 0)
    {
      char *mtu_name = ra_param ? ra_param->mtu_name : NULL;
      sprintf(daemon->namebuff, "/proc/sys/net/ipv6/conf/%s/mtu", mtu_name ? mtu_name : iface_name);
      if ((f = fopen(daemon->namebuff, "r")))
        {
          if (fgets(daemon->namebuff, MAXDNAME, f))
            mtu = atoi(daemon->namebuff);
          fclose(f);
        }
    }
#endif
  if (mtu > 0)
    {
      put_opt6_char(ICMP6_OPT_MTU);
      put_opt6_char(1);
      put_opt6_short(0);
      put_opt6_long(mtu);
    }
     
  iface_enumerate(AF_LOCAL, &send_iface, add_lla);
 
  /* RDNSS, RFC 6106, use relevant DHCP6 options */
  (void)option_filter(parm.tags, NULL, daemon->dhcp_opts6);
  
  for (opt_cfg = daemon->dhcp_opts6; opt_cfg; opt_cfg = opt_cfg->next)
    {
      int i;
      
      /* netids match and not encapsulated? */
      if (!(opt_cfg->flags & DHOPT_TAGOK))
        continue;
      
      if (opt_cfg->opt == OPTION6_DNS_SERVER)
        {
	  struct in6_addr *a;
	  int len;

	  done_dns = 1;

          if (opt_cfg->len == 0)
	    continue;
	  
	  /* reduce len for any addresses we can't substitute */
	  for (a = (struct in6_addr *)opt_cfg->val, len = opt_cfg->len, i = 0; 
	       i < opt_cfg->len; i += IN6ADDRSZ, a++)
	    if ((IN6_IS_ADDR_UNSPECIFIED(a) && parm.glob_pref_time == 0) ||
		(IN6_IS_ADDR_ULA_ZERO(a) && parm.ula_pref_time == 0) ||
		(IN6_IS_ADDR_LINK_LOCAL_ZERO(a) && parm.link_pref_time == 0))
	      len -= IN6ADDRSZ;

	  if (len != 0)
	    {
	      put_opt6_char(ICMP6_OPT_RDNSS);
	      put_opt6_char((len/8) + 1);
	      put_opt6_short(0);
	      put_opt6_long(min_pref_time);
	 
	      for (a = (struct in6_addr *)opt_cfg->val, i = 0; i <  opt_cfg->len; i += IN6ADDRSZ, a++)
		if (IN6_IS_ADDR_UNSPECIFIED(a))
		  {
		    if (parm.glob_pref_time != 0)
		      put_opt6(&parm.link_global, IN6ADDRSZ);
		  }
		else if (IN6_IS_ADDR_ULA_ZERO(a))
		  {
		    if (parm.ula_pref_time != 0)
		    put_opt6(&parm.ula, IN6ADDRSZ);
		  }
		else if (IN6_IS_ADDR_LINK_LOCAL_ZERO(a))
		  {
		    if (parm.link_pref_time != 0)
		      put_opt6(&parm.link_local, IN6ADDRSZ);
		  }
		else
		  put_opt6(a, IN6ADDRSZ);
	    }
	}
      
      if (opt_cfg->opt == OPTION6_DOMAIN_SEARCH && opt_cfg->len != 0)
	{
	  int len = ((opt_cfg->len+7)/8);
	  
	  put_opt6_char(ICMP6_OPT_DNSSL);
	  put_opt6_char(len + 1);
	  put_opt6_short(0);
	  put_opt6_long(min_pref_time); 
	  put_opt6(opt_cfg->val, opt_cfg->len);
	  
	  /* pad */
	  for (i = opt_cfg->len; i < len * 8; i++)
	    put_opt6_char(0);
	}
    }
	
  if (daemon->port == NAMESERVER_PORT && !done_dns && parm.link_pref_time != 0)
    {
      /* default == us, as long as we are supplying DNS service. */
      put_opt6_char(ICMP6_OPT_RDNSS);
      put_opt6_char(3);
      put_opt6_short(0);
      put_opt6_long(min_pref_time); 
      put_opt6(&parm.link_local, IN6ADDRSZ);
    }

  /* set managed bits unless we're providing only RA on this link */
  if (parm.managed)
    ra->flags |= 0x80; /* M flag, managed, */
   if (parm.other)
    ra->flags |= 0x40; /* O flag, other */ 
			
  /* decide where we're sending */
  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(IPPROTO_ICMPV6);
  if (dest)
    {
      addr.sin6_addr = *dest;
      if (IN6_IS_ADDR_LINKLOCAL(dest) ||
	  IN6_IS_ADDR_MC_LINKLOCAL(dest))
	addr.sin6_scope_id = iface;
    }
  else
    {
      inet_pton(AF_INET6, ALL_NODES, &addr.sin6_addr); 
      setsockopt(daemon->icmp6fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &send_iface, sizeof(send_iface));
    }
  
#ifdef HAVE_DUMPFILE
  dump_packet(DUMP_RA, (void *)daemon->outpacket.iov_base, save_counter(-1), NULL, (union mysockaddr *)&addr, -1);
#endif

  while (retry_send(sendto(daemon->icmp6fd, daemon->outpacket.iov_base, 
			   save_counter(-1), 0, (struct sockaddr *)&addr, 
			   sizeof(addr))));
  
}

/**
 * @brief Send Router Advertisement on interface using its own configuration
 * 
 * @detailed Simple wrapper around send_ra_alias() for the common case where the RA configuration
 * interface and physical transmission interface are the same (no aliasing). Constructs and transmits
 * RA packet with prefix information, router lifetime, M/O flags, and DNS options based on the
 * specified interface's DHCPv6 contexts.
 * 
 * @param now Current timestamp for RA lifetime calculations
 * @param iface Interface index for both RA configuration and transmission
 * @param iface_name Interface name for logging and configuration lookup
 * @param dest Destination address for solicited RA (unicast), or NULL for unsolicited multicast to ff02::1
 * 
 * @return void
 * 
 * @see send_ra_alias() for detailed RA construction and transmission logic
 * @see icmp6_packet() which calls this for solicited RAs
 * @see periodic_ra() which calls this for periodic unsolicited RAs
 * 
 * EXAMPLE USAGE:
 * @code
 * // Send periodic unsolicited RA on interface eth0
 * send_ra(time(NULL), 2, "eth0", NULL);
 * 
 * // Send solicited RA in response to Router Solicitation
 * struct in6_addr solicitor_addr;
 * send_ra(time(NULL), 2, "eth0", &solicitor_addr);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Delegates to send_ra_alias() which implements RFC 4861 Router Advertisement format.
 * 
 * SIDE EFFECTS:
 * All side effects are from send_ra_alias() - transmits RA packet via ICMPv6 socket.
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop thread.
 */
static void send_ra(time_t now, int iface, char *iface_name, struct in6_addr *dest)
{
  /* Send an RA on the same interface that the RA content is based
     on. */
  send_ra_alias(now, iface, iface_name, dest, iface);
}

/**
 * @brief Enumerate interface addresses and construct prefix information options for RA
 * 
 * @detailed Callback function for iface_enumerate() that processes each IPv6 address on an interface,
 * matching addresses against DHCPv6 contexts to build prefix information options for Router Advertisement.
 * Handles link-local addresses (saves for RDNSS), global unicast addresses, and ULA addresses. For each
 * matching context, determines SLAAC vs DHCPv6 mode, sets autonomous/on-link flags, calculates valid/
 * preferred lifetimes from context configuration, and constructs ICMP6_OPT_PREFIX option. Supports
 * advertising router addresses instead of prefixes (CONTEXT_RA_ROUTER per RFC 3775). Tracks M/O flags
 * for DHCPv6 coordination and collects context tags for DHCP option filtering.
 * 
 * @param local IPv6 address being enumerated from interface
 * @param prefix Prefix length for this address
 * @param scope Address scope (link-local, site-local, global) - unused
 * @param if_index Interface index for this address
 * @param flags Address flags including IFACE_DEPRECATED for deprecation
 * @param preferred Preferred lifetime from kernel (may be overridden by context)
 * @param valid Valid lifetime from kernel (may be overridden by context)
 * @param vparam Pointer to struct ra_param for RA construction state
 * 
 * @return 1 to continue enumeration, 0 would stop (but always returns 1)
 * 
 * @note Link-local address with longest preferred lifetime is selected if multiple exist
 * @note Prefix length is zeroed in address before creating prefix option (unless advertising router address)
 * @note Autonomous flag (0x40) set only if CONTEXT_RA and no DHCPv6 or CONTEXT_RA_STATELESS
 * @note On-link flag (0x80) set unless CONTEXT_RA_OFF_LINK specified
 * @note Router address flag (0x20) set if CONTEXT_RA_ROUTER specified
 * @note Floor for valid/preferred time is 3 * advertisement interval unless constructed context
 * 
 * @see send_ra_alias() which calls iface_enumerate() with this callback
 * @see iface_enumerate() for address enumeration interface
 * @see struct ra_param for state tracking across callback invocations
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_param parm;
 * parm.ind = iface_index;
 * parm.managed = 0;
 * // iface_enumerate calls add_prefixes for each address
 * iface_enumerate(AF_INET6, &parm, add_prefixes);
 * // parm now contains link_local, M/O flags, and outpacket has prefix options
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 4.6.2 (Prefix Information Option format):
 * - Prefix length, L (on-link) and A (autonomous) flags
 * - Valid and preferred lifetimes in seconds
 * - Prefix field with host bits zeroed
 * Also RFC 3775 Section 7.2 for router address advertisement (R flag)
 * 
 * SIDE EFFECTS:
 * - Appends struct prefix_opt to daemon->outpacket via expand()
 * - Updates param->link_local, param->link_global, param->ula with best addresses
 * - Updates param->link_pref_time, param->glob_pref_time, param->ula_pref_time with lifetimes
 * - Sets param->managed and param->other flags based on context configuration
 * - Sets param->adv_router if any context has CONTEXT_RA_ROUTER
 * - Marks contexts with CONTEXT_RA_DONE to avoid duplicate processing
 * - Modifies context->saved_valid to track advertised valid lifetime
 * - Logs RTR-ADVERT messages for each prefix unless OPT_QUIET_RA set
 * 
 * THREAD SAFETY:
 * Not thread-safe. Called from send_ra_alias() in main event loop only.
 */
static int add_prefixes(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			unsigned int preferred, unsigned int valid, void *vparam)
{
  struct ra_param *param = vparam;

  (void)scope; /* warning */
  
  if (if_index == param->ind)
    {
      if (IN6_IS_ADDR_LINKLOCAL(local))
	{
	  /* Can there be more than one LL address?
	     Select the one with the longest preferred time 
	     if there is. */
	  if (preferred > param->link_pref_time)
	    {
	      param->link_pref_time = preferred;
	      param->link_local = *local;
	    }
	}
      else if (!IN6_IS_ADDR_LOOPBACK(local) &&
	       !IN6_IS_ADDR_MULTICAST(local))
	{
	  int real_prefix = 0;
	  int do_slaac = 0;
	  int deprecate  = 0;
	  int constructed = 0;
	  int adv_router = 0;
	  int off_link = 0;
	  unsigned int time = 0xffffffff;
	  struct dhcp_context *context;
	  
	  for (context = daemon->dhcp6; context; context = context->next)
	    if (!(context->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
		prefix <= context->prefix &&
		is_same_net6(local, &context->start6, context->prefix) &&
		is_same_net6(local, &context->end6, context->prefix))
	      {
		context->saved_valid = valid;

		if (context->flags & CONTEXT_RA) 
		  {
		    do_slaac = 1;
		    if (context->flags & CONTEXT_DHCP)
		      {
			param->other = 1; 
			if (!(context->flags & CONTEXT_RA_STATELESS))
			  param->managed = 1;
		      }
		  }
		else
		  {
		    /* don't do RA for non-ra-only unless --enable-ra is set */
		    if (!option_bool(OPT_RA))
		      continue;
		    param->managed = 1;
		    param->other = 1;
		  }

		/* Configured to advertise router address, not prefix. See RFC 3775 7.2 
		 In this case we do all addresses associated with a context, 
		 hence the real_prefix setting here. */
		if (context->flags & CONTEXT_RA_ROUTER)
		  {
		    adv_router = 1;
		    param->adv_router = 1;
		    real_prefix = context->prefix;
		  }

		/* find floor time, don't reduce below 3 * RA interval.
		   If the lease time has been left as default, don't
		   use that as a floor. */
		if ((context->flags & CONTEXT_SETLEASE) &&
		    time > context->lease_time)
		  {
		    time = context->lease_time;
		    if (time < ((unsigned int)(3 * param->adv_interval)))
		      time = 3 * param->adv_interval;
		  }

		if (context->flags & CONTEXT_DEPRECATE)
		  deprecate = 1;
		
		if (context->flags & CONTEXT_CONSTRUCTED)
		  constructed = 1;


		/* collect dhcp-range tags */
		if (context->netid.next == &context->netid && context->netid.net)
		  {
		    context->netid.next = param->tags;
		    param->tags = &context->netid;
		  }
		  
		/* subsequent prefixes on the same interface 
		   and subsequent instances of this prefix don't need timers.
		   Be careful not to find the same prefix twice with different
		   addresses unless we're advertising the actual addresses. */
		if (!(context->flags & CONTEXT_RA_DONE))
		  {
		    if (!param->first)
		      context->ra_time = 0;
		    context->flags |= CONTEXT_RA_DONE;
		    real_prefix = context->prefix;
                    off_link = (context->flags & CONTEXT_RA_OFF_LINK);
		  }

		param->first = 0;
		/* found_context is the _last_ one we found, so if there's 
		   more than one, it's not the first. */
		param->found_context = context;
	      }

	  /* configured time is ceiling */
	  if (!constructed || valid > time)
	    valid = time;
	  
	  if (flags & IFACE_DEPRECATED)
	    preferred = 0;
	  
	  if (deprecate)
	    time = 0;
	  
	  /* configured time is ceiling */
	  if (!constructed || preferred > time)
	    preferred = time;
	  
	  if (IN6_IS_ADDR_ULA(local))
	    {
	      if (preferred > param->ula_pref_time)
		{
		  param->ula_pref_time = preferred;
		  param->ula = *local;
		}
	    }
	  else 
	    {
	      if (preferred > param->glob_pref_time)
		{
		  param->glob_pref_time = preferred;
		  param->link_global = *local;
		}
	    }
	  
	  if (real_prefix != 0)
	    {
	      struct prefix_opt *opt;
	     	      
	      if ((opt = expand(sizeof(struct prefix_opt))))
		{
		  /* zero net part of address */
		  if (!adv_router)
		    setaddr6part(local, addr6part(local) & ~((real_prefix == 64) ? (u64)-1LL : (1LLU << (128 - real_prefix)) - 1LLU));
		  
		  opt->type = ICMP6_OPT_PREFIX;
		  opt->len = 4;
		  opt->prefix_len = real_prefix;
		  /* autonomous only if we're not doing dhcp, set
                     "on-link" unless "off-link" was specified */
		  opt->flags = (off_link ? 0 : 0x80);
		  if (do_slaac)
		    opt->flags |= 0x40;
		  if (adv_router)
		    opt->flags |= 0x20;
		  opt->valid_lifetime = htonl(valid);
		  opt->preferred_lifetime = htonl(preferred);
		  opt->reserved = 0; 
		  opt->prefix = *local;
		  
		  inet_ntop(AF_INET6, local, daemon->addrbuff, ADDRSTRLEN);
		  if (!option_bool(OPT_QUIET_RA))
		    my_syslog(MS_DHCP | LOG_INFO, "RTR-ADVERT(%s) %s", param->if_name, daemon->addrbuff); 		    
		}
	    }
	}
    }          
  return 1;
}

/**
 * @brief Add source link-layer address option to Router Advertisement
 * 
 * @detailed Callback function for iface_enumerate(AF_LOCAL) that adds the ICMP6_OPT_SOURCE_MAC
 * option containing the interface's hardware (MAC) address to the Router Advertisement packet.
 * Per RFC 4861 Section 4.6.1, this option allows receivers to learn the sender's link-layer address
 * for resolving the router without additional Neighbor Discovery exchanges. Only processes the
 * specified interface index (passed via parm), returning 0 to stop enumeration once found.
 * 
 * @param index Interface index being enumerated
 * @param type Hardware address type (Ethernet, etc.) - unused
 * @param mac Pointer to hardware address bytes
 * @param maclen Length of hardware address in bytes (typically 6 for Ethernet)
 * @param parm Pointer to int containing target interface index
 * 
 * @return 0 if matching interface (stops enumeration), 1 to continue enumeration
 * 
 * @note Option length is in 8-octet units, calculated as (maclen + 9) >> 3
 * @note Option format: type (1 byte), length (1 byte), link-layer address (variable)
 * @note Pads option to 8-octet boundary with zeros via memset
 * 
 * @see send_ra_alias() which calls this via iface_enumerate(AF_LOCAL)
 * @see RFC 4861 Section 4.6.1 for Source Link-Layer Address option format
 * 
 * EXAMPLE USAGE:
 * @code
 * int send_iface = 2;
 * // iface_enumerate calls add_lla for each interface
 * iface_enumerate(AF_LOCAL, &send_iface, add_lla);
 * // Outpacket now contains source link-layer address option for interface 2
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 4.6.1 Source Link-Layer Address option:
 * - Type 1 (ICMP6_OPT_SOURCE_MAC)
 * - Length in 8-octet units
 * - Link-layer address immediately follows
 * 
 * SIDE EFFECTS:
 * - Appends link-layer address option to daemon->outpacket via expand()
 * - Returns 0 which stops iface_enumerate() iteration
 * 
 * THREAD SAFETY:
 * Not thread-safe. Called from send_ra_alias() in main event loop only.
 */
static int add_lla(int index, unsigned int type, char *mac, size_t maclen, void *parm)
{
  (void)type;

  if (index == *((int *)parm))
    {
      /* size is in units of 8 octets and includes type and length (2 bytes)
	 add 7 to round up */
      int len = (maclen + 9) >> 3;
      unsigned char *p = expand(len << 3);
      if (!p)
	return 1;
      memset(p, 0, len << 3);
      *p++ = ICMP6_OPT_SOURCE_MAC;
      *p++ = len;
      memcpy(p, mac, maclen);

      return 0;
    }

  return 1;
}

/**
 * @brief Execute periodic unsolicited Router Advertisement transmission
 * 
 * @detailed Main periodic RA transmission function called from daemon event loop to find DHCPv6
 * contexts with expired ra_time and send unsolicited RAs on corresponding interfaces. Searches all
 * DHCPv6 contexts for overdue RAs, locates the associated interface via address enumeration or stored
 * if_index for old contexts, validates interface is not in dhcp-except list, and calls send_ra().
 * Supports interface aliasing by enumerating bridge alias interfaces and sending RAs on each. Returns
 * timestamp of next scheduled RA for event loop timer management. Handles CONTEXT_OLD contexts for
 * phasing out old prefixes per RFC 6204. Reschedules RA timers via new_timeout() after transmission.
 * 
 * @param now Current timestamp for comparing against context->ra_time
 * 
 * @return Timestamp of next scheduled RA event, or 0 if no pending RAs
 * 
 * @note Continuously searches contexts until no overdue RAs remain
 * @note CONTEXT_OLD contexts use stored if_index since address may be gone
 * @note If interface not found for context, zeroes ra_time to prevent infinite retries
 * @note Enumerates bridge aliases to send RA on all aliased interfaces
 * @note Allocates temporary memory for alias interface indices (freed after use)
 * 
 * @warning Returns 0 if no contexts have ra_time set (no future events)
 * 
 * @see ra_start_unsolicited() for initial RA scheduling
 * @see send_ra() for actual RA packet transmission
 * @see new_timeout() for calculating next RA time
 * @see iface_search() for finding interface with overdue context
 * 
 * EXAMPLE USAGE:
 * @code
 * // Main event loop timer handling
 * time_t next_ra = periodic_ra(time(NULL));
 * if (next_ra != 0)
 *   set_timer(next_ra); // Schedule next periodic_ra() call
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 6.2.4 (Sending Unsolicited Router Advertisements):
 * - Sends periodic multicast RAs at intervals of MinRtrAdvInterval to MaxRtrAdvInterval
 * - Timing calculated by new_timeout() per RFC 4861 specifications
 * 
 * SIDE EFFECTS:
 * - Calls send_ra() which transmits ICMPv6 RA packets
 * - Modifies context->ra_time via new_timeout() for next transmission
 * - Zeroes ra_time for contexts without matching interfaces
 * - Logs RTR-ADVERT messages with alias counts unless OPT_QUIET_RA
 * - Allocates and frees memory for alias interface list (whine_malloc/free)
 * - Calls iface_enumerate() which may have platform-specific side effects
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop thread on timer expiration.
 */
time_t periodic_ra(time_t now)
{
  struct search_param param;
  struct dhcp_context *context;
  time_t next_event;
  struct alias_param aparam;
    
  param.now = now;
  param.iface = 0;

  while (1)
    {
      /* find overdue events, and time of first future event */
      for (next_event = 0, context = daemon->dhcp6; context; context = context->next)
	if (context->ra_time != 0)
	  {
	    if (difftime(context->ra_time, now) <= 0.0)
	      break; /* overdue */
	    
	    if (next_event == 0 || difftime(next_event, context->ra_time) > 0.0)
	      next_event = context->ra_time;
	  }
      
      /* none overdue */
      if (!context)
	break;
      
      if ((context->flags & CONTEXT_OLD) && 
	  context->if_index != 0 && 
	  indextoname(daemon->icmp6fd, context->if_index, param.name))
	{
	  /* A context for an old address. We'll not find the interface by 
	     looking for addresses, but we know it anyway, since the context is
	     constructed */
	  param.iface = context->if_index;
	  new_timeout(context, param.name, now);
	}
      else if (iface_enumerate(AF_INET6, &param, iface_search))
	/* There's a context overdue, but we can't find an interface
	   associated with it, because it's for a subnet we dont 
	   have an interface on. Probably we're doing DHCP on
	   a remote subnet via a relay. Zero the timer, since we won't
	   ever be able to send ra's and satisfy it. */
	context->ra_time = 0;
      
      if (param.iface != 0 &&
	  iface_check(AF_LOCAL, NULL, param.name, NULL))
	{
	  struct iname *tmp;
	  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
	    if (tmp->name && wildcard_match(tmp->name, param.name))
	      break;
	  if (!tmp)
            {
              send_ra(now, param.iface, param.name, NULL); 

              /* Also send on all interfaces that are aliases of this
                 one. */
              for (aparam.bridge = daemon->bridges;
                   aparam.bridge;
                   aparam.bridge = aparam.bridge->next)
                if ((int)if_nametoindex(aparam.bridge->iface) == param.iface)
                  {
                    /* Count the number of alias interfaces for this
                       'bridge', by calling iface_enumerate with
                       send_ra_to_aliases and NULL alias_ifs. */
                    aparam.iface = param.iface;
                    aparam.alias_ifs = NULL;
                    aparam.num_alias_ifs = 0;
                    iface_enumerate(AF_LOCAL, &aparam, send_ra_to_aliases);
                    my_syslog(MS_DHCP | LOG_INFO, "RTR-ADVERT(%s) %s => %d alias(es)",
                              param.name, daemon->addrbuff, aparam.num_alias_ifs);

                    /* Allocate memory to store the alias interface
                       indices. */
                    aparam.alias_ifs = (int *)whine_malloc(aparam.num_alias_ifs *
                                                           sizeof(int));
                    if (aparam.alias_ifs)
                      {
                        /* Use iface_enumerate again to get the alias
                           interface indices, then send on each of
                           those. */
                        aparam.max_alias_ifs = aparam.num_alias_ifs;
                        aparam.num_alias_ifs = 0;
                        iface_enumerate(AF_LOCAL, &aparam, send_ra_to_aliases);
                        for (; aparam.num_alias_ifs; aparam.num_alias_ifs--)
                          {
                            my_syslog(MS_DHCP | LOG_INFO, "RTR-ADVERT(%s) %s => i/f %d",
                                      param.name, daemon->addrbuff,
                                      aparam.alias_ifs[aparam.num_alias_ifs - 1]);
                            send_ra_alias(now,
                                          param.iface,
                                          param.name,
                                          NULL,
                                          aparam.alias_ifs[aparam.num_alias_ifs - 1]);
                          }
                        free(aparam.alias_ifs);
                      }

                    /* The source interface can only appear in at most
                       one --bridge-interface. */
                    break;
                  }
            }
	}
    }      
  return next_event;
}

/**
 * @brief Identify and collect interface alias indices for RA transmission
 * 
 * @detailed Callback function for iface_enumerate() that identifies interfaces matching alias
 * specifications in --bridge-interface configuration and collects their indices. Used in two passes:
 * first pass counts matching aliases (alias_ifs NULL), second pass stores indices in pre-allocated
 * array. Checks if interface name matches any alias pattern in the bridge configuration using
 * wildcard_matchn(). Part of interface aliasing mechanism where single RA configuration can be
 * transmitted on multiple physical interfaces.
 * 
 * @param index Interface index being enumerated
 * @param type Hardware address type - unused
 * @param mac Hardware address - unused
 * @param maclen Hardware address length - unused
 * @param parm Pointer to struct alias_param with bridge config and result storage
 * 
 * @return 1 to continue enumeration (always continues to find all aliases)
 * 
 * @note First pass (alias_ifs NULL): Only increments num_alias_ifs counter
 * @note Second pass (alias_ifs non-NULL): Stores index if num_alias_ifs < max_alias_ifs
 * @note Uses if_indextoname() to get interface name for pattern matching
 * 
 * @see periodic_ra() which uses this for alias interface enumeration
 * @see send_ra_alias() which is called for each identified alias interface
 * 
 * EXAMPLE USAGE:
 * @code
 * struct alias_param aparam;
 * aparam.bridge = find_bridge_config("br0");
 * aparam.alias_ifs = NULL;
 * aparam.num_alias_ifs = 0;
 * // First pass: count aliases
 * iface_enumerate(AF_LOCAL, &aparam, send_ra_to_aliases);
 * // Allocate and do second pass to collect indices
 * aparam.alias_ifs = malloc(aparam.num_alias_ifs * sizeof(int));
 * aparam.max_alias_ifs = aparam.num_alias_ifs;
 * aparam.num_alias_ifs = 0;
 * iface_enumerate(AF_LOCAL, &aparam, send_ra_to_aliases);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Not directly related to RFC 4861, supports dnsmasq-specific interface aliasing feature.
 * 
 * SIDE EFFECTS:
 * - Increments aparam->num_alias_ifs when matching alias found
 * - Stores interface index in aparam->alias_ifs array if space available
 * 
 * THREAD SAFETY:
 * Not thread-safe. Called from periodic_ra() in main event loop only.
 */
static int send_ra_to_aliases(int index, unsigned int type, char *mac, size_t maclen, void *parm)
{
  struct alias_param *aparam = (struct alias_param *)parm;
  char ifrn_name[IFNAMSIZ];
  struct dhcp_bridge *alias;

  (void)type;
  (void)mac;
  (void)maclen;

  if (if_indextoname(index, ifrn_name))
    for (alias = aparam->bridge->alias; alias; alias = alias->next)
      if (wildcard_matchn(alias->iface, ifrn_name, IFNAMSIZ))
        {
          if (aparam->alias_ifs && (aparam->num_alias_ifs < aparam->max_alias_ifs))
            aparam->alias_ifs[aparam->num_alias_ifs] = index;
          aparam->num_alias_ifs++;
        }

  return 1;
}

/**
 * @brief Search for interface with overdue Router Advertisement context
 * 
 * @detailed Callback function for iface_enumerate() used by periodic_ra() to locate the interface
 * associated with a DHCPv6 context that has an expired ra_time. Matches interface addresses against
 * DHCPv6 contexts using network comparison, validates interface is not in dhcp-except list, and checks
 * for DAD (Duplicate Address Detection) tentative state before allowing RA transmission. When matching
 * overdue context found, stores interface index in search_param, calls new_timeout() to schedule next
 * RA, and zeros ra_time for other contexts on same subnet to prevent redundant transmissions. Returns
 * 0 to abort search once match found.
 * 
 * @param local IPv6 address being enumerated from interface
 * @param prefix Prefix length for this address
 * @param scope Address scope - unused
 * @param if_index Interface index for this address
 * @param flags Address flags including IFACE_TENTATIVE for DAD in progress
 * @param preferred Preferred lifetime - unused
 * @param valid Valid lifetime - unused
 * @param vparam Pointer to struct search_param with search criteria and result storage
 * 
 * @return 0 if overdue context found (abort search), 1 to continue searching
 * 
 * @note Skips CONTEXT_TEMPLATE and CONTEXT_OLD contexts
 * @note Checks IFACE_TENTATIVE flag - delays RA if DAD not complete
 * @note Zeroes ra_time for duplicate contexts on same subnet after first match
 * @note Validates interface name via indextoname() and iface_check()
 * @note Checks against dhcp-except list via wildcard_match()
 * 
 * @see periodic_ra() which calls iface_enumerate() with this callback
 * @see new_timeout() for scheduling next RA transmission
 * 
 * EXAMPLE USAGE:
 * @code
 * struct search_param param;
 * param.now = time(NULL);
 * param.iface = 0;
 * // iface_enumerate calls iface_search for each address
 * if (!iface_enumerate(AF_INET6, &param, iface_search))
 *   // Found interface with overdue RA in param.iface and param.name
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 6.2.4 periodic RA transmission timing checks.
 * Respects DAD (RFC 4862 Section 5.4) by not sending RA on tentative addresses.
 * 
 * SIDE EFFECTS:
 * - Sets param->iface to matching interface index if not tentative
 * - Copies interface name to param->name
 * - Calls new_timeout() which updates context->ra_time
 * - Zeroes context->ra_time for duplicate contexts on same subnet
 * - Returns 0 which aborts iface_enumerate() iteration
 * 
 * THREAD SAFETY:
 * Not thread-safe. Called from periodic_ra() in main event loop only.
 */
static int iface_search(struct in6_addr *local,  int prefix,
			int scope, int if_index, int flags, 
			int preferred, int valid, void *vparam)
{
  struct search_param *param = vparam;
  struct dhcp_context *context;
  struct iname *tmp;
  
  (void)scope;
  (void)preferred;
  (void)valid;

  /* ignore interfaces we're not doing DHCP on. */
  if (!indextoname(daemon->icmp6fd, if_index, param->name) ||
      !iface_check(AF_LOCAL, NULL, param->name, NULL))
    return 1;

  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && wildcard_match(tmp->name, param->name))
      return 1;

  for (context = daemon->dhcp6; context; context = context->next)
    if (!(context->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
	prefix <= context->prefix &&
	is_same_net6(local, &context->start6, context->prefix) &&
	is_same_net6(local, &context->end6, context->prefix) &&
	context->ra_time != 0 && 
	difftime(context->ra_time, param->now) <= 0.0)
      {
	/* found an interface that's overdue for RA determine new 
	   timeout value and arrange for RA to be sent unless interface is
	   still doing DAD.*/
	if (!(flags & IFACE_TENTATIVE))
	  param->iface = if_index;
	
	new_timeout(context, param->name, param->now);
	
	/* zero timers for other contexts on the same subnet, so they don't timeout 
	   independently */
	for (context = context->next; context; context = context->next)
	  if (prefix <= context->prefix &&
	      is_same_net6(local, &context->start6, context->prefix) &&
	      is_same_net6(local, &context->end6, context->prefix))
	    context->ra_time = 0;
	
	return 0; /* found, abort */
      }
  
  return 1; /* keep searching */
}
 
/**
 * @brief Calculate and set next Router Advertisement transmission time
 * 
 * @detailed Computes next RA transmission timestamp based on RFC 4861 timing requirements and current
 * state. During initial 60-second short period after ra_short_period_start, uses rapid interval of
 * 5-20 seconds for reliability. After short period, uses randomized interval between 3/4 and full
 * MaxRtrAdvInterval (default 600s, configurable) per RFC 4861 Section 6.2.1. Randomization prevents
 * RA synchronization across multiple routers. Uses rand16() for generating random intervals.
 * 
 * @param context DHCPv6 context to update with new ra_time
 * @param iface_name Interface name for looking up configured advertisement interval
 * @param now Current timestamp for calculating timeout
 * 
 * @return void (modifies context->ra_time)
 * 
 * @note Short period (first 60 seconds): 5-20 second intervals calculated as 5 + (rand16()/4400)
 * @note Normal period: 3/4 to full MaxRtrAdvInterval calculated as (3*interval)/4 + random component
 * @note Random component uses rand16() scaled appropriately for interval range
 * 
 * @see calc_interval() for determining MaxRtrAdvInterval from configuration
 * @see find_iface_param() for retrieving interface-specific RA parameters
 * @see ra_start_unsolicited() which sets ra_short_period_start
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = find_context_for_interface("eth0");
 * new_timeout(ctx, "eth0", time(NULL));
 * // ctx->ra_time now contains next transmission time
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 6.2.1 and 6.2.4 timing requirements:
 * - MinRtrAdvInterval: 3/4 of MaxRtrAdvInterval (or 200s, whichever is less)
 * - MaxRtrAdvInterval: Default 600s (configurable via ra-param)
 * - Initial fast advertisements for first minute per Section 6.2.4
 * - Randomization to desynchronize multiple routers on same link
 * 
 * SIDE EFFECTS:
 * - Modifies context->ra_time with calculated next transmission timestamp
 * - Calls find_iface_param() which searches daemon->ra_interfaces list
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop thread.
 */
static void new_timeout(struct dhcp_context *context, char *iface_name, time_t now)
{
  if (difftime(now, context->ra_short_period_start) < 60.0)
    /* range 5 - 20 */
    context->ra_time = now + 5 + (rand16()/4400);
  else
    {
      /* range 3/4 - 1 times MaxRtrAdvInterval */
      unsigned int adv_interval = calc_interval(find_iface_param(iface_name));
      context->ra_time = now + (3 * adv_interval)/4 + ((adv_interval * (unsigned int)rand16()) >> 18);
    }
}

/**
 * @brief Lookup interface-specific Router Advertisement parameters
 * 
 * @detailed Searches daemon->ra_interfaces list for ra-param configuration matching the specified
 * interface name. Uses wildcard_match() to support pattern matching (e.g., "eth*" matches "eth0",
 * "eth1"). Returns first matching ra_interface structure containing customized interval, lifetime,
 * priority, and MTU settings. Returns NULL if no ra-param directive configured for interface,
 * causing callers to use default RA parameters.
 * 
 * @param iface Interface name to search for in ra-param configurations
 * 
 * @return Pointer to matching struct ra_interface, or NULL if no match found
 * 
 * @note Uses wildcard matching, so "eth*" pattern matches "eth0", "eth1", etc.
 * @note Returns first match if multiple patterns could match (configuration order matters)
 * 
 * @see calc_interval() which uses returned ra->interval
 * @see calc_lifetime() which uses returned ra->lifetime
 * @see calc_prio() which uses returned ra->prio
 * @see send_ra_alias() which uses returned ra->mtu and ra->mtu_name
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra_cfg = find_iface_param("eth0");
 * if (ra_cfg)
 *   interval = ra_cfg->interval; // Use configured interval
 * else
 *   interval = 600; // Use default
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Supports RFC 4861 Section 6.2.1 configurable MaxRtrAdvInterval and AdvDefaultLifetime.
 * 
 * SIDE EFFECTS:
 * None (read-only search of configuration structures).
 * 
 * THREAD SAFETY:
 * Thread-safe for read access. Configuration list should not be modified during execution.
 */
static struct ra_interface *find_iface_param(char *iface)
{
  struct ra_interface *ra;
  
  for (ra = daemon->ra_interfaces; ra; ra = ra->next)
    if (wildcard_match(ra->name, iface))
      return ra;

  return NULL;
}

/**
 * @brief Calculate Router Advertisement transmission interval (MaxRtrAdvInterval)
 * 
 * @detailed Determines RA transmission interval from ra-param configuration or uses default value
 * of 600 seconds. Enforces RFC 4861 constraints: minimum 4 seconds (stricter than RFC minimum of
 * 3 seconds), maximum 1800 seconds per RFC 4861 Section 6.2.1. Returns interval in seconds used
 * by new_timeout() for scheduling periodic RA transmissions and by send_ra_alias() for Advertisement
 * Interval option (RFC 6275).
 * 
 * @param ra Interface-specific RA parameters from ra-param config, or NULL for defaults
 * 
 * @return Interval in seconds, range [4, 1800], default 600
 * 
 * @note Default 600 seconds if no ra-param or ra->interval == 0
 * @note Enforces minimum of 4 seconds (slightly stricter than RFC 4861's 3 second minimum)
 * @note Enforces maximum of 1800 seconds per RFC 4861 Section 6.2.1
 * @note Used for Advertisement Interval option (converted to milliseconds by caller)
 * 
 * @see find_iface_param() for retrieving ra parameter
 * @see new_timeout() which uses this for scheduling periodic RAs
 * @see send_ra_alias() which includes result in Advertisement Interval option
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra = find_iface_param("eth0");
 * unsigned int interval = calc_interval(ra);
 * // interval is between 4 and 1800 seconds
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 6.2.1 MaxRtrAdvInterval:
 * - Default: 600 seconds
 * - Valid range: 4 to 1800 seconds
 * - Used with MinRtrAdvInterval (3/4 of Max) for random interval selection
 * 
 * SIDE EFFECTS:
 * None (pure calculation function).
 * 
 * THREAD SAFETY:
 * Thread-safe (read-only access to ra parameter).
 */
static unsigned int calc_interval(struct ra_interface *ra)
{
  int interval = 600;
  
  if (ra && ra->interval != 0)
    {
      interval = ra->interval;
      if (interval > 1800)
	interval = 1800;
      else if (interval < 4)
	interval = 4;
    }
  
  return (unsigned int)interval;
}

/**
 * @brief Calculate Router Lifetime for RA header
 * 
 * @detailed Computes Router Lifetime value (in seconds) to advertise in RA header, indicating how
 * long hosts should consider this router as default gateway. If not explicitly configured via
 * ra-param lifetime, defaults to 3 * MaxRtrAdvInterval per RFC 4861 recommendation. Enforces
 * constraints: must be at least MaxRtrAdvInterval (unless explicitly 0 to signal not a default
 * router), maximum 9000 seconds. Value of 0 signals router should not be used as default gateway.
 * 
 * @param ra Interface-specific RA parameters from ra-param config, or NULL for defaults
 * 
 * @return Router lifetime in seconds, range [0, 9000], default 3*interval
 * 
 * @note Default is 3 * calc_interval() if ra is NULL or ra->lifetime == -1
 * @note Configured lifetime < interval is adjusted to interval (unless explicitly 0)
 * @note Maximum 9000 seconds enforced (approximately 2.5 hours)
 * @note Lifetime 0 means "not a default router" per RFC 4861 Section 4.2
 * 
 * @see calc_interval() for MaxRtrAdvInterval used in default calculation
 * @see find_iface_param() for retrieving ra parameter
 * @see send_ra_alias() which sets this in ra->lifetime field of RA header
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra = find_iface_param("eth0");
 * unsigned int lifetime = calc_lifetime(ra);
 * ra_packet->lifetime = htons(lifetime);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4861 Section 4.2 Router Lifetime field:
 * - Default: 3 * MaxRtrAdvInterval (recommended in RFC 4861 Section 6.2.1)
 * - Valid range: 0 or MaxRtrAdvInterval to 9000 seconds
 * - 0 indicates router should not be used as default gateway
 * - Must be 0 or at least MaxRtrAdvInterval
 * 
 * SIDE EFFECTS:
 * None (pure calculation function).
 * 
 * THREAD SAFETY:
 * Thread-safe (read-only access to ra parameter).
 */
static unsigned int calc_lifetime(struct ra_interface *ra)
{
  int lifetime, interval = (int)calc_interval(ra);
  
  if (!ra || ra->lifetime == -1) /* not specified */
    lifetime = 3 * interval;
  else
    {
      lifetime = ra->lifetime;
      if (lifetime < interval && lifetime != 0)
	lifetime = interval;
      else if (lifetime > 9000)
	lifetime = 9000;
    }
  
  return (unsigned int)lifetime;
}

/**
 * @brief Calculate router priority for RA header flags field
 * 
 * @detailed Returns configured router priority value from ra-param or default of 0 (medium priority).
 * Priority is encoded in bits 3-4 of RA flags field per RFC 4191 Section 2.2. Values are: 0x00 (medium,
 * default), 0x08 (low), 0x18 (high). Priority affects default router selection when multiple routers
 * advertise on same link - higher priority routers are preferred. Medium priority (0) is appropriate
 * for most deployments.
 * 
 * @param ra Interface-specific RA parameters from ra-param config, or NULL for defaults
 * 
 * @return Router priority value: 0x00 (medium), 0x08 (low), or 0x18 (high)
 * 
 * @note Default priority is 0 (medium) if no ra-param configured
 * @note Value directly inserted into RA flags field bits 3-4
 * @note Does not validate that ra->prio contains legal value (0x00, 0x08, or 0x18)
 * 
 * @see find_iface_param() for retrieving ra parameter
 * @see send_ra_alias() which OR's this value into ra->flags field
 * 
 * EXAMPLE USAGE:
 * @code
 * struct ra_interface *ra = find_iface_param("eth0");
 * unsigned int prio = calc_prio(ra);
 * ra_packet->flags = prio | (managed ? 0x80 : 0) | (other ? 0x40 : 0);
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 4191 Section 2.2 Default Router Preferences:
 * - 0x00: Medium preference (default)
 * - 0x08: Low preference (00 in bits 4-3)
 * - 0x18: High preference (01 in bits 4-3)
 * - Encoded in Reserved field of RFC 4861 RA, redefined by RFC 4191
 * 
 * SIDE EFFECTS:
 * None (pure accessor function).
 * 
 * THREAD SAFETY:
 * Thread-safe (read-only access to ra parameter).
 */
static unsigned int calc_prio(struct ra_interface *ra)
{
  if (ra)
    return ra->prio;
  
  return 0;
}

#endif
