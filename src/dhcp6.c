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
 * @file dhcp6.c
 * @brief DHCPv6 server core logic coordinating with RFC 3315 protocol implementation
 *
 * DETAILED PURPOSE:
 * This file implements the DHCPv6 server core functionality for dnsmasq, coordinating
 * with rfc3315.c which handles the detailed RFC 3315 protocol message processing.
 * It manages DHCPv6 socket creation, packet reception and dispatching, DUID (DHCP Unique
 * Identifier) generation, IPv6 address allocation from configured ranges, prefix delegation,
 * and dynamic context construction based on interface addresses. Unlike DHCPv4 which uses
 * MAC addresses, DHCPv6 identifies clients using DUIDs. This module handles IA_NA (Identity
 * Association for Non-temporary Addresses) allocation, integrates with Router Advertisement
 * (radv.c) for M/O flag coordination, supports stateless INFORMATION-REQUEST handling,
 * and implements relay agent support for remote subnet allocation.
 *
 * KEY RESPONSIBILITIES:
 * - dhcp6_init(): Creates and binds DHCPv6 server socket on port 547
 * - dhcp6_packet(): Main packet reception entry point, dispatches to dhcp6_reply() in rfc3315.c
 * - get_client_mac(): Retrieves client MAC address via neighbor discovery for DUID generation
 * - address6_allocate(): Allocates free IPv6 addresses from configured ranges using SDBM hashing
 * - address6_available(): Validates whether address can be dynamically allocated
 * - address6_valid(): Checks if address is within valid configured context
 * - make_duid(): Generates DHCPv6 server DUID (DUID-LLT, DUID-LL, or DUID-EN)
 * - config_find_by_address6(): Finds static configuration by IPv6 address
 * - dhcp_construct_contexts(): Dynamically creates DHCPv6 contexts from interface addresses
 * - complete_context6(): Callback for interface enumeration to match contexts with addresses
 *
 * DEPENDENCIES:
 * - Includes: dnsmasq.h (main header with daemon structure, DHCP contexts, configuration)
 * - Includes: netinet/icmp6.h (ICMPv6 for neighbor discovery)
 * - Includes: dhcp6-protocol.h (DHCPv6 constants and option codes)
 * - Called by: Network event loop in dnsmasq.c when DHCPv6 packets arrive
 * - Calls: dhcp6_reply() in rfc3315.c for detailed protocol message handling
 * - Calls: relay_reply6(), relay_upstream6() for DHCPv6 relay functionality
 * - Calls: lease functions in lease.c (lease_prune, lease_update_file, lease_update_dns)
 * - Calls: ra_start_unsolicited() in radv.c for Router Advertisement coordination
 *
 * DATA STRUCTURES:
 * - struct iface_param (lines 23-27): Parameters for interface enumeration callback
 * - struct cparam (lines 639-642): Parameters for context construction callback
 * - struct dhcp_context: DHCPv6 address range configuration (defined in dnsmasq.h)
 * - struct dhcp_config: Static DHCPv6 host reservations (defined in dnsmasq.h)
 * - struct neigh_packet (lines 278): Neighbor solicitation packet for MAC address discovery
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP6: Mandatory - entire file compiled only if DHCPv6 support enabled
 * - HAVE_DUMPFILE: Optional - enables packet dumping to pcap file for debugging
 * - HAVE_BROKEN_RTC: Optional - affects DUID generation (use DUID-LL instead of DUID-LLT)
 * - HAVE_SOCKADDR_SA_LEN: Platform-specific - BSD-style sockaddr with sa_len field
 * - SO_REUSEPORT: Optional - allows multiple dnsmasq instances on same port
 * - IPV6_TCLASS: Optional - sets IPv6 traffic class for QoS
 *
 * THREADING/CONCURRENCY:
 * This module operates within dnsmasq's single-process, event-driven architecture.
 * All functions are called from the main event loop and are not re-entrant. DHCPv6
 * socket events trigger dhcp6_packet() which processes one packet per invocation.
 * No locking is required as there is no concurrent access. State is maintained in
 * the global daemon structure and DHCPv6 context chains.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DHCP_V6.md for DHCPv6 server architecture and RFC 3315 compliance
 * @see rfc3315.c for detailed DHCPv6 protocol message handling
 * @see radv.c for Router Advertisement integration
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

#include <netinet/icmp6.h>

struct iface_param {
  struct dhcp_context *current;
  struct in6_addr fallback, ll_addr, ula_addr;
  int ind, addr_match;
};


static int complete_context6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, int flags, 
			     unsigned int preferred, unsigned int valid, void *vparam);
static int make_duid1(int index, unsigned int type, char *mac, size_t maclen, void *parm); 

/**
 * @brief Initialize DHCPv6 server socket and bind to port 547
 *
 * @detailed Creates a UDP IPv6 socket for DHCPv6 server operations, configures socket options
 * including IPv6-only mode, traffic class (QoS), and address reuse for bind-interfaces mode,
 * then binds to the standard DHCPv6 server port (547). The socket is configured with IPV6_V6ONLY
 * to prevent IPv4-mapped addresses, and IPV6_PKTINFO to receive destination address information.
 * When bind-interfaces is set, SO_REUSEADDR and SO_REUSEPORT allow multiple dnsmasq instances
 * to bind the same port on different interfaces. The file descriptor is stored in daemon->dhcp6fd
 * for use by the main event loop.
 *
 * @return void - dies with error message on failure via die()
 *
 * @note Called once during daemon initialization from main() in dnsmasq.c
 * @note Sets IPv6 traffic class to CS6 (0xC0) if IPV6_TCLASS available for QoS marking
 * @note Configured socket is non-blocking via fix_fd() and has IPV6_PKTINFO enabled
 *
 * @warning Dies with EC_BADNET error code if socket creation or binding fails
 * @warning On bind-interfaces, dies if SO_REUSEADDR/SO_REUSEPORT setting fails
 *
 * @see dhcp6_packet() which uses daemon->dhcp6fd to receive DHCPv6 packets
 * @see fix_fd() in network.c for non-blocking configuration
 * @see set_ipv6pktinfo() in network.c for IPV6_PKTINFO setup
 *
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon startup
 * if (daemon->doing_dhcp6)
 *   dhcp6_init();
 * // Socket now ready for event loop
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 5.2 - DHCPv6 server listens on UDP port 547
 * RFC 3315 Section 22.1 - Client-Server exchanges on port 547
 *
 * SIDE EFFECTS:
 * - Creates UDP socket and stores file descriptor in daemon->dhcp6fd
 * - Binds to INADDR_ANY on port 547 (all interfaces)
 * - Dies and terminates daemon if socket setup fails
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main thread during initialization only.
 * Single-threaded event-driven architecture.
 */
void dhcp6_init(void)
{
  int fd;
  struct sockaddr_in6 saddr;
#if defined(IPV6_TCLASS) && defined(IPTOS_CLASS_CS6)
  int class = IPTOS_CLASS_CS6;
#endif
  int oneopt = 1;

  if ((fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1 ||
#if defined(IPV6_TCLASS) && defined(IPTOS_CLASS_CS6)
      setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &class, sizeof(class)) == -1 ||
#endif
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &oneopt, sizeof(oneopt)) == -1 ||
      !fix_fd(fd) ||
      !set_ipv6pktinfo(fd))
    die (_("cannot create DHCPv6 socket: %s"), NULL, EC_BADNET);
  
 /* When bind-interfaces is set, there might be more than one dnsmasq
     instance binding port 547. That's OK if they serve different networks.
     Need to set REUSEADDR|REUSEPORT to make this possible.
     Handle the case that REUSEPORT is defined, but the kernel doesn't 
     support it. This handles the introduction of REUSEPORT on Linux. */
  if (option_bool(OPT_NOWILD) || option_bool(OPT_CLEVERBIND))
    {
      int rc = 0;

#ifdef SO_REUSEPORT
      if ((rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &oneopt, sizeof(oneopt))) == -1 &&
	  errno == ENOPROTOOPT)
	rc = 0;
#endif
      
      if (rc != -1)
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &oneopt, sizeof(oneopt));
      
      if (rc == -1)
	die(_("failed to set SO_REUSE{ADDR|PORT} on DHCPv6 socket: %s"), NULL, EC_BADNET);
    }
  
  memset(&saddr, 0, sizeof(saddr));
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin6_len = sizeof(struct sockaddr_in6);
#endif
  saddr.sin6_family = AF_INET6;
  saddr.sin6_addr = in6addr_any;
  saddr.sin6_port = htons(DHCPV6_SERVER_PORT);
  
  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6)))
    die(_("failed to bind DHCPv6 server socket: %s"), NULL, EC_BADNET);
  
  daemon->dhcp6fd = fd;
}

/**
 * @brief Main DHCPv6 packet reception and dispatching entry point
 *
 * @detailed Receives DHCPv6 packets from the socket, determines the arrival interface and
 * destination address using IPV6_PKTINFO ancillary data, checks for relay mode operation,
 * validates interface configuration against include/exclude lists, enumerates interface
 * addresses to build DHCPv6 context chains, prunes expired leases, and dispatches to
 * dhcp6_reply() in rfc3315.c for protocol-specific message handling. This function handles
 * both direct client requests and relay-forwarded messages. It performs bridge interface
 * aliasing to allow DHCPv6 on virtualized networks, filters against --dhcp-except interfaces,
 * and coordinates with Router Advertisement for M/O flag settings. After processing,
 * responses are sent back to clients or relays via sendto() with appropriate port numbers
 * (546 for clients, 547 for relays).
 *
 * @param now Current time in seconds since epoch for lease expiry checking and timestamp operations
 *
 * @return void - processes one packet per invocation, returns silently on errors
 *
 * @note Called from main event loop when daemon->dhcp6fd becomes readable
 * @note Handles both unicast and multicast DHCPv6 traffic (All_DHCP_Relay_Agents_and_Servers FF02::1:2)
 * @note Bridge interface aliasing via --bridge-interface redirects to aliased interface contexts
 * @note Ignores packets to ALL_SERVERS multicast when listening for relay to avoid loops
 *
 * @warning Returns early without processing if interface index cannot be determined
 * @warning Returns early if interface is in --if-except or --dhcp-except lists
 * @warning Returns early if no valid DHCPv6 contexts found for arrival interface
 *
 * @see dhcp6_reply() in rfc3315.c for detailed message type handling (SOLICIT, REQUEST, etc.)
 * @see relay_reply6() for relay agent reply forwarding
 * @see relay_upstream6() for forwarding client requests to upstream relay
 * @see complete_context6() callback for interface address enumeration
 * @see lease_prune() in lease.c for expired lease removal
 * @see lease_update_file() in lease.c for persistent lease database updates
 *
 * EXAMPLE USAGE:
 * @code
 * // Main event loop in dnsmasq.c
 * if (poll_check(daemon->dhcp6fd, POLLIN))
 *   dhcp6_packet(time(NULL));
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 15 - DHCPv6 message types and server processing
 * RFC 3315 Section 20 - Relay agent behavior and message forwarding
 *
 * SIDE EFFECTS:
 * - Reads packet from daemon->dhcp6fd socket
 * - May send DHCPv6 response via daemon->dhcp6fd
 * - Calls lease_prune() to remove expired leases
 * - Calls lease_update_file() and lease_update_dns() after reply
 * - May dump packets to pcap file if HAVE_DUMPFILE enabled
 * - May trigger Router Advertisement transmission via lease_update_file()
 *
 * THREAD SAFETY:
 * Not thread-safe. Called from single-threaded event loop only.
 * Re-entrancy not supported - one packet processed per invocation.
 */
void dhcp6_packet(time_t now)
{
  struct dhcp_context *context;
  struct iface_param parm;
  struct cmsghdr *cmptr;
  struct msghdr msg;
  int if_index = 0;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_u;
  struct sockaddr_in6 from;
  ssize_t sz; 
  struct ifreq ifr;
  struct iname *tmp;
  unsigned short port;
  struct in6_addr dst_addr;
  struct in6_addr all_servers;
  
  memset(&dst_addr, 0, sizeof(dst_addr));

  msg.msg_control = control_u.control6;
  msg.msg_controllen = sizeof(control_u);
  msg.msg_flags = 0;
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_iov =  &daemon->dhcp_packet;
  msg.msg_iovlen = 1;
  
  if ((sz = recv_dhcp_packet(daemon->dhcp6fd, &msg)) == -1)
    return;
  
#ifdef HAVE_DUMPFILE
  dump_packet(DUMP_DHCPV6, (void *)daemon->dhcp_packet.iov_base, sz,
	      (union mysockaddr *)&from, NULL, DHCPV6_SERVER_PORT);
#endif
  
  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
    if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == daemon->v6pktinfo)
      {
	union {
	  unsigned char *c;
	  struct in6_pktinfo *p;
	} p;
	p.c = CMSG_DATA(cmptr);
        
	if_index = p.p->ipi6_ifindex;
	dst_addr = p.p->ipi6_addr;
      }

  if (!indextoname(daemon->dhcp6fd, if_index, ifr.ifr_name))
    return;

  if (relay_reply6(&from, sz, ifr.ifr_name))
    {
#ifdef HAVE_DUMPFILE
      dump_packet(DUMP_DHCPV6, (void *)daemon->outpacket.iov_base, save_counter(-1), NULL,
		  (union mysockaddr *)&from, DHCPV6_SERVER_PORT);
#endif
      
      while (retry_send(sendto(daemon->dhcp6fd, daemon->outpacket.iov_base, 
			       save_counter(-1), 0, (struct sockaddr *)&from, 
			       sizeof(from))));
    }
  else
    {
      struct dhcp_bridge *bridge, *alias;
      
      for (tmp = daemon->if_except; tmp; tmp = tmp->next)
	if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	  return;
      
      for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
	if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	  return;
      
      parm.current = NULL;
      parm.ind = if_index;
      parm.addr_match = 0;
      memset(&parm.fallback, 0, IN6ADDRSZ);
      memset(&parm.ll_addr, 0, IN6ADDRSZ);
      memset(&parm.ula_addr, 0, IN6ADDRSZ);
      
      /* If the interface on which the DHCPv6 request was received is
         an alias of some other interface (as specified by the
         --bridge-interface option), change parm.ind so that we look
         for DHCPv6 contexts associated with the aliased interface
         instead of with the aliasing one. */
      for (bridge = daemon->bridges; bridge; bridge = bridge->next)
	{
	  for (alias = bridge->alias; alias; alias = alias->next)
	    if (wildcard_matchn(alias->iface, ifr.ifr_name, IF_NAMESIZE))
	      {
		parm.ind = if_nametoindex(bridge->iface);
		if (!parm.ind)
		  {
		    my_syslog(MS_DHCP | LOG_WARNING,
			      _("unknown interface %s in bridge-interface"),
			      bridge->iface);
		    return;
		  }
		break;
	      }
	  if (alias)
	    break;
	}
      
      for (context = daemon->dhcp6; context; context = context->next)
	if (IN6_IS_ADDR_UNSPECIFIED(&context->start6) && context->prefix == 0)
	  {
	    /* wildcard context for DHCP-stateless only */
	    parm.current = context;
	    context->current = NULL;
	  }
	else
	  {
	    /* unlinked contexts are marked by context->current == context */
	    context->current = context;
	    memset(&context->local6, 0, IN6ADDRSZ);
	  }
      
      /* Ignore requests sent to the ALL_SERVERS multicast address for relay when
	 we're listening there for DHCPv6 server reasons. */
      inet_pton(AF_INET6, ALL_SERVERS, &all_servers);
      
      if (!IN6_ARE_ADDR_EQUAL(&dst_addr, &all_servers) &&
	  relay_upstream6(if_index, (size_t)sz, &from.sin6_addr, from.sin6_scope_id, now))
	return;
      
      if (!iface_enumerate(AF_INET6, &parm, complete_context6))
	return;
      
      /* Check for a relay again after iface_enumerate/complete_context has had
	 chance to fill in relay->iface_index fields. This handles first time through
	 and any changes in interface config. */
      if (!IN6_ARE_ADDR_EQUAL(&dst_addr, &all_servers) &&
	  relay_upstream6(if_index, (size_t)sz, &from.sin6_addr, from.sin6_scope_id, now))
	return;
      
      if (daemon->if_names || daemon->if_addrs)
	{
	  
	  for (tmp = daemon->if_names; tmp; tmp = tmp->next)
	    if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	      break;
	  
	  if (!tmp && !parm.addr_match)
	    return;
	}
      
      /* May have configured relay, but not DHCP server */
      if (!daemon->doing_dhcp6)
	return;
      
      lease_prune(NULL, now); /* lose any expired leases */
      
      port = dhcp6_reply(parm.current, if_index, ifr.ifr_name, &parm.fallback, 
			 &parm.ll_addr, &parm.ula_addr, sz, &from.sin6_addr, now);
      
      /* The port in the source address of the original request should
	 be correct, but at least once client sends from the server port,
	 so we explicitly send to the client port to a client, and the
	 server port to a relay. */
      if (port != 0)
	{
	  from.sin6_port = htons(port);
	  
#ifdef HAVE_DUMPFILE
	  dump_packet(DUMP_DHCPV6, (void *)daemon->outpacket.iov_base, save_counter(-1),
		      NULL, (union mysockaddr *)&from, DHCPV6_SERVER_PORT);
#endif 
	  
	  while (retry_send(sendto(daemon->dhcp6fd, daemon->outpacket.iov_base,
				   save_counter(-1), 0, (struct sockaddr *)&from, sizeof(from))));
	}
      
      /* These need to be called _after_ we send DHCPv6 packet, since lease_update_file()
	 may trigger sending an RA packet, which overwrites our buffer. */
      lease_update_file(now);
      lease_update_dns(0);
    }
}

/**
 * @brief Retrieve client MAC address via neighbor discovery for DUID generation
 *
 * @detailed Attempts to retrieve the link-layer (MAC) address of an IPv6 client using the
 * kernel's neighbor cache. Since receiving a packet does not automatically populate the
 * neighbor cache, this function sends ICMPv6 Neighbor Solicitation messages if the MAC
 * address is not immediately available. It retries up to 5 times with 100ms delays between
 * attempts to handle packet loss. The MAC address is essential for generating client-specific
 * DUID values and for identifying clients across requests. Uses find_mac() to query the
 * neighbor cache and sendto() on daemon->icmp6fd to transmit neighbor solicitation packets.
 *
 * @param client Pointer to IPv6 address of the DHCPv6 client to query
 * @param iface Interface index (scope_id) on which client is reachable
 * @param mac Buffer to store retrieved MAC address (minimum 6 bytes for Ethernet)
 * @param maclenp Pointer to store length of retrieved MAC address (typically 6 for Ethernet)
 * @param mactypep Pointer to store MAC address type (set to ARPHRD_ETHER for Ethernet)
 * @param now Current time for neighbor cache queries
 *
 * @return void - populates mac buffer and sets maclenp/mactypep output parameters
 *
 * @note Sends up to 5 Neighbor Solicitation attempts with 100ms delays
 * @note MAC address type always set to ARPHRD_ETHER (Ethernet hardware type)
 * @note If MAC not found after retries, maclenp will be 0
 *
 * @warning Requires daemon->icmp6fd to be valid for sending ICMP6 packets
 * @warning 100ms delays per retry may impact response latency (max 500ms total)
 *
 * @see find_mac() in arp.c for neighbor cache lookups
 * @see daemon->icmp6fd created in icmp6_init()
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac[6];
 * unsigned int maclen, mactype;
 * struct in6_addr client_addr = {...};
 * get_client_mac(&client_addr, if_index, mac, &maclen, &mactype, now);
 * if (maclen == 6)
 *   printf("Client MAC: %02x:%02x:...\n", mac[0], mac[1]);
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 4443 Section 2.3 - ICMPv6 checksum must be zero before calculation
 * RFC 4861 Section 4.3 - Neighbor Solicitation message format
 *
 * SIDE EFFECTS:
 * - Sends up to 5 ICMPv6 Neighbor Solicitation packets via daemon->icmp6fd
 * - Sleeps for 100ms between retry attempts (blocking operation)
 * - Modifies mac buffer, maclenp, and mactypep output parameters
 *
 * THREAD SAFETY:
 * Not thread-safe. Blocking nanosleep() calls make this unsuitable for concurrent use.
 * Must be called from main thread only.
 */
void get_client_mac(struct in6_addr *client, int iface, unsigned char *mac, unsigned int *maclenp, unsigned int *mactypep, time_t now)
{
  /* Receiving a packet from a host does not populate the neighbour
     cache, so we send a neighbour discovery request if we can't 
     find the sender. Repeat a few times in case of packet loss. */
  
  struct neigh_packet neigh;
  union mysockaddr addr;
  int i, maclen;

  neigh.type = ND_NEIGHBOR_SOLICIT;
  neigh.code = 0;
  neigh.reserved = 0;
  neigh.target = *client;
  /* RFC4443 section-2.3: checksum has to be zero to be calculated */
  neigh.checksum = 0;
   
  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
  addr.in6.sin6_family = AF_INET6;
  addr.in6.sin6_port = htons(IPPROTO_ICMPV6);
  addr.in6.sin6_addr = *client;
  addr.in6.sin6_scope_id = iface;
  
  for (i = 0; i < 5; i++)
    {
      struct timespec ts;
      
      if ((maclen = find_mac(&addr, mac, 0, now)) != 0)
	break;
	  
      while(retry_send(sendto(daemon->icmp6fd, &neigh, sizeof(neigh), 0, &addr.sa, sizeof(addr))));
      
      ts.tv_sec = 0;
      ts.tv_nsec = 100000000; /* 100ms */
      nanosleep(&ts, NULL);
    }

  *maclenp = maclen;
  *mactypep = ARPHRD_ETHER;
}
    
/**
 * @brief Callback to match DHCPv6 contexts with interface IPv6 addresses
 *
 * @detailed
 * This callback function is invoked by iface_enumerate() during interface address enumeration
 * to associate DHCPv6 contexts with actual interface addresses. It matches configured DHCPv6
 * address ranges (contexts) with the current IPv6 addresses on network interfaces, establishing
 * the link between logical address pools and physical network locations. Handles shared networks
 * (where one physical network uses multiple logical subnets), builds context chains ordered by
 * preferred lifetime, stores link-local and ULA addresses for later use, and sets up relay
 * agent mappings. Only processes addresses on the interface specified in param->ind, skipping
 * loopback, link-local (after storing), and multicast addresses for context matching.
 *
 * @param local IPv6 address found on the interface
 * @param prefix Prefix length of the address (typically 64 for standard IPv6)
 * @param scope Address scope (global, link-local, etc.) - currently unused
 * @param if_index Interface index where this address was found
 * @param flags Interface flags (IFACE_DEPRECATED, IFACE_PERMANENT, etc.)
 * @param preferred Preferred lifetime for this address in seconds (0xffffffff = infinite)
 * @param valid Valid lifetime for this address in seconds (0xffffffff = infinite)
 * @param vparam Void pointer to struct iface_param containing search parameters
 *
 * @return Always returns 1 to continue enumeration through all interface addresses
 *
 * @note Stores link-local address in param->ll_addr for later use
 * @note Stores ULA (Unique Local Address) in param->ula_addr
 * @note Stores global address in param->fallback as default DNS server address
 * @note Builds context chain ordered by decreasing preferred lifetime
 * @note Sets context->preferred and context->valid from interface or uses 0xffffffff
 * @note Honors CONTEXT_DEPRECATE flag to force preferred=0
 * @note Only matches contexts on the specific interface index in param->ind
 *
 * @warning Modifies param structure (ll_addr, ula_addr, fallback, current, addr_match)
 * @warning Modifies context->current to build linked list (destructive to existing value)
 * @warning Sets relay->iface_index for relay agents matching local address
 *
 * @see dhcp6_packet() which calls iface_enumerate() with this callback
 * @see struct iface_param definition (lines 23-27) for parameter structure
 * @see struct dhcp_context for context structure details
 *
 * EXAMPLE USAGE:
 * @code
 * struct iface_param parm;
 * parm.ind = if_index;
 * parm.current = NULL;
 * iface_enumerate(AF_INET6, &parm, complete_context6);
 * // parm.current now contains chain of matching contexts
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315: DHCPv6 address allocation from configured ranges
 * - RFC 4862: IPv6 address lifetimes (preferred and valid)
 *
 * SIDE EFFECTS:
 * - Chains matching contexts via context->current pointers
 * - Sets context->local6, context->preferred, context->valid
 * - Stores link-local, ULA, and fallback addresses in param structure
 * - Updates relay->iface_index for relay agent configuration
 * - Marks address match in param->addr_match if --listen-address matches
 *
 * THREAD SAFETY:
 * Not thread-safe. Called as callback from iface_enumerate() in single-threaded context.
 * Modifies shared context and relay structures without synchronization.
 */
static int complete_context6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, int flags, unsigned int preferred, 
			     unsigned int valid, void *vparam)
{
  struct dhcp_context *context;
  struct shared_network *share;
  struct dhcp_relay *relay;
  struct iface_param *param = vparam;
  struct iname *tmp;
  int match = !daemon->if_addrs;
 
  (void)scope; /* warning */
  
  if (if_index != param->ind)
    return 1;
  
  if (IN6_IS_ADDR_LINKLOCAL(local))
    param->ll_addr = *local;
  else if (IN6_IS_ADDR_ULA(local))
    param->ula_addr = *local;
      
  if (IN6_IS_ADDR_LOOPBACK(local) ||
      IN6_IS_ADDR_LINKLOCAL(local) ||
      IN6_IS_ADDR_MULTICAST(local))
    return 1;
  
  /* if we have --listen-address config, see if the 
     arrival interface has a matching address. */
  for (tmp = daemon->if_addrs; tmp; tmp = tmp->next)
    if (tmp->addr.sa.sa_family == AF_INET6 &&
	IN6_ARE_ADDR_EQUAL(&tmp->addr.in6.sin6_addr, local))
      match = param->addr_match = 1;
  
  /* Determine a globally address on the arrival interface, even
     if we have no matching dhcp-context, because we're only
     allocating on remote subnets via relays. This
     is used as a default for the DNS server option. */
  param->fallback = *local;
  
  for (context = daemon->dhcp6; context; context = context->next)
    if ((context->flags & CONTEXT_DHCP) &&
	!(context->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
	prefix <= context->prefix &&
	context->current == context)
      {
	if (is_same_net6(local, &context->start6, context->prefix) &&
	    is_same_net6(local, &context->end6, context->prefix))
	  {
	    struct dhcp_context *tmp, **up;
	    
	    /* use interface values only for constructed contexts */
	    if (!(context->flags & CONTEXT_CONSTRUCTED))
	      preferred = valid = 0xffffffff;
	    else if (flags & IFACE_DEPRECATED)
	      preferred = 0;
		    
	    if (context->flags & CONTEXT_DEPRECATE)
	      preferred = 0;
	    
	    /* order chain, longest preferred time first */
	    for (up = &param->current, tmp = param->current; tmp; tmp = tmp->current)
	      if (tmp->preferred <= preferred)
		break;
	      else
		up = &tmp->current;
	    
	    context->current = *up;
	    *up = context;
	    context->local6 = *local;
	    context->preferred = preferred;
	    context->valid = valid;
	  }
	else
	  {
	    for (share = daemon->shared_networks; share; share = share->next)
	      {
		/* IPv4 shared_address - ignore */
		if (share->shared_addr.s_addr != 0)
		  continue;
			
		if (share->if_index != 0)
		  {
		    if (share->if_index != if_index)
		      continue;
		  }
		else
		  {
		    if (!IN6_ARE_ADDR_EQUAL(&share->match_addr6, local))
		      continue;
		  }
		
		if (is_same_net6(&share->shared_addr6, &context->start6, context->prefix) &&
		    is_same_net6(&share->shared_addr6, &context->end6, context->prefix))
		  {
		    context->current = param->current;
		    param->current = context;
		    context->local6 = *local;
		    context->preferred = context->flags & CONTEXT_DEPRECATE ? 0 :0xffffffff;
		    context->valid = 0xffffffff;
		  }
	      }
	  }      
      }
  
  if (match)
    for (relay = daemon->relay6; relay; relay = relay->next)
      if (IN6_ARE_ADDR_EQUAL(local, &relay->local.addr6))
	relay->iface_index = if_index;
  
  return 1;
}

/**
 * @brief Find static DHCPv6 host configuration by IPv6 address
 *
 * @detailed Searches through linked list of DHCPv6 host configurations to find a static
 * reservation matching the given IPv6 address. Supports wildcard matching for /64 prefixes
 * (ADDRLIST_WILDCARD flag) and custom prefix lengths (ADDRLIST_PREFIX flag). Used to prevent
 * dynamic allocation of addresses that are statically configured for specific hosts, and to
 * enforce static address assignments configured via dhcp-host directives. Only considers
 * configurations with CONFIG_ADDR6 flag set indicating IPv6 address assignment.
 *
 * @param configs Head of linked list of dhcp_config structures to search
 * @param net Network prefix to match against, or NULL to skip network matching
 * @param prefix Prefix length for network matching (typically 64 for standard IPv6)
 * @param addr Specific IPv6 address to find in configuration
 *
 * @return Pointer to matching dhcp_config structure, or NULL if no match found
 *
 * @note Handles both exact /128 address matches and prefix-based matches
 * @note Wildcard flag allows /64 prefix matching regardless of configured prefix
 * @note Multiple address entries can exist per config (config->addr6 is a linked list)
 *
 * @warning Returns first matching config - does not check for multiple matches
 *
 * @see address6_allocate() which calls this to avoid allocating static addresses
 * @see struct dhcp_config in dnsmasq.h for configuration structure
 * @see struct addrlist for address list entries with flags
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client_addr = {...};
 * struct in6_addr network = {...};
 * struct dhcp_config *cfg = config_find_by_address6(daemon->dhcp_conf, 
 *                                                    &network, 64, &client_addr);
 * if (cfg)
 *   printf("Address reserved for host: %s\n", cfg->hostname);
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 18 - Static address assignment for specific clients
 *
 * SIDE EFFECTS:
 * None - read-only search operation
 *
 * THREAD SAFETY:
 * Not thread-safe if configs list modified concurrently. Read-only safe for single thread.
 */
struct dhcp_config *config_find_by_address6(struct dhcp_config *configs, struct in6_addr *net, int prefix,  struct in6_addr *addr)
{
  struct dhcp_config *config;
  
  for (config = configs; config; config = config->next)
    if (config->flags & CONFIG_ADDR6)
      {
	struct addrlist *addr_list;
	
	for (addr_list = config->addr6; addr_list; addr_list = addr_list->next)
	  if ((!net || is_same_net6(&addr_list->addr.addr6, net, prefix) || ((addr_list->flags & ADDRLIST_WILDCARD) && prefix == 64)) &&
	      is_same_net6(&addr_list->addr.addr6, addr, (addr_list->flags & ADDRLIST_PREFIX) ? addr_list->prefixlen : 128))
	    return config;
      }
  
  return NULL;
}

/**
 * @brief Allocate free IPv6 address from DHCPv6 context range
 *
 * @detailed Finds and allocates an available IPv6 address from configured DHCPv6 address ranges.
 * Uses SDBM hashing algorithm with client ID (CLID) and IAID to generate pseudo-random but
 * deterministic start address, then searches linearly for free address. For temporary addresses
 * (IA_TA), generates random start using rand64(). For consecutive addressing mode (OPT_CONSEC_ADDR),
 * allocates sequentially after largest existing lease to avoid reassigning rejected addresses.
 * Excludes addresses already leased, configured as static, or in use by server interfaces.
 * Supports tag-based network matching for conditional address pools. Iterates through context
 * chain trying netid-matched contexts first, then plain ranges. Assumes /64 or larger prefixes.
 *
 * @param context Head of DHCPv6 context chain to search for available addresses
 * @param clid Client DUID (client identifier) for hash-based address selection
 * @param clid_len Length of client ID in bytes
 * @param temp_addr Non-zero for temporary addresses (IA_TA), zero for normal (IA_NA)
 * @param iaid Identity Association Identifier from client request for hash input
 * @param serial Number of addresses client has rejected (adds to hash for different selection)
 * @param netids Network ID tags from client request for matching conditional contexts
 * @param plain_range Non-zero to allow untagged ranges, zero for tagged-only
 * @param ans Output pointer to store allocated IPv6 address
 *
 * @return Pointer to dhcp_context from which address was allocated, or NULL if no free address
 *
 * @note SDBM hash formula: j = clid[i] + (j << 6) + (j << 16) - j
 * @note For temp_addr, new random address generated each time (no client binding)
 * @note Consecutive mode uses lease_find_max_addr6() + serial + addr_epoch
 * @note Linear search wraps from end back to start of range
 * @note Skips contexts with CONTEXT_DEPRECATE, CONTEXT_STATIC, CONTEXT_RA_STATELESS, CONTEXT_USED flags
 *
 * @warning Assumes prefix >= 64 for address manipulation with addr6part()
 * @warning Returns NULL if all addresses in range exhausted
 * @warning May return same address to same client if lease expired and hash matches
 *
 * @see lease6_find_by_addr() in lease.c for checking address availability
 * @see config_find_by_address6() for checking static reservations
 * @see addr6part() and setaddr6part() for 64-bit address manipulation
 * @see match_netid() for network ID tag matching
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char clid[20] = {...};
 * unsigned int iaid = 0x12345678;
 * struct in6_addr allocated_addr;
 * struct dhcp_context *ctx = address6_allocate(parm.current, clid, 20, 0,
 *                                               iaid, 0, netids, 1, &allocated_addr);
 * if (ctx)
 *   printf("Allocated: %s from context\n", inet_ntop(AF_INET6, &allocated_addr, buf, sizeof(buf)));
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 17.1.2 - Server address allocation policy
 * RFC 3315 Section 22.4 - IA_NA (non-temporary address) allocation
 * RFC 3315 Section 22.5 - IA_TA (temporary address) allocation
 *
 * SIDE EFFECTS:
 * - Stores allocated address in *ans output parameter
 * - Returns matching context pointer (read-only, no state modification)
 * - May decrement context->addr_epoch if using consecutive addressing
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies context->addr_epoch in consecutive mode. Single-threaded use only.
 */
struct dhcp_context *address6_allocate(struct dhcp_context *context,  unsigned char *clid, int clid_len, int temp_addr,
				       unsigned int iaid, int serial, struct dhcp_netid *netids, int plain_range, struct in6_addr *ans)
{
  /* Find a free address: exclude anything in use and anything allocated to
     a particular hwaddr/clientid/hostname in our configuration.
     Try to return from contexts which match netids first. 
     
     Note that we assume the address prefix lengths are 64 or greater, so we can
     get by with 64 bit arithmetic.
*/

  u64 start, addr;
  struct dhcp_context *c, *d;
  int i, pass;
  u64 j; 

  /* hash hwaddr: use the SDBM hashing algorithm.  This works
     for MAC addresses, let's see how it manages with client-ids! 
     For temporary addresses, we generate a new random one each time. */
  if (temp_addr)
    j = rand64();
  else
    for (j = iaid, i = 0; i < clid_len; i++)
      j = clid[i] + (j << 6) + (j << 16) - j;
  
  for (pass = 0; pass <= plain_range ? 1 : 0; pass++)
    for (c = context; c; c = c->current)
      if (c->flags & (CONTEXT_DEPRECATE | CONTEXT_STATIC | CONTEXT_RA_STATELESS | CONTEXT_USED))
	continue;
      else if (!match_netid(c->filter, netids, pass))
	continue;
      else
	{ 
	  if (!temp_addr && option_bool(OPT_CONSEC_ADDR))
	    {
	      /* seed is largest extant lease addr in this context,
		 skip addresses equal to the number of addresses rejected
		 by clients. This should avoid the same client being offered the same
		 address after it has rjected it. */
	      start = lease_find_max_addr6(c) + 1 + serial + c->addr_epoch;
	      if (c->addr_epoch)
		c->addr_epoch--;
	    }
	  else
	    {
	      u64 range = 1 + addr6part(&c->end6) - addr6part(&c->start6);
	      u64 offset = j + c->addr_epoch;

	      /* don't divide by zero if range is whole 2^64 */
	      if (range != 0)
		offset = offset % range;

	      start = addr6part(&c->start6) + offset;
	    }

	  /* iterate until we find a free address. */
	  addr = start;
	  
	  do {
	    /* eliminate addresses in use by the server. */
	    for (d = context; d; d = d->current)
	      if (addr == addr6part(&d->local6))
		break;
	    
	    *ans = c->start6;
	    setaddr6part (ans, addr);

	    if (!d &&
		!lease6_find_by_addr(&c->start6, c->prefix, addr) && 
		!config_find_by_address6(daemon->dhcp_conf, &c->start6, c->prefix, ans))
	      return c;
	    
	    addr++;
	    
	    if (addr  == addr6part(&c->end6) + 1)
	      addr = addr6part(&c->start6);
	    
	  } while (addr != start);
	}
	   
  return NULL;
}

/**
 * @brief Check if IPv6 address can be dynamically allocated from context
 *
 * @detailed Validates whether a specific IPv6 address falls within a DHCPv6 context's
 * dynamic allocation range and can be assigned to clients. Checks that address is within
 * context start/end bounds, matches network prefix, is not marked static or RA-stateless,
 * and matches client network ID tags. Used when client requests specific address (SOLICIT
 * with IAADDR or REQUEST) to determine if requested address is allocatable. Iterates through
 * context chain checking each for address containment and network ID matching.
 *
 * @param context Head of DHCPv6 context chain to check
 * @param taddr Target IPv6 address to validate for dynamic allocation
 * @param netids Network ID tags from client request for conditional context matching
 * @param plain_range Non-zero to allow untagged contexts, zero for tagged-only
 *
 * @return Pointer to matching dhcp_context if address is dynamically allocatable, NULL otherwise
 *
 * @note Address must be within context->start6 to context->end6 range (inclusive)
 * @note Rejects addresses from contexts with CONTEXT_STATIC or CONTEXT_RA_STATELESS flags
 * @note Network prefix must match for both start and end (is_same_net6 checks)
 * @note Uses 64-bit addr6part() comparison for address range checking
 *
 * @warning Returns NULL if address outside any context range
 * @warning Returns NULL if no contexts match network ID tags
 * @warning Does not check if address already leased - only checks range membership
 *
 * @see address6_allocate() for actual address allocation logic
 * @see address6_valid() for checking if address is within any configured context
 * @see match_netid() for network ID tag matching
 * @see is_same_net6() for IPv6 network prefix comparison
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr requested_addr = {...};
 * struct dhcp_netid *client_tags = {...};
 * struct dhcp_context *ctx = address6_available(parm.current, &requested_addr,
 *                                                client_tags, 1);
 * if (ctx)
 *   printf("Address can be allocated from context\n");
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 18.2.1 - Server processing of REQUEST with IA containing IAADDR
 * RFC 3315 Section 17.1.3 - Address validation for client requests
 *
 * SIDE EFFECTS:
 * None - read-only validation operation
 *
 * THREAD SAFETY:
 * Thread-safe for read-only operations. No state modification.
 */
struct dhcp_context *address6_available(struct dhcp_context *context, 
					struct in6_addr *taddr,
					struct dhcp_netid *netids,
					int plain_range)
{
  u64 start, end, addr = addr6part(taddr);
  struct dhcp_context *tmp;
 
  for (tmp = context; tmp; tmp = tmp->current)
    {
      start = addr6part(&tmp->start6);
      end = addr6part(&tmp->end6);

      if (!(tmp->flags & (CONTEXT_STATIC | CONTEXT_RA_STATELESS)) &&
          is_same_net6(&tmp->start6, taddr, tmp->prefix) &&
	  is_same_net6(&tmp->end6, taddr, tmp->prefix) &&
	  addr >= start &&
          addr <= end &&
          match_netid(tmp->filter, netids, plain_range))
        return tmp;
    }

  return NULL;
}

/**
 * @brief Check if IPv6 address is within any configured DHCPv6 context
 *
 * @detailed Validates whether an IPv6 address falls within the network prefix of any
 * configured DHCPv6 context, regardless of allocation range boundaries. More permissive
 * than address6_available() - only checks network prefix matching (context->prefix) without
 * validating against start6/end6 range limits. Used to determine if server should process
 * requests for addresses outside dynamic allocation ranges but within served networks.
 * Supports static assignments, on-link verification, and CONFIRM message processing where
 * clients verify addresses from previous leases.
 *
 * @param context Head of DHCPv6 context chain to check
 * @param taddr Target IPv6 address to validate against context networks
 * @param netids Network ID tags from client request for conditional context matching
 * @param plain_range Non-zero to allow untagged contexts, zero for tagged-only
 *
 * @return Pointer to matching dhcp_context if address matches a context network, NULL otherwise
 *
 * @note Only checks network prefix match (context->prefix bits), not allocation range
 * @note Does not filter by CONTEXT_STATIC or CONTEXT_RA_STATELESS flags
 * @note Used for CONFIRM messages to verify addresses are on-link
 * @note More permissive than address6_available() for static address validation
 *
 * @warning Returns NULL if address not in any configured context network
 * @warning Returns NULL if no contexts match network ID tags
 * @warning Does not validate if address is actually assigned or available
 *
 * @see address6_available() for stricter dynamic allocation range checking
 * @see address6_allocate() for actual address assignment
 * @see is_same_net6() for network prefix comparison
 * @see match_netid() for network ID tag matching
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client_addr = {...};
 * struct dhcp_netid *tags = {...};
 * struct dhcp_context *ctx = address6_valid(parm.current, &client_addr, tags, 1);
 * if (ctx)
 *   printf("Address on-link for context with prefix /%d\n", ctx->prefix);
 * else
 *   send_reply(DHCP6NOTONLINK); // Address not on this link
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 18.2.2 - CONFIRM message processing (on-link verification)
 * RFC 3315 Section 22.5 - NotOnLink status code when address not valid
 *
 * SIDE EFFECTS:
 * None - read-only validation operation
 *
 * THREAD SAFETY:
 * Thread-safe for read-only operations. No state modification.
 */
struct dhcp_context *address6_valid(struct dhcp_context *context, 
				    struct in6_addr *taddr,
				    struct dhcp_netid *netids,
				    int plain_range)
{
  struct dhcp_context *tmp;
 
  for (tmp = context; tmp; tmp = tmp->current)
    if (is_same_net6(&tmp->start6, taddr, tmp->prefix) &&
	match_netid(tmp->filter, netids, plain_range))
      return tmp;

  return NULL;
}

/**
 * @brief Generate DHCPv6 server DUID (DHCP Unique Identifier)
 *
 * @detailed Creates the server's unique identifier for DHCPv6 operations. Three DUID types
 * supported: DUID-EN (Enterprise Number) if --dhcp-duid configured with custom value,
 * DUID-LLT (Link-layer address plus Time) if RTC available and persistent leases enabled,
 * or DUID-LL (Link-layer address only) for systems with HAVE_BROKEN_RTC or read-only leases.
 * DUID-LLT uses time since 2000-01-01 (epoch rebased from 1970) per RFC 3315. DUID-LL/LLT
 * use MAC address from first non-loopback, non-point-to-point interface with hardware type < 256.
 * Generated DUID stored in daemon->duid and daemon->duid_len for inclusion in all server messages.
 *
 * @param now Current time for DUID-LLT timestamp (unused if HAVE_BROKEN_RTC or configured DUID)
 *
 * @return void - dies with error if DUID generation fails
 *
 * @note DUID-EN format: type(2) + enterprise(4) + identifier(variable)
 * @note DUID-LLT format: type(1) + hwtype(2) + time(4) + MAC(variable)
 * @note DUID-LL format: type(3) + hwtype(2) + MAC(variable)
 * @note Epoch rebased to 946684800 (2000-01-01) for DUID-LLT per RFC 3315 Section 9.2
 * @note DUID persists across daemon restarts via lease file (not regenerated each time)
 *
 * @warning Dies with EC_MISC if no suitable interface found for DUID-LL/LLT generation
 * @warning Requires at least one hardware interface with address type < 256
 * @warning On --dhcp-duid, uses configured value directly without validation
 *
 * @see make_duid1() callback for interface enumeration
 * @see iface_enumerate() in network.c for iterating interfaces
 * @see daemon->duid_config set by --dhcp-duid option
 *
 * EXAMPLE USAGE:
 * @code
 * // Called once during daemon initialization
 * make_duid(time(NULL));
 * // daemon->duid and daemon->duid_len now set
 * // Include in DHCPv6 responses as OPTION6_SERVER_ID
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 9 - DUID (DHCP Unique Identifier) formats
 * RFC 3315 Section 9.1 - DUID-LLT structure and timestamp base
 * RFC 3315 Section 9.2 - DUID-EN for enterprise-assigned identifiers
 * RFC 3315 Section 9.3 - DUID-LL for systems without stable clock
 *
 * SIDE EFFECTS:
 * - Allocates memory for daemon->duid via safe_malloc()
 * - Sets daemon->duid_len to length of generated DUID
 * - Dies with EC_MISC error if generation fails
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon structure. Called from main thread only during init.
 */
void make_duid(time_t now)
{
  (void)now;

  if (daemon->duid_config)
    {
      unsigned char *p;
      
      daemon->duid = p = safe_malloc(daemon->duid_config_len + 6);
      daemon->duid_len = daemon->duid_config_len + 6;
      PUTSHORT(2, p); /* DUID_EN */
      PUTLONG(daemon->duid_enterprise, p);
      memcpy(p, daemon->duid_config, daemon->duid_config_len);
    }
  else
    {
      time_t newnow = 0;
      
      /* If we have no persistent lease database, or a non-stable RTC, use DUID_LL (newnow == 0) */
#ifndef HAVE_BROKEN_RTC
      /* rebase epoch to 1/1/2000 */
      if (!option_bool(OPT_LEASE_RO) || daemon->lease_change_command)
	newnow = now - 946684800;
#endif      
      
      iface_enumerate(AF_LOCAL, &newnow, make_duid1);
      
      if(!daemon->duid)
	die("Cannot create DHCPv6 server DUID: %s", NULL, EC_MISC);
    }
}

/**
 * @brief Callback function to create server DUID from first suitable interface MAC address
 *
 * @detailed
 * This callback is invoked by iface_enumerate() to construct the DHCPv6 server DUID
 * (DHCP Unique Identifier) as specified in RFC 3315. The function uses the MAC address
 * of the first suitable network interface found (not loopback, not point-to-point, and
 * with hardware address type < 256). Creates either DUID-LLT (Link-Layer Time) if a
 * stable timestamp is available, or DUID-LL (Link-Layer only) if compiled with
 * HAVE_BROKEN_RTC. Address types >= 256 (tunnels, virtual interfaces) are skipped as
 * they don't have usable MAC addresses.
 *
 * @param index Interface index (unused in this implementation)
 * @param type Hardware address type (e.g., ARPHRD_ETHER=1 for Ethernet)
 * @param mac Pointer to MAC address bytes
 * @param maclen Length of MAC address in bytes (typically 6 for Ethernet)
 * @param parm Pointer to time_t value: 0 for DUID-LL, non-zero timestamp for DUID-LLT
 *
 * @return 0 if DUID created successfully (stops enumeration)
 * @return 1 to continue enumeration (interface rejected due to type >= 256)
 *
 * @note Only processes interface types < 256 (physical network adapters)
 * @note Allocates daemon->duid and sets daemon->duid_len on first suitable interface
 * @note DUID format: [Type=1 or 3][HW Type][Time (DUID-LLT only)][MAC Address]
 *
 * @warning Modifies global daemon->duid and daemon->duid_len
 *
 * @see make_duid() which calls this via iface_enumerate()
 * @see RFC 3315 Section 9.2 (DUID-LLT) and Section 9.4 (DUID-LL)
 *
 * EXAMPLE USAGE:
 * @code
 * time_t timestamp = time(NULL) - 946684800; // Rebase to 2000-01-01
 * iface_enumerate(AF_LOCAL, &timestamp, make_duid1);
 * // daemon->duid now contains DUID-LLT with first interface MAC
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 9.2: DUID-LLT format (type=1, hw_type, time, link-layer-address)
 * - RFC 3315 Section 9.4: DUID-LL format (type=3, hw_type, link-layer-address)
 *
 * SIDE EFFECTS:
 * - Allocates memory for daemon->duid (4+maclen for DUID-LL, 8+maclen for DUID-LLT)
 * - Sets daemon->duid_len to length of allocated DUID
 * - Returns 0 to stop interface enumeration after first suitable interface
 *
 * THREAD SAFETY:
 * Not thread-safe. Called from single-threaded event loop context only.
 */
static int make_duid1(int index, unsigned int type, char *mac, size_t maclen, void *parm)
{
  /* create DUID as specified in RFC3315. We use the MAC of the
     first interface we find that isn't loopback or P-to-P and
     has address-type < 256. Address types above 256 are things like 
     tunnels which don't have usable MAC addresses. */
  
  unsigned char *p;
  (void)index;
  (void)parm;
  time_t newnow = *((time_t *)parm);
  
  if (type >= 256)
    return 1;

  if (newnow == 0)
    {
      daemon->duid = p = safe_malloc(maclen + 4);
      daemon->duid_len = maclen + 4;
      PUTSHORT(3, p); /* DUID_LL */
      PUTSHORT(type, p); /* address type */
    }
  else
    {
      daemon->duid = p = safe_malloc(maclen + 8);
      daemon->duid_len = maclen + 8;
      PUTSHORT(1, p); /* DUID_LLT */
      PUTSHORT(type, p); /* address type */
      PUTLONG(*((time_t *)parm), p); /* time */
    }
  
  memcpy(p, mac, maclen);

  return 0;
}

/**
 * @brief Parameter structure for context construction callback
 *
 * Used by dhcp_construct_contexts() to pass state through iface_enumerate()
 * callback chain and track whether any changes occurred requiring lease file
 * or Router Advertisement updates.
 *
 * @var cparam::now Current time for timestamp operations
 * @var cparam::newone Flag indicating new context created or context state changed
 * @var cparam::newname Flag indicating new RA_NAME context requiring SLAAC lease update
 */
struct cparam {
  time_t now;
  int newone, newname;
};

/**
 * @brief Callback to dynamically construct DHCPv6 contexts from interface addresses
 *
 * @detailed
 * This callback is invoked by iface_enumerate() during periodic context reconstruction
 * to dynamically create DHCPv6 contexts from template configurations based on actual
 * interface IPv6 addresses. Implements template expansion where wildcard interface names
 * (e.g., "eth*") match physical interfaces and context address ranges are instantiated
 * with the interface's actual prefix. Also fills in if_index and local6 for non-template
 * (absolute) contexts. When a previously-seen context reappears after being absent, triggers
 * fast Router Advertisement transmission. Creates new CONTEXT_CONSTRUCTED entries that are
 * automatically managed (garbage collected when address disappears). This enables dynamic
 * DHCPv6 configuration that adapts to interface address changes without manual reconfiguration.
 *
 * @param local IPv6 address found on the interface
 * @param prefix Prefix length of the address
 * @param scope Address scope (unused - marked void)
 * @param if_index Interface index where address was found
 * @param flags Interface flags (IFACE_PERMANENT, IFACE_DEPRECATED, etc.)
 * @param preferred Preferred lifetime (unused - marked void)
 * @param valid Valid lifetime (unused - marked void)
 * @param vparam Void pointer to struct cparam for result tracking
 *
 * @return Always returns 1 to continue interface enumeration
 *
 * @note Skips loopback, link-local, and multicast addresses
 * @note Requires IFACE_PERMANENT flag - ignores temporary addresses
 * @note Skips IFACE_DEPRECATED addresses
 * @note Checks dhcp_except list to exclude interfaces
 * @note Only processes interfaces passing iface_check()
 * @note Matches template->template_interface against actual interface name (wildcard matching)
 * @note Sets param->newone=1 if any context created/reappeared
 * @note Sets param->newname=1 if RA_NAME context affected (requires SLAAC update)
 *
 * @warning Modifies global daemon->dhcp6 context chain (adds new contexts)
 * @warning Modifies template->if_index and template->local6 for non-template contexts
 * @warning Clears CONTEXT_GC and CONTEXT_OLD flags on reappearing contexts
 * @warning Calls ra_start_unsolicited() which may send Router Advertisements
 *
 * @see dhcp_construct_contexts() which calls iface_enumerate() with this callback
 * @see struct cparam for parameter structure (lines 1235-1238)
 * @see CONTEXT_TEMPLATE flag to identify template vs absolute contexts
 * @see CONTEXT_CONSTRUCTED flag marking dynamically created contexts
 * @see CONTEXT_GC flag for garbage collection of disappeared contexts
 *
 * EXAMPLE USAGE:
 * @code
 * struct cparam param = {.now = time(NULL), .newone = 0, .newname = 0};
 * iface_enumerate(AF_INET6, &param, construct_worker);
 * if (param.newone) lease_update_file(param.now); // contexts changed
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315: Dynamic DHCPv6 context configuration
 * - RFC 4861: Router Advertisement transmission on context changes
 *
 * SIDE EFFECTS:
 * - May allocate and add new CONTEXT_CONSTRUCTED contexts to daemon->dhcp6
 * - Updates existing template contexts with if_index and local6
 * - Clears GC/OLD flags on reappearing contexts
 * - Triggers fast RA transmission via ra_start_unsolicited()
 * - Sets newone/newname flags in param for caller action
 * - Logs context changes via log_context()
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon structure and context chains.
 * Must be called from main thread only.
 */
static int construct_worker(struct in6_addr *local, int prefix, 
			    int scope, int if_index, int flags, 
			    int preferred, int valid, void *vparam)
{
  char ifrn_name[IFNAMSIZ];
  struct in6_addr start6, end6;
  struct dhcp_context *template, *context;
  struct iname *tmp;
  
  (void)scope;
  (void)flags;
  (void)valid;
  (void)preferred;

  struct cparam *param = vparam;

  if (IN6_IS_ADDR_LOOPBACK(local) ||
      IN6_IS_ADDR_LINKLOCAL(local) ||
      IN6_IS_ADDR_MULTICAST(local))
    return 1;

  if (!(flags & IFACE_PERMANENT))
    return 1;

  if (flags & IFACE_DEPRECATED)
    return 1;

  /* Ignore interfaces where we're not doing RA/DHCP6 */
  if (!indextoname(daemon->icmp6fd, if_index, ifrn_name) ||
      !iface_check(AF_LOCAL, NULL, ifrn_name, NULL))
    return 1;
  
  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
    if (tmp->name && wildcard_match(tmp->name, ifrn_name))
      return 1;

  for (template = daemon->dhcp6; template; template = template->next)
    if (!(template->flags & (CONTEXT_TEMPLATE | CONTEXT_CONSTRUCTED)))
      {
	/* non-template entries, just fill in interface and local addresses */
	if (prefix <= template->prefix &&
	    is_same_net6(local, &template->start6, template->prefix) &&
	    is_same_net6(local, &template->end6, template->prefix))
	  {
	    /* First time found, do fast RA. */
	    if (template->if_index == 0)
	      {
		ra_start_unsolicited(param->now, template);
		param->newone = 1;
	      }
	    
	    template->if_index = if_index;
	    template->local6 = *local;
	  }
	
      }
    else if (wildcard_match(template->template_interface, ifrn_name) &&
	     template->prefix >= prefix)
      {
	start6 = *local;
	setaddr6part(&start6, addr6part(&template->start6));
	end6 = *local;
	setaddr6part(&end6, addr6part(&template->end6));
	
	for (context = daemon->dhcp6; context; context = context->next)
	  if (!(context->flags & CONTEXT_TEMPLATE) &&
	      IN6_ARE_ADDR_EQUAL(&start6, &context->start6) &&
	      IN6_ARE_ADDR_EQUAL(&end6, &context->end6))
	    {
	      /* If there's an absolute address context covering this address
		 then don't construct one as well. */
	      if (!(context->flags & CONTEXT_CONSTRUCTED))
		break;
	      
	      if (context->if_index == if_index)
		{
		  int cflags = context->flags;
		  context->flags &= ~(CONTEXT_GC | CONTEXT_OLD);
		  if (cflags & CONTEXT_OLD)
		    {
		      /* address went, now it's back, and on the same interface */
		      log_context(AF_INET6, context); 
		      /* fast RAs for a while */
		      ra_start_unsolicited(param->now, context);
		      param->newone = 1; 
		      /* Add address to name again */
		      if (context->flags & CONTEXT_RA_NAME)
			param->newname = 1;
		    
		    }
		  break;
		}
	    }
	
	if (!context && (context = whine_malloc(sizeof (struct dhcp_context))))
	  {
	    *context = *template;
	    context->start6 = start6;
	    context->end6 = end6;
	    context->flags &= ~CONTEXT_TEMPLATE;
	    context->flags |= CONTEXT_CONSTRUCTED;
	    context->if_index = if_index;
	    context->local6 = *local;
	    context->saved_valid = 0;
	    
	    context->next = daemon->dhcp6;
	    daemon->dhcp6 = context;

	    ra_start_unsolicited(param->now, context);
	    /* we created a new one, need to call
	       lease_update_file to get periodic functions called */
	    param->newone = 1; 

	    /* Will need to add new putative SLAAC addresses to existing leases */
	    if (context->flags & CONTEXT_RA_NAME)
	      param->newname = 1;
	    
	    log_context(AF_INET6, context);
	  } 
      }
  
  return 1;
}

/**
 * @brief Periodically reconstruct DHCPv6 contexts from current interface addresses
 *
 * @detailed
 * This function is called periodically from the main event loop to dynamically maintain DHCPv6
 * contexts based on current IPv6 interface addresses. It implements garbage collection of
 * contexts whose interfaces/addresses have disappeared, and instantiates new contexts from
 * templates when matching interfaces appear. Marks all CONTEXT_CONSTRUCTED contexts with
 * CONTEXT_GC flag, then calls iface_enumerate() with construct_worker() callback which clears
 * the GC flag for still-valid contexts. Remaining GC-flagged contexts are either marked OLD
 * (triggering Router Advertisement with zero lifetime) or freed immediately if RA is disabled.
 * When contexts change (new/deleted), triggers lease file update and/or Router Advertisement
 * transmission. Also handles SLAAC address updates when RA_NAME contexts change.
 *
 * @param now Current timestamp for lease and RA operations
 *
 * @note Called periodically from main event loop (typically via periodic_ra() alarm)
 * @note Marks constructed contexts with CONTEXT_GC, then clears for still-present contexts
 * @note Contexts still marked GC after enumeration have disappeared
 * @note Disappeared contexts with RA enabled marked CONTEXT_OLD (advertise withdrawal)
 * @note Disappeared contexts without RA are immediately freed
 * @note OLD contexts retained for 2 hours maximum (RFC 4861 requirement)
 * @note Sets address_lost_time when context becomes OLD
 * @note Limits saved_valid to configured lease_time or 7200 seconds maximum
 *
 * @warning Modifies global daemon->dhcp6 context chain (may free contexts)
 * @warning May trigger Router Advertisement transmission (ra_start_unsolicited)
 * @warning May update lease file (lease_update_file) if contexts changed
 * @warning May update SLAAC leases (lease_update_slaac) if RA_NAME contexts changed
 * @warning May set alarm for periodic RA (send_alarm) if only doing RA, not DHCP
 *
 * @see construct_worker() callback which actually creates/updates contexts
 * @see struct cparam for parameter tracking (newone, newname flags)
 * @see CONTEXT_CONSTRUCTED flag marking dynamically created contexts
 * @see CONTEXT_GC flag for garbage collection marking
 * @see CONTEXT_OLD flag for contexts advertising withdrawal
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop alarm handler
 * dhcp_construct_contexts(time(NULL));
 * // Contexts now reflect current interface configuration
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315: Dynamic DHCPv6 configuration adapts to network changes
 * - RFC 4861 Section 6.2.5: Router Advertisement with zero lifetime for withdrawal
 * - RFC 4861: 2-hour maximum for advertising prefix withdrawal
 *
 * SIDE EFFECTS:
 * - Marks all CONTEXT_CONSTRUCTED contexts with CONTEXT_GC flag
 * - Calls iface_enumerate() which may create new contexts
 * - May free contexts no longer matching any interface
 * - May mark contexts CONTEXT_OLD and set address_lost_time
 * - May call ra_start_unsolicited() for new/old contexts
 * - May call lease_update_file() if contexts changed
 * - May call lease_update_slaac() if RA_NAME contexts changed
 * - May call send_alarm(periodic_ra()) if only doing RA
 * - Logs context changes via log_context()
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon structure and context chains.
 * Must be called from main thread only in single-process event loop.
 */
void dhcp_construct_contexts(time_t now)
{ 
  struct dhcp_context *context, *tmp, **up;
  struct cparam param;
  param.newone = 0;
  param.newname = 0;
  param.now = now;

  for (context = daemon->dhcp6; context; context = context->next)
    if (context->flags & CONTEXT_CONSTRUCTED)
      context->flags |= CONTEXT_GC;
   
  iface_enumerate(AF_INET6, &param, construct_worker);

  for (up = &daemon->dhcp6, context = daemon->dhcp6; context; context = tmp)
    {
      
      tmp = context->next; 
     
      if (context->flags & CONTEXT_GC && !(context->flags & CONTEXT_OLD))
	{
	  if ((context->flags & CONTEXT_RA) || option_bool(OPT_RA))
	    {
	      /* previously constructed context has gone. advertise it's demise */
	      context->flags |= CONTEXT_OLD;
	      context->address_lost_time = now;
	      /* Apply same ceiling of configured lease time as in radv.c */
	      if (context->saved_valid > context->lease_time)
		context->saved_valid = context->lease_time;
	      /* maximum time is 2 hours, from RFC */
	      if (context->saved_valid > 7200) /* 2 hours */
		context->saved_valid = 7200;
	      ra_start_unsolicited(now, context);
	      param.newone = 1; /* include deletion */ 
	      
	      if (context->flags & CONTEXT_RA_NAME)
		param.newname = 1; 
			      
	      log_context(AF_INET6, context);
	      
	      up = &context->next;
	    }
	  else
	    {
	      /* we were never doing RA for this, so free now */
	      *up = context->next;
	      free(context);
	    }
	}
      else
	 up = &context->next;
    }
  
  if (param.newone)
    {
      if (daemon->dhcp || daemon->doing_dhcp6)
	{
	  if (param.newname)
	    lease_update_slaac(now);
	  lease_update_file(now);
	}
      else 
	/* Not doing DHCP, so no lease system, manage alarms for ra only */
	send_alarm(periodic_ra(now), now);
    }
}

#endif /* HAVE_DHCP6 */
