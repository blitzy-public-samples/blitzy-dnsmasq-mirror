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
 * @file dhcp.c
 * @brief DHCPv4 server core logic and lease management
 *
 * DETAILED PURPOSE:
 * This file implements the core DHCPv4 server functionality for dnsmasq, coordinating
 * with rfc2131.c for RFC 2131 protocol message handling. It manages the infrastructure
 * required for DHCP operation including socket creation and binding, address pool
 * (dhcp_context) configuration and validation, integration with the lease database
 * (lease.c), and packet routing between network interfaces and the protocol handler.
 *
 * The module serves as the integration layer between the network layer (receiving packets
 * on UDP port 67), the protocol implementation (rfc2131.c for message construction/parsing),
 * and the lease management subsystem. It handles platform-specific packet transmission
 * (ARP injection on Linux, BPF on BSD), DHCP relay agent support for multi-subnet
 * deployments, and integration with DNS caching for dynamic hostname resolution.
 *
 * Additional responsibilities include ping-before-offer address conflict detection,
 * PXE/TFTP boot integration via separate PXE socket (port 4011), static host reservations
 * from /etc/ethers, and support for bridge interfaces where DHCP contexts apply across
 * multiple physical interfaces.
 *
 * KEY RESPONSIBILITIES:
 * - dhcp_init(): Initialize DHCPv4 sockets (server port 67 and optional PXE port 4011)
 * - dhcp_packet(): Main packet handler coordinating receive, process, and transmit
 * - complete_context(): Validate and complete DHCP context configuration with netmask/broadcast
 * - address_allocate(): Allocate IP addresses from configured pools with conflict detection
 * - do_icmp_ping(): Perform ping-before-offer checks with caching to detect address conflicts
 * - dhcp_read_ethers(): Load static host-to-MAC mappings from /etc/ethers file
 * - relay_upstream4(): Forward DHCP requests to upstream relay servers
 * - host_from_dns(): Retrieve client hostnames from DNS cache for lease records
 *
 * DEPENDENCIES:
 * - Internal includes: dnsmasq.h (core daemon structures, configuration, global state)
 * - Internal includes: dhcp-protocol.h (DHCPv4 packet structures, constants, message types)
 * - Calls to: rfc2131.c dhcp_reply() for protocol message handling
 * - Calls to: lease.c lease_prune(), lease_update_file(), lease_update_dns(), lease_find_by_addr()
 * - Calls to: cache.c cache_find_by_addr(), cache_get_name() for DNS-based hostname lookup
 * - Calls to: network.c send_from(), indextoname(), iface_enumerate(), iface_check()
 * - Called by: dnsmasq.c main event loop when DHCP packets arrive on monitored file descriptors
 *
 * DATA STRUCTURES:
 * - struct iface_param (lines 21-24): Parameter block for interface enumeration callbacks
 * - struct match_param (lines 26-29): Parameter block for secondary address matching
 * - struct dhcp_packet (dhcp-protocol.h): DHCPv4 wire format packet structure
 * - struct dhcp_context (dnsmasq.h): Address pool/range configuration with netmask and router
 * - struct dhcp_config (dnsmasq.h): Static host reservation configuration
 * - struct dhcp_relay (dnsmasq.h): DHCP relay agent configuration
 * - struct ping_result (dnsmasq.h): Cached ping results for conflict detection
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP (mandatory): Enables entire DHCPv4 server functionality
 * - HAVE_LINUX_NETWORK: Enables Linux-specific features (IP_PKTINFO, ARP injection via SIOCSARP)
 * - HAVE_BSD_NETWORK: Enables BSD-specific features (IP_RECVIF, BPF raw packet transmission)
 * - HAVE_SOLARIS_NETWORK: Enables Solaris-specific features (IP_BOUND_IF, SIOCGLIFCONF)
 * - HAVE_DUMPFILE: Enables packet capture logging to libpcap format for debugging
 * - SO_REUSEPORT: Enables multiple dnsmasq instances binding to same port (Linux 3.9+)
 * - HAVE_SOCKADDR_SA_LEN: Enables BSD-style sockaddr length field
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture using poll()-based event loop. All DHCP packet
 * processing occurs in main event loop thread triggered by socket readability. No thread
 * safety concerns as all access is serialized through event dispatch. Callbacks to
 * iface_enumerate() are synchronous. Signal handlers use self-pipe pattern for safe
 * event queuing. ICMP ping operations are non-blocking using icmp_ping() raw sockets.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

struct iface_param {
  struct dhcp_context *current;
  int ind;
};

struct match_param {
  int ind, matched;
  struct in_addr netmask, broadcast, addr;
};

static int complete_context(struct in_addr local, int if_index, char *label,
			    struct in_addr netmask, struct in_addr broadcast, void *vparam);
static int check_listen_addrs(struct in_addr local, int if_index, char *label,
			      struct in_addr netmask, struct in_addr broadcast, void *vparam);
static int relay_upstream4(int iface_index, struct dhcp_packet *mess, size_t sz);
static struct dhcp_relay *relay_reply4(struct dhcp_packet *mess, char *arrival_interface);

/**
 * @brief Create and bind DHCPv4 server socket with platform-specific options
 *
 * @detailed
 * Creates a UDP socket for DHCP server or PXE operation, configures socket options for
 * broadcast transmission and packet metadata reception, and binds to the specified port
 * on all interfaces (INADDR_ANY). Platform-specific socket options enable reception of
 * destination address information (IP_PKTINFO on Linux, IP_RECVIF on BSD/Solaris) required
 * for determining which interface received each packet. Additional options disable path MTU
 * discovery, set IP TOS for prioritization, and configure SO_REUSEADDR/SO_REUSEPORT for
 * bind-interfaces mode allowing multiple dnsmasq instances.
 *
 * @param port Port number to bind (typically daemon->dhcp_server_port=67 or PXE_PORT=4011)
 *
 * @return Socket file descriptor on success
 * @retval -1 Never returned (die() called on any error)
 *
 * @note Dies with EC_BADNET error code if socket creation, option setting, or binding fails
 * @note SO_REUSEPORT support detection handles kernels that define constant but lack implementation
 *
 * @warning Function calls die() and does not return on any error condition
 *
 * @see dhcp_init() Creates DHCP server and PXE sockets using this function
 * @see recv_dhcp_packet() in network.c Receives packets from socket created here
 *
 * EXAMPLE USAGE:
 * @code
 * int dhcp_fd = make_fd(DHCP_SERVER_PORT);  // Bind to port 67
 * int pxe_fd = make_fd(PXE_PORT);           // Bind to port 4011 for PXE
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.1 server socket requirements (UDP port 67 binding)
 *
 * SIDE EFFECTS:
 * - Creates new socket file descriptor consuming system resources
 * - Binds to specified port on all network interfaces
 * - Calls die() terminating process on any failure
 *
 * THREAD SAFETY:
 * Not reentrant due to die() calls and global error handling. Called only during daemon
 * initialization in single-threaded context before event loop starts.
 */
static int make_fd(int port)
{
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  struct sockaddr_in saddr;
  int oneopt = 1;
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
  int mtu = IP_PMTUDISC_DONT;
#endif
#if defined(IP_TOS) && defined(IPTOS_CLASS_CS6)
  int tos = IPTOS_CLASS_CS6;
#endif

  if (fd == -1)
    die (_("cannot create DHCP socket: %s"), NULL, EC_BADNET);
  
  if (!fix_fd(fd) ||
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
      setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu)) == -1 ||
#endif
#if defined(IP_TOS) && defined(IPTOS_CLASS_CS6)
      setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1 ||
#endif
#if defined(HAVE_LINUX_NETWORK)
      setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &oneopt, sizeof(oneopt)) == -1 ||
#else
      setsockopt(fd, IPPROTO_IP, IP_RECVIF, &oneopt, sizeof(oneopt)) == -1 ||
#endif
      setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &oneopt, sizeof(oneopt)) == -1)  
    die(_("failed to set options on DHCP socket: %s"), NULL, EC_BADNET);
  
  /* When bind-interfaces is set, there might be more than one dnsmasq
     instance binding port 67. That's OK if they serve different networks.
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
	die(_("failed to set SO_REUSE{ADDR|PORT} on DHCP socket: %s"), NULL, EC_BADNET);
    }
  
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(port);
  saddr.sin_addr.s_addr = INADDR_ANY;
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin_len = sizeof(struct sockaddr_in);
#endif

  if (bind(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)))
    die(_("failed to bind DHCP server socket: %s"), NULL, EC_BADNET);

  return fd;
}

/**
 * @brief Initialize DHCPv4 server sockets and platform-specific resources
 *
 * @detailed
 * Initializes all sockets and resources required for DHCPv4 server operation. Creates
 * main DHCP server socket on configured port (default 67) using make_fd(), and optionally
 * creates PXE boot socket on port 4011 if PXE support is enabled. On BSD platforms,
 * creates raw ICMP socket for ping-before-offer address conflict detection and initializes
 * BPF (Berkeley Packet Filter) for raw packet transmission required for sending to
 * unconfigured clients. Linux performs these operations later with capabilities dropped.
 *
 * @return void
 *
 * @note Must be called after configuration parsing and before dropping root privileges
 * @note On BSD, ICMP socket creation requires root and is disabled if OPT_NO_PING set
 * @note PXE socket (port 4011) only created if daemon->enable_pxe is set
 *
 * @warning Dies (terminates process) if socket creation fails on BSD platforms
 *
 * @see make_fd() Creates and binds UDP sockets for DHCP/PXE traffic
 * @see make_icmp_sock() in network.c Creates raw ICMP socket for ping checks (BSD only)
 * @see init_bpf() in bpf.c Initializes Berkeley Packet Filter for raw transmission (BSD only)
 * @see dhcp_packet() Main packet handler that receives on these sockets
 *
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization after config parsed
 * if (daemon->dhcp)
 *   dhcp_init();  // Sets daemon->dhcpfd and optionally daemon->pxefd
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.1 requiring DHCP server to listen on UDP port 67.
 * PXE port 4011 per PXE specification v2.1 for proxy DHCP operation.
 *
 * SIDE EFFECTS:
 * - Sets daemon->dhcpfd to main DHCP server socket file descriptor
 * - Sets daemon->pxefd to PXE socket fd if enabled, or -1 if disabled
 * - On BSD: Sets daemon->dhcp_icmp_fd to raw ICMP socket or -1 if disabled
 * - On BSD: Initializes BPF file descriptors for raw packet transmission
 * - All created file descriptors registered with event loop for monitoring
 *
 * THREAD SAFETY:
 * Not reentrant. Called once during daemon initialization in single-threaded context
 * before event loop starts. Modifies global daemon structure.
 */
void dhcp_init(void)
{
#if defined(HAVE_BSD_NETWORK)
  int oneopt = 1;
#endif

  daemon->dhcpfd = make_fd(daemon->dhcp_server_port);
  if (daemon->enable_pxe)
    daemon->pxefd = make_fd(PXE_PORT);
  else
    daemon->pxefd = -1;

#if defined(HAVE_BSD_NETWORK)
  /* When we're not using capabilities, we need to do this here before
     we drop root. Also, set buffer size small, to avoid wasting
     kernel buffers */
  
  if (option_bool(OPT_NO_PING))
    daemon->dhcp_icmp_fd = -1;
  else if ((daemon->dhcp_icmp_fd = make_icmp_sock()) == -1 ||
	   setsockopt(daemon->dhcp_icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) == -1 )
    die(_("cannot create ICMP raw socket: %s."), NULL, EC_BADNET);
  
  /* Make BPF raw send socket */
  init_bpf();
#endif  
}

/**
 * @brief Main DHCPv4 packet handler coordinating receive, process, and transmit
 *
 * @detailed
 * Central packet processing function called by main event loop when DHCP traffic arrives.
 * Receives packet with recvmsg() to extract metadata (receiving interface, destination address),
 * validates packet size and interface state, applies bridge-interface aliasing, handles relay
 * agent scenarios, enumerates interfaces to establish DHCP context chain, invokes rfc2131.c
 * dhcp_reply() for protocol processing, and transmits response using platform-specific methods
 * (ARP injection on Linux, BPF on BSD, standard sendmsg() otherwise). Manages lease database
 * updates and DNS cache synchronization after successful transaction. Handles both direct
 * client requests and relay agent forwarding/replies in multi-subnet environments.
 *
 * @param now Current time from main event loop for lease expiry and timestamp operations
 * @param pxe_fd Boolean flag: non-zero if packet received on PXE socket (port 4011), zero for main DHCP socket (port 67)
 *
 * @return void (no return value, errors logged via my_syslog())
 *
 * @note Function handles both standard DHCP (port 67) and PXE proxy DHCP (port 4011) traffic
 * @note Performs DHCP relay forwarding if configured, preventing local server response
 * @note Updates lease database and DNS cache only for successful non-relay transactions
 * @note Extracts packet arrival time from SIOCGSTAMP ioctl on Linux for accurate lease timing
 *
 * @warning Silently returns on errors (invalid packet size, unknown interface, no matching context)
 * @warning ARP injection failure on Linux logged but does not prevent packet transmission
 *
 * @see recv_dhcp_packet() in network.c Receives raw packet data with control metadata
 * @see dhcp_reply() in rfc2131.c Processes DHCP protocol messages and constructs responses
 * @see complete_context() Validates and links DHCP contexts to receiving interface
 * @see relay_upstream4() Forwards client requests to relay servers
 * @see relay_reply4() Detects and handles relay server replies
 * @see lease_prune() in lease.c Removes expired leases before allocation
 * @see lease_update_file() in lease.c Persists lease database to disk
 * @see lease_update_dns() in lease.c Synchronizes leases to DNS cache
 * @see send_via_bpf() in bpf.c Transmits via BPF on BSD platforms
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop when daemon->dhcpfd or daemon->pxefd readable
 * if (poll_check(daemon->dhcpfd, event_readers))
 *   dhcp_packet(now, 0);  // Standard DHCP traffic
 * if (daemon->pxefd != -1 && poll_check(daemon->pxefd, event_readers))
 *   dhcp_packet(now, 1);  // PXE proxy DHCP traffic
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Sections 3.1 (client-server interaction), 4.1 (server behavior),
 * and 4.3.1 through 4.3.6 (message processing). Relay agent support per RFC 1542 Section 4
 * (giaddr processing and hop count). Option 82 relay agent information per RFC 3046.
 *
 * SIDE EFFECTS:
 * - Receives packet from socket, modifying control_u union with interface metadata
 * - Calls lease_prune() removing expired leases from global lease database
 * - Calls dhcp_reply() in rfc2131.c which may allocate/modify lease records
 * - Calls lease_update_file() persisting lease database to disk
 * - Calls lease_update_dns() adding/updating DNS cache entries for DHCP clients
 * - On Linux: Injects ARP entries into kernel ARP cache via SIOCSARP ioctl
 * - On BSD: Sends raw Ethernet frames via BPF bypassing normal socket transmission
 * - Logs errors and relay operations to syslog
 * - Updates daemon->dhcp_packet.iov_base buffer with response data
 *
 * THREAD SAFETY:
 * Not reentrant. Must be called only from main event loop thread. Accesses global daemon
 * structure including packet buffer, configuration, and lease database. No mutex protection
 * as single-threaded event loop serializes all access.
 */
void dhcp_packet(time_t now, int pxe_fd)
{
  int fd = pxe_fd ? daemon->pxefd : daemon->dhcpfd;
  struct dhcp_packet *mess;
  struct dhcp_context *context;
  struct dhcp_relay *relay;
  int is_relay_reply = 0;
  struct iname *tmp;
  struct ifreq ifr;
  struct msghdr msg;
  struct sockaddr_in dest;
  struct cmsghdr *cmptr;
  struct iovec iov;
  ssize_t sz; 
  int iface_index = 0, unicast_dest = 0, is_inform = 0, loopback = 0;
  int rcvd_iface_index;
  struct in_addr iface_addr;
  struct iface_param parm;
  time_t recvtime = now;
#ifdef HAVE_LINUX_NETWORK
  struct arpreq arp_req;
  struct timeval tv;
#endif
  
  union {
    struct cmsghdr align; /* this ensures alignment */
#if defined(HAVE_LINUX_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(HAVE_SOLARIS_NETWORK)
    char control[CMSG_SPACE(sizeof(unsigned int))];
#elif defined(HAVE_BSD_NETWORK) 
    char control[CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
  } control_u;
  struct dhcp_bridge *bridge, *alias;

  msg.msg_controllen = sizeof(control_u);
  msg.msg_control = control_u.control;
  msg.msg_name = &dest;
  msg.msg_namelen = sizeof(dest);
  msg.msg_iov = &daemon->dhcp_packet;
  msg.msg_iovlen = 1;
  
  if ((sz = recv_dhcp_packet(fd, &msg)) == -1 || 
      (sz < (ssize_t)(sizeof(*mess) - sizeof(mess->options)))) 
    return;
  
#ifdef HAVE_DUMPFILE
  dump_packet(DUMP_DHCP, (void *)daemon->dhcp_packet.iov_base, sz, (union mysockaddr *)&dest, NULL,
	      pxe_fd ? PXE_PORT : daemon->dhcp_server_port);
#endif
  
#if defined (HAVE_LINUX_NETWORK)
  if (ioctl(fd, SIOCGSTAMP, &tv) == 0)
    recvtime = tv.tv_sec;
  
  if (msg.msg_controllen >= sizeof(struct cmsghdr))
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO)
	{
	  union {
	    unsigned char *c;
	    struct in_pktinfo *p;
	  } p;
	  p.c = CMSG_DATA(cmptr);
	  iface_index = p.p->ipi_ifindex;
	  if (p.p->ipi_addr.s_addr != INADDR_BROADCAST)
	    unicast_dest = 1;
	}

#elif defined(HAVE_BSD_NETWORK) 
  if (msg.msg_controllen >= sizeof(struct cmsghdr))
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
        {
	  union {
            unsigned char *c;
            struct sockaddr_dl *s;
          } p;
	  p.c = CMSG_DATA(cmptr);
	  iface_index = p.s->sdl_index;
	}
  
#elif defined(HAVE_SOLARIS_NETWORK) 
  if (msg.msg_controllen >= sizeof(struct cmsghdr))
    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
      if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
	{
	  union {
	    unsigned char *c;
	    unsigned int *i;
	  } p;
	  p.c = CMSG_DATA(cmptr);
	  iface_index = *(p.i);
	}
#endif
	
  if (!indextoname(daemon->dhcpfd, iface_index, ifr.ifr_name) ||
      ioctl(daemon->dhcpfd, SIOCGIFFLAGS, &ifr) != 0)
    return;
  
  mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
  loopback = !mess->giaddr.s_addr && (ifr.ifr_flags & IFF_LOOPBACK);
  
#ifdef HAVE_LINUX_NETWORK
  /* ARP fiddling uses original interface even if we pretend to use a different one. */
  safe_strncpy(arp_req.arp_dev, ifr.ifr_name, sizeof(arp_req.arp_dev));
#endif 

  /* If the interface on which the DHCP request was received is an
     alias of some other interface (as specified by the
     --bridge-interface option), change ifr.ifr_name so that we look
     for DHCP contexts associated with the aliased interface instead
     of with the aliasing one. */
  rcvd_iface_index = iface_index;
  for (bridge = daemon->bridges; bridge; bridge = bridge->next)
    {
      for (alias = bridge->alias; alias; alias = alias->next)
	if (wildcard_matchn(alias->iface, ifr.ifr_name, IF_NAMESIZE))
	  {
	    if (!(iface_index = if_nametoindex(bridge->iface)))
	      {
		my_syslog(MS_DHCP | LOG_WARNING,
			  _("unknown interface %s in bridge-interface"),
			  bridge->iface);
		return;
	      }
	    else 
	      {
		safe_strncpy(ifr.ifr_name,  bridge->iface, sizeof(ifr.ifr_name));
		break;
	      }
	  }
      
      if (alias)
	break;
    }

#ifdef MSG_BCAST
  /* OpenBSD tells us when a packet was broadcast */
  if (!(msg.msg_flags & MSG_BCAST))
    unicast_dest = 1;
#endif
  
  if ((relay = relay_reply4((struct dhcp_packet *)daemon->dhcp_packet.iov_base, ifr.ifr_name)))
    {
      /* Reply from server, using us as relay. */
      rcvd_iface_index = relay->iface_index;
      if (!indextoname(daemon->dhcpfd, rcvd_iface_index, ifr.ifr_name))
	return;
      is_relay_reply = 1; 
      iov.iov_len = sz;
#ifdef HAVE_LINUX_NETWORK
      safe_strncpy(arp_req.arp_dev, ifr.ifr_name, sizeof(arp_req.arp_dev));
#endif 
    }
  else
    {
      ifr.ifr_addr.sa_family = AF_INET;
      if (ioctl(daemon->dhcpfd, SIOCGIFADDR, &ifr) != -1 )
	iface_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
      else
	{
	  if (iface_check(AF_INET, NULL, ifr.ifr_name, NULL))
	    my_syslog(MS_DHCP | LOG_WARNING, _("DHCP packet received on %s which has no address"), ifr.ifr_name);
	  return;
	}
      
      for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
	if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	  return;
      
      /* unlinked contexts/relays are marked by context->current == context */
      for (context = daemon->dhcp; context; context = context->next)
	context->current = context;
      
      parm.current = NULL;
      parm.ind = iface_index;
      
      if (!iface_check(AF_INET, (union all_addr *)&iface_addr, ifr.ifr_name, NULL))
	{
	  /* If we failed to match the primary address of the interface, see if we've got a --listen-address
	     for a secondary */
	  struct match_param match;
	  
	  match.matched = 0;
	  match.ind = iface_index;
	  
	  if (!daemon->if_addrs ||
	      !iface_enumerate(AF_INET, &match, check_listen_addrs) ||
	      !match.matched)
	    return;
	  
	  iface_addr = match.addr;
	  /* make sure secondary address gets priority in case
	     there is more than one address on the interface in the same subnet */
	  complete_context(match.addr, iface_index, NULL, match.netmask, match.broadcast, &parm);
	}    
            
      if (relay_upstream4(iface_index, mess, (size_t)sz))
	return;
      
      if (!iface_enumerate(AF_INET, &parm, complete_context))
	return;

      /* Check for a relay again after iface_enumerate/complete_context has had
	 chance to fill in relay->iface_index fields. This handles first time through
	 and any changes in interface config. */
       if (relay_upstream4(iface_index, mess, (size_t)sz))
	return;
       
      /* May have configured relay, but not DHCP server */
      if (!daemon->dhcp)
	return;

      lease_prune(NULL, now); /* lose any expired leases */
      iov.iov_len = dhcp_reply(parm.current, ifr.ifr_name, iface_index, (size_t)sz, 
			       now, unicast_dest, loopback, &is_inform, pxe_fd, iface_addr, recvtime);
      lease_update_file(now);
      lease_update_dns(0);
      
      if (iov.iov_len == 0)
	return;
    }

  msg.msg_name = &dest;
  msg.msg_namelen = sizeof(dest);
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov = &iov;
  iov.iov_base = daemon->dhcp_packet.iov_base;
  
  /* packet buffer may have moved */
  mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
  
#ifdef HAVE_SOCKADDR_SA_LEN
  dest.sin_len = sizeof(struct sockaddr_in);
#endif
  
  if (pxe_fd)
    { 
      if (mess->ciaddr.s_addr != 0)
	dest.sin_addr = mess->ciaddr;
    }
  else if (mess->giaddr.s_addr && !is_relay_reply)
    {
      /* Send to BOOTP relay  */
      dest.sin_port = htons(daemon->dhcp_server_port);
      dest.sin_addr = mess->giaddr; 
    }
  else if (mess->ciaddr.s_addr)
    {
      /* If the client's idea of its own address tallys with
	 the source address in the request packet, we believe the
	 source port too, and send back to that.  If we're replying 
	 to a DHCPINFORM, trust the source address always. */
      if ((!is_inform && dest.sin_addr.s_addr != mess->ciaddr.s_addr) ||
	  dest.sin_port == 0 || dest.sin_addr.s_addr == 0 || is_relay_reply)
	{
	  dest.sin_port = htons(daemon->dhcp_client_port); 
	  dest.sin_addr = mess->ciaddr;
	}
    } 
#if defined(HAVE_LINUX_NETWORK)
  else
    {
      /* fill cmsg for outbound interface (both broadcast & unicast) */
      struct in_pktinfo *pkt;
      msg.msg_control = control_u.control;
      msg.msg_controllen = sizeof(control_u);
      cmptr = CMSG_FIRSTHDR(&msg);
      pkt = (struct in_pktinfo *)CMSG_DATA(cmptr);
      pkt->ipi_ifindex = rcvd_iface_index;
      pkt->ipi_spec_dst.s_addr = 0;
      msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
      cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
      cmptr->cmsg_level = IPPROTO_IP;
      cmptr->cmsg_type = IP_PKTINFO;

      if ((ntohs(mess->flags) & 0x8000) || mess->hlen == 0 ||
         mess->hlen > sizeof(ifr.ifr_addr.sa_data) || mess->htype == 0)
        {
          /* broadcast to 255.255.255.255 (or mac address invalid) */
          dest.sin_addr.s_addr = INADDR_BROADCAST;
          dest.sin_port = htons(daemon->dhcp_client_port);
        }
      else
        {
          /* unicast to unconfigured client. Inject mac address direct into ARP cache.
          struct sockaddr limits size to 14 bytes. */
          dest.sin_addr = mess->yiaddr;
          dest.sin_port = htons(daemon->dhcp_client_port);
          memcpy(&arp_req.arp_pa, &dest, sizeof(struct sockaddr_in));
          arp_req.arp_ha.sa_family = mess->htype;
          memcpy(arp_req.arp_ha.sa_data, mess->chaddr, mess->hlen);
          /* interface name already copied in */
          arp_req.arp_flags = ATF_COM;
          if (ioctl(daemon->dhcpfd, SIOCSARP, &arp_req) == -1)
            my_syslog(MS_DHCP | LOG_ERR, _("ARP-cache injection failed: %s"), strerror(errno));
        }
    }
#elif defined(HAVE_SOLARIS_NETWORK)
  else if ((ntohs(mess->flags) & 0x8000) || mess->hlen != ETHER_ADDR_LEN || mess->htype != ARPHRD_ETHER)
    {
      /* broadcast to 255.255.255.255 (or mac address invalid) */
      dest.sin_addr.s_addr = INADDR_BROADCAST;
      dest.sin_port = htons(daemon->dhcp_client_port);
      /* note that we don't specify the interface here: that's done by the
	 IP_BOUND_IF sockopt lower down. */
    }
  else
    {
      /* unicast to unconfigured client. Inject mac address direct into ARP cache. 
	 Note that this only works for ethernet on solaris, because we use SIOCSARP
	 and not SIOCSXARP, which would be perfect, except that it returns ENXIO 
	 mysteriously. Bah. Fall back to broadcast for other net types. */
      struct arpreq req;
      dest.sin_addr = mess->yiaddr;
      dest.sin_port = htons(daemon->dhcp_client_port);
      *((struct sockaddr_in *)&req.arp_pa) = dest;
      req.arp_ha.sa_family = AF_UNSPEC;
      memcpy(req.arp_ha.sa_data, mess->chaddr, mess->hlen);
      req.arp_flags = ATF_COM;
      ioctl(daemon->dhcpfd, SIOCSARP, &req);
    }
#elif defined(HAVE_BSD_NETWORK)
  else 
    {
#ifdef HAVE_DUMPFILE
      if (ntohs(mess->flags) & 0x8000)
        dest.sin_addr.s_addr = INADDR_BROADCAST;
      else
        dest.sin_addr = mess->yiaddr;
      dest.sin_port = htons(daemon->dhcp_client_port);
      
      dump_packet(DUMP_DHCP, (void *)iov.iov_base, iov.iov_len, NULL,
		  (union mysockaddr *)&dest, daemon->dhcp_server_port);
#endif
      
      send_via_bpf(mess, iov.iov_len, iface_addr, &ifr);
      return;
    }
#endif
   
#ifdef HAVE_SOLARIS_NETWORK
  setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &iface_index, sizeof(iface_index));
#endif

#ifdef HAVE_DUMPFILE
  dump_packet(DUMP_DHCP, (void *)iov.iov_base, iov.iov_len, NULL,
	      (union mysockaddr *)&dest, daemon->dhcp_server_port);
#endif
  
  while(retry_send(sendmsg(fd, &msg, 0)));

  /* This can fail when, eg, iptables DROPS destination 255.255.255.255 */
  if (errno != 0)
    {
      inet_ntop(AF_INET, &dest.sin_addr, daemon->addrbuff, ADDRSTRLEN);
      my_syslog(MS_DHCP | LOG_WARNING, _("Error sending DHCP packet to %s: %s"),
		daemon->addrbuff, strerror(errno));
    }
}

/**
 * @brief Check if local address matches --listen-address configuration for secondary interfaces
 *
 * @detailed
 * Callback function invoked by iface_enumerate() to match packet receiving interface against
 * --listen-address configurations for secondary IP addresses. When DHCP packet arrives on
 * interface with multiple addresses and primary address doesn't match DHCP context, this
 * function checks if any configured --listen-address matches, allowing DHCP service on
 * secondary interface addresses. Updates match_param structure with matched address details.
 *
 * @param local IP address being enumerated on interface
 * @param if_index Interface index being checked
 * @param label Interface name/label (unused, suppressed with (void) cast)
 * @param netmask Netmask for the local address
 * @param broadcast Broadcast address for the local address
 * @param vparam Pointer to struct match_param for passing results and parameters
 *
 * @return Always returns 1 to continue interface enumeration
 * @retval 1 Continue enumeration (standard iface_enumerate() callback protocol)
 *
 * @note Sets param->matched=1 when successful match found
 * @note Only checks if_index matches param->ind (target interface)
 * @note Compares against daemon->if_addrs list of configured --listen-address entries
 *
 * @see iface_enumerate() in network.c Enumerates all interface addresses, invoking this callback
 * @see dhcp_packet() Calls this via iface_enumerate() when primary address match fails (lines 320-323)
 * @see complete_context() Similar callback for completing DHCP context configuration
 *
 * EXAMPLE USAGE:
 * @code
 * struct match_param match;
 * match.matched = 0;
 * match.ind = iface_index;
 * if (iface_enumerate(AF_INET, &match, check_listen_addrs) && match.matched)
 *   iface_addr = match.addr;  // Use secondary address
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-mandated but enables RFC 2131 compliance on multi-homed hosts with
 * secondary addresses where DHCP service should bind to specific addresses only.
 *
 * SIDE EFFECTS:
 * - Modifies match_param structure (sets matched=1, addr, netmask, broadcast on match)
 * - No global state modifications
 * - Read-only access to daemon->if_addrs configuration list
 *
 * THREAD SAFETY:
 * Reentrant assuming vparam points to distinct match_param for each call. Read-only access
 * to daemon->if_addrs which is immutable after configuration parsing. Safe for single-threaded
 * event loop context.
 */
static int check_listen_addrs(struct in_addr local, int if_index, char *label,
			      struct in_addr netmask, struct in_addr broadcast, void *vparam)
{
  struct match_param *param = vparam;
  struct iname *tmp;

  (void) label;

  if (if_index == param->ind)
    {
      for (tmp = daemon->if_addrs; tmp; tmp = tmp->next)
	if ( tmp->addr.sa.sa_family == AF_INET &&
	     tmp->addr.in.sin_addr.s_addr == local.s_addr)
	  {
	    param->matched = 1;
	    param->addr = local;
	    param->netmask = netmask;
	    param->broadcast = broadcast;
	    break;
	  }
    }
  
  return 1;
}

/**
 * @brief Validate and infer netmask for DHCP ranges not explicitly configured with netmask
 *
 * @detailed
 * Validates consistency of DHCP address ranges (dhcp-range) against interface netmasks when
 * ranges were configured without explicit netmask. If range start and end addresses fall
 * within the same subnet as interface address using interface netmask, applies that netmask
 * to the DHCP context. Logs warning if range endpoints span subnet boundary indicating
 * misconfiguration. Allows automatic netmask inference from network topology.
 *
 * @param addr Interface address used for subnet matching
 * @param netmask Interface netmask to apply to contexts lacking explicit netmask
 *
 * @return void
 *
 * @note Only modifies contexts where CONTEXT_NETMASK flag is not set (user didn't specify netmask)
 * @note Logs MS_DHCP | LOG_WARNING if range is inconsistent with netmask (endpoints in different subnets)
 *
 * @warning Inconsistent range/netmask combinations logged but not rejected, may cause operational issues
 *
 * @see complete_context() Calls this function during interface enumeration (line 606)
 * @see is_same_net() in util.c Tests if two addresses are in same subnet given netmask
 *
 * EXAMPLE USAGE:
 * @code
 * // Interface 192.168.1.1/255.255.255.0 with range 192.168.1.10-192.168.1.250
 * guess_range_netmask(addr, netmask);  // Infers 255.255.255.0 for range
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-mandated but ensures RFC 2131 compliance by preventing address allocation
 * outside proper subnet boundaries which would violate client network configuration.
 *
 * SIDE EFFECTS:
 * - Modifies dhcp_context structures by setting context->netmask for unconfigured contexts
 * - Logs warnings to syslog for misconfigured ranges
 * - Read-write access to daemon->dhcp context chain
 *
 * THREAD SAFETY:
 * Not reentrant. Modifies global daemon->dhcp context list. Safe in single-threaded event
 * loop during packet processing as no concurrent modifications occur.
 */
static void guess_range_netmask(struct in_addr addr, struct in_addr netmask)
{
  struct dhcp_context *context;

  for (context = daemon->dhcp; context; context = context->next)
    if (!(context->flags & CONTEXT_NETMASK) &&
	(is_same_net(addr, context->start, netmask) ||
	 is_same_net(addr, context->end, netmask)))
      { 
	if (context->netmask.s_addr != netmask.s_addr &&
	    !(is_same_net(addr, context->start, netmask) &&
	      is_same_net(addr, context->end, netmask)))
	  {
	    inet_ntop(AF_INET, &context->start, daemon->dhcp_buff, DHCP_BUFF_SZ);
	    inet_ntop(AF_INET, &context->end, daemon->dhcp_buff2, DHCP_BUFF_SZ);
	    inet_ntop(AF_INET, &netmask, daemon->addrbuff, ADDRSTRLEN);
	    my_syslog(MS_DHCP | LOG_WARNING, _("DHCP range %s -- %s is not consistent with netmask %s"),
		      daemon->dhcp_buff, daemon->dhcp_buff2, daemon->addrbuff);
	  }	
	context->netmask = netmask;
      }
}

/**
 * @brief Validate and complete DHCP context configuration for packet receiving interface
 *
 * @detailed
 * Complex callback invoked by iface_enumerate() for each interface address to link applicable
 * DHCP contexts (address pools) to current packet's receiving interface. Performs critical
 * initialization: (1) Discards contexts for non-matching interfaces, (2) Fills in missing
 * netmasks by calling guess_range_netmask(), (3) Fills in missing broadcast addresses using
 * standard calculation (network OR inverted netmask), (4) Sets context->local to interface
 * address for Server Identifier option, (5) Sets context->router to interface address for
 * default gateway, (6) Links contexts via ->current pointer forming chain of applicable
 * contexts. Also handles shared-network configurations where multiple contexts apply to same
 * interface, and updates relay agent iface_index for relay forwarding.
 *
 * @param local IP address of interface being enumerated
 * @param if_index Interface index for the address
 * @param label Interface name/label (unused, suppressed with (void) cast)
 * @param netmask Netmask for the local address
 * @param broadcast Broadcast address for the local address
 * @param vparam Pointer to struct iface_param containing current context chain and target interface index
 *
 * @return Always returns 1 to continue interface enumeration
 * @retval 1 Continue enumeration (standard iface_enumerate() callback protocol)
 *
 * @note Current context chain (param->current) may be superseded later for static hosts or relay clients
 * @note Contexts marked with context->current == context are unlinked (not yet processed)
 * @note Shared-network support allows contexts on different subnets to share interface
 * @note Broadcast address calculated as start OR ~netmask if CONTEXT_BRDCAST flag not set
 *
 * @warning Router address set to 0.0.0.0 for shared-network contexts as no single default route applicable
 *
 * @see iface_enumerate() in network.c Enumerates addresses and invokes this callback
 * @see dhcp_packet() Calls this via iface_enumerate() to establish context chain (lines 308-335)
 * @see guess_range_netmask() Called to infer missing netmasks from interface configuration
 * @see narrow_context() Further refines context selection based on allocated address
 * @see is_same_net() in util.c Tests if addresses belong to same subnet
 *
 * EXAMPLE USAGE:
 * @code
 * struct iface_param parm;
 * parm.current = NULL;
 * parm.ind = iface_index;
 * iface_enumerate(AF_INET, &parm, complete_context);
 * // parm.current now points to chain of applicable contexts
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.3.1 requirement that server must determine client's subnet
 * and select appropriate address pool. Shared-network support follows common DHCP server
 * practice for multi-subnet configurations though not explicitly RFC-mandated.
 *
 * SIDE EFFECTS:
 * - Modifies dhcp_context structures: sets router, local, broadcast, netmask, and links via current pointer
 * - Calls guess_range_netmask() which may set netmasks and log warnings
 * - Updates dhcp_relay structures by setting iface_index for matching relay local addresses
 * - Modifies iface_param->current to build context chain
 * - Read-write access to daemon->dhcp, daemon->shared_networks, daemon->relay4 lists
 *
 * THREAD SAFETY:
 * Not reentrant. Modifies global daemon context and relay structures. Safe in single-threaded
 * event loop during packet processing. Assumes daemon configuration is immutable after parsing.
 */
static int complete_context(struct in_addr local, int if_index, char *label,
			    struct in_addr netmask, struct in_addr broadcast, void *vparam)
{
  struct dhcp_context *context;
  struct dhcp_relay *relay;
  struct iface_param *param = vparam;
  struct shared_network *share;
  
  (void)label;

  for (share = daemon->shared_networks; share; share = share->next)
    {
      
#ifdef HAVE_DHCP6
      if (share->shared_addr.s_addr == 0)
	continue;
#endif
      
      if (share->if_index != 0)
	{
	  if (share->if_index != if_index)
	    continue;
	}
      else
	{
	  if (share->match_addr.s_addr != local.s_addr)
	    continue;
	}

      for (context = daemon->dhcp; context; context = context->next)
	{
	  if (context->netmask.s_addr != 0 &&
	      is_same_net(share->shared_addr, context->start, context->netmask) &&
	      is_same_net(share->shared_addr, context->end, context->netmask))
	    {
	      /* link it onto the current chain if we've not seen it before */
	      if (context->current == context)
		{
		  /* For a shared network, we have no way to guess what the default route should be. */
		  context->router.s_addr = 0;
		  context->local = local; /* Use configured address for Server Identifier */
		  context->current = param->current;
		  param->current = context;
		}
	      
	      if (!(context->flags & CONTEXT_BRDCAST))
		context->broadcast.s_addr  = context->start.s_addr | ~context->netmask.s_addr;
	    }		
	}
    }

  guess_range_netmask(local, netmask);
  
  for (context = daemon->dhcp; context; context = context->next)
    {
      if (context->netmask.s_addr != 0 &&
	  is_same_net(local, context->start, context->netmask) &&
	  is_same_net(local, context->end, context->netmask))
	{
	  /* link it onto the current chain if we've not seen it before */
	  if (if_index == param->ind && context->current == context)
	    {
	      context->router = local;
	      context->local = local;
	      context->current = param->current;
	      param->current = context;
	    }
	  
	  if (!(context->flags & CONTEXT_BRDCAST))
	    {
	      if (is_same_net(broadcast, context->start, context->netmask))
		context->broadcast = broadcast;
	      else 
		context->broadcast.s_addr  = context->start.s_addr | ~context->netmask.s_addr;
	    }
	}		
    }

  for (relay = daemon->relay4; relay; relay = relay->next)
    if (relay->local.addr4.s_addr == local.s_addr)
      relay->iface_index = if_index;
  
  return 1;
}

/**
 * @brief Check if IP address is available for allocation within DHCP context chain
 *
 * @detailed
 * Validates whether specified address can be allocated to DHCP client by checking address
 * availability across context chain. Verifies address falls within configured range (start to end),
 * is not the router address reserved for gateway, is not marked STATIC or PROXY-only, and matches
 * client's netid tags for tag-based pool selection. Returns first matching context allowing
 * allocation, or NULL if address unavailable or reserved.
 *
 * @param context Pointer to head of dhcp_context chain (linked via ->current)
 * @param taddr IP address to check for availability (in network byte order)
 * @param netids Client's netid tags for matching against context filters
 *
 * @return Pointer to dhcp_context allowing this address allocation, or NULL if unavailable
 * @retval NULL Address is router address, out of range, in STATIC/PROXY context, or netid mismatch
 * @retval context Pointer to first context permitting address allocation
 *
 * @note Checks router address across ALL contexts in chain (not just matching one)
 * @note Requires address to be in host byte order comparison after ntohl() conversion
 * @note CONTEXT_STATIC and CONTEXT_PROXY contexts excluded from dynamic allocation
 *
 * @see narrow_context() Uses this function to validate static host addresses (line 684)
 * @see address_allocate() Calls this indirectly when validating allocated addresses
 * @see match_netid() in netid.c Tests if client netids match context filter
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr test_addr;
 * inet_pton(AF_INET, "192.168.1.100", &test_addr);
 * struct dhcp_context *ctx = address_available(context_chain, test_addr, client_netids);
 * if (ctx)
 *   // Address available in ctx pool
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 3.1 requirement that server allocate addresses only from
 * configured pools, and Section 4.3.1 address validation before offering.
 *
 * SIDE EFFECTS:
 * - Read-only operation on dhcp_context chain
 * - No modifications to any structures
 * - Calls match_netid() which traverses netid lists
 *
 * THREAD SAFETY:
 * Reentrant. Read-only access to context chain and netid structures. Safe for concurrent
 * calls with different context chains. Used in single-threaded event loop.
 */
struct dhcp_context *address_available(struct dhcp_context *context, 
				       struct in_addr taddr,
				       struct dhcp_netid *netids)
{
  /* Check is an address is OK for this network, check all
     possible ranges. Make sure that the address isn't in use
     by the server itself. */
  
  unsigned int start, end, addr = ntohl(taddr.s_addr);
  struct dhcp_context *tmp;

  for (tmp = context; tmp; tmp = tmp->current)
    if (taddr.s_addr == context->router.s_addr)
      return NULL;
  
  for (tmp = context; tmp; tmp = tmp->current)
    {
      start = ntohl(tmp->start.s_addr);
      end = ntohl(tmp->end.s_addr);

      if (!(tmp->flags & (CONTEXT_STATIC | CONTEXT_PROXY)) &&
	  addr >= start &&
	  addr <= end &&
	  match_netid(tmp->filter, netids, 1))
	return tmp;
    }

  return NULL;
}

/**
 * @brief Narrow context chain to single context matching specific address and client netids
 *
 * @detailed
 * Refines broad context chain (all contexts on physical interface) to single most-specific
 * context for given address. Used when client has pre-existing address (from static host
 * configuration or dhcp-host) that may fall outside normal ranges. Attempts three-tier
 * matching: (1) Normal dynamic range via address_available(), (2) Static-only range
 * (CONTEXT_STATIC) if netid matches and address in subnet, (3) Any non-proxy context in
 * correct subnet as fallback. Returns single context with ->current set to NULL to break chain,
 * or NULL if no suitable context exists (misconfigured static host on wrong subnet).
 *
 * @param context Pointer to head of dhcp_context chain to narrow
 * @param taddr IP address to match against contexts
 * @param netids Client's netid tags for matching context filters
 *
 * @return Pointer to single narrowed context with ->current=NULL, or NULL if no match
 * @retval NULL Address doesn't match any context's subnet or all contexts filtered by netids
 * @retval context Single context allowing this address, ->current set to NULL
 *
 * @note Sets tmp->current=NULL to break context chain, ensuring only one context returned
 * @note Fallback logic allows static hosts on correct subnet even if range doesn't include address
 * @note CONTEXT_PROXY contexts skipped in fallback (used for proxydhcp PXE only)
 *
 * @warning Configuration error if static host address doesn't match any context subnet
 *
 * @see address_available() First-pass check for addresses in normal dynamic ranges
 * @see dhcp_reply() in rfc2131.c Uses narrowed context for static host processing
 * @see match_netid() in netid.c Tests netid filter matching
 * @see is_same_net() in util.c Verifies address in context's subnet
 *
 * EXAMPLE USAGE:
 * @code
 * // Static host 192.168.1.10 with context chain for eth0
 * struct dhcp_context *ctx = narrow_context(context_chain, static_addr, client_netids);
 * if (!ctx)
 *   // Error: static host address not in any configured subnet
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.3.1 requirement that server select appropriate subnet
 * for client, with extensions supporting static host configuration outside normal ranges.
 *
 * SIDE EFFECTS:
 * - Modifies returned context by setting tmp->current = NULL to break chain
 * - Read-only on input context chain (original chain unchanged)
 * - Calls address_available() and match_netid() with potential side effects
 *
 * THREAD SAFETY:
 * Mostly reentrant but modifies returned context structure. Safe in single-threaded event
 * loop where context chain is per-packet state. Do not call concurrently on shared context.
 */
struct dhcp_context *narrow_context(struct dhcp_context *context, 
				    struct in_addr taddr,
				    struct dhcp_netid *netids)
{
  /* We start of with a set of possible contexts, all on the current physical interface.
     These are chained on ->current.
     Here we have an address, and return the actual context corresponding to that
     address. Note that none may fit, if the address came a dhcp-host and is outside
     any dhcp-range. In that case we return a static range if possible, or failing that,
     any context on the correct subnet. (If there's more than one, this is a dodgy 
     configuration: maybe there should be a warning.) */
  
  struct dhcp_context *tmp;

  if (!(tmp = address_available(context, taddr, netids)))
    {
      for (tmp = context; tmp; tmp = tmp->current)
	if (match_netid(tmp->filter, netids, 1) &&
	    is_same_net(taddr, tmp->start, tmp->netmask) && 
	    (tmp->flags & CONTEXT_STATIC))
	  break;
      
      if (!tmp)
	for (tmp = context; tmp; tmp = tmp->current)
	  if (match_netid(tmp->filter, netids, 1) &&
	      is_same_net(taddr, tmp->start, tmp->netmask) &&
	      !(tmp->flags & CONTEXT_PROXY))
	    break;
    }
  
  /* Only one context allowed now */
  if (tmp)
    tmp->current = NULL;
  
  return tmp;
}

/**
 * @brief Find static host configuration (dhcp-host) by IP address
 *
 * @detailed
 * Searches linked list of dhcp_config structures (static host reservations from dhcp-host
 * configuration) for entry with matching IP address. Used during address allocation to prevent
 * allocating addresses reserved for specific hosts, and during static host processing to
 * retrieve full host configuration. Simple linear search as static host counts typically low.
 *
 * @param configs Head of dhcp_config linked list to search (typically daemon->dhcp_conf)
 * @param addr IP address to search for in config entries
 *
 * @return Pointer to matching dhcp_config structure, or NULL if not found
 * @retval NULL No static host configured with this address
 * @retval config Pointer to dhcp_config with matching addr.s_addr
 *
 * @note Only matches configs with CONFIG_ADDR flag set (address configured)
 * @note Linear search acceptable as static host lists typically under 100 entries
 *
 * @see address_allocate() Calls this to avoid allocating reserved addresses (line 832)
 * @see dhcp_reply() in rfc2131.c Uses this to lookup static host configuration
 * @see lease_find_by_client() in lease.c Alternative search by client identifier
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr test_addr;
 * inet_pton(AF_INET, "192.168.1.100", &test_addr);
 * struct dhcp_config *cfg = config_find_by_address(daemon->dhcp_conf, test_addr);
 * if (cfg)
 *   // Found static host reservation for this address
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-mandated but implements common DHCP practice of static host reservations
 * as extension to RFC 2131 dynamic allocation.
 *
 * SIDE EFFECTS:
 * - Read-only operation on dhcp_config list
 * - No modifications to any structures
 * - Traverses linked list with O(n) complexity
 *
 * THREAD SAFETY:
 * Reentrant. Read-only access to dhcp_config list which is immutable after configuration
 * parsing (except dhcp_read_ethers() modifications). Safe for single-threaded event loop.
 */
struct dhcp_config *config_find_by_address(struct dhcp_config *configs, struct in_addr addr)
{
  struct dhcp_config *config;
  
  for (config = configs; config; config = config->next)
    if ((config->flags & CONFIG_ADDR) && config->addr.s_addr == addr.s_addr)
      return config;

  return NULL;
}

/**
 * @brief Perform ping-before-offer address conflict detection with caching and load limiting
 *
 * @detailed
 * Implements ping-before-offer conflict detection by sending ICMP echo request to candidate
 * address before allocating to DHCP client. Maintains cache of recently-pinged addresses
 * (PING_CACHE_TIME=30 seconds) to avoid redundant pings when clients request repeatedly.
 * Implements load limiting by refusing new pings if more than 60% of possible pings occurred
 * in cache window, preventing ping flood from misbehaving clients. Returns NULL if address
 * responds (in use/conflict), or pointer to cache entry if address available. Automatically
 * bypasses ping for loopback interfaces and when OPT_NO_PING option set.
 *
 * @param now Current time for cache expiry calculations
 * @param addr IP address to test for conflicts via ICMP ping
 * @param hash Client hardware address hash for consec-ip mode tracking
 * @param loopback Boolean flag: non-zero if address on loopback interface (no ping needed)
 *
 * @return Pointer to ping_result cache entry if address available, NULL if in use
 * @retval NULL Address responded to ICMP ping (conflict detected, cannot allocate)
 * @retval ping_result Pointer to cache entry recording address available, or &dummy if overloaded/loopback
 *
 * @note PING_CACHE_TIME (30 seconds) defines cache validity period
 * @note Load limit threshold: 60% of (PING_CACHE_TIME / PING_WAIT) max pings
 * @note Dummy static ping_result returned when overloaded to avoid NULL confusion
 * @note Cache entries expire after PING_CACHE_TIME and get recycled
 *
 * @warning Address may become occupied between ping check and actual allocation (race condition)
 * @warning Cache assumes address remains available for 30 seconds after successful ping
 *
 * @see icmp_ping() in network.c Performs actual ICMP echo request transmission
 * @see address_allocate() Calls this before offering address to client (line 846)
 * @see whine_malloc() in util.c Allocates new ping_result cache entries
 *
 * EXAMPLE USAGE:
 * @code
 * struct ping_result *pr = do_icmp_ping(now, candidate_addr, client_hash, 0);
 * if (pr)
 *   // Address available, allocate to client
 * else
 *   // Address in use, try next candidate
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 3.1 Paragraph 4 recommendation that server should probe
 * address with ICMP echo before allocating to detect conflicts with misconfigured clients.
 *
 * SIDE EFFECTS:
 * - Sends ICMP echo request packets to network
 * - Allocates new ping_result structures and adds to daemon->ping_results linked list
 * - Modifies ping_result cache (time, addr, hash fields updated)
 * - Recycles expired cache entries (victim reuse)
 * - Read-write access to daemon->ping_results cache list
 *
 * THREAD SAFETY:
 * Not reentrant. Modifies global daemon->ping_results cache. Safe in single-threaded event
 * loop as all DHCP processing serialized. ICMP sending is non-blocking.
 */
struct ping_result *do_icmp_ping(time_t now, struct in_addr addr, unsigned int hash, int loopback)
{
  static struct ping_result dummy;
  struct ping_result *r, *victim = NULL;
  int count, max = (int)(0.6 * (((float)PING_CACHE_TIME)/
				((float)PING_WAIT)));

  /* check if we failed to ping addr sometime in the last
     PING_CACHE_TIME seconds. If so, assume the same situation still exists.
     This avoids problems when a stupid client bangs
     on us repeatedly. As a final check, if we did more
     than 60% of the possible ping checks in the last 
     PING_CACHE_TIME, we are in high-load mode, so don't do any more. */
  for (count = 0, r = daemon->ping_results; r; r = r->next)
    if (difftime(now, r->time) >  (float)PING_CACHE_TIME)
      victim = r; /* old record */
    else 
      {
	count++;
	if (r->addr.s_addr == addr.s_addr)
	  return r;
      }
  
  /* didn't find cached entry */
  if ((count >= max) || option_bool(OPT_NO_PING) || loopback)
    {
      /* overloaded, or configured not to check, loopback interface, return "not in use" */
      dummy.hash = hash;
      return &dummy;
    }
  else if (icmp_ping(addr))
    return NULL; /* address in use. */
  else
    {
      /* at this point victim may hold an expired record */
      if (!victim)
	{
	  if ((victim = whine_malloc(sizeof(struct ping_result))))
	    {
	      victim->next = daemon->ping_results;
	      daemon->ping_results = victim;
	    }
	}
      
      /* record that this address is OK for 30s 
	 without more ping checks */
      if (victim)
	{
	  victim->addr = addr;
	  victim->time = now;
	  victim->hash = hash;
	}
      return victim;
    }
}

/**
 * @brief Allocate IP address from DHCP pool with conflict detection and hash-based distribution
 *
 * @detailed
 * Core address allocation function implementing two allocation strategies: (1) Hash-based
 * pseudo-random selection using SDBM hash of client MAC address for consistent address
 * assignment across renewals, or (2) Consecutive allocation starting from largest existing
 * lease if OPT_CONSEC_ADDR set. Searches contexts matching client netids, iterates through
 * address space avoiding router addresses, existing leases, static host reservations, and
 * broken Windows .0/.255 addresses in class C ranges. Performs ping-before-offer conflict
 * detection via do_icmp_ping() with caching. Implements addr_epoch perturbation on conflicts
 * to avoid repeated offering of busy addresses. Returns allocated address via addrp parameter.
 *
 * @param context Pointer to head of dhcp_context chain (all contexts for interface)
 * @param addrp Pointer to in_addr structure to receive allocated address (output parameter)
 * @param hwaddr Client hardware address (MAC) for hash-based address selection
 * @param hw_len Length of hardware address in bytes (typically 6 for Ethernet)
 * @param netids Client's netid tags for context filtering
 * @param now Current time for ping cache operations
 * @param loopback Boolean flag: non-zero if client on loopback interface (skip ping)
 *
 * @return 1 if address successfully allocated, 0 if no addresses available
 * @retval 1 Address allocated and stored in *addrp
 * @retval 0 All addresses exhausted, in use, or reserved (allocation failed)
 *
 * @note SDBM hash function provides good address distribution even for similar MAC addresses
 * @note Windows bug: .0 and .255 avoided in class C ranges even when valid with supernetting
 * @note Two-pass netid matching: first pass strict match, second pass relaxed if first fails
 * @note Hash j==0 is marker value, replaced with j=1 to avoid confusion
 * @note Consecutive mode uses lease_find_max_addr() to seed from largest existing lease
 * @note addr_epoch perturbation prevents repeatedly offering addresses that clients reject
 *
 * @warning Windows class C .0/.255 avoidance per KB281579 may waste addresses in modern networks
 * @warning Allocation race: address may be claimed between ping check and lease creation
 *
 * @see do_icmp_ping() Performs conflict detection via ICMP echo with caching
 * @see lease_find_by_addr() in lease.c Checks if address already leased
 * @see config_find_by_address() Checks if address reserved for static host
 * @see lease_find_max_addr() in lease.c Finds highest allocated address for consecutive mode
 * @see match_netid() in netid.c Tests client tags against context filters
 * @see dhcp_reply() in rfc2131.c Calls this during DHCPDISCOVER/DHCPREQUEST processing
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr allocated;
 * if (address_allocate(context, &allocated, client_mac, 6, netids, now, 0))
 *   // Successfully allocated address in 'allocated'
 * else
 *   // No addresses available, send DHCPNAK or DHCPOFFER failure
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.3.1 address selection algorithm including conflict detection
 * (ICMP ping) and ensuring offered address is valid for client's subnet. SDBM hash provides
 * stable pseudo-random allocation recommended by RFC 2131 for fair distribution.
 *
 * SIDE EFFECTS:
 * - Calls do_icmp_ping() which sends ICMP packets and modifies ping cache
 * - Modifies context->addr_epoch for perturbation on conflicts (increments on ping failure)
 * - Decrements context->addr_epoch in consec-ip mode for rejected addresses
 * - Stores allocated address in *addrp output parameter
 * - Iterates through entire address range potentially trying all addresses
 * - Read-only access to lease database and static host configuration
 *
 * THREAD SAFETY:
 * Not reentrant. Modifies context->addr_epoch field and accesses global lease database.
 * Safe in single-threaded event loop where contexts are per-packet and lease DB access serialized.
 */
int address_allocate(struct dhcp_context *context,
		     struct in_addr *addrp, unsigned char *hwaddr, int hw_len, 
		     struct dhcp_netid *netids, time_t now, int loopback)   
{
  /* Find a free address: exclude anything in use and anything allocated to
     a particular hwaddr/clientid/hostname in our configuration.
     Try to return from contexts which match netids first. */

  struct in_addr start, addr;
  struct dhcp_context *c, *d;
  int i, pass;
  unsigned int j; 

  /* hash hwaddr: use the SDBM hashing algorithm.  Seems to give good
     dispersal even with similarly-valued "strings". */ 
  for (j = 0, i = 0; i < hw_len; i++)
    j = hwaddr[i] + (j << 6) + (j << 16) - j;

  /* j == 0 is marker */
  if (j == 0)
    j = 1;
  
  for (pass = 0; pass <= 1; pass++)
    for (c = context; c; c = c->current)
      if (c->flags & (CONTEXT_STATIC | CONTEXT_PROXY))
	continue;
      else if (!match_netid(c->filter, netids, pass))
	continue;
      else
	{
	  if (option_bool(OPT_CONSEC_ADDR))
	    /* seed is largest extant lease addr in this context */
	    start = lease_find_max_addr(c);
	  else
	    /* pick a seed based on hwaddr */
	    start.s_addr = htonl(ntohl(c->start.s_addr) + 
				 ((j + c->addr_epoch) % (1 + ntohl(c->end.s_addr) - ntohl(c->start.s_addr))));

	  /* iterate until we find a free address. */
	  addr = start;
	  
	  do {
	    /* eliminate addresses in use by the server. */
	    for (d = context; d; d = d->current)
	      if (addr.s_addr == d->router.s_addr)
		break;

	    /* Addresses which end in .255 and .0 are broken in Windows even when using 
	       supernetting. ie dhcp-range=192.168.0.1,192.168.1.254,255,255,254.0
	       then 192.168.0.255 is a valid IP address, but not for Windows as it's
	       in the class C range. See  KB281579. We therefore don't allocate these 
	       addresses to avoid hard-to-diagnose problems. Thanks Bill. */	    
	    if (!d &&
		!lease_find_by_addr(addr) && 
		!config_find_by_address(daemon->dhcp_conf, addr) &&
		(!IN_CLASSC(ntohl(addr.s_addr)) || 
		 ((ntohl(addr.s_addr) & 0xff) != 0xff && ((ntohl(addr.s_addr) & 0xff) != 0x0))))
	      {
		/* in consec-ip mode, skip addresses equal to
		   the number of addresses rejected by clients. This
		   should avoid the same client being offered the same
		   address after it has rjected it. */
		if (option_bool(OPT_CONSEC_ADDR) && c->addr_epoch)
		  c->addr_epoch--;
		else
		  {
		    struct ping_result *r;
		    
		    if ((r = do_icmp_ping(now, addr, j, loopback)))
		      {
			/* consec-ip mode: we offered this address for another client
			   (different hash) recently, don't offer it to this one. */
			if (!option_bool(OPT_CONSEC_ADDR) || r->hash == j)
			  {
			    *addrp = addr;
			    return 1;
			  }
		      }
		    else
		      {
			/* address in use: perturb address selection so that we are
			   less likely to try this address again. */
			if (!option_bool(OPT_CONSEC_ADDR))
			  c->addr_epoch++;
		      }
		  }
	      }
	    
	    addr.s_addr = htonl(ntohl(addr.s_addr) + 1);
	    
	    if (addr.s_addr == htonl(ntohl(c->end.s_addr) + 1))
	      addr = c->start;
	    
	  } while (addr.s_addr != start.s_addr);
	}

  return 0;
}

/**
 * @brief Load static host-to-MAC address mappings from /etc/ethers file
 *
 * @detailed
 * Reads /etc/ethers file containing Ethernet address to hostname/IP mappings in format
 * "MAC hostname" or "MAC ipaddress" (one per line). Creates dhcp_config static host
 * reservations for each entry, allowing consistent address allocation to known hosts.
 * Handles SIGHUP reload by removing previous CONFIG_FROM_ETHERS entries before re-reading.
 * Validates MAC addresses (must be ETHER_ADDR_LEN=6 bytes), IP addresses (dotted-quad format),
 * and hostnames (legal DNS names only). Merges with existing dhcp_config entries if matching
 * MAC address found. Logs count of addresses loaded and errors for invalid entries.
 *
 * @return void
 *
 * @note ETHERSFILE typically defined as "/etc/ethers"
 * @note Lines starting with # (comment), + (NIS), or empty are skipped
 * @note Duplicate names or IPs logged as errors and skipped
 * @note Sets CONFIG_NOCLID flag as /etc/ethers entries lack client identifiers
 * @note Existing CONFIG_FROM_ETHERS entries removed on each call for clean reload
 * @note Merges with existing hwaddr-matched configs to preserve user-configured options
 *
 * @warning Silently continues on malloc failures, losing individual entries but not aborting
 * @warning CONFIG_FROM_ETHERS flag allows distinguishing auto-loaded from user-configured hosts
 *
 * @see canonicalise() in util.c Validates and normalizes hostnames
 * @see legal_hostname() in util.c Checks hostname validity per DNS rules
 * @see parse_hex() in util.c Parses colon-separated hex MAC address
 * @see whine_malloc() in util.c Allocates memory with error logging
 * @see dhcp_reply() in rfc2131.c Uses loaded static host configurations for reservations
 *
 * EXAMPLE USAGE:
 * @code
 * // /etc/ethers content:
 * // 00:11:22:33:44:55 workstation1
 * // aa:bb:cc:dd:ee:ff 192.168.1.100
 * dhcp_read_ethers();  // Loads 2 static host entries
 * // Called again on SIGHUP to reload changes
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-mandated but implements traditional Unix /etc/ethers integration common
 * in DHCP server implementations, extending RFC 2131 with static host reservations.
 *
 * SIDE EFFECTS:
 * - Opens and reads /etc/ethers file, logs error if inaccessible
 * - Removes all existing CONFIG_FROM_ETHERS entries from daemon->dhcp_conf list
 * - Allocates and adds new dhcp_config structures to daemon->dhcp_conf list
 * - Allocates hostname strings and hwaddr_config structures
 * - Logs MS_DHCP | LOG_INFO with count of loaded addresses
 * - Logs MS_DHCP | LOG_ERR for parsing errors (bad line, bad address, bad name, duplicates)
 * - Modifies global daemon->dhcp_conf configuration list
 *
 * THREAD SAFETY:
 * Not reentrant. Modifies global daemon->dhcp_conf list. Must be called only from main thread
 * during initialization or SIGHUP handling. File I/O is blocking.
 */
void dhcp_read_ethers(void)
{
  FILE *f = fopen(ETHERSFILE, "r");
  unsigned int flags;
  char *buff = daemon->namebuff;
  char *ip, *cp;
  struct in_addr addr;
  unsigned char hwaddr[ETHER_ADDR_LEN];
  struct dhcp_config **up, *tmp;
  struct dhcp_config *config;
  int count = 0, lineno = 0;

  addr.s_addr = 0; /* eliminate warning */
  
  if (!f)
    {
      my_syslog(MS_DHCP | LOG_ERR, _("failed to read %s: %s"), ETHERSFILE, strerror(errno));
      return;
    }

  /* This can be called again on SIGHUP, so remove entries created last time round. */
  for (up = &daemon->dhcp_conf, config = daemon->dhcp_conf; config; config = tmp)
    {
      tmp = config->next;
      if (config->flags & CONFIG_FROM_ETHERS)
	{
	  *up = tmp;
	  /* cannot have a clid */
	  if (config->flags & CONFIG_NAME)
	    free(config->hostname);
	  free(config->hwaddr);
	  free(config);
	}
      else
	up = &config->next;
    }

  while (fgets(buff, MAXDNAME, f))
    {
      char *host = NULL;
      
      lineno++;
      
      while (strlen(buff) > 0 && isspace((int)buff[strlen(buff)-1]))
	buff[strlen(buff)-1] = 0;
      
      if ((*buff == '#') || (*buff == '+') || (*buff == 0))
	continue;
      
      for (ip = buff; *ip && !isspace((int)*ip); ip++);
      for(; *ip && isspace((int)*ip); ip++)
	*ip = 0;
      if (!*ip || parse_hex(buff, hwaddr, ETHER_ADDR_LEN, NULL, NULL) != ETHER_ADDR_LEN)
	{
	  my_syslog(MS_DHCP | LOG_ERR, _("bad line at %s line %d"), ETHERSFILE, lineno); 
	  continue;
	}
      
      /* check for name or dotted-quad */
      for (cp = ip; *cp; cp++)
	if (!(*cp == '.' || (*cp >='0' && *cp <= '9')))
	  break;
      
      if (!*cp)
	{
	  if (inet_pton(AF_INET, ip, &addr.s_addr) < 1)
	    {
	      my_syslog(MS_DHCP | LOG_ERR, _("bad address at %s line %d"), ETHERSFILE, lineno); 
	      continue;
	    }

	  flags = CONFIG_ADDR;
	  
	  for (config = daemon->dhcp_conf; config; config = config->next)
	    if ((config->flags & CONFIG_ADDR) && config->addr.s_addr == addr.s_addr)
	      break;
	}
      else 
	{
	  int nomem;
	  if (!(host = canonicalise(ip, &nomem)) || !legal_hostname(host))
	    {
	      if (!nomem)
		my_syslog(MS_DHCP | LOG_ERR, _("bad name at %s line %d"), ETHERSFILE, lineno); 
	      free(host);
	      continue;
	    }
	      
	  flags = CONFIG_NAME;

	  for (config = daemon->dhcp_conf; config; config = config->next)
	    if ((config->flags & CONFIG_NAME) && hostname_isequal(config->hostname, host))
	      break;
	}

      if (config && (config->flags & CONFIG_FROM_ETHERS))
	{
	  my_syslog(MS_DHCP | LOG_ERR, _("ignoring %s line %d, duplicate name or IP address"), ETHERSFILE, lineno); 
	  continue;
	}
	
      if (!config)
	{ 
	  for (config = daemon->dhcp_conf; config; config = config->next)
	    {
	      struct hwaddr_config *conf_addr = config->hwaddr;
	      if (conf_addr && 
		  conf_addr->next == NULL && 
		  conf_addr->wildcard_mask == 0 &&
		  conf_addr->hwaddr_len == ETHER_ADDR_LEN &&
		  (conf_addr->hwaddr_type == ARPHRD_ETHER || conf_addr->hwaddr_type == 0) &&
		  memcmp(conf_addr->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0)
		break;
	    }
	  
	  if (!config)
	    {
	      if (!(config = whine_malloc(sizeof(struct dhcp_config))))
		continue;
	      config->flags = CONFIG_FROM_ETHERS;
	      config->hwaddr = NULL;
	      config->domain = NULL;
	      config->netid = NULL;
	      config->next = daemon->dhcp_conf;
	      daemon->dhcp_conf = config;
	    }
	  
	  config->flags |= flags;
	  
	  if (flags & CONFIG_NAME)
	    {
	      config->hostname = host;
	      host = NULL;
	    }
	  
	  if (flags & CONFIG_ADDR)
	    config->addr = addr;
	}
      
      config->flags |= CONFIG_NOCLID;
      if (!config->hwaddr)
	config->hwaddr = whine_malloc(sizeof(struct hwaddr_config));
      if (config->hwaddr)
	{
	  memcpy(config->hwaddr->hwaddr, hwaddr, ETHER_ADDR_LEN);
	  config->hwaddr->hwaddr_len = ETHER_ADDR_LEN;
	  config->hwaddr->hwaddr_type = ARPHRD_ETHER;
	  config->hwaddr->wildcard_mask = 0;
	  config->hwaddr->next = NULL;
	}
      count++;
      
      free(host);

    }
  
  fclose(f);

  my_syslog(MS_DHCP | LOG_INFO, _("read %s - %d addresses"), ETHERSFILE, count);
}

/**
 * @brief Retrieve client hostname from DNS cache for lease hostname assignment
 *
 * @detailed
 * Attempts to find hostname for DHCP client's IP address by querying dnsmasq's DNS cache
 * (from /etc/hosts or previous DNS queries). Used as fallback when client doesn't provide
 * hostname in DHCPREQUEST. Validates that cached hostname came from /etc/hosts (F_HOSTS flag)
 * for trust, verifies domain part matches get_domain() result for address, strips domain
 * suffix leaving bare hostname, and validates result is legal hostname (not just legal domain).
 * Only overwrites daemon->dhcp_buff on success to preserve existing content on failure.
 *
 * @param addr IP address to lookup in DNS cache
 *
 * @return Pointer to hostname in daemon->dhcp_buff if found, NULL if not found or invalid
 * @retval NULL DNS disabled (port 0), no cache entry, not from /etc/hosts, wrong domain, or illegal hostname
 * @retval daemon->dhcp_buff Pointer to validated hostname (domain stripped, max 256 chars)
 *
 * @note Only considers cache entries with F_HOSTS flag (from /etc/hosts file, not dynamic)
 * @note Domain validation ensures hostname matches --domain or --dhcp-domain configuration
 * @note Hostname legality check stricter than domain name rules (no underscores, length limits)
 * @note daemon->dhcp_buff only modified on successful lookup to preserve caller's data
 * @note Maximum hostname length limited by safe_strncpy() to 256 characters
 *
 * @warning Returns NULL if daemon->port==0 (DNS functionality disabled)
 * @warning Domain mismatch causes rejection even if hostname otherwise valid
 *
 * @see cache_find_by_addr() in cache.c Searches DNS cache for reverse (addr-to-name) lookup
 * @see cache_get_name() in cache.c Extracts hostname string from cache entry
 * @see get_domain() in domain.c Returns configured domain for address/interface
 * @see legal_hostname() in util.c Validates hostname conforms to RFC 1123
 * @see strip_hostname() in util.c Removes domain suffix leaving bare hostname
 * @see hostname_isequal() in util.c Case-insensitive domain comparison
 * @see dhcp_reply() in rfc2131.c Calls this when client omits hostname option
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr client_addr;
 * inet_pton(AF_INET, "192.168.1.100", &client_addr);
 * char *hostname = host_from_dns(client_addr);
 * if (hostname)
 *   // Use hostname from /etc/hosts for lease record
 * else
 *   // No hostname available, use IP-based name or leave blank
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-mandated but implements common DHCP practice of using reverse DNS
 * lookups to populate hostname field in lease records, enhancing RFC 2131 basic allocation.
 *
 * SIDE EFFECTS:
 * - Calls cache_find_by_addr() performing DNS cache lookup (read-only)
 * - Calls get_domain() which may trigger interface enumeration
 * - Modifies daemon->dhcp_buff on success (writes hostname up to 256 chars)
 * - Calls strip_hostname() which modifies daemon->dhcp_buff in-place
 * - No side effects on failure (daemon->dhcp_buff untouched)
 *
 * THREAD SAFETY:
 * Not reentrant due to use of shared daemon->dhcp_buff buffer. Safe in single-threaded event
 * loop where buffer access is serialized. Cache lookups are read-only and thread-safe.
 */
char *host_from_dns(struct in_addr addr)
{
  struct crec *lookup;

  if (daemon->port == 0)
    return NULL; /* DNS disabled. */
  
  lookup = cache_find_by_addr(NULL, (union all_addr *)&addr, 0, F_IPV4);

  if (lookup && (lookup->flags & F_HOSTS))
    {
      char *dot, *hostname = cache_get_name(lookup);
      dot = strchr(hostname, '.');
      
      if (dot && strlen(dot+1) != 0)
	{
	  char *d2 = get_domain(addr);
	  if (!d2 || !hostname_isequal(dot+1, d2))
	    return NULL; /* wrong domain */
	}

      if (!legal_hostname(hostname))
	return NULL;
      
      safe_strncpy(daemon->dhcp_buff, hostname, 256);
      strip_hostname(daemon->dhcp_buff);

      return daemon->dhcp_buff;
    }
  
  return NULL;
}

/**
 * @brief Forward DHCPv4 client request to upstream relay servers
 *
 * @detailed
 * Implements DHCP relay agent functionality by forwarding client BOOTREQUEST packets to
 * configured upstream DHCP servers. Matches relay configuration by receiving interface index,
 * fills in giaddr field with relay agent's address (unless already set by another relay),
 * increments hop count with loop prevention (max 20 hops), and transmits to all configured
 * relay servers for this interface. Supports broadcast relay to interface broadcast address
 * when server address is 0.0.0.0. Logs relay operations when OPT_LOG_OPTS enabled.
 *
 * @param iface_index Interface index on which client request was received
 * @param mess Pointer to DHCP packet to forward (giaddr and hops fields modified)
 * @param sz Size of DHCP packet in bytes
 *
 * @return 1 if packet forwarded to relay server(s), 0 if no relay configured or not BOOTREQUEST
 * @retval 0 No relay configured for interface, or packet is BOOTREPLY (not BOOTREQUEST)
 * @retval 1 Packet forwarded to at least one relay server
 *
 * @note Only forwards BOOTREQUEST packets (op==1), ignores BOOTREPLY to prevent loops
 * @note Preserves original giaddr if already set, detecting multi-hop relay chains
 * @note Refuses forwarding if hops >= 20 to prevent relay loops
 * @note Sets giaddr to relay->local.addr4 to identify relay agent to server
 * @note Detects loop if incoming giaddr matches relay local address
 * @note Broadcast relay requires interface name for SIOCGIFBRDADDR ioctl
 *
 * @warning Silently skips relay if hops exceeds 20 (continues to next relay in list)
 * @warning Silently skips relay if giaddr matches local address (loop detection)
 * @warning Logs error but continues if broadcast relay interface ioctl fails
 *
 * @see dhcp_packet() Calls this before local server processing (lines 331, 340)
 * @see relay_reply4() Detects and handles relay server replies
 * @see send_from() in network.c Transmits packet with specific source address
 * @see complete_context() Sets relay->iface_index during interface enumeration
 *
 * EXAMPLE USAGE:
 * @code
 * // Client request arrives on eth0 (index 2)
 * if (relay_upstream4(2, dhcp_packet, packet_size))
 *   return;  // Forwarded to relay, don't process locally
 * // No relay, process as normal DHCP server
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1542 Section 4 BOOTP relay agent behavior including giaddr setting,
 * hop count increment, and loop prevention. Also satisfies RFC 2131 Section 4.1.1 relay
 * requirements for DHCP packets.
 *
 * SIDE EFFECTS:
 * - Modifies mess->hops field (increments by 1 for each relay)
 * - Modifies mess->giaddr field (sets to relay local address if not already set)
 * - Transmits UDP packets to relay servers via send_from()
 * - Logs relay operations to syslog when OPT_LOG_OPTS set
 * - May perform SIOCGIFBRDADDR ioctl for broadcast relay
 * - Read-only access to daemon->relay4 configuration list
 *
 * THREAD SAFETY:
 * Not reentrant due to packet buffer modifications. Safe in single-threaded event loop where
 * mess pointer is per-packet state. Daemon->relay4 configuration is immutable after parsing.
 */
static int relay_upstream4(int iface_index, struct dhcp_packet *mess, size_t sz)
{
  struct in_addr giaddr = mess->giaddr;
  u8 hops = mess->hops;
  struct dhcp_relay *relay;

  if (mess->op != BOOTREQUEST)
    return 0;

  for (relay = daemon->relay4; relay; relay = relay->next)
    if (relay->iface_index != 0 && relay->iface_index == iface_index)
      break;

  /* No relay config. */
  if (!relay)
    return 0;
  
  for (; relay; relay = relay->next)
    if (relay->iface_index != 0 && relay->iface_index == iface_index)
      {
	union mysockaddr to;
	union all_addr from;

	mess->hops = hops;
	mess->giaddr = giaddr;
	
	if ((mess->hops++) > 20)
	  continue;
	
	/* source address == relay address */
	from.addr4 = relay->local.addr4;

	/* already gatewayed ? */
	if (giaddr.s_addr)
	  {
	    /* if so check if by us, to stomp on loops. */
	    if (giaddr.s_addr == relay->local.addr4.s_addr)
	      continue;
	  }
	else
	  {
	    /* plug in our address */
	    mess->giaddr.s_addr = relay->local.addr4.s_addr;
	  }
	
	to.sa.sa_family = AF_INET;
	to.in.sin_addr = relay->server.addr4;
	to.in.sin_port = htons(relay->port);
	
	/* Broadcasting to server. */
	if (relay->server.addr4.s_addr == 0)
	  {
	    struct ifreq ifr;
	    
	    if (relay->interface)
	      safe_strncpy(ifr.ifr_name, relay->interface, IF_NAMESIZE);
	    
	    if (!relay->interface || strchr(relay->interface, '*') ||
		ioctl(daemon->dhcpfd, SIOCGIFBRDADDR, &ifr) == -1)
	      {
		my_syslog(MS_DHCP | LOG_ERR, _("Cannot broadcast DHCP relay via interface %s"), relay->interface);
		continue;
	      }
	    
	    to.in.sin_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
	  }
	
#ifdef HAVE_DUMPFILE
	{
	  union mysockaddr fromsock;
	  fromsock.in.sin_port = htons(daemon->dhcp_server_port);
	  fromsock.in.sin_addr = from.addr4;
	  fromsock.sa.sa_family = AF_INET;
	  
	  dump_packet(DUMP_DHCP, (void *)mess, sz, &fromsock, &to, 0);
	}
#endif
	
	 send_from(daemon->dhcpfd, 0, (char *)mess, sz, &to, &from, 0);
	 
	 if (option_bool(OPT_LOG_OPTS))
	   {
	     inet_ntop(AF_INET, &relay->local, daemon->addrbuff, ADDRSTRLEN);
	     if (relay->server.addr4.s_addr == 0)
	       snprintf(daemon->dhcp_buff2, DHCP_BUFF_SZ, _("broadcast via %s"), relay->interface);
	     else
	       inet_ntop(AF_INET, &relay->server.addr4, daemon->dhcp_buff2, DHCP_BUFF_SZ);
	     my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay at %s -> %s"), daemon->addrbuff, daemon->dhcp_buff2);
	   }
      }
  
  return 1;
}

/**
 * @brief Detect and validate relay server BOOTREPLY for proper interface forwarding
 *
 * @detailed
 * Identifies whether received packet is reply from upstream DHCP server destined for relay
 * client by checking giaddr field (must be non-zero) and BOOTREPLY opcode. Matches giaddr
 * against configured relay local addresses to find corresponding relay configuration, then
 * validates arrival interface matches relay interface wildcard pattern. Returns relay structure
 * with iface_index for proper client interface forwarding, or NULL if not valid relay reply.
 *
 * @param mess Pointer to received DHCP packet to check for relay reply characteristics
 * @param arrival_interface Name of interface on which packet arrived (for wildcard matching)
 *
 * @return Pointer to dhcp_relay structure for forwarding if valid relay reply, NULL otherwise
 * @retval NULL Packet is not relay reply (giaddr==0 or op!=BOOTREPLY), or relay not found/matched
 * @retval relay Pointer to matching relay with iface_index!=0 for client interface forwarding
 *
 * @note Returns NULL if giaddr is 0.0.0.0 (direct client packet, not relayed)
 * @note Returns NULL if op field is not BOOTREPLY (only server replies are relayed)
 * @note Returns NULL if relay->iface_index==0 (incomplete relay configuration)
 * @note Wildcard matching allows relay->interface like "eth*" to match "eth0", "eth1", etc.
 * @note giaddr matching ensures reply is for this relay agent (security check)
 *
 * @warning Returns NULL for invalid relay config even if giaddr matches (iface_index==0)
 *
 * @see dhcp_packet() Calls this to detect relay replies before normal processing (line 276)
 * @see relay_upstream4() Forwards client requests to relay servers
 * @see wildcard_match() in util.c Performs glob-style interface name matching
 * @see complete_context() Sets relay->iface_index during interface enumeration
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_relay *relay = relay_reply4(packet, "eth0");
 * if (relay) {
 *   // Valid relay reply, forward to client on relay->iface_index interface
 *   rcvd_iface_index = relay->iface_index;
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1542 Section 4 relay agent reply processing, validating giaddr matches
 * relay agent address and forwarding reply to correct client-facing interface. Also satisfies
 * RFC 2131 Section 4.1 relay requirements.
 *
 * SIDE EFFECTS:
 * - Read-only operation on packet and relay configuration
 * - No modifications to any structures
 * - Traverses daemon->relay4 linked list
 * - Calls wildcard_match() for interface name pattern matching
 *
 * THREAD SAFETY:
 * Reentrant. Read-only access to packet and daemon->relay4 configuration which is immutable
 * after configuration parsing. Safe for single-threaded event loop.
 */
static struct dhcp_relay *relay_reply4(struct dhcp_packet *mess, char *arrival_interface)
{
  struct dhcp_relay *relay;

  if (mess->giaddr.s_addr == 0 || mess->op != BOOTREPLY)
    return NULL;

  for (relay = daemon->relay4; relay; relay = relay->next)
    {
      if (mess->giaddr.s_addr == relay->local.addr4.s_addr)
	{
	  if (!relay->interface || wildcard_match(relay->interface, arrival_interface))
	    return relay->iface_index != 0 ? relay : NULL;
	}
    }
  
  return NULL;	 
}     

#endif
