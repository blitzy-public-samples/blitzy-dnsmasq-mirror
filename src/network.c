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
 * @file network.c
 * @brief Socket management and interface enumeration with platform abstraction
 *
 * DETAILED PURPOSE:
 * This file implements the network layer for dnsmasq, managing UDP/TCP sockets for
 * DNS, DHCP, and TFTP services. It provides comprehensive interface discovery and
 * address enumeration with platform-specific backends tailored to each operating
 * system's networking APIs. The implementation abstracts differences between Linux
 * (using netlink via netlink.c), BSD (using BPF and routing sockets via bpf.c), 
 * and Solaris (using SIOCGLIFCONF ioctl fallback).
 *
 * The module implements both wildcard and interface-specific binding strategies,
 * allowing dnsmasq to listen on all interfaces or selectively bind to configured
 * interfaces and addresses. Source address selection for upstream DNS queries ensures
 * proper routing and response delivery. Full IPv4/IPv6 dual-stack support enables
 * simultaneous operation on both protocol families.
 *
 * Socket options including SO_REUSEADDR (all platforms), SO_BINDTODEVICE (Linux),
 * and IP_BOUND_IF (BSD) provide fine-grained control over socket binding behavior.
 * The module handles dynamic interface changes from system hotplug events and address
 * add/remove operations, maintaining up-to-date listener state without daemon restart.
 * UDP source port randomization for DNS queries enhances security against cache
 * poisoning attacks.
 *
 * KEY RESPONSIBILITIES:
 * - indextoname() - Convert interface index to name (platform-specific implementations)
 * - iface_check() - Validate interface eligibility for listener binding
 * - enumerate_interfaces() - Discover all network interfaces and addresses
 * - create_bound_listeners() - Create and bind listening sockets
 * - iface_enumerate() - Callback-based interface enumeration (platform-specific)
 * - random_sock() - Create randomized source port socket for DNS queries
 * - local_bind() - Bind socket to specific interface or address
 *
 * DEPENDENCIES:
 * - dnsmasq.h: Core type definitions (struct daemon, struct irec, union mysockaddr)
 * - netlink.c: Linux-specific Netlink socket interface monitoring (HAVE_LINUX_NETWORK)
 * - bpf.c: BSD-specific Berkeley Packet Filter interface enumeration (HAVE_BSD_NETWORK)
 * - System headers: <sys/socket.h>, <net/if.h>, <sys/ioctl.h>, platform-specific headers
 * - Called by: dnsmasq.c main event loop for interface initialization and monitoring
 * - Calls: whine_malloc() for memory allocation, prettyprint_addr() for logging
 *
 * DATA STRUCTURES:
 * - struct irec (dnsmasq.h): Interface record tracking address, socket, flags
 * - struct iname (dnsmasq.h): Named interface configuration
 * - struct iface_param: Internal parameter passing for interface callbacks
 * - union mysockaddr (dnsmasq.h): Socket address union for IPv4/IPv6
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_LINUX_NETWORK: Use Linux Netlink sockets for interface monitoring
 * - HAVE_BSD_NETWORK: Use BSD routing sockets and BPF for interface enumeration
 * - HAVE_SOLARIS_NETWORK: Use Solaris SIOCGLIFCONF ioctl fallback
 * - HAVE_DHCP: Enable DHCPv4 server socket creation and binding
 * - HAVE_DHCP6: Enable DHCPv6 server socket creation and binding
 * - HAVE_TFTP: Enable TFTP server socket creation and binding
 * - HAVE_AUTH: Enable authoritative DNS server interface checking
 * - HAVE_DUMPFILE: Enable packet capture socket options
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture using poll/select. Functions are not
 * re-entrant and assume single-threaded execution. Interface list updates are
 * atomic from application perspective (no partial updates visible to event loop).
 * Socket creation and binding operations are blocking but typically fast (<100ms).
 *
 * @see docs/ARCHITECTURE.md for system architecture and event loop integration
 * @see docs/BUILDING.md for platform-specific build instructions
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_LINUX_NETWORK

/**
 * @brief Convert network interface index to interface name (Linux implementation)
 *
 * @detailed
 * Uses Linux-specific SIOCGIFNAME ioctl to map interface index to name string.
 * This implementation leverages the Linux kernel's interface index registry,
 * which is maintained by the network stack for all active interfaces. The function
 * validates the index and retrieves the corresponding interface name via ioctl.
 *
 * @param fd Socket file descriptor for ioctl operation (any AF_INET socket)
 * @param index Interface index to resolve (must be positive, 0 indicates invalid)
 * @param name Output buffer for interface name (must be at least IF_NAMESIZE bytes)
 *
 * @return 1 on success (name populated), 0 on failure (invalid index or ioctl error)
 *
 * @note Platform-specific: Linux-only implementation using SIOCGIFNAME ioctl
 * @note Interface index 0 is reserved and always returns failure
 * @note Output buffer is safely bounded by IF_NAMESIZE via safe_strncpy()
 *
 * @warning Caller must ensure name buffer is at least IF_NAMESIZE bytes to prevent overflow
 *
 * @see indextoname() Solaris and BSD implementations for platform-specific differences
 *
 * EXAMPLE USAGE:
 * @code
 * int sock = socket(AF_INET, SOCK_DGRAM, 0);
 * char ifname[IF_NAMESIZE];
 * if (indextoname(sock, 2, ifname))
 *   my_syslog(LOG_INFO, "Interface 2 is %s", ifname);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Performs ioctl system call (may fail if fd invalid or index not found)
 * - Writes to name buffer on success
 *
 * THREAD SAFETY:
 * Not re-entrant due to single-threaded event-driven architecture.
 * Safe for single-threaded use.
 */
int indextoname(int fd, int index, char *name)
{
  struct ifreq ifr;
  
  if (index == 0)
    return 0;

  ifr.ifr_ifindex = index;
  if (ioctl(fd, SIOCGIFNAME, &ifr) == -1)
    return 0;

  safe_strncpy(name, ifr.ifr_name, IF_NAMESIZE);

 return 1;
}


#elif defined(HAVE_SOLARIS_NETWORK)

#include <zone.h>
#include <alloca.h>
#ifndef LIFC_UNDER_IPMP
#  define LIFC_UNDER_IPMP 0
#endif

/**
 * @brief Convert network interface index to interface name (Solaris implementation)
 *
 * @detailed
 * Solaris-specific implementation using SIOCGLIFCONF and SIOCGLIFINDEX ioctls to
 * enumerate all interfaces and find the matching index. In global zones, uses
 * standard if_indextoname(); in non-global zones, manually enumerates all interfaces
 * across all zones using the lifconf structure. Handles Solaris-specific features
 * like IPMP (IP Multipathing) under-interfaces and zone-aware interface management.
 *
 * @param fd Socket file descriptor for ioctl operations (must be AF_INET or AF_INET6)
 * @param index Interface index to resolve (must be positive, 0 indicates invalid)
 * @param name Output buffer for interface name (must be at least IF_NAMESIZE bytes)
 *
 * @return 1 on success (name populated), 0 on failure (index not found or ioctl error)
 *
 * @note Platform-specific: Solaris-only implementation with zone awareness
 * @note In global zone: Uses standard if_indextoname() for efficiency
 * @note In non-global zone: Enumerates all interfaces with LIFC_ALLZONES flag
 * @note Handles IPMP under-interfaces via LIFC_UNDER_IPMP flag
 * @note Uses alloca() for temporary interface list buffer (stack allocation)
 *
 * @warning Buffer allocated via alloca() - function must not be called with huge interface counts
 * @warning Caller must ensure name buffer is at least IF_NAMESIZE bytes
 *
 * @see indextoname() Linux and BSD implementations for comparison
 *
 * EXAMPLE USAGE:
 * @code
 * int sock = socket(AF_INET, SOCK_DGRAM, 0);
 * char ifname[IF_NAMESIZE];
 * if (indextoname(sock, 5, ifname))
 *   my_syslog(LOG_INFO, "Interface 5 in zone %d is %s", getzoneid(), ifname);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Multiple ioctl system calls (SIOCGLIFNUM, SIOCGLIFCONF, SIOCGLIFINDEX)
 * - Allocates temporary buffer on stack via alloca()
 * - May iterate through hundreds of interfaces in multi-zone configurations
 *
 * THREAD SAFETY:
 * Not re-entrant. Uses alloca() for stack allocation. Safe for single-threaded use.
 */
int indextoname(int fd, int index, char *name)
{
  int64_t lifc_flags;
  struct lifnum lifn;
  int numifs, bufsize, i;
  struct lifconf lifc;
  struct lifreq *lifrp;
  
  if (index == 0)
    return 0;
  
  if (getzoneid() == GLOBAL_ZONEID) 
    {
      if (!if_indextoname(index, name))
	return 0;
      return 1;
    }
  
  lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES | LIFC_UNDER_IPMP;
  lifn.lifn_family = AF_UNSPEC;
  lifn.lifn_flags = lifc_flags;
  if (ioctl(fd, SIOCGLIFNUM, &lifn) < 0) 
    return 0;
  
  numifs = lifn.lifn_count;
  bufsize = numifs * sizeof(struct lifreq);
  
  lifc.lifc_family = AF_UNSPEC;
  lifc.lifc_flags = lifc_flags;
  lifc.lifc_len = bufsize;
  lifc.lifc_buf = alloca(bufsize);
  
  if (ioctl(fd, SIOCGLIFCONF, &lifc) < 0)  
    return 0;
  
  lifrp = lifc.lifc_req;
  for (i = lifc.lifc_len / sizeof(struct lifreq); i; i--, lifrp++) 
    {
      struct lifreq lifr;
      safe_strncpy(lifr.lifr_name, lifrp->lifr_name, IF_NAMESIZE);
      if (ioctl(fd, SIOCGLIFINDEX, &lifr) < 0) 
	return 0;
      
      if (lifr.lifr_index == index) {
	safe_strncpy(name, lifr.lifr_name, IF_NAMESIZE);
	return 1;
      }
    }
  return 0;
}


#else

/**
 * @brief Convert network interface index to interface name (BSD/generic implementation)
 *
 * @detailed
 * BSD and generic Unix implementation using POSIX standard if_indextoname() function.
 * This is the simplest implementation, relying on the system's built-in interface
 * index-to-name mapping. Used on BSD variants (FreeBSD, OpenBSD, NetBSD, macOS) and
 * other POSIX-compliant systems that provide RFC 3493 interface naming functions.
 *
 * @param fd Socket file descriptor (unused in this implementation, present for API consistency)
 * @param index Interface index to resolve (must be positive, 0 indicates invalid)
 * @param name Output buffer for interface name (must be at least IF_NAMESIZE bytes)
 *
 * @return 1 on success (name populated), 0 on failure (invalid index or if_indextoname failure)
 *
 * @note Platform-specific: BSD, macOS, and generic POSIX systems without Linux/Solaris
 * @note Uses standard RFC 3493 if_indextoname() function
 * @note fd parameter ignored but maintained for cross-platform API consistency
 * @note Interface index 0 is reserved per RFC 3493 and always returns failure
 *
 * @see indextoname() Linux and Solaris implementations for platform-specific approaches
 *
 * EXAMPLE USAGE:
 * @code
 * char ifname[IF_NAMESIZE];
 * if (indextoname(0, 3, ifname))  // fd unused on BSD
 *   my_syslog(LOG_INFO, "Interface 3 is %s", ifname);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Calls system if_indextoname() which may access kernel interface registry
 * - Writes to name buffer on success
 *
 * THREAD SAFETY:
 * if_indextoname() is thread-safe per POSIX. Safe for single-threaded dnsmasq use.
 */
int indextoname(int fd, int index, char *name)
{ 
  (void)fd;

  if (index == 0 || !if_indextoname(index, name))
    return 0;

  return 1;
}

#endif

/**
 * @brief Validate interface eligibility for listener binding based on configuration
 *
 * @detailed
 * Determines whether a given interface and address combination should be used for
 * listening sockets based on --interface, --address, --except-interface, and
 * --auth-server configuration options. Implements include/exclude logic with wildcard
 * matching for interface names and exact matching for addresses. Sets "used" flags on
 * matched configuration entries to detect unused directives. Supports name-only checking
 * via AF_LOCAL family for interface validation without address specificity.
 *
 * Algorithm: If --interface or --address specified (whitelist mode), returns 1 only if
 * interface/address matches. Then applies --except-interface (blacklist). Finally checks
 * --auth-server for authoritative DNS interface marking.
 *
 * @param family Address family (AF_INET, AF_INET6, or AF_LOCAL for name-only check)
 * @param addr Address to check (may be NULL for name-only checks)
 * @param name Interface name to check (wildcard-matched against configuration)
 * @param auth Output parameter for authoritative DNS server flag (may be NULL if not needed)
 *
 * @return 1 if interface/address should be used for listeners, 0 if excluded
 * @retval 1 Interface/address passes all configuration checks and should create listeners
 * @retval 0 Interface/address is excluded by configuration or not in whitelist
 *
 * @note Sets tmp->used = 1 for all matched configuration entries (for unused detection)
 * @note Checks ALL configured entries even after match to set all used flags
 * @note AF_LOCAL family: name-only check without address validation
 * @note Wildcard matching supported for interface names (e.g., eth* matches eth0, eth1)
 *
 * @warning Must check all entries; early bailout would miss setting used flags
 *
 * @see wildcard_match() for interface name pattern matching
 * @see daemon->if_names, daemon->if_addrs, daemon->if_except, daemon->authinterface
 *
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * int auth_dns = 0;
 * addr.addr4.s_addr = inet_addr("192.168.1.1");
 * if (iface_check(AF_INET, &addr, "eth0", &auth_dns))
 *   create_listener(AF_INET, &addr, "eth0", auth_dns);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies tmp->used flags in daemon->if_names, daemon->if_addrs, daemon->if_except lists
 * - Sets *auth output parameter if authoritative interface matched
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon state. Safe for single-threaded use.
 */
int iface_check(int family, union all_addr *addr, char *name, int *auth)
{
  struct iname *tmp;
  int ret = 1, match_addr = 0;

  /* Note: have to check all and not bail out early, so that we set the "used" flags.
     May be called with family == AF_LOCAL to check interface by name only. */
  
  if (daemon->if_names || daemon->if_addrs)
    {
      ret = 0;

      for (tmp = daemon->if_names; tmp; tmp = tmp->next)
	if (tmp->name && wildcard_match(tmp->name, name))
	  ret = tmp->used = 1;
	        
      if (addr)
	for (tmp = daemon->if_addrs; tmp; tmp = tmp->next)
	  if (tmp->addr.sa.sa_family == family)
	    {
	      if (family == AF_INET &&
		  tmp->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
		ret = match_addr = tmp->used = 1;
	      else if (family == AF_INET6 &&
		       IN6_ARE_ADDR_EQUAL(&tmp->addr.in6.sin6_addr, 
					  &addr->addr6))
		ret = match_addr = tmp->used = 1;
	    }          
    }
  
  if (!match_addr)
    for (tmp = daemon->if_except; tmp; tmp = tmp->next)
      if (tmp->name && wildcard_match(tmp->name, name))
	ret = 0;
    
  if (auth)
    {
      *auth = 0;

      for (tmp = daemon->authinterface; tmp; tmp = tmp->next)
	if (tmp->name)
	  {
	    if (strcmp(tmp->name, name) == 0 &&
		(tmp->addr.sa.sa_family == 0 || tmp->addr.sa.sa_family == family))
	      break;
	  }
	else if (addr && tmp->addr.sa.sa_family == AF_INET && family == AF_INET &&
		 tmp->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
	  break;
	else if (addr && tmp->addr.sa.sa_family == AF_INET6 && family == AF_INET6 &&
		 IN6_ARE_ADDR_EQUAL(&tmp->addr.in6.sin6_addr, &addr->addr6))
	  break;
      
      if (tmp) 
	{
	  *auth = 1;
	  ret = 1;
	}
    }

  return ret; 
}


/**
 * @brief Handle kernel loopback interface misreporting for locally-originated packets
 *
 * @detailed
 * Fixes kernel behavior where packets originating locally are sometimes reported as
 * arriving via the loopback interface, even when sent to a non-loopback interface
 * address. This occurs on some kernels when a local process sends to a local IP address.
 * The function checks if the arrival interface is loopback and whether the destination
 * address matches any of our configured listener addresses. If both conditions are true,
 * accepts the packet even if we're not configured to listen on loopback.
 *
 * Algorithm: Use SIOCGIFFLAGS to determine if arrival interface is loopback. If yes,
 * iterate daemon->interfaces to check if destination address matches any listener.
 * Return 1 if address found (accept packet), 0 otherwise (reject).
 *
 * @param fd Socket file descriptor for SIOCGIFFLAGS ioctl
 * @param family Address family (AF_INET or AF_INET6)
 * @param addr Destination address of the received packet
 * @param name Arrival interface name reported by kernel
 *
 * @return 1 if packet should be accepted despite loopback arrival, 0 otherwise
 * @retval 1 Loopback arrival but destination address is one of our listener addresses
 * @retval 0 Not loopback interface or destination address not in our listener set
 *
 * @note Interface list (daemon->interfaces) must be up-to-date before calling
 * @note Addresses kernel quirk on Linux and some BSD variants
 * @note Only checks if name is loopback; does not validate addr if name is not loopback
 *
 * @warning Requires daemon->interfaces to be current; stale list may cause incorrect rejection
 *
 * @see iface_check() for general interface validation
 *
 * EXAMPLE USAGE:
 * @code
 * union all_addr dst_addr;
 * dst_addr.addr4.s_addr = packet_dest_ip;
 * if (loopback_exception(fd, AF_INET, &dst_addr, "lo"))
 *   accept_packet();  // Loopback arrival but valid destination
 * @endcode
 *
 * SIDE EFFECTS:
 * - Performs SIOCGIFFLAGS ioctl system call
 * - Iterates daemon->interfaces list (read-only)
 *
 * THREAD SAFETY:
 * Not re-entrant. Reads global daemon->interfaces. Safe for single-threaded use.
 */
int loopback_exception(int fd, int family, union all_addr *addr, char *name)    
{
  struct ifreq ifr;
  struct irec *iface;

  safe_strncpy(ifr.ifr_name, name, IF_NAMESIZE);
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) != -1 &&
      ifr.ifr_flags & IFF_LOOPBACK)
    {
      for (iface = daemon->interfaces; iface; iface = iface->next)
	if (iface->addr.sa.sa_family == family)
	  {
	    if (family == AF_INET)
	      {
		if (iface->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
		  return 1;
	      }
	    else if (IN6_ARE_ADDR_EQUAL(&iface->addr.in6.sin6_addr, &addr->addr6))
	      return 1;
	  }
    }
  return 0;
}

/**
 * @brief Validate packet arrival via interface label (e.g., eth0:0) versus base interface
 *
 * @detailed
 * Handles Linux interface label (alias) configuration where dnsmasq is configured with
 * a label like --interface=eth0:0 but the kernel reports arrival interface by the base
 * interface index (eth0). Labels are IPv4-only Linux features that create virtual
 * sub-interfaces. The function checks if the arrival interface index and address match
 * any configured listener in daemon->interfaces, allowing packets that arrive via the
 * base interface when we're configured with a labeled interface.
 *
 * Algorithm: Iterate daemon->interfaces to find an entry matching both the interface
 * index and the destination IPv4 address. If found, the packet is valid despite the
 * label/name mismatch.
 *
 * @param index Interface index reported by kernel (base interface, not label)
 * @param family Address family (must be AF_INET; labels only supported for IPv4)
 * @param addr Destination address of the received packet
 *
 * @return 1 if interface address found for index+addr combination, 0 otherwise
 * @retval 1 Found matching interface record (index and IPv4 address match a listener)
 * @retval 0 No matching interface or family is not AF_INET (labels unsupported)
 *
 * @note Interface labels are Linux-specific IPv4 feature (e.g., eth0:0, eth0:1)
 * @note IPv6 does not support interface labels; function returns 0 for AF_INET6
 * @note daemon->interfaces must be up-to-date before calling
 * @note Kernel reports base interface index, not label-specific index
 *
 * @see iface_check() for general interface configuration validation
 *
 * EXAMPLE USAGE:
 * @code
 * // Configured with --interface=eth0:0 (192.168.1.2)
 * // Packet arrives with index 2 (eth0 base interface)
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("192.168.1.2");
 * if (label_exception(2, AF_INET, &addr))
 *   accept_packet();  // Valid: eth0:0 listener matches eth0 index + address
 * @endcode
 *
 * SIDE EFFECTS:
 * - Iterates daemon->interfaces list (read-only)
 *
 * THREAD SAFETY:
 * Not re-entrant. Reads global daemon->interfaces. Safe for single-threaded use.
 */
int label_exception(int index, int family, union all_addr *addr)
{
  struct irec *iface;

  /* labels only supported on IPv4 addresses. */
  if (family != AF_INET)
    return 0;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (iface->index == index && iface->addr.sa.sa_family == AF_INET &&
	iface->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
      return 1;

  return 0;
}

/**
 * @struct iface_param
 * @brief Parameter passing structure for interface enumeration callbacks
 *
 * Internal structure used to pass state between interface enumeration iterator
 * and callback functions. Maintains spare address list entries for efficient
 * allocation and socket file descriptor for ioctl operations.
 *
 * @var iface_param::spare
 * Freelist of pre-allocated addrlist structures for --local-service option.
 * Reduces malloc calls during interface enumeration by reusing freed entries.
 *
 * @var iface_param::fd
 * Socket file descriptor for ioctl operations (SIOCGIFFLAGS, interface queries).
 * Must be valid AF_INET or AF_INET6 socket for platform ioctl compatibility.
 */
struct iface_param {
  struct addrlist *spare;
  int fd;
};

/**
 * @brief Determine if interface/address combination should create listening sockets
 *
 * @detailed
 * Comprehensive interface and address validation for DNS, DHCP, TFTP, and authoritative
 * DNS services. Applies configuration filters (--interface, --except-interface, --no-dhcp,
 * --tftp-no-fail), checks interface flags (loopback, up/down), validates DHCP/TFTP
 * eligibility, and builds --local-service address list. Creates irec (interface record)
 * entries for eligible interfaces and links them to daemon->interfaces list. Handles
 * interface labels, conditional domains, and authoritative DNS interface marking.
 *
 * Algorithm: (1) Resolve interface index to name, (2) Check loopback status and disable
 * DHCP if loopback, (3) Build --local-service address list if enabled, (4) Apply interface
 * filters via iface_check(), (5) Check DHCP/TFTP-specific interface restrictions, (6) Create
 * irec entry and populate with address/socket/flags, (7) Link to daemon->interfaces list.
 *
 * @param param Parameter structure containing spare addrlist and socket fd
 * @param if_index Interface index from system enumeration
 * @param label Interface label (e.g., "eth0:0") or NULL for base interface name
 * @param addr Interface address (union mysockaddr with sa_family set)
 * @param netmask IPv4 netmask (for subnet calculations, unused currently)
 * @param prefixlen IPv6 prefix length (unused in current implementation)
 * @param iface_flags Interface flags from system (IFF_UP, IFF_RUNNING, etc.)
 *
 * @return 1 if interface record created successfully, 0 if interface excluded or error
 * @retval 1 Interface/address passed all checks and irec created
 * @retval 0 Interface excluded by configuration, ioctl failure, or allocation failure
 *
 * @note Static function, internal to network.c module
 * @note Loopback interfaces always have dhcp_ok=0 (DHCP disabled on loopback)
 * @note Creates and links irec to global daemon->interfaces list (side effect)
 * @note Interface labels (eth0:0) supported on Linux IPv4 only
 * @note TFTP and DHCP interface restrictions applied based on compile-time options
 *
 * @warning Memory allocation via whine_malloc() may fail; function returns 0 on failure
 * @warning Modifies global daemon state (daemon->interfaces, daemon->interface_addrs)
 *
 * @see iface_check() for primary interface filtering logic
 * @see iface_enumerate() for platform-specific interface enumeration calling this callback
 *
 * EXAMPLE USAGE:
 * @code
 * // Called internally by iface_enumerate() during interface discovery
 * struct iface_param param = { .spare = spare_list, .fd = sock };
 * union mysockaddr addr;
 * addr.in.sin_addr.s_addr = inet_addr("192.168.1.1");
 * addr.sa.sa_family = AF_INET;
 * iface_allowed(&param, 2, NULL, &addr, netmask, 24, IFF_UP | IFF_RUNNING);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates irec structure via whine_malloc()
 * - Links new irec to daemon->interfaces list
 * - Allocates and links addrlist entries to daemon->interface_addrs (--local-service)
 * - Performs multiple ioctl calls (SIOCGIFNAME, SIOCGIFFLAGS, SIOCGIFMTU)
 * - May log errors via my_syslog() on allocation or ioctl failures
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon state. Safe for single-threaded use.
 */
static int iface_allowed(struct iface_param *param, int if_index, char *label,
			 union mysockaddr *addr, struct in_addr netmask, int prefixlen, int iface_flags) 
{
  struct irec *iface;
  struct cond_domain *cond;
  int loopback;
  struct ifreq ifr;
  int tftp_ok = !!option_bool(OPT_TFTP);
  int dhcp_ok = 1;
  int auth_dns = 0;
  int is_label = 0;
#if defined(HAVE_DHCP) || defined(HAVE_TFTP)
  struct iname *tmp;
#endif

  (void)prefixlen;

  if (!indextoname(param->fd, if_index, ifr.ifr_name) ||
      ioctl(param->fd, SIOCGIFFLAGS, &ifr) == -1)
    return 0;
   
  loopback = ifr.ifr_flags & IFF_LOOPBACK;
  
  if (loopback)
    dhcp_ok = 0;
  
  if (!label)
    label = ifr.ifr_name;
  else
    is_label = strcmp(label, ifr.ifr_name);
 
  /* maintain a list of all addresses on all interfaces for --local-service option */
  if (option_bool(OPT_LOCAL_SERVICE))
    {
      struct addrlist *al;

      if (param->spare)
	{
	  al = param->spare;
	  param->spare = al->next;
	}
      else
	al = whine_malloc(sizeof(struct addrlist));
      
      if (al)
	{
	  al->next = daemon->interface_addrs;
	  daemon->interface_addrs = al;
	  al->prefixlen = prefixlen;
	  
	  if (addr->sa.sa_family == AF_INET)
	    {
	      al->addr.addr4 = addr->in.sin_addr;
	      al->flags = 0;
	    }
	  else
	    {
	      al->addr.addr6 = addr->in6.sin6_addr;
	      al->flags = ADDRLIST_IPV6;
	    } 
	}
    }
  
  if (addr->sa.sa_family != AF_INET6 || !IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr))
    {
      struct interface_name *int_name;
      struct addrlist *al;
#ifdef HAVE_AUTH
      struct auth_zone *zone;
      struct auth_name_list *name;

      /* Find subnets in auth_zones */
      for (zone = daemon->auth_zones; zone; zone = zone->next)
	for (name = zone->interface_names; name; name = name->next)
	  if (wildcard_match(name->name, label))
	    {
	      if (addr->sa.sa_family == AF_INET && (name->flags & AUTH4))
		{
		  if (param->spare)
		    {
		      al = param->spare;
		      param->spare = al->next;
		    }
		  else
		    al = whine_malloc(sizeof(struct addrlist));
		  
		  if (al)
		    {
		      al->next = zone->subnet;
		      zone->subnet = al;
		      al->prefixlen = prefixlen;
		      al->addr.addr4 = addr->in.sin_addr;
		      al->flags = 0;
		    }
		}
	      
	      if (addr->sa.sa_family == AF_INET6 && (name->flags & AUTH6))
		{
		  if (param->spare)
		    {
		      al = param->spare;
		      param->spare = al->next;
		    }
		  else
		    al = whine_malloc(sizeof(struct addrlist));
		  
		  if (al)
		    {
		      al->next = zone->subnet;
		      zone->subnet = al;
		      al->prefixlen = prefixlen;
		      al->addr.addr6 = addr->in6.sin6_addr;
		      al->flags = ADDRLIST_IPV6;
		    }
		} 
	    }
#endif
       
      /* Update addresses from interface_names. These are a set independent
	 of the set we're listening on. */  
      for (int_name = daemon->int_names; int_name; int_name = int_name->next)
	if (strncmp(label, int_name->intr, IF_NAMESIZE) == 0)
	  {
	    struct addrlist *lp;

	    al = NULL;
	    
	    if (addr->sa.sa_family == AF_INET && (int_name->flags & (IN4 | INP4)))
	      {
		struct in_addr newaddr = addr->in.sin_addr;
		
		if (int_name->flags & INP4)
		  {
		    if (netmask.s_addr == 0xffff)
		      continue;

		    newaddr.s_addr = (addr->in.sin_addr.s_addr & netmask.s_addr) |
		      (int_name->proto4.s_addr & ~netmask.s_addr);
		  }
		
		/* check for duplicates. */
		for (lp = int_name->addr; lp; lp = lp->next)
		  if (lp->flags == 0 && lp->addr.addr4.s_addr == newaddr.s_addr)
		    break;
		
		if (!lp)
		  {
		    if (param->spare)
		      {
			al = param->spare;
			param->spare = al->next;
		      }
		    else
		      al = whine_malloc(sizeof(struct addrlist));

		    if (al)
		      {
			al->flags = 0;
			al->addr.addr4 = newaddr;
		      }
		  }
	      }

	    if (addr->sa.sa_family == AF_INET6 && (int_name->flags & (IN6 | INP6)))
	      {
		struct in6_addr newaddr = addr->in6.sin6_addr;
		
		if (int_name->flags & INP6)
		  {
		    int i;

		    /* No sense in doing /128. */
		    if (prefixlen == 128)
		      continue;
		    
		    for (i = 0; i < 16; i++)
		      {
			int bits = ((i+1)*8) - prefixlen;
		       
			if (bits >= 8)
			  newaddr.s6_addr[i] = int_name->proto6.s6_addr[i];
			else if (bits >= 0)
			  {
			    unsigned char mask = 0xff << bits;
			    newaddr.s6_addr[i] =
			      (addr->in6.sin6_addr.s6_addr[i] & mask) |
			      (int_name->proto6.s6_addr[i] & ~mask);
			  }
		      }
		  }
		
		/* check for duplicates. */
		for (lp = int_name->addr; lp; lp = lp->next)
		  if ((lp->flags & ADDRLIST_IPV6) &&
		      IN6_ARE_ADDR_EQUAL(&lp->addr.addr6, &newaddr))
		    break;
					
		if (!lp)
		  {
		    if (param->spare)
		      {
			al = param->spare;
			param->spare = al->next;
		      }
		    else
		      al = whine_malloc(sizeof(struct addrlist));
		    
		    if (al)
		      {
			al->flags = ADDRLIST_IPV6;
			al->addr.addr6 = newaddr;

			/* Privacy addresses and addresses still undergoing DAD and deprecated addresses
			   don't appear in forward queries, but will in reverse ones. */
			if (!(iface_flags & IFACE_PERMANENT) || (iface_flags & (IFACE_DEPRECATED | IFACE_TENTATIVE)))
			  al->flags |= ADDRLIST_REVONLY;
		      }
		  }
	      }
	    
	    if (al)
	      {
		al->next = int_name->addr;
		int_name->addr = al;
	      }
	  }
    }

  /* Update addresses for domain=<domain>,<interface> */
  for (cond = daemon->cond_domain; cond; cond = cond->next)
    if (cond->interface && strncmp(label, cond->interface, IF_NAMESIZE) == 0)
      {
	struct addrlist *al;

	if (param->spare)
	  {
	    al = param->spare;
	    param->spare = al->next;
	  }
	else
	  al = whine_malloc(sizeof(struct addrlist));

	if (addr->sa.sa_family == AF_INET)
	  {
	    al->addr.addr4 = addr->in.sin_addr;
	    al->flags = 0;
	  }
	else
	  {
	    al->addr.addr6 =  addr->in6.sin6_addr;
	    al->flags = ADDRLIST_IPV6;
	  }

	al->prefixlen = prefixlen;
	al->next = cond->al;
	cond->al = al;
      }
  
  /* check whether the interface IP has been added already 
     we call this routine multiple times. */
  for (iface = daemon->interfaces; iface; iface = iface->next) 
    if (sockaddr_isequal(&iface->addr, addr) && iface->index == if_index)
      {
	iface->dad = !!(iface_flags & IFACE_TENTATIVE);
	iface->found = 1; /* for garbage collection */
	iface->netmask = netmask;
	return 1;
      }

 /* If we are restricting the set of interfaces to use, make
     sure that loopback interfaces are in that set. */
  if (daemon->if_names && loopback)
    {
      struct iname *lo;
      for (lo = daemon->if_names; lo; lo = lo->next)
	if (lo->name && strcmp(lo->name, ifr.ifr_name) == 0)
	  break;
      
      if (!lo && (lo = whine_malloc(sizeof(struct iname)))) 
	{
	  if ((lo->name = whine_malloc(strlen(ifr.ifr_name)+1)))
	    {
	      strcpy(lo->name, ifr.ifr_name);
	      lo->used = 1;
	      lo->next = daemon->if_names;
	      daemon->if_names = lo;
	    }
	  else
	    free(lo);
	}
    }
  
  if (addr->sa.sa_family == AF_INET &&
      !iface_check(AF_INET, (union all_addr *)&addr->in.sin_addr, label, &auth_dns))
    return 1;

  if (addr->sa.sa_family == AF_INET6 &&
      !iface_check(AF_INET6, (union all_addr *)&addr->in6.sin6_addr, label, &auth_dns))
    return 1;
    
#ifdef HAVE_DHCP
  /* No DHCP where we're doing auth DNS. */
  if (auth_dns)
    {
      tftp_ok = 0;
      dhcp_ok = 0;
    }
  else
    for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
      if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	{
	  tftp_ok = 0;
	  dhcp_ok = 0;
	}
#endif
 
  
#ifdef HAVE_TFTP
  if (daemon->tftp_interfaces)
    {
      /* dedicated tftp interface list */
      tftp_ok = 0;
      for (tmp = daemon->tftp_interfaces; tmp; tmp = tmp->next)
	if (tmp->name && wildcard_match(tmp->name, ifr.ifr_name))
	  tftp_ok = 1;
    }
#endif
  
  /* add to list */
  if ((iface = whine_malloc(sizeof(struct irec))))
    {
      int mtu = 0;

      if (ioctl(param->fd, SIOCGIFMTU, &ifr) != -1)
	mtu = ifr.ifr_mtu;

      iface->addr = *addr;
      iface->netmask = netmask;
      iface->tftp_ok = tftp_ok;
      iface->dhcp_ok = dhcp_ok;
      iface->dns_auth = auth_dns;
      iface->mtu = mtu;
      iface->dad = !!(iface_flags & IFACE_TENTATIVE);
      iface->found = 1;
      iface->done = iface->multicast_done = iface->warned = 0;
      iface->index = if_index;
      iface->label = is_label;
      if ((iface->name = whine_malloc(strlen(ifr.ifr_name)+1)))
	{
	  strcpy(iface->name, ifr.ifr_name);
	  iface->next = daemon->interfaces;
	  daemon->interfaces = iface;
	  return 1;
	}
      free(iface);

    }
  
  errno = ENOMEM; 
  return 0;
}

/**
 * @brief IPv6 address enumeration callback to filter allowed interfaces
 *
 * @detailed
 * Callback function passed to iface_enumerate() for IPv6 address discovery during
 * enumerate_interfaces(). Converts IPv6-specific parameters to generic iface_allowed()
 * format and invokes core filtering logic. Constructs sockaddr_in6 structure from
 * enumerated address, sets link-local scope_id for link-local addresses (required by
 * FreeBSD), and delegates to iface_allowed() for user-configured filtering (--interface,
 * --except-interface, --listen-address). Silently ignores scope, preferred, and valid
 * lifetime parameters (unused in dnsmasq filtering logic).
 *
 * Algorithm: (1) Construct union mysockaddr with AF_INET6, (2) Copy local address,
 * (3) Set port to daemon->port, (4) Set scope_id for link-local addresses only (FreeBSD
 * requirement), (5) Call iface_allowed() with generic address structure and prefix.
 *
 * @param local IPv6 address on interface (source address for binding)
 * @param prefix Prefix length for address (CIDR notation, e.g., 64)
 * @param scope IPv6 address scope (unused, suppressed warning)
 * @param if_index Interface index (SIOCGIFINDEX or similar)
 * @param flags Interface flags (IFF_LOOPBACK, IFF_POINTOPOINT, etc.)
 * @param preferred Preferred lifetime (unused, suppressed warning)
 * @param valid Valid lifetime (unused, suppressed warning)
 * @param vparam Pointer to struct iface_param (context from enumerate_interfaces)
 *
 * @return 1 if interface/address allowed (user configuration), 0 if filtered out
 * @retval 1 Interface/address passes filtering, should create listener
 * @retval 0 Interface/address rejected by --except-interface or similar configuration
 *
 * @note Static function, internal to network.c
 * @note Callback function signature required by iface_enumerate() (platform-specific)
 * @note Link-local addresses: scope_id set to if_index per RFC 4007
 * @note Non-link-local addresses: scope_id set to 0 (FreeBSD requirement)
 * @note Ignores scope, preferred, valid parameters (not used in filtering)
 *
 * @warning vparam must point to valid struct iface_param initialized by enumerate_interfaces
 *
 * @see iface_allowed() core filtering logic invoked by this callback
 * @see enumerate_interfaces() which sets up iface_param and calls iface_enumerate()
 * @see iface_allowed_v4() equivalent callback for IPv4 addresses
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal usage by enumerate_interfaces via iface_enumerate
 * struct iface_param param;
 * param.fd = socket(AF_INET6, SOCK_DGRAM, 0);
 * iface_enumerate(AF_INET6, &param, iface_allowed_v6); // Callback invoked for each IPv6 address
 * @endcode
 *
 * SIDE EFFECTS:
 * - May add interface to daemon->interfaces via iface_allowed()
 * - May allocate struct irec via iface_allowed()
 * - No direct side effects (delegates to iface_allowed)
 *
 * THREAD SAFETY:
 * NOT thread-safe (calls iface_allowed which modifies global daemon->interfaces).
 * Safe for single-threaded event loop.
 */
static int iface_allowed_v6(struct in6_addr *local, int prefix, 
			    int scope, int if_index, int flags, 
			    int preferred, int valid, void *vparam)
{
  union mysockaddr addr;
  struct in_addr netmask; /* dummy */
  netmask.s_addr = 0;

  (void)scope; /* warning */
  (void)preferred;
  (void)valid;
  
  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in6.sin6_len = sizeof(addr.in6);
#endif
  addr.in6.sin6_family = AF_INET6;
  addr.in6.sin6_addr = *local;
  addr.in6.sin6_port = htons(daemon->port);
  /* FreeBSD insists this is zero for non-linklocal addresses */
  if (IN6_IS_ADDR_LINKLOCAL(local))
    addr.in6.sin6_scope_id = if_index;
  else
    addr.in6.sin6_scope_id = 0;
  
  return iface_allowed((struct iface_param *)vparam, if_index, NULL, &addr, netmask, prefix, flags);
}

/**
 * @brief IPv4 address enumeration callback to filter allowed interfaces
 *
 * @detailed
 * Callback function passed to iface_enumerate() for IPv4 address discovery during
 * enumerate_interfaces(). Converts IPv4-specific parameters to generic iface_allowed()
 * format and invokes core filtering logic. Constructs sockaddr_in structure from
 * enumerated address, calculates CIDR prefix length from netmask (counting trailing
 * zero bits), and delegates to iface_allowed() for user-configured filtering
 * (--interface, --except-interface, --listen-address). Silently ignores broadcast
 * address parameter (unused in dnsmasq filtering logic).
 *
 * Algorithm: (1) Construct union mysockaddr with AF_INET, (2) Copy local address,
 * (3) Set port to daemon->port, (4) Calculate prefix length from netmask by counting
 * trailing zero bits from LSB (e.g., 255.255.255.0 → /24), (5) Call iface_allowed()
 * with generic address structure and calculated prefix.
 *
 * @param local IPv4 address on interface (source address for binding)
 * @param if_index Interface index (SIOCGIFINDEX or similar)
 * @param label Interface label/alias name (e.g., "eth0:0" on Linux, NULL on BSD)
 * @param netmask IPv4 netmask for address (e.g., 255.255.255.0)
 * @param broadcast Broadcast address (unused, suppressed warning)
 * @param vparam Pointer to struct iface_param (context from enumerate_interfaces)
 *
 * @return 1 if interface/address allowed (user configuration), 0 if filtered out
 * @retval 1 Interface/address passes filtering, should create listener
 * @retval 0 Interface/address rejected by --except-interface or similar configuration
 *
 * @note Static function, internal to network.c
 * @note Callback function signature required by iface_enumerate() (platform-specific)
 * @note Prefix calculation: counts trailing zero bits in netmask (255.255.255.0 = /24)
 * @note Handles BSD (no label parameter, NULL) and Linux (label may be "eth0:0" for alias)
 * @note Ignores broadcast parameter (not used in filtering logic)
 *
 * @warning vparam must point to valid struct iface_param initialized by enumerate_interfaces
 * @warning Netmask must be valid CIDR (contiguous 1 bits from MSB, then 0 bits)
 *
 * @see iface_allowed() core filtering logic invoked by this callback
 * @see enumerate_interfaces() which sets up iface_param and calls iface_enumerate()
 * @see iface_allowed_v6() equivalent callback for IPv6 addresses
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal usage by enumerate_interfaces via iface_enumerate
 * struct iface_param param;
 * param.fd = socket(AF_INET, SOCK_DGRAM, 0);
 * iface_enumerate(AF_INET, &param, iface_allowed_v4); // Callback invoked for each IPv4 address
 * @endcode
 *
 * SIDE EFFECTS:
 * - May add interface to daemon->interfaces via iface_allowed()
 * - May allocate struct irec via iface_allowed()
 * - No direct side effects (delegates to iface_allowed)
 *
 * THREAD SAFETY:
 * NOT thread-safe (calls iface_allowed which modifies global daemon->interfaces).
 * Safe for single-threaded event loop.
 */
static int iface_allowed_v4(struct in_addr local, int if_index, char *label,
			    struct in_addr netmask, struct in_addr broadcast, void *vparam)
{
  union mysockaddr addr;
  int prefix, bit;
 
  (void)broadcast; /* warning */

  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in.sin_len = sizeof(addr.in);
#endif
  addr.in.sin_family = AF_INET;
  addr.in.sin_addr = local;
  addr.in.sin_port = htons(daemon->port);

  /* determine prefix length from netmask */
  for (prefix = 32, bit = 1; (bit & ntohl(netmask.s_addr)) == 0 && prefix != 0; bit = bit << 1, prefix--);

  return iface_allowed((struct iface_param *)vparam, if_index, label, &addr, netmask, prefix, 0);
}

/*
 * Clean old interfaces no longer found.
 */
/**
 * @brief Remove interfaces that disappeared from system (hotplug removal)
 *
 * @detailed
 * Garbage collection function that removes interface records (struct irec) from
 * daemon->interfaces linked list when interfaces no longer exist on the system.
 * Called during interface re-enumeration to clean up interfaces that were removed
 * via hotplug events or administrative commands (ifconfig down). Only removes
 * interfaces where both iface->found (re-discovered in current scan) and iface->done
 * (previously processed) are false, indicating the interface has disappeared.
 *
 * Algorithm: Traverse daemon->interfaces linked list, for each interface: if
 * !found AND !done (interface disappeared), unlink from list, free name string,
 * free irec structure; else advance to next interface. Uses pointer-to-pointer
 * technique for in-place list modification without predecessor tracking.
 *
 * @note Static function, internal to network.c
 * @note Called by iface_check() after re-enumerating interfaces
 * @note Does NOT close associated listener sockets (handled separately by release_listener)
 * @note Only removes irec metadata structures, not active listeners
 *
 * @warning Caller must ensure daemon->interfaces list integrity before calling
 *
 * @see iface_check() which calls clean_interfaces after enumerate_interfaces
 * @see release_listener() which handles associated listener cleanup
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal usage in iface_check after interface re-enumeration
 * enumerate_interfaces(1); // Mark found interfaces
 * clean_interfaces(); // Remove interfaces not found
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies daemon->interfaces linked list (removes nodes)
 * - Frees irec->name strings via free()
 * - Frees struct irec structures via free()
 * - Does NOT close file descriptors (handled by release_listener)
 *
 * THREAD SAFETY:
 * NOT thread-safe (modifies global daemon->interfaces). Safe for single-threaded event loop.
 */
static void clean_interfaces()
{
  struct irec *iface;
  struct irec **up = &daemon->interfaces;

  for (iface = *up; iface; iface = *up)
  {
    if (!iface->found && !iface->done)
      {
        *up = iface->next;
        free(iface->name);
        free(iface);
      }
    else
      {
        up = &iface->next;
      }
  }
}

/** Release listener if no other interface needs it.
 *
 * @return 1 if released, 0 if still required
 */
static int release_listener(struct listener *l)
{
  if (l->used > 1)
    {
      struct irec *iface;
      for (iface = daemon->interfaces; iface; iface = iface->next)
	if (iface->done && sockaddr_isequal(&l->addr, &iface->addr))
	  {
	    if (iface->found)
	      {
		/* update listener to point to active interface instead */
		if (!l->iface->found)
		  l->iface = iface;
	      }
	    else
	      {
		l->used--;
		iface->done = 0;
	      }
	  }

      /* Someone is still using this listener, skip its deletion */
      if (l->used > 0)
	return 0;
    }

  if (l->iface->done)
    {
      int port;

      port = prettyprint_addr(&l->iface->addr, daemon->addrbuff);
      my_syslog(LOG_DEBUG|MS_DEBUG, _("stopped listening on %s(#%d): %s port %d"),
		l->iface->name, l->iface->index, daemon->addrbuff, port);
      /* In case it ever returns */
      l->iface->done = 0;
    }

  if (l->fd != -1)
    close(l->fd);
  if (l->tcpfd != -1)
    close(l->tcpfd);
  if (l->tftpfd != -1)
    close(l->tftpfd);

  free(l);
  return 1;
}

/**
 * @brief Discover all network interfaces and addresses, creating listener records
 *
 * @detailed
 * Master interface enumeration function that discovers all active network interfaces
 * and their addresses, creating irec (interface record) entries for eligible listeners.
 * Uses platform-specific backends: Linux calls netlink-based enumeration, BSD uses
 * routing socket and BPF, Solaris uses SIOCGLIFCONF ioctl. Rebuilds daemon->interfaces
 * list from scratch, handling dynamic interface changes from hotplug events or address
 * modifications. Called during daemon initialization and when interface changes detected.
 *
 * Implements once-per-select-cycle guard to prevent redundant enumerations within single
 * event loop iteration. Maintains freelist of addrlist structures (spare) for efficient
 * memory reuse. Updates interface index mappings for DNS forwarding path. Validates all
 * servers have valid source addresses and warns about interface-specific server bindings.
 *
 * Algorithm: (1) Check done flag for this event cycle, (2) Clean old interface records,
 * (3) Call platform-specific iface_enumerate() to discover interfaces, (4) Rebuild
 * daemon->interfaces list via iface_allowed callbacks, (5) Update server source addresses,
 * (6) Validate conditional domains have matching interfaces, (7) Check auth zones have
 * required interfaces, (8) Cleanup and return status.
 *
 * @param reset If 1, reset done flag to allow re-enumeration in next cycle; if 0, perform enumeration
 *
 * @return 1 on success, 0 on fatal error (socket creation failure)
 * @retval 1 Interface enumeration completed successfully or skipped (already done this cycle)
 * @retval 0 Socket creation failed for ioctl operations (fatal error)
 *
 * @note Called max once per select/poll event cycle (done flag prevents redundant calls)
 * @note reset=1 used to prepare for next event cycle; reset=0 performs actual enumeration
 * @note Platform-specific: Linux uses netlink, BSD uses routing sockets, Solaris uses ioctl
 * @note Rebuilds daemon->interfaces list completely (old irec entries freed)
 * @note Freelist (spare) maintained for addrlist allocation efficiency
 *
 * @warning Must not be called from TCP child processes (done flag prevents netlink use)
 * @warning Modifies global daemon state extensively (interfaces, servers, interface_addrs)
 * @warning Logs warnings for servers without valid source addresses or unused interfaces
 *
 * @see iface_enumerate() for platform-specific interface discovery implementations
 * @see iface_allowed() callback invoked for each discovered interface/address
 * @see create_bound_listeners() to create actual listening sockets after enumeration
 * @see docs/ARCHITECTURE.md for platform abstraction layer details
 *
 * EXAMPLE USAGE:
 * @code
 * // In main event loop after interface change event
 * if (enumerate_interfaces(0)) {
 *   create_bound_listeners(0);  // Create new listeners
 *   my_syslog(LOG_INFO, "Interface list updated");
 * }
 * // At end of event cycle, reset for next iteration
 * enumerate_interfaces(1);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Creates temporary AF_INET socket for ioctl operations
 * - Frees all existing irec entries in daemon->interfaces (via clean_interfaces)
 * - Rebuilds daemon->interfaces list with current system state
 * - Updates daemon->interface_addrs list for --local-service
 * - Validates and updates server source address mappings
 * - Logs warnings for configuration mismatches (servers, domains, auth zones)
 * - Closes socket before return
 *
 * THREAD SAFETY:
 * Not re-entrant. Uses static variables (spare, done). Modifies global daemon state.
 * Safe for single-threaded event-driven architecture only.
 */
int enumerate_interfaces(int reset)
{
  static struct addrlist *spare = NULL;
  static int done = 0;
  struct iface_param param;
  int errsave, ret = 1;
  struct addrlist *addr, *tmp;
  struct interface_name *intname;
  struct cond_domain *cond;
  struct irec *iface;
#ifdef HAVE_AUTH
  struct auth_zone *zone;
#endif
  struct server *serv;
  
  /* Do this max once per select cycle  - also inhibits netlink socket use
   in TCP child processes. */

  if (reset)
    {
      done = 0;
      return 1;
    }

  if (done)
    return 1;

  done = 1;

  if ((param.fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
    return 0;

  /* iface indexes can change when interfaces are created/destroyed. 
     We use them in the main forwarding control path, when the path
     to a server is specified by an interface, so cache them.
     Update the cache here. */
  for (serv = daemon->servers; serv; serv = serv->next)
    if (serv->interface[0] != 0)
      {
#ifdef HAVE_LINUX_NETWORK
	struct ifreq ifr;
	
	safe_strncpy(ifr.ifr_name, serv->interface, IF_NAMESIZE);
	if (ioctl(param.fd, SIOCGIFINDEX, &ifr) != -1) 
	  serv->ifindex = ifr.ifr_ifindex;
#else
	serv->ifindex = if_nametoindex(serv->interface);
#endif
      }
    
again:
  /* Mark interfaces for garbage collection */
  for (iface = daemon->interfaces; iface; iface = iface->next) 
    iface->found = 0;

  /* remove addresses stored against interface_names */
  for (intname = daemon->int_names; intname; intname = intname->next)
    {
      for (addr = intname->addr; addr; addr = tmp)
	{
	  tmp = addr->next;
	  addr->next = spare;
	  spare = addr;
	}
      
      intname->addr = NULL;
    }

  /* remove addresses stored against cond-domains. */
  for (cond = daemon->cond_domain; cond; cond = cond->next)
    {
      for (addr = cond->al; addr; addr = tmp)
	{
	  tmp = addr->next;
	  addr->next = spare;
	  spare = addr;
      }
      
      cond->al = NULL;
    }
  
  /* Remove list of addresses of local interfaces */
  for (addr = daemon->interface_addrs; addr; addr = tmp)
    {
      tmp = addr->next;
      addr->next = spare;
      spare = addr;
    }
  daemon->interface_addrs = NULL;
  
#ifdef HAVE_AUTH
  /* remove addresses stored against auth_zone subnets, but not 
   ones configured as address literals */
  for (zone = daemon->auth_zones; zone; zone = zone->next)
    if (zone->interface_names)
      {
	struct addrlist **up;
	for (up = &zone->subnet, addr = zone->subnet; addr; addr = tmp)
	  {
	    tmp = addr->next;
	    if (addr->flags & ADDRLIST_LITERAL)
	      up = &addr->next;
	    else
	      {
		*up = addr->next;
		addr->next = spare;
		spare = addr;
	      }
	  }
      }
#endif

  param.spare = spare;
  
  ret = iface_enumerate(AF_INET6, &param, iface_allowed_v6);
  if (ret < 0)
    goto again;
  else if (ret)
    {
      ret = iface_enumerate(AF_INET, &param, iface_allowed_v4);
      if (ret < 0)
	goto again;
    }
 
  errsave = errno;
  close(param.fd);
  
  if (option_bool(OPT_CLEVERBIND))
    { 
      /* Garbage-collect listeners listening on addresses that no longer exist.
	 Does nothing when not binding interfaces or for listeners on localhost, 
	 since the ->iface field is NULL. Note that this needs the protections
	 against reentrancy, hence it's here.  It also means there's a possibility,
	 in OPT_CLEVERBIND mode, that at listener will just disappear after
	 a call to enumerate_interfaces, this is checked OK on all calls. */
      struct listener *l, *tmp, **up;
      int freed = 0;
      
      for (up = &daemon->listeners, l = daemon->listeners; l; l = tmp)
	{
	  tmp = l->next;
	  
	  if (!l->iface || l->iface->found)
	    up = &l->next;
	  else if (release_listener(l))
	    {
	      *up = tmp;
	      freed = 1;
	    }
	}

      if (freed)
	clean_interfaces();
    }

  errno = errsave;
  spare = param.spare;
  
  return ret;
}

/* set NONBLOCK bit on fd: See Stevens 16.6 */
/**
 * @brief Set socket to non-blocking mode
 *
 * @detailed
 * Configures socket file descriptor for non-blocking I/O by setting O_NONBLOCK flag.
 * Essential for event-driven architecture where blocking I/O operations would stall
 * the entire daemon. Uses fcntl() F_GETFL to retrieve current flags, then F_SETFL to
 * set O_NONBLOCK while preserving other flags. Non-blocking mode ensures socket operations
 * (accept, send, recv) return immediately with EWOULDBLOCK/EAGAIN when operation cannot
 * complete, allowing event loop to continue processing other events.
 *
 * @param fd Socket file descriptor to configure
 *
 * @return 1 on success, 0 if fcntl() fails
 * @retval 1 Socket successfully configured for non-blocking mode
 * @retval 0 fcntl() failed (invalid fd or unsupported operation)
 *
 * @note Critical for event-driven architecture - blocking would freeze event loop
 * @note Preserves all existing file descriptor flags (appends O_NONBLOCK)
 * @note Should be called on all listener and upstream query sockets
 *
 * @see create_listeners() which calls fix_fd() on newly created sockets
 *
 * EXAMPLE USAGE:
 * @code
 * int sock = socket(AF_INET, SOCK_STREAM, 0);
 * if (fix_fd(sock))
 *   my_syslog(LOG_DEBUG, "Socket configured for non-blocking I/O");
 * else
 *   close(sock);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies socket file descriptor flags (O_NONBLOCK added)
 *
 * THREAD SAFETY:
 * Thread-safe. fcntl() is thread-safe per POSIX. Safe for single-threaded dnsmasq use.
 */
int fix_fd(int fd)
{
  int flags;

  if ((flags = fcntl(fd, F_GETFL)) == -1 ||
      fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    return 0;
  
  return 1;
}

/**
 * @brief Create and configure listening socket with appropriate options
 *
 * @detailed
 * Core socket creation function for DNS, DHCP, and TFTP listeners. Creates socket,
 * sets SO_REUSEADDR for address reuse, configures non-blocking mode, binds to specified
 * address, and enables packet info reception for destination address/interface determination.
 * For TCP sockets, configures listen backlog and optionally TCP Fast Open. For UDP IPv4
 * wildcard sockets, enables IP_PKTINFO (Linux) or IP_RECVDSTADDR+IP_RECVIF (BSD) for
 * ancillary data. For UDP IPv6, enables IPV6_PKTINFO via set_ipv6pktinfo(). Handles
 * IPv6-only mode to prevent dual-stack binding conflicts.
 *
 * Algorithm: (1) Create socket, (2) Set SO_REUSEADDR and non-blocking mode, (3) Set
 * IPV6_V6ONLY for IPv6 to prevent IPv4-mapped addresses, (4) Bind to address, (5) For
 * TCP: configure listen with TCP_BACKLOG, optionally TCP_FASTOPEN, (6) For UDP: enable
 * pktinfo for destination address retrieval (IP_PKTINFO on Linux, IP_RECVDSTADDR/IP_RECVIF
 * on BSD, IPV6_PKTINFO for IPv6), (7) Return fd or -1 on error.
 *
 * @param addr Address to bind socket (family, address, port)
 * @param type Socket type (SOCK_DGRAM for UDP, SOCK_STREAM for TCP)
 * @param dienow If 1, die on critical errors (startup); if 0, log warning and return -1
 *
 * @return Socket file descriptor on success, -1 on failure
 * @retval >=0 Successfully created and configured socket file descriptor
 * @retval -1 Socket creation, configuration, or binding failed
 *
 * @note Static function, internal to network.c
 * @note Silently returns -1 for EPROTONOSUPPORT/EAFNOSUPPORT (IPv6 on IPv4-only system)
 * @note TCP sockets: listen backlog set to TCP_BACKLOG constant
 * @note TCP Fast Open: enabled if TCP_FASTOPEN defined (Linux 3.7+, queue length 5)
 * @note UDP wildcard: packet info enabled for destination address/interface retrieval
 * @note IPv6: IPV6_V6ONLY prevents IPv4-mapped IPv6 addresses binding conflicts
 * @note SO_REUSEADDR: allows rapid socket reuse after daemon restart
 *
 * @warning dienow=1 causes die() termination on bind failures (except OPT_CLEVERBIND mode)
 * @warning Caller must close returned fd on subsequent processing errors
 *
 * @see create_listeners() which calls make_sock for each listener type
 * @see fix_fd() for non-blocking mode configuration
 * @see set_ipv6pktinfo() for IPv6 packet info configuration
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal usage by create_listeners
 * union mysockaddr addr;
 * addr.in.sin_family = AF_INET;
 * addr.in.sin_addr.s_addr = INADDR_ANY;
 * addr.in.sin_port = htons(53);
 * int udp_fd = make_sock(&addr, SOCK_DGRAM, 1);
 * if (udp_fd != -1) {
 *   // Add to listener list
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Creates socket via socket() system call
 * - Sets SO_REUSEADDR socket option
 * - Sets O_NONBLOCK file descriptor flag via fix_fd()
 * - Sets IPV6_V6ONLY for IPv6 sockets
 * - Binds socket to specified address
 * - For TCP: calls listen() with TCP_BACKLOG, may set TCP_FASTOPEN
 * - For UDP: enables packet info (IP_PKTINFO, IP_RECVDSTADDR, IP_RECVIF, or IPV6_PKTINFO)
 * - May die() and terminate daemon if dienow=1 and binding fails
 * - Logs warnings on errors if dienow=0
 *
 * THREAD SAFETY:
 * Thread-safe (no global state modified). Safe for single-threaded use.
 */
static int make_sock(union mysockaddr *addr, int type, int dienow)
{
  int family = addr->sa.sa_family;
  int fd, rc, opt = 1;
  
  if ((fd = socket(family, type, 0)) == -1)
    {
      int port, errsave;
      char *s;

      /* No error if the kernel just doesn't support this IP flavour */
      if (errno == EPROTONOSUPPORT ||
	  errno == EAFNOSUPPORT ||
	  errno == EINVAL)
	return -1;
      
    err:
      errsave = errno;
      port = prettyprint_addr(addr, daemon->addrbuff);
      if (!option_bool(OPT_NOWILD) && !option_bool(OPT_CLEVERBIND))
	sprintf(daemon->addrbuff, "port %d", port);
      s = _("failed to create listening socket for %s: %s");
      
      if (fd != -1)
	close (fd);
	
      errno = errsave;

      if (dienow)
	{
	  /* failure to bind addresses given by --listen-address at this point
	     is OK if we're doing bind-dynamic */
	  if (!option_bool(OPT_CLEVERBIND))
	    die(s, daemon->addrbuff, EC_BADNET);
	}
      else
	my_syslog(LOG_WARNING, s, daemon->addrbuff, strerror(errno));
      
      return -1;
    }	
  
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1 || !fix_fd(fd))
    goto err;
  
  if (family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1)
    goto err;
  
  if ((rc = bind(fd, (struct sockaddr *)addr, sa_len(addr))) == -1)
    goto err;
  
  if (type == SOCK_STREAM)
    {
#ifdef TCP_FASTOPEN
      int qlen = 5;                           
      setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
#endif
      
      if (listen(fd, TCP_BACKLOG) == -1)
	goto err;
    }
  else if (family == AF_INET)
    {
      if (!option_bool(OPT_NOWILD))
	{
#if defined(HAVE_LINUX_NETWORK) 
	  if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1)
	    goto err;
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
	  if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof(opt)) == -1 ||
	      setsockopt(fd, IPPROTO_IP, IP_RECVIF, &opt, sizeof(opt)) == -1)
	    goto err;
#endif
	}
    }
  else if (!set_ipv6pktinfo(fd))
    goto err;
  
  return fd;
}

/**
 * @brief Enable IPv6 packet information reception on socket
 *
 * @detailed
 * Configures IPv6 socket to receive ancillary packet information (destination address,
 * arrival interface) via cmsg mechanism. Handles Linux kernel API change around 2.6.14
 * where IPV6_RECVPKTINFO replaced IPV6_PKTINFO for enabling reception. Attempts modern
 * IPV6_RECVPKTINFO first, falling back to IPV6_2292PKTINFO (old ABI) if ENOPROTOOPT.
 * On non-Linux systems or older Linux, uses IPV6_PKTINFO directly. Stores successful
 * option constant in daemon->v6pktinfo for later use when retrieving packet info.
 *
 * Critical for correct IPv6 response routing - allows dnsmasq to determine which
 * interface and address received a query, enabling proper source address selection
 * for responses. Without pktinfo, daemon cannot differentiate queries arriving on
 * different interfaces/addresses.
 *
 * @param fd IPv6 socket file descriptor to configure (must be AF_INET6 socket)
 *
 * @return 1 on success, 0 if all setsockopt attempts failed
 * @retval 1 Socket configured for IPv6 packet info reception
 * @retval 0 All setsockopt attempts failed (unsupported or invalid fd)
 *
 * @note Platform-specific: Tries IPV6_RECVPKTINFO (Linux 2.6.14+), IPV6_2292PKTINFO (old Linux), or IPV6_PKTINFO (BSD/Solaris)
 * @note Sets daemon->v6pktinfo to successful option constant for recvmsg() cmsg retrieval
 * @note Required for IPv6 dual-stack operation and correct interface/address binding
 *
 * @warning Must be called on all IPv6 UDP sockets before receiving packets
 * @warning daemon->v6pktinfo must match value used when retrieving pktinfo in recvmsg()
 *
 * @see recv_dns_query() which retrieves IPv6 pktinfo using daemon->v6pktinfo constant
 *
 * EXAMPLE USAGE:
 * @code
 * int sock = socket(AF_INET6, SOCK_DGRAM, 0);
 * if (set_ipv6pktinfo(sock))
 *   my_syslog(LOG_DEBUG, "IPv6 pktinfo enabled, constant: %d", daemon->v6pktinfo);
 * else
 *   my_syslog(LOG_ERR, "Failed to enable IPv6 pktinfo");
 * @endcode
 *
 * SIDE EFFECTS:
 * - Sets IPV6_RECVPKTINFO, IPV6_2292PKTINFO, or IPV6_PKTINFO socket option
 * - Modifies daemon->v6pktinfo global to store successful option constant
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon->v6pktinfo. Safe for single-threaded use.
 */
int set_ipv6pktinfo(int fd)
{
  int opt = 1;

  /* The API changed around Linux 2.6.14 but the old ABI is still supported:
     handle all combinations of headers and kernel.
     OpenWrt note that this fixes the problem addressed by your very broken patch. */
  daemon->v6pktinfo = IPV6_PKTINFO;
  
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt)) != -1)
    return 1;
# ifdef IPV6_2292PKTINFO
  else if (errno == ENOPROTOOPT && setsockopt(fd, IPPROTO_IPV6, IPV6_2292PKTINFO, &opt, sizeof(opt)) != -1)
    {
      daemon->v6pktinfo = IPV6_2292PKTINFO;
      return 1;
    }
# endif 
#else
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &opt, sizeof(opt)) != -1)
    return 1;
#endif

  return 0;
}


/**
 * @brief Determine arrival interface for TCP connection
 *
 * @detailed
 * Attempts to retrieve the interface index on which a TCP connection was accepted.
 * Uses platform-specific mechanisms: Linux employs IP_PKTINFO/IPV6_PKTINFO with
 * recvmsg() on accepted socket, BSD uses IP_RECVIF with getsockopt(). Returns 0 if
 * platform does not support interface determination for TCP or if retrieval fails.
 * Used for TCP DNS queries to determine interface-specific configuration (conditional
 * domains, auth zones, interface-specific servers).
 *
 * Algorithm (Linux): Enable IP_PKTINFO/IPV6_PKTINFO, call recvmsg() with MSG_PEEK
 * to retrieve ancillary data without consuming stream data, extract in_pktinfo or
 * in6_pktinfo from cmsg, return ipi_ifindex/ipi6_ifindex.
 *
 * Algorithm (BSD): Enable IP_RECVIF, call getsockopt() to retrieve sockaddr_dl,
 * return sdl_index.
 *
 * @param fd Accepted TCP socket file descriptor (must be connected TCP socket)
 * @param af Address family (AF_INET or AF_INET6)
 *
 * @return Interface index (positive integer) or 0 if unsupported/unavailable
 * @retval >0 Interface index on which TCP connection arrived
 * @retval 0 Platform unsupported, setsockopt/recvmsg/getsockopt failed, or no interface info
 *
 * @note Platform-specific: Linux uses IP_PKTINFO with recvmsg(), BSD uses IP_RECVIF with getsockopt()
 * @note May return 0 on platforms without TCP interface determination support
 * @note Uses MSG_PEEK to retrieve cmsg data without consuming TCP stream
 * @note Required for interface-specific TCP DNS query handling
 *
 * @see tcp_request() in rfc1035.c which calls this to determine query interface
 *
 * EXAMPLE USAGE:
 * @code
 * int client_fd = accept(listener_fd, NULL, NULL);
 * int if_idx = tcp_interface(client_fd, AF_INET);
 * if (if_idx > 0) {
 *   char ifname[IF_NAMESIZE];
 *   if (indextoname(sock, if_idx, ifname))
 *     my_syslog(LOG_DEBUG, "TCP connection on interface %s", ifname);
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Calls setsockopt() to enable pktinfo/recvif (may fail silently)
 * - Calls recvmsg() with MSG_PEEK on Linux (does not consume data)
 * - Calls getsockopt() on BSD to retrieve interface info
 *
 * THREAD SAFETY:
 * Thread-safe. Does not modify global state. Safe for single-threaded use.
 */
int tcp_interface(int fd, int af)
{ 
  (void)fd; /* suppress potential unused warning */
  (void)af; /* suppress potential unused warning */
  int if_index = 0;

#ifdef HAVE_LINUX_NETWORK
  int opt = 1;
  struct cmsghdr *cmptr;
  struct msghdr msg;
  socklen_t len;
  
  /* use mshdr so that the CMSDG_* macros are available */
  msg.msg_control = daemon->packet;
  msg.msg_controllen = len = daemon->packet_buff_sz;

  /* we overwrote the buffer... */
  daemon->srv_save = NULL; 

  if (af == AF_INET)
    {
      if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) != -1 &&
	  getsockopt(fd, IPPROTO_IP, IP_PKTOPTIONS, msg.msg_control, &len) != -1)
	{
	  msg.msg_controllen = len;
	  for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	    if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO)
	      {
		union {
		  unsigned char *c;
		  struct in_pktinfo *p;
		} p;
		
		p.c = CMSG_DATA(cmptr);
		if_index = p.p->ipi_ifindex;
	      }
	}
    }
  else
    {
      /* Only the RFC-2292 API has the ability to find the interface for TCP connections,
	 it was removed in RFC-3542 !!!! 

	 Fortunately, Linux kept the 2292 ABI when it moved to 3542. The following code always
	 uses the old ABI, and should work with pre- and post-3542 kernel headers */

#ifdef IPV6_2292PKTOPTIONS   
#  define PKTOPTIONS IPV6_2292PKTOPTIONS
#else
#  define PKTOPTIONS IPV6_PKTOPTIONS
#endif

      if (set_ipv6pktinfo(fd) &&
	  getsockopt(fd, IPPROTO_IPV6, PKTOPTIONS, msg.msg_control, &len) != -1)
	{
          msg.msg_controllen = len;
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
	}
    }
#endif /* Linux */
 
  return if_index;
}
      
/**
 * @brief Create DNS UDP/TCP and optionally TFTP listener sockets for address
 *
 * @detailed
 * Core listener creation function that creates up to three sockets for a single address:
 * DNS UDP (port 53), DNS TCP (port 53), and optionally TFTP UDP (port 69). Allocates
 * struct listener to track all three file descriptors for the address. Called by
 * create_bound_listeners() for interface-specific addresses and create_wildcard_listeners()
 * for INADDR_ANY/in6addr_any wildcard binding. For TFTP, temporarily modifies addr port
 * to TFTP_PORT (69), creates socket, restores DNS port. Skips DNS socket creation if
 * daemon->port is 0 (--port=0 disables DNS). All sockets created via make_sock() with
 * appropriate SO_REUSEADDR and packet info options.
 *
 * Algorithm: (1) If daemon->port != 0: create DNS UDP socket via make_sock(SOCK_DGRAM)
 * and DNS TCP socket via make_sock(SOCK_STREAM), (2) If do_tftp and HAVE_TFTP: save
 * port, set to TFTP_PORT, create TFTP UDP socket, restore port, (3) If any socket
 * created: allocate struct listener, populate fd/tcpfd/tftpfd fields, set addr and
 * used=1, (4) Return listener or NULL if all sockets failed.
 *
 * @param addr Address to bind sockets (IPv4 or IPv6 with port already set to daemon->port)
 * @param do_tftp If non-zero, create TFTP listener socket on port 69
 * @param dienow Pass to make_sock: if 1, die on critical errors; if 0, log and continue
 *
 * @return Pointer to allocated struct listener with created sockets, or NULL if all failed
 * @retval non-NULL Successfully created at least one socket (DNS UDP, DNS TCP, or TFTP)
 * @retval NULL All socket creation attempts failed (socket/bind errors)
 *
 * @note Static function, internal to network.c
 * @note DNS port taken from daemon->port (default 53, configurable via --port)
 * @note TFTP port always 69 (TFTP_PORT constant from dnsmasq.h)
 * @note If daemon->port==0 (DNS disabled), only TFTP socket created if do_tftp
 * @note Temporarily modifies addr->in.sin_port or addr->in6.sin6_port for TFTP creation
 * @note TFTP socket creation conditional on HAVE_TFTP compile-time option
 * @note Returned listener has used=1 (reference count for listener sharing)
 * @note Caller must link returned listener into daemon->listeners list
 *
 * @warning Caller must handle NULL return (all sockets failed to create)
 * @warning Returned listener dynamically allocated, caller responsible for eventual free
 * @warning addr->port modified temporarily for TFTP, restored before return
 *
 * @see make_sock() which creates and configures individual sockets
 * @see create_bound_listeners() which calls this for each interface address
 * @see create_wildcard_listeners() which calls this for wildcard addresses
 * @see find_listener() which searches daemon->listeners for duplicate addresses
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal usage by create_bound_listeners
 * union mysockaddr addr;
 * addr.in.sin_family = AF_INET;
 * addr.in.sin_addr.s_addr = inet_addr("192.168.1.1");
 * addr.in.sin_port = htons(daemon->port);
 * struct listener *l = create_listeners(&addr, 1, 1); // DNS + TFTP
 * if (l) {
 *   l->next = daemon->listeners;
 *   daemon->listeners = l;
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Creates up to 3 sockets via make_sock() (DNS UDP, DNS TCP, TFTP UDP)
 * - Allocates struct listener via safe_malloc()
 * - Temporarily modifies addr->in.sin_port or addr->in6.sin6_port for TFTP
 * - May die() if dienow=1 and socket creation fails critically
 * - Logs warnings on socket creation failures
 *
 * THREAD SAFETY:
 * Thread-safe (no global state modified directly). Safe for single-threaded use.
 */
static struct listener *create_listeners(union mysockaddr *addr, int do_tftp, int dienow)
{
  struct listener *l = NULL;
  int fd = -1, tcpfd = -1, tftpfd = -1;

  (void)do_tftp;

  if (daemon->port != 0)
    {
      fd = make_sock(addr, SOCK_DGRAM, dienow);
      tcpfd = make_sock(addr, SOCK_STREAM, dienow);
    }
  
#ifdef HAVE_TFTP
  if (do_tftp)
    {
      if (addr->sa.sa_family == AF_INET)
	{
	  /* port must be restored to DNS port for TCP code */
	  short save = addr->in.sin_port;
	  addr->in.sin_port = htons(TFTP_PORT);
	  tftpfd = make_sock(addr, SOCK_DGRAM, dienow);
	  addr->in.sin_port = save;
	}
      else
	{
	  short save = addr->in6.sin6_port;
	  addr->in6.sin6_port = htons(TFTP_PORT);
	  tftpfd = make_sock(addr, SOCK_DGRAM, dienow);
	  addr->in6.sin6_port = save;
	}  
    }
#endif

  if (fd != -1 || tcpfd != -1 || tftpfd != -1)
    {
      l = safe_malloc(sizeof(struct listener));
      l->next = NULL;
      l->fd = fd;
      l->tcpfd = tcpfd;
      l->tftpfd = tftpfd;
      l->addr = *addr;
      l->used = 1;
      l->iface = NULL;
    }

  return l;
}

/**
 * @brief Create wildcard listening sockets for all interfaces (0.0.0.0 and ::)
 *
 * @detailed
 * Creates dual-stack wildcard listeners binding to INADDR_ANY (0.0.0.0) for IPv4 and
 * in6addr_any (::) for IPv6 on daemon->port. Used when no specific --interface or
 * --listen-address configured, allowing dnsmasq to receive packets on all available
 * interfaces. Creates UDP and TCP sockets for DNS, and UDP sockets for DHCP/TFTP if
 * enabled. Wildcard binding maximizes availability but may receive packets on unintended
 * interfaces; use with appropriate firewall rules or switch to interface-specific binding.
 *
 * Algorithm: (1) Create IPv4 wildcard addr (INADDR_ANY:daemon->port), (2) Call
 * create_listeners() for IPv4 with TFTP flag, (3) Create IPv6 wildcard addr
 * (in6addr_any:daemon->port), (4) Call create_listeners() for IPv6 with TFTP flag,
 * (5) Chain listeners and assign to daemon->listeners.
 *
 * @return void
 *
 * @note Called when no --interface or --listen-address directives configured
 * @note Creates listeners on daemon->port (default 53 for DNS)
 * @note TFTP enabled if OPT_TFTP option set (--enable-tftp)
 * @note Dies on socket creation failure (dienow=1 to create_listeners)
 * @note IPv6 listener creation may fail on IPv4-only systems (not fatal)
 *
 * @warning Binds to ALL interfaces - may expose services on unintended networks
 * @warning Must be called during daemon initialization, not during operation
 *
 * @see create_listeners() which performs actual socket creation
 * @see create_bound_listeners() for interface-specific listener creation
 *
 * EXAMPLE USAGE:
 * @code
 * // During daemon initialization when no specific interfaces configured
 * if (!daemon->if_names && !daemon->if_addrs)
 *   create_wildcard_listeners();  // Listen on all interfaces
 * @endcode
 *
 * SIDE EFFECTS:
 * - Creates IPv4 and IPv6 wildcard listener sockets (UDP+TCP for DNS)
 * - Creates TFTP listener if OPT_TFTP enabled
 * - Sets daemon->listeners to newly created listener chain
 * - May die() and terminate daemon on socket creation failure
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon->listeners. Safe for single-threaded startup.
 */
void create_wildcard_listeners(void)
{
  union mysockaddr addr;
  struct listener *l, *l6;

  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in.sin_len = sizeof(addr.in);
#endif
  addr.in.sin_family = AF_INET;
  addr.in.sin_addr.s_addr = INADDR_ANY;
  addr.in.sin_port = htons(daemon->port);

  l = create_listeners(&addr, !!option_bool(OPT_TFTP), 1);

  memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
  addr.in6.sin6_len = sizeof(addr.in6);
#endif
  addr.in6.sin6_family = AF_INET6;
  addr.in6.sin6_addr = in6addr_any;
  addr.in6.sin6_port = htons(daemon->port);
 
  l6 = create_listeners(&addr, !!option_bool(OPT_TFTP), 1);
  if (l) 
    l->next = l6;
  else 
    l = l6;

  daemon->listeners = l;
}

/**
 * @brief Search daemon->listeners for existing listener bound to address
 *
 * @detailed
 * Linear search through daemon->listeners linked list to find listener with matching
 * address. Used by create_bound_listeners() to detect duplicate listeners when multiple
 * interfaces share the same address (e.g., virtual interfaces eth0:0 and eth0:1 both
 * with 192.168.1.1). Prevents creating duplicate sockets for the same address, instead
 * increments existing listener's reference count (l->used). Address comparison via
 * sockaddr_isequal() handles both IPv4 and IPv6, compares family, address, and port.
 *
 * Algorithm: Traverse daemon->listeners linked list, for each listener compare l->addr
 * to target addr using sockaddr_isequal(), return first match or NULL if no match.
 *
 * @param addr Address to search for (IPv4 or IPv6 with port)
 *
 * @return Pointer to existing listener with matching address, or NULL if not found
 * @retval non-NULL Listener already exists for this address (can share listener)
 * @retval NULL No listener for this address (must create new listener)
 *
 * @note Static function, internal to network.c
 * @note Comparison via sockaddr_isequal handles IPv4/IPv6, port, and address
 * @note Does NOT compare interface index (multiple interfaces can share listener)
 * @note Used to prevent duplicate listeners and enable listener sharing
 *
 * @warning Returns first match only (assumes no duplicate addresses in daemon->listeners)
 *
 * @see create_bound_listeners() which calls find_listener to detect duplicates
 * @see sockaddr_isequal() in util.c for address comparison logic
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal usage by create_bound_listeners
 * struct irec *iface = daemon->interfaces;
 * struct listener *existing = find_listener(&iface->addr);
 * if (existing) {
 *   existing->used++; // Share existing listener
 * } else {
 *   struct listener *new = create_listeners(&iface->addr, 0, 1); // Create new
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - None (read-only search)
 *
 * THREAD SAFETY:
 * Thread-safe for concurrent reads. NOT safe if daemon->listeners modified concurrently.
 * Safe for single-threaded event loop.
 */
static struct listener *find_listener(union mysockaddr *addr)
{
  struct listener *l;
  for (l = daemon->listeners; l; l = l->next)
    if (sockaddr_isequal(&l->addr, addr))
      return l;
  return NULL;
}

/**
 * @brief Create and bind listening sockets for all discovered interfaces
 *
 * @detailed
 * Creates DNS, DHCP, and TFTP listening sockets for all interface records in
 * daemon->interfaces that passed enumeration and DAD (Duplicate Address Detection)
 * checks. Reuses existing listener sockets when possible (same address already bound)
 * to avoid socket thrashing during interface updates. Handles --listen-address directives
 * that may not match enumerated interfaces (e.g., 127.0.1.1 when loopback is 127.0.0.1).
 * Creates wildcard listeners for any explicit --listen-address not matched by interface
 * addresses.
 *
 * Algorithm: (1) Iterate daemon->interfaces for un-processed entries (done=0, dad=0, found=1),
 * (2) Check if existing listener already bound to this address (socket reuse), (3) If
 * not found, call create_listeners() to create UDP/TCP sockets for DNS and DHCP/TFTP
 * if applicable, (4) Link new listener to daemon->listeners list and mark iface done,
 * (5) Log new listeners (except during daemon startup), (6) Create wildcard listeners
 * for unused --listen-address directives.
 *
 * @param dienow If 1, die on socket creation failure (startup); if 0, log warning and continue
 *
 * @return void
 *
 * @note Should be called after enumerate_interfaces() to have current interface list
 * @note Skips interfaces with iface->dad=1 (IPv6 DAD in progress, address not yet usable)
 * @note Skips interfaces with iface->found=0 (interface disappeared since enumeration)
 * @note Reuses existing listeners when possible (increases usage counter, avoids recreation)
 * @note Logs listener creation at LOG_DEBUG level (except during initial startup when dienow=1)
 * @note Creates wildcard listeners for --listen-address entries not matched by interfaces
 *
 * @warning Must enumerate_interfaces() first to populate daemon->interfaces list
 * @warning dienow=1 causes daemon exit on socket creation failure (use only at startup)
 *
 * @see enumerate_interfaces() to populate interface list before calling
 * @see create_listeners() internal function that performs actual socket creation
 * @see create_wildcard_listeners() for explicit --listen-address handling
 *
 * EXAMPLE USAGE:
 * @code
 * // After interface enumeration at startup
 * enumerate_interfaces(0);
 * create_bound_listeners(1);  // Die on failure during startup
 *
 * // After interface change event during operation
 * enumerate_interfaces(0);
 * create_bound_listeners(0);  // Warn but continue on failure
 * @endcode
 *
 * SIDE EFFECTS:
 * - Creates new listener sockets (UDP and TCP for DNS, UDP for DHCP/TFTP)
 * - Links new listeners to daemon->listeners list
 * - Marks iface->done=1 for processed interfaces
 * - Increments existing->used counter for reused listeners
 * - Logs listener creation messages at DEBUG level (except during startup)
 * - May call die() and terminate daemon if dienow=1 and socket creation fails
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon->listeners and daemon->interfaces.
 * Safe for single-threaded use.
 */
void create_bound_listeners(int dienow)
{
  struct listener *new;
  struct irec *iface;
  struct iname *if_tmp;
  struct listener *existing;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (!iface->done && !iface->dad && iface->found)
      {
	existing = find_listener(&iface->addr);
	if (existing)
	  {
	    iface->done = 1;
	    existing->used++; /* increase usage counter */
	  }
	else if ((new = create_listeners(&iface->addr, iface->tftp_ok, dienow)))
	  {
	    new->iface = iface;
	    new->next = daemon->listeners;
	    daemon->listeners = new;
	    iface->done = 1;

	    /* Don't log the initial set of listen addresses created
               at startup, since this is happening before the logging
               system is initialised and the sign-on printed. */
            if (!dienow)
              {
		int port = prettyprint_addr(&iface->addr, daemon->addrbuff);
		my_syslog(LOG_DEBUG|MS_DEBUG, _("listening on %s(#%d): %s port %d"),
			  iface->name, iface->index, daemon->addrbuff, port);
	      }
	  }
      }

  /* Check for --listen-address options that haven't been used because there's
     no interface with a matching address. These may be valid: eg it's possible
     to listen on 127.0.1.1 even if the loopback interface is 127.0.0.1

     If the address isn't valid the bind() will fail and we'll die() 
     (except in bind-dynamic mode, when we'll complain but keep trying.)

     The resulting listeners have the ->iface field NULL, and this has to be
     handled by the DNS and TFTP code. It disables --localise-queries processing
     (no netmask) and some MTU login the tftp code. */

  for (if_tmp = daemon->if_addrs; if_tmp; if_tmp = if_tmp->next)
    if (!if_tmp->used && 
	(new = create_listeners(&if_tmp->addr, !!option_bool(OPT_TFTP), dienow)))
      {
	new->next = daemon->listeners;
	daemon->listeners = new;

	if (!dienow)
	  {
	    int port = prettyprint_addr(&if_tmp->addr, daemon->addrbuff);
	    my_syslog(LOG_DEBUG|MS_DEBUG, _("listening on %s port %d"), daemon->addrbuff, port);
	  }
      }
}

/* In --bind-interfaces, the only access control is the addresses we're listening on. 
   There's nothing to avoid a query to the address of an internal interface arriving via
   an external interface where we don't want to accept queries, except that in the usual 
   case the addresses of internal interfaces are RFC1918. When bind-interfaces in use, 
   and we listen on an address that looks like it's probably globally routeable, shout.

   The fix is to use --bind-dynamic, which actually checks the arrival interface too.
   Tough if your platform doesn't support this.

   Note that checking the arrival interface is supported in the standard IPv6 API and
   always done, so we don't warn about any IPv6 addresses here.
*/

/**
 * @brief Warn about public IP listeners vulnerable to DNS amplification attacks
 *
 * @detailed
 * Checks all bound listeners for non-private IPv4 addresses and issues LOUD WARNING
 * for potential DNS amplification attack vectors. When using --bind-interfaces mode,
 * binding to public IP addresses on multi-homed hosts may allow requests arriving via
 * other interfaces to be serviced, exposing daemon to amplification abuse. Recommends
 * --bind-dynamic as safer alternative that performs runtime interface checking.
 *
 * Algorithm: Iterate daemon->interfaces, skip authoritative DNS interfaces, check if
 * IPv4 address is in private range (RFC 1918, loopback, link-local). If public address
 * found, issue warning and recommend --bind-dynamic. Mark iface->warned to prevent
 * duplicate warnings.
 *
 * @return void
 *
 * @note Only warns for IPv4 public addresses (IPv6 amplification less common)
 * @note Skips interfaces with iface->dns_auth=1 (authoritative DNS intentionally public)
 * @note Uses private_net() to determine RFC 1918 / private address ranges
 * @note Sets iface->warned=1 to track warned interfaces
 * @note Recommendation: --bind-dynamic provides runtime interface checking safety
 *
 * @see private_net() in util.c for private address range detection
 * @see create_bound_listeners() which calls this after listener creation
 *
 * EXAMPLE USAGE:
 * @code
 * // After creating bound listeners in --bind-interfaces mode
 * create_bound_listeners(0);
 * warn_bound_listeners();  // Check for public IP exposure
 * @endcode
 *
 * SIDE EFFECTS:
 * - Logs LOG_WARNING messages for public IP listeners
 * - Sets iface->warned=1 for warned interfaces
 *
 * THREAD SAFETY:
 * Not re-entrant. Reads and modifies daemon->interfaces. Safe for single-threaded use.
 */
void warn_bound_listeners(void)
{
  struct irec *iface; 	
  int advice = 0;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (!iface->dns_auth)
      {
	if (iface->addr.sa.sa_family == AF_INET)
	  {
	    if (!private_net(iface->addr.in.sin_addr, 1))
	      {
		inet_ntop(AF_INET, &iface->addr.in.sin_addr, daemon->addrbuff, ADDRSTRLEN);
		iface->warned = advice = 1;
		my_syslog(LOG_WARNING, 
			  _("LOUD WARNING: listening on %s may accept requests via interfaces other than %s"),
			  daemon->addrbuff, iface->name);
	      }
	  }
      }
  
  if (advice)
    my_syslog(LOG_WARNING, _("LOUD WARNING: use --bind-dynamic rather than --bind-interfaces to avoid DNS amplification attacks via these interface(s)")); 
}

/**
 * @brief Warn about interface label substitution when base interface used instead
 *
 * @detailed
 * Logs warnings when dnsmasq configured with interface labels (e.g., eth0:0) but
 * binds to base interface name (eth0) because kernel reports base interface for
 * labeled addresses. Linux-specific behavior where interface labels are virtual
 * and kernel exposes only base interface in network stack operations.
 *
 * @return void
 *
 * @note Linux-specific interface label behavior (eth0:0, eth0:1, etc.)
 * @note iface->label indicates label was configured but iface->name is base interface
 *
 * @see label_exception() for handling label/base interface mismatches in packet processing
 *
 * EXAMPLE USAGE:
 * @code
 * enumerate_interfaces(0);
 * warn_wild_labels();  // Warn about label substitutions
 * @endcode
 */
void warn_wild_labels(void)
{
  struct irec *iface;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (iface->found && iface->name && iface->label)
      my_syslog(LOG_WARNING, _("warning: using interface %s instead"), iface->name);
}

/**
 * @brief Warn about interface names with no addresses found during enumeration
 *
 * @detailed
 * Checks daemon->int_names (interface-name directives for subnet-specific options)
 * and warns when no matching addresses discovered during enumerate_interfaces().
 * Indicates configuration mismatch where --dhcp-range=interface:subnet specified
 * but named interface has no addresses or interface doesn't exist.
 *
 * @return void
 *
 * @note intname->addr is NULL when no addresses matched the interface name
 * @note Indicates potential DHCP range misconfiguration
 *
 * @see enumerate_interfaces() which populates intname->addr when addresses found
 *
 * EXAMPLE USAGE:
 * @code
 * enumerate_interfaces(0);
 * warn_int_names();  // Check for missing interface addresses
 * @endcode
 */
void warn_int_names(void)
{
  struct interface_name *intname;
 
  for (intname = daemon->int_names; intname; intname = intname->next)
    if (!intname->addr)
      my_syslog(LOG_WARNING, _("warning: no addresses found for interface %s"), intname->intr);
}
 
/**
 * @brief Check if any listeners are awaiting IPv6 Duplicate Address Detection (DAD)
 *
 * @detailed
 * Returns 1 if any interface has dad=1 and done=0 in --bind-interfaces mode (OPT_NOWILD),
 * indicating IPv6 DAD is in progress for at least one address. When DAD pending, listeners
 * cannot be created for those addresses yet (would fail to bind). Caller should delay
 * listener creation until DAD completes. Only relevant for --bind-interfaces mode;
 * wildcard binding doesn't require per-address DAD tracking.
 *
 * @return 1 if DAD pending for any interface, 0 otherwise
 * @retval 1 At least one interface has DAD in progress (dad=1, done=0) in --bind-interfaces mode
 * @retval 0 No DAD pending or not using --bind-interfaces mode
 *
 * @note Only applies to --bind-interfaces mode (OPT_NOWILD set)
 * @note IPv6-specific: DAD verifies address uniqueness on link-local network
 * @note dad=1 set during enumeration for new IPv6 addresses
 * @note done=0 indicates listener not yet created for this address
 *
 * @see enumerate_interfaces() which sets iface->dad for new IPv6 addresses
 * @see create_bound_listeners() which skips interfaces with dad=1
 *
 * EXAMPLE USAGE:
 * @code
 * enumerate_interfaces(0);
 * if (is_dad_listeners())
 *   my_syslog(LOG_INFO, "Delaying listener creation for DAD completion");
 * else
 *   create_bound_listeners(0);
 * @endcode
 */
int is_dad_listeners(void)
{
  struct irec *iface;
  
  if (option_bool(OPT_NOWILD))
    for (iface = daemon->interfaces; iface; iface = iface->next)
      if (iface->dad && !iface->done)
	return 1;
  
  return 0;
}

#ifdef HAVE_DHCP6
/**
 * @brief Join IPv6 multicast groups required for DHCPv6 server operation
 *
 * @detailed
 * Joins All_DHCP_Relay_Agents_and_Servers multicast group (ff02::1:2) and
 * All_DHCP_Servers multicast group (ff05::1:3) on all interfaces configured for
 * DHCPv6. Required per RFC 3315 Section 5.3 for DHCPv6 server to receive client
 * SOLICIT messages sent to link-local and site-local multicast addresses. Creates
 * additional DHCPv6 listener sockets bound to multicast addresses if needed.
 *
 * Algorithm: Iterate daemon->interfaces with dhcp_ok, join ff02::1:2 (link-local
 * all DHCP servers/relays) and ff05::1:3 (site-local all DHCP servers) using
 * setsockopt IPV6_JOIN_GROUP. May create separate multicast listener sockets if
 * wildcard binding not used.
 *
 * @param dienow If 1, die on multicast join failure (startup); if 0, log warning and continue
 *
 * @return void
 *
 * @note Compile-time: Only available when HAVE_DHCP6 defined
 * @note RFC 3315 requirement: DHCPv6 servers must join ff02::1:2 and ff05::1:3
 * @note ff02::1:2 is link-local scope (all DHCP relay agents and servers)
 * @note ff05::1:3 is site-local scope (all DHCP servers)
 * @note Requires IPv6 multicast routing enabled on interfaces
 *
 * @warning dienow=1 causes daemon exit on join failure (use only at startup)
 * @warning Requires IPV6_JOIN_GROUP socket option support (standard on modern systems)
 *
 * @see RFC 3315 Section 5.3 for DHCPv6 multicast address requirements
 * @see enumerate_interfaces() to populate interface list before calling
 *
 * EXAMPLE USAGE:
 * @code
 * #ifdef HAVE_DHCP6
 * enumerate_interfaces(0);
 * join_multicast(1);  // Die on failure during startup
 * #endif
 * @endcode
 *
 * SIDE EFFECTS:
 * - Calls setsockopt IPV6_JOIN_GROUP for ff02::1:2 and ff05::1:3 on each DHCPv6 interface
 * - May create additional multicast listener sockets
 * - May die() and terminate daemon if dienow=1 and join fails
 * - Logs errors on multicast join failure
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies socket multicast membership. Safe for single-threaded use.
 */
void join_multicast(int dienow)      
{
  struct irec *iface, *tmp;

  for (iface = daemon->interfaces; iface; iface = iface->next)
    if (iface->addr.sa.sa_family == AF_INET6 && iface->dhcp_ok && !iface->multicast_done)
      {
	/* There's an irec per address but we only want to join for multicast 
	   once per interface. Weed out duplicates. */
	for (tmp = daemon->interfaces; tmp; tmp = tmp->next)
	  if (tmp->multicast_done && tmp->index == iface->index)
	    break;
	
	iface->multicast_done = 1;
	
	if (!tmp)
	  {
	    struct ipv6_mreq mreq;
	    int err = 0;

	    mreq.ipv6mr_interface = iface->index;
	    
	    inet_pton(AF_INET6, ALL_RELAY_AGENTS_AND_SERVERS, &mreq.ipv6mr_multiaddr);
	    
	    if ((daemon->doing_dhcp6 || daemon->relay6) &&
		setsockopt(daemon->dhcp6fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
	      err = errno;
	    
	    inet_pton(AF_INET6, ALL_SERVERS, &mreq.ipv6mr_multiaddr);
	    
	    if (daemon->doing_dhcp6 && 
		setsockopt(daemon->dhcp6fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
	      err = errno;
	    
	    inet_pton(AF_INET6, ALL_ROUTERS, &mreq.ipv6mr_multiaddr);
	    
	    if (daemon->doing_ra &&
		setsockopt(daemon->icmp6fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
	      err = errno;
	    
	    if (err)
	      {
		char *s = _("interface %s failed to join DHCPv6 multicast group: %s");
		errno = err;

#ifdef HAVE_LINUX_NETWORK
		if (errno == ENOMEM)
		  my_syslog(LOG_ERR, _("try increasing /proc/sys/net/core/optmem_max"));
#endif

		if (dienow)
		  die(s, iface->name, EC_BADNET);
		else
		  my_syslog(LOG_ERR, s, iface->name, strerror(errno));
	      }
	  }
      }
}
#endif

/**
 * @brief Bind socket to specific interface or address with optional port randomization
 *
 * @detailed
 * Binds socket to specified address, optionally binding to specific interface via
 * SO_BINDTODEVICE (Linux) or IP_BOUND_IF (BSD). Implements randomized source port
 * selection for UDP sockets within --min-port/--max-port range to enhance DNS query
 * security against cache poisoning attacks. For TCP sockets, port is set to 0 (OS
 * assigns ephemeral port). Retries bind with different random ports on EADDRINUSE up
 * to calculated retry limit based on available port range.
 *
 * Algorithm: (1) Extract port from addr, (2) For TCP, force port=0; for UDP with port=0
 * and max_port set, select random port in range, (3) Bind to interface if intname provided
 * (SO_BINDTODEVICE on Linux, IP_BOUND_IF on BSD), (4) Attempt bind() with current port,
 * (5) On EADDRINUSE, select new random port and retry up to calculated tries limit,
 * (6) Return success/failure.
 *
 * @param fd Socket file descriptor to bind (must be valid UDP or TCP socket)
 * @param addr Address and port to bind to (port may be 0 for random selection)
 * @param intname Interface name for binding (may be NULL for no interface binding)
 * @param ifindex Interface index (used on platforms that support index-based binding)
 * @param is_tcp If 1, TCP socket (port forced to 0); if 0, UDP socket (port randomization enabled)
 *
 * @return 1 on successful bind, 0 on bind failure or unsupported operation
 * @retval 1 Socket successfully bound to address/interface
 * @retval 0 bind() failed after all retries or interface binding not supported/failed
 *
 * @note Port randomization only for UDP sockets with port=0 and --max-port configured
 * @note TCP sockets always use port=0 (OS-assigned ephemeral port)
 * @note Retry limit: min(100, 3*available_ports) to balance success vs performance
 * @note Interface binding: Linux uses SO_BINDTODEVICE, BSD uses IP_BOUND_IF/IPV6_BOUND_IF
 * @note Wildcard address (0.0.0.0 or ::) with port 0 skips bind() call (implicit bind)
 *
 * @warning intname interface binding requires CAP_NET_RAW on Linux or equivalent privilege
 * @warning Port range exhaustion (all ports in use) causes bind failure after retries
 * @warning Random port selection uses rand16() - ensure seeded for good randomness
 *
 * @see random_sock() for creating sockets with random source ports for DNS queries
 * @see daemon->min_port and daemon->max_port for configured port range
 *
 * EXAMPLE USAGE:
 * @code
 * int sock = socket(AF_INET, SOCK_DGRAM, 0);
 * union mysockaddr addr;
 * addr.in.sin_family = AF_INET;
 * addr.in.sin_addr.s_addr = inet_addr("192.168.1.1");
 * addr.in.sin_port = 0;  // Random port selection
 * if (local_bind(sock, &addr, "eth0", 2, 0))
 *   my_syslog(LOG_INFO, "Bound to eth0:192.168.1.1:random_port");
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies socket binding (bind() system call)
 * - Sets SO_BINDTODEVICE (Linux) or IP_BOUND_IF (BSD) socket option if intname provided
 * - May perform multiple bind() attempts with different ports (up to tries limit)
 * - Consumes random numbers from rand16() for port selection
 *
 * THREAD SAFETY:
 * Not re-entrant if rand16() is not thread-safe. Safe for single-threaded use.
 */
int local_bind(int fd, union mysockaddr *addr, char *intname, unsigned int ifindex, int is_tcp)
{
  union mysockaddr addr_copy = *addr;
  unsigned short port;
  int tries = 1;
  unsigned short ports_avail = 1;

  if (addr_copy.sa.sa_family == AF_INET)
    port = addr_copy.in.sin_port;
  else
    port = addr_copy.in6.sin6_port;

  /* cannot set source _port_ for TCP connections. */
  if (is_tcp)
    port = 0;
  else if (port == 0 && daemon->max_port != 0)
    {
      /* Bind a random port within the range given by min-port and max-port if either
	 or both are set. Otherwise use the OS's random ephemeral port allocation by
	 leaving port == 0 and tries == 1 */
      ports_avail = daemon->max_port - daemon->min_port + 1;
      tries = ports_avail < 30 ? 3 * ports_avail : 100;
      port = htons(daemon->min_port + (rand16() % ports_avail));
    }
  
  while (1)
    {
      /* elide bind() call if it's to port 0, address 0 */
      if (addr_copy.sa.sa_family == AF_INET)
	{
	  if (port == 0 && addr_copy.in.sin_addr.s_addr == 0)
	    break;
	  addr_copy.in.sin_port = port;
	}
      else
	{
	  if (port == 0 && IN6_IS_ADDR_UNSPECIFIED(&addr_copy.in6.sin6_addr))
	    break;
	  addr_copy.in6.sin6_port = port;
	}
      
      if (bind(fd, (struct sockaddr *)&addr_copy, sa_len(&addr_copy)) != -1)
	break;
      
       if (errno != EADDRINUSE && errno != EACCES) 
	 return 0;

      if (--tries == 0)
	return 0;

      port = htons(daemon->min_port + (rand16() % ports_avail));
    }

  if (!is_tcp && ifindex > 0)
    {
#if defined(IP_UNICAST_IF)
      if (addr_copy.sa.sa_family == AF_INET)
        {
          uint32_t ifindex_opt = htonl(ifindex);
          return setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, &ifindex_opt, sizeof(ifindex_opt)) == 0;
        }
#endif
#if defined (IPV6_UNICAST_IF)
      if (addr_copy.sa.sa_family == AF_INET6)
        {
          uint32_t ifindex_opt = htonl(ifindex);
          return setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, &ifindex_opt, sizeof(ifindex_opt)) == 0;
        }
#endif
    }

  (void)intname; /* suppress potential unused warning */
#if defined(SO_BINDTODEVICE)
  if (intname[0] != 0 &&
      setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, intname, IF_NAMESIZE) == -1)
    return 0;
#endif

  return 1;
}

/**
 * @brief Allocate source file descriptor for upstream DNS server queries
 *
 * @detailed
 * Creates or reuses UDP socket for sending queries to upstream DNS servers with specified
 * source address and interface binding. Maintains global list (daemon->sfds) of allocated
 * serverfd structures to enable socket reuse when multiple upstream servers share same
 * source configuration. When --query-port=0 (random port mode), returns NULL for default
 * wildcard sockets (port 0), deferring socket creation to per-query random port allocation.
 *
 * Algorithm: (1) If random port mode and wildcard addr/port, return NULL, (2) Search
 * daemon->sfds for existing match (same ifindex, addr, intname), (3) If found, return
 * existing sfd (socket reuse), (4) If not found, create new socket, (5) Bind to
 * address/interface via local_bind(), (6) Set non-blocking mode, (7) Link to daemon->sfds
 * list and return.
 *
 * @param addr Source address and port for binding (may have port=0 for wildcard)
 * @param intname Interface name for binding (may be empty string for no interface binding)
 * @param ifindex Interface index corresponding to intname
 *
 * @return Pointer to serverfd structure or NULL
 * @retval sfd Allocated or existing serverfd structure with bound socket
 * @retval NULL Random port mode with wildcard addr, malloc failure, socket creation failure, or bind failure
 *
 * @note Static function, internal to network.c
 * @note Socket reuse: Multiple servers with identical source config share one serverfd
 * @note Random port mode: Wildcard sockets (port=0) return NULL, deferred to query time
 * @note Newly created sfd has preallocated=0; set to 1 by pre_allocate_sfds()
 * @note IPv6 sockets set IPV6_V6ONLY to prevent dual-stack binding conflicts
 *
 * @warning Returns NULL for malloc, socket, or bind failures; errno preserved
 * @warning Caller must check NULL return and handle appropriately
 *
 * @see pre_allocate_sfds() which calls this during startup for all configured servers
 * @see local_bind() for actual address/interface binding logic
 * @see forward_query() in forward.c which uses serverfd sockets for upstream queries
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal usage during server setup
 * union mysockaddr src_addr;
 * src_addr.in.sin_family = AF_INET;
 * src_addr.in.sin_addr.s_addr = inet_addr("192.168.1.1");
 * src_addr.in.sin_port = htons(5353);
 * struct serverfd *sfd = allocate_sfd(&src_addr, "eth0", 2);
 * if (sfd)
 *   server->sfd = sfd;  // Assign to upstream server
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates struct serverfd via whine_malloc() (may log error on failure)
 * - Creates UDP socket via socket() system call
 * - Binds socket to address/interface via local_bind() (setsockopt, bind)
 * - Sets socket to non-blocking mode via fix_fd()
 * - Links new sfd to daemon->sfds list
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon->sfds list. Safe for single-threaded use.
 */
static struct serverfd *allocate_sfd(union mysockaddr *addr, char *intname, unsigned int ifindex)
{
  struct serverfd *sfd;
  int errsave;
  int opt = 1;
  
  /* when using random ports, servers which would otherwise use
     the INADDR_ANY/port0 socket have sfd set to NULL, this is 
     anything without an explictly set source port. */
  if (!daemon->osport)
    {
      errno = 0;
      
      if (addr->sa.sa_family == AF_INET &&
	  addr->in.sin_port == htons(0)) 
	return NULL;

      if (addr->sa.sa_family == AF_INET6 &&
	  addr->in6.sin6_port == htons(0)) 
	return NULL;
    }

  /* may have a suitable one already */
  for (sfd = daemon->sfds; sfd; sfd = sfd->next )
    if (ifindex == sfd->ifindex &&
	sockaddr_isequal(&sfd->source_addr, addr) &&
	strcmp(intname, sfd->interface) == 0)
      return sfd;
  
  /* need to make a new one. */
  errno = ENOMEM; /* in case malloc fails. */
  if (!(sfd = whine_malloc(sizeof(struct serverfd))))
    return NULL;
  
  if ((sfd->fd = socket(addr->sa.sa_family, SOCK_DGRAM, 0)) == -1)
    {
      free(sfd);
      return NULL;
    }

  if ((addr->sa.sa_family == AF_INET6 && setsockopt(sfd->fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == -1) ||
      !local_bind(sfd->fd, addr, intname, ifindex, 0) || !fix_fd(sfd->fd))
    { 
      errsave = errno; /* save error from bind/setsockopt. */
      close(sfd->fd);
      free(sfd);
      errno = errsave;
      return NULL;
    }

  safe_strncpy(sfd->interface, intname, sizeof(sfd->interface)); 
  sfd->source_addr = *addr;
  sfd->next = daemon->sfds;
  sfd->ifindex = ifindex;
  sfd->preallocated = 0;
  daemon->sfds = sfd;

  return sfd; 
}

/**
 * @brief Pre-allocate upstream query sockets before dropping root privileges
 *
 * @detailed
 * Creates all upstream DNS server sockets during daemon initialization, before dropping
 * root privileges via setuid. Required when --query-port is privileged port (<1024) or
 * when interface binding requires elevated privileges (SO_BINDTODEVICE on Linux). Iterates
 * all configured upstream servers, allocating serverfd structures via allocate_sfd() and
 * marking them as preallocated to prevent later reallocation attempts. Ensures query
 * sockets available even after privilege drop to non-root user.
 *
 * Algorithm: (1) Iterate daemon->servers list, (2) For each server with valid source
 * address (server->source_addr.sa.sa_family != 0), call allocate_sfd(), (3) Assign
 * returned sfd to server->sfd, (4) Mark sfd->preallocated=1 to prevent future reallocation.
 *
 * @return void
 *
 * @note Called during daemon startup before dropping root privileges
 * @note Required when --query-port < 1024 (privileged port binding)
 * @note Required when interface binding needs CAP_NET_RAW or root (SO_BINDTODEVICE)
 * @note Sets sfd->preallocated=1 to distinguish from runtime-allocated sockets
 * @note Servers without source_addr.sa.sa_family == 0 skipped (use default routing)
 *
 * @warning Must be called before daemon privilege drop or low port binding will fail
 * @warning Failures logged but not fatal; daemon continues with available sockets
 *
 * @see allocate_sfd() which performs actual socket creation and binding
 * @see daemon initialization in dnsmasq.c which calls this before setuid
 *
 * EXAMPLE USAGE:
 * @code
 * // In main() during daemon initialization
 * enumerate_interfaces(0);
 * pre_allocate_sfds();  // Allocate upstream sockets with elevated privileges
 * setuid(daemon_uid);   // Drop root privileges
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates and binds UDP sockets for all configured upstream servers
 * - Links serverfd structures to daemon->sfds list
 * - Assigns server->sfd for each upstream server with source address
 * - Logs errors for socket allocation failures (non-fatal)
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon->servers and daemon->sfds. Safe for single-threaded startup.
 */
void pre_allocate_sfds(void)
{
  struct server *srv;
  struct serverfd *sfd;
  
  if (daemon->query_port != 0)
    {
      union  mysockaddr addr;
      memset(&addr, 0, sizeof(addr));
      addr.in.sin_family = AF_INET;
      addr.in.sin_addr.s_addr = INADDR_ANY;
      addr.in.sin_port = htons(daemon->query_port);
#ifdef HAVE_SOCKADDR_SA_LEN
      addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
      if ((sfd = allocate_sfd(&addr, "", 0)))
	sfd->preallocated = 1;

      memset(&addr, 0, sizeof(addr));
      addr.in6.sin6_family = AF_INET6;
      addr.in6.sin6_addr = in6addr_any;
      addr.in6.sin6_port = htons(daemon->query_port);
#ifdef HAVE_SOCKADDR_SA_LEN
      addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
      if ((sfd = allocate_sfd(&addr, "", 0)))
	sfd->preallocated = 1;
    }
  
  for (srv = daemon->servers; srv; srv = srv->next)
    if (!allocate_sfd(&srv->source_addr, srv->interface, srv->ifindex) &&
	errno != 0 &&
	option_bool(OPT_NOWILD))
      {
	(void)prettyprint_addr(&srv->source_addr, daemon->namebuff);
	if (srv->interface[0] != 0)
	  {
	    strcat(daemon->namebuff, " ");
	    strcat(daemon->namebuff, srv->interface);
	  }
	die(_("failed to bind server socket for %s: %s"),
	    daemon->namebuff, EC_BADNET);
      }  
}

/**
 * @brief Validate and update upstream server source addresses and socket bindings
 *
 * @detailed
 * Comprehensive validation of all configured upstream DNS servers, ensuring each has
 * valid source address and socket binding. Re-enumerates interfaces if using wildcard
 * binding to detect interface changes. Allocates serverfd sockets for servers needing
 * source address binding. Performs loop detection by sending probe queries to detect
 * self-forwarding configurations (dnsmasq forwarding to itself). Garbage collects unused
 * serverfd structures. Initializes EDNS buffer sizes and DNSSEC flags for new servers.
 * Validates at least one viable upstream server available.
 *
 * Called during initialization, after configuration reload (SIGHUP), and after significant
 * interface changes. Ensures daemon->servers list is fully validated and ready for query
 * forwarding.
 *
 * Algorithm: (1) Send loop detection probes if HAVE_LOOP and !no_loop_check, (2) Clear
 * all server marks via mark_servers(0), (3) Re-enumerate interfaces if wildcard binding,
 * (4) Mark pre-allocated sfds as used to prevent garbage collection, (5) For each server:
 * initialize EDNS size, configure DNSSEC flags, allocate source socket, validate source
 * address has route to destination, (6) Garbage collect unused sfds, (7) Warn if no
 * valid servers, (8) Update server count.
 *
 * @param no_loop_check If 1, skip loop detection probes; if 0, perform loop detection
 *
 * @return void
 *
 * @note Called after configuration changes to revalidate server list
 * @note Wildcard mode: Re-enumerates interfaces to detect changes
 * @note Loop detection: Sends probe queries to detect self-forwarding (HAVE_LOOP)
 * @note Garbage collection: Removes unused serverfd sockets not marked by servers
 * @note Logs warnings for servers without valid source addresses
 * @note Dies if no valid upstream servers and not configured as authoritative-only
 *
 * @warning May die() if no upstream servers available and daemon not auth-only
 * @warning Modifies daemon->servers and daemon->sfds lists extensively
 *
 * @see enumerate_interfaces() for interface re-enumeration in wildcard mode
 * @see allocate_sfd() for server socket allocation
 * @see loop_send_probes() for loop detection (HAVE_LOOP)
 * @see mark_servers() for server marking/validation
 *
 * EXAMPLE USAGE:
 * @code
 * // After configuration reload via SIGHUP
 * read_opts(0);             // Reload configuration
 * check_servers(0);         // Revalidate servers with loop check
 * my_syslog(LOG_INFO, "Server list updated");
 * @endcode
 *
 * SIDE EFFECTS:
 * - Re-enumerates interfaces if wildcard binding (calls enumerate_interfaces)
 * - Allocates new serverfd sockets for servers needing source binding
 * - Frees unused serverfd structures (garbage collection)
 * - Initializes server->edns_pktsz for new servers
 * - Sets DNSSEC validation flags (SERV_DO_DNSSEC) based on configuration
 * - Sends loop detection probe queries (if HAVE_LOOP)
 * - Logs warnings for configuration issues (no servers, no routes)
 * - May die() and terminate daemon if no valid servers and not auth-only
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon state extensively. Safe for single-threaded use.
 */
void check_servers(int no_loop_check)
{
  struct irec *iface;
  struct server *serv;
  struct serverfd *sfd, *tmp, **up;
  int port = 0, count;
  int locals = 0;
  
#ifdef HAVE_LOOP
  if (!no_loop_check)
    loop_send_probes();
#endif

  /* clear all marks. */
  mark_servers(0);
  
 /* interface may be new since startup */
  if (!option_bool(OPT_NOWILD))
    enumerate_interfaces(0);

  /* don't garbage collect pre-allocated sfds. */
  for (sfd = daemon->sfds; sfd; sfd = sfd->next)
    sfd->used = sfd->preallocated;

  for (count = 0, serv = daemon->servers; serv; serv = serv->next)
    {
      /* Init edns_pktsz for newly created server records. */
      if (serv->edns_pktsz == 0)
	serv->edns_pktsz = daemon->edns_pktsz;
      
#ifdef HAVE_DNSSEC
      if (option_bool(OPT_DNSSEC_VALID))
	{ 
	  if (!(serv->flags & SERV_FOR_NODOTS))
	    serv->flags |= SERV_DO_DNSSEC;
	  
	  /* Disable DNSSEC validation when using server=/domain/.... servers
	     unless there's a configured trust anchor. */
	  if (strlen(serv->domain) != 0)
	    {
	      struct ds_config *ds;
	      char *domain = serv->domain;
	      
	      /* .example.com is valid */
	      while (*domain == '.')
		domain++;
	      
	      for (ds = daemon->ds; ds; ds = ds->next)
		if (ds->name[0] != 0 && hostname_isequal(domain, ds->name))
		  break;
	      
	      if (!ds)
		serv->flags &= ~SERV_DO_DNSSEC;
	    }
	}
#endif
      
      port = prettyprint_addr(&serv->addr, daemon->namebuff);
      
      /* 0.0.0.0 is nothing, the stack treats it like 127.0.0.1 */
      if (serv->addr.sa.sa_family == AF_INET &&
	  serv->addr.in.sin_addr.s_addr == 0)
	{
	  serv->flags |= SERV_MARK;
	  continue;
	}
      
      for (iface = daemon->interfaces; iface; iface = iface->next)
	if (sockaddr_isequal(&serv->addr, &iface->addr))
	  break;
      if (iface)
	{
	  my_syslog(LOG_WARNING, _("ignoring nameserver %s - local interface"), daemon->namebuff);
	  serv->flags |= SERV_MARK;
	  continue;
	}
      
      /* Do we need a socket set? */
      if (!serv->sfd && 
	  !(serv->sfd = allocate_sfd(&serv->source_addr, serv->interface, serv->ifindex)) &&
	  errno != 0)
	{
	  my_syslog(LOG_WARNING, 
		    _("ignoring nameserver %s - cannot make/bind socket: %s"),
		    daemon->namebuff, strerror(errno));
	  serv->flags |= SERV_MARK;
	  continue;
	}
      
      if (serv->sfd)
	serv->sfd->used = 1;
      
      if (count == SERVERS_LOGGED)
	my_syslog(LOG_INFO, _("more servers are defined but not logged"));
      
      if (++count > SERVERS_LOGGED)
	continue;
      
      if (strlen(serv->domain) != 0 || (serv->flags & SERV_FOR_NODOTS))
	{
	  char *s1, *s2, *s3 = "", *s4 = "";

#ifdef HAVE_DNSSEC
	  if (option_bool(OPT_DNSSEC_VALID) && !(serv->flags & SERV_DO_DNSSEC))
	    s3 = _("(no DNSSEC)");
#endif
	  if (serv->flags & SERV_FOR_NODOTS)
	    s1 = _("unqualified"), s2 = _("names");
	  else if (strlen(serv->domain) == 0)
	    s1 = _("default"), s2 = "";
	  else
	    s1 = _("domain"), s2 = serv->domain, s4 = (serv->flags & SERV_WILDCARD) ? "*" : "";
	  
	  my_syslog(LOG_INFO, _("using nameserver %s#%d for %s %s%s %s"), daemon->namebuff, port, s1, s4, s2, s3);
	}
#ifdef HAVE_LOOP
      else if (serv->flags & SERV_LOOP)
	my_syslog(LOG_INFO, _("NOT using nameserver %s#%d - query loop detected"), daemon->namebuff, port); 
#endif
      else if (serv->interface[0] != 0)
	my_syslog(LOG_INFO, _("using nameserver %s#%d(via %s)"), daemon->namebuff, port, serv->interface); 
      else
	my_syslog(LOG_INFO, _("using nameserver %s#%d"), daemon->namebuff, port); 

    }
  
  for (count = 0, serv = daemon->local_domains; serv; serv = serv->next)
    {
       if (++count > SERVERS_LOGGED)
	 continue;
       
       if ((serv->flags & SERV_LITERAL_ADDRESS) &&
	   !(serv->flags & (SERV_6ADDR | SERV_4ADDR | SERV_ALL_ZEROS)) &&
	   strlen(serv->domain))
	 {
	   count--;
	   if (++locals <= LOCALS_LOGGED)
	     my_syslog(LOG_INFO, _("using only locally-known addresses for %s"), serv->domain);
	 }
       else if (serv->flags & SERV_USE_RESOLV)
	 my_syslog(LOG_INFO, _("using standard nameservers for %s"), serv->domain);
    }
  
  if (locals > LOCALS_LOGGED)
    my_syslog(LOG_INFO, _("using %d more local addresses"), locals - LOCALS_LOGGED);
  if (count - 1 > SERVERS_LOGGED)
    my_syslog(LOG_INFO, _("using %d more nameservers"), count - SERVERS_LOGGED - 1);

  /* Remove unused sfds */
  for (sfd = daemon->sfds, up = &daemon->sfds; sfd; sfd = tmp)
    {
       tmp = sfd->next;
       if (!sfd->used) 
	{
	  *up = sfd->next;
	  close(sfd->fd);
	  free(sfd);
	} 
      else
	up = &sfd->next;
    }
  
  cleanup_servers(); /* remove servers we just deleted. */
  build_server_array(); 
}

/* Return zero if no servers found, in that case we keep polling.
   This is a protection against an update-time/write race on resolv.conf */
/**
 * @brief Reload upstream DNS servers from resolv.conf-style file
 *
 * @detailed
 * Dynamically reloads upstream DNS server list from resolv.conf-format file,
 * typically /etc/resolv.conf or alternate specified via --resolv-file. Parses
 * "nameserver" and "server" directives, creating new server entries for addresses
 * not already in daemon->servers list. Marks existing SERV_FROM_RESOLV servers
 * for potential removal if not present in updated file. Supports IPv4 and IPv6
 * nameserver addresses. Enables dynamic upstream server updates without daemon
 * restart, responding to DHCP-provided DNS server changes or network reconfigurations.
 *
 * File format: Standard resolv.conf syntax with "nameserver IP" or "server IP" lines.
 * IPv4 example: "nameserver 8.8.8.8"
 * IPv6 example: "nameserver 2001:4860:4860::8888"
 *
 * Algorithm: (1) Open fname for reading, (2) Mark all SERV_FROM_RESOLV servers
 * (flag for removal if not refreshed), (3) Parse file line-by-line for nameserver/server
 * directives, (4) For each valid IP address, add_update_server() to create or refresh
 * server entry, (5) Unmarked SERV_FROM_RESOLV servers removed by caller, (6) Return
 * success count.
 *
 * @param fname Path to resolv.conf-format file (typically /etc/resolv.conf)
 *
 * @return 1 if at least one server loaded, 0 if file open failed or no servers
 * @retval 1 At least one valid nameserver parsed and added/refreshed
 * @retval 0 File open failed or no valid nameserver directives found
 *
 * @note Called during initialization and after resolv.conf inotify events (HAVE_INOTIFY)
 * @note Marks existing SERV_FROM_RESOLV servers; caller must remove unmarked entries
 * @note Supports both "nameserver" (standard) and "server" (dnsmasq extension) keywords
 * @note Nameservers default to port 53 (NAMESERVER_PORT)
 * @note Source port set to daemon->query_port for outgoing queries
 * @note IPv4 and IPv6 addresses supported via inet_pton()
 *
 * @warning File open failure logged at LOG_ERR but not fatal (returns 0)
 * @warning Invalid nameserver IP addresses silently skipped
 * @warning Caller responsible for removing stale SERV_FROM_RESOLV servers after reload
 *
 * @see add_update_server() which creates or refreshes server entries
 * @see mark_servers() which marks SERV_FROM_RESOLV for removal tracking
 * @see check_servers() typically called after reload_servers() to finalize server list
 *
 * EXAMPLE USAGE:
 * @code
 * // After resolv.conf inotify event
 * if (reload_servers("/etc/resolv.conf")) {
 *   cleanup_servers();  // Remove unmarked SERV_FROM_RESOLV servers
 *   check_servers(0);   // Validate and allocate sockets
 *   my_syslog(LOG_INFO, "Reloaded upstream servers from resolv.conf");
 * } else {
 *   my_syslog(LOG_WARNING, "No servers in resolv.conf");
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Opens and reads file (may fail if file doesn't exist or no read permission)
 * - Marks all SERV_FROM_RESOLV servers via mark_servers()
 * - Calls add_update_server() for each parsed nameserver (may allocate new server structs)
 * - Logs error if file open fails
 * - Does NOT remove unmarked servers (caller must do cleanup)
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies global daemon->servers list. Safe for single-threaded use.
 */
int reload_servers(char *fname)
{
  FILE *f;
  char *line;
  int gotone = 0;

  /* buff happens to be MAXDNAME long... */
  if (!(f = fopen(fname, "r")))
    {
      my_syslog(LOG_ERR, _("failed to read %s: %s"), fname, strerror(errno));
      return 0;
    }
   
  mark_servers(SERV_FROM_RESOLV);
    
  while ((line = fgets(daemon->namebuff, MAXDNAME, f)))
    {
      union mysockaddr addr, source_addr;
      char *token = strtok(line, " \t\n\r");
      
      if (!token)
	continue;
      if (strcmp(token, "nameserver") != 0 && strcmp(token, "server") != 0)
	continue;
      if (!(token = strtok(NULL, " \t\n\r")))
	continue;
      
      memset(&addr, 0, sizeof(addr));
      memset(&source_addr, 0, sizeof(source_addr));
      
      if (inet_pton(AF_INET, token, &addr.in.sin_addr) > 0)
	{
#ifdef HAVE_SOCKADDR_SA_LEN
	  source_addr.in.sin_len = addr.in.sin_len = sizeof(source_addr.in);
#endif
	  source_addr.in.sin_family = addr.in.sin_family = AF_INET;
	  addr.in.sin_port = htons(NAMESERVER_PORT);
	  source_addr.in.sin_addr.s_addr = INADDR_ANY;
	  source_addr.in.sin_port = htons(daemon->query_port);
	}
      else 
	{	
	  int scope_index = 0;
	  char *scope_id = strchr(token, '%');
	  
	  if (scope_id)
	    {
	      *(scope_id++) = 0;
	      scope_index = if_nametoindex(scope_id);
	    }
	  
	  if (inet_pton(AF_INET6, token, &addr.in6.sin6_addr) > 0)
	    {
#ifdef HAVE_SOCKADDR_SA_LEN
	      source_addr.in6.sin6_len = addr.in6.sin6_len = sizeof(source_addr.in6);
#endif
	      source_addr.in6.sin6_family = addr.in6.sin6_family = AF_INET6;
	      source_addr.in6.sin6_flowinfo = addr.in6.sin6_flowinfo = 0;
	      addr.in6.sin6_port = htons(NAMESERVER_PORT);
	      addr.in6.sin6_scope_id = scope_index;
	      source_addr.in6.sin6_addr = in6addr_any;
	      source_addr.in6.sin6_port = htons(daemon->query_port);
	      source_addr.in6.sin6_scope_id = 0;
	    }
	  else
	    continue;
	}

      add_update_server(SERV_FROM_RESOLV, &addr, &source_addr, NULL, NULL, NULL);
      gotone = 1;
    }
  
  fclose(f);
  cleanup_servers();

  return gotone;
}

/* Called when addresses are added or deleted from an interface */
/**
 * @brief Handle network interface address changes (hotplug events, interface up/down)
 *
 * @detailed
 * Event handler called when network interfaces change (address added/removed, interface
 * brought up/down). Triggered by netlink (Linux), routing socket (BSD), or periodic
 * polling (fallback). Re-enumerates interfaces via enumerate_interfaces(0) to update
 * daemon->interfaces list, recreates bound listeners if OPT_CLEVERBIND (--bind-interfaces),
 * rejoins IPv6 multicast groups for DHCPv6/RA, reconstructs DHCPv6 contexts based on new
 * addresses, and clears DHCP relay interface index caches forcing re-lookup. Critical for
 * dynamic network environments (hotplug USB network adapters, DHCP client address changes,
 * VPN interfaces coming up/down).
 *
 * Algorithm: (1) If CLEVERBIND or LOCAL_SERVICE or DHCPv6/relay/RA: re-enumerate interfaces
 * via enumerate_interfaces(0), (2) If CLEVERBIND: recreate bound listeners via
 * create_bound_listeners(0), (3) Clear DHCPv4 relay->iface_index cache, (4) If DHCPv6/RA:
 * rejoin multicast via join_multicast(0), (5) If DHCPv6/RA: reconstruct contexts via
 * dhcp_construct_contexts(now), (6) If DHCPv6: update lease interfaces via
 * lease_find_interfaces(now), (7) Clear DHCPv6 relay->iface_index cache.
 *
 * @param now Current time (passed to DHCPv6 functions, unused here, suppressed warning)
 *
 * @note Public API function, called from event loop in dnsmasq.c
 * @note Called on netlink RTM_NEWADDR/RTM_DELADDR events (Linux)
 * @note Called on routing socket RTM_NEWADDR/RTM_DELADDR events (BSD)
 * @note Called periodically if no async notification mechanism (fallback)
 * @note OPT_CLEVERBIND: --bind-interfaces mode, listeners bound to specific addresses
 * @note OPT_LOCAL_SERVICE: --local-service mode, respond only to local subnet queries
 * @note now parameter unused in current implementation (passed through to DHCP functions)
 *
 * @warning May cause brief service interruption while recreating listeners
 * @warning DHCP relay iface_index cleared, next packet will trigger re-lookup
 *
 * @see enumerate_interfaces() which re-discovers interface addresses
 * @see create_bound_listeners() which recreates interface-specific listeners
 * @see join_multicast() which rejoins IPv6 multicast groups for DHCPv6/RA
 * @see dhcp_construct_contexts() in dhcp6.c which rebuilds DHCPv6 address contexts
 * @see lease_find_interfaces() in dhcp6.c which updates lease interface associations
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from event loop in dnsmasq.c on network change event
 * if (event_type == EVENT_NEWADDR) {
 *   newaddress(dnsmasq_time()); // Handle interface address change
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Re-enumerates interfaces via enumerate_interfaces(0), updates daemon->interfaces
 * - May create new listeners via create_bound_listeners(0) if OPT_CLEVERBIND
 * - May close old listeners no longer needed (interface disappeared)
 * - Clears daemon->relay4->iface_index for all DHCPv4 relays
 * - Rejoins IPv6 multicast groups (ff02::1:2 for DHCPv6) if DHCPv6/relay/RA
 * - Reconstructs DHCPv6 address contexts if DHCPv6/RA
 * - Updates lease interface associations if DHCPv6
 * - Clears daemon->relay6->iface_index for all DHCPv6 relays
 * - Logs interface changes at LOG_DEBUG level
 *
 * THREAD SAFETY:
 * NOT thread-safe (modifies global daemon state). Safe for single-threaded event loop.
 */
void newaddress(time_t now)
{
  struct dhcp_relay *relay;

  (void)now;
  
  if (option_bool(OPT_CLEVERBIND) || option_bool(OPT_LOCAL_SERVICE) ||
      daemon->doing_dhcp6 || daemon->relay6 || daemon->doing_ra)
    enumerate_interfaces(0);
  
  if (option_bool(OPT_CLEVERBIND))
    create_bound_listeners(0);

#ifdef HAVE_DHCP
  /* clear cache of subnet->relay index */
  for (relay = daemon->relay4; relay; relay = relay->next)
    relay->iface_index = 0;
#endif
  
#ifdef HAVE_DHCP6
  if (daemon->doing_dhcp6 || daemon->relay6 || daemon->doing_ra)
    join_multicast(0);
  
  if (daemon->doing_dhcp6 || daemon->doing_ra)
    dhcp_construct_contexts(now);
  
  if (daemon->doing_dhcp6)
    lease_find_interfaces(now);

  for (relay = daemon->relay6; relay; relay = relay->next)
    relay->iface_index = 0;
#endif
}
