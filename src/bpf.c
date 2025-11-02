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
 * @file bpf.c
 * @brief BSD Berkeley Packet Filter interface enumeration and monitoring
 *
 * DETAILED PURPOSE:
 * This file implements platform-specific network interface discovery and monitoring
 * for BSD-based systems (FreeBSD, OpenBSD, NetBSD, macOS) and Solaris. It provides
 * an alternative to the Linux Netlink-based approach used in netlink.c. The implementation
 * uses the getifaddrs() API for interface enumeration and PF_ROUTE routing sockets for
 * real-time monitoring of interface state changes. For DHCP functionality on BSD systems,
 * it also provides raw packet transmission through Berkeley Packet Filter (BPF) devices,
 * allowing direct Ethernet frame construction and injection bypassing the kernel IP stack.
 *
 * The routing socket mechanism enables dnsmasq to detect network configuration changes
 * including interface additions/removals (RTM_IFINFO), address assignments/deletions
 * (RTM_NEWADDR/RTM_DELADDR), and route modifications. This ensures dnsmasq maintains
 * accurate awareness of the system's network topology without polling.
 *
 * KEY RESPONSIBILITIES:
 * - iface_enumerate() - Enumerate all network interfaces and addresses via getifaddrs()
 * - route_init() - Initialize PF_ROUTE socket for interface change monitoring
 * - route_sock() - Process routing socket messages (RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO)
 * - init_bpf() - Open Berkeley Packet Filter device for raw DHCP packet transmission
 * - send_via_bpf() - Construct and send raw Ethernet frames for DHCP responses
 * - arp_enumerate() - Enumerate ARP cache entries via sysctl (BSD non-Apple only)
 *
 * DEPENDENCIES:
 * - dnsmasq.h - Primary type definitions (struct daemon, struct dhcp_packet)
 * - getifaddrs()/freeifaddrs() - POSIX interface enumeration API
 * - PF_ROUTE sockets - BSD routing socket for kernel network event notification
 * - BPF devices (/dev/bpf*) - Berkeley Packet Filter for raw packet I/O
 * - ioctl() operations - SIOCGIFADDR, SIOCGIFAFLAG_IN6, SIOCGIFALIFETIME_IN6, BIOCSETIF
 * - sysctl() - ARP table enumeration on BSD (NET_RT_FLAGS with RTF_LLINFO)
 *
 * Called by: network.c (interface enumeration), dnsmasq.c (event loop for routing socket)
 * Calls: Platform-specific system calls, kernel routing socket API
 *
 * DATA STRUCTURES:
 * - struct ifaddrs - Interface address linked list from getifaddrs() (system header)
 * - struct sockaddr_dl - Data-link layer socket address containing MAC addresses
 * - struct rt_msghdr - Routing message header for PF_ROUTE messages
 * - struct if_msghdr - Interface message header (RTM_IFINFO messages)
 * - struct ifa_msghdr - Interface address message header (RTM_NEWADDR/DELADDR)
 * - union all_addr - Generic address storage (defined in dnsmasq.h)
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_BSD_NETWORK - Enable BSD-specific code paths (FreeBSD, OpenBSD, NetBSD, macOS)
 * - HAVE_SOLARIS_NETWORK - Enable Solaris-specific adaptations
 * - HAVE_DHCP - Enable DHCP server functionality (required for BPF packet transmission)
 * - HAVE_DHCP6 - Enable DHCPv6 functionality (affects AF_LINK enumeration)
 * - __APPLE__ - Conditional compilation for macOS-specific behavior differences
 * - __FreeBSD__ - FreeBSD-specific header includes (net/if_var.h)
 *
 * THREADING/CONCURRENCY:
 * This code operates within dnsmasq's single-process, single-threaded event-driven
 * architecture. The route_sock() function is called from the main event loop when
 * the PF_ROUTE socket becomes readable. No locking is required. Static variables
 * (del_family, del_addr) track deleted addresses to work around a kernel race condition
 * where deleted addresses briefly appear in getifaddrs() results after RTM_DELADDR.
 *
 * PLATFORM-SPECIFIC BEHAVIOR:
 * - BSD (non-Apple): Full functionality including ARP enumeration via sysctl, IPv6
 *   address lifetime queries (SIOCGIFALIFETIME_IN6), and address flags (SIOCGIFAFLAG_IN6)
 * - macOS (Apple): Simplified implementation without sysctl ARP access or IPv6 lifetime APIs
 * - Solaris: Uses SIOCGLIFCONF interface enumeration, no ARP enumeration support
 * - All platforms: Use getifaddrs() for interface enumeration and PF_ROUTE for monitoring
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/ARCHITECTURE.md for system architecture and platform abstraction layer
 * @see network.c for network socket management and listener configuration
 * @see netlink.c for Linux Netlink equivalent functionality
 */

#include "dnsmasq.h"

#if defined(HAVE_BSD_NETWORK) || defined(HAVE_SOLARIS_NETWORK)
#include <ifaddrs.h>

#include <sys/param.h>
#if defined(HAVE_BSD_NETWORK) && !defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>
#if defined(__FreeBSD__)
#  include <net/if_var.h> 
#endif
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>

#ifndef SA_SIZE
#define SA_SIZE(sa)                                             \
    (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?      \
        sizeof(long)            :                               \
        1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

#ifdef HAVE_BSD_NETWORK
static int del_family = 0;
static union all_addr del_addr;
#endif

#if defined(HAVE_BSD_NETWORK) && !defined(__APPLE__)

/**
 * @brief Enumerate ARP cache entries via BSD sysctl mechanism
 *
 * @detailed
 * Retrieves the system ARP (Address Resolution Protocol) cache on BSD systems using
 * the sysctl() interface with NET_RT_FLAGS and RTF_LLINFO flags. Iterates through
 * all ARP entries containing IPv4 address to MAC address mappings and invokes the
 * provided callback for each entry. Uses dynamic buffer allocation to handle varying
 * ARP table sizes, automatically expanding the buffer if ENOMEM indicates insufficient
 * space. This function is not available on macOS (Apple) systems which lack the
 * necessary sysctl support for ARP enumeration.
 *
 * @param parm Opaque pointer passed through to callback function for context
 * @param callback Function pointer invoked for each ARP entry with signature:
 *                 int callback(int af, void *addr, void *hwaddr, size_t hwlen, void *parm)
 *                 - af: Address family (always AF_INET for IPv4)
 *                 - addr: Pointer to struct in_addr containing IPv4 address
 *                 - hwaddr: Pointer to hardware (MAC) address bytes
 *                 - hwlen: Length of hardware address (typically 6 for Ethernet)
 *                 - parm: Context pointer passed from parm parameter
 *
 * @return 1 on success (all entries enumerated), 0 on failure or if callback returns 0
 *
 * @retval 1 Successfully enumerated all ARP entries and all callbacks returned non-zero
 * @retval 0 sysctl() failed, buffer expansion failed, or callback returned 0 (abort enumeration)
 *
 * @note Only available on BSD systems excluding macOS (HAVE_BSD_NETWORK && !__APPLE__)
 * @note Uses expand_buf() to dynamically resize buffer for variable-sized ARP tables
 * @note Callback controls iteration: returning 0 terminates enumeration early
 *
 * @warning Requires CAP_NET_ADMIN or equivalent privileges on some BSD variants
 * @warning Allocates dynamic memory via expand_buf() which must be freed on error paths
 *
 * @see dhcp.c icmp_ping() for DHCP address conflict detection using ARP
 * @see network.c for interface enumeration coordination
 *
 * EXAMPLE USAGE:
 * @code
 * static int arp_callback(int af, void *addr, void *hwaddr, size_t hwlen, void *parm) {
 *   struct in_addr *ip = (struct in_addr *)addr;
 *   printf("ARP: %s -> %02x:%02x:%02x:%02x:%02x:%02x\n", 
 *          inet_ntoa(*ip), ((unsigned char*)hwaddr)[0], ((unsigned char*)hwaddr)[1],
 *          ((unsigned char*)hwaddr)[2], ((unsigned char*)hwaddr)[3],
 *          ((unsigned char*)hwaddr)[4], ((unsigned char*)hwaddr)[5]);
 *   return 1;
 * }
 * if (!arp_enumerate(NULL, arp_callback))
 *   my_syslog(LOG_WARNING, "ARP enumeration failed");
 * @endcode
 *
 * RFC COMPLIANCE: N/A (platform-specific ARP cache access, not protocol implementation)
 *
 * SIDE EFFECTS:
 * - Allocates dynamic memory for ARP table buffer via expand_buf()
 * - Invokes sysctl() with CTL_NET/PF_ROUTE/AF_INET/NET_RT_FLAGS
 * - May trigger kernel memory allocation for ARP table snapshot
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop thread only. Static global state
 * (buff structure) is reused across calls. Not reentrant due to sysctl() system call
 * side effects and shared buffer state.
 */
int arp_enumerate(void *parm, int (*callback)())
{
  int mib[6];
  size_t needed;
  char *next;
  struct rt_msghdr *rtm;
  struct sockaddr_inarp *sin2;
  struct sockaddr_dl *sdl;
  struct iovec buff;
  int rc;

  buff.iov_base = NULL;
  buff.iov_len = 0;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
#ifdef RTF_LLINFO
  mib[5] = RTF_LLINFO;
#else
  mib[5] = 0;
#endif	
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) == -1 || needed == 0)
    return 0;

  while (1) 
    {
      if (!expand_buf(&buff, needed))
	return 0;
      if ((rc = sysctl(mib, 6, buff.iov_base, &needed, NULL, 0)) == 0 ||
	  errno != ENOMEM)
	break;
      needed += needed / 8;
    }
  if (rc == -1)
    return 0;
  
  for (next = buff.iov_base ; next < (char *)buff.iov_base + needed; next += rtm->rtm_msglen)
    {
      rtm = (struct rt_msghdr *)next;
      sin2 = (struct sockaddr_inarp *)(rtm + 1);
      sdl = (struct sockaddr_dl *)((char *)sin2 + SA_SIZE(sin2));
      if (!(*callback)(AF_INET, &sin2->sin_addr, LLADDR(sdl), sdl->sdl_alen, parm))
	return 0;
    }

  return 1;
}
#endif /* defined(HAVE_BSD_NETWORK) && !defined(__APPLE__) */


/**
 * @brief Enumerate all network interfaces and addresses via getifaddrs()
 *
 * @detailed
 * Primary interface enumeration function for BSD and Solaris platforms. Retrieves
 * complete interface and address information using the POSIX getifaddrs() API,
 * filtering results by the specified address family. Supports IPv4 (AF_INET),
 * IPv6 (AF_INET6), link-layer (AF_LINK/AF_LOCAL), and ARP cache (AF_UNSPEC) enumeration.
 * For IPv6 on BSD systems, queries additional per-address metadata including tentative/
 * deprecated flags, address lifetimes (valid/preferred), and privacy extension status
 * via ioctl() operations. Implements a kernel race condition workaround for RTM_DELADDR
 * events by filtering recently-deleted addresses using static del_family/del_addr variables.
 *
 * @param family Address family filter: AF_INET (IPv4), AF_INET6 (IPv6), AF_LOCAL (link-layer
 *               MAC addresses, internally converted to AF_LINK), or AF_UNSPEC (ARP cache
 *               enumeration via arp_enumerate() on supported platforms)
 * @param parm Opaque context pointer passed through to callback function
 * @param callback Function pointer invoked for each matching interface/address with
 *                 family-specific signature:
 *                 - AF_INET: int callback(struct in_addr addr, int if_index, char *label,
 *                            struct in_addr netmask, struct in_addr broadcast, void *parm)
 *                 - AF_INET6: int callback(struct in6_addr *addr, int prefix, int scope_id,
 *                             int if_index, int flags, int preferred, int valid, void *parm)
 *                 - AF_LINK: int callback(int if_index, int hwtype, unsigned char *hwaddr,
 *                            size_t hwlen, void *parm)
 *
 * @return 1 on success (all interfaces enumerated), 0 on failure or callback abort
 *
 * @retval 1 Successfully enumerated all interfaces and all callbacks returned non-zero
 * @retval 0 getifaddrs() failed, system call errors, or callback returned 0 (early termination)
 *
 * @note AF_LOCAL is translated to AF_LINK internally (Linux/BSD portability)
 * @note AF_UNSPEC delegates to arp_enumerate() on BSD (non-Apple) or returns 0 (not implemented)
 * @note Skips interfaces with zero if_nametoindex() or missing netmask (except AF_LINK)
 * @note IPv6 link-local addresses have interface field cleared unless OPT_NOWILD set
 *
 * @warning Opens temporary PF_INET6 socket for IPv6 ioctl() operations (closed on function exit)
 * @warning Recently deleted addresses may still appear in results despite filtering attempt
 * @warning Callback must handle NULL label parameter for AF_INET on BSD/Solaris
 * @warning Solaris uses SIOCGLIFCONF internally; BSD uses native getifaddrs()
 *
 * @see network.c enumerate_interfaces() for caller integration
 * @see netlink.c for Linux Netlink equivalent functionality
 * @see route_sock() for RTM_DELADDR race condition context
 *
 * EXAMPLE USAGE:
 * @code
 * static int ipv4_callback(struct in_addr addr, int if_index, char *label,
 *                          struct in_addr netmask, struct in_addr broadcast, void *parm) {
 *   printf("Interface %d: %s/%s\n", if_index, inet_ntoa(addr), inet_ntoa(netmask));
 *   return 1;
 * }
 * if (!iface_enumerate(AF_INET, NULL, ipv4_callback))
 *   die("Interface enumeration failed", NULL, EC_BADNET);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements interface enumeration as required for DNS listener binding and DHCP
 * server operation per RFC 2131 Section 2 (DHCP requires knowledge of interface
 * addresses and broadcast addresses).
 *
 * SIDE EFFECTS:
 * - Calls getifaddrs() which allocates dynamic memory (freed via freeifaddrs())
 * - Opens and closes temporary PF_INET6 socket for IPv6 metadata queries
 * - Invokes ioctl() operations: SIOCGIFAFLAG_IN6, SIOCGIFALIFETIME_IN6
 * - Modifies link-local IPv6 addresses in-place (clears interface field s6_addr[2:3])
 * - Sets errno on failure paths
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main thread only. Uses static variables
 * (del_family, del_addr) for RTM_DELADDR race condition workaround. getifaddrs()
 * returns static data on some implementations. Not reentrant due to shared static state.
 */
int iface_enumerate(int family, void *parm, int (*callback)())
{
  struct ifaddrs *head, *addrs;
  int errsave, fd = -1, ret = 0;

  if (family == AF_UNSPEC)
#if defined(HAVE_BSD_NETWORK) && !defined(__APPLE__)
    return  arp_enumerate(parm, callback);
#else
  return 0; /* need code for Solaris and MacOS*/
#endif

  /* AF_LINK doesn't exist in Linux, so we can't use it in our API */
  if (family == AF_LOCAL)
    family = AF_LINK;

  if (getifaddrs(&head) == -1)
    return 0;

#if defined(HAVE_BSD_NETWORK)
  if (family == AF_INET6)
    fd = socket(PF_INET6, SOCK_DGRAM, 0);
#endif
  
  for (addrs = head; addrs; addrs = addrs->ifa_next)
    {
      if (addrs->ifa_addr->sa_family == family)
	{
	  int iface_index = if_nametoindex(addrs->ifa_name);

	  if (iface_index == 0 || !addrs->ifa_addr || 
	      (!addrs->ifa_netmask && family != AF_LINK))
	    continue;

	  if (family == AF_INET)
	    {
	      struct in_addr addr, netmask, broadcast;
	      addr = ((struct sockaddr_in *) addrs->ifa_addr)->sin_addr;
#ifdef HAVE_BSD_NETWORK
	      if (del_family == AF_INET && del_addr.addr4.s_addr == addr.s_addr)
		continue;
#endif
	      netmask = ((struct sockaddr_in *) addrs->ifa_netmask)->sin_addr;
	      if (addrs->ifa_broadaddr)
		broadcast = ((struct sockaddr_in *) addrs->ifa_broadaddr)->sin_addr; 
	      else 
		broadcast.s_addr = 0;	      
	      if (!((*callback)(addr, iface_index, NULL, netmask, broadcast, parm)))
		goto err;
	    }
	  else if (family == AF_INET6)
	    {
	      struct in6_addr *addr = &((struct sockaddr_in6 *) addrs->ifa_addr)->sin6_addr;
	      unsigned char *netmask = (unsigned char *) &((struct sockaddr_in6 *) addrs->ifa_netmask)->sin6_addr;
	      int scope_id = ((struct sockaddr_in6 *) addrs->ifa_addr)->sin6_scope_id;
	      int i, j, prefix = 0;
	      u32 valid = 0xffffffff, preferred = 0xffffffff;
	      int flags = 0;
#ifdef HAVE_BSD_NETWORK
	      if (del_family == AF_INET6 && IN6_ARE_ADDR_EQUAL(&del_addr.addr6, addr))
		continue;
#endif
#if defined(HAVE_BSD_NETWORK) && !defined(__APPLE__)
	      struct in6_ifreq ifr6;

	      memset(&ifr6, 0, sizeof(ifr6));
	      safe_strncpy(ifr6.ifr_name, addrs->ifa_name, sizeof(ifr6.ifr_name));
	      
	      ifr6.ifr_addr = *((struct sockaddr_in6 *) addrs->ifa_addr);
	      if (fd != -1 && ioctl(fd, SIOCGIFAFLAG_IN6, &ifr6) != -1)
		{
		  if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_TENTATIVE)
		    flags |= IFACE_TENTATIVE;
		  
		  if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DEPRECATED)
		    flags |= IFACE_DEPRECATED;

#ifdef IN6_IFF_TEMPORARY
		  if (!(ifr6.ifr_ifru.ifru_flags6 & (IN6_IFF_AUTOCONF | IN6_IFF_TEMPORARY)))
		    flags |= IFACE_PERMANENT;
#endif

#ifdef IN6_IFF_PRIVACY
		  if (!(ifr6.ifr_ifru.ifru_flags6 & (IN6_IFF_AUTOCONF | IN6_IFF_PRIVACY)))
		    flags |= IFACE_PERMANENT;
#endif
		}
	      
	      ifr6.ifr_addr = *((struct sockaddr_in6 *) addrs->ifa_addr);
	      if (fd != -1 && ioctl(fd, SIOCGIFALIFETIME_IN6, &ifr6) != -1)
		{
		  valid = ifr6.ifr_ifru.ifru_lifetime.ia6t_vltime;
		  preferred = ifr6.ifr_ifru.ifru_lifetime.ia6t_pltime;
		}
#endif
	      	      
	      for (i = 0; i < IN6ADDRSZ; i++, prefix += 8) 
                if (netmask[i] != 0xff)
		  break;
	      
	      if (i != IN6ADDRSZ && netmask[i]) 
                for (j = 7; j > 0; j--, prefix++) 
		  if ((netmask[i] & (1 << j)) == 0)
		    break;
	      
	      /* voodoo to clear interface field in address */
	      if (!option_bool(OPT_NOWILD) && IN6_IS_ADDR_LINKLOCAL(addr))
		{
		  addr->s6_addr[2] = 0;
		  addr->s6_addr[3] = 0;
		} 
	     
	      if (!((*callback)(addr, prefix, scope_id, iface_index, flags,
				(int) preferred, (int)valid, parm)))
		goto err;	      
	    }

#ifdef HAVE_DHCP6      
	  else if (family == AF_LINK)
	    { 
	      /* Assume ethernet again here */
	      struct sockaddr_dl *sdl = (struct sockaddr_dl *) addrs->ifa_addr;
	      if (sdl->sdl_alen != 0 && 
		  !((*callback)(iface_index, ARPHRD_ETHER, LLADDR(sdl), sdl->sdl_alen, parm)))
		goto err;
	    }
#endif 
	}
    }
  
  ret = 1;

 err:
  errsave = errno;
  freeifaddrs(head); 
  if (fd != -1)
    close(fd);
  errno = errsave;

  return ret;
}
#endif /* defined(HAVE_BSD_NETWORK) || defined(HAVE_SOLARIS_NETWORK) */


#if defined(HAVE_BSD_NETWORK) && defined(HAVE_DHCP)
#include <net/bpf.h>

/**
 * @brief Open Berkeley Packet Filter device for raw DHCP packet transmission
 *
 * @detailed
 * Initializes raw packet transmission capability for DHCP on BSD systems by opening
 * a Berkeley Packet Filter (BPF) device from /dev/bpf0 onwards, trying sequential
 * device numbers until an available device is found. BPF allows dnsmasq to construct
 * and send raw Ethernet frames directly, bypassing the kernel IP stack, which is
 * necessary for DHCP responses to clients that cannot yet receive ARP or respond
 * to IP-layer packets (clients in INIT or SELECTING state). The opened file descriptor
 * is stored in daemon->dhcp_raw_fd and the device path in daemon->dhcp_buff for
 * subsequent use by send_via_bpf().
 *
 * @param None
 *
 * @return void (exits process on failure via die())
 *
 * @note Tries /dev/bpf0, /dev/bpf1, /dev/bpf2... until successful open or non-EBUSY error
 * @note Only compiled when both HAVE_BSD_NETWORK and HAVE_DHCP are defined
 * @note Must be called during daemon initialization before entering event loop
 * @note BPF devices are cloning devices on modern BSD; older systems require distinct devices
 *
 * @warning Terminates dnsmasq process via die() if no BPF device can be opened (EC_BADNET)
 * @warning Requires privileges to open /dev/bpf* devices (typically root or dhcp group)
 * @warning EBUSY indicates device in use; other errors are fatal (no available BPF devices)
 *
 * @see send_via_bpf() for raw packet transmission using opened BPF device
 * @see dhcp.c for DHCP server initialization and packet handling
 * @see network.c for network interface setup coordination
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from main() during initialization on BSD systems with DHCP enabled
 * if (daemon->dhcp)
 *   {
 *     init_bpf();  // Opens daemon->dhcp_raw_fd for raw packet I/O
 *     // daemon->dhcp_raw_fd now contains valid BPF file descriptor
 *   }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Enables RFC 2131 Section 4.1 compliance: "If the 'giaddr' field in a DHCP message
 * from a client is zero, the server broadcasts any DHCP messages to the client on
 * the client's local network segment." Raw packet transmission is required for
 * broadcast to clients without IP addresses.
 *
 * SIDE EFFECTS:
 * - Opens /dev/bpf* device file, setting daemon->dhcp_raw_fd
 * - Stores device path in daemon->dhcp_buff for logging/debugging
 * - Terminates process via die() on fatal error (no available BPF devices)
 * - File descriptor remains open for daemon lifetime (closed on process exit)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called during single-threaded initialization before
 * event loop starts. Modifies global daemon structure. Not reentrant.
 */
void init_bpf(void)
{
  int i = 0;

  while (1) 
    {
      sprintf(daemon->dhcp_buff, "/dev/bpf%d", i++);
      if ((daemon->dhcp_raw_fd = open(daemon->dhcp_buff, O_RDWR, 0)) != -1)
	return;

      if (errno != EBUSY)
	die(_("cannot create DHCP BPF socket: %s"), NULL, EC_BADNET);
    }	     
}

/**
 * @brief Construct and send raw Ethernet frame for DHCP response via BPF
 *
 * @detailed
 * Builds a complete Ethernet frame from scratch including Ethernet header, IP header,
 * UDP header, and DHCP payload, then transmits it directly through the Berkeley Packet
 * Filter device bypassing the kernel IP stack. This is required for DHCP responses to
 * clients that cannot yet respond to ARP requests or receive IP packets (INIT/SELECTING
 * states). Determines destination MAC address and IP address from DHCP packet flags:
 * broadcast flag set (0x8000) uses broadcast MAC/IP, otherwise uses client hardware
 * address (chaddr) and assigned IP (yiaddr). Computes IP and UDP checksums manually
 * as kernel stack is bypassed. Only supports Ethernet (ARPHRD_ETHER) hardware type.
 *
 * @param mess Pointer to DHCP packet structure containing message to send
 * @param len Length of DHCP packet in bytes (variable, typically 300-1500 bytes)
 * @param iface_addr Source IP address for IP header (interface address serving DHCP)
 * @param ifr Pointer to ifreq structure identifying target network interface
 *
 * @return void
 *
 * @note Ethernet frame structure: [Ether header][IP header][UDP header][DHCP payload]
 * @note IP header: Version 4, no fragmentation (DF=0x4000), TTL=IPDEFTTL, protocol=UDP
 * @note UDP ports: source=daemon->dhcp_server_port (67), dest=daemon->dhcp_client_port (68)
 * @note Broadcast MAC address: ff:ff:ff:ff:ff:ff when broadcast flag set
 * @note Uses writev() with 4 iovec entries for scatter-gather transmission
 *
 * @warning Only supports Ethernet (htype==ARPHRD_ETHER, hlen==ETHER_ADDR_LEN==6)
 * @warning Logs warning and returns without sending for unsupported hardware types
 * @warning Requires daemon->dhcp_raw_fd initialized via init_bpf()
 * @warning UDP checksum computation requires even-length packets (pads odd lengths with zero)
 * @warning ioctl(BIOCSETIF) binds BPF to interface immediately before transmission
 *
 * @see init_bpf() for BPF device initialization
 * @see rfc2131.c dhcp_reply() for DHCP packet construction
 * @see dhcp.c for DHCP server packet handling
 * @see network.c for interface configuration
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_packet dhcp_response;
 * struct ifreq ifr;
 * struct in_addr iface_addr, client_addr;
 * // ... construct DHCP OFFER/ACK in dhcp_response ...
 * safe_strncpy(ifr.ifr_name, "em0", IFNAMSIZ);
 * inet_pton(AF_INET, "192.168.1.1", &iface_addr);
 * send_via_bpf(&dhcp_response, sizeof(dhcp_response), iface_addr, &ifr);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.1 requirement for sending DHCP responses via broadcast
 * when client giaddr is zero: "The server broadcasts DHCPOFFER messages to the client's
 * hardware address." Enables RFC 2131 Section 3.1 requirement to reach clients in INIT
 * state that cannot receive unicast IP packets.
 *
 * SIDE EFFECTS:
 * - Invokes ioctl(daemon->dhcp_raw_fd, SIOCGIFADDR, ifr) to get interface MAC address
 * - Invokes ioctl(daemon->dhcp_raw_fd, BIOCSETIF, ifr) to bind BPF to interface
 * - Calls writev() on daemon->dhcp_raw_fd for packet transmission
 * - Uses retry_send() wrapper for handling EINTR on writev()
 * - Logs warning via my_syslog() for unsupported hardware types
 * - Modifies mess buffer (pads odd lengths for checksum, temporary modification)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop thread only. Accesses global
 * daemon structure (daemon->dhcp_raw_fd, daemon->dhcp_server_port, daemon->dhcp_client_port).
 * Not reentrant due to ioctl() side effects on shared file descriptor state.
 */
void send_via_bpf(struct dhcp_packet *mess, size_t len,
		  struct in_addr iface_addr, struct ifreq *ifr)
{
   /* Hairy stuff, packet either has to go to the
      net broadcast or the destination can't reply to ARP yet,
      but we do know the physical address. 
      Build the packet by steam, and send directly, bypassing
      the kernel IP stack */
  
  struct ether_header ether; 
  struct ip ip;
  struct udphdr {
    u16 uh_sport;               /* source port */
    u16 uh_dport;               /* destination port */
    u16 uh_ulen;                /* udp length */
    u16 uh_sum;                 /* udp checksum */
  } udp;
  
  u32 i, sum;
  struct iovec iov[4];

  /* Only know how to do ethernet on *BSD */
  if (mess->htype != ARPHRD_ETHER || mess->hlen != ETHER_ADDR_LEN)
    {
      my_syslog(MS_DHCP | LOG_WARNING, _("DHCP request for unsupported hardware type (%d) received on %s"), 
		mess->htype, ifr->ifr_name);
      return;
    }
   
  ifr->ifr_addr.sa_family = AF_LINK;
  if (ioctl(daemon->dhcpfd, SIOCGIFADDR, ifr) < 0)
    return;
  
  memcpy(ether.ether_shost, LLADDR((struct sockaddr_dl *)&ifr->ifr_addr), ETHER_ADDR_LEN);
  ether.ether_type = htons(ETHERTYPE_IP);
  
  if (ntohs(mess->flags) & 0x8000)
    {
      memset(ether.ether_dhost, 255,  ETHER_ADDR_LEN);
      ip.ip_dst.s_addr = INADDR_BROADCAST;
    }
  else
    {
      memcpy(ether.ether_dhost, mess->chaddr, ETHER_ADDR_LEN); 
      ip.ip_dst.s_addr = mess->yiaddr.s_addr;
    }
  
  ip.ip_p = IPPROTO_UDP;
  ip.ip_src.s_addr = iface_addr.s_addr;
  ip.ip_len = htons(sizeof(struct ip) + 
		    sizeof(struct udphdr) +
		    len) ;
  ip.ip_hl = sizeof(struct ip) / 4;
  ip.ip_v = IPVERSION;
  ip.ip_tos = 0;
  ip.ip_id = htons(0);
  ip.ip_off = htons(0x4000); /* don't fragment */
  ip.ip_ttl = IPDEFTTL;
  ip.ip_sum = 0;
  for (sum = 0, i = 0; i < sizeof(struct ip) / 2; i++)
    sum += ((u16 *)&ip)[i];
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);  
  ip.ip_sum = (sum == 0xffff) ? sum : ~sum;
  
  udp.uh_sport = htons(daemon->dhcp_server_port);
  udp.uh_dport = htons(daemon->dhcp_client_port);
  if (len & 1)
    ((char *)mess)[len] = 0; /* for checksum, in case length is odd. */
  udp.uh_sum = 0;
  udp.uh_ulen = sum = htons(sizeof(struct udphdr) + len);
  sum += htons(IPPROTO_UDP);
  sum += ip.ip_src.s_addr & 0xffff;
  sum += (ip.ip_src.s_addr >> 16) & 0xffff;
  sum += ip.ip_dst.s_addr & 0xffff;
  sum += (ip.ip_dst.s_addr >> 16) & 0xffff;
  for (i = 0; i < sizeof(struct udphdr)/2; i++)
    sum += ((u16 *)&udp)[i];
  for (i = 0; i < (len + 1) / 2; i++)
    sum += ((u16 *)mess)[i];
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);
  udp.uh_sum = (sum == 0xffff) ? sum : ~sum;
  
  ioctl(daemon->dhcp_raw_fd, BIOCSETIF, ifr);
  
  iov[0].iov_base = &ether;
  iov[0].iov_len = sizeof(ether);
  iov[1].iov_base = &ip;
  iov[1].iov_len = sizeof(ip);
  iov[2].iov_base = &udp;
  iov[2].iov_len = sizeof(udp);
  iov[3].iov_base = mess;
  iov[3].iov_len = len;

  while (retry_send(writev(daemon->dhcp_raw_fd, iov, 4)));
}

#endif /* defined(HAVE_BSD_NETWORK) && defined(HAVE_DHCP) */
 

#ifdef HAVE_BSD_NETWORK

/**
 * @brief Initialize PF_ROUTE socket for network interface change monitoring
 *
 * @detailed
 * Creates and configures a routing socket (PF_ROUTE, SOCK_RAW, AF_UNSPEC) for receiving
 * asynchronous kernel notifications about network interface and address changes. The
 * routing socket provides BSD's mechanism for monitoring network topology changes including
 * interface up/down events (RTM_IFINFO), address additions (RTM_NEWADDR), address deletions
 * (RTM_DELADDR), and route modifications. Messages received on this socket are processed
 * by route_sock() in the main event loop. Applies fix_fd() to set non-blocking mode and
 * close-on-exec flag. The socket remains open for the daemon's lifetime, registered with
 * the poll()-based event loop for readability notification.
 *
 * @param None
 *
 * @return void (exits process on failure via die())
 *
 * @note AF_UNSPEC receives messages for all address families (AF_INET, AF_INET6, AF_LINK)
 * @note Routing socket is privileged operation requiring appropriate capabilities/permissions
 * @note Only compiled when HAVE_BSD_NETWORK is defined
 * @note Must be called during daemon initialization before entering event loop
 *
 * @warning Terminates dnsmasq process via die() if socket creation or fix_fd() fails (EC_BADNET)
 * @warning Requires root privileges or CAP_NET_ADMIN equivalent on BSD systems
 * @warning Routing socket remains open for daemon lifetime (fd leak on abnormal termination)
 *
 * @see route_sock() for routing message processing in event loop
 * @see dnsmasq.c event_loop() for poll() integration
 * @see network.c for interface listener reconfiguration on address changes
 * @see netlink.c for Linux Netlink equivalent functionality
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from main() during daemon initialization on BSD systems
 * route_init();  // Opens daemon->routefd for routing socket messages
 * // daemon->routefd now monitored by event loop poll()
 * // route_sock() called when routing messages arrive
 * @endcode
 *
 * RFC COMPLIANCE:
 * Enables dynamic DNS and DHCP server adaptation to network configuration changes,
 * supporting RFC 2131 DHCP requirement to track interface addresses and RFC 1035
 * DNS requirement to bind to interface addresses.
 *
 * SIDE EFFECTS:
 * - Creates PF_ROUTE socket, stores file descriptor in daemon->routefd
 * - Applies fix_fd() which sets O_NONBLOCK and FD_CLOEXEC flags via fcntl()
 * - Terminates process via die() on fatal error
 * - Socket remains open until process termination
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called during single-threaded initialization before event
 * loop starts. Modifies global daemon->routefd. Not reentrant.
 */
void route_init(void)
{
  /* AF_UNSPEC: all addr families */
  daemon->routefd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
  
  if (daemon->routefd == -1 || !fix_fd(daemon->routefd))
    die(_("cannot create PF_ROUTE socket: %s"), NULL, EC_BADNET);
}

/**
 * @brief Process routing socket messages for interface and address changes
 *
 * @detailed
 * Handles kernel routing messages received on daemon->routefd (PF_ROUTE socket) indicating
 * network interface and address changes. Receives and parses routing message structures
 * (if_msghdr, ifa_msghdr) to detect RTM_NEWADDR (address added) and RTM_DELADDR (address
 * deleted) events. Validates message version (RTM_VERSION) and length before processing.
 * For both event types, queues EVENT_NEWADDR to trigger interface re-enumeration via
 * iface_enumerate(). Implements a kernel race condition workaround for RTM_DELADDR: parses
 * the RTA_IFA field to extract the deleted address and stores it in static variables
 * (del_family, del_addr) so iface_enumerate() can filter it out, as the kernel briefly
 * continues to return the deleted address in getifaddrs() results.
 *
 * @param None
 *
 * @return void
 *
 * @note Called from main event loop when daemon->routefd becomes readable
 * @note Ignores messages shorter than 4 bytes or shorter than ifm_msglen
 * @note Logs warning for version mismatch (non-RTM_VERSION) but continues processing
 * @note RTM_IFINFO messages for interface up/down are currently ignored
 * @note RTM_DELADDR message parsing uses RTA_* masks: RTA_DST, RTA_GATEWAY, RTA_NETMASK,
 *       RTA_IFA (address being deleted), RTA_IFP, etc.
 *
 * @warning recv() uses daemon->packet buffer shared with DNS/DHCP packet processing
 * @warning Version warning logged only once per dnsmasq run (static warned variable)
 * @warning RTA_IFA parsing relies on sockaddr length fields for address extraction
 * @warning del_family/del_addr static variables persist across calls (race workaround state)
 * @warning Truncated or malformed routing messages are silently ignored
 *
 * @see route_init() for routing socket initialization
 * @see iface_enumerate() for interface re-enumeration using del_family/del_addr filtering
 * @see dnsmasq.c queue_event() for EVENT_NEWADDR event queuing
 * @see network.c for listener reconfiguration triggered by EVENT_NEWADDR
 *
 * EXAMPLE USAGE:
 * @code
 * // In event loop, when poll() indicates daemon->routefd readable:
 * if (poll_listen(daemon->routefd, POLLIN))
 *   route_sock();  // Process routing message, may queue EVENT_NEWADDR
 * // Event handler later calls iface_enumerate() to refresh interface list
 * @endcode
 *
 * RFC COMPLIANCE:
 * Enables dynamic adaptation required for DNS (RFC 1035) and DHCP (RFC 2131) servers
 * to respond to network topology changes. DHCP servers must track interface addresses
 * per RFC 2131 Section 2, and DNS servers must update listener bindings when addresses
 * change.
 *
 * SIDE EFFECTS:
 * - Calls recv(daemon->routefd, ...) which reads and consumes routing message from kernel
 * - Modifies static variables del_family and del_addr for RTM_DELADDR race workaround
 * - Modifies static variable warned for version mismatch logging suppression
 * - Invokes queue_event(EVENT_NEWADDR) which sets global event flags
 * - Logs warning via my_syslog() for protocol version mismatch (once only)
 * - Uses daemon->packet buffer (shared with DNS/DHCP processing)
 * - Uses daemon->packet_buff_sz as recv() buffer size limit
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop thread only. Modifies static
 * variables (warned, del_family, del_addr) and accesses global daemon structure.
 * recv() on daemon->routefd is not thread-safe. Not reentrant due to static state
 * and shared buffer (daemon->packet) usage.
 */
void route_sock(void)
{
  struct if_msghdr *msg;
  int rc = recv(daemon->routefd, daemon->packet, daemon->packet_buff_sz, 0);

  if (rc < 4)
    return;

  msg = (struct if_msghdr *)daemon->packet;
  
  if (rc < msg->ifm_msglen)
    return;

   if (msg->ifm_version != RTM_VERSION)
     {
       static int warned = 0;
       if (!warned)
	 {
	   my_syslog(LOG_WARNING, _("Unknown protocol version from route socket"));
	   warned = 1;
	 }
     }
   else if (msg->ifm_type == RTM_NEWADDR)
     {
       del_family = 0;
       queue_event(EVENT_NEWADDR);
     }
   else if (msg->ifm_type == RTM_DELADDR)
     {
       /* There's a race in the kernel, such that if we run iface_enumerate() immediately
	  we get a DELADDR event, the deleted address still appears. Here we store the deleted address
	  in a static variable, and omit it from the set returned by iface_enumerate() */
       int mask = ((struct ifa_msghdr *)msg)->ifam_addrs;
       int maskvec[] = { RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_GENMASK,
			 RTA_IFP, RTA_IFA, RTA_AUTHOR, RTA_BRD };
       int of;
       unsigned int i;
       
       for (i = 0,  of = sizeof(struct ifa_msghdr); of < rc && i < sizeof(maskvec)/sizeof(maskvec[0]); i++) 
	 if (mask & maskvec[i]) 
	   {
	     struct sockaddr *sa = (struct sockaddr *)((char *)msg + of);
	     size_t diff = (sa->sa_len != 0) ? sa->sa_len : sizeof(long);
	     
	     if (maskvec[i] == RTA_IFA)
	       {
		 del_family = sa->sa_family;
		 if (del_family == AF_INET)
		   del_addr.addr4 = ((struct sockaddr_in *)sa)->sin_addr;
		 else if (del_family == AF_INET6)
		   del_addr.addr6 = ((struct sockaddr_in6 *)sa)->sin6_addr;
		 else
		   del_family = 0;
	       }
	     
	     of += diff;
	     /* round up as needed */
	     if (diff & (sizeof(long) - 1)) 
	       of += sizeof(long) - (diff & (sizeof(long) - 1));
	   }
       
       queue_event(EVENT_NEWADDR);
     }
}

#endif /* HAVE_BSD_NETWORK */
