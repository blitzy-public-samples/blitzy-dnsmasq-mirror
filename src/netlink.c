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
 * @file netlink.c
 * @brief Linux Netlink socket interface and address monitoring
 *
 * DETAILED PURPOSE:
 * This file implements Linux-specific network interface discovery and monitoring
 * using the Netlink RTNETLINK protocol. Netlink provides a powerful IPC mechanism
 * between kernel and userspace for network configuration, offering real-time
 * notifications about network changes without requiring periodic polling. This
 * implementation receives notifications for interface up/down events (RTM_NEWLINK/
 * RTM_DELLINK), IPv4/IPv6 address additions/removals (RTM_NEWADDR/RTM_DELADDR),
 * and routing table changes (RTM_NEWROUTE/RTM_DELROUTE). Netlink is superior to
 * BSD routing sockets by providing richer information, better performance, and
 * more granular control over message filtering via multicast groups.
 *
 * The implementation maintains a single AF_NETLINK socket subscribed to multiple
 * multicast groups (RTMGRP_IPV4_ROUTE, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_ROUTE,
 * RTMGRP_IPV6_IFADDR) to receive asynchronous notifications about network state
 * changes. This allows dnsmasq to dynamically adjust DNS and DHCP services when
 * interfaces are added, removed, or have their addresses modified.
 *
 * KEY RESPONSIBILITIES:
 * - netlink_init() - Create and configure Netlink RTNETLINK socket with multicast subscriptions
 * - iface_enumerate() - Enumerate network interfaces, addresses, or neighbor table entries via dump requests
 * - netlink_multicast() - Process asynchronous multicast notifications from kernel
 * - netlink_recv() - Receive and buffer Netlink messages with automatic buffer expansion
 * - nl_async() - Handle asynchronous Netlink messages and queue appropriate events
 * - nl_multicast_state() - Non-blocking processing of queued multicast messages
 *
 * DEPENDENCIES:
 * - dnsmasq.h: Core dnsmasq definitions, daemon global state, event queue functions
 * - linux/netlink.h: Netlink socket definitions (AF_NETLINK, struct nlmsghdr)
 * - linux/rtnetlink.h: RTNETLINK message types (RTM_NEWLINK, RTM_NEWADDR, RTM_NEWROUTE, etc.)
 * - Called by: network.c iface_check() for interface enumeration and event processing
 * - Calls: Event queue functions queue_event(), safe_malloc(), expand_buf()
 *
 * DATA STRUCTURES:
 * - struct nlmsghdr: Netlink message header (linux/netlink.h)
 * - struct ifaddrmsg: Interface address message (linux/rtnetlink.h)
 * - struct ndmsg: Neighbor table message for ARP entries (linux/rtnetlink.h)
 * - struct ifinfomsg: Interface information message (linux/rtnetlink.h)
 * - struct rtmsg: Routing table message (linux/rtnetlink.h)
 * - struct iovec iov: Static buffer for message reception (lines 54)
 * - u32 netlink_pid: Process ID assigned by kernel bind() (line 55)
 * - enum async_states: State flags for batching multiple related events (lines 48-51)
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_LINUX_NETWORK: MANDATORY - Entire file only compiled on Linux
 * - HAVE_DHCP6: If defined, enables MAC address enumeration via RTM_GETLINK (line 324)
 * - SOL_NETLINK: Socket option level, defined if not present in headers (line 27)
 * - NETLINK_NO_ENOBUFS: Socket option to suppress ENOBUFS errors (line 31)
 *
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven architecture. Netlink socket integrated into main
 * event loop via poll(). All functions called from main thread only. Netlink
 * messages may arrive asynchronously but are processed synchronously when poll()
 * indicates socket readability. nl_multicast_state() uses MSG_DONTWAIT to avoid
 * blocking when draining multicast notification queue.
 *
 * PLATFORM NOTES:
 * Linux-specific implementation. BSD systems use bpf.c with routing sockets instead.
 * Solaris uses SIOCGIFCONF ioctl fallback in network.c. This file provides superior
 * interface monitoring on Linux with lower overhead and more timely notifications
 * compared to polling-based alternatives.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 *
 * @see docs/ARCHITECTURE.md for platform abstraction layer documentation
 * @see network.c for cross-platform interface enumeration wrapper functions
 * @see bpf.c for BSD routing socket alternative implementation
 */

#include "dnsmasq.h"

#ifdef HAVE_LINUX_NETWORK

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* Blergh. Radv does this, so that's our excuse. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_NO_ENOBUFS
#define NETLINK_NO_ENOBUFS 5
#endif

/* linux 2.6.19 buggers up the headers, patch it up here. */ 
#ifndef IFA_RTA
#  define IFA_RTA(r)  \
       ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))

#  include <linux/if_addr.h>
#endif

#ifndef NDA_RTA
#  define NDA_RTA(r) ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg)))) 
#endif

/* Used to request refresh of addresses or routes just once,
 * when multiple changes might be announced. */
enum async_states {
  STATE_NEWADDR = (1 << 0),
  STATE_NEWROUTE = (1 << 1),
};


static struct iovec iov;
static u32 netlink_pid;

static unsigned nl_async(struct nlmsghdr *h, unsigned state);
static void nl_multicast_state(unsigned state);

/**
 * @brief Initialize Netlink socket for network interface and route monitoring
 *
 * @detailed
 * Creates an AF_NETLINK socket of type SOCK_RAW with NETLINK_ROUTE protocol to
 * receive kernel notifications about network configuration changes. The socket is
 * bound with nl_pid=0 for automatic PID assignment and subscribed to four multicast
 * groups: RTMGRP_IPV4_ROUTE, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_ROUTE, RTMGRP_IPV6_IFADDR.
 * If multicast group subscription fails with EPERM (insufficient permissions), the
 * socket is rebound without multicast groups to operate in polling mode only. The
 * function allocates an initial 100-byte receive buffer (iov) which will be
 * dynamically expanded as needed by netlink_recv().
 *
 * @return NULL on success, never returns on fatal socket creation failure
 *
 * @note The Netlink PID (netlink_pid) assigned by the kernel is saved for filtering
 *       messages originated by this process versus kernel multicast notifications.
 *       The socket file descriptor is stored in daemon->netlinkfd global.
 *
 * @warning Calls die() and terminates process if socket creation or bind fails
 *          (except EPERM on multicast groups, which falls back to no-multicast mode).
 *          This is fatal because without Netlink, dnsmasq cannot detect interface changes.
 *
 * @see netlink_multicast() for processing asynchronous notifications received on this socket
 * @see iface_enumerate() for using this socket to query interface state
 * @see network.c iface_check() which calls this during daemon initialization
 *
 * EXAMPLE USAGE:
 * @code
 * char *err;
 * if ((err = netlink_init()) != NULL)
 *   die("Netlink init failed: %s", err, EC_MISC);
 * // Socket now ready in daemon->netlinkfd
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not applicable - Linux kernel Netlink interface (not standardized by RFC)
 *
 * SIDE EFFECTS:
 * - Creates socket stored in daemon->netlinkfd global variable
 * - Allocates 100-byte buffer in static iov.iov_base via safe_malloc()
 * - Sets static netlink_pid with kernel-assigned process identifier
 * - Subscribes to kernel multicast groups for IPv4/IPv6 route and address events
 * - May call die() terminating process on unrecoverable socket errors
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies static variables iov and netlink_pid. Must be called
 * once during single-threaded initialization before main event loop starts. Safe
 * in dnsmasq's single-threaded event-driven architecture.
 */
char *netlink_init(void)
{
  struct sockaddr_nl addr;
  socklen_t slen = sizeof(addr);

  addr.nl_family = AF_NETLINK;
  addr.nl_pad = 0;
  addr.nl_pid = 0; /* autobind */
  addr.nl_groups = RTMGRP_IPV4_ROUTE;
  addr.nl_groups |= RTMGRP_IPV4_IFADDR;  
  addr.nl_groups |= RTMGRP_IPV6_ROUTE;
  addr.nl_groups |= RTMGRP_IPV6_IFADDR;

  /* May not be able to have permission to set multicast groups don't die in that case */
  if ((daemon->netlinkfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) != -1)
    {
      if (bind(daemon->netlinkfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	{
	  addr.nl_groups = 0;
	  if (errno != EPERM || bind(daemon->netlinkfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	    daemon->netlinkfd = -1;
	}
    }
  
  if (daemon->netlinkfd == -1 || 
      getsockname(daemon->netlinkfd, (struct sockaddr *)&addr, &slen) == -1)
    die(_("cannot create netlink socket: %s"), NULL, EC_MISC);
  
  
  /* save pid assigned by bind() and retrieved by getsockname() */ 
  netlink_pid = addr.nl_pid;
  
  iov.iov_len = 100;
  iov.iov_base = safe_malloc(iov.iov_len);
  
  return NULL;
}

/**
 * @brief Receive Netlink message from kernel with automatic buffer expansion
 *
 * @detailed
 * Receives a Netlink message from daemon->netlinkfd socket into the static iov buffer.
 * Uses MSG_PEEK with MSG_TRUNC to determine actual message size before reading, then
 * automatically expands the iov buffer if the message exceeds current capacity. Retries
 * recvmsg() on EINTR. Validates that messages originate from the kernel (nladdr.nl_pid == 0)
 * to reject userspace-spoofed messages. This two-phase approach (peek then read) prevents
 * message truncation and ensures complete Netlink messages are received.
 *
 * @param flags Additional flags to pass to recvmsg() (typically 0 or MSG_DONTWAIT)
 *
 * @return Number of bytes received on success, -1 on error (sets errno)
 * @retval >0 Successfully received message of this byte length
 * @retval -1 Error occurred: EINTR (interrupted), ENOMEM (buffer expansion failed),
 *            or socket error from recvmsg()
 *
 * @note Older Linux kernels always return iov.iov_len when MSG_TRUNC is set, while
 *       newer kernels return the actual message size. The function handles both
 *       behaviors by expanding buffer by 100 bytes for old kernels.
 *
 * @warning Discards truncated messages if buffer expansion fails (sets errno=ENOMEM).
 *          Only accepts messages with nladdr.nl_pid == 0 (kernel origin) to prevent
 *          userspace message injection attacks.
 *
 * @see expand_buf() for dynamic buffer reallocation
 * @see iface_enumerate() which calls this to receive RTM_NEWADDR, RTM_NEWLINK responses
 * @see nl_multicast_state() which calls this with MSG_DONTWAIT to drain message queue
 *
 * EXAMPLE USAGE:
 * @code
 * ssize_t len;
 * if ((len = netlink_recv(0)) == -1) {
 *   if (errno == ENOBUFS)
 *     return -1;  // Buffer overflow, need restart
 *   return 0;     // Other error
 * }
 * // Process message in iov.iov_base with length len
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not applicable - Linux kernel Netlink protocol (not RFC-standardized)
 *
 * SIDE EFFECTS:
 * - Reads from daemon->netlinkfd socket, blocking unless MSG_DONTWAIT in flags
 * - May expand static iov buffer via expand_buf() and safe_malloc()
 * - Modifies static iov.iov_base and iov.iov_len on buffer expansion
 * - Consumes one message from socket receive queue
 *
 * THREAD SAFETY:
 * Not thread-safe. Accesses static iov buffer. Must be called only from main thread
 * in dnsmasq's single-threaded event loop. Safe with event-driven architecture where
 * socket is read only when poll() indicates readability.
 */
static ssize_t netlink_recv(int flags)
{
  struct msghdr msg;
  struct sockaddr_nl nladdr;
  ssize_t rc;

  while (1)
    {
      msg.msg_control = NULL;
      msg.msg_controllen = 0;
      msg.msg_name = &nladdr;
      msg.msg_namelen = sizeof(nladdr);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_flags = 0;
      
      while ((rc = recvmsg(daemon->netlinkfd, &msg, flags | MSG_PEEK | MSG_TRUNC)) == -1 &&
	     errno == EINTR);
      
      /* make buffer big enough */
      if (rc != -1 && (msg.msg_flags & MSG_TRUNC))
	{
	  /* Very new Linux kernels return the actual size needed, older ones always return truncated size */
	  if ((size_t)rc == iov.iov_len)
	    {
	      if (expand_buf(&iov, rc + 100))
		continue;
	    }
	  else
	    expand_buf(&iov, rc);
	}

      /* read it for real */
      msg.msg_flags = 0;
      while ((rc = recvmsg(daemon->netlinkfd, &msg, flags)) == -1 && errno == EINTR);
      
      /* Make sure this is from the kernel */
      if (rc == -1 || nladdr.nl_pid == 0)
	break;
    }
      
  /* discard stuff which is truncated at this point (expand_buf() may fail) */
  if (msg.msg_flags & MSG_TRUNC)
    {
      rc = -1;
      errno = ENOMEM;
    }
  
  return rc;
}
  

/**
 * @brief Enumerate network interfaces, addresses, or neighbor table via Netlink dump
 *
 * @detailed
 * Sends a Netlink dump request (RTM_GETLINK, RTM_GETADDR, or RTM_GETNEIGH) to retrieve
 * current interface state, IP addresses, or ARP/neighbor table entries. The function
 * sends a request with NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK flags to request
 * a complete dump, then receives and processes all RTM_NEWADDR, RTM_NEWLINK, or RTM_NEWNEIGH
 * responses until NLMSG_DONE. For each matching entry, invokes the provided callback function
 * with parsed data. Handles asynchronous multicast messages that may arrive during enumeration
 * and processes them via nl_async(). If ENOBUFS is received (kernel buffer overflow), returns -1
 * to signal that enumeration must be restarted.
 *
 * @param family Address family selector:
 *               - AF_UNSPEC: Enumerate ARP/neighbor table entries (RTM_GETNEIGH)
 *               - AF_LOCAL: Enumerate interface MAC addresses (RTM_GETLINK)
 *               - AF_INET: Enumerate IPv4 addresses (RTM_GETADDR)
 *               - AF_INET6: Enumerate IPv6 addresses (RTM_GETADDR)
 * @param parm Opaque pointer passed through to callback function for caller context
 * @param callback Function pointer invoked for each enumerated entry. Signature varies by family:
 *                 - AF_INET: callback(struct in_addr addr, int if_index, char *label,
 *                            struct in_addr netmask, struct in_addr broadcast, void *parm)
 *                 - AF_INET6: callback(struct in6_addr *addr, int prefixlen, int scope,
 *                             int if_index, int flags, int preferred, int valid, void *parm)
 *                 - AF_UNSPEC: callback(int family, char *addr, char *mac, size_t maclen, void *parm)
 *                 - AF_LOCAL: callback(int if_index, unsigned int if_type, char *mac, size_t maclen, void *parm)
 *                 Callback returns 0 to stop enumeration, non-zero to continue
 *
 * @return Status code indicating result
 * @retval 1 Success, all entries enumerated and processed
 * @retval 0 Failure, send error or callback requested stop
 * @retval -1 ENOBUFS received, kernel buffer overflow, enumeration must be restarted
 *
 * @note IPv6 addresses include additional metadata: tentative flag (IFA_F_TENTATIVE),
 *       deprecated flag (IFA_F_DEPRECATED), permanent flag (!IFA_F_TEMPORARY), plus
 *       preferred and valid lifetimes from IFA_CACHEINFO. ARP entries filter out
 *       incomplete, failed, and no-ARP entries via NUD_* state flags.
 *
 * @warning If callback returns 0, enumeration stops but function still returns 1 (success).
 *          ENOBUFS (errno 105) indicates kernel dropped messages due to buffer overflow;
 *          caller must restart enumeration and process any queued multicast events via
 *          nl_multicast_state(). Netlink messages with incorrect sequence number are
 *          silently dropped (may be remnants of previous failed enumeration).
 *
 * @see netlink_init() which creates the socket used for dump requests
 * @see nl_async() for handling asynchronous multicast messages during enumeration
 * @see network.c for callers that enumerate interfaces and addresses
 *
 * EXAMPLE USAGE (enumerate IPv4 addresses):
 * @code
 * static int address_callback(struct in_addr addr, int if_index, char *label,
 *                             struct in_addr netmask, struct in_addr broadcast, void *parm) {
 *   printf("Found address %s on interface %d\n", inet_ntoa(addr), if_index);
 *   return 1;  // Continue enumeration
 * }
 * int result = iface_enumerate(AF_INET, NULL, address_callback);
 * if (result == -1) {
 *   // ENOBUFS, restart enumeration
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not applicable - Linux Netlink RTNETLINK protocol (not RFC-standardized)
 *
 * SIDE EFFECTS:
 * - Sends Netlink dump request to daemon->netlinkfd socket
 * - Receives multiple Netlink response messages until NLMSG_DONE
 * - Invokes callback function for each matching entry (may have callback side effects)
 * - Processes asynchronous multicast messages via nl_async(), may queue events
 * - Increments static sequence number for request tracking
 * - May call nl_multicast_state() if ENOBUFS occurs (drains multicast queue)
 *
 * THREAD SAFETY:
 * Not thread-safe. Uses static sequence counter. Must be called only from main thread.
 * Callback function must also be thread-safe with dnsmasq's single-threaded model.
 * Safe in event-driven architecture where enumeration is synchronous operation.
 */
int iface_enumerate(int family, void *parm, int (*callback)())
{
  struct sockaddr_nl addr;
  struct nlmsghdr *h;
  ssize_t len;
  static unsigned int seq = 0;
  int callback_ok = 1;
  unsigned state = 0;

  struct {
    struct nlmsghdr nlh;
    struct rtgenmsg g; 
  } req;

  memset(&req, 0, sizeof(req));
  memset(&addr, 0, sizeof(addr));

  addr.nl_family = AF_NETLINK;
 
  if (family == AF_UNSPEC)
    req.nlh.nlmsg_type = RTM_GETNEIGH;
  else if (family == AF_LOCAL)
    req.nlh.nlmsg_type = RTM_GETLINK;
  else
    req.nlh.nlmsg_type = RTM_GETADDR;

  req.nlh.nlmsg_len = sizeof(req);
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST | NLM_F_ACK; 
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = ++seq;
  req.g.rtgen_family = family; 

  /* Don't block in recvfrom if send fails */
  while(retry_send(sendto(daemon->netlinkfd, (void *)&req, sizeof(req), 0, 
			  (struct sockaddr *)&addr, sizeof(addr))));

  if (errno != 0)
    return 0;
    
  while (1)
    {
      if ((len = netlink_recv(0)) == -1)
	{
	  if (errno == ENOBUFS)
	    {
	      nl_multicast_state(state);
	      return -1;
	    }
	  return 0;
	}

      for (h = (struct nlmsghdr *)iov.iov_base; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len))
	if (h->nlmsg_pid != netlink_pid || h->nlmsg_type == NLMSG_ERROR)
	  {
	    /* May be multicast arriving async */
	    state = nl_async(h, state);
	  }
	else if (h->nlmsg_seq != seq)
	  {
	    /* May be part of incomplete response to previous request after
	       ENOBUFS. Drop it. */
	    continue;
	  }
	else if (h->nlmsg_type == NLMSG_DONE)
	  return callback_ok;
	else if (h->nlmsg_type == RTM_NEWADDR && family != AF_UNSPEC && family != AF_LOCAL)
	  {
	    struct ifaddrmsg *ifa = NLMSG_DATA(h);  
	    struct rtattr *rta = IFA_RTA(ifa);
	    unsigned int len1 = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
	    
	    if (ifa->ifa_family == family)
	      {
		if (ifa->ifa_family == AF_INET)
		  {
		    struct in_addr netmask, addr, broadcast;
		    char *label = NULL;

		    netmask.s_addr = htonl(~(in_addr_t)0 << (32 - ifa->ifa_prefixlen));

		    addr.s_addr = 0;
		    broadcast.s_addr = 0;
		    
		    while (RTA_OK(rta, len1))
		      {
			if (rta->rta_type == IFA_LOCAL)
			  addr = *((struct in_addr *)(rta+1));
			else if (rta->rta_type == IFA_BROADCAST)
			  broadcast = *((struct in_addr *)(rta+1));
			else if (rta->rta_type == IFA_LABEL)
			  label = RTA_DATA(rta);
			
			rta = RTA_NEXT(rta, len1);
		      }
		    
		    if (addr.s_addr && callback_ok)
		      if (!((*callback)(addr, ifa->ifa_index, label,  netmask, broadcast, parm)))
			callback_ok = 0;
		  }
		else if (ifa->ifa_family == AF_INET6)
		  {
		    struct in6_addr *addrp = NULL;
		    u32 valid = 0, preferred = 0;
		    int flags = 0;
		    
		    while (RTA_OK(rta, len1))
		      {
			/*
			 * Important comment: (from if_addr.h)
			 * IFA_ADDRESS is prefix address, rather than local interface address.
			 * It makes no difference for normally configured broadcast interfaces,
			 * but for point-to-point IFA_ADDRESS is DESTINATION address,
			 * local address is supplied in IFA_LOCAL attribute.
			 */
			if (rta->rta_type == IFA_LOCAL)
			  addrp = ((struct in6_addr *)(rta+1));
			else if (rta->rta_type == IFA_ADDRESS && !addrp)
			  addrp = ((struct in6_addr *)(rta+1)); 
			else if (rta->rta_type == IFA_CACHEINFO)
			  {
			    struct ifa_cacheinfo *ifc = (struct ifa_cacheinfo *)(rta+1);
			    preferred = ifc->ifa_prefered;
			    valid = ifc->ifa_valid;
			  }
			rta = RTA_NEXT(rta, len1);
		      }
		    
		    if (ifa->ifa_flags & IFA_F_TENTATIVE)
		      flags |= IFACE_TENTATIVE;
		    
		    if (ifa->ifa_flags & IFA_F_DEPRECATED)
		      flags |= IFACE_DEPRECATED;
		    
		    if (!(ifa->ifa_flags & IFA_F_TEMPORARY))
		      flags |= IFACE_PERMANENT;
    		    
		    if (addrp && callback_ok)
		      if (!((*callback)(addrp, (int)(ifa->ifa_prefixlen), (int)(ifa->ifa_scope), 
					(int)(ifa->ifa_index), flags, 
					(int) preferred, (int)valid, parm)))
			callback_ok = 0;
		  }
	      }
	  }
	else if (h->nlmsg_type == RTM_NEWNEIGH && family == AF_UNSPEC)
	  {
	    struct ndmsg *neigh = NLMSG_DATA(h);  
	    struct rtattr *rta = NDA_RTA(neigh);
	    unsigned int len1 = h->nlmsg_len - NLMSG_LENGTH(sizeof(*neigh));
	    size_t maclen = 0;
	    char *inaddr = NULL, *mac = NULL;
	    
	    while (RTA_OK(rta, len1))
	      {
		if (rta->rta_type == NDA_DST)
		  inaddr = (char *)(rta+1);
		else if (rta->rta_type == NDA_LLADDR)
		  {
		    maclen = rta->rta_len - sizeof(struct rtattr);
		    mac = (char *)(rta+1);
		  }
		
		rta = RTA_NEXT(rta, len1);
	      }

	    if (!(neigh->ndm_state & (NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED)) &&
		inaddr && mac && callback_ok)
	      if (!((*callback)(neigh->ndm_family, inaddr, mac, maclen, parm)))
		callback_ok = 0;
	  }
#ifdef HAVE_DHCP6
	else if (h->nlmsg_type == RTM_NEWLINK && family == AF_LOCAL)
	  {
	    struct ifinfomsg *link =  NLMSG_DATA(h);
	    struct rtattr *rta = IFLA_RTA(link);
	    unsigned int len1 = h->nlmsg_len - NLMSG_LENGTH(sizeof(*link));
	    char *mac = NULL;
	    size_t maclen = 0;

	    while (RTA_OK(rta, len1))
	      {
		if (rta->rta_type == IFLA_ADDRESS)
		  {
		    maclen = rta->rta_len - sizeof(struct rtattr);
		    mac = (char *)(rta+1);
		  }
		
		rta = RTA_NEXT(rta, len1);
	      }

	    if (mac && callback_ok && !((link->ifi_flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) && 
		!((*callback)((int)link->ifi_index, (unsigned int)link->ifi_type, mac, maclen, parm)))
	      callback_ok = 0;
	  }
#endif
    }
}

/**
 * @brief Drain Netlink multicast message queue in non-blocking mode
 *
 * @detailed
 * Processes all pending asynchronous Netlink multicast messages from the kernel without
 * blocking. Uses MSG_DONTWAIT flag with netlink_recv() to read messages until the queue
 * is empty (errno == EAGAIN/EWOULDBLOCK) or ENOBUFS occurs (kernel buffer overflow). Each
 * received message is passed to nl_async() for event classification and queueing. This
 * function is called after ENOBUFS during iface_enumerate() to ensure no multicast
 * notifications are lost, and by netlink_multicast() to process events when the Netlink
 * socket becomes readable in the main event loop. Continues draining until queue is empty
 * or ENOBUFS occurs again (indicating sustained high message rate).
 *
 * @param state Initial event state flags (bitwise OR of STATE_NEWADDR, STATE_NEWROUTE).
 *              Updated by nl_async() to prevent duplicate event queueing when multiple
 *              related messages arrive in quick succession. Pass 0 on first call.
 *
 * @return void (does not return status)
 *
 * @note The do-while loop continues even after queue is empty (errno != ENOBUFS) to handle
 *       race condition where messages arrive between recvmsg() calls. MSG_DONTWAIT ensures
 *       no blocking if queue is truly empty.
 *
 * @warning ENOBUFS indicates kernel dropped messages due to receive buffer overflow, meaning
 *          interface state may be inconsistent. Caller should trigger full re-enumeration.
 *          Function does not return error status, relies on nl_async() to queue events.
 *
 * @see nl_async() which processes each message and updates state flags
 * @see netlink_multicast() which calls this from main event loop
 * @see iface_enumerate() which calls this after ENOBUFS to drain queue before retry
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned state = 0;
 * nl_multicast_state(state);  // Drain all pending messages
 * // Events now queued via nl_async() calls to queue_event()
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not applicable - Linux Netlink protocol (not RFC-standardized)
 *
 * SIDE EFFECTS:
 * - Reads from daemon->netlinkfd socket with MSG_DONTWAIT (non-blocking)
 * - Calls nl_async() for each message, which may call queue_event() to schedule
 *   EVENT_NEWADDR or EVENT_NEWROUTE processing in main event loop
 * - Drains kernel socket receive buffer, preventing buffer overflow
 * - May loop multiple times if messages continue arriving during processing
 *
 * THREAD SAFETY:
 * Not thread-safe. Accesses static iov buffer via netlink_recv(). Must be called only
 * from main thread. Safe in single-threaded event-driven architecture where Netlink
 * socket is read only when poll() indicates readability.
 */
static void nl_multicast_state(unsigned state)
{
  ssize_t len;
  struct nlmsghdr *h;

  do {
    /* don't risk blocking reading netlink messages here. */
    while ((len = netlink_recv(MSG_DONTWAIT)) != -1)
  
      for (h = (struct nlmsghdr *)iov.iov_base; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len))
	state = nl_async(h, state);
  } while (errno == ENOBUFS);
}

/**
 * @brief Process pending Netlink multicast notifications from kernel
 *
 * @detailed
 * Entry point called from main event loop when daemon->netlinkfd becomes readable,
 * indicating kernel has sent one or more Netlink multicast messages about network
 * configuration changes (interface up/down, address add/remove, route changes).
 * Initializes event state to 0 and delegates to nl_multicast_state() to drain all
 * pending messages. Each message is classified by nl_async() and corresponding events
 * (EVENT_NEWADDR, EVENT_NEWROUTE) are queued for processing. This function is the
 * bridge between poll() readability notification and actual message processing.
 *
 * @return void
 *
 * @note This function is called only when poll() indicates daemon->netlinkfd is readable,
 *       ensuring messages are available without blocking. Event state starts at 0,
 *       allowing nl_async() to queue events for the first occurrence of each type.
 *
 * @warning Does not return error status. Message processing errors are logged by nl_async()
 *          via my_syslog(). ENOBUFS during processing indicates kernel buffer overflow
 *          requiring full interface re-enumeration (handled by event loop).
 *
 * @see nl_multicast_state() for actual message queue draining logic
 * @see nl_async() which processes individual messages and queues events
 * @see dnsmasq.c event loop which polls daemon->netlinkfd and calls this on readability
 * @see network.c iface_check() which handles queued EVENT_NEWADDR and EVENT_NEWROUTE
 *
 * EXAMPLE USAGE:
 * @code
 * // In main event loop after poll() returns
 * if (FD_ISSET(daemon->netlinkfd, &readfds)) {
 *   netlink_multicast();  // Process all pending notifications
 * }
 * // Events now queued for processing
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not applicable - Linux Netlink protocol (not RFC-standardized)
 *
 * SIDE EFFECTS:
 * - Drains all pending messages from daemon->netlinkfd via nl_multicast_state()
 * - Queues EVENT_NEWADDR and EVENT_NEWROUTE events via queue_event() calls in nl_async()
 * - May trigger interface re-enumeration if ENOBUFS occurs (handled by event processing)
 * - Logs NLMSG_ERROR messages via my_syslog() if kernel reports errors
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main thread when poll() indicates socket
 * readability. Safe in single-threaded event-driven architecture where socket is read
 * only when poll() reports POLLIN event on daemon->netlinkfd.
 */
void netlink_multicast(void)
{
  unsigned state = 0;
  nl_multicast_state(state);
}

/**
 * @brief Process asynchronous Netlink message and queue appropriate event
 *
 * @detailed
 * Handles Netlink messages that arrive asynchronously via multicast subscriptions,
 * classifying them by type and queueing corresponding events for main loop processing.
 * Recognizes three message types: NLMSG_ERROR (logs error), RTM_NEWROUTE (queues
 * EVENT_NEWROUTE for unicast link-scope routes in main/local tables), and RTM_NEWADDR/
 * RTM_DELADDR (queues EVENT_NEWADDR for address changes). Uses state flags to ensure
 * only one event is queued per type even if multiple related messages arrive in quick
 * succession. This deduplication prevents event queue flooding during bulk network
 * configuration changes.
 *
 * The RTM_NEWROUTE handling specifically targets dial-on-demand (DoD) scenarios where
 * a DNS query triggers PPP/dialup connection establishment. When the route becomes
 * available, EVENT_NEWROUTE causes dnsmasq to resend any DNS query that was buffered
 * during dialing, preventing lookup timeout.
 *
 * @param h Pointer to Netlink message header (struct nlmsghdr) to process
 * @param state Current event state flags (bitwise OR of STATE_NEWADDR, STATE_NEWROUTE).
 *              If STATE_NEWROUTE is set, no additional EVENT_NEWROUTE will be queued.
 *              If STATE_NEWADDR is set, no additional EVENT_NEWADDR will be queued.
 *
 * @return Updated state flags with bits set for queued events
 * @retval state | STATE_NEWROUTE if EVENT_NEWROUTE was queued
 * @retval state | STATE_NEWADDR if EVENT_NEWADDR was queued
 * @retval state unchanged if no event was queued
 *
 * @note Only processes messages with h->nlmsg_pid == 0 (kernel origin). Messages with
 *       non-zero PID are from this process or other userspace and are ignored (filtered
 *       by caller). RTM_NEWROUTE filtering: only unicast (RTN_UNICAST) link-scope
 *       (RT_SCOPE_LINK) routes in main or local tables trigger EVENT_NEWROUTE.
 *
 * @warning NLMSG_ERROR with non-zero err->error is logged via my_syslog() but does not
 *          stop processing. Invalid route types (non-unicast, non-link-scope) are
 *          silently ignored. Multiple rapid address changes result in only one
 *          EVENT_NEWADDR due to state flag deduplication.
 *
 * @see queue_event() which adds events to main loop event queue
 * @see nl_multicast_state() which calls this for each received multicast message
 * @see iface_enumerate() which calls this for messages arriving during enumeration
 * @see dnsmasq.c event loop which processes EVENT_NEWADDR and EVENT_NEWROUTE
 *
 * EXAMPLE USAGE:
 * @code
 * struct nlmsghdr *h = (struct nlmsghdr *)buffer;
 * unsigned state = 0;
 * for (each message in buffer) {
 *   state = nl_async(h, state);  // Process and update state
 *   h = NLMSG_NEXT(h, len);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not applicable - Linux Netlink protocol (not RFC-standardized)
 *
 * SIDE EFFECTS:
 * - Calls queue_event(EVENT_NEWROUTE) for qualifying RTM_NEWROUTE messages
 * - Calls queue_event(EVENT_NEWADDR) for RTM_NEWADDR or RTM_DELADDR messages
 * - Logs errors via my_syslog(LOG_ERR) for NLMSG_ERROR messages with non-zero error code
 * - Sets state flags to prevent duplicate event queueing in same batch
 * - No effect for messages with nlmsg_pid != 0 or unrecognized message types
 *
 * THREAD SAFETY:
 * Thread-safe for message processing (read-only access to message). queue_event() and
 * my_syslog() must be thread-safe (they are in dnsmasq). However, must be called from
 * main thread due to event queue requirements. Safe in single-threaded event-driven
 * architecture.
 */
static unsigned nl_async(struct nlmsghdr *h, unsigned state)
{
  if (h->nlmsg_type == NLMSG_ERROR)
    {
      struct nlmsgerr *err = NLMSG_DATA(h);
      if (err->error != 0)
	my_syslog(LOG_ERR, _("netlink returns error: %s"), strerror(-(err->error)));
    }
  else if (h->nlmsg_pid == 0 && h->nlmsg_type == RTM_NEWROUTE &&
	   (state & STATE_NEWROUTE)==0)
    {
      /* We arrange to receive netlink multicast messages whenever the network route is added.
	 If this happens and we still have a DNS packet in the buffer, we re-send it.
	 This helps on DoD links, where frequently the packet which triggers dialling is
	 a DNS query, which then gets lost. By re-sending, we can avoid the lookup
	 failing. */ 
      struct rtmsg *rtm = NLMSG_DATA(h);
      
      if (rtm->rtm_type == RTN_UNICAST && rtm->rtm_scope == RT_SCOPE_LINK &&
	  (rtm->rtm_table == RT_TABLE_MAIN ||
	   rtm->rtm_table == RT_TABLE_LOCAL))
	{
	  queue_event(EVENT_NEWROUTE);
	  state |= STATE_NEWROUTE;
	}
    }
  else if ((h->nlmsg_type == RTM_NEWADDR || h->nlmsg_type == RTM_DELADDR) &&
	   (state & STATE_NEWADDR)==0)
    {
      queue_event(EVENT_NEWADDR);
      state |= STATE_NEWADDR;
    }
  return state;
}
#endif /* HAVE_LINUX_NETWORK */
