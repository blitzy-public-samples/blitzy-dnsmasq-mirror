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
 * @file tftp.c
 * @brief TFTP server implementation per RFC 1350 with PXE/UEFI boot support
 * 
 * DETAILED PURPOSE:
 * 
 * This file implements a complete TFTP (Trivial File Transfer Protocol) server
 * designed specifically for network boot scenarios including PXE (Pre-boot Execution
 * Environment) and UEFI HTTP boot. The implementation follows RFC 1350 for basic
 * TFTP operations while extending functionality through RFC 2347 (TFTP Option
 * Extension), RFC 2348 (TFTP Blocksize Option), and RFC 2349 (TFTP Timeout Interval
 * and Transfer Size Options).
 * 
 * The TFTP server integrates seamlessly with dnsmasq's DHCP server through options
 * 66 (TFTP server name) and 67 (boot filename), enabling complete network boot
 * infrastructure. Files are served from configured directories with comprehensive
 * security restrictions including path traversal prevention, permission checking,
 * and optional secure mode requiring file ownership by the dnsmasq user.
 * 
 * The implementation supports both standard 512-byte blocks and negotiated larger
 * block sizes up to 1468 bytes (limited by MTU) for improved transfer performance.
 * Network ASCII mode translation (CR-LF handling) is supported for text file transfers.
 * Per-transfer state tracking in struct tftp_transfer enables concurrent multi-client
 * operations with configurable limits.
 * 
 * KEY RESPONSIBILITIES:
 * 
 * - tftp_request() - Main entry point handling RRQ (Read Request) packets from clients,
 *   allocates transfer state, validates file permissions, initiates transfers
 * - check_tftp_listeners() - Polls TFTP sockets for incoming packets, handles timeouts
 *   and retransmissions with exponential backoff
 * - handle_tftp() - Processes ACK and ERR packets during active file transfers
 * - get_block() - Constructs DATA or OACK packets, manages block sequencing and
 *   netascii translation
 * - check_tftp_fileperm() - Validates file access permissions, implements security
 *   restrictions, manages file descriptor sharing for efficiency
 * 
 * DEPENDENCIES:
 * 
 * Includes:
 * - dnsmasq.h - Core daemon structures and function prototypes
 * 
 * Called By:
 * - check_dns_listeners() in dnsmasq.c - Polls TFTP listener sockets
 * - event_loop() in dnsmasq.c - Main event dispatch loop
 * 
 * Calls:
 * - send_from() in network.c - Sends UDP packets with source address control
 * - prettyprint_addr() in util.c - Formats addresses for logging
 * - find_mac() in dhcp.c - Retrieves MAC address for client (if HAVE_DHCP enabled)
 * - lease_find_by_addr() in lease.c - Looks up DHCP lease by IP (if HAVE_DHCP enabled)
 * 
 * DATA STRUCTURES:
 * 
 * - struct tftp_transfer (dnsmasq.h:1058-1070) - Per-client transfer state including
 *   socket, peer address, block number, blocksize, timeout, backoff counter
 * - struct tftp_file (dnsmasq.h:1050-1056) - Shared file descriptor with reference
 *   counting, inode tracking for efficient multi-client serving
 * - struct tftp_prefix (dnsmasq.h:1077-1082) - Per-interface TFTP root directory
 *   configuration
 * 
 * COMPILE-TIME OPTIONS:
 * 
 * - HAVE_TFTP - Required to compile this entire file, enables TFTP server functionality
 * - HAVE_DHCP - Optional, enables integration with DHCP lease database for MAC address
 *   lookup when using --tftp-unique-root=mac option
 * - HAVE_SCRIPT - Optional, enables post-transfer script execution via queue_tftp()
 * - HAVE_DUMPFILE - Optional, enables packet dumping for debugging
 * - OPT_SINGLE_PORT - Runtime option for single-port mode (all transfers via port 69)
 * - OPT_TFTP_SECURE - Runtime option requiring files owned by dnsmasq user
 * - OPT_TFTP_NOBLOCK - Runtime option disabling blksize negotiation
 * - OPT_TFTP_LC - Runtime option converting filenames to lowercase
 * - OPT_TFTP_APREF_IP - Runtime option adding client IP subdirectories
 * - OPT_TFTP_APREF_MAC - Runtime option adding client MAC subdirectories
 * 
 * THREADING/CONCURRENCY:
 * 
 * This module operates within dnsmasq's single-process, event-driven architecture.
 * All TFTP operations are non-blocking and integrated with the main poll() event loop.
 * Concurrent transfers are managed through a linked list (daemon->tftp_trans) with
 * each transfer maintaining independent state. File descriptors are shared when multiple
 * clients request the same file (reference counting in struct tftp_file) to conserve
 * resources during mass network boot scenarios. No threading or explicit locking is used;
 * all operations complete atomically within the event loop iteration.
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * 
 * @see docs/TFTP.md for complete protocol implementation documentation
 * @see RFC 1350 - The TFTP Protocol (Revision 2)
 * @see RFC 2347 - TFTP Option Extension
 * @see RFC 2348 - TFTP Blocksize Option
 * @see RFC 2349 - TFTP Timeout Interval and Transfer Size Options
 */

#include "dnsmasq.h"

#ifdef HAVE_TFTP

static void handle_tftp(time_t now, struct tftp_transfer *transfer, ssize_t len);
static struct tftp_file *check_tftp_fileperm(ssize_t *len, char *prefix, char *client);
static void free_transfer(struct tftp_transfer *transfer);
static ssize_t tftp_err(int err, char *packet, char *message, char *file, char *arg2);
static ssize_t tftp_err_oops(char *packet, const char *file);
static ssize_t get_block(char *packet, struct tftp_transfer *transfer);
static char *next(char **p, char *end);
static void sanitise(char *buf);

#define OP_RRQ  1
#define OP_WRQ  2
#define OP_DATA 3
#define OP_ACK  4
#define OP_ERR  5
#define OP_OACK 6

#define ERR_NOTDEF 0
#define ERR_FNF    1
#define ERR_PERM   2
#define ERR_FULL   3
#define ERR_ILL    4
#define ERR_TID    5

/**
 * @brief Process TFTP Read Request (RRQ) from client and initiate file transfer
 * 
 * @detailed
 * This function serves as the main entry point for TFTP requests. It receives RRQ packets
 * from clients, validates the request parameters, allocates transfer state, checks file
 * permissions, and sends either the first DATA block or an OACK (Option Acknowledgment)
 * if the client requested options like blksize or tsize. The function handles both
 * single-port mode (all transfers via port 69) and multi-port mode (ephemeral ports
 * per transfer). Platform-specific code extracts the destination interface and address
 * from the received packet to support multi-homed configurations.
 * 
 * @param listen Listener socket structure containing TFTP socket file descriptor and
 *               bound interface information, must not be NULL
 * @param now Current time in seconds since epoch for timeout calculation and lease lookups
 * 
 * @return void - No return value; errors result in TFTP error packets sent to client
 * 
 * @note Allocates struct tftp_transfer which is freed by free_transfer() on error or
 *       transfer completion. In single-port mode, may reuse existing transfer struct
 *       when client retransmits RRQ.
 * @note Uses daemon->packet buffer for both receiving and sending, overwriting
 *       daemon->srv_save
 * @warning File path traversal (/../) is blocked to prevent directory escape attacks
 * @warning In secure mode (OPT_TFTP_SECURE), files must be owned by the dnsmasq user
 * @warning Running as root requires world-readable permission on served files
 * 
 * @see check_tftp_fileperm() for file permission validation logic
 * @see get_block() for DATA/OACK packet construction
 * @see handle_tftp() for subsequent ACK processing
 * @see RFC 1350 Section 5 for RRQ packet format
 * 
 * EXAMPLE USAGE:
 * @code
 * struct listener *tftp_listener = ...; // Listener on port 69
 * time_t current_time = time(NULL);
 * tftp_request(tftp_listener, current_time); // Process received RRQ
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 5: RRQ packet format (opcode, filename, mode, zero bytes)
 * - RFC 2347: TFTP Option Extension (processes blksize, tsize options)
 * - RFC 2348: TFTP Blocksize Option (negotiates 1-65464 bytes, MTU limited)
 * - RFC 2349: TFTP Transfer Size Option (reports file size in OACK)
 * 
 * SIDE EFFECTS:
 * - Allocates struct tftp_transfer and adds to daemon->tftp_trans list
 * - Opens file descriptor via check_tftp_fileperm()
 * - Sends UDP packet to client (DATA or OACK or ERROR)
 * - May create socket (in multi-port mode) bound to ephemeral or configured port range
 * - Logs to syslog on errors
 * - Overwrites daemon->packet and daemon->srv_save
 * 
 * THREAD SAFETY:
 * Single-threaded event-driven model. Not reentrant. Must be called only from main
 * event loop. Relies on global daemon structure for state.
 */
void tftp_request(struct listener *listen, time_t now)
{
  ssize_t len;
  char *packet = daemon->packet;
  char *filename, *mode, *p, *end, *opt;
  union mysockaddr addr, peer;
  struct msghdr msg;
  struct iovec iov;
  struct ifreq ifr;
  int is_err = 1, if_index = 0, mtu = 0;
  struct iname *tmp;
  struct tftp_transfer *transfer = NULL, **up;
  int port = daemon->start_tftp_port; /* may be zero to use ephemeral port */
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
  int mtuflag = IP_PMTUDISC_DONT;
#endif
  char namebuff[IF_NAMESIZE];
  char *name = NULL;
  char *prefix = daemon->tftp_prefix;
  struct tftp_prefix *pref;
  union all_addr addra;
  int family = listen->addr.sa.sa_family;
  /* Can always get recvd interface for IPv6 */
  int check_dest = !option_bool(OPT_NOWILD) || family == AF_INET6;
  union {
    struct cmsghdr align; /* this ensures alignment */
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#if defined(HAVE_LINUX_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#elif defined(HAVE_SOLARIS_NETWORK)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(unsigned int))];
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
    char control[CMSG_SPACE(sizeof(struct in_addr)) +
		 CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
  } control_u; 

  msg.msg_controllen = sizeof(control_u);
  msg.msg_control = control_u.control;
  msg.msg_flags = 0;
  msg.msg_name = &peer;
  msg.msg_namelen = sizeof(peer);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  iov.iov_base = packet;
  iov.iov_len = daemon->packet_buff_sz;

  /* we overwrote the buffer... */
  daemon->srv_save = NULL;

  if ((len = recvmsg(listen->tftpfd, &msg, 0)) < 2)
    return;

#ifdef HAVE_DUMPFILE
  dump_packet(DUMP_TFTP, (void *)packet, len, (union mysockaddr *)&peer, NULL, TFTP_PORT);
#endif
  
  /* Can always get recvd interface for IPv6 */
  if (!check_dest)
    {
      if (listen->iface)
	{
	  addr = listen->iface->addr;
	  name = listen->iface->name;
	  mtu = listen->iface->mtu;
	  if (daemon->tftp_mtu != 0 && daemon->tftp_mtu < mtu)
	    mtu = daemon->tftp_mtu;
	}
      else
	{
	  /* we're listening on an address that doesn't appear on an interface,
	     ask the kernel what the socket is bound to */
	  socklen_t tcp_len = sizeof(union mysockaddr);
	  if (getsockname(listen->tftpfd, (struct sockaddr *)&addr, &tcp_len) == -1)
	    return;
	}
    }
  else
    {
      struct cmsghdr *cmptr;

      if (msg.msg_controllen < sizeof(struct cmsghdr))
        return;
      
      addr.sa.sa_family = family;
      
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
	      addr.in.sin_addr = p.p->ipi_spec_dst;
	      if_index = p.p->ipi_ifindex;
	    }
      
#elif defined(HAVE_SOLARIS_NETWORK)
      if (family == AF_INET)
	for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	  {
	    union {
	      unsigned char *c;
	      struct in_addr *a;
	      unsigned int *i;
	    } p;
	    p.c = CMSG_DATA(cmptr);
	    if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVDSTADDR)
	    addr.in.sin_addr = *(p.a);
	    else if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
	    if_index = *(p.i);
	  }
      
#elif defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
      if (family == AF_INET)
	for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr))
	  {
	    union {
	      unsigned char *c;
	      struct in_addr *a;
	      struct sockaddr_dl *s;
	    } p;
	    p.c = CMSG_DATA(cmptr);
	    if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVDSTADDR)
	      addr.in.sin_addr = *(p.a);
	    else if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
	      if_index = p.s->sdl_index;
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
                  
                addr.in6.sin6_addr = p.p->ipi6_addr;
                if_index = p.p->ipi6_ifindex;
              }
        }
      
      if (!indextoname(listen->tftpfd, if_index, namebuff))
	return;

      name = namebuff;
      
      addra.addr4 = addr.in.sin_addr;

      if (family == AF_INET6)
	addra.addr6 = addr.in6.sin6_addr;

      if (daemon->tftp_interfaces)
	{
	  /* dedicated tftp interface list */
	  for (tmp = daemon->tftp_interfaces; tmp; tmp = tmp->next)
	    if (tmp->name && wildcard_match(tmp->name, name))
	      break;

	  if (!tmp)
	    return;
	}
      else
	{
	  /* Do the same as DHCP */
	  if (!iface_check(family, &addra, name, NULL))
	    {
	      if (!option_bool(OPT_CLEVERBIND))
		enumerate_interfaces(0); 
	      if (!loopback_exception(listen->tftpfd, family, &addra, name) &&
		  !label_exception(if_index, family, &addra))
		return;
	    }
	  
#ifdef HAVE_DHCP      
	  /* allowed interfaces are the same as for DHCP */
	  for (tmp = daemon->dhcp_except; tmp; tmp = tmp->next)
	    if (tmp->name && wildcard_match(tmp->name, name))
	      return;
#endif
	}

      safe_strncpy(ifr.ifr_name, name, IF_NAMESIZE);
      if (ioctl(listen->tftpfd, SIOCGIFMTU, &ifr) != -1)
	{
	  mtu = ifr.ifr_mtu;  
	  if (daemon->tftp_mtu != 0 && daemon->tftp_mtu < mtu)
	    mtu = daemon->tftp_mtu;    
	}
    }

  /* Failed to get interface mtu - can use configured value. */
  if (mtu == 0)
    mtu = daemon->tftp_mtu;

  /* data transfer via server listening socket */
  if (option_bool(OPT_SINGLE_PORT))
    {
      int tftp_cnt;

      for (tftp_cnt = 0, transfer = daemon->tftp_trans, up = &daemon->tftp_trans; transfer; up = &transfer->next, transfer = transfer->next)
	{
	  tftp_cnt++;

	  if (sockaddr_isequal(&peer, &transfer->peer))
	    {
	      if (ntohs(*((unsigned short *)packet)) == OP_RRQ)
		{
		  /* Handle repeated RRQ or abandoned transfer from same host and port 
		     by unlinking and reusing the struct transfer. */
		  *up = transfer->next;
		  break;
		}
	      else
		{
		  handle_tftp(now, transfer, len);
		  return;
		}
	    }
	}
      
      /* Enforce simultaneous transfer limit. In non-single-port mode
	 this is doene by not listening on the server socket when
	 too many transfers are in progress. */
      if (!transfer && tftp_cnt >= daemon->tftp_max)
	return;
    }
  
  if (name)
    {
      /* check for per-interface prefix */ 
      for (pref = daemon->if_prefix; pref; pref = pref->next)
	if (strcmp(pref->interface, name) == 0)
	  prefix = pref->prefix;  
    }

  if (family == AF_INET)
    {
      addr.in.sin_port = htons(port);
#ifdef HAVE_SOCKADDR_SA_LEN
      addr.in.sin_len = sizeof(addr.in);
#endif
    }
  else
    {
      addr.in6.sin6_port = htons(port);
      addr.in6.sin6_flowinfo = 0;
      addr.in6.sin6_scope_id = 0;
#ifdef HAVE_SOCKADDR_SA_LEN
      addr.in6.sin6_len = sizeof(addr.in6);
#endif
    }

  /* May reuse struct transfer from abandoned transfer in single port mode. */
  if (!transfer && !(transfer = whine_malloc(sizeof(struct tftp_transfer))))
    return;
  
  if (option_bool(OPT_SINGLE_PORT))
    transfer->sockfd = listen->tftpfd;
  else if ((transfer->sockfd = socket(family, SOCK_DGRAM, 0)) == -1)
    {
      free(transfer);
      return;
    }
  
  transfer->peer = peer;
  transfer->source = addra;
  transfer->if_index = if_index;
  transfer->timeout = now + 2;
  transfer->backoff = 1;
  transfer->block = 1;
  transfer->blocksize = 512;
  transfer->offset = 0;
  transfer->file = NULL;
  transfer->opt_blocksize = transfer->opt_transize = 0;
  transfer->netascii = transfer->carrylf = 0;
 
  (void)prettyprint_addr(&peer, daemon->addrbuff);
  
  /* if we have a nailed-down range, iterate until we find a free one. */
  while (!option_bool(OPT_SINGLE_PORT))
    {
      if (bind(transfer->sockfd, &addr.sa, sa_len(&addr)) == -1 ||
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
	  setsockopt(transfer->sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &mtuflag, sizeof(mtuflag)) == -1 ||
#endif
	  !fix_fd(transfer->sockfd))
	{
	  if (errno == EADDRINUSE && daemon->start_tftp_port != 0)
	    {
	      if (++port <= daemon->end_tftp_port)
		{ 
		  if (family == AF_INET)
		    addr.in.sin_port = htons(port);
		  else
		    addr.in6.sin6_port = htons(port);
		  
		  continue;
		}
	      my_syslog(MS_TFTP | LOG_ERR, _("unable to get free port for TFTP"));
	    }
	  free_transfer(transfer);
	  return;
	}
      break;
    }
  
  p = packet + 2;
  end = packet + len;
  
  if (ntohs(*((unsigned short *)packet)) != OP_RRQ ||
      !(filename = next(&p, end)) ||
      !(mode = next(&p, end)) ||
      (strcasecmp(mode, "octet") != 0 && strcasecmp(mode, "netascii") != 0))
    {
      len = tftp_err(ERR_ILL, packet, _("unsupported request from %s"), daemon->addrbuff, NULL);
      is_err = 1;
    }
  else
    {
      if (strcasecmp(mode, "netascii") == 0)
	transfer->netascii = 1;
      
      while ((opt = next(&p, end)))
	{
	  if (strcasecmp(opt, "blksize") == 0)
	    {
	      if ((opt = next(&p, end)) && !option_bool(OPT_TFTP_NOBLOCK))
		{
		  /* 32 bytes for IP, UDP and TFTP headers, 52 bytes for IPv6 */
		  int overhead = (family == AF_INET) ? 32 : 52;
		  transfer->blocksize = atoi(opt);
		  if (transfer->blocksize < 1)
		    transfer->blocksize = 1;
		  if (transfer->blocksize > (unsigned)daemon->packet_buff_sz - 4)
		    transfer->blocksize = (unsigned)daemon->packet_buff_sz - 4;
		  if (mtu != 0 && transfer->blocksize > (unsigned)mtu - overhead)
		    transfer->blocksize = (unsigned)mtu - overhead;
		  transfer->opt_blocksize = 1;
		  transfer->block = 0;
		}
	    }
	  else if (strcasecmp(opt, "tsize") == 0 && next(&p, end) && !transfer->netascii)
	    {
	      transfer->opt_transize = 1;
	      transfer->block = 0;
	    }
	}

      /* cope with backslashes from windows boxen. */
      for (p = filename; *p; p++)
	if (*p == '\\')
	  *p = '/';
	else if (option_bool(OPT_TFTP_LC))
	  *p = tolower(*p);
		
      strcpy(daemon->namebuff, "/");
      if (prefix)
	{
	  if (prefix[0] == '/')
	    daemon->namebuff[0] = 0;
	  strncat(daemon->namebuff, prefix, (MAXDNAME-1) - strlen(daemon->namebuff));
	  if (prefix[strlen(prefix)-1] != '/')
	    strncat(daemon->namebuff, "/", (MAXDNAME-1) - strlen(daemon->namebuff));

	  if (option_bool(OPT_TFTP_APREF_IP))
	    {
	      size_t oldlen = strlen(daemon->namebuff);
	      struct stat statbuf;
	      
	      strncat(daemon->namebuff, daemon->addrbuff, (MAXDNAME-1) - strlen(daemon->namebuff));
	      strncat(daemon->namebuff, "/", (MAXDNAME-1) - strlen(daemon->namebuff));
	      
	      /* remove unique-directory if it doesn't exist */
	      if (stat(daemon->namebuff, &statbuf) == -1 || !S_ISDIR(statbuf.st_mode))
		daemon->namebuff[oldlen] = 0;
	    }
	  
	  if (option_bool(OPT_TFTP_APREF_MAC))
	    {
	      unsigned char *macaddr = NULL;
	      unsigned char macbuf[DHCP_CHADDR_MAX];
	      
#ifdef HAVE_DHCP
	      if (daemon->dhcp && peer.sa.sa_family == AF_INET)
	        {
		  /* Check if the client IP is in our lease database */
		  struct dhcp_lease *lease = lease_find_by_addr(peer.in.sin_addr);
		  if (lease && lease->hwaddr_type == ARPHRD_ETHER && lease->hwaddr_len == ETHER_ADDR_LEN)
		    macaddr = lease->hwaddr;
		}
#endif
	      
	      /* If no luck, try to find in ARP table. This only works if client is in same (V)LAN */
	      if (!macaddr && find_mac(&peer, macbuf, 1, now) > 0)
		macaddr = macbuf;
	      
	      if (macaddr)
	        {
		  size_t oldlen = strlen(daemon->namebuff);
		  struct stat statbuf;

		  snprintf(daemon->namebuff + oldlen, (MAXDNAME-1) - oldlen, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x/",
			   macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
		  
		  /* remove unique-directory if it doesn't exist */
		  if (stat(daemon->namebuff, &statbuf) == -1 || !S_ISDIR(statbuf.st_mode))
		    daemon->namebuff[oldlen] = 0;
		}
	    }
	  
	  /* Absolute pathnames OK if they match prefix */
	  if (filename[0] == '/')
	    {
	      if (strstr(filename, daemon->namebuff) == filename)
		daemon->namebuff[0] = 0;
	      else
		filename++;
	    }
	}
      else if (filename[0] == '/')
	daemon->namebuff[0] = 0;
      strncat(daemon->namebuff, filename, (MAXDNAME-1) - strlen(daemon->namebuff));
      
      /* check permissions and open file */
      if ((transfer->file = check_tftp_fileperm(&len, prefix, daemon->addrbuff)))
	{
	  if ((len = get_block(packet, transfer)) == -1)
	    len = tftp_err_oops(packet, daemon->namebuff);
	  else
	    is_err = 0;
	}
    }

  send_from(transfer->sockfd, !option_bool(OPT_SINGLE_PORT), packet, len, &peer, &addra, if_index);

#ifdef HAVE_DUMPFILE
  dump_packet(DUMP_TFTP, (void *)packet, len, NULL, (union mysockaddr *)&peer, TFTP_PORT);
#endif
  
  if (is_err)
    free_transfer(transfer);
  else
    {
      transfer->next = daemon->tftp_trans;
      daemon->tftp_trans = transfer;
    }
}

/**
 * @brief Validate file permissions and open file for TFTP transfer
 * 
 * @detailed
 * This function performs comprehensive security checks before allowing TFTP file access.
 * It validates that the requested file path does not contain directory traversal sequences
 * (/../), opens the file with appropriate permissions, and verifies ownership/readability
 * based on the daemon's running UID and secure mode settings. To optimize resource usage
 * during mass boot scenarios, file descriptors are shared via reference counting when
 * multiple clients request the same file (matched by dev/inode pair and filename).
 * 
 * @param len Pointer to ssize_t where error packet length is stored on failure, must not
 *            be NULL, output parameter modified only on error
 * @param prefix TFTP root directory prefix for this interface, may be NULL for no prefix,
 *               used for path traversal detection
 * @param client Pretty-printed client address string for error logging, must not be NULL,
 *               typically from daemon->addrbuff
 * 
 * @return Pointer to struct tftp_file on success with fd open and refcount=1 or incremented,
 *         NULL on error with *len set to error packet size to send
 * 
 * @retval non-NULL Success, file opened and validated, caller owns reference
 * @retval NULL Failure, *len contains error packet length, error already logged
 * 
 * @note Returned struct tftp_file must be released by decrementing refcount and freeing
 *       when refcount reaches zero (handled by free_transfer())
 * @note File descriptor sharing saves FDs during mass boot (100+ clients booting same image)
 * @note Uses daemon->namebuff for resolved pathname
 * 
 * @warning Path traversal attack prevention: rejects paths containing /../ when prefix set
 * @warning Secure mode (OPT_TFTP_SECURE): requires file ownership by dnsmasq UID
 * @warning Root mode: requires world-readable (S_IROTH) permission
 * @warning Race condition mitigated: fstat() on opened FD, not stat() on pathname
 * 
 * @see tftp_request() which calls this for initial file validation
 * @see free_transfer() which decrements refcount and closes FD when reaching zero
 * @see struct tftp_file (dnsmasq.h:1050-1056) for file descriptor structure
 * 
 * EXAMPLE USAGE:
 * @code
 * ssize_t error_len;
 * char *client_addr = "192.168.1.100";
 * struct tftp_file *file = check_tftp_fileperm(&error_len, "/tftpboot", client_addr);
 * if (!file) {
 *     send_error_packet(error_len); // Send error to client
 * } else {
 *     // Proceed with transfer
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 4: Error codes ERR_FNF (file not found), ERR_PERM (access violation)
 * - RFC 1350 Section 5: File access semantics for read requests
 * 
 * SIDE EFFECTS:
 * - Opens file descriptor via open() system call
 * - Allocates struct tftp_file via whine_malloc() on first access
 * - Increments refcount on existing tftp_file if file already open
 * - Logs to syslog on errors (file not found, permission denied, I/O errors)
 * - Modifies *len parameter with error packet size on failure
 * - Uses daemon->namebuff for pathname storage
 * 
 * THREAD SAFETY:
 * Not thread-safe. Relies on global daemon structure. Must be called only from
 * single-threaded event loop context.
 */
static struct tftp_file *check_tftp_fileperm(ssize_t *len, char *prefix, char *client)
{
  char *packet = daemon->packet, *namebuff = daemon->namebuff;
  struct tftp_file *file;
  struct tftp_transfer *t;
  uid_t uid = geteuid();
  struct stat statbuf;
  int fd = -1;

  /* trick to ban moving out of the subtree */
  if (prefix && strstr(namebuff, "/../"))
    goto perm;
  
  if ((fd = open(namebuff, O_RDONLY)) == -1)
    {
      if (errno == ENOENT)
	{
	  *len = tftp_err(ERR_FNF, packet, _("file %s not found for %s"), namebuff, client);
	  return NULL;
	}
      else if (errno == EACCES)
	goto perm;
      else
	goto oops;
    }
  
  /* stat the file descriptor to avoid stat->open races */
  if (fstat(fd, &statbuf) == -1)
    goto oops;
  
  /* running as root, must be world-readable */
  if (uid == 0)
    {
      if (!(statbuf.st_mode & S_IROTH))
	goto perm;
    }
  /* in secure mode, must be owned by user running dnsmasq */
  else if (option_bool(OPT_TFTP_SECURE) && uid != statbuf.st_uid)
    goto perm;
      
  /* If we're doing many transfers from the same file, only 
     open it once this saves lots of file descriptors 
     when mass-booting a big cluster, for instance. 
     Be conservative and only share when inode and name match
     this keeps error messages sane. */
  for (t = daemon->tftp_trans; t; t = t->next)
    if (t->file->dev == statbuf.st_dev && 
	t->file->inode == statbuf.st_ino &&
	strcmp(t->file->filename, namebuff) == 0)
      {
	close(fd);
	t->file->refcount++;
	return t->file;
      }
  
  if (!(file = whine_malloc(sizeof(struct tftp_file) + strlen(namebuff) + 1)))
    {
      errno = ENOMEM;
      goto oops;
    }

  file->fd = fd;
  file->size = statbuf.st_size;
  file->dev = statbuf.st_dev;
  file->inode = statbuf.st_ino;
  file->refcount = 1;
  strcpy(file->filename, namebuff);
  return file;
  
 perm:
  *len =  tftp_err(ERR_PERM, packet, _("cannot access %s: %s"), namebuff, strerror(EACCES));
  if (fd != -1)
    close(fd);
  return NULL;

 oops:
  *len =  tftp_err_oops(packet, namebuff);
  if (fd != -1)
    close(fd);
  return NULL;
}

/**
 * @brief Poll TFTP sockets and handle timeouts and retransmissions
 * 
 * @detailed
 * This function is called from the main event loop to process active TFTP transfers.
 * In multi-port mode, it polls each transfer's socket for incoming ACK/ERROR packets.
 * For all transfers (single-port and multi-port), it checks for timeouts and retransmits
 * DATA blocks with exponential backoff. The function implements RFC 1350's timeout and
 * retransmission requirements, ultimately aborting transfers after 7+ backoff iterations.
 * Completed transfers are moved to daemon->tftp_done_trans for script processing.
 * 
 * @param now Current time in seconds since epoch for timeout comparison
 * 
 * @return void - No return value; transfer state updated or cleaned up internally
 * 
 * @note In single-port mode, all packets arrive via port 69 through tftp_request()
 *       and handle_tftp(), so socket polling is skipped
 * @note Exponential backoff formula: timeout += 1 + (1 << (backoff/2)), giving sequence
 *       1, 1, 2, 2, 4, 4, 8, 8 seconds for backoff values 0-7
 * @note Transfer is terminated after backoff > 7 (approximately 30 seconds total)
 * @note Last ACK timeout (when transfer complete) is not logged as error per RFC 1350
 * 
 * @warning TID (Transfer ID) mismatch packets from wrong source address generate
 *          ERR_TID error response per RFC 1350 paragraph 4
 * 
 * @see tftp_request() for initial request handling
 * @see handle_tftp() which processes ACK/ERR packets
 * @see get_block() which constructs DATA blocks for retransmission
 * @see do_tftp_script_run() which executes scripts for completed transfers
 * @see RFC 1350 Section 4 for timeout and retransmission requirements
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t current_time = time(NULL);
 * check_tftp_listeners(current_time); // Called from main event loop
 * // Polls active transfers, handles timeouts, retransmits blocks
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 4: "The TFTP timeout is determined by the round trip time"
 * - RFC 1350 Paragraph 4: TID (port) mismatch error handling
 * - RFC 1350: Exponential backoff on timeout (implementation detail)
 * 
 * SIDE EFFECTS:
 * - Polls file descriptors via poll_check() in multi-port mode
 * - Receives UDP packets via recvfrom()
 * - Sends UDP packets (DATA retransmit, ERR_TID)
 * - Modifies transfer state (timeout, backoff, block number)
 * - Removes transfers from daemon->tftp_trans list on completion/abort
 * - Moves completed transfers to daemon->tftp_done_trans for script execution
 * - Logs transfer completion/failure to syslog
 * - Calls free_transfer() on error or timeout abort
 * 
 * THREAD SAFETY:
 * Not thread-safe. Manipulates global daemon->tftp_trans list. Must be called only
 * from main event loop in single-threaded context.
 */
void check_tftp_listeners(time_t now)
{
  struct tftp_transfer *transfer, *tmp, **up;
  
  /* In single port mode, all packets come via port 69 and tftp_request() */
  if (!option_bool(OPT_SINGLE_PORT))
    for (transfer = daemon->tftp_trans; transfer; transfer = transfer->next)
      if (poll_check(transfer->sockfd, POLLIN))
	{
	  union mysockaddr peer;
	  socklen_t addr_len = sizeof(union mysockaddr);
	  ssize_t len;
	  
	  /* we overwrote the buffer... */
	  daemon->srv_save = NULL;

	  if ((len = recvfrom(transfer->sockfd, daemon->packet, daemon->packet_buff_sz, 0, &peer.sa, &addr_len)) > 0)
	    {
	      if (sockaddr_isequal(&peer, &transfer->peer)) 
		handle_tftp(now, transfer, len);
	      else
		{
		  /* Wrong source address. See rfc1350 para 4. */
		  prettyprint_addr(&peer, daemon->addrbuff);
		  len = tftp_err(ERR_TID, daemon->packet, _("ignoring packet from %s (TID mismatch)"), daemon->addrbuff, NULL);
		  while(retry_send(sendto(transfer->sockfd, daemon->packet, len, 0, &peer.sa, sa_len(&peer))));

#ifdef HAVE_DUMPFILE
		  dump_packet(DUMP_TFTP, (void *)daemon->packet, len, NULL, (union mysockaddr *)&peer, TFTP_PORT);
#endif
		}
	    }
	}
	  
  for (transfer = daemon->tftp_trans, up = &daemon->tftp_trans; transfer; transfer = tmp)
    {
      tmp = transfer->next;
      
      if (difftime(now, transfer->timeout) >= 0.0)
	{
	  int endcon = 0;
	  ssize_t len;

	  /* timeout, retransmit */
	  transfer->timeout += 1 + (1<<(transfer->backoff/2));
	  	  
	  /* we overwrote the buffer... */
	  daemon->srv_save = NULL;

	  if ((len = get_block(daemon->packet, transfer)) == -1)
	    {
	      len = tftp_err_oops(daemon->packet, transfer->file->filename);
	      endcon = 1;
	    }
	  else if (++transfer->backoff > 7)
	    {
	      /* don't complain about timeout when we're awaiting the last
		 ACK, some clients never send it */
	      if ((unsigned)len == transfer->blocksize + 4)
		endcon = 1;
	      len = 0;
	    }

	  if (len != 0)
	    {
	      send_from(transfer->sockfd, !option_bool(OPT_SINGLE_PORT), daemon->packet, len,
			&transfer->peer, &transfer->source, transfer->if_index);
#ifdef HAVE_DUMPFILE
	      dump_packet(DUMP_TFTP, (void *)daemon->packet, len, NULL, (union mysockaddr *)&transfer->peer, TFTP_PORT);
#endif
	    }
	  
	  if (endcon || len == 0)
	    {
	      strcpy(daemon->namebuff, transfer->file->filename);
	      sanitise(daemon->namebuff);
	      (void)prettyprint_addr(&transfer->peer, daemon->addrbuff);
	      my_syslog(MS_TFTP | LOG_INFO, endcon ? _("failed sending %s to %s") : _("sent %s to %s"), daemon->namebuff, daemon->addrbuff);
	      /* unlink */
	      *up = tmp;
	      if (endcon)
		free_transfer(transfer);
	      else
		{
		  /* put on queue to be sent to script and deleted */
		  transfer->next = daemon->tftp_done_trans;
		  daemon->tftp_done_trans = transfer;
		}
	      continue;
	    }
	}

      up = &transfer->next;
    }    
}

/**
 * @brief Process ACK or ERROR packets during active TFTP file transfer
 * 
 * @detailed
 * This function handles client responses during an ongoing TFTP transfer. When an ACK
 * packet is received with the correct block number, the transfer advances to the next
 * block and resets timeout/backoff counters to trigger immediate retransmission. When
 * an ERROR packet is received, the transfer is marked for abort by setting excessive
 * backoff. The function validates packet size and block numbers before processing to
 * ensure protocol correctness.
 * 
 * @param now Current time in seconds since epoch, used to reset transfer timeout
 * @param transfer Pointer to active transfer state, must not be NULL, modified in place
 * @param len Length of received packet in daemon->packet buffer, must be >= 4 bytes
 *            for valid ACK/ERROR packets
 * 
 * @return void - No return value; transfer state modified to reflect ACK/ERROR reception
 * 
 * @note Assumes received packet is already in daemon->packet buffer
 * @note Only processes ACK for current block number, ignoring duplicates or out-of-sequence
 * @note ERROR packets are sanitized before logging to prevent control character injection
 * @note Setting backoff=100 on ERROR ensures check_tftp_listeners() aborts the transfer
 * 
 * @warning Does not validate source address (assumed validated by caller)
 * @warning Packets < 4 bytes are silently ignored
 * 
 * @see check_tftp_listeners() which calls this in multi-port mode
 * @see tftp_request() which calls this in single-port mode
 * @see get_block() which constructs the next DATA block after ACK
 * @see RFC 1350 Section 5 for ACK packet format (opcode=4, block number)
 * @see RFC 1350 Section 5 for ERROR packet format (opcode=5, error code, message)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct tftp_transfer *xfer = ...; // Active transfer
 * ssize_t packet_len = recvfrom(...); // Receive ACK/ERROR
 * handle_tftp(time(NULL), xfer, packet_len);
 * // Transfer state updated: block incremented on ACK, aborted on ERROR
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 5: ACK packet format with opcode=4 and block number
 * - RFC 1350 Section 5: ERROR packet format with opcode=5, error code, and message
 * - RFC 1350: Block number wraparound (implementation handles 16-bit wraparound)
 * 
 * SIDE EFFECTS:
 * - Modifies transfer->timeout to current time (resets timeout on valid ACK)
 * - Modifies transfer->backoff to 0 (resets exponential backoff on valid ACK)
 * - Increments transfer->block on successful ACK
 * - Updates transfer->offset to next read position in file
 * - Sets transfer->backoff=100 on ERROR to trigger abort
 * - Logs ERROR messages to syslog with sanitized error text
 * - Reads error message from daemon->packet buffer
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies transfer state in place. Must be called from main event
 * loop in single-threaded context.
 */
static void handle_tftp(time_t now, struct tftp_transfer *transfer, ssize_t len)
{
  struct ack {
    unsigned short op, block;
  } *mess = (struct ack *)daemon->packet;
  
  if (len >= (ssize_t)sizeof(struct ack))
    {
      if (ntohs(mess->op) == OP_ACK && ntohs(mess->block) == (unsigned short)transfer->block) 
	{
	  /* Got ack, ensure we take the (re)transmit path */
	  transfer->timeout = now;
	  transfer->backoff = 0;
	  if (transfer->block++ != 0)
	    transfer->offset += transfer->blocksize - transfer->expansion;
	}
      else if (ntohs(mess->op) == OP_ERR)
	{
	  char *p = daemon->packet + sizeof(struct ack);
	  char *end = daemon->packet + len;
	  char *err = next(&p, end);
	  
	  (void)prettyprint_addr(&transfer->peer, daemon->addrbuff);
	  
	  /* Sanitise error message */
	  if (!err)
	    err = "";
	  else
	    sanitise(err);
	  
	  my_syslog(MS_TFTP | LOG_ERR, _("error %d %s received from %s"),
		    (int)ntohs(mess->block), err, 
		    daemon->addrbuff);	
	  
	  /* Got err, ensure we take abort */
	  transfer->timeout = now;
	  transfer->backoff = 100;
	}
    }
}

/**
 * @brief Release TFTP transfer resources including socket and file descriptor
 * 
 * @detailed
 * This function deallocates a struct tftp_transfer and releases associated resources.
 * In multi-port mode, it closes the transfer-specific socket. For the file reference,
 * it decrements the reference count and closes the file descriptor only when the count
 * reaches zero, allowing efficient file descriptor sharing when multiple clients download
 * the same file simultaneously (common in network boot scenarios).
 * 
 * @param transfer Pointer to transfer structure to free, must not be NULL
 * 
 * @return void - No return value; transfer and associated file resources released
 * 
 * @note In single-port mode (OPT_SINGLE_PORT), socket is shared and not closed here
 * @note File descriptor closed only when refcount reaches zero (last client completes)
 * @note Caller responsible for unlinking transfer from daemon->tftp_trans list before calling
 * 
 * @warning Must not be called with transfer still linked in daemon->tftp_trans list
 * @warning After return, transfer pointer is invalid (freed memory)
 * 
 * @see tftp_request() which calls this on initial error paths
 * @see check_tftp_listeners() which calls this on timeout/completion
 * @see check_tftp_fileperm() which allocates the tftp_file with refcount=1
 * 
 * EXAMPLE USAGE:
 * @code
 * struct tftp_transfer *xfer = ...; // Completed or failed transfer
 * // Unlink from list first
 * *up_ptr = xfer->next;
 * // Now safe to free
 * free_transfer(xfer); // Releases socket and file descriptor if last reference
 * @endcode
 * 
 * RFC COMPLIANCE:
 * N/A - Resource cleanup implementation detail, not protocol-specific
 * 
 * SIDE EFFECTS:
 * - Closes transfer->sockfd via close() in multi-port mode
 * - Decrements transfer->file->refcount
 * - Closes transfer->file->fd via close() when refcount reaches zero
 * - Frees transfer->file via free() when refcount reaches zero
 * - Frees transfer via free()
 * 
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop. Assumes no concurrent
 * access to transfer or file structures.
 */
static void free_transfer(struct tftp_transfer *transfer)
{
  if (!option_bool(OPT_SINGLE_PORT))
    close(transfer->sockfd);

  if (transfer->file && (--transfer->file->refcount) == 0)
    {
      close(transfer->file->fd);
      free(transfer->file);
    }
  
  free(transfer);
}

/**
 * @brief Extract next null-terminated string from TFTP packet buffer
 * 
 * @detailed
 * This utility function parses null-terminated strings from TFTP request packets.
 * It validates that the buffer is properly null-terminated, returns the string pointer,
 * and advances the parse position past the string and its terminating null byte. Used
 * primarily to extract filename, mode, and option name/value pairs from RRQ packets.
 * 
 * @param p Pointer to current parse position pointer, modified to point past extracted
 *          string, must not be NULL
 * @param end Pointer to one byte past end of packet buffer, must not be NULL, used for
 *            bounds checking
 * 
 * @return Pointer to extracted null-terminated string on success, NULL on malformed packet
 * 
 * @retval non-NULL Valid string pointer, *p advanced past string and null terminator
 * @retval NULL Malformed packet: not null-terminated, already at end, or zero-length string
 * 
 * @note Advances *p by strlen(string) + 1 on success
 * @note Zero-length strings (empty string) return NULL (treated as malformed)
 * 
 * @warning Does not validate string content, only null-termination and boundaries
 * @warning Caller must ensure 'end' pointer is valid packet boundary
 * 
 * @see tftp_request() which uses this to parse filename, mode, and option strings
 * @see RFC 1350 Section 5 for RRQ packet format with null-terminated strings
 * 
 * EXAMPLE USAGE:
 * @code
 * char *packet = ...; // Received RRQ packet
 * char *p = packet + 2; // Skip opcode
 * char *end = packet + packet_len;
 * char *filename = next(&p, end); // Extract filename
 * char *mode = next(&p, end);     // Extract mode ("octet" or "netascii")
 * if (!filename || !mode) {
 *     // Malformed packet
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 5: RRQ/WRQ format with null-separated filename and mode strings
 * - RFC 2347: Option strings in same null-separated format
 * 
 * SIDE EFFECTS:
 * - Modifies *p to point past extracted string (input/output parameter)
 * - No memory allocation or external state modification
 * 
 * THREAD SAFETY:
 * Thread-safe as a pure function with no shared state, only modifies caller's pointer.
 */
static char *next(char **p, char *end)
{
  char *ret = *p;
  size_t len;

  if (*(end-1) != 0 || 
      *p == end ||
      (len = strlen(ret)) == 0)
    return NULL;

  *p += len + 1;
  return ret;
}

/**
 * @brief Remove non-printable characters from string for safe logging
 * 
 * @detailed
 * This function sanitizes strings before logging to prevent control character injection
 * in syslog messages. It scans the input string and copies only printable ASCII characters
 * (isprint() returns true) to the output, compacting in place. Used to sanitize filenames
 * and error messages from TFTP packets before writing to system logs.
 * 
 * @param buf Null-terminated string to sanitize, modified in place, must not be NULL
 * 
 * @return void - No return value; buf modified in place with non-printable characters removed
 * 
 * @note Modifies string in place by compacting printable characters
 * @note Resulting string is always shorter or equal length, null-terminated
 * @note Uses isprint() which considers ASCII 0x20-0x7E as printable
 * 
 * @warning Input buffer is modified; caller must pass writable memory
 * @warning Does not validate UTF-8 or other multi-byte encodings
 * 
 * @see handle_tftp() which sanitizes client ERROR messages before logging
 * @see check_tftp_listeners() which sanitizes filenames before logging
 * @see tftp_err() which sanitizes file arguments before logging
 * 
 * EXAMPLE USAGE:
 * @code
 * char error_msg[] = "File\x07not\x1bfound"; // Contains BEL and ESC control chars
 * sanitise(error_msg);
 * // Result: "Filenotfound" (control characters removed)
 * my_syslog(LOG_ERR, "Error: %s", error_msg); // Safe to log
 * @endcode
 * 
 * RFC COMPLIANCE:
 * N/A - Security best practice for logging, not protocol-specific
 * 
 * SIDE EFFECTS:
 * - Modifies input buffer in place, removing non-printable characters
 * - No memory allocation or external state modification
 * 
 * THREAD SAFETY:
 * Thread-safe as long as buf is not shared between threads during execution.
 * No global state access.
 */
static void sanitise(char *buf)
{
  unsigned char *q, *r;
  for (q = r = (unsigned char *)buf; *r; r++)
    if (isprint((int)*r))
      *(q++) = *r;
  *q = 0;

}

#define MAXMESSAGE 500 /* limit to make packet < 512 bytes and definitely smaller than buffer */

/**
 * @brief Construct TFTP ERROR packet with formatted message
 * 
 * @detailed
 * This function builds a TFTP ERROR packet according to RFC 1350 format with opcode=5,
 * error code, and null-terminated error message. The message is formatted using printf-style
 * format string with up to two arguments (file and arg2). The packet is constructed in the
 * provided buffer (typically daemon->packet) and logged to syslog unless it's a "file not
 * found" error with quiet TFTP mode enabled.
 * 
 * @param err TFTP error code: ERR_NOTDEF (0), ERR_FNF (1), ERR_PERM (2), ERR_FULL (3),
 *            ERR_ILL (4), ERR_TID (5) per RFC 1350 Section 5
 * @param packet Buffer to construct ERROR packet, must be at least 516 bytes, typically
 *               daemon->packet, modified with ERROR packet content
 * @param message Printf-style format string for error message, must not be NULL, supports
 *                up to 2 format specifiers (%s)
 * @param file First argument for message formatting, typically filename, may be NULL,
 *             sanitized before inclusion in packet
 * @param arg2 Second argument for message formatting, typically client address, may be NULL
 * 
 * @return Length of constructed ERROR packet in bytes (minimum 4, maximum ~516)
 * 
 * @note Message is truncated to MAXMESSAGE (500 bytes) to ensure packet stays under 512 bytes
 * @note File argument is sanitized via sanitise() before inclusion
 * @note Error is logged to syslog unless ERR_FNF with OPT_QUIET_TFTP enabled
 * 
 * @warning Packet buffer must be >= 516 bytes (4 byte header + MAXMESSAGE + null + overhead)
 * @warning Message format string must match number of provided arguments
 * 
 * @see tftp_err_oops() for errno-based error packet construction
 * @see sanitise() which removes control characters from file argument
 * @see RFC 1350 Section 5 for ERROR packet format
 * 
 * EXAMPLE USAGE:
 * @code
 * char packet[512];
 * ssize_t err_len = tftp_err(ERR_FNF, packet,
 *                            _("file %s not found for %s"),
 *                            "pxelinux.0", "192.168.1.100");
 * sendto(sockfd, packet, err_len, 0, ...); // Send ERROR to client
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 5: ERROR packet format (opcode=5, error code, message, null)
 * - RFC 1350 Section 5: Error codes 0-5 defined (not defined, file not found, access
 *   violation, disk full, illegal operation, unknown transfer ID)
 * 
 * SIDE EFFECTS:
 * - Writes ERROR packet to packet buffer (4 + message_length + 1 bytes)
 * - Zeroes entire packet buffer via memset()
 * - Sanitizes file argument via sanitise()
 * - Logs to syslog via my_syslog() unless ERR_FNF with OPT_QUIET_TFTP
 * 
 * THREAD SAFETY:
 * Not thread-safe due to packet buffer modification. Must be called from single-threaded
 * event loop context.
 */
static ssize_t tftp_err(int err, char *packet, char *message, char *file, char *arg2)
{
  struct errmess {
    unsigned short op, err;
    char message[];
  } *mess = (struct errmess *)packet;
  ssize_t len, ret = 4;
    
  memset(packet, 0, daemon->packet_buff_sz);
  if (file)
    sanitise(file);
  
  mess->op = htons(OP_ERR);
  mess->err = htons(err);
  len = snprintf(mess->message, MAXMESSAGE,  message, file, arg2);
  ret += (len < MAXMESSAGE) ? len + 1 : MAXMESSAGE; /* include terminating zero */
  
  if (err != ERR_FNF || !option_bool(OPT_QUIET_TFTP))
    my_syslog(MS_TFTP | LOG_ERR, "%s", mess->message);
  
  return  ret;
}

/**
 * @brief Construct TFTP ERROR packet for file read errors using errno
 * 
 * @detailed
 * This convenience function constructs a TFTP ERROR packet (opcode 0 = not defined) for
 * file I/O errors. It formats the error message to include both the filename and the
 * system error description from errno (via strerror). The function uses daemon->namebuff
 * as a scratch buffer to safely handle the filename argument which may have multiple
 * references in active transfers.
 * 
 * @param packet Buffer to construct ERROR packet, must be at least 516 bytes, typically
 *               daemon->packet
 * @param file Filename that failed to read, may be NULL, may point to daemon->namebuff
 *             or other memory, copied to daemon->namebuff before formatting
 * 
 * @return Length of constructed ERROR packet in bytes via tftp_err()
 * 
 * @note Uses ERR_NOTDEF (0) as error code for undefined/general errors
 * @note Copies file to daemon->namebuff to avoid aliasing issues with file parameter
 * @note Error message format: "cannot read %s: %s" with file and strerror(errno)
 * 
 * @warning Relies on errno being set by previous I/O operation
 * @warning Overwrites daemon->namebuff
 * 
 * @see tftp_err() which constructs the actual ERROR packet
 * @see get_block() which calls this on lseek() or read() failures
 * @see check_tftp_fileperm() which calls this on open() or fstat() failures
 * 
 * EXAMPLE USAGE:
 * @code
 * if (read(fd, buffer, size) == -1) {
 *     ssize_t err_len = tftp_err_oops(daemon->packet, filename);
 *     sendto(sockfd, daemon->packet, err_len, 0, ...); // Send ERROR to client
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 5: ERROR packet with code 0 (not defined) for general errors
 * 
 * SIDE EFFECTS:
 * - Copies file argument to daemon->namebuff via strcpy() if file != daemon->namebuff
 * - Calls tftp_err() which writes ERROR packet and logs to syslog
 * - Reads errno global variable
 * 
 * THREAD SAFETY:
 * Not thread-safe. Uses global daemon->namebuff and errno. Must be called from
 * single-threaded event loop context.
 */
static ssize_t tftp_err_oops(char *packet, const char *file)
{
  /* May have >1 refs to file, so potentially mangle a copy of the name */
  if (file != daemon->namebuff)
    strcpy(daemon->namebuff, file);
  return tftp_err(ERR_NOTDEF, packet, _("cannot read %s: %s"), daemon->namebuff, strerror(errno));
}

/**
 * @brief Construct OACK or DATA packet for TFTP transfer
 * 
 * @detailed
 * This function generates the appropriate TFTP packet based on transfer state. For block 0,
 * it constructs an OACK (Option Acknowledgment) packet if the client requested options like
 * blksize or tsize. For subsequent blocks, it reads data from the file and constructs a
 * DATA packet with the appropriate block number. In netascii mode, it performs CR-LF
 * translation by inserting CR before each LF character, tracking carry state across block
 * boundaries to handle LF at block end correctly.
 * 
 * @param packet Buffer to construct OACK/DATA packet, must be at least packet_buff_sz bytes,
 *               typically daemon->packet, zeroed and filled with packet content
 * @param transfer Active transfer state, must not be NULL, contains block number, file
 *                 descriptor, blocksize, offset, and netascii mode flag
 * 
 * @return Packet length in bytes (OACK or DATA), 0 if transfer complete, -1 on read error
 * 
 * @retval >0 Packet constructed successfully, length includes 4-byte header plus data
 * @retval 0 Transfer complete (offset >= file size)
 * @retval -1 File read error (lseek or read failed)
 * 
 * @note Block 0 (after option negotiation) sends OACK instead of DATA
 * @note Block numbers wrap at 65535 per RFC 1350 (unsigned short)
 * @note Netascii expansion reduces effective blocksize by number of added CRs
 * @note Tracks carrylf flag to prevent double-expansion of LF at block boundaries
 * 
 * @warning lseek() failure returns -1 (indicates I/O error)
 * @warning read_write() failure returns -1 (indicates I/O error)
 * @warning Netascii mode only supported for text files, not recommended for binaries
 * 
 * @see tftp_request() which calls this for initial block after options negotiated
 * @see check_tftp_listeners() which calls this for retransmissions
 * @see RFC 1350 Section 5 for DATA packet format (opcode=3, block, data)
 * @see RFC 2347 for OACK packet format (opcode=6, option/value pairs)
 * @see RFC 2348 for blksize option semantics
 * @see RFC 2349 for tsize option semantics
 * 
 * EXAMPLE USAGE:
 * @code
 * struct tftp_transfer *xfer = ...; // Active transfer
 * ssize_t pkt_len = get_block(daemon->packet, xfer);
 * if (pkt_len == -1) {
 *     // Read error, send ERROR packet
 * } else if (pkt_len == 0) {
 *     // Transfer complete
 * } else {
 *     sendto(sockfd, daemon->packet, pkt_len, 0, ...); // Send DATA or OACK
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * - RFC 1350 Section 5: DATA packet format with opcode=3, block number, and data
 * - RFC 2347: OACK packet format with opcode=6 and null-separated option/value pairs
 * - RFC 2348: blksize option included in OACK with negotiated value
 * - RFC 2349: tsize option included in OACK with file size value
 * - RFC 1350: Netascii mode requires LF → CR-LF translation
 * 
 * SIDE EFFECTS:
 * - Zeroes packet buffer via memset()
 * - Reads from file via lseek() and read_write()
 * - Updates transfer->expansion with CR count (for netascii mode)
 * - Updates transfer->carrylf flag for cross-block LF tracking
 * - Writes OACK or DATA packet to packet buffer
 * 
 * THREAD SAFETY:
 * Not thread-safe. Modifies transfer state and packet buffer. Must be called from
 * single-threaded event loop context.
 */
static ssize_t get_block(char *packet, struct tftp_transfer *transfer)
{
  memset(packet, 0, daemon->packet_buff_sz);
  
  if (transfer->block == 0)
    {
      /* send OACK */
      char *p;
      struct oackmess {
	unsigned short op;
	char data[];
      } *mess = (struct oackmess *)packet;
      
      p = mess->data;
      mess->op = htons(OP_OACK);
      if (transfer->opt_blocksize)
	{
	  p += (sprintf(p, "blksize") + 1);
	  p += (sprintf(p, "%u", transfer->blocksize) + 1);
	}
      if (transfer->opt_transize)
	{
	  p += (sprintf(p,"tsize") + 1);
	  p += (sprintf(p, "%u", (unsigned int)transfer->file->size) + 1);
	}

      return p - packet;
    }
  else
    {
      /* send data packet */
      struct datamess {
	unsigned short op, block;
	unsigned char data[];
      } *mess = (struct datamess *)packet;
      
      size_t size = transfer->file->size - transfer->offset; 
      
      if (transfer->offset > transfer->file->size)
	return 0; /* finished */
      
      if (size > transfer->blocksize)
	size = transfer->blocksize;
      
      mess->op = htons(OP_DATA);
      mess->block = htons((unsigned short)(transfer->block));
      
      if (lseek(transfer->file->fd, transfer->offset, SEEK_SET) == (off_t)-1 ||
	  !read_write(transfer->file->fd, mess->data, size, 1))
	return -1;
      
      transfer->expansion = 0;
      
      /* Map '\n' to CR-LF in netascii mode */
      if (transfer->netascii)
	{
	  size_t i;
	  int newcarrylf;

	  for (i = 0, newcarrylf = 0; i < size; i++)
	    if (mess->data[i] == '\n' && ( i != 0 || !transfer->carrylf))
	      {
		transfer->expansion++;

		if (size != transfer->blocksize)
		  size++; /* room in this block */
		else  if (i == size - 1)
		  newcarrylf = 1; /* don't expand LF again if it moves to the next block */
		  
		/* make space and insert CR */
		memmove(&mess->data[i+1], &mess->data[i], size - (i + 1));
		mess->data[i] = '\r';
		
		i++;
	      }
	  transfer->carrylf = newcarrylf;
	  
	}

      return size + 4;
    }
}

/**
 * @brief Execute post-transfer script for completed TFTP transfer
 * 
 * @detailed
 * This function is called from the main event loop to process completed TFTP transfers
 * that are queued for script execution. It removes one transfer from the
 * daemon->tftp_done_trans queue, invokes the user-configured script via queue_tftp()
 * (if HAVE_SCRIPT is enabled) with transfer details (file size, filename, client address),
 * and frees the transfer resources. This allows non-blocking script execution without
 * stalling the TFTP server during file transfer completion.
 * 
 * @return 1 if a transfer was processed, 0 if queue is empty
 * 
 * @retval 1 Transfer processed and script queued for execution
 * @retval 0 No transfers in done queue (daemon->tftp_done_trans is NULL)
 * 
 * @note Script execution is queued, not synchronous; actual execution happens via helper.c
 * @note Transfer resources released after queueing, preventing resource leaks
 * @note Script receives: file size, filename, client address as parameters
 * 
 * @warning Only processes one transfer per call; caller must loop until return 0
 * @warning Requires HAVE_SCRIPT compile-time option for script execution
 * 
 * @see check_tftp_listeners() which moves completed transfers to tftp_done_trans queue
 * @see queue_tftp() in helper.c which queues the script for execution
 * @see free_transfer() which releases transfer resources
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called from main event loop after transfer completion
 * while (do_tftp_script_run()) {
 *     // Process all queued completed transfers
 * }
 * // All scripts queued, can continue event loop
 * @endcode
 * 
 * RFC COMPLIANCE:
 * N/A - Implementation-specific post-processing feature, not part of TFTP protocol
 * 
 * SIDE EFFECTS:
 * - Removes one transfer from daemon->tftp_done_trans queue
 * - Calls queue_tftp() to queue script execution (if HAVE_SCRIPT)
 * - Calls free_transfer() to release socket and file descriptor
 * - Modifies daemon->tftp_done_trans pointer
 * 
 * THREAD SAFETY:
 * Not thread-safe. Manipulates global daemon->tftp_done_trans list. Must be called
 * only from main event loop in single-threaded context.
 */
int do_tftp_script_run(void)
{
  struct tftp_transfer *transfer;

  if ((transfer = daemon->tftp_done_trans))
    {
      daemon->tftp_done_trans = transfer->next;
#ifdef HAVE_SCRIPT
      queue_tftp(transfer->file->size, transfer->file->filename, &transfer->peer);
#endif
      free_transfer(transfer);
      return 1;
    }

  return 0;
}
#endif
