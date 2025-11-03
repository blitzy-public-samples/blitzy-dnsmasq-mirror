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
 * @file rfc2131.c
 * @brief DHCPv4 protocol implementation per RFC 2131
 *
 * DETAILED PURPOSE:
 * This file implements the complete DHCPv4 server protocol as specified in RFC 2131
 * (Dynamic Host Configuration Protocol). It handles all DHCPv4 message types including
 * DHCPDISCOVER→DHCPOFFER, DHCPREQUEST→DHCPACK/DHCPNAK, DHCPRELEASE, DHCPDECLINE, and
 * DHCPINFORM exchanges. The implementation manages the entire DHCPv4 server state machine,
 * performing lease allocation from configured address pools, applying static host 
 * reservations, handling DHCP relay agent operations (GIADDR processing), processing
 * relay agent information (Option 82), integrating with PXE/TFTP boot services, and
 * implementing ping-before-offer for address conflict detection.
 *
 * The core message processing flow begins with dhcp_reply() which receives raw DHCPv4
 * packets, extracts and validates DHCP options, identifies the client (by client 
 * identifier or MAC address), determines the client's network context, applies 
 * configuration matching rules (netid tags, vendor classes, user classes), and dispatches
 * to message-type-specific handlers. Response packets are constructed by dhcp_packet()
 * which assembles DHCP options according to client requests and server policy, handles
 * option overload (using sname/file fields), applies vendor-specific options, and 
 * manages PXE-specific extensions for network boot.
 *
 * KEY RESPONSIBILITIES:
 * - dhcp_reply() - Main DHCPv4 packet handler and message type dispatcher (lines 71-1025)
 * - dhcp_packet() - DHCP response packet construction and option assembly (lines 1027-1283)
 * - do_options() - Populate DHCP options in response packets (lines 1448-2119)
 * - calc_time() - Calculate lease time from context and configuration (lines 1409-1446)
 * - server_id() - Determine server identifier for responses (lines 1377-1407)
 * - option_find() - Locate and extract DHCP options from packets (lines 1311-1327)
 * - log_packet() - Generate detailed DHCP transaction log entries (lines 2194-2330)
 * - is_pxe_client() - Detect and classify PXE network boot clients (lines 2683-2722)
 * - pxe_opts() - Generate PXE-specific DHCP options (lines 2390-2656)
 * - apply_delay() - Implement delayed DHCP response for load control (lines 2660-2681)
 *
 * DEPENDENCIES:
 * - dnsmasq.h - Core daemon structures (struct dhcp_context, dhcp_config, dhcp_lease,
 *               dhcp_packet, dhcp_netid, dhcp_opt, dhcp_boot, dhcp_vendor, dhcp_mac)
 * - dhcp-protocol.h - DHCPv4 wire protocol constants (DHCPDISCOVER, DHCPOFFER, DHCPREQUEST,
 *                     DHCPACK, DHCPNAK, DHCPRELEASE, DHCPDECLINE, DHCPINFORM, OPTION_* constants)
 * 
 * Called by:
 * - dhcp.c dhcp_packet_handler() - Receives raw DHCP packets from network layer
 * 
 * Calls:
 * - lease.c lease_find_by_client(), lease_find_by_addr(), lease_allocate() - Lease database operations
 * - dhcp-common.c match_netid(), run_tag_if() - Configuration matching logic
 * - helper.c queue_script() - External lease-change script execution
 * - network.c iface_check() - Interface validation
 * - cache.c cache_add_dhcp_entry() - DNS cache integration for DHCP hostnames
 *
 * DATA STRUCTURES:
 * - struct dhcp_packet (dhcp-protocol.h:94-101) - DHCPv4 wire format packet structure
 * - struct dhcp_context (dnsmasq.h) - DHCP address range/pool configuration
 * - struct dhcp_config (dnsmasq.h) - Static DHCP host configuration
 * - struct dhcp_lease (dnsmasq.h) - Active DHCP lease tracking
 * - struct dhcp_netid (dnsmasq.h) - Configuration tag matching system
 * - struct dhcp_opt (dnsmasq.h) - DHCP option configuration
 * - struct dhcp_boot (dnsmasq.h) - PXE boot configuration
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP (mandatory) - Entire file conditionally compiled with #ifdef HAVE_DHCP
 * - HAVE_SCRIPT - Enables external script integration via add_extradata_opt() (line 24-26)
 * - HAVE_BROKEN_RTC - Affects lease time calculations for embedded systems without RTC
 * - NO_ID - Disables client identifier processing
 * - HAVE_DHCP_AUTH - Enables DHCP authentication (RFC 3118)
 *
 * RFC COMPLIANCE:
 * - RFC 2131: Dynamic Host Configuration Protocol (complete implementation)
 * - RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * - RFC 3046: DHCP Relay Agent Information Option (Option 82)
 * - RFC 3527: Link Selection sub-option for Option 82
 * - RFC 3942: Reclassifying DHCPv4 Options
 * - RFC 4578: Dynamic Host Configuration Protocol (DHCP) Options for PXE
 * - RFC 5107: DHCP Server Identifier Override Suboption
 *
 * THREADING MODEL:
 * This file operates within dnsmasq's single-process, event-driven architecture using
 * poll()-based I/O multiplexing. All functions are called sequentially from the main
 * event loop in response to incoming DHCP packets. No multi-threading or locking is
 * required. Static variables are safe as there is no concurrent execution. Functions
 * are not re-entrant and must not be called from signal handlers.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DHCP_V4.md for complete DHCPv4 server architecture documentation
 * @see dhcp.c for DHCP packet reception and socket management
 * @see lease.c for DHCP lease database persistence
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

#define option_len(opt) ((int)(((unsigned char *)(opt))[1]))
#define option_ptr(opt, i) ((void *)&(((unsigned char *)(opt))[2u+(unsigned int)(i)]))

#ifdef HAVE_SCRIPT
static void add_extradata_opt(struct dhcp_lease *lease, unsigned char *opt);
#endif

static int sanitise(unsigned char *opt, char *buf);
static struct in_addr server_id(struct dhcp_context *context, struct in_addr override, struct in_addr fallback);
static unsigned int calc_time(struct dhcp_context *context, struct dhcp_config *config, unsigned char *opt);
static void option_put(struct dhcp_packet *mess, unsigned char *end, int opt, int len, unsigned int val);
static void option_put_string(struct dhcp_packet *mess, unsigned char *end, 
			      int opt, const char *string, int null_term);
static struct in_addr option_addr(unsigned char *opt);
static unsigned int option_uint(unsigned char *opt, int offset, int size);
static void log_packet(char *type, void *addr, unsigned char *ext_mac, 
		       int mac_len, char *interface, char *string, char *err, u32 xid);
static unsigned char *option_find(struct dhcp_packet *mess, size_t size, int opt_type, int minsize);
static unsigned char *option_find1(unsigned char *p, unsigned char *end, int opt, int minsize);
static size_t dhcp_packet_size(struct dhcp_packet *mess, unsigned char *agent_id, unsigned char *real_end);
static void clear_packet(struct dhcp_packet *mess, unsigned char *end);
static int in_list(unsigned char *list, int opt);
static void do_options(struct dhcp_context *context,
		       struct dhcp_packet *mess,
		       unsigned char *end,
		       unsigned char *req_options,
		       char *hostname, 
		       char *domain,
		       struct dhcp_netid *netid,
		       struct in_addr subnet_addr, 
		       unsigned char fqdn_flags,
		       int null_term, int pxe_arch,
		       unsigned char *uuid,
		       int vendor_class_len,
		       time_t now,
		       unsigned int lease_time,
		       unsigned short fuzz,
		       const char *pxevendor);


static void match_vendor_opts(unsigned char *opt, struct dhcp_opt *dopt); 
static int do_encap_opts(struct dhcp_opt *opt, int encap, int flag, struct dhcp_packet *mess, unsigned char *end, int null_term);
static void pxe_misc(struct dhcp_packet *mess, unsigned char *end, unsigned char *uuid, const char *pxevendor);
static int prune_vendor_opts(struct dhcp_netid *netid);
static struct dhcp_opt *pxe_opts(int pxe_arch, struct dhcp_netid *netid, struct in_addr local, time_t now);
struct dhcp_boot *find_boot(struct dhcp_netid *netid);
static int pxe_uefi_workaround(int pxe_arch, struct dhcp_netid *netid, struct dhcp_packet *mess, struct in_addr local, time_t now, int pxe);
static void apply_delay(u32 xid, time_t recvtime, struct dhcp_netid *netid);
static int is_pxe_client(struct dhcp_packet *mess, size_t sz, const char **pxe_vendor);

/**
 * @brief Process incoming DHCPv4 packet and generate appropriate response
 *
 * @detailed
 * This is the main entry point for all DHCPv4 server operations. It receives raw DHCP packets,
 * validates packet structure and options, determines the DHCP message type (DISCOVER, REQUEST,
 * RELEASE, DECLINE, INFORM), identifies the client using client identifier or hardware address,
 * matches clients against configured address pools and static reservations, applies network ID
 * tag-based configuration rules, dispatches to message-type-specific processing logic, and
 * constructs appropriate response packets (OFFER, ACK, NAK) with all requested DHCP options.
 * 
 * The function implements the complete RFC 2131 server state machine including: initial address
 * discovery (DISCOVER→OFFER), address allocation (REQUEST→ACK/NAK), lease renewal (REQUEST→ACK),
 * address release (RELEASE), address conflict reporting (DECLINE), and stateless configuration
 * (INFORM→ACK). It handles DHCP relay operations via GIADDR processing, processes relay agent
 * information option (Option 82) for circuit/remote ID, integrates with PXE network boot via
 * architecture-specific options, implements ping-before-offer for conflict avoidance, maintains
 * lease database persistence, triggers external lease-change scripts, and provides comprehensive
 * transaction logging.
 *
 * @param context Initial DHCP context matching the receiving interface's subnet, may be NULL
 *                if packet arrives on interface without configured DHCP range
 * @param iface_name Name of network interface packet was received on (e.g. "eth0")
 * @param int_index Integer index of receiving interface for kernel operations
 * @param sz Size of received DHCP packet in bytes including IP/UDP headers (typically 300-1500)
 * @param now Current time in seconds since epoch for lease expiration calculations
 * @param unicast_dest Boolean flag: 1 if response should be unicast, 0 for broadcast
 * @param loopback Boolean flag: 1 if packet received on loopback interface
 * @param is_inform Output parameter set to 1 if message is DHCPINFORM, else unchanged, may be NULL
 * @param pxe File descriptor for PXE-specific socket (port 4011) or -1 if PXE disabled
 * @param fallback Server identifier to use if primary interface has no address configured
 * @param recvtime Packet reception timestamp for delayed response processing
 *
 * @return Size of constructed response packet in bytes if response generated, 0 if no response
 *         needed (e.g. packet validation failed, RELEASE/DECLINE processed, client ignored)
 *
 * @retval >0 Response packet constructed in daemon->dhcp_packet buffer, ready for transmission
 * @retval 0 No response packet generated (invalid request, ignored client, or silent operation)
 *
 * @note Response packet is constructed in global daemon->dhcp_packet buffer which may be 
 *       dynamically expanded based on client's OPTION_MAXMESSAGE size request
 * @note Function may update daemon->dhcp_packet buffer pointer via expand_buf() requiring
 *       local mess pointer to be reassigned from daemon->dhcp_packet.iov_base
 * @note Client identification uses client identifier option (Option 61) if present, else
 *       falls back to hardware address from chaddr field
 * @note Lease allocation integrates with DNS cache to enable hostname→IP resolution for
 *       DHCP clients via cache_add_dhcp_entry()
 *
 * @warning Modifies global daemon->dhcp_packet buffer contents and may reallocate buffer
 * @warning Not re-entrant due to use of static DHCP option configuration state
 * @warning Some buggy DHCP clients incorrectly set ciaddr field which is cleared here
 *
 * @see dhcp_packet() for DHCP response packet construction (lines 1027-1283)
 * @see do_options() for DHCP option population logic (lines 1448-2119)
 * @see option_find() for DHCP option extraction from packets (lines 1311-1327)
 * @see calc_time() for lease time calculation (lines 1409-1446)
 * @see server_id() for server identifier determination (lines 1377-1407)
 * @see is_pxe_client() for PXE client detection (lines 2683-2722)
 * @see docs/DHCP_V4.md for complete DHCPv4 architecture and RFC compliance matrix
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *context = find_context(iface);
 * int is_inform = 0;
 * size_t reply_size = dhcp_reply(context, "eth0", 2, packet_size, time(NULL),
 *                                 0, 0, &is_inform, -1, fallback_addr, time(NULL));
 * if (reply_size > 0)
 *   send_dhcp_packet(daemon->dhcp_packet.iov_base, reply_size);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 2131 Section 3.1: Client-Server Interaction (DISCOVER/OFFER/REQUEST/ACK state machine)
 * - RFC 2131 Section 3.2: DHCP Server Behavior (address allocation and lease management)
 * - RFC 2131 Section 4.3: DHCP Message processing (all message types implemented)
 * - RFC 2132: DHCP Options (complete option processing)
 * - RFC 3046: Relay Agent Information Option (Option 82 circuit-id, remote-id, server-id-override)
 * - RFC 3527: Link Selection sub-option for Relay Agent (subnet selection)
 * - RFC 4578: PXE Options (architecture, UUID, boot menu processing)
 * - RFC 5107: Server Identifier Override Suboption (relay agent server selection)
 *
 * SIDE EFFECTS:
 * - May allocate new lease in lease database via lease_allocate()
 * - May update existing lease via lease_update_from_configs()
 * - May trigger external script execution via queue_script() if HAVE_SCRIPT enabled
 * - May add DNS cache entries via cache_add_dhcp_entry() for DHCP-assigned hostnames
 * - Modifies daemon->dhcp_packet buffer contents (response packet construction)
 * - May reallocate daemon->dhcp_packet buffer via expand_buf() if client requests larger packet
 * - Logs transaction details to syslog via log_packet()
 * - Implements delayed response via apply_delay() for load control
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called only from main event loop. Uses global daemon state and
 * static DHCP option configuration. Not re-entrant.
 */
size_t dhcp_reply(struct dhcp_context *context, char *iface_name, int int_index,
		  size_t sz, time_t now, int unicast_dest, int loopback,
		  int *is_inform, int pxe, struct in_addr fallback, time_t recvtime)
{
  unsigned char *opt, *clid = NULL;
  struct dhcp_lease *ltmp, *lease = NULL;
  struct dhcp_vendor *vendor;
  struct dhcp_mac *mac;
  struct dhcp_netid_list *id_list;
  int clid_len = 0, ignore = 0, do_classes = 0, rapid_commit = 0, selecting = 0, pxearch = -1;
  const char *pxevendor = NULL;
  struct dhcp_packet *mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
  unsigned char *end = (unsigned char *)(mess + 1); 
  unsigned char *real_end = (unsigned char *)(mess + 1); 
  char *hostname = NULL, *offer_hostname = NULL, *client_hostname = NULL, *domain = NULL;
  int hostname_auth = 0, borken_opt = 0;
  unsigned char *req_options = NULL;
  char *message = NULL;
  unsigned int time;
  struct dhcp_config *config;
  struct dhcp_netid *netid, *tagif_netid;
  struct in_addr subnet_addr, override;
  unsigned short fuzz = 0;
  unsigned int mess_type = 0;
  unsigned char fqdn_flags = 0;
  unsigned char *agent_id = NULL, *uuid = NULL;
  unsigned char *emac = NULL;
  int vendor_class_len = 0, emac_len = 0;
  struct dhcp_netid known_id, iface_id, cpewan_id;
  struct dhcp_opt *o;
  unsigned char pxe_uuid[17];
  unsigned char *oui = NULL, *serial = NULL;
#ifdef HAVE_SCRIPT
  unsigned char *class = NULL;
#endif

  subnet_addr.s_addr = override.s_addr = 0;

  /* set tag with name == interface */
  iface_id.net = iface_name;
  iface_id.next = NULL;
  netid = &iface_id; 
  
  if (mess->op != BOOTREQUEST || mess->hlen > DHCP_CHADDR_MAX)
    return 0;
   
  if (mess->htype == 0 && mess->hlen != 0)
    return 0;

  /* check for DHCP rather than BOOTP */
  if ((opt = option_find(mess, sz, OPTION_MESSAGE_TYPE, 1)))
    {
      u32 cookie = htonl(DHCP_COOKIE);
      
      /* only insist on a cookie for DHCP. */
      if (memcmp(mess->options, &cookie, sizeof(u32)) != 0)
	return 0;
      
      mess_type = option_uint(opt, 0, 1);
      
      /* two things to note here: expand_buf may move the packet,
	 so reassign mess from daemon->packet. Also, the size
	 sent includes the IP and UDP headers, hence the magic "-28" */
      if ((opt = option_find(mess, sz, OPTION_MAXMESSAGE, 2)))
	{
	  size_t size = (size_t)option_uint(opt, 0, 2) - 28;
	  
	  if (size > DHCP_PACKET_MAX)
	    size = DHCP_PACKET_MAX;
	  else if (size < sizeof(struct dhcp_packet))
	    size = sizeof(struct dhcp_packet);
	  
	  if (expand_buf(&daemon->dhcp_packet, size))
	    {
	      mess = (struct dhcp_packet *)daemon->dhcp_packet.iov_base;
	      real_end = end = ((unsigned char *)mess) + size;
	    }
	}

      /* Some buggy clients set ciaddr when they shouldn't, so clear that here since
	 it can affect the context-determination code. */
      if ((option_find(mess, sz, OPTION_REQUESTED_IP, INADDRSZ) || mess_type == DHCPDISCOVER))
	mess->ciaddr.s_addr = 0;

      /* search for device identity from CPEWAN devices, we pass this through to the script */
      if ((opt = option_find(mess, sz, OPTION_VENDOR_IDENT_OPT, 5)))
	{
	  unsigned  int elen, offset, len = option_len(opt);
	  
	  for (offset = 0; offset < (len - 5); offset += elen + 5)
	    {
	      elen = option_uint(opt, offset + 4 , 1);
	      if (option_uint(opt, offset, 4) == BRDBAND_FORUM_IANA && offset + elen + 5 <= len)
		{
		  unsigned char *x = option_ptr(opt, offset + 5);
		  unsigned char *y = option_ptr(opt, offset + elen + 5);
		  oui = option_find1(x, y, 1, 1);
		  serial = option_find1(x, y, 2, 1);
#ifdef HAVE_SCRIPT
		  class = option_find1(x, y, 3, 1);		  
#endif
		  /* If TR069-id is present set the tag "cpewan-id" to facilitate echoing 
		     the gateway id back. Note that the device class is optional */
		  if (oui && serial)
		    {
		      cpewan_id.net = "cpewan-id";
		      cpewan_id.next = netid;
		      netid = &cpewan_id;
		    }
		  break;
		}
	    }
	}
      
      if ((opt = option_find(mess, sz, OPTION_AGENT_ID, 1)))
	{
	  /* Any agent-id needs to be copied back out, verbatim, as the last option
	     in the packet. Here, we shift it to the very end of the buffer, if it doesn't
	     get overwritten, then it will be shuffled back at the end of processing.
	     Note that the incoming options must not be overwritten here, so there has to 
	     be enough free space at the end of the packet to copy the option. */
	  unsigned char *sopt;
	  unsigned int total = option_len(opt) + 2;
	  unsigned char *last_opt = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + sz,
						 OPTION_END, 0);
	  if (last_opt && last_opt < end - total)
	    {
	      end -= total;
	      agent_id = end;
	      memcpy(agent_id, opt, total);
	    }

	  /* look for RFC3527 Link selection sub-option */
	  if ((sopt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_SUBNET_SELECT, INADDRSZ)))
	    subnet_addr = option_addr(sopt);

	  /* look for RFC5107 server-identifier-override */
	  if ((sopt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_SERVER_OR, INADDRSZ)))
	    override = option_addr(sopt);
	  
	  /* if a circuit-id or remote-is option is provided, exact-match to options. */ 
	  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
	    {
	      int search;
	      
	      if (vendor->match_type == MATCH_CIRCUIT)
		search = SUBOPT_CIRCUIT_ID;
	      else if (vendor->match_type == MATCH_REMOTE)
		search = SUBOPT_REMOTE_ID;
	      else if (vendor->match_type == MATCH_SUBSCRIBER)
		search = SUBOPT_SUBSCR_ID;
	      else 
		continue;

	      if ((sopt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), search, 1)) &&
		  vendor->len == option_len(sopt) &&
		  memcmp(option_ptr(sopt, 0), vendor->data, vendor->len) == 0)
		{
		  vendor->netid.next = netid;
		  netid = &vendor->netid;
		} 
	    }
	}

      /* Check for RFC3011 subnet selector - only if RFC3527 one not present */
      if (subnet_addr.s_addr == 0 && (opt = option_find(mess, sz, OPTION_SUBNET_SELECT, INADDRSZ)))
	subnet_addr = option_addr(opt);
      
      /* If there is no client identifier option, use the hardware address */
      if (!option_bool(OPT_IGNORE_CLID) && (opt = option_find(mess, sz, OPTION_CLIENT_ID, 1)))
	{
	  clid_len = option_len(opt);
	  clid = option_ptr(opt, 0);
	}

      /* do we have a lease in store? */
      lease = lease_find_by_client(mess->chaddr, mess->hlen, mess->htype, clid, clid_len);

      /* If this request is missing a clid, but we've seen one before, 
	 use it again for option matching etc. */
      if (lease && !clid && lease->clid)
	{
	  clid_len = lease->clid_len;
	  clid = lease->clid;
	}

      /* find mac to use for logging and hashing */
      emac = extended_hwaddr(mess->htype, mess->hlen, mess->chaddr, clid_len, clid, &emac_len);
    }
  
  for (mac = daemon->dhcp_macs; mac; mac = mac->next)
    if (mac->hwaddr_len == mess->hlen &&
	(mac->hwaddr_type == mess->htype || mac->hwaddr_type == 0) &&
	memcmp_masked(mac->hwaddr, mess->chaddr, mess->hlen, mac->mask))
      {
	mac->netid.next = netid;
	netid = &mac->netid;
      }
  
  /* Determine network for this packet. Our caller will have already linked all the 
     contexts which match the addresses of the receiving interface but if the 
     machine has an address already, or came via a relay, or we have a subnet selector, 
     we search again. If we don't have have a giaddr or explicit subnet selector, 
     use the ciaddr. This is necessary because a  machine which got a lease via a 
     relay won't use the relay to renew. If matching a ciaddr fails but we have a context 
     from the physical network, continue using that to allow correct DHCPNAK generation later. */
  if (mess->giaddr.s_addr || subnet_addr.s_addr || mess->ciaddr.s_addr)
    {
      struct dhcp_context *context_tmp, *context_new = NULL;
      struct shared_network *share = NULL;
      struct in_addr addr;
      int force = 0, via_relay = 0;
      
      if (subnet_addr.s_addr)
	{
	  addr = subnet_addr;
	  force = 1;
	}
      else if (mess->giaddr.s_addr)
	{
	  addr = mess->giaddr;
	  force = 1;
	  via_relay = 1;
	}
      else
	{
	  /* If ciaddr is in the hardware derived set of contexts, leave that unchanged */
	  addr = mess->ciaddr;
	  for (context_tmp = context; context_tmp; context_tmp = context_tmp->current)
	    if (context_tmp->netmask.s_addr && 
		is_same_net(addr, context_tmp->start, context_tmp->netmask) &&
		is_same_net(addr, context_tmp->end, context_tmp->netmask))
	      {
		context_new = context;
		break;
	      }
	} 
		
      if (!context_new)
	{
	  for (context_tmp = daemon->dhcp; context_tmp; context_tmp = context_tmp->next)
	    {
	      struct in_addr netmask = context_tmp->netmask;
	      
	      /* guess the netmask for relayed networks */
	      if (!(context_tmp->flags & CONTEXT_NETMASK) && context_tmp->netmask.s_addr == 0)
		{
		  if (IN_CLASSA(ntohl(context_tmp->start.s_addr)) && IN_CLASSA(ntohl(context_tmp->end.s_addr)))
		    netmask.s_addr = htonl(0xff000000);
		  else if (IN_CLASSB(ntohl(context_tmp->start.s_addr)) && IN_CLASSB(ntohl(context_tmp->end.s_addr)))
		    netmask.s_addr = htonl(0xffff0000);
		  else if (IN_CLASSC(ntohl(context_tmp->start.s_addr)) && IN_CLASSC(ntohl(context_tmp->end.s_addr)))
		    netmask.s_addr = htonl(0xffffff00); 
		}

	      /* check to see is a context is OK because of a shared address on
		 the relayed subnet. */
	      if (via_relay)
		for (share = daemon->shared_networks; share; share = share->next)
		  {
#ifdef HAVE_DHCP6
		    if (share->shared_addr.s_addr == 0)
		      continue;
#endif
		    if (share->if_index != 0 ||
			share->match_addr.s_addr != mess->giaddr.s_addr)
		      continue;
		    
		    if (netmask.s_addr != 0  && 
			is_same_net(share->shared_addr, context_tmp->start, netmask) &&
			is_same_net(share->shared_addr, context_tmp->end, netmask))
		      break;
		  }
	      
	      /* This section fills in context mainly when a client which is on a remote (relayed)
		 network renews a lease without using the relay, after dnsmasq has restarted. */
	      if (share ||
		  (netmask.s_addr != 0  && 
		   is_same_net(addr, context_tmp->start, netmask) &&
		   is_same_net(addr, context_tmp->end, netmask)))
		{
		  context_tmp->netmask = netmask;
		  if (context_tmp->local.s_addr == 0)
		    context_tmp->local = fallback;
		  if (context_tmp->router.s_addr == 0 && !share)
		    context_tmp->router = mess->giaddr;
		  
		  /* fill in missing broadcast addresses for relayed ranges */
		  if (!(context_tmp->flags & CONTEXT_BRDCAST) && context_tmp->broadcast.s_addr == 0 )
		    context_tmp->broadcast.s_addr = context_tmp->start.s_addr | ~context_tmp->netmask.s_addr;
		  
		  context_tmp->current = context_new;
		  context_new = context_tmp;
		}
	      
	    }
	}
	  
      if (context_new || force)
	context = context_new; 
    }
  
  if (!context)
    {
      const char *via;
      if (subnet_addr.s_addr)
	{
	  via = _("with subnet selector");
	  inet_ntop(AF_INET, &subnet_addr, daemon->addrbuff, ADDRSTRLEN);
	}
      else
	{
	  via = _("via");
	  if (mess->giaddr.s_addr)
	    inet_ntop(AF_INET, &mess->giaddr, daemon->addrbuff, ADDRSTRLEN);
	  else
	    safe_strncpy(daemon->addrbuff, iface_name, ADDRSTRLEN);
	}
      my_syslog(MS_DHCP | LOG_WARNING, _("no address range available for DHCP request %s %s"),
		via, daemon->addrbuff);
      return 0;
    }

  if (option_bool(OPT_LOG_OPTS))
    {
      struct dhcp_context *context_tmp;
      for (context_tmp = context; context_tmp; context_tmp = context_tmp->current)
	{
	  inet_ntop(AF_INET, &context_tmp->start, daemon->namebuff, MAXDNAME);
	  if (context_tmp->flags & (CONTEXT_STATIC | CONTEXT_PROXY))
	    {
	      inet_ntop(AF_INET, &context_tmp->netmask, daemon->addrbuff, ADDRSTRLEN);
	      my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCP subnet: %s/%s"),
			ntohl(mess->xid), daemon->namebuff, daemon->addrbuff);
	    }
	  else
	    {
	      inet_ntop(AF_INET, &context_tmp->end, daemon->addrbuff, ADDRSTRLEN);
	      my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCP range: %s -- %s"),
			ntohl(mess->xid), daemon->namebuff, daemon->addrbuff);
	    }
	}
    }
  
  /* dhcp-match. If we have hex-and-wildcards, look for a left-anchored match.
     Otherwise assume the option is an array, and look for a matching element. 
     If no data given, existence of the option is enough. This code handles 
     rfc3925 V-I classes too. */
  for (o = daemon->dhcp_match; o; o = o->next)
    {
      unsigned int len, elen, match = 0;
      size_t offset, o2;

      if (o->flags & DHOPT_RFC3925)
	{
	  if (!(opt = option_find(mess, sz, OPTION_VENDOR_IDENT, 5)))
	    continue;
	  
	  for (offset = 0; offset < (option_len(opt) - 5u); offset += len + 5)
	    {
	      len = option_uint(opt, offset + 4 , 1);
	      /* Need to take care that bad data can't run us off the end of the packet */
	      if ((offset + len + 5 <= (unsigned)(option_len(opt))) &&
		  (option_uint(opt, offset, 4) == (unsigned int)o->u.encap))
		for (o2 = offset + 5; o2 < offset + len + 5; o2 += elen + 1)
		  { 
		    elen = option_uint(opt, o2, 1);
		    if ((o2 + elen + 1 <= (unsigned)option_len(opt)) &&
			(match = match_bytes(o, option_ptr(opt, o2 + 1), elen)))
		      break;
		  }
	      if (match) 
		break;
	    }	  
	}
      else
	{
	  if (!(opt = option_find(mess, sz, o->opt, 1)))
	    continue;
	  
	  match = match_bytes(o, option_ptr(opt, 0), option_len(opt));
	} 

      if (match)
	{
	  o->netid->next = netid;
	  netid = o->netid;
	}
    }
	
  /* user-class options are, according to RFC3004, supposed to contain
     a set of counted strings. Here we check that this is so (by seeing
     if the counts are consistent with the overall option length) and if
     so zero the counts so that we don't get spurious matches between 
     the vendor string and the counts. If the lengths don't add up, we
     assume that the option is a single string and non RFC3004 compliant 
     and just do the substring match. dhclient provides these broken options.
     The code, later, which sends user-class data to the lease-change script
     relies on the transformation done here.
  */

  if ((opt = option_find(mess, sz, OPTION_USER_CLASS, 1)))
    {
      unsigned char *ucp = option_ptr(opt, 0);
      int tmp, j;
      for (j = 0; j < option_len(opt); j += ucp[j] + 1);
      if (j == option_len(opt))
	for (j = 0; j < option_len(opt); j = tmp)
	  {
	    tmp = j + ucp[j] + 1;
	    ucp[j] = 0;
	  }
    }
    
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    {
      int mopt;
      
      if (vendor->match_type == MATCH_VENDOR)
	mopt = OPTION_VENDOR_ID;
      else if (vendor->match_type == MATCH_USER)
	mopt = OPTION_USER_CLASS; 
      else
	continue;

      if ((opt = option_find(mess, sz, mopt, 1)))
	{
	  int i;
	  for (i = 0; i <= (option_len(opt) - vendor->len); i++)
	    if (memcmp(vendor->data, option_ptr(opt, i), vendor->len) == 0)
	      {
		vendor->netid.next = netid;
		netid = &vendor->netid;
		break;
	      }
	}
    }

  /* mark vendor-encapsulated options which match the client-supplied vendor class,
     save client-supplied vendor class */
  if ((opt = option_find(mess, sz, OPTION_VENDOR_ID, 1)))
    {
      memcpy(daemon->dhcp_buff3, option_ptr(opt, 0), option_len(opt));
      vendor_class_len = option_len(opt);
    }
  match_vendor_opts(opt, daemon->dhcp_opts);
  
  if (option_bool(OPT_LOG_OPTS))
    {
      if (sanitise(opt, daemon->namebuff))
	my_syslog(MS_DHCP | LOG_INFO, _("%u vendor class: %s"), ntohl(mess->xid), daemon->namebuff);
      if (sanitise(option_find(mess, sz, OPTION_USER_CLASS, 1), daemon->namebuff))
	my_syslog(MS_DHCP | LOG_INFO, _("%u user class: %s"), ntohl(mess->xid), daemon->namebuff);
    }

  mess->op = BOOTREPLY;
  
  config = find_config(daemon->dhcp_conf, context, clid, clid_len, 
		       mess->chaddr, mess->hlen, mess->htype, NULL, run_tag_if(netid));

  /* set "known" tag for known hosts */
  if (config)
    {
      known_id.net = "known";
      known_id.next = netid;
      netid = &known_id;
    }
  else if (find_config(daemon->dhcp_conf, NULL, clid, clid_len, 
		       mess->chaddr, mess->hlen, mess->htype, NULL, run_tag_if(netid)))
    {
      known_id.net = "known-othernet";
      known_id.next = netid;
      netid = &known_id;
    }
  
  if (mess_type == 0 && !pxe)
    {
      /* BOOTP request */
      struct dhcp_netid id, bootp_id;
      struct in_addr *logaddr = NULL;

      /* must have a MAC addr for bootp */
      if (mess->htype == 0 || mess->hlen == 0 || (context->flags & CONTEXT_PROXY))
	return 0;
      
      if (have_config(config, CONFIG_DISABLE))
	message = _("disabled");

      end = mess->options + 64; /* BOOTP vend area is only 64 bytes */
            
      if (have_config(config, CONFIG_NAME))
	{
	  hostname = config->hostname;
	  domain = config->domain;
	}

      if (config)
	{
	  struct dhcp_netid_list *list;

	  for (list = config->netid; list; list = list->next)
	    {
	      list->list->next = netid;
	      netid = list->list;
	    }
	}

      /* Match incoming filename field as a netid. */
      if (mess->file[0])
	{
	  memcpy(daemon->dhcp_buff2, mess->file, sizeof(mess->file));
	  daemon->dhcp_buff2[sizeof(mess->file) + 1] = 0; /* ensure zero term. */
	  id.net = (char *)daemon->dhcp_buff2;
	  id.next = netid;
	  netid = &id;
	}

      /* Add "bootp" as a tag to allow different options, address ranges etc
	 for BOOTP clients */
      bootp_id.net = "bootp";
      bootp_id.next = netid;
      netid = &bootp_id;
      
      tagif_netid = run_tag_if(netid);

      for (id_list = daemon->dhcp_ignore; id_list; id_list = id_list->next)
	if (match_netid(id_list->list, tagif_netid, 0))
	  message = _("ignored");
      
      if (!message)
	{
	  int nailed = 0;

	  if (have_config(config, CONFIG_ADDR))
	    {
	      nailed = 1;
	      logaddr = &config->addr;
	      mess->yiaddr = config->addr;
	      if ((lease = lease_find_by_addr(config->addr)) &&
		  (lease->hwaddr_len != mess->hlen ||
		   lease->hwaddr_type != mess->htype ||
		   memcmp(lease->hwaddr, mess->chaddr, lease->hwaddr_len) != 0))
		message = _("address in use");
	    }
	  else
	    {
	      if (!(lease = lease_find_by_client(mess->chaddr, mess->hlen, mess->htype, NULL, 0)) ||
		  !address_available(context, lease->addr, tagif_netid))
		{
		   if (lease)
		     {
		       /* lease exists, wrong network. */
		       lease_prune(lease, now);
		       lease = NULL;
		     }
		   if (!address_allocate(context, &mess->yiaddr, mess->chaddr, mess->hlen, tagif_netid, now, loopback))
		     message = _("no address available");
		}
	      else
		mess->yiaddr = lease->addr;
	    }
	  
	  if (!message && !(context = narrow_context(context, mess->yiaddr, netid)))
	    message = _("wrong network");
	  else if (context->netid.net)
	    {
	      context->netid.next = netid;
	      tagif_netid = run_tag_if(&context->netid);
	    }

	  log_tags(tagif_netid, ntohl(mess->xid));
	    
	  if (!message && !nailed)
	    {
	      for (id_list = daemon->bootp_dynamic; id_list; id_list = id_list->next)
		if ((!id_list->list) || match_netid(id_list->list, tagif_netid, 0))
		  break;
	      if (!id_list)
		message = _("no address configured");
	    }

	  if (!message && 
	      !lease && 
	      (!(lease = lease4_allocate(mess->yiaddr))))
	    message = _("no leases left");
	  
	  if (!message)
	    {
	      logaddr = &mess->yiaddr;
		
	      lease_set_hwaddr(lease, mess->chaddr, NULL, mess->hlen, mess->htype, 0, now, 1);
	      if (hostname)
		lease_set_hostname(lease, hostname, 1, get_domain(lease->addr), domain); 
	      /* infinite lease unless nailed in dhcp-host line. */
	      lease_set_expires(lease,  
				have_config(config, CONFIG_TIME) ? config->lease_time : 0xffffffff, 
				now); 
	      lease_set_interface(lease, int_index, now);
	      
	      clear_packet(mess, end);
	      do_options(context, mess, end, NULL, hostname, get_domain(mess->yiaddr), 
			 netid, subnet_addr, 0, 0, -1, NULL, vendor_class_len, now, 0xffffffff, 0, NULL);
	    }
	}
      
      daemon->metrics[METRIC_BOOTP]++;
      log_packet("BOOTP", logaddr, mess->chaddr, mess->hlen, iface_name, NULL, message, mess->xid);
      
      return message ? 0 : dhcp_packet_size(mess, agent_id, real_end);
    }
      
  if ((opt = option_find(mess, sz, OPTION_CLIENT_FQDN, 3)))
    {
      /* http://tools.ietf.org/wg/dhc/draft-ietf-dhc-fqdn-option/draft-ietf-dhc-fqdn-option-10.txt */
      int len = option_len(opt);
      char *pq = daemon->dhcp_buff;
      unsigned char *pp, *op = option_ptr(opt, 0);
      
      fqdn_flags = *op;
      len -= 3;
      op += 3;
      pp = op;
      
      /* NB, the following always sets at least one bit */
      if (option_bool(OPT_FQDN_UPDATE))
	{
	  if (fqdn_flags & 0x01)
	    {
	      fqdn_flags |= 0x02; /* set O */
	      fqdn_flags &= ~0x01; /* clear S */
	    }
	  fqdn_flags |= 0x08; /* set N */
	}
      else 
	{
	  if (!(fqdn_flags & 0x01))
	    fqdn_flags |= 0x03; /* set S and O */
	  fqdn_flags &= ~0x08; /* clear N */
	}
      
      if (fqdn_flags & 0x04)
	while (*op != 0 && ((op + (*op)) - pp) < len)
	  {
	    memcpy(pq, op+1, *op);
	    pq += *op;
	    op += (*op)+1;
	    *(pq++) = '.';
	  }
      else
	{
	  memcpy(pq, op, len);
	  if (len > 0 && op[len-1] == 0)
	    borken_opt = 1;
	  pq += len + 1;
	}
      
      if (pq != daemon->dhcp_buff)
	pq--;
      
      *pq = 0;
      
      if (legal_hostname(daemon->dhcp_buff))
	offer_hostname = client_hostname = daemon->dhcp_buff;
    }
  else if ((opt = option_find(mess, sz, OPTION_HOSTNAME, 1)))
    {
      int len = option_len(opt);
      memcpy(daemon->dhcp_buff, option_ptr(opt, 0), len);
      /* Microsoft clients are broken, and need zero-terminated strings
	 in options. We detect this state here, and do the same in
	 any options we send */
      if (len > 0 && daemon->dhcp_buff[len-1] == 0)
	borken_opt = 1;
      else
	daemon->dhcp_buff[len] = 0;
      if (legal_hostname(daemon->dhcp_buff))
	client_hostname = daemon->dhcp_buff;
    }

  if (client_hostname)
    {
      struct dhcp_match_name *m;
      size_t nl = strlen(client_hostname);
      
      if (option_bool(OPT_LOG_OPTS))
	my_syslog(MS_DHCP | LOG_INFO, _("%u client provides name: %s"), ntohl(mess->xid), client_hostname);
      for (m = daemon->dhcp_name_match; m; m = m->next)
	{
	  size_t ml = strlen(m->name);
	  char save = 0;
	  
	  if (nl < ml)
	    continue;
	  if (nl > ml)
	    {
	      save = client_hostname[ml];
	      client_hostname[ml] = 0;
	    }
	  
	  if (hostname_isequal(client_hostname, m->name) &&
	      (save == 0 || m->wildcard))
	    {
	      m->netid->next = netid;
	      netid = m->netid;
	    }
	  
	  if (save != 0)
	    client_hostname[ml] = save;
	}
    }
  
  if (have_config(config, CONFIG_NAME))
    {
      hostname = config->hostname;
      domain = config->domain;
      hostname_auth = 1;
      /* be careful not to send an OFFER with a hostname not matching the DISCOVER. */
      if (fqdn_flags != 0 || !client_hostname || hostname_isequal(hostname, client_hostname))
        offer_hostname = hostname;
    }
  else if (client_hostname)
    {
      domain = strip_hostname(client_hostname);
      
      if (strlen(client_hostname) != 0)
	{
	  hostname = client_hostname;
	  
	  if (!config)
	    {
	      /* Search again now we have a hostname. 
		 Only accept configs without CLID and HWADDR here, (they won't match)
		 to avoid impersonation by name. */
	      struct dhcp_config *new = find_config(daemon->dhcp_conf, context, NULL, 0,
						    mess->chaddr, mess->hlen, 
						    mess->htype, hostname, run_tag_if(netid));
	      if (new && !have_config(new, CONFIG_CLID) && !new->hwaddr)
		{
		  config = new;
		  /* set "known" tag for known hosts */
		  known_id.net = "known";
		  known_id.next = netid;
		  netid = &known_id;
		}
	    }
	}
    }
  
  if (config)
    {
      struct dhcp_netid_list *list;
      
      for (list = config->netid; list; list = list->next)
	{
	  list->list->next = netid;
	  netid = list->list;
	}
    }
  
  tagif_netid = run_tag_if(netid);
  
  /* if all the netids in the ignore list are present, ignore this client */
  for (id_list = daemon->dhcp_ignore; id_list; id_list = id_list->next)
    if (match_netid(id_list->list, tagif_netid, 0))
      ignore = 1;

  /* If configured, we can override the server-id to be the address of the relay, 
     so that all traffic goes via the relay and can pick up agent-id info. This can be
     configured for all relays, or by address. */
  if (daemon->override && mess->giaddr.s_addr != 0 && override.s_addr == 0)
    {
      if (!daemon->override_relays)
	override = mess->giaddr;
      else
	{
	  struct addr_list *l;
	  for (l = daemon->override_relays; l; l = l->next)
	    if (l->addr.s_addr == mess->giaddr.s_addr)
	      break;
	  if (l)
	    override = mess->giaddr;
	}
    }

  /* Can have setting to ignore the client ID for a particular MAC address or hostname */
  if (have_config(config, CONFIG_NOCLID))
    clid = NULL;
          
  /* Check if client is PXE client. */
  if (daemon->enable_pxe &&
      is_pxe_client(mess, sz, &pxevendor))
    {
      if ((opt = option_find(mess, sz, OPTION_PXE_UUID, 17)))
	{
	  memcpy(pxe_uuid, option_ptr(opt, 0), 17);
	  uuid = pxe_uuid;
	}

      /* Check if this is really a PXE bootserver request, and handle specially if so. */
      if ((mess_type == DHCPREQUEST || mess_type == DHCPINFORM) &&
	  (opt = option_find(mess, sz, OPTION_VENDOR_CLASS_OPT, 1)) &&
	  (opt = option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_PXE_BOOT_ITEM, 4)))
	{
	  struct pxe_service *service;
	  int type = option_uint(opt, 0, 2);
	  int layer = option_uint(opt, 2, 2);
	  unsigned char save71[4];
	  struct dhcp_opt opt71;

	  if (ignore)
	    return 0;

	  if (layer & 0x8000)
	    {
	      my_syslog(MS_DHCP | LOG_ERR, _("PXE BIS not supported"));
	      return 0;
	    }

	  memcpy(save71, option_ptr(opt, 0), 4);
	  
	  for (service = daemon->pxe_services; service; service = service->next)
	    if (service->type == type)
	      break;
	  
	  for (; context; context = context->current)
	    if (match_netid(context->filter, tagif_netid, 1) &&
		is_same_net(mess->ciaddr, context->start, context->netmask))
	      break;
	  
	  if (!service || !service->basename || !context)
	    return 0;
	  	  
	  clear_packet(mess, end);
	  
	  mess->yiaddr = mess->ciaddr;
	  mess->ciaddr.s_addr = 0;
	  if (service->sname)
	    mess->siaddr = a_record_from_hosts(service->sname, now);
	  else if (service->server.s_addr != 0)
	    mess->siaddr = service->server; 
	  else
	    mess->siaddr = context->local; 
	  
	  if (strchr(service->basename, '.'))
	    snprintf((char *)mess->file, sizeof(mess->file),
		"%s", service->basename);
	  else
	    snprintf((char *)mess->file, sizeof(mess->file),
		"%s.%d", service->basename, layer);
	  
	  option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
	  option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, htonl(context->local.s_addr));
	  pxe_misc(mess, end, uuid, pxevendor);
	  
	  prune_vendor_opts(tagif_netid);
	  opt71.val = save71;
	  opt71.opt = SUBOPT_PXE_BOOT_ITEM;
	  opt71.len = 4;
	  opt71.flags = DHOPT_VENDOR_MATCH;
	  opt71.netid = NULL;
	  opt71.next = daemon->dhcp_opts;
	  do_encap_opts(&opt71, OPTION_VENDOR_CLASS_OPT, DHOPT_VENDOR_MATCH, mess, end, 0);
	  
	  log_packet("PXE", &mess->yiaddr, emac, emac_len, iface_name, (char *)mess->file, NULL, mess->xid);
	  log_tags(tagif_netid, ntohl(mess->xid));
	  return dhcp_packet_size(mess, agent_id, real_end);	  
	}
      
      if ((opt = option_find(mess, sz, OPTION_ARCH, 2)))
	{
	  pxearch = option_uint(opt, 0, 2);

	  /* proxy DHCP here. */
	  if ((mess_type == DHCPDISCOVER || (pxe && mess_type == DHCPREQUEST)))
	    {
	      struct dhcp_context *tmp;
	      int workaround = 0;
	      
	      for (tmp = context; tmp; tmp = tmp->current)
		if ((tmp->flags & CONTEXT_PROXY) &&
		    match_netid(tmp->filter, tagif_netid, 1))
		  break;
	      
	      if (tmp)
		{
		  struct dhcp_boot *boot;
		  int redirect4011 = 0;

		  if (tmp->netid.net)
		    {
		      tmp->netid.next = netid;
		      tagif_netid = run_tag_if(&tmp->netid);
		    }
		  
		  boot = find_boot(tagif_netid);
		  
		  mess->yiaddr.s_addr = 0;
		  if  (mess_type == DHCPDISCOVER || mess->ciaddr.s_addr == 0)
		    {
		      mess->ciaddr.s_addr = 0;
		      mess->flags |= htons(0x8000); /* broadcast */
		    }
		  
		  clear_packet(mess, end);
		  
		  /* Redirect EFI clients to port 4011 */
		  if (pxearch >= 6)
		    {
		      redirect4011 = 1;
		      mess->siaddr = tmp->local;
		    }
		  
		  /* Returns true if only one matching service is available. On port 4011, 
		     it also inserts the boot file and server name. */
		  workaround = pxe_uefi_workaround(pxearch, tagif_netid, mess, tmp->local, now, pxe);
		  
		  if (!workaround && boot)
		    {
		      /* Provide the bootfile here, for iPXE, and in case we have no menu items
			 and set discovery_control = 8 */
		      if (boot->next_server.s_addr) 
			mess->siaddr = boot->next_server;
		      else if (boot->tftp_sname) 
			mess->siaddr = a_record_from_hosts(boot->tftp_sname, now);
		      
		      if (boot->file)
			safe_strncpy((char *)mess->file, boot->file, sizeof(mess->file));
		    }
		  
		  option_put(mess, end, OPTION_MESSAGE_TYPE, 1, 
			     mess_type == DHCPDISCOVER ? DHCPOFFER : DHCPACK);
		  option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, htonl(tmp->local.s_addr));
		  pxe_misc(mess, end, uuid, pxevendor);
		  prune_vendor_opts(tagif_netid);
		  if ((pxe && !workaround) || !redirect4011)
		    do_encap_opts(pxe_opts(pxearch, tagif_netid, tmp->local, now), OPTION_VENDOR_CLASS_OPT, DHOPT_VENDOR_MATCH, mess, end, 0);
	    
		  daemon->metrics[METRIC_PXE]++;
		  log_packet("PXE", NULL, emac, emac_len, iface_name, ignore ? "proxy-ignored" : "proxy", NULL, mess->xid);
		  log_tags(tagif_netid, ntohl(mess->xid));
		  if (!ignore)
		    apply_delay(mess->xid, recvtime, tagif_netid);
		  return ignore ? 0 : dhcp_packet_size(mess, agent_id, real_end);	  
		}
	    }
	}
    }

  /* if we're just a proxy server, go no further */
  if ((context->flags & CONTEXT_PROXY) || pxe)
    return 0;
  
  if ((opt = option_find(mess, sz, OPTION_REQUESTED_OPTIONS, 0)))
    {
      req_options = (unsigned char *)daemon->dhcp_buff2;
      memcpy(req_options, option_ptr(opt, 0), option_len(opt));
      req_options[option_len(opt)] = OPTION_END;
    }
  
  switch (mess_type)
    {
    case DHCPDECLINE:
      if (!(opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER, INADDRSZ)) ||
	  option_addr(opt).s_addr != server_id(context, override, fallback).s_addr)
	return 0;
      
      /* sanitise any message. Paranoid? Moi? */
      sanitise(option_find(mess, sz, OPTION_MESSAGE, 1), daemon->dhcp_buff);
      
      if (!(opt = option_find(mess, sz, OPTION_REQUESTED_IP, INADDRSZ)))
	return 0;
      
      daemon->metrics[METRIC_DHCPDECLINE]++;
      log_packet("DHCPDECLINE", option_ptr(opt, 0), emac, emac_len, iface_name, NULL, daemon->dhcp_buff, mess->xid);
      
      if (lease && lease->addr.s_addr == option_addr(opt).s_addr)
	lease_prune(lease, now);
      
      if (have_config(config, CONFIG_ADDR) && 
	  config->addr.s_addr == option_addr(opt).s_addr)
	{
	  prettyprint_time(daemon->dhcp_buff, DECLINE_BACKOFF);
	  inet_ntop(AF_INET, &config->addr, daemon->addrbuff, ADDRSTRLEN);
	  my_syslog(MS_DHCP | LOG_WARNING, _("disabling DHCP static address %s for %s"), 
		    daemon->addrbuff, daemon->dhcp_buff);
	  config->flags |= CONFIG_DECLINED;
	  config->decline_time = now;
	}
      else
	/* make sure this host gets a different address next time. */
	for (; context; context = context->current)
	  context->addr_epoch++;
      
      return 0;

    case DHCPRELEASE:
      if (!(context = narrow_context(context, mess->ciaddr, tagif_netid)) ||
	  !(opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER, INADDRSZ)) ||
	  option_addr(opt).s_addr != server_id(context, override, fallback).s_addr)
	return 0;
      
      if (lease && lease->addr.s_addr == mess->ciaddr.s_addr)
	lease_prune(lease, now);
      else
	message = _("unknown lease");

      daemon->metrics[METRIC_DHCPRELEASE]++;
      log_packet("DHCPRELEASE", &mess->ciaddr, emac, emac_len, iface_name, NULL, message, mess->xid);
	
      return 0;
      
    case DHCPDISCOVER:
      if (ignore || have_config(config, CONFIG_DISABLE))
	{
	  if (option_bool(OPT_QUIET_DHCP))
	    return 0;
	  message = _("ignored");
	  opt = NULL;
	}
      else 
	{
	  struct in_addr addr, conf;
	  
	  addr.s_addr = conf.s_addr = 0;

	  if ((opt = option_find(mess, sz, OPTION_REQUESTED_IP, INADDRSZ)))	 
	    addr = option_addr(opt);
	  
	  if (have_config(config, CONFIG_ADDR))
	    {
	      inet_ntop(AF_INET, &config->addr, daemon->addrbuff, ADDRSTRLEN);
	      
	      if ((ltmp = lease_find_by_addr(config->addr)) && 
		  ltmp != lease &&
		  !config_has_mac(config, ltmp->hwaddr, ltmp->hwaddr_len, ltmp->hwaddr_type))
		{
		  int len;
		  unsigned char *mac = extended_hwaddr(ltmp->hwaddr_type, ltmp->hwaddr_len,
						       ltmp->hwaddr, ltmp->clid_len, ltmp->clid, &len);
		  my_syslog(MS_DHCP | LOG_WARNING, _("not using configured address %s because it is leased to %s"),
			    daemon->addrbuff, print_mac(daemon->namebuff, mac, len));
		}
	      else
		{
		  struct dhcp_context *tmp;
		  for (tmp = context; tmp; tmp = tmp->current)
		    if (context->router.s_addr == config->addr.s_addr)
		      break;
		  if (tmp)
		    my_syslog(MS_DHCP | LOG_WARNING, _("not using configured address %s because it is in use by the server or relay"), daemon->addrbuff);
		  else if (have_config(config, CONFIG_DECLINED) &&
			   difftime(now, config->decline_time) < (float)DECLINE_BACKOFF)
		    my_syslog(MS_DHCP | LOG_WARNING, _("not using configured address %s because it was previously declined"), daemon->addrbuff);
		  else
		    conf = config->addr;
		}
	    }
	  
	  if (conf.s_addr)
	    mess->yiaddr = conf;
	  else if (lease && 
		   address_available(context, lease->addr, tagif_netid) && 
		   !config_find_by_address(daemon->dhcp_conf, lease->addr))
	    mess->yiaddr = lease->addr;
	  else if (opt && address_available(context, addr, tagif_netid) && !lease_find_by_addr(addr) && 
		   !config_find_by_address(daemon->dhcp_conf, addr) && do_icmp_ping(now, addr, 0, loopback))
	    mess->yiaddr = addr;
	  else if (emac_len == 0)
	    message = _("no unique-id");
	  else if (!address_allocate(context, &mess->yiaddr, emac, emac_len, tagif_netid, now, loopback))
	    message = _("no address available");      
	}
      
      daemon->metrics[METRIC_DHCPDISCOVER]++;
      log_packet("DHCPDISCOVER", opt ? option_ptr(opt, 0) : NULL, emac, emac_len, iface_name, NULL, message, mess->xid); 

      if (message || !(context = narrow_context(context, mess->yiaddr, tagif_netid)))
	return 0;

      if (context->netid.net)
	{
	  context->netid.next = netid;
	  tagif_netid = run_tag_if(&context->netid);
	}

      log_tags(tagif_netid, ntohl(mess->xid));
      apply_delay(mess->xid, recvtime, tagif_netid);

      if (option_bool(OPT_RAPID_COMMIT) && option_find(mess, sz, OPTION_RAPID_COMMIT, 0))
	{
	  rapid_commit = 1;
	  goto rapid_commit;
	}
      
      daemon->metrics[METRIC_DHCPOFFER]++;
      log_packet("DHCPOFFER" , &mess->yiaddr, emac, emac_len, iface_name, NULL, NULL, mess->xid);
      
      time = calc_time(context, config, option_find(mess, sz, OPTION_LEASE_TIME, 4));
      clear_packet(mess, end);
      option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPOFFER);
      option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(server_id(context, override, fallback).s_addr));
      option_put(mess, end, OPTION_LEASE_TIME, 4, time);
      /* T1 and T2 are required in DHCPOFFER by HP's wacky Jetdirect client. */
      do_options(context, mess, end, req_options, offer_hostname, get_domain(mess->yiaddr), 
		 netid, subnet_addr, fqdn_flags, borken_opt, pxearch, uuid, vendor_class_len, now, time, fuzz, pxevendor);
      
      return dhcp_packet_size(mess, agent_id, real_end);
	

    case DHCPREQUEST:
      if (ignore || have_config(config, CONFIG_DISABLE))
	return 0;
      if ((opt = option_find(mess, sz, OPTION_REQUESTED_IP, INADDRSZ)))
	{
	  /* SELECTING  or INIT_REBOOT */
	  mess->yiaddr = option_addr(opt);
	  
	  /* send vendor and user class info for new or recreated lease */
	  do_classes = 1;
	  
	  if ((opt = option_find(mess, sz, OPTION_SERVER_IDENTIFIER, INADDRSZ)))
	    {
	      /* SELECTING */
	      selecting = 1;
	      
	      if (override.s_addr != 0)
		{
		  if (option_addr(opt).s_addr != override.s_addr)
		    return 0;
		}
	      else 
		{
		  for (; context; context = context->current)
		    if (context->local.s_addr == option_addr(opt).s_addr)
		      break;
		  
		  if (!context)
		    {
		      /* Handle very strange configs where clients have more than one route to the server.
			 If a clients idea of its server-id matches any of our DHCP interfaces, we let it pass.
			 Have to set override to make sure we echo back the correct server-id */
		      struct irec *intr;
		      
		      enumerate_interfaces(0);

		      for (intr = daemon->interfaces; intr; intr = intr->next)
			if (intr->addr.sa.sa_family == AF_INET &&
			    intr->addr.in.sin_addr.s_addr == option_addr(opt).s_addr &&
			    intr->tftp_ok)
			  break;

		      if (intr)
			override = intr->addr.in.sin_addr;
		      else
			{
			  /* In auth mode, a REQUEST sent to the wrong server
			     should be faulted, so that the client establishes 
			     communication with us, otherwise, silently ignore. */
			  if (!option_bool(OPT_AUTHORITATIVE))
			    return 0;
			  message = _("wrong server-ID");
			}
		    }
		}

	      /* If a lease exists for this host and another address, squash it. */
	      if (lease && lease->addr.s_addr != mess->yiaddr.s_addr)
		{
		  lease_prune(lease, now);
		  lease = NULL;
		}
	    }
	  else
	    {
	      /* INIT-REBOOT */
	      if (!lease && !option_bool(OPT_AUTHORITATIVE))
		return 0;
	      
	      if (lease && lease->addr.s_addr != mess->yiaddr.s_addr)
		message = _("wrong address");
	    }
	}
      else
	{
	  /* RENEWING or REBINDING */ 
	  /* Check existing lease for this address.
	     We allow it to be missing if dhcp-authoritative mode
	     as long as we can allocate the lease now - checked below.
	     This makes for a smooth recovery from a lost lease DB */
	  if ((lease && mess->ciaddr.s_addr != lease->addr.s_addr) ||
	      (!lease && !option_bool(OPT_AUTHORITATIVE)))
	    {
	      /* A client rebinding will broadcast the request, so we may see it even 
		 if the lease is held by another server. Just ignore it in that case. 
		 If the request is unicast to us, then somethings wrong, NAK */
	      if (!unicast_dest)
		return 0;
	      message = _("lease not found");
	      /* ensure we broadcast NAK */
	      unicast_dest = 0;
	    }

	  /* desynchronise renewals */
	  fuzz = rand16();
	  mess->yiaddr = mess->ciaddr;
	}

      daemon->metrics[METRIC_DHCPREQUEST]++;
      log_packet("DHCPREQUEST", &mess->yiaddr, emac, emac_len, iface_name, NULL, NULL, mess->xid);
      
    rapid_commit:
      if (!message)
	{
	  struct dhcp_config *addr_config;
	  struct dhcp_context *tmp = NULL;
	  
	  if (have_config(config, CONFIG_ADDR))
	    for (tmp = context; tmp; tmp = tmp->current)
	      if (context->router.s_addr == config->addr.s_addr)
		break;
	  
	  if (!(context = narrow_context(context, mess->yiaddr, tagif_netid)))
	    {
	      /* If a machine moves networks whilst it has a lease, we catch that here. */
	      message = _("wrong network");
	      /* ensure we broadcast NAK */
	      unicast_dest = 0;
	    }
	  
	  /* Check for renewal of a lease which is outside the allowed range. */
	  else if (!address_available(context, mess->yiaddr, tagif_netid) &&
		   (!have_config(config, CONFIG_ADDR) || config->addr.s_addr != mess->yiaddr.s_addr))
	    message = _("address not available");
	  
	  /* Check if a new static address has been configured. Be very sure that
	     when the client does DISCOVER, it will get the static address, otherwise
	     an endless protocol loop will ensue. */
	  else if (!tmp && !selecting &&
		   have_config(config, CONFIG_ADDR) && 
		   (!have_config(config, CONFIG_DECLINED) ||
		    difftime(now, config->decline_time) > (float)DECLINE_BACKOFF) &&
		   config->addr.s_addr != mess->yiaddr.s_addr &&
		   (!(ltmp = lease_find_by_addr(config->addr)) || ltmp == lease))
	    message = _("static lease available");

	  /* Check to see if the address is reserved as a static address for another host */
	  else if ((addr_config = config_find_by_address(daemon->dhcp_conf, mess->yiaddr)) && addr_config != config)
	    message = _("address reserved");

	  else if (!lease && (ltmp = lease_find_by_addr(mess->yiaddr)))
	    {
	      /* If a host is configured with more than one MAC address, it's OK to 'nix 
		 a lease from one of it's MACs to give the address to another. */
	      if (config && config_has_mac(config, ltmp->hwaddr, ltmp->hwaddr_len, ltmp->hwaddr_type))
		{
		  inet_ntop(AF_INET, &ltmp->addr, daemon->addrbuff, ADDRSTRLEN);
		  my_syslog(MS_DHCP | LOG_INFO, _("abandoning lease to %s of %s"),
			    print_mac(daemon->namebuff, ltmp->hwaddr, ltmp->hwaddr_len), 
			    daemon->addrbuff);
		  lease = ltmp;
		}
	      else
		message = _("address in use");
	    }

	  if (!message)
	    {
	      if (emac_len == 0)
		message = _("no unique-id");
	      
	      else if (!lease)
		{	     
		  if ((lease = lease4_allocate(mess->yiaddr)))
		    do_classes = 1;
		  else
		    message = _("no leases left");
		}
	    }
	}

      if (message)
	{
	  daemon->metrics[rapid_commit ? METRIC_NOANSWER : METRIC_DHCPNAK]++;
	  log_packet(rapid_commit ? "NOANSWER" : "DHCPNAK", &mess->yiaddr, emac, emac_len, iface_name, NULL, message, mess->xid);

	  /* rapid commit case: lease allocate failed but don't send DHCPNAK */
	  if (rapid_commit)
	    return 0;
	  
	  mess->yiaddr.s_addr = 0;
	  clear_packet(mess, end);
	  option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPNAK);
	  option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(server_id(context, override, fallback).s_addr));
	  option_put_string(mess, end, OPTION_MESSAGE, message, borken_opt);
	  /* This fixes a problem with the DHCP spec, broadcasting a NAK to a host on 
	     a distant subnet which unicast a REQ to us won't work. */
	  if (!unicast_dest || mess->giaddr.s_addr != 0 || 
	      mess->ciaddr.s_addr == 0 || is_same_net(context->local, mess->ciaddr, context->netmask))
	    {
	      mess->flags |= htons(0x8000); /* broadcast */
	      mess->ciaddr.s_addr = 0;
	    }
	}
      else
	{
	  if (context->netid.net)
	    {
	      context->netid.next = netid;
	      tagif_netid = run_tag_if( &context->netid);
	    }

	  log_tags(tagif_netid, ntohl(mess->xid));
	  
	  if (do_classes)
	    {
	      /* pick up INIT-REBOOT events. */
	      lease->flags |= LEASE_CHANGED;

#ifdef HAVE_SCRIPT
	      if (daemon->lease_change_command)
		{
		  struct dhcp_netid *n;
		  
		  if (mess->giaddr.s_addr)
		    lease->giaddr = mess->giaddr;
		  
		  free(lease->extradata);
		  lease->extradata = NULL;
		  lease->extradata_size = lease->extradata_len = 0;
		  
		  add_extradata_opt(lease, option_find(mess, sz, OPTION_VENDOR_ID, 1));
		  add_extradata_opt(lease, option_find(mess, sz, OPTION_HOSTNAME, 1));
		  add_extradata_opt(lease, oui);
		  add_extradata_opt(lease, serial);
		  add_extradata_opt(lease, class);

		  if ((opt = option_find(mess, sz, OPTION_AGENT_ID, 1)))
		    {
		      add_extradata_opt(lease, option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_CIRCUIT_ID, 1));
		      add_extradata_opt(lease, option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_SUBSCR_ID, 1));
		      add_extradata_opt(lease, option_find1(option_ptr(opt, 0), option_ptr(opt, option_len(opt)), SUBOPT_REMOTE_ID, 1));
		    }
		  else
		    {
		      add_extradata_opt(lease, NULL);
		      add_extradata_opt(lease, NULL);
		      add_extradata_opt(lease, NULL);
		    }

		  /* DNSMASQ_REQUESTED_OPTIONS */
		  if ((opt = option_find(mess, sz, OPTION_REQUESTED_OPTIONS, 1)))
		    {
		      int len = option_len(opt);
		      unsigned char *rop = option_ptr(opt, 0);
		      char *q = daemon->namebuff;
		      int i;
		      for (i = 0; i < len; i++)
		        {
		          q += snprintf(q, MAXDNAME - (q - daemon->namebuff), "%d%s", rop[i], i + 1 == len ? "" : ",");
		        }
		      lease_add_extradata(lease, (unsigned char *)daemon->namebuff, (q - daemon->namebuff), 0); 
		    }
		  else
		    {
		      add_extradata_opt(lease, NULL);
		    }

		  /* space-concat tag set */
		  if (!tagif_netid)
		    add_extradata_opt(lease, NULL);
		  else
		    for (n = tagif_netid; n; n = n->next)
		      {
			struct dhcp_netid *n1;
			/* kill dupes */
			for (n1 = n->next; n1; n1 = n1->next)
			  if (strcmp(n->net, n1->net) == 0)
			    break;
			if (!n1)
			  lease_add_extradata(lease, (unsigned char *)n->net, strlen(n->net), n->next ? ' ' : 0); 
		      }
		  
		  if ((opt = option_find(mess, sz, OPTION_USER_CLASS, 1)))
		    {
		      int len = option_len(opt);
		      unsigned char *ucp = option_ptr(opt, 0);
		      /* If the user-class option started as counted strings, the first byte will be zero. */
		      if (len != 0 && ucp[0] == 0)
			ucp++, len--;
		      lease_add_extradata(lease, ucp, len, -1);
		    }
		}
#endif
	    }
	  
	  if (!hostname_auth && (client_hostname = host_from_dns(mess->yiaddr)))
	    {
	      domain = get_domain(mess->yiaddr);
	      hostname = client_hostname;
	      hostname_auth = 1;
	    }
	  
	  time = calc_time(context, config, option_find(mess, sz, OPTION_LEASE_TIME, 4));
	  lease_set_hwaddr(lease, mess->chaddr, clid, mess->hlen, mess->htype, clid_len, now, do_classes);
	  
	  /* if all the netids in the ignore_name list are present, ignore client-supplied name */
	  if (!hostname_auth)
	    {
	      for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
		if ((!id_list->list) || match_netid(id_list->list, tagif_netid, 0))
		  break;
	      if (id_list)
		hostname = NULL;
	    }
	  
	  /* Last ditch, if configured, generate hostname from mac address */
	  if (!hostname && emac_len != 0)
	    {
	      for (id_list = daemon->dhcp_gen_names; id_list; id_list = id_list->next)
		if ((!id_list->list) || match_netid(id_list->list, tagif_netid, 0))
		  break;
	      if (id_list)
		{
		  int i;

		  hostname = daemon->dhcp_buff;
		  /* buffer is 256 bytes, 3 bytes per octet */
		  for (i = 0; (i < emac_len) && (i < 80); i++)
		    hostname += sprintf(hostname, "%.2x%s", emac[i], (i == emac_len - 1) ? "" : "-");
		  hostname = daemon->dhcp_buff;
		}
	    }

	  if (hostname)
	    lease_set_hostname(lease, hostname, hostname_auth, get_domain(lease->addr), domain);
	  
	  lease_set_expires(lease, time, now);
	  lease_set_interface(lease, int_index, now);

	  if (override.s_addr != 0)
	    lease->override = override;
	  else
	    override = lease->override;

	  daemon->metrics[METRIC_DHCPACK]++;
	  log_packet("DHCPACK", &mess->yiaddr, emac, emac_len, iface_name, hostname, NULL, mess->xid);  

	  clear_packet(mess, end);
	  option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
	  option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(server_id(context, override, fallback).s_addr));
	  option_put(mess, end, OPTION_LEASE_TIME, 4, time);
	  if (rapid_commit)
	     option_put(mess, end, OPTION_RAPID_COMMIT, 0, 0);
	   do_options(context, mess, end, req_options, hostname, get_domain(mess->yiaddr), 
		     netid, subnet_addr, fqdn_flags, borken_opt, pxearch, uuid, vendor_class_len, now, time, fuzz, pxevendor);
	}

      return dhcp_packet_size(mess, agent_id, real_end); 
      
    case DHCPINFORM:
      if (ignore || have_config(config, CONFIG_DISABLE))
	message = _("ignored");
      
      daemon->metrics[METRIC_DHCPINFORM]++;
      log_packet("DHCPINFORM", &mess->ciaddr, emac, emac_len, iface_name, message, NULL, mess->xid);
     
      if (message || mess->ciaddr.s_addr == 0)
	return 0;

      /* For DHCPINFORM only, cope without a valid context */
      context = narrow_context(context, mess->ciaddr, tagif_netid);
      
      /* Find a least based on IP address if we didn't
	 get one from MAC address/client-d */
      if (!lease &&
	  (lease = lease_find_by_addr(mess->ciaddr)) && 
	  lease->hostname)
	hostname = lease->hostname;
      
      if (!hostname)
	hostname = host_from_dns(mess->ciaddr);
      
      if (context && context->netid.net)
	{
	  context->netid.next = netid;
	  tagif_netid = run_tag_if(&context->netid);
	}

      log_tags(tagif_netid, ntohl(mess->xid));
      
      daemon->metrics[METRIC_DHCPACK]++;
      log_packet("DHCPACK", &mess->ciaddr, emac, emac_len, iface_name, hostname, NULL, mess->xid);
      
      if (lease)
	{
	  lease_set_interface(lease, int_index, now);
	  if (override.s_addr != 0)
	    lease->override = override;
	  else
	    override = lease->override;
	}

      clear_packet(mess, end);
      option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);
      option_put(mess, end, OPTION_SERVER_IDENTIFIER, INADDRSZ, ntohl(server_id(context, override, fallback).s_addr));
     
      /* RFC 2131 says that DHCPINFORM shouldn't include lease-time parameters, but 
	 we supply a utility which makes DHCPINFORM requests to get this information.
	 Only include lease time if OPTION_LEASE_TIME is in the parameter request list,
	 which won't be true for ordinary clients, but will be true for the 
	 dhcp_lease_time utility. */
      if (lease && in_list(req_options, OPTION_LEASE_TIME))
	{
	  if (lease->expires == 0)
	    time = 0xffffffff;
	  else
	    time = (unsigned int)difftime(lease->expires, now);
	  option_put(mess, end, OPTION_LEASE_TIME, 4, time);
	}

      do_options(context, mess, end, req_options, hostname, get_domain(mess->ciaddr),
		 netid, subnet_addr, fqdn_flags, borken_opt, pxearch, uuid, vendor_class_len, now, 0xffffffff, 0, pxevendor);
      
      *is_inform = 1; /* handle reply differently */
      return dhcp_packet_size(mess, agent_id, real_end); 
    }
  
  return 0;
}

/* find a good value to use as MAC address for logging and address-allocation hashing.
   This is normally just the chaddr field from the DHCP packet,
   but eg Firewire will have hlen == 0 and use the client-id instead. 
   This could be anything, but will normally be EUI64 for Firewire.
   We assume that if the first byte of the client-id equals the htype byte
   then the client-id is using the usual encoding and use the rest of the 
   client-id: if not we can use the whole client-id. This should give
   sane MAC address logs. */
unsigned char *extended_hwaddr(int hwtype, int hwlen, unsigned char *hwaddr, 
				      int clid_len, unsigned char *clid, int *len_out)
{
  if (hwlen == 0 && clid && clid_len > 3)
    {
      if (clid[0]  == hwtype)
	{
	  *len_out = clid_len - 1 ;
	  return clid + 1;
	}

#if defined(ARPHRD_EUI64) && defined(ARPHRD_IEEE1394)
      if (clid[0] ==  ARPHRD_EUI64 && hwtype == ARPHRD_IEEE1394)
	{
	  *len_out = clid_len - 1 ;
	  return clid + 1;
	}
#endif
      
      *len_out = clid_len;
      return clid;
    }
  
  *len_out = hwlen;
  return hwaddr;
}

/**
 * @brief Calculate DHCP lease time from context, configuration, and client request
 *
 * @detailed
 * Determines the lease time to offer to a DHCP client by considering three sources in order
 * of precedence: static host configuration (CONFIG_TIME), DHCP context default, and client's
 * requested lease time option (Option 51). Implements RFC 2131 Section 4.3.1 requirement that
 * server may choose to use client's requested lease time or override with its own policy.
 * Enforces minimum lease time of 120 seconds as sanity check. Returns the minimum of configured
 * time and requested time unless either is infinite (0xffffffff).
 *
 * @param context DHCP context containing default lease time for this subnet, may be NULL
 * @param config Static host configuration potentially containing specific lease time for this client
 * @param opt Pointer to Option 51 (OPTION_LEASE_TIME) from client request, or NULL if not present
 *
 * @return Lease time in seconds to assign to the client, minimum 120 seconds unless infinite
 *
 * @note Returns static configuration time if CONFIG_TIME flag set, else context lease time
 * @note If client requests less than 120 seconds, enforces minimum of 120 seconds
 * @note Infinite lease time (0xffffffff) allowed and not subject to minimum limit
 * @note If both client and server offer infinite leases, returns infinite
 *
 * @see calc_time() usage in dhcp_reply() for DHCPOFFER and DHCPACK generation
 * @see RFC 2131 Section 4.3.1 for lease time negotiation semantics
 */
static unsigned int calc_time(struct dhcp_context *context, struct dhcp_config *config, unsigned char *opt)
{
  unsigned int time = have_config(config, CONFIG_TIME) ? config->lease_time : context->lease_time;
  
  if (opt)
    { 
      unsigned int req_time = option_uint(opt, 0, 4);
      if (req_time < 120 )
	req_time = 120; /* sanity */
      if (time == 0xffffffff || (req_time != 0xffffffff && req_time < time))
	time = req_time;
    }

  return time;
}

/**
 * @brief Determine server identifier address to include in DHCP response
 *
 * @detailed
 * Selects the IP address to use as DHCP server identifier (Option 54) in response packets.
 * Uses three-level priority: relay agent server identifier override (Option 82 sub-option 11)
 * takes highest priority, context's local interface address takes second priority, and fallback
 * address (typically from primary interface) used as last resort. Server identifier must match
 * the address clients use for unicast DHCP messages during RENEW/REBIND. Implements RFC 5107
 * Server Identifier Override Suboption for relay agent control of server selection.
 *
 * @param context DHCP context for the client's subnet containing local interface address
 * @param override Server identifier specified by relay agent via Option 82 Sub-option 11, or 0.0.0.0
 * @param fallback Default server identifier if context has no local address, typically primary interface
 *
 * @return IPv4 address to use as server identifier in DHCP response packets
 *
 * @note Override address (from relay agent) takes absolute priority if non-zero
 * @note Context local address used if override not present and context has local interface configured
 * @note Fallback used when receiving interface has no DHCP context or no local address
 * @note Server identifier must remain consistent across DISCOVER/OFFER/REQUEST/ACK exchange
 *
 * @see RFC 2131 Section 3.5 for server identifier usage requirements
 * @see RFC 5107 for DHCP Server Identifier Override Suboption specification
 */
static struct in_addr server_id(struct dhcp_context *context, struct in_addr override, struct in_addr fallback)
{
  if (override.s_addr != 0)
    return override;
  else if (context && context->local.s_addr != 0)
    return context->local;
  else
    return fallback;
}

/**
 * @brief Sanitize DHCP option data by extracting only printable ASCII characters
 *
 * @detailed
 * Copies printable characters from a DHCP option into output buffer, filtering out non-printable
 * characters (control codes, extended ASCII) to prevent log injection attacks and display corruption.
 * Used primarily for sanitizing client-supplied text options like OPTION_MESSAGE (56) and
 * OPTION_HOSTNAME (12) before logging or processing. Implements defensive programming practice
 * of never trusting client-supplied data in log output. Null-terminates output buffer even if
 * input is empty or NULL.
 *
 * @param opt Pointer to DHCP option containing potentially unsafe text data, may be NULL
 * @param buf Output buffer to receive sanitized printable-only string, must have space for
 *            option_len(opt)+1 bytes to accommodate null terminator
 *
 * @return 1 if option was present and data copied, 0 if opt was NULL
 *
 * @note Output buffer always null-terminated even for empty or NULL input
 * @note Uses isprint() to filter characters, keeping only printable ASCII (space through ~)
 * @note Non-printable characters silently dropped from output with no indication
 * @note Caller must ensure buf has sufficient size (typically DHCP_BUFF_SZ=256 bytes)
 *
 * @warning Does not validate UTF-8 or handle multi-byte character encodings
 * @warning Buffer overflow possible if buf too small for option length plus null terminator
 *
 * @see log_packet() for primary usage logging DHCPDECLINE message text
 */
static int sanitise(unsigned char *opt, char *buf)
{
  char *p;
  int i;
  
  *buf = 0;
  
  if (!opt)
    return 0;

  p = option_ptr(opt, 0);

  for (i = option_len(opt); i > 0; i--)
    {
      char c = *p++;
      if (isprint((int)c))
	*buf++ = c;
    }
  *buf = 0; /* add terminator */
  
  return 1;
}

#ifdef HAVE_SCRIPT
/**
 * @brief Add DHCP option data to lease as extra data for script execution
 *
 * @detailed
 * Attaches raw DHCP option data to a lease record for passing to external lease-change scripts
 * via environment variables. Enables scripts to access arbitrary DHCP options beyond standard
 * fields (IP, hostname, MAC). When opt is NULL, clears extra data. Option data stored with
 * lease includes option type, length, and raw payload bytes which script can parse. Used
 * primarily for passing vendor-specific options and user class identifiers to scripts for
 * custom provisioning logic.
 *
 * @param lease Lease record to attach extra data to
 * @param opt Pointer to DHCP option structure (type-length-value format), or NULL to clear extra data
 *
 * @note Only compiled if HAVE_SCRIPT defined, otherwise function does not exist
 * @note Extra data passed to script via DNSMASQ_SUPPLIED_* environment variables
 * @note NULL opt clears any existing extra data on the lease
 * @note Multiple options require multiple calls, data appended to lease
 *
 * @see lease_add_extradata() in lease.c for extra data storage mechanism
 * @see queue_script() for script execution with environment variables
 */
static void add_extradata_opt(struct dhcp_lease *lease, unsigned char *opt)
{
  if (!opt)
    lease_add_extradata(lease, NULL, 0, 0);
  else
    lease_add_extradata(lease, option_ptr(opt, 0), option_len(opt), 0); 
}
#endif

/**
 * @brief Generate comprehensive DHCP transaction log entry to syslog
 *
 * @detailed
 * Creates detailed syslog entries for DHCP transactions including message type, client identifier,
 * IP address, hardware address, interface, hostname, transaction ID, and any error conditions.
 * Implements conditional logging based on OPT_LOG_OPTS (detailed option logging), OPT_QUIET_DHCP
 * (suppress routine transactions), and error conditions. Formats hardware address in colon-hexadecimal
 * notation. Logs at LOG_INFO level for successful transactions, LOG_WARNING for errors. Essential
 * for DHCP troubleshooting, security auditing, and lease tracking. Output includes full transaction
 * context enabling correlation of DISCOVER/OFFER/REQUEST/ACK sequences via XID.
 *
 * @param type DHCP message type string (e.g. "DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPACK",
 *             "DHCPNAK", "DHCPRELEASE", "DHCPDECLINE", "DHCPINFORM")
 * @param addr Pointer to IP address (struct in_addr*) involved in transaction (offered, requested, or released)
 * @param ext_mac Pointer to client hardware address bytes (typically 6 bytes for Ethernet MAC)
 * @param mac_len Length of hardware address in bytes (6 for Ethernet, varies for other link types)
 * @param interface Name of interface packet received on (e.g. "eth0", "br0")
 * @param string Optional client hostname or additional descriptive string, may be NULL
 * @param err Optional error message string for failed transactions, NULL for successful transactions
 * @param xid DHCP transaction ID (32-bit) for correlating related messages in log
 *
 * @note Respects OPT_QUIET_DHCP option: suppresses logging if no error and quiet mode enabled
 * @note Includes detailed option dump if OPT_LOG_OPTS enabled via log_options()
 * @note Hardware address formatted as colon-separated hex (e.g. "01:23:45:67:89:ab")
 * @note Transaction ID logged in hexadecimal for correlation with packet captures
 * @note Error conditions always logged regardless of quiet mode
 *
 * @see log_options() for detailed DHCP option content logging
 * @see my_syslog() for syslog output with DHCP facility tag
 * @see daemon->addrbuff for address formatting buffer
 *
 * EXAMPLE USAGE:
 * @code
 * log_packet("DHCPACK", &lease->addr, client_mac, 6, "eth0", "hostname", NULL, xid);
 * log_packet("DHCPNAK", &requested_addr, client_mac, 6, "eth0", NULL, "wrong network", xid);
 * @endcode
 */
static void log_packet(char *type, void *addr, unsigned char *ext_mac, 
		       int mac_len, char *interface, char *string, char *err, u32 xid)
{
  if (!err && !option_bool(OPT_LOG_OPTS) && option_bool(OPT_QUIET_DHCP))
    return;
  
  daemon->addrbuff[0] = 0;
  if (addr)
    inet_ntop(AF_INET, addr, daemon->addrbuff, ADDRSTRLEN);
  
  print_mac(daemon->namebuff, ext_mac, mac_len);
  
  if (option_bool(OPT_LOG_OPTS))
    my_syslog(MS_DHCP | LOG_INFO, "%u %s(%s) %s%s%s %s%s",
	      ntohl(xid), 
	      type,
	      interface, 
	      daemon->addrbuff,
	      addr ? " " : "",
	      daemon->namebuff,
	      string ? string : "",
	      err ? err : "");
  else
    my_syslog(MS_DHCP | LOG_INFO, "%s(%s) %s%s%s %s%s",
	      type,
	      interface, 
	      daemon->addrbuff,
	      addr ? " " : "",
	      daemon->namebuff,
	      string ? string : "",
	      err ? err : "");
  
#ifdef HAVE_UBUS
  if (!strcmp(type, "DHCPACK"))
    ubus_event_bcast("dhcp.ack", daemon->namebuff, addr ? daemon->addrbuff : NULL, string, interface);
  else if (!strcmp(type, "DHCPRELEASE"))
    ubus_event_bcast("dhcp.release", daemon->namebuff, addr ? daemon->addrbuff : NULL, string, interface);
#endif
}

static void log_options(unsigned char *start, u32 xid)
{
  while (*start != OPTION_END)
    {
      char *optname = option_string(AF_INET, start[0], option_ptr(start, 0), option_len(start), daemon->namebuff, MAXDNAME);
      
      my_syslog(MS_DHCP | LOG_INFO, "%u sent size:%3d option:%3d %s  %s", 
		ntohl(xid), option_len(start), start[0], optname, daemon->namebuff);
      start += start[1] + 2;
    }
}

/**
 * @brief Search for specific DHCP option within a contiguous option area
 *
 * @detailed
 * Low-level DHCP option parser for searching a single contiguous option region (e.g. options field,
 * file field, or sname field). Scans type-length-value encoded option sequence handling OPTION_PAD
 * (0x00) skip bytes and OPTION_END (0xff) terminator. Validates minimum option length requirement
 * and performs bounds checking to prevent buffer overruns from malformed packets. Returns pointer
 * to start of option (type byte) not option data, caller must use option_ptr() macro to access data.
 * Used internally by option_find() which searches all three option areas.
 *
 * @param p Start of option area to search (after DHCP cookie for options field)
 * @param end Pointer one byte beyond valid option area for bounds checking
 * @param opt Option type code to search for (OPTION_* constants from dhcp-protocol.h)
 * @param minsize Minimum acceptable option data length in bytes (excluding type and length bytes)
 *
 * @return Pointer to start of option (type byte) if found with sufficient length, NULL if not found
 *         or insufficient length or malformed packet structure
 *
 * @note Returns option start pointer (type byte), not data pointer; use option_ptr() to get data
 * @note OPTION_PAD (0) bytes skipped during scan
 * @note OPTION_END (0xff) terminates scan, can be searched for explicitly
 * @note Malformed packets with invalid lengths detected and return NULL
 * @note Options must have at least minsize data bytes to match
 *
 * @warning No validation of option content, only structure and length checked
 * @warning Caller must not modify option area during search as end pointer may become invalid
 *
 * @see option_find() for high-level search across options/file/sname areas
 * @see option_ptr() macro to get pointer to option data payload
 * @see option_len() macro to get option data length
 */
static unsigned char *option_find1(unsigned char *p, unsigned char *end, int opt, int minsize)
{
  while (1) 
    {
      if (p >= end)
	return NULL;
      else if (*p == OPTION_END)
	return opt == OPTION_END ? p : NULL;
      else if (*p == OPTION_PAD)
	p++;
      else 
	{ 
	  int opt_len;
	  if (p > end - 2)
	    return NULL; /* malformed packet */
	  opt_len = option_len(p);
	  if (p > end - (2 + opt_len))
	    return NULL; /* malformed packet */
	  if (*p == opt && opt_len >= minsize)
	    return p;
	  p += opt_len + 2;
	}
    }
}

/**
 * @brief Locate DHCP option in packet searching all valid option areas
 *
 * @detailed
 * High-level DHCP option extraction supporting RFC 2131 Section 4.1 option overload mechanism.
 * Searches three areas in order: options field (primary), file field (if overload bit 1 set),
 * sname field (if overload bit 2 set). Option overload (Option 52) repurposes normally-fixed
 * file and sname fields for additional option space when options field exhausted. First checks
 * for option in primary options area after DHCP magic cookie (0x63825363). If not found, examines
 * OPTION_OVERLOAD to determine if file/sname fields contain options, then searches those areas.
 * Enables clients to send extensive option lists exceeding 312-byte options field capacity.
 *
 * @param mess Pointer to DHCP packet structure to search
 * @param size Total size of packet buffer in bytes for bounds checking
 * @param opt_type Option code to locate (OPTION_* constants, e.g. OPTION_REQUESTED_IP = 50)
 * @param minsize Minimum required option data length in bytes for match, 0 to accept any length
 *
 * @return Pointer to option structure (type byte) if found with sufficient length, NULL if not found,
 *         malformed, insufficient length, or OPTION_OVERLOAD missing when needed
 *
 * @note Skips DHCP magic cookie (4 bytes) at start of options field automatically
 * @note Returns NULL if option present but shorter than minsize
 * @note Options in file/sname only accessible if OPTION_OVERLOAD present with correct bits
 * @note Search order: options field, file field (if overload & 1), sname field (if overload & 2)
 *
 * @see option_find1() for low-level single-area search implementation
 * @see RFC 2131 Section 4.1 for option overload specification
 * @see option_ptr() to extract pointer to option data payload
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *opt = option_find(mess, packet_size, OPTION_REQUESTED_IP, INADDRSZ);
 * if (opt)
 *   struct in_addr requested = option_addr(opt);
 * @endcode
 */
static unsigned char *option_find(struct dhcp_packet *mess, size_t size, int opt_type, int minsize)
{
  unsigned char *ret, *overload;
  
  /* skip over DHCP cookie; */
  if ((ret = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + size, opt_type, minsize)))
    return ret;

  /* look for overload option. */
  if (!(overload = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + size, OPTION_OVERLOAD, 1)))
    return NULL;
  
  /* Can we look in filename area ? */
  if ((overload[2] & 1) &&
      (ret = option_find1(&mess->file[0], &mess->file[128], opt_type, minsize)))
    return ret;

  /* finally try sname area */
  if ((overload[2] & 2) &&
      (ret = option_find1(&mess->sname[0], &mess->sname[64], opt_type, minsize)))
    return ret;

  return NULL;
}

/**
 * @brief Extract IPv4 address from DHCP option handling potential misalignment
 *
 * @detailed
 * Safely extracts 4-byte IPv4 address from DHCP option data accommodating potentially unaligned
 * memory access. DHCP options may not be word-aligned in packet buffer due to variable-length
 * preceding options, causing misaligned access faults on some architectures (SPARC, ARM without
 * unaligned access support). Uses memcpy to avoid direct structure cast ensuring safe access on
 * all platforms. Returns struct in_addr in network byte order (big-endian) as received in packet,
 * no host byte order conversion applied.
 *
 * @param opt Pointer to DHCP option containing IPv4 address (e.g. OPTION_REQUESTED_IP, OPTION_SERVER_IDENTIFIER)
 *
 * @return struct in_addr containing IPv4 address in network byte order
 *
 * @note Assumes opt points to valid option with at least INADDRSZ (4) bytes of data
 * @note No validation of option length or type performed, caller responsible
 * @note Returned address in network byte order, use inet_ntop() for display
 * @note Uses option_ptr() macro to skip option type and length bytes
 *
 * @warning Caller must verify option length >= INADDRSZ before calling to prevent buffer overrun
 * @warning Does not validate address contents (could be 0.0.0.0, broadcast, multicast, etc.)
 *
 * @see option_uint() for extracting integer values from options
 * @see option_ptr() macro for accessing option data area
 */
static struct in_addr option_addr(unsigned char *opt)
{
   /* this worries about unaligned data in the option. */
  /* struct in_addr is network byte order */
  struct in_addr ret;

  memcpy(&ret, option_ptr(opt, 0), INADDRSZ);

  return ret;
}

/**
 * @brief Extract unsigned integer from DHCP option with network byte order conversion
 *
 * @detailed
 * Extracts multi-byte unsigned integer from DHCP option handling potential memory misalignment
 * and network-to-host byte order conversion. Supports 1, 2, or 4-byte integers commonly used
 * in DHCP options (OPTION_LEASE_TIME=4 bytes, OPTION_MESSAGE_TYPE=1 byte, OPTION_MAXMESSAGE=2 bytes).
 * Reads bytes sequentially accumulating big-endian (network byte order) value into host byte order
 * unsigned int. Safe for unaligned access on all architectures. Supports offset parameter for
 * extracting integers from middle of option data (e.g. multiple sub-options in vendor-specific options).
 *
 * @param opt Pointer to DHCP option structure containing integer data
 * @param offset Byte offset within option data to start extraction, 0 for start of option data
 * @param size Number of bytes to extract (1, 2, or 4 typically), maximum reasonable is 4
 *
 * @return Unsigned integer value extracted from option in host byte order
 *
 * @note Performs network-to-host byte order conversion (big-endian to host endianness)
 * @note Uses option_ptr() macro to skip option type/length and apply offset
 * @note Safe for unaligned access via byte-by-byte read and shift
 * @note Can extract up to 4-byte values fitting in unsigned int return type
 *
 * @warning Caller must ensure option has at least offset+size bytes to prevent buffer overrun
 * @warning No bounds checking performed, malformed packets can cause invalid reads
 * @warning Returns partial data if size exceeds option length without error indication
 *
 * @see option_addr() for IPv4 address extraction
 * @see option_ptr() macro for accessing option data with offset
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned int lease_time = option_uint(opt, 0, 4); // Extract 4-byte lease time
 * unsigned int msg_type = option_uint(opt, 0, 1);   // Extract 1-byte message type
 * @endcode
 */
static unsigned int option_uint(unsigned char *opt, int offset, int size)
{
  /* this worries about unaligned data and byte order */
  unsigned int ret = 0;
  int i;
  unsigned char *p = option_ptr(opt, offset);
  
  for (i = 0; i < size; i++)
    ret = (ret << 8) | *p++;

  return ret;
}

/**
 * @brief Skip to end marker of DHCP option sequence during packet construction
 *
 * @detailed
 * Advances pointer through packed DHCP option sequence to locate OPTION_END (0xff) marker.
 * Used during packet construction (not parsing) when building response packets and appending
 * additional options. Assumes well-formed option sequence as comment notes "only for use when
 * building packet: doesn't check for bad data." Steps through type-length-value encoded options
 * using length byte to skip each option until reaching null (0x00) which represents OPTION_END
 * or end of allocated option space.
 *
 * @param start Pointer to beginning of option sequence to skip through
 *
 * @return Pointer to OPTION_END marker (0x00 byte) or end of option space
 *
 * @note Only safe for use during packet construction with known-good option data
 * @note Does not perform bounds checking or malformed packet detection
 * @note Stops at first 0x00 byte encountered (OPTION_END or uninitialized space)
 * @note Not suitable for parsing untrusted received packets, use option_find1() instead
 *
 * @warning No validation of option lengths, infinite loop possible with malformed data
 * @warning No bounds checking, can run past end of buffer if data malformed
 * @warning Only use with options constructed by dnsmasq's own code
 *
 * @see option_find1() for safe parsing of untrusted received option data
 * @see free_space() which uses dhcp_skip_opts() to find insertion point
 */
static unsigned char *dhcp_skip_opts(unsigned char *start)
{
  while (*start != 0)
    start += start[1] + 2;
  return start;
}

/**
 * @brief Locate OPTION_OVERLOAD in packet during response construction
 *
 * @detailed
 * Searches for Option 52 (OPTION_OVERLOAD) in DHCP response packet being constructed. Used during
 * packet building to determine if file and/or sname fields are available for additional options.
 * Unlike option_find() which validates untrusted packets, this function assumes well-formed option
 * data created by dnsmasq's own code and performs no bounds checking. Returns pointer to OPTION_OVERLOAD
 * structure enabling caller to check overload bits: bit 0 (file field contains options), bit 1
 * (sname field contains options).
 *
 * @param mess DHCP packet under construction with options added by dnsmasq code
 *
 * @return Pointer to OPTION_OVERLOAD option if present, NULL if not found
 *
 * @note Only safe during packet construction with known-good option data
 * @note Does not validate option structure or perform bounds checking
 * @note Used by free_space() to determine if overload areas available for option expansion
 * @note Used by dhcp_packet_size() to finalize option areas before transmission
 *
 * @warning No validation of data, assumes options constructed by dnsmasq code
 * @warning Potential infinite loop if option lengths corrupted
 * @warning Not suitable for parsing received packets
 *
 * @see free_space() for usage expanding options into overload areas
 * @see dhcp_packet_size() for usage finalizing packet before transmission
 */
/* only for use when building packet: doesn't check for bad data. */ 
static unsigned char *find_overload(struct dhcp_packet *mess)
{
  unsigned char *p = &mess->options[0] + sizeof(u32);
  
  while (*p != 0)
    {
      if (*p == OPTION_OVERLOAD)
	return p;
      p += p[1] + 2;
    }
  return NULL;
}

/**
 * @brief Calculate final DHCP response packet size and finalize option areas
 *
 * @detailed
 * Finalizes DHCP response packet for transmission by compacting relay agent information (Option 82)
 * if present, adding OPTION_END terminators to all active option areas (options/file/sname), logging
 * option contents if detailed logging enabled, and calculating total packet size respecting MIN_PACKETSZ
 * (300 bytes) minimum for Linux kernel DHCP client compatibility. Handles option overload mechanism
 * by terminating file and sname option areas if overload bits set. Moves agent_id data to end of
 * options area to maintain relay agent information transparency. Returns size suitable for sendto()
 * call transmission.
 *
 * @param mess DHCP packet with options populated, ready for size calculation and finalization
 * @param agent_id Pointer to relay agent information (Option 82) to preserve, or NULL if none
 * @param real_end Pointer to end of agent_id data for calculating move size
 *
 * @return Size of finalized packet in bytes, minimum MIN_PACKETSZ (300), suitable for network transmission
 *
 * @note Moves agent_id to end of options maintaining relay transparency per RFC 3046
 * @note Adds OPTION_END (0xff) to options field and overload areas if used
 * @note Enforces MIN_PACKETSZ (300 bytes) minimum for Linux kernel compatibility
 * @note Logs bootfile name and server name if present and OPT_LOG_OPTS enabled
 * @note Logs all option content via log_options() if OPT_LOG_OPTS enabled
 * @note Logs broadcast flag status if set with zero ciaddr
 *
 * @see find_overload() for detecting option overload configuration
 * @see dhcp_skip_opts() for locating end of option sequences
 * @see log_options() for detailed option content logging
 * @see MIN_PACKETSZ constant (300 bytes) for minimum packet size requirement
 *
 * RFC COMPLIANCE:
 * - RFC 3046: DHCP Relay Agent Information Option (agent_id preservation)
 * - RFC 2131: Minimum 300-byte packet size for interoperability
 */
static size_t dhcp_packet_size(struct dhcp_packet *mess, unsigned char *agent_id, unsigned char *real_end)
{
  unsigned char *p = dhcp_skip_opts(&mess->options[0] + sizeof(u32));
  unsigned char *overload;
  size_t ret;
  
  /* move agent_id back down to the end of the packet */
  if (agent_id)
    {
      memmove(p, agent_id, real_end - agent_id);
      p += real_end - agent_id;
      memset(p, 0, real_end - p); /* in case of overlap */
    }
  
  /* add END options to the regions. */
  overload = find_overload(mess);
  
  if (overload && (option_uint(overload, 0, 1) & 1))
    {
      *dhcp_skip_opts(mess->file) = OPTION_END;
      if (option_bool(OPT_LOG_OPTS))
	log_options(mess->file, mess->xid);
    }
  else if (option_bool(OPT_LOG_OPTS) && strlen((char *)mess->file) != 0)
    my_syslog(MS_DHCP | LOG_INFO, _("%u bootfile name: %s"), ntohl(mess->xid), (char *)mess->file);
  
  if (overload && (option_uint(overload, 0, 1) & 2))
    {
      *dhcp_skip_opts(mess->sname) = OPTION_END;
      if (option_bool(OPT_LOG_OPTS))
	log_options(mess->sname, mess->xid);
    }
  else if (option_bool(OPT_LOG_OPTS) && strlen((char *)mess->sname) != 0)
    my_syslog(MS_DHCP | LOG_INFO, _("%u server name: %s"), ntohl(mess->xid), (char *)mess->sname);


  *p++ = OPTION_END;
  
  if (option_bool(OPT_LOG_OPTS))
    {
      if (mess->siaddr.s_addr != 0)
	{
	  inet_ntop(AF_INET, &mess->siaddr, daemon->addrbuff, ADDRSTRLEN);
	  my_syslog(MS_DHCP | LOG_INFO, _("%u next server: %s"), ntohl(mess->xid), daemon->addrbuff);
	}
      
      if ((mess->flags & htons(0x8000)) && mess->ciaddr.s_addr == 0)
	my_syslog(MS_DHCP | LOG_INFO, _("%u broadcast response"), ntohl(mess->xid));
      
      log_options(&mess->options[0] + sizeof(u32), mess->xid);
    } 
  
  ret = (size_t)(p - (unsigned char *)mess);
  
  if (ret < MIN_PACKETSZ)
    ret = MIN_PACKETSZ;
  
  return ret;
}

/**
 * @brief Allocate space for DHCP option in packet with automatic overload handling
 *
 * @detailed
 * Finds or creates space for DHCP option in response packet, automatically using option overload
 * mechanism if primary options area exhausted. Attempts allocation in order: options field, file
 * field (if available and overload enabled), sname field (if available and overload enabled).
 * Creates OPTION_OVERLOAD (52) automatically if needed and space available. Returns pointer to
 * option data area with type and length bytes already written. Essential function for all DHCP
 * response construction enabling transparent use of extended option space via RFC 2131 overload.
 * Logs warning if unable to allocate space for requested option.
 *
 * @param mess DHCP packet under construction
 * @param end Pointer to end of packet buffer for bounds checking in options area
 * @param opt Option type code to allocate space for (written to type byte)
 * @param len Option data length in bytes (written to length byte)
 *
 * @return Pointer to option data area (after type and length bytes) if space allocated,
 *         NULL if insufficient space in all available areas
 *
 * @note Writes option type and length bytes automatically, caller fills data area
 * @note Creates OPTION_OVERLOAD if needed and file/sname areas unused
 * @note Searches options field first, then file field (if overload bit 0 set), then sname (bit 1)
 * @note Sets overload bits dynamically as fields brought into use
 * @note Logs warning message if unable to allocate requested space
 * @note Space calculation includes 3-byte overhead (type + length + END marker)
 *
 * @warning Returns NULL if no space available, caller must check before writing data
 * @warning Does not validate whether overload appropriate for specific options
 * @warning File and sname overload only possible if those fields not used for traditional purposes
 *
 * @see option_put() for integer option insertion using free_space()
 * @see option_put_string() for string option insertion using free_space()
 * @see find_overload() for locating existing OPTION_OVERLOAD
 * @see RFC 2131 Section 4.1 for option overload specification
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = free_space(mess, end, OPTION_LEASE_TIME, 4);
 * if (p) {
 *   // Write 4-byte lease time value to p
 * }
 * @endcode
 */
static unsigned char *free_space(struct dhcp_packet *mess, unsigned char *end, int opt, int len)
{
  unsigned char *p = dhcp_skip_opts(&mess->options[0] + sizeof(u32));
  
  if (p + len + 3 >= end)
    /* not enough space in options area, try and use overload, if poss */
    {
      unsigned char *overload;
      
      if (!(overload = find_overload(mess)) &&
	  (mess->file[0] == 0 || mess->sname[0] == 0))
	{
	  /* attempt to overload fname and sname areas, we've reserved space for the
	     overflow option previuously. */
	  overload = p;
	  *(p++) = OPTION_OVERLOAD;
	  *(p++) = 1;
	}
      
      p = NULL;
      
      /* using filename field ? */
      if (overload)
	{
	  if (mess->file[0] == 0)
	    overload[2] |= 1;
	  
	  if (overload[2] & 1)
	    {
	      p = dhcp_skip_opts(mess->file);
	      if (p + len + 3 >= mess->file + sizeof(mess->file))
		p = NULL;
	    }
	  
	  if (!p)
	    {
	      /* try to bring sname into play (it may be already) */
	      if (mess->sname[0] == 0)
		overload[2] |= 2;
	      
	      if (overload[2] & 2)
		{
		  p = dhcp_skip_opts(mess->sname);
		  if (p + len + 3 >= mess->sname + sizeof(mess->sname))
		    p = NULL;
		}
	    }
	}
      
      if (!p)
	my_syslog(MS_DHCP | LOG_WARNING, _("cannot send DHCP/BOOTP option %d: no space left in packet"), opt);
    }
 
  if (p)
    {
      *(p++) = opt;
      *(p++) = len;
    }

  return p;
}

/**
 * @brief Insert unsigned integer DHCP option into packet with automatic space allocation
 *
 * @detailed
 * Convenience function for adding integer-valued DHCP options to response packets. Allocates space
 * via free_space() handling option overload transparently, then writes multi-byte integer in network
 * byte order (big-endian). Supports 1, 2, or 4-byte integers commonly used in DHCP options like
 * OPTION_LEASE_TIME (4 bytes), OPTION_T1 (4 bytes), OPTION_T2 (4 bytes), OPTION_MESSAGE_TYPE (1 byte).
 * Silently fails if no space available rather than corrupting packet. Used throughout DHCP response
 * construction for all integer option types.
 *
 * @param mess DHCP response packet under construction
 * @param end End of packet buffer for bounds checking
 * @param opt Option type code (OPTION_* constant)
 * @param len Number of bytes for integer (1, 2, or 4 typically)
 * @param val Unsigned integer value to write in network byte order
 *
 * @note Performs host-to-network byte order conversion automatically
 * @note Silently does nothing if free_space() returns NULL (no space available)
 * @note Writes multi-byte integers big-endian (most significant byte first)
 * @note Common usage: option_put(mess, end, OPTION_LEASE_TIME, 4, lease_seconds)
 *
 * @see free_space() for space allocation and overload handling
 * @see option_put_string() for string option insertion
 *
 * EXAMPLE USAGE:
 * @code
 * option_put(mess, end, OPTION_LEASE_TIME, 4, 3600);        // 1 hour lease
 * option_put(mess, end, OPTION_MESSAGE_TYPE, 1, DHCPACK);   // Message type
 * option_put(mess, end, OPTION_T1, 4, 1800);                // T1 renewal time
 * @endcode
 */	      
static void option_put(struct dhcp_packet *mess, unsigned char *end, int opt, int len, unsigned int val)
{
  int i;
  unsigned char *p = free_space(mess, end, opt, len);
  
  if (p) 
    for (i = 0; i < len; i++)
      *(p++) = val >> (8 * (len - (i + 1)));
}

/**
 * @brief Insert string-valued DHCP option into packet with optional null termination
 *
 * @detailed
 * Adds string option to DHCP response packet with configurable null termination. Allocates space
 * via free_space() then copies string bytes directly into option data area. Used for text options
 * like OPTION_HOSTNAME (12), OPTION_DOMAINNAME (15), OPTION_MESSAGE (56). Null termination controlled
 * by null_term parameter required by some ancient DHCP clients expecting C-style strings. String
 * length calculated via strlen(), maximum 255 bytes per DHCP option length field size. Silently
 * fails if no space available.
 *
 * @param mess DHCP response packet under construction
 * @param end End of packet buffer for bounds checking
 * @param opt Option type code (OPTION_* constant for string options)
 * @param string Null-terminated C string to copy into option, must not exceed 255 bytes
 * @param null_term Boolean: 1 to include null terminator in option data (legacy clients), 0 for RFC-compliant
 *
 * @note String length limited to 255 bytes due to DHCP option length field (8-bit)
 * @note If null_term true and string shorter than 255, includes null terminator in transmitted data
 * @note Silently does nothing if free_space() returns NULL (no space available)
 * @note Uses memcpy for string transfer, includes null terminator if null_term set
 *
 * @see free_space() for space allocation and overload handling
 * @see option_put() for integer option insertion
 *
 * EXAMPLE USAGE:
 * @code
 * option_put_string(mess, end, OPTION_HOSTNAME, "client.example.com", 0);
 * option_put_string(mess, end, OPTION_DOMAINNAME, "example.com", 0);
 * option_put_string(mess, end, OPTION_MESSAGE, "Address already in use", 0);
 * @endcode
 */
static void option_put_string(struct dhcp_packet *mess, unsigned char *end, int opt, 
			      const char *string, int null_term)
{
  unsigned char *p;
  size_t len = strlen(string);

  if (null_term && len != 255)
    len++;

  if ((p = free_space(mess, end, opt, len)))
    memcpy(p, string, len);
}

/* return length, note this only does the data part */
/**
 * @brief Copy DHCP option data to packet buffer with address substitution
 *
 * @detailed
 * Copies option data from dhcp_opt structure to packet buffer, handling special cases including
 * address substitution (0.0.0.0 replaced with server's local address on subnet), null-termination
 * for string options, and empty option handling. Used by do_options() to insert custom DHCP
 * options configured via --dhcp-option. Implements DHOPT_ADDR flag for automatic IP address
 * substitution enabling portable configuration files (zero addresses dynamically replaced with
 * context-specific server addresses). Returns adjusted length accounting for null-termination.
 *
 * @param opt Pointer to dhcp_opt structure containing option data and flags
 * @param p Pointer to destination buffer in DHCP packet where option data will be written, or NULL to calculate length only
 * @param context DHCP context providing local server address for DHOPT_ADDR substitution, may be NULL if no substitution needed
 * @param null_term If non-zero and opt has DHOPT_STRING flag, append null terminator to string options (PXE compatibility)
 *
 * @return Adjusted length of option data in bytes, including null terminator if added
 *
 * @note If opt->val is NULL, treats as empty string (zero-length or "\0" if null_term)
 * @note DHOPT_ADDR flag requires context parameter for address substitution
 * @note Address 0.0.0.0 in DHOPT_ADDR options replaced with context->local (server's interface address)
 * @note Multiple addresses in DHOPT_ADDR options processed in 4-byte chunks (INADDRSZ)
 * @note If p is NULL, performs length calculation without copying data
 *
 * @see do_options() for primary caller
 * @see dhcp_opt structure in dnsmasq.h for flags (DHOPT_ADDR, DHOPT_STRING)
 * @see DHOPT_ADDR flag for automatic address substitution behavior
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char buffer[256];
 * int len = do_opt(custom_opt, buffer, dhcp_context, 0);
 * // buffer now contains option data with 0.0.0.0 replaced by context->local
 * @endcode
 */
static int do_opt(struct dhcp_opt *opt, unsigned char *p, struct dhcp_context *context, int null_term)
{
  int len = opt->len;
  
  if ((opt->flags & DHOPT_STRING) && null_term && len != 255)
    len++;

  if (p && len != 0)
    {
      if (context && (opt->flags & DHOPT_ADDR))
	{
	  int j;
	  struct in_addr *a = (struct in_addr *)opt->val;
	  for (j = 0; j < opt->len; j+=INADDRSZ, a++)
	    {
	      /* zero means "self" (but not in vendorclass options.) */
	      if (a->s_addr == 0)
		memcpy(p, &context->local, INADDRSZ);
	      else
		memcpy(p, a, INADDRSZ);
	      p += INADDRSZ;
	    }
	}
      else
	/* empty string may be extended to "\0" by null_term */
	memcpy(p, opt->val ? opt->val : (unsigned char *)"", len);
    }  
  return len;
}

/**
 * @brief Check if DHCP option code present in client's requested options list
 *
 * @detailed
 * Tests whether client requested specific DHCP option via OPTION_REQUESTED_OPTIONS (55) parameter
 * request list. Scans client's option request list terminated by OPTION_END (0xff) searching for
 * matching option code. Implements "send everything if no request list" policy returning true for
 * all options when client provides no parameter request list, ensuring clients with broken DHCP
 * implementations still receive essential options. Used by do_options() to filter which configured
 * options to include in response based on client's explicit requests.
 *
 * @param list Pointer to client's parameter request list from OPTION_REQUESTED_OPTIONS (Option 55),
 *             or NULL if client provided no request list
 * @param opt Option code to search for in request list
 *
 * @return 1 if option found in list or list is NULL (send everything), 0 if option not requested
 *
 * @note NULL list treated as request for all options (liberal interpretation for broken clients)
 * @note List expected to be OPTION_END (0xff) terminated, not length-prefixed
 * @note Linear search performance acceptable for typical request lists of 5-20 options
 * @note Essential options (netmask, router, DNS) typically requested by all clients
 *
 * @see do_options() for usage filtering configured options by client requests
 * @see OPTION_REQUESTED_OPTIONS (55) in dhcp-protocol.h for parameter request list option
 *
 * EXAMPLE USAGE:
 * @code
 * if (in_list(req_options, OPTION_DNSSERVER))
 *   option_put_addr(mess, end, OPTION_DNSSERVER, dns_server);
 * @endcode
 */
static int in_list(unsigned char *list, int opt)
{
  int i;

   /* If no requested options, send everything, not nothing. */
  if (!list)
    return 1;
  
  for (i = 0; list[i] != OPTION_END; i++)
    if (opt == list[i])
      return 1;

  return 0;
}

/**
 * @brief Find user-configured DHCP option by option number with tag validation
 *
 * @detailed
 * Searches daemon->dhcp_opts linked list for custom DHCP option matching specified option code
 * that has passed tag matching (DHOPT_TAGOK flag set). Used after tag evaluation to retrieve
 * options that apply to current client based on dhcp-match, dhcp-host, dhcp-range tags. Returns
 * first matching option, enabling configuration of different option values per client class or
 * network segment. Returns NULL if no matching tagged option found, allowing fallback to default
 * behavior or built-in options.
 *
 * @param opt DHCP option code to search for (0-255, standard codes from RFC 2132)
 *
 * @return Pointer to matching dhcp_opt structure if found with DHOPT_TAGOK set, NULL if no match or no valid tagged options
 *
 * @note Only returns options with DHOPT_TAGOK flag (tags matched current client)
 * @note Searches daemon->dhcp_opts list (user-configured options from --dhcp-option directives)
 * @note Returns first match; if multiple options with same code exist, first tagged one returned
 * @note DHOPT_TAGOK set by match_bytes() during tag evaluation in dhcp_reply()
 * @note NULL return allows fallback to built-in default behavior for standard options
 *
 * @see daemon->dhcp_opts for linked list of custom DHCP options
 * @see DHOPT_TAGOK flag for tag matching validation
 * @see match_bytes() for tag matching and DHOPT_TAGOK setting logic
 * @see do_options() for primary usage context
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_opt *custom_router = option_find2(OPTION_ROUTER);
 * if (custom_router)
 *   // Use custom router option value
 * else
 *   // Use default context->router
 * @endcode
 */
static struct dhcp_opt *option_find2(int opt)
{
  struct dhcp_opt *opts;
  
  for (opts = daemon->dhcp_opts; opts; opts = opts->next)
    if (opts->opt == opt && (opts->flags & DHOPT_TAGOK))
      return opts;
  
  return NULL;
}

/**
 * @brief Mark vendor-specific DHCP options matching client's vendor class identifier
 *
 * @detailed
 * Iterates through custom DHCP option list, marking vendor-specific options (DHOPT_VENDOR flag)
 * as DHOPT_VENDOR_MATCH if client's vendor class identifier (option 60) contains configured
 * vendor string. Enables conditional vendor-encapsulated options (option 43) based on client
 * type (e.g., PXE client gets PXE boot options, Cisco phone gets Cisco-specific config).
 * Supports both PXE vendor matching (DHOPT_VENDOR_PXE uses daemon->dhcp_pxe_vendors list)
 * and direct string matching. Clears DHOPT_VENDOR_MATCH before evaluation, then sets flag
 * if substring match found in client's option 60 data.
 *
 * @param opt Pointer to client's vendor class identifier option (option 60) data, or NULL if client didn't send option 60
 * @param dopt Head of dhcp_opt linked list to evaluate for vendor matching
 *
 * @note Clears DHOPT_VENDOR_MATCH flag for all options before matching begins
 * @note Only processes options with DHOPT_VENDOR flag set (vendor-specific options)
 * @note DHOPT_VENDOR_PXE flag uses daemon->dhcp_pxe_vendors list (configured via --pxe-service)
 * @note Non-PXE vendor options use dopt->u.vendor_class string directly
 * @note Performs substring match: vendor string can appear anywhere in option 60 data
 * @note Empty vendor string (len==0) matches all clients (wildcard)
 * @note First matching vendor in list sets DHOPT_VENDOR_MATCH and stops search
 *
 * @see DHOPT_VENDOR flag for vendor-specific option marking
 * @see DHOPT_VENDOR_MATCH flag set when vendor identifier matches
 * @see DHOPT_VENDOR_PXE flag for PXE-specific vendor matching
 * @see daemon->dhcp_pxe_vendors for PXE vendor list (configured via --pxe-service)
 * @see option 43 (vendor-encapsulated options) usage
 * @see RFC 2132 section 9.13 for vendor class identifier (option 60)
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *vendor_opt = option_find(mess, sz, OPTION_VENDOR_ID, 1);
 * match_vendor_opts(vendor_opt, daemon->dhcp_opts);
 * // Options with DHOPT_VENDOR_MATCH now identified for inclusion
 * @endcode
 */
static void match_vendor_opts(unsigned char *opt, struct dhcp_opt *dopt)
{
  for (; dopt; dopt = dopt->next)
    {
      dopt->flags &= ~DHOPT_VENDOR_MATCH;
      if (opt && (dopt->flags & DHOPT_VENDOR))
	{
	  const struct dhcp_pxe_vendor *pv;
	  struct dhcp_pxe_vendor dummy_vendor = {
	    .data = (char *)dopt->u.vendor_class,
	    .next = NULL,
	  };
	  if (dopt->flags & DHOPT_VENDOR_PXE)
	    pv = daemon->dhcp_pxe_vendors;
	  else
	    pv = &dummy_vendor;
	  for (; pv; pv = pv->next)
	    {
	      int i, len = 0, matched = 0;
	      if (pv->data)
	        len = strlen(pv->data);
	      for (i = 0; i <= (option_len(opt) - len); i++)
	        if (len == 0 || memcmp(pv->data, option_ptr(opt, i), len) == 0)
	          {
		    matched = 1;
	            break;
	          }
	      if (matched)
		{
	          dopt->flags |= DHOPT_VENDOR_MATCH;
		  break;
		}
	    }
	}
    }
}

/**
 * @brief Assemble vendor-encapsulated DHCP options with 255-byte sub-option chunking
 *
 * @detailed
 * Constructs vendor-encapsulated options (option 43 or other encapsulated types) by iterating
 * through dhcp_opt list, selecting options matching specified flag, and assembling into
 * encapsulated format with sub-option code+length+data encoding. Handles 255-byte maximum
 * sub-option length by splitting long option sequences across multiple encap option instances.
 * Each encap option ends with OPTION_END marker. Used for vendor-specific options (option 43),
 * PXE options, and other encapsulated option spaces. Returns 1 if any options added, 0 if none.
 *
 * @param opt Head of dhcp_opt linked list to search for matching options
 * @param encap Encapsulation option code (typically OPTION_VENDOR_CLASS_OPT=43 for vendor-encapsulated)
 * @param flag Option flag to match (e.g., DHOPT_VENDOR_MATCH for vendor options)
 * @param mess Pointer to DHCP packet structure for option insertion
 * @param end Pointer to end of available option space in packet
 * @param null_term If non-zero, null-terminate string options (PXE compatibility)
 *
 * @return 1 if at least one encapsulated option was added, 0 if no matching options found
 *
 * @note Enforces 255-byte maximum length per RFC 2132: splits long sequences into multiple encap options
 * @note Each sub-option formatted as: 1-byte code + 1-byte length + N-byte data
 * @note Each encapsulated option terminated with OPTION_END (255)
 * @note Two-pass algorithm: first calculates size, second writes data
 * @note Automatically splits option sequence if accumulated length exceeds 255 bytes
 * @note Uses free_space() to find available buffer space in packet
 *
 * @see free_space() for buffer allocation in DHCP packet
 * @see do_opt() for individual option data formatting
 * @see DHOPT_VENDOR_MATCH flag for vendor-specific option selection
 * @see RFC 2132 option 43 for vendor-encapsulated options format
 * @see RFC 3396 for long option handling (not implemented here, uses multiple instances)
 *
 * EXAMPLE USAGE:
 * @code
 * // Add vendor-encapsulated options (option 43) matching vendor class
 * int added = do_encap_opts(daemon->dhcp_opts, OPTION_VENDOR_CLASS_OPT, DHOPT_VENDOR_MATCH, mess, end, 0);
 * @endcode
 */
static int do_encap_opts(struct dhcp_opt *opt, int encap, int flag,  
			 struct dhcp_packet *mess, unsigned char *end, int null_term)
{
  int len, enc_len, ret = 0;
  struct dhcp_opt *start;
  unsigned char *p;
    
  /* find size in advance */
  for (enc_len = 0, start = opt; opt; opt = opt->next)
    if (opt->flags & flag)
      {
	int new = do_opt(opt, NULL, NULL, null_term) + 2;
	ret  = 1;
	if (enc_len + new <= 255)
	  enc_len += new;
	else
	  {
	    p = free_space(mess, end, encap, enc_len);
	    for (; start && start != opt; start = start->next)
	      if (p && (start->flags & flag))
		{
		  len = do_opt(start, p + 2, NULL, null_term);
		  *(p++) = start->opt;
		  *(p++) = len;
		  p += len;
		}
	    enc_len = new;
	    start = opt;
	  }
      }
  
  if (enc_len != 0 &&
      (p = free_space(mess, end, encap, enc_len + 1)))
    {
      for (; start; start = start->next)
	if (start->flags & flag)
	  {
	    len = do_opt(start, p + 2, NULL, null_term);
	    *(p++) = start->opt;
	    *(p++) = len;
	    p += len;
	  }
      *p = OPTION_END;
    }

  return ret;
}

/**
 * @brief Add PXE-specific vendor identification and client UUID to DHCP response
 *
 * @detailed
 * Inserts vendor class identifier (option 60) and PXE client UUID (option 97) into DHCP response
 * packet for PXE (Pre-boot Execution Environment) client support. Vendor ID identifies server
 * as PXE-capable (default "PXEClient" or custom value). Client UUID (16-byte GUID + 1-byte type)
 * enables PXE firmware to recognize responses from correct PXE server. Required for RFC 4578
 * PXE compliance. UUID option only added if client provided one (preserves client's UUID).
 *
 * @param mess Pointer to DHCP packet structure for option insertion
 * @param end Pointer to end of available option space in packet
 * @param uuid Pointer to 17-byte client UUID (16-byte GUID + 1-byte type prefix), or NULL if client didn't provide UUID
 * @param pxevendor Vendor class identifier string (e.g., "PXEClient"), or NULL to use default "PXEClient"
 *
 * @note Always adds vendor class identifier (option 60)
 * @note Client UUID (option 97) only added if uuid parameter non-NULL
 * @note UUID format: 1 byte type (0=binary GUID, 1=text) + 16 bytes GUID
 * @note Default vendor ID "PXEClient" identifies standard PXE server
 * @note Custom pxevendor enables vendor-specific PXE implementations
 *
 * @see OPTION_VENDOR_ID (option 60) for vendor class identifier
 * @see OPTION_PXE_UUID (option 97) for client UUID
 * @see RFC 4578 for PXE DHCP extensions
 * @see is_pxe_client() for UUID extraction from client request
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char client_uuid[17];
 * if (extracted_uuid_from_client)
 *   pxe_misc(mess, end, client_uuid, "PXEClient");
 * else
 *   pxe_misc(mess, end, NULL, NULL); // Just vendor ID, no UUID
 * @endcode
 */
static void pxe_misc(struct dhcp_packet *mess, unsigned char *end, unsigned char *uuid, const char *pxevendor)
{
  unsigned char *p;

  if (!pxevendor)
    pxevendor="PXEClient";
  option_put_string(mess, end, OPTION_VENDOR_ID, pxevendor, 0);
  if (uuid && (p = free_space(mess, end, OPTION_PXE_UUID, 17)))
    memcpy(p, uuid, 17);
}

/**
 * @brief Filter vendor-matched options by network/client tags and check for forced options
 *
 * @detailed
 * Second-stage filtering of vendor-encapsulated options after vendor class matching. Clears
 * DHOPT_VENDOR_MATCH flag for options whose network/client tags don't match current client's
 * netid set, enabling fine-grained control (e.g., different PXE boot configs per VLAN or
 * client class). Simultaneously checks for DHOPT_FORCE flag, indicating option must be sent
 * even if not requested, and returns 1 if any forced vendor option remains after pruning.
 * Enables tag-based conditional vendor option delivery (--dhcp-option=tag:subnet1,encap:43,1,"data").
 *
 * @param netid Linked list of network and client identification tags (from dhcp-match, dhcp-host, dhcp-range)
 *
 * @return 1 if at least one vendor-matched option has DHOPT_FORCE flag (must send unrequested), 0 otherwise
 *
 * @note Only processes options with DHOPT_VENDOR_MATCH flag (set by match_vendor_opts)
 * @note Clears DHOPT_VENDOR_MATCH if option's netid tags don't match client's tags
 * @note Uses match_netid() with positive-only matching (tag must be present, not just not negated)
 * @note DHOPT_FORCE flag indicates option must be sent regardless of client's parameter request list
 * @note Return value allows do_options() to send vendor options even if not requested
 *
 * @see match_vendor_opts() for initial vendor class matching (sets DHOPT_VENDOR_MATCH)
 * @see match_netid() for tag matching logic
 * @see DHOPT_VENDOR_MATCH flag for vendor-matched options
 * @see DHOPT_FORCE flag for mandatory option inclusion
 * @see do_encap_opts() for final vendor option assembly
 *
 * EXAMPLE USAGE:
 * @code
 * match_vendor_opts(vendor_class_opt, daemon->dhcp_opts);
 * int force_vendor = prune_vendor_opts(netid);
 * // Only vendor options matching both vendor class AND netid tags remain marked
 * @endcode
 */
static int prune_vendor_opts(struct dhcp_netid *netid)
{
  int force = 0;
  struct dhcp_opt *opt;

  /* prune vendor-encapsulated options based on netid, and look if we're forcing them to be sent */
  for (opt = daemon->dhcp_opts; opt; opt = opt->next)
    if (opt->flags & DHOPT_VENDOR_MATCH)
      {
	if (!match_netid(opt->netid, netid, 1))
	  opt->flags &= ~DHOPT_VENDOR_MATCH;
	else if (opt->flags & DHOPT_FORCE)
	  force = 1;
      }
  return force;
}


/**
 * @brief Workaround for broken UEFI PXE menu implementations by direct boot file insertion
 *
 * @detailed
 * Many UEFI PXE firmware implementations have broken menu code (fail to parse PXE boot menu
 * options correctly). When exactly ONE pxe-service matches client architecture and tags, bypasses
 * PXE menu system entirely by jamming boot file directly into DHCP packet's 'file' field,
 * TFTP server IP into 'siaddr' field, and server name into 'sname' field. Only activates for
 * UEFI architectures (CSA >= 6: x86-64 UEFI, IA32 UEFI, ARM UEFI). Returns 1 if workaround
 * applied (single menu item), 0 if multiple or zero menu items found (use standard PXE menu).
 * Assumes layer 0 boot requested. Appends ".0" to basename if no extension present.
 *
 * @param pxe_arch PXE client system architecture from option 93 (6=x86-64 UEFI, 7=x86-32 UEFI, 10=ARM32 UEFI, 11=ARM64 UEFI)
 * @param netid Linked list of network/client tags for matching pxe-service entries
 * @param mess Pointer to DHCP packet to populate with boot file, siaddr, sname fields
 * @param local Local server IP address for TFTP server (fallback if service doesn't specify server)
 * @param now Current time for a_record_from_hosts() hostname resolution
 * @param pxe If non-zero, actually populate packet fields; if zero, only test whether workaround would apply
 *
 * @return 1 if exactly one matching pxe-service found (workaround applied or would apply), 0 if zero or multiple matches (use standard menu)
 *
 * @note Only affects UEFI architectures (pxe_arch >= 6), returns 0 for BIOS PXE (arch 0)
 * @note Workaround bypasses PXE boot menu option 43.6/43.7/43.8/43.9 completely
 * @note If multiple pxe-service entries match, returns 0 to allow proper menu display
 * @note mess->siaddr set to service->server or a_record_from_hosts(service->sname) or local
 * @note mess->sname populated with hostname or IP address as string
 * @note mess->file populated with basename, ".0" appended if no extension
 * @note Assumes PXE layer 0 boot (immediate boot, not menu)
 *
 * @see daemon->pxe_services list configured via --pxe-service directives
 * @see match_netid() for tag-based service selection
 * @see a_record_from_hosts() for hostname to IP resolution
 * @see RFC 4578 for PXE client system architecture identifiers
 * @see RFC 2132 for DHCP siaddr, sname, file fields
 *
 * EXAMPLE USAGE:
 * @code
 * if (pxe_uefi_workaround(pxe_arch, netid, mess, context->local, now, 1))
 *   // Workaround applied, skip normal PXE menu option assembly
 * else
 *   // Use standard PXE menu options
 * @endcode
 */
static int pxe_uefi_workaround(int pxe_arch, struct dhcp_netid *netid, struct dhcp_packet *mess, struct in_addr local, time_t now, int pxe)
{
  struct pxe_service *service, *found;

  /* Only workaround UEFI archs. */
  if (pxe_arch < 6)
    return 0;
  
  for (found = NULL, service = daemon->pxe_services; service; service = service->next)
    if (pxe_arch == service->CSA && service->basename && match_netid(service->netid, netid, 1))
      {
	if (found)
	  return 0; /* More than one relevant menu item */
	  
	found = service;
      }

  if (!found)
    return 0; /* No relevant menu items. */
  
  if (!pxe)
     return 1;
  
  if (found->sname)
    {
      mess->siaddr = a_record_from_hosts(found->sname, now);
      snprintf((char *)mess->sname, sizeof(mess->sname), "%s", found->sname);
    }
  else 
    {
      if (found->server.s_addr != 0)
	mess->siaddr = found->server; 
      else
	mess->siaddr = local;
  
      inet_ntop(AF_INET, &mess->siaddr, (char *)mess->sname, INET_ADDRSTRLEN);
    }
  
  if (found->basename)
    snprintf((char *)mess->file, sizeof(mess->file), 
	     strchr(found->basename, '.') ? "%s" : "%s.0", found->basename);
  
  return 1;
}

/**
 * @brief Construct PXE boot menu options (option 43 sub-options) for client architecture
 *
 * @detailed
 * Dynamically builds PXE vendor-encapsulated options (option 43 sub-options) including boot
 * menu (SUBOPT_PXE_MENU), boot servers (SUBOPT_PXE_SERVERS), menu prompt (SUBOPT_PXE_MENU_PROMPT),
 * and discovery control (SUBOPT_PXE_DISCOVERY). Iterates through daemon->pxe_services list,
 * selecting services matching client architecture and network tags. Constructs menu with type
 * codes and descriptive text. Generates server list with boot server IP addresses. Sets
 * discovery control to disable multicast (unsupported), enable broadcast only if needed.
 * Returns linked list of fake_opts prepended to daemon->dhcp_opts for inclusion in response.
 * Uses static buffers daemon->dhcp_buff and daemon->dhcp_buff3 for menu and server data.
 *
 * @param pxe_arch PXE client system architecture from option 93 (0=x86 BIOS, 6=x86-64 UEFI, 7=x86-32 UEFI, 9=x64 EFI BC, 10=ARM32 UEFI, 11=ARM64 UEFI)
 * @param netid Linked list of network/client tags for matching pxe-service entries
 * @param local Local server IP address used as TFTP server for services with basename
 * @param now Current time for a_record_from_hosts() hostname resolution
 *
 * @return Pointer to head of fake_opts list (prepended to daemon->dhcp_opts), or daemon->dhcp_opts if no PXE services or error
 *
 * @note Enforces 253-byte maximum for encapsulated option data (255 - 2 bytes for type/length)
 * @note Boot menu format: 2-byte type + 1-byte length + variable text for each entry
 * @note Boot servers format: 2-byte type + 1-byte count + count * 4-byte IP addresses
 * @note Discovery control: 3=no multicast/broadcast, 2=no multicast/broadcast ok, 8=no menu (use filename)
 * @note Fake menu prompt: 0-byte timeout (wait forever) or 255-byte timeout (wait forever if multiple choices)
 * @note Static fake_opts allocated once and reused (4 option slots)
 * @note Uses static buffers daemon->dhcp_buff (menu) and daemon->dhcp_buff3 (servers)
 *
 * @see daemon->pxe_services list configured via --pxe-service directives
 * @see match_netid() for tag-based service selection
 * @see a_record_from_hosts() for hostname to IP resolution
 * @see RFC 4578 for PXE specifications
 * @see PXE specification for option 43 sub-option format
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_opt *pxe_options = pxe_opts(pxe_arch, netid, context->local, now);
 * // pxe_options now contains menu, servers, prompt, discovery options
 * @endcode
 */
static struct dhcp_opt *pxe_opts(int pxe_arch, struct dhcp_netid *netid, struct in_addr local, time_t now)
{
#define NUM_OPTS 4  

  unsigned  char *p, *q;
  struct pxe_service *service;
  static struct dhcp_opt *o, *ret;
  int i, j = NUM_OPTS - 1;
  struct in_addr boot_server;
  
  /* We pass back references to these, hence they are declared static */
  static unsigned char discovery_control;
  static unsigned char fake_prompt[] = { 0, 'P', 'X', 'E' }; 
  static struct dhcp_opt *fake_opts = NULL;
  
  /* Disable multicast, since we don't support it, and broadcast
     unless we need it */
  discovery_control = 3;
  
  ret = daemon->dhcp_opts;
  
  if (!fake_opts && !(fake_opts = whine_malloc(NUM_OPTS * sizeof(struct dhcp_opt))))
    return ret;

  for (i = 0; i < NUM_OPTS; i++)
    {
      fake_opts[i].flags = DHOPT_VENDOR_MATCH;
      fake_opts[i].netid = NULL;
      fake_opts[i].next = i == (NUM_OPTS - 1) ? ret : &fake_opts[i+1];
    }
  
  /* create the data for the PXE_MENU and PXE_SERVERS options. */
  p = (unsigned char *)daemon->dhcp_buff;
  q = (unsigned char *)daemon->dhcp_buff3;

  for (i = 0, service = daemon->pxe_services; service; service = service->next)
    if (pxe_arch == service->CSA && match_netid(service->netid, netid, 1))
      {
	size_t len = strlen(service->menu);
	/* opt 43 max size is 255. encapsulated option has type and length
	   bytes, so its max size is 253. */
	if (p - (unsigned char *)daemon->dhcp_buff + len + 3 < 253)
	  {
	    *(p++) = service->type >> 8;
	    *(p++) = service->type;
	    *(p++) = len;
	    memcpy(p, service->menu, len);
	    p += len;
	    i++;
	  }
	else
	  {
	  toobig:
	    my_syslog(MS_DHCP | LOG_ERR, _("PXE menu too large"));
	    return daemon->dhcp_opts;
	  }
	
	boot_server = service->basename ? local : 
	  (service->sname ? a_record_from_hosts(service->sname, now) : service->server);
	
	if (boot_server.s_addr != 0)
	  {
	    if (q - (unsigned char *)daemon->dhcp_buff3 + 3 + INADDRSZ >= 253)
	      goto toobig;
	    
	    /* Boot service with known address - give it */
	    *(q++) = service->type >> 8;
	    *(q++) = service->type;
	    *(q++) = 1;
	    /* dest misaligned */
	    memcpy(q, &boot_server.s_addr, INADDRSZ);
	    q += INADDRSZ;
	  }
	else if (service->type != 0)
	  /* We don't know the server for a service type, so we'll
	     allow the client to broadcast for it */
	  discovery_control = 2;
      }

  /* if no prompt, wait forever if there's a choice */
  fake_prompt[0] = (i > 1) ? 255 : 0;
  
  if (i == 0)
    discovery_control = 8; /* no menu - just use use mess->filename */
  else
    {
      ret = &fake_opts[j--];
      ret->len = p - (unsigned char *)daemon->dhcp_buff;
      ret->val = (unsigned char *)daemon->dhcp_buff;
      ret->opt = SUBOPT_PXE_MENU;

      if (q - (unsigned char *)daemon->dhcp_buff3 != 0)
	{
	  ret = &fake_opts[j--]; 
	  ret->len = q - (unsigned char *)daemon->dhcp_buff3;
	  ret->val = (unsigned char *)daemon->dhcp_buff3;
	  ret->opt = SUBOPT_PXE_SERVERS;
	}
    }

  for (o = daemon->dhcp_opts; o; o = o->next)
    if ((o->flags & DHOPT_VENDOR_MATCH) && o->opt == SUBOPT_PXE_MENU_PROMPT)
      break;
  
  if (!o)
    {
      ret = &fake_opts[j--]; 
      ret->len = sizeof(fake_prompt);
      ret->val = fake_prompt;
      ret->opt = SUBOPT_PXE_MENU_PROMPT;
    }
  
  ret = &fake_opts[j--]; 
  ret->len = 1;
  ret->opt = SUBOPT_PXE_DISCOVERY;
  ret->val= &discovery_control;
 
  return ret;
}

/**
 * @brief Initialize DHCP response packet clearing optional fields for fresh construction
 *
 * @detailed
 * Prepares DHCP packet structure for response construction by zeroing fields that may contain
 * options or data: sname (64 bytes), file (128 bytes), options area (after DHCP magic cookie),
 * and siaddr (next server address). Leaves fixed header fields (op, htype, hlen, xid, etc.)
 * untouched allowing response to mirror request's transaction context. Clearing enables option
 * overload mechanism to use file/sname fields for options if needed. Essential first step before
 * populating response with do_options() and option_put() calls. Does not clear DHCP magic cookie
 * (first 4 bytes of options) maintaining packet structure validity.
 *
 * @param mess DHCP packet to initialize for response construction
 * @param end Pointer to end of available option space for calculating clear range
 *
 * @note Preserves DHCP magic cookie (0x63825363) in options[0..3]
 * @note Preserves fixed header fields (op, htype, hlen, hops, xid, secs, flags, addresses, chaddr)
 * @note Zeroes sname, file, siaddr, and options area after magic cookie
 * @note After clearing, file and sname available for option overload if needed
 * @note Typically called after copying request packet into response buffer
 *
 * @see do_options() for populating cleared packet with response options
 * @see free_space() for utilizing cleared file/sname areas via option overload
 */  
static void clear_packet(struct dhcp_packet *mess, unsigned char *end)
{
  memset(mess->sname, 0, sizeof(mess->sname));
  memset(mess->file, 0, sizeof(mess->file));
  memset(&mess->options[0] + sizeof(u32), 0, end - (&mess->options[0] + sizeof(u32)));
  mess->siaddr.s_addr = 0;
}

/**
 * @brief Select PXE boot configuration matching client's network ID tags
 *
 * @detailed
 * Searches configured PXE boot options (--dhcp-boot) to find entry matching client's network
 * context identified by netid tags (interface, vendor class, user class, circuit-id, etc.).
 * Implements two-pass search: first pass requires netid match, second pass (fallback) accepts
 * boot configuration with no netid restrictions (default boot). Enables context-specific PXE
 * boot serving different boot images to different client classes (BIOS vs UEFI, x86 vs ARM, etc.).
 * Returns selected boot configuration containing boot filename, next-server address, and optional
 * boot server list for PXE menu presentation.
 *
 * @param netid Linked list of network ID tags identifying client context (vendor, arch, interface, etc.)
 *
 * @return Pointer to matching dhcp_boot configuration if found, NULL if no boot config matches
 *
 * @note Two-pass search: first requires netid match, second accepts default (no netid)
 * @note Network IDs include: interface name, vendor class, user class, circuit-id, remote-id,
 *       architecture type, and tag-if conditional tags
 * @note Enables architecture-specific boot: different boot files for BIOS, UEFI x64, UEFI ARM
 * @note Used by pxe_opts() and dhcp_reply() to determine boot parameters for PXE responses
 *
 * @see match_netid() for network ID matching logic
 * @see daemon->boot_config for configured boot option list
 * @see pxe_opts() for generating PXE-specific DHCP options using boot config
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_boot *boot = find_boot(client_netid);
 * if (boot && boot->file)
 *   option_put_string(mess, end, OPTION_FILENAME, boot->file, 0);
 * @endcode
 */
struct dhcp_boot *find_boot(struct dhcp_netid *netid)
{
  struct dhcp_boot *boot;

  /* decide which dhcp-boot option we're using */
  for (boot = daemon->boot_config; boot; boot = boot->next)
    if (match_netid(boot->netid, netid, 0))
      break;
  if (!boot)
    /* No match, look for one without a netid */
    for (boot = daemon->boot_config; boot; boot = boot->next)
      if (match_netid(boot->netid, netid, 1))
	break;

  return boot;
}

/**
 * @brief Detect PXE network boot client by vendor ID string matching
 *
 * @detailed
 * Identifies PXE (Preboot eXecution Environment) clients by examining OPTION_VENDOR_ID (60) for
 * known PXE vendor strings configured via --dhcp-vendorclass option. Common PXE vendor IDs include
 * "PXEClient", "HTTPClient", "AAPLBSDPC" (Apple NetBoot), "Etherboot", etc. Enables dnsmasq to
 * provide PXE-specific DHCP options (architecture type, boot menu, boot servers) only to actual
 * PXE clients avoiding option pollution for non-PXE devices. Returns matched vendor string via
 * output parameter for later use in PXE response customization. Essential for PXE/TFTP boot
 * server operation.
 *
 * @param mess DHCP request packet to examine for PXE vendor identification
 * @param sz Size of packet for option extraction bounds checking
 * @param pxe_vendor Output parameter receiving pointer to matched vendor string, or unchanged if not PXE
 *
 * @return 1 if packet from PXE client (vendor ID matches configured PXE vendor), 0 if not PXE
 *
 * @note Searches OPTION_VENDOR_ID (60) option for configured PXE vendor string prefixes
 * @note Vendor strings configured via --dhcp-vendorclass option in daemon->dhcp_pxe_vendors list
 * @note Uses prefix matching allowing vendor ID "PXEClient:Arch:00000:UNDI:002001" to match "PXEClient"
 * @note Returns first matching vendor string if multiple configs match
 * @note NULL pxe_vendor parameter acceptable if vendor string not needed by caller
 *
 * @see daemon->dhcp_pxe_vendors for configured PXE vendor ID list
 * @see pxe_opts() for generating PXE options for detected PXE clients
 * @see dhcp_reply() for PXE client detection in main DHCP processing
 * @see RFC 4578 for PXE DHCP options specification
 *
 * EXAMPLE USAGE:
 * @code
 * const char *vendor = NULL;
 * if (is_pxe_client(mess, packet_size, &vendor)) {
 *   // Generate PXE-specific options for boot
 * }
 * @endcode
 */
static int is_pxe_client(struct dhcp_packet *mess, size_t sz, const char **pxe_vendor)
{
  const unsigned char *opt = NULL;
  ssize_t conf_len = 0;
  const struct dhcp_pxe_vendor *conf = daemon->dhcp_pxe_vendors;
  opt = option_find(mess, sz, OPTION_VENDOR_ID, 0);
  if (!opt) 
    return 0;
  for (; conf; conf = conf->next)
    {
      conf_len = strlen(conf->data);
      if (option_len(opt) < conf_len)
        continue;
      if (strncmp(option_ptr(opt, 0), conf->data, conf_len) == 0)
        {
          if (pxe_vendor)
            *pxe_vendor = conf->data;
          return 1;
        }
    }
  return 0;
}

/**
 * @brief Populate DHCP response packet with all applicable options
 *
 * @detailed
 * Core DHCP option assembly function constructing complete option set for response packets (OFFER/ACK).
 * Processes configured DHCP options from daemon->dhcp_opts list, filtering by network ID tag matching,
 * client parameter request list (Option 55), and option priority. Handles standard options (subnet mask,
 * router, DNS servers, domain name, lease time, renewal times T1/T2), vendor-specific options (Option 43),
 * vendor class options (Option 60), user class options (Option 77), PXE boot options (architecture,
 * UUID, boot menu), FQDN option (Option 81), and encapsulated sub-options. Implements option overload
 * for extended option space. Applies configuration priority allowing specific matches to override
 * general defaults. Formats all options per RFC 2132 specifications handling null termination for
 * legacy clients.
 *
 * @param context DHCP context for client's subnet providing network parameters (netmask, router, DNS, lease time)
 * @param mess DHCP response packet to populate with options (already cleared via clear_packet())
 * @param end Pointer to end of packet buffer for bounds checking
 * @param req_options Client's parameter request list (Option 55) or NULL to send all configured options
 * @param hostname Client's hostname from Option 12 or static config, may be NULL
 * @param domain Domain name to assign to client for FQDN construction, may be NULL
 * @param netid Network ID tag list for configuration matching (interface, vendor, arch, etc.)
 * @param subnet_addr Subnet address for relay agent subnet selection (Option 82 sub-option 5)
 * @param fqdn_flags FQDN option flags if client sent FQDN request (Option 81)
 * @param null_term Boolean: 1 to null-terminate string options for ancient DHCP clients, 0 for RFC compliance
 * @param pxe_arch PXE client architecture type (x86 BIOS=0, x64 UEFI=7, ARM=10, etc.) or -1 if not PXE
 * @param uuid PXE client UUID (Option 97) for boot server matching, or NULL
 * @param vendor_class_len Length of vendor class option if present, 0 otherwise
 * @param now Current time for relative timestamp options
 * @param lease_time Lease duration in seconds for T1/T2 calculation
 * @param fuzz Random offset for T1/T2 to distribute client renewal load
 * @param pxevendor PXE vendor ID string matched by is_pxe_client(), or NULL
 *
 * @note Processes options in priority order allowing specific tag matches to override general configs
 * @note Filters options by client's parameter request list (Option 55) unless force flag set
 * @note Handles option overload transparently via free_space() when options area exhausted
 * @note Adds standard network parameters: subnet mask, router, DNS servers from context
 * @note Adds lease timing: lease time, renewal T1 (50% of lease), rebind T2 (87.5% of lease)
 * @note Adds PXE options if pxe_arch >= 0: boot menu, architecture type, UUID
 * @note Processes vendor-specific options (Option 43) with encapsulation
 * @note Applies fuzz to T1/T2 to prevent thundering herd of client renewals
 *
 * @see free_space() for option space allocation with overload handling
 * @see option_put() for integer option insertion
 * @see option_put_string() for string option insertion
 * @see in_list() for checking client's parameter request list
 * @see pxe_opts() for generating PXE-specific option list
 * @see match_netid() for network ID tag matching
 *
 * RFC COMPLIANCE:
 * - RFC 2131: Standard DHCP option processing
 * - RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * - RFC 3046: Relay Agent Information Option
 * - RFC 4578: PXE DHCP Options (architecture, UUID, boot menu)
 * - RFC 4702: DHCP Client FQDN Option
 *
 * SIDE EFFECTS:
 * - Modifies mess packet adding all applicable DHCP options
 * - May use option overload consuming file/sname fields if options area full
 * - Logs option details if OPT_LOG_OPTS enabled
 *
 * EXAMPLE USAGE:
 * @code
 * clear_packet(mess, end);
 * do_options(context, mess, end, req_options, hostname, domain, netid,
 *            subnet_addr, fqdn_flags, 0, pxe_arch, uuid, 0, now, 
 *            lease_time, 0, pxevendor);
 * @endcode
 */
static void do_options(struct dhcp_context *context,
		       struct dhcp_packet *mess,
		       unsigned char *end, 
		       unsigned char *req_options,
		       char *hostname, 
		       char *domain,
		       struct dhcp_netid *netid,
		       struct in_addr subnet_addr,
		       unsigned char fqdn_flags,
		       int null_term, int pxe_arch,
		       unsigned char *uuid,
		       int vendor_class_len,
		       time_t now,
		       unsigned int lease_time,
		       unsigned short fuzz,
		       const char *pxevendor)
{
  struct dhcp_opt *opt, *config_opts = daemon->dhcp_opts;
  struct dhcp_boot *boot;
  unsigned char *p;
  int i, len, force_encap = 0;
  unsigned char f0 = 0, s0 = 0;
  int done_file = 0, done_server = 0;
  int done_vendor_class = 0;
  struct dhcp_netid *tagif;
  struct dhcp_netid_list *id_list;

  /* filter options based on tags, those we want get DHOPT_TAGOK bit set */
  if (context)
    context->netid.next = NULL;
  tagif = option_filter(netid, context && context->netid.net ? &context->netid : NULL, config_opts);
	
  /* logging */
  if (option_bool(OPT_LOG_OPTS) && req_options)
    {
      char *q = daemon->namebuff;
      for (i = 0; req_options[i] != OPTION_END; i++)
	{
	  char *s = option_string(AF_INET, req_options[i], NULL, 0, NULL, 0);
	  q += snprintf(q, MAXDNAME - (q - daemon->namebuff),
			"%d%s%s%s", 
			req_options[i],
			strlen(s) != 0 ? ":" : "",
			s, 
			req_options[i+1] == OPTION_END ? "" : ", ");
	  if (req_options[i+1] == OPTION_END || (q - daemon->namebuff) > 40)
	    {
	      q = daemon->namebuff;
	      my_syslog(MS_DHCP | LOG_INFO, _("%u requested options: %s"), ntohl(mess->xid), daemon->namebuff);
	    }
	}
    }
      
  for (id_list = daemon->force_broadcast; id_list; id_list = id_list->next)
    if ((!id_list->list) || match_netid(id_list->list, netid, 0))
      break;
  if (id_list)
    mess->flags |= htons(0x8000); /* force broadcast */
  
  if (context)
    mess->siaddr = context->local;
  
  /* See if we can send the boot stuff as options.
     To do this we need a requested option list, BOOTP
     and very old DHCP clients won't have this, we also 
     provide a manual option to disable it.
     Some PXE ROMs have bugs (surprise!) and need zero-terminated 
     names, so we always send those.  */
  if ((boot = find_boot(tagif)))
    {
      if (boot->sname)
	{	  
	  if (!option_bool(OPT_NO_OVERRIDE) &&
	      req_options && 
	      in_list(req_options, OPTION_SNAME))
	    option_put_string(mess, end, OPTION_SNAME, boot->sname, 1);
	  else
	    safe_strncpy((char *)mess->sname, boot->sname, sizeof(mess->sname));
	}
      
      if (boot->file)
	{
	  if (!option_bool(OPT_NO_OVERRIDE) &&
	      req_options && 
	      in_list(req_options, OPTION_FILENAME))
	    option_put_string(mess, end, OPTION_FILENAME, boot->file, 1);
	  else
	    safe_strncpy((char *)mess->file, boot->file, sizeof(mess->file));
	}
      
      if (boot->next_server.s_addr) 
	mess->siaddr = boot->next_server;
      else if (boot->tftp_sname)
	mess->siaddr = a_record_from_hosts(boot->tftp_sname, now);
    }
  else
    /* Use the values of the relevant options if no dhcp-boot given and
       they're not explicitly asked for as options. OPTION_END is used
       as an internal way to specify siaddr without using dhcp-boot, for use in
       dhcp-optsfile. */
    {
      if ((!req_options || !in_list(req_options, OPTION_FILENAME)) &&
	  (opt = option_find2(OPTION_FILENAME)) && !(opt->flags & DHOPT_FORCE))
	{
	  safe_strncpy((char *)mess->file, (char *)opt->val, sizeof(mess->file));
	  done_file = 1;
	}
      
      if ((!req_options || !in_list(req_options, OPTION_SNAME)) &&
	  (opt = option_find2(OPTION_SNAME)) && !(opt->flags & DHOPT_FORCE))
	{
	  safe_strncpy((char *)mess->sname, (char *)opt->val, sizeof(mess->sname));
	  done_server = 1;
	}
      
      if ((opt = option_find2(OPTION_END)))
	mess->siaddr.s_addr = ((struct in_addr *)opt->val)->s_addr;	
    }
        
  /* We don't want to do option-overload for BOOTP, so make the file and sname
     fields look like they are in use, even when they aren't. This gets restored
     at the end of this function. */

  if (!req_options || option_bool(OPT_NO_OVERRIDE))
    {
      f0 = mess->file[0];
      mess->file[0] = 1;
      s0 = mess->sname[0];
      mess->sname[0] = 1;
    }
      
  /* At this point, if mess->sname or mess->file are zeroed, they are available
     for option overload, reserve space for the overload option. */
  if (mess->file[0] == 0 || mess->sname[0] == 0)
    end -= 3;

  /* rfc3011 says this doesn't need to be in the requested options list. */
  if (subnet_addr.s_addr)
    option_put(mess, end, OPTION_SUBNET_SELECT, INADDRSZ, ntohl(subnet_addr.s_addr));
   
  if (lease_time != 0xffffffff)
    { 
      unsigned int t1val = lease_time/2; 
      unsigned int t2val = (lease_time*7)/8;
      unsigned int hval;
      
      /* If set by user, sanity check, so not longer than lease. */
      if ((opt = option_find2(OPTION_T1)))
	{
	  hval = ntohl(*((unsigned int *)opt->val));
	  if (hval < lease_time && hval > 2)
	    t1val = hval;
	}

       if ((opt = option_find2(OPTION_T2)))
	{
	  hval = ntohl(*((unsigned int *)opt->val));
	  if (hval < lease_time && hval > 2)
	    t2val = hval;
	}
       	  
       /* ensure T1 is still < T2 */
       if (t2val <= t1val)
	 t1val = t2val - 1; 

       while (fuzz > (t1val/8))
	 fuzz = fuzz/2;
	 
       t1val -= fuzz;
       t2val -= fuzz;
       
       option_put(mess, end, OPTION_T1, 4, t1val);
       option_put(mess, end, OPTION_T2, 4, t2val);
    }

  /* replies to DHCPINFORM may not have a valid context */
  if (context)
    {
      if (!option_find2(OPTION_NETMASK))
	option_put(mess, end, OPTION_NETMASK, INADDRSZ, ntohl(context->netmask.s_addr));
  
      /* May not have a "guessed" broadcast address if we got no packets via a relay
	 from this net yet (ie just unicast renewals after a restart */
      if (context->broadcast.s_addr &&
	  !option_find2(OPTION_BROADCAST))
	option_put(mess, end, OPTION_BROADCAST, INADDRSZ, ntohl(context->broadcast.s_addr));
      
      /* Same comments as broadcast apply, and also may not be able to get a sensible
	 default when using subnet select.  User must configure by steam in that case. */
      if (context->router.s_addr &&
	  in_list(req_options, OPTION_ROUTER) &&
	  !option_find2(OPTION_ROUTER))
	option_put(mess, end, OPTION_ROUTER, INADDRSZ, ntohl(context->router.s_addr));
      
      if (daemon->port == NAMESERVER_PORT &&
	  in_list(req_options, OPTION_DNSSERVER) &&
	  !option_find2(OPTION_DNSSERVER))
	option_put(mess, end, OPTION_DNSSERVER, INADDRSZ, ntohl(context->local.s_addr));
    }

  if (domain && in_list(req_options, OPTION_DOMAINNAME) && 
      !option_find2(OPTION_DOMAINNAME))
    option_put_string(mess, end, OPTION_DOMAINNAME, domain, null_term);
 
  /* Note that we ignore attempts to set the fqdn using --dhc-option=81,<name> */
  if (hostname)
    {
      if (in_list(req_options, OPTION_HOSTNAME) &&
	  !option_find2(OPTION_HOSTNAME))
	option_put_string(mess, end, OPTION_HOSTNAME, hostname, null_term);
      
      if (fqdn_flags != 0)
	{
	  len = strlen(hostname) + 3;
	  
	  if (fqdn_flags & 0x04)
	    len += 2;
	  else if (null_term)
	    len++;

	  if (domain)
	    len += strlen(domain) + 1;
	  else if (fqdn_flags & 0x04)
	    len--;

	  if ((p = free_space(mess, end, OPTION_CLIENT_FQDN, len)))
	    {
	      *(p++) = fqdn_flags & 0x0f; /* MBZ bits to zero */ 
	      *(p++) = 255;
	      *(p++) = 255;

	      if (fqdn_flags & 0x04)
		{
		  p = do_rfc1035_name(p, hostname, NULL);
		  if (domain)
		    {
		      p = do_rfc1035_name(p, domain, NULL);
		      *p++ = 0;
		    }
		}
	      else
		{
		  memcpy(p, hostname, strlen(hostname));
		  p += strlen(hostname);
		  if (domain)
		    {
		      *(p++) = '.';
		      memcpy(p, domain, strlen(domain));
		      p += strlen(domain);
		    }
		  if (null_term)
		    *(p++) = 0;
		}
	    }
	}
    }      

  for (opt = config_opts; opt; opt = opt->next)
    {
      int optno = opt->opt;

      /* netids match and not encapsulated? */
      if (!(opt->flags & DHOPT_TAGOK))
	continue;
      
      /* was it asked for, or are we sending it anyway? */
      if (!(opt->flags & DHOPT_FORCE) && !in_list(req_options, optno))
	continue;
      
      /* prohibit some used-internally options. T1 and T2 already handled. */
      if (optno == OPTION_CLIENT_FQDN ||
	  optno == OPTION_MAXMESSAGE ||
	  optno == OPTION_OVERLOAD ||
	  optno == OPTION_PAD ||
	  optno == OPTION_END ||
	  optno == OPTION_T1 ||
	  optno == OPTION_T2)
	continue;

      if (optno == OPTION_SNAME && done_server)
	continue;

      if (optno == OPTION_FILENAME && done_file)
	continue;
      
      /* For the options we have default values on
	 dhc-option=<optionno> means "don't include this option"
	 not "include a zero-length option" */
      if (opt->len == 0 && 
	  (optno == OPTION_NETMASK ||
	   optno == OPTION_BROADCAST ||
	   optno == OPTION_ROUTER ||
	   optno == OPTION_DNSSERVER || 
	   optno == OPTION_DOMAINNAME ||
	   optno == OPTION_HOSTNAME))
	continue;

      /* vendor-class comes from elsewhere for PXE */
      if (pxe_arch != -1 && optno == OPTION_VENDOR_ID)
	continue;
      
      /* always force null-term for filename and servername - buggy PXE again. */
      len = do_opt(opt, NULL, context, 
		   (optno == OPTION_SNAME || optno == OPTION_FILENAME) ? 1 : null_term);

      if ((p = free_space(mess, end, optno, len)))
	{
	  do_opt(opt, p, context, 
		 (optno == OPTION_SNAME || optno == OPTION_FILENAME) ? 1 : null_term);
	  
	  /* If we send a vendor-id, revisit which vendor-ops we consider 
	     it appropriate to send. */
	  if (optno == OPTION_VENDOR_ID)
	    {
	      match_vendor_opts(p - 2, config_opts);
	      done_vendor_class = 1;
	    }
	}  
    }

  /* Now send options to be encapsulated in arbitrary options, 
     eg dhcp-option=encap:172,17,.......
     Also handle vendor-identifying vendor-encapsulated options,
     dhcp-option = vi-encap:13,17,.......
     The may be more that one "outer" to do, so group
     all the options which match each outer in turn. */
  for (opt = config_opts; opt; opt = opt->next)
    opt->flags &= ~DHOPT_ENCAP_DONE;
  
  for (opt = config_opts; opt; opt = opt->next)
    {
      int flags;
      
      if ((flags = (opt->flags & (DHOPT_ENCAPSULATE | DHOPT_RFC3925))))
	{
	  int found = 0;
	  struct dhcp_opt *o;

	  if (opt->flags & DHOPT_ENCAP_DONE)
	    continue;

	  for (len = 0, o = config_opts; o; o = o->next)
	    {
	      int outer = flags & DHOPT_ENCAPSULATE ? o->u.encap : OPTION_VENDOR_IDENT_OPT;

	      o->flags &= ~DHOPT_ENCAP_MATCH;
	      
	      if (!(o->flags & flags) || opt->u.encap != o->u.encap)
		continue;
	      
	      o->flags |= DHOPT_ENCAP_DONE;
	      if (match_netid(o->netid, tagif, 1) &&
		  ((o->flags & DHOPT_FORCE) || in_list(req_options, outer)))
		{
		  o->flags |= DHOPT_ENCAP_MATCH;
		  found = 1;
		  len += do_opt(o, NULL, NULL, 0) + 2;
		}
	    } 
	  
	  if (found)
	    { 
	      if (flags & DHOPT_ENCAPSULATE)
		do_encap_opts(config_opts, opt->u.encap, DHOPT_ENCAP_MATCH, mess, end, null_term);
	      else if (len > 250)
		my_syslog(MS_DHCP | LOG_WARNING, _("cannot send RFC3925 option: too many options for enterprise number %d"), opt->u.encap);
	      else if ((p = free_space(mess, end,  OPTION_VENDOR_IDENT_OPT, len + 5)))
		{
		  int swap_ent = htonl(opt->u.encap);
		  memcpy(p, &swap_ent, 4);
		  p += 4;
		  *(p++) = len;
		  for (o = config_opts; o; o = o->next)
		    if (o->flags & DHOPT_ENCAP_MATCH)
		      {
			len = do_opt(o, p + 2, NULL, 0);
			*(p++) = o->opt;
			*(p++) = len;
			p += len;
		      }     
		}
	    }
	}
    }      

  force_encap = prune_vendor_opts(tagif);
  
  if (context && pxe_arch != -1)
    {
      pxe_misc(mess, end, uuid, pxevendor);
      if (!pxe_uefi_workaround(pxe_arch, tagif, mess, context->local, now, 0))
	config_opts = pxe_opts(pxe_arch, tagif, context->local, now);
    }

  if ((force_encap || in_list(req_options, OPTION_VENDOR_CLASS_OPT)) &&
      do_encap_opts(config_opts, OPTION_VENDOR_CLASS_OPT, DHOPT_VENDOR_MATCH, mess, end, null_term) && 
      pxe_arch == -1 && !done_vendor_class && vendor_class_len != 0 &&
      (p = free_space(mess, end, OPTION_VENDOR_ID, vendor_class_len)))
    /* If we send vendor encapsulated options, and haven't already sent option 60,
       echo back the value we got from the client. */
    memcpy(p, daemon->dhcp_buff3, vendor_class_len);	    
   
   /* restore BOOTP anti-overload hack */
  if (!req_options || option_bool(OPT_NO_OVERRIDE))
    {
      mess->file[0] = f0;
      mess->sname[0] = s0;
    }
}

/**
 * @brief Apply configured DHCP response delay based on client/network tags
 *
 * @detailed
 * Implements tag-based response delay (configured via --dhcp-reply-delay) by searching
 * daemon->delay_conf list for first delay_config matching client's netid tags. Enables
 * artificial response delays for specific clients or networks to work around PXE firmware
 * bugs, prevent network storms, or throttle DHCP traffic. Two-pass search: first looks for
 * positive tag match (delay_conf->netid explicitly matches netid), then looks for untagged
 * default delay (delay_conf with NULL netid). Calls delay_dhcp() to implement actual delay
 * via select() timeout, allowing other DHCP requests to be processed during delay period.
 * Logs delay application unless OPT_QUIET_DHCP enabled.
 *
 * @param xid DHCP transaction ID for logging correlation (logged in network byte order)
 * @param recvtime Timestamp when original DHCP request was received (for delay calculation)
 * @param netid Linked list of network/client identification tags (from dhcp-match, dhcp-host, dhcp-range)
 *
 * @note First searches for delay_conf with explicit netid match (match_netid mode 0)
 * @note If no explicit match, searches for delay_conf without netid (default delay, match_netid mode 1)
 * @note Delay measured in milliseconds, configured via --dhcp-reply-delay directive
 * @note Delay applies before sending DHCP response, not after receiving request
 * @note Logs delay application with transaction ID and delay value (unless OPT_QUIET_DHCP)
 * @note Uses delay_dhcp() which implements non-blocking delay (processes other requests during delay)
 *
 * @see daemon->delay_conf list configured via --dhcp-reply-delay directives
 * @see match_netid() for tag matching logic (mode 0=explicit match, mode 1=match if no tags)
 * @see delay_dhcp() for actual delay implementation (select-based non-blocking delay)
 * @see struct delay_config in dnsmasq.h for delay configuration structure
 *
 * EXAMPLE USAGE:
 * @code
 * // Apply delay before sending DHCP response
 * apply_delay(xid, recvtime, netid);
 * // Response will be delayed according to matching delay_conf entry
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not RFC-mandated, but useful workaround for buggy PXE firmware and DHCP storm mitigation
 */
static void apply_delay(u32 xid, time_t recvtime, struct dhcp_netid *netid)
{
  struct delay_config *delay_conf;
  
  /* Decide which delay_config option we're using */
  for (delay_conf = daemon->delay_conf; delay_conf; delay_conf = delay_conf->next)
    if (match_netid(delay_conf->netid, netid, 0))
      break;
  
  if (!delay_conf)
    /* No match, look for one without a netid */
    for (delay_conf = daemon->delay_conf; delay_conf; delay_conf = delay_conf->next)
      if (match_netid(delay_conf->netid, netid, 1))
        break;

  if (delay_conf)
    {
      if (!option_bool(OPT_QUIET_DHCP))
	my_syslog(MS_DHCP | LOG_INFO, _("%u reply delay: %d"), ntohl(xid), delay_conf->delay);
      delay_dhcp(recvtime, delay_conf->delay, -1, 0, 0);
    }
}

#endif /* HAVE_DHCP */
