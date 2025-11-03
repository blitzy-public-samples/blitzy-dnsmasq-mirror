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
 * @file rfc3315.c
 * @brief DHCPv6 protocol implementation per RFC 3315
 *
 * DETAILED PURPOSE:
 * This file implements the DHCPv6 server and relay agent functionality according to 
 * RFC 3315 (DHCPv6), RFC 3633 (Prefix Delegation), RFC 4361 (DUID client identifiers),
 * RFC 6939 (Client Link-Layer Address Option), and RFC 8415 (DHCPv6 bis). It handles
 * stateful DHCPv6 address allocation (IA_NA - Identity Association for Non-temporary
 * Addresses), temporary address allocation (IA_TA), prefix delegation (IA_PD), and
 * stateless configuration (INFORMATION-REQUEST). The implementation supports DHCPv6
 * relay forwarding/reply messages enabling multi-hop relay chains, and uses DUID-based
 * client identification instead of MAC addresses.
 *
 * The DHCPv6 message exchange typically follows a four-message pattern:
 * SOLICIT→ADVERTISE→REQUEST→REPLY for stateful address allocation, or a two-message
 * rapid commit exchange (SOLICIT→REPLY). Additional message types support lease
 * lifecycle: CONFIRM (address validation), RENEW (lease renewal from same server),
 * REBIND (lease renewal from any server), RELEASE (explicit lease termination), and
 * DECLINE (address conflict notification). The stateless mode uses INFORMATION-REQUEST
 * for configuration parameters without address allocation.
 *
 * Unlike DHCPv4, DHCPv6 uses TLV (Type-Length-Value) option encoding, supports multiple
 * IAs (Identity Associations) per client, and operates over link-local addresses or
 * through relay agents that provide link-address information for address pool selection.
 *
 * KEY RESPONSIBILITIES:
 * - dhcp6_reply() - Main entry point dispatching DHCPv6 messages by type (lines 71-104)
 * - dhcp6_maybe_relay() - Handle RELAY-FORW messages with recursive relay chain processing (lines 107-260)
 * - dhcp6_no_relay() - Process direct client messages: SOLICIT, REQUEST, CONFIRM, RENEW, REBIND, RELEASE, DECLINE, INFORMATION-REQUEST (lines 262-1104)
 * - check_ia() - Validate IA_NA/IA_TA/IA_PD options and extract address/prefix suboptions (lines 1107-1210)
 * - build_ia() - Construct IA response with allocated addresses/prefixes and T1/T2 timers (lines 1213-1437)
 * - add_address() - Allocate IPv6 address from context pool and create/update lease (lines 1575-1666)
 * - update_leases() - Update existing DHCPv6 lease database with renewed address bindings (lines 1669-1756)
 *
 * DEPENDENCIES:
 * - #include "dnsmasq.h" - Primary header with struct daemon, dhcp_context, dhcp_config, dhcp_lease
 * - #include "dhcp6-protocol.h" (via dnsmasq.h) - DHCPv6 message types (DHCP6SOLICIT, DHCP6ADVERTISE, etc.) and option codes (OPTION6_IA_NA, OPTION6_IAADDR, etc.)
 * - Called by: Network packet receive loop when DHCPv6 packet (port 547) arrives
 * - Calls: lease_find_by_client(), lease_update_from_configs(), log_packet(), option processing functions
 *
 * DATA STRUCTURES:
 * - struct state (lines 22-34) - Ephemeral per-request state tracking DUID, IA type, selected context, tags, MAC address, hostname, packet boundaries
 * - struct dhcp_context (dnsmasq.h) - Address/prefix pool configuration with start6/end6 range, preferred/valid lifetimes, network matching
 * - struct dhcp_config (dnsmasq.h) - Static client reservations by DUID with fixed addresses and options
 * - struct dhcp_lease (dnsmasq.h) - Persistent lease database entry with CLID (DUID), IAID, IPv6 address, expiry time
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP6 (mandatory) - Entire file conditionally compiled only if DHCPv6 support enabled
 * - HAVE_SCRIPT - Enables lease-change script execution via helper process
 * - HAVE_BROKEN_RTC - Adjusts lease expiry handling for systems without real-time clock
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Function is called from main event loop poll()
 * when DHCPv6 packet arrives on UDP port 547. Not reentrant - uses global daemon->dhcp_packet
 * buffer and daemon->outpacket for reply construction. State passed via stack-allocated
 * struct state, no persistent per-request state between calls.
 *
 * RFC COMPLIANCE:
 * - RFC 3315: DHCPv6 core protocol (message types, option format, DUID, IA_NA/IA_TA)
 * - RFC 3633: IPv6 Prefix Delegation (IA_PD, IAPREFIX options)
 * - RFC 4361: DUID definition and format (DUID-LLT, DUID-EN, DUID-LL)
 * - RFC 6939: Client Link-Layer Address Option (OPTION6_CLIENT_MAC in relay messages)
 * - RFC 8415: DHCPv6 bis (updated DHCPv6 specification incorporating errata)
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DHCP_V6.md for complete DHCPv6 architecture and state machine documentation
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

/**
 * @struct state
 * @brief Ephemeral per-request DHCPv6 transaction state
 *
 * Tracks all information needed to process a single DHCPv6 request/reply cycle.
 * This structure is stack-allocated for each incoming DHCPv6 message and destroyed
 * after reply transmission. It consolidates client identification (DUID), network
 * context selection, option parsing boundaries, and accumulated tags for conditional
 * configuration matching.
 *
 * LIFECYCLE:
 * - Allocated: Stack allocation in dhcp6_reply() for each incoming DHCPv6 packet
 * - Initialized: Members set to NULL/0, then populated during dhcp6_maybe_relay() and dhcp6_no_relay()
 * - Used: Passed by pointer through entire DHCPv6 processing pipeline
 * - Destroyed: Automatic deallocation on function return (stack variable)
 *
 * MEMORY LAYOUT:
 * Total size approximately 100-120 bytes depending on pointer size. Contains pointers
 * to packet data (clid, packet_options, end), allocated strings (hostname, domain),
 * and embedded MAC address array. No dynamic allocation within struct itself.
 *
 * USAGE PATTERNS:
 * Always accessed via pointer (struct state *state). Modified throughout request
 * processing to accumulate client information, selected address pools, and configuration
 * tags. The link_address field is particularly critical for relay agent scenarios,
 * pointing to the innermost relay's link-address for pool selection.
 */
struct state {
  unsigned char *clid;           /**< Client DUID (DHCPv6 Unique Identifier), extracted from OPTION6_CLIENT_ID */
  int clid_len;                  /**< Length of DUID in bytes (variable length per RFC 3315 Section 9) */
  int ia_type;                   /**< Identity Association type: OPTION6_IA_NA (non-temporary), OPTION6_IA_TA (temporary), or OPTION6_IA_PD (prefix delegation) */
  int interface;                 /**< Receiving interface index for packet arrival interface */
  int hostname_auth;             /**< Boolean: client-provided hostname authenticated/authorized for DNS updates */
  int lease_allocate;            /**< Boolean: whether new lease allocation occurred (vs renewal) */
  char *client_hostname;         /**< Hostname supplied by client in OPTION6_FQDN */
  char *hostname;                /**< Resolved/validated hostname to use for this client */
  char *domain;                  /**< Domain name for FQDN construction */
  char *send_domain;             /**< Domain to send in OPTION6_DOMAIN_SEARCH reply */
  struct dhcp_context *context;  /**< Selected address pool/context for allocation, linked list of applicable contexts */
  struct in6_addr *link_address; /**< Link address from relay agent (innermost RELAY-FORW), used for pool selection */
  struct in6_addr *fallback;     /**< Fallback address for replies when client address unknown */
  struct in6_addr *ll_addr;      /**< Link-local address of receiving interface */
  struct in6_addr *ula_addr;     /**< Unique Local Address (ULA) of receiving interface */
  unsigned int xid;              /**< Transaction ID (24-bit) from DHCPv6 message header */
  unsigned int fqdn_flags;       /**< FQDN option flags controlling server DNS update behavior */
  unsigned int iaid;             /**< Identity Association Identifier from IA_NA/IA_TA/IA_PD option */
  char *iface_name;              /**< Interface name string (e.g., "eth0") for logging and tag matching */
  void *packet_options;          /**< Start of DHCPv6 options in request packet (after 4-byte header) */
  void *end;                     /**< End boundary of request packet for bounds checking */
  struct dhcp_netid *tags;       /**< Linked list of accumulated tags for conditional configuration matching */
  struct dhcp_netid *context_tags; /**< Tags derived from selected dhcp_context */
  unsigned char mac[DHCP_CHADDR_MAX]; /**< Client MAC address from OPTION6_CLIENT_MAC (RFC 6939) or local ND cache */
  unsigned int mac_len;          /**< Length of MAC address in bytes (typically 6 for Ethernet) */
  unsigned int mac_type;         /**< Hardware type code (RFC 826): 1=Ethernet, 6=IEEE 802 */
};

/* Forward declarations for static helper functions */
static int dhcp6_maybe_relay(struct state *state, unsigned char *inbuff, size_t sz, 
			     struct in6_addr *client_addr, int is_unicast, time_t now);
static int dhcp6_no_relay(struct state *state, int msg_type, unsigned char *inbuff, size_t sz, int is_unicast, time_t now);
static void log6_opts(int nest, unsigned int xid, void *start_opts, void *end_opts);
static void log6_packet(struct state *state, char *type, struct in6_addr *addr, char *string);
static void log6_quiet(struct state *state, char *type, struct in6_addr *addr, char *string);
static void *opt6_find (void *opts, void *end, unsigned int search, unsigned int minsize);
static void *opt6_next(void *opts, void *end);
static unsigned int opt6_uint(unsigned char *opt, int offset, int size);
static void get_context_tag(struct state *state, struct dhcp_context *context);
static int check_ia(struct state *state, void *opt, void **endp, void **ia_option);
static int build_ia(struct state *state, int *t1cntr);
static void end_ia(int t1cntr, unsigned int min_time, int do_fuzz);
static void mark_context_used(struct state *state, struct in6_addr *addr);
static void mark_config_used(struct dhcp_context *context, struct in6_addr *addr);
static int check_address(struct state *state, struct in6_addr *addr);
static int config_valid(struct dhcp_config *config, struct dhcp_context *context, struct in6_addr *addr, struct state *state, time_t now);
static struct addrlist *config_implies(struct dhcp_config *config, struct dhcp_context *context, struct in6_addr *addr);
static void add_address(struct state *state, struct dhcp_context *context, unsigned int lease_time, void *ia_option, 
			unsigned int *min_time, struct in6_addr *addr, time_t now);
static void update_leases(struct state *state, struct dhcp_context *context, struct in6_addr *addr, unsigned int lease_time, time_t now);
static int add_local_addrs(struct dhcp_context *context);
static struct dhcp_netid *add_options(struct state *state, int do_refresh);
static void calculate_times(struct dhcp_context *context, unsigned int *min_time, unsigned int *valid_timep, 
			    unsigned int *preferred_timep, unsigned int lease_time);

/**
 * @def opt6_len
 * @brief Extract length field from DHCPv6 option
 * Accesses 2 bytes before option data to read TLV length field.
 */
#define opt6_len(opt) ((int)(opt6_uint(opt, -2, 2)))

/**
 * @def opt6_type
 * @brief Extract type field from DHCPv6 option
 * Accesses 4 bytes before option data to read TLV type field.
 */
#define opt6_type(opt) (opt6_uint(opt, -4, 2))

/**
 * @def opt6_ptr
 * @brief Get pointer to option data at offset i
 * Skips 4-byte TLV header (2-byte type + 2-byte length) to access value.
 */
#define opt6_ptr(opt, i) ((void *)&(((unsigned char *)(opt))[4+(i)]))

/**
 * @def opt6_user_vendor_ptr
 * @brief Get pointer to user/vendor option data at offset i
 * Uses 2-byte header offset for nested vendor-specific options.
 */
#define opt6_user_vendor_ptr(opt, i) ((void *)&(((unsigned char *)(opt))[2+(i)]))

/**
 * @def opt6_user_vendor_len
 * @brief Extract length from user/vendor option
 * Reads length field with 4-byte offset for vendor option structures.
 */
#define opt6_user_vendor_len(opt) ((int)(opt6_uint(opt, -4, 2)))

/**
 * @def opt6_user_vendor_next
 * @brief Advance to next user/vendor option
 * Adjusts pointer 2 bytes back before calling opt6_next() for proper alignment.
 */
#define opt6_user_vendor_next(opt, end) (opt6_next(((void *) opt) - 2, end))
 

/**
 * @brief Main DHCPv6 packet handler and request dispatcher
 *
 * Primary entry point for all incoming DHCPv6 packets received on UDP port 547.
 * Determines packet type (relay vs direct client message), initializes per-request
 * state structure, and delegates to dhcp6_maybe_relay() for relay processing or
 * message-type-specific handling. Returns destination port number for reply routing:
 * DHCPV6_SERVER_PORT (547) for relay replies, DHCPV6_CLIENT_PORT (546) for direct
 * client replies, or 0 for packet rejection/drop.
 *
 * @param context Initial address pool context list from receiving interface configuration
 * @param interface Interface index where packet arrived (for get_client_mac() ND cache lookup)
 * @param iface_name Interface name string (e.g., "eth0") for logging and tag-based configuration
 * @param fallback Fallback source address for replies when client address cannot be determined
 * @param ll_addr Link-local address of receiving interface for preference calculation
 * @param ula_addr Unique Local Address of receiving interface for ULA-only client support
 * @param sz Packet size in bytes from recvmsg(), must be >4 to contain message type
 * @param client_addr Source IPv6 address from packet (multicast or unicast)
 * @param now Current time_t for lease expiry calculations and timestamp logging
 *
 * @return Destination port for reply: DHCPV6_SERVER_PORT (547) for relay agent replies,
 *         DHCPV6_CLIENT_PORT (546) for direct client replies, 0 for packet drop (invalid/ignored)
 *
 * @note Packet data accessed via global daemon->dhcp_packet.iov_base buffer, reply constructed
 *       in daemon->outpacket. Both buffers owned by caller in main event loop.
 * @warning Not reentrant - modifies global vendor->netid.next pointers to prevent duplicate
 *          vendor matching. Must be serialized by event loop.
 *
 * @see dhcp6_maybe_relay() for relay agent forwarding logic
 * @see dhcp6_no_relay() for direct message type handling (SOLICIT, REQUEST, RENEW, etc.)
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client, ll, ula, fallback;
 * unsigned short dest_port = dhcp6_reply(daemon->dhcp6, if_index, "eth0", 
 *                                         &fallback, &ll, &ula, packet_len, &client, time(NULL));
 * if (dest_port) send_reply_to_port(dest_port);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 15: Message type determination and relay detection
 * - RFC 3315 Section 20: Server message processing overview
 *
 * SIDE EFFECTS:
 * - Initializes daemon option counter via reset_counter()
 * - Modifies vendor->netid.next for all daemon->dhcp_vendors (reset on each call)
 * - May construct reply in daemon->outpacket buffer via recursive relay/message processing
 *
 * THREAD SAFETY:
 * Not thread-safe. Relies on single-threaded event loop guaranteeing serialized packet
 * processing. Access to global daemon structure and vendor list not protected by locks.
 */
unsigned short dhcp6_reply(struct dhcp_context *context, int interface, char *iface_name,
			   struct in6_addr *fallback,  struct in6_addr *ll_addr, struct in6_addr *ula_addr,
			   size_t sz, struct in6_addr *client_addr, time_t now)
{
  struct dhcp_vendor *vendor;
  int msg_type;
  struct state state;
  
  if (sz <= 4)
    return 0;
  
  msg_type = *((unsigned char *)daemon->dhcp_packet.iov_base);
  
  /* Mark these so we only match each at most once, to avoid tangled linked lists */
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    vendor->netid.next = &vendor->netid;
  
  reset_counter();
  state.context = context;
  state.interface = interface;
  state.iface_name = iface_name;
  state.fallback = fallback;
  state.ll_addr = ll_addr;
  state.ula_addr = ula_addr;
  state.mac_len = 0;
  state.tags = NULL;
  state.link_address = NULL;

  if (dhcp6_maybe_relay(&state, daemon->dhcp_packet.iov_base, sz, client_addr, 
			IN6_IS_ADDR_MULTICAST(client_addr), now))
    return msg_type == DHCP6RELAYFORW ? DHCPV6_SERVER_PORT : DHCPV6_CLIENT_PORT;

  return 0;
}

/**
 * @brief Process DHCPv6 relay agent messages with recursive relay chain handling
 *
 * Handles RELAY-FORW (relay forward) messages from DHCPv6 relay agents per RFC 3315
 * Section 20.1, recursively unwrapping nested relay encapsulation to extract the
 * innermost client message. Constructs RELAY-REPL (relay reply) with preserved relay
 * options and encapsulated server response. If message is not RELAY-FORW, delegates
 * to dhcp6_no_relay() for direct client message processing. The link-address from the
 * innermost relay determines address pool selection for network topology awareness.
 *
 * Original author's warning comment preserved: "This cost me blood to write, it will
 * probably cost you blood to understand - srk." The complexity arises from recursive
 * relay chain traversal, careful pointer arithmetic for TLV parsing, and maintaining
 * both request and reply packet structures simultaneously.
 *
 * @param state Per-request state structure, modified to set state->link_address to
 *              innermost relay's link-address field for pool selection. Also accumulates
 *              vendor tags from OPTION6_SUBSCRIBER_ID and OPTION6_REMOTE_ID relay options.
 * @param inbuff Input packet buffer starting at message-type byte (not necessarily
 *               daemon->dhcp_packet, may be recursively unwrapped RELAY_MSG option)
 * @param sz Size of inbuff in bytes, must be >=38 for RELAY-FORW minimum size
 * @param client_addr Source address for final reply routing (from outermost packet)
 * @param is_unicast Boolean: true if client sent to server unicast (forbidden for
 *                   some message types per RFC 3315 Section 15), false for multicast
 * @param now Current time_t for lease operations
 *
 * @return 1 if packet processed successfully (reply constructed in daemon->outpacket),
 *         0 if packet invalid/rejected/no-address-range-available (no reply sent)
 *
 * @note Recursively calls itself when processing nested RELAY-FORW messages found in
 *       OPTION6_RELAY_MSG, unwrapping up to maximum relay hop count.
 * @warning Modifies state->link_address pointer to reference aligned copy of relay's
 *          link-address field. Pointer only valid during request processing lifetime.
 *
 * @see dhcp6_no_relay() for actual message type handling after relay unwrapping
 * @see opt6_find() for TLV option searching in relay options
 *
 * EXAMPLE USAGE:
 * @code
 * struct state state = {0};
 * if (dhcp6_maybe_relay(&state, packet_data, packet_len, &src_addr, is_multicast, now)) {
 *     // Reply constructed, send daemon->outpacket buffer
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 20.1: Relay-forward message processing
 * - RFC 3315 Section 20.3: Constructing relay-reply messages
 * - RFC 6939 Section 4: Client Link-Layer Address Option in relay messages
 *
 * SIDE EFFECTS:
 * - Writes RELAY-REPL header to daemon->outpacket via put_opt6()
 * - Copies relay options to reply packet (except OPTION6_CLIENT_MAC filtered out)
 * - Modifies state->tags by prepending vendor netid tags for matching relay options
 * - Recalculates state->context if state->link_address indicates different network segment
 *
 * THREAD SAFETY:
 * Not thread-safe. Uses global daemon structures and modifies vendor netid chains.
 * Must be called from single-threaded event loop context.
 */
/* This cost me blood to write, it will probably cost you blood to understand - srk. */
static int dhcp6_maybe_relay(struct state *state, unsigned char *inbuff, size_t sz, 
			     struct in6_addr *client_addr, int is_unicast, time_t now)
{
  void *end = inbuff + sz;
  void *opts = inbuff + 34;
  int msg_type = *inbuff;
  unsigned char *outmsgtypep;
  void *opt;
  struct dhcp_vendor *vendor;

  /* if not an encapsulated relayed message, just do the stuff */
  if (msg_type != DHCP6RELAYFORW)
    {
      /* if link_address != NULL if points to the link address field of the 
	 innermost nested RELAYFORW message, which is where we find the
	 address of the network on which we can allocate an address.
	 Recalculate the available contexts using that information. 

      link_address == NULL means there's no relay in use, so we try and find the client's 
      MAC address from the local ND cache. */
      
      if (!state->link_address)
	get_client_mac(client_addr, state->interface, state->mac, &state->mac_len, &state->mac_type, now);
      else
	{
	  struct dhcp_context *c;
	  struct shared_network *share = NULL;
	  state->context = NULL;

	  if (!IN6_IS_ADDR_LOOPBACK(state->link_address) &&
	      !IN6_IS_ADDR_LINKLOCAL(state->link_address) &&
	      !IN6_IS_ADDR_MULTICAST(state->link_address))
	    for (c = daemon->dhcp6; c; c = c->next)
	      {
		for (share = daemon->shared_networks; share; share = share->next)
		  {
		    if (share->shared_addr.s_addr != 0)
		      continue;
		    
		    if (share->if_index != 0 ||
			!IN6_ARE_ADDR_EQUAL(state->link_address, &share->match_addr6))
		      continue;
		    
		    if ((c->flags & CONTEXT_DHCP) &&
			!(c->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
			is_same_net6(&share->shared_addr6, &c->start6, c->prefix) &&
			is_same_net6(&share->shared_addr6, &c->end6, c->prefix))
		      break;
		  }
		
		if (share ||
		    ((c->flags & CONTEXT_DHCP) &&
		     !(c->flags & (CONTEXT_TEMPLATE | CONTEXT_OLD)) &&
		     is_same_net6(state->link_address, &c->start6, c->prefix) &&
		     is_same_net6(state->link_address, &c->end6, c->prefix)))
		  {
		    c->preferred = c->valid = 0xffffffff;
		    c->current = state->context;
		    state->context = c;
		  }
	      }
	  
	  if (!state->context)
	    {
	      inet_ntop(AF_INET6, state->link_address, daemon->addrbuff, ADDRSTRLEN); 
	      my_syslog(MS_DHCP | LOG_WARNING, 
			_("no address range available for DHCPv6 request from relay at %s"),
			daemon->addrbuff);
	      return 0;
	    }
	}
	  
      if (!state->context)
	{
	  my_syslog(MS_DHCP | LOG_WARNING, 
		    _("no address range available for DHCPv6 request via %s"), state->iface_name);
	  return 0;
	}

      return dhcp6_no_relay(state, msg_type, inbuff, sz, is_unicast, now);
    }

  /* must have at least msg_type+hopcount+link_address+peer_address+minimal size option
     which is               1   +    1   +    16      +     16     + 2 + 2 = 38 */
  if (sz < 38)
    return 0;
  
  /* copy header stuff into reply message and set type to reply */
  if (!(outmsgtypep = put_opt6(inbuff, 34)))
    return 0;
  *outmsgtypep = DHCP6RELAYREPL;

  /* look for relay options and set tags if found. */
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    {
      int mopt;
      
      if (vendor->match_type == MATCH_SUBSCRIBER)
	mopt = OPTION6_SUBSCRIBER_ID;
      else if (vendor->match_type == MATCH_REMOTE)
	mopt = OPTION6_REMOTE_ID; 
      else
	continue;

      if ((opt = opt6_find(opts, end, mopt, 1)) &&
	  vendor->len == opt6_len(opt) &&
	  memcmp(vendor->data, opt6_ptr(opt, 0), vendor->len) == 0 &&
	  vendor->netid.next != &vendor->netid)
	{
	  vendor->netid.next = state->tags;
	  state->tags = &vendor->netid;
	  break;
	}
    }
  
  /* RFC-6939 */
  if ((opt = opt6_find(opts, end, OPTION6_CLIENT_MAC, 3)))
    {
      if (opt6_len(opt) - 2 > DHCP_CHADDR_MAX) {
        return 0;
      }
      state->mac_type = opt6_uint(opt, 0, 2);
      state->mac_len = opt6_len(opt) - 2;
      memcpy(&state->mac[0], opt6_ptr(opt, 2), state->mac_len);
    }
  
  for (opt = opts; opt; opt = opt6_next(opt, end))
    {
      if (opt6_ptr(opt, 0) + opt6_len(opt) > end) 
        return 0;
     
      /* Don't copy MAC address into reply. */
      if (opt6_type(opt) != OPTION6_CLIENT_MAC)
	{
	  int o = new_opt6(opt6_type(opt));
	  if (opt6_type(opt) == OPTION6_RELAY_MSG)
	    {
	      struct in6_addr align;
	      /* the packet data is unaligned, copy to aligned storage */
	      memcpy(&align, inbuff + 2, IN6ADDRSZ); 
	      state->link_address = &align;
	      /* zero is_unicast since that is now known to refer to the 
		 relayed packet, not the original sent by the client */
	      if (!dhcp6_maybe_relay(state, opt6_ptr(opt, 0), opt6_len(opt), client_addr, 0, now))
		return 0;
	    }
	  else
	    put_opt6(opt6_ptr(opt, 0), opt6_len(opt));
	  end_opt6(o);
	}
    }
  
  return 1;
}

/**
 * @brief Process direct client DHCPv6 messages by message type
 *
 * Handles non-relay DHCPv6 messages from clients including SOLICIT (discover available
 * servers), ADVERTISE (server availability announcement - not received by server),
 * REQUEST (request specific addresses/prefixes), CONFIRM (address validation after
 * network change), RENEW (lease renewal from original server), REBIND (lease renewal
 * from any server), RELEASE (explicit lease termination), DECLINE (address conflict
 * notification), and INFORMATION-REQUEST (stateless configuration). Validates message
 * structure, extracts CLIENT-ID and SERVER-ID, processes vendor/user class options for
 * tag-based configuration, and dispatches to appropriate handler logic for each message
 * type. Constructs REPLY or ADVERTISE response in daemon->outpacket.
 *
 * This function implements the core DHCPv6 server state machine transitions per RFC 3315
 * Section 15 and 18, handling client lifecycle from initial address discovery through
 * renewal and release. It enforces RFC requirements such as rejecting unicast messages
 * when multicast required, validating SERVER-ID matches for non-SOLICIT messages, and
 * including mandatory options in replies.
 *
 * @param state Per-request state structure with context, interface, tags initialized
 *              by caller. Modified to populate clid, xid, mac, hostname, config.
 * @param msg_type DHCPv6 message type from packet header: DHCP6SOLICIT, DHCP6REQUEST,
 *                 DHCP6CONFIRM, DHCP6RENEW, DHCP6REBIND, DHCP6RELEASE, DHCP6DECLINE,
 *                 or DHCP6IREQ (INFORMATION-REQUEST). Type determines response behavior.
 * @param inbuff Packet buffer starting at message-type byte (after relay unwrapping if
 *               relayed), contains transaction-id and options.
 * @param sz Size of inbuff in bytes
 * @param is_unicast Boolean: true if message sent to server unicast address (triggers
 *                   UseMulticast status code for REQUEST/RENEW/RELEASE/DECLINE per
 *                   RFC 3315 Section 18.2.1)
 * @param now Current time_t for lease expiry calculations
 *
 * @return 1 if reply constructed successfully in daemon->outpacket (send to client),
 *         0 if message invalid/ignored (missing CLIENT-ID, wrong SERVER-ID, no ranges)
 *
 * @note Expects CLIENT-ID option (OPTION6_CLIENT_ID) in all messages except INFORMATION-REQUEST.
 *       Missing CLIENT-ID causes silent packet drop per RFC 3315 Section 15.
 * @warning Implements RFC 3315 Section 18.2.1 unicast rejection: REQUEST, RENEW, RELEASE,
 *          DECLINE sent unicast receive REPLY with UseMulticast status instead of processing.
 *
 * @see check_ia() for IA_NA/IA_TA/IA_PD validation and address extraction
 * @see build_ia() for IA response construction with allocated addresses
 * @see add_options() for DHCPv6 option construction (DNS servers, domain search, etc.)
 *
 * EXAMPLE USAGE:
 * @code
 * struct state state = {.context = daemon->dhcp6, .interface = if_idx};
 * int msg_type = inbuff[0];
 * if (dhcp6_no_relay(&state, msg_type, inbuff, packet_len, is_unicast, now)) {
 *     send_packet(daemon->outpacket, outpacket_len, &client_addr);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 15: Message validation requirements
 * - RFC 3315 Section 17-18: Server message processing by type
 * - RFC 3315 Section 18.2.1: UseMulticast status code for incorrectly unicast messages
 * - RFC 4361: DUID-based client identification instead of MAC addresses
 *
 * SIDE EFFECTS:
 * - Constructs full REPLY or ADVERTISE message in daemon->outpacket via new_opt6/put_opt6
 * - Allocates/updates leases in global daemon->dhcp_lease_db via add_address/update_leases
 * - Logs message processing to syslog via log6_packet() if logging enabled
 * - May invoke lease-change scripts via helper process
 * - Modifies state->tags by prepending interface and "dhcpv6" tags for conditional config
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->outpacket buffer and lease database. Must
 * be serialized by single-threaded event loop.
 */
static int dhcp6_no_relay(struct state *state, int msg_type, unsigned char *inbuff, size_t sz, int is_unicast, time_t now)
{
  void *opt;
  int i, o, o1, start_opts, start_msg;
  struct dhcp_opt *opt_cfg;
  struct dhcp_netid *tagif;
  struct dhcp_config *config = NULL;
  struct dhcp_netid known_id, iface_id, v6_id;
  unsigned char outmsgtype;
  struct dhcp_vendor *vendor;
  struct dhcp_context *context_tmp;
  struct dhcp_mac *mac_opt;
  unsigned int ignore = 0;

  state->packet_options = inbuff + 4;
  state->end = inbuff + sz;
  state->clid = NULL;
  state->clid_len = 0;
  state->lease_allocate = 0;
  state->context_tags = NULL;
  state->domain = NULL;
  state->send_domain = NULL;
  state->hostname_auth = 0;
  state->hostname = NULL;
  state->client_hostname = NULL;
  state->fqdn_flags = 0x01; /* default to send if we receive no FQDN option */

  /* set tag with name == interface */
  iface_id.net = state->iface_name;
  iface_id.next = state->tags;
  state->tags = &iface_id; 

  /* set tag "dhcpv6" */
  v6_id.net = "dhcpv6";
  v6_id.next = state->tags;
  state->tags = &v6_id;

  start_msg = save_counter(-1);
  /* copy over transaction-id */
  if (!put_opt6(inbuff, 4))
    return 0;
  start_opts = save_counter(-1);
  state->xid = inbuff[3] | inbuff[2] << 8 | inbuff[1] << 16;
    
  /* We're going to be linking tags from all context we use. 
     mark them as unused so we don't link one twice and break the list */
  for (context_tmp = state->context; context_tmp; context_tmp = context_tmp->current)
    {
      context_tmp->netid.next = &context_tmp->netid;

      if (option_bool(OPT_LOG_OPTS))
	{
	   inet_ntop(AF_INET6, &context_tmp->start6, daemon->dhcp_buff, ADDRSTRLEN); 
	   inet_ntop(AF_INET6, &context_tmp->end6, daemon->dhcp_buff2, ADDRSTRLEN); 
	   if (context_tmp->flags & (CONTEXT_STATIC))
	     my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCPv6 subnet: %s/%d"),
		       state->xid, daemon->dhcp_buff, context_tmp->prefix);
	   else
	     my_syslog(MS_DHCP | LOG_INFO, _("%u available DHCP range: %s -- %s"), 
		       state->xid, daemon->dhcp_buff, daemon->dhcp_buff2);
	}
    }

  if ((opt = opt6_find(state->packet_options, state->end, OPTION6_CLIENT_ID, 1)))
    {
      state->clid = opt6_ptr(opt, 0);
      state->clid_len = opt6_len(opt);
      o = new_opt6(OPTION6_CLIENT_ID);
      put_opt6(state->clid, state->clid_len);
      end_opt6(o);
    }
  else if (msg_type != DHCP6IREQ)
    return 0;

  /* server-id must match except for SOLICIT, CONFIRM and REBIND messages */
  if (msg_type != DHCP6SOLICIT && msg_type != DHCP6CONFIRM && msg_type != DHCP6IREQ && msg_type != DHCP6REBIND &&
      (!(opt = opt6_find(state->packet_options, state->end, OPTION6_SERVER_ID, 1)) ||
       opt6_len(opt) != daemon->duid_len ||
       memcmp(opt6_ptr(opt, 0), daemon->duid, daemon->duid_len) != 0))
    return 0;
  
  o = new_opt6(OPTION6_SERVER_ID);
  put_opt6(daemon->duid, daemon->duid_len);
  end_opt6(o);

  if (is_unicast &&
      (msg_type == DHCP6REQUEST || msg_type == DHCP6RENEW || msg_type == DHCP6RELEASE || msg_type == DHCP6DECLINE))
    
    {  
      outmsgtype = DHCP6REPLY;
      o1 = new_opt6(OPTION6_STATUS_CODE);
      put_opt6_short(DHCP6USEMULTI);
      put_opt6_string("Use multicast");
      end_opt6(o1);
      return 1;
    }

  /* match vendor and user class options */
  for (vendor = daemon->dhcp_vendors; vendor; vendor = vendor->next)
    {
      int mopt;
      
      if (vendor->match_type == MATCH_VENDOR)
	mopt = OPTION6_VENDOR_CLASS;
      else if (vendor->match_type == MATCH_USER)
	mopt = OPTION6_USER_CLASS; 
      else
	continue;

      if ((opt = opt6_find(state->packet_options, state->end, mopt, 2)))
	{
	  void *enc_opt, *enc_end = opt6_ptr(opt, opt6_len(opt));
	  int offset = 0;
	  
	  if (mopt == OPTION6_VENDOR_CLASS)
	    {
	      if (opt6_len(opt) < 4)
		continue;
	      
	      if (vendor->enterprise != opt6_uint(opt, 0, 4))
		continue;
	    
	      offset = 4;
	    }
 
	  /* Note that format if user/vendor classes is different to DHCP options - no option types. */
	  for (enc_opt = opt6_ptr(opt, offset); enc_opt; enc_opt = opt6_user_vendor_next(enc_opt, enc_end))
	    for (i = 0; i <= (opt6_user_vendor_len(enc_opt) - vendor->len); i++)
	      if (memcmp(vendor->data, opt6_user_vendor_ptr(enc_opt, i), vendor->len) == 0)
		{
		  vendor->netid.next = state->tags;
		  state->tags = &vendor->netid;
		  break;
		}
	}
    }

  if (option_bool(OPT_LOG_OPTS) && (opt = opt6_find(state->packet_options, state->end, OPTION6_VENDOR_CLASS, 4)))
    my_syslog(MS_DHCP | LOG_INFO, _("%u vendor class: %u"), state->xid, opt6_uint(opt, 0, 4));
  
  /* dhcp-match. If we have hex-and-wildcards, look for a left-anchored match.
     Otherwise assume the option is an array, and look for a matching element. 
     If no data given, existence of the option is enough. This code handles 
     V-I opts too. */
  for (opt_cfg = daemon->dhcp_match6; opt_cfg; opt_cfg = opt_cfg->next)
    {
      int match = 0;
      
      if (opt_cfg->flags & DHOPT_RFC3925)
	{
	  for (opt = opt6_find(state->packet_options, state->end, OPTION6_VENDOR_OPTS, 4);
	       opt;
	       opt = opt6_find(opt6_next(opt, state->end), state->end, OPTION6_VENDOR_OPTS, 4))
	    {
	      void *vopt;
	      void *vend = opt6_ptr(opt, opt6_len(opt));
	      
	      for (vopt = opt6_find(opt6_ptr(opt, 4), vend, opt_cfg->opt, 0);
		   vopt;
		   vopt = opt6_find(opt6_next(vopt, vend), vend, opt_cfg->opt, 0))
		if ((match = match_bytes(opt_cfg, opt6_ptr(vopt, 0), opt6_len(vopt))))
		  break;
	    }
	  if (match)
	    break;
	}
      else
	{
	  if (!(opt = opt6_find(state->packet_options, state->end, opt_cfg->opt, 1)))
	    continue;
	  
	  match = match_bytes(opt_cfg, opt6_ptr(opt, 0), opt6_len(opt));
	} 
  
      if (match)
	{
	  opt_cfg->netid->next = state->tags;
	  state->tags = opt_cfg->netid;
	}
    }

  if (state->mac_len != 0)
    {
      if (option_bool(OPT_LOG_OPTS))
	{
	  print_mac(daemon->dhcp_buff, state->mac, state->mac_len);
	  my_syslog(MS_DHCP | LOG_INFO, _("%u client MAC address: %s"), state->xid, daemon->dhcp_buff);
	}

      for (mac_opt = daemon->dhcp_macs; mac_opt; mac_opt = mac_opt->next)
	if ((unsigned)mac_opt->hwaddr_len == state->mac_len &&
	    ((unsigned)mac_opt->hwaddr_type == state->mac_type || mac_opt->hwaddr_type == 0) &&
	    memcmp_masked(mac_opt->hwaddr, state->mac, state->mac_len, mac_opt->mask))
	  {
	    mac_opt->netid.next = state->tags;
	    state->tags = &mac_opt->netid;
	  }
    }
  
  if ((opt = opt6_find(state->packet_options, state->end, OPTION6_FQDN, 1)))
    {
      /* RFC4704 refers */
       int len = opt6_len(opt) - 1;
       
       state->fqdn_flags = opt6_uint(opt, 0, 1);
       
       /* Always force update, since the client has no way to do it itself. */
       if (!option_bool(OPT_FQDN_UPDATE) && !(state->fqdn_flags & 0x01))
	 state->fqdn_flags |= 0x03;
 
       state->fqdn_flags &= ~0x04;

       if (len != 0 && len < 255)
	 {
	   unsigned char *pp, *op = opt6_ptr(opt, 1);
	   char *pq = daemon->dhcp_buff;
	   
	   pp = op;
	   while (*op != 0 && ((op + (*op)) - pp) < len)
	     {
	       memcpy(pq, op+1, *op);
	       pq += *op;
	       op += (*op)+1;
	       *(pq++) = '.';
	     }
	   
	   if (pq != daemon->dhcp_buff)
	     pq--;
	   *pq = 0;
	   
	   if (legal_hostname(daemon->dhcp_buff))
	     {
	       struct dhcp_match_name *m;
	       size_t nl = strlen(daemon->dhcp_buff);
	       
	       state->client_hostname = daemon->dhcp_buff;
	       
	       if (option_bool(OPT_LOG_OPTS))
		 my_syslog(MS_DHCP | LOG_INFO, _("%u client provides name: %s"), state->xid, state->client_hostname);
	       
	       for (m = daemon->dhcp_name_match; m; m = m->next)
		 {
		   size_t ml = strlen(m->name);
		   char save = 0;
		   
		   if (nl < ml)
		     continue;
		   if (nl > ml)
		     {
		       save = state->client_hostname[ml];
		       state->client_hostname[ml] = 0;
		     }
		   
		   if (hostname_isequal(state->client_hostname, m->name) &&
		       (save == 0 || m->wildcard))
		     {
		       m->netid->next = state->tags;
		       state->tags = m->netid;
		     }
		   
		   if (save != 0)
		     state->client_hostname[ml] = save;
		 }
	     }
	 }
    }	 
  
  if (state->clid &&
      (config = find_config(daemon->dhcp_conf, state->context, state->clid, state->clid_len,
			    state->mac, state->mac_len, state->mac_type, NULL, run_tag_if(state->tags))) &&
      have_config(config, CONFIG_NAME))
    {
      state->hostname = config->hostname;
      state->domain = config->domain;
      state->hostname_auth = 1;
    }
  else if (state->client_hostname)
    {
      state->domain = strip_hostname(state->client_hostname);
      
      if (strlen(state->client_hostname) != 0)
	{
	  state->hostname = state->client_hostname;
	  
	  if (!config)
	    {
	      /* Search again now we have a hostname. 
		 Only accept configs without CLID here, (it won't match)
		 to avoid impersonation by name. */
	      struct dhcp_config *new = find_config(daemon->dhcp_conf, state->context, NULL, 0, NULL, 0, 0, state->hostname, run_tag_if(state->tags));
	      if (new && !have_config(new, CONFIG_CLID) && !new->hwaddr)
		config = new;
	    }
	}
    }

  if (config)
    {
      struct dhcp_netid_list *list;
      
      for (list = config->netid; list; list = list->next)
        {
          list->list->next = state->tags;
          state->tags = list->list;
        }

      /* set "known" tag for known hosts */
      known_id.net = "known";
      known_id.next = state->tags;
      state->tags = &known_id;

      if (have_config(config, CONFIG_DISABLE))
	ignore = 1;
    }
  else if (state->clid &&
	   find_config(daemon->dhcp_conf, NULL, state->clid, state->clid_len,
		       state->mac, state->mac_len, state->mac_type, NULL, run_tag_if(state->tags)))
    {
      known_id.net = "known-othernet";
      known_id.next = state->tags;
      state->tags = &known_id;
    }
  
  tagif = run_tag_if(state->tags);
  
  /* if all the netids in the ignore list are present, ignore this client */
  if (daemon->dhcp_ignore)
    {
      struct dhcp_netid_list *id_list;
     
      for (id_list = daemon->dhcp_ignore; id_list; id_list = id_list->next)
	if (match_netid(id_list->list, tagif, 0))
	  ignore = 1;
    }
  
  /* if all the netids in the ignore_name list are present, ignore client-supplied name */
  if (!state->hostname_auth)
    {
       struct dhcp_netid_list *id_list;
       
       for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
	 if ((!id_list->list) || match_netid(id_list->list, tagif, 0))
	   break;
       if (id_list)
	 state->hostname = NULL;
    }
  

  switch (msg_type)
    {
    default:
      return 0;
      
      
    case DHCP6SOLICIT:
      {
      	int address_assigned = 0;
	/* tags without all prefix-class tags */
	struct dhcp_netid *solicit_tags;
	struct dhcp_context *c;
	
	outmsgtype = DHCP6ADVERTISE;
	
	if (opt6_find(state->packet_options, state->end, OPTION6_RAPID_COMMIT, 0))
	  {
	    outmsgtype = DHCP6REPLY;
	    state->lease_allocate = 1;
	    o = new_opt6(OPTION6_RAPID_COMMIT);
	    end_opt6(o);
	  }
	
  	log6_quiet(state, "DHCPSOLICIT", NULL, ignore ? _("ignored") : NULL);

      request_no_address:
	solicit_tags = tagif;
	
	if (ignore)
	  return 0;
	
	/* reset USED bits in leases */
	lease6_reset();

	/* Can use configured address max once per prefix */
	for (c = state->context; c; c = c->current)
	  c->flags &= ~CONTEXT_CONF_USED;

	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {   
	    void *ia_option, *ia_end;
	    unsigned int min_time = 0xffffffff;
	    int t1cntr;
	    int ia_counter;
	    /* set unless we're sending a particular prefix-class, when we
	       want only dhcp-ranges with the correct tags set and not those without any tags. */
	    int plain_range = 1;
	    u32 lease_time;
	    struct dhcp_lease *ltmp;
	    struct in6_addr req_addr, addr;
	    
	    if (!check_ia(state, opt, &ia_end, &ia_option))
	      continue;
	    
	    /* reset USED bits in contexts - one address per prefix per IAID */
	    for (c = state->context; c; c = c->current)
	      c->flags &= ~CONTEXT_USED;

	    o = build_ia(state, &t1cntr);
	    if (address_assigned)
		address_assigned = 2;

	    for (ia_counter = 0; ia_option; ia_counter++, ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
	      {
		/* worry about alignment here. */
		memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
				
		if ((c = address6_valid(state->context, &req_addr, solicit_tags, plain_range)))
		  {
		    lease_time = c->lease_time;
		    /* If the client asks for an address on the same network as a configured address, 
		       offer the configured address instead, to make moving to newly-configured
		       addresses automatic. */
		    if (!(c->flags & CONTEXT_CONF_USED) && config_valid(config, c, &addr, state, now))
		      {
			req_addr = addr;
			mark_config_used(c, &addr);
			if (have_config(config, CONFIG_TIME))
			  lease_time = config->lease_time;
		      }
		    else if (!(c = address6_available(state->context, &req_addr, solicit_tags, plain_range)))
		      continue; /* not an address we're allowed */
		    else if (!check_address(state, &req_addr))
		      continue; /* address leased elsewhere */
		    
		    /* add address to output packet */
		    add_address(state, c, lease_time, ia_option, &min_time, &req_addr, now);
		    mark_context_used(state, &req_addr);
		    get_context_tag(state, c);
		    address_assigned = 1;
		  }
	      }
	    
	    /* Suggest configured address(es) */
	    for (c = state->context; c; c = c->current) 
	      if (!(c->flags & CONTEXT_CONF_USED) &&
		  match_netid(c->filter, solicit_tags, plain_range) &&
		  config_valid(config, c, &addr, state, now))
		{
		  mark_config_used(state->context, &addr);
		  if (have_config(config, CONFIG_TIME))
		    lease_time = config->lease_time;
		  else
		    lease_time = c->lease_time;

		  /* add address to output packet */
		  add_address(state, c, lease_time, NULL, &min_time, &addr, now);
		  mark_context_used(state, &addr);
		  get_context_tag(state, c);
		  address_assigned = 1;
		}
	    
	    /* return addresses for existing leases */
	    ltmp = NULL;
	    while ((ltmp = lease6_find_by_client(ltmp, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA, state->clid, state->clid_len, state->iaid)))
	      {
		req_addr = ltmp->addr6;
		if ((c = address6_available(state->context, &req_addr, solicit_tags, plain_range)))
		  {
		    add_address(state, c, c->lease_time, NULL, &min_time, &req_addr, now);
		    mark_context_used(state, &req_addr);
		    get_context_tag(state, c);
		    address_assigned = 1;
		  }
	      }
		 	   
	    /* Return addresses for all valid contexts which don't yet have one */
	    while ((c = address6_allocate(state->context, state->clid, state->clid_len, state->ia_type == OPTION6_IA_TA,
					  state->iaid, ia_counter, solicit_tags, plain_range, &addr)))
	      {
		add_address(state, c, c->lease_time, NULL, &min_time, &addr, now);
		mark_context_used(state, &addr);
		get_context_tag(state, c);
		address_assigned = 1;
	      }
	    
	    if (address_assigned != 1)
	      {
		/* If the server will not assign any addresses to any IAs in a
		   subsequent Request from the client, the server MUST send an Advertise
		   message to the client that doesn't include any IA options. */
		if (!state->lease_allocate)
		  {
		    save_counter(o);
		    continue;
		  }
		
		/* If the server cannot assign any addresses to an IA in the message
		   from the client, the server MUST include the IA in the Reply message
		   with no addresses in the IA and a Status Code option in the IA
		   containing status code NoAddrsAvail. */
		o1 = new_opt6(OPTION6_STATUS_CODE);
		put_opt6_short(DHCP6NOADDRS);
		put_opt6_string(_("address unavailable"));
		end_opt6(o1);
	      }
	    
	    end_ia(t1cntr, min_time, 0);
	    end_opt6(o);	
	  }

	if (address_assigned) 
	  {
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6SUCCESS);
	    put_opt6_string(_("success"));
	    end_opt6(o1);
	    
	    /* If --dhcp-authoritative is set, we can tell client not to wait for
	       other possible servers */
	    o = new_opt6(OPTION6_PREFERENCE);
	    put_opt6_char(option_bool(OPT_AUTHORITATIVE) ? 255 : 0);
	    end_opt6(o);
	    tagif = add_options(state, 0);
	  }
	else
	  { 
	    /* no address, return error */
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6NOADDRS);
	    put_opt6_string(_("no addresses available"));
	    end_opt6(o1);

	    /* Some clients will ask repeatedly when we're not giving
	       out addresses because we're in stateless mode. Avoid spamming
	       the log in that case. */
	    for (c = state->context; c; c = c->current)
	      if (!(c->flags & CONTEXT_RA_STATELESS))
		{
		  log6_packet(state, state->lease_allocate ? "DHCPREPLY" : "DHCPADVERTISE", NULL, _("no addresses available"));
		  break;
		}
	  }

	break;
      }
      
    case DHCP6REQUEST:
      {
	int address_assigned = 0;
	int start = save_counter(-1);

	/* set reply message type */
	outmsgtype = DHCP6REPLY;
	state->lease_allocate = 1;

	log6_quiet(state, "DHCPREQUEST", NULL, ignore ? _("ignored") : NULL);
	
	if (ignore)
	  return 0;
	
	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {   
	    void *ia_option, *ia_end;
	    unsigned int min_time = 0xffffffff;
	    int t1cntr;
	    
	     if (!check_ia(state, opt, &ia_end, &ia_option))
	       continue;

	     if (!ia_option)
	       {
		 /* If we get a request with an IA_*A without addresses, treat it exactly like
		    a SOLICT with rapid commit set. */
		 save_counter(start);
		 goto request_no_address; 
	       }

	    o = build_ia(state, &t1cntr);
	      
	    for (; ia_option; ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
	      {
		struct in6_addr req_addr;
		struct dhcp_context *dynamic, *c;
		unsigned int lease_time;
		int config_ok = 0;

		/* align. */
		memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
		
		if ((c = address6_valid(state->context, &req_addr, tagif, 1)))
		  config_ok = (config_implies(config, c, &req_addr) != NULL);
		
		if ((dynamic = address6_available(state->context, &req_addr, tagif, 1)) || c)
		  {
		    if (!dynamic && !config_ok)
		      {
			/* Static range, not configured. */
			o1 = new_opt6(OPTION6_STATUS_CODE);
			put_opt6_short(DHCP6NOADDRS);
			put_opt6_string(_("address unavailable"));
			end_opt6(o1);
		      }
		    else if (!check_address(state, &req_addr))
		      {
			/* Address leased to another DUID/IAID */
			o1 = new_opt6(OPTION6_STATUS_CODE);
			put_opt6_short(DHCP6UNSPEC);
			put_opt6_string(_("address in use"));
			end_opt6(o1);
		      } 
		    else 
		      {
			if (!dynamic)
			  dynamic = c;

			lease_time = dynamic->lease_time;
			
			if (config_ok && have_config(config, CONFIG_TIME))
			  lease_time = config->lease_time;

			add_address(state, dynamic, lease_time, ia_option, &min_time, &req_addr, now);
			get_context_tag(state, dynamic);
			address_assigned = 1;
		      }
		  }
		else 
		  {
		    /* requested address not on the correct link */
		    o1 = new_opt6(OPTION6_STATUS_CODE);
		    put_opt6_short(DHCP6NOTONLINK);
		    put_opt6_string(_("not on link"));
		    end_opt6(o1);
		  }
	      }
	 
	    end_ia(t1cntr, min_time, 0);
	    end_opt6(o);	
	  }

	if (address_assigned) 
	  {
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6SUCCESS);
	    put_opt6_string(_("success"));
	    end_opt6(o1);
	  }
	else
	  { 
	    /* no address, return error */
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6NOADDRS);
	    put_opt6_string(_("no addresses available"));
	    end_opt6(o1);
	    log6_packet(state, "DHCPREPLY", NULL, _("no addresses available"));
	  }

	tagif = add_options(state, 0);
	break;
      }
      
  
    case DHCP6RENEW:
    case DHCP6REBIND:
      {
	int address_assigned = 0;

	/* set reply message type */
	outmsgtype = DHCP6REPLY;
	
	log6_quiet(state, msg_type == DHCP6RENEW ? "DHCPRENEW" : "DHCPREBIND", NULL, NULL);

	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {
	    void *ia_option, *ia_end;
	    unsigned int min_time = 0xffffffff;
	    int t1cntr, iacntr;
	    
	    if (!check_ia(state, opt, &ia_end, &ia_option))
	      continue;
	    
	    o = build_ia(state, &t1cntr);
	    iacntr = save_counter(-1); 
	    
	    for (; ia_option; ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
	      {
		struct dhcp_lease *lease = NULL;
		struct in6_addr req_addr;
		unsigned int preferred_time =  opt6_uint(ia_option, 16, 4);
		unsigned int valid_time =  opt6_uint(ia_option, 20, 4);
		char *message = NULL;
		struct dhcp_context *this_context;

		memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ); 
		
		if (!(lease = lease6_find(state->clid, state->clid_len,
					  state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA, 
					  state->iaid, &req_addr)))
		  {
		    if (msg_type == DHCP6REBIND)
		      {
			/* When rebinding, we can create a lease if it doesn't exist. */
			lease = lease6_allocate(&req_addr, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA);
			if (lease)
			  lease_set_iaid(lease, state->iaid);
			else
			  break;
		      }
		    else
		      {
			/* If the server cannot find a client entry for the IA the server
			   returns the IA containing no addresses with a Status Code option set
			   to NoBinding in the Reply message. */
			save_counter(iacntr);
			t1cntr = 0;
			
			log6_packet(state, "DHCPREPLY", &req_addr, _("lease not found"));
			
			o1 = new_opt6(OPTION6_STATUS_CODE);
			put_opt6_short(DHCP6NOBINDING);
			put_opt6_string(_("no binding found"));
			end_opt6(o1);
			
			preferred_time = valid_time = 0;
			break;
		      }
		  }
		
		if ((this_context = address6_available(state->context, &req_addr, tagif, 1)) ||
		    (this_context = address6_valid(state->context, &req_addr, tagif, 1)))
		  {
		    unsigned int lease_time;

		    get_context_tag(state, this_context);
		    
		    if (config_implies(config, this_context, &req_addr) && have_config(config, CONFIG_TIME))
		      lease_time = config->lease_time;
		    else 
		      lease_time = this_context->lease_time;
		    
		    calculate_times(this_context, &min_time, &valid_time, &preferred_time, lease_time); 
		    
		    lease_set_expires(lease, valid_time, now);
		    /* Update MAC record in case it's new information. */
		    if (state->mac_len != 0)
		      lease_set_hwaddr(lease, state->mac, state->clid, state->mac_len, state->mac_type, state->clid_len, now, 0);
		    if (state->ia_type == OPTION6_IA_NA && state->hostname)
		      {
			char *addr_domain = get_domain6(&req_addr);
			if (!state->send_domain)
			  state->send_domain = addr_domain;
			lease_set_hostname(lease, state->hostname, state->hostname_auth, addr_domain, state->domain); 
			message = state->hostname;
		      }
		    
		    
		    if (preferred_time == 0)
		      message = _("deprecated");

		    address_assigned = 1;
		  }
		else
		  {
		    preferred_time = valid_time = 0;
		    message = _("address invalid");
		  } 

		if (message && (message != state->hostname))
		  log6_packet(state, "DHCPREPLY", &req_addr, message);	
		else
		  log6_quiet(state, "DHCPREPLY", &req_addr, message);
	
		o1 =  new_opt6(OPTION6_IAADDR);
		put_opt6(&req_addr, sizeof(req_addr));
		put_opt6_long(preferred_time);
		put_opt6_long(valid_time);
		end_opt6(o1);
	      }
	    
	    end_ia(t1cntr, min_time, 1);
	    end_opt6(o);
	  }

	if (!address_assigned && msg_type == DHCP6REBIND)
	  { 
	    /* can't create lease for any address, return error */
	    o1 = new_opt6(OPTION6_STATUS_CODE);
	    put_opt6_short(DHCP6NOADDRS);
	    put_opt6_string(_("no addresses available"));
	    end_opt6(o1);
	  }
	
	tagif = add_options(state, 0);
	break;
      }
      
    case DHCP6CONFIRM:
      {
	int good_addr = 0;

	/* set reply message type */
	outmsgtype = DHCP6REPLY;
	
	log6_quiet(state, "DHCPCONFIRM", NULL, NULL);
	
	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {
	    void *ia_option, *ia_end;
	    
	    for (check_ia(state, opt, &ia_end, &ia_option);
		 ia_option;
		 ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24))
	      {
		struct in6_addr req_addr;

		/* alignment */
		memcpy(&req_addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
		
		if (!address6_valid(state->context, &req_addr, tagif, 1))
		  {
		    o1 = new_opt6(OPTION6_STATUS_CODE);
		    put_opt6_short(DHCP6NOTONLINK);
		    put_opt6_string(_("confirm failed"));
		    end_opt6(o1);
		    log6_quiet(state, "DHCPREPLY", &req_addr, _("confirm failed"));
		    return 1;
		  }

		good_addr = 1;
		log6_quiet(state, "DHCPREPLY", &req_addr, state->hostname);
	      }
	  }	 
	
	/* No addresses, no reply: RFC 3315 18.2.2 */
	if (!good_addr)
	  return 0;

	o1 = new_opt6(OPTION6_STATUS_CODE);
	put_opt6_short(DHCP6SUCCESS );
	put_opt6_string(_("all addresses still on link"));
	end_opt6(o1);
	break;
    }
      
    case DHCP6IREQ:
      {
	/* We can't discriminate contexts based on address, as we don't know it.
	   If there is only one possible context, we can use its tags */
	if (state->context && state->context->netid.net && !state->context->current)
	  {
	    state->context->netid.next = NULL;
	    state->context_tags =  &state->context->netid;
	  }

	/* Similarly, we can't determine domain from address, but if the FQDN is
	   given in --dhcp-host, we can use that, and failing that we can use the 
	   unqualified configured domain, if any. */
	if (state->hostname_auth)
	  state->send_domain = state->domain;
	else
	  state->send_domain = get_domain6(NULL);

	log6_quiet(state, "DHCPINFORMATION-REQUEST", NULL, ignore ? _("ignored") : state->hostname);
	if (ignore)
	  return 0;
	outmsgtype = DHCP6REPLY;
	tagif = add_options(state, 1);
	break;
      }
      
      
    case DHCP6RELEASE:
      {
	/* set reply message type */
	outmsgtype = DHCP6REPLY;

	log6_quiet(state, "DHCPRELEASE", NULL, NULL);

	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {
	    void *ia_option, *ia_end;
	    int made_ia = 0;
	    	    
	    for (check_ia(state, opt, &ia_end, &ia_option);
		 ia_option;
		 ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24)) 
	      {
		struct dhcp_lease *lease;
		struct in6_addr addr;

		/* align */
		memcpy(&addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);
		if ((lease = lease6_find(state->clid, state->clid_len, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA,
					 state->iaid, &addr)))
		  lease_prune(lease, now);
		else
		  {
		    if (!made_ia)
		      {
			o = new_opt6(state->ia_type);
			put_opt6_long(state->iaid);
			if (state->ia_type == OPTION6_IA_NA)
			  {
			    put_opt6_long(0);
			    put_opt6_long(0); 
			  }
			made_ia = 1;
		      }
		    
		    o1 = new_opt6(OPTION6_IAADDR);
		    put_opt6(&addr, IN6ADDRSZ);
		    put_opt6_long(0);
		    put_opt6_long(0);
		    end_opt6(o1);
		  }
	      }
	    
	    if (made_ia)
	      {
		o1 = new_opt6(OPTION6_STATUS_CODE);
		put_opt6_short(DHCP6NOBINDING);
		put_opt6_string(_("no binding found"));
		end_opt6(o1);
		
		end_opt6(o);
	      }
	  }
	
	o1 = new_opt6(OPTION6_STATUS_CODE);
	put_opt6_short(DHCP6SUCCESS);
	put_opt6_string(_("release received"));
	end_opt6(o1);
	
	break;
      }

    case DHCP6DECLINE:
      {
	/* set reply message type */
	outmsgtype = DHCP6REPLY;
	
	log6_quiet(state, "DHCPDECLINE", NULL, NULL);

	for (opt = state->packet_options; opt; opt = opt6_next(opt, state->end))
	  {
	    void *ia_option, *ia_end;
	    int made_ia = 0;
	    	    
	    for (check_ia(state, opt, &ia_end, &ia_option);
		 ia_option;
		 ia_option = opt6_find(opt6_next(ia_option, ia_end), ia_end, OPTION6_IAADDR, 24)) 
	      {
		struct dhcp_lease *lease;
		struct in6_addr addr;
		struct addrlist *addr_list;
		
		/* align */
		memcpy(&addr, opt6_ptr(ia_option, 0), IN6ADDRSZ);

		if ((addr_list = config_implies(config, state->context, &addr)))
		  {
		    prettyprint_time(daemon->dhcp_buff3, DECLINE_BACKOFF);
		    inet_ntop(AF_INET6, &addr, daemon->addrbuff, ADDRSTRLEN);
		    my_syslog(MS_DHCP | LOG_WARNING, _("disabling DHCP static address %s for %s"), 
			      daemon->addrbuff, daemon->dhcp_buff3);
		    addr_list->flags |= ADDRLIST_DECLINED;
		    addr_list->decline_time = now;
		  }
		else
		  /* make sure this host gets a different address next time. */
		  for (context_tmp = state->context; context_tmp; context_tmp = context_tmp->current)
		    context_tmp->addr_epoch++;
		
		if ((lease = lease6_find(state->clid, state->clid_len, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA,
					 state->iaid, &addr)))
		  lease_prune(lease, now);
		else
		  {
		    if (!made_ia)
		      {
			o = new_opt6(state->ia_type);
			put_opt6_long(state->iaid);
			if (state->ia_type == OPTION6_IA_NA)
			  {
			    put_opt6_long(0);
			    put_opt6_long(0); 
			  }
			made_ia = 1;
		      }
		    
		    o1 = new_opt6(OPTION6_IAADDR);
		    put_opt6(&addr, IN6ADDRSZ);
		    put_opt6_long(0);
		    put_opt6_long(0);
		    end_opt6(o1);
		  }
	      }
	    
	    if (made_ia)
	      {
		o1 = new_opt6(OPTION6_STATUS_CODE);
		put_opt6_short(DHCP6NOBINDING);
		put_opt6_string(_("no binding found"));
		end_opt6(o1);
		
		end_opt6(o);
	      }
	    
	  }

	/* We must answer with 'success' in global section anyway */
	o1 = new_opt6(OPTION6_STATUS_CODE);
	put_opt6_short(DHCP6SUCCESS);
	put_opt6_string(_("success"));
	end_opt6(o1);
	break;
      }

    }

  /* Fill in the message type. Note that we store the offset,
     not a direct pointer, since the packet memory may have been 
     reallocated. */
  ((unsigned char *)(daemon->outpacket.iov_base))[start_msg] = outmsgtype;

  log_tags(tagif, state->xid);
  log6_opts(0, state->xid, daemon->outpacket.iov_base + start_opts, daemon->outpacket.iov_base + save_counter(-1));
  
  return 1;

}

/**
 * @brief Construct DHCPv6 option set for reply packet based on tags and client requests
 *
 * Builds complete DHCPv6 option payload for ADVERTISE/REPLY messages by filtering configured
 * options (daemon->dhcp_opts6) through tag matching (option_filter), honoring client Option
 * Request Option (ORO, OPTION6_ORO), and adding required options like DNS servers (RFC 3646),
 * NTP servers (RFC 5908), refresh time (RFC 4242), vendor-encapsulated options (RFC 3925),
 * and FQDN (RFC 4704). Supports conditional options (dhcp-option=tag:...), forced options
 * (DHOPT_FORCE), special address substitutions (:: = local addrs, fe80:: = link-local,
 * fec0:: = ULA), and NTP multicast/unicast sub-option encoding.
 *
 * Option processing phases:
 * 1. Tag filtering: option_filter() marks DHOPT_TAGOK for options matching accumulated tags
 * 2. ORO matching: For non-forced options, verify client requested via OPTION6_ORO
 * 3. Address substitution: Replace :: with server local addrs, fe80:: with LL, fec0:: with ULA
 * 4. Vendor encapsulation: Group RFC 3925 vendor options by enterprise number
 * 5. FQDN option: Add client FQDN if hostname validated and authorized
 * 6. Logging: Log requested options if OPT_LOG_OPTS enabled
 *
 * Special address handling (DHOPT_ADDR6 options like DNS_SERVER, NTP_SERVER):
 * - IN6_IS_ADDR_UNSPECIFIED (::): Call add_local_addrs() to include server's own addresses
 * - IN6_IS_ADDR_LINK_LOCAL_ZERO (fe80::): Replace with state->ll_addr
 * - IN6_IS_ADDR_ULA_ZERO (fec0::): Replace with state->ula_addr
 * - Skip if substitution address unspecified
 *
 * @param state Per-request state with tags (client classification), context_tags (subnet tags),
 *              packet_options/end (client's ORO), fallback/ll_addr/ula_addr (server addresses),
 *              hostname/send_domain/fqdn_flags (for FQDN option), xid (for logging)
 * @param do_refresh If non-zero, include OPTION6_REFRESH_TIME with minimum context lease time
 *                   (\u2265600 seconds per RFC 4242). Zero suppresses refresh time.
 *
 * @return Pointer to filtered tag list (dhcp_netid chain) representing active conditional
 *         tags after option_filter(), used by caller for further tag-dependent processing,
 *         or NULL if no tags active
 *
 * @note RFC 4242 mandates OPTION6_REFRESH_TIME \u2265 600 seconds. Function enforces floor.
 * @warning Function calls new_opt6()/put_opt6()/end_opt6() which modify global packet buffer
 *          (daemon->outpacket). Not reentrant. Assumes sufficient buffer space via
 *          save_counter()/reset_counter() overflow protection elsewhere.
 *
 * @see option_filter() for tag-based option filtering (marks DHOPT_TAGOK)
 * @see add_local_addrs() for appending server's own IPv6 addresses
 * @see new_opt6() for starting new DHCPv6 option in reply packet
 * @see put_opt6() for appending data to current option
 * @see end_opt6() for finalizing option with correct length field
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid *tagif = add_options(state, 1); // Include refresh time
 * // Now daemon->outpacket contains complete option set for client
 * if (tagif) {
 *     // Conditional tags active, may affect further processing
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22.7: Option Request Option (ORO) processing
 * - RFC 3646: DNS Recursive Name Server Option (OPTION6_DNS_SERVER)
 * - RFC 3925: Vendor-Identifying Vendor Options (OPTION6_VENDOR_OPTS)
 * - RFC 4242: Information Refresh Time Option (OPTION6_REFRESH_TIME \u2265 600s)
 * - RFC 4704: Client FQDN Option (OPTION6_FQDN)
 * - RFC 5908: NTP Server Option (OPTION6_NTP_SERVER with sub-options)
 *
 * SIDE EFFECTS:
 * - Calls option_filter() which may modify opt->flags (sets DHOPT_TAGOK)
 * - Calls new_opt6()/put_opt6()/end_opt6() appending to daemon->outpacket
 * - Calls add_local_addrs() which advances packet write pointer
 * - Modifies opt_cfg->flags (DHOPT_ENCAP_DONE, DHOPT_ENCAP_MATCH) for vendor option tracking
 * - Logs to syslog if OPT_LOG_OPTS enabled
 *
 * THREAD SAFETY: Not thread-safe (modifies global packet buffer and option flags)
 */
static struct dhcp_netid *add_options(struct state *state, int do_refresh)  
{
  void *oro;
  /* filter options based on tags, those we want get DHOPT_TAGOK bit set */
  struct dhcp_netid *tagif = option_filter(state->tags, state->context_tags, daemon->dhcp_opts6);
  struct dhcp_opt *opt_cfg;
  int done_dns = 0, done_refresh = !do_refresh, do_encap = 0;
  int i, o, o1;

  oro = opt6_find(state->packet_options, state->end, OPTION6_ORO, 0);
  
  for (opt_cfg = daemon->dhcp_opts6; opt_cfg; opt_cfg = opt_cfg->next)
    {
      /* netids match and not encapsulated? */
      if (!(opt_cfg->flags & DHOPT_TAGOK))
	continue;
      
      if (!(opt_cfg->flags & DHOPT_FORCE) && oro)
	{
	  for (i = 0; i <  opt6_len(oro) - 1; i += 2)
	    if (opt6_uint(oro, i, 2) == (unsigned)opt_cfg->opt)
	      break;
	  
	  /* option not requested */
	  if (i >=  opt6_len(oro) - 1)
	    continue;
	}
      
      if (opt_cfg->opt == OPTION6_REFRESH_TIME)
	done_refresh = 1;
       
      if (opt_cfg->opt == OPTION6_DNS_SERVER)
	done_dns = 1;
      
      if (opt_cfg->flags & DHOPT_ADDR6)
	{
	  int len, j;
	  struct in6_addr *a;
	  
	  for (a = (struct in6_addr *)opt_cfg->val, len = opt_cfg->len, j = 0; 
	       j < opt_cfg->len; j += IN6ADDRSZ, a++)
	    if ((IN6_IS_ADDR_ULA_ZERO(a) && IN6_IS_ADDR_UNSPECIFIED(state->ula_addr)) ||
		(IN6_IS_ADDR_LINK_LOCAL_ZERO(a) && IN6_IS_ADDR_UNSPECIFIED(state->ll_addr)))
	      len -= IN6ADDRSZ;
	  
	  if (len != 0)
	    {
	      
	      o = new_opt6(opt_cfg->opt);
	      	  
	      for (a = (struct in6_addr *)opt_cfg->val, j = 0; j < opt_cfg->len; j+=IN6ADDRSZ, a++)
		{
		  struct in6_addr *p = NULL;

		  if (IN6_IS_ADDR_UNSPECIFIED(a))
		    {
		      if (!add_local_addrs(state->context))
			p = state->fallback;
		    }
		  else if (IN6_IS_ADDR_ULA_ZERO(a))
		    {
		      if (!IN6_IS_ADDR_UNSPECIFIED(state->ula_addr))
			p = state->ula_addr;
		    }
		  else if (IN6_IS_ADDR_LINK_LOCAL_ZERO(a))
		    {
		      if (!IN6_IS_ADDR_UNSPECIFIED(state->ll_addr))
			p = state->ll_addr;
		    }
		  else
		    p = a;

		  if (!p)
		    continue;
		  else if (opt_cfg->opt == OPTION6_NTP_SERVER)
		    {
		      if (IN6_IS_ADDR_MULTICAST(p))
			o1 = new_opt6(NTP_SUBOPTION_MC_ADDR);
		      else
			o1 = new_opt6(NTP_SUBOPTION_SRV_ADDR);
		      put_opt6(p, IN6ADDRSZ);
		      end_opt6(o1);
		    }
		  else
		    put_opt6(p, IN6ADDRSZ);
		}

	      end_opt6(o);
	    }
	}
      else
	{
	  o = new_opt6(opt_cfg->opt);
	  if (opt_cfg->val)
	    put_opt6(opt_cfg->val, opt_cfg->len);
	  end_opt6(o);
	}
    }
  
  if (daemon->port == NAMESERVER_PORT && !done_dns)
    {
      o = new_opt6(OPTION6_DNS_SERVER);
      if (!add_local_addrs(state->context))
	put_opt6(state->fallback, IN6ADDRSZ);
      end_opt6(o); 
    }

  if (state->context && !done_refresh)
    {
      struct dhcp_context *c;
      unsigned int lease_time = 0xffffffff;
      
      /* Find the smallest lease tie of all contexts,
	 subject to the RFC-4242 stipulation that this must not 
	 be less than 600. */
      for (c = state->context; c; c = c->next)
	if (c->lease_time < lease_time)
	  {
	    if (c->lease_time < 600)
	      lease_time = 600;
	    else
	      lease_time = c->lease_time;
	  }

      o = new_opt6(OPTION6_REFRESH_TIME);
      put_opt6_long(lease_time);
      end_opt6(o); 
    }
   
    /* handle vendor-identifying vendor-encapsulated options,
       dhcp-option = vi-encap:13,17,....... */
  for (opt_cfg = daemon->dhcp_opts6; opt_cfg; opt_cfg = opt_cfg->next)
    opt_cfg->flags &= ~DHOPT_ENCAP_DONE;
    
  if (oro)
    for (i = 0; i <  opt6_len(oro) - 1; i += 2)
      if (opt6_uint(oro, i, 2) == OPTION6_VENDOR_OPTS)
	do_encap = 1;
  
  for (opt_cfg = daemon->dhcp_opts6; opt_cfg; opt_cfg = opt_cfg->next)
    { 
      if (opt_cfg->flags & DHOPT_RFC3925)
	{
	  int found = 0;
	  struct dhcp_opt *oc;
	  
	  if (opt_cfg->flags & DHOPT_ENCAP_DONE)
	    continue;
	  
	  for (oc = daemon->dhcp_opts6; oc; oc = oc->next)
	    {
	      oc->flags &= ~DHOPT_ENCAP_MATCH;
	      
	      if (!(oc->flags & DHOPT_RFC3925) || opt_cfg->u.encap != oc->u.encap)
		continue;
	      
	      oc->flags |= DHOPT_ENCAP_DONE;
	      if (match_netid(oc->netid, tagif, 1))
		{
		  /* option requested/forced? */
		  if (!oro || do_encap || (oc->flags & DHOPT_FORCE))
		    {
		      oc->flags |= DHOPT_ENCAP_MATCH;
		      found = 1;
		    }
		} 
	    }
	  
	  if (found)
	    { 
	      o = new_opt6(OPTION6_VENDOR_OPTS);	      
	      put_opt6_long(opt_cfg->u.encap);	
	     
	      for (oc = daemon->dhcp_opts6; oc; oc = oc->next)
		if (oc->flags & DHOPT_ENCAP_MATCH)
		  {
		    o1 = new_opt6(oc->opt);
		    put_opt6(oc->val, oc->len);
		    end_opt6(o1);
		  }
	      end_opt6(o);
	    }
	}
    }      


  if (state->hostname)
    {
      unsigned char *p;
      size_t len = strlen(state->hostname);
      
      if (state->send_domain)
	len += strlen(state->send_domain) + 2;

      o = new_opt6(OPTION6_FQDN);
      if ((p = expand(len + 2)))
	{
	  *(p++) = state->fqdn_flags;
	  p = do_rfc1035_name(p, state->hostname, NULL);
	  if (state->send_domain)
	    {
	      p = do_rfc1035_name(p, state->send_domain, NULL);
	      *p = 0;
	    }
	}
      end_opt6(o);
    }


  /* logging */
  if (option_bool(OPT_LOG_OPTS) && oro)
    {
      char *q = daemon->namebuff;
      for (i = 0; i <  opt6_len(oro) - 1; i += 2)
	{
	  char *s = option_string(AF_INET6, opt6_uint(oro, i, 2), NULL, 0, NULL, 0);
	  q += snprintf(q, MAXDNAME - (q - daemon->namebuff),
			"%d%s%s%s", 
			opt6_uint(oro, i, 2),
			strlen(s) != 0 ? ":" : "",
			s, 
			(i > opt6_len(oro) - 3) ? "" : ", ");
	  if ( i >  opt6_len(oro) - 3 || (q - daemon->namebuff) > 40)
	    {
	      q = daemon->namebuff;
	      my_syslog(MS_DHCP | LOG_INFO, _("%u requested options: %s"), state->xid, daemon->namebuff);
	    }
	}
    } 

  return tagif;
}

/**
 * @brief Add local server IPv6 addresses to DHCPv6 reply packet
 *
 * Appends OPTION6_IA_ADDR entries for local server IPv6 addresses (context->local6) from
 * CONTEXT_USED address pools to DHCPv6 reply packet. Used for Information-Request replies
 * to provide server DNS/NTP addresses to clients. Deduplicates addresses when multiple
 * contexts share same local6 value (e.g., overlapping ranges on same interface). Only
 * includes contexts marked CONTEXT_USED (actually selected for this client) and with
 * non-unspecified local6 address.
 *
 * Local address semantics: context->local6 is server's own IPv6 address on the subnet,
 * typically used for DNS recursive resolver address (OPTION6_NAME_SERVERS) or NTP server
 * address (OPTION6_NTP_SERVER). Clients use these addresses for subsequent protocol
 * communication after DHCP configuration.
 *
 * @param context Address pool context chain to iterate (context->current linkage)
 *
 * @return 1 if at least one local address added to packet,
 *         0 if no local addresses added (all contexts unspecified or no CONTEXT_USED)
 *
 * @note Duplicate suppression: Iterates context->current chain for each candidate to check
 *       if same local6 already seen. Only first occurrence added to reply.
 * @warning Assumes packet buffer has sufficient space (no overflow checking). Caller must
 *          ensure space via save_counter()/reset_counter() mechanism.
 *
 * @see put_opt6() for appending raw bytes to DHCPv6 reply packet
 * @see add_options() for primary caller (adds local addrs after other options)
 *
 * EXAMPLE USAGE:
 * @code
 * if (add_local_addrs(state->context)) {
 *     // At least one server address included in reply
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 18.2.6: Information-Request processing and server addresses
 * - RFC 3646: DNS Configuration Options (OPTION6_NAME_SERVERS)
 * - RFC 5908: NTP Server Option for DHCPv6 (OPTION6_NTP_SERVER)
 *
 * SIDE EFFECTS:
 * - Calls put_opt6() which advances packet write pointer (daemon->outpacket.iov_len)
 *
 * THREAD SAFETY: Not thread-safe (modifies global outpacket buffer)
 */
 
static int add_local_addrs(struct dhcp_context *context)
{
  int done = 0;
  
  for (; context; context = context->current)
    if ((context->flags & CONTEXT_USED) && !IN6_IS_ADDR_UNSPECIFIED(&context->local6))
      {
	/* squash duplicates */
	struct dhcp_context *c;
	for (c = context->current; c; c = c->current)
	  if ((c->flags & CONTEXT_USED) &&
	      IN6_ARE_ADDR_EQUAL(&context->local6, &c->local6))
	    break;
	
	if (!c)
	  { 
	    done = 1;
	    put_opt6(&context->local6, IN6ADDRSZ);
	  }
      }

  return done;
}

/**
 * @brief Accumulate network identification tags from address pool context
 *
 * Extracts netid tags from address pool context (context->netid) and appends to per-request
 * accumulated tag chain (state->context_tags). Tags used for conditional option processing
 * (dhcp-option=tag:foo,...) and hostname authorization (dhcp-ignore-names). Implements
 * single-use tagging: context->netid.next initially points to self (sentinel), set to
 * state->context_tags after first use to prevent duplicate tag accumulation. Conditionally
 * disables hostname registration (state->hostname=NULL) if dhcp-ignore-names matches
 * accumulated tags.
 *
 * Tag semantics: Each context has optional netid.net string (e.g., "vlan10") identifying
 * subnet characteristics. Tags accumulate across multiple matching contexts (client may
 * match multiple overlapping ranges). Accumulated tags in state->context_tags used by
 * add_options() for tag-based option selection.
 *
 * Hostname authorization: If state->hostname_auth not already set (client hostname not
 * pre-authorized via dhcp-host), checks daemon->dhcp_ignore_names list. If matching
 * tag-based ignore rule found, nulls state->hostname preventing DNS registration.
 *
 * @param state Per-request state with context_tags chain (accumulated tags) and hostname
 *              (candidate hostname for DNS registration, may be nulled by ignore rules)
 * @param context Address pool context providing netid tag to potentially add
 *
 * @return None (void function, modifies state->context_tags and potentially state->hostname)
 *
 * @note Self-referencing sentinel: context->netid.next == &context->netid indicates unused
 *       tag. Once used, netid.next points into state->context_tags chain.
 * @warning Modifies both state and context structures. Context modification (netid.next)
 *          prevents re-tagging but makes context non-reentrant for subsequent requests.
 *
 * @see add_options() for using accumulated tags to select conditional DHCP options
 * @see match_netid() for tag matching logic in dhcp_ignore_names
 *
 * EXAMPLE USAGE:
 * @code
 * for (context = state->context; context; context = context->current) {
 *     get_context_tag(state, context); // Accumulate tags from all matching contexts
 * }
 * // Now state->context_tags contains complete tag chain for option selection
 * @endcode
 *
 * RFC COMPLIANCE: Not RFC-mandated (dnsmasq-specific tagging/conditional option feature)
 *
 * SIDE EFFECTS:
 * - Modifies context->netid.next (first-use marking)
 * - Appends to state->context_tags linked list
 * - May set state->hostname = NULL (disabling DNS registration)
 *
 * THREAD SAFETY: Not thread-safe (modifies shared context and per-request state)
 */
static void get_context_tag(struct state *state, struct dhcp_context *context)
{
  /* get tags from context if we've not used it before */
  if (context->netid.next == &context->netid && context->netid.net)
    {
      context->netid.next = state->context_tags;
      state->context_tags = &context->netid;
      if (!state->hostname_auth)
	{
	  struct dhcp_netid_list *id_list;
	  
	  for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
	    if ((!id_list->list) || match_netid(id_list->list, &context->netid, 0))
	      break;
	  if (id_list)
	    state->hostname = NULL;
	}
    }
} 

/**
 * @brief Validate Identity Association option structure and extract IAID and address suboptions
 *
 * Verifies IA_NA (non-temporary address) or IA_TA (temporary address) option meets minimum
 * size requirements per RFC 3315 Section 22.4-22.5, extracts IAID (Identity Association
 * Identifier) for client IA tracking, and searches for IAADDR suboptions containing requested
 * or allocated IPv6 addresses. Sets state->ia_type for subsequent processing and provides
 * boundary pointers for iterating through IA suboptions.
 *
 * IA_NA structure: 4-byte IAID + 4-byte T1 + 4-byte T2 + suboptions (minimum 12 bytes total)
 * IA_TA structure: 4-byte IAID + suboptions (minimum 4 bytes total, no T1/T2 for temporary)
 *
 * @param state Per-request state structure, modified to set state->ia_type (OPTION6_IA_NA
 *              or OPTION6_IA_TA) and state->iaid (4-byte Identity Association Identifier)
 * @param opt Pointer to IA_NA or IA_TA option start (type field)
 * @param[out] endp Output pointer set to end of IA option suboptions area for iteration
 * @param[out] ia_option Output pointer set to first IAADDR suboption if found, NULL otherwise
 *
 * @return 1 if option is valid IA_NA or IA_TA with correct size, 0 if invalid/unsupported type
 *
 * @note Does not validate IAADDR suboption content (preferred/valid lifetimes, address validity),
 *       only locates first occurrence. Caller must iterate for multiple IAADDR suboptions.
 * @warning Prefix Delegation (IA_PD/IAPREFIX) not handled by this function, returns 0
 *
 * @see build_ia() for constructing IA response with allocated addresses
 * @see add_address() for processing IAADDR suboptions and allocating addresses
 *
 * EXAMPLE USAGE:
 * @code
 * void *endp, *ia_addr_opt;
 * if (check_ia(state, ia_na_opt, &endp, &ia_addr_opt)) {
 *     // Process IA_NA with IAID in state->iaid, iterate IAADDR options
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22.4: IA_NA option format (IAID + T1 + T2 + options)
 * - RFC 3315 Section 22.5: IA_TA option format (IAID + options, no T1/T2)
 * - RFC 3315 Section 22.6: IAADDR option (address + preferred + valid lifetimes)
 *
 * SIDE EFFECTS:
 * - Modifies state->ia_type to OPTION6_IA_NA or OPTION6_IA_TA
 * - Modifies state->iaid to extracted 4-byte IAID value
 *
 * THREAD SAFETY: Thread-safe (only modifies caller-owned state structure)
 */
static int check_ia(struct state *state, void *opt, void **endp, void **ia_option)
{
  state->ia_type = opt6_type(opt);
  *ia_option = NULL;

  if (state->ia_type != OPTION6_IA_NA && state->ia_type != OPTION6_IA_TA)
    return 0;
  
  if (state->ia_type == OPTION6_IA_NA && opt6_len(opt) < 12)
    return 0;
	    
  if (state->ia_type == OPTION6_IA_TA && opt6_len(opt) < 4)
    return 0;
  
  *endp = opt6_ptr(opt, opt6_len(opt));
  state->iaid = opt6_uint(opt, 0, 4);
  *ia_option = opt6_find(opt6_ptr(opt, state->ia_type == OPTION6_IA_NA ? 12 : 4), *endp, OPTION6_IAADDR, 24);

  return 1;
}

/**
 * @brief Begin constructing IA_NA or IA_TA response option in reply packet
 *
 * Initializes Identity Association response option in daemon->outpacket with client's
 * IAID echoed back for IA matching per RFC 3315 Section 18. For IA_NA, reserves space
 * for T1 (renewal time) and T2 (rebind time) timers to be filled later by end_ia() after
 * calculating minimum lease time across all allocated addresses. For IA_TA, no T1/T2
 * needed as temporary addresses don't have renewal semantics.
 *
 * Typical call sequence: build_ia() → multiple add_address() → end_ia() to construct
 * complete IA with addresses and timer values.
 *
 * @param state Per-request state containing ia_type (OPTION6_IA_NA or OPTION6_IA_TA)
 *              and iaid (Identity Association Identifier to echo in response)
 * @param[out] t1cntr Output pointer set to save_counter() position for T1/T2 fields
 *                    in IA_NA (0 for IA_TA which has no T1/T2), used by end_ia() to
 *                    backfill timer values after address allocation
 *
 * @return Option handle from new_opt6() for passing to end_opt6() after addresses added
 *
 * @note Caller must call end_ia() with returned t1cntr to finalize IA_NA with T1/T2 values
 * @warning After build_ia(), daemon->outpacket write position is immediately after IAID
 *          (and T1/T2 placeholders for IA_NA). Caller adds IAADDR suboptions before end_ia().
 *
 * @see end_ia() for finalizing IA_NA with calculated T1/T2 renewal timers
 * @see add_address() for adding IAADDR suboptions within IA
 *
 * EXAMPLE USAGE:
 * @code
 * int ia_option_handle, t1cntr;
 * ia_option_handle = build_ia(state, &t1cntr);
 * add_address(state, context, lease_time, NULL, &min_time, &addr, now); // Add addresses
 * end_ia(t1cntr, min_time, 1); // Finalize with T1/T2
 * end_opt6(ia_option_handle);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22.4: IA_NA format with IAID + T1 + T2
 * - RFC 3315 Section 22.5: IA_TA format with IAID only (no T1/T2)
 *
 * SIDE EFFECTS:
 * - Writes IAID to daemon->outpacket via put_opt6_long()
 * - For IA_NA: writes placeholder 0 values for T1/T2, saves position in *t1cntr
 *
 * THREAD SAFETY: Not thread-safe (modifies global daemon->outpacket buffer)
 */
static int build_ia(struct state *state, int *t1cntr)
{
  int  o = new_opt6(state->ia_type);
 
  put_opt6_long(state->iaid);
  *t1cntr = 0;
	    
  if (state->ia_type == OPTION6_IA_NA)
    {
      /* save pointer */
      *t1cntr = save_counter(-1);
      /* so we can fill these in later */
      put_opt6_long(0);
      put_opt6_long(0); 
    }

  return o;
}

/**
 * @brief Finalize IA_NA option by backfilling T1 and T2 renewal timer values
 *
 * Calculates and writes T1 (renewal time) and T2 (rebind time) timer values into IA_NA
 * response option after all addresses added and minimum lease time determined. Per RFC 3315
 * Section 22.4, T1 defaults to 50% of minimum valid lifetime (when client should begin
 * renewal with original server), T2 to 87.5% (when client should begin rebinding with any
 * server). Optionally applies random fuzz to prevent thundering herd of simultaneous renewals.
 *
 * For IA_TA (temporary addresses), t1cntr is 0 and function is no-op as temporary addresses
 * don't have renewal semantics per RFC 3315 Section 22.5.
 *
 * @param t1cntr Save counter position from build_ia() pointing to T1 field in IA_NA,
 *               or 0 for IA_TA (no-op). Used to seek back in daemon->outpacket buffer
 *               and overwrite placeholder zeros with calculated timers.
 * @param min_time Minimum valid lifetime across all IAADDR suboptions in seconds, determines
 *                 T1/T2 calculation base. Special value 0xffffffff (infinite) propagates
 *                 to T1/T2 as infinite (no renewal required).
 * @param do_fuzz Boolean: if true, subtract random value (up to min_time/16) from T1/T2
 *                to randomize renewal timing and prevent synchronized renewal storms
 *
 * @return None (void function, modifies daemon->outpacket buffer in-place)
 *
 * @note T1 calculation: min_time/2 - fuzz, T2 calculation: (min_time/8)*7 - fuzz.
 *       Fuzz repeatedly halved until ≤ min_time/16 for bounded randomization.
 * @warning Must be called after all add_address() calls complete and min_time determined.
 *          Calling before addresses added results in incorrect T1/T2 based on stale min_time.
 *
 * @see build_ia() for creating IA_NA with t1cntr save point
 * @see calculate_times() for determining min_time from context lifetimes
 *
 * EXAMPLE USAGE:
 * @code
 * int t1cntr;
 * unsigned int min_time = 0xffffffff;
 * build_ia(state, &t1cntr);
 * add_address(state, context, lease_time, NULL, &min_time, &addr1, now);
 * add_address(state, context, lease_time, NULL, &min_time, &addr2, now);
 * end_ia(t1cntr, min_time, 1); // Apply fuzz for renewal randomization
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22.4: T1/T2 values in IA_NA option
 * - RFC 3315 Section 22.21: T1 < T2 < preferred < valid lifetime requirement
 *
 * SIDE EFFECTS:
 * - Seeks to t1cntr position in daemon->outpacket, writes 8 bytes (T1 + T2), restores position
 * - If do_fuzz true, calls rand16() for randomization
 *
 * THREAD SAFETY: Not thread-safe (modifies global daemon->outpacket, calls non-reentrant rand16())
 */
static void end_ia(int t1cntr, unsigned int min_time, int do_fuzz)
{
  if (t1cntr != 0)
    {
      /* go back and fill in fields in IA_NA option */
      int sav = save_counter(t1cntr);
      unsigned int t1, t2, fuzz = 0;

      if (do_fuzz)
	{
	  fuzz = rand16();
      
	  while (fuzz > (min_time/16))
	    fuzz = fuzz/2;
	}
      
      t1 = (min_time == 0xffffffff) ? 0xffffffff : min_time/2 - fuzz;
      t2 = (min_time == 0xffffffff) ? 0xffffffff : ((min_time/8)*7) - fuzz;
      put_opt6_long(t1);
      put_opt6_long(t2);
      save_counter(sav);
    }	
}

/**
 * @brief Add IAADDR suboption to IA response with allocated IPv6 address and lifetimes
 *
 * Constructs IAADDR suboption per RFC 3315 Section 22.6 containing allocated IPv6 address,
 * preferred lifetime (address usable for new connections), and valid lifetime (address
 * usable for existing connections). Honors client-requested lifetimes from ia_option if
 * provided, but clamps to server policy via calculate_times(). Updates or creates lease
 * in database if state->lease_allocate true (REPLY vs ADVERTISE). Accumulates context tags
 * for conditional configuration and logs allocation with log6_quiet().
 *
 * Preferred lifetime ≤ Valid lifetime per RFC 3315 Section 22.21. Address remains valid
 * for ongoing connections until valid lifetime expires, but should not be used for new
 * connections after preferred lifetime expires (deprecation). Lifetimes calculated from
 * context configuration, lease time override, and optional client hints.
 *
 * @param state Per-request state with CLID, XID, context tags for logging and configuration.
 *              state->lease_allocate determines if lease database modified (REPLY) or
 *              tentative allocation only (ADVERTISE).
 * @param context Address pool context providing default preferred/valid lifetime policy
 * @param lease_time Configured lease duration in seconds from static config or default,
 *                   used as baseline for lifetime calculation
 * @param ia_option Pointer to client's IAADDR suboption from request (if RENEW/REBIND)
 *                  containing requested preferred/valid lifetimes at offsets 16 and 20,
 *                  or NULL if SOLICIT (use defaults)
 * @param[in,out] min_time Pointer to accumulated minimum valid lifetime across all IAADDR
 *                         suboptions in IA, updated to min(current, valid_time) for T1/T2
 *                         calculation by end_ia()
 * @param addr IPv6 address to allocate/renew, already selected from pool by caller
 * @param now Current time_t for lease expiry calculation (valid_time + now = expiry)
 *
 * @return None (void function, adds IAADDR to daemon->outpacket and optionally updates leases)
 *
 * @note Only updates lease database if state->lease_allocate true. SOLICIT→ADVERTISE uses
 *       lease_allocate=0 for tentative allocation, REQUEST→REPLY uses lease_allocate=1
 *       for committed allocation.
 * @warning Caller must ensure addr is valid allocation from context pool and not duplicate.
 *          No duplicate address detection performed by this function.
 *
 * @see calculate_times() for preferred/valid lifetime policy enforcement
 * @see update_leases() for lease database modification
 * @see build_ia() and end_ia() for IA container construction
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned int min_time = 0xffffffff;
 * struct in6_addr addr;
 * select_address_from_pool(context, &addr); // Hypothetical allocation
 * add_address(state, context, 3600, NULL, &min_time, &addr, now);
 * end_ia(t1cntr, min_time, 1); // Finalize IA with calculated T1/T2
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22.6: IAADDR option format (address + preferred + valid)
 * - RFC 3315 Section 22.21: Lifetime relationships (preferred ≤ valid ≤ lease)
 * - RFC 3315 Section 18.2.4: Server SHOULD grant requested lifetimes if within policy
 *
 * SIDE EFFECTS:
 * - Writes IAADDR option (28 bytes: 16-byte address + 4-byte preferred + 4-byte valid +
 *   4-byte TLV header) to daemon->outpacket via put_opt6()
 * - Updates *min_time if valid_time < current *min_time
 * - Calls update_leases() to modify lease database if state->lease_allocate true
 * - Marks lease LEASE_USED flag if existing lease found via lease6_find_by_addr()
 * - Accumulates context->netid tags into state->context_tags for conditional config
 * - Logs allocation via log6_quiet() (respects OPT_QUIET_DHCP6)
 *
 * THREAD SAFETY: Not thread-safe (modifies global daemon structures and lease database)
 */
static void add_address(struct state *state, struct dhcp_context *context, unsigned int lease_time, void *ia_option, 
			unsigned int *min_time, struct in6_addr *addr, time_t now)
{
  unsigned int valid_time = 0, preferred_time = 0;
  int o = new_opt6(OPTION6_IAADDR);
  struct dhcp_lease *lease;

  /* get client requested times */
  if (ia_option)
    {
      preferred_time =  opt6_uint(ia_option, 16, 4);
      valid_time =  opt6_uint(ia_option, 20, 4);
    }

  calculate_times(context, min_time, &valid_time, &preferred_time, lease_time); 
  
  put_opt6(addr, sizeof(*addr));
  put_opt6_long(preferred_time);
  put_opt6_long(valid_time); 		    
  end_opt6(o);
  
  if (state->lease_allocate)
    update_leases(state, context, addr, valid_time, now);

  if ((lease = lease6_find_by_addr(addr, 128, 0)))
    lease->flags |= LEASE_USED;

  /* get tags from context if we've not used it before */
  if (context->netid.next == &context->netid && context->netid.net)
    {
      context->netid.next = state->context_tags;
      state->context_tags = &context->netid;
      
      if (!state->hostname_auth)
	{
	  struct dhcp_netid_list *id_list;
	  
	  for (id_list = daemon->dhcp_ignore_names; id_list; id_list = id_list->next)
	    if ((!id_list->list) || match_netid(id_list->list, &context->netid, 0))
	      break;
	  if (id_list)
	    state->hostname = NULL;
	}
    }

  log6_quiet(state, state->lease_allocate ? "DHCPREPLY" : "DHCPADVERTISE", addr, state->hostname);

}

/**
 * @brief Mark address pool context as having allocated address for tracking
 *
 * Sets CONTEXT_USED flag on all contexts in state->context chain whose IPv6 prefix matches
 * the allocated address. Used for tracking which address pools have active allocations to
 * prevent premature context reclamation and for statistics/monitoring. Multiple contexts
 * can match if address falls within overlapping ranges (e.g., specific /64 within broader /48).
 *
 * @param state Per-request state with context chain to search
 * @param addr Allocated IPv6 address to match against context prefixes
 *
 * @return None (void function, modifies context->flags)
 *
 * @note Uses is_same_net6() for prefix matching with context->prefix mask length
 * @warning Modifies context->flags for ALL matching contexts in chain, not just first match
 *
 * @see mark_config_used() for similar tracking at static config level
 *
 * EXAMPLE USAGE:
 * @code
 * mark_context_used(state, &allocated_addr); // Mark pool as used after allocation
 * @endcode
 *
 * RFC COMPLIANCE: Not RFC-mandated (internal tracking feature)
 *
 * SIDE EFFECTS: Sets context->flags |= CONTEXT_USED for all matching contexts
 * THREAD SAFETY: Not thread-safe (modifies shared context structures)
 */
static void mark_context_used(struct state *state, struct in6_addr *addr)
{
  struct dhcp_context *context;

  /* Mark that we have an address for this prefix. */
  for (context = state->context; context; context = context->current)
    if (is_same_net6(addr, &context->start6, context->prefix))
      context->flags |= CONTEXT_USED;
}

/**
 * @brief Mark address pool contexts as having static config address allocated
 *
 * Sets CONTEXT_CONF_USED flag on all contexts whose IPv6 prefix matches the statically
 * configured address from dhcp-host. Distinguishes between dynamic pool allocations
 * (CONTEXT_USED) and static host reservation usage (CONTEXT_CONF_USED) for address pool
 * management and statistics. Static reservations take priority over dynamic allocation,
 * so CONTEXT_CONF_USED indicates reserved address space within pool.
 *
 * @param context Address pool context chain to search and mark
 * @param addr IPv6 address from static dhcp-host configuration to match against prefixes
 *
 * @return None (void function, modifies context->flags)
 *
 * @note Typically called when allocating from dhcp_config->addr6 static reservation list
 * @warning Modifies ALL contexts whose prefix matches address, not just first match
 *
 * @see mark_context_used() for dynamic allocation tracking
 * @see config_valid() for validation of static config addresses
 *
 * EXAMPLE USAGE:
 * @code
 * if (config && config->addr6) {
 *     mark_config_used(context, &config->addr6->addr.addr6); // Mark static reservation
 * }
 * @endcode
 *
 * RFC COMPLIANCE: Not RFC-mandated (internal pool management feature)
 *
 * SIDE EFFECTS: Sets context->flags |= CONTEXT_CONF_USED for matching contexts
 * THREAD SAFETY: Not thread-safe (modifies shared context structures)
 */
static void mark_config_used(struct dhcp_context *context, struct in6_addr *addr)
{
  for (; context; context = context->current)
    if (is_same_net6(addr, &context->start6, context->prefix))
      context->flags |= CONTEXT_CONF_USED;
}

/**
 * @brief Verify IPv6 address available for allocation to current client
 *
 * Ensures address not already leased to different client (different DUID or IAID) to prevent
 * duplicate address allocation. Per RFC 3315, each DUID+IAID pair identifies unique client
 * Identity Association requiring distinct address set. Allows renewal if address already
 * leased to same DUID+IAID (client renewing existing allocation). Critical for preventing
 * IPv6 address conflicts and maintaining lease database integrity.
 *
 * Original comment preserved: "make sure address not leased to another CLID/IAID"
 *
 * @param state Per-request state containing clid (DUID) and clid_len for client identification,
 *              plus iaid (Identity Association Identifier) for IA matching
 * @param addr IPv6 address to check for availability
 *
 * @return 1 if address available (not leased, or leased to same DUID+IAID for renewal),
 *         0 if address already leased to different client (allocation forbidden)
 *
 * @note Performs exact byte-wise comparison of DUID (clid) and IAID. DUID comparison is
 *       case-sensitive as DUIDs are binary data, not text strings.
 * @warning Does not perform on-link duplicate address detection (DAD). Only checks lease
 *          database. Actual on-link conflicts detected by client ICMPv6 Neighbor Discovery.
 *
 * @see lease6_find_by_addr() for lease database lookup
 * @see add_address() for calling check_address() before allocation
 *
 * EXAMPLE USAGE:
 * @code
 * if (check_address(state, &candidate_addr)) {
 *     // Address available, proceed with allocation
 *     add_address(state, context, lease_time, ia_opt, &min_time, &candidate_addr, now);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 18.2: Server must not assign address to multiple clients
 * - RFC 3315 Section 25.6: IAID identifies IA, must match for address reuse
 *
 * SIDE EFFECTS: None (read-only lease database query)
 * THREAD SAFETY: Thread-safe (read-only operation on lease database)
 */
/* make sure address not leased to another CLID/IAID */
static int check_address(struct state *state, struct in6_addr *addr)
{ 
  struct dhcp_lease *lease;

  if (!(lease = lease6_find_by_addr(addr, 128, 0)))
    return 1;

  if (lease->clid_len != state->clid_len || 
      memcmp(lease->clid, state->clid, state->clid_len) != 0 ||
      lease->iaid != state->iaid)
    return 0;

  return 1;
}

/**
 * @brief Check if IPv6 address matches static dhcp-host configuration address pattern
 *
 * Validates whether candidate address could have been generated from specified dhcp-host
 * configuration by testing against config's static address list (config->addr6). Supports
 * wildcard host-part addressing (e.g., dhcp-host=id:*,::1234 meaning any /64 with host
 * portion ::1234) and explicit prefix specifications. Returns matching addrlist entry if
 * address implies configuration, NULL if no match. Used for renewal validation to verify
 * client renewing address originally allocated from static reservation.
 *
 * Original comment preserved: "return true of *addr could have been generated from config."
 * (Note: Typo "of" vs "if" preserved from original for historical accuracy)
 *
 * Matching logic: For each addr6 in config->addr6 list:
 * - If ADDRLIST_WILDCARD and context->prefix==64: Match network part from context->start6
 *   with host part from config->addr6, allowing ::1234 to match 2001:db8::1234 in subnet
 * - If ADDRLIST_PREFIX set: Use addr_list->prefixlen for subnet matching (e.g., /60)
 * - Otherwise: Full 128-bit address match or context subnet match
 *
 * @param config Static dhcp-host configuration (dhcp-host=duid:...,addr6:...), NULL if none
 * @param context Address pool context providing network prefix (context->start6, context->prefix)
 * @param addr Candidate IPv6 address to test against config patterns
 *
 * @return Pointer to matching addrlist entry from config->addr6 chain if address matches pattern,
 *         NULL if no config, config lacks CONFIG_ADDR6 flag, or no address pattern matches
 *
 * @note Wildcard matching requires context->prefix == 64 (single subnet). Non-/64 prefixes
 *       cannot use wildcard host-part addressing (returns NULL for wildcard on non-/64).
 * @warning Does not validate if address is actually allocated or available. Only checks
 *          pattern match between address and static configuration address list.
 *
 * @see config_valid() for finding valid available address from static configuration
 * @see check_address() for verifying address not leased to another client
 *
 * EXAMPLE USAGE:
 * @code
 * struct addrlist *matched = config_implies(config, context, &renewal_addr);
 * if (matched) {
 *     // Address matches static reservation pattern, allow renewal
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 18.2.3: Server should honor client-requested addresses if valid
 *
 * SIDE EFFECTS: None (read-only validation, no state modifications)
 * THREAD SAFETY: Thread-safe (read-only operation)
 */
/* return true of *addr could have been generated from config. */
static struct addrlist *config_implies(struct dhcp_config *config, struct dhcp_context *context, struct in6_addr *addr)
{
  int prefix;
  struct in6_addr wild_addr;
  struct addrlist *addr_list;
  
  if (!config || !(config->flags & CONFIG_ADDR6))
    return NULL;
  
  for (addr_list = config->addr6; addr_list; addr_list = addr_list->next)
    {
      prefix = (addr_list->flags & ADDRLIST_PREFIX) ? addr_list->prefixlen : 128;
      wild_addr = addr_list->addr.addr6;
      
      if ((addr_list->flags & ADDRLIST_WILDCARD) && context->prefix == 64)
	{
	  wild_addr = context->start6;
	  setaddr6part(&wild_addr, addr6part(&addr_list->addr.addr6));
	}
      else if (!is_same_net6(&context->start6, addr, context->prefix))
	continue;
      
      if (is_same_net6(&wild_addr, addr, prefix))
	return addr_list;
    }
  
  return NULL;
}

/**
 * @brief Find valid available address from static dhcp-host configuration
 *
 * Searches dhcp-host static address configuration (config->addr6 list) for available address
 * matching current context and not already leased to another client. Handles prefix ranges
 * (e.g., addr6=2001:db8::100-1ff/120 allocates from 128-address range) and wildcard host
 * portions. Skips addresses marked ADDRLIST_DECLINED unless DECLINE_BACKOFF (10 minutes)
 * elapsed since decline, allowing gradual decline recovery. Returns via *addr pointer
 * modification, setting to first valid available address found. Returns 1 on success, 0 if
 * no valid address available from configuration.
 *
 * Address validation per entry:
 * - ADDRLIST_DECLINED: Skip if decline_time < now-DECLINE_BACKOFF (recent decline)
 * - ADDRLIST_PREFIX: Iterate through all addresses in prefix range (2^(128-prefixlen))
 * - ADDRLIST_WILDCARD: Substitute network part from context->start6 (requires /64)
 * - For each candidate: check_address(state, addr) ensures not leased to different client
 *
 * @param config Static dhcp-host configuration with addr6 address list, NULL returns 0
 * @param context Address pool context providing network prefix and subnet boundaries
 * @param[out] addr Pointer to in6_addr to receive valid address if found, modified on success
 * @param state Per-request state with clid/iaid for check_address() lease conflict detection
 * @param now Current time_t for decline backoff calculation (DECLINE_BACKOFF = 600 seconds)
 *
 * @return 1 if valid available address found (addr set to valid address),
 *         0 if no config, config lacks CONFIG_ADDR6, or all addresses declined/leased
 *
 * @note Prefix ranges allow single dhcp-host entry to reserve multiple addresses
 *       (e.g., /120 = 256 addresses from ::0 to ::ff). Useful for host pools.
 * @warning Wildcard addressing requires context->prefix == 64. Non-/64 contexts skip
 *          wildcard entries (continue to next addr_list entry).
 *
 * @see config_implies() for testing if address matches config pattern
 * @see check_address() for per-address availability validation
 * @see add_address() for allocating valid address from config
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr static_addr;
 * if (config_valid(config, context, &static_addr, state, now)) {
 *     // static_addr contains valid available address from static reservation
 *     add_address(state, context, lease_time, ia_opt, &min_time, &static_addr, now);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 18: Static address reservations per DUID
 * - RFC 8415 Section 18.3.12: DHCPv6 DECLINE for duplicate detection recovery
 *
 * SIDE EFFECTS:
 * - Modifies *addr output parameter with valid address on success
 * - Calls check_address() which performs read-only lease database query
 * - setaddr6part() used to construct candidate addresses in-place in *addr
 *
 * THREAD SAFETY: Thread-safe (read-only on config/context, modifies only caller's addr)
 */
static int config_valid(struct dhcp_config *config, struct dhcp_context *context, struct in6_addr *addr, struct state *state, time_t now)
{
  u64 addrpart, i, addresses;
  struct addrlist *addr_list;
  
  if (!config || !(config->flags & CONFIG_ADDR6))
    return 0;

  for (addr_list = config->addr6; addr_list; addr_list = addr_list->next)
    if (!(addr_list->flags & ADDRLIST_DECLINED) ||
	difftime(now, addr_list->decline_time) >= (float)DECLINE_BACKOFF)
      {
	addrpart = addr6part(&addr_list->addr.addr6);
	addresses = 1;
	
	if (addr_list->flags & ADDRLIST_PREFIX)
	  addresses = (u64)1<<(128-addr_list->prefixlen);
	
	if ((addr_list->flags & ADDRLIST_WILDCARD))
	  {
	    if (context->prefix != 64)
	      continue;
	    
	    *addr = context->start6;
	  }
	else if (is_same_net6(&context->start6, &addr_list->addr.addr6, context->prefix))
	  *addr = addr_list->addr.addr6;
	else
	  continue;
	
	for (i = 0 ; i < addresses; i++)
	  {
	    setaddr6part(addr, addrpart+i);
	    
	    if (check_address(state, addr))
	      return 1;
	  }
      }
  
  return 0;
}

/**
 * @brief Calculate valid and preferred lifetimes for IAADDR option in DHCPv6 replies
 *
 * Determines appropriate valid (total address usability) and preferred (new connection usage)
 * lifetimes to send in IAADDR response option by honoring client-requested lifetimes from
 * RENEW/REBIND while enforcing server policy limits. Per RFC 3315 Section 22.21, preferred
 * lifetime must not exceed valid lifetime. Applies minimum 120-second sanity floor to prevent
 * unreasonably short lifetimes. Handles address deprecation (preferred=0) when context marked
 * CONTEXT_DEPRECATE or when local interface address deprecated. Tracks minimum lifetime
 * across multiple addresses in IA for T1/T2 renewal timer calculation by end_ia().
 *
 * Lifetime semantics per RFC 3315: preferred lifetime is duration address SHOULD be used for
 * new connections (after expiry, address "deprecated" but still valid for existing connections).
 * Valid lifetime is total duration address MAY be used (after expiry, address invalid and
 * packets discarded). Relationship: 0 ≤ preferred ≤ valid ≤ lease_time.
 *
 * INPUTS (passed by reference, modified in-place):
 * - *valid_timep: Client-requested valid lifetime from IAADDR option (0 = no preference)
 * - *preferred_timep: Client-requested preferred lifetime from IAADDR option (0 = no preference)
 * - *min_time: Accumulated minimum valid lifetime across all IAADDR in IA
 *
 * INPUTS (read-only):
 * - context: Address pool with context->valid, context->preferred (local interface lifetimes),
 *           context->flags & CONTEXT_DEPRECATE (explicit deprecation flag)
 * - lease_time: Server policy lease duration from dhcp-range configuration
 *
 * OUTPUTS (via pointer modification):
 * - *valid_timep: Calculated valid lifetime to send (min of requested and policy)
 * - *preferred_timep: Calculated preferred lifetime (min of requested and policy, or 0 if deprecated)
 * - *min_time: Updated to minimum of existing *min_time and calculated valid_time
 *
 * @param context Address pool context providing server policy limits and deprecation status
 * @param[in,out] min_time Pointer to minimum valid lifetime accumulator for T1/T2 calculation,
 *                         updated if valid_time < *min_time
 * @param[in,out] valid_timep Pointer to valid lifetime: input is client request (0=no preference),
 *                            output is server-determined lifetime (≥120 seconds, ≤lease_time)
 * @param[in,out] preferred_timep Pointer to preferred lifetime: input is client request,
 *                                output is server-determined lifetime (0 if deprecated, ≤valid_time)
 * @param lease_time Server policy lease duration in seconds from dhcp-range or static config
 *
 * @return None (void function, modifies lifetime pointers in-place)
 *
 * @note Client requests of 0 for preferred or valid lifetime mean "no preference, use server
 *       default" per RFC 3315 Section 22.6, not "zero lifetime" or "infinite lifetime".
 * @warning RFC 3315 compliance: If client requests preferred > valid, server MUST ignore both
 *          client requests and use server defaults. This prevents invalid lifetime relationships.
 *
 * @see end_ia() for using *min_time to calculate T1 (renewal) and T2 (rebind) timers
 * @see add_address() for calling calculate_times() during address allocation
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned int min_time = 0xffffffff;
 * unsigned int valid = 7200, preferred = 3600; // Client requested
 * calculate_times(context, &min_time, &valid, &preferred, lease_time);
 * // Now valid and preferred clamped to policy, min_time updated
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22.6: IAADDR preferred/valid lifetime fields
 * - RFC 3315 Section 22.21: Lifetime relationships (preferred ≤ valid)
 * - RFC 3315 Section 18.2.4: Server SHOULD grant requested lifetimes within policy
 *
 * SIDE EFFECTS:
 * - Modifies *valid_timep, *preferred_timep, *min_time via pointers
 * - No global state modifications
 *
 * THREAD SAFETY: Thread-safe (only modifies caller-provided pointers, no shared state)
 */
static void calculate_times(struct dhcp_context *context, unsigned int *min_time, unsigned int *valid_timep, 
			    unsigned int *preferred_timep, unsigned int lease_time)
{
  unsigned int req_preferred = *preferred_timep, req_valid = *valid_timep;
  unsigned int valid_time = lease_time, preferred_time = lease_time;
  
  /* RFC 3315: "A server ignores the lifetimes set
     by the client if the preferred lifetime is greater than the valid
     lifetime. */
  if (req_preferred <= req_valid)
    {
      if (req_preferred != 0)
	{
	  /* 0 == "no preference from client" */
	  if (req_preferred < 120u)
	    req_preferred = 120u; /* sanity */
	  
	  if (req_preferred < preferred_time)
	    preferred_time = req_preferred;
	}
      
      if (req_valid != 0)
	/* 0 == "no preference from client" */
	{
	  if (req_valid < 120u)
	    req_valid = 120u; /* sanity */
	  
	  if (req_valid < valid_time)
	    valid_time = req_valid;
	}
    }

  /* deprecate (preferred == 0) which configured, or when local address 
     is deprecated */
  if ((context->flags & CONTEXT_DEPRECATE) || context->preferred == 0)
    preferred_time = 0;
  
  if (preferred_time != 0 && preferred_time < *min_time)
    *min_time = preferred_time;
  
  if (valid_time != 0 && valid_time < *min_time)
    *min_time = valid_time;
  
  *valid_timep = valid_time;
  *preferred_timep = preferred_time;
}

/**
 * @brief Update DHCPv6 lease database with allocated/renewed address information
 *
 * Creates new lease or updates existing lease in persistent lease database (daemon->dhcp6)
 * with binding between client DUID+IAID and allocated IPv6 address. Sets lease expiry,
 * hardware address, hostname for DNS updates, and interface association. For OPTION6_IA_NA
 * (non-temporary addresses), associates hostname and domain for DDNS updates. Conditionally
 * invokes lease-change script (HAVE_SCRIPT) with client classification tags and vendor class
 * information for external integration (e.g., DNS updates, firewall rules, monitoring).
 *
 * Lease lifecycle: lease6_find_by_addr() searches for existing lease by address, if not found
 * lease6_allocate() creates new entry. Lease persisted to lease file (typically
 * /var/lib/misc/dnsmasq.leases6) for survival across daemon restarts. Lease expiry triggers
 * automatic reclamation for pool reuse.
 *
 * @param state Per-request state with CLID (DUID), clid_len, iaid (Identity Association ID),
 *              mac/mac_len/mac_type (client MAC from OPTION6_CLIENT_MAC or ND cache),
 *              hostname (validated client hostname for DDNS), interface (receiving interface
 *              index), ia_type (OPTION6_IA_NA or OPTION6_IA_TA), tags (accumulated config tags),
 *              packet_options/end (for VENDOR_CLASS/USER_CLASS extraction)
 * @param context Address pool context (currently unused but passed for future extensions,
 *                marked (void)context to suppress compiler warning)
 * @param addr IPv6 address being allocated/renewed (lease binding key)
 * @param lease_time Lease duration in seconds from add_address() calculation
 * @param now Current time_t for lease expiry calculation (expires = now + lease_time)
 *
 * @return None (void function, modifies global lease database and optionally queues script)
 *
 * @note OPTION6_IA_TA (temporary addresses) do not get hostname/domain association as they
 *       are intentionally unlinkable per RFC 4941 privacy extensions. Only IA_NA addresses
 *       eligible for DDNS updates.
 * @warning If HAVE_SCRIPT enabled and daemon->lease_change_command configured, this function
 *          allocates lease extradata (vendor class, user class, tags, link-address) which
 *          triggers asynchronous helper process via queue_script(). Helper invoked later
 *          from event loop, not synchronously during update_leases().
 *
 * @see lease6_find_by_addr() for existing lease lookup
 * @see lease6_allocate() for new lease creation
 * @see lease_add_extradata() for script parameter construction
 * @see queue_script() for asynchronous lease-change script invocation
 *
 * EXAMPLE USAGE:
 * @code
 * if (state->lease_allocate) // REPLY not ADVERTISE
 *     update_leases(state, context, &allocated_addr, lease_time, now);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 18: Lease binding creation per DUID+IAID
 * - RFC 4704: DHCPv6 Client FQDN Option for hostname registration
 *
 * SIDE EFFECTS:
 * - Calls lease6_find_by_addr() searching global daemon->dhcp6 lease list
 * - Calls lease6_allocate() creating new lease entry if not found
 * - Modifies lease fields: expires, iaid, hwaddr (DUID), interface, hostname, flags
 * - Sets lease->flags |= LEASE_CHANGED if lease-change script configured
 * - Allocates/frees lease->extradata with client classification for script parameters
 * - Calls get_domain6() to determine domain suffix from address
 * - Modifies state->send_domain if not already set (for FQDN option reply)
 * - Logs lease modification if logging enabled
 *
 * THREAD SAFETY: Not thread-safe (modifies global lease database without locking)
 */
static void update_leases(struct state *state, struct dhcp_context *context, struct in6_addr *addr, unsigned int lease_time, time_t now)
{
  struct dhcp_lease *lease = lease6_find_by_addr(addr, 128, 0);
#ifdef HAVE_SCRIPT
  struct dhcp_netid *tagif = run_tag_if(state->tags);
#endif

  (void)context;

  if (!lease)
    lease = lease6_allocate(addr, state->ia_type == OPTION6_IA_NA ? LEASE_NA : LEASE_TA);
  
  if (lease)
    {
      lease_set_expires(lease, lease_time, now);
      lease_set_iaid(lease, state->iaid); 
      lease_set_hwaddr(lease, state->mac, state->clid, state->mac_len, state->mac_type, state->clid_len, now, 0);
      lease_set_interface(lease, state->interface, now);
      if (state->hostname && state->ia_type == OPTION6_IA_NA)
	{
	  char *addr_domain = get_domain6(addr);
	  if (!state->send_domain)
	    state->send_domain = addr_domain;
	  lease_set_hostname(lease, state->hostname, state->hostname_auth, addr_domain, state->domain);
	}
      
#ifdef HAVE_SCRIPT
      if (daemon->lease_change_command)
	{
	  void *class_opt;
	  lease->flags |= LEASE_CHANGED;
	  free(lease->extradata);
	  lease->extradata = NULL;
	  lease->extradata_size = lease->extradata_len = 0;
	  lease->vendorclass_count = 0; 
	  
	  if ((class_opt = opt6_find(state->packet_options, state->end, OPTION6_VENDOR_CLASS, 4)))
	    {
	      void *enc_opt, *enc_end = opt6_ptr(class_opt, opt6_len(class_opt));
	      lease->vendorclass_count++;
	      /* send enterprise number first  */
	      sprintf(daemon->dhcp_buff2, "%u", opt6_uint(class_opt, 0, 4));
	      lease_add_extradata(lease, (unsigned char *)daemon->dhcp_buff2, strlen(daemon->dhcp_buff2), 0);
	      
	      if (opt6_len(class_opt) >= 6) 
		for (enc_opt = opt6_ptr(class_opt, 4); enc_opt; enc_opt = opt6_next(enc_opt, enc_end))
		  {
		    lease->vendorclass_count++;
		    lease_add_extradata(lease, opt6_ptr(enc_opt, 0), opt6_len(enc_opt), 0);
		  }
	    }
	  
	  lease_add_extradata(lease, (unsigned char *)state->client_hostname, 
			      state->client_hostname ? strlen(state->client_hostname) : 0, 0);				
	  
	  /* space-concat tag set */
	  if (!tagif && !context->netid.net)
	    lease_add_extradata(lease, NULL, 0, 0);
	  else
	    {
	      if (context->netid.net)
		lease_add_extradata(lease, (unsigned char *)context->netid.net, strlen(context->netid.net), tagif ? ' ' : 0);
	      
	      if (tagif)
		{
		  struct dhcp_netid *n;
		  for (n = tagif; n; n = n->next)
		    {
		      struct dhcp_netid *n1;
		      /* kill dupes */
		      for (n1 = n->next; n1; n1 = n1->next)
			if (strcmp(n->net, n1->net) == 0)
			  break;
		      if (!n1)
			lease_add_extradata(lease, (unsigned char *)n->net, strlen(n->net), n->next ? ' ' : 0); 
		    }
		}
	    }
	  
	  if (state->link_address)
	    inet_ntop(AF_INET6, state->link_address, daemon->addrbuff, ADDRSTRLEN);
	  
	  lease_add_extradata(lease, (unsigned char *)daemon->addrbuff, state->link_address ? strlen(daemon->addrbuff) : 0, 0);
	  
	  if ((class_opt = opt6_find(state->packet_options, state->end, OPTION6_USER_CLASS, 2)))
	    {
	      void *enc_opt, *enc_end = opt6_ptr(class_opt, opt6_len(class_opt));
	      for (enc_opt = opt6_ptr(class_opt, 0); enc_opt; enc_opt = opt6_next(enc_opt, enc_end))
		lease_add_extradata(lease, opt6_ptr(enc_opt, 0), opt6_len(enc_opt), 0);
	    }
	}
#endif	
      
    }
}
			  
			
	
/**
 * @brief Log all DHCPv6 options in packet or nested IA option for debugging
 *
 * Recursively iterates through DHCPv6 option list logging each option's type, size,
 * and decoded value to syslog when OPT_LOG_OPTS enabled. Provides special handling
 * for Identity Association options (IA_NA, IA_TA) with IAADDR suboptions, recursively
 * logging nested options within IA containers. Essential for troubleshooting client
 * configuration issues and verifying option encoding correctness.
 *
 * @param nest Recursion depth indicator: 0 for top-level options (labeled "sent"),
 *             1+ for nested options within IA_NA/IA_TA/IAADDR (labeled "nest")
 * @param xid Transaction ID for correlation with packet in logs (24-bit from header)
 * @param start_opts Starting boundary of options to log
 * @param end_opts Ending boundary of options area
 *
 * @return None (void function, output to syslog only)
 *
 * @note Special formatting for IA_NA (shows IAID, T1, T2), IA_TA (shows IAID),
 *       IAADDR (shows IPv6 address, preferred/valid lifetimes), STATUS_CODE (shows
 *       status code number and message text). Other options formatted via option_string().
 * @warning Truncates very long option values to fit in daemon->namebuff (MAXDNAME bytes).
 *          CLID longer than 100 bytes truncated to prevent buffer overflow.
 *
 * EXAMPLE USAGE:
 * @code
 * log6_opts(0, state->xid, state->packet_options, state->end); // Log request options
 * log6_opts(0, state->xid, daemon->outpacket, outpacket_end);  // Log reply options
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22: All standard DHCPv6 options decoded and labeled
 * - RFC 3315 Section 22.4-22.6: IA_NA/IA_TA/IAADDR structure correctly parsed
 *
 * SIDE EFFECTS:
 * - Writes log messages to syslog via my_syslog() for each option found
 * - Modifies daemon->namebuff and daemon->addrbuff for temporary string formatting
 * - Recursively calls itself for nested IA options (stack depth limited by nesting)
 *
 * THREAD SAFETY: Not thread-safe (uses global daemon buffers for string formatting)
 */
static void log6_opts(int nest, unsigned int xid, void *start_opts, void *end_opts)
{
  void *opt;
  char *desc = nest ? "nest" : "sent";
  
  if (!option_bool(OPT_LOG_OPTS) || start_opts == end_opts)
    return;
  
  for (opt = start_opts; opt; opt = opt6_next(opt, end_opts))
    {
      int type = opt6_type(opt);
      void *ia_options = NULL;
      char *optname;
      
      if (type == OPTION6_IA_NA)
	{
	  sprintf(daemon->namebuff, "IAID=%u T1=%u T2=%u",
		  opt6_uint(opt, 0, 4), opt6_uint(opt, 4, 4), opt6_uint(opt, 8, 4));
	  optname = "ia-na";
	  ia_options = opt6_ptr(opt, 12);
	}
      else if (type == OPTION6_IA_TA)
	{
	  sprintf(daemon->namebuff, "IAID=%u", opt6_uint(opt, 0, 4));
	  optname = "ia-ta";
	  ia_options = opt6_ptr(opt, 4);
	}
      else if (type == OPTION6_IAADDR)
	{
	  struct in6_addr addr;

	  /* align */
	  memcpy(&addr, opt6_ptr(opt, 0), IN6ADDRSZ);
	  inet_ntop(AF_INET6, &addr, daemon->addrbuff, ADDRSTRLEN);
	  sprintf(daemon->namebuff, "%s PL=%u VL=%u", 
		  daemon->addrbuff, opt6_uint(opt, 16, 4), opt6_uint(opt, 20, 4));
	  optname = "iaaddr";
	  ia_options = opt6_ptr(opt, 24);
	}
      else if (type == OPTION6_STATUS_CODE)
	{
	  int len = sprintf(daemon->namebuff, "%u ", opt6_uint(opt, 0, 2));
	  memcpy(daemon->namebuff + len, opt6_ptr(opt, 2), opt6_len(opt)-2);
	  daemon->namebuff[len + opt6_len(opt) - 2] = 0;
	  optname = "status";
	}
      else
	{
	  /* account for flag byte on FQDN */
	  int offset = type == OPTION6_FQDN ? 1 : 0;
	  optname = option_string(AF_INET6, type, opt6_ptr(opt, offset), opt6_len(opt) - offset, daemon->namebuff, MAXDNAME);
	}
      
      my_syslog(MS_DHCP | LOG_INFO, "%u %s size:%3d option:%3d %s  %s", 
		xid, desc, opt6_len(opt), type, optname, daemon->namebuff);
      
      if (ia_options)
	log6_opts(1, xid, ia_options, opt6_ptr(opt, opt6_len(opt)));
    }
}		 
 
/**
 * @brief Conditionally log DHCPv6 packet based on quiet mode setting
 *
 * Wrapper around log6_packet() that respects OPT_QUIET_DHCP6 configuration option.
 * Logs packet only if explicit option logging enabled (OPT_LOG_OPTS) or quiet mode
 * disabled. Enables selective DHCPv6 transaction logging without flooding syslog with
 * routine SOLICIT/ADVERTISE/REQUEST/REPLY exchanges in high-traffic environments.
 *
 * @param state Per-request state with CLID, XID, interface for logging context
 * @param type Message type string for display: "SOLICIT", "ADVERTISE", "REQUEST", "REPLY", etc.
 * @param addr IPv6 address to log (allocated/renewed/released), or NULL if not applicable
 * @param string Additional context string (hostname, status message), or NULL
 *
 * @return None (void function)
 *
 * @note Typical usage: log6_quiet() for routine transactions (SOLICIT, REQUEST),
 *       log6_packet() for exceptional conditions (DECLINE, errors) to bypass quiet mode
 *
 * EXAMPLE USAGE:
 * @code
 * log6_quiet(state, "SOLICIT", NULL, hostname);  // May be suppressed by OPT_QUIET_DHCP6
 * log6_packet(state, "DECLINE", &declined_addr, "address conflict"); // Always logged
 * @endcode
 *
 * RFC COMPLIANCE: Not RFC-mandated (operational logging feature only)
 *
 * SIDE EFFECTS: Conditionally calls log6_packet() which logs to syslog
 * THREAD SAFETY: Inherits thread-safety properties of log6_packet()
 */
static void log6_quiet(struct state *state, char *type, struct in6_addr *addr, char *string)
{
  if (option_bool(OPT_LOG_OPTS) || !option_bool(OPT_QUIET_DHCP6))
    log6_packet(state, type, addr, string);
}

/**
 * @brief Log DHCPv6 packet transaction with client DUID, address, and message
 *
 * Primary DHCPv6 logging function formatting transaction information for syslog:
 * transaction ID, message type, receiving interface, IPv6 address (if applicable),
 * client DUID (formatted as hex MAC address style), and optional status string.
 * Provides essential audit trail of all DHCPv6 address allocations, renewals, and
 * releases for troubleshooting and compliance.
 *
 * @param state Per-request state containing clid (DUID), clid_len, xid (transaction ID),
 *              iface_name (receiving interface) for log message formatting
 * @param type Message type string: "SOLICIT", "ADVERTISE", "REQUEST", "REPLY", "RENEW",
 *             "REBIND", "CONFIRM", "RELEASE", "DECLINE", "INFORMATION-REQUEST"
 * @param addr IPv6 address being allocated/renewed/released, or NULL if not address-related
 *             (e.g., INFORMATION-REQUEST for stateless configuration)
 * @param string Optional contextual information: hostname, error message, status description
 *
 * @return None (void function, output to syslog only)
 *
 * @note CLID truncated to 100 bytes if longer to prevent buffer overflow in print_mac().
 *       Format varies based on OPT_LOG_OPTS: includes transaction ID if option logging
 *       enabled, omits XID for cleaner logs in non-verbose mode.
 * @warning Uses global daemon->namebuff and daemon->dhcp_buff2 for temporary formatting,
 *          not reentrant if called from multiple threads simultaneously
 *
 * EXAMPLE USAGE:
 * @code
 * log6_packet(state, "ADVERTISE", NULL, "no address available");
 * log6_packet(state, "REPLY", &allocated_addr, client_hostname);
 * log6_packet(state, "RELEASE", &released_addr, NULL);
 * @endcode
 *
 * RFC COMPLIANCE: Not RFC-mandated (operational logging feature)
 *
 * SIDE EFFECTS:
 * - Writes formatted message to syslog via my_syslog() at LOG_INFO level with MS_DHCP tag
 * - Modifies daemon->namebuff (for CLID hex formatting) and daemon->dhcp_buff2 (for IPv6 address)
 *
 * THREAD SAFETY: Not thread-safe due to global buffer usage
 */
static void log6_packet(struct state *state, char *type, struct in6_addr *addr, char *string)
{
  int clid_len = state->clid_len;

  /* avoid buffer overflow */
  if (clid_len > 100)
    clid_len = 100;
  
  print_mac(daemon->namebuff, state->clid, clid_len);

  if (addr)
    {
      inet_ntop(AF_INET6, addr, daemon->dhcp_buff2, DHCP_BUFF_SZ - 1);
      strcat(daemon->dhcp_buff2, " ");
    }
  else
    daemon->dhcp_buff2[0] = 0;

  if(option_bool(OPT_LOG_OPTS))
    my_syslog(MS_DHCP | LOG_INFO, "%u %s(%s) %s%s %s",
	      state->xid, 
	      type,
	      state->iface_name, 
	      daemon->dhcp_buff2,
	      daemon->namebuff,
	      string ? string : "");
  else
    my_syslog(MS_DHCP | LOG_INFO, "%s(%s) %s%s %s",
	      type,
	      state->iface_name, 
	      daemon->dhcp_buff2,
	      daemon->namebuff,
	      string ? string : "");
}

/**
 * @brief Search for specific DHCPv6 option in TLV option list
 *
 * Iterates through DHCPv6 option list searching for option matching specified type code.
 * Each option follows TLV (Type-Length-Value) format: 2-byte type, 2-byte length,
 * variable-length value. Validates option boundaries to prevent buffer overruns and
 * ensures found option meets minimum size requirement. Returns pointer to option start
 * (beginning of type field) or NULL if not found.
 *
 * @param opts Starting position of option search (typically state->packet_options)
 * @param end End boundary of option area for bounds checking (typically state->end)
 * @param search Option type code to find (e.g., OPTION6_CLIENT_ID, OPTION6_IA_NA)
 * @param minsize Minimum required value length in bytes (0 for no size check)
 *
 * @return Pointer to start of matching option (type field), or NULL if not found,
 *         opts is NULL, option too short, or buffer boundary exceeded
 *
 * @note Returned pointer points to 2-byte type field. Use opt6_ptr(result, 0) to
 *       access value, opt6_len(result) for length, opt6_type(result) for type.
 * @warning Does not validate option-specific value format, only length. Caller must
 *          perform additional validation for complex options like IA_NA.
 *
 * EXAMPLE USAGE:
 * @code
 * void *client_id_opt = opt6_find(state->packet_options, state->end, OPTION6_CLIENT_ID, 1);
 * if (client_id_opt) {
 *     state->clid = opt6_ptr(client_id_opt, 0);
 *     state->clid_len = opt6_len(client_id_opt);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22.1: DHCPv6 option format (2-byte type, 2-byte length, value)
 *
 * SIDE EFFECTS: None (read-only option scanning)
 * THREAD SAFETY: Thread-safe (pure function, no shared state modification)
 */
static void *opt6_find (void *opts, void *end, unsigned int search, unsigned int minsize)
{
  u16 opt, opt_len;
  void *start;
  
  if (!opts)
    return NULL;
    
  while (1)
    {
      if (end - opts < 4) 
	return NULL;
      
      start = opts;
      GETSHORT(opt, opts);
      GETSHORT(opt_len, opts);
      
      if (opt_len > (end - opts))
	return NULL;
      
      if (opt == search && (opt_len >= minsize))
	return start;
      
      opts += opt_len;
    }
}

/**
 * @brief Advance to next DHCPv6 option in TLV list
 *
 * Calculates pointer to next option by reading current option's length field and
 * skipping past its value. Used for iterating through all options when specific
 * option type is not known in advance. Performs bounds checking to prevent reading
 * past end of options area.
 *
 * @param opts Pointer to current option start (type field)
 * @param end End boundary of options area for bounds checking
 *
 * @return Pointer to start of next option (type field), or NULL if no more options
 *         (insufficient space for 4-byte header, or length extends past end boundary)
 *
 * @note Typical usage pattern: for (opt = opts; opt; opt = opt6_next(opt, end))
 * @warning Caller must validate returned pointer is not NULL before dereferencing
 *
 * EXAMPLE USAGE:
 * @code
 * for (void *opt = opts; opt; opt = opt6_next(opt, end)) {
 *     unsigned int opt_type = opt6_type(opt);
 *     if (opt_type == OPTION6_IA_NA) process_ia_na(opt);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315 Section 22.1: Option format enables sequential option iteration
 *
 * SIDE EFFECTS: None (read-only pointer arithmetic)
 * THREAD SAFETY: Thread-safe (pure function)
 */
static void *opt6_next(void *opts, void *end)
{
  u16 opt_len;
  
  if (end - opts < 4) 
    return NULL;
  
  opts += 2;
  GETSHORT(opt_len, opts);
  
  if (opt_len >= (end - opts))
    return NULL;
  
  return opts + opt_len;
}

/**
 * @brief Extract unsigned integer from DHCPv6 option with unaligned data handling
 *
 * Reads multi-byte unsigned integer from option data handling both unaligned memory
 * access and network byte order (big-endian) conversion. Supports extracting integers
 * at negative offsets (for type/length fields before option value) or positive offsets
 * (within option value). Safely handles 1-byte, 2-byte, or 4-byte integers.
 *
 * Original comment preserved: "this worries about unaligned data and byte order" - critical
 * for portability to architectures requiring aligned memory access (SPARC, older ARM).
 *
 * @param opt Pointer to option value start (after 4-byte TLV header), NOT to type field
 * @param offset Byte offset from opt pointer: negative for type/length fields (-4 for type,
 *               -2 for length), positive or 0 for value fields
 * @param size Number of bytes to read: 1, 2, or 4 for uint8/uint16/uint32 extraction
 *
 * @return Unsigned integer value in host byte order (big-endian converted to host endian)
 *
 * @note Commonly used via macros: opt6_len(opt) calls opt6_uint(opt, -2, 2),
 *       opt6_type(opt) calls opt6_uint(opt, -4, 2)
 * @warning Caller must ensure offset and size do not exceed option boundaries to avoid
 *          reading invalid memory. No bounds checking performed.
 *
 * EXAMPLE USAGE:
 * @code
 * void *ia_na_opt = opt6_find(opts, end, OPTION6_IA_NA, 12);
 * unsigned int iaid = opt6_uint(opt6_ptr(ia_na_opt, 0), 0, 4); // Extract 4-byte IAID
 * unsigned int t1 = opt6_uint(opt6_ptr(ia_na_opt, 0), 4, 4);   // Extract T1 timer
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 3315: All DHCPv6 integers in network byte order (big-endian per RFC 1700)
 *
 * SIDE EFFECTS: None (read-only memory access)
 * THREAD SAFETY: Thread-safe (pure function, no shared state)
 */
static unsigned int opt6_uint(unsigned char *opt, int offset, int size)
{
  /* this worries about unaligned data and byte order */
  unsigned int ret = 0;
  int i;
  unsigned char *p = opt6_ptr(opt, offset);
  
  for (i = 0; i < size; i++)
    ret = (ret << 8) | *p++;
  
  return ret;
} 

int relay_upstream6(int iface_index, ssize_t sz, 
		    struct in6_addr *peer_address, u32 scope_id, time_t now)
{
  unsigned char *header;
  unsigned char *inbuff = daemon->dhcp_packet.iov_base;
  int msg_type = *inbuff;
  int hopcount, o;
  struct in6_addr multicast;
  unsigned int maclen, mactype;
  unsigned char mac[DHCP_CHADDR_MAX];
  struct dhcp_relay *relay;
  
  for (relay = daemon->relay6; relay; relay = relay->next)
    if (relay->iface_index != 0 && relay->iface_index == iface_index)
      break;

  /* No relay config. */
  if (!relay)
    return 0;
  
  inet_pton(AF_INET6, ALL_SERVERS, &multicast);
  get_client_mac(peer_address, scope_id, mac, &maclen, &mactype, now);
  
  /* Get hop count from nested relayed message */ 
  if (msg_type == DHCP6RELAYFORW)
    hopcount = *((unsigned char *)inbuff+1) + 1;
  else
    hopcount = 0;

  reset_counter();

  /* RFC 3315 HOP_COUNT_LIMIT */
  if (hopcount > 32 || !(header = put_opt6(NULL, 34)))
    return 1;
  
  header[0] = DHCP6RELAYFORW;
  header[1] = hopcount;
  memcpy(&header[18], peer_address, IN6ADDRSZ);
  
  /* RFC-6939 */
  if (maclen != 0)
    {
      o = new_opt6(OPTION6_CLIENT_MAC);
      put_opt6_short(mactype);
      put_opt6(mac, maclen);
      end_opt6(o);
    }
  
  o = new_opt6(OPTION6_RELAY_MSG);
  put_opt6(inbuff, sz);
  end_opt6(o);
  
  for (; relay; relay = relay->next)
    if (relay->iface_index != 0 && relay->iface_index == iface_index)
      {
	union mysockaddr to;
	union all_addr from;
	
	/* source address == relay address */
	from.addr6 = relay->local.addr6;
	memcpy(&header[2], &relay->local.addr6, IN6ADDRSZ);
	
	to.sa.sa_family = AF_INET6;
	to.in6.sin6_addr = relay->server.addr6;
	to.in6.sin6_port = htons(relay->port);
	to.in6.sin6_flowinfo = 0;
	to.in6.sin6_scope_id = 0;
	
	if (IN6_ARE_ADDR_EQUAL(&relay->server.addr6, &multicast))
	  {
	    int multicast_iface;
	    if (!relay->interface || strchr(relay->interface, '*') ||
		(multicast_iface = if_nametoindex(relay->interface)) == 0 ||
		setsockopt(daemon->dhcp6fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &multicast_iface, sizeof(multicast_iface)) == -1)
	      {
		my_syslog(MS_DHCP | LOG_ERR, _("Cannot multicast DHCP relay via interface %s"), relay->interface);
		continue;
	      }
	  }
	
#ifdef HAVE_DUMPFILE
	{
	  union mysockaddr fromsock;
	  fromsock.in6.sin6_port = htons(DHCPV6_SERVER_PORT);
	  fromsock.in6.sin6_addr = from.addr6;
	  fromsock.sa.sa_family = AF_INET6;
	  fromsock.in6.sin6_flowinfo = 0;
	  fromsock.in6.sin6_scope_id = 0;
	  
	  dump_packet(DUMP_DHCPV6, (void *)daemon->outpacket.iov_base, save_counter(-1), &fromsock, &to, 0);
	}
#endif
	send_from(daemon->dhcp6fd, 0, daemon->outpacket.iov_base, save_counter(-1), &to, &from, 0);
	
	if (option_bool(OPT_LOG_OPTS))
	  {
	    inet_ntop(AF_INET6, &relay->local, daemon->addrbuff, ADDRSTRLEN);
	    if (IN6_ARE_ADDR_EQUAL(&relay->server.addr6, &multicast))
	      snprintf(daemon->namebuff, MAXDNAME, _("multicast via %s"), relay->interface);
	    else
	      inet_ntop(AF_INET6, &relay->server, daemon->namebuff, ADDRSTRLEN);
	    my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay at %s -> %s"), daemon->addrbuff, daemon->namebuff);
	  }
	
      }
  
  return 1;
}

int relay_reply6(struct sockaddr_in6 *peer, ssize_t sz, char *arrival_interface)
{
  struct dhcp_relay *relay;
  struct in6_addr link;
  unsigned char *inbuff = daemon->dhcp_packet.iov_base;
  
  /* must have at least msg_type+hopcount+link_address+peer_address+minimal size option
     which is               1   +    1   +    16      +     16     + 2 + 2 = 38 */
  
  if (sz < 38 || *inbuff != DHCP6RELAYREPL)
    return 0;
  
  memcpy(&link, &inbuff[2], IN6ADDRSZ); 
  
  for (relay = daemon->relay6; relay; relay = relay->next)
    if (IN6_ARE_ADDR_EQUAL(&link, &relay->local.addr6) &&
	(!relay->interface || wildcard_match(relay->interface, arrival_interface)))
      break;
      
  reset_counter();

  if (relay)
    {
      void *opt, *opts = inbuff + 34;
      void *end = inbuff + sz;
      for (opt = opts; opt; opt = opt6_next(opt, end))
	if (opt6_type(opt) == OPTION6_RELAY_MSG && opt6_len(opt) > 0)
	  {
	    int encap_type = *((unsigned char *)opt6_ptr(opt, 0));
	    put_opt6(opt6_ptr(opt, 0), opt6_len(opt));
	    memcpy(&peer->sin6_addr, &inbuff[18], IN6ADDRSZ); 
	    peer->sin6_scope_id = relay->iface_index;

	    if (encap_type == DHCP6RELAYREPL)
	      {
		peer->sin6_port = ntohs(DHCPV6_SERVER_PORT);
		return 1;
	      }

	    peer->sin6_port = ntohs(DHCPV6_CLIENT_PORT);
	    
#ifdef HAVE_SCRIPT
	    if (daemon->lease_change_command && encap_type == DHCP6REPLY)
	      {
		/* decapsulate relayed message */
		opts = opt6_ptr(opt, 4);
		end = opt6_ptr(opt, opt6_len(opt));

		for (opt = opts; opt; opt = opt6_next(opt, end))
		  if (opt6_type(opt) == OPTION6_IA_PD && opt6_len(opt) > 12) 
		    {
		      void *ia_opts = opt6_ptr(opt, 12);
		      void *ia_end = opt6_ptr(opt, opt6_len(opt));
		      void *ia_opt;
		      
		      for (ia_opt = ia_opts; ia_opt; ia_opt = opt6_next(ia_opt, ia_end))
			/* valid lifetime must not be zero. */
			if (opt6_type(ia_opt) == OPTION6_IAPREFIX && opt6_len(ia_opt) >= 25 && opt6_uint(ia_opt, 4, 4) != 0)
			  {
			    if (daemon->free_snoops ||
				(daemon->free_snoops = whine_malloc(sizeof(struct snoop_record))))
			      {
				struct snoop_record *snoop = daemon->free_snoops;
				
				daemon->free_snoops = snoop->next;
				snoop->client = peer->sin6_addr;
				snoop->prefix_len = opt6_uint(ia_opt, 8, 1); 
				memcpy(&snoop->prefix, opt6_ptr(ia_opt, 9), IN6ADDRSZ); 
				snoop->next = relay->snoop_records;
				relay->snoop_records = snoop;
			      }
			  }
		    }
	      }
#endif		
	    return 1;
	  }
      
    }
  
  return 0;
}

#ifdef HAVE_SCRIPT
int do_snoop_script_run(void)
{
  struct dhcp_relay *relay;
  struct snoop_record *snoop;
  
  for (relay = daemon->relay6; relay; relay = relay->next)
    if ((snoop = relay->snoop_records))
      {
	relay->snoop_records = snoop->next;
	snoop->next = daemon->free_snoops;
	daemon->free_snoops = snoop;
	
	queue_relay_snoop(&snoop->client, relay->iface_index, &snoop->prefix, snoop->prefix_len);
	return 1;
      }
  
  return 0;
}
#endif

#endif
