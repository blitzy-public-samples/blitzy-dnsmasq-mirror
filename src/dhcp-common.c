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
 * @file dhcp-common.c
 * @brief Shared DHCPv4/DHCPv6 utilities and option handling
 *
 * DETAILED PURPOSE:
 * This file implements common functionality used by both DHCPv4 (dhcp.c, rfc2131.c)
 * and DHCPv6 (dhcp6.c, rfc3315.c) servers. It provides essential shared utilities
 * for option parsing and encoding, vendor class matching, tag-based conditional
 * configuration, device binding, packet validation, and client configuration matching.
 * The code handles the complex logic of matching DHCP clients to their configuration
 * entries using multiple identification methods (client ID, hardware address, hostname)
 * and supports wildcard matching and tag-based filtering for flexible configuration.
 *
 * KEY RESPONSIBILITIES:
 * - find_config(): Matches clients to dhcp_config entries by client ID, MAC, or hostname
 * - match_bytes(): Compares byte arrays for option matching with wildcard support
 * - option_filter(): Applies tag-based filtering to determine which options are valid
 * - match_netid(): Checks if network ID sets match for conditional configuration
 * - option_string(): Converts DHCP options to human-readable strings for logging
 * - log_context(): Logs DHCP context information (address ranges, lease times)
 * - recv_dhcp_packet(): Receives DHCP packets with automatic buffer expansion
 * - dhcp_update_configs(): Updates static DHCP configurations from /etc/hosts
 *
 * DEPENDENCIES:
 * Includes: dnsmasq.h (all core types), dhcp-protocol.h (DHCP packet structures)
 * Called by: dhcp.c, dhcp6.c, rfc2131.c, rfc3315.c (DHCP server implementations)
 * Calls: Network functions (recvmsg), cache functions (cache_find_by_name),
 *        utility functions (safe_malloc, inet_ntop, hostname_isequal)
 *
 * DATA STRUCTURES:
 * - struct dhcp_config (dnsmasq.h:860-875): Static DHCP host configuration entries
 * - struct dhcp_context (dnsmasq.h:994-1010): DHCP address range contexts
 * - struct dhcp_netid (dnsmasq.h:831-834): Network ID tags for conditional config
 * - struct dhcp_opt (dnsmasq.h:892-902): DHCP option specifications
 * - struct dhcp_relay (dnsmasq.h:1084-1097): DHCP relay agent configuration
 * - opttab/opttab6: Static tables mapping option names to numbers and types
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP: Required - enables all DHCPv4 functionality
 * - HAVE_DHCP6: Enables DHCPv6-specific code paths (dual-stack support)
 * - HAVE_SCRIPT: Enables lease-change script execution support
 * - HAVE_LUASCRIPT: Enables Lua scripting for lease events
 * - HAVE_LINUX_NETWORK: Enables SO_BINDTODEVICE for per-interface binding (Linux only)
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven model with no threading. All functions are called
 * from the main event loop and are not re-entrant. Signal handlers use async-signal-safe
 * operations only and queue events via self-pipe pattern for main loop processing.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

/**
 * @brief Initialize DHCP common buffer infrastructure
 * @detailed
 * Allocates shared buffer space used by both DHCPv4 and DHCPv6 for packet processing
 * and option handling. Creates three general-purpose buffers (DHCP_BUFF_SZ each) and
 * initializes expandable packet buffers for DHCPv4 (dhcp_packet) and optionally DHCPv6
 * (outpacket). These buffers are reused across DHCP transactions to avoid repeated
 * allocation/deallocation overhead.
 *
 * @return void
 * @note Must be called during daemon initialization before any DHCP processing begins
 * @warning Calls die() via safe_malloc() if memory allocation fails
 * @see dhcp.c dhcp_packet() for DHCPv4 usage
 * @see dhcp6.c for DHCPv6 usage
 *
 * EXAMPLE USAGE:
 * @code
 * // Called once from main daemon initialization
 * dhcp_common_init();
 * // Buffers now available in daemon->dhcp_buff, daemon->dhcp_buff2, daemon->dhcp_buff3
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates daemon->dhcp_buff (DHCP_BUFF_SZ bytes)
 * - Allocates daemon->dhcp_buff2 (DHCP_BUFF_SZ bytes)
 * - Allocates daemon->dhcp_buff3 (DHCP_BUFF_SZ bytes)
 * - Expands daemon->dhcp_packet buffer to sizeof(struct dhcp_packet)
 * - If HAVE_DHCP6: Expands daemon->outpacket buffer for DHCPv6
 *
 * THREAD SAFETY:
 * Called only during single-threaded initialization phase. Not re-entrant.
 */
void dhcp_common_init(void)
{
  /* These each hold a DHCP option max size 255
     and get a terminating zero added */
  daemon->dhcp_buff = safe_malloc(DHCP_BUFF_SZ);
  daemon->dhcp_buff2 = safe_malloc(DHCP_BUFF_SZ); 
  daemon->dhcp_buff3 = safe_malloc(DHCP_BUFF_SZ);
  
  /* dhcp_packet is used by v4 and v6, outpacket only by v6 
     sizeof(struct dhcp_packet) is as good an initial size as any,
     even for v6 */
  expand_buf(&daemon->dhcp_packet, sizeof(struct dhcp_packet));
#ifdef HAVE_DHCP6
  if (daemon->dhcp6)
    expand_buf(&daemon->outpacket, sizeof(struct dhcp_packet));
#endif
}

/**
 * @brief Receive DHCP packet with automatic buffer expansion
 * @detailed
 * Receives a DHCP packet from a socket using recvmsg() with MSG_PEEK to determine
 * required buffer size, then automatically expands the buffer if the packet is larger
 * than current capacity (MSG_TRUNC flag). Handles kernel variations where some return
 * actual packet size while others return buffer size. Includes workaround for kernels
 * that ignore MSG_PEEK and dequeue packets prematurely (returns EAGAIN/EWOULDBLOCK).
 *
 * @param fd Socket file descriptor to receive from (DHCPv4 or DHCPv6 socket)
 * @param msg Pointer to msghdr structure with pre-allocated iov buffer, updated with received data
 * @return Bytes received on success, -1 on error or if message truncated after expansion
 * @retval >0 Number of bytes successfully received
 * @retval -1 Error occurred (check errno) or message still truncated after buffer expansion
 * @note Buffer expansion uses expand_buf() which may reallocate msg->msg_iov memory
 * @warning On very large packets, may fail if expand_buf() cannot allocate sufficient memory
 * @see expand_buf() in util.c for buffer expansion mechanism
 *
 * EXAMPLE USAGE:
 * @code
 * struct msghdr msg;
 * msg.msg_iov = &daemon->dhcp_packet;
 * ssize_t sz = recv_dhcp_packet(daemon->dhcpfd, &msg);
 * if (sz > 0) {
 *     // Process packet in msg.msg_iov->iov_base
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Used for receiving RFC 2131 DHCPv4 and RFC 3315 DHCPv6 packets.
 *
 * SIDE EFFECTS:
 * - May expand msg->msg_iov buffer via expand_buf() (reallocates memory)
 * - Consumes packet from socket receive queue
 * - Blocking: May wait for packet arrival (but socket is typically non-blocking in event loop)
 *
 * THREAD SAFETY:
 * Not re-entrant. Must be called from main event loop thread only.
 */
ssize_t recv_dhcp_packet(int fd, struct msghdr *msg)
{  
  ssize_t sz, new_sz;
 
  while (1)
    {
      msg->msg_flags = 0;
      while ((sz = recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC)) == -1 && errno == EINTR);
      
      if (sz == -1)
	return -1;
      
      if (!(msg->msg_flags & MSG_TRUNC))
	break;

      /* Very new Linux kernels return the actual size needed, 
	 older ones always return truncated size */
      if ((size_t)sz == msg->msg_iov->iov_len)
	{
	  if (!expand_buf(msg->msg_iov, sz + 100))
	    return -1;
	}
      else
	{
	  expand_buf(msg->msg_iov, sz);
	  break;
	}
    }
  
  while ((new_sz = recvmsg(fd, msg, 0)) == -1 && errno == EINTR);

  /* Some kernels seem to ignore MSG_PEEK, and dequeue the packet anyway. 
     If that happens we get EAGAIN here because the socket is non-blocking.
     Use the result of the original testing recvmsg as long as the buffer
     was big enough. There's a small race here that may lose the odd packet,
     but it's UDP anyway. */
  
  if (new_sz == -1 && (errno == EWOULDBLOCK || errno == EAGAIN))
    new_sz = sz;
  
  return (msg->msg_flags & MSG_TRUNC) ? -1 : new_sz;
}

/**
 * @brief Match network IDs with wildcard support
 * @detailed
 * Similar to match_netid() but supports trailing '*' wildcard in check tags for prefix
 * matching. Verifies that every tag in the check list matches at least one tag in the
 * pool list. Supports negation with '!' or '#' prefix (backwards compatibility). Used
 * by run_tag_if() to evaluate conditional tag-if expressions for interface groups.
 *
 * @param check Linked list of network ID tags to match (may contain wildcards and negations)
 * @param pool Linked list of available network ID tags to match against
 * @return 1 if all check tags match, 0 if any check tag fails to match
 * @retval 1 All check tags satisfied (all positive tags found in pool, no negative tags found)
 * @retval 0 At least one check tag not satisfied
 * @note Wildcard '*' must be at end of tag string, matches any suffix
 * @note '!' and '#' prefix negates the match (tag must NOT be in pool)
 * @see match_netid() for non-wildcard version
 * @see run_tag_if() caller that uses this for tag-if evaluation
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid check_tag = {"vlan*", NULL};  // Matches "vlan10", "vlan20", etc.
 * struct dhcp_netid pool_tags = {"vlan10", &pool_tags2};
 * if (match_netid_wild(&check_tag, &pool_tags)) {
 *     // Wildcard match succeeded
 * }
 * @endcode
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY:
 * Re-entrant if input lists are not modified concurrently. Safe for read-only access.
 */
int match_netid_wild(struct dhcp_netid *check, struct dhcp_netid *pool)
{
  struct dhcp_netid *tmp1;
  
  for (; check; check = check->next)
    {
      const int check_len = strlen(check->net);
      const int is_wc = (check_len > 0 && check->net[check_len - 1] == '*');
      
      /* '#' for not is for backwards compat. */
      if (check->net[0] != '!' && check->net[0] != '#')
	{
	  for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	    if (is_wc ? (strncmp(check->net, tmp1->net, check_len-1) == 0) :
		(strcmp(check->net, tmp1->net) == 0))
	      break;
	  if (!tmp1)
	    return 0;
	}
      else
	for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	  if (is_wc ? (strncmp((check->net)+1, tmp1->net, check_len-2) == 0) :
	      (strcmp((check->net)+1, tmp1->net) == 0))
	    return 0;
    }
  return 1;
}

/**
 * @brief Evaluate tag-if conditional expressions and add resulting tags
 * @detailed
 * Iterates through all tag-if expressions in daemon->tag_if and evaluates each condition
 * using match_netid_wild(). When a condition matches the current tags, all tags in the
 * expression's 'set' list are prepended to the tag list. This implements conditional
 * tagging: "if tags match pattern, then add these additional tags". Supports wildcards
 * for matching groups of interfaces (e.g., "vlan*" matches all VLAN interfaces).
 *
 * @param tags Current linked list of network ID tags (e.g., from interface, context, client)
 * @return Extended linked list with additional tags prepended from matching tag-if expressions
 * @note Returns modified list with new tags prepended; original list is not freed
 * @warning Returned list shares memory with input and daemon->tag_if; do not free individual nodes
 * @see match_netid_wild() for wildcard matching logic
 * @see option_filter() caller that uses result for option filtering
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid *client_tags = get_client_tags();
 * struct dhcp_netid *expanded_tags = run_tag_if(client_tags);
 * // expanded_tags now includes conditional tags from tag-if rules
 * @endcode
 *
 * SIDE EFFECTS:
 * - Prepends new dhcp_netid nodes to input tag list (shares memory from daemon->tag_if)
 * - Does not allocate new memory; returned list uses existing tag_if structures
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies linked list structure. Must be called from main event loop only.
 */
struct dhcp_netid *run_tag_if(struct dhcp_netid *tags)
{
  struct tag_if *exprs;
  struct dhcp_netid_list *list;

  /* this now uses match_netid_wild() above so that tag_if can
   * be used to set a 'group of interfaces' tag.
   */
  for (exprs = daemon->tag_if; exprs; exprs = exprs->next)
    if (match_netid_wild(exprs->tag, tags))
      for (list = exprs->set; list; list = list->next)
	{
	  list->list->next = tags;
	  tags = list->list;
	}

  return tags;
}


/**
 * @brief Filter DHCP options based on network ID tags with priority rules
 * @detailed
 * Implements tag-based conditional option delivery by evaluating which options from the
 * opts list should be sent to a client based on their network ID tags. Uses three-phase
 * algorithm: (1) mark options matching tags (sans context_tags), (2) if context_tags
 * provided, re-evaluate with context to inhibit lower-priority duplicates, (3) mark
 * untagged options if not overridden by tagged ones. Sets DHOPT_TAGOK flag on valid
 * options. Eliminates duplicates favoring earlier (higher priority) options in config.
 *
 * @param tags Client's network ID tags (from interface, subnet, vendor class, etc.)
 * @param context_tags Additional context tags from DHCP context (address range), or NULL
 * @param opts Linked list of dhcp_opt structures to filter (modified in place)
 * @return Expanded tag list after running tag-if expressions via run_tag_if()
 * @note Modifies opts list by setting/clearing DHOPT_TAGOK flags on each option
 * @note Does not filter encapsulated options (DHOPT_ENCAPSULATE, DHOPT_VENDOR, DHOPT_RFC3925)
 * @warning Logs warning via my_syslog() if duplicate untagged options detected
 * @see run_tag_if() for tag expansion with tag-if expressions
 * @see match_netid() for tag matching logic
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid *client_tags = get_client_tags();
 * struct dhcp_netid *context_tags = context->netid;
 * struct dhcp_opt *options = daemon->dhcp_opts;
 * struct dhcp_netid *final_tags = option_filter(client_tags, context_tags, options);
 * // Options with DHOPT_TAGOK flag are now valid for this client
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies flags field (DHOPT_TAGOK bit) in all opts structures
 * - May log warnings for duplicate option numbers
 * - Calls run_tag_if() which modifies tag list structure
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies shared opts list. Must be called from main event loop only.
 */
struct dhcp_netid *option_filter(struct dhcp_netid *tags, struct dhcp_netid *context_tags, struct dhcp_opt *opts)
{
  struct dhcp_netid *tagif = run_tag_if(tags);
  struct dhcp_opt *opt;
  struct dhcp_opt *tmp;  

  /* flag options which are valid with the current tag set (sans context tags) */
  for (opt = opts; opt; opt = opt->next)
    {
      opt->flags &= ~DHOPT_TAGOK;
      if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925)) &&
	  match_netid(opt->netid, tagif, 0))
	opt->flags |= DHOPT_TAGOK;
    }

  /* now flag options which are valid, including the context tags,
     otherwise valid options are inhibited if we found a higher priority one above */
  if (context_tags)
    {
      struct dhcp_netid *last_tag;

      for (last_tag = context_tags; last_tag->next; last_tag = last_tag->next);
      last_tag->next = tags;
      tagif = run_tag_if(context_tags);
      
      /* reset stuff with tag:!<tag> which now matches. */
      for (opt = opts; opt; opt = opt->next)
	if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925)) &&
	    (opt->flags & DHOPT_TAGOK) &&
	    !match_netid(opt->netid, tagif, 0))
	  opt->flags &= ~DHOPT_TAGOK;

      for (opt = opts; opt; opt = opt->next)
	if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925 | DHOPT_TAGOK)) &&
	    match_netid(opt->netid, tagif, 0))
	  {
	    struct dhcp_opt *tmp;  
	    for (tmp = opts; tmp; tmp = tmp->next) 
	      if (tmp->opt == opt->opt && opt->netid && (tmp->flags & DHOPT_TAGOK))
		break;
	    if (!tmp)
	      opt->flags |= DHOPT_TAGOK;
	  }      
    }
  
  /* now flag untagged options which are not overridden by tagged ones */
  for (opt = opts; opt; opt = opt->next)
    if (!(opt->flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925 | DHOPT_TAGOK)) && !opt->netid)
      {
	for (tmp = opts; tmp; tmp = tmp->next) 
	  if (tmp->opt == opt->opt && (tmp->flags & DHOPT_TAGOK))
	    break;
	if (!tmp)
	  opt->flags |= DHOPT_TAGOK;
	else if (!tmp->netid)
	  my_syslog(MS_DHCP | LOG_WARNING, _("Ignoring duplicate dhcp-option %d"), tmp->opt); 
      }

  /* Finally, eliminate duplicate options later in the chain, and therefore earlier in the config file. */
  for (opt = opts; opt; opt = opt->next)
    if (opt->flags & DHOPT_TAGOK)
      for (tmp = opt->next; tmp; tmp = tmp->next) 
	if (tmp->opt == opt->opt)
	  tmp->flags &= ~DHOPT_TAGOK;
  
  return tagif;
}
	
/**
 * @brief Match network ID lists without wildcard support
 * @detailed
 * Verifies that every tag in the check list has an exact match in the pool list. Supports
 * negation with '!' or '#' prefix (backwards compatibility): negated tags must NOT appear
 * in pool. If tagnotneeded is true, allows check to be NULL (treats as "matches any").
 * Used extensively for option filtering, config matching, and conditional tag evaluation.
 *
 * @param check Linked list of network ID tags to verify (each must match pool)
 * @param pool Linked list of available network ID tags to match against
 * @param tagnotneeded If non-zero, NULL check list is considered a match (untagged allowed)
 * @return 1 if all check tags match, 0 if any check tag fails to match
 * @retval 1 All check tags satisfied (positive tags found, negative tags not found)
 * @retval 0 At least one check tag not satisfied, or check is NULL and tagnotneeded is 0
 * @note '!' and '#' prefix negates the match (tag must NOT be in pool)
 * @see match_netid_wild() for wildcard-enabled version
 * @see option_filter() caller that uses this for option tag matching
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid check_tag = {"vlan10", NULL};
 * struct dhcp_netid pool_tags = {"vlan10", &pool_tags2};
 * if (match_netid(&check_tag, &pool_tags, 0)) {
 *     // Exact match succeeded
 * }
 * @endcode
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY:
 * Re-entrant if input lists are not modified concurrently. Safe for read-only access.
 */
int match_netid(struct dhcp_netid *check, struct dhcp_netid *pool, int tagnotneeded)
{
  struct dhcp_netid *tmp1;
  
  if (!check && !tagnotneeded)
    return 0;

  for (; check; check = check->next)
    {
      /* '#' for not is for backwards compat. */
      if (check->net[0] != '!' && check->net[0] != '#')
	{
	  for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	    if (strcmp(check->net, tmp1->net) == 0)
	      break;
	  if (!tmp1)
	    return 0;
	}
      else
	for (tmp1 = pool; tmp1; tmp1 = tmp1->next)
	  if (strcmp((check->net)+1, tmp1->net) == 0)
	    return 0;
    }
  return 1;
}

/**
 * @brief Extract and separate domain suffix from hostname
 * @detailed
 * Searches for the first '.' in hostname and splits the string at that point, replacing
 * the '.' with '\0' to terminate the hostname portion. Returns pointer to the domain
 * suffix (text after the '.') if present and non-empty, or NULL if no domain or empty
 * domain. Modifies the input string in place by truncating at the dot separator.
 *
 * @param hostname Null-terminated hostname string (may contain domain), modified in place
 * @return Pointer to domain suffix (after original '.') or NULL if no domain
 * @retval non-NULL Pointer to domain suffix string (part after '.' in original hostname)
 * @retval NULL No '.' found in hostname, or domain portion is empty
 * @warning Modifies hostname string in place by inserting '\0' at '.' position
 * @note Calling function must handle truncated hostname and returned domain separately
 * @see DHCP hostname option processing in rfc2131.c and rfc3315.c
 *
 * EXAMPLE USAGE:
 * @code
 * char name[] = "host.example.com";
 * char *domain = strip_hostname(name);
 * // Now name is "host\0example.com" and domain points to "example.com"
 * printf("Hostname: %s, Domain: %s\n", name, domain ? domain : "none");
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies input hostname string by replacing first '.' with '\0'
 * - Input string is truncated to hostname portion only
 *
 * THREAD SAFETY:
 * Re-entrant. Operates only on caller-provided buffer.
 */
char *strip_hostname(char *hostname)
{
  char *dot = strchr(hostname, '.');
 
  if (!dot)
    return NULL;
  
  *dot = 0; /* truncate */
  if (strlen(dot+1) != 0)
    return dot+1;
  
  return NULL;
}

/**
 * @brief Log network ID tags for DHCP transaction
 * @detailed
 * Logs all unique network ID tags associated with a DHCP transaction to syslog if
 * OPT_LOG_OPTS option is enabled. Removes duplicate tags before logging to produce
 * clean comma-separated output. Uses daemon->namebuff as scratch space (MAXDNAME-1 limit).
 * Useful for debugging tag-based conditional configuration and understanding which
 * tags matched for a particular client transaction.
 *
 * @param netid Linked list of network ID tags to log (may contain duplicates)
 * @param xid Transaction ID for associating log message with DHCP transaction
 * @return void
 * @note Only logs if option_bool(OPT_LOG_OPTS) is true (--log-dhcp command-line option)
 * @note Silently truncates tag list if exceeds MAXDNAME-1 characters
 * @warning Uses daemon->namebuff as scratch space; not re-entrant
 * @see option_filter() which determines which tags are active
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_netid *tags = get_client_tags();
 * u32 transaction_id = ntohl(packet->xid);
 * log_tags(tags, transaction_id);
 * // Logs: "12345 tags: vlan10, known-client, pxe-client"
 * @endcode
 *
 * SIDE EFFECTS:
 * - Writes to syslog with MS_DHCP | LOG_INFO priority
 * - Uses daemon->namebuff as temporary string buffer (modified)
 *
 * THREAD SAFETY:
 * Not re-entrant. Uses shared daemon->namebuff. Must be called from main event loop only.
 */
void log_tags(struct dhcp_netid *netid, u32 xid)
{
  if (netid && option_bool(OPT_LOG_OPTS))
    {
      char *s = daemon->namebuff;
      for (*s = 0; netid; netid = netid->next)
	{
	  /* kill dupes. */
	  struct dhcp_netid *n;
	  
	  for (n = netid->next; n; n = n->next)
	    if (strcmp(netid->net, n->net) == 0)
	      break;
	  
	  if (!n)
	    {
	      strncat (s, netid->net, (MAXDNAME-1) - strlen(s));
	      if (netid->next)
		strncat (s, ", ", (MAXDNAME-1) - strlen(s));
	    }
	}
      my_syslog(MS_DHCP | LOG_INFO, _("%u tags: %s"), xid, s);
    } 
}   
  
/**
 * @brief Match byte array against DHCP option value with wildcard support
 * @detailed
 * Compares byte array p of length len against the value stored in dhcp_opt structure o.
 * Supports three matching modes: (1) DHOPT_HEX flag: masked comparison using o->u.wildcard_mask
 * for partial byte matching, (2) DHOPT_STRING flag: substring search allowing match at any
 * position, (3) default: exact match at aligned positions only. Used for vendor class,
 * user class, and client ID matching with flexible wildcarding.
 *
 * @param o DHCP option structure containing value to match and flags controlling match mode
 * @param p Byte array to search for matches (typically from received DHCP option)
 * @param len Length of byte array p in bytes
 * @return 1 if match found according to mode, 0 if no match
 * @retval 1 Match succeeded (exact match, wildcard match, or substring match depending on flags)
 * @retval 0 No match found, or o->len > len (option value longer than search array)
 * @note o->len == 0 is treated as universal match (returns 1 always)
 * @note DHOPT_HEX: Uses memcmp_masked() for bitwise wildcard matching
 * @note DHOPT_STRING: Searches for substring at any byte position
 * @see memcmp_masked() in util.c for wildcard mask comparison
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_opt vendor_match;
 * vendor_match.val = "PXEClient";
 * vendor_match.len = 9;
 * vendor_match.flags = DHOPT_STRING;
 * unsigned char vendor_class[] = "PXEClient:Arch:00000";
 * if (match_bytes(&vendor_match, vendor_class, sizeof(vendor_class))) {
 *     // Vendor class contains "PXEClient" substring
 * }
 * @endcode
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY:
 * Re-entrant. Safe for concurrent calls with different parameters.
 */
int match_bytes(struct dhcp_opt *o, unsigned char *p, int len)
{
  int i;
  
  if (o->len > len)
    return 0;
  
  if (o->len == 0)
    return 1;
     
  if (o->flags & DHOPT_HEX)
    { 
      if (memcmp_masked(o->val, p, o->len, o->u.wildcard_mask))
	return 1;
    }
  else 
    for (i = 0; i <= (len - o->len); ) 
      {
	if (memcmp(o->val, p + i, o->len) == 0)
	  return 1;
	    
	if (o->flags & DHOPT_STRING)
	  i++;
	else
	  i += o->len;
      }
  
  return 0;
}

/**
 * @brief Check if DHCP config contains exact hardware address match
 * @detailed
 * Searches the linked list of hardware address configurations in config->hwaddr for an
 * exact match with the provided hardware address. Requires exact length and type match
 * (or type 0 wildcard in config), and exact byte-for-byte address match with no wildcard
 * mask (wildcard_mask == 0). Used to determine if a specific MAC address has explicit
 * static configuration before attempting wildcard matching.
 *
 * @param config DHCP configuration entry to search (contains linked list of hwaddr_config)
 * @param hwaddr Hardware address to match (typically MAC address from DHCP packet)
 * @param len Length of hwaddr in bytes (typically 6 for Ethernet MAC)
 * @param type Hardware address type (typically ARPHRD_ETHER=1 for Ethernet)
 * @return 1 if exact match found, 0 if no match
 * @retval 1 Exact hardware address match found in config (no wildcards)
 * @retval 0 No exact match, or all matches have wildcard masks
 * @note Only matches configurations with wildcard_mask == 0 (exact match only)
 * @see find_config_match() which calls this for config selection
 * @see hwaddr_config structure in dnsmasq.h:853-858
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_config *conf = daemon->dhcp_conf;
 * unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * if (config_has_mac(conf, mac, 6, ARPHRD_ETHER)) {
 *     // Exact MAC match found, use this configuration
 * }
 * @endcode
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY:
 * Re-entrant if config structures are not modified concurrently. Safe for read-only access.
 */
int config_has_mac(struct dhcp_config *config, unsigned char *hwaddr, int len, int type)
{
  struct hwaddr_config *conf_addr;
  
  for (conf_addr = config->hwaddr; conf_addr; conf_addr = conf_addr->next)
    if (conf_addr->wildcard_mask == 0 &&
	conf_addr->hwaddr_len == len &&
	(conf_addr->hwaddr_type == type || conf_addr->hwaddr_type == 0) &&
	memcmp(conf_addr->hwaddr, hwaddr, len) == 0)
      return 1;
  
  return 0;
}

/**
 * @brief Check if DHCP configuration is valid within given context (address range)
 * @detailed
 * Verifies that a dhcp_config entry's static IP address(es) fall within the subnet range
 * defined by the dhcp_context. For IPv4, checks if config->addr is in context subnet using
 * netmask. For IPv6, checks if any addr6 addresses match context prefix. Returns true if
 * context is NULL (called from lease_update_from_configs), or if config has no address
 * specified (CONFIG_ADDR/CONFIG_ADDR6 flags not set), allowing hostname-only configurations.
 *
 * @param context DHCP context defining address range and subnet, or NULL for no context check
 * @param config DHCP configuration entry to validate against context
 * @return 1 if config is valid in context, 0 if config address is outside context range
 * @retval 1 Config address is within context subnet, or no context, or no address in config
 * @retval 0 Config address is outside context subnet range
 * @note If context is NULL, always returns 1 (allows usage from lease_update_from_configs)
 * @note Handles both IPv4 (CONFIG_ADDR) and IPv6 (CONFIG_ADDR6) addresses
 * @note IPv6 supports wildcard addresses (ADDRLIST_WILDCARD) for prefix=64 contexts
 * @see find_config_match() caller that uses this to filter configs by subnet
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = find_context_for_interface(iface);
 * struct dhcp_config *conf = daemon->dhcp_conf;
 * if (is_config_in_context(ctx, conf)) {
 *     // Configuration address is valid for this subnet
 * }
 * @endcode
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY:
 * Re-entrant. Safe for concurrent calls with different parameters.
 */
static int is_config_in_context(struct dhcp_context *context, struct dhcp_config *config)
{
  if (!context) /* called via find_config() from lease_update_from_configs() */
    return 1; 

  if (!(config->flags & (CONFIG_ADDR | CONFIG_ADDR6)))
    return 1;
  
#ifdef HAVE_DHCP6
  if (context->flags & CONTEXT_V6)
    {
       struct addrlist *addr_list;

       if (config->flags & CONFIG_ADDR6)
	 for (; context; context = context->current)
	   for (addr_list = config->addr6; addr_list; addr_list = addr_list->next)
	     {
	       if ((addr_list->flags & ADDRLIST_WILDCARD) && context->prefix == 64)
		 return 1;
	       
	       if (is_same_net6(&addr_list->addr.addr6, &context->start6, context->prefix))
		 return 1;
	     }
    }
  else
#endif
    {
      for (; context; context = context->current)
	if ((config->flags & CONFIG_ADDR) && is_same_net(config->addr, context->start, context->netmask))
	  return 1;
    }

  return 0;
}

/**
 * @brief Find matching DHCP configuration with tag filtering
 * @detailed
 * Searches configs list for best match using multi-phase priority algorithm: (1) client ID
 * exact match (with dhcpcd compatibility for zero-prefixed ASCII client IDs), (2) hardware
 * address exact match, (3) hostname match, (4) wildcard hardware address match (selecting
 * config with most matching non-wildcard octets). All matches must pass context subnet check
 * and tag filter. The tag_not_needed parameter controls whether untagged configs are allowed.
 *
 * @param configs Linked list of dhcp_config entries to search
 * @param context DHCP context for subnet validation, or NULL to skip context check
 * @param clid Client identifier from DHCP packet, or NULL if not provided
 * @param clid_len Length of client identifier in bytes
 * @param hwaddr Hardware address (MAC) from DHCP packet, or NULL if not available
 * @param hw_len Length of hardware address in bytes (typically 6 for Ethernet)
 * @param hw_type Hardware type (typically ARPHRD_ETHER=1 for Ethernet)
 * @param hostname Hostname from DHCP packet hostname option, or NULL if not provided
 * @param tags Network ID tags for tag-based filtering
 * @param tag_not_needed If non-zero, allows untagged configs; if zero, requires tag match
 * @return Pointer to matching dhcp_config or NULL if no match found
 * @retval non-NULL Best matching configuration entry
 * @retval NULL No configuration matches all criteria
 * @note Handles dhcpcd bug where ASCII client IDs are prefixed with zero byte
 * @note Wildcard hardware address matching uses memcmp_masked() and selects best match
 * @see find_config() wrapper that calls this twice (tagged then untagged)
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_config *conf = find_config_match(
 *     daemon->dhcp_conf, context,
 *     clid, clid_len, chaddr, hlen, htype,
 *     hostname, tags, 0);
 * if (conf) {
 *     // Use conf->addr for static address assignment
 * }
 * @endcode
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY:
 * Re-entrant if config structures are not modified concurrently. Safe for read-only access.
 */
static struct dhcp_config *find_config_match(struct dhcp_config *configs,
					     struct dhcp_context *context,
					     unsigned char *clid, int clid_len,
					     unsigned char *hwaddr, int hw_len, 
					     int hw_type, char *hostname,
					     struct dhcp_netid *tags, int tag_not_needed)
{
  int count, new;
  struct dhcp_config *config, *candidate; 
  struct hwaddr_config *conf_addr;

  if (clid)
    for (config = configs; config; config = config->next)
      if (config->flags & CONFIG_CLID)
	{
	  if (config->clid_len == clid_len && 
	      memcmp(config->clid, clid, clid_len) == 0 &&
	      is_config_in_context(context, config) &&
	      match_netid(config->filter, tags, tag_not_needed))
	    
	    return config;
	  
	  /* dhcpcd prefixes ASCII client IDs by zero which is wrong, but we try and
	     cope with that here. This is IPv4 only. context==NULL implies IPv4, 
	     see lease_update_from_configs() */
	  if ((!context || !(context->flags & CONTEXT_V6)) && *clid == 0 && config->clid_len == clid_len-1  &&
	      memcmp(config->clid, clid+1, clid_len-1) == 0 &&
	      is_config_in_context(context, config) &&
	      match_netid(config->filter, tags, tag_not_needed))
	    return config;
	}
  

  if (hwaddr)
    for (config = configs; config; config = config->next)
      if (config_has_mac(config, hwaddr, hw_len, hw_type) &&
	  is_config_in_context(context, config) &&
	  match_netid(config->filter, tags, tag_not_needed))
	return config;
  
  if (hostname && context)
    for (config = configs; config; config = config->next)
      if ((config->flags & CONFIG_NAME) && 
	  hostname_isequal(config->hostname, hostname) &&
	  is_config_in_context(context, config) &&
	  match_netid(config->filter, tags, tag_not_needed))
	return config;

  
  if (!hwaddr)
    return NULL;

  /* use match with fewest wildcard octets */
  for (candidate = NULL, count = 0, config = configs; config; config = config->next)
    if (is_config_in_context(context, config) &&
	match_netid(config->filter, tags, tag_not_needed))
      for (conf_addr = config->hwaddr; conf_addr; conf_addr = conf_addr->next)
	if (conf_addr->wildcard_mask != 0 &&
	    conf_addr->hwaddr_len == hw_len &&	
	    (conf_addr->hwaddr_type == hw_type || conf_addr->hwaddr_type == 0) &&
	    (new = memcmp_masked(conf_addr->hwaddr, hwaddr, hw_len, conf_addr->wildcard_mask)) > count)
	  {
	      count = new;
	      candidate = config;
	  }
  
  return candidate;
}

/**
 * @brief Find best matching DHCP configuration with two-pass tag matching
 * @detailed
 * Wrapper around find_config_match() that performs two searches: first for tagged configs
 * (requiring tag match), then for untagged configs if first search fails. This implements
 * priority where tagged (conditional) configurations override untagged (global) ones.
 * Primary entry point for DHCP servers to locate static host configurations based on
 * client identification (client ID, MAC address, or hostname).
 *
 * @param configs Linked list of dhcp_config entries to search
 * @param context DHCP context for subnet validation, or NULL to skip context check
 * @param clid Client identifier from DHCP packet, or NULL if not provided
 * @param clid_len Length of client identifier in bytes
 * @param hwaddr Hardware address (MAC) from DHCP packet, or NULL if not available
 * @param hw_len Length of hardware address in bytes (typically 6 for Ethernet)
 * @param hw_type Hardware type (typically ARPHRD_ETHER=1 for Ethernet)
 * @param hostname Hostname from DHCP packet hostname option, or NULL if not provided
 * @param tags Network ID tags for tag-based filtering
 * @return Pointer to best matching dhcp_config or NULL if no match found
 * @retval non-NULL Best matching configuration (tagged configs have priority over untagged)
 * @retval NULL No configuration matches identification and tag criteria
 * @note Called by dhcp_reply() in rfc2131.c and dhcp6_reply() in rfc3315.c
 * @see find_config_match() for detailed matching algorithm
 * @see dhcp_reply() in rfc2131.c for DHCPv4 usage
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_config *conf = find_config(
 *     daemon->dhcp_conf, context,
 *     option_ptr(opt, 0, clid_len), clid_len,
 *     packet->chaddr, packet->hlen, packet->htype,
 *     hostname, tags);
 * if (conf && (conf->flags & CONFIG_ADDR)) {
 *     mess->yiaddr = conf->addr;  // Assign static address
 * }
 * @endcode
 *
 * SIDE EFFECTS: None (read-only operation)
 *
 * THREAD SAFETY:
 * Re-entrant if config structures are not modified concurrently. Safe for read-only access.
 */
struct dhcp_config *find_config(struct dhcp_config *configs,
				struct dhcp_context *context,
				unsigned char *clid, int clid_len,
				unsigned char *hwaddr, int hw_len, 
				int hw_type, char *hostname, struct dhcp_netid *tags)
{
  struct dhcp_config *ret = find_config_match(configs, context, clid, clid_len, hwaddr, hw_len, hw_type, hostname, tags, 0);

  if (!ret)
    ret = find_config_match(configs, context, clid, clid_len, hwaddr, hw_len, hw_type, hostname, tags, 1);

  return ret;
}

/**
 * @brief Update DHCP static configurations from /etc/hosts cache
 * @detailed
 * Synchronizes dhcp_config entries with addresses from /etc/hosts file (via DNS cache).
 * For each config with CONFIG_NAME but no CONFIG_ADDR/CONFIG_ADDR6, searches cache for
 * hostname match and assigns address if found and unique (not already used by another
 * config). Restores previous state first to handle /etc/hosts reload (SIGHUP). Maintains
 * invariant: each IP address appears in at most one dhcp-host configuration. Processes
 * both IPv4 and IPv6 in two passes.
 *
 * @param configs Linked list of dhcp_config entries to update (modified in place)
 * @return void
 * @note Clears CONFIG_ADDR_HOSTS and CONFIG_ADDR6_HOSTS flags before reassignment
 * @note Logs warnings via my_syslog() for multiple addresses and duplicate IPs
 * @note Only processes if daemon->port != 0 (DNS enabled for cache lookup)
 * @warning Uses daemon->addrbuff for temporary string formatting
 * @see cache_find_by_name() for /etc/hosts lookup
 * @see config_find_by_address() for duplicate IPv4 detection
 *
 * EXAMPLE USAGE:
 * @code
 * // Called after /etc/hosts reload (SIGHUP) or during initialization
 * dhcp_update_configs(daemon->dhcp_conf);
 * // Static DHCP entries now have addresses from /etc/hosts
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies flags field (CONFIG_ADDR_HOSTS, CONFIG_ADDR6_HOSTS) in config entries
 * - Sets config->addr or config->addr6 from cache when match found
 * - Logs warnings for multiple addresses in /etc/hosts or duplicate IP conflicts
 * - Allocates config->addr6 structure if needed (via whine_malloc)
 *
 * THREAD SAFETY:
 * Not re-entrant. Modifies shared config list and uses daemon->addrbuff. Main event loop only.
 */
void dhcp_update_configs(struct dhcp_config *configs)
{
  /* Some people like to keep all static IP addresses in /etc/hosts.
     This goes through /etc/hosts and sets static addresses for any DHCP config
     records which don't have an address and whose name matches. 
     We take care to maintain the invariant that any IP address can appear
     in at most one dhcp-host. Since /etc/hosts can be re-read by SIGHUP, 
     restore the status-quo ante first. */
  
  struct dhcp_config *config, *conf_tmp;
  struct crec *crec;
  int prot = AF_INET;

  for (config = configs; config; config = config->next)
  {
    if (config->flags & CONFIG_ADDR_HOSTS)
      config->flags &= ~(CONFIG_ADDR | CONFIG_ADDR_HOSTS);
#ifdef HAVE_DHCP6
    if (config->flags & CONFIG_ADDR6_HOSTS)
      config->flags &= ~(CONFIG_ADDR6 | CONFIG_ADDR6_HOSTS);
#endif
  }

#ifdef HAVE_DHCP6 
 again:  
#endif

  if (daemon->port != 0)
    for (config = configs; config; config = config->next)
      {
	int conflags = CONFIG_ADDR;
	int cacheflags = F_IPV4;

#ifdef HAVE_DHCP6
	if (prot == AF_INET6)
	  {
	    conflags = CONFIG_ADDR6;
	    cacheflags = F_IPV6;
	  }
#endif
	if (!(config->flags & conflags) &&
	    (config->flags & CONFIG_NAME) && 
	    (crec = cache_find_by_name(NULL, config->hostname, 0, cacheflags)) &&
	    (crec->flags & F_HOSTS))
	  {
	    if (cache_find_by_name(crec, config->hostname, 0, cacheflags))
	      {
		/* use primary (first) address */
		while (crec && !(crec->flags & F_REVERSE))
		  crec = cache_find_by_name(crec, config->hostname, 0, cacheflags);
		if (!crec)
		  continue; /* should be never */
		inet_ntop(prot, &crec->addr, daemon->addrbuff, ADDRSTRLEN);
		my_syslog(MS_DHCP | LOG_WARNING, _("%s has more than one address in hostsfile, using %s for DHCP"), 
			  config->hostname, daemon->addrbuff);
	      }
	    
	    if (prot == AF_INET && 
		(!(conf_tmp = config_find_by_address(configs, crec->addr.addr4)) || conf_tmp == config))
	      {
		config->addr = crec->addr.addr4;
		config->flags |= CONFIG_ADDR | CONFIG_ADDR_HOSTS;
		continue;
	      }

#ifdef HAVE_DHCP6
	    if (prot == AF_INET6 && 
		(!(conf_tmp = config_find_by_address6(configs, NULL, 0, &crec->addr.addr6)) || conf_tmp == config))
	      {
		/* host must have exactly one address if comming from /etc/hosts. */
		if (!config->addr6 && (config->addr6 = whine_malloc(sizeof(struct addrlist))))
		  {
		    config->addr6->next = NULL;
		    config->addr6->flags = 0;
		  }

		if (config->addr6 && !config->addr6->next && !(config->addr6->flags & (ADDRLIST_WILDCARD|ADDRLIST_PREFIX)))
		  {
		    memcpy(&config->addr6->addr.addr6, &crec->addr.addr6, IN6ADDRSZ);
		    config->flags |= CONFIG_ADDR6 | CONFIG_ADDR6_HOSTS;
		  }
	    
		continue;
	      }
#endif

	    inet_ntop(prot, &crec->addr, daemon->addrbuff, ADDRSTRLEN);
	    my_syslog(MS_DHCP | LOG_WARNING, _("duplicate IP address %s (%s) in dhcp-config directive"), 
		      daemon->addrbuff, config->hostname);
	    
	    
	  }
      }

#ifdef HAVE_DHCP6
  if (prot == AF_INET)
    {
      prot = AF_INET6;
      goto again;
    }
#endif

}

#ifdef HAVE_LINUX_NETWORK

/**
 * @brief Determine single DHCP-enabled interface for SO_BINDTODEVICE
 * @detailed
 * Detects if exactly one interface is configured for DHCP (via --interface without wildcards)
 * and that interface exists and is marked dhcp_ok. Returns device name for SO_BINDTODEVICE
 * socket binding to avoid packet confusion in multi-VLAN environments (e.g., OpenStack where
 * separate dnsmasq instances run per VLAN). Returns NULL if multiple interfaces, wildcards
 * present, or configured interface doesn't exist yet (may arrive later).
 *
 * @return Allocated string with interface name, or NULL if binding inappropriate
 * @retval non-NULL Interface name string (caller must eventually free)
 * @retval NULL Multiple interfaces configured, wildcards used, or --interface not specified
 * @note Only available on Linux (SO_BINDTODEVICE is Linux-specific)
 * @note Checks daemon->if_names list for wildcards and unused interfaces
 * @warning Returns allocated memory that caller must free with free()
 * @see bind_dhcp_devices() caller that uses result for socket binding
 *
 * EXAMPLE USAGE:
 * @code
 * char *device = whichdevice();
 * if (device) {
 *     bind_dhcp_devices(device);
 *     free(device);
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates memory via safe_malloc() (returned string)
 * - Caller must free returned string
 *
 * THREAD SAFETY:
 * Not re-entrant. Accesses shared daemon->if_names and daemon->interfaces. Main event loop only.
 */
char *whichdevice(void)
{
  /* If we are doing DHCP on exactly one interface, and running linux, do SO_BINDTODEVICE
     to that device. This is for the use case of  (eg) OpenStack, which runs a new
     dnsmasq instance for each VLAN interface it creates. Without the BINDTODEVICE, 
     individual processes don't always see the packets they should.
     SO_BINDTODEVICE is only available Linux. 

     Note that if wildcards are used in --interface, or --interface is not used at all,
     or a configured interface doesn't yet exist, then more interfaces may arrive later, 
     so we can't safely assert there is only one interface and proceed.
*/
  
  struct irec *iface, *found;
  struct iname *if_tmp;
  
  if (!daemon->if_names)
    return NULL;
  
  for (if_tmp = daemon->if_names; if_tmp; if_tmp = if_tmp->next)
    if (if_tmp->name && (!if_tmp->used || strchr(if_tmp->name, '*')))
      return NULL;

  for (found = NULL, iface = daemon->interfaces; iface; iface = iface->next)
    if (iface->dhcp_ok)
      {
	if (!found)
	  found = iface;
	else if (strcmp(found->name, iface->name) != 0) 
	  return NULL; /* more than one. */
      }

  if (found)
    {
      char *ret = safe_malloc(strlen(found->name)+1);
      strcpy(ret, found->name);
      return ret;
    }
  
  return NULL;
}
 
/**
 * @brief Bind socket to specific network device using SO_BINDTODEVICE
 * @detailed
 * Sets SO_BINDTODEVICE socket option to restrict socket to receiving/sending packets
 * only on the specified network interface. This is Linux-specific and requires root
 * privileges (or CAP_NET_RAW capability). Truncates device name to IFNAMSIZ if necessary.
 * Used to prevent packet confusion when multiple dnsmasq instances run on different
 * VLANs or namespaces on the same host.
 *
 * @param device Interface name string (e.g., "eth0", "vlan10") to bind socket to
 * @param fd Socket file descriptor to apply SO_BINDTODEVICE option to
 * @return Status code indicating success or failure
 * @retval 1 Successfully bound to device
 * @retval 2 setsockopt() failed with error other than EPERM
 * @note EPERM error is silently ignored (returns 1) - occurs when not root but not fatal
 * @note Only available on Linux (SO_BINDTODEVICE is Linux-specific)
 * @warning Requires root privileges or CAP_NET_RAW capability to succeed
 * @see bind_dhcp_devices() caller that applies this to all DHCP sockets
 *
 * EXAMPLE USAGE:
 * @code
 * int status = bindtodevice("eth0", daemon->dhcpfd);
 * if (status == 2) {
 *     // Binding failed with non-permission error
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies socket fd with SO_BINDTODEVICE option (restricts to single interface)
 * - Socket will only receive packets from specified interface after successful bind
 *
 * THREAD SAFETY:
 * Re-entrant. Safe for concurrent calls on different sockets.
 */
static int bindtodevice(char *device, int fd)
{
  size_t len = strlen(device)+1;
  if (len > IFNAMSIZ)
    len = IFNAMSIZ;
  /* only allowed by root. */
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, len) == -1 &&
      errno != EPERM)
    return 2;
  
  return 1;
}

/**
 * @brief Apply SO_BINDTODEVICE to all DHCP server sockets
 * @detailed
 * Binds all active DHCP server sockets (DHCPv4, DHCPv4-PXE, DHCPv6) to the specified
 * network device using SO_BINDTODEVICE. Only binds sockets that are enabled and not
 * operating in relay mode (relay servers listen on all interfaces). Returns bitwise OR
 * of all bindtodevice() return values for error detection. Used in single-interface
 * DHCP deployments (e.g., OpenStack per-VLAN instances) to avoid packet confusion.
 *
 * @param bound_device Interface name to bind all DHCP sockets to, or NULL for no binding
 * @return Bitwise OR of bindtodevice() results (0 if no bindings attempted, non-zero if any bound)
 * @retval 0 No device specified (bound_device is NULL) or no sockets bound
 * @retval >0 One or more sockets bound (value 1=success, value 2=error occurred)
 * @note Only binds non-relay sockets (daemon->relay4/relay6 must be false)
 * @note Binds daemon->dhcpfd (DHCPv4), daemon->pxefd (PXE if enabled), daemon->dhcp6fd (DHCPv6)
 * @note Only available on Linux (SO_BINDTODEVICE is Linux-specific)
 * @see whichdevice() which determines if single-interface binding is appropriate
 *
 * EXAMPLE USAGE:
 * @code
 * char *device = whichdevice();
 * int result = bind_dhcp_devices(device);
 * if (result & 2) {
 *     my_syslog(LOG_WARNING, "Failed to bind DHCP sockets to %s", device);
 * }
 * free(device);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies DHCP socket file descriptors with SO_BINDTODEVICE option
 * - Restricts all bound sockets to single interface
 *
 * THREAD SAFETY:
 * Not re-entrant. Accesses shared daemon socket file descriptors. Main event loop only.
 */
int bind_dhcp_devices(char *bound_device)
{
  int ret = 0;

  if (bound_device)
    {
      if (daemon->dhcp)
	{
	  if (!daemon->relay4)
	    ret |= bindtodevice(bound_device, daemon->dhcpfd);
	  
	  if (daemon->enable_pxe && daemon->pxefd != -1)
	    ret |= bindtodevice(bound_device, daemon->pxefd);
	}
      
#if defined(HAVE_DHCP6)
      if (daemon->doing_dhcp6 && !daemon->relay6)
	ret |= bindtodevice(bound_device, daemon->dhcp6fd);
#endif
    }
  
  return ret;
}
#endif

static const struct opttab_t {
  char *name;
  u16 val, size;
} opttab[] = {
  { "netmask", 1, OT_ADDR_LIST },
  { "time-offset", 2, 4 },
  { "router", 3, OT_ADDR_LIST  },
  { "dns-server", 6, OT_ADDR_LIST },
  { "log-server", 7, OT_ADDR_LIST },
  { "lpr-server", 9, OT_ADDR_LIST },
  { "hostname", 12, OT_INTERNAL | OT_NAME },
  { "boot-file-size", 13, 2 | OT_DEC },
  { "domain-name", 15, OT_NAME },
  { "swap-server", 16, OT_ADDR_LIST },
  { "root-path", 17, OT_NAME },
  { "extension-path", 18, OT_NAME },
  { "ip-forward-enable", 19, 1 },
  { "non-local-source-routing", 20, 1 },
  { "policy-filter", 21, OT_ADDR_LIST },
  { "max-datagram-reassembly", 22, 2 | OT_DEC },
  { "default-ttl", 23, 1 | OT_DEC },
  { "mtu", 26, 2 | OT_DEC },
  { "all-subnets-local", 27, 1 },
  { "broadcast", 28, OT_INTERNAL | OT_ADDR_LIST },
  { "router-discovery", 31, 1 },
  { "router-solicitation", 32, OT_ADDR_LIST },
  { "static-route", 33, OT_ADDR_LIST },
  { "trailer-encapsulation", 34, 1 },
  { "arp-timeout", 35, 4 | OT_DEC },
  { "ethernet-encap", 36, 1 },
  { "tcp-ttl", 37, 1 },
  { "tcp-keepalive", 38, 4 | OT_DEC },
  { "nis-domain", 40, OT_NAME },
  { "nis-server", 41, OT_ADDR_LIST },
  { "ntp-server", 42, OT_ADDR_LIST },
  { "vendor-encap", 43, OT_INTERNAL },
  { "netbios-ns", 44, OT_ADDR_LIST },
  { "netbios-dd", 45, OT_ADDR_LIST },
  { "netbios-nodetype", 46, 1 },
  { "netbios-scope", 47, 0 },
  { "x-windows-fs", 48, OT_ADDR_LIST },
  { "x-windows-dm", 49, OT_ADDR_LIST },
  { "requested-address", 50, OT_INTERNAL | OT_ADDR_LIST },
  { "lease-time", 51, OT_INTERNAL | OT_TIME },
  { "option-overload", 52, OT_INTERNAL },
  { "message-type", 53, OT_INTERNAL | OT_DEC },
  { "server-identifier", 54, OT_INTERNAL | OT_ADDR_LIST },
  { "parameter-request", 55, OT_INTERNAL },
  { "message", 56, OT_INTERNAL },
  { "max-message-size", 57, OT_INTERNAL },
  { "T1", 58, OT_TIME},
  { "T2", 59, OT_TIME},
  { "vendor-class", 60, 0 },
  { "client-id", 61, OT_INTERNAL },
  { "nis+-domain", 64, OT_NAME },
  { "nis+-server", 65, OT_ADDR_LIST },
  { "tftp-server", 66, OT_NAME },
  { "bootfile-name", 67, OT_NAME },
  { "mobile-ip-home", 68, OT_ADDR_LIST }, 
  { "smtp-server", 69, OT_ADDR_LIST }, 
  { "pop3-server", 70, OT_ADDR_LIST }, 
  { "nntp-server", 71, OT_ADDR_LIST }, 
  { "irc-server", 74, OT_ADDR_LIST }, 
  { "user-class", 77, 0 },
  { "rapid-commit", 80, 0 },
  { "FQDN", 81, OT_INTERNAL },
  { "agent-id", 82, OT_INTERNAL },
  { "client-arch", 93, 2 | OT_DEC },
  { "client-interface-id", 94, 0 },
  { "client-machine-id", 97, 0 },
  { "posix-timezone", 100, OT_NAME }, /* RFC 4833, Sec. 2 */
  { "tzdb-timezone", 101, OT_NAME }, /* RFC 4833, Sec. 2 */
  { "subnet-select", 118, OT_INTERNAL },
  { "domain-search", 119, OT_RFC1035_NAME },
  { "sip-server", 120, 0 },
  { "classless-static-route", 121, 0 },
  { "vendor-id-encap", 125, 0 },
  { "tftp-server-address", 150, OT_ADDR_LIST },
  { "server-ip-address", 255, OT_ADDR_LIST }, /* special, internal only, sets siaddr */
  { NULL, 0, 0 }
};

#ifdef HAVE_DHCP6
static const struct opttab_t opttab6[] = {
  { "client-id", 1, OT_INTERNAL },
  { "server-id", 2, OT_INTERNAL },
  { "ia-na", 3, OT_INTERNAL },
  { "ia-ta", 4, OT_INTERNAL },
  { "iaaddr", 5, OT_INTERNAL },
  { "oro", 6, OT_INTERNAL },
  { "preference", 7, OT_INTERNAL | OT_DEC },
  { "unicast", 12, OT_INTERNAL },
  { "status", 13, OT_INTERNAL },
  { "rapid-commit", 14, OT_INTERNAL },
  { "user-class", 15, OT_INTERNAL | OT_CSTRING },
  { "vendor-class", 16, OT_INTERNAL | OT_CSTRING },
  { "vendor-opts", 17, OT_INTERNAL },
  { "sip-server-domain", 21,  OT_RFC1035_NAME },
  { "sip-server", 22, OT_ADDR_LIST },
  { "dns-server", 23, OT_ADDR_LIST },
  { "domain-search", 24, OT_RFC1035_NAME },
  { "nis-server", 27, OT_ADDR_LIST },
  { "nis+-server", 28, OT_ADDR_LIST },
  { "nis-domain", 29,  OT_RFC1035_NAME },
  { "nis+-domain", 30, OT_RFC1035_NAME },
  { "sntp-server", 31,  OT_ADDR_LIST },
  { "information-refresh-time", 32, OT_TIME },
  { "FQDN", 39, OT_INTERNAL | OT_RFC1035_NAME },
  { "ntp-server", 56, 0 /* OT_ADDR_LIST | OT_RFC1035_NAME */ },
  { "bootfile-url", 59, OT_NAME },
  { "bootfile-param", 60, OT_CSTRING },
  { NULL, 0, 0 }
};
#endif



/**
 * @brief Display known DHCPv4 option names and numbers
 * @detailed
 * Prints to stdout a list of all known DHCPv4 DHCP options from the opttab[] static table,
 * excluding internal-only options (marked with OT_INTERNAL flag). Used for --help-dhcp
 * command-line option to assist users in configuring dhcp-option directives. Output format
 * is "number name" (e.g., "1 netmask", "3 router").
 *
 * @return void
 * @note Outputs to stdout using printf, not syslog
 * @note Only displays options without OT_INTERNAL flag
 * @see opttab[] static table at lines 616-696 for complete option list
 * @see display_opts6() for DHCPv6 equivalent
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from option processing when --help-dhcp specified
 * display_opts();
 * // Outputs:
 * // Known DHCP options:
 * //   1 netmask
 * //   2 time-offset
 * //   3 router
 * //   ...
 * @endcode
 *
 * SIDE EFFECTS:
 * - Writes to stdout (printf)
 * - No permanent state changes
 *
 * THREAD SAFETY:
 * Re-entrant. Safe for concurrent calls (output may interleave).
 */
void display_opts(void)
{
  int i;
  
  printf(_("Known DHCP options:\n"));
  
  for (i = 0; opttab[i].name; i++)
    if (!(opttab[i].size & OT_INTERNAL))
      printf("%3d %s\n", opttab[i].val, opttab[i].name);
}

#ifdef HAVE_DHCP6
/**
 * @brief Display known DHCPv6 option names and numbers
 * @detailed
 * Prints to stdout a list of all known DHCPv6 options from the opttab6[] static table,
 * excluding internal-only options (marked with OT_INTERNAL flag). Used for --help-dhcp6
 * command-line option to assist users in configuring dhcp-option directives for IPv6.
 * Output format is "number name" (e.g., "23 dns-server", "24 domain-search").
 *
 * @return void
 * @note Only compiled if HAVE_DHCP6 is defined (DHCPv6 support enabled)
 * @note Outputs to stdout using printf, not syslog
 * @note Only displays options without OT_INTERNAL flag
 * @see opttab6[] static table at lines 699-728 for complete DHCPv6 option list
 * @see display_opts() for DHCPv4 equivalent
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from option processing when --help-dhcp6 specified
 * display_opts6();
 * // Outputs:
 * // Known DHCPv6 options:
 * //  23 dns-server
 * //  24 domain-search
 * //  ...
 * @endcode
 *
 * SIDE EFFECTS:
 * - Writes to stdout (printf)
 * - No permanent state changes
 *
 * THREAD SAFETY:
 * Re-entrant. Safe for concurrent calls (output may interleave).
 */
void display_opts6(void)
{
  int i;
  printf(_("Known DHCPv6 options:\n"));
  
  for (i = 0; opttab6[i].name; i++)
    if (!(opttab6[i].size & OT_INTERNAL))
      printf("%3d %s\n", opttab6[i].val, opttab6[i].name);
}
#endif

/**
 * @brief Lookup DHCP option number by name
 * @detailed
 * Searches opttab (DHCPv4) or opttab6 (DHCPv6) for option name and returns corresponding
 * option number. Case-insensitive string comparison using strcasecmp(). Used during
 * configuration parsing to convert human-readable option names (e.g., "dns-server") to
 * option codes (e.g., 6 for DHCPv4, 23 for DHCPv6) for dhcp-option directives.
 *
 * @param prot Protocol family: AF_INET for DHCPv4, AF_INET6 for DHCPv6
 * @param name Option name string to lookup (case-insensitive, e.g., "router", "DNS-Server")
 * @return Option number if found, -1 if name not recognized
 * @retval >=0 Valid DHCP option number corresponding to name
 * @retval -1 Option name not found in table
 * @note Case-insensitive matching (DNS-Server == dns-server == DNS-SERVER)
 * @see opttab[] and opttab6[] static tables for valid option names
 * @see lookup_dhcp_len() to get option size/type after finding number
 *
 * EXAMPLE USAGE:
 * @code
 * int opt_num = lookup_dhcp_opt(AF_INET, "router");
 * // Returns 3 (DHCPv4 router option)
 * opt_num = lookup_dhcp_opt(AF_INET6, "dns-server");
 * // Returns 23 (DHCPv6 DNS server option)
 * @endcode
 *
 * SIDE EFFECTS: None (read-only table lookup)
 *
 * THREAD SAFETY:
 * Re-entrant. Safe for concurrent calls.
 */
int lookup_dhcp_opt(int prot, char *name)
{
  const struct opttab_t *t;
  int i;

  (void)prot;

#ifdef HAVE_DHCP6
  if (prot == AF_INET6)
    t = opttab6;
  else
#endif
    t = opttab;

  for (i = 0; t[i].name; i++)
    if (strcasecmp(t[i].name, name) == 0)
      return t[i].val;
  
  return -1;
}

/**
 * @brief Get DHCP option size/type by option number
 * @detailed
 * Searches opttab or opttab6 for option with given number and returns size/type field
 * with OT_DEC flag removed. Size field encodes fixed size (for fixed-length options) or
 * type flags (OT_ADDR_LIST, OT_NAME, OT_INTERNAL, etc.) for variable-length options.
 * Used to validate option data length and determine parsing method.
 *
 * @param prot Protocol family: AF_INET for DHCPv4, AF_INET6 for DHCPv6
 * @param val DHCP option number to look up (e.g., 3 for router, 6 for dns-server in v4)
 * @return Option size/type flags (with OT_DEC bit cleared), 0 if option not found
 * @retval >0 Option size or type flags (OT_ADDR_LIST=256, OT_NAME=257, etc.)
 * @retval 0 Option number not found in table
 * @note OT_DEC flag is masked out as it affects display only, not size
 * @warning Returned value is size for fixed-length options, type code for variable-length
 * @see opttab[] and opttab6[] for option definitions
 * @see lookup_dhcp_opt() to find option number by name first
 *
 * EXAMPLE USAGE:
 * @code
 * int len = lookup_dhcp_len(AF_INET, 3);
 * // Returns OT_ADDR_LIST (router is variable-length address list)
 * len = lookup_dhcp_len(AF_INET, 2);
 * // Returns 4 (time-offset is fixed 4-byte value)
 * @endcode
 *
 * SIDE EFFECTS: None (read-only table lookup)
 *
 * THREAD SAFETY:
 * Re-entrant. Safe for concurrent calls.
 */
int lookup_dhcp_len(int prot, int val)
{
  const struct opttab_t *t;
  int i;

  (void)prot;

#ifdef HAVE_DHCP6
  if (prot == AF_INET6)
    t = opttab6;
  else
#endif
    t = opttab;

  for (i = 0; t[i].name; i++)
    if (val == t[i].val)
      return t[i].size & ~OT_DEC;

   return 0;
}

/**
 * @brief Convert DHCP option to human-readable string
 * @detailed
 * Formats DHCP option data as human-readable string based on option type. Handles address
 * lists (converts to dotted-decimal/colon-hex), names (ASCII filtering), RFC1035 names
 * (DNS compression), decimal/time values, and hex fallback. Used for logging DHCP options
 * to syslog when OPT_LOG_OPTS is enabled. Returns option name string and fills buffer with
 * formatted value representation.
 *
 * @param prot Protocol family: AF_INET for DHCPv4, AF_INET6 for DHCPv6
 * @param opt DHCP option number to format (e.g., 3 = router, 6 = dns-server)
 * @param val Pointer to option data bytes to format
 * @param opt_len Length of option data in bytes
 * @param buf Buffer to receive formatted string, or NULL to skip formatting
 * @param buf_len Size of output buffer in bytes
 * @return Pointer to option name string from opttab, or "" if option unknown
 * @retval "option-name" Known option (e.g., "router", "dns-server")
 * @retval "" Unknown option number
 * @note If buf is NULL, only option name lookup is performed (no formatting)
 * @warning Buffer may be truncated if opt_len is very large (>14 bytes shown as hex)
 * @see opttab[] and opttab6[] for option type definitions
 * @see my_syslog() calls in DHCP code that use this for logging
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char dns_data[] = {192, 168, 1, 1, 8, 8, 8, 8};
 * char buffer[256];
 * const char *name = option_string(AF_INET, 6, dns_data, 8, buffer, sizeof(buffer));
 * // name = "dns-server", buffer = "192.168.1.1, 8.8.8.8"
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 1035 Section 4.1.4 - DNS name compression (for DHCPv6 RFC1035_NAME options)
 *
 * SIDE EFFECTS:
 * Modifies buf with formatted string. Uses daemon->addrbuff temporarily for inet_ntop.
 *
 * THREAD SAFETY:
 * Not re-entrant due to daemon->addrbuff usage. Single-threaded event model only.
 */
char *option_string(int prot, unsigned int opt, unsigned char *val, int opt_len, char *buf, int buf_len)
{
  int o, i, j, nodecode = 0;
  const struct opttab_t *ot = opttab;

#ifdef HAVE_DHCP6
  if (prot == AF_INET6)
    ot = opttab6;
#endif

  for (o = 0; ot[o].name; o++)
    if (ot[o].val == opt)
      {
	if (buf)
	  {
	    memset(buf, 0, buf_len);
	    
	    if (ot[o].size & OT_ADDR_LIST) 
	      {
		union all_addr addr;
		int addr_len = INADDRSZ;

#ifdef HAVE_DHCP6
		if (prot == AF_INET6)
		  addr_len = IN6ADDRSZ;
#endif
		for (buf[0]= 0, i = 0; i <= opt_len - addr_len; i += addr_len) 
		  {
		    if (i != 0)
		      strncat(buf, ", ", buf_len - strlen(buf));
		    /* align */
		    memcpy(&addr, &val[i], addr_len); 
		    inet_ntop(prot, &val[i], daemon->addrbuff, ADDRSTRLEN);
		    strncat(buf, daemon->addrbuff, buf_len - strlen(buf));
		  }
	      }
	    else if (ot[o].size & OT_NAME)
		for (i = 0, j = 0; i < opt_len && j < buf_len ; i++)
		  {
		    char c = val[i];
		    if (isprint((int)c))
		      buf[j++] = c;
		  }
#ifdef HAVE_DHCP6
	    /* We don't handle compressed rfc1035 names, so no good in IPv4 land */
	    else if ((ot[o].size & OT_RFC1035_NAME) && prot == AF_INET6)
	      {
		i = 0, j = 0;
		while (i < opt_len && val[i] != 0)
		  {
		    int k, l = i + val[i] + 1;
		    for (k = i + 1; k < opt_len && k < l && j < buf_len ; k++)
		     {
		       char c = val[k];
		       if (isprint((int)c))
			 buf[j++] = c;
		     }
		    i = l;
		    if (val[i] != 0 && j < buf_len)
		      buf[j++] = '.';
		  }
	      }
	    else if ((ot[o].size & OT_CSTRING))
	      {
		int k, len;
		unsigned char *p;

		i = 0, j = 0;
		while (1)
		  {
		    p = &val[i];
		    GETSHORT(len, p);
		    for (k = 0; k < len && j < buf_len; k++)
		      {
		       char c = *p++;
		       if (isprint((int)c))
			 buf[j++] = c;
		     }
		    i += len +2;
		    if (i >= opt_len)
		      break;

		    if (j < buf_len)
		      buf[j++] = ',';
		  }
	      }	      
#endif
	    else if ((ot[o].size & (OT_DEC | OT_TIME)) && opt_len != 0)
	      {
		unsigned int dec = 0;
		
		for (i = 0; i < opt_len; i++)
		  dec = (dec << 8) | val[i]; 

		if (ot[o].size & OT_TIME)
		  prettyprint_time(buf, dec);
		else
		  sprintf(buf, "%u", dec);
	      }
	    else
	      nodecode = 1;
	  }
	break;
      }

  if (opt_len != 0 && buf && (!ot[o].name || nodecode))
    {
      int trunc  = 0;
      if (opt_len > 14)
	{
	  trunc = 1;
	  opt_len = 14;
	}
      print_mac(buf, val, opt_len);
      if (trunc)
	strncat(buf, "...", buf_len - strlen(buf));
    

    }

  return ot[o].name ? ot[o].name : "";

}

/**
 * @brief Log DHCP context information to syslog
 * @detailed
 * Logs comprehensive DHCP context details including address range, lease time, context flags
 * (static, proxy, RA stateless, deprecated), template information, and constructed prefix
 * information for DHCPv6. Formats IPv4/IPv6 addresses appropriately and handles special
 * contexts like router advertisement (RA) and DHCPv4-derived IPv6 names. Called during
 * daemon startup and context updates to record active DHCP ranges.
 *
 * @param family Address family: AF_INET for DHCPv4 contexts, AF_INET6 for DHCPv6/RA contexts
 * @param context Pointer to dhcp_context structure to log (contains range, flags, lease time)
 * @return void
 * @note Uses daemon->namebuff, daemon->addrbuff, daemon->dhcp_buff* for formatting
 * @warning Not re-entrant due to shared global buffers (single-threaded model)
 * @see dhcp_context structure (dnsmasq.h:994-1010) for context flags and fields
 * @see my_syslog() for actual logging output
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = daemon->dhcp;
 * log_context(AF_INET, ctx);
 * // Logs: "DHCP, IP range 192.168.1.100 -- 192.168.1.200, lease time 1h"
 * @endcode
 *
 * SIDE EFFECTS:
 * Writes to syslog via my_syslog(). Modifies daemon->namebuff, daemon->addrbuff,
 * daemon->dhcp_buff, daemon->dhcp_buff3 temporarily.
 *
 * THREAD SAFETY:
 * Not re-entrant. Requires single-threaded event-driven model.
 */
void log_context(int family, struct dhcp_context *context)
{
  /* Cannot use dhcp_buff* for RA contexts */

  void *start = &context->start;
  void *end = &context->end;
  char *template = "", *p = daemon->namebuff;
  
  *p = 0;
    
#ifdef HAVE_DHCP6
  if (family == AF_INET6)
    {
      struct in6_addr subnet = context->start6;
      if (!(context->flags & CONTEXT_TEMPLATE))
	setaddr6part(&subnet, 0);
      inet_ntop(AF_INET6, &subnet, daemon->addrbuff, ADDRSTRLEN); 
      start = &context->start6;
      end = &context->end6;
    }
#endif

  if (family != AF_INET && (context->flags & CONTEXT_DEPRECATE))
    strcpy(daemon->namebuff, _(", prefix deprecated"));
  else
    {
      p += sprintf(p, _(", lease time "));
      prettyprint_time(p, context->lease_time);
      p += strlen(p);
    }	

#ifdef HAVE_DHCP6
  if (context->flags & CONTEXT_CONSTRUCTED)
    {
      char ifrn_name[IFNAMSIZ];
      
      template = p;
      p += sprintf(p, ", ");
      
      if (indextoname(daemon->icmp6fd, context->if_index, ifrn_name))
	sprintf(p, "%s for %s", (context->flags & CONTEXT_OLD) ? "old prefix" : "constructed", ifrn_name);
    }
  else if (context->flags & CONTEXT_TEMPLATE && !(context->flags & CONTEXT_RA_STATELESS))
    {
      template = p;
      p += sprintf(p, ", ");
      
      sprintf(p, "template for %s", context->template_interface);  
    }
#endif
     
  if (!(context->flags & CONTEXT_OLD) &&
      ((context->flags & CONTEXT_DHCP) || family == AF_INET)) 
    {
#ifdef HAVE_DHCP6
      if (context->flags & CONTEXT_RA_STATELESS)
	{
	  if (context->flags & CONTEXT_TEMPLATE)
	    strncpy(daemon->dhcp_buff, context->template_interface, DHCP_BUFF_SZ);
	  else
	    strcpy(daemon->dhcp_buff, daemon->addrbuff);
	}
      else 
#endif
	inet_ntop(family, start, daemon->dhcp_buff, DHCP_BUFF_SZ);
      inet_ntop(family, end, daemon->dhcp_buff3, DHCP_BUFF_SZ);
      my_syslog(MS_DHCP | LOG_INFO, 
		(context->flags & CONTEXT_RA_STATELESS) ? 
		_("%s stateless on %s%.0s%.0s%s") :
		(context->flags & CONTEXT_STATIC) ? 
		_("%s, static leases only on %.0s%s%s%.0s") :
		(context->flags & CONTEXT_PROXY) ?
		_("%s, proxy on subnet %.0s%s%.0s%.0s") :
		_("%s, IP range %s -- %s%s%.0s"),
		(family != AF_INET) ? "DHCPv6" : "DHCP",
		daemon->dhcp_buff, daemon->dhcp_buff3, daemon->namebuff, template);
    }
  
#ifdef HAVE_DHCP6
  if (context->flags & CONTEXT_TEMPLATE)
    {
      strcpy(daemon->addrbuff, context->template_interface);
      template = "";
    }

  if ((context->flags & CONTEXT_RA_NAME) && !(context->flags & CONTEXT_OLD))
    my_syslog(MS_DHCP | LOG_INFO, _("DHCPv4-derived IPv6 names on %s%s"), daemon->addrbuff, template);
  
  if ((context->flags & CONTEXT_RA) || (option_bool(OPT_RA) && (context->flags & CONTEXT_DHCP) && family == AF_INET6)) 
    my_syslog(MS_DHCP | LOG_INFO, _("router advertisement on %s%s"), daemon->addrbuff, template);
#endif

}

/**
 * @brief Log DHCP relay configuration to syslog
 * @detailed
 * Logs DHCP relay agent configuration showing local interface address, relay destination
 * server address, port numbers (if non-default), and interface name. Handles both DHCPv4
 * and DHCPv6 relay configurations. Broadcast/multicast destinations are detected and logged
 * appropriately (IPv4 0.0.0.0 = broadcast, IPv6 ff02::1:2 = All_DHCP_Relay_Agents_and_Servers
 * multicast). Called during daemon initialization to record active relay configurations.
 *
 * @param family Address family: AF_INET for DHCPv4 relay, AF_INET6 for DHCPv6 relay
 * @param relay Pointer to dhcp_relay structure containing relay configuration
 * @return void
 * @note DHCPv4 default port is 67 (DHCP_SERVER_PORT), DHCPv6 default is 547 (DHCPV6_SERVER_PORT)
 * @warning Uses daemon->addrbuff and daemon->namebuff (not re-entrant)
 * @see dhcp_relay structure (dnsmasq.h:1084-1097) for relay configuration fields
 * @see my_syslog() for actual logging output
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_relay *relay = daemon->relay4;
 * log_relay(AF_INET, relay);
 * // Logs: "DHCP relay from 192.168.1.1 to 10.0.0.1 via eth0"
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 20 - DHCPv6 relay agents (All_DHCP_Relay_Agents_and_Servers = ff02::1:2)
 * RFC 2131 Section 4 - DHCPv4 relay agents (BOOTPS port 67)
 *
 * SIDE EFFECTS:
 * Writes to syslog via my_syslog(). Modifies daemon->addrbuff and daemon->namebuff temporarily.
 *
 * THREAD SAFETY:
 * Not re-entrant. Requires single-threaded event-driven model.
 */
void log_relay(int family, struct dhcp_relay *relay)
{
  int broadcast = relay->server.addr4.s_addr == 0;
  inet_ntop(family, &relay->local, daemon->addrbuff, ADDRSTRLEN);
  inet_ntop(family, &relay->server, daemon->namebuff, ADDRSTRLEN);

  if (family == AF_INET && relay->port != DHCP_SERVER_PORT)
    sprintf(daemon->namebuff + strlen(daemon->namebuff), "#%u", relay->port);

#ifdef HAVE_DHCP6
  struct in6_addr multicast;

  inet_pton(AF_INET6, ALL_SERVERS, &multicast);

  if (family == AF_INET6)
    {
      broadcast = IN6_ARE_ADDR_EQUAL(&relay->server.addr6, &multicast);
      if (relay->port != DHCPV6_SERVER_PORT)
	sprintf(daemon->namebuff + strlen(daemon->namebuff), "#%u", relay->port);
    }
#endif
  
  
  if (relay->interface)
    {
      if (broadcast)
	my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay from %s via %s"), daemon->addrbuff, relay->interface);
      else
	my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay from %s to %s via %s"), daemon->addrbuff, daemon->namebuff, relay->interface);
    }
  else
    my_syslog(MS_DHCP | LOG_INFO, _("DHCP relay from %s to %s"), daemon->addrbuff, daemon->namebuff);
}
   
#endif
