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
 * @file nftset.c
 * @brief Linux nftables set integration (successor to ipset)
 * 
 * DETAILED PURPOSE
 * 
 * This module provides automatic addition of resolved DNS addresses to nftables
 * sets using the libnftables API. Nftables is the modern replacement for iptables
 * and ipset in Linux, offering richer data types, better performance, and improved
 * integration with the Linux kernel netfilter framework. When dnsmasq resolves
 * DNS queries for domains configured with --nftset options, the resolved IP
 * addresses are automatically added to the specified nftables sets, enabling
 * dynamic firewall rules and routing policies based on DNS resolution results.
 * 
 * Unlike the older ipset integration (ipset.c), nftables supports native IPv4
 * and IPv6 address families, more flexible set definitions, and unified rule
 * syntax. Sets are identified using the format "table#family#set" where table
 * is the nftables table name, family is the address family (ip, ip6, inet),
 * and set is the set name within that table.
 * 
 * KEY RESPONSIBILITIES
 * 
 * - nftset_init() - Initialize libnftables context for set operations
 * - add_to_nftset() - Add or remove IP addresses to/from nftables sets
 * - Command buffer management for nft commands
 * - Error handling and logging of nftables operations
 * 
 * DEPENDENCIES
 * 
 * Includes: dnsmasq.h (main header), nftables/libnftables.h (nftables API),
 *           string.h (string operations), arpa/inet.h (inet_ntop)
 * 
 * Called by: DNS forwarding code (forward.c) when resolution completes,
 *            DHCP lease code when addresses are allocated
 * 
 * Calls: nft_ctx_new(), nft_ctx_buffer_error(), nft_run_cmd_from_buffer(),
 *        nft_ctx_get_error_buffer(), inet_ntop(), whine_malloc(), my_syslog(), die()
 * 
 * DATA STRUCTURES
 * 
 * - struct nft_ctx (libnftables) - Nftables context handle (line 27)
 * - union all_addr (dnsmasq.h) - IPv4/IPv6 address container used for IP addresses
 * - Static command templates for add/delete element operations (lines 28-29)
 * - Static command buffer with dynamic resizing (lines 47-48)
 * 
 * COMPILE-TIME OPTIONS
 * 
 * - HAVE_NFTSET - Enables nftables set integration (required)
 * - HAVE_LINUX_NETWORK - Linux-specific networking support (required)
 * 
 * Impact: When both macros are defined, this entire module is compiled and
 * nftables set operations become available. Without these, the module is
 * excluded and --nftset configuration options are unavailable.
 * 
 * Required external library: libnftables (Debian/Ubuntu: libnftables-dev,
 * RedHat/CentOS: nftables-devel)
 * 
 * THREADING/CONCURRENCY
 * 
 * Single-threaded event-driven model. The nftables context (ctx) is initialized
 * once at startup and reused for all operations. The static command buffer is
 * not thread-safe but this is acceptable in dnsmasq's single-threaded architecture.
 * All nftables operations execute synchronously within the main event loop.
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * 
 * @see docs/ARCHITECTURE.md for system integration
 * @see ipset.c for the older ipset-based implementation
 * @see forward.c for DNS resolution triggering nftset updates
 */

#include "dnsmasq.h"

#if defined (HAVE_NFTSET) && defined (HAVE_LINUX_NETWORK)

#include <nftables/libnftables.h>

#include <string.h>
#include <arpa/inet.h>

static struct nft_ctx *ctx = NULL;
static const char *cmd_add = "add element %s { %s }";
static const char *cmd_del = "delete element %s { %s }";

/**
 * @brief Initialize libnftables context for set operations
 * 
 * @detailed
 * Creates and configures the libnftables context required for all subsequent
 * nftables set operations. This must be called once during dnsmasq initialization
 * before any add_to_nftset() calls. The context is stored in the static variable
 * ctx and reused for all operations. Error output from libnftables is buffered
 * to prevent unwanted console output, allowing dnsmasq to control logging.
 * 
 * @return void - Function terminates process on failure via die()
 * 
 * @note This function must be called during daemon initialization, typically
 *       from main() in dnsmasq.c when HAVE_NFTSET is enabled. The nftables
 *       context is never freed as it's needed for the entire daemon lifetime.
 * 
 * @note Requires nftables kernel support (Linux 3.13+) and libnftables library.
 *       On systems without nftables support, nft_ctx_new() will fail and
 *       the daemon will terminate with EC_MISC error code.
 * 
 * @warning Terminates the entire dnsmasq process if context creation fails.
 *          This is intentional as nftables functionality would be broken.
 * 
 * @see add_to_nftset() for the function that uses this initialized context
 * @see nft_ctx_new() in libnftables documentation for context creation details
 * 
 * EXAMPLE USAGE:
 * @code
 * #ifdef HAVE_NFTSET
 *   nftset_init();  // Called once during daemon startup
 * #endif
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Allocates nftables context in static variable ctx
 * - Configures libnftables to buffer error messages instead of printing to stderr
 * - Process termination via die() if initialization fails
 * 
 * THREAD SAFETY:
 * Not thread-safe due to static variable modification, but safe in dnsmasq's
 * single-threaded event-driven model. Must be called only once at startup.
 */
void nftset_init()
{
  ctx = nft_ctx_new(NFT_CTX_DEFAULT);
  if (ctx == NULL)
    die(_("failed to create nftset context"), NULL, EC_MISC);

  /* disable libnftables output */
  nft_ctx_buffer_error(ctx);
}

/**
 * @brief Add or remove IP address to/from nftables set
 * 
 * @detailed
 * Adds or removes an IPv4 or IPv6 address to/from a specified nftables set by
 * executing nftables commands via libnftables API. The set is identified by name
 * in the format "table#family#set" (e.g., "filter#ip#blacklist"). The function
 * constructs nftables commands like "add element filter#ip#blacklist { 192.0.2.1 }"
 * and executes them through nft_run_cmd_from_buffer(). The command buffer is
 * dynamically resized as needed to accommodate long set names and addresses.
 * 
 * The function supports address family filtering via optional "4 " or "6 " prefix
 * in setname to restrict updates to IPv4 or IPv6 addresses respectively. This
 * allows configuration like "--nftset=4 filter#ip#whitelist" to only add IPv4.
 * 
 * @param setname Set identifier in format "table#family#set", or with optional
 *                address family prefix "4 table#family#set" or "6 table#family#set".
 *                Examples: "filter#ip#blacklist", "4 mangle#ip#ratelimit",
 *                "nat#ip6#vpn_clients". The table must exist in nftables and
 *                the set must be pre-created with appropriate type (ipv4_addr or ipv6_addr).
 *                NULL or empty strings are not permitted and will cause errors.
 * 
 * @param ipaddr Pointer to union all_addr containing IPv4 (addr.addr4) or IPv6
 *               (addr.addr6) address to add/remove. Must not be NULL. Address
 *               family is determined by flags parameter, not by inspecting the union.
 * 
 * @param flags Bit flags indicating address family and operation mode. F_IPV4 flag
 *              indicates IPv4 address (AF_INET), absence indicates IPv6 (AF_INET6).
 *              Used to determine which union member to access and which address
 *              family to pass to inet_ntop(). Additional flags may be present but
 *              are not used by this function.
 * 
 * @param remove Boolean flag: 0 to add address to set, non-zero to remove address
 *               from set. Controls whether "add element" or "delete element" command
 *               is executed. Removing non-existent addresses typically generates
 *               errors logged to syslog but does not affect daemon operation.
 * 
 * @return 0 on success (nftables command executed without error)
 * @retval 0 Successfully added/removed address to/from nftables set
 * @retval -1 Address family filter mismatch (e.g., "4 " prefix with IPv6 address)
 * @retval non-zero Nftables command execution failure (set doesn't exist, permission
 *                  denied, kernel module not loaded, etc.). Error details logged to syslog.
 * 
 * @note Uses static command buffer that grows as needed but is never freed.
 *       Initial allocation is 150 bytes, subsequent allocations add 10 bytes
 *       to snprintf() result to ensure adequate space.
 * 
 * @note The nftables set must be pre-created with appropriate type. For IPv4,
 *       use "type ipv4_addr", for IPv6 use "type ipv6_addr". Example nftables
 *       configuration: "nft add set filter blacklist { type ipv4_addr; }"
 * 
 * @warning On memory allocation failure (whine_malloc returns NULL), function
 *          returns 0 (success) to prevent DNS resolution failures from affecting
 *          nftset failures. This is logged by whine_malloc().
 * 
 * @warning Requires nftset_init() to have been called successfully during startup,
 *          otherwise ctx will be NULL and nft_run_cmd_from_buffer() will fail.
 * 
 * @see nftset_init() for context initialization required before calling this function
 * @see ipset.c add_to_ipset() for equivalent functionality using legacy ipsets
 * @see forward.c for DNS resolution code that triggers nftset updates
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("192.0.2.1");
 * int result = add_to_nftset("filter#ip#blacklist", &addr, F_IPV4, 0);
 * if (result != 0)
 *   my_syslog(LOG_WARNING, "Failed to add address to nftset");
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Not applicable - nftables is a Linux-specific netfilter feature, not an RFC protocol.
 * 
 * SIDE EFFECTS:
 * - Modifies nftables ruleset by adding/removing set elements
 * - Grows static command buffer on first call or when larger commands needed
 * - Logs errors to syslog when nftables commands fail
 * - Uses daemon->addrbuff for temporary string conversion
 * 
 * THREAD SAFETY:
 * Not thread-safe due to static command buffer, but safe in dnsmasq's single-threaded
 * model. Multiple concurrent calls would corrupt the static buffer and ctx usage.
 */
int add_to_nftset(const char *setname, const union all_addr *ipaddr, int flags, int remove)
{
  const char *cmd = remove ? cmd_del : cmd_add;
  int ret, af = (flags & F_IPV4) ? AF_INET : AF_INET6;
  size_t new_sz;
  char *new, *err, *nl;
  static char *cmd_buf = NULL;
  static size_t cmd_buf_sz = 0;

  inet_ntop(af, ipaddr, daemon->addrbuff, ADDRSTRLEN);

  if (setname[1] == ' ' && (setname[0] == '4' || setname[0] == '6'))
    {
      if (setname[0] == '4' && !(flags & F_IPV4))
	return -1;

      if (setname[0] == '6' && !(flags & F_IPV6))
	return -1;

      setname += 2;
    }
  
  if (cmd_buf_sz == 0)
    new_sz = 150; /* initial allocation */
  else
    new_sz = snprintf(cmd_buf, cmd_buf_sz, cmd, setname, daemon->addrbuff);
  
  if (new_sz > cmd_buf_sz)
    {
      if (!(new = whine_malloc(new_sz + 10)))
	return 0;

      if (cmd_buf)
	free(cmd_buf);
      cmd_buf = new;
      cmd_buf_sz = new_sz + 10;
      snprintf(cmd_buf, cmd_buf_sz, cmd, setname, daemon->addrbuff);
    }

  ret = nft_run_cmd_from_buffer(ctx, cmd_buf);
  err = (char *)nft_ctx_get_error_buffer(ctx);

  if (ret != 0)
    {
      /* Log only first line of error return. */
      if ((nl = strchr(err, '\n')))
	*nl = 0;
      my_syslog(LOG_ERR,  "nftset %s %s", setname, err);
    }
  
  return ret;
}

#endif
