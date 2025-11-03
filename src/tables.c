/* tables.c is Copyright (c) 2014 Sven Falempin  All Rights Reserved.

   Author's email: sfalempin@citypassenger.com 

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
 * @file tables.c
 * @brief BSD Packet Filter (pf) table integration for DNS-based firewall rules
 *
 * DETAILED PURPOSE:
 * This module provides integration with BSD's Packet Filter (pf) firewall system,
 * enabling dnsmasq to dynamically populate pf tables with IP addresses resolved
 * from DNS queries. This is the BSD equivalent of Linux's ipset (src/ipset.c) or
 * nftables set (src/nftset.c) integration, allowing DNS-based blocking, routing,
 * or traffic shaping policies.
 *
 * When dnsmasq resolves a domain name matching configured ipset rules, the
 * resolved IP addresses are added to specified pf tables. These tables can then
 * be referenced in pf.conf rules for filtering, NAT, or redirection decisions.
 * This enables dynamic firewall policies based on DNS resolution without manual
 * IP address maintenance.
 *
 * The implementation uses pf's ioctl interface (/dev/pf) to manipulate tables
 * at runtime. Tables are created automatically if they don't exist (with
 * PFR_TFLAG_PERSIST flag), and addresses are added or removed using
 * DIOCRADDADDRS/DIOCRDELADDRS ioctl commands.
 *
 * KEY RESPONSIBILITIES:
 * - ipset_init() - Initialize pf device access by opening /dev/pf
 * - add_to_ipset() - Add or remove IPv4/IPv6 addresses from pf tables
 * - pfr_strerror() - Translate pf-specific error codes to descriptive messages
 *
 * DEPENDENCIES:
 * - dnsmasq.h - Core type definitions including union all_addr, F_IPV6 flag
 * - net/pfvar.h - BSD pf kernel structures (pfr_addr, pfioc_table, pfr_table)
 * - /dev/pf device - Requires read/write access (typically root privileges)
 *
 * External functions called:
 * - open() - Opens /dev/pf device
 * - ioctl() - DIOCRADDTABLES, DIOCRADDADDRS, DIOCRDELADDRS commands
 * - my_syslog() - Logging (from dnsmasq core)
 * - die() - Fatal error termination (from dnsmasq core)
 *
 * Called by:
 * - DNS resolution code when ipset= configuration matches resolved domains
 *
 * DATA STRUCTURES:
 * - pfr_addr (net/pfvar.h) - Represents IP address with address family and netmask
 * - pfioc_table (net/pfvar.h) - ioctl structure for table operations
 * - pfr_table (net/pfvar.h) - Represents pf table with name and flags
 * - union all_addr (dnsmasq.h:303) - Union of IPv4 (addr4) and IPv6 (addr6) addresses
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_IPSET - Must be defined to enable ipset/table integration
 * - HAVE_BSD_NETWORK - Must be defined to compile BSD-specific networking code
 * - Both macros required (line 21: #if defined(HAVE_IPSET) && defined(HAVE_BSD_NETWORK))
 *
 * Without these definitions, this entire file is excluded from compilation.
 * This ensures the code only compiles on BSD systems (FreeBSD, OpenBSD, NetBSD)
 * where pf is available.
 *
 * THREADING/CONCURRENCY:
 * This code operates within dnsmasq's single-threaded, event-driven architecture.
 * No explicit locking is required as all pf operations are performed synchronously
 * from the main event loop. The /dev/pf device file descriptor is opened once at
 * initialization and reused for all subsequent operations.
 *
 * Thread safety notes:
 * - Not thread-safe due to static global 'dev' file descriptor
 * - Assumes single-threaded execution model (dnsmasq design)
 * - ioctl() operations are atomic at the kernel level
 * - No concurrent access to pf device from multiple threads
 *
 * @copyright Copyright (c) 2014 Sven Falempin. All Rights Reserved.
 * @license GPL-2.0-or-later
 *
 * @see src/ipset.c for Linux ipset equivalent implementation
 * @see src/nftset.c for Linux nftables set equivalent implementation
 * @see src/option.c for ipset= configuration parsing
 */

#include "dnsmasq.h"

#if defined(HAVE_IPSET) && defined(HAVE_BSD_NETWORK)

#include <string.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>

#define UNUSED(x) (void)(x)

static char *pf_device = "/dev/pf";
static int dev = -1;

/**
 * @brief Convert pf-specific error codes to descriptive error messages
 *
 * @detailed
 * Translates specific errno values returned by pf ioctl operations into
 * human-readable error messages. This function provides better diagnostic
 * information than generic strerror() for pf-specific operations. It handles
 * ESRCH (table does not exist) and ENOENT (anchor/ruleset does not exist)
 * specially, falling back to standard strerror() for other error codes.
 *
 * @param errnum Error number from errno after failed pf ioctl operation
 *
 * @return Pointer to static error message string (do not free)
 * @retval "Table does not exist" if errnum == ESRCH
 * @retval "Anchor or Ruleset does not exist" if errnum == ENOENT
 * @retval Result of strerror(errnum) for all other error codes
 *
 * @note Return value points to static storage and should not be modified or freed
 * @note This is a helper function for add_to_ipset() error reporting
 *
 * @warning Not thread-safe due to potential strerror() usage (strerror is not
 *          guaranteed to be thread-safe in all implementations), but safe in
 *          dnsmasq's single-threaded context
 *
 * @see add_to_ipset() which calls this function for error logging
 * @see strerror(3) for standard error message conversion
 *
 * EXAMPLE USAGE:
 * @code
 * if (ioctl(dev, DIOCRADDADDRS, &io) < 0) {
 *     my_syslog(LOG_WARNING, "pf error: %s", pfr_strerror(errno));
 *     return -1;
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * None. Pure function that only performs error code lookup.
 *
 * THREAD SAFETY:
 * Not guaranteed thread-safe due to strerror() usage in default case, but
 * acceptable in dnsmasq's single-threaded execution model. For thread-safe
 * operation, strerror_r() would be required.
 */
static char *pfr_strerror(int errnum)
{
  switch (errnum) 
    {
    case ESRCH:
      return "Table does not exist";
    case ENOENT:
      return "Anchor or Ruleset does not exist";
    default:
      return strerror(errnum);
    }
}

/**
 * @brief Initialize BSD packet filter device for table manipulation
 *
 * @detailed
 * Opens the /dev/pf device file for read/write access, which is required for
 * all subsequent pf table operations. This function must be called during
 * dnsmasq initialization before any add_to_ipset() calls are made. The opened
 * file descriptor is stored in the static 'dev' variable and reused for all
 * table operations throughout the daemon's lifetime.
 *
 * On failure, this function calls err(1) and die(), terminating the program
 * immediately. This is intentional as dnsmasq cannot fulfill its ipset=
 * configuration directives without pf access.
 *
 * @return void (never returns on failure - calls die() instead)
 *
 * @note Requires root privileges or appropriate permissions to open /dev/pf
 * @note This function is called once during dnsmasq startup (from main.c)
 * @note File descriptor remains open for the lifetime of the dnsmasq process
 * @note On BSD systems, /dev/pf permissions are typically 0600 owned by root
 *
 * @warning Terminates the program on failure - no graceful degradation
 * @warning Must be called before any add_to_ipset() operations
 * @warning Not idempotent - calling multiple times would leak file descriptors
 *
 * @see add_to_ipset() which requires this function to be called first
 * @see open(2) for file descriptor creation
 *
 * EXAMPLE USAGE:
 * @code
 * // During dnsmasq initialization:
 * if (daemon->ipsets) {
 *     ipset_init();  // Opens /dev/pf
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Opens /dev/pf and stores file descriptor in static global 'dev' variable
 * - Terminates program (exit code 1) if device cannot be opened
 * - Logs fatal error message via err(1) and die() on failure
 * - Allocates a file descriptor that persists for process lifetime
 *
 * THREAD SAFETY:
 * Not thread-safe due to modification of static global 'dev' variable.
 * Must be called from single-threaded context (dnsmasq initialization phase).
 * Acceptable in dnsmasq's single-threaded event-driven architecture.
 */
void ipset_init(void) 
{
  dev = open( pf_device, O_RDWR);
  if (dev == -1)
    {
      err(1, "%s", pf_device);
      die (_("failed to access pf devices: %s"), NULL, EC_MISC);
    }
}

/**
 * @brief Add or remove IP address from BSD pf table
 *
 * @detailed
 * Adds or removes an IPv4 or IPv6 address to/from a specified pf table. This
 * function is the core integration point between dnsmasq's DNS resolution and
 * BSD's Packet Filter firewall. When dnsmasq resolves a domain matching ipset=
 * configuration directives, this function populates the corresponding pf tables
 * for use in firewall rules.
 *
 * The function creates the table if it doesn't exist (with PERSIST flag),
 * then performs the add or remove operation using pf ioctl commands. Both
 * IPv4 (/32 single host) and IPv6 (/128 single host) addresses are supported,
 * determined by the F_IPV6 flag in the flags parameter.
 *
 * @param setname Name of the pf table (e.g., "blocklist"). Must be less than
 *                PF_TABLE_NAME_SIZE (typically 32 characters). This table name
 *                must match tables referenced in pf.conf rules. Cannot be NULL.
 * @param ipaddr  Pointer to union all_addr containing IPv4 (addr4.s_addr) or
 *                IPv6 (addr6) address to add/remove. Cannot be NULL. Address
 *                family determined by flags parameter.
 * @param flags   Bitmask of flags, primarily F_IPV6 (1u<<8) to indicate IPv6
 *                address. If F_IPV6 is set, ipaddr->addr6 is used; otherwise
 *                ipaddr->addr4.s_addr is used for IPv4.
 * @param remove  Non-zero to remove address from table, zero to add address.
 *                Controls whether DIOCRDELADDRS or DIOCRADDADDRS ioctl is used.
 *
 * @return Number of addresses successfully added/removed (typically 1)
 * @retval >0 Success - number of addresses modified (typically 1, logged to syslog)
 * @retval -1 Failure - pf device not initialized, table name too long, strlcpy failed,
 *            ioctl error, or address operation failed. Error details logged via my_syslog()
 * @retval 0  Possible but unlikely - no addresses modified (should not occur normally)
 *
 * @note Table is created automatically if it doesn't exist (DIOCRADDTABLES ioctl)
 * @note Table is created with PFR_TFLAG_PERSIST flag to survive ruleset reloads
 * @note IPv4 addresses use /32 netmask (pfra_net = 0x20), single host entries
 * @note IPv6 addresses use /128 netmask (pfra_net = 0x80), single host entries
 * @note All operations are logged to syslog at LOG_INFO or LOG_WARNING levels
 *
 * @warning Requires ipset_init() to have been called successfully first
 * @warning Table name longer than PF_TABLE_NAME_SIZE returns -1 with ENAMETOOLONG
 * @warning If /dev/pf is not open (dev == -1), logs error and returns -1
 * @warning pf.conf must reference the table name, or table entries have no effect
 * @warning ioctl operations require appropriate privileges (typically root)
 *
 * @see ipset_init() must be called once at startup before using this function
 * @see src/ipset.c for Linux ipset equivalent implementation
 * @see src/nftset.c for Linux nftables set equivalent implementation
 * @see src/option.c for ipset= configuration directive parsing
 * @see pf.conf(5) for table usage in firewall rules
 *
 * EXAMPLE USAGE:
 * @code
 * // Add resolved IPv4 address to "malware" pf table:
 * union all_addr addr;
 * addr.addr4.s_addr = resolved_ipv4;
 * int result = add_to_ipset("malware", &addr, 0, 0);
 * if (result < 0) {
 *     // Error already logged via my_syslog
 * }
 *
 * // Add resolved IPv6 address to "blocklist" pf table:
 * union all_addr addr6;
 * memcpy(&addr6.addr6, &resolved_ipv6, sizeof(struct in6_addr));
 * int result = add_to_ipset("blocklist", &addr6, F_IPV6, 0);
 *
 * // Remove IPv4 address from table:
 * int result = add_to_ipset("allowlist", &addr, 0, 1);
 * @endcode
 *
 * PF.CONF USAGE EXAMPLE:
 * @code
 * # In pf.conf, reference the table populated by dnsmasq:
 * table <malware> persist
 * block in quick from <malware> to any
 * block out quick from any to <malware>
 * @endcode
 *
 * SIDE EFFECTS:
 * - Creates pf table if it doesn't exist (DIOCRADDTABLES ioctl)
 * - Modifies pf table contents by adding or removing IP addresses (DIOCRADDADDRS/DIOCRDELADDRS)
 * - Logs operations to syslog (LOG_INFO for success, LOG_WARNING/LOG_ERR for errors)
 * - Sets errno on various failure conditions (ENAMETOOLONG, or pf ioctl errors)
 * - pf table changes take effect immediately and persist across pf rule reloads
 * - Firewall rules referencing the table immediately see the updated address set
 *
 * THREAD SAFETY:
 * Not thread-safe due to:
 * - Use of static global 'dev' file descriptor
 * - ioctl operations on shared pf device
 * - Errno is thread-local but could be overwritten by signal handlers
 *
 * Acceptable in dnsmasq's single-threaded, event-driven architecture where
 * this function is called only from the main event loop. No concurrent
 * execution occurs.
 */
int add_to_ipset(const char *setname, const union all_addr *ipaddr,
		 int flags, int remove)
{
  struct pfr_addr addr;
  struct pfioc_table io;
  struct pfr_table table;

  if (dev == -1) 
    {
      my_syslog(LOG_ERR, _("warning: no opened pf devices %s"), pf_device);
      return -1;
    }

  bzero(&table, sizeof(struct pfr_table));
  table.pfrt_flags |= PFR_TFLAG_PERSIST;
  if (strlen(setname) >= PF_TABLE_NAME_SIZE)
    {
      my_syslog(LOG_ERR, _("error: cannot use table name %s"), setname);
      errno = ENAMETOOLONG;
      return -1;
    }
  
  if (strlcpy(table.pfrt_name, setname,
	      sizeof(table.pfrt_name)) >= sizeof(table.pfrt_name)) 
    {
      my_syslog(LOG_ERR, _("error: cannot strlcpy table name %s"), setname);
      return -1;
    }
  
  bzero(&io, sizeof io);
  io.pfrio_flags = 0;
  io.pfrio_buffer = &table;
  io.pfrio_esize = sizeof(table);
  io.pfrio_size = 1;
  if (ioctl(dev, DIOCRADDTABLES, &io))
    {
      my_syslog(LOG_WARNING, _("IPset: error: %s"), pfr_strerror(errno));
      
      return -1;
    }
  
  table.pfrt_flags &= ~PFR_TFLAG_PERSIST;
  if (io.pfrio_nadd)
    my_syslog(LOG_INFO, _("info: table created"));
 
  bzero(&addr, sizeof(addr));

  if (flags & F_IPV6) 
    {
      addr.pfra_af = AF_INET6;
      addr.pfra_net = 0x80;
      memcpy(&(addr.pfra_ip6addr), ipaddr, sizeof(struct in6_addr));
    } 
  else 
    {
      addr.pfra_af = AF_INET;
      addr.pfra_net = 0x20;
      addr.pfra_ip4addr.s_addr = ipaddr->addr4.s_addr;
    }

  bzero(&io, sizeof(io));
  io.pfrio_flags = 0;
  io.pfrio_table = table;
  io.pfrio_buffer = &addr;
  io.pfrio_esize = sizeof(addr);
  io.pfrio_size = 1;
  if (ioctl(dev, ( remove ? DIOCRDELADDRS : DIOCRADDADDRS ), &io)) 
    {
      my_syslog(LOG_WARNING, _("warning: DIOCR%sADDRS: %s"), ( remove ? "DEL" : "ADD" ), pfr_strerror(errno));
      return -1;
    }
  
  my_syslog(LOG_INFO, _("%d addresses %s"),
            io.pfrio_nadd, ( remove ? "removed" : "added" ));
  
  return io.pfrio_nadd;
}


#endif
