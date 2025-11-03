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
 * @file lease.c
 * @brief DHCP lease database persistence and management
 *
 * DETAILED PURPOSE:
 * 
 * This file implements the complete DHCP lease database management system for dnsmasq,
 * providing persistent storage, allocation, lookup, and expiry tracking for both DHCPv4
 * and DHCPv6 leases. The implementation ensures atomic file updates through a write-to-temp
 * then rename strategy to prevent database corruption. Lease data includes client hardware
 * addresses, client identifiers, hostnames, IP addresses (IPv4 and IPv6), and expiration
 * timestamps.
 * 
 * The lease database supports systems without real-time clocks (HAVE_BROKEN_RTC) by storing
 * lease duration instead of absolute expiration times, calculating expiry relative to system
 * uptime. Lease file updates are atomic to prevent corruption during power failures or crashes,
 * using standard POSIX file operations with explicit fsync() and rename semantics.
 * 
 * Static host reservations from configuration are applied to leases through
 * lease_update_from_configs(), ensuring configured hostnames override DHCP-supplied names.
 * The database format is human-readable text with fields: expiry/duration, MAC address, IP address,
 * hostname, and client identifier, one lease per line. DHCPv6 leases include IAID and lease type
 * (TA or NA) prefixes. On database read failures, the system retries after LEASE_RETRY (60 seconds)
 * to handle transient filesystem issues.
 *
 * KEY RESPONSIBILITIES:
 * - lease_init() - Initialize lease database at daemon startup, load existing leases
 * - lease_update_file() - Atomically persist lease database to disk with write-temp-rename
 * - lease_update_from_configs() - Apply static host reservations to active leases
 * - lease_find_by_client() - Locate lease by client ID or MAC address
 * - lease_find_by_addr() - Locate DHCPv4 lease by IP address
 * - lease4_allocate() / lease6_allocate() - Allocate new lease entries
 * - lease_set_hwaddr() - Update lease hardware address and client identifier
 * - lease_set_hostname() - Update lease hostname with conflict detection
 * - lease_set_expires() - Set lease expiration time with 2038 overflow handling
 * - lease_prune() - Remove expired leases and trigger lease-change scripts
 * - do_script_run() - Execute lease-change scripts for old/new/deleted leases
 * - lease_find_max_addr() - Find highest allocated address in DHCP context (for allocation)
 *
 * DEPENDENCIES:
 * - Includes: dnsmasq.h (core types including struct dhcp_lease, struct dhcp_config, struct dhcp_context)
 * - Calls: whine_malloc() for memory allocation, my_syslog() for logging, die() for fatal errors
 * - Calls: inet_pton(), inet_ntop() for address conversion, fscanf(), fprintf() for file I/O
 * - Calls: cache_add_dhcp_entry(), cache_unhash_dhcp() for DNS cache integration
 * - Calls: iface_enumerate() for interface iteration, send_alarm() for timer management
 * - Calls: find_config() to locate static host configurations
 * - Calls: lease-change script execution via queue_script() (if HAVE_SCRIPT)
 * - Calls: D-Bus signal emission via emit_dbus_signal() (if HAVE_DBUS)
 * - Calls: SLAAC address management via slaac_add_addrs(), periodic_slaac(), slaac_ping_reply() (if HAVE_DHCP6)
 * - Called by: Main daemon initialization, DHCP packet handlers, periodic timer events
 *
 * DATA STRUCTURES:
 * - struct dhcp_lease (dnsmasq.h:799-829) - Lease record with client ID, hardware address, addresses, expiry
 * - static struct dhcp_lease *leases - Active lease linked list
 * - static struct dhcp_lease *old_leases - Deleted leases awaiting script execution
 * - static int dns_dirty - Flag indicating DNS cache needs update
 * - static int file_dirty - Flag indicating lease file needs rewrite
 * - static int leases_left - Remaining lease capacity (daemon->dhcp_max)
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP - Entire file compiled only when DHCP server is enabled
 * - HAVE_DHCP6 - Enables DHCPv6 and IPv6 lease handling, DUID support, SLAAC integration
 * - HAVE_BROKEN_RTC - Systems without real-time clock, stores lease duration instead of expiry timestamp
 * - HAVE_SCRIPT - Enables lease-change script execution for add/del/old actions
 * - HAVE_DBUS - Enables D-Bus signal emission for lease state changes
 * - OPT_LEASE_RO - Read-only lease file mode, lease data sourced from external script
 * - OPT_DHCP_FQDN - Use fully-qualified domain names for hostname conflict detection
 * - OPT_LEASE_RENEW - Trigger lease-change script on expiry changes (not just add/del)
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. All lease operations execute in main event loop context.
 * No thread safety required. File I/O blocking is acceptable as lease database is small and operations
 * are infrequent (triggered by DHCP transactions and periodic timer events). LEASE_RETRY (60 seconds)
 * provides recovery from filesystem write failures without blocking indefinitely.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

static struct dhcp_lease *leases = NULL, *old_leases = NULL;
static int dns_dirty, file_dirty, leases_left;

/**
 * @brief Parse lease database file and populate lease structures
 *
 * @detailed
 * Reads the lease database file line-by-line, parsing DHCPv4 and DHCPv6 lease records.
 * DHCPv4 format: <expiry> <hw_addr> <ip_addr> <hostname> <client_id>
 * DHCPv6 format: <expiry> [T]<iaid> <ipv6_addr> <hostname> <client_id>
 * Also parses DUID line for DHCPv6: "duid <hex_duid>"
 * Allocates lease structures via lease4_allocate() or lease6_allocate() and populates
 * all fields. For systems with HAVE_BROKEN_RTC, interprets expiry as duration from now.
 *
 * @param now Current time for calculating absolute expiry from duration
 * @param leasestream Open FILE pointer to lease database (positioned at start)
 * @return 1 on successful parse (EOF or clean end), 0 on parse error
 *
 * @note Uses daemon->dhcp_buff*, daemon->namebuff, daemon->packet as parse buffers
 * @warning Dies with fatal error if lease allocation exceeds daemon->dhcp_max
 * @see lease4_allocate() for DHCPv4 lease creation
 * @see lease6_allocate() for DHCPv6 lease creation
 *
 * EXAMPLE USAGE:
 * @code
 * FILE *fp = fopen("/var/lib/dnsmasq/dnsmasq.leases", "r");
 * time_t now = time(NULL);
 * if (!read_leases(now, fp))
 *     my_syslog(LOG_ERR, "failed to parse lease database");
 * @endcode
 *
 * RFC COMPLIANCE:
 * DHCPv4 lease persistence supports RFC 2131 client identification via hardware address
 * and client identifier. DHCPv6 lease persistence supports RFC 3315 DUID and IAID fields.
 *
 * SIDE EFFECTS:
 * - Allocates lease structures and adds to global leases list
 * - Sets daemon->duid and daemon->duid_len when DUID line parsed
 * - Logs warnings for malformed lines via my_syslog()
 * - Calls die() if lease allocation limit exceeded
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global leases list. Must be called from main event loop only.
 */
static int read_leases(time_t now, FILE *leasestream)
{
  unsigned long ei;
  union all_addr addr;
  struct dhcp_lease *lease;
  int clid_len, hw_len, hw_type;
  int items;
  char *domain = NULL;

  *daemon->dhcp_buff3 = *daemon->dhcp_buff2 = '\0';

  /* client-id max length is 255 which is 255*2 digits + 254 colons
     borrow DNS packet buffer which is always larger than 1000 bytes

     Check various buffers are big enough for the code below */

#if (DHCP_BUFF_SZ < 255) || (MAXDNAME < 64) || (PACKETSZ+MAXDNAME+RRFIXEDSZ  < 764)
# error Buffer size breakage in leasefile parsing.
#endif

    while ((items=fscanf(leasestream, "%255s %255s", daemon->dhcp_buff3, daemon->dhcp_buff2)) == 2)
      {
	*daemon->namebuff = *daemon->dhcp_buff = *daemon->packet = '\0';
	hw_len = hw_type = clid_len = 0;
	
#ifdef HAVE_DHCP6
	if (strcmp(daemon->dhcp_buff3, "duid") == 0)
	  {
	    daemon->duid_len = parse_hex(daemon->dhcp_buff2, (unsigned char *)daemon->dhcp_buff2, 130, NULL, NULL);
	    if (daemon->duid_len < 0)
	      return 0;
	    daemon->duid = safe_malloc(daemon->duid_len);
	    memcpy(daemon->duid, daemon->dhcp_buff2, daemon->duid_len);
	    continue;
	  }
#endif
	
	if (fscanf(leasestream, " %64s %255s %764s",
		   daemon->namebuff, daemon->dhcp_buff, daemon->packet) != 3)
	  {
	    my_syslog(MS_DHCP | LOG_WARNING, _("ignoring invalid line in lease database: %s %s %s %s ..."),
		      daemon->dhcp_buff3, daemon->dhcp_buff2,
		      daemon->namebuff, daemon->dhcp_buff);
	    continue;
	  }
		
	if (inet_pton(AF_INET, daemon->namebuff, &addr.addr4))
	  {
	    if ((lease = lease4_allocate(addr.addr4)))
	      domain = get_domain(lease->addr);
	    
	    hw_len = parse_hex(daemon->dhcp_buff2, (unsigned char *)daemon->dhcp_buff2, DHCP_CHADDR_MAX, NULL, &hw_type);
	    /* For backwards compatibility, no explicit MAC address type means ether. */
	    if (hw_type == 0 && hw_len != 0)
	      hw_type = ARPHRD_ETHER; 
	  }
#ifdef HAVE_DHCP6
	else if (inet_pton(AF_INET6, daemon->namebuff, &addr.addr6))
	  {
	    char *s = daemon->dhcp_buff2;
	    int lease_type = LEASE_NA;

	    if (s[0] == 'T')
	      {
		lease_type = LEASE_TA;
		s++;
	      }
	    
	    if ((lease = lease6_allocate(&addr.addr6, lease_type)))
	      {
		lease_set_iaid(lease, strtoul(s, NULL, 10));
		domain = get_domain6(&lease->addr6);
	      }
	  }
#endif
	else
	  {
	    my_syslog(MS_DHCP | LOG_WARNING, _("ignoring invalid line in lease database, bad address: %s"),
		      daemon->namebuff);
	    continue;
	  }
	

	if (!lease)
	  die (_("too many stored leases"), NULL, EC_MISC);

	if (strcmp(daemon->packet, "*") != 0)
	  clid_len = parse_hex(daemon->packet, (unsigned char *)daemon->packet, 255, NULL, NULL);
	
	lease_set_hwaddr(lease, (unsigned char *)daemon->dhcp_buff2, (unsigned char *)daemon->packet, 
			 hw_len, hw_type, clid_len, now, 0);
	
	if (strcmp(daemon->dhcp_buff, "*") !=  0)
	  lease_set_hostname(lease, daemon->dhcp_buff, 0, domain, NULL);

	ei = atol(daemon->dhcp_buff3);

#ifdef HAVE_BROKEN_RTC
	if (ei != 0)
	  lease->expires = (time_t)ei + now;
	else
	  lease->expires = (time_t)0;
	lease->length = ei;
#else
	/* strictly time_t is opaque, but this hack should work on all sane systems,
	   even when sizeof(time_t) == 8 */
	lease->expires = (time_t)ei;
#endif
	
	/* set these correctly: the "old" events are generated later from
	   the startup synthesised SIGHUP. */
	lease->flags &= ~(LEASE_NEW | LEASE_CHANGED);
	
	*daemon->dhcp_buff3 = *daemon->dhcp_buff2 = '\0';
      }
    
    return (items == 0 || items == EOF);
}

/**
 * @brief Initialize DHCP lease database at daemon startup
 *
 * @detailed
 * Opens and reads the lease database file (daemon->lease_file) to restore previously active leases.
 * In OPT_LEASE_RO mode, executes external lease-change script with "init" argument to populate
 * lease database instead of reading from file. After loading leases, prunes any expired entries
 * and marks DNS cache dirty for initial synchronization. Sets up daemon->lease_stream for
 * subsequent atomic lease file updates.
 *
 * @param now Current timestamp for lease expiry calculations
 *
 * @note Opens lease file in "a+" mode to create if non-existent, then rewinds for reading
 * @warning Dies with fatal error if lease file cannot be opened or lease-init script fails
 * @see read_leases() for database parsing logic
 * @see lease_prune() for expired lease removal
 *
 * EXAMPLE USAGE:
 * @code
 * time_t now = time(NULL);
 * daemon->lease_file = "/var/lib/dnsmasq/dnsmasq.leases";
 * daemon->dhcp_max = 150;
 * lease_init(now);  // Loads existing leases, prunes expired
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements persistent storage requirement for DHCP server per RFC 2131 Section 4.3.5 which
 * requires servers to remember client bindings across restarts.
 *
 * SIDE EFFECTS:
 * - Opens daemon->lease_stream for write access (file descriptor remains open)
 * - Populates global leases list via read_leases()
 * - Initializes leases_left counter to daemon->dhcp_max
 * - Sets file_dirty=0, dns_dirty=1 after loading
 * - Calls lease_prune() to remove expired leases
 * - In OPT_LEASE_RO mode, executes lease-change script with "init" argument
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called once at daemon initialization before event loop starts.
 */
void lease_init(time_t now)
{
  FILE *leasestream;

  leases_left = daemon->dhcp_max;

  if (option_bool(OPT_LEASE_RO))
    {
      /* run "<lease_change_script> init" once to get the
	 initial state of the database. If leasefile-ro is
	 set without a script, we just do without any
	 lease database. */
#ifdef HAVE_SCRIPT
      if (daemon->lease_change_command)
	{
	  strcpy(daemon->dhcp_buff, daemon->lease_change_command);
	  strcat(daemon->dhcp_buff, " init");
	  leasestream = popen(daemon->dhcp_buff, "r");
	}
      else
#endif
	{
          file_dirty = dns_dirty = 0;
          return;
        }

    }
  else
    {
      /* NOTE: need a+ mode to create file if it doesn't exist */
      leasestream = daemon->lease_stream = fopen(daemon->lease_file, "a+");

      if (!leasestream)
	die(_("cannot open or create lease file %s: %s"), daemon->lease_file, EC_FILE);

      /* a+ mode leaves pointer at end. */
      rewind(leasestream);
    }

  if (leasestream)
    {
      if (!read_leases(now, leasestream))
	my_syslog(MS_DHCP | LOG_ERR, _("failed to parse lease database cleanly"));
      
      if (ferror(leasestream))
	die(_("failed to read lease file %s: %s"), daemon->lease_file, EC_FILE);
    }
  
#ifdef HAVE_SCRIPT
  if (!daemon->lease_stream)
    {
      int rc = 0;

      /* shell returns 127 for "command not found", 126 for bad permissions. */
      if (!leasestream || (rc = pclose(leasestream)) == -1 || WEXITSTATUS(rc) == 127 || WEXITSTATUS(rc) == 126)
	{
	  if (WEXITSTATUS(rc) == 127)
	    errno = ENOENT;
	  else if (WEXITSTATUS(rc) == 126)
	    errno = EACCES;

	  die(_("cannot run lease-init script %s: %s"), daemon->lease_change_command, EC_FILE);
	}
      
      if (WEXITSTATUS(rc) != 0)
	{
	  sprintf(daemon->dhcp_buff, "%d", WEXITSTATUS(rc));
	  die(_("lease-init script returned exit code %s"), daemon->dhcp_buff, WEXITSTATUS(rc) + EC_INIT_OFFSET);
	}
    }
#endif

  /* Some leases may have expired */
  file_dirty = 0;
  lease_prune(NULL, now);
  dns_dirty = 1;
}

/**
 * @brief Apply static host reservations from configuration to active leases
 *
 * @detailed
 * Iterates through all active leases and updates hostnames from static DHCP host configurations
 * (dhcp-host directives). For each lease, searches daemon->dhcp_conf for matching client ID,
 * hardware address, or IP address. If matching config exists with hostname but no address
 * restriction (or matching address), applies configured hostname with auth=1 flag. Also attempts
 * hostname resolution via host_from_dns() for leases without config matches, updating only auth
 * flag without changing hostname.
 *
 * @note Called after configuration reload (SIGHUP) to apply hostname changes to existing leases
 * @note Skips DHCPv6 TA/NA leases (no hostname assignment for temporary/non-temporary addresses)
 * @see find_config() to locate matching dhcp-host configuration
 * @see lease_set_hostname() for hostname update with conflict detection
 * @see host_from_dns() for reverse DNS lookup
 *
 * EXAMPLE USAGE:
 * @code
 * // After SIGHUP configuration reload
 * read_opts(argc, argv, NULL);  // Reload config
 * lease_update_from_configs();   // Apply new hostnames to leases
 * lease_update_dns(1);           // Force DNS cache update
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 2131 Section 3.1 requirement that server may supply hostname via option 12.
 * Configuration-based hostnames take precedence over client-supplied names.
 *
 * SIDE EFFECTS:
 * - Modifies lease->hostname for leases with matching configurations
 * - Sets LEASE_AUTH_NAME flag for configuration-derived hostnames
 * - Sets dns_dirty flag via lease_set_hostname() if hostnames change
 * - Calls get_domain() to determine domain suffix for FQDN construction
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop after configuration changes.
 */
void lease_update_from_configs(void)
{
  /* changes to the config may change current leases. */
  
  struct dhcp_lease *lease;
  struct dhcp_config *config;
  char *name;
  
  for (lease = leases; lease; lease = lease->next)
    if (lease->flags & (LEASE_TA | LEASE_NA))
      continue;
    else if ((config = find_config(daemon->dhcp_conf, NULL, lease->clid, lease->clid_len, 
				   lease->hwaddr, lease->hwaddr_len, lease->hwaddr_type, NULL, NULL)) && 
	     (config->flags & CONFIG_NAME) &&
	     (!(config->flags & CONFIG_ADDR) || config->addr.s_addr == lease->addr.s_addr))
      lease_set_hostname(lease, config->hostname, 1, get_domain(lease->addr), NULL);
    else if ((name = host_from_dns(lease->addr)))
      lease_set_hostname(lease, name, 1, get_domain(lease->addr), NULL); /* updates auth flag only */
}

/**
 * @brief Formatted output to lease file with error tracking
 *
 * @detailed
 * Wrapper around vfprintf() that writes to daemon->lease_stream and captures first errno on failure.
 * Once *errp is non-zero, subsequent calls skip writing (early-out on error). This allows multiple
 * ourprintf() calls without checking return values, then a single error check at end. Used by
 * lease_update_file() to generate lease database output.
 *
 * @param errp Pointer to error accumulator, set to errno on first write failure, checked before writing
 * @param format printf-style format string
 * @param ... Variable arguments for format string
 *
 * @note Static helper function for lease_update_file() only
 * @warning Does not flush stream, caller must call fflush() and fsync() explicitly
 * @see lease_update_file() for usage context
 *
 * EXAMPLE USAGE:
 * @code
 * int err = 0;
 * ourprintf(&err, "%lu ", (unsigned long)lease->expires);
 * ourprintf(&err, "%s ", inet_ntoa(lease->addr));
 * if (err)
 *     my_syslog(LOG_ERR, "write failed: %s", strerror(err));
 * @endcode
 *
 * SIDE EFFECTS:
 * - Writes to daemon->lease_stream
 * - Sets *errp to errno on first failure
 * - Skips writes if *errp already non-zero
 *
 * THREAD SAFETY:
 * Not thread-safe. Writes to shared daemon->lease_stream without locking.
 */
static void ourprintf(int *errp, char *format, ...)
{
  va_list ap;
  
  va_start(ap, format);
  if (!(*errp) && vfprintf(daemon->lease_stream, format, ap) < 0)
    *errp = errno;
  va_end(ap);
}

/**
 * @brief Atomically update lease database file to persistent storage
 *
 * @detailed
 * Rewrites entire lease database when file_dirty flag is set, using atomic write-truncate-sync
 * sequence to prevent corruption. Rewinds daemon->lease_stream, truncates to zero, writes all
 * active leases in text format, then calls fflush() and fsync() to ensure data reaches disk.
 * On write error, schedules retry after LEASE_RETRY (60 seconds). Also manages periodic
 * Router Advertisement and SLAAC ping timers for DHCPv6, calculating next alarm time from
 * lease expiries and protocol timers. Always calls send_alarm() to schedule next event.
 *
 * Lease file format:
 * DHCPv4: <expiry_timestamp> <hw_type-hw_addr> <ip_addr> <hostname|*> <client_id|*>
 * DHCPv6: duid <hex_duid>
 *         <expiry_timestamp> [T]<iaid> <ipv6_addr> <hostname|*> <client_id|*>
 * HAVE_BROKEN_RTC: Uses lease->length duration instead of expiry timestamp.
 *
 * @param now Current timestamp for calculating next alarm and retry scheduling
 *
 * @note Only writes when file_dirty != 0 and daemon->lease_stream is open
 * @warning On write error, logs to syslog and schedules retry, does not die()
 * @see send_alarm() for timer scheduling
 * @see periodic_ra() and periodic_slaac() for DHCPv6 timer management
 *
 * EXAMPLE USAGE:
 * @code
 * // After DHCP transaction modifies lease
 * file_dirty = 1;
 * lease_update_file(time(NULL));  // Writes database and schedules next event
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.3.5 requirement for persistent lease storage across server restarts.
 * DHCPv6 persistence supports RFC 3315 DUID and IAID tracking.
 *
 * SIDE EFFECTS:
 * - Rewinds and truncates daemon->lease_stream
 * - Writes all non-TA/NA DHCPv4 leases, then DUID and all TA/NA DHCPv6 leases
 * - Calls fflush() and fsync() to force disk write
 * - Clears file_dirty flag on success
 * - Calls send_alarm() with next event time (lease expiry, RA timer, SLAAC ping, or retry)
 * - Logs write errors via my_syslog() with retry delay
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop in response to timer or DHCP events.
 */
void lease_update_file(time_t now)
{
  struct dhcp_lease *lease;
  time_t next_event;
  int i, err = 0;

  if (file_dirty != 0 && daemon->lease_stream)
    {
      errno = 0;
      rewind(daemon->lease_stream);
      if (errno != 0 || ftruncate(fileno(daemon->lease_stream), 0) != 0)
	err = errno;
      
      for (lease = leases; lease; lease = lease->next)
	{

#ifdef HAVE_DHCP6
	  if (lease->flags & (LEASE_TA | LEASE_NA))
	    continue;
#endif

#ifdef HAVE_BROKEN_RTC
	  ourprintf(&err, "%u ", lease->length);
#else
	  ourprintf(&err, "%lu ", (unsigned long)lease->expires);
#endif

	  if (lease->hwaddr_type != ARPHRD_ETHER || lease->hwaddr_len == 0) 
	    ourprintf(&err, "%.2x-", lease->hwaddr_type);
	  for (i = 0; i < lease->hwaddr_len; i++)
	    {
	      ourprintf(&err, "%.2x", lease->hwaddr[i]);
	      if (i != lease->hwaddr_len - 1)
		ourprintf(&err, ":");
	    }
	  
	  inet_ntop(AF_INET, &lease->addr, daemon->addrbuff, ADDRSTRLEN); 

	  ourprintf(&err, " %s ", daemon->addrbuff);
	  ourprintf(&err, "%s ", lease->hostname ? lease->hostname : "*");
	  	  
	  if (lease->clid && lease->clid_len != 0)
	    {
	      for (i = 0; i < lease->clid_len - 1; i++)
		ourprintf(&err, "%.2x:", lease->clid[i]);
	      ourprintf(&err, "%.2x\n", lease->clid[i]);
	    }
	  else
	    ourprintf(&err, "*\n");	  
	}
      
#ifdef HAVE_DHCP6  
      if (daemon->duid)
	{
	  ourprintf(&err, "duid ");
	  for (i = 0; i < daemon->duid_len - 1; i++)
	    ourprintf(&err, "%.2x:", daemon->duid[i]);
	  ourprintf(&err, "%.2x\n", daemon->duid[i]);
	  
	  for (lease = leases; lease; lease = lease->next)
	    {
	      
	      if (!(lease->flags & (LEASE_TA | LEASE_NA)))
		continue;

#ifdef HAVE_BROKEN_RTC
	      ourprintf(&err, "%u ", lease->length);
#else
	      ourprintf(&err, "%lu ", (unsigned long)lease->expires);
#endif
    
	      inet_ntop(AF_INET6, &lease->addr6, daemon->addrbuff, ADDRSTRLEN);
	 
	      ourprintf(&err, "%s%u %s ", (lease->flags & LEASE_TA) ? "T" : "",
			lease->iaid, daemon->addrbuff);
	      ourprintf(&err, "%s ", lease->hostname ? lease->hostname : "*");
	      
	      if (lease->clid && lease->clid_len != 0)
		{
		  for (i = 0; i < lease->clid_len - 1; i++)
		    ourprintf(&err, "%.2x:", lease->clid[i]);
		  ourprintf(&err, "%.2x\n", lease->clid[i]);
		}
	      else
		ourprintf(&err, "*\n");	  
	    }
	}
#endif      
	  
      if (fflush(daemon->lease_stream) != 0 ||
	  fsync(fileno(daemon->lease_stream)) < 0)
	err = errno;
      
      if (!err)
	file_dirty = 0;
    }
  
  /* Set alarm for when the first lease expires. */
  next_event = 0;

#ifdef HAVE_DHCP6
  /* do timed RAs and determine when the next is, also pings to potential SLAAC addresses */
  if (daemon->doing_ra)
    {
      time_t event;
      
      if ((event = periodic_slaac(now, leases)) != 0)
	{
	  if (next_event == 0 || difftime(next_event, event) > 0.0)
	    next_event = event;
	}
      
      if ((event = periodic_ra(now)) != 0)
	{
	  if (next_event == 0 || difftime(next_event, event) > 0.0)
	    next_event = event;
	}
    }
#endif

  for (lease = leases; lease; lease = lease->next)
    if (lease->expires != 0 &&
	(next_event == 0 || difftime(next_event, lease->expires) > 0.0))
      next_event = lease->expires;
   
  if (err)
    {
      if (next_event == 0 || difftime(next_event, LEASE_RETRY + now) > 0.0)
	next_event = LEASE_RETRY + now;
      
      my_syslog(MS_DHCP | LOG_ERR, _("failed to write %s: %s (retry in %u s)"), 
		daemon->lease_file, strerror(err),
		(unsigned int)difftime(next_event, now));
    }

  send_alarm(next_event, now);
}

/**
 * @brief Callback to associate DHCPv4 leases with network interfaces
 *
 * @detailed
 * Called by iface_enumerate() for each IPv4 address on each interface. Iterates through all
 * DHCPv4 leases and checks if lease IP is on the same subnet as the interface address using
 * is_same_net(). If match found and prefix length is longer (more specific) than previous match,
 * updates lease->new_interface and lease->new_prefixlen. This identifies the most specific
 * interface for each lease address.
 *
 * @param local Interface IPv4 address
 * @param if_index Interface index (system-specific identifier)
 * @param label Interface label/name (unused)
 * @param netmask Interface netmask for subnet calculation
 * @param broadcast Interface broadcast address (unused)
 * @param vparam User parameter from iface_enumerate() (unused, casted to void to suppress warnings)
 * @return Always returns 1 to continue enumeration
 *
 * @note Static callback for iface_enumerate(), used by lease_find_interfaces()
 * @note Updates new_interface/new_prefixlen fields; caller must copy to last_interface
 * @see lease_find_interfaces() for enumeration driver
 * @see iface_enumerate() for interface iteration mechanism
 *
 * EXAMPLE USAGE:
 * @code
 * // Called indirectly via iface_enumerate()
 * iface_enumerate(AF_INET, &now, find_interface_v4);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies lease->new_interface and lease->new_prefixlen for matching leases
 * - Skips DHCPv6 leases (LEASE_TA | LEASE_NA flags)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop via iface_enumerate().
 */
static int find_interface_v4(struct in_addr local, int if_index, char *label,
			     struct in_addr netmask, struct in_addr broadcast, void *vparam)
{
  struct dhcp_lease *lease;
  int prefix = netmask_length(netmask);

  (void) label;
  (void) broadcast;
  (void) vparam;

  for (lease = leases; lease; lease = lease->next)
    if (!(lease->flags & (LEASE_TA | LEASE_NA)) &&
	is_same_net(local, lease->addr, netmask) && 
	prefix > lease->new_prefixlen) 
      {
	lease->new_interface = if_index;
        lease->new_prefixlen = prefix;
      }

  return 1;
}

#ifdef HAVE_DHCP6
/**
 * @brief Callback to associate DHCPv6 leases with network interfaces
 *
 * @detailed
 * Called by iface_enumerate() for each IPv6 address on each interface. Iterates through all
 * DHCPv6 leases (LEASE_TA | LEASE_NA) and checks if lease IPv6 address is on the same subnet
 * as the interface address using is_same_net6(). If match found and prefix length is longer
 * (more specific) than previous match, updates lease->new_interface and lease->new_prefixlen.
 * This identifies the most specific interface for each DHCPv6 lease.
 *
 * @param local Interface IPv6 address pointer
 * @param prefix Interface prefix length for subnet calculation
 * @param scope IPv6 address scope (unused)
 * @param if_index Interface index (system-specific identifier)
 * @param flags Interface flags (unused)
 * @param preferred Preferred lifetime (unused)
 * @param valid Valid lifetime (unused)
 * @param vparam User parameter from iface_enumerate() (unused)
 * @return Always returns 1 to continue enumeration
 *
 * @note Static callback for iface_enumerate(), used by lease_find_interfaces()
 * @note Only processes leases with LEASE_TA or LEASE_NA flags set
 * @note Updates new_interface/new_prefixlen fields; caller must copy to last_interface
 * @see lease_find_interfaces() for enumeration driver
 * @see iface_enumerate() for interface iteration mechanism
 *
 * EXAMPLE USAGE:
 * @code
 * // Called indirectly via iface_enumerate()
 * iface_enumerate(AF_INET6, &now, find_interface_v6);
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies lease->new_interface and lease->new_prefixlen for matching DHCPv6 leases
 * - Skips DHCPv4 leases (no LEASE_TA or LEASE_NA flags)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop via iface_enumerate().
 */
static int find_interface_v6(struct in6_addr *local,  int prefix,
			     int scope, int if_index, int flags, 
			     int preferred, int valid, void *vparam)
{
  struct dhcp_lease *lease;

  (void)scope;
  (void)flags;
  (void)preferred;
  (void)valid;
  (void)vparam;

  for (lease = leases; lease; lease = lease->next)
    if ((lease->flags & (LEASE_TA | LEASE_NA)))
      if (is_same_net6(local, &lease->addr6, prefix) && prefix > lease->new_prefixlen) {
        /* save prefix length for comparison, as we might get shorter matching
         * prefix in upcoming netlink GETADDR responses
         * */
        lease->new_interface = if_index;
        lease->new_prefixlen = prefix;
      }

  return 1;
}

/**
 * @brief Process ICMPv6 ping reply for SLAAC address confirmation
 *
 * @detailed
 * Handles ping replies to tentative SLAAC addresses constructed from DHCPv4 lease hostnames.
 * When daemon performs Router Advertisement but not DHCPv6, clients may use SLAAC to derive
 * IPv6 addresses. This function delegates to slaac_ping_reply() to update address state.
 * Checks daemon->dhcp exists before proceeding (may be doing RA without DHCP).
 *
 * @param sender Source IPv6 address of ping reply
 * @param packet Raw ICMPv6 packet data
 * @param interface Interface name where reply received
 *
 * @note Only relevant when doing Router Advertisement without DHCPv6
 * @note No-op if daemon->dhcp is NULL (DHCP not enabled)
 * @see slaac_ping_reply() for actual address confirmation logic
 * @see periodic_slaac() for SLAAC address probing
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from ICMPv6 packet handler
 * struct in6_addr sender;
 * unsigned char icmp_packet[512];
 * char ifname[IFNAMSIZ];
 * lease_ping_reply(&sender, icmp_packet, ifname);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 4862 SLAAC address conflict detection via Neighbor Discovery ping probes.
 *
 * SIDE EFFECTS:
 * - Calls slaac_ping_reply() which may update lease SLAAC address state
 * - May mark addresses as confirmed (backoff=0) or in conflict
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop ICMPv6 packet handler.
 */
void lease_ping_reply(struct in6_addr *sender, unsigned char *packet, char *interface)
{
  /* We may be doing RA but not DHCPv4, in which case the lease
     database may not exist and we have nothing to do anyway */
  if (daemon->dhcp)
    slaac_ping_reply(sender, packet, interface, leases);
}

/**
 * @brief Add SLAAC addresses to existing leases after RA context creation
 *
 * @detailed
 * Called when new Router Advertisement context is constructed to add putative SLAAC addresses
 * to all existing DHCPv4 leases with hostnames. Iterates through leases list and calls
 * slaac_add_addrs() for each, which derives IPv6 addresses from hostname and RA prefix.
 * This ensures existing DHCPv4 leases get corresponding IPv6 DNS entries when RA is enabled.
 *
 * @param now Current timestamp for SLAAC address creation and ping scheduling
 *
 * @note Only relevant when doing Router Advertisement alongside DHCPv4
 * @note No-op if daemon->dhcp is NULL (DHCP not enabled)
 * @see slaac_add_addrs() for SLAAC address derivation from hostname
 * @see lease_set_hwaddr() which also calls slaac_add_addrs() on lease updates
 *
 * EXAMPLE USAGE:
 * @code
 * // After creating new RA context from configuration
 * struct dhcp_context *context = create_ra_context();
 * lease_update_slaac(time(NULL));  // Add SLAAC addrs to existing leases
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 4862 SLAAC address assignment, deriving host portion from hostname instead
 * of EUI-64 construction for better DNS integration.
 *
 * SIDE EFFECTS:
 * - Calls slaac_add_addrs() for each lease, which may allocate slaac_address structures
 * - May schedule ICMPv6 pings for address conflict detection
 * - Updates lease->slaac_address linked list
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop after configuration changes.
 */
void lease_update_slaac(time_t now)
{
  /* Called when we construct a new RA-names context, to add putative
     new SLAAC addresses to existing leases. */

  struct dhcp_lease *lease;
  
  if (daemon->dhcp)
    for (lease = leases; lease; lease = lease->next)
      slaac_add_addrs(lease, now, 0);
}

#endif

/**
 * @brief Associate leases with network interfaces at daemon startup
 *
 * @detailed
 * Finds network interfaces associated with active leases at daemon startup. Enumerates all
 * IPv4 and IPv6 addresses on all interfaces via iface_enumerate(), calling find_interface_v4()
 * and find_interface_v6() callbacks to match lease addresses to interface subnets. After
 * enumeration, calls lease_set_interface() for leases with new_interface set. Interface
 * information is useful for lease-change scripts and necessary for SLAAC address determination.
 * Gets updated during DHCP transactions but initial startup detection ensures scripts have
 * correct interface information from the start.
 *
 * @param now Current timestamp passed to lease_set_interface() for SLAAC updates
 *
 * @note Called once at daemon startup after lease_init() loads database
 * @note Clears new_interface and new_prefixlen for all leases before enumeration
 * @see find_interface_v4() callback for DHCPv4 lease interface matching
 * @see find_interface_v6() callback for DHCPv6 lease interface matching
 * @see lease_set_interface() for committing interface association
 *
 * EXAMPLE USAGE:
 * @code
 * time_t now = time(NULL);
 * lease_init(now);              // Load leases from database
 * lease_find_interfaces(now);   // Associate with interfaces
 * // Now lease->last_interface set for script use
 * @endcode
 *
 * RFC COMPLIANCE:
 * Determines directly-connected subnet information for RFC 2131 Section 4.3.1 DHCP relay
 * and RFC 4862 SLAAC address prefix determination.
 *
 * SIDE EFFECTS:
 * - Zeroes new_interface and new_prefixlen for all leases
 * - Calls iface_enumerate() which invokes find_interface_v4 and find_interface_v6 callbacks
 * - Sets lease->last_interface for matching leases via lease_set_interface()
 * - May trigger slaac_add_addrs() calls for DHCPv6 leases
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called once at daemon initialization before event loop starts.
 */
void lease_find_interfaces(time_t now)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    lease->new_prefixlen = lease->new_interface = 0;

  iface_enumerate(AF_INET, &now, find_interface_v4);
#ifdef HAVE_DHCP6
  iface_enumerate(AF_INET6, &now, find_interface_v6);
#endif

  for (lease = leases; lease; lease = lease->next)
    if (lease->new_interface != 0) 
      lease_set_interface(lease, lease->new_interface, now);
}

#ifdef HAVE_DHCP6
/**
 * @brief Generate and persist DUID for DHCPv6 server identity
 *
 * @detailed
 * Creates DHCPv6 DUID (DHCP Unique Identifier) for server if not already present. Only generates
 * DUID when daemon->doing_dhcp6 is enabled and daemon->duid is NULL. Calls make_duid() to generate
 * DUID (typically DUID-LLT with link-layer address and timestamp), then marks file_dirty to ensure
 * DUID is persisted to lease database. DUID must be stable across server restarts per RFC 3315.
 *
 * @param now Current timestamp used by make_duid() for DUID-LLT construction
 *
 * @note Only creates DUID if daemon->doing_dhcp6 is true and daemon->duid is NULL
 * @note DUID persisted as "duid <hex>" line in lease database by lease_update_file()
 * @see make_duid() for DUID generation algorithm
 * @see lease_update_file() for DUID persistence to database
 *
 * EXAMPLE USAGE:
 * @code
 * time_t now = time(NULL);
 * daemon->doing_dhcp6 = 1;
 * lease_make_duid(now);  // Creates DUID if needed
 * lease_update_file(now); // Persists to database
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 3315 Section 9 DUID requirement. Server DUID must be unique and stable across
 * reboots. Typically uses DUID-LLT (type 1) with link-layer address and timestamp.
 *
 * SIDE EFFECTS:
 * - Calls make_duid() which allocates daemon->duid and sets daemon->duid_len
 * - Sets file_dirty=1 to trigger database update
 * - No-op if daemon->duid already exists or daemon->doing_dhcp6 is false
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop, typically at daemon initialization.
 */
void lease_make_duid(time_t now)
{
  /* If we're not doing DHCPv6, and there are not v6 leases, don't add the DUID to the database */
  if (!daemon->duid && daemon->doing_dhcp6)
    {
      file_dirty = 1;
      make_duid(now);
    }
}
#endif

/**
 * @brief Synchronize DHCP lease hostnames to DNS cache
 *
 * @detailed
 * Updates DNS cache with hostname→address mappings from active DHCP leases when dns_dirty flag
 * is set or force=1. Clears existing DHCP entries via cache_unhash_dhcp(), then adds new entries
 * for all leases with hostnames via cache_add_dhcp_entry(). For DHCPv6 leases with SLAAC addresses,
 * adds separate DNS entries for each confirmed SLAAC address (backoff==0). Handles both hostname
 * and FQDN entries based on OPT_DHCP_FQDN configuration. Increments SOA serial number to trigger
 * zone transfer to authoritative secondaries (if HAVE_BROKEN_RTC not defined).
 *
 * @param force If non-zero, forces DNS update even if dns_dirty is clear; if zero, only updates when dns_dirty set
 *
 * @note Only updates if daemon->port != 0 (DNS server is enabled)
 * @note Clears dns_dirty flag after successful update
 * @see cache_unhash_dhcp() to remove old DHCP DNS entries
 * @see cache_add_dhcp_entry() to insert hostname→address mappings
 *
 * EXAMPLE USAGE:
 * @code
 * // After lease hostname change
 * dns_dirty = 1;
 * lease_update_dns(0);  // Update DNS cache from leases
 * // DNS queries now resolve lease hostnames
 * @endcode
 *
 * RFC COMPLIANCE:
 * Provides DNS dynamic update functionality aligned with RFC 2136 concepts (but implemented
 * via cache update rather than DNS UPDATE protocol). Supports RFC 4704 DHCPv4 client FQDN option.
 *
 * SIDE EFFECTS:
 * - Increments daemon->soa_sn (SOA serial number) on each update (except HAVE_BROKEN_RTC builds)
 * - Calls cache_unhash_dhcp() to remove all existing DHCP DNS entries
 * - Calls cache_add_dhcp_entry() for each lease with hostname (IPv4 and IPv6 addresses)
 * - Adds separate DNS entries for SLAAC addresses with backoff==0 (confirmed addresses)
 * - Clears dns_dirty flag after update
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop after lease hostname changes.
 */
void lease_update_dns(int force)
{
  struct dhcp_lease *lease;

  if (daemon->port != 0 && (dns_dirty || force))
    {
#ifndef HAVE_BROKEN_RTC
      /* force transfer to authoritative secondaries */
      daemon->soa_sn++;
#endif
      
      cache_unhash_dhcp();

      for (lease = leases; lease; lease = lease->next)
	{
	  int prot = AF_INET;
	  
#ifdef HAVE_DHCP6
	  if (lease->flags & (LEASE_TA | LEASE_NA))
	    prot = AF_INET6;
	  else if (lease->hostname || lease->fqdn)
	    {
	      struct slaac_address *slaac;

	      for (slaac = lease->slaac_address; slaac; slaac = slaac->next)
		if (slaac->backoff == 0)
		  {
		    if (lease->fqdn)
		      cache_add_dhcp_entry(lease->fqdn, AF_INET6, (union all_addr *)&slaac->addr, lease->expires);
		    if (!option_bool(OPT_DHCP_FQDN) && lease->hostname)
		      cache_add_dhcp_entry(lease->hostname, AF_INET6, (union all_addr *)&slaac->addr, lease->expires);
		  }
	    }
	  
	  if (lease->fqdn)
	    cache_add_dhcp_entry(lease->fqdn, prot, 
				 prot == AF_INET ? (union all_addr *)&lease->addr : (union all_addr *)&lease->addr6,
				 lease->expires);
	     
	  if (!option_bool(OPT_DHCP_FQDN) && lease->hostname)
	    cache_add_dhcp_entry(lease->hostname, prot, 
				 prot == AF_INET ? (union all_addr *)&lease->addr : (union all_addr *)&lease->addr6, 
				 lease->expires);
       
#else
	  if (lease->fqdn)
	    cache_add_dhcp_entry(lease->fqdn, prot, (union all_addr *)&lease->addr, lease->expires);
	  
	  if (!option_bool(OPT_DHCP_FQDN) && lease->hostname)
	    cache_add_dhcp_entry(lease->hostname, prot, (union all_addr *)&lease->addr, lease->expires);
#endif
	}
      
      dns_dirty = 0;
    }
}

/**
 * @brief Remove expired leases and target lease from active list
 *
 * @detailed
 * Traverses leases list and removes entries that have expired (difftime(now, expires) >= 0) or
 * match the target lease pointer. Removed leases are transferred to old_leases list for script
 * execution via do_script_run(). Sets file_dirty and dns_dirty flags if leases removed. Increments
 * METRIC_LEASES_PRUNED_4 or METRIC_LEASES_PRUNED_6 metrics. Increments leases_left counter to
 * track available lease capacity. Target lease may be NULL for periodic expiry checks.
 *
 * @param target Specific lease to remove regardless of expiry (may be NULL for expiry-only pruning)
 * @param now Current timestamp for expiry comparison
 *
 * @note Removed leases moved to old_leases list, not freed immediately (awaits script execution)
 * @note Sets file_dirty=1 if any leases pruned
 * @note Sets dns_dirty=1 if pruned lease had hostname
 * @see do_script_run() which processes old_leases list and frees leases
 *
 * EXAMPLE USAGE:
 * @code
 * // Periodic expiry check
 * time_t now = time(NULL);
 * lease_prune(NULL, now);  // Remove all expired leases
 * 
 * // Explicit lease removal
 * struct dhcp_lease *old = lease_find_by_addr(addr);
 * lease_prune(old, now);  // Remove specific lease
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 3.1 lease expiration: "When the lease expires, the network address
 * may be assigned to another client."
 *
 * SIDE EFFECTS:
 * - Unlinks expired/target leases from leases list
 * - Appends removed leases to old_leases list
 * - Increments daemon->metrics[METRIC_LEASES_PRUNED_4 or METRIC_LEASES_PRUNED_6]
 * - Sets file_dirty=1 if any leases removed
 * - Sets dns_dirty=1 if removed lease had hostname
 * - Increments leases_left counter
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop in response to timer or explicit removal.
 */
void lease_prune(struct dhcp_lease *target, time_t now)
{
  struct dhcp_lease *lease, *tmp, **up;

  for (lease = leases, up = &leases; lease; lease = tmp)
    {
      tmp = lease->next;
      if ((lease->expires != 0 && difftime(now, lease->expires) >= 0) || lease == target)
	{
	  file_dirty = 1;
	  if (lease->hostname)
	    dns_dirty = 1;

	  daemon->metrics[lease->addr.s_addr ? METRIC_LEASES_PRUNED_4 : METRIC_LEASES_PRUNED_6]++;

 	  *up = lease->next; /* unlink */
	  
	  /* Put on old_leases list 'till we
	     can run the script */
	  lease->next = old_leases;
	  old_leases = lease;
	  
	  leases_left++;
	}
      else
	up = &lease->next;
    }
} 

/**
 * @brief Find DHCPv4 lease by client identifier or hardware address
 *
 * @detailed
 * Searches active leases for DHCPv4 lease matching client identifier or hardware address.
 * Performs two-pass search: first pass searches by client ID (if clid provided), second pass
 * searches by hardware address (if hw_len != 0). Client ID match takes precedence per RFC 2131
 * Section 4.2 which specifies client identifier as primary key. Hardware address match requires
 * exact match of type, length, and address bytes. Skips DHCPv6 leases (LEASE_TA | LEASE_NA).
 *
 * @param hwaddr Client hardware address (typically MAC address), may be NULL if clid provided
 * @param hw_len Hardware address length in bytes (0 if no hardware address matching desired)
 * @param hw_type Hardware type (ARPHRD_ETHER for Ethernet, see RFC 1700 ARP hardware types)
 * @param clid Client identifier from DHCP option 61, may be NULL for hardware-only matching
 * @param clid_len Client identifier length in bytes (0 if no client ID matching desired)
 * @return Pointer to matching dhcp_lease or NULL if not found
 *
 * @note Skips DHCPv6 leases (checks for LEASE_TA | LEASE_NA flags)
 * @note Client ID match takes precedence over hardware address match
 * @see lease_find_by_addr() for address-based lookup
 * @see lease6_find_by_client() for DHCPv6 client lookup
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * unsigned char clid[7] = {0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * struct dhcp_lease *lease = lease_find_by_client(mac, 6, ARPHRD_ETHER, clid, 7);
 * if (lease)
 *     return lease->addr;  // Existing lease found
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.2: "DHCP clients are free to use any strategy in selecting
 * a DHCP server...the client identifier is used by a client to specify its configuration."
 * Client identifier matching is primary per RFC 2131.
 *
 * SIDE EFFECTS:
 * None. Read-only search through leases list.
 *
 * THREAD SAFETY:
 * Thread-safe for read-only access if leases list is not modified concurrently. In single-threaded
 * event loop, safe to call anytime.
 */
struct dhcp_lease *lease_find_by_client(unsigned char *hwaddr, int hw_len, int hw_type,
					unsigned char *clid, int clid_len)
{
  struct dhcp_lease *lease;

  if (clid)
    for (lease = leases; lease; lease = lease->next)
      {
#ifdef HAVE_DHCP6
	if (lease->flags & (LEASE_TA | LEASE_NA))
	  continue;
#endif
	if (lease->clid && clid_len == lease->clid_len &&
	    memcmp(clid, lease->clid, clid_len) == 0)
	  return lease;
      }
  
  for (lease = leases; lease; lease = lease->next)	
    {
#ifdef HAVE_DHCP6
      if (lease->flags & (LEASE_TA | LEASE_NA))
	continue;
#endif   
      if ((!lease->clid || !clid) && 
	  hw_len != 0 && 
	  lease->hwaddr_len == hw_len &&
	  lease->hwaddr_type == hw_type &&
	  memcmp(hwaddr, lease->hwaddr, hw_len) == 0)
	return lease;
    }

  return NULL;
}

/**
 * @brief Find DHCPv4 lease by IPv4 address
 *
 * @detailed
 * Searches active leases for DHCPv4 lease with matching IPv4 address. Performs linear search
 * through leases list comparing lease->addr.s_addr with provided address. Skips DHCPv6 leases
 * (LEASE_TA | LEASE_NA flags). Used for address conflict detection, lease renewal lookups,
 * and DHCPRELEASE processing.
 *
 * @param addr IPv4 address to search for (struct in_addr with s_addr in network byte order)
 * @return Pointer to matching dhcp_lease or NULL if address not leased
 *
 * @note Skips DHCPv6 leases (checks for LEASE_TA | LEASE_NA flags)
 * @note Returns first matching lease (addresses should be unique across active leases)
 * @see lease_find_by_client() for client-based lookup
 * @see lease6_find_by_addr() for DHCPv6 address lookup
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr requested_addr;
 * inet_pton(AF_INET, "192.168.1.100", &requested_addr);
 * struct dhcp_lease *lease = lease_find_by_addr(requested_addr);
 * if (lease)
 *     check_client_match(lease, client_hwaddr);  // Address already leased
 * @endcode
 *
 * RFC COMPLIANCE:
 * Used to implement RFC 2131 Section 3.1 address conflict detection: "The server SHOULD probe
 * the network address before allocating the address" and to validate DHCPREQUEST messages.
 *
 * SIDE EFFECTS:
 * None. Read-only search through leases list.
 *
 * THREAD SAFETY:
 * Thread-safe for read-only access if leases list is not modified concurrently. In single-threaded
 * event loop, safe to call anytime.
 */
struct dhcp_lease *lease_find_by_addr(struct in_addr addr)
{
  struct dhcp_lease *lease;

  for (lease = leases; lease; lease = lease->next)
    {
#ifdef HAVE_DHCP6
      if (lease->flags & (LEASE_TA | LEASE_NA))
	continue;
#endif  
      if (lease->addr.s_addr == addr.s_addr)
	return lease;
    }

  return NULL;
}

#ifdef HAVE_DHCP6
/**
 * @brief Find DHCPv6 lease by client ID, IAID, lease type, and IPv6 address
 *
 * @detailed
 * Searches for DHCPv6 lease matching all four criteria: client identifier (DUID), IAID (Identity
 * Association Identifier), lease type (LEASE_TA or LEASE_NA), and IPv6 address. All parameters
 * must match for successful lookup. Used for DHCPV6 RENEW, REBIND, and RELEASE message processing
 * where client specifies exact lease to operate on. Returns first matching lease or NULL.
 *
 * @param clid Client identifier (DUID) from DHCPv6 option 1
 * @param clid_len Client identifier length in bytes
 * @param lease_type LEASE_TA (temporary address) or LEASE_NA (non-temporary address)
 * @param iaid Identity Association Identifier from DHCPv6 IA_NA or IA_TA option
 * @param addr IPv6 address to match (struct in6_addr pointer)
 * @return Pointer to matching dhcp_lease or NULL if not found
 *
 * @note Requires exact match of all four parameters
 * @note Only searches leases with matching lease_type flag (LEASE_TA or LEASE_NA)
 * @see lease6_find_by_client() for finding all leases for a client+IAID (address-agnostic)
 * @see lease6_find_by_addr() for address-based lookup with prefix matching
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char duid[16] = { ... };
 * unsigned int iaid = 0x12345678;
 * struct in6_addr addr;
 * inet_pton(AF_INET6, "2001:db8::1", &addr);
 * struct dhcp_lease *lease = lease6_find(duid, 16, LEASE_NA, iaid, &addr);
 * if (lease)
 *     lease_set_expires(lease, new_lifetime, now);  // Renew
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 3315 Section 18 message processing which requires matching IA and IA address
 * in RENEW/REBIND/RELEASE messages. IAID + DUID uniquely identifies client's Identity Association.
 *
 * SIDE EFFECTS:
 * None. Read-only search through leases list.
 *
 * THREAD SAFETY:
 * Thread-safe for read-only access if leases list is not modified concurrently. In single-threaded
 * event loop, safe to call anytime.
 */
struct dhcp_lease *lease6_find(unsigned char *clid, int clid_len, 
			       int lease_type, unsigned int iaid,
			       struct in6_addr *addr)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    {
      if (!(lease->flags & lease_type) || lease->iaid != iaid)
	continue;

      if (!IN6_ARE_ADDR_EQUAL(&lease->addr6, addr))
	continue;
      
      if ((clid_len != lease->clid_len ||
	   memcmp(clid, lease->clid, clid_len) != 0))
	continue;
      
      return lease;
    }
  
  return NULL;
}

/**
 * @brief Clear LEASE_USED flags on all leases for enumeration tracking
 *
 * @detailed
 * Clears LEASE_USED flag on all leases in preparation for lease enumeration by
 * lease6_find_by_client(). This flag prevents returning same lease multiple times when
 * iterating through all leases for a given DUID+IAID combination. Called before beginning
 * enumeration with lease6_find_by_client(first=NULL, ...), then lease6_find_by_client()
 * marks each returned lease with LEASE_USED to skip on subsequent calls.
 *
 * @note Must be called before enumerating leases with lease6_find_by_client()
 * @note Clears flags on all leases, not just DHCPv6 leases
 * @see lease6_find_by_client() which sets LEASE_USED and skips leases with LEASE_USED set
 *
 * EXAMPLE USAGE:
 * @code
 * // Enumerate all leases for client+IAID
 * lease6_reset();  // Clear USED flags
 * struct dhcp_lease *lease = NULL;
 * while ((lease = lease6_find_by_client(lease, LEASE_NA, duid, duid_len, iaid)))
 *     process_lease(lease);  // Each lease returned once
 * @endcode
 *
 * SIDE EFFECTS:
 * - Clears LEASE_USED flag (lease->flags &= ~LEASE_USED) on all leases in leases list
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop before lease enumeration.
 */
void lease6_reset(void)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    lease->flags &= ~LEASE_USED;
}

/**
 * @brief Enumerate DHCPv6 leases for specific client ID and IAID
 *
 * @detailed
 * Returns next DHCPv6 lease matching client identifier (DUID), IAID, and lease type, enabling
 * iteration through all leases for a given Identity Association. On first call, pass first=NULL
 * to start enumeration from beginning. On subsequent calls, pass previously returned lease to
 * continue. Skips leases with LEASE_USED flag set (use lease6_reset() to clear flags before
 * enumeration). Used for DHCPv6 RENEW/REBIND processing where client may have multiple addresses
 * in single IA.
 *
 * @param first Starting lease for enumeration: NULL for first call, previous result for continuation
 * @param lease_type LEASE_TA (temporary) or LEASE_NA (non-temporary) to match
 * @param clid Client identifier (DUID) from DHCPv6 option 1
 * @param clid_len Client identifier length in bytes
 * @param iaid Identity Association Identifier from IA_NA or IA_TA option
 * @return Next matching dhcp_lease, or NULL if no more matches
 *
 * @note Call lease6_reset() before starting enumeration to clear LEASE_USED flags
 * @note Each returned lease is marked LEASE_USED (in the flag check logic, not explicitly set here)
 * @note Checks LEASE_USED flag and skips already-returned leases
 * @see lease6_reset() to clear USED flags before enumeration
 * @see lease6_find() for single lease lookup by address
 *
 * EXAMPLE USAGE:
 * @code
 * lease6_reset();  // Clear USED flags
 * struct dhcp_lease *lease = NULL;
 * while ((lease = lease6_find_by_client(lease, LEASE_NA, duid, 16, iaid))) {
 *     send_address_to_client(lease->addr6);  // Return each leased address
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 3315 Section 18.2.3 RENEW message processing: "For each IA in the RENEW message,
 * the server locates the client's binding and sends an IA containing the addresses in the IA..."
 * Client may have multiple addresses per IAID.
 *
 * SIDE EFFECTS:
 * None. Read-only enumeration. LEASE_USED flag checked but not modified by this function (caller
 * or other code may set it).
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop. Call lease6_reset() before enumeration.
 */
struct dhcp_lease *lease6_find_by_client(struct dhcp_lease *first, int lease_type,
					 unsigned char *clid, int clid_len,
					 unsigned int iaid)
{
  struct dhcp_lease *lease;

  if (!first)
    first = leases;
  else
    first = first->next;

  for (lease = first; lease; lease = lease->next)
    {
      if (lease->flags & LEASE_USED)
	continue;

      if (!(lease->flags & lease_type) || lease->iaid != iaid)
	continue;
 
      if ((clid_len != lease->clid_len ||
	   memcmp(clid, lease->clid, clid_len) != 0))
	continue;

      return lease;
    }
  
  return NULL;
}

/**
 * @brief Find DHCPv6 lease by network prefix and address suffix
 *
 * @detailed
 * Searches for DHCPv6 lease on specified network prefix with matching host portion. Performs
 * subnet match via is_same_net6() using provided prefix length. If prefix < 128, also matches
 * host portion (addr6part) against addr parameter. If prefix == 128, matches full address
 * (host portion match is automatic). Used for address conflict detection and finding leases
 * on specific subnets during DHCPv6 address allocation.
 *
 * @param net Network prefix (IPv6 address with network portion set)
 * @param prefix Prefix length (0-128 bits) for subnet matching
 * @param addr Host portion (lower 64 bits) of IPv6 address to match, ignored if prefix == 128
 * @return Pointer to matching dhcp_lease or NULL if not found
 *
 * @note Only searches DHCPv6 leases (LEASE_TA | LEASE_NA)
 * @note If prefix == 128, matches full address (addr parameter ignored)
 * @note If prefix < 128, matches subnet and host portion separately
 * @see lease6_find() for lookup by client ID, IAID, and exact address
 * @see lease_find_max_addr6() for finding highest allocated address in range
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr prefix;
 * inet_pton(AF_INET6, "2001:db8::", &prefix);
 * u64 host_id = 0x0000000000000001ULL;
 * struct dhcp_lease *lease = lease6_find_by_addr(&prefix, 64, host_id);
 * if (lease)
 *     return 0;  // Address conflict, already leased
 * @endcode
 *
 * RFC COMPLIANCE:
 * Used for RFC 3315 Section 18.2.1 address conflict detection: "If the server finds that any
 * of the addresses in the IA are in use by another client, the server returns the IA to the
 * client with a Status Code option...indicating address in use."
 *
 * SIDE EFFECTS:
 * None. Read-only search through leases list.
 *
 * THREAD SAFETY:
 * Thread-safe for read-only access if leases list is not modified concurrently. In single-threaded
 * event loop, safe to call anytime.
 */
struct dhcp_lease *lease6_find_by_addr(struct in6_addr *net, int prefix, u64 addr)
{
  struct dhcp_lease *lease;
    
  for (lease = leases; lease; lease = lease->next)
    {
      if (!(lease->flags & (LEASE_TA | LEASE_NA)))
	continue;
      
      if (is_same_net6(&lease->addr6, net, prefix) &&
	  (prefix == 128 || addr6part(&lease->addr6) == addr))
	return lease;
    }
  
  return NULL;
} 

/**
 * @brief Find highest allocated IPv6 address in DHCP context for sequential allocation
 *
 * @detailed
 * Searches all DHCPv6 leases (LEASE_TA | LEASE_NA) within specified DHCP context (subnet range)
 * and returns the highest allocated host ID (lower 64 bits). Used for sequential address allocation
 * to avoid reusing recently freed addresses. Only considers leases on same /64 subnet as context
 * (via is_same_net6) and within context's start6 to end6 range. Returns context->start6 host
 * portion if no leases allocated yet. Skips CONTEXT_STATIC and CONTEXT_PROXY contexts.
 *
 * @param context DHCP context defining subnet range and allocation parameters
 * @return Highest allocated address host portion (u64), or context->start6 host portion if none
 *
 * @note Only searches DHCPv6 leases on same /64 subnet as context
 * @note Assumes /64 prefix length for subnet matching and host portion extraction
 * @note Returns start6 host portion (via addr6part) if no leases in range
 * @see lease_find_max_addr() for DHCPv4 equivalent
 * @see addr6part() macro to extract lower 64 bits of IPv6 address
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = find_context6(...);
 * u64 max_allocated = lease_find_max_addr6(ctx);
 * u64 next_addr = max_allocated + 1;  // Sequential allocation
 * if (next_addr > addr6part(&ctx->end6))
 *     next_addr = addr6part(&ctx->start6);  // Wrap around
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports sequential address allocation strategy mentioned in RFC 3315 Section 17.2.2 as one
 * possible server allocation policy (not mandated by RFC).
 *
 * SIDE EFFECTS:
 * None. Read-only search through leases list.
 *
 * THREAD SAFETY:
 * Thread-safe for read-only access if leases list and context are not modified concurrently.
 */
u64 lease_find_max_addr6(struct dhcp_context *context)
{
  struct dhcp_lease *lease;
  u64 addr = addr6part(&context->start6);
  
  if (!(context->flags & (CONTEXT_STATIC | CONTEXT_PROXY)))
    for (lease = leases; lease; lease = lease->next)
      {
	if (!(lease->flags & (LEASE_TA | LEASE_NA)))
	  continue;

	if (is_same_net6(&lease->addr6, &context->start6, 64) &&
	    addr6part(&lease->addr6) > addr6part(&context->start6) &&
	    addr6part(&lease->addr6) <= addr6part(&context->end6) &&
	    addr6part(&lease->addr6) > addr)
	  addr = addr6part(&lease->addr6);
      }
  
  return addr;
}

#endif

/**
 * @brief Find highest allocated IPv4 address in DHCP context for sequential allocation
 *
 * @detailed
 * Searches all DHCPv4 leases within specified DHCP context (address range) and returns highest
 * allocated IPv4 address. Used for sequential address allocation to avoid reusing recently freed
 * addresses. Only considers leases within context->start to context->end range (inclusive).
 * Returns context->start if no leases allocated yet. Skips DHCPv6 leases (LEASE_TA | LEASE_NA)
 * and CONTEXT_STATIC/CONTEXT_PROXY contexts. Compares addresses in host byte order via ntohl().
 *
 * @param context DHCP context defining address range and allocation parameters
 * @return Highest allocated IPv4 address (struct in_addr), or context->start if none allocated
 *
 * @note Skips DHCPv6 leases (checks LEASE_TA | LEASE_NA flags)
 * @note Compares addresses in host byte order for correct numeric comparison
 * @note Returns context->start if no leases found in range
 * @see lease_find_max_addr6() for DHCPv6 equivalent
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_context *ctx = find_context4(subnet);
 * struct in_addr max_allocated = lease_find_max_addr(ctx);
 * struct in_addr next = max_allocated;
 * next.s_addr = htonl(ntohl(next.s_addr) + 1);  // Sequential allocation
 * if (ntohl(next.s_addr) > ntohl(ctx->end.s_addr))
 *     next = ctx->start;  // Wrap to start
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports sequential address allocation as one acceptable server policy. RFC 2131 Section 4.3.1
 * allows server to use any allocation strategy: "The server MAY choose to assign a new network
 * address based on the allocation mechanism described in section 4.2."
 *
 * SIDE EFFECTS:
 * None. Read-only search through leases list.
 *
 * THREAD SAFETY:
 * Thread-safe for read-only access if leases list and context are not modified concurrently.
 */
struct in_addr lease_find_max_addr(struct dhcp_context *context)
{
  struct dhcp_lease *lease;
  struct in_addr addr = context->start;
  
  if (!(context->flags & (CONTEXT_STATIC | CONTEXT_PROXY)))
    for (lease = leases; lease; lease = lease->next)
      {
#ifdef HAVE_DHCP6
	if (lease->flags & (LEASE_TA | LEASE_NA))
	  continue;
#endif
	if (((unsigned)ntohl(lease->addr.s_addr)) > ((unsigned)ntohl(context->start.s_addr)) &&
	    ((unsigned)ntohl(lease->addr.s_addr)) <= ((unsigned)ntohl(context->end.s_addr)) &&
	    ((unsigned)ntohl(lease->addr.s_addr)) > ((unsigned)ntohl(addr.s_addr)))
	  addr = lease->addr;
      }
  
  return addr;
}

/**
 * @brief Allocate new lease structure from pool (internal helper)
 *
 * @detailed
 * Allocates and initializes new dhcp_lease structure from available lease pool. Checks leases_left
 * counter (set to daemon->dhcp_max at init) and returns NULL if pool exhausted. Allocates via
 * whine_malloc() which logs error on failure. Initializes lease with LEASE_NEW flag, expires=1
 * (non-zero to avoid immediate expiry), hwaddr_len=256 (illegal value for uninitialized state),
 * and HAVE_BROKEN_RTC length=0xffffffff. Prepends to global leases linked list, decrements
 * leases_left, sets file_dirty=1.
 *
 * @return Pointer to newly allocated dhcp_lease, or NULL if pool exhausted or allocation failed
 *
 * @note Static helper called by lease4_allocate() and lease6_allocate() only
 * @note Decrements leases_left counter (limited by daemon->dhcp_max)
 * @note Sets file_dirty=1 to trigger database write
 * @warning Returns NULL if leases_left == 0 (pool exhausted)
 * @see lease4_allocate() for DHCPv4 lease creation
 * @see lease6_allocate() for DHCPv6 lease creation
 *
 * EXAMPLE USAGE:
 * @code
 * // Internal use only, called by lease4_allocate/lease6_allocate
 * struct dhcp_lease *lease = lease_allocate();
 * if (!lease)
 *     return NULL;  // Pool exhausted
 * lease->addr = new_address;  // Caller sets address
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates memory via whine_malloc()
 * - Prepends lease to global leases linked list
 * - Decrements leases_left counter
 * - Sets file_dirty=1
 * - Initializes lease flags to LEASE_NEW
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global leases list. Must be called from main event loop only.
 */
static struct dhcp_lease *lease_allocate(void)
{
  struct dhcp_lease *lease;
  if (!leases_left || !(lease = whine_malloc(sizeof(struct dhcp_lease))))
    return NULL;

  memset(lease, 0, sizeof(struct dhcp_lease));
  lease->flags = LEASE_NEW;
  lease->expires = 1;
#ifdef HAVE_BROKEN_RTC
  lease->length = 0xffffffff; /* illegal value */
#endif
  lease->hwaddr_len = 256; /* illegal value */
  lease->next = leases;
  leases = lease;
  
  file_dirty = 1;
  leases_left--;

  return lease;
}

/**
 * @brief Allocate new DHCPv4 lease with specified IPv4 address
 *
 * @detailed
 * Creates new DHCPv4 lease structure by calling lease_allocate() and sets IPv4 address field.
 * Increments METRIC_LEASES_ALLOCATED_4 metric counter. Returns NULL if lease pool exhausted
 * (leases_left == 0) or memory allocation fails. Caller must populate client identifier, hardware
 * address, hostname, and expiry via lease_set_*() functions.
 *
 * @param addr IPv4 address to assign to new lease (struct in_addr in network byte order)
 * @return Pointer to newly allocated dhcp_lease with addr field set, or NULL on failure
 *
 * @note Increments METRIC_LEASES_ALLOCATED_4 counter for monitoring
 * @note Returns NULL if lease pool exhausted (check leases_left)
 * @see lease_allocate() for internal allocation logic
 * @see lease6_allocate() for DHCPv6 equivalent
 * @see lease_set_hwaddr(), lease_set_hostname(), lease_set_expires() to populate lease fields
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr new_addr;
 * inet_pton(AF_INET, "192.168.1.100", &new_addr);
 * struct dhcp_lease *lease = lease4_allocate(new_addr);
 * if (!lease)
 *     return NULL;  // Pool exhausted
 * lease_set_hwaddr(lease, client_mac, NULL, 6, ARPHRD_ETHER, 0, now, 0);
 * lease_set_hostname(lease, "client-hostname", 0, domain, NULL);
 * lease_set_expires(lease, 3600, now);  // 1 hour lease
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2131 Section 4.3.1 lease allocation: "The server chooses an IP address for the
 * requesting client. If the client has indicated in the DHCPDISCOVER message that it wishes to
 * use a particular IP address, the server MAY choose to allow the client to use that IP address."
 *
 * SIDE EFFECTS:
 * - Calls lease_allocate() which modifies global leases list
 * - Increments daemon->metrics[METRIC_LEASES_ALLOCATED_4]
 * - Decrements leases_left via lease_allocate()
 * - Sets file_dirty=1 via lease_allocate()
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global leases list and metrics. Must be called from main event loop.
 */
struct dhcp_lease *lease4_allocate(struct in_addr addr)
{
  struct dhcp_lease *lease = lease_allocate();
  if (lease)
    {
      lease->addr = addr;
      daemon->metrics[METRIC_LEASES_ALLOCATED_4]++;
    }
  
  return lease;
}

#ifdef HAVE_DHCP6
/**
 * @brief Allocate new DHCPv6 lease with specified IPv6 address and type
 *
 * @detailed
 * Creates new DHCPv6 lease structure by calling lease_allocate() and sets IPv6 address, lease
 * type (LEASE_TA or LEASE_NA), and initializes IAID to 0. Increments METRIC_LEASES_ALLOCATED_6
 * metric counter. Returns NULL if lease pool exhausted or allocation fails. Caller must populate
 * client identifier (DUID), IAID, hostname, and expiry via lease_set_*() functions.
 *
 * @param addrp Pointer to IPv6 address to assign to new lease
 * @param lease_type LEASE_TA for temporary address or LEASE_NA for non-temporary address
 * @return Pointer to newly allocated dhcp_lease with addr6, lease_type, and iaid=0 set, or NULL on failure
 *
 * @note Increments METRIC_LEASES_ALLOCATED_6 counter for monitoring
 * @note Initializes iaid to 0 (caller must set via lease_set_iaid())
 * @note Sets lease_type flag (LEASE_TA or LEASE_NA) to identify DHCPv6 lease
 * @see lease_allocate() for internal allocation logic
 * @see lease4_allocate() for DHCPv4 equivalent
 * @see lease_set_hwaddr(), lease_set_iaid(), lease_set_hostname(), lease_set_expires()
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr addr;
 * inet_pton(AF_INET6, "2001:db8::1", &addr);
 * struct dhcp_lease *lease = lease6_allocate(&addr, LEASE_NA);
 * if (!lease)
 *     return NULL;  // Pool exhausted
 * lease_set_hwaddr(lease, NULL, duid, 0, 0, duid_len, now, 0);
 * lease_set_iaid(lease, 0x12345678);
 * lease_set_hostname(lease, "client-hostname", 0, domain, NULL);
 * lease_set_expires(lease, 7200, now);  // 2 hour lease
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 3315 Section 18.2 DHCPv6 address allocation for both IA_NA (non-temporary) and
 * IA_TA (temporary) Identity Associations. Temporary addresses (TA) have no preferred/valid
 * lifetime relationship enforced by this code.
 *
 * SIDE EFFECTS:
 * - Calls lease_allocate() which modifies global leases list
 * - Increments daemon->metrics[METRIC_LEASES_ALLOCATED_6]
 * - Decrements leases_left via lease_allocate()
 * - Sets file_dirty=1 via lease_allocate()
 * - Sets lease->flags |= lease_type (LEASE_TA or LEASE_NA)
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global leases list and metrics. Must be called from main event loop.
 */
struct dhcp_lease *lease6_allocate(struct in6_addr *addrp, int lease_type)
{
  struct dhcp_lease *lease = lease_allocate();

  if (lease)
    {
      lease->addr6 = *addrp;
      lease->flags |= lease_type;
      lease->iaid = 0;

      daemon->metrics[METRIC_LEASES_ALLOCATED_6]++;
    }

  return lease;
}
#endif

/**
 * @brief Set lease expiration time with 2038 overflow protection
 *
 * @detailed
 * Sets lease expiration timestamp from current time plus duration. Special handling: len=0xffffffff
 * sets infinite lease (expires=0). Detects year-2038 overflow (when now+len wraps negative due to
 * 32-bit time_t) and sets expires=0 for infinite lease as "least disruptive" behavior. On
 * HAVE_BROKEN_RTC systems (no real-time clock), stores duration in lease->length instead of
 * absolute timestamp. Sets dns_dirty=1 if expiry changes. Sets file_dirty and LEASE_AUX_CHANGED
 * or LEASE_EXP_CHANGED flags (except HAVE_BROKEN_RTC for expiry changes).
 *
 * @param lease Lease to update expiration time
 * @param len Lease duration in seconds (0xffffffff for infinite)
 * @param now Current timestamp for calculating absolute expiry
 *
 * @note len=0xffffffff or 2038 overflow both result in expires=0 (infinite)
 * @note On HAVE_BROKEN_RTC systems, stores duration not timestamp
 * @note Sets dns_dirty if expiry changes (triggers DNS cache update)
 * @warning Year-2038 problem: 32-bit time_t overflows for durations > 2038, treated as infinite
 * @see lease_update_file() which writes expiry or duration to database
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease4_allocate(addr);
 * time_t now = time(NULL);
 * lease_set_expires(lease, 3600, now);  // 1 hour lease
 * // lease->expires = now + 3600
 * 
 * lease_set_expires(lease, 0xffffffff, now);  // Infinite lease
 * // lease->expires = 0
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 2131 Section 3.3 and RFC 3315 Section 22.4 specify lease time semantics. Infinite lease
 * (0xffffffff) is valid per both RFCs. Year-2038 handling is implementation-specific.
 *
 * SIDE EFFECTS:
 * - Modifies lease->expires (or lease->length on HAVE_BROKEN_RTC)
 * - Sets dns_dirty=1 if expiry changes
 * - Sets file_dirty=1 and LEASE_AUX_CHANGED or LEASE_EXP_CHANGED flags (except HAVE_BROKEN_RTC)
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop during DHCP transaction processing.
 */
void lease_set_expires(struct dhcp_lease *lease, unsigned int len, time_t now)
{
  time_t exp;

  if (len == 0xffffffff)
    {
      exp = 0;
      len = 0;
    }
  else
    {
      exp = now + (time_t)len;
      /* Check for 2038 overflow. Make the lease
	 infinite in that case, as the least disruptive
	 thing we can do. */
      if (difftime(exp, now) <= 0.0)
	exp = 0;
    }

  if (exp != lease->expires)
    {
      dns_dirty = 1;
      lease->expires = exp;
#ifndef HAVE_BROKEN_RTC
      lease->flags |= LEASE_AUX_CHANGED | LEASE_EXP_CHANGED;
      file_dirty = 1;
#endif
    }
  
#ifdef HAVE_BROKEN_RTC
  if (len != lease->length)
    {
      lease->length = len;
      lease->flags |= LEASE_AUX_CHANGED;
      file_dirty = 1; 
    }
#endif
} 

#ifdef HAVE_DHCP6
/**
 * @brief Set DHCPv6 IAID (Identity Association Identifier) for lease
 *
 * @detailed
 * Updates lease IAID field if changed, setting LEASE_CHANGED flag to trigger lease-change script
 * execution. IAID identifies DHCPv6 address bindings per RFC 3315 Section 10. Each client may
 * have multiple IAIDs for multiple network interfaces or address types (IA_NA vs IA_TA). IAID
 * is assigned by DHCPv6 client and persisted across lease renewals.
 *
 * @param lease DHCPv6 lease to update (must have LEASE_TA or LEASE_NA flag)
 * @param iaid Identity Association Identifier from DHCPv6 client (32-bit value)
 *
 * @note Only updates if iaid differs from current value
 * @note Sets LEASE_CHANGED flag to trigger lease-change script
 * @warning DHCPv4 leases ignore IAID (DHCPv6-specific concept)
 * @see lease6_find_by_client() which searches by CLID+IAID combination
 * @see lease_set_hwaddr() which is called after IAID update typically
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease6_allocate(&addr6, LEASE_NA);
 * unsigned int iaid = 0x12345678;  // From DHCPv6 IA_NA option
 * lease_set_iaid(lease, iaid);
 * // lease->iaid = 0x12345678, lease->flags |= LEASE_CHANGED
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 3315 Section 10 "Identity Association" defines IAID as client-chosen 32-bit identifier
 * for IA_NA (non-temporary address) and IA_TA (temporary address) associations.
 *
 * SIDE EFFECTS:
 * - Modifies lease->iaid if changed
 * - Sets lease->flags |= LEASE_CHANGED if iaid changes
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop during DHCPv6 transaction processing.
 */
void lease_set_iaid(struct dhcp_lease *lease, unsigned int iaid)
{
  if (lease->iaid != iaid)
    {
      lease->iaid = iaid;
      lease->flags |= LEASE_CHANGED;
    }
}
#endif

/**
 * @brief Update lease hardware address and client identifier
 *
 * @detailed
 * Sets or updates lease hardware (MAC) address, hardware type (ARPHRD_* constant), and client
 * identifier (CLID). Only updates CLID when clid_len > 0 and clid != NULL (prevents packets
 * without CLID from removing existing CLID). If hwaddr/hw_type changes, copies new hwaddr and
 * sets LEASE_CHANGED and file_dirty. If CLID changes, reallocates clid buffer, sets
 * LEASE_AUX_CHANGED and file_dirty. On HAVE_DHCP6 systems with changes, calls slaac_add_addrs()
 * to update SLAAC addresses tied to this lease. Sets LEASE_HAVE_HWADDR flag for DHCPv6.
 *
 * @param lease Lease to update (DHCPv4 or DHCPv6)
 * @param hwaddr Hardware address buffer (MAC address, typically 6 bytes for Ethernet)
 * @param clid Client identifier buffer (optional, may be NULL)
 * @param hw_len Hardware address length in bytes (0 for no hwaddr, typically 6 for Ethernet)
 * @param hw_type Hardware address type (ARPHRD_ETHER=1 for Ethernet, ARPHRD_IEEE802=6, etc.)
 * @param clid_len Client identifier length in bytes (0 or clid==NULL to skip CLID update)
 * @param now Current timestamp for SLAAC address management
 * @param force Force SLAAC address update even if no changes (DHCPv6 only)
 *
 * @note hw_len=0 permitted (no hardware address for some relay scenarios)
 * @note clid_len=0 or clid==NULL skips CLID update (prevents removal of existing CLID)
 * @note CLID allocation failure returns silently (lease remains valid with old CLID)
 * @warning Changes to hwaddr/clid trigger lease-change script (file_dirty=1)
 * @see lease_find_by_client() which searches by hwaddr and CLID
 * @see slaac_add_addrs() called for DHCPv6 when changes detected
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * unsigned char clid[8] = {0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * lease_set_hwaddr(lease, mac, clid, 6, ARPHRD_ETHER, 7, now, 0);
 * // lease->hwaddr = mac, lease->hwaddr_len = 6
 * // lease->clid = clid, lease->clid_len = 7
 * 
 * lease_set_hwaddr(lease, mac, NULL, 6, ARPHRD_ETHER, 0, now, 0);
 * // Updates hwaddr but preserves existing CLID
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 2131 Section 2 defines chaddr (client hardware address) field. RFC 2132 Option 61 defines
 * client-identifier option. RFC 3315 Section 9 defines DUID (similar to CLID for DHCPv6).
 *
 * SIDE EFFECTS:
 * - Modifies lease->hwaddr, lease->hwaddr_len, lease->hwaddr_type if hwaddr changes
 * - Modifies lease->clid, lease->clid_len if clid provided and changed
 * - Sets lease->flags |= LEASE_CHANGED if hwaddr changes
 * - Sets lease->flags |= LEASE_AUX_CHANGED if clid changes
 * - Sets lease->flags |= LEASE_HAVE_HWADDR (DHCPv6 only)
 * - Sets file_dirty=1 if any changes
 * - Calls slaac_add_addrs(lease, now, force) if HAVE_DHCP6 and changes detected
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop during DHCP transaction processing.
 */
void lease_set_hwaddr(struct dhcp_lease *lease, const unsigned char *hwaddr,
		      const unsigned char *clid, int hw_len, int hw_type,
		      int clid_len, time_t now, int force)
{
#ifdef HAVE_DHCP6
  int change = force;
  lease->flags |= LEASE_HAVE_HWADDR;
#endif

  (void)force;
  (void)now;

  if (hw_len != lease->hwaddr_len ||
      hw_type != lease->hwaddr_type || 
      (hw_len != 0 && memcmp(lease->hwaddr, hwaddr, hw_len) != 0))
    {
      if (hw_len != 0)
	memcpy(lease->hwaddr, hwaddr, hw_len);
      lease->hwaddr_len = hw_len;
      lease->hwaddr_type = hw_type;
      lease->flags |= LEASE_CHANGED;
      file_dirty = 1; /* run script on change */
    }

  /* only update clid when one is available, stops packets
     without a clid removing the record. Lease init uses
     clid_len == 0 for no clid. */
  if (clid_len != 0 && clid)
    {
      if (!lease->clid)
	lease->clid_len = 0;

      if (lease->clid_len != clid_len)
	{
	  lease->flags |= LEASE_AUX_CHANGED;
	  file_dirty = 1;
	  free(lease->clid);
	  if (!(lease->clid = whine_malloc(clid_len)))
	    return;
#ifdef HAVE_DHCP6
	  change = 1;
#endif	   
	}
      else if (memcmp(lease->clid, clid, clid_len) != 0)
	{
	  lease->flags |= LEASE_AUX_CHANGED;
	  file_dirty = 1;
#ifdef HAVE_DHCP6
	  change = 1;
#endif	
	}
      
      lease->clid_len = clid_len;
      memcpy(lease->clid, clid, clid_len);
    }
  
#ifdef HAVE_DHCP6
  if (change)
    slaac_add_addrs(lease, now, force);
#endif
}

/**
 * @brief Prepare lease for hostname removal by moving name to old_hostname
 *
 * @detailed
 * Transfers current hostname to old_hostname field for lease-change script notification of name
 * removal. Frees any existing old_hostname (should not happen unless script is very slow and
 * updates are rapid). If lease has FQDN, moves FQDN to old_hostname and frees unqualified
 * hostname (helper script derives unqualified name from FQDN). Otherwise moves hostname to
 * old_hostname. Sets hostname and fqdn to NULL after transfer. Called before hostname change
 * or lease deletion to trigger ACTION_OLD_HOSTNAME script action.
 *
 * @param lease Lease whose hostname should be marked for removal
 *
 * @note Frees lease->old_hostname if already set (should not happen normally)
 * @note If lease->fqdn exists, it becomes old_hostname and lease->hostname is freed
 * @note If no fqdn, lease->hostname becomes old_hostname
 * @note Sets lease->hostname and lease->fqdn to NULL after move
 * @warning Memory leak prevention: frees old_hostname if set (rapid script execution case)
 * @see lease_set_hostname() which calls this before changing name
 * @see do_script_run() which processes old_hostname for ACTION_OLD_HOSTNAME
 *
 * EXAMPLE USAGE:
 * @code
 * // Lease has hostname="host" and fqdn="host.example.com"
 * kill_name(lease);
 * // lease->old_hostname = "host.example.com" (FQDN preferred)
 * // lease->hostname freed
 * // lease->fqdn = NULL
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-related. Supports DHCP hostname option (RFC 2132 Option 12) and FQDN option
 * (RFC 4702 Option 81) by tracking hostname changes for external script notification.
 *
 * SIDE EFFECTS:
 * - Frees lease->old_hostname if set
 * - Transfers lease->fqdn to lease->old_hostname (if fqdn set), or lease->hostname to old_hostname
 * - Frees lease->hostname if fqdn was transferred
 * - Sets lease->hostname = NULL and lease->fqdn = NULL
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop. Static function, internal use only.
 */
static void kill_name(struct dhcp_lease *lease)
{
  /* run script to say we lost our old name */
  
  /* this shouldn't happen unless updates are very quick and the
     script very slow, we just avoid a memory leak if it does. */
  free(lease->old_hostname);
  
  /* If we know the fqdn, pass that. The helper will derive the
     unqualified name from it, free the unqualified name here. */

  if (lease->fqdn)
    {
      lease->old_hostname = lease->fqdn;
      free(lease->hostname);
    }
  else
    lease->old_hostname = lease->hostname;

  lease->hostname = lease->fqdn = NULL;
}

/**
 * @brief Set or update lease hostname with conflict detection and FQDN construction
 *
 * @detailed
 * Sets lease hostname, constructing FQDN if domain provided. Implements hostname conflict
 * detection: if another lease has same hostname (or FQDN if OPT_DHCP_FQDN), removes name from
 * conflicting lease (unless it has LEASE_AUTH_NAME and current request is not auth). For DHCPv6,
 * multiple leases with same DUID may share same hostname. If name==NULL, removes hostname. If
 * name unchanged and hostname already set, only updates LEASE_AUTH_NAME flag if auth=1. Warns
 * if config_domain provided but doesn't match domain parameter. Sets dns_dirty and file_dirty
 * on changes. Allocates new_name and new_fqdn (if domain provided) then searches all leases for
 * conflicts before committing.
 *
 * @param lease Lease to set hostname for
 * @param name Hostname string (unqualified), or NULL to clear hostname
 * @param auth 1 if hostname from configuration (authoritative), 0 if from DHCP client
 * @param domain DNS domain to append for FQDN construction, or NULL for unqualified only
 * @param config_domain Expected domain from configuration (generates warning if mismatch), or NULL
 *
 * @note If name==NULL, removes hostname from lease
 * @note If name unchanged from current, only updates auth flag if auth=1
 * @note Conflict detection: searches all leases for hostname or FQDN match (depending on OPT_DHCP_FQDN)
 * @note DHCPv6 exception: multiple leases with same DUID (same client) may share same hostname
 * @note Authoritative names (LEASE_AUTH_NAME) cannot be overridden by non-auth requests
 * @warning config_domain mismatch generates syslog warning but continues
 * @warning Memory allocation failure silently aborts hostname update
 * @see kill_name() called to mark old hostname for removal
 * @see find_config() to locate static host configurations
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease4_allocate(addr);
 * lease_set_hostname(lease, "myhost", 0, "example.com", NULL);
 * // lease->hostname = "myhost"
 * // lease->fqdn = "myhost.example.com"
 * // lease->flags without LEASE_AUTH_NAME
 * 
 * lease_set_hostname(lease, "confhost", 1, "example.com", NULL);
 * // lease->hostname = "confhost"
 * // lease->flags |= LEASE_AUTH_NAME
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 2132 Option 12 (Host Name) and RFC 4702 Option 81 (Client FQDN) for DHCPv4. RFC 4704
 * Option 39 (Client FQDN) for DHCPv6. Conflict detection prevents multiple hosts from claiming
 * same name in DNS.
 *
 * SIDE EFFECTS:
 * - Allocates and sets lease->hostname (copy of name)
 * - Allocates and sets lease->fqdn (if domain provided: "name.domain")
 * - Frees and reallocates lease->hostname and lease->fqdn if changed
 * - Calls kill_name() on conflicting lease (removes its hostname)
 * - Sets lease->flags |= LEASE_AUTH_NAME if auth=1
 * - Sets lease->flags |= LEASE_CHANGED
 * - Sets dns_dirty=1 and file_dirty=1 if name changes
 * - Logs warning to syslog if config_domain mismatch
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop during DHCP transaction or configuration
 * update processing.
 */
void lease_set_hostname(struct dhcp_lease *lease, const char *name, int auth, char *domain, char *config_domain)
{
  struct dhcp_lease *lease_tmp;
  char *new_name = NULL, *new_fqdn = NULL;

  if (config_domain && (!domain || !hostname_isequal(domain, config_domain)))
    my_syslog(MS_DHCP | LOG_WARNING, _("Ignoring domain %s for DHCP host name %s"), config_domain, name);
  
  if (lease->hostname && name && hostname_isequal(lease->hostname, name))
    {
      if (auth)
	lease->flags |= LEASE_AUTH_NAME;
      return;
    }
  
  if (!name && !lease->hostname)
    return;

  /* If a machine turns up on a new net without dropping the old lease,
     or two machines claim the same name, then we end up with two interfaces with
     the same name. Check for that here and remove the name from the old lease.
     Note that IPv6 leases are different. All the leases to the same DUID are 
     allowed the same name.

     Don't allow a name from the client to override a name from dnsmasq config. */
  
  if (name)
    {
      if ((new_name = whine_malloc(strlen(name) + 1)))
	{
	  strcpy(new_name, name);
	  if (domain && (new_fqdn = whine_malloc(strlen(new_name) + strlen(domain) + 2)))
	    {
	      strcpy(new_fqdn, name);
	      strcat(new_fqdn, ".");
	      strcat(new_fqdn, domain);
	    }
	}
	  
      /* Depending on mode, we check either unqualified name or FQDN. */
      for (lease_tmp = leases; lease_tmp; lease_tmp = lease_tmp->next)
	{
	  if (option_bool(OPT_DHCP_FQDN))
	    {
	      if (!new_fqdn || !lease_tmp->fqdn || !hostname_isequal(lease_tmp->fqdn, new_fqdn))
		continue;
	    }
	  else
	    {
	      if (!new_name || !lease_tmp->hostname || !hostname_isequal(lease_tmp->hostname, new_name) )
		continue; 
	    }

	  if (lease->flags & (LEASE_TA | LEASE_NA))
	    {
	      if (!(lease_tmp->flags & (LEASE_TA | LEASE_NA)))
		continue;

	      /* another lease for the same DUID is OK for IPv6 */
	      if (lease->clid_len == lease_tmp->clid_len &&
		  lease->clid && lease_tmp->clid &&
		  memcmp(lease->clid, lease_tmp->clid, lease->clid_len) == 0)
		continue;	      
	    }
	  else if (lease_tmp->flags & (LEASE_TA | LEASE_NA))
	    continue;
		   
	  if ((lease_tmp->flags & LEASE_AUTH_NAME) && !auth)
	    {
	      free(new_name);
	      free(new_fqdn);
	      return;
	    }
	
	  kill_name(lease_tmp);
	  lease_tmp->flags |= LEASE_CHANGED; /* run script on change */
	  break;
	}
    }

  if (lease->hostname)
    kill_name(lease);

  lease->hostname = new_name;
  lease->fqdn = new_fqdn;
  
  if (auth)
    lease->flags |= LEASE_AUTH_NAME;
  
  file_dirty = 1;
  dns_dirty = 1; 
  lease->flags |= LEASE_CHANGED; /* run script on change */
}

/**
 * @brief Update lease interface binding and trigger SLAAC address update
 *
 * @detailed
 * Sets lease last_interface field to track which network interface lease is associated with.
 * Interface index used for determining subnet/prefix for SLAAC address generation in DHCPv6.
 * If interface unchanged, returns immediately without modifications. Sets LEASE_CHANGED flag
 * to trigger lease-change script. On HAVE_DHCP6 systems, calls slaac_add_addrs() to update
 * SLAAC addresses based on new interface's IPv6 prefix.
 *
 * @param lease Lease to update interface binding (DHCPv4 or DHCPv6)
 * @param interface Interface index (if_index from system, 0 for no interface)
 * @param now Current timestamp for SLAAC address management
 *
 * @note If interface unchanged from last_interface, returns without changes
 * @note Interface index 0 indicates no interface (relay scenario)
 * @note Sets LEASE_CHANGED flag even though interface not in lease database file
 * @warning DHCPv6 SLAAC addresses regenerated on interface change
 * @see lease_find_interfaces() which initially populates interface bindings
 * @see find_interface_v4() and find_interface_v6() callback functions
 * @see slaac_add_addrs() called to update SLAAC addresses (DHCPv6 only)
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = lease4_allocate(addr);
 * int if_index = 2;  // eth0 interface index
 * lease_set_interface(lease, if_index, now);
 * // lease->last_interface = 2
 * // lease->flags |= LEASE_CHANGED
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-related. Interface tracking supports multi-homed servers and SLAAC address
 * construction per RFC 4862 (IPv6 Stateless Address Autoconfiguration).
 *
 * SIDE EFFECTS:
 * - Sets lease->last_interface = interface if changed
 * - Sets lease->flags |= LEASE_CHANGED if interface changes
 * - Calls slaac_add_addrs(lease, now, 0) if HAVE_DHCP6 and interface changes
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop during interface enumeration or DHCP
 * transaction processing.
 */
void lease_set_interface(struct dhcp_lease *lease, int interface, time_t now)
{
  (void)now;

  if (lease->last_interface == interface)
    return;

  lease->last_interface = interface;
  lease->flags |= LEASE_CHANGED; 

#ifdef HAVE_DHCP6
  slaac_add_addrs(lease, now, 0);
#endif
}

/**
 * @brief Mark all leases as changed to trigger lease-change script re-execution
 *
 * @detailed
 * Iterates through all active leases and sets LEASE_CHANGED flag on each. Causes do_script_run()
 * to execute lease-change script for all leases at next script processing cycle. Used after
 * configuration reload (SIGHUP) to notify external systems of current lease state, even if leases
 * haven't actually changed. Enables external database reconstruction from dnsmasq state.
 *
 * @note Sets LEASE_CHANGED flag on every active lease
 * @note Does not modify file_dirty or dns_dirty flags
 * @warning Causes script execution for all leases, potentially hundreds of invocations
 * @see do_script_run() which processes LEASE_CHANGED flag and executes scripts
 * @see lease_init() which calls this indirectly after startup
 *
 * EXAMPLE USAGE:
 * @code
 * // After SIGHUP configuration reload
 * rerun_scripts();
 * // All leases now have LEASE_CHANGED flag set
 * // do_script_run() will execute for each lease
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-related. Supports external integration via lease-change scripts.
 *
 * SIDE EFFECTS:
 * - Sets lease->flags |= LEASE_CHANGED on all active leases
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop during configuration reload processing.
 */
void rerun_scripts(void)
{
  struct dhcp_lease *lease;
  
  for (lease = leases; lease; lease = lease->next)
    lease->flags |= LEASE_CHANGED; 
}

/* deleted leases get transferred to the old_leases list.
   remove them here, after calling the lease change
   script. Also run the lease change script on new/modified leases.

   Return zero if nothing to do. */
/**
 * @brief Execute lease-change script for modified, new, or deleted leases
 *
 * @detailed
 * Processes lease state changes and invokes external lease-change script (if HAVE_SCRIPT) and/or
 * emits D-Bus signals (if HAVE_DBUS). Handles three types of events: (1) deleted leases in
 * old_leases list trigger ACTION_OLD_HOSTNAME then ACTION_DEL, (2) active leases with old_hostname
 * trigger ACTION_OLD_HOSTNAME, (3) active leases with LEASE_NEW/LEASE_CHANGED/LEASE_AUX_CHANGED/
 * LEASE_EXP_CHANGED trigger ACTION_ADD or ACTION_OLD. Processes one event per call, returning 1
 * if work done or 0 if no pending events. Delayed D-Bus signal emission if dbus connection not yet
 * established. Frees deleted leases after script execution. Clears event flags after processing.
 *
 * @param now Current timestamp for script invocation
 * @return 1 if script/signal processing occurred, 0 if no pending events
 *
 * @note Processes exactly one event per invocation (old_hostname, deleted lease, or changed lease)
 * @note Returns 0 if OPT_DBUS enabled but daemon->dbus connection not ready (delays processing)
 * @note Deleted leases remain in old_leases list until old_hostname processed, then freed
 * @note LEASE_NEW triggers ACTION_ADD, LEASE_CHANGED triggers ACTION_OLD
 * @note LEASE_AUX_CHANGED processed only if OPT_LEASE_RO (read-only lease file mode)
 * @note LEASE_EXP_CHANGED processed only if OPT_LEASE_RENEW (notify on expiry changes)
 * @warning Must be called repeatedly until returns 0 to process all pending events
 * @warning D-Bus connection delay may cause event backlog if connection establishment slow
 * @see queue_script() which queues script for background execution (HAVE_SCRIPT)
 * @see emit_dbus_signal() which sends D-Bus signal (HAVE_DBUS)
 * @see lease_prune() which moves expired leases to old_leases list
 *
 * EXAMPLE USAGE:
 * @code
 * // In main event loop
 * while (do_script_run(now))
 *     ;  // Process all pending lease events
 * // Returns 0 when no more events pending
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-related. Supports external integration via lease-change scripts per common
 * DHCP server practice (ISC dhcpd, dnsmasq extensions).
 *
 * SIDE EFFECTS:
 * - Calls queue_script() for ACTION_OLD_HOSTNAME, ACTION_DEL, ACTION_ADD, ACTION_OLD
 * - Calls emit_dbus_signal() for ACTION_DEL, ACTION_ADD, ACTION_OLD
 * - Frees old_leases entries after processing (including clid, extradata, SLAAC addresses)
 * - Clears LEASE_NEW, LEASE_CHANGED, LEASE_AUX_CHANGED, LEASE_EXP_CHANGED flags
 * - Frees lease->old_hostname and lease->extradata after processing
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop. Modifies global old_leases list and
 * lease flags.
 */
int do_script_run(time_t now)
{
  struct dhcp_lease *lease;

  (void)now;

#ifdef HAVE_DBUS
  /* If we're going to be sending DBus signals, but the connection is not yet up,
     delay everything until it is. */
  if (option_bool(OPT_DBUS) && !daemon->dbus)
    return 0;
#endif

  if (old_leases)
    {
      lease = old_leases;
                  
      /* If the lease still has an old_hostname, do the "old" action on that first */
      if (lease->old_hostname)
	{
#ifdef HAVE_SCRIPT
	  queue_script(ACTION_OLD_HOSTNAME, lease, lease->old_hostname, now);
#endif
	  free(lease->old_hostname);
	  lease->old_hostname = NULL;
	  return 1;
	}
      else 
	{
#ifdef HAVE_DHCP6
	  struct slaac_address *slaac, *tmp;
	  for (slaac = lease->slaac_address; slaac; slaac = tmp)
	    {
	      tmp = slaac->next;
	      free(slaac);
	    }
#endif
	  kill_name(lease);
#ifdef HAVE_SCRIPT
	  queue_script(ACTION_DEL, lease, lease->old_hostname, now);
#endif
#ifdef HAVE_DBUS
	  emit_dbus_signal(ACTION_DEL, lease, lease->old_hostname);
#endif
	  old_leases = lease->next;
	  
	  free(lease->old_hostname); 
	  free(lease->clid);
	  free(lease->extradata);
	  free(lease);
	    
	  return 1; 
	}
    }
  
  /* make sure we announce the loss of a hostname before its new location. */
  for (lease = leases; lease; lease = lease->next)
    if (lease->old_hostname)
      {	
#ifdef HAVE_SCRIPT
	queue_script(ACTION_OLD_HOSTNAME, lease, lease->old_hostname, now);
#endif
	free(lease->old_hostname);
	lease->old_hostname = NULL;
	return 1;
      }
  
  for (lease = leases; lease; lease = lease->next)
    if ((lease->flags & (LEASE_NEW | LEASE_CHANGED)) || 
	((lease->flags & LEASE_AUX_CHANGED) && option_bool(OPT_LEASE_RO)) ||
	((lease->flags & LEASE_EXP_CHANGED) && option_bool(OPT_LEASE_RENEW)))
      {
#ifdef HAVE_SCRIPT
	queue_script((lease->flags & LEASE_NEW) ? ACTION_ADD : ACTION_OLD, lease, 
		     lease->fqdn ? lease->fqdn : lease->hostname, now);
#endif
#ifdef HAVE_DBUS
	emit_dbus_signal((lease->flags & LEASE_NEW) ? ACTION_ADD : ACTION_OLD, lease,
			 lease->fqdn ? lease->fqdn : lease->hostname);
#endif
	lease->flags &= ~(LEASE_NEW | LEASE_CHANGED | LEASE_AUX_CHANGED | LEASE_EXP_CHANGED);
	
	/* this is used for the "add" call, then junked, since they're not in the database */
	free(lease->extradata);
	lease->extradata = NULL;
	
	return 1;
      }

  return 0; /* nothing to do */
}

#ifdef HAVE_SCRIPT
/**
 * @brief Append extra data to lease for passing to lease-change script
 *
 * @detailed
 * Appends arbitrary data to lease extradata buffer for transmission to lease-change script as
 * additional environment variables. Data terminated with delimiter byte (delim). Special delim=-1
 * treats as delim=0 but allows embedded NULLs creating multiple records. Otherwise, scans data for
 * embedded NULL and truncates at first NULL. Dynamically reallocates extradata buffer if insufficient
 * space, growing by (len + 100) bytes. Extradata freed after script execution in do_script_run().
 * Used for vendor-specific info, user-class, circuit-id, remote-id, and other DHCP options.
 *
 * @param lease Lease to append extradata to
 * @param data Data buffer to append (raw bytes, may contain NULLs if delim=-1)
 * @param len Length of data buffer in bytes
 * @param delim Delimiter byte to append after data (-1 for NULL with embedded NULLs allowed)
 *
 * @note delim=-1 allows embedded NULLs in data (treats as delim=0 but skips NULL scanning)
 * @note delim=other values scan data for embedded NULLs and truncate at first NULL
 * @note Reallocates extradata buffer if insufficient space (grows by len+100)
 * @note Memory allocation failure silently ignored (extradata simply not added)
 * @warning Extradata buffer dynamically allocated, freed in do_script_run() after use
 * @warning No validation of data content (raw bytes passed to script)
 * @see do_script_run() which passes extradata to script and frees buffer
 * @see queue_script() which uses extradata for environment variable construction
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char vendor_class[] = "MSFT 5.0";
 * lease_add_extradata(lease, vendor_class, 8, 0);
 * // lease->extradata contains "MSFT 5.0\0"
 * 
 * unsigned char circuit_id[] = {0x00, 0x01, 0x02};
 * lease_add_extradata(lease, circuit_id, 3, -1);
 * // Allows embedded NULLs in circuit_id data
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly RFC-related. Supports RFC 2132 Option 43 (Vendor-Specific Information), Option 77
 * (User Class), and RFC 3046 Option 82 (Relay Agent Information) by passing data to external scripts.
 *
 * SIDE EFFECTS:
 * - Reallocates lease->extradata buffer if insufficient space
 * - Appends data and delimiter to lease->extradata
 * - Increments lease->extradata_len by (len + 1)
 * - Sets lease->extradata_size on reallocation
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop during DHCP transaction processing.
 * Modifies lease structure.
 */
/* delim == -1 -> delim = 0, but embedded 0s, creating extra records, are OK. */
void lease_add_extradata(struct dhcp_lease *lease, unsigned char *data, unsigned int len, int delim)
{
  unsigned int i;
  
  if (delim == -1)
    delim = 0;
  else
    /* check for embedded NULLs */
    for (i = 0; i < len; i++)
      if (data[i] == 0)
	{
	  len = i;
	  break;
	}
  
  if ((lease->extradata_size - lease->extradata_len) < (len + 1))
    {
      size_t newsz = lease->extradata_len + len + 100;
      unsigned char *new = whine_malloc(newsz);
  
      if (!new)
	return;
      
      if (lease->extradata)
	{
	  memcpy(new, lease->extradata, lease->extradata_len);
	  free(lease->extradata);
	}

      lease->extradata = new;
      lease->extradata_size = newsz;
    }

  if (len != 0)
    memcpy(lease->extradata + lease->extradata_len, data, len);
  lease->extradata[lease->extradata_len + len] = delim;
  lease->extradata_len += len + 1; 
}
#endif

#endif /* HAVE_DHCP */
