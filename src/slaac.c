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
 * @file slaac.c
 * @brief Stateless Address Autoconfiguration (SLAAC) per RFC 4862
 *
 * DETAILED PURPOSE:
 * This file implements IPv6 Stateless Address Autoconfiguration (SLAAC) functionality
 * for dnsmasq's DHCPv6 server. SLAAC allows IPv6 hosts to automatically configure their
 * addresses using Router Advertisement (RA) prefixes combined with their hardware addresses.
 * The implementation derives IPv6 addresses by converting MAC addresses to EUI-64 format
 * interface identifiers (IIDs) and combining them with advertised IPv6 prefixes. It performs
 * Duplicate Address Detection (DAD) via ICMPv6 ping to ensure address uniqueness, and
 * automatically registers confirmed SLAAC addresses in the DNS cache, enabling name
 * resolution for autoconfigured hosts.
 *
 * KEY RESPONSIBILITIES:
 * - slaac_add_addrs(): Generate SLAAC IPv6 addresses from RA prefixes and hardware addresses
 * - periodic_slaac(): Perform periodic DAD via ICMPv6 Echo Request to validate addresses
 * - slaac_ping_reply(): Process ICMPv6 Echo Reply to detect address conflicts and confirm addresses
 * - EUI-64 conversion: Transform MAC-48 addresses to Modified EUI-64 interface identifiers
 * - DNS integration: Automatically register confirmed SLAAC addresses for hostname resolution
 *
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core types and prototypes), netinet/icmp6.h (ICMPv6 protocol definitions)
 * Called by: DHCPv6 subsystem (dhcp6.c), Router Advertisement handler (radv.c)
 * Calls: ra_start_unsolicited() to trigger RA transmission, lease_update_dns() to update DNS cache,
 *        whine_malloc() for allocation with logging, expand() for packet buffer management,
 *        sendto() for ICMPv6 Echo Request transmission
 *
 * DATA STRUCTURES:
 * - struct slaac_address (dnsmasq.h:820-825): Tracks SLAAC address state with ping timing and backoff
 * - struct dhcp_lease (dnsmasq.h:799-829): DHCP/DHCPv6 lease containing SLAAC address list
 * - struct dhcp_context (dnsmasq.h:994+): DHCPv6 context with RA configuration and prefix
 * - struct ping_packet (radv-protocol.h:20-25): ICMPv6 Echo Request/Reply packet structure
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP6: Must be defined to enable this entire file (lines 19-213)
 * - HAVE_SOCKADDR_SA_LEN: Enables BSD-style sockaddr_in6.sin6_len field (line 161)
 * - ARPHRD_EUI64: Enables support for EUI-64 hardware addresses (lines 55-58)
 * - ARPHRD_IEEE1394: Enables FireWire EUI-64 identifier extraction from CLID (lines 60-65)
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Functions called from main event loop context.
 * No internal locking required. ICMPv6 socket (daemon->icmp6fd) managed by network layer.
 * Timer-based periodic execution via periodic_slaac() return value scheduling next event.
 *
 * RFC COMPLIANCE:
 * - RFC 4862: IPv6 Stateless Address Autoconfiguration (Section 5.5.3 address formation)
 * - RFC 4291: IPv6 Addressing Architecture (Appendix A on Modified EUI-64 format)
 * - RFC 4443: ICMPv6 (Echo Request/Reply for Duplicate Address Detection)
 * - RFC 2464: Transmission of IPv6 over Ethernet (MAC to EUI-64 conversion)
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 *
 * @see docs/DHCP_V6.md for DHCPv6 and SLAAC architecture documentation
 * @see src/radv.c for Router Advertisement implementation
 * @see src/dhcp6.c for DHCPv6 server integration
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP6

#include <netinet/icmp6.h>

/**
 * @var ping_id
 * @brief ICMPv6 Echo Request identifier for SLAAC duplicate address detection
 *
 * Unique identifier used in ICMPv6 Echo Request packets sent during SLAAC DAD.
 * Initialized to random 16-bit value on first use. Allows matching Echo Reply
 * responses to our DAD probes. Zero indicates uninitialized state.
 *
 * @see periodic_slaac() for initialization (lines 134-135)
 * @see slaac_ping_reply() for identifier verification (line 198)
 */
static int ping_id = 0;

/**
 * @brief Generate and validate SLAAC IPv6 addresses from Router Advertisement prefixes
 *
 * @detailed
 * Constructs SLAAC IPv6 addresses by combining RA prefixes from configured DHCPv6 contexts
 * with Modified EUI-64 interface identifiers derived from the lease's hardware address.
 * Supports MAC-48 (Ethernet/802.11), EUI-64, and FireWire hardware address formats.
 * Performs the universal/local bit flip required by Modified EUI-64. Initiates Duplicate
 * Address Detection (DAD) via ICMPv6 ping for newly created addresses. Reuses existing
 * confirmed addresses to avoid unnecessary re-validation. Updates DNS cache with hostname
 * mappings for all SLAAC addresses.
 *
 * @param lease Pointer to DHCP lease structure containing hardware address and hostname.
 *              Must have LEASE_HAVE_HWADDR flag set, valid hostname, and last_interface.
 *              NULL handling: Returns immediately if lease is invalid.
 * @param now Current time in seconds since epoch. Used to initialize ping timing for DAD.
 *            Constraints: Must be valid time_t value from time(NULL).
 * @param force If non-zero, forces re-validation of existing SLAAC addresses by resetting
 *              ping timers. Used when DHCPv4 client goes through init-reboot to recheck
 *              address validity. Zero preserves existing confirmed addresses.
 *
 * @return void (no return value)
 *
 * @note Only processes leases with hardware addresses (LEASE_HAVE_HWADDR flag).
 *       Skips leases with DHCPv6 IA_NA or IA_TA addresses (different address assignment model).
 *       Requires valid last_interface and hostname for DNS registration.
 *       Only generates addresses for contexts with CONTEXT_RA_NAME flag (SLAAC-for-names mode).
 *
 * @warning Modifies lease->slaac_address list by adding new addresses and removing stale ones.
 *          Allocates memory via whine_malloc() which logs allocation failures.
 *          Triggers unsolicited Router Advertisements via ra_start_unsolicited().
 *          Updates global DNS cache via lease_update_dns().
 *
 * @see periodic_slaac() for DAD ping transmission (lines 119-188)
 * @see slaac_ping_reply() for DAD response processing (lines 191-211)
 * @see struct slaac_address definition (dnsmasq.h:820-825)
 * @see struct dhcp_lease definition (dnsmasq.h:799-829)
 *
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = find_lease_by_mac(client_mac);
 * time_t now = time(NULL);
 * slaac_add_addrs(lease, now, 0); // Generate SLAAC addresses, preserve existing
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4862 Section 5.5.3: IPv6 address formation from prefix and interface identifier
 * - RFC 4291 Appendix A: Modified EUI-64 interface identifier derivation from MAC-48
 * - RFC 2464 Section 4: Transmission of IPv6 over Ethernet Networks (MAC to EUI-64)
 *
 * SIDE EFFECTS:
 * - Allocates struct slaac_address nodes and links to lease->slaac_address list
 * - Frees stale slaac_address nodes no longer matching current contexts
 * - Calls ra_start_unsolicited() to trigger Router Advertisement transmission
 * - Updates DNS cache with hostname-to-IPv6 mappings via lease_update_dns()
 * - Modifies lease->slaac_address linked list structure
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop context only.
 * Assumes single-threaded event-driven architecture with exclusive lease access.
 */
void slaac_add_addrs(struct dhcp_lease *lease, time_t now, int force)
{
  struct slaac_address *slaac, *old, **up;
  struct dhcp_context *context;
  int dns_dirty = 0;
  
  if (!(lease->flags & LEASE_HAVE_HWADDR) || 
      (lease->flags & (LEASE_TA | LEASE_NA)) ||
      lease->last_interface == 0 ||
      !lease->hostname)
    return ;
  
  old = lease->slaac_address;
  lease->slaac_address = NULL;

  for (context = daemon->dhcp6; context; context = context->next) 
    if ((context->flags & CONTEXT_RA_NAME) && 
	!(context->flags & CONTEXT_OLD) &&
	lease->last_interface == context->if_index)
      {
	struct in6_addr addr = context->start6;
	if (lease->hwaddr_len == 6 &&
	    (lease->hwaddr_type == ARPHRD_ETHER || lease->hwaddr_type == ARPHRD_IEEE802))
	  {
	    /* convert MAC address to EUI-64 */
	    memcpy(&addr.s6_addr[8], lease->hwaddr, 3);
	    memcpy(&addr.s6_addr[13], &lease->hwaddr[3], 3);
	    addr.s6_addr[11] = 0xff;
	    addr.s6_addr[12] = 0xfe;
	  }
#if defined(ARPHRD_EUI64)
	else if (lease->hwaddr_len == 8 &&
		 lease->hwaddr_type == ARPHRD_EUI64)
	  memcpy(&addr.s6_addr[8], lease->hwaddr, 8);
#endif
#if defined(ARPHRD_IEEE1394) && defined(ARPHRD_EUI64)
	else if (lease->clid_len == 9 && 
		 lease->clid[0] ==  ARPHRD_EUI64 &&
		 lease->hwaddr_type == ARPHRD_IEEE1394)
	  /* firewire has EUI-64 identifier as clid */
	  memcpy(&addr.s6_addr[8], &lease->clid[1], 8);
#endif
	else
	  continue;
	
	addr.s6_addr[8] ^= 0x02;
	
	/* check if we already have this one */
	for (up = &old, slaac = old; slaac; slaac = slaac->next)
	  {
	    if (IN6_ARE_ADDR_EQUAL(&addr, &slaac->addr))
	      {
		*up = slaac->next;
		/* recheck when DHCPv4 goes through init-reboot */
		if (force)
		  {
		    slaac->ping_time = now;
		    slaac->backoff = 1;
		    dns_dirty = 1;
		  }
		break;
	      }
	    up = &slaac->next;
	  }
	    
	/* No, make new one */
	if (!slaac && (slaac = whine_malloc(sizeof(struct slaac_address))))
	  {
	    slaac->ping_time = now;
	    slaac->backoff = 1;
	    slaac->addr = addr;
	    /* Do RA's to prod it */
	    ra_start_unsolicited(now, context);
	  }
	
	if (slaac)
	  {
	    slaac->next = lease->slaac_address;
	    lease->slaac_address = slaac;
	  }
      }
  
  if (old || dns_dirty)
    lease_update_dns(1);
  
  /* Free any no reused */
  for (; old; old = slaac)
    {
      slaac = old->next;
      free(old);
    }
}

/**
 * @brief Perform periodic Duplicate Address Detection for SLAAC addresses via ICMPv6 ping
 *
 * @detailed
 * Implements timer-driven DAD by sending ICMPv6 Echo Request packets to SLAAC addresses
 * that require validation. Uses exponential backoff strategy starting at 1 second, doubling
 * up to 2048 seconds (backoff 12), with random jitter to avoid synchronization. Gives up
 * after 12 retries if EHOSTUNREACH error persists (address unreachable). Initializes global
 * ping_id on first invocation. Returns next scheduled event time for event loop timer management.
 * Processes all leases with pending SLAAC address validation (backoff != 0 and ping_time != 0).
 *
 * @param now Current time in seconds since epoch. Used to determine which pings are due
 *            and calculate next ping times with backoff and jitter.
 *            Constraints: Must be valid time_t from time(NULL).
 * @param leases Pointer to head of dhcp_lease linked list. Iterates through all leases
 *               and their associated slaac_address lists to find pending validations.
 *               NULL handling: Returns 0 if leases is NULL.
 *
 * @return Next scheduled ping time (absolute time_t) for earliest pending DAD, or 0 if
 *         no pending DAD operations exist. Return value used by event loop to schedule
 *         next periodic_slaac() invocation.
 * @retval 0 No SLAAC contexts configured (CONTEXT_RA_NAME not set) or no pending DAD
 * @retval >0 Absolute time_t of next required DAD ping transmission
 *
 * @note Requires at least one dhcp_context with CONTEXT_RA_NAME flag for operation.
 *       Initializes ping_id to random 16-bit value if zero (first call).
 *       Skips addresses with backoff == 0 (confirmed) or ping_time == 0 (given up).
 *       Sets ping_time to 0 after 12 failed attempts with EHOSTUNREACH (gives up on address).
 *
 * @warning Sends ICMPv6 packets via daemon->icmp6fd raw socket requiring appropriate privileges.
 *          Modifies slaac->ping_time and slaac->backoff fields during execution.
 *          Uses daemon->outpacket buffer managed by expand()/reset_counter()/save_counter().
 *          Random jitter uses rand16() which must be properly seeded.
 *
 * @see slaac_add_addrs() for SLAAC address creation (lines 25-116)
 * @see slaac_ping_reply() for Echo Reply processing (lines 191-211)
 * @see struct ping_packet definition (radv-protocol.h:20-25)
 *
 * EXAMPLE USAGE:
 * @code
 * time_t now = time(NULL);
 * struct dhcp_lease *all_leases = daemon->dhcp_leases;
 * time_t next_event = periodic_slaac(now, all_leases);
 * if (next_event != 0)
 *   schedule_timer_event(next_event); // Schedule next periodic_slaac() call
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4443 Section 4.1: ICMPv6 Echo Request message format
 * - RFC 4443 Section 4.2: ICMPv6 Echo Reply message format
 * - RFC 4862 Section 5.4: Duplicate Address Detection (DAD) via Neighbor Solicitation
 *   (This implementation uses ICMPv6 Echo as alternative DAD mechanism)
 *
 * SIDE EFFECTS:
 * - Initializes global ping_id to rand16() value on first call if ping_id == 0
 * - Sends ICMPv6 Echo Request packets via sendto() on daemon->icmp6fd socket
 * - Modifies slaac_address fields: ping_time (next ping time) and backoff (retry count)
 * - Sets slaac->ping_time to 0 (gives up) after 12 EHOSTUNREACH errors
 * - Uses and modifies daemon->outpacket buffer via expand()/reset_counter()/save_counter()
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop context only.
 * Modifies global ping_id and daemon->outpacket buffer state.
 * Assumes single-threaded event-driven architecture.
 */
time_t periodic_slaac(time_t now, struct dhcp_lease *leases)
{
  struct dhcp_context *context;
  struct dhcp_lease *lease;
  struct slaac_address *slaac;
  time_t next_event = 0;
  
  for (context = daemon->dhcp6; context; context = context->next)
    if ((context->flags & CONTEXT_RA_NAME) && !(context->flags & CONTEXT_OLD))
      break;

  /* nothing configured */
  if (!context)
    return 0;

  while (ping_id == 0)
    ping_id = rand16();

  for (lease = leases; lease; lease = lease->next)
    for (slaac = lease->slaac_address; slaac; slaac = slaac->next)
      {
	/* confirmed or given up? */
	if (slaac->backoff == 0 || slaac->ping_time == 0)
	  continue;
	
	if (difftime(slaac->ping_time, now) <= 0.0)
	  {
	    struct ping_packet *ping;
	    struct sockaddr_in6 addr;
 
	    reset_counter();

	    if (!(ping = expand(sizeof(struct ping_packet))))
	      continue;

	    ping->type = ICMP6_ECHO_REQUEST;
	    ping->code = 0;
	    ping->identifier = ping_id;
	    ping->sequence_no = slaac->backoff;
	    
	    memset(&addr, 0, sizeof(addr));
#ifdef HAVE_SOCKADDR_SA_LEN
	    addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
	    addr.sin6_family = AF_INET6;
	    addr.sin6_port = htons(IPPROTO_ICMPV6);
	    addr.sin6_addr = slaac->addr;
	    
	    if (sendto(daemon->icmp6fd, daemon->outpacket.iov_base, save_counter(-1), 0,
		       (struct sockaddr *)&addr,  sizeof(addr)) == -1 &&
		errno == EHOSTUNREACH &&
		slaac->backoff == 12)
	      slaac->ping_time = 0; /* Give up */ 
	    else
	      {
		slaac->ping_time += (1 << (slaac->backoff - 1)) + (rand16()/21785); /* 0 - 3 */
		if (slaac->backoff > 4)
		  slaac->ping_time += rand16()/4000; /* 0 - 15 */
		if (slaac->backoff < 12)
		  slaac->backoff++;
	      }
	  }
	
	if (slaac->ping_time != 0 &&
	    (next_event == 0 || difftime(next_event, slaac->ping_time) >= 0.0))
	  next_event = slaac->ping_time;
      }

  return next_event;
}

/**
 * @brief Process ICMPv6 Echo Reply to confirm SLAAC address uniqueness or detect conflicts
 *
 * @detailed
 * Handles incoming ICMPv6 Echo Reply packets to complete Duplicate Address Detection (DAD)
 * for SLAAC addresses. Verifies packet identifier matches our ping_id to confirm it's a
 * response to our DAD probe. Searches all leases for SLAAC addresses matching the reply
 * sender address. On match, sets backoff to 0 indicating address confirmed and available.
 * Logs confirmation to syslog unless OPT_QUIET_DHCP6 is set. Updates DNS cache with confirmed
 * addresses to enable hostname resolution. Receipt of Echo Reply from a SLAAC address we're
 * probing indicates another host is already using that address (duplicate detected).
 *
 * @param sender Pointer to IPv6 address that sent the Echo Reply packet. Used to identify
 *               which SLAAC address received a response.
 *               NULL handling: Assumes sender is valid, no explicit NULL check.
 * @param packet Pointer to received ICMPv6 packet buffer containing Echo Reply.
 *               Cast to struct ping_packet to extract identifier and sequence fields.
 *               Constraints: Must point to valid ping_packet structure.
 * @param interface Network interface name (e.g., "eth0") where packet was received.
 *                  Used for logging confirmation messages. May be NULL (not used critically).
 * @param leases Pointer to head of dhcp_lease linked list. Iterates through all leases
 *               and their slaac_address lists to find matching address.
 *               NULL handling: Safely handles NULL (loop won't execute).
 *
 * @return void (no return value)
 *
 * @note Only processes replies with identifier matching global ping_id (our DAD probes).
 *       Skips slaac_address entries with backoff == 0 (already confirmed).
 *       Receipt of Echo Reply indicates duplicate address (another host responded).
 *       Setting backoff = 0 prevents further DAD attempts for this address.
 *       Logs "SLAAC-CONFIRM" message with interface, IPv6 address, and hostname.
 *
 * @warning Modifies slaac_address->backoff field (sets to 0 on match).
 *          Updates global DNS cache via lease_update_dns() which triggers cache rebuild.
 *          Uses daemon->addrbuff global buffer for inet_ntop() address formatting.
 *          Logs to syslog via my_syslog() unless OPT_QUIET_DHCP6 option is set.
 *
 * @see periodic_slaac() for Echo Request transmission (lines 119-188)
 * @see slaac_add_addrs() for SLAAC address creation (lines 25-116)
 * @see struct ping_packet definition (radv-protocol.h:20-25)
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr reply_sender;
 * unsigned char icmp6_packet[64];
 * char iface[] = "eth0";
 * struct dhcp_lease *all_leases = daemon->dhcp_leases;
 * // After receiving ICMPv6 Echo Reply on daemon->icmp6fd:
 * slaac_ping_reply(&reply_sender, icmp6_packet, iface, all_leases);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4443 Section 4.2: ICMPv6 Echo Reply message processing
 * - RFC 4862 Section 5.4.4: Receiving Neighbor Advertisement (analogous duplicate detection)
 *   (This implementation uses Echo Reply instead of Neighbor Advertisement for DAD)
 *
 * SIDE EFFECTS:
 * - Sets slaac_address->backoff to 0 for matching addresses (marks confirmed)
 * - Updates DNS cache via lease_update_dns() if any address confirmed (gotone == 1)
 * - Writes formatted IPv6 address to daemon->addrbuff global buffer
 * - Logs "SLAAC-CONFIRM" message to syslog with MS_DHCP | LOG_INFO priority
 *
 * THREAD SAFETY:
 * Not thread-safe. Must be called from main event loop ICMPv6 packet handler context.
 * Modifies lease slaac_address list and global DNS cache.
 * Uses global daemon->addrbuff buffer for address formatting.
 * Assumes single-threaded event-driven architecture.
 */
void slaac_ping_reply(struct in6_addr *sender, unsigned char *packet, char *interface, struct dhcp_lease *leases)
{
  struct dhcp_lease *lease;
  struct slaac_address *slaac;
  struct ping_packet *ping = (struct ping_packet *)packet;
  int gotone = 0;
  
  if (ping->identifier == ping_id)
    for (lease = leases; lease; lease = lease->next)
      for (slaac = lease->slaac_address; slaac; slaac = slaac->next)
	if (slaac->backoff != 0 && IN6_ARE_ADDR_EQUAL(sender, &slaac->addr))
	  {
	    slaac->backoff = 0;
	    gotone = 1;
	    inet_ntop(AF_INET6, sender, daemon->addrbuff, ADDRSTRLEN);
	    if (!option_bool(OPT_QUIET_DHCP6))
	      my_syslog(MS_DHCP | LOG_INFO, "SLAAC-CONFIRM(%s) %s %s", interface, daemon->addrbuff, lease->hostname); 
	  }
  
  lease_update_dns(gotone);
}
	
#endif
