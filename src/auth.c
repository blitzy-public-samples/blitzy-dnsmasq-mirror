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
 * @file auth.c
 * @brief Authoritative DNS server for local zones
 *
 * DETAILED PURPOSE:
 * This module implements an authoritative DNS server capability within dnsmasq,
 * allowing it to authoritatively answer DNS queries for configured zones. It serves
 * SOA, NS, A, AAAA, CNAME, MX, SRV, TXT, and NAPTR records from local configuration
 * data. The module provides secondary DNS server functionality for local domain names
 * (e.g., *.lan domains), handles zone transfers (AXFR) to authorized secondary servers,
 * and integrates with the DHCP subsystem to serve dynamically assigned hostnames as
 * authoritative DNS records. This enables dnsmasq to act as the authoritative source
 * for local network naming, combining DHCP address assignment with DNS resolution.
 *
 * KEY RESPONSIBILITIES:
 * - answer_auth() - Generate authoritative DNS responses for configured zones
 * - in_zone() - Determine if a domain name falls within an authoritative zone
 * - filter_zone() - Apply subnet and exclusion filters to zone queries
 * - find_subnet() - Locate matching subnet configuration for reverse zones
 * - find_exclude() - Check if an address is in the exclusion list
 *
 * DEPENDENCIES:
 * Includes: dnsmasq.h (provides all core type definitions and prototypes)
 * Called by: Functions in forward.c and dnsmasq.c for query processing
 * Calls: Functions in cache.c (cache_find_by_name, cache_find_by_addr, cache_enumerate),
 *        rfc1035.c (extract_name, add_resource_record, skip_questions),
 *        util.c (hostname_isequal, in_arpa_name_2_addr, is_same_net, is_same_net6),
 *        log.c (log_query, my_syslog)
 *
 * DATA STRUCTURES:
 * - struct auth_zone (dnsmasq.h) - Defines authoritative zone configuration with domain,
 *   subnet restrictions, and exclusion lists
 * - struct addrlist (dnsmasq.h) - Address list entries for subnet matching with prefix lengths
 * - struct dns_header (dns-protocol.h) - DNS packet header for response construction
 * - struct crec (dnsmasq.h) - Cache records integrated into authoritative responses
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_AUTH - Must be defined to enable authoritative DNS server functionality. When
 *   undefined, this entire file is excluded from compilation. Affects integration with
 *   forward.c, option.c (configuration parsing), and network.c (authoritative interface binding).
 *
 * THREADING/CONCURRENCY:
 * This module operates within dnsmasq's single-process, event-driven architecture. All
 * functions are called from the main event loop in response to DNS query packets. No
 * multi-threading or locking mechanisms are required. Functions are re-entrant within
 * the context of sequential query processing but are not thread-safe.
 *
 * @see docs/ARCHITECTURE.md for overall system design
 * @see docs/DNS_FORWARDING.md for integration with DNS query processing pipeline
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_AUTH

/**
 * @brief Search address list for matching network address
 *
 * @detailed
 * Iterates through a linked list of address ranges to find an entry whose network
 * prefix matches the provided address. Supports both IPv4 and IPv6 address matching
 * using CIDR prefix length comparison. For IPv4, calculates netmask from prefix length
 * and performs bitwise network comparison. For IPv6, uses is_same_net6() for prefix matching.
 *
 * @param list Head of addrlist linked list to search through
 * @param flag Address family flag (F_IPV4 or F_IPV6) indicating type of addr_u
 * @param addr_u Pointer to address union containing IPv4 or IPv6 address to match
 *
 * @return Pointer to matching addrlist entry if found, NULL if no match
 *
 * @note Compares addresses using prefix length from addrlist->prefixlen
 * @note Skips entries where address family doesn't match flag parameter
 *
 * @see find_subnet() which calls this for subnet matching
 * @see find_exclude() which calls this for exclusion checking
 * @see struct addrlist defined in dnsmasq.h for list structure
 *
 * EXAMPLE USAGE:
 * @code
 * union all_addr client_addr;
 * client_addr.addr4.s_addr = inet_addr("192.168.1.50");
 * struct addrlist *match = find_addrlist(zone->subnet, F_IPV4, &client_addr);
 * if (match) process_authorized_query();
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements CIDR subnet matching per RFC 4632 (Classless Inter-domain Routing)
 *
 * SIDE EFFECTS:
 * None - read-only traversal of addrlist linked list
 *
 * THREAD SAFETY:
 * Re-entrant for read-only access to addrlist structures. Not thread-safe if
 * list is concurrently modified.
 */
static struct addrlist *find_addrlist(struct addrlist *list, int flag, union all_addr *addr_u)
{
  do {
    if (!(list->flags & ADDRLIST_IPV6))
      {
	struct in_addr netmask, addr = addr_u->addr4;
	
	if (!(flag & F_IPV4))
	  continue;
	
	netmask.s_addr = htonl(~(in_addr_t)0 << (32 - list->prefixlen));
	
	if  (is_same_net(addr, list->addr.addr4, netmask))
	  return list;
      }
    else if (is_same_net6(&(addr_u->addr6), &list->addr.addr6, list->prefixlen))
      return list;
    
  } while ((list = list->next));
  
  return NULL;
}

/**
 * @brief Locate matching subnet in authoritative zone configuration
 *
 * @detailed
 * Searches the subnet list configured for an authoritative zone to determine if
 * the provided address falls within any of the zone's authorized subnet ranges.
 * Returns NULL immediately if the zone has no subnet restrictions, or delegates
 * to find_addrlist() to perform the actual subnet matching.
 *
 * @param zone Pointer to auth_zone structure containing subnet configuration
 * @param flag Address family flag (F_IPV4 or F_IPV6) for address type
 * @param addr_u Pointer to address union to match against zone subnets
 *
 * @return Pointer to matching addrlist entry if address is in zone subnet, NULL otherwise
 * @retval NULL Zone has no subnet restrictions (zone->subnet is NULL)
 * @retval NULL Address does not match any configured subnet
 * @retval <addrlist*> Address matches a configured subnet entry
 *
 * @note Used for reverse DNS zone queries to determine authoritative scope
 * @warning Assumes zone pointer is valid (not NULL)
 *
 * @see find_addrlist() for actual subnet matching logic
 * @see filter_zone() which uses this for query filtering
 * @see struct auth_zone defined in dnsmasq.h for zone structure
 *
 * EXAMPLE USAGE:
 * @code
 * struct auth_zone *zone = daemon->auth_zones;
 * union all_addr query_addr;
 * struct addrlist *subnet = find_subnet(zone, F_IPV4, &query_addr);
 * if (subnet) generate_ptr_response();
 * @endcode
 *
 * RFC COMPLIANCE:
 * Supports RFC 2317 (Classless IN-ADDR.ARPA delegation) subnet matching
 *
 * SIDE EFFECTS:
 * None - read-only check of zone configuration
 *
 * THREAD SAFETY:
 * Re-entrant for read-only access. Not thread-safe if zone->subnet is modified concurrently.
 */
static struct addrlist *find_subnet(struct auth_zone *zone, int flag, union all_addr *addr_u)
{
  if (!zone->subnet)
    return NULL;
  
  return find_addrlist(zone->subnet, flag, addr_u);
}

/**
 * @brief Check if address is in zone exclusion list
 *
 * @detailed
 * Searches the exclusion list configured for an authoritative zone to determine
 * if the provided address should be excluded from authoritative responses. This
 * allows fine-grained control over which addresses within a zone's subnet ranges
 * are actually served authoritatively. Returns NULL if no exclusions configured.
 *
 * @param zone Pointer to auth_zone structure containing exclusion list
 * @param flag Address family flag (F_IPV4 or F_IPV6) for address type
 * @param addr_u Pointer to address union to check against exclusion list
 *
 * @return Pointer to matching exclusion entry if address is excluded, NULL otherwise
 * @retval NULL Zone has no exclusion list (zone->exclude is NULL)
 * @retval NULL Address is not in any exclusion range
 * @retval <addrlist*> Address matches an exclusion entry (should not be served)
 *
 * @note Exclusions take precedence over subnet inclusions in filter_zone()
 * @warning Assumes zone pointer is valid (not NULL)
 *
 * @see find_addrlist() for actual exclusion matching logic
 * @see filter_zone() which uses this to reject excluded addresses
 * @see struct auth_zone defined in dnsmasq.h for zone structure
 *
 * EXAMPLE USAGE:
 * @code
 * struct auth_zone *zone = daemon->auth_zones;
 * union all_addr client_addr;
 * if (find_exclude(zone, F_IPV4, &client_addr))
 *   return 0; // Address is excluded, do not serve
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements address filtering for authoritative responses per RFC 1035 zone control
 *
 * SIDE EFFECTS:
 * None - read-only check of zone exclusion configuration
 *
 * THREAD SAFETY:
 * Re-entrant for read-only access. Not thread-safe if zone->exclude is modified concurrently.
 */
static struct addrlist *find_exclude(struct auth_zone *zone, int flag, union all_addr *addr_u)
{
  if (!zone->exclude)
    return NULL;
  
  return find_addrlist(zone->exclude, flag, addr_u);
}

/**
 * @brief Apply subnet filtering to determine if address is authorized for zone
 *
 * @detailed
 * Implements a two-stage filtering process for authoritative zone queries: first checks
 * if the address is explicitly excluded (via find_exclude), immediately rejecting if so.
 * Then checks if subnets are configured - if not, accepts all addresses. Finally, verifies
 * the address is within an authorized subnet (via find_subnet). This provides flexible
 * access control for authoritative responses based on client address or queried PTR address.
 *
 * @param zone Pointer to auth_zone structure containing filter configuration
 * @param flag Address family flag (F_IPV4 or F_IPV6) for address type
 * @param addr_u Pointer to address union to filter
 *
 * @return 1 if address passes filter (authorized), 0 if address is rejected
 * @retval 0 Address is in exclusion list (explicitly rejected)
 * @retval 1 No subnets configured (all addresses authorized by default)
 * @retval 1 Address matches a configured subnet (authorized)
 * @retval 0 Address does not match any configured subnet (rejected)
 *
 * @note Exclusions take precedence over inclusions (checked first)
 * @note Absence of subnet configuration means no filtering (permissive default)
 * @warning Assumes zone pointer is valid (not NULL)
 *
 * @see find_exclude() for exclusion checking
 * @see find_subnet() for subnet matching
 * @see answer_auth() which calls this for query authorization
 *
 * EXAMPLE USAGE:
 * @code
 * struct auth_zone *zone = daemon->auth_zones;
 * union all_addr client_addr = get_client_address();
 * if (filter_zone(zone, F_IPV4, &client_addr))
 *   add_resource_record(...); // Authorized, add record to response
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements zone access control for authoritative DNS per RFC 1035 Section 6.1
 *
 * SIDE EFFECTS:
 * None - read-only filtering based on zone configuration
 *
 * THREAD SAFETY:
 * Re-entrant for read-only access. Not thread-safe if zone configuration is modified concurrently.
 */
static int filter_zone(struct auth_zone *zone, int flag, union all_addr *addr_u)
{
  if (find_exclude(zone, flag, addr_u))
    return 0;

  /* No subnets specified, no filter */
  if (!zone->subnet)
    return 1;
  
  return find_subnet(zone, flag, addr_u) != NULL;
}

/**
 * @brief Determine if domain name is within authoritative zone
 *
 * @detailed
 * Performs hierarchical domain name matching to determine if a given fully-qualified
 * domain name (FQDN) falls within the specified authoritative zone. Checks if the name
 * ends with the zone's domain suffix, handling exact matches and subdomain cases. If a
 * match is found and the cut parameter is provided, sets cut to point to the '.' separator
 * between the subdomain and zone domain, enabling subdomain extraction. Uses case-insensitive
 * comparison via hostname_isequal() per DNS standards.
 *
 * @param zone Pointer to auth_zone structure containing zone->domain to match against
 * @param name Fully-qualified domain name to check (null-terminated string)
 * @param cut Optional pointer to char* that will be set to subdomain separator position,
 *            or NULL if cut information is not needed
 *
 * @return 1 if name is in zone (exact match or subdomain), 0 otherwise
 * @retval 0 Name does not end with zone domain (out of zone)
 * @retval 1 Name exactly matches zone domain (e.g., "lan" matches zone "lan")
 * @retval 1 Name is subdomain of zone (e.g., "host.lan" matches zone "lan", cut set to '.')
 *
 * @note If cut is non-NULL and match succeeds, *cut points to '.' before zone domain
 * @note If cut is non-NULL and no match, *cut is set to NULL
 * @note Comparison is case-insensitive per DNS RFC specifications
 * @warning Assumes zone and name pointers are valid and name is null-terminated
 *
 * @see hostname_isequal() in util.c for case-insensitive domain comparison
 * @see answer_auth() which calls this extensively for zone matching
 * @see struct auth_zone defined in dnsmasq.h containing zone->domain
 *
 * EXAMPLE USAGE:
 * @code
 * struct auth_zone *zone = daemon->auth_zones;
 * char *name = "server.example.lan";
 * char *cut_point;
 * if (in_zone(zone, name, &cut_point)) {
 *   *cut_point = 0; // Isolate subdomain: "server.example"
 *   process_subdomain(name);
 *   *cut_point = '.'; // Restore full name
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements DNS zone matching per RFC 1035 Section 4.3.2 (zone authority determination)
 *
 * SIDE EFFECTS:
 * Modifies *cut if provided and match succeeds (sets pointer to '.' in name string)
 *
 * THREAD SAFETY:
 * Re-entrant. Thread-safe for read-only zone access. Caller must ensure name string
 * is not concurrently modified if cut is used.
 */
int in_zone(struct auth_zone *zone, char *name, char **cut)
{
  size_t namelen = strlen(name);
  size_t domainlen = strlen(zone->domain);

  if (cut)
    *cut = NULL;
  
  if (namelen >= domainlen && 
      hostname_isequal(zone->domain, &name[namelen - domainlen]))
    {
      
      if (namelen == domainlen)
	return 1;
      
      if (name[namelen - domainlen - 1] == '.')
	{
	  if (cut)
	    *cut = &name[namelen - domainlen - 1]; 
	  return 1;
	}
    }

  return 0;
}

/**
 * @brief Generate authoritative DNS response for configured zones
 *
 * @detailed
 * Main entry point for authoritative DNS server functionality. Processes DNS queries to
 * determine if dnsmasq is authoritative for the queried domain, then constructs complete
 * DNS responses including answer, authority, and additional sections. Handles all standard
 * DNS record types (A, AAAA, PTR, MX, SRV, TXT, NAPTR, CNAME, SOA, NS) by consulting
 * configured static records, DHCP lease data, and cache entries. Supports zone transfers
 * (AXFR) to authorized secondary servers. Implements subnet filtering for reverse zones
 * and wildcard CNAME expansion. Integrates with DHCP to serve dynamically assigned
 * hostnames as authoritative records. Constructs responses conforming to RFC 1035 format
 * with proper header flags (AA, TC, QR, RA) and RCODE values (NOERROR, NXDOMAIN, REFUSED).
 *
 * @param header Pointer to DNS packet header structure to be populated with response
 * @param limit Pointer to end of available buffer space (for overflow prevention)
 * @param qlen Length of original query packet in bytes
 * @param now Current time in seconds since epoch for TTL calculations
 * @param peer_addr Socket address of querying client (for AXFR authorization)
 * @param local_query 1 if query originated from local system, 0 if from network
 * @param do_bit DNSSEC OK bit from query (always cleared in responses, data not signed)
 * @param have_pseudoheader 1 if query contained EDNS0 OPT record, 0 otherwise
 *
 * @return Size of generated DNS response packet in bytes, or 0 if query rejected
 * @retval 0 Invalid query (zero questions, bad opcode, malformed packet)
 * @retval 0 AXFR request from unauthorized peer (auth-peers check failed)
 * @retval >0 Size of complete DNS response packet with all sections populated
 *
 * @note Sets AA (Authoritative Answer) flag if dnsmasq is authoritative for queried zone
 * @note Sets TC (Truncation) flag if response exceeds buffer space
 * @note Sets NXDOMAIN if authoritative for zone but name does not exist
 * @note Sets REFUSED if query is for out-of-zone domain
 * @note Data is never DNSSEC signed (AD flag always cleared, do_bit ignored)
 * @note AXFR requires --auth-sec-servers or --auth-peer configuration
 *
 * @warning Modifies header structure and buffer in place
 * @warning AXFR responses can be very large (entire zone contents)
 * @warning Local queries always get RA (Recursion Available) flag set
 *
 * @see in_zone() for zone matching logic
 * @see filter_zone() for subnet-based access control
 * @see add_resource_record() in rfc1035.c for record construction
 * @see extract_name() in rfc1035.c for query name parsing
 * @see cache_find_by_name() in cache.c for DHCP/hosts integration
 * @see cache_find_by_addr() in cache.c for PTR record resolution
 * @see struct dns_header in dns-protocol.h for packet format
 * @see struct auth_zone in dnsmasq.h for zone configuration
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * char *limit = packet + sizeof(packet);
 * union mysockaddr client_addr;
 * size_t response_len = answer_auth(header, limit, query_len, time(NULL),
 *                                     &client_addr, 0, 0, 1);
 * if (response_len > 0)
 *   send(sock, packet, response_len, 0);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 1035 Section 4.3.2 - Authoritative answers and zone authority
 * - RFC 1035 Section 6 - Name server data structures and algorithms
 * - RFC 2181 Section 5.4.1 - Authoritative Answer (AA) flag semantics
 * - RFC 5936 - DNS Zone Transfer Protocol (AXFR) for secondary servers
 * - RFC 2317 - Classless IN-ADDR.ARPA delegation for reverse zones
 *
 * SIDE EFFECTS:
 * - Modifies header and buffer contents to construct DNS response
 * - Logs query processing via log_query() (syslog/file output)
 * - Logs AXFR rejections via my_syslog() if unauthorized
 * - May enumerate cache via cache_enumerate() for AXFR zone dumps
 * - Temporarily modifies zone->domain strings (restored before return)
 *
 * THREAD SAFETY:
 * Not thread-safe. Designed for single-process event-driven architecture. Modifies
 * global daemon structure and cache state. Must be called sequentially from main event loop.
 */
size_t answer_auth(struct dns_header *header, char *limit, size_t qlen, time_t now, union mysockaddr *peer_addr, 
		   int local_query, int do_bit, int have_pseudoheader) 
{
  char *name = daemon->namebuff;
  unsigned char *p, *ansp;
  int qtype, qclass, rc;
  int nameoffset, axfroffset = 0;
  int q, anscount = 0, authcount = 0;
  struct crec *crecp;
  int  auth = !local_query, trunc = 0, nxdomain = 1, soa = 0, ns = 0, axfr = 0, out_of_zone = 0;
  struct auth_zone *zone = NULL;
  struct addrlist *subnet = NULL;
  char *cut;
  struct mx_srv_record *rec, *move, **up;
  struct txt_record *txt;
  struct interface_name *intr;
  struct naptr *na;
  union all_addr addr;
  struct cname *a, *candidate;
  unsigned int wclen;
  
  if (ntohs(header->qdcount) == 0 || OPCODE(header) != QUERY )
    return 0;

  /* determine end of question section (we put answers there) */
  if (!(ansp = skip_questions(header, qlen)))
    return 0; /* bad packet */
  
  /* now process each question, answers go in RRs after the question */
  p = (unsigned char *)(header+1);

  for (q = ntohs(header->qdcount); q != 0; q--)
    {
      unsigned int flag = 0;
      int found = 0;
      int cname_wildcard = 0;
  
      /* save pointer to name for copying into answers */
      nameoffset = p - (unsigned char *)header;

      /* now extract name as .-concatenated string into name */
      if (!extract_name(header, qlen, &p, name, 1, 4))
	return 0; /* bad packet */
 
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      
      if (qclass != C_IN)
	{
	  auth = 0;
	  out_of_zone = 1;
	  continue;
	}

      if ((qtype == T_PTR || qtype == T_SOA || qtype == T_NS) &&
	  (flag = in_arpa_name_2_addr(name, &addr)) &&
	  !local_query)
	{
	  for (zone = daemon->auth_zones; zone; zone = zone->next)
	    if ((subnet = find_subnet(zone, flag, &addr)))
	      break;
	  
	  if (!zone)
	    {
	      out_of_zone = 1;
	      auth = 0;
	      continue;
	    }
	  else if (qtype == T_SOA)
	    soa = 1, found = 1;
	  else if (qtype == T_NS)
	    ns = 1, found = 1;
	}

      if (qtype == T_PTR && flag)
	{
	  intr = NULL;

	  if (flag == F_IPV4)
	    for (intr = daemon->int_names; intr; intr = intr->next)
	      {
		struct addrlist *addrlist;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		  if (!(addrlist->flags & ADDRLIST_IPV6) && addr.addr4.s_addr == addrlist->addr.addr4.s_addr)
		    break;
		
		if (addrlist)
		  break;
		else
		  while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
		    intr = intr->next;
	      }
	  else if (flag == F_IPV6)
	    for (intr = daemon->int_names; intr; intr = intr->next)
	      {
		struct addrlist *addrlist;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		  if ((addrlist->flags & ADDRLIST_IPV6) && IN6_ARE_ADDR_EQUAL(&addr.addr6, &addrlist->addr.addr6))
		    break;
		
		if (addrlist)
		  break;
		else
		  while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
		    intr = intr->next;
	      }
	  
	  if (intr)
	    {
	      if (local_query || in_zone(zone, intr->name, NULL))
		{	
		  found = 1;
		  log_query(flag | F_REVERSE | F_CONFIG, intr->name, &addr, NULL, 0);
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  daemon->auth_ttl, NULL,
					  T_PTR, C_IN, "d", intr->name))
		    anscount++;
		}
	    }
	  
	  if ((crecp = cache_find_by_addr(NULL, &addr, now, flag)))
	    do { 
	      strcpy(name, cache_get_name(crecp));
	      
	      if (crecp->flags & F_DHCP && !option_bool(OPT_DHCP_FQDN))
		{
		  char *p = strchr(name, '.');
		  if (p)
		    *p = 0; /* must be bare name */
		  
		  /* add  external domain */
		  if (zone)
		    {
		      strcat(name, ".");
		      strcat(name, zone->domain);
		    }
		  log_query(flag | F_DHCP | F_REVERSE, name, &addr, record_source(crecp->uid), 0);
		  found = 1;
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  daemon->auth_ttl, NULL,
					  T_PTR, C_IN, "d", name))
		    anscount++;
		}
	      else if (crecp->flags & (F_DHCP | F_HOSTS) && (local_query || in_zone(zone, name, NULL)))
		{
		  log_query(crecp->flags & ~F_FORWARD, name, &addr, record_source(crecp->uid), 0);
		  found = 1;
		  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					  daemon->auth_ttl, NULL,
					  T_PTR, C_IN, "d", name))
		    anscount++;
		}
	      else
		continue;
		    
	    } while ((crecp = cache_find_by_addr(crecp, &addr, now, flag)));

	  if (!found && is_rev_synth(flag, &addr, name) && (local_query || in_zone(zone, name, NULL)))
	    {
	      log_query(F_CONFIG | F_REVERSE | flag, name, &addr, NULL, 0);
	      found = 1;
	      
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				      daemon->auth_ttl, NULL,
				      T_PTR, C_IN, "d", name))
		anscount++;
	    }

	  if (found)
	    nxdomain = 0;
	  else
	    log_query(flag | F_NEG | F_NXDOMAIN | F_REVERSE | (auth ? F_AUTH : 0), NULL, &addr, NULL, 0);

	  continue;
	}
      
    cname_restart:
      if (found)
	/* NS and SOA .arpa requests have set found above. */
	cut = NULL;
      else
	{
	  for (zone = daemon->auth_zones; zone; zone = zone->next)
	    if (in_zone(zone, name, &cut))
	      break;
	  
	  if (!zone)
	    {
	      out_of_zone = 1;
	      auth = 0;
	      continue;
	    }
	}

      for (rec = daemon->mxnames; rec; rec = rec->next)
	if (!rec->issrv && (rc = hostname_issubdomain(name, rec->name)))
	  {
	    nxdomain = 0;
	         
	    if (rc == 2 && qtype == T_MX)
	      {
		found = 1;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<MX>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_MX, C_IN, "sd", rec->weight, rec->target))
		  anscount++;
	      }
	  }
      
      for (move = NULL, up = &daemon->mxnames, rec = daemon->mxnames; rec; rec = rec->next)
	if (rec->issrv && (rc = hostname_issubdomain(name, rec->name)))
	  {
	    nxdomain = 0;
	    
	    if (rc == 2 && qtype == T_SRV)
	      {
		found = 1;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<SRV>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_SRV, C_IN, "sssd", 
					rec->priority, rec->weight, rec->srvport, rec->target))

		  anscount++;
	      } 
	    
	    /* unlink first SRV record found */
	    if (!move)
	      {
		move = rec;
		*up = rec->next;
	      }
	    else
	      up = &rec->next;      
	  }
	else
	  up = &rec->next;
	  
      /* put first SRV record back at the end. */
      if (move)
	{
	  *up = move;
	  move->next = NULL;
	}

      for (txt = daemon->rr; txt; txt = txt->next)
	if ((rc = hostname_issubdomain(name, txt->name)))
	  {
	    nxdomain = 0;
	    if (rc == 2 && txt->class == qtype)
	      {
		found = 1;
		log_query(F_CONFIG | F_RRNAME, name, NULL, NULL, txt->class);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, txt->class, C_IN, "t", txt->len, txt->txt))
		  anscount++;
	      }
	  }
      
      for (txt = daemon->txt; txt; txt = txt->next)
	if (txt->class == C_IN && (rc = hostname_issubdomain(name, txt->name)))
	  {
	    nxdomain = 0;
	    if (rc == 2 && qtype == T_TXT)
	      {
		found = 1;
		log_query(F_CONFIG | F_RRNAME, name, NULL, "<TXT>", 0);
		if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl,
					NULL, T_TXT, C_IN, "t", txt->len, txt->txt))
		  anscount++;
	      }
	  }

       for (na = daemon->naptr; na; na = na->next)
	 if ((rc = hostname_issubdomain(name, na->name)))
	   {
	     nxdomain = 0;
	     if (rc == 2 && qtype == T_NAPTR)
	       {
		 found = 1;
		 log_query(F_CONFIG | F_RRNAME, name, NULL, "<NAPTR>", 0);
		 if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->auth_ttl, 
					 NULL, T_NAPTR, C_IN, "sszzzd", 
					 na->order, na->pref, na->flags, na->services, na->regexp, na->replace))
			  anscount++;
	       }
	   }
    
       if (qtype == T_A)
	 flag = F_IPV4;
       
       if (qtype == T_AAAA)
	 flag = F_IPV6;
       
       for (intr = daemon->int_names; intr; intr = intr->next)
	 if ((rc = hostname_issubdomain(name, intr->name)))
	   {
	     struct addrlist *addrlist;
	     
	     nxdomain = 0;
	     
	     if (rc == 2 && flag)
	       for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)  
		 if (((addrlist->flags & ADDRLIST_IPV6)  ? T_AAAA : T_A) == qtype &&
		     (local_query || filter_zone(zone, flag, &addrlist->addr)))
		   {
		     if (addrlist->flags & ADDRLIST_REVONLY)
		       continue;

		     found = 1;
		     log_query(F_FORWARD | F_CONFIG | flag, name, &addrlist->addr, NULL, 0);
		     if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					     daemon->auth_ttl, NULL, qtype, C_IN, 
					     qtype == T_A ? "4" : "6", &addrlist->addr))
		       anscount++;
		   }
	     }

       if (!found && is_name_synthetic(flag, name, &addr) )
	 {
	   nxdomain = 0;
	   
	   log_query(F_FORWARD | F_CONFIG | flag, name, &addr, NULL, 0);
	   if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				   daemon->auth_ttl, NULL, qtype, C_IN, qtype == T_A ? "4" : "6", &addr))
	     anscount++;
	 }
       
      if (!cut)
	{
	  nxdomain = 0;
	  
	  if (qtype == T_SOA)
	    {
	      auth = soa = 1; /* inhibits auth section */
	      log_query(F_RRNAME | F_AUTH, zone->domain, NULL, "<SOA>", 0);
	    }
      	  else if (qtype == T_AXFR)
	    {
	      struct iname *peers;
	      
	      if (peer_addr->sa.sa_family == AF_INET)
		peer_addr->in.sin_port = 0;
	      else
		{
		  peer_addr->in6.sin6_port = 0; 
		  peer_addr->in6.sin6_scope_id = 0;
		}
	      
	      for (peers = daemon->auth_peers; peers; peers = peers->next)
		if (sockaddr_isequal(peer_addr, &peers->addr))
		  break;
	      
	      /* Refuse all AXFR unless --auth-sec-servers or auth-peers is set */
	      if ((!daemon->secondary_forward_server && !daemon->auth_peers) ||
		  (daemon->auth_peers && !peers)) 
		{
		  if (peer_addr->sa.sa_family == AF_INET)
		    inet_ntop(AF_INET, &peer_addr->in.sin_addr, daemon->addrbuff, ADDRSTRLEN);
		  else
		    inet_ntop(AF_INET6, &peer_addr->in6.sin6_addr, daemon->addrbuff, ADDRSTRLEN); 
		  
		  my_syslog(LOG_WARNING, _("ignoring zone transfer request from %s"), daemon->addrbuff);
		  return 0;
		}
	       	      
	      auth = 1;
	      soa = 1; /* inhibits auth section */
	      ns = 1; /* ensure we include NS records! */
	      axfr = 1;
	      axfroffset = nameoffset;
	      log_query(F_RRNAME | F_AUTH, zone->domain, NULL, "<AXFR>", 0);
	    }
      	  else if (qtype == T_NS)
	    {
	      auth = 1;
	      ns = 1; /* inhibits auth section */
	      log_query(F_RRNAME | F_AUTH, zone->domain, NULL, "<NS>", 0);
	    }
	}
      
      if (!option_bool(OPT_DHCP_FQDN) && cut)
	{	  
	  *cut = 0; /* remove domain part */
	  
	  if (!strchr(name, '.') && (crecp = cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6)))
	    {
	      if (crecp->flags & F_DHCP)
		do
		  { 
		    nxdomain = 0;
		    if ((crecp->flags & flag) && 
			(local_query || filter_zone(zone, flag, &(crecp->addr))))
		      {
			*cut = '.'; /* restore domain part */
			log_query(crecp->flags, name, &crecp->addr, record_source(crecp->uid), 0);
			*cut  = 0; /* remove domain part */
			if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						daemon->auth_ttl, NULL, qtype, C_IN, 
						qtype == T_A ? "4" : "6", &crecp->addr))
			  anscount++;
		      }
		  } while ((crecp = cache_find_by_name(crecp, name, now,  F_IPV4 | F_IPV6)));
	    }
       	  
	  *cut = '.'; /* restore domain part */	    
	}
      
      if ((crecp = cache_find_by_name(NULL, name, now, F_IPV4 | F_IPV6)))
	{
	  if ((crecp->flags & F_HOSTS) || (((crecp->flags & F_DHCP) && option_bool(OPT_DHCP_FQDN))))
	    do
	      { 
		 nxdomain = 0;
		 if ((crecp->flags & flag) && (local_query || filter_zone(zone, flag, &(crecp->addr))))
		   {
		     log_query(crecp->flags, name, &crecp->addr, record_source(crecp->uid), 0);
		     if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					     daemon->auth_ttl, NULL, qtype, C_IN, 
					     qtype == T_A ? "4" : "6", &crecp->addr))
		       anscount++;
		   }
	      } while ((crecp = cache_find_by_name(crecp, name, now, F_IPV4 | F_IPV6)));
	}
      
      /* Only supply CNAME if no record for any type is known. */
      if (nxdomain)
	{
	  /* Check for possible wildcard match against *.domain 
	     return length of match, to get longest.
	     Note that if return length of wildcard section, so
	     we match b.simon to _both_ *.simon and b.simon
	     but return a longer (better) match to b.simon.
	  */  
	  for (wclen = 0, candidate = NULL, a = daemon->cnames; a; a = a->next)
	    if (a->alias[0] == '*')
	      {
		char *test = name;
		
		while ((test = strchr(test+1, '.')))
		  {
		    if (hostname_isequal(test, &(a->alias[1])))
		      {
			if (strlen(test) > wclen && !cname_wildcard)
			  {
			    wclen = strlen(test);
			    candidate = a;
			    cname_wildcard = 1;
			  }
			break;
		      }
		  }
		
	      }
	    else if (hostname_isequal(a->alias, name) && strlen(a->alias) > wclen)
	      {
		/* Simple case, no wildcard */
		wclen = strlen(a->alias);
		candidate = a;
	      }
	  
	  if (candidate)
	    {
	      log_query(F_CONFIG | F_CNAME, name, NULL, NULL, 0);
	      strcpy(name, candidate->target);
	      if (!strchr(name, '.'))
		{
		  strcat(name, ".");
		  strcat(name, zone->domain);
		}
	      found = 1;
	      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
				      daemon->auth_ttl, &nameoffset,
				      T_CNAME, C_IN, "d", name))
		anscount++;
	      
	      goto cname_restart;
	    }
	  else if (cache_find_non_terminal(name, now))
	    nxdomain = 0;

	  log_query(flag | F_NEG | (nxdomain ? F_NXDOMAIN : 0) | F_FORWARD | F_AUTH, name, NULL, NULL, 0);
	}
      
    }
  
  /* Add auth section */
  if (auth && zone)
    {
      char *authname;
      int newoffset, offset = 0;

      if (!subnet)
	authname = zone->domain;
      else
	{
	  /* handle NS and SOA for PTR records */
	  
	  authname = name;

	  if (!(subnet->flags & ADDRLIST_IPV6))
	    {
	      in_addr_t a = ntohl(subnet->addr.addr4.s_addr) >> 8;
	      char *p = name;
	      
	      if (subnet->prefixlen >= 24)
		p += sprintf(p, "%u.", a & 0xff);
	      a = a >> 8;
	      if (subnet->prefixlen >= 16 )
		p += sprintf(p, "%u.", a & 0xff);
	      a = a >> 8;
	      sprintf(p, "%u.in-addr.arpa", a & 0xff);
	      
	    }
	  else
	    {
	      char *p = name;
	      int i;
	      
	      for (i = subnet->prefixlen-1; i >= 0; i -= 4)
		{ 
		  int dig = ((unsigned char *)&subnet->addr.addr6)[i>>3];
		  p += sprintf(p, "%.1x.", (i>>2) & 1 ? dig & 15 : dig >> 4);
		}
	      sprintf(p, "ip6.arpa");
	      
	    }
	}
      
      /* handle NS and SOA in auth section or for explicit queries */
       newoffset = ansp - (unsigned char *)header;
       if (((anscount == 0 && !ns) || soa) &&
	  add_resource_record(header, limit, &trunc, 0, &ansp, 
			      daemon->auth_ttl, NULL, T_SOA, C_IN, "ddlllll",
			      authname, daemon->authserver,  daemon->hostmaster,
			      daemon->soa_sn, daemon->soa_refresh, 
			      daemon->soa_retry, daemon->soa_expiry, 
			      daemon->auth_ttl))
	{
	  offset = newoffset;
	  if (soa)
	    anscount++;
	  else
	    authcount++;
	}
      
      if (anscount != 0 || ns)
	{
	  struct name_list *secondary;
	  
	  /* Only include the machine running dnsmasq if it's acting as an auth server */
	  if (daemon->authinterface)
	    {
	      newoffset = ansp - (unsigned char *)header;
	      if (add_resource_record(header, limit, &trunc, -offset, &ansp, 
				      daemon->auth_ttl, NULL, T_NS, C_IN, "d", offset == 0 ? authname : NULL, daemon->authserver))
		{
		  if (offset == 0) 
		    offset = newoffset;
		  if (ns) 
		    anscount++;
		  else
		    authcount++;
		}
	    }

	  if (!subnet)
	    for (secondary = daemon->secondary_forward_server; secondary; secondary = secondary->next)
	      if (add_resource_record(header, limit, &trunc, offset, &ansp, 
				      daemon->auth_ttl, NULL, T_NS, C_IN, "d", secondary->name))
		{
		  if (ns) 
		    anscount++;
		  else
		    authcount++;
		}
	}
      
      if (axfr)
	{
	  for (rec = daemon->mxnames; rec; rec = rec->next)
	    if (in_zone(zone, rec->name, &cut))
	      {
		if (cut)
		   *cut = 0;

		if (rec->issrv)
		  {
		    if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl,
					    NULL, T_SRV, C_IN, "sssd", cut ? rec->name : NULL,
					    rec->priority, rec->weight, rec->srvport, rec->target))
		      
		      anscount++;
		  }
		else
		  {
		    if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl,
					    NULL, T_MX, C_IN, "sd", cut ? rec->name : NULL, rec->weight, rec->target))
		      anscount++;
		  }
		
		/* restore config data */
		if (cut)
		  *cut = '.';
	      }
	      
	  for (txt = daemon->rr; txt; txt = txt->next)
	    if (in_zone(zone, txt->name, &cut))
	      {
		if (cut)
		  *cut = 0;
		
		if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl,
					NULL, txt->class, C_IN, "t",  cut ? txt->name : NULL, txt->len, txt->txt))
		  anscount++;
		
		/* restore config data */
		if (cut)
		  *cut = '.';
	      }
	  
	  for (txt = daemon->txt; txt; txt = txt->next)
	    if (txt->class == C_IN && in_zone(zone, txt->name, &cut))
	      {
		if (cut)
		  *cut = 0;
		
		if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl,
					NULL, T_TXT, C_IN, "t", cut ? txt->name : NULL, txt->len, txt->txt))
		  anscount++;
		
		/* restore config data */
		if (cut)
		  *cut = '.';
	      }
	  
	  for (na = daemon->naptr; na; na = na->next)
	    if (in_zone(zone, na->name, &cut))
	      {
		if (cut)
		  *cut = 0;
		
		if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, daemon->auth_ttl, 
					NULL, T_NAPTR, C_IN, "sszzzd", cut ? na->name : NULL,
					na->order, na->pref, na->flags, na->services, na->regexp, na->replace))
		  anscount++;
		
		/* restore config data */
		if (cut)
		  *cut = '.'; 
	      }
	  
	  for (intr = daemon->int_names; intr; intr = intr->next)
	    if (in_zone(zone, intr->name, &cut))
	      {
		struct addrlist *addrlist;
		
		if (cut)
		  *cut = 0;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next) 
		  if (!(addrlist->flags & ADDRLIST_IPV6) &&
		      (local_query || filter_zone(zone, F_IPV4, &addrlist->addr)) && 
		      add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
					  daemon->auth_ttl, NULL, T_A, C_IN, "4", cut ? intr->name : NULL, &addrlist->addr))
		    anscount++;
		
		for (addrlist = intr->addr; addrlist; addrlist = addrlist->next) 
		  if ((addrlist->flags & ADDRLIST_IPV6) && 
		      (local_query || filter_zone(zone, F_IPV6, &addrlist->addr)) &&
		      add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
					  daemon->auth_ttl, NULL, T_AAAA, C_IN, "6", cut ? intr->name : NULL, &addrlist->addr))
		    anscount++;
		
		/* restore config data */
		if (cut)
		  *cut = '.'; 
	      }
             
	  for (a = daemon->cnames; a; a = a->next)
	    if (in_zone(zone, a->alias, &cut))
	      {
		strcpy(name, a->target);
		if (!strchr(name, '.'))
		  {
		    strcat(name, ".");
		    strcat(name, zone->domain);
		  }
		
		if (cut)
		  *cut = 0;
		
		if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
					daemon->auth_ttl, NULL,
					T_CNAME, C_IN, "d",  cut ? a->alias : NULL, name))
		  anscount++;
	      }
	
	  cache_enumerate(1);
	  while ((crecp = cache_enumerate(0)))
	    {
	      if ((crecp->flags & (F_IPV4 | F_IPV6)) &&
		  !(crecp->flags & (F_NEG | F_NXDOMAIN)) &&
		  (crecp->flags & F_FORWARD))
		{
		  if ((crecp->flags & F_DHCP) && !option_bool(OPT_DHCP_FQDN))
		    {
		      char *cache_name = cache_get_name(crecp);
		      if (!strchr(cache_name, '.') && 
			  (local_query || filter_zone(zone, (crecp->flags & (F_IPV6 | F_IPV4)), &(crecp->addr))) &&
			  add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
					      daemon->auth_ttl, NULL, (crecp->flags & F_IPV6) ? T_AAAA : T_A, C_IN, 
					      (crecp->flags & F_IPV4) ? "4" : "6", cache_name, &crecp->addr))
			anscount++;
		    }
		  
		  if ((crecp->flags & F_HOSTS) || (((crecp->flags & F_DHCP) && option_bool(OPT_DHCP_FQDN))))
		    {
		      strcpy(name, cache_get_name(crecp));
		      if (in_zone(zone, name, &cut) && 
			  (local_query || filter_zone(zone, (crecp->flags & (F_IPV6 | F_IPV4)), &(crecp->addr))))
			{
			  if (cut)
			    *cut = 0;

			  if (add_resource_record(header, limit, &trunc, -axfroffset, &ansp, 
						  daemon->auth_ttl, NULL, (crecp->flags & F_IPV6) ? T_AAAA : T_A, C_IN, 
						  (crecp->flags & F_IPV4) ? "4" : "6", cut ? name : NULL, &crecp->addr))
			    anscount++;
			}
		    }
		}
	    }
	   
	  /* repeat SOA as last record */
	  if (add_resource_record(header, limit, &trunc, axfroffset, &ansp, 
				  daemon->auth_ttl, NULL, T_SOA, C_IN, "ddlllll",
				  daemon->authserver,  daemon->hostmaster,
				  daemon->soa_sn, daemon->soa_refresh, 
				  daemon->soa_retry, daemon->soa_expiry, 
				  daemon->auth_ttl))
	    anscount++;
	  
	}
      
    }
  
  /* done all questions, set up header and return length of result */
  /* clear authoritative and truncated flags, set QR flag */
  header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC)) | HB3_QR;

  if (local_query)
    {
      /* set RA flag */
      header->hb4 |= HB4_RA;
    }
  else
    {
      /* clear RA flag */
      header->hb4 &= ~HB4_RA;
    }

  /* data is never DNSSEC signed. */
  header->hb4 &= ~HB4_AD;

  /* authoritative */
  if (auth)
    header->hb3 |= HB3_AA;
  
  /* truncation */
  if (trunc)
    header->hb3 |= HB3_TC;
  
  if ((auth || local_query) && nxdomain)
    SET_RCODE(header, NXDOMAIN);
  else
    SET_RCODE(header, NOERROR); /* no error */
  
  header->ancount = htons(anscount);
  header->nscount = htons(authcount);
  header->arcount = htons(0);

  if (!local_query && out_of_zone)
    {
      SET_RCODE(header, REFUSED); 
      header->ancount = htons(0);
      header->nscount = htons(0);
      addr.log.rcode = REFUSED;
      addr.log.ede = EDE_NOT_AUTH;
      log_query(F_UPSTREAM | F_RCODE, "error", &addr, NULL, 0);
      return resize_packet(header,  ansp - (unsigned char *)header, NULL, 0);
    }
  
  /* Advertise our packet size limit in our reply */
  if (have_pseudoheader)
    return add_pseudoheader(header,  ansp - (unsigned char *)header, (unsigned char *)limit, daemon->edns_pktsz, 0, NULL, 0, do_bit, 0);

  return ansp - (unsigned char *)header;
}
  
#endif  
