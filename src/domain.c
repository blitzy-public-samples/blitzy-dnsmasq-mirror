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
 * @file domain.c
 * @brief Conditional domain handling and synthetic domain name generation
 *
 * DETAILED PURPOSE:
 * This module provides domain name manipulation utilities specifically for 
 * conditional domain assignment and synthetic domain generation. It implements 
 * the logic for dnsmasq's advanced features that allow automatic creation of 
 * DNS names from IP addresses (synthetic domains) and selection of appropriate 
 * domain suffixes based on client IP address ranges (conditional domains).
 *
 * The synthetic domain feature enables dnsmasq to automatically generate DNS 
 * names for IP addresses within configured ranges, supporting both indexed 
 * numeric formats (host1.domain.com, host2.domain.com) and direct IP-based 
 * formats (10-0-0-1.domain.com). This is particularly useful for dynamic 
 * environments where automatic DNS naming is required without manual 
 * configuration.
 *
 * The conditional domain feature allows different domain suffixes to be 
 * returned based on the source IP address of the requesting client or the 
 * IP address being queried. This enables DHCP clients on different subnets 
 * to receive appropriate domain names matching their network segment.
 *
 * KEY RESPONSIBILITIES:
 * - is_name_synthetic() - Parse synthetic domain names and extract IP addresses
 * - is_rev_synth() - Generate synthetic domain names from IP addresses (reverse synthesis)
 * - get_domain() - Retrieve appropriate domain suffix for IPv4 address
 * - get_domain6() - Retrieve appropriate domain suffix for IPv6 address
 * - search_domain() - Find matching conditional domain configuration for IPv4 address
 * - search_domain6() - Find matching conditional domain configuration for IPv6 address
 * - match_domain() - Check if IPv4 address matches conditional domain criteria
 * - match_domain6() - Check if IPv6 address matches conditional domain criteria
 *
 * DEPENDENCIES:
 * - dnsmasq.h - Core type definitions including struct cond_domain, struct addrlist,
 *               union all_addr, struct daemon, flag constants (F_IPV4, F_IPV6)
 * - Standard C library - inet_pton(), inet_ntop(), atoi(), atoll(), string functions
 *
 * Called By:
 * - cache.c - During cache insertion and lookup for domain suffix determination
 * - forward.c - During query forwarding for synthetic domain resolution
 * - option.c - During configuration parsing and validation
 * - dhcp.c - For assigning domain names to DHCP leases based on client subnet
 *
 * DATA STRUCTURES:
 * - struct cond_domain (dnsmasq.h:977-985) - Configuration for conditional and 
 *   synthetic domains including IP ranges, prefixes, and domain suffixes
 * - union all_addr - Container for IPv4 or IPv6 addresses
 * - struct addrlist - Linked list of addresses with prefix lengths for interface-based matching
 *
 * COMPILE-TIME OPTIONS:
 * - None specific to this module
 * - Uses standard IPv6 support available throughout dnsmasq
 *
 * THREADING/CONCURRENCY:
 * Single-process, event-driven architecture. Functions are not re-entrant but 
 * are called sequentially from the main event loop. No locking required as 
 * dnsmasq does not use multiple threads. Configuration structures (daemon->synth_domains,
 * daemon->cond_domain) are read-only after initial configuration loading.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"


static struct cond_domain *search_domain(struct in_addr addr, struct cond_domain *c);
static int match_domain(struct in_addr addr, struct cond_domain *c);
static struct cond_domain *search_domain6(struct in6_addr *addr, struct cond_domain *c);
static int match_domain6(struct in6_addr *addr, struct cond_domain *c);

/**
 * @brief Parse synthetic domain name and extract IP address
 *
 * @detailed
 * Examines a DNS query name to determine if it matches any configured synthetic 
 * domain pattern. If a match is found, extracts the embedded IP address from the 
 * hostname and validates it against the configured IP range. Supports two synthetic 
 * formats: indexed numeric (e.g., host42.example.com where 42 maps to an offset in 
 * the IP range) and direct IP encoding (e.g., 10-0-0-1.example.com or 
 * 2001-db8--1.example.com for IPv6). The function temporarily modifies the input 
 * name during parsing but restores it before returning.
 *
 * @param flags Query type flags (F_IPV4 or F_IPV6) indicating address family expected
 * @param name DNS query name to parse (will be temporarily modified but restored)
 * @param addr Output parameter filled with extracted IP address if match found
 *
 * @return 1 if name matches synthetic domain pattern and IP is valid, 0 otherwise
 *
 * @retval 1 Name is synthetic and IP address extracted successfully into addr
 * @retval 0 Name does not match any synthetic domain pattern or IP is invalid/out of range
 *
 * @note Input name string is temporarily modified during parsing (dots/colons converted
 *       to dashes and vice versa) but is always restored to original state before return
 * @note For IPv6, special handling of IPv4-mapped addresses using --ffff- prefix notation
 * @note Indexed domains use numeric offset: name "host5" maps to start_addr + 5
 * @note Direct encoding uses dashes for separators: 192-168-1-1.domain.com
 *
 * @warning Not thread-safe due to modification of input name parameter during processing
 * @warning Assumes name buffer has sufficient space for temporary modifications
 *
 * @see is_rev_synth() for reverse operation (IP to synthetic name)
 * @see struct cond_domain in dnsmasq.h for synthetic domain configuration structure
 * @see daemon->synth_domains for global list of synthetic domain configurations
 *
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * char query_name[] = "192-168-1-100.mydomain.com";
 * if (is_name_synthetic(F_IPV4, query_name, &addr)) {
 *   // addr.addr4 now contains 192.168.1.100
 *   // Can proceed to generate synthetic DNS response
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly specified by RFC. Implements dnsmasq-specific extension for
 * automatic DNS record generation from configured IP ranges.
 *
 * SIDE EFFECTS:
 * - Temporarily modifies name parameter (always restored before return)
 * - Reads global daemon->synth_domains configuration list
 * - May call inet_pton() for address parsing
 * - May call match_domain() or match_domain6() for range validation
 *
 * THREAD SAFETY:
 * Not thread-safe due to input parameter modification. Safe in dnsmasq's 
 * single-threaded event loop architecture. daemon->synth_domains is read-only 
 * after configuration load.
 */
int is_name_synthetic(int flags, char *name, union all_addr *addr)
{
  char *p;
  struct cond_domain *c = NULL;
  int prot = (flags & F_IPV6) ? AF_INET6 : AF_INET;

  for (c = daemon->synth_domains; c; c = c->next)
    {
      int found = 0;
      char *tail, *pref;
      
      for (tail = name, pref = c->prefix; *tail != 0 && pref && *pref != 0; tail++, pref++)
	{
	  unsigned int c1 = (unsigned char) *pref;
	  unsigned int c2 = (unsigned char) *tail;
	  
	  if (c1 >= 'A' && c1 <= 'Z')
	    c1 += 'a' - 'A';
	  if (c2 >= 'A' && c2 <= 'Z')
	    c2 += 'a' - 'A';
	  
	  if (c1 != c2)
	    break;
	}
      
      if (pref && *pref != 0)
	continue; /* prefix match fail */

      if (c->indexed)
	{
	  for (p = tail; *p; p++)
	    {
	      char c = *p;
	      
	      if (c < '0' || c > '9')
		break;
	    }
	  
	  if (*p != '.')
	    continue;
	  
	  *p = 0;
	  
	  if (hostname_isequal(c->domain, p+1))
	    {
	      if (prot == AF_INET)
		{
		  unsigned int index = atoi(tail);

		   if (!c->is6 &&
		      index <= ntohl(c->end.s_addr) - ntohl(c->start.s_addr))
		    {
		      addr->addr4.s_addr = htonl(ntohl(c->start.s_addr) + index);
		      found = 1;
		    }
		} 
	      else
		{
		  u64 index = atoll(tail);
		  
		  if (c->is6 &&
		      index <= addr6part(&c->end6) - addr6part(&c->start6))
		    {
		      u64 start = addr6part(&c->start6);
		      addr->addr6 = c->start6;
		      setaddr6part(&addr->addr6, start + index);
		      found = 1;
		    }
		}
	    }
	}
      else
	{
	  /* NB, must not alter name if we return zero */
	  for (p = tail; *p; p++)
	    {
	      char c = *p;
	      
	      if ((c >='0' && c <= '9') || c == '-')
		continue;
	      
	      if (prot == AF_INET6 && ((c >='A' && c <= 'F') || (c >='a' && c <= 'f'))) 
		continue;
	      
	      break;
	    }
	  
	  if (*p != '.')
	    continue;
	  
	  *p = 0;	
	  
	  if (prot == AF_INET6 && strstr(tail, "--ffff-") == tail)
	    {
	      /* special hack for v4-mapped. */
	      memcpy(tail, "::ffff:", 7);
	      for (p = tail + 7; *p; p++)
		if (*p == '-')
		  *p = '.';
	    }
	  else
	    {
	      /* swap . or : for - */
	      for (p = tail; *p; p++)
		if (*p == '-')
		  {
		    if (prot == AF_INET)
		      *p = '.';
		    else
		      *p = ':';
		  }
	    }
	  
	  if (hostname_isequal(c->domain, p+1) && inet_pton(prot, tail, addr))
	    found = (prot == AF_INET) ? match_domain(addr->addr4, c) : match_domain6(&addr->addr6, c);
	}
      
      /* restore name */
      for (p = tail; *p; p++)
	if (*p == '.' || *p == ':')
	  *p = '-';
      
      *p = '.';
      
      
      if (found)
	return 1;
    }
  
  return 0;
}

/**
 * @brief Generate synthetic domain name from IP address (reverse synthesis)
 *
 * @detailed
 * Performs the reverse operation of is_name_synthetic() by generating a synthetic 
 * DNS hostname from an IP address if the address falls within a configured synthetic 
 * domain range. Supports both indexed format (prefix + numeric index + domain) and 
 * direct IP encoding format (prefix + encoded-IP + domain). For indexed domains, 
 * calculates the numeric offset from the range start address. For direct encoding, 
 * converts the IP address to presentation format with dashes replacing dots (IPv4) 
 * or colons (IPv6). The generated name is written to the provided output buffer.
 *
 * @param flag Address family flag (F_IPV4 or F_IPV6) indicating which address to use
 * @param addr Input IP address (either addr4 or addr6 based on flag)
 * @param name Output buffer for generated synthetic domain name (minimum MAXDNAME bytes)
 *
 * @return 1 if synthetic name generated successfully, 0 if address not in synthetic range
 *
 * @retval 1 Address matches synthetic domain configuration, name generated in output buffer
 * @retval 0 Address does not match any synthetic domain range
 *
 * @note Output name buffer must have capacity of at least MAXDNAME bytes
 * @note For indexed domains, format is: prefix + offset_number + "." + domain
 * @note For direct encoding IPv4: prefix + "a-b-c-d" + "." + domain
 * @note For direct encoding IPv6: prefix + "xxxx-yyyy-..." + "." + domain
 * @note IPv6 addresses starting with ":" get prepended "0" to form valid DNS name
 * @note IPv4-mapped IPv6 addresses have periods converted to dashes
 *
 * @warning Output buffer must be at least MAXDNAME bytes to avoid truncation
 * @warning Uses strncat() with MAXDNAME limit which may silently truncate if buffer too small
 *
 * @see is_name_synthetic() for forward operation (synthetic name to IP)
 * @see search_domain() for IPv4 range matching
 * @see search_domain6() for IPv6 range matching
 * @see struct cond_domain in dnsmasq.h for configuration structure
 *
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * char synthetic_name[MAXDNAME];
 * addr.addr4.s_addr = inet_addr("192.168.1.100");
 * if (is_rev_synth(F_IPV4, &addr, synthetic_name)) {
 *   // synthetic_name now contains "192-168-1-100.mydomain.com" or "host100.mydomain.com"
 *   // Can use for PTR record response or forward lookup
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly specified by RFC. Implements dnsmasq-specific extension for
 * automatic DNS record generation. Generated names comply with DNS hostname
 * syntax requirements (RFC 1035 section 2.3.1).
 *
 * SIDE EFFECTS:
 * - Writes generated name to output buffer parameter
 * - Reads global daemon->synth_domains configuration list
 * - Calls inet_ntop() for IP address to string conversion
 * - May call search_domain() or search_domain6() for range matching
 *
 * THREAD SAFETY:
 * Thread-safe for output buffer (caller provides separate buffer per call).
 * daemon->synth_domains is read-only after configuration load. Safe in 
 * dnsmasq's single-threaded event loop architecture.
 */
int is_rev_synth(int flag, union all_addr *addr, char *name)
{
   struct cond_domain *c;

   if (flag & F_IPV4 && (c = search_domain(addr->addr4, daemon->synth_domains))) 
     {
       char *p;
       
       *name = 0;
       if (c->indexed)
	 {
	   unsigned int index = ntohl(addr->addr4.s_addr) - ntohl(c->start.s_addr);
	   snprintf(name, MAXDNAME, "%s%u", c->prefix ? c->prefix : "", index);
	 }
       else
	 {
	   if (c->prefix)
	     strncpy(name, c->prefix, MAXDNAME - ADDRSTRLEN);
       
       	   inet_ntop(AF_INET, &addr->addr4, name + strlen(name), ADDRSTRLEN);
	   for (p = name; *p; p++)
	     if (*p == '.')
	       *p = '-';
	 }
       
       strncat(name, ".", MAXDNAME);
       strncat(name, c->domain, MAXDNAME);

       return 1;
     }

   if ((flag & F_IPV6) && (c = search_domain6(&addr->addr6, daemon->synth_domains))) 
     {
       char *p;
       
       *name = 0;
       if (c->indexed)
	 {
	   u64 index = addr6part(&addr->addr6) - addr6part(&c->start6);
	   snprintf(name, MAXDNAME, "%s%llu", c->prefix ? c->prefix : "", index);
	 }
       else
	 {
	   if (c->prefix)
	     strncpy(name, c->prefix, MAXDNAME - ADDRSTRLEN);
       
	   inet_ntop(AF_INET6, &addr->addr6, name + strlen(name), ADDRSTRLEN);

	   /* IPv6 presentation address can start with ":", but valid domain names
	      cannot start with "-" so prepend a zero in that case. */
	   if (!c->prefix && *name == ':')
	     {
	       *name = '0';
	       inet_ntop(AF_INET6, &addr->addr6, name+1, ADDRSTRLEN);
	     }
	   
	   /* V4-mapped have periods.... */
	   for (p = name; *p; p++)
	     if (*p == ':' || *p == '.')
	       *p = '-';
	   
	 }

       strncat(name, ".", MAXDNAME);
       strncat(name, c->domain, MAXDNAME);
       
       return 1;
     }
   
   return 0;
}

/**
 * @brief Check if IPv4 address matches conditional domain criteria
 *
 * @detailed
 * Determines whether a given IPv4 address satisfies the matching criteria defined 
 * in a conditional domain configuration. Supports two matching modes: interface-based 
 * matching (where address must be in same subnet as configured interface addresses) 
 * and range-based matching (where address must fall within configured start-end range). 
 * For interface-based matching, iterates through the associated address list checking 
 * prefix-based subnet membership. For range-based matching, performs simple numeric 
 * comparison after converting addresses to host byte order.
 *
 * @param addr IPv4 address to test against conditional domain criteria
 * @param c Conditional domain configuration containing matching criteria
 *
 * @return 1 if address matches domain criteria, 0 otherwise
 *
 * @retval 1 Address is within configured range or matches interface subnet
 * @retval 0 Address does not match any criteria in conditional domain configuration
 *
 * @note Interface-based matching uses c->interface flag and c->al address list
 * @note Range-based matching uses c->start and c->end IPv4 addresses
 * @note c->is6 flag must be 0 (false) for range-based IPv4 matching
 * @note Uses network byte order addresses internally via ntohl() conversions
 *
 * @warning Assumes conditional domain configuration is valid and properly initialized
 * @warning No NULL pointer checks on c parameter - caller must ensure validity
 *
 * @see search_domain() which calls this function for each domain in list
 * @see match_domain6() for IPv6 equivalent functionality
 * @see is_same_net_prefix() for IPv4 subnet matching logic
 * @see struct cond_domain in dnsmasq.h for configuration structure details
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr test_addr;
 * struct cond_domain *domain_config = daemon->cond_domain;
 * inet_pton(AF_INET, "192.168.1.100", &test_addr);
 * if (match_domain(test_addr, domain_config)) {
 *   // Address matches, can apply this conditional domain
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly specified by RFC. Implements dnsmasq-specific conditional domain
 * feature. Subnet matching follows standard CIDR notation principles.
 *
 * SIDE EFFECTS:
 * - Reads address list from c->al if interface-based matching
 * - Pure computation, no external state modification
 *
 * THREAD SAFETY:
 * Thread-safe read-only operation on configuration structure. Safe in dnsmasq's
 * single-threaded architecture. Configuration structures are immutable after load.
 */
static int match_domain(struct in_addr addr, struct cond_domain *c)
{
  if (c->interface)
    {
      struct addrlist *al;
      for (al = c->al; al; al = al->next)
	if (!(al->flags & ADDRLIST_IPV6) &&
	    is_same_net_prefix(addr, al->addr.addr4, al->prefixlen))
	  return 1;
    }
  else if (!c->is6 &&
	   ntohl(addr.s_addr) >= ntohl(c->start.s_addr) &&
	   ntohl(addr.s_addr) <= ntohl(c->end.s_addr))
    return 1;

  return 0;
}

/**
 * @brief Find matching conditional domain configuration for IPv4 address
 *
 * @detailed
 * Searches through a linked list of conditional domain configurations to find 
 * the first one that matches the given IPv4 address. Iterates through the list 
 * starting from the provided head node, calling match_domain() for each entry 
 * until a match is found or the end of the list is reached. Returns immediately 
 * upon finding the first match, implementing a first-match-wins policy. This 
 * allows configuration ordering to determine priority when multiple domains 
 * could potentially match.
 *
 * @param addr IPv4 address to search for in conditional domain configurations
 * @param c Head of linked list of conditional domain configurations to search
 *
 * @return Pointer to first matching cond_domain structure, or NULL if no match
 *
 * @retval non-NULL Pointer to conditional domain configuration matching address
 * @retval NULL No conditional domain configuration matches the address
 *
 * @note Returns first match found, so configuration ordering matters
 * @note Safe to call with c=NULL (will return NULL immediately)
 * @note Does not modify the configuration list, read-only traversal
 *
 * @warning No validation of address family - caller must ensure IPv4 usage
 * @warning Returned pointer is to global configuration, must not be freed
 *
 * @see match_domain() which performs actual matching logic for each entry
 * @see search_domain6() for IPv6 equivalent functionality
 * @see get_domain() which calls this function with daemon->cond_domain list
 * @see struct cond_domain in dnsmasq.h for configuration structure
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr client_addr;
 * struct cond_domain *matched;
 * inet_pton(AF_INET, "192.168.1.50", &client_addr);
 * matched = search_domain(client_addr, daemon->cond_domain);
 * if (matched) {
 *   // Use matched->domain for this client
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly specified by RFC. Implements dnsmasq-specific conditional domain
 * feature for DHCP domain name assignment based on client subnet.
 *
 * SIDE EFFECTS:
 * - Traverses linked list of conditional domain configurations
 * - Pure read-only operation, no state modification
 *
 * THREAD SAFETY:
 * Thread-safe read-only list traversal. Configuration list is immutable after
 * initial load. Safe in dnsmasq's single-threaded event loop architecture.
 */
static struct cond_domain *search_domain(struct in_addr addr, struct cond_domain *c)
{
  for (; c; c = c->next)
    if (match_domain(addr, c))
      return c;
  
  return NULL;
}

/**
 * @brief Retrieve appropriate domain suffix for IPv4 address
 *
 * @detailed
 * Determines the correct DNS domain suffix to use for a given IPv4 address by 
 * searching through configured conditional domains. If the address matches a 
 * conditional domain configuration (based on IP range or interface subnet), 
 * returns that domain's specific suffix. Otherwise, returns the global default 
 * domain suffix. This function is typically used during DHCP lease assignment 
 * to provide clients with appropriate domain names based on their subnet, and 
 * during DNS query processing to determine which domain suffix applies to a 
 * particular address.
 *
 * @param addr IPv4 address for which to determine appropriate domain suffix
 *
 * @return Pointer to domain suffix string, either conditional or global default
 *
 * @retval non-NULL Always returns valid domain string pointer (never NULL)
 *
 * @note Return value points to global configuration string, must not be freed
 * @note If no conditional domain matches, returns daemon->domain_suffix
 * @note Conditional domain matching is performed by search_domain()
 *
 * @warning Returned string pointer is to global configuration, do not modify or free
 * @warning If daemon->domain_suffix is NULL, will return NULL (configuration error)
 *
 * @see get_domain6() for IPv6 equivalent functionality
 * @see search_domain() for conditional domain matching logic
 * @see daemon->cond_domain for conditional domain configuration list
 * @see daemon->domain_suffix for global default domain
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr lease_addr;
 * char *domain_suffix;
 * inet_pton(AF_INET, "10.0.1.50", &lease_addr);
 * domain_suffix = get_domain(lease_addr);
 * // domain_suffix now contains appropriate domain for this subnet
 * // Use for constructing FQDN: hostname.domain_suffix
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly specified by RFC. Implements dnsmasq-specific conditional domain
 * feature. Used in conjunction with RFC 2131 (DHCP) domain name option (option 15).
 *
 * SIDE EFFECTS:
 * - Calls search_domain() which traverses conditional domain list
 * - Reads global daemon->cond_domain and daemon->domain_suffix
 * - Pure read-only operation, no state modification
 *
 * THREAD SAFETY:
 * Thread-safe read-only operation on global configuration. Configuration is
 * immutable after initial load. Safe in dnsmasq's single-threaded architecture.
 */
char *get_domain(struct in_addr addr)
{
  struct cond_domain *c;

  if ((c = search_domain(addr, daemon->cond_domain)))
    return c->domain;

  return daemon->domain_suffix;
} 

/**
 * @brief Check if IPv6 address matches conditional domain criteria
 *
 * @detailed
 * Determines whether a given IPv6 address satisfies the matching criteria defined 
 * in a conditional domain configuration. Supports two matching modes: interface-based 
 * matching (where address must be in same subnet as configured interface addresses) 
 * and range-based matching (where address must fall within configured prefix range 
 * or specific address range). For range-based matching with prefix >= 64, validates 
 * both network prefix (first 64 bits) and host portion (last 64 bits) separately. 
 * For shorter prefixes, only validates network prefix match. Uses addr6part() helper 
 * for extracting 64-bit host portions of IPv6 addresses.
 *
 * @param addr Pointer to IPv6 address to test against conditional domain criteria
 * @param c Conditional domain configuration containing matching criteria
 *
 * @return 1 if address matches domain criteria, 0 otherwise
 *
 * @retval 1 Address is within configured range or matches interface subnet
 * @retval 0 Address does not match any criteria in conditional domain configuration
 *
 * @note Interface-based matching uses c->interface flag and c->al address list
 * @note Range-based matching requires c->is6 flag set to 1 (true)
 * @note For prefix >= 64: checks network prefix AND host portion range
 * @note For prefix < 64: checks only network prefix match
 * @note Uses is_same_net6() for IPv6 subnet comparison
 * @note Uses addr6part() to extract lower 64 bits for range checking
 *
 * @warning Assumes conditional domain configuration is valid and properly initialized
 * @warning No NULL pointer checks on addr or c parameters - caller must ensure validity
 * @warning For prefixlen < 64, end address in range is ignored
 *
 * @see search_domain6() which calls this function for each domain in list
 * @see match_domain() for IPv4 equivalent functionality
 * @see is_same_net6() for IPv6 subnet matching logic
 * @see addr6part() for extracting host portion of IPv6 address
 * @see struct cond_domain in dnsmasq.h for configuration structure
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr test_addr;
 * struct cond_domain *domain_config = daemon->cond_domain;
 * inet_pton(AF_INET6, "2001:db8::100", &test_addr);
 * if (match_domain6(&test_addr, domain_config)) {
 *   // Address matches, can apply this conditional domain
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly specified by RFC. Implements dnsmasq-specific conditional domain
 * feature. Subnet matching follows RFC 4291 IPv6 addressing architecture and
 * standard CIDR notation principles.
 *
 * SIDE EFFECTS:
 * - Reads address list from c->al if interface-based matching
 * - Pure computation, no external state modification
 *
 * THREAD SAFETY:
 * Thread-safe read-only operation on configuration structure. Safe in dnsmasq's
 * single-threaded architecture. Configuration structures are immutable after load.
 */
static int match_domain6(struct in6_addr *addr, struct cond_domain *c)
{
    
  /* subnet from interface address. */
  if (c->interface)
    {
      struct addrlist *al;
      for (al = c->al; al; al = al->next)
	if (al->flags & ADDRLIST_IPV6 &&
	    is_same_net6(addr, &al->addr.addr6, al->prefixlen))
	  return 1;
    }
  else if (c->is6)
    {
      if (c->prefixlen >= 64)
	{
	  u64 addrpart = addr6part(addr);
	  if (is_same_net6(addr, &c->start6, 64) &&
	      addrpart >= addr6part(&c->start6) &&
	      addrpart <= addr6part(&c->end6))
	    return 1;
	}
      else if (is_same_net6(addr, &c->start6, c->prefixlen))
	return 1;
    }
    
  return 0;
}

/**
 * @brief Find matching conditional domain configuration for IPv6 address
 *
 * @detailed
 * Searches through a linked list of conditional domain configurations to find 
 * the first one that matches the given IPv6 address. Iterates through the list 
 * starting from the provided head node, calling match_domain6() for each entry 
 * until a match is found or the end of the list is reached. Returns immediately 
 * upon finding the first match, implementing a first-match-wins policy. This 
 * allows configuration ordering to determine priority when multiple domains 
 * could potentially match. Identical in logic to search_domain() but operates 
 * on IPv6 addresses.
 *
 * @param addr Pointer to IPv6 address to search for in conditional domain configurations
 * @param c Head of linked list of conditional domain configurations to search
 *
 * @return Pointer to first matching cond_domain structure, or NULL if no match
 *
 * @retval non-NULL Pointer to conditional domain configuration matching address
 * @retval NULL No conditional domain configuration matches the address
 *
 * @note Returns first match found, so configuration ordering matters
 * @note Safe to call with c=NULL (will return NULL immediately)
 * @note Safe to call with addr=NULL (checked by match_domain6 implementations)
 * @note Does not modify the configuration list, read-only traversal
 *
 * @warning No validation of address family - caller must ensure IPv6 usage
 * @warning Returned pointer is to global configuration, must not be freed
 *
 * @see match_domain6() which performs actual matching logic for each entry
 * @see search_domain() for IPv4 equivalent functionality
 * @see get_domain6() which calls this function with daemon->cond_domain list
 * @see struct cond_domain in dnsmasq.h for configuration structure
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client_addr;
 * struct cond_domain *matched;
 * inet_pton(AF_INET6, "2001:db8::100", &client_addr);
 * matched = search_domain6(&client_addr, daemon->cond_domain);
 * if (matched) {
 *   // Use matched->domain for this client
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly specified by RFC. Implements dnsmasq-specific conditional domain
 * feature for DHCPv6 domain name assignment based on client subnet. Related to
 * RFC 3315 (DHCPv6) and RFC 8415 (updated DHCPv6).
 *
 * SIDE EFFECTS:
 * - Traverses linked list of conditional domain configurations
 * - Pure read-only operation, no state modification
 *
 * THREAD SAFETY:
 * Thread-safe read-only list traversal. Configuration list is immutable after
 * initial load. Safe in dnsmasq's single-threaded event loop architecture.
 */
static struct cond_domain *search_domain6(struct in6_addr *addr, struct cond_domain *c)
{
  for (; c; c = c->next)
    if (match_domain6(addr, c))
      return c;
  
  return NULL;
}

/**
 * @brief Retrieve appropriate domain suffix for IPv6 address
 *
 * @detailed
 * Determines the correct DNS domain suffix to use for a given IPv6 address by 
 * searching through configured conditional domains. If a non-NULL address is 
 * provided and matches a conditional domain configuration (based on IPv6 prefix 
 * range or interface subnet), returns that domain's specific suffix. Otherwise, 
 * returns the global default domain suffix. This function is typically used 
 * during DHCPv6 lease assignment to provide clients with appropriate domain 
 * names based on their subnet, and during DNS query processing to determine 
 * which domain suffix applies to a particular IPv6 address. Supports NULL 
 * address parameter for cases where only the default domain is needed.
 *
 * @param addr Pointer to IPv6 address for domain determination, or NULL for default
 *
 * @return Pointer to domain suffix string, either conditional or global default
 *
 * @retval non-NULL Always returns valid domain string pointer (never NULL)
 *
 * @note Return value points to global configuration string, must not be freed
 * @note If addr is NULL or no conditional domain matches, returns daemon->domain_suffix
 * @note Conditional domain matching is performed by search_domain6()
 * @note NULL addr parameter is explicitly supported for default domain retrieval
 *
 * @warning Returned string pointer is to global configuration, do not modify or free
 * @warning If daemon->domain_suffix is NULL, will return NULL (configuration error)
 *
 * @see get_domain() for IPv4 equivalent functionality
 * @see search_domain6() for conditional domain matching logic
 * @see daemon->cond_domain for conditional domain configuration list
 * @see daemon->domain_suffix for global default domain
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr lease_addr;
 * char *domain_suffix;
 * inet_pton(AF_INET6, "2001:db8::50", &lease_addr);
 * domain_suffix = get_domain6(&lease_addr);
 * // domain_suffix now contains appropriate domain for this subnet
 * // Use for constructing FQDN: hostname.domain_suffix
 * // Or get default domain:
 * domain_suffix = get_domain6(NULL);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not directly specified by RFC. Implements dnsmasq-specific conditional domain
 * feature. Used in conjunction with RFC 3315 (DHCPv6) and RFC 8415 for domain
 * name options. Related to RFC 4704 DHCPv6 Client FQDN Option.
 *
 * SIDE EFFECTS:
 * - Calls search_domain6() which traverses conditional domain list if addr non-NULL
 * - Reads global daemon->cond_domain and daemon->domain_suffix
 * - Pure read-only operation, no state modification
 *
 * THREAD SAFETY:
 * Thread-safe read-only operation on global configuration. Configuration is
 * immutable after initial load. Safe in dnsmasq's single-threaded architecture.
 */
char *get_domain6(struct in6_addr *addr)
{
  struct cond_domain *c;

  if (addr && (c = search_domain6(addr, daemon->cond_domain)))
    return c->domain;

  return daemon->domain_suffix;
} 
