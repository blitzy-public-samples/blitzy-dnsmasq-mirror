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
 * @file domain-match.c
 * @brief Domain name matching and server selection for DNS query routing
 *
 * DETAILED PURPOSE:
 * This file implements domain-based server selection for DNS forwarding, enabling
 * dnsmasq to route different DNS queries to different upstream servers based on
 * domain name patterns. The implementation uses a binary search algorithm on a sorted
 * server array for efficient longest-suffix matching, allowing queries like
 * "www.example.com" to match servers configured for "example.com" or ".com" with
 * appropriate precedence.
 *
 * The module handles wildcard matching (*.example.com), short name handling via
 * NODOTS servers, and complex filtering based on IPv4/IPv6 address families, DNSSEC
 * capability requirements, and local vs upstream server types. It integrates with the
 * DNS forwarding pipeline in forward.c to determine which upstream servers should
 * receive each query, and with option.c for server configuration management.
 *
 * Server organization follows a hierarchical specificity model: most-specific domains
 * are searched first (longest suffix match), followed by progressively shorter domain
 * suffixes, with NODOTS servers as fallback for unqualified names. The sorted server
 * array enables O(log n) lookup performance for domain matching operations.
 *
 * KEY RESPONSIBILITIES:
 * - build_server_array(): Construct and sort the global server array for binary search
 * - lookup_domain(): Perform longest-suffix domain matching with binary search
 * - filter_servers(): Apply flag-based filtering (DNSSEC, IPv4/IPv6, local/upstream)
 * - is_local_answer(): Determine if query has local answer (hosts file, literal address)
 * - make_local_answer(): Generate DNS response from local data sources
 * - dnssec_server(): Find DNSSEC-capable server for validation queries
 * - server_samegroup(): Check server equivalence for round-robin grouping
 * - mark_servers(): Set flags on servers for configuration reload
 * - cleanup_servers(): Remove marked servers from configuration
 * - add_update_server(): Add new or update existing server configuration
 *
 * DEPENDENCIES:
 * - Includes: dnsmasq.h (struct server, struct daemon, all type definitions)
 * - Called by: forward.c (query routing), option.c (server configuration management)
 * - Calls: whine_malloc() for memory allocation, canonicalise() for domain normalization,
 *   hostname_isequal() for domain comparison, setup_reply() and add_resource_record()
 *   for local answer generation, check_for_local_domain() for hosts file integration
 *
 * DATA STRUCTURES:
 * - daemon->serverarray: Sorted array of struct server* for binary search (lines 26-89)
 * - daemon->servers: Linked list of upstream servers (lines 31-77)
 * - daemon->local_domains: Linked list of local domain servers (lines 41-46)
 * - struct server: Server definition with domain, flags, address (defined in dnsmasq.h)
 * - struct serv_addr4/serv_addr6: IPv4/IPv6 literal address servers (lines 414-429)
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_LOOP: Enables loop detection, excludes SERV_LOOP servers from array (lines 32-34, 69-71)
 * - HAVE_DNSSEC: Enables dnssec_server() function for DNSSEC validation routing (lines 448-477)
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Functions modify global daemon state
 * (serverarray, servers, local_domains) and are not thread-safe. Called from main
 * event loop context only. No locking required due to single-threaded execution model.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

static int order(char *qdomain, size_t qlen, struct server *serv);
static int order_qsort(const void *a, const void *b);
static int order_servers(struct server *s, struct server *s2);

/* If the server is USE_RESOLV or LITERAL_ADDRES, it lives on the local_domains chain. */
#define SERV_IS_LOCAL (SERV_USE_RESOLV | SERV_LITERAL_ADDRESS)

/**
 * @brief Build and sort the server array for efficient domain lookups
 *
 * @detailed Constructs the sorted server array (daemon->serverarray) by counting servers
 * from daemon->servers and daemon->local_domains chains, allocating or reallocating
 * the array with 10-element hysteresis to avoid frequent reallocations, populating
 * the array with server pointers, and sorting by domain specificity using qsort with
 * the order_qsort() comparator. Sets arrayposn field for upstream servers to enable
 * efficient equivalence group lookups. Excludes SERV_LOOP servers if HAVE_LOOP is defined.
 *
 * @return void
 *
 * @note Must be called after any server configuration changes (add/remove servers).
 * Sets daemon->server_has_wildcard flag if any server has SERV_WILDCARD flag.
 * Array is sorted longest-domain-first for binary search efficiency in lookup_domain().
 * The 10-element hysteresis prevents frequent reallocations during dynamic updates.
 *
 * @warning Modifies global daemon state: serverarray, serverarraysz, serverarrayhwm,
 * and server_has_wildcard. Sets server->serial for strict-order processing and
 * server->arrayposn for upstream servers to enable group lookups.
 *
 * @see order_qsort() for sorting comparator implementation
 * @see lookup_domain() for binary search usage of the sorted array
 * @see add_update_server() for server addition that requires array rebuild
 *
 * EXAMPLE USAGE:
 * @code
 * // After configuration reload
 * read_opts(argc, argv);
 * build_server_array();  // Rebuild sorted array with new servers
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates memory via whine_malloc() for serverarray (with hysteresis)
 * - Sets server->serial field to array index for each server
 * - Sets server->arrayposn field for upstream servers (not local)
 * - Sets server->last_server to -1 for all servers
 * - Sets daemon->server_has_wildcard global flag
 * - Frees old serverarray if reallocating
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon state without locking. Must be called
 * from main event loop context only in single-threaded execution model.
 */
void build_server_array(void)
{
  struct server *serv;
  int count = 0;
  
  for (serv = daemon->servers; serv; serv = serv->next)
#ifdef HAVE_LOOP
    if (!(serv->flags & SERV_LOOP))
#endif
      {
	count++;
	if (serv->flags & SERV_WILDCARD)
	  daemon->server_has_wildcard = 1;
      }
  
  for (serv = daemon->local_domains; serv; serv = serv->next)
    {
      count++;
      if (serv->flags & SERV_WILDCARD)
	daemon->server_has_wildcard = 1;
    }
  
  daemon->serverarraysz = count;

  if (count > daemon->serverarrayhwm)
    {
      struct server **new;

      count += 10; /* A few extra without re-allocating. */

      if ((new = whine_malloc(count * sizeof(struct server *))))
	{
	  if (daemon->serverarray)
	    free(daemon->serverarray);
	  
	  daemon->serverarray = new;
	  daemon->serverarrayhwm = count;
	}
    }

  count = 0;
  
  for (serv = daemon->servers; serv; serv = serv->next)
#ifdef HAVE_LOOP
    if (!(serv->flags & SERV_LOOP))
#endif
      {
	daemon->serverarray[count] = serv;
	serv->serial = count;
	serv->last_server = -1;
	count++;
      }
  
  for (serv = daemon->local_domains; serv; serv = serv->next, count++)
    daemon->serverarray[count] = serv;
  
  qsort(daemon->serverarray, daemon->serverarraysz, sizeof(struct server *), order_qsort);
  
  /* servers need the location in the array to find all the whole
     set of equivalent servers from a pointer to a single one. */
  for (count = 0; count < daemon->serverarraysz; count++)
    if (!(daemon->serverarray[count]->flags & SERV_IS_LOCAL))
      daemon->serverarray[count]->arrayposn = count;
}

/**
 * @brief Find server(s) matching domain with longest suffix match
 *
 * @detailed Performs binary search in the sorted serverarray to find the server(s)
 * with the longest exact right-hand (RH) suffix match to qdomain. Handles empty names,
 * NODOTS servers for short unqualified names, wildcard matching, and flag-based filtering
 * (F_SERVER, F_DNSSECOK, F_DOMAINSRV, F_CONFIG). Returns index range [lowout, highout)
 * spanning all servers with matching domains. The algorithm progressively shortens the
 * query domain by removing labels from the left to find successively shorter suffix matches.
 *
 * @param domain Query domain name to match (may be modified by prepending '.')
 * @param flags Filter flags: F_SERVER (upstream only), F_DNSSECOK (DNSSEC-capable),
 *              F_DOMAINSRV (domain-specific), F_CONFIG (local replies). F_DNSSECOK
 *              also disables NODOTS server selection
 * @param lowout Output pointer for lowest matching server index in serverarray
 * @param highout Output pointer for highest matching server index + 1 (exclusive end)
 *
 * @return 1 if match found (lowout != highout), 0 if no servers or no match
 *
 * @note Handles domain truncation to find progressively shorter suffixes when exact
 * match fails. NODOTS servers (for short names without dots) are checked as fallback
 * unless F_DNSSECOK flag is set. Wildcard matching handles both "example.com" and
 * "*.example.com" patterns with proper precedence (exact match favored over wildcard).
 * Query domain may be prepended with '.' during search but is not preserved.
 *
 * @warning May modify the domain parameter by prepending '.' during matching process.
 * Requires serverarray to be sorted by domain specificity (call build_server_array()
 * first). Returns empty range (lowout == highout) if no match found.
 *
 * @see build_server_array() must be called first to sort serverarray
 * @see filter_servers() for additional filtering of the returned range
 * @see order() for domain comparison function used in binary search
 *
 * EXAMPLE USAGE:
 * @code
 * int low, high;
 * char query[] = "www.example.com";
 * if (lookup_domain(query, F_SERVER, &low, &high)) {
 *   // Servers [low, high) match the query domain
 *   filter_servers(low, F_IPV4, &low, &high);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements longest-suffix matching per DNS resolution conventions. Supports
 * hierarchical domain matching as specified in RFC 1034 Section 4.3.2 for
 * server selection policies.
 *
 * SIDE EFFECTS:
 * None to global state. May modify the domain parameter (not preserved after call).
 * Calls filter_servers() internally which is side-effect free.
 *
 * THREAD SAFETY:
 * Re-entrant if domain parameter is not shared between threads. Reads daemon->
 * serverarray and daemon->serverarraysz without modification. Binary search is
 * safe for concurrent reads in single-threaded event loop model.
 */
int lookup_domain(char *domain, int flags, int *lowout, int *highout)
{
  int rc, crop_query, nodots;
  ssize_t qlen;
  int try, high, low = 0;
  int nlow = 0, nhigh = 0;
  char *cp, *qdomain = domain;

  /* may be no configured servers. */
  if (daemon->serverarraysz == 0)
    return 0;
  
  /* find query length and presence of '.' */
  for (cp = qdomain, nodots = 1, qlen = 0; *cp; qlen++, cp++)
    if (*cp == '.')
      nodots = 0;

  /* Handle empty name, and searches for DNSSEC queries without
     diverting to NODOTS servers. */
  if (qlen == 0 || flags & F_DNSSECOK)
    nodots = 0;

  /* Search shorter and shorter RHS substrings for a match */
  while (qlen >= 0)
    {
      /* Note that when we chop off a label, all the possible matches
	 MUST be at a larger index than the nearest failing match with one more
	 character, since the array is sorted longest to smallest. Hence 
	 we don't reset low to zero here, we can go further below and crop the 
	 search string to the size of the largest remaining server
	 when this match fails. */
      high = daemon->serverarraysz;
      crop_query = 1;
      
      /* binary search */
      while (1) 
	{
	  try = (low + high)/2;

	  if ((rc = order(qdomain, qlen, daemon->serverarray[try])) == 0)
	    break;
	  
	  if (rc < 0)
	    {
	      if (high == try)
		{
		  /* qdomain is longer or same length as longest domain, and try == 0 
		     crop the query to the longest domain. */
		  crop_query = qlen - daemon->serverarray[try]->domain_len;
		  break;
		}
	      high = try;
	    }
	  else
	    {
	      if (low == try)
		{
		  /* try now points to the last domain that sorts before the query, so 
		     we know that a substring of the query shorter than it is required to match, so
		     find the largest domain that's shorter than try. Note that just going to
		     try+1 is not optimal, consider searching bbb in (aaa,ccc,bb). try will point
		     to aaa, since ccc sorts after bbb, but the first domain that has a chance to 
		     match is bb. So find the length of the first domain later than try which is
		     is shorter than it. 
		     There's a nasty edge case when qdomain sorts before _any_ of the 
		     server domains, where try _doesn't point_ to the last domain that sorts
		     before the query, since no such domain exists. In that case, the loop 
		     exits via the rc < 0 && high == try path above and this code is
		     not executed. */
		  ssize_t len, old = daemon->serverarray[try]->domain_len;
		  while (++try != daemon->serverarraysz)
		    {
		      if (old != (len = daemon->serverarray[try]->domain_len))
			{
			  crop_query = qlen - len;
			  break;
			}
		    }
		  break;
		}
	      low = try;
	    }
	};
      
      if (rc == 0)
	{
	  int found = 1;

	  if (daemon->server_has_wildcard)
	    {
	      /* if we have example.com and *example.com we need to check against *example.com, 
		 but the binary search may have found either. Use the fact that example.com is sorted before *example.com
		 We favour example.com in the case that both match (ie www.example.com) */
	      while (try != 0 && order(qdomain, qlen, daemon->serverarray[try-1]) == 0)
		try--;
	      
	      if (!(qdomain == domain || *qdomain == 0 || *(qdomain-1) == '.'))
		{
		  while (try < daemon->serverarraysz-1 && order(qdomain, qlen, daemon->serverarray[try+1]) == 0)
		    try++;
		  
		  if (!(daemon->serverarray[try]->flags & SERV_WILDCARD))
		     found = 0;
		}
	    }
	  
	  if (found && filter_servers(try, flags, &nlow, &nhigh))
	    /* We have a match, but it may only be (say) an IPv6 address, and
	       if the query wasn't for an AAAA record, it's no good, and we need
	       to continue generalising */
	    {
	      /* We've matched a setting which says to use servers without a domain.
		 Continue the search with empty query */
	      if (daemon->serverarray[nlow]->flags & SERV_USE_RESOLV)
		crop_query = qlen;
	      else
		break;
	    }
	}
      
      /* crop_query must be at least one always. */
      if (crop_query == 0)
	crop_query = 1;

      /* strip chars off the query based on the largest possible remaining match,
	 then continue to the start of the next label unless we have a wildcard
	 domain somewhere, in which case we have to go one at a time. */
      qlen -= crop_query;
      qdomain += crop_query;
      if (!daemon->server_has_wildcard)
	while (qlen > 0 &&  (*(qdomain-1) != '.'))
	  qlen--, qdomain++;
    }

  /* domain has no dots, and we have at least one server configured to handle such,
     These servers always sort to the very end of the array. 
     A configured server eg server=/lan/ will take precdence. */
  if (nodots &&
      (daemon->serverarray[daemon->serverarraysz-1]->flags & SERV_FOR_NODOTS) &&
      (nlow == nhigh || daemon->serverarray[nlow]->domain_len == 0))
    filter_servers(daemon->serverarraysz-1, flags, &nlow, &nhigh);
  
  if (lowout)
    *lowout = nlow;
  
  if (highout)
    *highout = nhigh;

  if (nlow == nhigh)
    return 0;

  return 1;
}

/**
 * @brief Check if two servers are in the same equivalence group
 *
 * @detailed Determines if two servers belong to the same equivalence group for
 * round-robin selection purposes. Servers are equivalent if they have identical
 * domains, identical flags (excluding SERV_LITERAL_ADDRESS and SERV_USE_RESOLV
 * differences), and identical source addresses. Used to group servers for load
 * distribution in query forwarding.
 *
 * @param a First server to compare
 * @param b Second server to compare
 *
 * @return 1 if servers are in the same equivalence group, 0 otherwise
 *
 * @note Equivalence is determined by order_servers() comparison which checks
 * domain, domain length, wildcard flags, and other server properties. Does not
 * compare SERV_LITERAL_ADDRESS or SERV_USE_RESOLV flags for equivalence.
 *
 * @see order_servers() for the underlying comparison logic
 * @see filter_servers() which uses server groups for round-robin selection
 *
 * EXAMPLE USAGE:
 * @code
 * struct server *s1 = daemon->serverarray[0];
 * struct server *s2 = daemon->serverarray[1];
 * if (server_samegroup(s1, s2)) {
 *   // Servers can be used interchangeably for round-robin
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * None. Pure comparison function with no state modifications.
 *
 * THREAD SAFETY:
 * Re-entrant. Only reads server structures without modification.
 */
int server_samegroup(struct server *a, struct server *b)
{
  return order_servers(a, b) == 0;
}

/**
 * @brief Filter server array by flags and return narrowed index range
 *
 * @detailed Narrows the server selection range [*lowout, *highout) based on query
 * requirements specified in flags. First expands the range to include all equivalent
 * servers (same domain), then applies hierarchical filtering: IPv6 literal addresses,
 * IPv4 literal addresses, all-zeros addresses, resolv.conf servers, upstream servers,
 * and NXDOMAIN literals, in that priority order. Handles DNSSEC capability filtering,
 * domain-specific server requirements, and address family preferences (IPv4/IPv6).
 *
 * @param seed Starting server index for round-robin rotation (typically from lookup_domain)
 * @param flags Filter flags: F_DNSSECOK (DNSSEC-capable servers), F_SERVER (upstream only),
 *              F_CONFIG (local replies), F_IPV4 (IPv4 queries), F_IPV6 (IPv6 queries),
 *              F_NOEXTRA (no additional processing), F_DOMAINSRV (domain-specific),
 *              F_QUERY (query context)
 * @param lowout Input/output pointer for lowest matching server index
 * @param highout Input/output pointer for highest matching server index + 1 (exclusive)
 *
 * @return 1 if matching servers found (*lowout != *highout), 0 otherwise (range empty)
 *
 * @note Implements complex hierarchical filtering with priority ordering: IPv6 literals
 * > IPv4 literals > all-zeros > resolv.conf > upstream servers > local-only. For F_CONFIG
 * flag, returns only servers with SERV_LOCAL_ADDRESS (SERV_6ADDR | SERV_4ADDR |
 * SERV_ALL_ZEROS). DNSSEC filtering requires SERV_DO_DNSSEC flag. Address family
 * filtering matches F_IPV4 with SERV_4ADDR and F_IPV6 with SERV_6ADDR.
 *
 * @warning Modifies *lowout and *highout in place. If no matches found after filtering,
 * sets *lowout == *highout (empty range). DNSSEC filtering is strict: if F_DNSSECOK
 * is set and no DNSSEC-capable servers exist in range, returns empty range.
 *
 * @see lookup_domain() typically provides initial seed and range
 * @see dnssec_server() for DNSSEC-specific server selection
 * @see order_servers() for server equivalence determination during range expansion
 *
 * EXAMPLE USAGE:
 * @code
 * int low = 0, high = daemon->serverarraysz;
 * if (lookup_domain("example.com", F_SERVER, &low, &high)) {
 *   // Narrow to IPv4-capable upstream servers
 *   if (filter_servers(low, F_SERVER | F_IPV4, &low, &high)) {
 *     // Use servers in range [low, high)
 *   }
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * None to global state. Modifies output parameters *lowout and *highout to narrow
 * or expand server range based on filtering criteria.
 *
 * THREAD SAFETY:
 * Re-entrant. Reads daemon->serverarray without modification. Safe for concurrent
 * reads in single-threaded event loop model.
 */
int filter_servers(int seed, int flags, int *lowout, int *highout)
{
  int nlow = seed, nhigh = seed;
  int i;
  
  /* expand nlow and nhigh to cover all the records with the same domain 
     nlow is the first, nhigh - 1 is the last. nlow=nhigh means no servers,
     which can happen below. */
  while (nlow > 0 && order_servers(daemon->serverarray[nlow-1], daemon->serverarray[nlow]) == 0)
    nlow--;
  
  while (nhigh < daemon->serverarraysz-1 && order_servers(daemon->serverarray[nhigh], daemon->serverarray[nhigh+1]) == 0)
    nhigh++;
  
  nhigh++;
  
#define SERV_LOCAL_ADDRESS (SERV_6ADDR | SERV_4ADDR | SERV_ALL_ZEROS)
  
  if (flags & F_CONFIG)
    {
      /* We're just lookin for any matches that return an RR. */
      for (i = nlow; i < nhigh; i++)
	if (daemon->serverarray[i]->flags & SERV_LOCAL_ADDRESS)
	  break;
      
      /* failed, return failure. */
      if (i == nhigh)
	nhigh = nlow;
    }
  else
    {
      /* Now the servers are on order between low and high, in the order
	 IPv6 addr, IPv4 addr, return zero for both, resolvconf servers, send upstream, no-data return.
	 
	 See which of those match our query in that priority order and narrow (low, high) */
      
      for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_6ADDR); i++);
      
      if (i != nlow && (flags & F_IPV6))
	nhigh = i;
      else
	{
	  nlow = i;
	  
	  for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_4ADDR); i++);
	  
	  if (i != nlow && (flags & F_IPV4))
	    nhigh = i;
	  else
	    {
	      nlow = i;
	      
	      for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_ALL_ZEROS); i++);
	      
	      if (i != nlow && (flags & (F_IPV4 | F_IPV6)))
		nhigh = i;
	      else
		{
		  nlow = i;
		  
		  /* Short to resolv.conf servers */
		  for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_USE_RESOLV); i++);
		  
		  if (i != nlow)
		    nhigh = i;
		  else
		    {
		      /* now look for a server */
		      for (i = nlow; i < nhigh && !(daemon->serverarray[i]->flags & SERV_LITERAL_ADDRESS); i++);
		      
		      if (i != nlow)
			{
			  /* If we want a server that can do DNSSEC, and this one can't, 
			     return nothing, similarly if were looking only for a server
			     for a particular domain. */
			  if ((flags & F_DNSSECOK) && !(daemon->serverarray[nlow]->flags & SERV_DO_DNSSEC))
			    nlow = nhigh;
			  else if ((flags & F_DOMAINSRV) && daemon->serverarray[nlow]->domain_len == 0)
			    nlow = nhigh;
			  else
			    nhigh = i;
			}
		      else
			{
			  /* --local=/domain/, only return if we don't need a server. */
			  if (flags & (F_DNSSECOK | F_DOMAINSRV | F_SERVER))
			    nhigh = i;
			}
		    }
		}
	    }
	}
    }

  *lowout = nlow;
  *highout = nhigh;
  
  return (nlow != nhigh);
}

/**
 * @brief Check if query has a local answer (hosts file or literal address)
 *
 * @detailed Examines the server at index 'first' in daemon->serverarray to determine
 * if the query can be answered locally without forwarding to upstream servers. Local
 * answers include literal IPv4/IPv6 addresses (SERV_LITERAL_ADDRESS with SERV_4ADDR,
 * SERV_6ADDR, or SERV_ALL_ZEROS), hosts file entries, or negative responses (NXDOMAIN).
 * Rolls back to find the first server for the domain to check for alternative answer
 * types if the specific query type doesn't match.
 *
 * @param now Current timestamp for cache staleness checking (used by check_for_local_domain)
 * @param first Index of first server in range to check (typically from filter_servers)
 * @param name Domain name being queried
 *
 * @return Flags indicating local answer type: F_IPV4 (IPv4 address available),
 *         F_IPV6 (IPv6 address available), F_IPV4|F_IPV6 (both/all-zeros),
 *         F_NOERR (local domain but different RR type), F_NXDOMAIN (negative response),
 *         or 0 (no local answer)
 *
 * @note Handles the case where a domain has multiple answer types (e.g., both A and
 * AAAA records) by rolling back to the domain's first server entry. Uses check_for_
 * local_domain() to verify hosts file entries. For SERV_ALL_ZEROS, returns both
 * F_IPV4 and F_IPV6 flags (0.0.0.0 and :: responses).
 *
 * @see make_local_answer() to generate the actual DNS response for local answers
 * @see check_for_local_domain() for hosts file integration
 * @see filter_servers() which typically provides the first index
 *
 * EXAMPLE USAGE:
 * @code
 * int low, high;
 * if (lookup_domain("local.example", F_CONFIG, &low, &high)) {
 *   int flags = is_local_answer(time(NULL), low, "local.example");
 *   if (flags & F_IPV4) {
 *     // Generate A record response
 *   }
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * None. Reads server configuration and may call check_for_local_domain() which
 * reads hosts file cache, but does not modify state.
 *
 * THREAD SAFETY:
 * Re-entrant. Reads daemon->serverarray and calls check_for_local_domain() without
 * modifying state. Safe in single-threaded event loop model.
 */
int is_local_answer(time_t now, int first, char *name)
{
  int flags = 0;
  int rc = 0;
  
  if ((flags = daemon->serverarray[first]->flags) & SERV_LITERAL_ADDRESS)
    {
      if (flags & SERV_4ADDR)
	rc = F_IPV4;
      else if (flags & SERV_6ADDR)
	rc = F_IPV6;
      else if (flags & SERV_ALL_ZEROS)
	rc = F_IPV4 | F_IPV6;
      else
	{
	  /* argument first is the first struct server which matches the query type;
	     now roll back to the server which is just the same domain, to check if that 
	     provides an answer of a different type. */

	  for (;first > 0 && order_servers(daemon->serverarray[first-1], daemon->serverarray[first]) == 0; first--);
	  
	  if ((daemon->serverarray[first]->flags & SERV_LOCAL_ADDRESS) ||
	      check_for_local_domain(name, now))
	    rc = F_NOERR;
	  else
	    rc = F_NXDOMAIN;
	}
    }

  return rc;
}

/**
 * @brief Generate DNS response from local data (hosts file, literal addresses)
 *
 * @detailed Constructs a complete DNS answer section from local data sources within
 * packet size limits. Handles IPv4 A records from SERV_4ADDR servers, IPv6 AAAA records
 * from SERV_6ADDR servers, all-zeros addresses (0.0.0.0 and ::), and error responses
 * (NXDOMAIN, NODATA) with optional Extended DNS Error (EDE) codes per RFC 8914. Sets
 * appropriate DNS header flags, answer count, and truncation bit if packet limit exceeded.
 *
 * @param flags Query flags indicating answer type: F_IPV4 (IPv4 query), F_IPV6 (IPv6 query),
 *              F_NXDOMAIN (name doesn't exist), F_NOERR (name exists but no RR for type),
 *              and gotname flags to control answer generation
 * @param gotname Indicates if name was found in local data (combined with flags)
 * @param size Current DNS packet size (typically sizeof(struct dns_header) initially)
 * @param header Pointer to DNS header structure to populate with response
 * @param name Domain name being answered
 * @param limit Pointer to end of packet buffer (size limit for truncation detection)
 * @param first First server index in serverarray range to process
 * @param last Last server index + 1 (exclusive end of range)
 * @param ede Extended DNS Error code for error responses (RFC 8914), 0 if not used
 *
 * @return New packet size after adding answer records, or 0 if skip_questions() fails
 *
 * @note Iterates through servers [first, last) adding resource records for each matching
 * address. Sets TC (truncation) bit in header if packet exceeds limit. Logs all generated
 * answers via log_query(). Handles SERV_ALL_ZEROS by generating zero addresses (0.0.0.0
 * or ::). For negative responses (F_NXDOMAIN | F_NOERR), only logs the query without
 * adding answer records.
 *
 * @warning Modifies the DNS packet in place, advancing pointer p through answer section.
 * If packet size exceeds limit, sets truncation bit and stops adding records. Requires
 * limit pointer to be valid end of packet buffer to prevent buffer overflows.
 *
 * @see is_local_answer() to determine if local answer generation is appropriate
 * @see setup_reply() for DNS header initialization with flags and EDE
 * @see add_resource_record() for individual RR addition to packet
 * @see skip_questions() to advance past question section
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * char name[] = "localhost";
 * int low, high;
 * lookup_domain(name, F_CONFIG, &low, &high);
 * size_t new_size = make_local_answer(F_IPV4, F_IPV4, sizeof(*header),
 *                                     header, name, packet + 512, low, high, 0);
 * // Send packet of new_size bytes
 * @endcode
 *
 * RFC COMPLIANCE:
 * RFC 1035: DNS response format with header, question, and answer sections
 * RFC 8914: Extended DNS Errors (EDE) for detailed error information
 *
 * SIDE EFFECTS:
 * - Modifies DNS packet header (flags, answer count, truncation bit)
 * - Adds answer records to packet, advancing internal pointer
 * - Logs all generated answers via log_query()
 * - Calls setup_reply() which may add EDE OPT record
 *
 * THREAD SAFETY:
 * Re-entrant if packet buffer is not shared. Modifies provided packet buffer and
 * header structure. Safe in single-threaded event loop where each query has
 * dedicated packet buffer.
 */
size_t make_local_answer(int flags, int gotname, size_t size, struct dns_header *header, char *name, char *limit, int first, int last, int ede)
{
  int trunc = 0, anscount = 0;
  unsigned char *p;
  int start;
  union all_addr addr;
  
  if (flags & (F_NXDOMAIN | F_NOERR))
    log_query(flags | gotname | F_NEG | F_CONFIG | F_FORWARD, name, NULL, NULL, 0);
	  
  setup_reply(header, flags, ede);
	  
  if (!(p = skip_questions(header, size)))
    return 0;
	  
  if (flags & gotname & F_IPV4)
    for (start = first; start != last; start++)
      {
	struct serv_addr4 *srv = (struct serv_addr4 *)daemon->serverarray[start];

	if (srv->flags & SERV_ALL_ZEROS)
	  memset(&addr, 0, sizeof(addr));
	else
	  addr.addr4 = srv->addr;
	
	if (add_resource_record(header, limit, &trunc, sizeof(struct dns_header), &p, daemon->local_ttl, NULL, T_A, C_IN, "4", &addr))
	  anscount++;
	log_query((flags | F_CONFIG | F_FORWARD) & ~F_IPV6, name, (union all_addr *)&addr, NULL, 0);
      }
  
  if (flags & gotname & F_IPV6)
    for (start = first; start != last; start++)
      {
	struct serv_addr6 *srv = (struct serv_addr6 *)daemon->serverarray[start];

	if (srv->flags & SERV_ALL_ZEROS)
	  memset(&addr, 0, sizeof(addr));
	else
	  addr.addr6 = srv->addr;
	
	if (add_resource_record(header, limit, &trunc, sizeof(struct dns_header), &p, daemon->local_ttl, NULL, T_AAAA, C_IN, "6", &addr))
	  anscount++;
	log_query((flags | F_CONFIG | F_FORWARD) & ~F_IPV4, name, (union all_addr *)&addr, NULL, 0);
      }

  if (trunc)
    header->hb3 |= HB3_TC;
  header->ancount = htons(anscount);
  
  return p - (unsigned char *)header;
}

#ifdef HAVE_DNSSEC
/**
 * @brief Find DNSSEC-capable server for validation queries
 *
 * @detailed Searches for an upstream server supporting DNSSEC validation for the given
 * keyname (typically a DNSKEY or DS record name). Attempts to use the original query
 * server if it appears in the keyname's domain match range, otherwise selects the
 * first server from the newly looked-up set, preferring the last successfully used
 * server if available. Ensures the selected server is DNSSEC-capable (SERV_DO_DNSSEC).
 *
 * @param server Original server used for the query requiring DNSSEC validation
 * @param keyname Domain name for DNSSEC key/DS record lookup (e.g., "example.com" for keys)
 * @param firstp Output pointer for first server index in matching range (may be NULL)
 * @param lastp Output pointer for last server index + 1 in matching range (may be NULL)
 *
 * @return Index in serverarray of selected DNSSEC-capable server, or -1 if no match found
 *
 * @note This function enables DNSSEC validation to use domain-specific servers when
 * configured. For example, if "example.com" queries use server A, DNSSEC validation
 * queries for "example.com" keys will prefer server A if it supports DNSSEC. Falls
 * back to last successful server via server->last_server if original not in range.
 * Only available when compiled with HAVE_DNSSEC.
 *
 * @warning Returns -1 if lookup_domain() finds no servers for keyname, indicating
 * DNSSEC validation cannot proceed. Caller must handle this error condition.
 *
 * @see lookup_domain() for initial keyname domain matching with F_DNSSECOK flag
 * @see filter_servers() which performs DNSSEC capability filtering
 * @see dnssec.c for DNSSEC validation pipeline using this function
 *
 * EXAMPLE USAGE:
 * @code
 * struct server *orig_server = daemon->serverarray[5];
 * char keyname[] = "example.com";
 * int first, last;
 * int index = dnssec_server(orig_server, keyname, &first, &last);
 * if (index >= 0) {
 *   struct server *dnssec_srv = daemon->serverarray[index];
 *   // Send DNSKEY query to dnssec_srv
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * None to global state. Reads daemon->serverarray and server fields without
 * modification. Output parameters firstp and lastp are set if non-NULL.
 *
 * THREAD SAFETY:
 * Re-entrant. Reads server structures without modification. Safe for concurrent
 * reads in single-threaded event loop model.
 */
int dnssec_server(struct server *server, char *keyname, int *firstp, int *lastp)
{
  int first, last, index;

  /* Find server to send DNSSEC query to. This will normally be the 
     same as for the original query, but may be another if
     servers for domains are involved. */		      
  if (!lookup_domain(keyname, F_DNSSECOK, &first, &last))
    return -1;

  for (index = first; index != last; index++)
    if (daemon->serverarray[index] == server)
      break;
	      
  /* No match to server used for original query.
     Use newly looked up set. */
  if (index == last)
    index =  daemon->serverarray[first]->last_server == -1 ?
      first : daemon->serverarray[first]->last_server;

  if (firstp)
    *firstp = first;

  if (lastp)
    *lastp = last;
   
  return index;
}
#endif

/**
 * @brief Compare query domain to server domain for binary search ordering
 *
 * @detailed Comparison function for binary search in lookup_domain(). Orders domains
 * first by length (longer domains sort before shorter), then by lexicographic order
 * for equal-length domains using hostname_order(). SERV_FOR_NODOTS servers always
 * sort last (return -1) since they handle dotless names as special case.
 *
 * @param qdomain Query domain string to compare
 * @param qlen Query domain length in characters
 * @param serv Server whose domain to compare against
 *
 * @return -1 if qdomain sorts before serv->domain, 0 if equal, 1 if qdomain sorts after
 *
 * @note NODOTS servers (SERV_FOR_NODOTS flag) always sort to end of array (return -1
 * from query perspective). This ensures they're only matched after all other domain
 * patterns have been tried. Length comparison enables longest-suffix matching priority.
 *
 * @see lookup_domain() uses this for binary search comparisons
 * @see order_servers() uses this for server-to-server comparisons
 * @see hostname_order() for lexicographic domain comparison
 *
 * SIDE EFFECTS: None. Pure comparison function.
 * THREAD SAFETY: Re-entrant. Only reads parameters without modification.
 */
static int order(char *qdomain, size_t qlen, struct server *serv)
{
  size_t dlen = 0;
    
  /* servers for dotless names always sort last 
     searched for name is never dotless. */
  if (serv->flags & SERV_FOR_NODOTS)
    return -1;

  dlen = serv->domain_len;
  
  if (qlen < dlen)
    return 1;
  
  if (qlen > dlen)
    return -1;

  return hostname_order(qdomain, serv->domain);
}

/**
 * @brief Compare two servers for sorting and equivalence determination
 *
 * @detailed Compares two servers for qsort ordering and equivalence group determination.
 * Uses order() to compare domains by length and lexicographic order, then applies
 * wildcard precedence: wildcard servers (SERV_WILDCARD) sort before non-wildcard
 * servers for the same domain. NODOTS servers only match other NODOTS servers.
 *
 * @param s1 First server to compare
 * @param s2 Second server to compare
 *
 * @return 0 if servers are equivalent (same domain, both wildcard or both not),
 *         -1 if s1 sorts before s2, 1 if s1 sorts after s2
 *
 * @note SERV_FOR_NODOTS servers only compare equal to other NODOTS servers (returns 0),
 * otherwise return 1 (sort to end). Wildcard precedence ensures "*.example.com" is
 * checked before "example.com" when both exist. Return value 0 indicates servers are
 * in same equivalence group for server_samegroup() and filter_servers() grouping.
 *
 * @see order() for underlying domain comparison
 * @see order_qsort() wraps this for qsort callback
 * @see server_samegroup() uses this to determine server equivalence
 * @see filter_servers() uses this to expand equivalence groups
 *
 * SIDE EFFECTS: None. Pure comparison function.
 * THREAD SAFETY: Re-entrant. Only reads server structures without modification.
 */
static int order_servers(struct server *s1, struct server *s2)
{
  int rc;

  /* need full comparison of dotless servers in 
     order_qsort() and filter_servers() */

  if (s1->flags & SERV_FOR_NODOTS)
     return (s2->flags & SERV_FOR_NODOTS) ? 0 : 1;
   
  if ((rc = order(s1->domain, s1->domain_len, s2)) != 0)
    return rc;

  /* For identical domains, sort wildcard ones first */
  if (s1->flags & SERV_WILDCARD)
    return (s2->flags & SERV_WILDCARD) ? 0 : 1;

  return (s2->flags & SERV_WILDCARD) ? -1 : 0;
}
  
/**
 * @brief qsort comparator wrapper for server array sorting
 *
 * @detailed Comparator function for qsort() in build_server_array(). Dereferences void
 * pointers to struct server** and applies multi-level sorting: (1) domain ordering via
 * order_servers(), (2) server type ordering (IPv6 literal > IPv4 literal > all-zeros >
 * resolv.conf > upstream > NXDOMAIN), (3) serial number for --strict-order. The
 * SERV_LITERAL_ADDRESS bit is flipped to achieve the desired literal address ordering.
 *
 * @param a Pointer to first struct server* pointer (const void* for qsort compatibility)
 * @param b Pointer to second struct server* pointer (const void* for qsort compatibility)
 *
 * @return -1 if server a sorts before b, 0 if equal, 1 if a sorts after b
 *
 * @note The bit manipulation ((flags & ...) ^ SERV_LITERAL_ADDRESS) creates the specific
 * ordering for local responses: IPv6 addr (SERV_6ADDR|SERV_LITERAL_ADDRESS), IPv4 addr
 * (SERV_4ADDR|SERV_LITERAL_ADDRESS), all-zeros (SERV_ALL_ZEROS|SERV_LITERAL_ADDRESS),
 * resolv.conf (SERV_USE_RESOLV), upstream (neither flag), NXDOMAIN (SERV_LITERAL_ADDRESS
 * only). Serial number ordering implements --strict-order option for upstream server
 * selection based on configuration file appearance order.
 *
 * @see build_server_array() calls qsort() with this comparator
 * @see order_servers() for primary domain/wildcard sorting
 * @see config.h for SERV_* flag definitions
 *
 * SIDE EFFECTS: None. Pure comparison function for qsort.
 * THREAD SAFETY: Re-entrant. Only reads server structures without modification.
 */
static int order_qsort(const void *a, const void *b)
{
  int rc;
  
  struct server *s1 = *((struct server **)a);
  struct server *s2 = *((struct server **)b);
  
  rc = order_servers(s1, s2);

  /* Sort all literal NODATA and local IPV4 or IPV6 responses together,
     in a very specific order. We flip the SERV_LITERAL_ADDRESS bit
     so the order is IPv6 literal, IPv4 literal, all-zero literal, 
     unqualified servers, upstream server, NXDOMAIN literal. */
  if (rc == 0)
    rc = ((s2->flags & (SERV_LITERAL_ADDRESS | SERV_4ADDR | SERV_6ADDR | SERV_USE_RESOLV | SERV_ALL_ZEROS)) ^ SERV_LITERAL_ADDRESS) -
      ((s1->flags & (SERV_LITERAL_ADDRESS | SERV_4ADDR | SERV_6ADDR | SERV_USE_RESOLV | SERV_ALL_ZEROS)) ^ SERV_LITERAL_ADDRESS);

  /* Finally, order by appearance in /etc/resolv.conf etc, for --strict-order */
  if (rc == 0)
    if (!(s1->flags & SERV_LITERAL_ADDRESS))
      rc = s1->serial - s2->serial;

  return rc;
}

/**
 * @brief Mark servers for deletion and prepare for configuration reload
 *
 * @detailed Prepares server lists for configuration reload by marking existing servers
 * with SERV_MARK flag based on whether they have the specified flag. Updates daemon->
 * servers_tail to last server in chain for efficient server addition. For local_domains
 * chain (--address, --server=/domain/ with addresses), immediately deletes entries
 * with the specified flag rather than marking them, since these are numerous and
 * recreated on reload.
 *
 * @param flag Server flag to check (e.g., SERV_FROM_RESOLV for resolv.conf servers).
 *             Servers with this flag are marked with SERV_MARK for later deletion.
 *             If flag is 0, clears SERV_MARK from all servers.
 *
 * @return void
 *
 * @note Must be called before add_update_server() during configuration reload to set
 * daemon->servers_tail correctly. After marking, call cleanup_servers() to remove
 * marked entries. For daemon->local_domains, servers with flag are deleted immediately
 * (not marked) because they're numerous and fully recreated each reload.
 *
 * @warning Modifies server->flags for all servers in daemon->servers chain. Deletes
 * and frees servers in daemon->local_domains chain if they have the specified flag.
 * Sets daemon->servers_tail global pointer.
 *
 * @see cleanup_servers() must be called after reload to remove marked servers
 * @see add_update_server() requires servers_tail to be set by this function
 * @see option.c read_opts() for configuration reload workflow
 *
 * EXAMPLE USAGE:
 * @code
 * // Configuration reload workflow
 * mark_servers(SERV_FROM_RESOLV);  // Mark resolv.conf servers
 * read_resolv_file();               // Re-read resolv.conf, updates marked servers
 * cleanup_servers();                // Remove servers still marked (deleted from config)
 * build_server_array();             // Rebuild sorted array
 * @endcode
 *
 * SIDE EFFECTS:
 * - Sets or clears SERV_MARK flag on all servers in daemon->servers chain
 * - Deletes and frees servers in daemon->local_domains if they have specified flag
 * - Sets daemon->servers_tail to last server in chain (or NULL if empty)
 * - Frees server->domain and server structures for deleted local_domains entries
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->servers, daemon->local_domains, and
 * daemon->servers_tail. Must be called from main event loop context only.
 */
void mark_servers(int flag)
{
  struct server *serv, **up;

  daemon->servers_tail = NULL;
  
  /* mark everything with argument flag */
  for (serv = daemon->servers; serv; serv = serv->next)
    {
      if (serv->flags & flag)
	serv->flags |= SERV_MARK;
      else
	serv->flags &= ~SERV_MARK;

      daemon->servers_tail = serv;
    }
  
  /* --address etc is different: since they are expected to be 
     1) numerous and 2) not reloaded often. We just delete 
     and recreate. */
  if (flag)
    for (serv = daemon->local_domains, up = &daemon->local_domains; serv; serv = serv->next)
      {
	if (serv->flags & flag)
	  {
	    *up = serv->next;
	    free(serv->domain);
	    free(serv);
	  }
	else 
	  up = &serv->next;
      }
}

/**
 * @brief Remove servers marked for deletion from server lists
 *
 * @detailed Removes all servers with SERV_MARK flag from daemon->servers chain,
 * calling server_gone() for cleanup actions (closing sockets, freeing queries),
 * then freeing server->domain and server structure. Updates daemon->servers_tail
 * to point to last remaining server. This completes the configuration reload
 * cycle started by mark_servers().
 *
 * @return void
 *
 * @note Must be called after mark_servers() and configuration re-reading to complete
 * the reload cycle. Servers that were re-added during configuration re-read will have
 * had SERV_MARK cleared by add_update_server(), so only deleted servers remain marked.
 * Updates daemon->servers_tail to maintain correct tail pointer for future additions.
 *
 * @warning Frees server memory and calls server_gone() which may close file descriptors
 * and cancel pending queries. Modifies daemon->servers chain and daemon->servers_tail.
 * After calling this, must call build_server_array() to rebuild sorted serverarray.
 *
 * @see mark_servers() must be called before configuration reload
 * @see server_gone() performs cleanup for each deleted server (forward.c)
 * @see add_update_server() clears SERV_MARK when server is re-added
 * @see build_server_array() must be called after cleanup to rebuild array
 *
 * EXAMPLE USAGE:
 * @code
 * // Configuration reload sequence
 * mark_servers(SERV_FROM_RESOLV);
 * read_resolv_file();      // Re-adds servers, clearing SERV_MARK
 * cleanup_servers();        // Removes servers still marked
 * build_server_array();     // Rebuild sorted array
 * @endcode
 *
 * SIDE EFFECTS:
 * - Calls server_gone() for each marked server (closes sockets, frees queries)
 * - Frees server->domain strings for marked servers
 * - Frees struct server memory for marked servers
 * - Updates daemon->servers chain to remove marked servers
 * - Sets daemon->servers_tail to last remaining server (or NULL if all removed)
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->servers and daemon->servers_tail,
 * frees memory, and closes file descriptors. Must be called from main event
 * loop context only.
 */
void cleanup_servers(void)
{
  struct server *serv, *tmp, **up;

  /* unlink and free anything still marked. */
  for (serv = daemon->servers, up = &daemon->servers, daemon->servers_tail = NULL; serv; serv = tmp) 
    {
      tmp = serv->next;
      if (serv->flags & SERV_MARK)
       {
         server_gone(serv);
         *up = serv->next;
	 free(serv->domain);
	 free(serv);
       }
      else 
	{
	  up = &serv->next;
	  daemon->servers_tail = serv;
	}
    }
}

/**
 * @brief Add new server or update existing server in configuration
 *
 * @detailed Creates a new struct server or updates an existing marked server with
 * matching domain. Handles both upstream servers (daemon->servers chain) and local
 * domain servers (daemon->local_domains chain) based on SERV_IS_LOCAL flags. For
 * upstream servers, searches for marked server with matching domain and reuses it
 * (clearing SERV_MARK), moving to end of chain to maintain --strict-order. For
 * local servers, allocates appropriate structure size (serv_addr4, serv_addr6, or
 * serv_local) and adds to local_domains chain.
 *
 * @param flags Server flags: SERV_IS_LOCAL (USE_RESOLV|LITERAL_ADDRESS) for local,
 *              SERV_4ADDR/SERV_6ADDR for address family, SERV_WILDCARD for wildcard
 *              domains, SERV_DO_DNSSEC for DNSSEC capability, etc.
 * @param addr Upstream server address (sockaddr), NULL for local servers
 * @param source_addr Source address for queries to this server, NULL for default
 * @param interface Interface name to bind for queries to this server, NULL for any
 * @param domain Domain name for server (empty string "" for default), supports
 *               leading "." or "*" which are normalized
 * @param local_addr IPv4/IPv6 address for local (literal) address servers, NULL for
 *                   upstream servers
 *
 * @return 1 on success (server added or updated), 0 on memory allocation failure
 *
 * @note Domain name normalization: Leading "." is removed (historical compatibility),
 * leading "*" enables SERV_WILDCARD flag and is removed. Empty domain becomes "".
 * For upstream servers, matching is by domain name only - if found with SERV_MARK,
 * server is reused and moved to end of list. For local servers, appropriate structure
 * size is allocated: sizeof(serv_addr6) for IPv6, sizeof(serv_addr4) for IPv4,
 * sizeof(serv_local) for others.
 *
 * @warning Allocates memory via whine_malloc() which may return NULL on failure.
 * Caller must check return value. For upstream servers, requires daemon->servers_tail
 * to be set correctly by prior mark_servers() call. Domain string is canonicalised
 * and must be freed with server on cleanup.
 *
 * @see mark_servers() must be called before reload cycle to set servers_tail
 * @see cleanup_servers() removes servers still marked after reload
 * @see canonicalise() for domain name normalization
 * @see whine_malloc() for memory allocation with error logging
 * @see build_server_array() must be called after all additions to rebuild array
 *
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr addr;
 * addr.sa.sa_family = AF_INET;
 * inet_pton(AF_INET, "8.8.8.8", &addr.in.sin_addr);
 * if (add_update_server(SERV_DO_DNSSEC, &addr, NULL, NULL, 
 *                       "example.com", NULL)) {
 *   // Server added successfully
 * }
 * @endcode
 *
 * SIDE EFFECTS:
 * - Allocates memory for struct server and canonicalised domain string
 * - For upstream: adds to daemon->servers chain or reuses marked server
 * - For local: adds to daemon->local_domains chain
 * - Clears SERV_MARK flag if reusing existing upstream server
 * - Updates daemon->servers_tail for new upstream servers
 * - Sets server->uid random value if HAVE_LOOP is defined
 * - Copies interface name, addresses, domain to server structure
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global daemon->servers or daemon->local_domains chains,
 * allocates memory, and updates daemon->servers_tail. Must be called from main event
 * loop context only.
 */
int add_update_server(int flags,
		      union mysockaddr *addr,
		      union mysockaddr *source_addr,
		      const char *interface,
		      const char *domain,
		      union all_addr *local_addr)
{
  struct server *serv = NULL;
  char *alloc_domain;
  
  if (!domain)
    domain = "";

  /* .domain == domain, for historical reasons. */
  if (*domain == '.')
    while (*domain == '.') domain++;
  else if (*domain == '*')
    {
      domain++;
      if (*domain != 0)
	flags |= SERV_WILDCARD;
    }
  
  if (*domain == 0)
    alloc_domain = whine_malloc(1);
  else
    alloc_domain = canonicalise((char *)domain, NULL);

  if (!alloc_domain)
    return 0;

  if (flags & SERV_IS_LOCAL)
    {
      size_t size;
      
      if (flags & SERV_6ADDR)
	size = sizeof(struct serv_addr6);
      else if (flags & SERV_4ADDR)
	size = sizeof(struct serv_addr4);
      else
	size = sizeof(struct serv_local);
      
      if (!(serv = whine_malloc(size)))
	{
	  free(alloc_domain);
	  return 0;
	}
      
      serv->next = daemon->local_domains;
      daemon->local_domains = serv;
      
      if (flags & SERV_4ADDR)
	((struct serv_addr4*)serv)->addr = local_addr->addr4;
      
      if (flags & SERV_6ADDR)
	((struct serv_addr6*)serv)->addr = local_addr->addr6;
    }
  else
    { 
      /* Upstream servers. See if there is a suitable candidate, if so unmark
	 and move to the end of the list, for order. The entry found may already
	 be at the end. */
      struct server **up, *tmp;
      
      for (serv = daemon->servers, up = &daemon->servers; serv; serv = tmp)
	{
	  tmp = serv->next;
	  if ((serv->flags & SERV_MARK) &&
	      hostname_isequal(alloc_domain, serv->domain))
	    {
	      /* Need to move down? */
	      if (serv->next)
		{
		  *up = serv->next;
		  daemon->servers_tail->next = serv;
		  daemon->servers_tail = serv;
		  serv->next = NULL;
		}
	      break;
	    }	
	}

      if (serv)
	{
	  free(alloc_domain);
	  alloc_domain = serv->domain;
	}
      else
	{
	  if (!(serv = whine_malloc(sizeof(struct server))))
	    {
	      free(alloc_domain);
	      return 0;
	    }
	  
	  memset(serv, 0, sizeof(struct server));
	  
	  /* Add to the end of the chain, for order */
	  if (daemon->servers_tail)
	    daemon->servers_tail->next = serv;
	  else
	    daemon->servers = serv;
	  daemon->servers_tail = serv;
	}
      
#ifdef HAVE_LOOP
      serv->uid = rand32();
#endif      
	  
      if (interface)
	safe_strncpy(serv->interface, interface, sizeof(serv->interface));
      if (addr)
	serv->addr = *addr;
      if (source_addr)
	serv->source_addr = *source_addr;
    }
    
  serv->flags = flags;
  serv->domain = alloc_domain;
  serv->domain_len = strlen(alloc_domain);
  
  return 1;
}

