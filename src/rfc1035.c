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
 * @file rfc1035.c
 * @brief DNS packet format handling per RFC 1035
 *
 * DETAILED PURPOSE:
 * This file implements the core DNS wire format parsing and generation functionality
 * according to RFC 1035. It handles the construction and deconstruction of DNS messages,
 * including support for DNS name compression (label pointers), question and answer
 * section processing, and various resource record types. The implementation provides
 * robust buffer safety through the CHECK_LEN macro pattern to prevent buffer overruns
 * during packet parsing. It also handles special processing for reverse DNS lookups
 * (in-addr.arpa and ip6.arpa domains), TCP length prefix handling for DNS-over-TCP,
 * and integration with dnsmasq's caching and forwarding subsystems.
 *
 * KEY RESPONSIBILITIES:
 * - extract_name(): Parse DNS names from wire format with compression pointer following
 * - skip_name(): Advance packet pointer past a DNS name without extraction
 * - skip_questions(): Skip over the question section of a DNS packet
 * - skip_section(): Skip over answer/authority/additional sections
 * - resize_packet(): Adjust packet buffer size for response construction
 * - answer_request(): Generate complete DNS response packets from cache or local data
 * - add_resource_record(): Add individual resource records to DNS responses
 * - extract_addresses(): Parse and validate address records from DNS responses
 * - extract_request(): Extract query name and type from incoming DNS requests
 * - setup_reply(): Initialize DNS response header with appropriate flags
 *
 * DEPENDENCIES:
 * - dnsmasq.h: Core dnsmasq type definitions and function prototypes
 * - dns-protocol.h: DNS protocol constants, struct dns_header, CHECK_LEN macro
 * - Called by: forward.c (query/response processing), cache.c (cache operations)
 * - Calls: cache.c functions for cache lookup/insertion, util.c for network utilities
 *
 * DATA STRUCTURES:
 * - struct dns_header (dns-protocol.h): DNS message header with ID, flags, section counts
 * - union all_addr (dnsmasq.h): Storage for IPv4/IPv6 addresses
 * - struct crec (dnsmasq.h): Cache record entries
 * - struct bogus_addr (dnsmasq.h): Bogus address detection configuration
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC: Enables DNSSEC-aware name parsing with NAME_ESCAPE character handling
 * - HAVE_IPV6: Enables IPv6 address parsing and reverse lookup support
 * - Affects name extraction (extract_name), address parsing (in_arpa_name_2_addr),
 *   and response generation (answer_request)
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. All functions are called from the main
 * event loop context and are not thread-safe. DNS packet processing is stateless
 * per-request, with state maintained only during the execution of a single request
 * handling function. No locking required as there is no concurrent access.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * 
 * @see docs/DNS_FORWARDING.md for DNS forwarding pipeline documentation
 * @see docs/DNS_CACHING.md for cache integration details
 * @see forward.c for query routing and upstream server management
 * @see cache.c for DNS cache operations
 */

#include "dnsmasq.h"

/**
 * @brief Parse DNS name from wire format with compression pointer following
 *
 * @detailed
 * Extracts a DNS domain name from a DNS packet, handling RFC 1035 label compression
 * (pointer labels starting with 0xC0). The function can operate in two modes: extraction
 * mode (copying the name to output buffer) or comparison mode (comparing against provided
 * name). Follows compression pointers up to 255 hops to prevent infinite loops from
 * malicious packets. Validates all buffer accesses using CHECK_LEN to prevent overruns.
 * DNS names in wire format consist of length-prefixed labels terminated by a zero-length
 * label, with compression pointers providing offsets to previously occurring labels.
 *
 * @param header Pointer to DNS packet header for base address calculations and validation
 * @param plen Total length of the DNS packet in bytes for bounds checking
 * @param pp Pointer to current position pointer in packet; updated to position after name
 * @param name Output buffer (extraction mode) or comparison string (comparison mode)
 * @param isExtract Mode flag: 1 for extraction to name buffer, 0 for comparison with name
 * @param extrabytes Number of additional bytes expected after the name (e.g., QTYPE+QCLASS)
 *
 * @return 1 on success with name matching (comparison mode) or extraction successful
 * @return 2 on success but names don't match (comparison mode only)
 * @return 0 on error (malformed packet, buffer overrun, loop detected, invalid label type)
 *
 * @note Compression pointers are identified by top 2 bits being 11 (0xC0 mask)
 * @note Maximum 255 compression pointer hops prevents infinite loop attacks
 * @note Label type 0x00 = normal label, 0xC0 = compression pointer, 0x40/0x80 = unsupported
 * @note In DNSSEC mode with OPT_DNSSEC_VALID, escapes special characters using NAME_ESCAPE
 *
 * @warning Buffer overrun protection relies on CHECK_LEN macro throughout
 * @warning Caller must ensure name buffer is at least MAXDNAME (1025) bytes for extraction
 * @warning Malformed compression pointers could cause denial of service if not hop-limited
 *
 * @see skip_name() for advancing past names without extraction
 * @see CHECK_LEN macro in dns-protocol.h for buffer validation pattern
 * @see RFC 1035 Section 4.1.4 for DNS message compression specification
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * unsigned char *p = (unsigned char *)(header + 1);
 * char qname[MAXDNAME];
 * if (extract_name(header, packet_len, &p, qname, 1, 4))
 *     printf("Query name: %s\n", qname);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 4.1.4 "Message compression" for label pointer following
 * and Section 3.1 "Name space definitions" for domain name format validation.
 *
 * SIDE EFFECTS:
 * - Updates *pp to point past the name in the packet
 * - In extraction mode, writes null-terminated domain name to name buffer
 * - In comparison mode, reads from name buffer for matching
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies name buffer and pp pointer. Should only be called from
 * single-threaded event loop context.
 */
int extract_name(struct dns_header *header, size_t plen, unsigned char **pp, 
		 char *name, int isExtract, int extrabytes)
{
  unsigned char *cp = (unsigned char *)name, *p = *pp, *p1 = NULL;
  unsigned int j, l, namelen = 0, hops = 0;
  int retvalue = 1;
  
  if (isExtract)
    *cp = 0;

  while (1)
    { 
      unsigned int label_type;

      if (!CHECK_LEN(header, p, plen, 1))
	return 0;
      
      if ((l = *p++) == 0) 
	/* end marker */
	{
	  /* check that there are the correct no. of bytes after the name */
	  if (!CHECK_LEN(header, p1 ? p1 : p, plen, extrabytes))
	    return 0;
	  
	  if (isExtract)
	    {
	      if (cp != (unsigned char *)name)
		cp--;
	      *cp = 0; /* terminate: lose final period */
	    }
	  else if (*cp != 0)
	    retvalue = 2;
	  
	  if (p1) /* we jumped via compression */
	    *pp = p1;
	  else
	    *pp = p;
	  
	  return retvalue;
	}

      label_type = l & 0xc0;
      
      if (label_type == 0xc0) /* pointer */
	{ 
	  if (!CHECK_LEN(header, p, plen, 1))
	    return 0;
	      
	  /* get offset */
	  l = (l&0x3f) << 8;
	  l |= *p++;
	  
	  if (!p1) /* first jump, save location to go back to */
	    p1 = p;
	      
	  hops++; /* break malicious infinite loops */
	  if (hops > 255)
	    return 0;
	  
	  p = l + (unsigned char *)header;
	}
      else if (label_type == 0x00)
	{ /* label_type = 0 -> label. */
	  namelen += l + 1; /* include period */
	  if (namelen >= MAXDNAME)
	    return 0;
	  if (!CHECK_LEN(header, p, plen, l))
	    return 0;
	  
	  for(j=0; j<l; j++, p++)
	    if (isExtract)
	      {
		unsigned char c = *p;
#ifdef HAVE_DNSSEC
		if (option_bool(OPT_DNSSEC_VALID))
		  {
		    if (c == 0 || c == '.' || c == NAME_ESCAPE)
		      {
			*cp++ = NAME_ESCAPE;
			*cp++ = c+1;
		      }
		    else
		      *cp++ = c; 
		  }
		else
#endif
		if (c != 0 && c != '.')
		  *cp++ = c;
		else
		  return 0;
	      }
	    else 
	      {
		unsigned char c1 = *cp, c2 = *p;
		
		if (c1 == 0)
		  retvalue = 2;
		else 
		  {
		    cp++;
		    if (c1 >= 'A' && c1 <= 'Z')
		      c1 += 'a' - 'A';
#ifdef HAVE_DNSSEC
		    if (option_bool(OPT_DNSSEC_VALID) && c1 == NAME_ESCAPE)
		      c1 = (*cp++)-1;
#endif
		    
		    if (c2 >= 'A' && c2 <= 'Z')
		      c2 += 'a' - 'A';
		     
		    if (c1 != c2)
		      retvalue =  2;
		  }
	      }
	    
	  if (isExtract)
	    *cp++ = '.';
	  else if (*cp != 0 && *cp++ != '.')
	    retvalue = 2;
	}
      else
	return 0; /* label types 0x40 and 0x80 not supported */
    }
}
 
/* Max size of input string (for IPv6) is 75 chars.) */
#define MAXARPANAME 75

/**
 * @brief Convert reverse DNS name (in-addr.arpa or ip6.arpa) to IP address
 *
 * @detailed
 * Parses reverse DNS lookup names (PTR queries) and extracts the IP address they represent.
 * Handles both IPv4 (xxx.yyy.zzz.www.in-addr.arpa) and IPv6 formats including nibble format
 * (x.x.x...x.ip6.arpa or x.x.x...x.ip6.int) and bitstring format (\[xHEXSTRING/128].ip6.arpa).
 * For IPv4, missing low-order octets are set to zero per RFC 2317 CNAME-based delegation.
 * Validates that IPv4 components contain only digits to avoid processing CNAME targets.
 * Supports both modern .arpa and legacy .int suffixes for IPv6.
 *
 * @param namein Null-terminated reverse DNS name string (max MAXARPANAME = 75 chars)
 * @param addrp Output union to receive parsed IPv4 or IPv6 address
 *
 * @return F_IPV4 if valid IPv4 reverse name parsed successfully
 * @return F_IPV6 if valid IPv6 reverse name parsed successfully  
 * @return 0 if not a valid reverse DNS name or parse error
 *
 * @note IPv4 format: d.d.d.d.in-addr.arpa (d = 0-255 decimal, reversed order)
 * @note IPv6 nibble format: x.x.x...x.ip6.arpa (32 hex nibbles, reversed order)
 * @note IPv6 bitstring format: \[xHEXSTRING/128].ip6.arpa (obsolete but supported)
 * @note RFC 2317 allows partial IPv4 addresses for CNAME-based delegation
 *
 * @warning Input name must not exceed MAXARPANAME (75) characters
 * @warning addrp contents undefined if function returns 0
 * @warning Non-digit characters in IPv4 labels cause rejection (CNAME target detection)
 *
 * @see extract_addresses() for forward address record processing
 * @see RFC 1035 Section 3.5 for in-addr.arpa format
 * @see RFC 2317 for classless in-addr.arpa delegation
 * @see RFC 3596 for ip6.arpa format (obsoletes ip6.int)
 *
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * char *revname = "4.3.2.1.in-addr.arpa";
 * int type = in_arpa_name_2_addr(revname, &addr);
 * if (type == F_IPV4)
 *     printf("IPv4: %s\n", inet_ntoa(addr.addr4));
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 3.5 (in-addr.arpa format) and RFC 3596 (ip6.arpa format).
 * Supports RFC 2317 classless delegation with partial IPv4 addresses.
 *
 * SIDE EFFECTS:
 * - Clears addrp to zero before parsing
 * - Modifies local name buffer (copy of namein) during parsing
 *
 * THREAD SAFETY:
 * Thread-safe. Uses only local variables and output parameter. No global state access.
 */
int in_arpa_name_2_addr(char *namein, union all_addr *addrp)
{
  int j;
  char name[MAXARPANAME+1], *cp1;
  unsigned char *addr = (unsigned char *)addrp;
  char *lastchunk = NULL, *penchunk = NULL;
  
  if (strlen(namein) > MAXARPANAME)
    return 0;

  memset(addrp, 0, sizeof(union all_addr));

  /* turn name into a series of asciiz strings */
  /* j counts no. of labels */
  for(j = 1,cp1 = name; *namein; cp1++, namein++)
    if (*namein == '.')
      {
	penchunk = lastchunk;
        lastchunk = cp1 + 1;
	*cp1 = 0;
	j++;
      }
    else
      *cp1 = *namein;
  
  *cp1 = 0;

  if (j<3)
    return 0;

  if (hostname_isequal(lastchunk, "arpa") && hostname_isequal(penchunk, "in-addr"))
    {
      /* IP v4 */
      /* address arrives as a name of the form
	 www.xxx.yyy.zzz.in-addr.arpa
	 some of the low order address octets might be missing
	 and should be set to zero. */
      for (cp1 = name; cp1 != penchunk; cp1 += strlen(cp1)+1)
	{
	  /* check for digits only (weeds out things like
	     50.0/24.67.28.64.in-addr.arpa which are used 
	     as CNAME targets according to RFC 2317 */
	  char *cp;
	  for (cp = cp1; *cp; cp++)
	    if (!isdigit((unsigned char)*cp))
	      return 0;
	  
	  addr[3] = addr[2];
	  addr[2] = addr[1];
	  addr[1] = addr[0];
	  addr[0] = atoi(cp1);
	}

      return F_IPV4;
    }
  else if (hostname_isequal(penchunk, "ip6") && 
	   (hostname_isequal(lastchunk, "int") || hostname_isequal(lastchunk, "arpa")))
    {
      /* IP v6:
         Address arrives as 0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.ip6.[int|arpa]
    	 or \[xfedcba9876543210fedcba9876543210/128].ip6.[int|arpa]
      
	 Note that most of these the various representations are obsolete and 
	 left-over from the many DNS-for-IPv6 wars. We support all the formats
	 that we can since there is no reason not to.
      */

      if (*name == '\\' && *(name+1) == '[' && 
	  (*(name+2) == 'x' || *(name+2) == 'X'))
	{	  
	  for (j = 0, cp1 = name+3; *cp1 && isxdigit((unsigned char) *cp1) && j < 32; cp1++, j++)
	    {
	      char xdig[2];
	      xdig[0] = *cp1;
	      xdig[1] = 0;
	      if (j%2)
		addr[j/2] |= strtol(xdig, NULL, 16);
	      else
		addr[j/2] = strtol(xdig, NULL, 16) << 4;
	    }
	  
	  if (*cp1 == '/' && j == 32)
	    return F_IPV6;
	}
      else
	{
	  for (cp1 = name; cp1 != penchunk; cp1 += strlen(cp1)+1)
	    {
	      if (*(cp1+1) || !isxdigit((unsigned char)*cp1))
		return 0;
	      
	      for (j = sizeof(struct in6_addr)-1; j>0; j--)
		addr[j] = (addr[j] >> 4) | (addr[j-1] << 4);
	      addr[0] = (addr[0] >> 4) | (strtol(cp1, NULL, 16) << 4);
	    }
	  
	  return F_IPV6;
	}
    }
  
  return 0;
}

/**
 * @brief Advance packet pointer past a DNS name without extraction
 *
 * @detailed
 * Skips over a DNS name in wire format without extracting or validating its content,
 * updating the pointer to the position immediately after the name. Handles standard
 * labels (type 0x00), compression pointers (type 0xC0), and extended label types
 * (type 0x40 for bitstrings, obsolete but supported). Uses CHECK_LEN throughout for
 * buffer safety. More efficient than extract_name() when name content is not needed.
 * Commonly used when processing answer sections where only the RDATA is of interest.
 *
 * @param ansp Current position in DNS packet to start skipping from
 * @param header Pointer to DNS packet header for base address and bounds checking
 * @param plen Total length of DNS packet in bytes
 * @param extrabytes Number of additional bytes expected after the name
 *
 * @return Pointer to position immediately after the name and extrabytes on success
 * @return NULL on error (malformed name, buffer overrun, unsupported label type)
 *
 * @note Label type 0x00 = normal label, 0xC0 = compression pointer (2 bytes)
 * @note Label type 0x40 = extended (bitstring), 0x80 = reserved (rejected)
 * @note Zero-length label (0x00) marks end of name
 * @note Bitstring labels (type 0x40, subtype 1) calculate byte length from bit count
 *
 * @warning Buffer validation via CHECK_LEN and ADD_RDLEN macros is critical
 * @warning Returns NULL on any bounds check failure - caller must handle
 * @warning Extended label types (0x40) are obsolete per RFC 2673/6891
 *
 * @see extract_name() for name extraction with compression pointer following
 * @see skip_questions() for skipping entire question section
 * @see skip_section() for skipping answer/authority/additional sections
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = (unsigned char *)(header + 1);
 * p = skip_name(p, header, packet_len, 4); // Skip QNAME, expect QTYPE+QCLASS
 * if (p) {
 *     unsigned short qtype;
 *     GETSHORT(qtype, p);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 4.1.4 (message compression) and Section 3.1 (name format).
 * Handles RFC 2673 extended labels (bitstrings) though obsoleted by RFC 6891.
 *
 * SIDE EFFECTS:
 * None. Returns new pointer position without modifying packet or global state.
 *
 * THREAD SAFETY:
 * Thread-safe. Pure function with no global state access.
 */
unsigned char *skip_name(unsigned char *ansp, struct dns_header *header, size_t plen, int extrabytes)
{
  while(1)
    {
      unsigned int label_type;
      
      if (!CHECK_LEN(header, ansp, plen, 1))
	return NULL;
      
      label_type = (*ansp) & 0xc0;

      if (label_type == 0xc0)
	{
	  /* pointer for compression. */
	  ansp += 2;	
	  break;
	}
      else if (label_type == 0x80)
	return NULL; /* reserved */
      else if (label_type == 0x40)
	{
	  /* Extended label type */
	  unsigned int count;
	  
	  if (!CHECK_LEN(header, ansp, plen, 2))
	    return NULL;
	  
	  if (((*ansp++) & 0x3f) != 1)
	    return NULL; /* we only understand bitstrings */
	  
	  count = *(ansp++); /* Bits in bitstring */
	  
	  if (count == 0) /* count == 0 means 256 bits */
	    ansp += 32;
	  else
	    ansp += ((count-1)>>3)+1;
	}
      else
	{ /* label type == 0 Bottom six bits is length */
	  unsigned int len = (*ansp++) & 0x3f;
	  
	  if (!ADD_RDLEN(header, ansp, plen, len))
	    return NULL;

	  if (len == 0)
	    break; /* zero length label marks the end. */
	}
    }

  if (!CHECK_LEN(header, ansp, plen, extrabytes))
    return NULL;
  
  return ansp;
}

/**
 * @brief Skip over the question section of a DNS packet
 *
 * @detailed
 * Advances the packet pointer past all questions in the DNS question section,
 * positioning it at the start of the answer section. Processes qdcount questions,
 * each consisting of a QNAME (variable length), QTYPE (2 bytes), and QCLASS (2 bytes).
 * Uses skip_name() for each question name with extrabytes=4 to account for type and class.
 * Essential for response processing where answers are the primary interest.
 *
 * @param header Pointer to DNS packet header containing qdcount and for bounds checking
 * @param plen Total length of DNS packet in bytes
 *
 * @return Pointer to start of answer section (first byte after questions) on success
 * @return NULL if any question is malformed or buffer overrun detected
 *
 * @note Question section immediately follows DNS header (header+1)
 * @note Each question: QNAME (variable) + QTYPE (2 bytes) + QCLASS (2 bytes)
 * @note qdcount is in network byte order, converted with ntohs()
 *
 * @warning Returns NULL on malformed packet - caller must check before proceeding
 * @warning Depends on skip_name() for proper bounds checking
 *
 * @see skip_name() for individual name skipping
 * @see skip_section() for skipping answer/authority/additional sections
 * @see extract_request() for extracting question details
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * unsigned char *p = skip_questions(header, packet_len);
 * if (p) {
 *     // Now at start of answer section
 *     process_answers(p, header, packet_len);
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 4.1.2 (Question section format) parsing.
 *
 * SIDE EFFECTS:
 * None. Pure function returning new pointer position.
 *
 * THREAD SAFETY:
 * Thread-safe. No global state access.
 */
unsigned char *skip_questions(struct dns_header *header, size_t plen)
{
  int q;
  unsigned char *ansp = (unsigned char *)(header+1);

  for (q = ntohs(header->qdcount); q != 0; q--)
    {
      if (!(ansp = skip_name(ansp, header, plen, 4)))
	return NULL;
      ansp += 4; /* class and type */
    }
  
  return ansp;
}

/**
 * @brief Skip over DNS answer, authority, or additional section records
 *
 * @detailed
 * Advances the packet pointer past a specified number of resource records in any
 * DNS section (answer, authority, or additional). Each RR consists of NAME (variable),
 * TYPE (2 bytes), CLASS (2 bytes), TTL (4 bytes), RDLENGTH (2 bytes), and RDATA
 * (RDLENGTH bytes). Validates bounds at each step using CHECK_LEN and ADD_RDLEN.
 * Commonly used to skip authority/additional sections when only answers are needed,
 * or to skip all sections when resizing packets.
 *
 * @param ansp Starting position in packet (typically start of target section)
 * @param count Number of resource records to skip (from ancount/nscount/arcount)
 * @param header Pointer to DNS packet header for base address and bounds checking
 * @param plen Total length of DNS packet in bytes
 *
 * @return Pointer to position immediately after skipped records on success
 * @return NULL if any record is malformed or buffer overrun detected
 *
 * @note Resource record format: NAME + TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) + RDATA (variable)
 * @note Fixed portion is 10 bytes (TYPE+CLASS+TTL+RDLENGTH), hence extrabytes=10 to skip_name()
 * @note RDLENGTH determines RDATA size, validated with ADD_RDLEN before advancing
 *
 * @warning Returns NULL on malformed record - caller must check
 * @warning RDLENGTH from untrusted packet - must validate bounds before advancing
 * @warning Large RDLENGTH values could indicate attack - ADD_RDLEN provides protection
 *
 * @see skip_name() for name skipping within each record
 * @see skip_questions() for skipping question section specifically
 * @see resize_packet() for packet truncation using this function
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = skip_questions(header, plen);
 * // Skip answer section
 * p = skip_section(p, ntohs(header->ancount), header, plen);
 * if (p) {
 *     // Now at authority section
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 4.1.3 (Resource record format) parsing for all section types.
 *
 * SIDE EFFECTS:
 * None. Pure function returning new pointer position.
 *
 * THREAD SAFETY:
 * Thread-safe. No global state access.
 */
unsigned char *skip_section(unsigned char *ansp, int count, struct dns_header *header, size_t plen)
{
  int i, rdlen;
  
  for (i = 0; i < count; i++)
    {
      if (!(ansp = skip_name(ansp, header, plen, 10)))
	return NULL; 
      ansp += 8; /* type, class, TTL */
      GETSHORT(rdlen, ansp);
      if (!ADD_RDLEN(header, ansp, plen, rdlen))
	return NULL;
    }

  return ansp;
}

/**
 * @brief Adjust DNS packet size by truncating at end of last section
 *
 * @detailed
 * Resizes a DNS packet by calculating its actual used size after skipping all sections,
 * then optionally restores a pseudoheader (EDNS0 OPT record) to the additional section.
 * Used to strip excess buffer space after packet construction or to reinsert EDNS0 OPT
 * records that were temporarily removed for processing. If packet is malformed (skip
 * functions return NULL), returns original size unchanged to avoid corruption. Ensures
 * additional record count reflects presence of restored pseudoheader.
 *
 * @param header Pointer to DNS packet header
 * @param plen Current (possibly oversized) packet length in bytes
 * @param pheader Pointer to pseudoheader (OPT record) to restore, or NULL if none
 * @param hlen Length of pseudoheader in bytes (ignored if pheader is NULL)
 *
 * @return Actual packet size in bytes (tightly fit to content) on success
 * @return Original plen if packet is malformed (safe fallback)
 *
 * @note Skips question section, then all answer/authority/additional sections
 * @note If pheader provided and arcount==0, restores pseudoheader and sets arcount=1
 * @note Uses memmove() for pseudoheader copy to handle potential overlap safely
 * @note Returns original plen on malformed packet to preserve data integrity
 *
 * @warning pheader buffer must remain valid during function execution
 * @warning Caller must not use returned size if larger than buffer allocation
 * @warning If arcount>0, pseudoheader is not restored (assumes already present)
 *
 * @see skip_questions() for question section navigation
 * @see skip_section() for answer/authority/additional section skipping
 * @see EDNS0 OPT record (RFC 6891) for pseudoheader format details
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char opt_record[11]; // Saved EDNS0 OPT
 * size_t opt_len = 11;
 * // ... process packet, possibly modifying sections ...
 * size_t new_len = resize_packet(header, buffer_size, opt_record, opt_len);
 * // Packet now tightly sized with OPT restored
 * @endcode
 *
 * RFC COMPLIANCE:
 * Packet structure per RFC 1035 Section 4.1. EDNS0 OPT handling per RFC 6891.
 *
 * SIDE EFFECTS:
 * - May modify header->arcount if pseudoheader restored
 * - Writes pseudoheader to packet buffer if pheader provided
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies packet buffer and header. Single-threaded use only.
 */
size_t resize_packet(struct dns_header *header, size_t plen, unsigned char *pheader, size_t hlen)
{
  unsigned char *ansp = skip_questions(header, plen);
    
  /* if packet is malformed, just return as-is. */
  if (!ansp)
    return plen;
  
  if (!(ansp = skip_section(ansp, ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount),
			    header, plen)))
    return plen;
    
  /* restore pseudoheader */
  if (pheader && ntohs(header->arcount) == 0)
    {
      /* must use memmove, may overlap */
      memmove(ansp, pheader, hlen);
      header->arcount = htons(1);
      ansp += hlen;
    }

  return ansp - (unsigned char *)header;
}

/**
 * @brief Check if IPv4 address is in non-globally-routed (private) IP space
 *
 * @detailed
 * Determines if an IPv4 address belongs to private/reserved address ranges per various
 * RFCs. Used to prevent DNS rebinding attacks and enforce --bogus-priv option by rejecting
 * answers containing private addresses from upstream servers. Checks loopback (127/8),
 * RFC 1918 private ranges (10/8, 172.16/12, 192.168/16), link-local (169.254/16),
 * documentation/test ranges (192.0.2/24, 198.51.100/24, 203.0.113/24), and broadcast.
 * Optionally treats localhost/0.0.0.0 as private based on configuration.
 *
 * @param addr IPv4 address in network byte order (struct in_addr)
 * @param ban_localhost If non-zero, treat 127.0.0.0/8 and 0.0.0.0 as private
 *
 * @return Non-zero (true) if address is in private/reserved range
 * @return 0 (false) if address is globally routable
 *
 * @note Detects RFC 1918 private addresses: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 * @note Detects RFC 3927 link-local: 169.254.0.0/16
 * @note Detects RFC 5737 test ranges: 192.0.2.0/24, 198.51.100/24, 203.0.113.0/24
 * @note Detects RFC 5735 "here" network: 0.0.0.0/8 (if ban_localhost set)
 * @note Detects loopback 127.0.0.0/8 (if ban_localhost set)
 *
 * @warning Address must be in network byte order; converts to host order internally
 *
 * @see private_net6() for IPv6 equivalent private address checking
 * @see check_for_bogus_wildcard() for bogus address validation in DNS responses
 * @see --bogus-priv command-line option for rejecting private addresses
 *
 * EXAMPLE USAGE:
 * @code
 * struct in_addr test_addr;
 * inet_aton("192.168.1.1", &test_addr);
 * if (private_net(test_addr, 0))
 *     printf("Private address detected\n");
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements address range checks per RFC 1918 (private), RFC 3927 (link-local),
 * RFC 5735 (special use), RFC 5737 (documentation).
 *
 * SIDE EFFECTS:
 * None. Pure function performing address range checks only.
 *
 * THREAD SAFETY:
 * Thread-safe. No global state access, pure calculation.
 */
/* is addr in the non-globally-routed IP space? */ 
int private_net(struct in_addr addr, int ban_localhost) 
{
  in_addr_t ip_addr = ntohl(addr.s_addr);

  return
    (((ip_addr & 0xFF000000) == 0x7F000000) && ban_localhost)  /* 127.0.0.0/8    (loopback) */ ||
    (((ip_addr & 0xFF000000) == 0x00000000) && ban_localhost) /* RFC 5735 section 3. "here" network */ ||
    ((ip_addr & 0xFF000000) == 0x0A000000)  /* 10.0.0.0/8     (private)  */ ||
    ((ip_addr & 0xFFF00000) == 0xAC100000)  /* 172.16.0.0/12  (private)  */ ||
    ((ip_addr & 0xFFFF0000) == 0xC0A80000)  /* 192.168.0.0/16 (private)  */ ||
    ((ip_addr & 0xFFFF0000) == 0xA9FE0000)  /* 169.254.0.0/16 (zeroconf) */ ||
    ((ip_addr & 0xFFFFFF00) == 0xC0000200)  /* 192.0.2.0/24   (test-net) */ ||
    ((ip_addr & 0xFFFFFF00) == 0xC6336400)  /* 198.51.100.0/24(test-net) */ ||
    ((ip_addr & 0xFFFFFF00) == 0xCB007100)  /* 203.0.113.0/24 (test-net) */ ||
    ((ip_addr & 0xFFFFFFFF) == 0xFFFFFFFF)  /* 255.255.255.255/32 (broadcast)*/ ;
}

/**
 * @brief Check if IPv6 address is in non-globally-routed (private) IP space
 *
 * @detailed
 * Determines if an IPv6 address belongs to private/reserved/local address ranges per
 * RFCs 4193, 6303, and others. Handles IPv4-mapped IPv6 addresses by extracting the
 * IPv4 portion and delegating to private_net(). Checks unspecified (::), loopback (::1),
 * link-local (fe80::/10), site-local (deprecated fec0::/10), ULA (fd00::/8), and
 * documentation (2001:db8::/32). Used for --bogus-priv enforcement and DNS rebinding
 * prevention in IPv6 context.
 *
 * @param a Pointer to IPv6 address structure (struct in6_addr)
 * @param ban_localhost If non-zero, treat :: and ::1 as private
 *
 * @return Non-zero (true) if address is in private/reserved range
 * @return 0 (false) if address is globally routable
 *
 * @note IPv4-mapped addresses (::ffff:x.x.x.x) checked via private_net()
 * @note Link-local fe80::/10 always considered private (RFC 6303 4.5)
 * @note ULA fd00::/8 considered private (RFC 6303 4.4, RFC 4193)
 * @note Site-local fec0::/10 considered private (deprecated, RFC 3879)
 * @note Documentation 2001:db8::/32 considered private (RFC 6303 4.6)
 *
 * @warning Address pointer must be valid; no NULL check performed
 *
 * @see private_net() for IPv4 private address checking
 * @see IN6_IS_ADDR_* macros for IPv6 address type classification
 * @see RFC 4193 for Unique Local Addresses (ULA)
 * @see RFC 6303 for filtering of locally-served DNS zones
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr test_addr;
 * inet_pton(AF_INET6, "fd00::1", &test_addr);
 * if (private_net6(&test_addr, 0))
 *     printf("Private IPv6 address detected\n");
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 4193 (ULA), RFC 6303 (locally-served zones), RFC 3879 (site-local deprecation).
 *
 * SIDE EFFECTS:
 * None. Pure function performing address range checks only.
 *
 * THREAD SAFETY:
 * Thread-safe. No global state access, pure calculation.
 */
static int private_net6(struct in6_addr *a, int ban_localhost)
{
  /* Block IPv4-mapped IPv6 addresses in private IPv4 address space */
  if (IN6_IS_ADDR_V4MAPPED(a))
    {
      struct in_addr v4;
      v4.s_addr = ((const uint32_t *) (a))[3];
      return private_net(v4, ban_localhost);
    }

  return
    (IN6_IS_ADDR_UNSPECIFIED(a) && ban_localhost) || /* RFC 6303 4.3 */
    (IN6_IS_ADDR_LOOPBACK(a) && ban_localhost) ||    /* RFC 6303 4.3 */
    IN6_IS_ADDR_LINKLOCAL(a) ||   /* RFC 6303 4.5 */
    IN6_IS_ADDR_SITELOCAL(a) ||
    ((unsigned char *)a)[0] == 0xfd ||   /* RFC 6303 4.4 */
    ((u32 *)a)[0] == htonl(0x20010db8); /* RFC 6303 4.6 */
}

/**
 * @brief Rewrite IPv4 addresses in DNS answer records per --alias configuration
 *
 * @detailed
 * Implements the --alias (doctor) functionality by scanning answer section A records
 * and rewriting addresses that match configured ranges/networks to alternate addresses.
 * Used for network address translation in DNS responses, allowing internal addresses
 * to be rewritten to external equivalents. Processes count records starting at position
 * p, checking each A record (C_IN class, T_A type) against the doctor list. When a
 * match is found, replaces the address bits specified by the mask, clears the AA
 * (authoritative answer) flag, and sets the doctored flag. Skips non-A records.
 *
 * @param p Current position in DNS packet (typically start of answer section)
 * @param count Number of records to process from this section
 * @param header Pointer to DNS packet header for bounds checking and flag modification
 * @param qlen Total length of DNS packet in bytes
 * @param doctored Output flag: set to 1 if any address was rewritten, unchanged otherwise
 *
 * @return Pointer to position after processed records on success
 * @return 0 (NULL cast to unsigned char *) on malformed packet or buffer overrun
 *
 * @note Only processes C_IN class, T_A type records (IPv4 addresses)
 * @note Doctor configuration in daemon->doctors linked list (struct doctor)
 * @note Supports range matching (in.s_addr to end.s_addr) or network matching (mask)
 * @note Clears HB3_AA flag when rewriting to indicate non-authoritative answer
 * @note Uses memcpy for address alignment safety
 *
 * @warning Modifies packet contents in-place - not safe for cached/shared packets
 * @warning Clears authoritative flag which may affect DNSSEC validation
 * @warning Returns 0 on error - caller must handle NULL return
 *
 * @see struct doctor in dnsmasq.h for --alias configuration structure
 * @see answer_request() which calls do_doctor() during response generation
 * @see --alias command-line option for configuration
 *
 * EXAMPLE USAGE:
 * @code
 * int doctored = 0;
 * unsigned char *p = skip_questions(header, qlen);
 * p = do_doctor(p, ntohs(header->ancount), header, qlen, &doctored);
 * if (p && doctored)
 *     printf("Addresses rewritten\n");
 * @endcode
 *
 * RFC COMPLIANCE:
 * Modifies standard DNS response processing. When doctoring occurs, AA flag cleared
 * to indicate response is no longer authoritative (RFC 1035 Section 4.1.1).
 *
 * SIDE EFFECTS:
 * - Modifies address RDATA in packet buffer
 * - Clears HB3_AA flag in header if addresses rewritten
 * - Sets *doctored flag if modifications made
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies packet buffer and accesses global daemon->doctors list.
 * Must be called from single-threaded event loop context.
 */
static unsigned char *do_doctor(unsigned char *p, int count, struct dns_header *header, size_t qlen, int *doctored)
{
  int i, qtype, qclass, rdlen;

  for (i = count; i != 0; i--)
    {
      if (!(p = skip_name(p, header, qlen, 10)))
	return 0; /* bad packet */
      
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      p += 4; /* ttl */
      GETSHORT(rdlen, p);
      
      if (qclass == C_IN && qtype == T_A)
	{
	  struct doctor *doctor;
	  struct in_addr addr;
	  
	  if (!CHECK_LEN(header, p, qlen, INADDRSZ))
	    return 0;
	  
	  /* alignment */
	  memcpy(&addr, p, INADDRSZ);
	  
	  for (doctor = daemon->doctors; doctor; doctor = doctor->next)
	    {
	      if (doctor->end.s_addr == 0)
		{
		  if (!is_same_net(doctor->in, addr, doctor->mask))
		    continue;
		}
	      else if (ntohl(doctor->in.s_addr) > ntohl(addr.s_addr) || 
		       ntohl(doctor->end.s_addr) < ntohl(addr.s_addr))
		continue;
	      
	      addr.s_addr &= ~doctor->mask.s_addr;
	      addr.s_addr |= (doctor->out.s_addr & doctor->mask.s_addr);
	      /* Since we munged the data, the server it came from is no longer authoritative */
	      header->hb3 &= ~HB3_AA;
	      *doctored = 1;
	      memcpy(p, &addr, INADDRSZ);
	      break;
	    }
	}
      
      if (!ADD_RDLEN(header, p, qlen, rdlen))
	 return 0; /* bad packet */
    }
  
  return p; 
}

/**
 * @brief Find SOA record in authority section and determine minimum TTL
 *
 * @detailed
 * Searches the authority (NS) section of a DNS packet for SOA (Start of Authority) records
 * and extracts the minimum TTL value for negative caching. Processes answer section with
 * do_doctor() first, then scans authority section for C_IN/T_SOA records, tracking the
 * smallest TTL from both the SOA record's own TTL and its MINIMUM field (last field in
 * SOA RDATA). Also processes additional section for address doctoring. If no SOA found,
 * returns daemon->neg_ttl as default negative caching TTL. Used for NXDOMAIN and NODATA
 * responses to determine how long to cache negative answers.
 *
 * @param header Pointer to DNS packet header
 * @param qlen Total length of DNS packet in bytes
 * @param doctored Output flag: set if do_doctor() modified any addresses
 *
 * @return Minimum TTL value from SOA record(s) if SOA found, else daemon->neg_ttl
 * @return 0 on malformed packet or buffer overrun
 *
 * @note SOA RDATA format: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
 * @note Skips MNAME and RNAME (domain names), SERIAL/REFRESH/RETRY/EXPIRE (16 bytes total)
 * @note MINIMUM field (last 4 bytes of SOA) is the TTL for negative caching per RFC 2308
 * @note Tracks minimum of SOA record TTL and SOA MINIMUM field
 * @note Processes answer section via do_doctor() even though SOA typically in authority
 *
 * @warning Returns 0 on malformed packet - caller should treat as error
 * @warning Accesses global daemon->neg_ttl for default value
 *
 * @see do_doctor() for address rewriting in answer/additional sections
 * @see RFC 2308 for negative caching and SOA MINIMUM field semantics
 * @see extract_addresses() which uses this for negative answer caching
 *
 * EXAMPLE USAGE:
 * @code
 * int doctored = 0;
 * unsigned long min_ttl = find_soa(header, qlen, &doctored);
 * if (min_ttl)
 *     cache_negative(name, min_ttl);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 2308 (negative caching) by extracting SOA MINIMUM field for negative TTL.
 *
 * SIDE EFFECTS:
 * - May modify packet via do_doctor() if --alias configured
 * - Sets *doctored flag if addresses rewritten
 * - Accesses global daemon->neg_ttl
 *
 * THREAD SAFETY:
 * Not thread-safe. Calls do_doctor() which modifies packet, accesses global daemon.
 * Single-threaded event loop use only.
 */
static int find_soa(struct dns_header *header, size_t qlen, int *doctored)
{
  unsigned char *p;
  int qtype, qclass, rdlen;
  unsigned long ttl, minttl = ULONG_MAX;
  int i, found_soa = 0;
  
  /* first move to NS section and find TTL from any SOA section */
  if (!(p = skip_questions(header, qlen)) ||
      !(p = do_doctor(p, ntohs(header->ancount), header, qlen, doctored)))
    return 0;  /* bad packet */
  
  for (i = ntohs(header->nscount); i != 0; i--)
    {
      if (!(p = skip_name(p, header, qlen, 10)))
	return 0; /* bad packet */
      
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
      
      if ((qclass == C_IN) && (qtype == T_SOA))
	{
	  found_soa = 1;
	  if (ttl < minttl)
	    minttl = ttl;

	  /* MNAME */
	  if (!(p = skip_name(p, header, qlen, 0)))
	    return 0;
	  /* RNAME */
	  if (!(p = skip_name(p, header, qlen, 20)))
	    return 0;
	  p += 16; /* SERIAL REFRESH RETRY EXPIRE */
	  
	  GETLONG(ttl, p); /* minTTL */
	  if (ttl < minttl)
	    minttl = ttl;
	}
      else if (!ADD_RDLEN(header, p, qlen, rdlen))
	return 0; /* bad packet */
    }
  
  /* rewrite addresses in additional section too */
  if (!do_doctor(p, ntohs(header->arcount), header, qlen, doctored))
    return 0;
  
  if (!found_soa)
    minttl = daemon->neg_ttl;

  return minttl;
}

/**
 * @brief Log TXT record content to query log with sanitization
 *
 * @detailed
 * Extracts and logs the content of a TXT resource record to the query log. TXT records
 * consist of one or more length-prefixed strings (1 byte length + data). Sanitizes
 * non-printable characters by truncating at first non-printable byte. Temporarily
 * modifies buffer to create null-terminated strings for logging, then restores original
 * format. Used when --log-queries is enabled to log TXT query responses alongside other
 * record types. Validates buffer bounds to prevent reading beyond RDATA length.
 *
 * @param header Pointer to DNS packet header for bounds checking
 * @param qlen Total length of DNS packet in bytes
 * @param name Domain name associated with this TXT record (for logging)
 * @param p Pointer to start of TXT RDATA (length-prefixed strings)
 * @param ardlen Length of TXT RDATA in bytes
 * @param secflag Security flags to pass to log_query() (DNSSEC status, etc.)
 *
 * @return 1 on success (all TXT strings logged)
 * @return 0 on malformed TXT data (invalid length, buffer overrun)
 *
 * @note TXT RDATA format: <len1><data1><len2><data2>... (one or more length-prefixed strings)
 * @note Each string: 1 byte length (0-255) followed by that many data bytes
 * @note Stops logging string at first non-printable character (sanitization)
 * @note Temporarily null-terminates strings for logging, then restores with memmove
 *
 * @warning Temporarily modifies packet buffer - not safe for concurrent access
 * @warning Truncates at non-printable characters which may hide malicious content
 * @warning Buffer restoration via memmove - assumes no overlap issues
 *
 * @see log_query() for actual logging to syslog/file
 * @see extract_addresses() which calls this for TXT record logging
 * @see isprint() for printable character determination
 *
 * EXAMPLE USAGE:
 * @code
 * // After extracting TXT record from packet
 * if (qtype == T_TXT) {
 *     if (!print_txt(header, qlen, name, rdata_ptr, rdlen, secflag))
 *         // Malformed TXT record
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * TXT record format per RFC 1035 Section 3.3.14 (character-string format).
 *
 * SIDE EFFECTS:
 * - Temporarily modifies packet buffer (restored before return)
 * - Calls log_query() which writes to syslog/log file
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies packet buffer temporarily. Single-threaded use only.
 */
/* Print TXT reply to log */
static int print_txt(struct dns_header *header, const size_t qlen, char *name,
		     unsigned char *p, const int ardlen, int secflag)
{
  unsigned char *p1 = p;
  if (!CHECK_LEN(header, p1, qlen, ardlen))
    return 0;
  /* Loop over TXT payload */
  while ((p1 - p) < ardlen)
    {
      unsigned int i, len = *p1;
      unsigned char *p3 = p1;
      if ((p1 + len - p) >= ardlen)
	return 0; /* bad packet */

      /* make counted string zero-term and sanitise */
      for (i = 0; i < len; i++)
	{
	  if (!isprint((int)*(p3+1)))
	    break;
	  *p3 = *(p3+1);
	  p3++;
	}

      *p3 = 0;
      log_query(secflag | F_FORWARD | F_UPSTREAM, name, NULL, (char*)p1, 0);
      /* restore */
      memmove(p1 + 1, p1, i);
      *p1 = len;
      p1 += len+1;
    }
  return 1;
}

/**
 * @brief Parse and cache address records from DNS response with validation
 *
 * @detailed
 * Extracts A, AAAA, CNAME, and other resource records from a DNS response packet and
 * inserts them into the cache. Performs comprehensive validation including DNS rebinding
 * attack prevention (private address filtering), bogus wildcard detection, CNAME chain
 * loop detection (CNAME_CHAIN limit), and ipset/nftset integration for resolved addresses.
 * Follows CNAME chains recursively, handling both explicit CNAMEs and implicit CNAMEs
 * from wildcard records. Applies SOA-based negative caching for NXDOMAIN/NODATA.
 * Integrates with DNSSEC validation via secure flag and handles --local-service and
 * --bogus-priv options. May create incomplete CNAME chains due to memory constraints
 * which are cleaned up by cache expiry. Supports TXT record logging and MX/SRV/PTR
 * record caching.
 *
 * @param header Pointer to DNS packet header
 * @param qlen Total length of DNS packet in bytes
 * @param name Query name being processed (may be updated during CNAME following)
 * @param now Current time for TTL calculation and cache insertion
 * @param ipsets Pointer to ipset configuration list for address insertion (HAVE_IPSET)
 * @param nftsets Pointer to nftset configuration list for address insertion (HAVE_NFTSET)
 * @param is_sign DNSSEC signature present flag (affects caching decisions)
 * @param check_rebind If non-zero, reject private addresses to prevent DNS rebinding
 * @param no_cache_dnssec If non-zero, don't cache DNSSEC-signed records
 * @param secure DNSSEC validation status (affects cache entry flags)
 * @param doctored Output flag: set if addresses were rewritten via --alias
 *
 * @return 0 on success (addresses extracted and cached normally)
 * @return 1 if address rejected due to DNS rebinding attack detection (private address)
 * @return 0 on malformed packet (unable to parse)
 *
 * @note CNAME chain following limited to CNAME_CHAIN (10) iterations to prevent loops
 * @note Private address rejection controlled by check_rebind and --local-service options
 * @note Creates cache entries with appropriate TTL from RR TTL field
 * @note Handles both IPv4 (A) and IPv6 (AAAA) address records
 * @note Integrates with ipset/nftset for firewall rule population
 * @note May create incomplete CNAME chains - cache code handles cleanup via expiry
 *
 * @warning Returns 1 for rebinding attack - caller must treat as special case
 * @warning Modifies name parameter during CNAME following
 * @warning Accesses global daemon structure for configuration
 * @warning May partially populate cache even on error/rejection
 *
 * @see find_soa() for SOA-based negative TTL extraction
 * @see cache_insert() for actual cache entry creation
 * @see check_for_bogus_wildcard() for bogus wildcard detection
 * @see private_net() and private_net6() for rebinding attack prevention
 * @see do_doctor() for --alias address rewriting
 *
 * EXAMPLE USAGE:
 * @code
 * char qname[MAXDNAME];
 * int doctored = 0;
 * int rebind = extract_addresses(header, len, qname, time(NULL),
 *                                ipsets, nftsets, 0, 1, 0, 0, &doctored);
 * if (rebind)
 *     log_query(F_CONFIG | F_FORWARD, qname, NULL, "<DNS rebinding attack>");
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 (DNS packet format), RFC 2308 (negative caching with SOA),
 * RFC 3596 (AAAA records). Rebinding attack prevention is a security extension.
 *
 * SIDE EFFECTS:
 * - Inserts entries into global DNS cache via cache_insert()
 * - May add addresses to ipset/nftset firewall rules
 * - Calls log_query() for query logging if enabled
 * - May modify packet via do_doctor() for --alias
 * - Updates name parameter during CNAME following
 * - Accesses and modifies global daemon structure
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global cache, accesses global daemon config.
 * Must be called from single-threaded event loop context.
 */
/* Note that the following code can create CNAME chains that don't point to a real record,
   either because of lack of memory, or lack of SOA records.  These are treated by the cache code as 
   expired and cleaned out that way. 
   Return 1 if we reject an address because it look like part of dns-rebinding attack. */
int extract_addresses(struct dns_header *header, size_t qlen, char *name, time_t now, 
		      struct ipsets *ipsets, struct ipsets *nftsets, int is_sign, int check_rebind,
		      int no_cache_dnssec, int secure, int *doctored)
{
  unsigned char *p, *p1, *endrr, *namep;
  int j, qtype, qclass, aqtype, aqclass, ardlen, res, searched_soa = 0;
  unsigned long ttl = 0;
  union all_addr addr;
#ifdef HAVE_IPSET
  char **ipsets_cur;
#else
  (void)ipsets; /* unused */
#endif
#ifdef HAVE_NFTSET
  char **nftsets_cur;
#else
  (void)nftsets; /* unused */
#endif
  int found = 0, cname_count = CNAME_CHAIN;
  struct crec *cpp = NULL;
  int flags = RCODE(header) == NXDOMAIN ? F_NXDOMAIN : 0;
#ifdef HAVE_DNSSEC
  int cname_short = 0;
#endif
  unsigned long cttl = ULONG_MAX, attl;
  
  cache_start_insert();

  /* find_soa is needed for dns_doctor side effects, so don't call it lazily if there are any. */
  if (daemon->doctors || option_bool(OPT_DNSSEC_VALID))
    {
      searched_soa = 1;
      ttl = find_soa(header, qlen, doctored);

      if (*doctored)
	{
	  if (secure)
	    return 0;
#ifdef HAVE_DNSSEC
	  if (option_bool(OPT_DNSSEC_VALID))
	    for (j = 0; j < ntohs(header->ancount); j++)
	      if (daemon->rr_status[j] != 0)
		return 0;
#endif
	}
    }
  
  namep = p = (unsigned char *)(header+1);
  
  if (ntohs(header->qdcount) != 1 || !extract_name(header, qlen, &p, name, 1, 4))
    return 0; /* bad packet */
  
  GETSHORT(qtype, p); 
  GETSHORT(qclass, p);
  
  if (qclass != C_IN)
    return 0;
  
  /* PTRs: we chase CNAMEs here, since we have no way to 
     represent them in the cache. */
  if (qtype == T_PTR)
    { 
      int insert = 1, name_encoding = in_arpa_name_2_addr(name, &addr);
      
      if (!(flags & F_NXDOMAIN))
	{
	cname_loop:
	  if (!(p1 = skip_questions(header, qlen)))
	    return 0;
	  
	  for (j = 0; j < ntohs(header->ancount); j++) 
	    {
	      int secflag = 0;
	      if (!(res = extract_name(header, qlen, &p1, name, 0, 10)))
		return 0; /* bad packet */
	      
	      GETSHORT(aqtype, p1); 
	      GETSHORT(aqclass, p1);
	      GETLONG(attl, p1);
	      
	      if ((daemon->max_ttl != 0) && (attl > daemon->max_ttl) && !is_sign)
		{
		  (p1) -= 4;
		  PUTLONG(daemon->max_ttl, p1);
		}
	      GETSHORT(ardlen, p1);
	      endrr = p1+ardlen;
	      
	      /* TTL of record is minimum of CNAMES and PTR */
	      if (attl < cttl)
		cttl = attl;
	      
	      if (aqclass == C_IN && res != 2 && (aqtype == T_CNAME || aqtype == T_PTR))
		{
#ifdef HAVE_DNSSEC
		  if (option_bool(OPT_DNSSEC_VALID) && !no_cache_dnssec && daemon->rr_status[j] != 0)
		    {
		      /* validated RR anywhere in CNAME chain, don't cache. */
		      if (cname_short || aqtype == T_CNAME)
			insert = 0;
		      
		      secflag = F_DNSSECOK;
		      /* limit TTL based on signature. */
		      if (daemon->rr_status[j] < cttl)
			cttl = daemon->rr_status[j];
		    }
#endif

		  if (aqtype == T_CNAME)
		    log_query(secflag | F_CNAME | F_FORWARD | F_UPSTREAM, name, NULL, NULL, 0);
		  
		  if (!extract_name(header, qlen, &p1, name, 1, 0))
		    return 0;
		  
		  if (aqtype == T_CNAME)
		    {
		      if (!cname_count--)
			return 0; /* looped CNAMES, we can't cache. */
#ifdef HAVE_DNSSEC
		      cname_short = 1;
#endif
		      goto cname_loop;
		    }
		  
		  found = 1; 
		  
		  if (!name_encoding)
		    log_query(secflag | F_FORWARD | F_UPSTREAM, name, NULL, NULL, aqtype);
		  else
		    {
		      log_query(name_encoding | secflag | F_REVERSE | F_UPSTREAM, name, &addr, NULL, 0);
		      if (insert)
			cache_insert(name, &addr, C_IN, now, cttl, name_encoding | secflag | F_REVERSE);
		    }
		}

	      p1 = endrr;
	      if (!CHECK_LEN(header, p1, qlen, 0))
		return 0; /* bad packet */
	    }
	}
      
      if (!found && !option_bool(OPT_NO_NEG))
	{
	  if (!searched_soa)
	    {
	      searched_soa = 1;
	      ttl = find_soa(header, qlen, doctored);
	    }
	  
	  flags |= F_NEG | (secure ?  F_DNSSECOK : 0);
	  if (name_encoding && ttl)
	    {
	      flags |= F_REVERSE | name_encoding;
	      cache_insert(NULL, &addr, C_IN, now, ttl, flags);
	    }
	  
	  log_query(flags | F_UPSTREAM, name, &addr, NULL, 0);
	}
    }
  else
    {
      /* everything other than PTR */
      struct crec *newc;
      int addrlen = 0, insert = 1;
      
      if (qtype == T_A)
	{
	  addrlen = INADDRSZ;
	  flags |= F_IPV4;
	}
      else if (qtype == T_AAAA)
	{
	  addrlen = IN6ADDRSZ;
	  flags |= F_IPV6;
	}
      else if (qtype == T_SRV)
	flags |= F_SRV;
      else
	insert = 0; /* NOTE: do not cache data from CNAME queries. */
      
    cname_loop1:
      if (!(p1 = skip_questions(header, qlen)))
	return 0;
      
      for (j = 0; j < ntohs(header->ancount); j++) 
	{
	  int secflag = 0;
	  
	  if (!(res = extract_name(header, qlen, &p1, name, 0, 10)))
	    return 0; /* bad packet */
	  
	  GETSHORT(aqtype, p1); 
	  GETSHORT(aqclass, p1);
	  GETLONG(attl, p1);
	  if ((daemon->max_ttl != 0) && (attl > daemon->max_ttl) && !is_sign)
	    {
	      (p1) -= 4;
	      PUTLONG(daemon->max_ttl, p1);
	    }
	  GETSHORT(ardlen, p1);
	  endrr = p1+ardlen;
	  
	  /* Not what we're looking for? */
	  if (aqclass != C_IN || res == 2)
	    {
	      p1 = endrr;
	      if (!CHECK_LEN(header, p1, qlen, 0))
		return 0; /* bad packet */
	      continue;
	    }
	  
#ifdef HAVE_DNSSEC
	  if (option_bool(OPT_DNSSEC_VALID) && !no_cache_dnssec && daemon->rr_status[j] != 0)
	    {
	      secflag = F_DNSSECOK;
	      
	      /* limit TTl based on sig. */
	      if (daemon->rr_status[j] < attl)
		attl = daemon->rr_status[j];
	    }
#endif	  
	  
	  if (aqtype == T_CNAME)
	    {
	      if (!cname_count--)
		return 0; /* looped CNAMES */
	      
	      log_query(secflag | F_CNAME | F_FORWARD | F_UPSTREAM, name, NULL, NULL, 0);
	      
	      if (insert)
		{
		  if ((newc = cache_insert(name, NULL, C_IN, now, attl, F_CNAME | F_FORWARD | secflag)))
		    {
		      newc->addr.cname.target.cache = NULL;
		      newc->addr.cname.is_name_ptr = 0; 
		      if (cpp)
			{
			  next_uid(newc);
			  cpp->addr.cname.target.cache = newc;
			  cpp->addr.cname.uid = newc->uid;
			}
		    }
		  
		  cpp = newc;
		  if (attl < cttl)
		    cttl = attl;
		}
	      
	      namep = p1;
	      if (!extract_name(header, qlen, &p1, name, 1, 0))
		return 0;
	      
	      if (qtype != T_CNAME)
		goto cname_loop1;

	      found = 1;
	    }
	  else if (aqtype != qtype)
	    {
#ifdef HAVE_DNSSEC
	      if (!option_bool(OPT_DNSSEC_VALID) || aqtype != T_RRSIG)
#endif
		log_query(secflag | F_FORWARD | F_UPSTREAM, name, NULL, NULL, aqtype);
	    }
	  else if (!(flags & F_NXDOMAIN))
	    {
	      found = 1;
	      
	      if (flags & F_SRV)
		{
		  unsigned char *tmp = namep;
		  
		  if (!CHECK_LEN(header, p1, qlen, 6))
		    return 0; /* bad packet */
		  GETSHORT(addr.srv.priority, p1);
		  GETSHORT(addr.srv.weight, p1);
		  GETSHORT(addr.srv.srvport, p1);
		  if (!extract_name(header, qlen, &p1, name, 1, 0))
		    return 0;
		  addr.srv.targetlen = strlen(name) + 1; /* include terminating zero */
		  if (!(addr.srv.target = blockdata_alloc(name, addr.srv.targetlen)))
		    return 0;
		  
		  /* we overwrote the original name, so get it back here. */
		  if (!extract_name(header, qlen, &tmp, name, 1, 0))
		    return 0;
		}
	      else if (flags & (F_IPV4 | F_IPV6))
		{
		  /* copy address into aligned storage */
		  if (!CHECK_LEN(header, p1, qlen, addrlen))
		    return 0; /* bad packet */
		  memcpy(&addr, p1, addrlen);
		  
		  /* check for returned address in private space */
		  if (check_rebind)
		    {
		      if ((flags & F_IPV4) &&
			  private_net(addr.addr4, !option_bool(OPT_LOCAL_REBIND)))
			return 1;
		      
		      if ((flags & F_IPV6) &&
			  private_net6(&addr.addr6, !option_bool(OPT_LOCAL_REBIND)))
			return 1;
		    }
		  
#ifdef HAVE_IPSET
		  if (ipsets && (flags & (F_IPV4 | F_IPV6)))
		    for (ipsets_cur = ipsets->sets; *ipsets_cur; ipsets_cur++)
		      if (add_to_ipset(*ipsets_cur, &addr, flags, 0) == 0)
			log_query((flags & (F_IPV4 | F_IPV6)) | F_IPSET, ipsets->domain, &addr, *ipsets_cur, 1);
#endif
#ifdef HAVE_NFTSET
		  if (nftsets && (flags & (F_IPV4 | F_IPV6)))
		    for (nftsets_cur = nftsets->sets; *nftsets_cur; nftsets_cur++)
		      if (add_to_nftset(*nftsets_cur, &addr, flags, 0) == 0)
			log_query((flags & (F_IPV4 | F_IPV6)) | F_IPSET, nftsets->domain, &addr, *nftsets_cur, 0);
#endif
		}
	      
	      if (insert)
		{
		  newc = cache_insert(name, &addr, C_IN, now, attl, flags | F_FORWARD | secflag);
		  if (newc && cpp)
		    {
		      next_uid(newc);
		      cpp->addr.cname.target.cache = newc;
		      cpp->addr.cname.uid = newc->uid;
		    }
		  cpp = NULL;
		}
	      
	      if (aqtype == T_TXT)
		{
		  if (!print_txt(header, qlen, name, p1, ardlen, secflag))
		    return 0;
		}
	      else
		log_query(flags | F_FORWARD | secflag | F_UPSTREAM, name, &addr, NULL, aqtype);
	    }
	  
	  p1 = endrr;
	  if (!CHECK_LEN(header, p1, qlen, 0))
	    return 0; /* bad packet */
	}
      
      if (!found && (qtype != T_ANY || (flags & F_NXDOMAIN)))
	{
	  if (flags & F_NXDOMAIN)
	    {
	      flags &= ~(F_IPV4 | F_IPV6 | F_SRV);
	      
	      /* Can store NXDOMAIN reply to CNAME or ANY query. */
	      if (qtype == T_CNAME || qtype == T_ANY)
		insert = 1;
	    }
	  
	  log_query(F_UPSTREAM | F_FORWARD | F_NEG | flags | (secure ? F_DNSSECOK : 0), name, NULL, NULL, 0);
	  
	  if (!searched_soa)
	    {
	      searched_soa = 1;
	      ttl = find_soa(header, qlen, doctored);
	    }
	  
	  /* If there's no SOA to get the TTL from, but there is a CNAME 
	     pointing at this, inherit its TTL */
	  if (insert && !option_bool(OPT_NO_NEG) && (ttl || cpp))
	    {
	      if (ttl == 0)
		ttl = cttl;
	      
	      newc = cache_insert(name, NULL, C_IN, now, ttl, F_FORWARD | F_NEG | flags | (secure ? F_DNSSECOK : 0));	
	      if (newc && cpp)
		{
		  next_uid(newc);
		  cpp->addr.cname.target.cache = newc;
		  cpp->addr.cname.uid = newc->uid;
		}
	    }
	}
    }
  
  /* Don't put stuff from a truncated packet into the cache.
     Don't cache replies from non-recursive nameservers, since we may get a 
     reply containing a CNAME but not its target, even though the target 
     does exist. */
  if (!(header->hb3 & HB3_TC) && 
      !(header->hb4 & HB4_CD) &&
      (header->hb4 & HB4_RA) &&
      !no_cache_dnssec)
    cache_end_insert();

  return 0;
}

#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)

/**
 * @brief Validate that name contains only printable ASCII characters
 *
 * @detailed
 * Safety check ensuring a domain name string contains only printable characters
 * (ASCII 32-126). Used before passing names to external integrations like ubus
 * event broadcasting to prevent injection attacks or malformed data propagation.
 * Rejects names with control characters, nulls, or high-bit characters that
 * could cause issues in log files, scripts, or external APIs. Simple validation
 * suitable for names extracted from DNS packets before external use.
 *
 * @param name Null-terminated string to validate (domain name)
 *
 * @return 1 (true) if all characters are printable (isprint() returns true)
 * @return 0 (false) if any character is non-printable (control char, null, extended ASCII)
 *
 * @note Uses standard isprint() which checks for ASCII 32-126 (space through tilde)
 * @note Domain names from DNS should be ASCII-safe, but malicious packets may not be
 * @note Rejects high-bit characters (> 127) which could be UTF-8 or malicious
 * @note Compiled only when HAVE_CONNTRACK and HAVE_UBUS are both defined
 *
 * @warning Does not validate DNS name syntax (labels, dots, length limits)
 * @warning Only checks printability, not DNS name validity
 *
 * @see report_addresses() which uses this before ubus event broadcasting
 * @see isprint() for printable character determination
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME];
 * // ... extract name from DNS packet ...
 * if (safe_name(name))
 *     ubus_event_bcast_connmark_allowlist_resolved(mark, name, ip, ttl);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not DNS-specific. General safety check for external API integration.
 *
 * SIDE EFFECTS:
 * None. Pure validation function.
 *
 * THREAD SAFETY:
 * Thread-safe. Pure function with no global state.
 */
/* Don't pass control chars and weird escapes to UBus. */
static int safe_name(char *name)
{
  unsigned char *r;
  
  for (r = (unsigned char *)name; *r; r++)
    if (!isprint((int)*r))
      return 0;
  
  return 1;
}

/**
 * @brief Broadcast resolved address records via ubus for conntrack integration
 *
 * @detailed
 * Extracts A, AAAA, and CNAME records from DNS responses and broadcasts them via
 * ubus events for conntrack-based firewalling and allowlist management. Used on
 * OpenWrt systems with connmark allowlist filtering to notify firewall of resolved
 * addresses matching connection tracking marks. Skips reporting if packet has error
 * RCODE or if mark matches allowlist wildcard patterns. Validates names with safe_name()
 * before broadcasting to prevent injection attacks. Only processes C_IN class records.
 *
 * @param header Pointer to DNS packet header
 * @param len Total length of DNS packet in bytes
 * @param mark Connection tracking mark (connmark) associated with this query
 *
 * @return None (void function)
 *
 * @note Only compiled when HAVE_CONNTRACK and HAVE_UBUS are both defined
 * @note Skips processing if RCODE is not NOERROR (errors not reported)
 * @note Skips if mark matches allowlist wildcard pattern ("*")
 * @note Uses daemon->allowlist_mask and allowlist->mask for mark matching
 * @note Broadcasts via ubus_event_bcast_connmark_allowlist_resolved() (ubus.c)
 * @note Validates names with safe_name() to prevent control character injection
 *
 * @warning Accesses global daemon->allowlists and daemon->namebuff/workspacename
 * @warning Returns silently on any parsing error (malformed packet)
 * @warning No error indication - failures are silent
 *
 * @see safe_name() for name validation before broadcasting
 * @see ubus_event_bcast_connmark_allowlist_resolved() in ubus.c for event broadcasting
 * @see extract_addresses() for similar address extraction for caching
 *
 * EXAMPLE USAGE:
 * @code
 * u32 conn_mark = get_connection_mark();
 * struct dns_header *response = receive_dns_response();
 * report_addresses(response, response_len, conn_mark);
 * // Addresses now broadcast to ubus subscribers
 * @endcode
 *
 * RFC COMPLIANCE:
 * Uses standard DNS packet format (RFC 1035). Ubus broadcasting is platform-specific.
 *
 * SIDE EFFECTS:
 * - Broadcasts ubus events (external IPC)
 * - Uses global daemon->namebuff and daemon->workspacename as scratch buffers
 * - Accesses global daemon->allowlists configuration
 *
 * THREAD SAFETY:
 * Not thread-safe. Uses global buffers, accesses global daemon config.
 * Must be called from single-threaded event loop context.
 */
void report_addresses(struct dns_header *header, size_t len, u32 mark)
{
  unsigned char *p, *endrr;
  int i;
  unsigned long attl;
  struct allowlist *allowlists;
  char **pattern_pos;
  
  if (RCODE(header) != NOERROR)
    return;
  
  for (allowlists = daemon->allowlists; allowlists; allowlists = allowlists->next)
    if (allowlists->mark == (mark & daemon->allowlist_mask & allowlists->mask))
      for (pattern_pos = allowlists->patterns; *pattern_pos; pattern_pos++)
	if (!strcmp(*pattern_pos, "*"))
	  return;
  
  if (!(p = skip_questions(header, len)))
    return;
  for (i = ntohs(header->ancount); i != 0; i--)
    {
      int aqtype, aqclass, ardlen;
      
      if (!extract_name(header, len, &p, daemon->namebuff, 1, 10))
	return;
      
      if (!CHECK_LEN(header, p, len, 10))
	return;
      GETSHORT(aqtype, p);
      GETSHORT(aqclass, p);
      GETLONG(attl, p);
      GETSHORT(ardlen, p);
      
      if (!CHECK_LEN(header, p, len, ardlen))
	return;
      endrr = p+ardlen;
      
      if (aqclass == C_IN)
	{
	  if (aqtype == T_CNAME)
	    {
	      if (!extract_name(header, len, &p, daemon->workspacename, 1, 0))
		return;
	      if (safe_name(daemon->namebuff) && safe_name(daemon->workspacename))
		ubus_event_bcast_connmark_allowlist_resolved(mark, daemon->namebuff, daemon->workspacename, attl);
	    }
	  if (aqtype == T_A)
	    {
	      struct in_addr addr;
	      char ip[INET_ADDRSTRLEN];
	      if (ardlen != INADDRSZ)
		return;
	      memcpy(&addr, p, ardlen);
	      if (inet_ntop(AF_INET, &addr, ip, sizeof ip) && safe_name(daemon->namebuff))
		ubus_event_bcast_connmark_allowlist_resolved(mark, daemon->namebuff, ip, attl);
	    }
	  else if (aqtype == T_AAAA)
	    {
	      struct in6_addr addr;
	      char ip[INET6_ADDRSTRLEN];
	      if (ardlen != IN6ADDRSZ)
		return;
	      memcpy(&addr, p, ardlen);
	      if (inet_ntop(AF_INET6, &addr, ip, sizeof ip) && safe_name(daemon->namebuff))
		ubus_event_bcast_connmark_allowlist_resolved(mark, daemon->namebuff, ip, attl);
	    }
	}
      
      p = endrr;
    }
}
#endif

/**
 * @brief Extract query name and type from DNS request packet
 *
 * @detailed
 * Parses the question section of a DNS query packet to extract the queried domain name
 * and determine the query type. Validates that packet contains exactly one question
 * (qdcount=1), is a standard query (OPCODE=QUERY), and is properly formed. Returns
 * flags indicating address family (F_IPV4 for A, F_IPV6 for AAAA, both for T_ANY) or
 * query category. Sets query type in typep output parameter. Used by query processing
 * to determine routing and caching strategy. Rejects non-standard queries (with answers/
 * authority in query packet) and malformed packets.
 *
 * @param header Pointer to DNS packet header
 * @param qlen Total length of DNS packet in bytes
 * @param name Output buffer for extracted query name (must be MAXDNAME bytes)
 * @param typep Output pointer for query type (QTYPE), or NULL if not needed
 *
 * @return F_IPV4 if query is C_IN class T_A type (IPv4 address query)
 * @return F_IPV6 if query is C_IN class T_AAAA type (IPv6 address query)
 * @return F_IPV4|F_IPV6 if query is C_IN class T_ANY type (any address)
 * @return F_DNSSECOK if query is DS or DNSKEY (DNSSEC, HAVE_DNSSEC only)
 * @return F_QUERY for other query types (MX, PTR, TXT, etc.)
 * @return 0 on error (malformed packet, non-standard query, multiple questions)
 *
 * @note Requires exactly one question (qdcount=1) - rejects multiple questions
 * @note Requires standard query (OPCODE=QUERY) - rejects IQUERY, STATUS, NOTIFY
 * @note Rejects queries with ancount/nscount > 0 (non-standard)
 * @note Sets *name to empty string if no valid query found
 * @note Sets *typep to 0 if typep is non-NULL but no valid query found
 *
 * @warning name buffer must be at least MAXDNAME (1025) bytes
 * @warning typep may be NULL if query type not needed
 * @warning Returns 0 for multiple error conditions - caller cannot distinguish
 *
 * @see extract_name() for QNAME extraction from packet
 * @see forward.c receive_query() which calls this for query routing
 * @see F_IPV4, F_IPV6, F_QUERY, F_DNSSECOK flag definitions
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * char qname[MAXDNAME];
 * unsigned short qtype;
 * unsigned int flags = extract_request(header, len, qname, &qtype);
 * if (flags & (F_IPV4|F_IPV6))
 *     printf("Address query for %s type %d\n", qname, qtype);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 4.1.2 (Question section format).
 * OPCODE validation per RFC 1035 Section 4.1.1.
 *
 * SIDE EFFECTS:
 * - Writes extracted name to name buffer
 * - Writes query type to *typep if typep non-NULL
 *
 * THREAD SAFETY:
 * Thread-safe for packet parsing. Output buffers must not be shared across threads.
 */
/* If the packet holds exactly one query
   return F_IPV4 or F_IPV6  and leave the name from the query in name */
unsigned int extract_request(struct dns_header *header, size_t qlen, char *name, unsigned short *typep)
{
  unsigned char *p = (unsigned char *)(header+1);
  int qtype, qclass;

  if (typep)
    *typep = 0;

  *name = 0; /* return empty name if no query found. */
  
  if (ntohs(header->qdcount) != 1 || OPCODE(header) != QUERY)
    return 0; /* must be exactly one query. */
  
  if (!(header->hb3 & HB3_QR) && (ntohs(header->ancount) != 0 || ntohs(header->nscount) != 0))
    return 0; /* non-standard query. */
  
  if (!extract_name(header, qlen, &p, name, 1, 4))
    return 0; /* bad packet */
   
  GETSHORT(qtype, p); 
  GETSHORT(qclass, p);

  if (typep)
    *typep = qtype;

  if (qclass == C_IN)
    {
      if (qtype == T_A)
	return F_IPV4;
      if (qtype == T_AAAA)
	return F_IPV6;
      if (qtype == T_ANY)
	return  F_IPV4 | F_IPV6;
    }

#ifdef HAVE_DNSSEC
  /* F_DNSSECOK as agument to search_servers() inhibits forwarding
     to servers for domains without a trust anchor. This make the
     behaviour for DS and DNSKEY queries we forward the same
     as for DS and DNSKEY queries we originate. */
  if (option_bool(OPT_DNSSEC_VALID) && (qtype == T_DS || qtype == T_DNSKEY))
    return F_DNSSECOK;
#endif
  
  return F_QUERY;
}

/**
 * @brief Initialize DNS response header with appropriate flags and RCODE
 *
 * @detailed
 * Prepares a DNS packet header for use as a response by setting/clearing header flags
 * appropriately. Sets QR (query/response) flag, clears AA (authoritative answer) and
 * TC (truncated) flags, sets RA (recursion available), clears AD (authenticated data),
 * and zeros all section counts. Sets RCODE based on flags parameter: NOERROR for
 * successful/empty responses, NXDOMAIN for non-existent domains, REFUSED for forwarding
 * failures with optional EDE (Extended DNS Error) logging. Sets AA flag for local
 * authoritative answers (F_IPV4|F_IPV6 flag present).
 *
 * @param header Pointer to DNS packet header to initialize for response
 * @param flags Response type flags: F_NOERR (empty), F_NXDOMAIN, F_IPV4|F_IPV6 (local auth), other (refused)
 * @param ede Extended DNS Error code for REFUSED responses (RFC 8914), or EDE_UNSET if none
 *
 * @return None (void function)
 *
 * @note Sets QR flag (this is a response, not a query)
 * @note Clears AA and TC flags initially; sets AA if F_IPV4/F_IPV6 present (local authority)
 * @note Sets RA flag (recursion available)
 * @note Clears AD flag (authenticated data - set later if DNSSEC validated)
 * @note Zeros ancount/nscount/arcount - caller adds records after this initialization
 * @note Logs REFUSED responses with RCODE and EDE code
 *
 * @warning Modifies header in-place - not safe for shared/cached packets
 * @warning Caller must populate answer section after setup_reply()
 * @warning EDE logging only occurs for REFUSED responses
 *
 * @see extract_request() for extracting query information before setup_reply()
 * @see answer_request() which calls setup_reply() during response generation
 * @see RFC 1035 Section 4.1.1 for DNS header format and flag meanings
 * @see RFC 8914 for Extended DNS Errors (EDE)
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)response_buf;
 * memcpy(header, query_header, sizeof(*header)); // Copy query header
 * setup_reply(header, F_IPV4, EDE_UNSET); // Initialize for A record response
 * // Now add answer records...
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 4.1.1 (header format) and RFC 8914 (EDE).
 *
 * SIDE EFFECTS:
 * - Modifies header flags and section counts in-place
 * - Logs to query log if REFUSED (F_CONFIG | F_RCODE)
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies header in-place. Single-threaded use only.
 */
void setup_reply(struct dns_header *header, unsigned int flags, int ede)
{
  /* clear authoritative and truncated flags, set QR flag */
  header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC )) | HB3_QR;
  /* clear AD flag, set RA flag */
  header->hb4 = (header->hb4 & ~HB4_AD) | HB4_RA;

  header->nscount = htons(0);
  header->arcount = htons(0);
  header->ancount = htons(0); /* no answers unless changed below */
  if (flags == F_NOERR)
    SET_RCODE(header, NOERROR); /* empty domain */
  else if (flags == F_NXDOMAIN)
    SET_RCODE(header, NXDOMAIN);
  else if (flags & ( F_IPV4 | F_IPV6))
    {
      SET_RCODE(header, NOERROR);
      header->hb3 |= HB3_AA;
    }
  else /* nowhere to forward to */
    {
      union all_addr a;
      a.log.rcode = REFUSED;
      a.log.ede = ede;
      log_query(F_CONFIG | F_RCODE, "error", &a, NULL, 0);
      SET_RCODE(header, REFUSED);
    }
}

/**
 * @brief Check if domain name matches locally-served authoritative records
 *
 * @detailed
 * Determines if a queried domain name should be answered locally (authoritatively)
 * rather than forwarded to upstream servers. Searches through all local record
 * configuration lists: NAPTR records, MX records, TXT records, interface names,
 * PTR records, and cache non-terminal entries. Uses hostname_issubdomain() to check
 * if query name is a subdomain of any configured local domain. Used by query routing
 * logic to decide whether to generate local authoritative answer or forward to upstream.
 *
 * @param name Query domain name to check against local configuration
 * @param now Current time for cache lookup timestamp
 *
 * @return 1 (true) if name matches any local authoritative record configuration
 * @return 0 (false) if name is not locally served and should be forwarded
 *
 * @note Checks daemon->naptr, daemon->mxnames, daemon->txt, daemon->int_names, daemon->ptr
 * @note Uses hostname_issubdomain() for wildcard subdomain matching
 * @note Checks cache_find_non_terminal() for CNAME/DNAME records that create subdomains
 * @note Used by forward.c to determine if query should be answered locally
 *
 * @warning Accesses global daemon structure for configuration lists
 * @warning Order of checks may affect performance for common cases
 *
 * @see hostname_issubdomain() for subdomain matching logic
 * @see cache_find_non_terminal() for cache-based subdomain detection
 * @see forward.c for query routing decisions using this function
 * @see --mx-host, --txt-record, --ptr-record, --naptr-record configuration options
 *
 * EXAMPLE USAGE:
 * @code
 * char qname[MAXDNAME];
 * strcpy(qname, "subdomain.localnet");
 * if (check_for_local_domain(qname, time(NULL)))
 *     // Answer locally, don't forward
 * else
 *     // Forward to upstream
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not protocol-specific. Internal routing decision based on local configuration.
 *
 * SIDE EFFECTS:
 * - Accesses global daemon->naptr, ->mxnames, ->txt, ->int_names, ->ptr
 * - Calls cache_find_non_terminal() which may update cache access timestamps
 *
 * THREAD SAFETY:
 * Not thread-safe. Accesses global daemon configuration lists.
 * Must be called from single-threaded event loop context.
 */
/* check if name matches local names ie from /etc/hosts or DHCP or local mx names. */
int check_for_local_domain(char *name, time_t now)
{
  struct mx_srv_record *mx;
  struct txt_record *txt;
  struct interface_name *intr;
  struct ptr_record *ptr;
  struct naptr *naptr;

  for (naptr = daemon->naptr; naptr; naptr = naptr->next)
     if (hostname_issubdomain(name, naptr->name))
      return 1;

   for (mx = daemon->mxnames; mx; mx = mx->next)
    if (hostname_issubdomain(name, mx->name))
      return 1;

  for (txt = daemon->txt; txt; txt = txt->next)
    if (hostname_issubdomain(name, txt->name))
      return 1;

  for (intr = daemon->int_names; intr; intr = intr->next)
    if (hostname_issubdomain(name, intr->name))
      return 1;

  for (ptr = daemon->ptr; ptr; ptr = ptr->next)
    if (hostname_issubdomain(name, ptr->name))
      return 1;

  if (cache_find_non_terminal(name, now))
    return 1;

  return 0;
}

/**
 * @brief Check if DNS answer contains addresses matching bogus/ignore configuration
 *
 * @detailed
 * Scans answer section of a DNS response for A/AAAA records containing addresses that
 * match a configured list of bogus or ignored address ranges. Used to implement
 * --bogus-nxdomain and --ignore-address options. Compares each address record against
 * the provided bogus_addr linked list using network prefix matching. Optionally extracts
 * the answer name and TTL for cache insertion. Returns immediately on first match without
 * checking remaining records. Used as a subroutine by check_for_bogus_wildcard() and
 * check_for_ignored_address().
 *
 * @param header Pointer to DNS packet header
 * @param qlen Total length of DNS packet in bytes
 * @param baddr Linked list of bogus_addr structures defining address ranges to detect
 * @param name Output buffer for answer name (may be NULL if name not needed)
 * @param ttlp Output pointer for answer TTL (may be NULL if TTL not needed)
 *
 * @return 1 (true) if any answer address matches configured bogus/ignore ranges
 * @return 0 (false) if no match found or packet malformed
 *
 * @note Only checks C_IN class records (T_A for IPv4, T_AAAA for IPv6)
 * @note Uses is_same_net_prefix() for IPv4 and is_same_net6() for IPv6 prefix matching
 * @note Processes ancount records from answer section only (not authority/additional)
 * @note Returns 0 on malformed packet (safe fallback - no bogus match)
 * @note If name is NULL, skips name extraction for performance
 * @note If ttlp is NULL, TTL extracted but not returned
 *
 * @warning Returns 0 on parse error - cannot distinguish from "no match"
 * @warning name buffer must be MAXDNAME bytes if provided
 *
 * @see check_for_bogus_wildcard() which uses this for --bogus-nxdomain
 * @see check_for_ignored_address() which uses this for --ignore-address
 * @see struct bogus_addr in dnsmasq.h for address range configuration
 * @see is_same_net_prefix() and is_same_net6() for prefix matching
 *
 * EXAMPLE USAGE:
 * @code
 * char name[MAXDNAME];
 * unsigned long ttl;
 * if (check_bad_address(header, len, daemon->bogus_addr, name, &ttl))
 *     log_query(F_CONFIG, name, NULL, "bogus address detected");
 * @endcode
 *
 * RFC COMPLIANCE:
 * Standard DNS packet parsing per RFC 1035. Address filtering is a local policy extension.
 *
 * SIDE EFFECTS:
 * - Writes answer name to name buffer if name is non-NULL
 * - Writes answer TTL to *ttlp if ttlp is non-NULL
 *
 * THREAD SAFETY:
 * Thread-safe for packet parsing. Output buffers must not be shared across threads.
 */
static int check_bad_address(struct dns_header *header, size_t qlen, struct bogus_addr *baddr, char *name, unsigned long *ttlp)
{
  unsigned char *p;
  int i, qtype, qclass, rdlen;
  unsigned long ttl;
  struct bogus_addr *baddrp;
  
  /* skip over questions */
  if (!(p = skip_questions(header, qlen)))
    return 0; /* bad packet */

  for (i = ntohs(header->ancount); i != 0; i--)
    {
      if (name && !extract_name(header, qlen, &p, name, 1, 10))
	return 0; /* bad packet */

      if (!name && !(p = skip_name(p, header, qlen, 10)))
	return 0;
      
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);

      if (ttlp)
	*ttlp = ttl;
      
      if (qclass == C_IN)
	{
	  if (qtype == T_A)
	    {
	      struct in_addr addr;
	      
	      if (!CHECK_LEN(header, p, qlen, INADDRSZ))
		return 0;

	      memcpy(&addr, p, INADDRSZ);

	      for (baddrp = baddr; baddrp; baddrp = baddrp->next)
		if (!baddrp->is6 && is_same_net_prefix(addr, baddrp->addr.addr4, baddrp->prefix))
		  return 1;
	    }
	  else if (qtype == T_AAAA)
	    {
	      struct in6_addr addr;
	      
	      if (!CHECK_LEN(header, p, qlen, IN6ADDRSZ))
		return 0;

	      memcpy(&addr, p, IN6ADDRSZ);

	      for (baddrp = baddr; baddrp; baddrp = baddrp->next)
		if (baddrp->is6 && is_same_net6(&addr, &baddrp->addr.addr6, baddrp->prefix))
		  return 1;
	    }
	}
      
      if (!ADD_RDLEN(header, p, qlen, rdlen))
	return 0;
    }
  
  return 0;
}

/**
 * @brief Detect and convert bogus wildcard responses to NXDOMAIN
 *
 * @detailed
 * Implements --bogus-nxdomain option by detecting DNS responses containing configured
 * bogus addresses (typically used by ISP redirect/intercept systems or DNS poisoning).
 * If any answer address matches daemon->bogus_addr configuration, converts the response
 * to NXDOMAIN by caching a negative entry. Used to defeat wildcard DNS hijacking where
 * ISPs return their own addresses for non-existent domains instead of proper NXDOMAIN.
 * Creates a negative cache entry with F_NXDOMAIN flag using the TTL from the bogus
 * answer record. Common bogus addresses include ISP redirect pages (e.g., 127.0.53.53).
 *
 * @param header Pointer to DNS packet header (will be converted to NXDOMAIN if bogus)
 * @param qlen Total length of DNS packet in bytes
 * @param name Domain name that was queried (for negative cache entry)
 * @param now Current time for negative cache insertion timestamp
 *
 * @return 1 (true) if bogus address detected and negative cache entry inserted
 * @return 0 (false) if no bogus address found (legitimate response)
 *
 * @note Uses check_bad_address() to scan for configured bogus address ranges
 * @note Inserts negative cache entry with F_IPV4|F_FORWARD|F_NEG|F_NXDOMAIN flags
 * @note TTL for negative cache taken from the bogus answer record's TTL
 * @note No SOA record available for TTL, so uses answer TTL directly
 * @note Configured via --bogus-nxdomain command-line option
 *
 * @warning Modifies global cache by inserting negative entry
 * @warning Caller must convert packet header to NXDOMAIN RCODE after this returns 1
 * @warning name must be valid domain name (from extract_request)
 *
 * @see check_bad_address() for address matching implementation
 * @see cache_insert() for negative cache entry creation
 * @see --bogus-nxdomain command-line option for configuration
 * @see forward.c reply_query() which uses this to filter bogus responses
 *
 * EXAMPLE USAGE:
 * @code
 * char qname[MAXDNAME];
 * extract_request(header, len, qname, NULL);
 * if (check_for_bogus_wildcard(header, len, qname, time(NULL))) {
 *     setup_reply(header, F_NXDOMAIN, EDE_UNSET);
 *     // Response converted to NXDOMAIN
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * Converts legitimate response to NXDOMAIN (RFC 1035 Section 4.1.1) based on local
 * policy. Used to defeat non-compliant ISP DNS interception/hijacking.
 *
 * SIDE EFFECTS:
 * - Inserts negative cache entry into global DNS cache
 * - Calls cache_start_insert() and cache_end_insert()
 * - Accesses global daemon->bogus_addr configuration
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies global cache. Must be called from single-threaded event loop.
 */
/* Is the packet a reply with the answer address equal to addr?
   If so mung is into an NXDOMAIN reply and also put that information
   in the cache. */
int check_for_bogus_wildcard(struct dns_header *header, size_t qlen, char *name, time_t now)
{
  unsigned long ttl;

  if (check_bad_address(header, qlen, daemon->bogus_addr, name, &ttl))
    {
      /* Found a bogus address. Insert that info here, since there no SOA record
	 to get the ttl from in the normal processing */
      cache_start_insert();
      cache_insert(name, NULL, C_IN, now, ttl, F_IPV4 | F_FORWARD | F_NEG | F_NXDOMAIN);
      cache_end_insert();

      return 1;
    }

  return 0;
}

/**
 * @brief Check if DNS response contains addresses matching --ignore-address configuration
 *
 * @detailed
 * Implements --ignore-address option by detecting DNS responses containing configured
 * address ranges that should be silently ignored (dropped). Unlike --bogus-nxdomain,
 * this does not cache negative entries or convert to NXDOMAIN - it simply indicates
 * that the response should be discarded. Used to filter out unwanted addresses from
 * upstream responses without affecting caching behavior. Lightweight wrapper around
 * check_bad_address() that uses daemon->ignore_addr configuration without extracting
 * name or TTL.
 *
 * @param header Pointer to DNS packet header
 * @param qlen Total length of DNS packet in bytes
 *
 * @return 1 (true) if any answer address matches daemon->ignore_addr configuration
 * @return 0 (false) if no ignored address found (response should be processed normally)
 *
 * @note Uses check_bad_address() with daemon->ignore_addr and NULL name/ttl
 * @note More efficient than check_for_bogus_wildcard() as it doesn't extract name/TTL
 * @note Caller typically drops packet silently on return value 1
 * @note Configured via --ignore-address command-line option
 * @note Different from --bogus-nxdomain: no caching, just drop
 *
 * @warning Accesses global daemon->ignore_addr configuration
 *
 * @see check_bad_address() for address matching implementation
 * @see check_for_bogus_wildcard() for similar bogus address detection with caching
 * @see --ignore-address command-line option for configuration
 * @see forward.c reply_query() which uses this to filter responses
 *
 * EXAMPLE USAGE:
 * @code
 * if (check_for_ignored_address(header, len)) {
 *     // Drop this response silently, don't cache or forward
 *     return;
 * }
 * // Process response normally
 * @endcode
 *
 * RFC COMPLIANCE:
 * Filters responses based on local policy. Does not violate RFC compliance as responses
 * are simply not forwarded (equivalent to packet loss).
 *
 * SIDE EFFECTS:
 * - Accesses global daemon->ignore_addr configuration
 * - No cache modifications (unlike check_for_bogus_wildcard)
 *
 * THREAD SAFETY:
 * Thread-safe for packet parsing. Accesses global read-only configuration.
 */
int check_for_ignored_address(struct dns_header *header, size_t qlen)
{
  return check_bad_address(header, qlen, daemon->ignore_addr, NULL, NULL);
}

/**
 * @brief Add a resource record to DNS response packet with automatic truncation handling
 *
 * @detailed
 * Constructs and appends a DNS resource record to a response packet using variable
 * arguments specified by format string. Handles name compression via nameoffset pointer,
 * automatic RDATA length calculation, and truncation detection if record exceeds buffer
 * limit. Supports multiple RDATA formats via format string: '4'=IPv4 address, '6'=IPv6,
 * 'b'=byte, 's'=short, 'l'=long, 'd'=domain name, 't'=raw bytes, 'z'=length-prefixed
 * string. Updates *pp pointer to position after added record. Used extensively by
 * answer_request() and other response generation functions. Sets truncation flag if
 * limit exceeded, allowing caller to set TC bit and handle truncation appropriately.
 *
 * @param header Pointer to DNS packet header (for base address calculations)
 * @param limit Pointer to buffer limit, or NULL to disable limit checking
 * @param truncp Pointer to truncation flag: set to 1 if truncation occurs, or NULL
 * @param nameoffset Name compression: >0=offset for pointer, <0=negate for pointer after name, 0=full name from varargs
 * @param pp Pointer to current position pointer in packet; updated to position after record
 * @param ttl Time-to-live value for this resource record (seconds)
 * @param offset Output pointer for domain name offset in RDATA (for 'd' format), or NULL
 * @param type DNS record type (T_A, T_AAAA, T_CNAME, T_MX, etc.)
 * @param class DNS class (typically C_IN)
 * @param format Format string specifying RDATA layout and varargs types
 * @param ... Variable arguments based on format string specification
 *
 * @return 1 on success (record added, *pp updated)
 * @return 0 on truncation (limit exceeded, *truncp set if provided)
 *
 * @note Format characters: '4'=IPv4 (char*, INADDRSZ), '6'=IPv6 (char*, IN6ADDRSZ),
 *       'b'=byte (int), 's'=short (int), 'l'=long (long), 'd'=domain name (char*),
 *       't'=raw bytes (int len, char* data), 'z'=length-prefixed string (char*, max 255)
 * @note nameoffset encoding: >0=use as compression pointer offset, <0=negate and use
 *       as pointer after extracting name from varargs, 0=use full name from varargs
 * @note RDLENGTH calculated automatically from format processing
 * @note Sets *truncp=1 if truncation occurs (caller should set TC bit in header)
 * @note 'd' format writes null-terminated domain name with compression
 *
 * @warning Format string must match varargs types exactly - no type checking
 * @warning limit pointer must point to valid buffer end or be NULL
 * @warning Caller must increment appropriate section count in header after success
 * @warning Domain names in RDATA ('d' format) limited by buffer size
 *
 * @see do_rfc1035_name() for domain name encoding with compression
 * @see answer_request() for extensive use of this function
 * @see PUTSHORT, PUTLONG macros for network byte order encoding
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = packet + sizeof(struct dns_header);
 * int trunc = 0;
 * // Add A record: example.com -> 192.0.2.1
 * struct in_addr addr;
 * inet_aton("192.0.2.1", &addr);
 * if (add_resource_record(header, packet + 512, &trunc, name_offset, &p,
 *                         3600, NULL, T_A, C_IN, "4", &addr))
 *     header->ancount = htons(ntohs(header->ancount) + 1);
 * @endcode
 *
 * RFC COMPLIANCE:
 * Resource record format per RFC 1035 Section 4.1.3 (NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA).
 *
 * SIDE EFFECTS:
 * - Updates *pp to point after added record
 * - Sets *truncp to 1 if truncation occurs
 * - Sets *offset to domain name position if offset non-NULL and 'd' format used
 * - Writes record data to packet buffer
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies packet buffer. Single-threaded use only.
 */
int add_resource_record(struct dns_header *header, char *limit, int *truncp, int nameoffset, unsigned char **pp, 
			unsigned long ttl, int *offset, unsigned short type, unsigned short class, char *format, ...)
{
  va_list ap;
  unsigned char *sav, *p = *pp;
  int j;
  unsigned short usval;
  long lval;
  char *sval;
  
#define CHECK_LIMIT(size) \
  if (limit && p + (size) > (unsigned char*)limit) goto truncated;

  va_start(ap, format);   /* make ap point to 1st unamed argument */
  
  if (truncp && *truncp)
    goto truncated;
  
  if (nameoffset > 0)
    {
      CHECK_LIMIT(2);
      PUTSHORT(nameoffset | 0xc000, p);
    }
  else
    {
      char *name = va_arg(ap, char *);
      if (name && !(p = do_rfc1035_name(p, name, limit)))
	goto truncated;
      
      if (nameoffset < 0)
	{
	  CHECK_LIMIT(2);
	  PUTSHORT(-nameoffset | 0xc000, p);
	}
      else
	{
	  CHECK_LIMIT(1);
	  *p++ = 0;
	}
    }

  /* type (2) + class (2) + ttl (4) + rdlen (2) */
  CHECK_LIMIT(10);
  
  PUTSHORT(type, p);
  PUTSHORT(class, p);
  PUTLONG(ttl, p);      /* TTL */

  sav = p;              /* Save pointer to RDLength field */
  PUTSHORT(0, p);       /* Placeholder RDLength */

  for (; *format; format++)
    switch (*format)
      {
      case '6':
        CHECK_LIMIT(IN6ADDRSZ);
	sval = va_arg(ap, char *); 
	memcpy(p, sval, IN6ADDRSZ);
	p += IN6ADDRSZ;
	break;
	
      case '4':
        CHECK_LIMIT(INADDRSZ);
	sval = va_arg(ap, char *); 
	memcpy(p, sval, INADDRSZ);
	p += INADDRSZ;
	break;
	
      case 'b':
        CHECK_LIMIT(1);
	usval = va_arg(ap, int);
	*p++ = usval;
	break;
	
      case 's':
        CHECK_LIMIT(2);
	usval = va_arg(ap, int);
	PUTSHORT(usval, p);
	break;
	
      case 'l':
        CHECK_LIMIT(4);
	lval = va_arg(ap, long);
	PUTLONG(lval, p);
	break;
	
      case 'd':
        /* get domain-name answer arg and store it in RDATA field */
        if (offset)
          *offset = p - (unsigned char *)header;
        if (!(p = do_rfc1035_name(p, va_arg(ap, char *), limit)))
	  goto truncated;
	CHECK_LIMIT(1);
        *p++ = 0;
	break;
	
      case 't':
	usval = va_arg(ap, int);
        CHECK_LIMIT(usval);
	sval = va_arg(ap, char *);
	if (usval != 0)
	  memcpy(p, sval, usval);
	p += usval;
	break;

      case 'z':
	sval = va_arg(ap, char *);
	usval = sval ? strlen(sval) : 0;
	if (usval > 255)
	  usval = 255;
        CHECK_LIMIT(usval + 1);
	*p++ = (unsigned char)usval;
	memcpy(p, sval, usval);
	p += usval;
	break;
      }

  va_end(ap);	/* clean up variable argument pointer */
  
  /* Now, store real RDLength. sav already checked against limit. */
  j = p - sav - 2;
  PUTSHORT(j, sav);
  
  *pp = p;
  return 1;
  
 truncated:
  va_end(ap);
  if (truncp)
    *truncp = 1;
  return 0;

#undef CHECK_LIMIT
}

/**
 * @brief Calculate effective TTL for cache record based on type and configuration
 *
 * @detailed
 * Determines the appropriate TTL value to return in DNS responses for a given cache
 * record, accounting for record type (DHCP vs normal), immortal flag, configured TTL
 * limits, and remaining lifetime. DHCP entries use configured local_ttl or dhcp_ttl
 * (if use_dhcp_ttl set), capped by actual lease expiry time. Immortal entries (from
 * /etc/hosts or config) use configured TTL from ttd field. Normal cached entries use
 * remaining TTL (ttd - now), capped by daemon->max_ttl if configured. Prevents returning
 * TTLs longer than configured maximum or longer than DHCP lease lifetimes.
 *
 * @param crecp Pointer to cache record (struct crec) to calculate TTL for
 * @param now Current time for TTL calculation (time_t seconds since epoch)
 *
 * @return Effective TTL in seconds to use in DNS response
 *
 * @note DHCP entries (F_DHCP flag): Use daemon->local_ttl or daemon->dhcp_ttl,
 *       capped by lease expiry (ttd - now) unless F_IMMORTAL
 * @note Immortal non-DHCP entries (F_IMMORTAL without F_DHCP): Return ttd field directly
 *       (contains configured TTL, not expiry time)
 * @note Normal cached entries: Return remaining TTL (ttd - now), capped by daemon->max_ttl
 * @note daemon->max_ttl == 0 means no maximum TTL cap
 *
 * @warning Assumes crecp is valid and not null
 * @warning Accesses global daemon->use_dhcp_ttl, daemon->dhcp_ttl, daemon->local_ttl, daemon->max_ttl
 * @warning May return 0 or negative if cache entry has expired (caller should check)
 *
 * @see struct crec in dnsmasq.h for cache record structure
 * @see answer_request() which uses this for response generation
 * @see --local-ttl, --dhcp-ttl, --max-ttl command-line options
 *
 * EXAMPLE USAGE:
 * @code
 * struct crec *cache_entry = cache_lookup(...);
 * unsigned long ttl = crec_ttl(cache_entry, time(NULL));
 * add_resource_record(header, limit, &trunc, name_offset, &p, ttl, ...);
 * @endcode
 *
 * RFC COMPLIANCE:
 * TTL value per RFC 1035 Section 4.1.3. TTL capping is a local policy extension.
 *
 * SIDE EFFECTS:
 * - Accesses global daemon configuration fields
 *
 * THREAD SAFETY:
 * Thread-safe for reading. Accesses global read-only configuration.
 */
static unsigned long crec_ttl(struct crec *crecp, time_t now)
{
  /* Return 0 ttl for DHCP entries, which might change
     before the lease expires, unless configured otherwise. */

  if (crecp->flags & F_DHCP)
    {
      int conf_ttl = daemon->use_dhcp_ttl ? daemon->dhcp_ttl : daemon->local_ttl;
      
      /* Apply ceiling of actual lease length to configured TTL. */
      if (!(crecp->flags & F_IMMORTAL) && (crecp->ttd - now) < conf_ttl)
	return crecp->ttd - now;
      
      return conf_ttl;
    }	  
  
  /* Immortal entries other than DHCP are local, and hold TTL in TTD field. */
  if (crecp->flags & F_IMMORTAL)
    return crecp->ttd;

  /* Return the Max TTL value if it is lower than the actual TTL */
  if (daemon->max_ttl == 0 || ((unsigned)(crecp->ttd - now) < daemon->max_ttl))
    return crecp->ttd - now;
  else
    return daemon->max_ttl;
}

/**
 * @brief Check if cache entry failed DNSSEC validation
 *
 * @detailed
 * Determines if a cache record represents a DNSSEC validation failure. Returns true
 * if DNSSEC validation is enabled globally (OPT_DNSSEC_VALID option) but the cache
 * entry does not have the F_DNSSECOK flag set, indicating that the record failed
 * DNSSEC validation or was not validated. Used by answer_request() to determine
 * whether to return the record or treat it as invalid. Only meaningful when DNSSEC
 * validation is configured and enabled.
 *
 * @param crecp Pointer to cache record (struct crec) to check
 *
 * @return Non-zero (true) if DNSSEC validation enabled and record is NOT validated (failed/unvalidated)
 * @return 0 (false) if DNSSEC validation disabled or record is validated (F_DNSSECOK set)
 *
 * @note Only compiled when HAVE_DNSSEC is defined
 * @note Checks global option_bool(OPT_DNSSEC_VALID) flag
 * @note F_DNSSECOK flag in cache entry indicates successful DNSSEC validation
 * @note Inverse logic: returns true for validation FAILURE, false for success or disabled
 *
 * @warning Assumes crecp is valid and not null
 * @warning Accesses global option flags via option_bool()
 *
 * @see option_bool() for global option checking
 * @see answer_request() which uses this to filter unvalidated records
 * @see F_DNSSECOK flag in struct crec for validation status
 * @see --dnssec command-line option for enabling DNSSEC validation
 *
 * EXAMPLE USAGE:
 * @code
 * struct crec *cache_entry = cache_lookup(...);
 * if (cache_validated(cache_entry)) {
 *     // DNSSEC validation failed or not validated, don't return this record
 *     return 0;
 * }
 * // Record is OK to return
 * @endcode
 *
 * RFC COMPLIANCE:
 * DNSSEC validation per RFCs 4033-4035. Cache flag checking is implementation detail.
 *
 * SIDE EFFECTS:
 * - Accesses global daemon options via option_bool()
 *
 * THREAD SAFETY:
 * Thread-safe for reading. Accesses global read-only option configuration.
 */
static int cache_validated(const struct crec *crecp)
{
  return (option_bool(OPT_DNSSEC_VALID) && !(crecp->flags & F_DNSSECOK));
}

/**
 * @brief Generate complete DNS response from cache and local configuration
 *
 * @detailed
 * Main DNS response generation function that constructs authoritative and cached answers
 * from local data sources (cache, /etc/hosts, DHCP leases, static configuration). Processes
 * DNS queries and generates responses for supported record types (A, AAAA, CNAME, PTR, MX,
 * SRV, TXT, SOA, NS, NAPTR) using cache lookups and configured local records. Handles CNAME
 * chain following (up to 255 iterations), DNSSEC DO bit processing, truncation detection,
 * interface address filtering, private address filtering, and authoritative/non-authoritative
 * flag setting. Returns 0 if query cannot be answered from local sources (requiring upstream
 * forwarding) or packet size if complete response generated. Implements two-pass algorithm:
 * dry run if additional section present, then real response construction.
 *
 * @param header Pointer to DNS query packet header (modified in-place to response)
 * @param limit Pointer to buffer limit for truncation detection
 * @param qlen Length of query packet in bytes
 * @param local_addr Local interface IPv4 address for interface filtering
 * @param local_netmask Local interface netmask for same-subnet checks
 * @param now Current time for TTL calculation and cache expiry
 * @param ad_reqd If non-zero, client requested AD (authenticated data) flag
 * @param do_bit If non-zero, DNSSEC OK (DO) bit set in query (EDNS0)
 * @param have_pseudoheader If non-zero, query has EDNS0 OPT pseudoheader
 *
 * @return 0 if query cannot be answered from local sources (forward to upstream)
 * @return Packet size in bytes if complete response generated from local data
 *
 * @note Rejects non-standard queries (ancount/nscount > 0, qdcount != 1, non-QUERY opcode)
 * @note Rejects queries without RD bit set (cache snooping prevention)
 * @note Follows CNAME chains up to 255 iterations to prevent loops
 * @note Sets AA (authoritative) flag for locally-authoritative answers
 * @note Sets AD (authenticated data) flag only if DNSSEC validation successful
 * @note Clears AD flag if CD (checking disabled) bit set in query
 * @note Two-pass processing if additional section present: dry run then real
 * @note Handles interface filtering (--interface-name, --localise-queries)
 * @note Applies private address filtering for reverse DNS (--bogus-priv)
 * @note Supports multiple questions but only if same name/type (unusual case)
 *
 * @warning Modifies header and packet buffer in-place
 * @warning Accesses global daemon configuration and cache extensively
 * @warning May return 0 even if partial answer possible (e.g., missing glue records)
 * @warning Large function (~700 lines) handling many record types and edge cases
 *
 * @see cache_find_by_name() for cache lookups
 * @see add_resource_record() for adding RRs to response
 * @see crec_ttl() for TTL calculation
 * @see extract_name() for query name extraction
 * @see setup_reply() for response header initialization
 *
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet;
 * size_t response_len = answer_request(header, packet + 512, query_len,
 *                                      local_ip, netmask, time(NULL),
 *                                      0, has_do_bit, has_opt);
 * if (response_len == 0)
 *     // Forward query to upstream server
 * else
 *     // Send response_len bytes back to client
 * @endcode
 *
 * RFC COMPLIANCE:
 * Implements RFC 1035 (DNS) response generation with extensions from RFC 2181 (clarifications),
 * RFC 3596 (AAAA), RFC 2782 (SRV), RFC 2915 (NAPTR), RFC 4035 (DNSSEC), RFC 6891 (EDNS0).
 *
 * SIDE EFFECTS:
 * - Modifies packet buffer to construct DNS response
 * - Updates header flags (QR, AA, AD, RA, TC)
 * - Updates header section counts (ancount, nscount, arcount)
 * - Calls log_query() for query logging if enabled
 * - Accesses global daemon configuration and cache
 * - May call do_doctor() for address rewriting
 *
 * THREAD SAFETY:
 * Not thread-safe. Modifies packet buffer, accesses global daemon and cache.
 * Must be called from single-threaded event loop context.
 */
/* return zero if we can't answer from cache, or packet size if we can */
size_t answer_request(struct dns_header *header, char *limit, size_t qlen,  
		      struct in_addr local_addr, struct in_addr local_netmask, 
		      time_t now, int ad_reqd, int do_bit, int have_pseudoheader) 
{
  char *name = daemon->namebuff;
  unsigned char *p, *ansp;
  unsigned int qtype, qclass;
  union all_addr addr;
  int nameoffset;
  unsigned short flag;
  int q, ans, anscount = 0, addncount = 0;
  int dryrun = 0;
  struct crec *crecp;
  int nxdomain = 0, notimp = 0, auth = 1, trunc = 0, sec_data = 1;
  struct mx_srv_record *rec;
  size_t len;
  int rd_bit = (header->hb3 & HB3_RD);

  /* never answer queries with RD unset, to avoid cache snooping. */
  if (ntohs(header->ancount) != 0 ||
      ntohs(header->nscount) != 0 ||
      ntohs(header->qdcount) == 0 ||
      OPCODE(header) != QUERY )
    return 0;

  /* Don't return AD set if checking disabled. */
  if (header->hb4 & HB4_CD)
    sec_data = 0;
  
  /* If there is an  additional data section then it will be overwritten by
     partial replies, so we have to do a dry run to see if we can answer
     the query. */
  if (ntohs(header->arcount) != 0)
    dryrun = 1;

  for (rec = daemon->mxnames; rec; rec = rec->next)
    rec->offset = 0;
  
 rerun:
  /* determine end of question section (we put answers there) */
  if (!(ansp = skip_questions(header, qlen)))
    return 0; /* bad packet */
   
  /* now process each question, answers go in RRs after the question */
  p = (unsigned char *)(header+1);

  for (q = ntohs(header->qdcount); q != 0; q--)
    {
      int count = 255; /* catch loops */
      
      /* save pointer to name for copying into answers */
      nameoffset = p - (unsigned char *)header;

      /* now extract name as .-concatenated string into name */
      if (!extract_name(header, qlen, &p, name, 1, 4))
	return 0; /* bad packet */
            
      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);

      ans = 0; /* have we answered this question */

      if (qclass == C_IN)
	while (--count != 0 && (crecp = cache_find_by_name(NULL, name, now, F_CNAME | F_NXDOMAIN)))
	  {
	    char *cname_target;

	    if (crecp->flags & F_NXDOMAIN)
	      {
		if (qtype == T_CNAME)
		  {
		   if (!dryrun)
		     log_query(crecp->flags, name, NULL, record_source(crecp->uid), 0);
		    auth = 0;
		    nxdomain = 1;
		    ans = 1;
		  }
		break;
	      }  

	    cname_target = cache_get_cname_target(crecp);
	    
	    /* If the client asked for DNSSEC  don't use cached data. */
	    if ((crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) ||
		(rd_bit && (!do_bit || cache_validated(crecp))))
	      {
		if (crecp->flags & F_CONFIG || qtype == T_CNAME)
		  ans = 1;
		
		if (!(crecp->flags & F_DNSSECOK))
		  sec_data = 0;
		
		if (!dryrun)
		  {
		    log_query(crecp->flags, name, NULL, record_source(crecp->uid), 0);
		    if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					    crec_ttl(crecp, now), &nameoffset,
					    T_CNAME, C_IN, "d", cname_target))
		      anscount++;
		  }
		
	      }
	    else
	      return 0; /* give up if any cached CNAME in chain can't be used for DNSSEC reasons. */
	    
	    if (qtype == T_CNAME)
	      break;
	    
	    strcpy(name, cname_target);
	  }
      
      if (qtype == T_TXT || qtype == T_ANY)
	{
	  struct txt_record *t;
	  for(t = daemon->txt; t ; t = t->next)
	    {
	      if (t->class == qclass && hostname_isequal(name, t->name))
		{
		  ans = 1, sec_data = 0;
		  if (!dryrun)
		    {
		      unsigned long ttl = daemon->local_ttl;
		      int ok = 1;
#ifndef NO_ID
		      /* Dynamically generate stat record */
		      if (t->stat != 0)
			{
			  ttl = 0;
			  if (!cache_make_stat(t))
			    ok = 0;
			}
#endif
		      if (ok)
			{
			  log_query(F_CONFIG | F_RRNAME, name, NULL, "<TXT>", 0);
			  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						  ttl, NULL,
						  T_TXT, t->class, "t", t->len, t->txt))
			    anscount++;
			}
		    }
		}
	    }
	}

      if (qclass == C_CHAOS)
	{
	  /* don't forward *.bind and *.server chaos queries - always reply with NOTIMP */
	  if (hostname_issubdomain("bind", name) || hostname_issubdomain("server", name))
	    {
	      if (!ans)
		{
		  notimp = 1, auth = 0;
		  if (!dryrun)
		    {
		       addr.log.rcode = NOTIMP;
		       log_query(F_CONFIG | F_RCODE, name, &addr, NULL, 0);
		    }
		  ans = 1, sec_data = 0;
		}
	    }
	}

      if (qclass == C_IN)
	{
	  struct txt_record *t;

	  for (t = daemon->rr; t; t = t->next)
	    if ((t->class == qtype || qtype == T_ANY) && hostname_isequal(name, t->name))
	      {
		ans = 1;
		sec_data = 0;
		if (!dryrun)
		  {
		    log_query(F_CONFIG | F_RRNAME, name, NULL, NULL, t->class);
		    if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					    daemon->local_ttl, NULL,
					    t->class, C_IN, "t", t->len, t->txt))
		      anscount++;
		  }
	      }
		
	  if (qtype == T_PTR || qtype == T_ANY)
	    {
	      /* see if it's w.z.y.z.in-addr.arpa format */
	      int is_arpa = in_arpa_name_2_addr(name, &addr);
	      struct ptr_record *ptr;
	      struct interface_name* intr = NULL;

	      for (ptr = daemon->ptr; ptr; ptr = ptr->next)
		if (hostname_isequal(name, ptr->name))
		  break;

	      if (is_arpa == F_IPV4)
		for (intr = daemon->int_names; intr; intr = intr->next)
		  {
		    struct addrlist *addrlist;
		    
		    for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		      if (!(addrlist->flags & ADDRLIST_IPV6) && addr.addr4.s_addr == addrlist->addr.addr4.s_addr)
			break;
		    
		    if (addrlist)
		      break;
		    else if (!(intr->flags & INP4))
		      while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
			intr = intr->next;
		  }
	      else if (is_arpa == F_IPV6)
		for (intr = daemon->int_names; intr; intr = intr->next)
		  {
		    struct addrlist *addrlist;
		    
		    for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
		      if ((addrlist->flags & ADDRLIST_IPV6) && IN6_ARE_ADDR_EQUAL(&addr.addr6, &addrlist->addr.addr6))
			break;
		    
		    if (addrlist)
		      break;
		    else if (!(intr->flags & INP6))
		      while (intr->next && strcmp(intr->intr, intr->next->intr) == 0)
			intr = intr->next;
		  }
	      
	      if (intr)
		{
		  sec_data = 0;
		  ans = 1;
		  if (!dryrun)
		    {
		      log_query(is_arpa | F_REVERSE | F_CONFIG, intr->name, &addr, NULL, 0);
		      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					      daemon->local_ttl, NULL,
					      T_PTR, C_IN, "d", intr->name))
			anscount++;
		    }
		}
	      else if (ptr)
		{
		  ans = 1;
		  sec_data = 0;
		  if (!dryrun)
		    {
		      log_query(F_CONFIG | F_RRNAME, name, NULL, "<PTR>", 0);
		      for (ptr = daemon->ptr; ptr; ptr = ptr->next)
			if (hostname_isequal(name, ptr->name) &&
			    add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						daemon->local_ttl, NULL,
						T_PTR, C_IN, "d", ptr->ptr))
			  anscount++;
			 
		    }
		}
	      else if (is_arpa && (crecp = cache_find_by_addr(NULL, &addr, now, is_arpa)))
		{
		  /* Don't use cache when DNSSEC data required, unless we know that
		     the zone is unsigned, which implies that we're doing
		     validation. */
		  if ((crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) ||
		      (rd_bit && (!do_bit || cache_validated(crecp)) ))
		    {
		      do 
			{ 
			  /* don't answer wildcard queries with data not from /etc/hosts or dhcp leases */
			  if (qtype == T_ANY && !(crecp->flags & (F_HOSTS | F_DHCP)))
			    continue;
			  
			  if (!(crecp->flags & F_DNSSECOK))
			    sec_data = 0;
			   
			  ans = 1;
			   
			  if (crecp->flags & F_NEG)
			    {
			      auth = 0;
			      if (crecp->flags & F_NXDOMAIN)
				nxdomain = 1;
			      if (!dryrun)
				log_query(crecp->flags & ~F_FORWARD, name, &addr, NULL, 0);
			    }
			  else
			    {
			      if (!(crecp->flags & (F_HOSTS | F_DHCP)))
				auth = 0;
			      if (!dryrun)
				{
				  log_query(crecp->flags & ~F_FORWARD, cache_get_name(crecp), &addr, 
					    record_source(crecp->uid), 0);
				  
				  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
							  crec_ttl(crecp, now), NULL,
							  T_PTR, C_IN, "d", cache_get_name(crecp)))
				    anscount++;
				}
			    }
			} while ((crecp = cache_find_by_addr(crecp, &addr, now, is_arpa)));
		    }
		}
	      else if (is_rev_synth(is_arpa, &addr, name))
		{
		  ans = 1;
		  sec_data = 0;
		  if (!dryrun)
		    {
		      log_query(F_CONFIG | F_REVERSE | is_arpa, name, &addr, NULL, 0);
		      
		      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					      daemon->local_ttl, NULL,
					      T_PTR, C_IN, "d", name))
			      anscount++;
		    }
		}
	      else if (option_bool(OPT_BOGUSPRIV) &&
		       ((is_arpa == F_IPV6 && private_net6(&addr.addr6, 1)) || (is_arpa == F_IPV4 && private_net(addr.addr4, 1))) &&
		       !lookup_domain(name, F_DOMAINSRV, NULL, NULL))
		{
		  /* if no configured server, not in cache, enabled and private IPV4 address, return NXDOMAIN */
		  ans = 1;
		  sec_data = 0;
		  nxdomain = 1;
		  if (!dryrun)
		    log_query(F_CONFIG | F_REVERSE | is_arpa | F_NEG | F_NXDOMAIN,
			      name, &addr, NULL, 0);
		}
	    }

	  for (flag = F_IPV4; flag; flag = (flag == F_IPV4) ? F_IPV6 : 0)
	    {
	      unsigned short type = (flag == F_IPV6) ? T_AAAA : T_A;
	      struct interface_name *intr;

	      if (qtype != type && qtype != T_ANY)
		continue;
	      
	      /* interface name stuff */
	      for (intr = daemon->int_names; intr; intr = intr->next)
		if (hostname_isequal(name, intr->name))
		  break;
	      
	      if (intr)
		{
		  struct addrlist *addrlist;
		  int gotit = 0, localise = 0;

		  enumerate_interfaces(0);
		    
		  /* See if a putative address is on the network from which we received
		     the query, is so we'll filter other answers. */
		  if (local_addr.s_addr != 0 && option_bool(OPT_LOCALISE) && type == T_A)
		    for (intr = daemon->int_names; intr; intr = intr->next)
		      if (hostname_isequal(name, intr->name))
			for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
			  if (!(addrlist->flags & ADDRLIST_IPV6) && 
			      is_same_net(addrlist->addr.addr4, local_addr, local_netmask))
			    {
			      localise = 1;
			      break;
			    }
		  
		  for (intr = daemon->int_names; intr; intr = intr->next)
		    if (hostname_isequal(name, intr->name))
		      {
			for (addrlist = intr->addr; addrlist; addrlist = addrlist->next)
			  if (((addrlist->flags & ADDRLIST_IPV6) ? T_AAAA : T_A) == type)
			    {
			      if (localise && 
				  !is_same_net(addrlist->addr.addr4, local_addr, local_netmask))
				continue;

			      if (addrlist->flags & ADDRLIST_REVONLY)
				continue;

			      ans = 1;	
			      sec_data = 0;
			      if (!dryrun)
				{
				  gotit = 1;
				  log_query(F_FORWARD | F_CONFIG | flag, name, &addrlist->addr, NULL, 0);
				  if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
							  daemon->local_ttl, NULL, type, C_IN, 
							  type == T_A ? "4" : "6", &addrlist->addr))
				    anscount++;
				}
			    }
		      }
		  
		  if (!dryrun && !gotit)
		    log_query(F_FORWARD | F_CONFIG | flag | F_NEG, name, NULL, NULL, 0);
		     
		  continue;
		}

	      if ((crecp = cache_find_by_name(NULL, name, now, flag | F_NXDOMAIN | (dryrun ? F_NO_RR : 0))))
		{
		  int localise = 0;
		  
		  /* See if a putative address is on the network from which we received
		     the query, is so we'll filter other answers. */
		  if (local_addr.s_addr != 0 && option_bool(OPT_LOCALISE) && flag == F_IPV4)
		    {
		      struct crec *save = crecp;
		      do {
			if ((crecp->flags & F_HOSTS) &&
			    is_same_net(crecp->addr.addr4, local_addr, local_netmask))
			  {
			    localise = 1;
			    break;
			  } 
			} while ((crecp = cache_find_by_name(crecp, name, now, flag)));
		      crecp = save;
		    }

		  /* If the client asked for DNSSEC  don't use cached data. */
		  if ((crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) ||
		      (rd_bit && (!do_bit || cache_validated(crecp)) ))
		    do
		      { 
			/* don't answer wildcard queries with data not from /etc/hosts
			   or DHCP leases */
			if (qtype == T_ANY && !(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
			  break;
			
			if (!(crecp->flags & F_DNSSECOK))
			  sec_data = 0;
			
			if (crecp->flags & F_NEG)
			  {
			    ans = 1;
			    auth = 0;
			    if (crecp->flags & F_NXDOMAIN)
			      nxdomain = 1;
			    if (!dryrun)
			      log_query(crecp->flags, name, NULL, NULL, 0);
			  }
			else 
			  {
			    /* If we are returning local answers depending on network,
			       filter here. */
			    if (localise && 
				(crecp->flags & F_HOSTS) &&
				!is_same_net(crecp->addr.addr4, local_addr, local_netmask))
			      continue;
			    
			    if (!(crecp->flags & (F_HOSTS | F_DHCP)))
			      auth = 0;
			    
			    ans = 1;
			    if (!dryrun)
			      {
				log_query(crecp->flags & ~F_REVERSE, name, &crecp->addr,
					  record_source(crecp->uid), 0);
				
				if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
							crec_ttl(crecp, now), NULL, type, C_IN, 
							type == T_A ? "4" : "6", &crecp->addr))
				  anscount++;
			      }
			  }
		      } while ((crecp = cache_find_by_name(crecp, name, now, flag)));
		}
	      else if (is_name_synthetic(flag, name, &addr))
		{
		  ans = 1, sec_data = 0;
		  if (!dryrun)
		    {
		      log_query(F_FORWARD | F_CONFIG | flag, name, &addr, NULL, 0);
		      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
					      daemon->local_ttl, NULL, type, C_IN, type == T_A ? "4" : "6", &addr))
			anscount++;
		    }
		}
	    }

	  if (qtype == T_MX || qtype == T_ANY)
	    {
	      int found = 0;
	      for (rec = daemon->mxnames; rec; rec = rec->next)
		if (!rec->issrv && hostname_isequal(name, rec->name))
		  {
		    ans = found = 1;
		    sec_data = 0;
		    if (!dryrun)
		      {
			int offset;
			log_query(F_CONFIG | F_RRNAME, name, NULL, "<MX>", 0);
			if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->local_ttl,
						&offset, T_MX, C_IN, "sd", rec->weight, rec->target))
			  {
			    anscount++;
			    if (rec->target)
			      rec->offset = offset;
			  }
		      }
		  }
	      
	      if (!found && (option_bool(OPT_SELFMX) || option_bool(OPT_LOCALMX)) &&
		  cache_find_by_name(NULL, name, now, F_HOSTS | F_DHCP | F_NO_RR))
		{ 
		  ans = 1;
		  sec_data = 0;
		  if (!dryrun)
		    {
		      log_query(F_CONFIG | F_RRNAME, name, NULL, "<MX>", 0);
		      if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->local_ttl, NULL, 
					      T_MX, C_IN, "sd", 1, 
					      option_bool(OPT_SELFMX) ? name : daemon->mxtarget))
			anscount++;
		    }
		}
	    }
	  	  
	  if (qtype == T_SRV || qtype == T_ANY)
	    {
	      int found = 0;
	      struct mx_srv_record *move = NULL, **up = &daemon->mxnames;

	      for (rec = daemon->mxnames; rec; rec = rec->next)
		if (rec->issrv && hostname_isequal(name, rec->name))
		  {
		    found = ans = 1;
		    sec_data = 0;
		    if (!dryrun)
		      {
			int offset;
			log_query(F_CONFIG | F_RRNAME, name, NULL, "<SRV>", 0);
			if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->local_ttl, 
						&offset, T_SRV, C_IN, "sssd", 
						rec->priority, rec->weight, rec->srvport, rec->target))
			  {
			    anscount++;
			    if (rec->target)
			      rec->offset = offset;
			  }
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

	      if (!found)
		{
		  if ((crecp = cache_find_by_name(NULL, name, now, F_SRV | F_NXDOMAIN | (dryrun ? F_NO_RR : 0))) &&
		      rd_bit && (!do_bit || (option_bool(OPT_DNSSEC_VALID) && !(crecp->flags & F_DNSSECOK))))
		    do
		      {
			/* don't answer wildcard queries with data not from /etc/hosts or dhcp leases, except for NXDOMAIN */
			if (qtype == T_ANY && !(crecp->flags & (F_NXDOMAIN)))
			  break;
			
			if (!(crecp->flags & F_DNSSECOK))
			  sec_data = 0;
			
			auth = 0;
			found = ans = 1;
			
			if (crecp->flags & F_NEG)
			  {
			    if (crecp->flags & F_NXDOMAIN)
			      nxdomain = 1;
			    if (!dryrun)
			      log_query(crecp->flags, name, NULL, NULL, 0);
			  }
			else if (!dryrun)
			  {
			    char *target = blockdata_retrieve(crecp->addr.srv.target, crecp->addr.srv.targetlen, NULL);
			    log_query(crecp->flags, name, NULL, NULL, 0);
			    
			    if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, 
						    crec_ttl(crecp, now), NULL, T_SRV, C_IN, "sssd",
						    crecp->addr.srv.priority, crecp->addr.srv.weight, crecp->addr.srv.srvport,
						    target))
			      anscount++;
			  }
		      } while ((crecp = cache_find_by_name(crecp, name, now, F_SRV)));
		    }
	      
	      if (!found && option_bool(OPT_FILTER) && (qtype == T_SRV || (qtype == T_ANY && strchr(name, '_'))))
		{
		  ans = 1;
		  sec_data = 0;
		  if (!dryrun)
		    log_query(F_CONFIG | F_NEG, name, NULL, NULL, 0);
		}
	    }

	  if (qtype == T_NAPTR || qtype == T_ANY)
	    {
	      struct naptr *na;
	      for (na = daemon->naptr; na; na = na->next)
		if (hostname_isequal(name, na->name))
		  {
		    ans = 1;
		    sec_data = 0;
		    if (!dryrun)
		      {
			log_query(F_CONFIG | F_RRNAME, name, NULL, "<NAPTR>", 0);
			if (add_resource_record(header, limit, &trunc, nameoffset, &ansp, daemon->local_ttl, 
						NULL, T_NAPTR, C_IN, "sszzzd", 
						na->order, na->pref, na->flags, na->services, na->regexp, na->replace))
			  anscount++;
		      }
		  }
	    }
	  
	  if (qtype == T_MAILB)
	    ans = 1, nxdomain = 1, sec_data = 0;

	  if (qtype == T_SOA && option_bool(OPT_FILTER))
	    {
	      ans = 1;
	      sec_data = 0;
	      if (!dryrun)
		log_query(F_CONFIG | F_NEG, name, &addr, NULL, 0);
	    }
	}

      if (!ans)
	return 0; /* failed to answer a question */
    }
  
  if (dryrun)
    {
      dryrun = 0;
      goto rerun;
    }
  
  /* create an additional data section, for stuff in SRV and MX record replies. */
  for (rec = daemon->mxnames; rec; rec = rec->next)
    if (rec->offset != 0)
      {
	/* squash dupes */
	struct mx_srv_record *tmp;
	for (tmp = rec->next; tmp; tmp = tmp->next)
	  if (tmp->offset != 0 && hostname_isequal(rec->target, tmp->target))
	    tmp->offset = 0;
	
	crecp = NULL;
	while ((crecp = cache_find_by_name(crecp, rec->target, now, F_IPV4 | F_IPV6)))
	  {
	    int type =  crecp->flags & F_IPV4 ? T_A : T_AAAA;

	    if (crecp->flags & F_NEG)
	      continue;

	    if (add_resource_record(header, limit, NULL, rec->offset, &ansp, 
				    crec_ttl(crecp, now), NULL, type, C_IN, 
				    crecp->flags & F_IPV4 ? "4" : "6", &crecp->addr))
	      addncount++;
	  }
      }
  
  /* done all questions, set up header and return length of result */
  /* clear authoritative and truncated flags, set QR flag */
  header->hb3 = (header->hb3 & ~(HB3_AA | HB3_TC)) | HB3_QR;
  /* set RA flag */
  header->hb4 |= HB4_RA;
   
  /* authoritative - only hosts and DHCP derived names. */
  if (auth)
    header->hb3 |= HB3_AA;
  
  /* truncation */
  if (trunc)
    header->hb3 |= HB3_TC;
  
  if (nxdomain)
    SET_RCODE(header, NXDOMAIN);
  else if (notimp)
    SET_RCODE(header, NOTIMP);
  else
    SET_RCODE(header, NOERROR); /* no error */
  header->ancount = htons(anscount);
  header->nscount = htons(0);
  header->arcount = htons(addncount);

  len = ansp - (unsigned char *)header;
  
  /* Advertise our packet size limit in our reply */
  if (have_pseudoheader)
    len = add_pseudoheader(header, len, (unsigned char *)limit, daemon->edns_pktsz, 0, NULL, 0, do_bit, 0);
  
  if (ad_reqd && sec_data)
    header->hb4 |= HB4_AD;
  else
    header->hb4 &= ~HB4_AD;
  
  return len;
}
