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
 * @file rrfilter.c
 * @brief DNS resource record filtering and safe RR elision from response packets
 * 
 * DETAILED PURPOSE:
 * 
 * This module provides safe removal of DNS resource records (RRs) from DNS response
 * packets while maintaining packet validity and DNS name compression integrity. The
 * primary challenge in RR removal is handling DNS name compression pointers that may
 * reference removed records. The implementation performs multi-pass processing to
 * detect invalid pointer references, adjust compression offsets, and physically
 * remove records while preserving packet structure per RFC 1035.
 * 
 * The filtering is used for multiple purposes: removing DNSSEC validation records
 * (RRSIG, NSEC, NSEC3) when not explicitly requested, stripping EDNS0 OPT pseudo-records,
 * and filtering specific record types (A or AAAA) from answer sections for privacy
 * or policy enforcement. All operations maintain DNS packet validity by updating
 * section counts (ancount, nscount, arcount) and ensuring name compression pointers
 * remain valid after record removal.
 * 
 * KEY RESPONSIBILITIES:
 * 
 * - rrfilter() - Main entry point for selective RR removal with four-pass algorithm
 * - rrfilter_desc() - Returns descriptor array for RR types containing domain names
 * - expand_workspace() - Dynamic array expansion for tracking removed record positions
 * - check_name() - Validates and adjusts DNS name compression pointers (static helper)
 * - check_rrs() - Validates domain names in RR data sections (static helper)
 * 
 * DEPENDENCIES:
 * 
 * - dnsmasq.h - Core type definitions, macros, and structure declarations
 * - dns-protocol.h (via dnsmasq.h) - DNS packet structures, CHECK_LEN, ADD_RDLEN macros
 * - struct dns_header - DNS packet header with section counts
 * - RRFILTER_* constants - Filter mode definitions (EDNS0, DNSSEC, A, AAAA)
 * - DNS type constants - T_NS, T_CNAME, T_SOA, T_MX, T_RRSIG, T_NSEC, T_NSEC3, T_OPT
 * - Memory functions - memmove(), memcpy(), free(), whine_malloc()
 * - Network byte order functions - ntohs(), htons()
 * 
 * Called by: forward.c (reply processing), dnssec.c (validation record cleanup)
 * Calls: skip_name() (rfc1035.c), whine_malloc() (util.c)
 * 
 * DATA STRUCTURES:
 * 
 * - struct dns_header (dnsmasq.h ~line 150) - DNS packet header with question/answer counts
 * - Static unsigned char **rrs - Dynamic array tracking start/end pointers of removed RRs
 * - Static int rr_sz - Current allocated size of rrs array
 * - u16 rr_desc[] - Descriptor array mapping RR types to domain name locations in RDATA
 * 
 * COMPILE-TIME OPTIONS:
 * 
 * None - This module has no conditional compilation. RR filtering is always available
 * as core DNS processing functionality regardless of HAVE_DNSSEC or other feature flags.
 * 
 * THREADING/CONCURRENCY:
 * 
 * Single-process event-driven model. Functions are re-entrant except for rrfilter()
 * which uses static storage for the rrs array workspace (not thread-safe if called
 * concurrently, but dnsmasq processes one packet at a time in its event loop). The
 * static rrs array is reused across calls for efficiency, growing as needed via
 * expand_workspace().
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

/* Code to safely remove RRs from a DNS answer */ 

#include "dnsmasq.h"

/**
 * @brief Validate and adjust DNS name compression pointers after RR removal
 * 
 * @detailed
 * Traverses a DNS domain name to validate or fix compression pointers after resource
 * records have been removed from a packet. DNS names use compression where repeated
 * domain components are replaced with two-byte pointers to earlier occurrences (RFC 1035
 * Section 4.1.4). When RRs are removed, pointers must be adjusted to account for the
 * removed bytes, and pointers targeting removed sections must be detected as invalid.
 * 
 * The function handles three label types: normal labels (0x00), compression pointers
 * (0xc0), and extended labels for bitstrings (0x40). For compression pointers, it
 * calculates adjustments based on the rrs array which contains start/end positions
 * of removed RRs. If fixup is true, pointers are rewritten with corrected offsets.
 * 
 * @param[in,out] namep Pointer to pointer to domain name bytes, advanced past name on success
 * @param[in] header DNS packet header for bounds checking
 * @param[in] plen Total packet length in bytes for boundary validation
 * @param[in] fixup If non-zero, rewrite compression pointers with adjusted offsets; if zero, only validate
 * @param[in] rrs Array of pointers marking start/end of removed RRs (pairs: start at even index, end at odd)
 * @param[in] rr_count Number of pointers in rrs array (must be even, pairs of start/end)
 * 
 * @return 1 on success (name valid or successfully fixed), 0 on failure (pointer into removed section or packet truncation)
 * 
 * @note This function is called twice per name during rrfilter: once to validate (fixup=0) and once to fix (fixup=1)
 * @note Compression pointer offsets are 14-bit values (0x3fff mask) with 0xc0 flag bits
 * @note Extended labels (0x40) support bitstring labels but only type 1 bitstrings are implemented
 * 
 * @warning Fails if compression pointer targets a removed RR section (odd index in rrs array traversal)
 * @warning Reserved label type 0x80 causes immediate failure per RFC 1035
 * @warning Modifies *namep to advance past the parsed name on success
 * 
 * @see check_rrs() for RR-level name checking
 * @see rrfilter() for multi-pass compression pointer fixup algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *name_ptr = packet_position;
 * if (!check_name(&name_ptr, header, packet_len, 1, removed_rrs, rr_count)) {
 *     // Name contains invalid compression pointer
 *     return 0;
 * }
 * // name_ptr now points past the domain name
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 4.1.4 (Domain Name Compression) validation and adjustment.
 * Handles RFC 2673 binary labels (extended label type 0x41 for bitstrings).
 * 
 * SIDE EFFECTS:
 * - Advances *namep past the parsed domain name on success
 * - Modifies compression pointer bytes in packet if fixup=1
 * - No side effects on failure (namep unchanged)
 * 
 * THREAD SAFETY:
 * Re-entrant. No static or global state. Safe for concurrent use with different packet buffers.
 */
/* Go through a domain name, find "pointers" and fix them up based on how many bytes
   we've chopped out of the packet, or check they don't point into an elided part.  */
static int check_name(unsigned char **namep, struct dns_header *header, size_t plen, int fixup, unsigned char **rrs, int rr_count)
{
  unsigned char *ansp = *namep;

  while(1)
    {
      unsigned int label_type;
      
      if (!CHECK_LEN(header, ansp, plen, 1))
	return 0;
      
      label_type = (*ansp) & 0xc0;

      if (label_type == 0xc0)
	{
	  /* pointer for compression. */
	  unsigned int offset;
	  int i;
	  unsigned char *p;
	  
	  if (!CHECK_LEN(header, ansp, plen, 2))
	    return 0;

	  offset = ((*ansp++) & 0x3f) << 8;
	  offset |= *ansp++;

	  p = offset + (unsigned char *)header;
	  
	  for (i = 0; i < rr_count; i++)
	    if (p < rrs[i])
	      break;
	    else
	      if (i & 1)
		offset -= rrs[i] - rrs[i-1];

	  /* does the pointer end up in an elided RR? */
	  if (i & 1)
	    return 0;

	  /* No, scale the pointer */
	  if (fixup)
	    {
	      ansp -= 2;
	      *ansp++ = (offset >> 8) | 0xc0;
	      *ansp++ = offset & 0xff;
	    }
	  break;
	}
      else if (label_type == 0x80)
	return 0; /* reserved */
      else if (label_type == 0x40)
	{
	  /* Extended label type */
	  unsigned int count;
	  
	  if (!CHECK_LEN(header, ansp, plen, 2))
	    return 0;
	  
	  if (((*ansp++) & 0x3f) != 1)
	    return 0; /* we only understand bitstrings */
	  
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
	    return 0;

	  if (len == 0)
	    break; /* zero length label marks the end. */
	}
    }

  *namep = ansp;

  return 1;
}

/**
 * @brief Validate and adjust domain names within DNS resource record data sections
 * 
 * @detailed
 * Iterates through all resource records in answer, authority, and additional sections
 * to validate or fix domain names embedded in RR RDATA fields. Many RR types contain
 * domain names as part of their data (NS, CNAME, MX, SOA, etc.), and these names may
 * use compression pointers that require adjustment after RR removal. The function
 * uses rrfilter_desc() to determine which RR types contain domain names and where
 * those names are located within the RDATA.
 * 
 * Records marked for removal (present in the rrs array) are skipped entirely since
 * their contents will be discarded. For remaining records, the function validates
 * the RR owner name and any domain names within RDATA using check_name(). For class
 * IN records, the RR type descriptor guides traversal through fixed-length fields
 * and variable-length domain names.
 * 
 * @param[in] p Pointer to first RR after question section
 * @param[in] header DNS packet header for section counts and bounds checking
 * @param[in] plen Total packet length in bytes
 * @param[in] fixup If non-zero, fix compression pointers; if zero, only validate
 * @param[in] rrs Array of pointers marking start/end of removed RRs (pairs)
 * @param[in] rr_count Number of pointers in rrs array
 * 
 * @return 1 on success (all names valid or successfully fixed), 0 on failure (invalid pointer or truncation)
 * 
 * @note Processes ancount + nscount + arcount RRs as indicated by DNS header
 * @note Uses skip_name() to traverse RR owner names efficiently
 * @note RR format: owner_name (variable), type (2 bytes), class (2 bytes), TTL (4 bytes), rdlen (2 bytes), rdata (rdlen bytes)
 * 
 * @warning Fails if any name validation fails (propagates check_name() failures)
 * @warning Assumes RRs to be removed have been identified and stored in rrs array
 * @warning Only handles class IN (C_IN) RDATA name fixup; other classes pass through without RDATA processing
 * 
 * @see check_name() for name compression pointer validation/fixup
 * @see rrfilter_desc() for RR type descriptor lookup
 * @see rrfilter() for overall removal algorithm
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *rr_start = packet + question_len;
 * if (!check_rrs(rr_start, header, packet_len, 0, removed_rrs, rr_count)) {
 *     // Validation failed, cannot safely remove RRs
 *     return original_packet_len;
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 3.2.1 (Format) and Section 4.1.3 (Resource Record Format).
 * Handles RDATA name compression per RFC 1035 Section 4.1.4.
 * 
 * SIDE EFFECTS:
 * - Calls check_name() which may modify compression pointers if fixup=1
 * - Traverses entire RR section, no state changes if fixup=0
 * 
 * THREAD SAFETY:
 * Re-entrant. No static or global state. Safe for concurrent use with different packet buffers.
 */
/* Go through RRs and check or fixup the domain names contained within */
static int check_rrs(unsigned char *p, struct dns_header *header, size_t plen, int fixup, unsigned char **rrs, int rr_count)
{
  int i, j, type, class, rdlen;
  unsigned char *pp;
  
  for (i = 0; i < ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount); i++)
    {
      pp = p;

      if (!(p = skip_name(p, header, plen, 10)))
	return 0;
      
      GETSHORT(type, p); 
      GETSHORT(class, p);
      p += 4; /* TTL */
      GETSHORT(rdlen, p);

      /* If this RR is to be elided, don't fix up its contents */
      for (j = 0; j < rr_count; j += 2)
	if (rrs[j] == pp)
	  break;

      if (j >= rr_count)
	{
	  /* fixup name of RR */
	  if (!check_name(&pp, header, plen, fixup, rrs, rr_count))
	    return 0;
	  
	  if (class == C_IN)
	    {
	      u16 *d;
 
	      for (pp = p, d = rrfilter_desc(type); *d != (u16)-1; d++)
		{
		  if (*d != 0)
		    pp += *d;
		  else if (!check_name(&pp, header, plen, fixup, rrs, rr_count))
		    return 0;
		}
	    }
	}
      
      if (!ADD_RDLEN(header, p, plen, rdlen))
	return 0;
    }
  
  return 1;
}
	

/**
 * @brief Remove resource records matching filter criteria from DNS response packet
 * 
 * @detailed
 * Performs selective removal of DNS resource records from a response packet using a
 * safe four-pass algorithm that handles DNS name compression correctly. The function
 * can filter EDNS0 OPT pseudo-RRs, DNSSEC validation records (RRSIG/NSEC/NSEC3), or
 * specific address record types (A or AAAA) based on the mode parameter. The multi-pass
 * approach identifies records to remove, validates that compression pointers won't
 * reference removed sections, adjusts compression offsets, and finally performs physical
 * removal with memmove().
 * 
 * Pass 1: Scan all RRs and identify those matching filter criteria, storing start/end
 * pointers in the static rrs array. Pass 2: Validate that no compression pointers in
 * kept records point into sections to be removed. Pass 3: Adjust compression pointer
 * offsets to account for removed bytes. Pass 4: Physically remove RRs using memmove()
 * and update DNS header section counts. If validation fails, the original packet is
 * returned unchanged.
 * 
 * @param[in,out] header DNS packet header, section counts updated on successful removal
 * @param[in] plen Original packet length in bytes
 * @param[in] mode Filter mode: RRFILTER_EDNS0 (remove OPT from additional), RRFILTER_DNSSEC (remove RRSIG/NSEC/NSEC3),
 *                 RRFILTER_A (remove A from answers), RRFILTER_AAAA (remove AAAA from answers)
 * 
 * @return New packet length after removal, or original plen if removal failed or no records matched
 * 
 * @retval plen (unchanged) if qdcount != 1, packet truncated, validation failed, or no records to remove
 * @retval <plen (reduced) if records successfully removed and compression pointers adjusted
 * 
 * @note Uses static rrs array that persists and grows across calls for efficiency
 * @note EDNS0 mode only removes T_OPT from additional section, preserves OPT in answer/authority
 * @note DNSSEC mode removes RRSIG/NSEC/NSEC3 from all sections except when explicitly queried for
 * @note A/AAAA modes only examine answer section, ignore authority/additional
 * @note Returns original packet unchanged if any validation step fails (safe failure mode)
 * 
 * @warning Modifies packet in-place on success, caller must not use old pointers after call
 * @warning Uses static storage (rrs array) - not thread-safe, but dnsmasq is single-threaded
 * @warning If expand_workspace() fails (memory allocation), returns unchanged packet
 * @warning Header section counts (ancount/nscount/arcount) updated only on successful removal
 * 
 * @see rrfilter_desc() for RR type descriptors
 * @see check_name() for compression pointer validation/fixup
 * @see check_rrs() for RR-level name validation
 * @see expand_workspace() for dynamic rrs array growth
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header *)packet_buffer;
 * size_t new_len = rrfilter(header, packet_len, RRFILTER_DNSSEC);
 * if (new_len < packet_len) {
 *     // DNSSEC records successfully removed, packet shrunk
 *     send_packet(packet_buffer, new_len);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Implements RFC 1035 Section 4.1.4 (Message Compression) handling during RR removal.
 * Maintains packet structure per RFC 1035 Section 4.1 (Format).
 * EDNS0 handling per RFC 6891 (Extension Mechanisms for DNS).
 * DNSSEC record handling per RFC 4034 (Resource Records for DNSSEC).
 * 
 * SIDE EFFECTS:
 * - Modifies DNS packet bytes in-place (shifts remaining RRs with memmove)
 * - Updates header->ancount, header->nscount, header->arcount on success
 * - Grows static rrs array if needed via expand_workspace()
 * - Resets packet length to reduced value
 * 
 * THREAD SAFETY:
 * NOT re-entrant due to static rrs array. Safe only in single-threaded event loop.
 * Dnsmasq's architecture processes one packet at a time so concurrent calls do not occur.
 */
/* mode may be remove EDNS0 or DNSSEC RRs or remove A or AAAA from answer section. */
size_t rrfilter(struct dns_header *header, size_t plen, int mode)
{
  static unsigned char **rrs;
  static int rr_sz = 0;

  unsigned char *p = (unsigned char *)(header+1);
  int i, rdlen, qtype, qclass, rr_found, chop_an, chop_ns, chop_ar;

  if (ntohs(header->qdcount) != 1 ||
      !(p = skip_name(p, header, plen, 4)))
    return plen;
  
  GETSHORT(qtype, p);
  GETSHORT(qclass, p);

  /* First pass, find pointers to start and end of all the records we wish to elide:
     records added for DNSSEC, unless explicitly queried for */
  for (rr_found = 0, chop_ns = 0, chop_an = 0, chop_ar = 0, i = 0; 
       i < ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount);
       i++)
    {
      unsigned char *pstart = p;
      int type, class;

      if (!(p = skip_name(p, header, plen, 10)))
	return plen;
      
      GETSHORT(type, p); 
      GETSHORT(class, p);
      p += 4; /* TTL */
      GETSHORT(rdlen, p);
        
      if (!ADD_RDLEN(header, p, plen, rdlen))
	return plen;

      if (mode == RRFILTER_EDNS0) /* EDNS */
	{
	  /* EDNS mode, remove T_OPT from additional section only */
	  if (i < (ntohs(header->nscount) + ntohs(header->ancount)) || type != T_OPT)
	    continue;
	}
      else if (mode == RRFILTER_DNSSEC)
	{
	  if (type != T_NSEC && type != T_NSEC3 && type != T_RRSIG)
	    /* DNSSEC mode, remove SIGs and NSECs from all three sections. */
	    continue;

	  /* Don't remove the answer. */
	  if (i < ntohs(header->ancount) && type == qtype && class == qclass)
	    continue;
	}
      else
	{
	  /* Only looking at answer section now. */
	  if (i >= ntohs(header->ancount))
	    break;

	  if (class != C_IN)
	    continue;
	  
	  if (mode == RRFILTER_A && type != T_A)
	    continue;

	  if (mode == RRFILTER_AAAA && type != T_AAAA)
	    continue;
	}
      
      if (!expand_workspace(&rrs, &rr_sz, rr_found + 1))
	return plen; 
      
      rrs[rr_found++] = pstart;
      rrs[rr_found++] = p;
      
      if (i < ntohs(header->ancount))
	chop_an++;
      else if (i < (ntohs(header->nscount) + ntohs(header->ancount)))
	chop_ns++;
      else
	chop_ar++;
    }
  
  /* Nothing to do. */
  if (rr_found == 0)
    return plen;

  /* Second pass, look for pointers in names in the records we're keeping and make sure they don't
     point to records we're going to elide. This is theoretically possible, but unlikely. If
     it happens, we give up and leave the answer unchanged. */
  p = (unsigned char *)(header+1);
  
  /* question first */
  if (!check_name(&p, header, plen, 0, rrs, rr_found))
    return plen;
  p += 4; /* qclass, qtype */
  
  /* Now answers and NS */
  if (!check_rrs(p, header, plen, 0, rrs, rr_found))
    return plen;
  
  /* Third pass, actually fix up pointers in the records */
  p = (unsigned char *)(header+1);
  
  check_name(&p, header, plen, 1, rrs, rr_found);
  p += 4; /* qclass, qtype */
  
  check_rrs(p, header, plen, 1, rrs, rr_found);

  /* Fourth pass, elide records */
  for (p = rrs[0], i = 1; i < rr_found; i += 2)
    {
      unsigned char *start = rrs[i];
      unsigned char *end = (i != rr_found - 1) ? rrs[i+1] : ((unsigned char *)header) + plen;
      
      memmove(p, start, end-start);
      p += end-start;
    }
     
  plen = p - (unsigned char *)header;
  header->ancount = htons(ntohs(header->ancount) - chop_an);
  header->nscount = htons(ntohs(header->nscount) - chop_ns);
  header->arcount = htons(ntohs(header->arcount) - chop_ar);

  return plen;
}

/**
 * @brief Return descriptor array for RR type indicating domain name locations in RDATA
 * 
 * @detailed
 * Provides a descriptor array that maps a DNS resource record type to the structure
 * of its RDATA, specifically indicating where domain names appear. The descriptor is
 * an array of u16 values where 0 indicates a domain name at that position, positive
 * integers indicate that many bytes of fixed data to skip, and -1 (0xffff) marks the
 * end. This enables generic traversal of RDATA to find and process embedded domain
 * names during compression pointer fixup.
 * 
 * For example, MX records have descriptor [2, 0, -1] meaning: skip 2 bytes (preference),
 * then a domain name (mail exchanger), then end. SOA has [0, 0, -1]: primary nameserver
 * domain, responsible person domain, then end (fixed fields follow but don't contain
 * names). The function returns a pointer positioned after the matching type identifier,
 * ready to be traversed sequentially.
 * 
 * @param[in] type DNS RR type (T_NS, T_CNAME, T_MX, T_SOA, etc.) from dns-protocol.h
 * 
 * @return Pointer to descriptor array for this type positioned after type identifier, never NULL
 * 
 * @retval [0, -1] for types containing only a domain name (NS, CNAME, PTR, etc.)
 * @retval [2, 0, -1] for MX (2-byte preference + domain name)
 * @retval [-1] for types with no domain names (returned for unknown types via wildcard entry)
 * 
 * @note Descriptor array is static constant data, shared across all calls
 * @note Unknown RR types return wildcard descriptor [-1] indicating no name processing needed
 * @note Used by both rrfilter.c (compression fixup) and dnssec.c (signature validation traversal)
 * @note Descriptor format: 0=domain name, N>0=skip N bytes, 0xffff=end
 * 
 * @warning Returned pointer is to static data, must not be modified or freed
 * @warning Does not validate type parameter, always returns valid pointer (wildcard for unknown)
 * 
 * @see check_rrs() for usage in RR RDATA traversal
 * @see rrfilter() for compression pointer fixup using descriptors
 * 
 * EXAMPLE USAGE:
 * @code
 * u16 *desc = rrfilter_desc(T_MX);
 * unsigned char *rdata = ...;
 * for (u16 *d = desc; *d != (u16)-1; d++) {
 *     if (*d != 0)
 *         rdata += *d;  // Skip fixed bytes
 *     else
 *         process_domain_name(&rdata);  // Handle domain name
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Descriptor content matches RDATA formats defined in:
 * - RFC 1035 Section 3.3 (Standard RRs: NS, CNAME, SOA, PTR, MX, TXT, etc.)
 * - RFC 2535 Section 4.1 (SIG record format)
 * - RFC 2163 (PX record)
 * - RFC 2535 (NXT record)
 * - RFC 2782 (SRV record)
 * - RFC 2672 (DNAME record)
 * 
 * SIDE EFFECTS:
 * None. Pure lookup function returning pointer to static const data.
 * 
 * THREAD SAFETY:
 * Re-entrant and thread-safe. Returns pointer to read-only static const data.
 */
/* This is used in the DNSSEC code too, hence it's exported */
u16 *rrfilter_desc(int type)
{
  /* List of RRtypes which include domains in the data.
     0 -> domain
     integer -> no. of plain bytes
     -1 -> end

     zero is not a valid RRtype, so the final entry is returned for
     anything which needs no mangling.
  */
  
  static u16 rr_desc[] = 
    { 
      T_NS, 0, -1, 
      T_MD, 0, -1,
      T_MF, 0, -1,
      T_CNAME, 0, -1,
      T_SOA, 0, 0, -1,
      T_MB, 0, -1,
      T_MG, 0, -1,
      T_MR, 0, -1,
      T_PTR, 0, -1,
      T_MINFO, 0, 0, -1,
      T_MX, 2, 0, -1,
      T_RP, 0, 0, -1,
      T_AFSDB, 2, 0, -1,
      T_RT, 2, 0, -1,
      T_SIG, 18, 0, -1,
      T_PX, 2, 0, 0, -1,
      T_NXT, 0, -1,
      T_KX, 2, 0, -1,
      T_SRV, 6, 0, -1,
      T_DNAME, 0, -1,
      0, -1 /* wildcard/catchall */
    }; 
  
  u16 *p = rr_desc;
  
  while (*p != type && *p != 0)
    while (*p++ != (u16)-1);

  return p+1;
}

/**
 * @brief Expand dynamic pointer array workspace if needed to accommodate more entries
 * 
 * @detailed
 * Grows a dynamically allocated array of unsigned char pointers when the current size
 * is insufficient for the requested capacity. Used by rrfilter() to expand the rrs
 * array that tracks start/end positions of removed resource records. The function
 * implements a growth strategy that adds 5 slots beyond the requested size and imposes
 * a hard limit of 100 entries to prevent runaway memory consumption from malformed
 * packets.
 * 
 * If expansion is needed, allocates a new array with whine_malloc() (which logs on
 * failure), copies existing pointers from the old array, frees the old array, and
 * updates the size. If the current size already accommodates the request, returns
 * success immediately without allocation. The function preserves existing array
 * contents during expansion.
 * 
 * @param[in,out] wkspc Pointer to pointer to array (updated to new array on expansion)
 * @param[in,out] szp Pointer to current size (updated to new size on expansion)
 * @param[in] new Minimum required capacity (number of pointers needed)
 * 
 * @return 1 on success (expansion performed or not needed), 0 on failure (allocation failed or limit exceeded)
 * 
 * @retval 1 if current size >= new+1 (no expansion needed)
 * @retval 1 if expansion succeeded and new array allocated
 * @retval 0 if new >= 100 (hard limit to prevent excessive allocation)
 * @retval 0 if whine_malloc() fails (out of memory)
 * 
 * @note Growth strategy: allocates new_size = requested + 5 to reduce reallocation frequency
 * @note Hard limit of 100 entries prevents malicious packets from consuming excessive memory
 * @note Preserves existing array contents via memcpy during expansion
 * @note Frees old array only after successful copy to new array
 * @note Initial call with *wkspc=NULL and *szp=0 allocates first array
 * 
 * @warning Frees old *wkspc array on successful expansion, caller must not use old pointer
 * @warning Imposes hard limit of 100 entries total (returns 0 if new >= 100)
 * @warning Does not initialize newly allocated slots beyond copied region
 * @warning On failure (return 0), *wkspc and *szp are unchanged
 * 
 * @see rrfilter() for usage in rrs array expansion
 * @see whine_malloc() (util.c) for logging memory allocation wrapper
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char **rrs = NULL;
 * int rr_sz = 0;
 * if (!expand_workspace(&rrs, &rr_sz, 10)) {
 *     // Allocation failed or limit exceeded
 *     return error;
 * }
 * // rrs now has capacity for at least 11 pointers (10+1), rr_sz updated
 * rrs[0] = some_pointer;
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Not protocol-specific. General-purpose memory management utility.
 * 
 * SIDE EFFECTS:
 * - Allocates new array via whine_malloc() if expansion needed
 * - Frees old array if expansion succeeded and old array existed
 * - Updates *wkspc to point to new array
 * - Updates *szp to new capacity
 * - Logs allocation failures via whine_malloc()
 * 
 * THREAD SAFETY:
 * Re-entrant. No static or global state. Safe for concurrent use with different workspace arrays.
 * However, caller must ensure exclusive access to *wkspc and *szp parameters.
 */
int expand_workspace(unsigned char ***wkspc, int *szp, int new)
{
  unsigned char **p;
  int old = *szp;

  if (old >= new+1)
    return 1;

  if (new >= 100)
    return 0;

  new += 5;
  
  if (!(p = whine_malloc(new * sizeof(unsigned char *))))
    return 0;  
  
  if (old != 0 && *wkspc)
    {
      memcpy(p, *wkspc, old * sizeof(unsigned char *));
      free(*wkspc);
    }
  
  *wkspc = p;
  *szp = new;

  return 1;
}
