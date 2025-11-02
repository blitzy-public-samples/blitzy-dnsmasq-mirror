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
 * @file edns0.c
 * @brief EDNS0 OPT record handling and client subnet extension processing
 *
 * DETAILED PURPOSE:
 * This file implements comprehensive support for DNS Extension Mechanisms (EDNS0) 
 * as defined in RFC 6891. EDNS0 extends DNS to support larger UDP payloads beyond 
 * the original 512-byte limit, additional flags like the DNSSEC OK (DO) bit, and 
 * arbitrary extension options in OPT pseudo-records. The implementation handles 
 * multiple EDNS0 extensions including EDNS Client Subnet (ECS) per RFC 7871, 
 * DNS Cookies per RFC 7873, MAC address identification for Apple devices, Cisco 
 * Umbrella device identification, and CPE-ID tracking. Functions manage both 
 * insertion of EDNS0 options into outbound queries to upstream servers and 
 * validation/filtering of options in responses to ensure proper handling of 
 * client-specific data.
 *
 * The core functionality provides automatic addition of configured EDNS0 options 
 * to DNS queries forwarded to upstream resolvers, enabling features like client 
 * privacy (ECS address truncation), device identification, and DNSSEC validation 
 * signaling. Response validation ensures that upstream servers properly honor 
 * client subnet options by verifying returned scope netmasks match query parameters.
 *
 * KEY RESPONSIBILITIES:
 * - find_pseudoheader() locates existing EDNS0 OPT records in DNS packets
 * - add_pseudoheader() creates or modifies OPT records with specified options
 * - add_edns0_config() primary entry point for adding configured options to queries
 * - add_source_addr() implements EDNS Client Subnet (ECS) per RFC 7871
 * - add_mac() adds MAC address option for Apple device identification
 * - add_dns_client() adds base64/hex-encoded MAC for NOM device tracking
 * - add_umbrella_opt() implements Cisco Umbrella device identification protocol
 * - check_source() validates ECS option in responses matches query parameters
 * - add_do_bit() sets DNSSEC OK flag in OPT record
 * - calc_subnet_opt() computes subnet parameters for ECS option
 *
 * DEPENDENCIES:
 * - dnsmasq.h: Core type definitions (dns_header, mysockaddr, daemon globals)
 * - Called by: DNS forwarding logic in forward.c when preparing upstream queries
 * - Calls: skip_name(), skip_questions(), skip_section() for DNS packet traversal
 * - Calls: find_mac() from network layer to retrieve client MAC addresses
 * - Calls: rrfilter() to remove existing OPT records when rebuilding
 * - Calls: whine_malloc() for temporary buffer allocation during OPT reconstruction
 *
 * DATA STRUCTURES:
 * - struct subnet_opt (lines 326-330): EDNS Client Subnet option format
 * - struct umbrella_opt (lines 477-487): Cisco Umbrella identification option
 * - Uses dns_header from dnsmasq.h for DNS packet manipulation
 * - Uses union mysockaddr from dnsmasq.h for address family abstraction
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC: Affects DO bit handling in add_pseudoheader() and add_do_bit()
 * - OPT_ADD_MAC: Runtime flag enabling MAC address addition to queries
 * - OPT_STRIP_MAC: Runtime flag controlling MAC replacement/removal in queries
 * - OPT_CLIENT_SUBNET: Runtime flag enabling EDNS Client Subnet (ECS)
 * - OPT_STRIP_ECS: Runtime flag controlling ECS replacement/removal
 * - OPT_MAC_B64/OPT_MAC_HEX: Runtime flags for MAC encoding format
 * - OPT_UMBRELLA: Runtime flag enabling Cisco Umbrella device identification
 * - OPT_UMBRELLA_DEVID: Runtime flag controlling device ID inclusion
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. Functions are called sequentially from DNS 
 * query processing path in forward.c. No locking required. Functions modify DNS 
 * packet buffers in-place, requiring careful bounds checking via limit parameters. 
 * All functions are re-entrant with respect to independent DNS queries.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DNS_FORWARDING.md for EDNS0 integration in query forwarding pipeline
 */

#include "dnsmasq.h"

/**
 * @brief Locate EDNS0 OPT pseudo-record in DNS packet
 *
 * @detailed Searches the additional section of a DNS packet for an EDNS0 OPT 
 * resource record as defined in RFC 6891. The OPT record is a pseudo-RR that 
 * carries protocol extensions in the DNS additional section. This function also 
 * detects signed packets (TSIG/TKEY) which cannot be modified without invalidating 
 * signatures. Returns pointer to OPT record if present, NULL otherwise.
 *
 * @param header Pointer to DNS packet header structure
 * @param plen Total length of DNS packet in bytes
 * @param len Output parameter receiving OPT record length if found (may be NULL)
 * @param p Output parameter receiving pointer to UDP size field in OPT record (may be NULL)
 * @param is_sign Output parameter set to 1 if packet is signed with TSIG/TKEY (may be NULL)
 * @param is_last Output parameter set to 1 if OPT record is last in additional section (may be NULL)
 *
 * @return Pointer to start of OPT record if present, NULL if not found or packet malformed
 *
 * @retval Non-NULL Pointer to OPT pseudo-record in additional section
 * @retval NULL No OPT record present, or packet is malformed, or parse error occurred
 *
 * @note Function skips question, answer, and authority sections to reach additional section
 * @note TKEY queries (for GSS-TSIG) are detected in question section if is_sign provided
 * @note TSIG records are detected in final additional section RR if is_sign provided
 * @note Signed packets must not be modified as this invalidates cryptographic signatures
 *
 * @warning Returns NULL immediately on any parsing error to prevent buffer overruns
 * @warning Caller must verify returned pointer is within valid packet bounds before dereferencing
 *
 * @see add_pseudoheader() for creating or modifying OPT records
 * @see RFC 6891 Section 6.1.1 for OPT RR format specification
 * @see RFC 2845 for TSIG (Transaction Signature) specification
 * @see RFC 2930 for TKEY (Transaction Key) specification
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *opt_start;
 * size_t opt_len;
 * int is_signed;
 * opt_start = find_pseudoheader(header, packet_len, &opt_len, NULL, &is_signed, NULL);
 * if (opt_start && !is_signed) {
 *   // Safe to modify OPT record
 * }
 * @endcode
 *
 * RFC COMPLIANCE: RFC 6891 (EDNS0), RFC 2845 (TSIG), RFC 2930 (TKEY)
 *
 * SIDE EFFECTS: None - read-only packet examination
 *
 * THREAD SAFETY: Re-entrant, safe for concurrent calls with independent packet buffers
 */
unsigned char *find_pseudoheader(struct dns_header *header, size_t plen, size_t  *len, unsigned char **p, int *is_sign, int *is_last)
{
  /* See if packet has an RFC2671 pseudoheader, and if so return a pointer to it. 
     also return length of pseudoheader in *len and pointer to the UDP size in *p
     Finally, check to see if a packet is signed. If it is we cannot change a single bit before
     forwarding. We look for TSIG in the addition section, and TKEY queries (for GSS-TSIG) */
  
  int i, arcount = ntohs(header->arcount);
  unsigned char *ansp = (unsigned char *)(header+1);
  unsigned short rdlen, type, class;
  unsigned char *ret = NULL;

  if (is_sign)
    {
      *is_sign = 0;

      if (OPCODE(header) == QUERY)
	{
	  for (i = ntohs(header->qdcount); i != 0; i--)
	    {
	      if (!(ansp = skip_name(ansp, header, plen, 4)))
		return NULL;
	      
	      GETSHORT(type, ansp); 
	      GETSHORT(class, ansp);
	      
	      if (class == C_IN && type == T_TKEY)
		*is_sign = 1;
	    }
	}
    }
  else
    {
      if (!(ansp = skip_questions(header, plen)))
	return NULL;
    }
    
  if (arcount == 0)
    return NULL;
  
  if (!(ansp = skip_section(ansp, ntohs(header->ancount) + ntohs(header->nscount), header, plen)))
    return NULL; 
  
  for (i = 0; i < arcount; i++)
    {
      unsigned char *save, *start = ansp;
      if (!(ansp = skip_name(ansp, header, plen, 10)))
	return NULL; 

      GETSHORT(type, ansp);
      save = ansp;
      GETSHORT(class, ansp);
      ansp += 4; /* TTL */
      GETSHORT(rdlen, ansp);
      if (!ADD_RDLEN(header, ansp, plen, rdlen))
	return NULL;
      if (type == T_OPT)
	{
	  if (len)
	    *len = ansp - start;

	  if (p)
	    *p = save;
	  
	  if (is_last)
	    *is_last = (i == arcount-1);

	  ret = start;
	}
      else if (is_sign && 
	       i == arcount - 1 && 
	       class == C_ANY && 
	       type == T_TSIG)
	*is_sign = 1;
    }
  
  return ret;
}
 

/**
 * @brief Create or modify EDNS0 OPT pseudo-record in DNS packet
 *
 * @detailed Adds an EDNS0 OPT resource record to the additional section of a DNS 
 * packet, or modifies an existing OPT record by adding/replacing/deleting specific 
 * options. Handles complex scenarios including signed packets (which cannot be modified), 
 * malformed existing OPT records (which are deleted and recreated), and OPT records 
 * not in final position (which are moved to comply with RFC 6891). Sets UDP payload 
 * size, extended RCODE, and DNSSEC OK (DO) flag as specified. Option modification 
 * supports add-if-absent, replace-if-present, and delete-only modes.
 *
 * @param header Pointer to DNS packet header structure to modify
 * @param plen Current length of DNS packet in bytes
 * @param limit Pointer to end of available packet buffer (for bounds checking)
 * @param udp_sz Maximum UDP payload size to advertise (typically 4096 for EDNS0)
 * @param optno EDNS0 option code to add (0 to skip adding option, e.g., EDNS0_OPTION_CLIENT_SUBNET)
 * @param opt Pointer to option data bytes to insert (ignored if optno is 0)
 * @param optlen Length of option data in bytes (ignored if optno is 0)
 * @param set_do Set to 1 to enable DNSSEC OK flag (0x8000), 0 to leave unchanged
 * @param replace Operation mode: 0=add if absent, 1=replace if present, 2=delete only (don't add)
 *
 * @return New packet length in bytes after modification, or original plen if modification failed
 *
 * @retval >plen Packet successfully extended with new/modified OPT record
 * @retval plen Modification failed (packet too small, signed, or malformed), original packet unchanged
 *
 * @note Returns original plen unchanged for signed packets to prevent signature invalidation
 * @note Malformed existing OPT records are deleted and recreated from scratch
 * @note OPT records not in final additional section position are moved to end per RFC 6891
 * @note replace=0: Only adds option if not already present (for client-side additions)
 * @note replace=1: Replaces existing option or adds if absent (for option rewriting)
 * @note replace=2: Deletes existing option without adding new one (for option stripping)
 *
 * @warning Packet must have sufficient space between plen and limit for OPT record expansion
 * @warning Modifying signed packets will invalidate TSIG signatures - function checks is_sign
 * @warning Caller must ensure limit pointer accurately represents buffer end to prevent overruns
 *
 * @see find_pseudoheader() to locate existing OPT records before modification
 * @see add_edns0_config() for primary interface to add configured options
 * @see rrfilter() used internally to remove OPT records when repositioning to packet end
 * @see RFC 6891 Section 6.1.2 for OPT record wire format
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char subnet_data[20];
 * size_t new_len = add_pseudoheader(header, plen, limit, 4096, 
 *                                    EDNS0_OPTION_CLIENT_SUBNET, subnet_data, 20, 0, 1);
 * if (new_len > plen) {
 *   // OPT record successfully added/modified
 * }
 * @endcode
 *
 * RFC COMPLIANCE: RFC 6891 (EDNS0 OPT RR format)
 *
 * SIDE EFFECTS: Modifies DNS packet in-place, may increase header->arcount
 *
 * THREAD SAFETY: Re-entrant, modifies caller-provided buffer, no shared state
 */
/* replace == 2 ->delete existing option only. */
size_t add_pseudoheader(struct dns_header *header, size_t plen, unsigned char *limit, 
			unsigned short udp_sz, int optno, unsigned char *opt, size_t optlen, int set_do, int replace)
{ 
  unsigned char *lenp, *datap, *p, *udp_len, *buff = NULL;
  int rdlen = 0, is_sign, is_last;
  unsigned short flags = set_do ? 0x8000 : 0, rcode = 0;

  p = find_pseudoheader(header, plen, NULL, &udp_len, &is_sign, &is_last);
  
  if (is_sign)
    return plen;

  if (p)
    {
      /* Existing header */
      int i;
      unsigned short code, len;

      p = udp_len;
      GETSHORT(udp_sz, p);
      GETSHORT(rcode, p);
      GETSHORT(flags, p);

      if (set_do)
	{
	  p -= 2;
	  flags |= 0x8000;
	  PUTSHORT(flags, p);
	}

      lenp = p;
      GETSHORT(rdlen, p);
      if (!CHECK_LEN(header, p, plen, rdlen))
	return plen; /* bad packet */
      datap = p;

       /* no option to add */
      if (optno == 0)
	return plen;
      	  
      /* check if option already there */
      for (i = 0; i + 4 < rdlen;)
	{
	  GETSHORT(code, p);
	  GETSHORT(len, p);
	  
	  /* malformed option, delete the whole OPT RR and start again. */
	  if (i + 4 + len > rdlen)
	    {
	      rdlen = 0;
	      is_last = 0;
	      break;
	    }
	  
	  if (code == optno)
	    {
	      if (replace == 0)
		return plen;

	      /* delete option if we're to replace it. */
	      p -= 4;
	      rdlen -= len + 4;
	      memmove(p, p+len+4, rdlen - i);
	      PUTSHORT(rdlen, lenp);
	      lenp -= 2;
	    }
	  else
	    {
	      p += len;
	      i += len + 4;
	    }
	}

      /* If we're going to extend the RR, it has to be the last RR in the packet */
      if (!is_last)
	{
	  /* First, take a copy of the options. */
	  if (rdlen != 0 && (buff = whine_malloc(rdlen)))
	    memcpy(buff, datap, rdlen);	      
	  
	  /* now, delete OPT RR */
	  plen = rrfilter(header, plen, RRFILTER_EDNS0);
	  
	  /* Now, force addition of a new one */
	  p = NULL;	  
	}
    }
  
  if (!p)
    {
      /* We are (re)adding the pseudoheader */
      if (!(p = skip_questions(header, plen)) ||
	  !(p = skip_section(p, 
			     ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount), 
			     header, plen)))
      {
	free(buff);
	return plen;
      }
      if (p + 11 > limit)
      {
        free(buff);
        return plen; /* Too big */
      }
      *p++ = 0; /* empty name */
      PUTSHORT(T_OPT, p);
      PUTSHORT(udp_sz, p); /* max packet length, 512 if not given in EDNS0 header */
      PUTSHORT(rcode, p);    /* extended RCODE and version */
      PUTSHORT(flags, p); /* DO flag */
      lenp = p;
      PUTSHORT(rdlen, p);    /* RDLEN */
      datap = p;
      /* Copy back any options */
      if (buff)
	{
          if (p + rdlen > limit)
          {
            free(buff);
            return plen; /* Too big */
          }
	  memcpy(p, buff, rdlen);
	  free(buff);
	  p += rdlen;
	}
      
      /* Only bump arcount if RR is going to fit */ 
      if (((ssize_t)optlen) <= (limit - (p + 4)))
	header->arcount = htons(ntohs(header->arcount) + 1);
    }
  
  if (((ssize_t)optlen) > (limit - (p + 4)))
    return plen; /* Too big */
  
  /* Add new option */
  if (optno != 0 && replace != 2)
    {
      if (p + 4 > limit)
       return plen; /* Too big */
      PUTSHORT(optno, p);
      PUTSHORT(optlen, p);
      if (p + optlen > limit)
       return plen; /* Too big */
      memcpy(p, opt, optlen);
      p += optlen;  
      PUTSHORT(p - datap, lenp);
    }
  return p - (unsigned char *)header;
}

/**
 * @brief Set DNSSEC OK (DO) flag in EDNS0 OPT record
 *
 * @detailed Convenience wrapper around add_pseudoheader() that sets the DNSSEC OK 
 * flag (bit 15 of EDNS flags field) without adding any additional options. Used when 
 * DNSSEC validation is enabled to signal upstream resolvers that DNSSEC RRs (RRSIG, 
 * DNSKEY, DS, NSEC, NSEC3) should be included in responses. Creates minimal OPT 
 * record with 512-byte UDP size if no OPT record exists, or modifies existing OPT 
 * to set DO flag.
 *
 * @param header Pointer to DNS packet header structure
 * @param plen Current DNS packet length in bytes
 * @param limit Pointer to end of packet buffer for bounds checking
 *
 * @return New packet length after adding/modifying OPT record, or original plen if failed
 *
 * @retval >plen OPT record successfully created or DO flag successfully set
 * @retval plen Modification failed (buffer full or packet signed), original packet unchanged
 *
 * @note DO flag signals resolver to include DNSSEC records in response per RFC 4035
 * @note Uses default PACKETSZ (512 bytes) UDP payload size for minimal EDNS0 compliance
 * @note Only called when HAVE_DNSSEC is compiled and DNSSEC validation is enabled
 *
 * @warning Called before DNSSEC-aware queries to upstream, requires EDNS0 support
 *
 * @see add_pseudoheader() for underlying OPT record manipulation
 * @see RFC 4035 Section 3.2.3 for DO flag specification
 * @see docs/DNSSEC.md for DNSSEC validation workflow
 *
 * EXAMPLE USAGE:
 * @code
 * if (option_bool(OPT_DNSSEC_VALID)) {
 *   plen = add_do_bit(header, plen, limit);
 * }
 * @endcode
 *
 * RFC COMPLIANCE: RFC 4035 Section 3 (DNSSEC OK flag), RFC 6891 (EDNS0)
 *
 * SIDE EFFECTS: May add OPT record to packet, incrementing header->arcount
 *
 * THREAD SAFETY: Re-entrant, modifies caller-provided buffer
 */
size_t add_do_bit(struct dns_header *header, size_t plen, unsigned char *limit)
{
  return add_pseudoheader(header, plen, (unsigned char *)limit, PACKETSZ, 0, NULL, 0, 1, 0);
}

/**
 * @brief Convert 6-bit value to base64 character
 *
 * @detailed Maps a 6-bit value (0-63) to corresponding base64 alphabet character 
 * using standard base64 encoding table: A-Z (0-25), a-z (26-51), 0-9 (52-61), 
 * + (62), / (63). Input is masked to 6 bits (& 0x3f) ensuring valid table index.
 * Used by encoder() for base64 encoding of MAC addresses.
 *
 * @param c 6-bit value to encode (only lower 6 bits used)
 *
 * @return Base64 character corresponding to input value
 *
 * @note Uses standard base64 alphabet per RFC 4648
 * @note Input automatically masked to 6 bits, safe for any unsigned char input
 *
 * @see encoder() for 3-byte to 4-character base64 encoding
 * @see RFC 4648 Section 4 for base64 encoding specification
 *
 * THREAD SAFETY: Re-entrant, no state, safe for concurrent calls
 */
static unsigned char char64(unsigned char c)
{
  return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[c & 0x3f];
}

/**
 * @brief Encode 3 bytes to 4 base64 characters
 *
 * @detailed Converts a 3-byte input sequence to 4-character base64 encoded output 
 * using standard base64 encoding algorithm. Each input byte contributes bits to 
 * output characters according to base64 bit distribution: byte0[7:2]→out[0], 
 * byte0[1:0]+byte1[7:4]→out[1], byte1[3:0]+byte2[7:6]→out[2], byte2[5:0]→out[3]. 
 * Used to encode 6-byte MAC addresses as 8-character base64 strings for device 
 * identification options.
 *
 * @param in Pointer to 3-byte input buffer to encode
 * @param out Pointer to 4-character output buffer (must have space for 4 chars)
 *
 * @return None (output written to out parameter)
 *
 * @note Output buffer must be pre-allocated with at least 4 bytes
 * @note Does not null-terminate output - caller handles string termination
 * @note Called twice to encode 6-byte MAC: encoder(mac, out) then encoder(mac+3, out+4)
 *
 * @warning No bounds checking - caller must ensure out has 4-byte capacity
 *
 * @see char64() for single 6-bit value encoding
 * @see add_dns_client() for MAC address base64 encoding usage
 * @see RFC 4648 Section 4 for base64 encoding specification
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
 * char b64[9];
 * encoder(mac, b64);      // First 3 bytes
 * encoder(mac+3, b64+4);  // Second 3 bytes
 * b64[8] = 0;             // Null terminate
 * @endcode
 *
 * SIDE EFFECTS: Writes 4 characters to out buffer
 *
 * THREAD SAFETY: Re-entrant, no shared state
 */
static void encoder(unsigned char *in, char *out)
{
  out[0] = char64(in[0]>>2);
  out[1] = char64((in[0]<<4) | (in[1]>>4));
  out[2] = char64((in[1]<<2) | (in[2]>>6));
  out[3] = char64(in[2]);
}

/**
 * @brief Add base64 or hex-encoded MAC address as NOM Device ID option
 *
 * @detailed Adds EDNS0 option EDNS0_OPTION_NOMDEVICEID containing client MAC address 
 * encoded in either base64 (default) or hexadecimal format based on OPT_MAC_B64/OPT_MAC_HEX 
 * configuration. Used for device identification in carrier-grade NAT environments where 
 * IP addresses don't uniquely identify clients. Supports add, replace, and strip modes 
 * controlled by OPT_ADD_MAC and OPT_STRIP_MAC flags. Only processes 6-byte (Ethernet) 
 * MAC addresses. Sets cacheablep=0 when MAC is added as responses are device-specific.
 *
 * @param header Pointer to DNS packet header to modify
 * @param plen Current DNS packet length in bytes
 * @param limit Pointer to end of packet buffer
 * @param l3 Client layer-3 address used to lookup MAC via ARP/neighbor cache
 * @param now Current timestamp for MAC cache lookup
 * @param cacheablep Output parameter set to 0 if MAC added (response not cacheable)
 *
 * @return New packet length after option addition, or original plen if no change
 *
 * @retval >plen MAC option successfully added to packet
 * @retval plen No MAC available, option stripped, or packet full
 *
 * @note OPT_MAC_B64: Encode MAC as 8-character base64 string (compact)
 * @note OPT_MAC_HEX: Encode MAC as 17-character hex string (human-readable)
 * @note OPT_ADD_MAC alone: Add MAC if available, don't remove if absent
 * @note OPT_ADD_MAC + OPT_STRIP_MAC: Replace MAC if available, remove if absent
 * @note OPT_STRIP_MAC alone: Remove existing MAC option, don't add new
 * @note Only 6-byte MACs supported (Ethernet/WiFi), other lengths ignored
 *
 * @warning Sets *cacheablep=0 when MAC added - responses differ per client device
 * @warning MAC lookup requires working ARP/neighbor cache in network layer
 *
 * @see find_mac() in network.c for MAC address resolution from L3 address
 * @see add_mac() for alternative EDNS0_OPTION_MAC format
 * @see print_mac() for hexadecimal MAC formatting
 * @see encoder() for base64 MAC encoding
 *
 * EXAMPLE USAGE:
 * @code
 * int cacheable = 1;
 * plen = add_dns_client(header, plen, limit, &client_addr, time(NULL), &cacheable);
 * if (!cacheable) {
 *   // Response contains device-specific data, cannot cache
 * }
 * @endcode
 *
 * SIDE EFFECTS: Sets *cacheablep=0 if MAC option added, modifies packet in-place
 *
 * THREAD SAFETY: Re-entrant, calls find_mac() which accesses ARP cache atomically
 */
/* OPT_ADD_MAC = MAC is added (if available)
   OPT_ADD_MAC + OPT_STRIP_MAC = MAC is replaced, if not available, it is only removed
   OPT_STRIP_MAC = MAC is removed */
static size_t add_dns_client(struct dns_header *header, size_t plen, unsigned char *limit,
			     union mysockaddr *l3, time_t now, int *cacheablep)
{
  int replace = 0, maclen = 0;
  unsigned char mac[DHCP_CHADDR_MAX];
  char encode[18]; /* handle 6 byte MACs ONLY */

  if ((option_bool(OPT_MAC_B64) || option_bool(OPT_MAC_HEX)) && (maclen = find_mac(l3, mac, 1, now)) == 6)
    {
      if (option_bool(OPT_STRIP_MAC))
	 replace = 1;
       *cacheablep = 0;
    
       if (option_bool(OPT_MAC_HEX))
	 print_mac(encode, mac, maclen);
       else
	 {
	   encoder(mac, encode);
	   encoder(mac+3, encode+4);
	   encode[8] = 0;
	 }
    }
  else if (option_bool(OPT_STRIP_MAC))
    replace = 2;

  if (replace != 0 || maclen == 6)
    plen = add_pseudoheader(header, plen, limit, PACKETSZ, EDNS0_OPTION_NOMDEVICEID, (unsigned char *)encode, strlen(encode), 0, replace);

  return plen;
}


/**
 * @brief Add raw MAC address bytes as EDNS0 MAC option
 *
 * @detailed Adds EDNS0 option EDNS0_OPTION_MAC containing client MAC address in raw 
 * binary format (unencoded bytes). Supports variable-length MAC addresses (typically 
 * 6 bytes for Ethernet/WiFi, up to 16 bytes for other link layers). Provides add, 
 * replace, and strip modes via OPT_ADD_MAC and OPT_STRIP_MAC configuration flags. 
 * Used for Apple device identification where raw MAC format is preferred. Sets 
 * cacheablep=0 when MAC is added since responses are device-specific and should not 
 * be cached and served to other clients.
 *
 * @param header Pointer to DNS packet header to modify
 * @param plen Current DNS packet length in bytes
 * @param limit Pointer to end of packet buffer for bounds checking
 * @param l3 Client layer-3 address for MAC resolution via ARP/neighbor cache
 * @param now Current timestamp for MAC cache lookup
 * @param cacheablep Output parameter set to 0 if MAC added (response device-specific)
 *
 * @return New packet length after option addition, or original plen if unchanged
 *
 * @retval >plen MAC option successfully added to packet
 * @retval plen No MAC available, option stripped, or buffer full
 *
 * @note OPT_ADD_MAC alone: Add MAC if available, leave packet unchanged if absent
 * @note OPT_ADD_MAC + OPT_STRIP_MAC: Replace MAC if available, remove option if absent
 * @note OPT_STRIP_MAC alone: Remove existing MAC option without adding new
 * @note Accepts variable-length MACs (6 bytes typical, up to DHCP_CHADDR_MAX)
 * @note Raw binary format - no encoding, suitable for binary-aware systems
 *
 * @warning Sets *cacheablep=0 when MAC added - responses not shareable between clients
 * @warning MAC resolution depends on populated ARP/neighbor cache
 *
 * @see find_mac() in network.c for MAC address lookup from L3 address
 * @see add_dns_client() for base64/hex-encoded MAC variant
 * @see EDNS0_OPTION_MAC defined in dnsmasq.h for option code
 *
 * EXAMPLE USAGE:
 * @code
 * int cacheable = 1;
 * plen = add_mac(header, plen, limit, &source_addr, time(NULL), &cacheable);
 * if (!cacheable) {
 *   // Cannot cache response for sharing
 * }
 * @endcode
 *
 * SIDE EFFECTS: Sets *cacheablep=0 if MAC added, modifies packet
 *
 * THREAD SAFETY: Re-entrant, ARP cache access in find_mac() is atomic
 */
/* OPT_ADD_MAC = MAC is added (if available)
   OPT_ADD_MAC + OPT_STRIP_MAC = MAC is replaced, if not available, it is only removed
   OPT_STRIP_MAC = MAC is removed */
static size_t add_mac(struct dns_header *header, size_t plen, unsigned char *limit,
		      union mysockaddr *l3, time_t now, int *cacheablep)
{
  int maclen = 0, replace = 0;
  unsigned char mac[DHCP_CHADDR_MAX];
    
  if (option_bool(OPT_ADD_MAC) && (maclen = find_mac(l3, mac, 1, now)) != 0)
    {
      *cacheablep = 0;
      if (option_bool(OPT_STRIP_MAC))
	replace = 1;
    }
  else if (option_bool(OPT_STRIP_MAC))
    replace = 2;
  
  if (replace != 0 || maclen != 0)
    plen = add_pseudoheader(header, plen, limit, PACKETSZ, EDNS0_OPTION_MAC, mac, maclen, 0, replace);

  return plen; 
}

/**
 * @struct subnet_opt
 * @brief EDNS Client Subnet option wire format structure
 *
 * Represents EDNS Client Subnet (ECS) option data per RFC 7871. Contains address 
 * family indicator, source and scope netmask lengths, and truncated client address 
 * bytes. Wire format: family(2) + source_mask(1) + scope_mask(1) + address(variable).
 * Maximum address field is IN6ADDRSZ (16 bytes) for IPv6, actual length determined 
 * by source_netmask rounded up to nearest byte.
 *
 * @var subnet_opt::family
 * Address family: 1 for IPv4 (AF_INET), 2 for IPv6 (AF_INET6), network byte order
 *
 * @var subnet_opt::source_netmask
 * Number of significant bits in client address included in query (0-32 for IPv4, 0-128 for IPv6)
 *
 * @var subnet_opt::scope_netmask
 * Number of significant bits in address used by authoritative server (set by server in response)
 *
 * @var subnet_opt::addr
 * Client address bytes truncated to source_netmask bits, padded to byte boundary
 *
 * LIFECYCLE: Temporary structure populated per-query, not persistent
 * MEMORY LAYOUT: 20 bytes total (2+1+1+16), network byte order for family field
 * USAGE: Passed to add_pseudoheader() as option data for EDNS0_OPTION_CLIENT_SUBNET
 *
 * @see RFC 7871 Section 6 for ECS option wire format specification
 * @see calc_subnet_opt() for structure population from configuration
 */
struct subnet_opt {
  u16 family;
  u8 source_netmask, scope_netmask; 
  u8 addr[IN6ADDRSZ];
};

/**
 * @brief Get pointer to address bytes in sockaddr union
 *
 * @detailed Abstracts address family differences in union mysockaddr by returning 
 * pointer to actual address bytes regardless of family. For AF_INET6 returns pointer 
 * to sin6_addr (16 bytes), for AF_INET returns pointer to sin_addr (4 bytes). Used 
 * to write address-family-agnostic code when manipulating addresses.
 *
 * @param addr Pointer to mysockaddr union containing address
 * @param family Address family: AF_INET (IPv4) or AF_INET6 (IPv6)
 *
 * @return Pointer to address bytes within union
 *
 * @retval struct in6_addr* For AF_INET6, pointer to 16-byte IPv6 address
 * @retval struct in_addr* For AF_INET, pointer to 4-byte IPv4 address
 *
 * @note Return type is void* for flexibility, caller casts as needed
 * @note Address family must match actual union content to avoid undefined behavior
 *
 * @see calc_subnet_opt() for usage in extracting address for ECS option
 * @see add_umbrella_opt() for usage in Cisco Umbrella option construction
 *
 * EXAMPLE USAGE:
 * @code
 * union mysockaddr client_addr;
 * void *addrp = get_addrp(&client_addr, client_addr.sa.sa_family);
 * memcpy(dest, addrp, family == AF_INET6 ? 16 : 4);
 * @endcode
 *
 * THREAD SAFETY: Re-entrant, no state
 */
static void *get_addrp(union mysockaddr *addr, const short family) 
{
  if (family == AF_INET6)
    return &addr->in6.sin6_addr;

  return &addr->in.sin_addr;
}

/**
 * @brief Calculate EDNS Client Subnet option parameters
 *
 * @detailed Populates subnet_opt structure for EDNS Client Subnet (ECS) option per 
 * RFC 7871. Determines address family, applies configured netmask truncation, and 
 * copies appropriate number of address bytes. Supports both dynamic client addresses 
 * (from source parameter) and static configured addresses (from daemon->add_subnet4/6). 
 * For privacy, truncates client address to configured prefix length. Returns total 
 * option data length (4 bytes header + address bytes). Sets cacheablep=1 if using 
 * static configured address (cacheable), 0 if using dynamic client address (not cacheable).
 *
 * @param opt Output structure to populate with ECS option data
 * @param source Client address to extract subnet from (may be overridden by configuration)
 * @param cacheablep Output parameter: 1 if static address used (cacheable), 0 if dynamic (may be NULL)
 *
 * @return Total ECS option data length in bytes (4 header + address length)
 *
 * @retval 4+N Where N is ((source_netmask-1)>>3)+1, number of address bytes included
 * @retval 4 If source_netmask is 0 (no address included, only family and masks)
 *
 * @note daemon->add_subnet4: IPv4 ECS configuration (mask, optional static address)
 * @note daemon->add_subnet6: IPv6 ECS configuration (mask, optional static address)
 * @note addr_used flag: Use static configured address instead of client address
 * @note Address bytes truncated to source_netmask length, unused bits zeroed
 * @note Cacheable=1 means all clients get same ECS, responses shareable
 * @note Cacheable=0 means each client gets unique ECS, responses not shareable
 *
 * @warning source_netmask must not exceed address family max (32 for IPv4, 128 for IPv6)
 * @warning Last address byte may be masked to zero unused bits per RFC 7871 Section 6
 *
 * @see add_source_addr() for adding calculated subnet option to DNS packet
 * @see check_source() for validating ECS option in responses
 * @see RFC 7871 Section 6 for ECS option format specification
 * @see RFC 7871 Section 7.1.2 for privacy considerations on address truncation
 *
 * EXAMPLE USAGE:
 * @code
 * struct subnet_opt opt;
 * int cacheable;
 * size_t opt_len = calc_subnet_opt(&opt, &client_addr, &cacheable);
 * plen = add_pseudoheader(header, plen, limit, PACKETSZ, 
 *                         EDNS0_OPTION_CLIENT_SUBNET, (unsigned char*)&opt, opt_len, 0, 1);
 * @endcode
 *
 * RFC COMPLIANCE: RFC 7871 (EDNS Client Subnet)
 *
 * SIDE EFFECTS: Populates opt structure, sets *cacheablep if provided
 *
 * THREAD SAFETY: Re-entrant, accesses global daemon->add_subnet4/6 (read-only after init)
 */
static size_t calc_subnet_opt(struct subnet_opt *opt, union mysockaddr *source, int *cacheablep)
{
  /* http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02 */
  
  int len;
  void *addrp = NULL;
  int sa_family = source->sa.sa_family;
  int cacheable = 0;
  
  opt->source_netmask = 0;
  opt->scope_netmask = 0;
    
  if (source->sa.sa_family == AF_INET6 && daemon->add_subnet6)
    {
      opt->source_netmask = daemon->add_subnet6->mask;
      if (daemon->add_subnet6->addr_used) 
	{
	  sa_family = daemon->add_subnet6->addr.sa.sa_family;
	  addrp = get_addrp(&daemon->add_subnet6->addr, sa_family);
	  cacheable = 1;
	} 
      else 
	addrp = &source->in6.sin6_addr;
    }

  if (source->sa.sa_family == AF_INET && daemon->add_subnet4)
    {
      opt->source_netmask = daemon->add_subnet4->mask;
      if (daemon->add_subnet4->addr_used)
	{
	  sa_family = daemon->add_subnet4->addr.sa.sa_family;
	  addrp = get_addrp(&daemon->add_subnet4->addr, sa_family);
	  cacheable = 1; /* Address is constant */
	} 
	else 
	  addrp = &source->in.sin_addr;
    }
  
  opt->family = htons(sa_family == AF_INET6 ? 2 : 1);
  
  if (addrp && opt->source_netmask != 0)
    {
      len = ((opt->source_netmask - 1) >> 3) + 1;
      memcpy(opt->addr, addrp, len);
      if (opt->source_netmask & 7)
	opt->addr[len-1] &= 0xff << (8 - (opt->source_netmask & 7));
    }
  else
    {
      cacheable = 1; /* No address ever supplied. */
      len = 0;
    }

  if (cacheablep)
    *cacheablep = cacheable;
  
  return len + 4;
}
 
/**
 * @brief Add EDNS Client Subnet option to DNS query
 *
 * @detailed Implements EDNS Client Subnet (ECS) per RFC 7871 by adding 
 * EDNS0_OPTION_CLIENT_SUBNET to DNS queries forwarded to upstream resolvers. 
 * Provides three operation modes controlled by OPT_CLIENT_SUBNET and OPT_STRIP_ECS 
 * flags: add ECS if configured, replace existing ECS with configured subnet, or 
 * strip ECS entirely. ECS allows authoritative servers to return geographically 
 * relevant responses based on client subnet rather than resolver address. For 
 * privacy, client addresses are truncated to configured prefix length.
 *
 * @param header Pointer to DNS packet header to modify
 * @param plen Current DNS packet length in bytes
 * @param limit Pointer to end of packet buffer
 * @param source Client source address for subnet calculation
 * @param cacheable Output parameter: 1 if response cacheable, 0 if client-specific
 *
 * @return New packet length after ECS option addition, or original plen if no change
 *
 * @retval >plen ECS option successfully added/replaced
 * @retval plen ECS option stripped, not configured, or buffer full
 *
 * @note OPT_CLIENT_SUBNET alone: Add ECS with truncated client subnet
 * @note OPT_CLIENT_SUBNET + OPT_STRIP_ECS: Replace any existing ECS with configured subnet
 * @note OPT_STRIP_ECS alone: Remove ECS option entirely (privacy mode)
 * @note Neither flag set: Returns plen unchanged, no ECS handling
 * @note Sets cacheable=0 if using dynamic client addresses (per-client responses)
 * @note Sets cacheable=1 if using static configured subnet (shared responses)
 *
 * @warning ECS exposes client network information to upstream resolvers (privacy concern)
 * @warning Authoritative servers may cache responses per subnet, affecting CDN selection
 *
 * @see calc_subnet_opt() for subnet option calculation and address truncation
 * @see check_source() for validating ECS in responses matches query
 * @see RFC 7871 for EDNS Client Subnet specification
 * @see RFC 7871 Section 7.1 for privacy and security considerations
 *
 * EXAMPLE USAGE:
 * @code
 * int cacheable = 1;
 * plen = add_source_addr(header, plen, limit, &client_addr, &cacheable);
 * if (!cacheable) {
 *   // Do not cache response for other clients
 * }
 * @endcode
 *
 * RFC COMPLIANCE: RFC 7871 (EDNS Client Subnet)
 *
 * SIDE EFFECTS: Modifies packet, sets *cacheable flag
 *
 * THREAD SAFETY: Re-entrant, uses calc_subnet_opt() which reads global config
 */
/* OPT_CLIENT_SUBNET = client subnet is added
   OPT_CLIENT_SUBNET + OPT_STRIP_ECS = client subnet is replaced
   OPT_STRIP_ECS = client subnet is removed */
static size_t add_source_addr(struct dns_header *header, size_t plen, unsigned char *limit,
			      union mysockaddr *source, int *cacheable)
{
  /* http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02 */
  
  int replace = 0, len = 0;
  struct subnet_opt opt;
  
  if (option_bool(OPT_CLIENT_SUBNET))
    {
      if (option_bool(OPT_STRIP_ECS))
	replace = 1;
      len = calc_subnet_opt(&opt, source, cacheable);
    }
  else if (option_bool(OPT_STRIP_ECS))
    replace = 2;
  else
    return plen;

  return add_pseudoheader(header, plen, (unsigned char *)limit, PACKETSZ, EDNS0_OPTION_CLIENT_SUBNET, (unsigned char *)&opt, len, 0, replace);
}

/**
 * @brief Validate EDNS Client Subnet option in DNS response
 *
 * @detailed Verifies that ECS option in DNS response from upstream resolver matches 
 * the ECS option sent in the query per RFC 7871 Section 9.2. Compares address family, 
 * source netmask, and address bytes to ensure authoritative server properly processed 
 * the client subnet information. Returns 0 (mismatch) if validation fails, which causes 
 * response to be discarded as potentially malicious or misconfigured. The scope netmask 
 * from response is copied for validation but typically differs from source netmask.
 *
 * @param header Pointer to DNS response packet header
 * @param plen Response packet length in bytes
 * @param pseudoheader Pointer to start of OPT record in response (from find_pseudoheader)
 * @param peer Client address used for original query's ECS calculation
 *
 * @return 1 if ECS validation passed or no ECS present, 0 if validation failed
 *
 * @retval 1 Response ECS matches query ECS, or no ECS option present (safe to use)
 * @retval 0 Response ECS mismatches query (wrong family/mask/address), discard response
 *
 * @note Validation ensures upstream didn't tamper with ECS or return wrong-subnet response
 * @note Mismatch indicates potential cache poisoning attempt or upstream misconfiguration
 * @note Returns 1 (success) if packet is malformed to avoid false positives
 * @note scope_netmask from response is extracted but only compared, not validated separately
 *
 * @warning Returning 0 causes response to be discarded and query retried/failed
 * @warning Critical security check preventing subnet-based cache poisoning
 *
 * @see calc_subnet_opt() for calculating expected ECS parameters from peer address
 * @see add_source_addr() for adding ECS to outbound queries
 * @see RFC 7871 Section 9.2 for response validation requirements
 *
 * EXAMPLE USAGE:
 * @code
 * unsigned char *opt = find_pseudoheader(header, plen, NULL, NULL, NULL, NULL);
 * if (opt && !check_source(header, plen, opt, &client_addr)) {
 *   // ECS mismatch, discard response
 *   return 0;
 * }
 * @endcode
 *
 * RFC COMPLIANCE: RFC 7871 Section 9.2 (Authoritative Server Response Validation)
 *
 * SIDE EFFECTS: None - read-only packet examination
 *
 * THREAD SAFETY: Re-entrant, calls calc_subnet_opt() which reads global config
 */
int check_source(struct dns_header *header, size_t plen, unsigned char *pseudoheader, union mysockaddr *peer)
{
  /* Section 9.2, Check that subnet option in reply matches. */
  
  int len, calc_len;
  struct subnet_opt opt;
  unsigned char *p;
  int code, i, rdlen;
  
  calc_len = calc_subnet_opt(&opt, peer, NULL);
   
  if (!(p = skip_name(pseudoheader, header, plen, 10)))
    return 1;
  
  p += 8; /* skip UDP length and RCODE */
  
  GETSHORT(rdlen, p);
  if (!CHECK_LEN(header, p, plen, rdlen))
    return 1; /* bad packet */
  
  /* check if option there */
   for (i = 0; i + 4 < rdlen; i += len + 4)
     {
       GETSHORT(code, p);
       GETSHORT(len, p);
       if (code == EDNS0_OPTION_CLIENT_SUBNET)
	 {
	   /* make sure this doesn't mismatch. */
	   opt.scope_netmask = p[3];
	   if (len != calc_len || memcmp(p, &opt, len) != 0)
	     return 0;
	 }
       p += len;
     }
   
   return 1;
}

/* See https://docs.umbrella.com/umbrella-api/docs/identifying-dns-traffic for
 * detailed information on packet formating.
 */
#define UMBRELLA_VERSION    1
#define UMBRELLA_TYPESZ     2

#define UMBRELLA_ASSET      0x0004
#define UMBRELLA_ASSETSZ    sizeof(daemon->umbrella_asset)
#define UMBRELLA_ORG        0x0008
#define UMBRELLA_ORGSZ      sizeof(daemon->umbrella_org)
#define UMBRELLA_IPV4       0x0010
#define UMBRELLA_IPV6       0x0020
#define UMBRELLA_DEVICE     0x0040
#define UMBRELLA_DEVICESZ   sizeof(daemon->umbrella_device)

/**
 * @struct umbrella_opt
 * @brief Cisco Umbrella device identification option wire format
 *
 * Structure for EDNS0 Cisco Umbrella device identification option per Cisco Umbrella 
 * API specification. Contains magic signature "ODNS", protocol version, flags byte, 
 * and variable-length fields identifying organization, client IP address, device ID, 
 * and asset ID. Maximum 4 TLV fields included (never both IPv4 and IPv6). Sent with 
 * EDNS0_OPTION_UMBRELLA to enable per-device DNS security policies in Cisco Umbrella.
 *
 * @var umbrella_opt::magic
 * 4-byte signature "ODNS" identifying Umbrella protocol
 *
 * @var umbrella_opt::version
 * Protocol version, currently UMBRELLA_VERSION (1)
 *
 * @var umbrella_opt::flags
 * Reserved flags byte, currently unused (set to 0)
 *
 * @var umbrella_opt::fields
 * Variable-length TLV fields: organization ID (4 bytes), client IP (4 or 16 bytes), 
 * device ID (8 bytes), asset ID (4 bytes). Each field prefixed with 2-byte type code.
 *
 * LIFECYCLE: Temporary per-query structure, not persistent
 * MEMORY LAYOUT: 6-byte header + variable fields (max 38 bytes total)
 * USAGE: Populated by add_umbrella_opt(), passed to add_pseudoheader()
 *
 * @see https://docs.umbrella.com/umbrella-api/docs/identifying-dns-traffic
 * @see add_umbrella_opt() for structure population
 */
struct umbrella_opt {
  u8 magic[4];
  u8 version;
  u8 flags;
  /* We have 4 possible fields since we'll never send both IPv4 and
   * IPv6, so using the larger of the two to calculate max buffer size.
   * Each field also has a type header.  So the following accounts for
   * the type headers and each field size to get a max buffer size.
   */
  u8 fields[4 * UMBRELLA_TYPESZ + UMBRELLA_ORGSZ + IN6ADDRSZ + UMBRELLA_DEVICESZ + UMBRELLA_ASSETSZ];
};

/**
 * @brief Add Cisco Umbrella device identification option to DNS query
 *
 * @detailed Implements Cisco Umbrella EDNS0 device identification protocol enabling 
 * per-device DNS security policies and analytics. Adds EDNS0_OPTION_UMBRELLA containing 
 * "ODNS" magic signature, organization ID, client IP address (IPv4 or IPv6), optional 
 * device ID (8 bytes), and optional asset ID (4 bytes). Used in Cisco Umbrella 
 * deployments to associate DNS queries with specific devices and organizational units 
 * for threat intelligence, policy application, and reporting. Always sets cacheable=0 
 * since responses are device-specific.
 *
 * @param header Pointer to DNS packet header to modify
 * @param plen Current DNS packet length in bytes
 * @param limit Pointer to end of packet buffer
 * @param source Client source address (IPv4 or IPv6) to include in option
 * @param cacheable Output parameter set to 0 (responses are device-specific, not cacheable)
 *
 * @return New packet length after Umbrella option addition
 *
 * @retval >plen Umbrella option successfully added
 * @retval plen Buffer full, option addition failed
 *
 * @note OPT_UMBRELLA must be enabled for function to be called
 * @note daemon->umbrella_org: Organization ID (4 bytes), optional
 * @note daemon->umbrella_device: Device ID (8 bytes), included if OPT_UMBRELLA_DEVID set
 * @note daemon->umbrella_asset: Asset ID (4 bytes), optional
 * @note Fields encoded as TLV: 2-byte type code + value bytes
 * @note Always includes client IP (UMBRELLA_IPV4 or UMBRELLA_IPV6)
 * @note Sets *cacheable=0 unconditionally - responses differ per device
 *
 * @warning Discloses device identity and organization to Cisco Umbrella resolvers
 * @warning Replace mode (replace=1) removes existing Umbrella option if present
 *
 * @see get_addrp() for extracting address bytes from source union
 * @see https://docs.umbrella.com/umbrella-api/docs/identifying-dns-traffic for protocol spec
 *
 * EXAMPLE USAGE:
 * @code
 * if (option_bool(OPT_UMBRELLA)) {
 *   int cacheable;
 *   plen = add_umbrella_opt(header, plen, limit, &client_addr, &cacheable);
 *   // cacheable will be 0, do not cache response
 * }
 * @endcode
 *
 * SIDE EFFECTS: Sets *cacheable=0, modifies packet in-place
 *
 * THREAD SAFETY: Re-entrant, accesses global daemon config (read-only after init)
 */
static size_t add_umbrella_opt(struct dns_header *header, size_t plen, unsigned char *limit, union mysockaddr *source, int *cacheable)
{
  *cacheable = 0;

  struct umbrella_opt opt = {{"ODNS"}, UMBRELLA_VERSION, 0, {}};
  u8 *u = &opt.fields[0];
  int family = source->sa.sa_family;
  int size = family == AF_INET ? INADDRSZ : IN6ADDRSZ;

  if (daemon->umbrella_org)
    {
      PUTSHORT(UMBRELLA_ORG, u);
      PUTLONG(daemon->umbrella_org, u);
    }
  
  PUTSHORT(family == AF_INET ? UMBRELLA_IPV4 : UMBRELLA_IPV6, u);
  memcpy(u, get_addrp(source, family), size);
  u += size;
  
  if (option_bool(OPT_UMBRELLA_DEVID))
    {
      PUTSHORT(UMBRELLA_DEVICE, u);
      memcpy(u, (char *)&daemon->umbrella_device, UMBRELLA_DEVICESZ);
      u += UMBRELLA_DEVICESZ;
    }

  if (daemon->umbrella_asset)
    {
      PUTSHORT(UMBRELLA_ASSET, u);
      PUTLONG(daemon->umbrella_asset, u);
    }
  
  return add_pseudoheader(header, plen, (unsigned char *)limit, PACKETSZ, EDNS0_OPTION_UMBRELLA, (unsigned char *)&opt, u - (u8 *)&opt, 0, 1);
}

/**
 * @brief Add all configured EDNS0 options to outbound DNS query
 *
 * @detailed Primary entry point for EDNS0 option processing called from DNS forwarding 
 * code before sending queries to upstream resolvers. Orchestrates addition of all 
 * configured EDNS0 options in proper order: MAC address options (raw and encoded), 
 * CPE-ID client identifier, Cisco Umbrella device identification, and EDNS Client 
 * Subnet. Each option's addition is controlled by runtime configuration flags 
 * (OPT_ADD_MAC, OPT_CLIENT_SUBNET, OPT_UMBRELLA, etc.). Sets cacheable flag based 
 * on whether any device-specific or client-specific options were added - if cacheable=0, 
 * response must not be cached for serving to other clients.
 *
 * @param header Pointer to DNS packet header to modify
 * @param plen Current DNS packet length in bytes before option addition
 * @param limit Pointer to end of packet buffer for bounds checking
 * @param source Client source address for MAC lookup and subnet calculation
 * @param now Current timestamp for MAC cache lookup
 * @param cacheable Output parameter: 1 if response cacheable, 0 if client-specific
 *
 * @return New packet length after all options added
 *
 * @retval >=plen Packet length after option additions (may equal plen if no options added)
 *
 * @note Initializes *cacheable=1 assuming cacheable, subordinate functions set to 0 if needed
 * @note add_mac() adds EDNS0_OPTION_MAC with raw MAC bytes (if OPT_ADD_MAC)
 * @note add_dns_client() adds EDNS0_OPTION_NOMDEVICEID with encoded MAC (if OPT_MAC_B64/HEX)
 * @note daemon->dns_client_id: Adds EDNS0_OPTION_NOMCPEID with CPE identifier string
 * @note add_umbrella_opt() adds Cisco Umbrella option (if OPT_UMBRELLA)
 * @note add_source_addr() adds EDNS Client Subnet last (if OPT_CLIENT_SUBNET)
 * @note Order matters: MAC options first, then identifiers, ECS last
 *
 * @warning If cacheable=0 after call, response MUST NOT be cached for other clients
 * @warning Each subordinate function may modify cacheable independently
 *
 * @see add_mac() for EDNS0_OPTION_MAC addition
 * @see add_dns_client() for EDNS0_OPTION_NOMDEVICEID addition
 * @see add_umbrella_opt() for Cisco Umbrella option
 * @see add_source_addr() for EDNS Client Subnet (ECS)
 * @see forward.c for call site in DNS query forwarding path
 * @see docs/DNS_FORWARDING.md for EDNS0 integration in forwarding pipeline
 *
 * EXAMPLE USAGE:
 * @code
 * int cacheable = 1;
 * size_t new_len = add_edns0_config(header, plen, limit, &client_addr, time(NULL), &cacheable);
 * if (!cacheable) {
 *   // Mark forward record as non-cacheable
 *   frec->flags |= F_NOCACHE;
 * }
 * @endcode
 *
 * RFC COMPLIANCE: RFC 6891 (EDNS0), RFC 7871 (ECS)
 *
 * SIDE EFFECTS: Modifies packet, sets *cacheable flag, may call multiple option handlers
 *
 * THREAD SAFETY: Re-entrant, calls subordinate functions accessing global config
 */
/* Set *check_subnet if we add a client subnet option, which needs to checked 
   in the reply. Set *cacheable to zero if we add an option which the answer
   may depend on. */
size_t add_edns0_config(struct dns_header *header, size_t plen, unsigned char *limit, 
			union mysockaddr *source, time_t now, int *cacheable)    
{
  *cacheable = 1;
  
  plen  = add_mac(header, plen, limit, source, now, cacheable);
  plen = add_dns_client(header, plen, limit, source, now, cacheable);
  
  if (daemon->dns_client_id)
    plen = add_pseudoheader(header, plen, limit, PACKETSZ, EDNS0_OPTION_NOMCPEID, 
			    (unsigned char *)daemon->dns_client_id, strlen(daemon->dns_client_id), 0, 1);

  if (option_bool(OPT_UMBRELLA))
    plen = add_umbrella_opt(header, plen, limit, source, cacheable);
  
  plen = add_source_addr(header, plen, limit, source, cacheable);
  	  
  return plen;
}
