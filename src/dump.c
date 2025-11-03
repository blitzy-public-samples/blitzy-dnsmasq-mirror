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
 * @file dump.c
 * @brief Packet capture to libpcap format for debugging
 *
 * DETAILED PURPOSE:
 * This module provides packet dumping functionality for debugging DNS and DHCP traffic
 * by writing packets to a standard libpcap-format file that can be analyzed with
 * wireshark or tcpdump. The implementation creates pcap-compatible capture files with
 * proper global headers, per-packet headers with timestamps, and reconstructed IP/UDP
 * headers for protocol identification. This allows protocol-level debugging without
 * requiring external packet capture tools or network interfaces in promiscuous mode.
 *
 * KEY RESPONSIBILITIES:
 * - dump_init(): Initialize packet dump file with pcap global header
 * - dump_packet(): Write individual packets with pcap record headers
 * - Packet count tracking for debugging correlation
 *
 * DEPENDENCIES:
 * - dnsmasq.h: Global daemon structure, type definitions, utility functions
 * - netinet/icmp6.h: ICMPv6 header structures for checksum calculation
 * - Standard I/O and file operations (stat, creat, open, read_write)
 *
 * DATA STRUCTURES:
 * - struct pcap_hdr_s (lines 26-34): Libpcap global file header with magic number and version
 * - struct pcaprec_hdr_s (lines 36-41): Per-packet record header with timestamp and length
 * - packet_count (line 23): Static counter tracking total dumped packets
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DUMPFILE: Master switch enabling entire packet dumping feature (wraps entire file)
 *   When disabled, no packet capture code is compiled, saving binary size for embedded systems
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Functions are re-entrant safe as they operate
 * on the global daemon->dumpfd file descriptor, which is accessed only from the main event
 * loop thread. No locking required due to single-threaded execution model.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 *
 * @see https://wiki.wireshark.org/Development/LibpcapFileFormat
 * @see docs/ARCHITECTURE.md for event-driven model explanation
 */

#include "dnsmasq.h"

#ifdef HAVE_DUMPFILE

#include <netinet/icmp6.h>

/**
 * @var packet_count
 * @brief Global counter tracking total packets written to dump file
 * 
 * Incremented with each successful dump_packet() call. Used for logging
 * packet sequence numbers to correlate dump file contents with syslog output.
 * Persists across dump file reopens by counting existing records during init.
 */
static u32 packet_count;

/**
 * @struct pcap_hdr_s
 * @brief Libpcap global file header written once at file creation
 *
 * Standard pcap file format global header per libpcap specification.
 * Written at the beginning of the dump file to identify the file format,
 * version, and capture parameters for wireshark/tcpdump compatibility.
 *
 * LIFECYCLE:
 * - Created and written by dump_init() when creating new dump file
 * - Read and validated by dump_init() when opening existing dump file
 * - Remains constant for the lifetime of the dump file
 *
 * MEMORY LAYOUT:
 * Total size: 24 bytes (6 x u32 + 2 x u16)
 * All fields in native byte order (0xa1b2c3d4 magic indicates native endian)
 *
 * @see https://wiki.wireshark.org/Development/LibpcapFileFormat
 */
struct pcap_hdr_s {
        u32 magic_number;   /**< Magic number 0xa1b2c3d4 for native byte order */
        u16 version_major;  /**< Major version number, always 2 */
        u16 version_minor;  /**< Minor version number, always 4 */
        u32 thiszone;       /**< GMT to local correction, always 0 (UTC) */
        u32 sigfigs;        /**< Timestamp accuracy, always 0 (microsecond precision) */
        u32 snaplen;        /**< Max packet capture length (EDNS packet size + 200 byte slop) */
        u32 network;        /**< Data link type, 101 = DLT_RAW (raw IP packets, no link layer) */
};

/**
 * @struct pcaprec_hdr_s
 * @brief Libpcap per-packet record header preceding each captured packet
 *
 * Standard pcap packet record header written before each packet's data.
 * Contains timestamp and length information for the following packet data.
 * Enables frame-by-frame parsing by wireshark and tcpdump.
 *
 * LIFECYCLE:
 * - Created and written by dump_packet() for each captured packet
 * - Read by dump_init() when counting existing packets in file
 * - Remains in file permanently as part of pcap record stream
 *
 * MEMORY LAYOUT:
 * Total size: 16 bytes (4 x u32)
 * Immediately followed by packet data of incl_len bytes
 *
 * @see https://wiki.wireshark.org/Development/LibpcapFileFormat
 */
struct pcaprec_hdr_s {
        u32 ts_sec;         /**< Timestamp seconds since epoch (from gettimeofday) */
        u32 ts_usec;        /**< Timestamp microseconds (from gettimeofday) */
        u32 incl_len;       /**< Number of octets of packet saved in file (IP hdr + UDP hdr + payload) */
        u32 orig_len;       /**< Original packet length (same as incl_len, no truncation) */
};

/**
 * @brief Initialize packet dump file with libpcap global header
 *
 * @detailed
 * Opens or creates the packet dump file specified by daemon->dump_file and initializes
 * it with a standard libpcap global header if newly created. For existing files, validates
 * the magic number and counts existing packet records to maintain continuous packet numbering.
 * The file uses DLT_RAW format (raw IP packets without link-layer headers) with snaplen sized
 * to accommodate maximum EDNS packet sizes plus IP/UDP header overhead.
 *
 * @return void (calls die() on fatal errors, never returns on failure)
 *
 * @retval Sets daemon->dumpfd to valid file descriptor on success
 * @retval Calls die() on file creation, access, or validation errors
 *
 * @note File created with S_IRUSR | S_IWUSR permissions (0600, owner read/write only)
 * @note Existing files opened with O_APPEND | O_RDWR for read validation and append writes
 * @note Global packet_count initialized to 0 for new files, or count of existing records
 *
 * @warning Dies with EC_FILE error code if file operations fail
 * @warning Assumes daemon->dump_file and daemon->edns_pktsz are valid before call
 * @warning File descriptor remains open for daemon lifetime; no cleanup on SIGHUP reload
 *
 * @see dump_packet() for packet writing using initialized file descriptor
 * @see struct pcap_hdr_s for global header format details
 * @see struct pcaprec_hdr_s for record counting logic
 *
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization after option parsing
 * if (daemon->dump_file)
 *   dump_init(); // Opens dump file and validates/creates pcap header
 * @endcode
 *
 * RFC COMPLIANCE:
 * N/A - Uses standard libpcap file format, not an IETF protocol
 *
 * SIDE EFFECTS:
 * - Creates new file daemon->dump_file if it doesn't exist
 * - Opens existing file and seeks to end after counting records
 * - Sets daemon->dumpfd to valid file descriptor
 * - Initializes packet_count static variable
 * - Writes 24-byte pcap_hdr_s to new files
 * - Terminates process (via die()) on any file operation error
 *
 * THREAD SAFETY:
 * Re-entrant safe. Called once during daemon initialization in single-threaded context
 * before event loop starts. No concurrent access concerns.
 */
void dump_init(void)
{
  struct stat buf;
  struct pcap_hdr_s header;
  struct pcaprec_hdr_s pcap_header;

  packet_count = 0;
  
  if (stat(daemon->dump_file, &buf) == -1)
    {
      /* doesn't exist, create and add header */
      header.magic_number = 0xa1b2c3d4;
      header.version_major = 2;
      header.version_minor = 4;
      header.thiszone = 0;
      header.sigfigs = 0;
      header.snaplen = daemon->edns_pktsz + 200; /* slop for IP/UDP headers */
      header.network = 101; /* DLT_RAW http://www.tcpdump.org/linktypes.html */

      if (errno != ENOENT ||
	  (daemon->dumpfd = creat(daemon->dump_file, S_IRUSR | S_IWUSR)) == -1 ||
	  !read_write(daemon->dumpfd, (void *)&header, sizeof(header), 0))
	die(_("cannot create %s: %s"), daemon->dump_file, EC_FILE);
    }
  else if ((daemon->dumpfd = open(daemon->dump_file, O_APPEND | O_RDWR)) == -1 ||
	   !read_write(daemon->dumpfd, (void *)&header, sizeof(header), 1))
    die(_("cannot access %s: %s"), daemon->dump_file, EC_FILE);
  else if (header.magic_number != 0xa1b2c3d4)
    die(_("bad header in %s"), daemon->dump_file, EC_FILE);
  else
    {
      /* count existing records */
      while (read_write(daemon->dumpfd, (void *)&pcap_header, sizeof(pcap_header), 1))
	{
	  lseek(daemon->dumpfd, pcap_header.incl_len, SEEK_CUR);
	  packet_count++;
	}
    }
}

/**
 * @brief Write packet to dump file in libpcap format with reconstructed IP/UDP headers
 *
 * @detailed
 * Constructs a complete libpcap packet record including pcap record header, IP header
 * (IPv4 or IPv6), UDP or ICMP/ICMPv6 header, and payload. Calculates proper checksums
 * for IP and UDP/ICMP headers to produce valid packets that wireshark can parse correctly.
 * The mask parameter allows selective dumping based on packet type (DNS query, DNS reply,
 * DHCP, etc.). Timestamps each packet with microsecond precision for timing analysis.
 *
 * @param mask Packet type bitmask for selective dumping (DUMP_QUERY, DUMP_REPLY, etc.)
 * @param packet Pointer to packet payload data (DNS message, DHCP packet, ICMP data)
 * @param len Length of packet payload in bytes (not including IP/UDP headers)
 * @param src Source address (union mysockaddr with sa_family, IPv4 in, or IPv6 in6), NULL for generated packets
 * @param dst Destination address (union mysockaddr), NULL for replies with only source known
 * @param port UDP port number for src/dst, or -1 for ICMP/ICMPv6 packets
 *
 * @return void (logs errors to syslog, does not terminate on write failure)
 *
 * @retval Logs success to syslog with packet count and mask on successful write
 * @retval Logs error to syslog on write failure, continues execution
 *
 * @note Writes 16-byte pcaprec_hdr_s + IP header (20 or 40 bytes) + UDP header (8 bytes) + payload
 * @note Port value -1 indicates ICMP (IPv4) or ICMPv6 (IPv6) packet instead of UDP
 * @note Address family determined from src if non-NULL, otherwise from dst
 * @note Both IPv4 and IPv6 pseudoheader checksums calculated identically per RFC for UDP length <65536
 *
 * @warning Returns immediately if daemon->dumpfd == -1 or mask not in daemon->dump_mask
 * @warning Modifies packet buffer byte at packet[len] for odd-length checksum calculation
 * @warning Does not validate packet pointer; caller must ensure valid memory region
 * @warning File I/O errors logged but do not stop daemon operation
 *
 * @see dump_init() for file descriptor initialization
 * @see struct pcaprec_hdr_s for packet record header format
 * @see https://wiki.wireshark.org/Development/LibpcapFileFormat
 *
 * EXAMPLE USAGE:
 * @code
 * // Dump DNS query packet with source and destination addresses
 * if (daemon->dumpfd >= 0)
 *   dump_packet(DUMP_QUERY, dns_packet, dns_len, &source_addr, &dest_addr, 53);
 * 
 * // Dump ICMPv6 packet (port -1 indicates ICMP)
 * dump_packet(DUMP_REPLY, icmp6_data, icmp6_len, &src_addr, &dst_addr, -1);
 * @endcode
 *
 * RFC COMPLIANCE:
 * - IPv4 header checksum per RFC 791 Section 3.1
 * - IPv6 header format per RFC 2460 Section 3
 * - UDP checksum per RFC 768 with IPv4/IPv6 pseudoheaders
 * - ICMPv6 checksum per RFC 4443 Section 2.3
 * - ICMP checksum per RFC 792
 *
 * SIDE EFFECTS:
 * - Writes pcap record header (16 bytes) + IP header + optional UDP header + packet to daemon->dumpfd
 * - Increments packet_count static variable on success
 * - Logs packet dump to syslog (LOG_INFO on success, LOG_ERR on failure)
 * - Calls gettimeofday() for packet timestamp
 * - May modify packet[len] byte if length is odd (for checksum calculation)
 * - File position advances by total record size on successful write
 *
 * THREAD SAFETY:
 * Re-entrant safe if daemon->dumpfd is separate per thread (not applicable - single-threaded).
 * Safe for single-process event-driven model as all calls from main event loop with no concurrency.
 */
void dump_packet(int mask, void *packet, size_t len,
		 union mysockaddr *src, union mysockaddr *dst, int port)
{
  struct ip ip;
  struct ip6_hdr ip6;
  int family;
  struct udphdr {
    u16 uh_sport;               /* source port */
    u16 uh_dport;               /* destination port */
    u16 uh_ulen;                /* udp length */
    u16 uh_sum;                 /* udp checksum */
  } udp;
  struct pcaprec_hdr_s pcap_header;
  struct timeval time;
  u32 i, sum;
  void *iphdr;
  size_t ipsz;
  int rc;
  
  if (daemon->dumpfd == -1 || !(mask & daemon->dump_mask))
    return;
  
  /* So wireshark can Id the packet. */
  udp.uh_sport = udp.uh_dport = htons(port);

  if (src)
    family = src->sa.sa_family;
  else
    family = dst->sa.sa_family;

  if (family == AF_INET6)
    {
      iphdr = &ip6;
      ipsz = sizeof(ip6);
      memset(&ip6, 0, sizeof(ip6));
      
      ip6.ip6_vfc = 6 << 4;
      ip6.ip6_hops = 64;

      if (port == -1)
	{
	  ip6.ip6_plen = htons(len);
	  ip6.ip6_nxt = IPPROTO_ICMPV6;
	}
      else
	{
	  ip6.ip6_plen = htons(sizeof(struct udphdr) + len);
	  ip6.ip6_nxt = IPPROTO_UDP;
	}
      
      if (src)
	{
	  memcpy(&ip6.ip6_src, &src->in6.sin6_addr, IN6ADDRSZ);
	  udp.uh_sport = src->in6.sin6_port;
	}
      
      if (dst)
	{
	  memcpy(&ip6.ip6_dst, &dst->in6.sin6_addr, IN6ADDRSZ);
	  udp.uh_dport = dst->in6.sin6_port;
	}
            
      /* start UDP checksum */
      for (sum = 0, i = 0; i < IN6ADDRSZ; i+=2)
	{
	  sum += ntohs((ip6.ip6_src.s6_addr[i] << 8) + (ip6.ip6_src.s6_addr[i+1])) ;
	  sum += ntohs((ip6.ip6_dst.s6_addr[i] << 8) + (ip6.ip6_dst.s6_addr[i+1])) ; 
	}
    }
  else
    {
      iphdr = &ip;
      ipsz = sizeof(ip);
      memset(&ip, 0, sizeof(ip));
      
      ip.ip_v = IPVERSION;
      ip.ip_hl = sizeof(struct ip) / 4;
      ip.ip_ttl = IPDEFTTL;

      if (port == -1)
	{
	  ip.ip_len = htons(sizeof(struct ip) + len);
	  ip.ip_p = IPPROTO_ICMP;
	}
      else
	{
	  ip.ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + len); 
	  ip.ip_p = IPPROTO_UDP;
	}
      
      if (src)
	{
	  ip.ip_src = src->in.sin_addr;
	  udp.uh_sport = src->in.sin_port;
	}

      if (dst)
	{
	  ip.ip_dst = dst->in.sin_addr;
	  udp.uh_dport = dst->in.sin_port;
	}
      
      ip.ip_sum = 0;
      for (sum = 0, i = 0; i < sizeof(struct ip) / 2; i++)
	sum += ((u16 *)&ip)[i];
      while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);  
      ip.ip_sum = (sum == 0xffff) ? sum : ~sum;
      
      /* start UDP checksum */
      sum = ip.ip_src.s_addr & 0xffff;
      sum += (ip.ip_src.s_addr >> 16) & 0xffff;
      sum += ip.ip_dst.s_addr & 0xffff;
      sum += (ip.ip_dst.s_addr >> 16) & 0xffff;
    }
  
  if (len & 1)
    ((unsigned char *)packet)[len] = 0; /* for checksum, in case length is odd. */

  if (port == -1)
    {
      /* ICMP - ICMPv6 packet is a superset of ICMP */
      struct icmp6_hdr *icmp = packet;
      
      /* See comment in UDP code below. */
      sum += htons((family == AF_INET6) ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
      sum += htons(len);
      
      icmp->icmp6_cksum = 0;
      for (i = 0; i < (len + 1) / 2; i++)
	sum += ((u16 *)packet)[i];
      while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);
      icmp->icmp6_cksum = (sum == 0xffff) ? sum : ~sum;

      pcap_header.incl_len = pcap_header.orig_len = ipsz + len;
    }
  else
    {
      /* Add Remaining part of the pseudoheader. Note that though the
	 IPv6 pseudoheader is very different to the IPv4 one, the 
	 net result of this calculation is correct as long as the 
	 packet length is less than 65536, which is fine for us. */
      sum += htons(IPPROTO_UDP);
      sum += htons(sizeof(struct udphdr) + len);
      
      udp.uh_sum = 0;
      udp.uh_ulen = htons(sizeof(struct udphdr) + len);
      
      for (i = 0; i < sizeof(struct udphdr)/2; i++)
	sum += ((u16 *)&udp)[i];
      for (i = 0; i < (len + 1) / 2; i++)
	sum += ((u16 *)packet)[i];
      while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);
      udp.uh_sum = (sum == 0xffff) ? sum : ~sum;

      pcap_header.incl_len = pcap_header.orig_len = ipsz + sizeof(udp) + len;
    }
  
  rc = gettimeofday(&time, NULL);
  pcap_header.ts_sec = time.tv_sec;
  pcap_header.ts_usec = time.tv_usec;
  
  if (rc == -1 ||
      !read_write(daemon->dumpfd, (void *)&pcap_header, sizeof(pcap_header), 0) ||
      !read_write(daemon->dumpfd, iphdr, ipsz, 0) ||
      (port != -1 && !read_write(daemon->dumpfd, (void *)&udp, sizeof(udp), 0)) ||
      !read_write(daemon->dumpfd, (void *)packet, len, 0))
    my_syslog(LOG_ERR, _("failed to write packet dump"));
  else
    my_syslog(LOG_INFO, _("dumping packet %u mask 0x%04x"), ++packet_count, mask);

}

#endif
