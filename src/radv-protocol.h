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
 * @file radv-protocol.h
 * @brief IPv6 Router Advertisement protocol structures per RFC 4861
 *
 * DETAILED PURPOSE:
 * This header file defines the ICMPv6 protocol structures and constants used for
 * IPv6 Router Advertisement (RA) and Neighbor Discovery Protocol (NDP) functionality
 * in dnsmasq. It provides wire-format packet structures that match the binary layout
 * specified in RFC 4861 for router advertisements, neighbor solicitation/advertisement,
 * and associated ICMPv6 options. These structures enable dnsmasq to construct and parse
 * RA messages for IPv6 prefix delegation, stateless address autoconfiguration (SLAAC)
 * support per RFC 4862, and router lifetime announcements on local network segments.
 *
 * The structures defined here are used directly for packet construction and parsing
 * with minimal copying, requiring careful attention to network byte order (big-endian)
 * and structure padding. All multi-byte fields must be converted using htons/htonl
 * before transmission and ntohs/ntohl upon reception.
 *
 * KEY RESPONSIBILITIES:
 * - Define ICMPv6 Router Advertisement packet format (struct ra_packet)
 * - Define ICMPv6 Neighbor Discovery packet formats (struct neigh_packet, struct ping_packet)
 * - Define RA option structures including prefix information (struct prefix_opt)
 * - Declare IPv6 multicast addresses for all-nodes and all-routers groups
 * - Define ICMPv6 option type constants for RA message options
 * - Provide wire-format structures matching RFC 4861 binary specifications
 *
 * DEPENDENCIES:
 * - <netinet/in.h>: struct in6_addr for IPv6 addresses (included via dnsmasq.h)
 * - <stdint.h>: Fixed-width integer types u8, u16, u32 (via dnsmasq.h)
 * - Used by: radv.c (Router Advertisement transmission)
 * - Used by: dhcp6.c (DHCPv6 integration with RA)
 * - Used by: rfc3315.c (DHCPv6 managed/other config flags coordination)
 *
 * DATA STRUCTURES:
 * - struct ping_packet (lines 20-25): ICMPv6 Echo Request/Reply packet format
 * - struct ra_packet (lines 27-34): ICMPv6 Router Advertisement message format
 * - struct neigh_packet (lines 36-41): Neighbor Solicitation/Advertisement format
 * - struct prefix_opt (lines 43-47): Prefix Information option for SLAAC
 *
 * COMPILE-TIME OPTIONS:
 * - This header is only compiled when HAVE_DHCP6 is defined
 * - HAVE_DHCP6 implies DHCPv6 and Router Advertisement support
 * - Used in conjunction with IPv6-enabled network stack
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Structures accessed only during
 * packet construction in event handlers. No concurrent access protection needed.
 *
 * RFC COMPLIANCE:
 * - RFC 4861 Section 4.1: ICMPv6 Router Advertisement Message Format
 * - RFC 4861 Section 4.2: Router Advertisement packet structure and fields
 * - RFC 4861 Section 4.6: Prefix Information Option format
 * - RFC 4862: IPv6 Stateless Address Autoconfiguration (SLAAC)
 * - RFC 2464: Transmission of IPv6 Packets over Ethernet Networks (multicast addresses)
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

/**
 * @def ALL_NODES
 * @brief IPv6 multicast address for all-nodes group on local network segment
 *
 * "FF02::1" is the link-local scope all-nodes multicast address per RFC 4291
 * Section 2.7.1. Router Advertisement messages are sent to this address to
 * reach all IPv6-capable nodes on the local link. Equivalent to IPv4 broadcast
 * for router announcements. Used by radv.c when transmitting periodic RA messages
 * and RA responses to Router Solicitation requests.
 *
 * Scope: Link-local (FF02::/16)
 * Membership: All IPv6 nodes automatically join this group
 */
#define ALL_NODES                 "FF02::1"

/**
 * @def ALL_ROUTERS
 * @brief IPv6 multicast address for all-routers group on local network segment
 *
 * "FF02::2" is the link-local scope all-routers multicast address per RFC 4291
 * Section 2.7.1. Hosts send Router Solicitation messages to this address to
 * request immediate Router Advertisement from local routers rather than waiting
 * for periodic announcements. Only nodes configured as IPv6 routers join this
 * multicast group.
 *
 * Scope: Link-local (FF02::/16)
 * Membership: IPv6 routers only
 */
#define ALL_ROUTERS               "FF02::2"

/**
 * @struct ping_packet
 * @brief ICMPv6 Echo Request/Reply packet structure per RFC 4443
 *
 * Wire-format structure for ICMPv6 Echo Request (type 128) and Echo Reply (type 129)
 * messages. Used in dnsmasq for ICMPv6 ping operations during DHCPv6 duplicate address
 * detection (ping-before-offer equivalent for IPv6). Structure matches RFC 4443 Section
 * 4.1 exactly with no padding.
 *
 * LIFECYCLE: Temporary structure allocated on stack for ping packet construction
 * MEMORY LAYOUT: 8 bytes total, naturally aligned, network byte order for multi-byte fields
 * USAGE PATTERN: Constructed in dhcp6.c for address conflict detection before lease assignment
 *
 * RFC COMPLIANCE: RFC 4443 Section 4.1 - Echo Request/Reply Message Format
 */
struct ping_packet {
  u8 type;          /**< ICMPv6 message type: 128 (Echo Request) or 129 (Echo Reply) */
  u8 code;          /**< ICMPv6 code: 0 for Echo Request/Reply per RFC 4443 */
  u16 checksum;     /**< ICMPv6 checksum covering entire packet plus IPv6 pseudo-header */
  u16 identifier;   /**< Echo identifier for matching request/reply pairs, host byte order */
  u16 sequence_no;  /**< Echo sequence number for packet ordering, host byte order */
};

/**
 * @struct ra_packet
 * @brief ICMPv6 Router Advertisement message structure per RFC 4861 Section 4.2
 *
 * Wire-format structure for ICMPv6 Router Advertisement messages (type 134). This is the
 * primary structure for IPv6 router announcements containing router lifetime, reachability
 * parameters, and flags indicating DHCPv6 managed/other configuration availability. RA
 * messages are sent periodically (default every 600 seconds) and in response to Router
 * Solicitation requests to advertise the router's presence and configuration parameters.
 *
 * The RA packet is followed by zero or more ICMPv6 options including source link-layer
 * address, MTU, prefix information (struct prefix_opt), and recursive DNS server (RDNSS)
 * options. The flags field contains critical M-bit (managed address configuration via
 * DHCPv6) and O-bit (other configuration via DHCPv6) that control client behavior.
 *
 * LIFECYCLE: 
 * - Allocated on stack in radv.c send_ra() function
 * - Initialized with router parameters from daemon configuration
 * - Transmitted to ALL_NODES (FF02::1) multicast address
 * - Destroyed when send_ra() returns
 *
 * MEMORY LAYOUT: 
 * - 16 bytes total structure size
 * - Network byte order (big-endian) for all multi-byte fields
 * - No padding required (naturally aligned)
 * - Followed immediately by variable-length ICMPv6 options in packet buffer
 *
 * USAGE PATTERN:
 * - Constructed in radv.c for periodic advertisements (every MinRtrAdvInterval to MaxRtrAdvInterval)
 * - Sent in response to Router Solicitation from hosts
 * - Coordinates with DHCPv6 via M-bit and O-bit flags
 * - Enables SLAAC when prefix options included with A-flag set
 *
 * RFC COMPLIANCE:
 * - RFC 4861 Section 4.2: Router Advertisement Message Format
 * - RFC 4861 Section 6.2.3: Router Advertisement transmission rules
 * - RFC 4862: Integration with Stateless Address Autoconfiguration
 */
struct ra_packet {
  u8 type;            /**< ICMPv6 message type: 134 (Router Advertisement) per RFC 4861 */
  u8 code;            /**< ICMPv6 code: 0 for Router Advertisement per RFC 4861 */
  u16 checksum;       /**< ICMPv6 checksum covering packet plus IPv6 pseudo-header, network byte order */
  u8 hop_limit;       /**< Current Hop Limit: suggested value for outgoing IPv6 packets, 0 = unspecified */
  u8 flags;           /**< RA flags: M-bit (0x80) managed address config, O-bit (0x40) other config, 
                           reserved bits 0x3F. M-bit=1 indicates DHCPv6 for addresses, O-bit=1 
                           indicates DHCPv6 for other configuration (DNS, NTP, etc.) */
  u16 lifetime;       /**< Router lifetime in seconds (0-9000), 0 = not a default router, network byte order.
                           Indicates how long this router should be used as default gateway */
  u32 reachable_time; /**< Reachable time in milliseconds for Neighbor Unreachability Detection, 
                           0 = unspecified, network byte order. Time a neighbor is considered 
                           reachable after receiving reachability confirmation */
  u32 retrans_time;   /**< Retransmission timer in milliseconds for Neighbor Solicitation messages,
                           0 = unspecified, network byte order. Time between retransmitted NS messages */
};

/**
 * @struct neigh_packet
 * @brief ICMPv6 Neighbor Solicitation/Advertisement packet structure per RFC 4861 Section 4.3-4.4
 *
 * Wire-format structure for ICMPv6 Neighbor Solicitation (type 135) and Neighbor Advertisement
 * (type 136) messages used in IPv6 Neighbor Discovery Protocol. Neighbor Solicitation is the
 * IPv6 equivalent of IPv4 ARP requests, while Neighbor Advertisement is the equivalent of ARP
 * replies. Used for address resolution (IPv6 address to link-layer address mapping) and
 * duplicate address detection (DAD).
 *
 * In dnsmasq context, primarily used for DHCPv6 duplicate address detection before assigning
 * IPv6 addresses to clients, similar to ping-before-offer in DHCPv4.
 *
 * LIFECYCLE: Allocated on stack during DAD checks or address resolution
 * MEMORY LAYOUT: 24 bytes (8 byte header + 16 byte IPv6 address), network byte order for checksum
 * USAGE PATTERN: Constructed for duplicate address detection in dhcp6.c before lease assignment
 *
 * RFC COMPLIANCE:
 * - RFC 4861 Section 4.3: Neighbor Solicitation Message Format
 * - RFC 4861 Section 4.4: Neighbor Advertisement Message Format
 */
struct neigh_packet {
  u8 type;              /**< ICMPv6 message type: 135 (Neighbor Solicitation) or 136 (Neighbor Advertisement) */
  u8 code;              /**< ICMPv6 code: 0 for both NS and NA messages per RFC 4861 */
  u16 checksum;         /**< ICMPv6 checksum covering packet plus IPv6 pseudo-header, network byte order */
  u16 reserved;         /**< Reserved field for Neighbor Solicitation (must be 0), or flags for 
                             Neighbor Advertisement (R-bit router, S-bit solicited, O-bit override) */
  struct in6_addr target; /**< Target IPv6 address: address being queried (NS) or announced (NA),
                               network byte order (16 bytes) */
};

/**
 * @struct prefix_opt
 * @brief ICMPv6 Prefix Information Option for Router Advertisement per RFC 4861 Section 4.6
 *
 * Wire-format structure for the Prefix Information option included in Router Advertisement
 * messages. This option advertises IPv6 prefixes that can be used for on-link determination
 * and/or stateless address autoconfiguration (SLAAC) per RFC 4862. Multiple prefix options
 * can be included in a single RA message to advertise different prefixes with different
 * lifetimes and configuration parameters.
 *
 * The A-flag (autonomous address configuration) in the flags field indicates whether this
 * prefix can be used for SLAAC. When A-flag=1, hosts automatically configure addresses by
 * combining the prefix with their interface identifier (EUI-64 or privacy extension). The
 * L-flag (on-link) indicates whether addresses matching this prefix are on the local link.
 *
 * Valid lifetime controls how long addresses configured from this prefix remain valid for
 * new connections, while preferred lifetime controls how long they remain preferred for
 * new connections. When preferred lifetime expires, addresses become deprecated but still
 * valid for existing connections.
 *
 * LIFECYCLE:
 * - Allocated as part of RA packet buffer in radv.c
 * - Initialized with prefix from dhcp_context configuration
 * - Valid/preferred lifetimes set from context or defaults
 * - Transmitted immediately following struct ra_packet in packet buffer
 *
 * MEMORY LAYOUT:
 * - 32 bytes total structure size
 * - Type field = ICMP6_OPT_PREFIX (3)
 * - Length field = 4 (in units of 8 bytes, so 32 bytes total)
 * - Network byte order for all multi-byte fields
 * - No padding required
 *
 * USAGE PATTERN:
 * - One prefix_opt per advertised IPv6 prefix
 * - A-flag set for SLAAC-enabled prefixes
 * - L-flag set for on-link prefixes
 * - Valid lifetime typically 2592000 seconds (30 days)
 * - Preferred lifetime typically 604800 seconds (7 days)
 * - Used by radv.c in send_ra() to construct RA messages
 *
 * RFC COMPLIANCE:
 * - RFC 4861 Section 4.6.2: Prefix Information Option format
 * - RFC 4862 Section 5.5.3: Processing of prefix information for SLAAC
 */
struct prefix_opt {
  u8 type;                /**< ICMPv6 option type: ICMP6_OPT_PREFIX (3) for Prefix Information */
  u8 len;                 /**< Option length in units of 8 bytes: 4 for this option (32 bytes total) */
  u8 prefix_len;          /**< Prefix length in bits (0-128), typically 64 for standard /64 prefixes */
  u8 flags;               /**< Prefix flags: L-bit (0x80) on-link flag, A-bit (0x40) autonomous address
                               config flag, reserved bits 0x3F. L-bit=1 means prefix is on-link for
                               link determination. A-bit=1 enables SLAAC for this prefix per RFC 4862 */
  u32 valid_lifetime;     /**< Valid lifetime in seconds (network byte order): time this prefix remains
                               valid for address configuration. 0xFFFFFFFF = infinity. Addresses remain
                               valid (usable for communication) until this expires */
  u32 preferred_lifetime; /**< Preferred lifetime in seconds (network byte order): time this prefix
                               remains preferred for new connections. Must be <= valid_lifetime.
                               After expiry, addresses become deprecated but still valid */
  u32 reserved;           /**< Reserved field: must be set to 0 on transmission, ignored on reception */
  struct in6_addr prefix; /**< IPv6 prefix being advertised, network byte order (16 bytes). Only the
                               first prefix_len bits are significant, remaining bits should be 0 */
};

/**
 * @def ICMP6_OPT_SOURCE_MAC
 * @brief ICMPv6 option type for Source Link-Layer Address per RFC 4861 Section 4.6.1
 *
 * Option type value (1) for including the link-layer (MAC) address of the source interface
 * in ICMPv6 Neighbor Discovery messages. Used in Router Solicitation, Router Advertisement,
 * and Neighbor Solicitation messages to provide the sender's link-layer address for
 * efficient address resolution without additional Neighbor Solicitation exchanges.
 *
 * In Router Advertisements, this option provides the router's MAC address so clients can
 * populate their neighbor cache immediately without performing address resolution.
 */
#define ICMP6_OPT_SOURCE_MAC   1

/**
 * @def ICMP6_OPT_PREFIX
 * @brief ICMPv6 option type for Prefix Information per RFC 4861 Section 4.6.2
 *
 * Option type value (3) for advertising IPv6 address prefixes in Router Advertisement
 * messages. Uses struct prefix_opt format. This is the primary mechanism for distributing
 * prefix information to hosts for on-link determination and stateless address
 * autoconfiguration (SLAAC). Multiple prefix options can be included in a single RA to
 * advertise different prefixes (e.g., multiple subnets, ULA + GUA).
 *
 * Essential for SLAAC operation per RFC 4862. Clients use advertised prefixes with A-flag
 * set to automatically generate IPv6 addresses without DHCPv6 server interaction.
 */
#define ICMP6_OPT_PREFIX       3

/**
 * @def ICMP6_OPT_MTU
 * @brief ICMPv6 option type for MTU per RFC 4861 Section 4.6.4
 *
 * Option type value (5) for advertising the Maximum Transmission Unit for the link in
 * Router Advertisement messages. Format: type(1) + len(1) + reserved(2) + MTU(4 bytes).
 * Allows routers to inform hosts of the link MTU to avoid fragmentation and enable
 * efficient packet sizing for the local network segment.
 *
 * Common MTU values: 1500 (Ethernet), 1280 (IPv6 minimum), 9000 (jumbo frames).
 * Hosts use advertised MTU to set link MTU, overriding default assumptions.
 */
#define ICMP6_OPT_MTU          5

/**
 * @def ICMP6_OPT_ADV_INTERVAL
 * @brief ICMPv6 option type for Advertisement Interval per RFC 6275 Section 7.3
 *
 * Option type value (7) for advertising the router's maximum time between unsolicited
 * multicast Router Advertisements. Format: type(1) + len(1) + reserved(2) + interval(4 bytes).
 * Allows mobile IPv6 home agents to indicate their RA transmission interval so mobile nodes
 * can predict when the next RA will be sent and optimize power consumption.
 *
 * Used in Mobile IPv6 contexts. Standard routers typically omit this option and use default
 * intervals (MinRtrAdvInterval 200s to MaxRtrAdvInterval 600s per RFC 4861).
 */
#define ICMP6_OPT_ADV_INTERVAL 7

/**
 * @def ICMP6_OPT_RT_INFO
 * @brief ICMPv6 option type for Route Information per RFC 4191 Section 2.3
 *
 * Option type value (24) for advertising specific routes in Router Advertisement messages.
 * Extends basic RA functionality to include more-specific routing information beyond default
 * gateway announcements. Format includes prefix, prefix length, route lifetime, and route
 * preference (high/medium/low). Enables routers to advertise routes to off-link destinations
 * without requiring a routing protocol.
 *
 * Used in multi-homing scenarios where hosts need to select among multiple routers for
 * specific destination prefixes. Not commonly used in simple network configurations.
 */
#define ICMP6_OPT_RT_INFO     24

/**
 * @def ICMP6_OPT_RDNSS
 * @brief ICMPv6 option type for Recursive DNS Server per RFC 8106 Section 5.1
 *
 * Option type value (25) for advertising DNS recursive resolver IPv6 addresses in Router
 * Advertisement messages. Format: type(1) + len(variable) + reserved(2) + lifetime(4) +
 * one or more IPv6 addresses (16 bytes each). Enables stateless DNS configuration without
 * DHCPv6, allowing hosts to discover DNS servers through RA messages alone.
 *
 * Critical for DNS resolution in SLAAC-only networks (no DHCPv6). Dnsmasq includes this
 * option in RA messages when configured with dns-server addresses, providing integrated
 * DNS and RA services. Lifetime indicates how long the DNS server addresses remain valid.
 */
#define ICMP6_OPT_RDNSS       25

/**
 * @def ICMP6_OPT_DNSSL
 * @brief ICMPv6 option type for DNS Search List per RFC 8106 Section 5.2
 *
 * Option type value (31) for advertising DNS search domain suffixes in Router Advertisement
 * messages. Format: type(1) + len(variable) + reserved(2) + lifetime(4) + one or more
 * domain names in DNS wire format. Enables stateless DNS search list configuration without
 * DHCPv6, allowing hosts to automatically append domain suffixes for unqualified hostname
 * lookups.
 *
 * Complements ICMP6_OPT_RDNSS (25) for complete stateless DNS configuration. Hosts use
 * advertised search domains to resolve short names (e.g., "server" -> "server.example.com").
 * Dnsmasq includes this option when configured with domain search lists for IPv6 clients.
 */
#define ICMP6_OPT_DNSSL       31
