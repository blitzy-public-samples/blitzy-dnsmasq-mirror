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
 * @file dhcp6-protocol.h
 * @brief DHCPv6 protocol structures and constants per RFC 3315
 *
 * DETAILED PURPOSE:
 * This header file defines the complete set of DHCPv6 protocol constants,
 * message types, option codes, and status codes as specified in RFC 3315
 * (DHCPv6), RFC 3633 (Prefix Delegation), and RFC 4361 (Node-specific Identifiers).
 * Unlike DHCPv4 which uses a fixed-format packet structure, DHCPv6 employs a
 * Type-Length-Value (TLV) encoding for all options, providing greater extensibility.
 * This file provides the canonical definitions used throughout the DHCPv6 
 * implementation in dhcp6.c, rfc3315.c, and radv.c.
 *
 * KEY PROTOCOL DIFFERENCES FROM DHCPv4:
 * - TLV-based option encoding (not fixed position fields)
 * - DUID (DHCP Unique Identifier) instead of MAC address for client identification
 * - Identity Association (IA) concept for grouping addresses/prefixes
 * - Separate message types for stateless (INFORMATION-REQUEST) vs stateful configuration
 * - Built-in relay agent support with RELAY-FORW/RELAY-REPL messages
 * - Status codes embedded in replies for granular error reporting
 * - Prefix delegation support for routing scenarios (RFC 3633)
 *
 * MESSAGE FORMAT:
 * All DHCPv6 messages begin with a 1-byte message type followed by a 3-byte
 * transaction ID, then zero or more TLV-encoded options. Relay messages have
 * a different structure with hop count and link/peer addresses.
 *
 * RFC COMPLIANCE:
 * - RFC 3315: DHCPv6 base protocol (message types, options, DUID types)
 * - RFC 3633: IPv6 Prefix Delegation (IA_PD, IAPREFIX options)
 * - RFC 4361: Node-specific Identifiers for DHCPv4 and DHCPv6
 * - RFC 3646: DNS Configuration Options (DNS_SERVER, DOMAIN_SEARCH)
 * - RFC 5908: NTP Server Option (NTP_SERVER with suboptions)
 * - RFC 6939: Client Link-Layer Address Option (CLIENT_MAC)
 *
 * USAGE:
 * These constants are used by:
 * - rfc3315.c: DHCPv6 message parsing and construction
 * - dhcp6.c: DHCPv6 server core logic and option handling
 * - radv.c: Router Advertisement integration with DHCPv6 flags
 * - outpacket.c: DHCPv6 option assembly and encoding
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

/**
 * @def DHCPV6_SERVER_PORT
 * @brief DHCPv6 server listening port (UDP 547)
 *
 * Standard UDP port for DHCPv6 servers and relay agents per RFC 3315 Section 5.2.
 * Servers bind to this port to receive client messages (SOLICIT, REQUEST, etc.)
 * and relay agent forwarded messages. Must be privileged port requiring elevated
 * permissions or capability CAP_NET_BIND_SERVICE on Linux.
 */
#define DHCPV6_SERVER_PORT 547

/**
 * @def DHCPV6_CLIENT_PORT
 * @brief DHCPv6 client listening port (UDP 546)
 *
 * Standard UDP port for DHCPv6 clients per RFC 3315 Section 5.2. Clients
 * bind to this port to receive server responses (ADVERTISE, REPLY, RECONFIGURE).
 * Relay agents also use this port when forwarding messages toward clients.
 * Does not require elevated privileges as it is an unprivileged port (>1024).
 */
#define DHCPV6_CLIENT_PORT 546

/**
 * @def ALL_SERVERS
 * @brief IPv6 multicast address for all DHCPv6 servers (site-local scope)
 *
 * Multicast address FF05::1:3 with site-local scope (FF05) per RFC 3315 Section 5.1.
 * Used by relay agents to forward client messages to all DHCPv6 servers within
 * the administrative site. Site-local scope is broader than link-local, allowing
 * DHCPv6 servers to be located on different network segments.
 */
#define ALL_SERVERS                  "FF05::1:3"

/**
 * @def ALL_RELAY_AGENTS_AND_SERVERS
 * @brief IPv6 multicast address for all DHCPv6 relay agents and servers (link-local)
 *
 * Multicast address FF02::1:2 with link-local scope (FF02) per RFC 3315 Section 5.1.
 * Used by DHCPv6 clients to discover servers and relay agents on the local link.
 * Clients send SOLICIT, CONFIRM, REBIND, and INFORMATION-REQUEST messages to
 * this address when they don't have a specific server address. Link-local scope
 * restricts delivery to the directly attached network segment.
 */
#define ALL_RELAY_AGENTS_AND_SERVERS "FF02::1:2"

/**
 * @def DHCP6SOLICIT
 * @brief DHCPv6 SOLICIT message type (1)
 *
 * Client-to-server message to locate available DHCPv6 servers per RFC 3315 Section 17.1.1.
 * First message in the 4-message exchange for stateful address assignment
 * (SOLICIT → ADVERTISE → REQUEST → REPLY). Sent to ALL_RELAY_AGENTS_AND_SERVERS
 * multicast address. Contains client DUID, IA_NA or IA_TA for addresses, and
 * may include IA_PD for prefix delegation. Servers respond with ADVERTISE.
 */
#define DHCP6SOLICIT      1

/**
 * @def DHCP6ADVERTISE
 * @brief DHCPv6 ADVERTISE message type (2)
 *
 * Server-to-client message offering configuration parameters per RFC 3315 Section 17.1.2.
 * Second message in 4-message exchange, responding to client SOLICIT. Contains
 * server DUID, available addresses in IA_NA/IA_TA, prefixes in IA_PD, and server
 * preference value. Client may receive multiple ADVERTISE messages from different
 * servers and selects one based on preference and offered parameters. Not sent
 * if client includes Rapid Commit option (2-message exchange).
 */
#define DHCP6ADVERTISE    2

/**
 * @def DHCP6REQUEST
 * @brief DHCPv6 REQUEST message type (3)
 *
 * Client-to-server message requesting confirmation of offered parameters per
 * RFC 3315 Section 18.1.1. Third message in 4-message exchange, sent after
 * client selects a server from ADVERTISE messages. Sent to unicast server
 * address (if server provided UNICAST option) or multicast. Contains client
 * and server DUIDs, and the specific IA_NA/IA_TA/IA_PD selections. Server
 * responds with REPLY containing committed configuration or error status.
 */
#define DHCP6REQUEST      3

/**
 * @def DHCP6CONFIRM
 * @brief DHCPv6 CONFIRM message type (4)
 *
 * Client-to-server message to verify address assignment is still valid per
 * RFC 3315 Section 18.1.2. Used when client with existing address moves to
 * a new link or reboots. Sent to ALL_RELAY_AGENTS_AND_SERVERS multicast.
 * Does not request new addresses, only confirms existing addresses in IA_NA
 * are appropriate for the current link. Server responds with REPLY containing
 * success status or NotOnLink status code if addresses are invalid for link.
 */
#define DHCP6CONFIRM      4

/**
 * @def DHCP6RENEW
 * @brief DHCPv6 RENEW message type (5)
 *
 * Client-to-server message to extend address lifetimes per RFC 3315 Section 18.1.3.
 * Sent to the specific server that assigned the addresses (unicast) at T1 timer
 * expiration (typically 50% of preferred lifetime). Contains client and server
 * DUIDs and all IAs (IA_NA/IA_TA/IA_PD) for renewal. Server responds with REPLY
 * containing extended lifetimes or error status. If RENEW fails, client attempts
 * REBIND at T2 timer.
 */
#define DHCP6RENEW        5

/**
 * @def DHCP6REBIND
 * @brief DHCPv6 REBIND message type (6)
 *
 * Client-to-server message to extend address lifetimes from any server per
 * RFC 3315 Section 18.1.4. Sent to ALL_RELAY_AGENTS_AND_SERVERS multicast at
 * T2 timer expiration (typically 80% of preferred lifetime) if RENEW failed or
 * original server is unreachable. Any server can respond with REPLY containing
 * extended lifetimes. Last attempt before addresses expire and client must
 * restart with SOLICIT.
 */
#define DHCP6REBIND       6

/**
 * @def DHCP6REPLY
 * @brief DHCPv6 REPLY message type (7)
 *
 * Server-to-client message providing configuration and status per RFC 3315 Section 18.2.
 * Final message in both 4-message and 2-message exchanges. Responds to REQUEST,
 * CONFIRM, RENEW, REBIND, RELEASE, DECLINE, and INFORMATION-REQUEST. Contains
 * committed addresses in IA_NA/IA_TA with lifetimes, prefixes in IA_PD, DNS
 * servers, domain search list, and status codes. If Rapid Commit option present,
 * REPLY sent directly in response to SOLICIT (2-message exchange).
 */
#define DHCP6REPLY        7

/**
 * @def DHCP6RELEASE
 * @brief DHCPv6 RELEASE message type (8)
 *
 * Client-to-server message releasing assigned addresses per RFC 3315 Section 18.1.6.
 * Sent when client no longer needs addresses (shutdown, moving to different network).
 * Sent to the specific server that assigned addresses (unicast). Contains client
 * and server DUIDs and all IAs to be released. Server responds with REPLY containing
 * status. Releases make addresses available for reassignment. Client must stop
 * using addresses after sending RELEASE.
 */
#define DHCP6RELEASE      8

/**
 * @def DHCP6DECLINE
 * @brief DHCPv6 DECLINE message type (9)
 *
 * Client-to-server message indicating assigned addresses are already in use per
 * RFC 3315 Section 18.1.7. Sent when client detects Duplicate Address Detection
 * (DAD) failure per RFC 4862. Sent to the specific server that assigned addresses
 * (unicast). Contains client and server DUIDs and IAs with problematic addresses.
 * Server responds with REPLY and marks addresses as unavailable for reassignment
 * for an extended period. Client must request different addresses.
 */
#define DHCP6DECLINE      9

/**
 * @def DHCP6RECONFIGURE
 * @brief DHCPv6 RECONFIGURE message type (10)
 *
 * Server-to-client message instructing client to initiate new transaction per
 * RFC 3315 Section 19.1. Allows server to push configuration changes to clients.
 * Sent to client unicast address. Contains reconfigure message type (RENEW or
 * INFORMATION-REQUEST) and authentication option (mandatory for security).
 * Client must authenticate message before processing. Upon receipt, client
 * initiates RENEW or INFORMATION-REQUEST as directed. Requires prior client
 * acceptance via RECONF_ACCEPT option.
 */
#define DHCP6RECONFIGURE  10

/**
 * @def DHCP6IREQ
 * @brief DHCPv6 INFORMATION-REQUEST message type (11)
 *
 * Client-to-server message requesting configuration without address assignment per
 * RFC 3315 Section 18.1.5. Used for stateless DHCPv6 where client obtains IPv6
 * address via SLAAC but needs additional parameters (DNS servers, domain search,
 * NTP servers). Sent to ALL_RELAY_AGENTS_AND_SERVERS multicast. Does not contain
 * IA_NA, IA_TA, or IA_PD options. Server responds with REPLY containing requested
 * configuration options only.
 */
#define DHCP6IREQ         11

/**
 * @def DHCP6RELAYFORW
 * @brief DHCPv6 RELAY-FORW message type (12)
 *
 * Relay-agent-to-server message encapsulating client message per RFC 3315 Section 20.1.
 * Used by relay agents to forward client messages to servers on different links.
 * Contains hop count (incremented by each relay), link address (identifying client
 * link), peer address (client or downstream relay), and encapsulated client message
 * in RELAY_MSG option. May include INTERFACE_ID, REMOTE_ID, and SUBSCRIBER_ID options
 * for client identification. Relay agents enable DHCPv6 to work across routers.
 */
#define DHCP6RELAYFORW    12

/**
 * @def DHCP6RELAYREPL
 * @brief DHCPv6 RELAY-REPL message type (13)
 *
 * Server-to-relay-agent message encapsulating server response per RFC 3315 Section 20.2.
 * Sent by servers in response to RELAY-FORW messages. Contains same hop count,
 * link address, and peer address as corresponding RELAY-FORW, plus encapsulated
 * server message (ADVERTISE, REPLY) in RELAY_MSG option. Relay agents decrement
 * hop count and forward toward client, ultimately delivering server message to
 * client unicast address. Maintains relay chain information for multi-hop scenarios.
 */
#define DHCP6RELAYREPL    13

/**
 * @def OPTION6_CLIENT_ID
 * @brief DHCPv6 Client Identifier option code (1)
 *
 * Contains client DUID (DHCP Unique Identifier) per RFC 3315 Section 22.2.
 * Mandatory in all client messages. Uniquely identifies client across network
 * moves and reboots. DUID types: DUID-LLT (link-layer + time), DUID-EN
 * (enterprise number), DUID-LL (link-layer only). Unlike DHCPv4 which uses
 * MAC address, DUID provides stable identity even when link-layer address changes.
 * Format: 2-byte type + variable-length identifier (minimum 1 byte).
 */
#define OPTION6_CLIENT_ID       1

/**
 * @def OPTION6_SERVER_ID
 * @brief DHCPv6 Server Identifier option code (2)
 *
 * Contains server DUID per RFC 3315 Section 22.3. Included in server ADVERTISE
 * and REPLY messages to identify the responding server. Clients copy this option
 * into REQUEST, RENEW, RELEASE, and DECLINE messages to direct messages to specific
 * server. Enables client to maintain relationship with specific server for lease
 * lifecycle. Format identical to CLIENT_ID: 2-byte DUID type + identifier.
 */
#define OPTION6_SERVER_ID       2

/**
 * @def OPTION6_IA_NA
 * @brief DHCPv6 Identity Association for Non-temporary Addresses option code (3)
 *
 * Container for non-temporary address assignment per RFC 3315 Section 22.4.
 * Client uses IA_NA to request normal addresses (not temporary privacy addresses).
 * Contains 4-byte IAID (Identity Association Identifier, chosen by client),
 * 4-byte T1 timer (when to RENEW), 4-byte T2 timer (when to REBIND), followed
 * by IA Address options (IAADDR) with actual IPv6 addresses and lifetimes.
 * Multiple IA_NA options allowed in single message for different interfaces.
 */
#define OPTION6_IA_NA           3

/**
 * @def OPTION6_IA_TA
 * @brief DHCPv6 Identity Association for Temporary Addresses option code (4)
 *
 * Container for temporary address assignment per RFC 3315 Section 22.5 and
 * RFC 4941 (Privacy Extensions). Used for privacy-sensitive communications where
 * client doesn't want stable address. Contains 4-byte IAID followed by IA Address
 * options. Unlike IA_NA, does not have T1/T2 timers (temporary addresses managed
 * differently). Temporary addresses have shorter lifetimes and are not renewed,
 * providing better privacy by limiting address correlation over time.
 */
#define OPTION6_IA_TA           4

/**
 * @def OPTION6_IAADDR
 * @brief DHCPv6 IA Address option code (5)
 *
 * Actual IPv6 address within IA_NA or IA_TA per RFC 3315 Section 22.6.
 * Contains 16-byte IPv6 address, 4-byte preferred lifetime (when address becomes
 * deprecated but still usable), and 4-byte valid lifetime (when address becomes
 * invalid and must not be used). Preferred lifetime ≤ valid lifetime. Multiple
 * IAADDR options can appear within single IA_NA or IA_TA. May contain STATUS_CODE
 * sub-option for per-address error reporting.
 */
#define OPTION6_IAADDR          5

/**
 * @def OPTION6_ORO
 * @brief DHCPv6 Option Request Option code (6)
 *
 * List of option codes client wants server to provide per RFC 3315 Section 22.7.
 * Contains sequence of 2-byte option codes (e.g., DNS_SERVER, DOMAIN_SEARCH,
 * NTP_SERVER). Used in SOLICIT, REQUEST, RENEW, REBIND, INFORMATION-REQUEST, and
 * RECONFIGURE messages. Server includes requested options in REPLY if configured
 * to provide them. Allows client to explicitly request configuration parameters
 * beyond mandatory address assignment.
 */
#define OPTION6_ORO             6

/**
 * @def OPTION6_PREFERENCE
 * @brief DHCPv6 Preference option code (7)
 *
 * Server preference value (0-255) in ADVERTISE messages per RFC 3315 Section 22.8.
 * Higher values indicate greater server preference. Client receiving multiple
 * ADVERTISE messages selects server with highest preference (unless using Rapid
 * Commit). Value 255 instructs client to immediately send REQUEST without waiting
 * for other ADVERTISEs. Allows server administrators to prioritize servers for
 * load balancing or failover scenarios.
 */
#define OPTION6_PREFERENCE      7

/**
 * @def OPTION6_ELAPSED_TIME
 * @brief DHCPv6 Elapsed Time option code (8)
 *
 * Time elapsed since client began current transaction per RFC 3315 Section 22.9.
 * Contains 2-byte value in centiseconds (1/100th second). Included in client
 * messages to help servers prioritize responses to clients that have been waiting
 * longest. Value 0xFFFF indicates 655.35 seconds or greater. Servers can use this
 * to detect and assist clients experiencing difficulty obtaining configuration.
 * Client sets to 0 in first message, increments in retransmissions.
 */
#define OPTION6_ELAPSED_TIME    8

/**
 * @def OPTION6_RELAY_MSG
 * @brief DHCPv6 Relay Message option code (9)
 *
 * Encapsulated DHCPv6 message within RELAY-FORW or RELAY-REPL per RFC 3315 Section 22.10.
 * Contains complete original message (client-to-server in RELAY-FORW, server-to-client
 * in RELAY-REPL). Allows relay agents to forward messages between links while
 * preserving original message content and adding relay information. Relay chain
 * can be multiple hops deep with nested RELAY_MSG options. Essential for DHCPv6
 * operation across routed networks.
 */
#define OPTION6_RELAY_MSG       9

/**
 * @def OPTION6_AUTH
 * @brief DHCPv6 Authentication option code (11)
 *
 * Message authentication information per RFC 3315 Section 22.11. Contains protocol
 * type, algorithm, replay detection method (RDM), replay detection value, and
 * authentication information (e.g., HMAC). Mandatory in RECONFIGURE messages to
 * prevent spoofing. Optional in other messages for enhanced security. Provides
 * integrity protection and sender authentication. Requires pre-shared keys or
 * PKI infrastructure. Note: Option code 10 is unassigned (gap in RFC numbering).
 */
#define OPTION6_AUTH            11

/**
 * @def OPTION6_UNICAST
 * @brief DHCPv6 Server Unicast option code (12)
 *
 * Server IPv6 address for unicast messaging per RFC 3315 Section 22.12.
 * Included in ADVERTISE or REPLY to tell client it may unicast subsequent messages
 * (REQUEST, RENEW, RELEASE, DECLINE) directly to server instead of using multicast.
 * Reduces network traffic and improves reliability. Contains 16-byte server IPv6
 * address. Client must still use multicast for initial SOLICIT and for REBIND
 * (when trying to reach any server).
 */
#define OPTION6_UNICAST         12

/**
 * @def OPTION6_STATUS_CODE
 * @brief DHCPv6 Status Code option code (13)
 *
 * Success or error status per RFC 3315 Section 22.13. Contains 2-byte status code
 * (Success=0, UnspecFail=1, NoAddrsAvail=2, NoBinding=3, NotOnLink=4, UseMulticast=5)
 * followed by UTF-8 status message for human display. Can appear at message level
 * or within IA_NA/IA_TA/IA_PD options for per-association status. Provides granular
 * error reporting: message-level status for general issues, IA-level status for
 * specific address/prefix assignment problems.
 */
#define OPTION6_STATUS_CODE     13

/**
 * @def OPTION6_RAPID_COMMIT
 * @brief DHCPv6 Rapid Commit option code (14)
 *
 * Signals 2-message exchange instead of 4-message per RFC 3315 Section 22.14.
 * Zero-length option (no data). Client includes in SOLICIT to indicate willingness
 * to accept REPLY without ADVERTISE/REQUEST steps. Server responds with REPLY
 * (containing Rapid Commit option) if configured to allow rapid commit. Reduces
 * address assignment from 4 messages to 2 (SOLICIT → REPLY), improving performance
 * for diskless boot and other latency-sensitive scenarios. Both client and server
 * must support and enable rapid commit.
 */
#define OPTION6_RAPID_COMMIT    14

/**
 * @def OPTION6_USER_CLASS
 * @brief DHCPv6 User Class option code (15)
 *
 * User class categorization per RFC 3315 Section 22.15. Contains one or more
 * opaque data fields identifying user class (e.g., "engineering", "guest").
 * Each field has 2-byte length + data. Allows servers to provide different
 * configuration based on user category. Complementary to VENDOR_CLASS (which
 * identifies device type). Useful in enterprise environments for role-based
 * configuration policies.
 */
#define OPTION6_USER_CLASS      15

/**
 * @def OPTION6_VENDOR_CLASS
 * @brief DHCPv6 Vendor Class option code (16)
 *
 * Vendor class identification per RFC 3315 Section 22.16. Contains 4-byte
 * enterprise number (IANA-assigned) followed by one or more opaque vendor class
 * data fields. Identifies device vendor and model for vendor-specific configuration.
 * Works with VENDOR_OPTS to enable vendor-specific option extensions. Example:
 * Network boot clients include vendor class to receive appropriate boot parameters.
 */
#define OPTION6_VENDOR_CLASS    16

/**
 * @def OPTION6_VENDOR_OPTS
 * @brief DHCPv6 Vendor-specific Information option code (17)
 *
 * Vendor-specific options per RFC 3315 Section 22.17. Contains 4-byte enterprise
 * number followed by vendor-defined option data. Allows vendors to extend DHCPv6
 * with proprietary options without IANA registration. Server provides vendor options
 * matching client's enterprise number from VENDOR_CLASS. Commonly used for device-
 * specific configuration (VoIP phones, set-top boxes). Vendor option data structure
 * is vendor-defined and opaque to standard DHCPv6 processing.
 */
#define OPTION6_VENDOR_OPTS     17

/**
 * @def OPTION6_INTERFACE_ID
 * @brief DHCPv6 Interface-ID option code (18)
 *
 * Relay agent interface identifier per RFC 3315 Section 22.18. Opaque value
 * (defined by relay agent) identifying client-facing interface. Included in
 * RELAY-FORW messages by relay agent, copied to RELAY-REPL by server. Allows
 * relay agent to identify correct interface for client message delivery when
 * relay has multiple client-facing interfaces. Content is relay-implementation-
 * specific (could be interface index, name, or arbitrary identifier).
 */
#define OPTION6_INTERFACE_ID    18

/**
 * @def OPTION6_RECONFIGURE_MSG
 * @brief DHCPv6 Reconfigure Message option code (19)
 *
 * Type of reconfiguration requested in RECONFIGURE message per RFC 3315 Section 22.19.
 * Contains 1-byte message type: RENEW (5) to trigger client RENEW, or
 * INFORMATION-REQUEST (11) to trigger stateless reconfiguration. Tells client
 * what type of transaction to initiate in response to server's RECONFIGURE.
 * Mandatory in all RECONFIGURE messages. Allows server to selectively trigger
 * full renewal or just configuration parameter update.
 */
#define OPTION6_RECONFIGURE_MSG 19

/**
 * @def OPTION6_RECONF_ACCEPT
 * @brief DHCPv6 Reconfigure Accept option code (20)
 *
 * Client willingness to accept RECONFIGURE messages per RFC 3315 Section 22.20.
 * Zero-length option (no data). Client includes in SOLICIT, REQUEST, RENEW, or
 * REBIND to indicate it will accept authenticated RECONFIGURE messages from server.
 * Without this option, server must not send RECONFIGURE to client. Allows clients
 * to opt into server-initiated configuration updates while preventing unwanted
 * reconfiguration of clients that don't support or want this feature.
 */
#define OPTION6_RECONF_ACCEPT   20

/**
 * @def OPTION6_DNS_SERVER
 * @brief DHCPv6 DNS Recursive Name Server option code (23)
 *
 * List of DNS server IPv6 addresses per RFC 3646 Section 3. Contains one or more
 * 16-byte IPv6 addresses of recursive DNS servers in preference order. Equivalent
 * to DHCPv4 option 6. Provided in REPLY messages for both stateful and stateless
 * configuration. Client configures resolver with these addresses. Essential for
 * name resolution. Typically includes primary and secondary DNS servers. Note:
 * Options 21-22 are assigned to other RFCs (SIP servers).
 */
#define OPTION6_DNS_SERVER      23

/**
 * @def OPTION6_DOMAIN_SEARCH
 * @brief DHCPv6 Domain Search List option code (24)
 *
 * DNS domain search list per RFC 3646 Section 4. Contains one or more domain names
 * encoded in DNS wire format (with compression). Equivalent to DHCPv4 option 119.
 * Client appends these domains to unqualified hostnames during resolution. Example:
 * with search list ["example.com", "example.net"], query for "host" tries
 * "host.example.com" then "host.example.net". Improves user experience by allowing
 * short hostnames in local domain.
 */
#define OPTION6_DOMAIN_SEARCH   24

/**
 * @def OPTION6_IA_PD
 * @brief DHCPv6 Identity Association for Prefix Delegation option code (25)
 *
 * Container for delegated prefix assignment per RFC 3633 Section 10. Used by
 * requesting routers to obtain IPv6 prefix(es) for downstream networks. Contains
 * 4-byte IAID, 4-byte T1 timer, 4-byte T2 timer, followed by IA Prefix options
 * (IAPREFIX) with actual delegated prefixes and lifetimes. Router can request
 * multiple IA_PDs. Enables hierarchical address assignment: ISP delegates /48 to
 * customer router, which delegates /64 subnets to internal networks.
 */
#define OPTION6_IA_PD           25

/**
 * @def OPTION6_IAPREFIX
 * @brief DHCPv6 IA Prefix option code (26)
 *
 * Actual delegated prefix within IA_PD per RFC 3633 Section 10. Contains 4-byte
 * preferred lifetime, 4-byte valid lifetime, 1-byte prefix length (0-128), and
 * 16-byte IPv6 prefix. Requesting router advertises this prefix on downstream
 * interfaces (via Router Advertisement). Multiple IAPREFIX options can appear
 * within single IA_PD. May contain STATUS_CODE sub-option for per-prefix error
 * reporting. Prefix delegation is key to IPv6 auto-configuration for routers.
 * Note: Options 27-31 assigned to other RFCs (various DHCPv6 extensions).
 */
#define OPTION6_IAPREFIX        26

/**
 * @def OPTION6_REFRESH_TIME
 * @brief DHCPv6 Information Refresh Time option code (32)
 *
 * Suggested interval for stateless configuration refresh per RFC 4242. Contains
 * 4-byte time in seconds. Server includes in REPLY to INFORMATION-REQUEST to tell
 * client how often to refresh stateless configuration (DNS servers, domain search,
 * etc.). Without this option, RFC 3315 specifies client should use IRT_DEFAULT
 * (86400 seconds = 1 day). Allows server to tune refresh rate based on configuration
 * stability: frequent for dynamic environments, infrequent for static environments.
 * Note: Options 27-31 handle NIS, SNTP, and other services.
 */
#define OPTION6_REFRESH_TIME    32

/**
 * @def OPTION6_REMOTE_ID
 * @brief DHCPv6 Relay Agent Remote-ID option code (37)
 *
 * Relay agent identifier for remote client per RFC 4649. Contains 4-byte enterprise
 * number followed by opaque remote ID. Inserted by relay agent to identify remote
 * client's location or connection properties (e.g., DSL line, cable modem, PPP
 * session). Server can use for access control, accounting, or per-client configuration.
 * Relay agent copies option from RELAY-FORW to RELAY-REPL. Complementary to
 * SUBSCRIBER_ID for multi-level client identification. Note: Options 33-36 handle
 * BCMCS, remote ID (older version), and other services.
 */
#define OPTION6_REMOTE_ID       37

/**
 * @def OPTION6_SUBSCRIBER_ID
 * @brief DHCPv6 Relay Agent Subscriber-ID option code (38)
 *
 * Relay agent subscriber identification per RFC 4580. Contains opaque subscriber
 * identifier (e.g., account number, circuit ID). Inserted by relay agent to identify
 * subscribing customer. Server can use for accounting, billing, access control, or
 * per-subscriber configuration policies. Unlike REMOTE_ID (which may identify port
 * or connection), SUBSCRIBER_ID identifies the customer account. Useful in service
 * provider environments for correlating DHCPv6 transactions with subscriber records.
 */
#define OPTION6_SUBSCRIBER_ID   38

/**
 * @def OPTION6_FQDN
 * @brief DHCPv6 Client FQDN option code (39)
 *
 * Fully Qualified Domain Name option per RFC 4704. Contains flags (S=server-update,
 * O=override, N=no-update), followed by domain name in DNS wire format. Coordinates
 * DNS updates between client and server. Flag combinations: client requests server
 * to update DNS (S=1), client updates DNS itself (S=0), server can override client
 * name (O=1). Enables dynamic DNS integration with DHCPv6. Server responds with
 * same option indicating actual update responsibility. Essential for maintaining
 * DNS records synchronized with DHCPv6 address assignments.
 * Note: Options 40-55 handle various DHCPv6 extensions (NIS+, BCMCS, geolocation, etc.).
 */
#define OPTION6_FQDN            39

/**
 * @def OPTION6_NTP_SERVER
 * @brief DHCPv6 NTP Server option code (56)
 *
 * Network Time Protocol server configuration per RFC 5908. Contains one or more
 * sub-options specifying NTP server addresses or FQDNs. Sub-option types:
 * NTP_SUBOPTION_SRV_ADDR (unicast address), NTP_SUBOPTION_MC_ADDR (multicast address),
 * NTP_SUBOPTION_SRV_FQDN (FQDN for server). Allows flexible NTP server specification
 * via IPv6 address or DNS name. Client configures NTP using provided servers for
 * time synchronization. Replaces older SNTP option. Essential for maintaining
 * accurate time on DHCPv6 clients.
 * Note: Options 40-55 include PCP, CAPTIVE_PORTAL, and many other extensions.
 */
#define OPTION6_NTP_SERVER      56

/**
 * @def OPTION6_CLIENT_MAC
 * @brief DHCPv6 Client Link-Layer Address option code (79)
 *
 * Client hardware address per RFC 6939. Contains 2-byte link-layer type (from
 * ARP hardware types) followed by link-layer address (typically 6-byte MAC address).
 * Inserted by relay agent when client message doesn't traverse client's link-layer
 * (e.g., relayed from different segment). Allows server to use MAC address for
 * identification, reservations, and logging even when client uses DUID. Bridges
 * DHCPv4-style MAC-based management to DHCPv6 DUID-based protocol. Particularly
 * useful for consistent device identification across DHCPv4 and DHCPv6 deployments.
 * Note: Options 57-78 include many vendor-specific and protocol-specific extensions.
 */
#define OPTION6_CLIENT_MAC      79

/**
 * @def NTP_SUBOPTION_SRV_ADDR
 * @brief NTP Server Address suboption type (1)
 *
 * NTP server unicast IPv6 address per RFC 5908 Section 4.1. Sub-option within
 * OPTION6_NTP_SERVER containing 16-byte IPv6 address of NTP server. Multiple
 * instances allowed for redundancy. Client contacts server using standard NTP
 * protocol on UDP port 123. Most common NTP configuration method, specifying
 * direct server address. Used when NTP server has stable IPv6 address.
 */
#define NTP_SUBOPTION_SRV_ADDR  1

/**
 * @def NTP_SUBOPTION_MC_ADDR
 * @brief NTP Multicast Address suboption type (2)
 *
 * NTP server multicast IPv6 address per RFC 5908 Section 4.2. Sub-option within
 * OPTION6_NTP_SERVER containing 16-byte IPv6 multicast address. Client joins
 * multicast group and receives NTP broadcasts. Less common than unicast but useful
 * for local time distribution without individual server connections. Multicast
 * NTP reduces server load in large networks. Typical multicast address: FF05::101.
 */
#define NTP_SUBOPTION_MC_ADDR   2

/**
 * @def NTP_SUBOPTION_SRV_FQDN
 * @brief NTP Server FQDN suboption type (3)
 *
 * NTP server Fully Qualified Domain Name per RFC 5908 Section 4.3. Sub-option
 * within OPTION6_NTP_SERVER containing DNS name in wire format. Client resolves
 * FQDN via DNS (AAAA query) to obtain server IPv6 address, then contacts via NTP.
 * Allows NTP server addresses to change without DHCPv6 reconfiguration. Useful
 * for pool.ntp.org and other round-robin DNS-based NTP services. Client must have
 * DNS resolver configured (via OPTION6_DNS_SERVER) before resolving NTP FQDN.
 */
#define NTP_SUBOPTION_SRV_FQDN  3

/**
 * @def DHCP6SUCCESS
 * @brief DHCPv6 status code: Success (0)
 *
 * Transaction completed successfully per RFC 3315 Section 24.4. Included in
 * STATUS_CODE option at message level or within IA_NA/IA_TA/IA_PD to indicate
 * successful operation. No error message required but may include informational
 * text. Default assumption if STATUS_CODE option absent. Used in REPLY messages
 * to confirm successful address assignment, renewal, release, or configuration.
 */
#define DHCP6SUCCESS     0

/**
 * @def DHCP6UNSPEC
 * @brief DHCPv6 status code: UnspecFail (1)
 *
 * Unspecified failure per RFC 3315 Section 24.4. Generic error when no more
 * specific status code applies. Included in STATUS_CODE option with human-readable
 * error message. Server uses when encountering internal error, resource exhaustion,
 * or other unexpected condition. Client should not retry immediately. Status message
 * should provide details for troubleshooting. Equivalent to "Internal Server Error"
 * in HTTP terms.
 */
#define DHCP6UNSPEC      1

/**
 * @def DHCP6NOADDRS
 * @brief DHCPv6 status code: NoAddrsAvail (2)
 *
 * No addresses available for assignment per RFC 3315 Section 24.4. Included in
 * STATUS_CODE option within IA_NA or IA_TA when server has no free addresses in
 * requested address pool. May be temporary (addresses currently allocated) or
 * permanent (pool exhausted). Client may retry later with exponential backoff or
 * try different server. Common in high-utilization networks. Server should include
 * explanatory message indicating whether condition is temporary.
 */
#define DHCP6NOADDRS     2

/**
 * @def DHCP6NOBINDING
 * @brief DHCPv6 status code: NoBinding (3)
 *
 * Server has no binding for requesting client per RFC 3315 Section 24.4. Included
 * in message-level STATUS_CODE in response to RENEW, REBIND, RELEASE, or DECLINE
 * when server has no record of previous address assignment to this client. May occur
 * if server restarted and lost lease database, or client contacted wrong server.
 * Client receiving this must stop using addresses and restart with SOLICIT. Also
 * used within IA_NA/IA_TA when specific identity association is unknown.
 */
#define DHCP6NOBINDING   3

/**
 * @def DHCP6NOTONLINK
 * @brief DHCPv6 status code: NotOnLink (4)
 *
 * Client's addresses not appropriate for link per RFC 3315 Section 24.4. Returned
 * in message-level STATUS_CODE in response to CONFIRM message when client's existing
 * addresses are not valid for the link it's currently attached to. Client has moved
 * to different network segment. Client receiving this must stop using addresses and
 * initiate new SOLICIT to obtain appropriate addresses for current link. Critical
 * for detecting network moves and preventing address conflicts.
 */
#define DHCP6NOTONLINK   4

/**
 * @def DHCP6USEMULTI
 * @brief DHCPv6 status code: UseMulticast (5)
 *
 * Client must use multicast, not unicast per RFC 3315 Section 24.4. Returned in
 * message-level STATUS_CODE when client sent message to server unicast address
 * without server having provided UNICAST option authorizing unicast. Enforces
 * protocol requirement that clients use multicast unless explicitly allowed unicast.
 * Client receiving this must resend message to ALL_RELAY_AGENTS_AND_SERVERS multicast
 * address. Prevents unauthorized unicast which could bypass relay agents and their
 * associated policies.
 */
#define DHCP6USEMULTI    5
