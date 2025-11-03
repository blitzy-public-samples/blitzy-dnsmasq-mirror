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
 * @file dhcp-protocol.h
 * @brief DHCPv4 protocol structures and constants per RFC 2131
 *
 * DETAILED PURPOSE:
 * This header file defines the wire-format structures, constants, and symbolic
 * names for the Dynamic Host Configuration Protocol version 4 (DHCPv4) as
 * specified in RFC 2131 and RFC 2132. It provides the binary packet layout
 * used for network transmission, DHCP message type identifiers, option codes
 * for DHCP options, and port number definitions for client-server communication.
 * 
 * The core of this file is struct dhcp_packet, which represents the 236-byte
 * fixed header plus variable-length options field that comprises a DHCPv4
 * packet on the wire. This structure is used throughout dhcp.c, rfc2131.c,
 * and dhcp-common.c for constructing, parsing, and validating DHCPv4 messages.
 * 
 * All numeric constants follow RFC 2131 Section 2 (packet format) and RFC 2132
 * (DHCP options). The message type codes (DHCPDISCOVER through DHCPINFORM)
 * correspond to the values carried in DHCP option 53 (Message Type).
 *
 * KEY RESPONSIBILITIES:
 * - Define DHCPv4 wire-format packet structure (struct dhcp_packet)
 * - Provide symbolic names for DHCP message types (DHCPDISCOVER, DHCPOFFER, etc.)
 * - Define DHCP and BOOTP option codes per RFC 2132
 * - Specify standard UDP port numbers for DHCP communication
 * - Define PXE (Pre-boot Execution Environment) protocol extensions
 * - Provide suboption codes for option 82 (Relay Agent Information)
 *
 * DEPENDENCIES:
 * - <netinet/in.h> for struct in_addr (IPv4 address structure)
 * - <sys/types.h> for u8, u16, u32 typedefs (included via dnsmasq.h)
 * - Used by: dhcp.c (DHCPv4 server), rfc2131.c (protocol implementation),
 *   dhcp-common.c (shared utilities), network.c (socket setup)
 *
 * DATA STRUCTURES:
 * - struct dhcp_packet (lines 94-101): DHCPv4 wire-format packet with 236-byte
 *   fixed header plus 312-byte options field, total 548 bytes minimum
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP: When defined, enables DHCPv4 server functionality and inclusion
 *   of this header in the build
 * - No conditional compilation within this file; all definitions are standard
 *   DHCPv4 protocol elements
 *
 * THREADING/CONCURRENCY:
 * - Header file with constant definitions only, no threading considerations
 * - Struct dhcp_packet instances are allocated per-transaction in single-threaded
 *   event loop (dnsmasq.c)
 * - No shared mutable state
 *
 * RFC COMPLIANCE:
 * - RFC 2131: Dynamic Host Configuration Protocol (packet format, message types)
 * - RFC 2132: DHCP Options and BOOTP Vendor Extensions (option codes)
 * - RFC 3527: Link Selection suboption (SUBOPT_SUBNET_SELECT)
 * - RFC 3393: Subscriber-ID suboption (SUBOPT_SUBSCR_ID)
 * - RFC 5107: Server Override suboption (SUBOPT_SERVER_OR)
 * - PXE Specification: PXE boot options (SUBOPT_PXE_*)
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

/** @def DHCP_SERVER_PORT
 *  @brief Standard UDP port for DHCP server (67)
 * 
 *  Well-known port number for DHCP/BOOTP server per RFC 2131 Section 4.1.
 *  Servers bind to this port to receive DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE,
 *  DHCPDECLINE, and DHCPINFORM messages from clients. Also used for BOOTP
 *  protocol compatibility (RFC 951).
 */
#define DHCP_SERVER_PORT 67

/** @def DHCP_CLIENT_PORT
 *  @brief Standard UDP port for DHCP client (68)
 * 
 *  Well-known port number for DHCP/BOOTP client per RFC 2131 Section 4.1.
 *  Clients bind to this port to receive DHCPOFFER, DHCPACK, and DHCPNAK
 *  messages from servers. Used for both broadcast and unicast responses.
 */
#define DHCP_CLIENT_PORT 68

/** @def DHCP_SERVER_ALTPORT
 *  @brief Alternate DHCP server port (1067)
 * 
 *  Non-standard alternate port for DHCP server operation, used when standard
 *  port 67 conflicts with other services or for testing purposes. Configured
 *  via --dhcp-alternate-port command-line option.
 */
#define DHCP_SERVER_ALTPORT 1067

/** @def DHCP_CLIENT_ALTPORT
 *  @brief Alternate DHCP client port (1068)
 * 
 *  Non-standard alternate port for DHCP client communication, paired with
 *  DHCP_SERVER_ALTPORT. Used when standard port 68 is unavailable.
 */
#define DHCP_CLIENT_ALTPORT 1068

/** @def PXE_PORT
 *  @brief PXE (Pre-boot Execution Environment) server port (4011)
 * 
 *  Well-known port for PXE boot servers per PXE specification. Used for
 *  proxy DHCP mode where PXE-specific options (boot filename, TFTP server)
 *  are served separately from IP address allocation. See rfc2131.c for
 *  PXE option handling.
 */
#define PXE_PORT 4011

/** @def DHCP_BUFF_SZ
 *  @brief Maximum size for DHCP option value buffer (256 bytes)
 * 
 *  Buffer size to hold one DHCP option with maximum value length (255 bytes
 *  per RFC 2132 Section 2) plus one terminating zero byte for string safety.
 *  Used throughout option parsing code in dhcp-common.c to prevent buffer
 *  overflows when extracting option values from packets.
 */
#define DHCP_BUFF_SZ 256

/** @def BOOTREQUEST
 *  @brief BOOTP/DHCP request operation code (1)
 * 
 *  Value for dhcp_packet.op field indicating message is from client to server.
 *  Used for DHCPDISCOVER, DHCPREQUEST, DHCPDECLINE, DHCPRELEASE, and DHCPINFORM
 *  messages per RFC 2131 Section 2. Also used for BOOTP requests (RFC 951).
 */
#define BOOTREQUEST              1

/** @def BOOTREPLY
 *  @brief BOOTP/DHCP reply operation code (2)
 * 
 *  Value for dhcp_packet.op field indicating message is from server to client.
 *  Used for DHCPOFFER, DHCPACK, and DHCPNAK messages per RFC 2131 Section 2.
 *  Also used for BOOTP replies (RFC 951).
 */
#define BOOTREPLY                2

/** @def DHCP_COOKIE
 *  @brief DHCP magic cookie (0x63825363)
 * 
 *  Magic number identifying DHCP options in packet per RFC 2131 Section 3.
 *  First four bytes of options field must contain this value in network byte
 *  order (99, 130, 83, 99 decimal). Distinguishes DHCP packets from legacy
 *  BOOTP packets. Verified in rfc2131.c packet validation.
 */
#define DHCP_COOKIE              0x63825363

/** @def MIN_PACKETSZ
 *  @brief Minimum DHCPv4 packet size (300 bytes)
 * 
 *  Minimum packet size enforced to work around Linux in-kernel DHCP client
 *  bug that silently ignores smaller packets. Packets shorter than this are
 *  padded with OPTION_PAD (0) bytes before transmission in rfc2131.c.
 *  Standard minimum is 236-byte fixed header, but this ensures compatibility.
 */
#define MIN_PACKETSZ             300

/*
 * DHCP Option Codes per RFC 2132
 * 
 * These constants define the option codes used in the DHCP options field.
 * Each option consists of: code (1 byte), length (1 byte), data (0-255 bytes).
 * Options appear after the DHCP magic cookie (0x63825363) in the options field
 * of struct dhcp_packet. See RFC 2132 for complete option specifications.
 */

/** @def OPTION_PAD
 *  @brief Padding option (0) per RFC 2132 Section 3.1
 *  No data, used to pad options field to minimum packet size or align options.
 */
#define OPTION_PAD               0

/** @def OPTION_NETMASK
 *  @brief Subnet mask option (1) per RFC 2132 Section 3.3
 *  4-byte IPv4 subnet mask for client's network (e.g., 255.255.255.0).
 */
#define OPTION_NETMASK           1

/** @def OPTION_ROUTER
 *  @brief Router/default gateway option (3) per RFC 2132 Section 3.5
 *  List of IPv4 addresses (4 bytes each) for routers on client's subnet,
 *  in order of preference. Most common option after subnet mask.
 */
#define OPTION_ROUTER            3

/** @def OPTION_DNSSERVER
 *  @brief Domain name server option (6) per RFC 2132 Section 3.8
 *  List of IPv4 addresses (4 bytes each) for DNS servers available to client,
 *  in order of preference. Critical for name resolution.
 */
#define OPTION_DNSSERVER         6

/** @def OPTION_HOSTNAME
 *  @brief Hostname option (12) per RFC 2132 Section 3.14
 *  Client's hostname (ASCII string, max 255 bytes). Sent by client in
 *  DHCPREQUEST, may be assigned by server in DHCPACK for dynamic DNS updates.
 */
#define OPTION_HOSTNAME          12

/** @def OPTION_DOMAINNAME
 *  @brief Domain name option (15) per RFC 2132 Section 3.17
 *  DNS domain name for client (ASCII string, e.g., "example.com").
 *  Used for FQDN construction and DNS search path.
 */
#define OPTION_DOMAINNAME        15

/** @def OPTION_BROADCAST
 *  @brief Broadcast address option (28) per RFC 2132 Section 5.3
 *  4-byte IPv4 broadcast address for client's subnet (e.g., 192.168.1.255).
 *  Used for subnet-directed broadcasts.
 */
#define OPTION_BROADCAST         28

/** @def OPTION_VENDOR_CLASS_OPT
 *  @brief Vendor-specific information option (43) per RFC 2132 Section 8.4
 *  Vendor-specific data, interpretation depends on vendor class ID (option 60).
 *  Used for PXE boot parameters and vendor extensions.
 */
#define OPTION_VENDOR_CLASS_OPT  43

/** @def OPTION_REQUESTED_IP
 *  @brief Requested IP address option (50) per RFC 2132 Section 9.1
 *  4-byte IPv4 address client requests in DHCPDISCOVER (hint) or DHCPREQUEST
 *  (confirmation). Server may honor or override request.
 */
#define OPTION_REQUESTED_IP      50 

/** @def OPTION_LEASE_TIME
 *  @brief IP address lease time option (51) per RFC 2132 Section 9.2
 *  4-byte unsigned integer, lease duration in seconds. Requested by client
 *  in DHCPDISCOVER, assigned by server in DHCPOFFER/DHCPACK. Triggers renewal
 *  at T1 (default 50% of lease) and rebinding at T2 (default 87.5%).
 */
#define OPTION_LEASE_TIME        51

/** @def OPTION_OVERLOAD
 *  @brief Option overload option (52) per RFC 2132 Section 9.3
 *  1-byte flag: 1=file field contains options, 2=sname field contains options,
 *  3=both. Allows options to exceed 312-byte options field by reusing fixed
 *  header fields when not needed for BOOTP compatibility.
 */
#define OPTION_OVERLOAD          52

/** @def OPTION_MESSAGE_TYPE
 *  @brief DHCP message type option (53) per RFC 2132 Section 9.6
 *  1-byte message type: DHCPDISCOVER(1), DHCPOFFER(2), DHCPREQUEST(3),
 *  DHCPDECLINE(4), DHCPACK(5), DHCPNAK(6), DHCPRELEASE(7), DHCPINFORM(8).
 *  Mandatory in all DHCP messages, distinguishes message purpose.
 */
#define OPTION_MESSAGE_TYPE      53

/** @def OPTION_SERVER_IDENTIFIER
 *  @brief Server identifier option (54) per RFC 2132 Section 9.7
 *  4-byte IPv4 address identifying DHCP server. Included in DHCPOFFER, DHCPACK,
 *  DHCPNAK. Client includes in DHCPREQUEST to indicate which server's offer
 *  is being accepted or which server to send release/decline.
 */
#define OPTION_SERVER_IDENTIFIER 54

/** @def OPTION_REQUESTED_OPTIONS
 *  @brief Parameter request list option (55) per RFC 2132 Section 9.8
 *  List of option codes (1 byte each) client requests server to provide.
 *  Allows client to specify which options it needs (e.g., router, DNS, domain).
 */
#define OPTION_REQUESTED_OPTIONS 55

/** @def OPTION_MESSAGE
 *  @brief Message option (56) per RFC 2132 Section 9.9
 *  ASCII string error message from server (e.g., in DHCPNAK explaining why
 *  request was rejected). For human consumption, logged but not processed.
 */
#define OPTION_MESSAGE           56

/** @def OPTION_MAXMESSAGE
 *  @brief Maximum DHCP message size option (57) per RFC 2132 Section 9.10
 *  2-byte unsigned integer, maximum DHCP message size client can accept.
 *  Minimum 576 bytes. Informs server of client's buffer capacity.
 */
#define OPTION_MAXMESSAGE        57

/** @def OPTION_T1
 *  @brief Renewal time value T1 option (58) per RFC 2132 Section 9.11
 *  4-byte unsigned integer, seconds until client enters RENEWING state
 *  (default 50% of lease time). Client unicasts DHCPREQUEST to server at T1.
 */
#define OPTION_T1                58

/** @def OPTION_T2
 *  @brief Rebinding time value T2 option (59) per RFC 2132 Section 9.12
 *  4-byte unsigned integer, seconds until client enters REBINDING state
 *  (default 87.5% of lease time). Client broadcasts DHCPREQUEST at T2.
 */
#define OPTION_T2                59

/** @def OPTION_VENDOR_ID
 *  @brief Vendor class identifier option (60) per RFC 2132 Section 9.13
 *  ASCII string identifying client vendor/model (e.g., "PXEClient"). Used
 *  by server to determine which vendor-specific options to provide. Critical
 *  for PXE boot (identifies PXE clients).
 */
#define OPTION_VENDOR_ID         60

/** @def OPTION_CLIENT_ID
 *  @brief Client identifier option (61) per RFC 2132 Section 9.14
 *  Unique client identifier (1 byte type + variable data). Type 1 is hardware
 *  address (MAC). Preferred over chaddr field for lease identification as it
 *  survives hardware changes. Used as primary lease database key.
 */
#define OPTION_CLIENT_ID         61

/** @def OPTION_SNAME
 *  @brief TFTP server name option (66) per RFC 2132 Section 9.4
 *  ASCII string hostname of TFTP server for network booting. Alternative to
 *  using fixed siaddr and sname fields. Used in PXE boot environments.
 */
#define OPTION_SNAME             66

/** @def OPTION_FILENAME
 *  @brief Boot filename option (67) per RFC 2132 Section 9.5
 *  ASCII string boot file pathname on TFTP server (e.g., "pxelinux.0").
 *  Alternative to using fixed file field. Used in PXE and network boot.
 */
#define OPTION_FILENAME          67

/** @def OPTION_USER_CLASS
 *  @brief User class option (77) per RFC 3004
 *  Client-defined classification data for policy-based address allocation.
 *  Allows administrators to group clients and apply different configurations.
 */
#define OPTION_USER_CLASS        77

/** @def OPTION_RAPID_COMMIT
 *  @brief Rapid commit option (80) per RFC 4039
 *  0-length option enabling 2-message exchange (DHCPDISCOVER/DHCPACK) instead
 *  of 4-message (DISCOVER/OFFER/REQUEST/ACK). Improves latency when supported
 *  by both client and server. Not widely used.
 */
#define OPTION_RAPID_COMMIT      80

/** @def OPTION_CLIENT_FQDN
 *  @brief Client fully-qualified domain name option (81) per RFC 4702
 *  Structured data for dynamic DNS updates: flags (1 byte) + domain name.
 *  Allows client to request server perform DNS updates, negotiate update
 *  responsibility. Used with --dhcp-client-update option.
 */
#define OPTION_CLIENT_FQDN       81

/** @def OPTION_AGENT_ID
 *  @brief Relay agent information option (82) per RFC 3027
 *  Sub-options added by DHCP relay agents: circuit ID, remote ID, etc.
 *  Provides relay with information about client's network location.
 *  See SUBOPT_* definitions for sub-option codes. Critical for ISP deployments.
 */
#define OPTION_AGENT_ID          82

/** @def OPTION_ARCH
 *  @brief Client system architecture option (93) per RFC 4578
 *  2-byte architecture type for PXE boot: 0x0000=IA32, 0x0006=IA32 EFI,
 *  0x0007=x64 EFI, 0x0009=x64 EFI BC. Allows server to provide architecture-
 *  specific boot images.
 */
#define OPTION_ARCH              93

/** @def OPTION_PXE_UUID
 *  @brief Client machine identifier option (97) per RFC 4578
 *  17-byte UUID: 1-byte type (0=UUID) + 16-byte UUID. Unique identifier for
 *  PXE client machine. Used for persistent boot configuration.
 */
#define OPTION_PXE_UUID          97

/** @def OPTION_SUBNET_SELECT
 *  @brief Subnet selection option (118) per RFC 3011
 *  4-byte IPv4 subnet address. Used by relay agents and clients to indicate
 *  which subnet the address should be allocated from, overriding giaddr.
 */
#define OPTION_SUBNET_SELECT     118

/** @def OPTION_DOMAIN_SEARCH
 *  @brief Domain search list option (119) per RFC 3397
 *  Compressed domain name list (DNS format) for DNS search path. Multiple
 *  domains for name resolution when unqualified names are queried.
 */
#define OPTION_DOMAIN_SEARCH     119

/** @def OPTION_SIP_SERVER
 *  @brief SIP servers option (120) per RFC 3361
 *  List of SIP (Session Initiation Protocol) server IPv4 addresses or
 *  compressed domain names. Used in VoIP deployments.
 */
#define OPTION_SIP_SERVER        120

/** @def OPTION_VENDOR_IDENT
 *  @brief Vendor-identifying vendor class option (124) per RFC 3925
 *  Enterprise number (4 bytes) + vendor data. More structured alternative
 *  to option 60, allows multiple vendors in one option.
 */
#define OPTION_VENDOR_IDENT      124

/** @def OPTION_VENDOR_IDENT_OPT
 *  @brief Vendor-identifying vendor-specific option (125) per RFC 3925
 *  Enterprise number (4 bytes) + sub-options. Vendor-specific configuration
 *  data, allows multiple vendors' options in one DHCP option.
 */
#define OPTION_VENDOR_IDENT_OPT  125

/** @def OPTION_END
 *  @brief End option (255) per RFC 2132 Section 3.2
 *  No data, marks end of options in packet. All data after this is padding
 *  (OPTION_PAD). Mandatory at end of options field.
 */
#define OPTION_END               255

/*
 * Relay Agent Information Sub-Options (option 82)
 * 
 * These sub-options appear within OPTION_AGENT_ID (82) data field.
 * Used by DHCP relay agents to provide information about client's physical
 * or logical network location. See RFC 3027 and related RFCs.
 */

/** @def SUBOPT_CIRCUIT_ID
 *  @brief Circuit ID sub-option (1) per RFC 3027 Section 2.1
 *  Identifies relay agent's circuit (port, VLAN, etc.) where client request
 *  was received. Opaque data meaningful to relay agent and server.
 */
#define SUBOPT_CIRCUIT_ID        1

/** @def SUBOPT_REMOTE_ID
 *  @brief Remote ID sub-option (2) per RFC 3027 Section 2.2
 *  Identifies relay agent or remote client (subscriber line, DSL modem ID).
 *  Used by ISPs to identify customer location.
 */
#define SUBOPT_REMOTE_ID         2

/** @def SUBOPT_SUBNET_SELECT
 *  @brief Subnet selection sub-option (5) per RFC 3527
 *  4-byte IPv4 subnet address. Relay agent indicates which subnet to allocate
 *  address from, overriding packet's giaddr field.
 */
#define SUBOPT_SUBNET_SELECT     5

/** @def SUBOPT_SUBSCR_ID
 *  @brief Subscriber ID sub-option (6) per RFC 3393
 *  Subscriber identifier assigned by relay agent (NAS-Port-Id, DSL line ID).
 *  Used for subscriber-specific policies and billing.
 */
#define SUBOPT_SUBSCR_ID         6

/** @def SUBOPT_SERVER_OR
 *  @brief Server override sub-option (11) per RFC 5107
 *  List of 4-byte IPv4 addresses of DHCP servers. Relay agent specifies which
 *  servers to forward requests to, overriding broadcast.
 */
#define SUBOPT_SERVER_OR         11

/*
 * PXE (Pre-boot Execution Environment) Sub-Options
 * 
 * These appear within OPTION_VENDOR_CLASS_OPT (43) for PXE boot.
 * See PXE specification version 2.1 for details.
 */

/** @def SUBOPT_PXE_BOOT_ITEM
 *  @brief PXE boot item sub-option (71) per PXE spec
 *  Boot menu item: type (2 bytes) + layer (2 bytes). Describes available
 *  boot images (e.g., Linux, Windows, diagnostic tools).
 */
#define SUBOPT_PXE_BOOT_ITEM     71

/** @def SUBOPT_PXE_DISCOVERY
 *  @brief PXE discovery control sub-option (6) per PXE spec
 *  1-byte flags controlling PXE client's multicast/broadcast discovery
 *  behavior. Optimizes boot server location.
 */
#define SUBOPT_PXE_DISCOVERY     6

/** @def SUBOPT_PXE_SERVERS
 *  @brief PXE boot servers sub-option (8) per PXE spec
 *  List of boot server addresses: type (2 bytes) + count + IPv4 addresses.
 *  Specifies which servers provide which boot image types.
 */
#define SUBOPT_PXE_SERVERS       8

/** @def SUBOPT_PXE_MENU
 *  @brief PXE boot menu sub-option (9) per PXE spec
 *  Boot menu entries: type (2 bytes) + description length + description string.
 *  Displayed to user for boot image selection.
 */
#define SUBOPT_PXE_MENU          9

/** @def SUBOPT_PXE_MENU_PROMPT
 *  @brief PXE menu prompt sub-option (10) per PXE spec
 *  Timeout (1 byte) + prompt string. Message displayed before boot menu
 *  with timeout in seconds (0=no timeout, 255=wait forever).
 */
#define SUBOPT_PXE_MENU_PROMPT   10

/*
 * DHCP Message Types (option 53 values)
 * 
 * These values appear in OPTION_MESSAGE_TYPE (53) to identify DHCP message
 * purpose per RFC 2131 Section 3.1. Each message type defines specific
 * required and optional options and processing rules.
 */

/** @def DHCPDISCOVER
 *  @brief DHCP Discover message type (1) per RFC 2131 Section 3.1
 *  Broadcast by client to locate available DHCP servers. Client includes
 *  option 55 (requested options) and optionally 50 (requested IP). Servers
 *  respond with DHCPOFFER. First message in 4-message exchange.
 */
#define DHCPDISCOVER             1

/** @def DHCPOFFER
 *  @brief DHCP Offer message type (2) per RFC 2131 Section 3.1
 *  Unicast/broadcast by server in response to DHCPDISCOVER. Contains offered
 *  IP address in yiaddr field plus configuration options (lease time, router,
 *  DNS, etc.). Client may receive multiple offers from different servers.
 */
#define DHCPOFFER                2

/** @def DHCPREQUEST
 *  @brief DHCP Request message type (3) per RFC 2131 Section 3.1
 *  Broadcast by client to request offered IP (includes option 54 server ID)
 *  or renew/rebind existing lease. Also unicast to server during RENEWING.
 *  Third message in 4-message exchange, triggers DHCPACK or DHCPNAK.
 */
#define DHCPREQUEST              3

/** @def DHCPDECLINE
 *  @brief DHCP Decline message type (4) per RFC 2131 Section 3.1
 *  Client informs server that offered IP address is already in use (detected
 *  via ARP). Server must not allocate that address to other clients.
 *  Rare in practice; requires client to start discovery over.
 */
#define DHCPDECLINE              4

/** @def DHCPACK
 *  @brief DHCP Acknowledgment message type (5) per RFC 2131 Section 3.1
 *  Server confirms IP address allocation in response to DHCPREQUEST. Contains
 *  committed IP in yiaddr and final configuration options. Client enters
 *  BOUND state. Final message in 4-message exchange.
 */
#define DHCPACK                  5

/** @def DHCPNAK
 *  @brief DHCP Negative Acknowledgment message type (6) per RFC 2131 Section 3.1
 *  Server rejects DHCPREQUEST (requested IP unavailable, lease expired, client
 *  on wrong network). Client must return to INIT state and restart discovery.
 *  Includes option 56 (message) with human-readable reason.
 */
#define DHCPNAK                  6

/** @def DHCPRELEASE
 *  @brief DHCP Release message type (7) per RFC 2131 Section 3.1
 *  Client voluntarily releases IP address before lease expiry (e.g., clean
 *  shutdown). Unicast to server identified in option 54. Server marks lease
 *  available immediately. No server response required.
 */
#define DHCPRELEASE              7

/** @def DHCPINFORM
 *  @brief DHCP Inform message type (8) per RFC 2131 Section 3.1
 *  Client with manually-configured IP requests configuration parameters only
 *  (no IP allocation). Server responds with DHCPACK containing options but
 *  yiaddr=0. Used for diskless workstations with fixed addressing.
 */
#define DHCPINFORM               8

/** @def BRDBAND_FORUM_IANA
 *  @brief Broadband Forum IANA enterprise number (3561)
 *  IANA-assigned enterprise number for Broadband Forum. Used in vendor-
 *  identifying options (124, 125) for DSL Forum / Broadband Forum equipment.
 */
#define BRDBAND_FORUM_IANA       3561

/** @def DHCP_CHADDR_MAX
 *  @brief Maximum client hardware address length (16 bytes)
 *  Size of chaddr field in struct dhcp_packet per RFC 2131 Section 2.
 *  Accommodates Ethernet MAC (6 bytes), token ring (6 bytes), and other
 *  hardware address types with padding. Actual length in hlen field.
 */
#define DHCP_CHADDR_MAX 16

/**
 * @struct dhcp_packet
 * @brief DHCPv4 wire-format packet structure per RFC 2131 Section 2
 *
 * DETAILED PURPOSE:
 * Represents the complete DHCPv4/BOOTP packet format transmitted over UDP.
 * This structure defines the exact byte layout of DHCP packets on the network,
 * including 236-byte fixed header and 312-byte variable-length options field,
 * for a minimum total size of 548 bytes (padded to MIN_PACKETSZ=300 minimum).
 * 
 * The structure is used for both requests (client to server) and replies
 * (server to client), with interpretation varying by op field (BOOTREQUEST
 * vs BOOTREPLY) and message type (option 53). All multi-byte fields are in
 * network byte order (big-endian).
 * 
 * Used throughout DHCPv4 implementation in dhcp.c (packet construction),
 * rfc2131.c (protocol handling), dhcp-common.c (option parsing), and
 * network.c (packet transmission/reception).
 *
 * LIFECYCLE:
 * - Allocated: On stack or heap per incoming UDP datagram in dhcp.c
 * - Initialized: Zeroed, then populated field-by-field in rfc2131.c
 * - Transmitted: Via UDP sendto() to ports DHCP_CLIENT_PORT/DHCP_SERVER_PORT
 * - Received: Via UDP recvfrom() in network.c, validated before processing
 * - Deallocated: Automatic (stack) or explicit free() after processing complete
 *
 * MEMORY LAYOUT:
 * Total size: 548 bytes (236 fixed + 312 options)
 * Alignment: Natural alignment for u8/u16/u32 fields (no padding required)
 * Byte offsets:
 *   0-3:   op, htype, hlen, hops (4 bytes)
 *   4-7:   xid (4 bytes)
 *   8-11:  secs, flags (4 bytes)
 *   12-15: ciaddr (4 bytes)
 *   16-19: yiaddr (4 bytes)
 *   20-23: siaddr (4 bytes)
 *   24-27: giaddr (4 bytes)
 *   28-43: chaddr (16 bytes)
 *   44-107: sname (64 bytes)
 *   108-235: file (128 bytes)
 *   236-547: options (312 bytes)
 *
 * USAGE PATTERNS:
 * Client sending DHCPDISCOVER:
 *   op=BOOTREQUEST, xid=random, ciaddr=0, chaddr=client MAC,
 *   options starts with DHCP_COOKIE, includes option 53=DHCPDISCOVER
 * 
 * Server sending DHCPOFFER:
 *   op=BOOTREPLY, xid=from request, yiaddr=offered IP, siaddr=server IP,
 *   options includes option 53=DHCPOFFER, option 51=lease time
 * 
 * All DHCP packets:
 *   - First 4 bytes of options must be DHCP_COOKIE (0x63825363)
 *   - Options end with OPTION_END (255)
 *   - Padded with OPTION_PAD (0) to MIN_PACKETSZ if needed
 *
 * RFC COMPLIANCE:
 * - RFC 2131 Section 2: Packet format definition (all fields)
 * - RFC 2132: Options field format and encoding
 * - RFC 951: BOOTP compatibility (legacy field usage)
 *
 * @see dhcp.c for packet construction and transmission
 * @see rfc2131.c for protocol-level packet handling
 * @see dhcp-common.c for option parsing and encoding
 */
struct dhcp_packet {
  /** @var op
   *  Message operation code: BOOTREQUEST (1) for client-to-server messages,
   *  BOOTREPLY (2) for server-to-client messages. Byte offset 0.
   */
  u8 op;
  
  /** @var htype
   *  Hardware address type per ARP protocol: 1=Ethernet (10Mbps), 6=IEEE 802,
   *  etc. See RFC 1700. Typically 1 for Ethernet networks. Byte offset 1.
   */
  u8 htype;
  
  /** @var hlen
   *  Hardware address length in bytes: 6 for Ethernet MAC addresses,
   *  0-16 for other types. Must match length of meaningful data in chaddr.
   *  Byte offset 2.
   */
  u8 hlen;
  
  /** @var hops
   *  Hop count incremented by each DHCP relay agent. Client sets to 0.
   *  Used to detect forwarding loops (discarded if exceeds configured
   *  threshold, typically 4). Byte offset 3.
   */
  u8 hops;
  
  /** @var xid
   *  Transaction ID, random 32-bit value chosen by client. Remains constant
   *  across all messages in one transaction (DISCOVER/OFFER/REQUEST/ACK).
   *  Used to match requests with replies. Network byte order. Byte offset 4-7.
   */
  u32 xid;
  
  /** @var secs
   *  Seconds elapsed since client began address acquisition or renewal, set
   *  by client. Server may use for prioritization (older requests first).
   *  Network byte order. Byte offset 8-9.
   */
  u16 secs;
  
  /** @var flags
   *  Flags field: bit 0x8000=BROADCAST flag (client cannot receive unicast
   *  until configured), other bits reserved and MUST be zero per RFC 2131.
   *  Network byte order. Byte offset 10-11.
   */
  u16 flags;
  
  /** @var ciaddr
   *  Client IP address. Filled by client in BOUND, RENEWING, REBINDING states
   *  when it has valid IP address. Zero in INIT and SELECTING states.
   *  Used in DHCPREQUEST for renewal/rebinding. Byte offset 12-15.
   */
  struct in_addr ciaddr;
  
  /** @var yiaddr
   *  "Your" (client) IP address. Filled by server in DHCPOFFER and DHCPACK
   *  with IP address being offered or committed to client. Zero in requests.
   *  Byte offset 16-19.
   */
  struct in_addr yiaddr;
  
  /** @var siaddr
   *  Next server IP address (TFTP server for boot files). Used in DHCPOFFER/
   *  DHCPACK when boot file is provided. Client uses this for TFTP connection.
   *  Alternative: option 66 (TFTP server name). Byte offset 20-23.
   */
  struct in_addr siaddr;
  
  /** @var giaddr
   *  Relay agent (gateway) IP address. Set by DHCP relay agent to its address
   *  when forwarding client requests to server. Zero when no relay involved
   *  (client and server on same subnet). Server uses for subnet selection.
   *  Byte offset 24-27.
   */
  struct in_addr giaddr;
  
  /** @var chaddr
   *  Client hardware address (MAC address for Ethernet). Length specified by
   *  hlen field (typically 6 bytes for Ethernet), padded with zeros to 16 bytes.
   *  Historically primary client identifier, now option 61 preferred.
   *  Byte offset 28-43.
   */
  u8 chaddr[DHCP_CHADDR_MAX];
  
  /** @var sname
   *  Optional server hostname (ASCII NUL-terminated string, max 64 bytes).
   *  Filled by server in DHCPOFFER/DHCPACK with server's hostname. Legacy
   *  BOOTP field, rarely used in modern DHCP (option 54 server identifier
   *  preferred). May be reused for options if option 52 overload=2 or 3.
   *  Byte offset 44-107.
   */
  u8 sname[64];
  
  /** @var file
   *  Boot filename (ASCII NUL-terminated string, max 128 bytes). Server fills
   *  with boot file pathname for network boot (e.g., "pxelinux.0"). Client
   *  requests file from TFTP server at siaddr. Alternative: option 67 (boot
   *  filename). May be reused for options if option 52 overload=1 or 3.
   *  Byte offset 108-235.
   */
  u8 file[128];
  
  /** @var options
   *  Variable-length options field (312 bytes in this structure, but can
   *  extend into sname/file if option 52 overload used). Format:
   *  - Bytes 0-3: DHCP magic cookie (0x63825363) mandatory for DHCP
   *  - Bytes 4+: Options as TLV (Type-Length-Value): code(1) + len(1) + data(len)
   *  - Special codes: 0=PAD (no length/data), 255=END (no length/data)
   *  - Must end with option 255 (END)
   *  See RFC 2132 for complete option specifications. Byte offset 236-547.
   */
  u8 options[312];
};
