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
 * @file dns-protocol.h
 * @brief DNS protocol data structures and constants per RFC 1035
 *
 * DETAILED PURPOSE:
 * 
 * This header file defines the fundamental DNS protocol structures, constants, and
 * macros required for parsing and constructing DNS messages according to RFC 1035.
 * It provides the wire-format representation of DNS packets including the 12-byte
 * header structure, resource record type definitions, query classes, opcodes, and
 * response codes. The file also includes DNSSEC-related types (DNSKEY, RRSIG, DS,
 * NSEC, NSEC3) per RFCs 4033-4035, IPv6 AAAA records per RFC 3596, and EDNS0
 * extended options per RFC 6891 and RFC 8914.
 * 
 * All structures and constants defined here represent the actual on-the-wire byte
 * layout of DNS protocol messages. Multi-byte integer fields are stored in network
 * byte order (big-endian) and must be converted using the provided GETSHORT/GETLONG
 * and PUTSHORT/PUTLONG macros. The dns_header structure provides access to the fixed
 * 12-byte header present in all DNS messages, with bit-field flags encoded in bytes
 * hb3 and hb4 according to RFC 1035 Section 4.1.1.
 * 
 * This header is protocol-neutral and contains no dnsmasq-specific logic or state.
 * It serves as the foundation for DNS message processing in rfc1035.c, forward.c,
 * cache.c, and dnssec.c, ensuring consistent interpretation of DNS wire format
 * across all DNS-related subsystems.
 *
 * KEY RESPONSIBILITIES:
 * 
 * - Define struct dns_header representing the 12-byte DNS message header
 * - Provide DNS resource record type constants (T_A, T_AAAA, T_MX, T_CNAME, etc.)
 * - Define DNS query classes (C_IN, C_CHAOS, C_ANY)
 * - Provide DNS response code constants (NOERROR, NXDOMAIN, SERVFAIL, etc.)
 * - Define EDNS0 option codes for client subnet, extended errors, vendor extensions
 * - Provide byte-order conversion macros (GETSHORT, GETLONG, PUTSHORT, PUTLONG)
 * - Define buffer safety check macros (CHECK_LEN, ADD_RDLEN)
 * - Establish protocol size limits (PACKETSZ, MAXDNAME, MAXLABEL)
 *
 * DEPENDENCIES:
 * 
 * Included by:
 * - rfc1035.c (DNS packet parsing and construction)
 * - forward.c (DNS query forwarding)
 * - cache.c (DNS caching, requires RR types)
 * - dnssec.c (DNSSEC validation, requires DNSKEY/RRSIG/DS/NSEC types)
 * - auth.c (Authoritative DNS server)
 * - edns0.c (EDNS0 extension handling)
 * - All DNS-related modules
 * 
 * Includes:
 * - None (standalone protocol definition header)
 * 
 * Requires:
 * - u8, u16, u32 type definitions (provided by dnsmasq.h)
 * - Network byte order awareness by consuming modules
 *
 * DATA STRUCTURES:
 * 
 * - struct dns_header (lines 119-123) - DNS message header, 12 bytes fixed size
 *   Contains: id (2 bytes), flags (2 bytes as hb3/hb4), four 16-bit counts
 *   (qdcount, ancount, nscount, arcount) for questions, answers, authority, and
 *   additional records sections
 *
 * COMPILE-TIME OPTIONS:
 * 
 * This header has no compile-time conditionals. All DNS protocol constants are
 * unconditionally defined regardless of HAVE_DNSSEC, HAVE_TFTP, or other feature
 * flags. DNSSEC-specific RR types (T_DNSKEY, T_RRSIG, T_DS, T_NSEC, T_NSEC3) are
 * always defined but only used when HAVE_DNSSEC is enabled in consuming modules.
 *
 * THREADING/CONCURRENCY:
 * 
 * This header defines only constants and data structure layouts. No threading
 * concerns exist as there are no functions or mutable state. The defined structures
 * represent immutable protocol specifications and can be safely accessed from any
 * context in dnsmasq's single-process event-driven architecture.
 *
 * RFC COMPLIANCE:
 * 
 * - RFC 1035: Domain Names - Implementation and Specification (core DNS protocol)
 *   Section 4.1: Message format and header structure
 *   Section 3.2.2-3.2.4: Resource record types and classes
 * - RFC 2535: Domain Name System Security Extensions (original DNSSEC, obsoleted)
 * - RFC 3596: DNS Extensions to Support IP Version 6 (AAAA records)
 * - RFC 4033: DNS Security Introduction and Requirements
 * - RFC 4034: Resource Records for the DNS Security Extensions
 * - RFC 4035: Protocol Modifications for the DNS Security Extensions
 * - RFC 6891: Extension Mechanisms for DNS (EDNS0)
 * - RFC 8914: Extended DNS Errors (EDE codes)
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * 
 * @see rfc1035.c for DNS packet parsing using these structures
 * @see forward.c for DNS query forwarding
 * @see dnssec.c for DNSSEC validation using security RR types
 */

/**
 * @def NAMESERVER_PORT
 * @brief Standard DNS server port number (53)
 * 
 * Well-known port for DNS queries and responses over UDP and TCP per RFC 1035.
 * Used for all DNS communication unless explicitly overridden by user configuration.
 */
#define NAMESERVER_PORT 53

/**
 * @def TFTP_PORT
 * @brief Standard TFTP server port number (69)
 * 
 * Well-known port for TFTP file transfers per RFC 1350. Used by dnsmasq's
 * integrated TFTP server for PXE network boot support when HAVE_TFTP enabled.
 */
#define TFTP_PORT       69

/**
 * @def MIN_PORT
 * @brief First non-reserved port (1024)
 * 
 * Ports below 1024 are privileged/reserved on Unix systems. Used as lower bound
 * for dynamic port allocation and source port randomization for DNS queries.
 */
#define MIN_PORT        1024           /* first non-reserved port */

/**
 * @def MAX_PORT
 * @brief Maximum valid port number (65535)
 * 
 * Upper bound for 16-bit port numbers. Used for port range validation and
 * source port randomization upper limit.
 */
#define MAX_PORT        65535u

/**
 * @def IN6ADDRSZ
 * @brief Size of IPv6 address in bytes (16)
 * 
 * IPv6 addresses are 128 bits (16 bytes). Used for buffer sizing when handling
 * AAAA records and IPv6 socket addresses.
 */
#define IN6ADDRSZ       16

/**
 * @def INADDRSZ
 * @brief Size of IPv4 address in bytes (4)
 * 
 * IPv4 addresses are 32 bits (4 bytes). Used for buffer sizing when handling
 * A records and IPv4 socket addresses.
 */
#define INADDRSZ        4

/**
 * @def PACKETSZ
 * @brief Default maximum DNS packet size (512 bytes)
 * 
 * Per RFC 1035 Section 4.2.1, DNS messages over UDP must be limited to 512 bytes
 * unless EDNS0 is used to negotiate a larger buffer size. This is the baseline
 * packet size that all DNS implementations must support. Actual buffer sizes may
 * be larger when EDNS0 is negotiated (see EDNS_PKTSZ in config.h).
 */
#define PACKETSZ	512		/* maximum packet size */

/**
 * @def MAXDNAME
 * @brief Maximum presentation format domain name length (1025 bytes)
 * 
 * Maximum length for a domain name in presentation format (ASCII with dots).
 * Per RFC 1035, wire format names are limited to 255 bytes, but with compression
 * expansion and conversion to presentation format with escape sequences, the
 * buffer must be larger. Size includes null terminator.
 */
#define MAXDNAME	1025		/* maximum presentation domain name */

/**
 * @def RRFIXEDSZ
 * @brief Fixed size of resource record header (10 bytes)
 * 
 * Every DNS resource record has a fixed 10-byte header containing TYPE (2 bytes),
 * CLASS (2 bytes), TTL (4 bytes), and RDLENGTH (2 bytes) per RFC 1035 Section 4.1.3.
 * RDATA follows these fixed fields with length specified by RDLENGTH.
 */
#define RRFIXEDSZ	10		/* #/bytes of fixed data in r record */

/**
 * @def MAXLABEL
 * @brief Maximum length of single domain name label (63 bytes)
 * 
 * Per RFC 1035 Section 3.1, each label in a domain name is limited to 63 octets.
 * Labels are separated by dots in presentation format and by length bytes in wire
 * format. This limit ensures the length fits in 6 bits (top 2 bits reserved for
 * compression pointer identification).
 */
#define MAXLABEL        63              /* maximum length of domain label */

/**
 * @def NOERROR
 * @brief DNS response code 0: No error condition
 * 
 * Per RFC 1035 Section 4.1.1, RCODE=0 indicates the query was successfully
 * processed with no errors. This is the success response code.
 */
#define NOERROR		0		/* no error */

/**
 * @def FORMERR
 * @brief DNS response code 1: Format error
 * 
 * Per RFC 1035 Section 4.1.1, RCODE=1 indicates the name server was unable to
 * interpret the query due to a format error in the request message.
 */
#define FORMERR		1		/* format error */

/**
 * @def SERVFAIL
 * @brief DNS response code 2: Server failure
 * 
 * Per RFC 1035 Section 4.1.1, RCODE=2 indicates the name server was unable to
 * process the query due to a problem with the name server. This is a temporary
 * failure; the query may succeed if retried.
 */
#define SERVFAIL	2		/* server failure */

/**
 * @def NXDOMAIN
 * @brief DNS response code 3: Non-existent domain
 * 
 * Per RFC 1035 Section 4.1.1, RCODE=3 indicates the domain name referenced in
 * the query does not exist. Only authoritative name servers can return this code.
 * This response is cached as negative cache entry.
 */
#define NXDOMAIN	3		/* non existent domain */

/**
 * @def NOTIMP
 * @brief DNS response code 4: Not implemented
 * 
 * Per RFC 1035 Section 4.1.1, RCODE=4 indicates the name server does not support
 * the requested kind of query (usually unsupported OPCODE).
 */
#define NOTIMP		4		/* not implemented */

/**
 * @def REFUSED
 * @brief DNS response code 5: Query refused
 * 
 * Per RFC 1035 Section 4.1.1, RCODE=5 indicates the name server refuses to
 * perform the requested operation for policy reasons (e.g., zone transfer denied,
 * update refused, recursive query to non-recursive server).
 */
#define REFUSED		5		/* query refused */

/**
 * @def QUERY
 * @brief DNS opcode 0: Standard query
 * 
 * Per RFC 1035 Section 4.1.1, OPCODE=0 is a standard query. This is the normal
 * DNS query operation for looking up resource records. Other opcodes include
 * IQUERY (inverse query, deprecated) and STATUS (server status request).
 */
#define QUERY           0               /* opcode */

/**
 * @def C_IN
 * @brief DNS class 1: Internet (IN)
 * 
 * Per RFC 1035 Section 3.2.4, class IN (value 1) represents the Internet system.
 * This is the standard class for all Internet DNS queries and is used for nearly
 * all modern DNS traffic. See also C_CHAOS, C_HESIOD.
 */
#define C_IN            1               /* the arpa internet */

/**
 * @def C_CHAOS
 * @brief DNS class 3: CHAOS network
 * 
 * Per RFC 1035 Section 3.2.4, class CHAOS (value 3) was used for MIT's CHAOS
 * network. Rarely used in modern DNS. Some implementations use it for special
 * queries like version.bind TXT queries.
 */
#define C_CHAOS         3               /* for chaos net (MIT) */

/**
 * @def C_HESIOD
 * @brief DNS class 4: Hesiod name service
 * 
 * Hesiod is a name service developed at MIT using DNS infrastructure. Rarely
 * used in modern deployments.
 */
#define C_HESIOD        4               /* hesiod */

/**
 * @def C_ANY
 * @brief DNS class 255: Wildcard match (ANY)
 * 
 * Per RFC 1035 Section 3.2.5, QCLASS=255 in queries requests records of any class.
 * Used in queries to match any class, though typically only C_IN records exist.
 */
#define C_ANY           255             /* wildcard match */

/**
 * @def T_A
 * @brief DNS RR type 1: IPv4 address record
 * 
 * Per RFC 1035 Section 3.4.1, A records contain a 32-bit IPv4 address. This is
 * the most common DNS record type for forward DNS lookups (hostname to IP address).
 * RDATA is 4 bytes containing the IPv4 address in network byte order.
 */
#define T_A		1

/**
 * @def T_NS
 * @brief DNS RR type 2: Authoritative name server
 * 
 * Per RFC 1035 Section 3.3.11, NS records specify authoritative name servers for
 * a DNS zone. RDATA contains a domain name pointing to the name server host.
 */
#define T_NS            2

/**
 * @def T_MD
 * @brief DNS RR type 3: Mail destination (obsolete)
 * 
 * Per RFC 1035, MD records specified mail destinations. This type is obsolete and
 * replaced by MX records. Retained for protocol completeness but rarely used.
 */
#define T_MD            3

/**
 * @def T_MF
 * @brief DNS RR type 4: Mail forwarder (obsolete)
 * 
 * Per RFC 1035, MF records specified mail forwarders. This type is obsolete and
 * replaced by MX records. Retained for protocol completeness but rarely used.
 */
#define T_MF            4             

/**
 * @def T_CNAME
 * @brief DNS RR type 5: Canonical name (alias)
 * 
 * Per RFC 1035 Section 3.3.1, CNAME records provide an alias from one domain name
 * to another (the canonical name). When a CNAME is encountered, the resolver must
 * restart the query using the canonical name. dnsmasq follows CNAME chains up to
 * CNAME_CHAIN=10 hops to prevent infinite loops (see cache.c).
 */
#define T_CNAME		5

/**
 * @def T_SOA
 * @brief DNS RR type 6: Start of authority
 * 
 * Per RFC 1035 Section 3.3.13, SOA records mark the start of a zone and contain
 * zone metadata: primary name server, responsible email, serial number, refresh/
 * retry/expire timers, and minimum TTL. Required in all authoritative zones.
 */
#define T_SOA		6

/**
 * @def T_MB
 * @brief DNS RR type 7: Mailbox domain name (experimental)
 * 
 * Per RFC 1035, MB records specify a mailbox domain name. This is an experimental
 * record type rarely used in practice.
 */
#define T_MB            7

/**
 * @def T_MG
 * @brief DNS RR type 8: Mail group member (experimental)
 * 
 * Per RFC 1035, MG records specify members of a mail group. This is an experimental
 * record type rarely used in practice.
 */
#define T_MG            8

/**
 * @def T_MR
 * @brief DNS RR type 9: Mail rename domain name (experimental)
 * 
 * Per RFC 1035, MR records specify a mail rename domain. This is an experimental
 * record type rarely used in practice.
 */
#define T_MR            9

/**
 * @def T_PTR
 * @brief DNS RR type 12: Pointer record (reverse DNS)
 * 
 * Per RFC 1035 Section 3.3.12, PTR records map IP addresses back to hostnames
 * (reverse DNS). Used in .in-addr.arpa (IPv4) and .ip6.arpa (IPv6) zones.
 * RDATA contains the domain name associated with the IP address.
 */
#define T_PTR		12

/**
 * @def T_MINFO
 * @brief DNS RR type 14: Mailbox information
 * 
 * Per RFC 1035, MINFO records provide mailbox or mail list information. Rarely
 * used in modern DNS deployments.
 */
#define T_MINFO         14

/**
 * @def T_MX
 * @brief DNS RR type 15: Mail exchange
 * 
 * Per RFC 1035 Section 3.3.9, MX records specify mail servers for a domain and
 * their priority. RDATA contains a 16-bit preference value (lower is higher
 * priority) followed by the mail server hostname. Multiple MX records provide
 * redundancy and load distribution for email delivery.
 */
#define T_MX		15

/**
 * @def T_TXT
 * @brief DNS RR type 16: Text record
 * 
 * Per RFC 1035 Section 3.3.14, TXT records contain arbitrary text strings. Used
 * for SPF records, DKIM keys, domain verification, and other text-based metadata.
 * RDATA is one or more character strings, each preceded by a length byte.
 */
#define T_TXT		16

/**
 * @def T_RP
 * @brief DNS RR type 17: Responsible person
 * 
 * Per RFC 1183, RP records identify the responsible person for a domain, with
 * email address and optional text record reference.
 */
#define T_RP            17

/**
 * @def T_AFSDB
 * @brief DNS RR type 18: AFS database location
 * 
 * Per RFC 1183, AFSDB records provide location of AFS (Andrew File System) cell
 * database servers. Used in AFS distributed filesystem deployments.
 */
#define T_AFSDB         18

/**
 * @def T_RT
 * @brief DNS RR type 21: Route through
 * 
 * Per RFC 1183, RT records specify intermediate hosts for routing to destination.
 * Rarely used in modern networks.
 */
#define T_RT            21

/**
 * @def T_SIG
 * @brief DNS RR type 24: Signature (original DNSSEC, obsolete)
 * 
 * Per RFC 2535 (obsoleted by RFC 4034), SIG records contained cryptographic
 * signatures for DNSSEC. Replaced by RRSIG (type 46) in modern DNSSEC.
 */
#define T_SIG		24

/**
 * @def T_PX
 * @brief DNS RR type 26: Pointer to X.400 mapping information
 * 
 * Per RFC 2163, PX records provide X.400 to RFC822 email mapping. Used in
 * X.400 email system integration, rarely encountered today.
 */
#define T_PX            26

/**
 * @def T_AAAA
 * @brief DNS RR type 28: IPv6 address record
 * 
 * Per RFC 3596, AAAA records (quad-A) contain a 128-bit IPv6 address. This is
 * the IPv6 equivalent of A records for forward DNS lookups. RDATA is 16 bytes
 * containing the IPv6 address in network byte order.
 */
#define T_AAAA		28

/**
 * @def T_NXT
 * @brief DNS RR type 30: Next record (original DNSSEC, obsolete)
 * 
 * Per RFC 2535 (obsoleted by RFC 4034), NXT records provided authenticated denial
 * of existence in original DNSSEC. Replaced by NSEC (type 47) in modern DNSSEC.
 */
#define T_NXT           30

/**
 * @def T_SRV
 * @brief DNS RR type 33: Service locator
 * 
 * Per RFC 2763, SRV records specify location of services (host and port). RDATA
 * contains priority, weight, port, and target hostname. Used for service discovery
 * (e.g., _ldap._tcp.example.com, _sip._udp.example.com). Format: priority weight
 * port target.
 */
#define T_SRV		33

/**
 * @def T_NAPTR
 * @brief DNS RR type 35: Naming authority pointer
 * 
 * Per RFC 2915, NAPTR records provide rewrite rules for URIs and are used in ENUM
 * (telephone number to URI mapping) and dynamic delegation discovery systems.
 */
#define T_NAPTR		35

/**
 * @def T_KX
 * @brief DNS RR type 36: Key exchanger
 * 
 * Per RFC 2230, KX records specify key exchange servers for a domain. Used with
 * some email encryption systems.
 */
#define T_KX            36

/**
 * @def T_DNAME
 * @brief DNS RR type 39: Delegation name
 * 
 * Per RFC 6672, DNAME records provide redirection for an entire subtree of the
 * DNS namespace (unlike CNAME which only redirects a single name). Used for
 * delegating entire zones.
 */
#define T_DNAME         39

/**
 * @def T_OPT
 * @brief DNS RR type 41: EDNS0 option (pseudo-record)
 * 
 * Per RFC 6891 (EDNS0), OPT is a pseudo-record used to advertise extended DNS
 * capabilities. It appears in the additional section and is not cached. Used to
 * negotiate larger UDP packet sizes, DNSSEC OK bit, client subnet information,
 * and extended error codes. See edns0.c for handling.
 */
#define T_OPT		41

/**
 * @def T_DS
 * @brief DNS RR type 43: Delegation signer (DNSSEC)
 * 
 * Per RFC 4034, DS records contain a hash of a DNSKEY record from a child zone.
 * Placed in the parent zone to establish the chain of trust in DNSSEC. Contains
 * key tag, algorithm, digest type, and digest. See dnssec.c for validation.
 */
#define T_DS            43

/**
 * @def T_RRSIG
 * @brief DNS RR type 46: Resource record signature (DNSSEC)
 * 
 * Per RFC 4034, RRSIG records contain cryptographic signatures for a set of DNS
 * records (RRset). Each RRset in a signed zone has a corresponding RRSIG. Contains
 * type covered, algorithm, labels, original TTL, signature expiration/inception,
 * key tag, signer name, and signature. See dnssec.c and crypto.c for verification.
 */
#define T_RRSIG         46

/**
 * @def T_NSEC
 * @brief DNS RR type 47: Next secure record (DNSSEC)
 * 
 * Per RFC 4034, NSEC records provide authenticated denial of existence in DNSSEC.
 * Links each name to the next name in canonical order and lists RR types present.
 * Used to prove that a queried name or type does not exist. See dnssec.c for
 * validation. NSEC3 (type 50) is a hashed alternative to prevent zone enumeration.
 */
#define T_NSEC          47

/**
 * @def T_DNSKEY
 * @brief DNS RR type 48: DNS public key (DNSSEC)
 * 
 * Per RFC 4034, DNSKEY records contain public keys used to verify RRSIG signatures.
 * Contains flags (KSK/ZSK), protocol (always 3), algorithm, and public key data.
 * Zone-signing keys (ZSK) sign zone data, key-signing keys (KSK) sign DNSKEY
 * records. See dnssec.c and crypto.c for validation.
 */
#define T_DNSKEY        48

/**
 * @def T_NSEC3
 * @brief DNS RR type 50: Next secure record version 3 (DNSSEC)
 * 
 * Per RFC 5155, NSEC3 records provide authenticated denial of existence like NSEC
 * but use hashed names to prevent zone enumeration (walking the zone to list all
 * names). Contains hash algorithm, flags, iterations, salt, next hashed owner name,
 * and type bit maps. See dnssec.c for validation.
 */
#define T_NSEC3         50

/**
 * @def T_TKEY
 * @brief DNS RR type 249: Transaction key (DNS security)
 * 
 * Per RFC 2930, TKEY records establish shared secret keys for TSIG authentication.
 * Used for secure dynamic updates. This is a meta-record processed during connection
 * setup, not cached.
 */
#define	T_TKEY		249		

/**
 * @def T_TSIG
 * @brief DNS RR type 250: Transaction signature (DNS security)
 * 
 * Per RFC 2845, TSIG records provide transaction-level authentication for DNS
 * messages using shared secret keys. Used to authenticate dynamic updates and zone
 * transfers. This is a meta-record that appears in the additional section and is
 * not cached.
 */
#define	T_TSIG		250

/**
 * @def T_AXFR
 * @brief DNS RR type 252: Zone transfer (query type)
 * 
 * Per RFC 1035 Section 3.2.3, AXFR is a query type requesting a full zone transfer.
 * Only valid in questions, never in resource records. Transfers entire zone contents
 * over TCP. Used for zone replication between name servers.
 */
#define T_AXFR          252

/**
 * @def T_MAILB
 * @brief DNS RR type 253: Mailbox-related records (query type)
 * 
 * Per RFC 1035 Section 3.2.3, QTYPE=253 requests all mailbox-related records
 * (MB, MG, MR). Only valid in questions as a query type, not a real RR type.
 */
#define T_MAILB		253	

/**
 * @def T_ANY
 * @brief DNS RR type 255: All records (query type)
 * 
 * Per RFC 1035 Section 3.2.3, QTYPE=255 requests all record types for a name.
 * Only valid in questions. Responses may include any/all RR types present for
 * the queried name. Some authoritative servers now refuse ANY queries per RFC 8482
 * to prevent amplification attacks.
 */
#define T_ANY		255

/**
 * @def T_CAA
 * @brief DNS RR type 257: Certification authority authorization
 * 
 * Per RFC 6844, CAA records specify which certificate authorities are authorized
 * to issue certificates for a domain. Used by CAs to validate certificate issuance
 * requests. RDATA contains flags, tag (e.g., "issue", "issuewild"), and value
 * specifying authorized CA.
 */
#define T_CAA           257

/**
 * @def EDNS0_OPTION_MAC
 * @brief EDNS0 option code 65001: MAC address (dyndns.org temporary)
 * 
 * Temporary EDNS0 option code assigned by dyndns.org to carry client MAC addresses.
 * Used in some dynamic DNS implementations to identify clients by hardware address.
 * This is a vendor-specific extension in the private use range (>= 65000).
 * See edns0.c for handling.
 */
#define EDNS0_OPTION_MAC            65001 /* dyndns.org temporary assignment */

/**
 * @def EDNS0_OPTION_CLIENT_SUBNET
 * @brief EDNS0 option code 8: Client subnet (EDNS-Client-Subnet)
 * 
 * Per RFC 7871, IANA-assigned EDNS0 option for client subnet information. Allows
 * recursive resolvers to include client subnet data in queries to authoritative
 * servers, enabling geographically-aware responses (CDN optimization, geolocation).
 * Contains address family, source prefix length, scope prefix length, and address.
 * See edns0.c for processing.
 */
#define EDNS0_OPTION_CLIENT_SUBNET  8     /* IANA */

/**
 * @def EDNS0_OPTION_EDE
 * @brief EDNS0 option code 15: Extended DNS errors
 * 
 * Per RFC 8914, IANA-assigned option for Extended DNS Errors (EDE). Provides
 * additional error information beyond basic RCODE, with error code and optional
 * UTF-8 text. Helps diagnose DNSSEC validation failures, filtering, and other
 * DNS operational issues. See EDE_* constants for error codes.
 */
#define EDNS0_OPTION_EDE            15    /* IANA - RFC 8914 */

/**
 * @def EDNS0_OPTION_NOMDEVICEID
 * @brief EDNS0 option code 65073: Device ID (Nominum temporary)
 * 
 * Temporary EDNS0 option code assigned by Nominum to carry device identifiers.
 * Used in some subscriber management systems for device tracking. Vendor-specific
 * extension in private use range.
 */
#define EDNS0_OPTION_NOMDEVICEID    65073 /* Nominum temporary assignment */

/**
 * @def EDNS0_OPTION_NOMCPEID
 * @brief EDNS0 option code 65074: CPE ID (Nominum temporary)
 * 
 * Temporary EDNS0 option code assigned by Nominum to carry Customer Premises
 * Equipment (CPE) identifiers. Used in ISP subscriber management. Vendor-specific
 * extension in private use range.
 */
#define EDNS0_OPTION_NOMCPEID       65074 /* Nominum temporary assignment */

/**
 * @def EDNS0_OPTION_UMBRELLA
 * @brief EDNS0 option code 20292: Umbrella identification (Cisco temporary)
 * 
 * Temporary EDNS0 option code assigned by Cisco for Umbrella cloud security
 * platform. Used to pass client identification to Cisco's DNS security service.
 * Vendor-specific extension.
 */
#define EDNS0_OPTION_UMBRELLA       20292 /* Cisco Umbrella temporary assignment */

/* RFC-8914 extended errors, negative values are our definitions */

/**
 * @def EDE_UNSET
 * @brief Extended DNS error code -1: No extended error available (dnsmasq internal)
 * 
 * Internal dnsmasq value (negative values are dnsmasq-specific) indicating no
 * extended DNS error information is available. Used as sentinel value when EDE
 * is not applicable or not generated. Not transmitted on the wire.
 */
#define EDE_UNSET          -1  /* No extended DNS error available */

/**
 * @def EDE_OTHER
 * @brief Extended DNS error code 0: Other error
 * 
 * Per RFC 8914, error code 0 indicates an error not covered by other specific codes.
 * Generic fallback error. Should include EXTRA-TEXT field with explanation.
 */
#define EDE_OTHER           0  /* Other */

/**
 * @def EDE_USUPDNSKEY
 * @brief Extended DNS error code 1: Unsupported DNSKEY algorithm
 * 
 * Per RFC 8914, indicates DNSSEC validation failed because the DNSKEY uses an
 * algorithm not supported by the validator. Resolver cannot validate signatures
 * made with this key.
 */
#define EDE_USUPDNSKEY      1  /* Unsupported DNSKEY algo */

/**
 * @def EDE_USUPDS
 * @brief Extended DNS error code 2: Unsupported DS digest type
 * 
 * Per RFC 8914, indicates DNSSEC validation failed because the DS record uses a
 * digest type not supported by the validator. Cannot establish chain of trust.
 */
#define EDE_USUPDS          2  /* Unsupported DS Digest */

/**
 * @def EDE_STALE
 * @brief Extended DNS error code 3: Stale answer
 * 
 * Per RFC 8914, indicates the resolver is returning stale cached data because
 * it cannot contact authoritative servers. Data is past its TTL but returned
 * due to serve-stale functionality per RFC 8767.
 */
#define EDE_STALE           3  /* Stale answer */

/**
 * @def EDE_FORGED
 * @brief Extended DNS error code 4: Forged answer
 * 
 * Per RFC 8914, indicates the resolver detected the answer data is forged or
 * manipulated. May indicate DNS poisoning attempt or man-in-the-middle attack.
 */
#define EDE_FORGED          4  /* Forged answer */

/**
 * @def EDE_DNSSEC_IND
 * @brief Extended DNS error code 5: DNSSEC indeterminate
 * 
 * Per RFC 8914, indicates DNSSEC validation could not be completed, but no specific
 * failure was detected. Result is neither secure nor bogus (insecure or indeterminate).
 * May be due to missing data, timeouts, or configuration issues.
 */
#define EDE_DNSSEC_IND      5  /* DNSSEC Indeterminate  */

/**
 * @def EDE_DNSSEC_BOGUS
 * @brief Extended DNS error code 6: DNSSEC bogus
 * 
 * Per RFC 8914, indicates DNSSEC validation definitely failed. Signature verification
 * failed, DS/DNSKEY mismatch, or other validation error. Answer is not trustworthy.
 * See dnssec.c for validation logic.
 */
#define EDE_DNSSEC_BOGUS    6  /* DNSSEC Bogus */

/**
 * @def EDE_SIG_EXP
 * @brief Extended DNS error code 7: Signature expired
 * 
 * Per RFC 8914, indicates DNSSEC validation failed because the RRSIG signature
 * has passed its expiration time. Zone needs re-signing.
 */
#define EDE_SIG_EXP         7  /* Signature Expired */

/**
 * @def EDE_SIG_NYV
 * @brief Extended DNS error code 8: Signature not yet valid
 * 
 * Per RFC 8914, indicates DNSSEC validation failed because the RRSIG signature
 * inception time is in the future. Client clock may be wrong or zone was pre-signed
 * too far in advance.
 */
#define EDE_SIG_NYV         8  /* Signature Not Yet Valid  */

/**
 * @def EDE_NO_DNSKEY
 * @brief Extended DNS error code 9: DNSKEY missing
 * 
 * Per RFC 8914, indicates DNSSEC validation failed because required DNSKEY record
 * is missing. Cannot verify RRSIG signatures without the public key.
 */
#define EDE_NO_DNSKEY       9  /* DNSKEY missing */

/**
 * @def EDE_NO_RRSIG
 * @brief Extended DNS error code 10: RRSIGs missing
 * 
 * Per RFC 8914, indicates DNSSEC validation failed because required RRSIG records
 * are missing. Zone claims to be signed but signatures are absent.
 */
#define EDE_NO_RRSIG       10  /* RRSIGs missing */

/**
 * @def EDE_NO_ZONEKEY
 * @brief Extended DNS error code 11: No zone key bit set
 * 
 * Per RFC 8914, indicates DNSSEC validation failed because the DNSKEY does not
 * have the Zone Key flag (bit 7) set. Key cannot be used to verify zone data.
 */
#define EDE_NO_ZONEKEY     11  /* No Zone Key Bit Set */

/**
 * @def EDE_NO_NSEC
 * @brief Extended DNS error code 12: NSEC missing
 * 
 * Per RFC 8914, indicates DNSSEC validation failed because required NSEC or NSEC3
 * records for authenticated denial of existence are missing. Cannot prove non-existence.
 */
#define EDE_NO_NSEC        12  /* NSEC Missing  */

/**
 * @def EDE_CACHED_ERR
 * @brief Extended DNS error code 13: Cached error
 * 
 * Per RFC 8914, indicates resolver is returning a cached error response (e.g.,
 * cached NXDOMAIN or SERVFAIL) rather than querying authoritative servers.
 */
#define EDE_CACHED_ERR     13  /* Cached Error */

/**
 * @def EDE_NOT_READY
 * @brief Extended DNS error code 14: Not ready
 * 
 * Per RFC 8914, indicates the server is not ready to answer (startup, configuration
 * loading, zone loading in progress). Temporary condition that should resolve.
 */
#define EDE_NOT_READY      14  /* Not Ready */

/**
 * @def EDE_BLOCKED
 * @brief Extended DNS error code 15: Blocked
 * 
 * Per RFC 8914, indicates the query was blocked by policy (security filtering,
 * parental controls, malware protection). Distinguished from censorship.
 */
#define EDE_BLOCKED        15  /* Blocked */

/**
 * @def EDE_CENSORED
 * @brief Extended DNS error code 16: Censored
 * 
 * Per RFC 8914, indicates the query result was censored by legal or governmental
 * requirement. Distinguished from security blocking.
 */
#define EDE_CENSORED       16  /* Censored */

/**
 * @def EDE_FILTERED
 * @brief Extended DNS error code 17: Filtered
 * 
 * Per RFC 8914, indicates the query was filtered per policy (content filtering,
 * safe search enforcement). General filtering category.
 */
#define EDE_FILTERED       17  /* Filtered */

/**
 * @def EDE_PROHIBITED
 * @brief Extended DNS error code 18: Prohibited
 * 
 * Per RFC 8914, indicates the query type or operation is prohibited by policy.
 * Different from REFUSED (which is at DNS protocol level).
 */
#define EDE_PROHIBITED     18  /* Prohibited */

/**
 * @def EDE_STALE_NXD
 * @brief Extended DNS error code 19: Stale NXDOMAIN answer
 * 
 * Per RFC 8914, indicates resolver is returning a stale NXDOMAIN from cache
 * because authoritative servers are unreachable. Combines EDE_STALE with NXDOMAIN.
 */
#define EDE_STALE_NXD      19  /* Stale NXDOMAIN */

/**
 * @def EDE_NOT_AUTH
 * @brief Extended DNS error code 20: Not authoritative
 * 
 * Per RFC 8914, indicates the server is not authoritative for the queried zone
 * but was expected to be (e.g., lame delegation).
 */
#define EDE_NOT_AUTH       20  /* Not Authoritative */

/**
 * @def EDE_NOT_SUP
 * @brief Extended DNS error code 21: Not supported
 * 
 * Per RFC 8914, indicates the requested query type or operation is not supported.
 * Similar to NOTIMP RCODE but with more context.
 */
#define EDE_NOT_SUP        21  /* Not Supported */

/**
 * @def EDE_NO_AUTH
 * @brief Extended DNS error code 22: No reachable authority
 * 
 * Per RFC 8914, indicates resolver cannot reach any authoritative server for the
 * zone. All upstream servers are unreachable or timing out. Network or routing issue.
 */
#define EDE_NO_AUTH        22  /* No Reachable Authority */

/**
 * @def EDE_NETERR
 * @brief Extended DNS error code 23: Network error
 * 
 * Per RFC 8914, indicates a network-level error prevented query completion (socket
 * errors, routing failures, interface down). Distinguished from DNS protocol errors.
 */
#define EDE_NETERR         23  /* Network error */

/**
 * @def EDE_INVALID_DATA
 * @brief Extended DNS error code 24: Invalid data
 * 
 * Per RFC 8914, indicates response data is invalid or malformed at a semantic level
 * (beyond FORMERR). May indicate broken authoritative server or data corruption.
 */
#define EDE_INVALID_DATA   24  /* Invalid Data */

/**
 * @struct dns_header
 * @brief DNS message header structure (12 bytes fixed size)
 * 
 * This structure represents the fixed 12-byte header present in all DNS messages
 * per RFC 1035 Section 4.1.1. The header precedes the variable-length question,
 * answer, authority, and additional sections. All multi-byte fields are in network
 * byte order (big-endian).
 * 
 * LIFECYCLE:
 * 
 * This structure is typically overlaid on received packet buffers or used to
 * construct outgoing packets. No dynamic allocation is required - the structure
 * is sized to match the wire format exactly. Fields are accessed directly from
 * packet buffers in rfc1035.c, forward.c, and cache.c.
 * 
 * MEMORY LAYOUT:
 * 
 * Total size: 12 bytes (96 bits)
 * Offset 0-1:   id (16 bits)
 * Offset 2:     hb3 (8 bits) - QR, OPCODE, AA, TC, RD flags
 * Offset 3:     hb4 (8 bits) - RA, Z, AD, CD, RCODE flags  
 * Offset 4-5:   qdcount (16 bits)
 * Offset 6-7:   ancount (16 bits)
 * Offset 8-9:   nscount (16 bits)
 * Offset 10-11: arcount (16 bits)
 * 
 * Alignment: No padding required. Structure packs to exactly 12 bytes matching
 * wire format. Use of u8 for flag bytes avoids alignment issues.
 * 
 * USAGE PATTERNS:
 * 
 * Receiving packets: Cast packet buffer to struct dns_header*, access fields,
 * use ntohs() or GETSHORT macro for 16-bit fields (id and counts).
 * 
 * Sending packets: Construct header in buffer, set fields, use htons() or
 * PUTSHORT macro for 16-bit fields. Use HB3_* and HB4_* constants to set flags
 * in hb3/hb4 bytes.
 * 
 * @see rfc1035.c for DNS packet parsing using this header
 * @see forward.c for query forwarding that manipulates this header
 * @see GETSHORT, PUTSHORT macros for byte-order conversion
 * @see HB3_*, HB4_* constants for flag bit manipulation
 */
struct dns_header {
  u16 id;          /**< Transaction ID for matching queries and responses. Randomized 
                        for security (see util.c rand16()). Copied from query to response. */
  u8  hb3,         /**< Header byte 3 containing QR, OPCODE, AA, TC, RD flags.
                        Access via HB3_QR, HB3_OPCODE, HB3_AA, HB3_TC, HB3_RD constants
                        and OPCODE(), SET_OPCODE() macros. */
      hb4;         /**< Header byte 4 containing RA, Z, AD, CD, RCODE flags.
                        Access via HB4_RA, HB4_AD, HB4_CD, HB4_RCODE constants
                        and RCODE(), SET_RCODE() macros. */
  u16 qdcount,     /**< Question count: Number of entries in question section.
                        Usually 1 for standard queries. Use ntohs() or GETSHORT to convert
                        from network byte order. */
      ancount,     /**< Answer count: Number of resource records in answer section.
                        0 in queries, >= 0 in responses. */
      nscount,     /**< Authority count: Number of name server records in authority section.
                        Used for NS records indicating authoritative servers. */
      arcount;     /**< Additional count: Number of records in additional section.
                        Used for additional information (A records for NS names, EDNS0 OPT). */
};

/**
 * @def HB3_QR
 * @brief Query/Response flag bit in header byte 3 (bit 7, mask 0x80)
 * 
 * Per RFC 1035 Section 4.1.1, QR bit distinguishes queries (QR=0) from responses
 * (QR=1). This is the most significant bit of hb3. Check with (hb3 & HB3_QR) to
 * test if message is a response, or set with (hb3 |= HB3_QR) to mark as response.
 */
#define HB3_QR       0x80 /* Query */

/**
 * @def HB3_OPCODE
 * @brief OPCODE field mask in header byte 3 (bits 6-3, mask 0x78)
 * 
 * Per RFC 1035 Section 4.1.1, OPCODE occupies bits 3-6 of hb3 and specifies the
 * kind of query (0=QUERY standard query, 1=IQUERY inverse query, 2=STATUS server
 * status request). Extract with OPCODE(header) macro, set with SET_OPCODE(header, code).
 */
#define HB3_OPCODE   0x78

/**
 * @def HB3_AA
 * @brief Authoritative Answer flag in header byte 3 (bit 2, mask 0x04)
 * 
 * Per RFC 1035 Section 4.1.1, AA bit indicates the responding name server is
 * authoritative for the queried domain. Only set in responses from authoritative
 * servers, never in queries. Used by cache to determine cacheability.
 */
#define HB3_AA       0x04 /* Authoritative Answer */

/**
 * @def HB3_TC
 * @brief Truncation flag in header byte 3 (bit 1, mask 0x02)
 * 
 * Per RFC 1035 Section 4.1.1, TC bit indicates the message was truncated due to
 * length exceeding transmission channel capacity. When set in UDP response, client
 * must retry over TCP to get complete answer. See forward.c for TCP fallback logic.
 */
#define HB3_TC       0x02 /* TrunCated */

/**
 * @def HB3_RD
 * @brief Recursion Desired flag in header byte 3 (bit 0, mask 0x01)
 * 
 * Per RFC 1035 Section 4.1.1, RD bit indicates the client desires recursive query
 * processing. Set in queries to request that the server pursue the query recursively.
 * Copied from query to response. dnsmasq acts as recursive resolver when RD=1.
 */
#define HB3_RD       0x01 /* Recursion Desired */

/**
 * @def HB4_RA
 * @brief Recursion Available flag in header byte 4 (bit 7, mask 0x80)
 * 
 * Per RFC 1035 Section 4.1.1, RA bit indicates recursive query support is available
 * at the server. Set in responses from recursive resolvers like dnsmasq, clear in
 * responses from authoritative-only servers.
 */
#define HB4_RA       0x80 /* Recursion Available */

/**
 * @def HB4_AD
 * @brief Authenticated Data flag in header byte 4 (bit 5, mask 0x20)
 * 
 * Per RFC 4035 Section 3.2.3 (DNSSEC), AD bit indicates all data in the answer
 * and authority sections has been verified per DNSSEC policies. Set by validating
 * resolvers when DNSSEC validation succeeds. See dnssec.c for validation logic.
 */
#define HB4_AD       0x20 /* Authenticated Data */

/**
 * @def HB4_CD
 * @brief Checking Disabled flag in header byte 4 (bit 4, mask 0x10)
 * 
 * Per RFC 4035 Section 3.2.2 (DNSSEC), CD bit in queries requests that the server
 * disable DNSSEC validation. Used by validating stubs that want to perform their
 * own validation. Not commonly used; most clients rely on resolver validation.
 */
#define HB4_CD       0x10 /* Checking Disabled */

/**
 * @def HB4_RCODE
 * @brief Response code field mask in header byte 4 (bits 3-0, mask 0x0f)
 * 
 * Per RFC 1035 Section 4.1.1, RCODE occupies bits 0-3 of hb4 and indicates response
 * status (0=NOERROR, 3=NXDOMAIN, 2=SERVFAIL, etc.). Extract with RCODE(header) macro,
 * set with SET_RCODE(header, code). See NOERROR, NXDOMAIN, SERVFAIL constants.
 */
#define HB4_RCODE    0x0f

/**
 * @def OPCODE
 * @brief Extract OPCODE field from DNS header
 * 
 * Extracts the 4-bit OPCODE field from header byte 3 (bits 6-3). Returns 0 for
 * standard query (QUERY), 1 for inverse query (IQUERY, obsolete), 2 for server
 * status (STATUS). Used to dispatch query handling logic in rfc1035.c.
 * 
 * @param x Pointer to struct dns_header
 * @return OPCODE value (0-15, though only 0-2 defined in RFC 1035)
 */
#define OPCODE(x)          (((x)->hb3 & HB3_OPCODE) >> 3)

/**
 * @def SET_OPCODE
 * @brief Set OPCODE field in DNS header
 * 
 * Sets the 4-bit OPCODE field in header byte 3 while preserving other flags.
 * Typically called when constructing response packets to match query OPCODE.
 * 
 * @param x Pointer to struct dns_header
 * @param code OPCODE value to set (0=QUERY, 1=IQUERY, 2=STATUS), pre-shifted left by 3
 * 
 * @note code parameter must be pre-shifted (e.g., QUERY << 3), not the raw value
 */
#define SET_OPCODE(x, code) (x)->hb3 = ((x)->hb3 & ~HB3_OPCODE) | code

/**
 * @def RCODE
 * @brief Extract RCODE field from DNS header
 * 
 * Extracts the 4-bit response code from header byte 4 (bits 3-0). Returns values
 * like NOERROR (0), NXDOMAIN (3), SERVFAIL (2). Used throughout dnsmasq to check
 * response status and determine caching behavior. See forward.c and cache.c.
 * 
 * @param x Pointer to struct dns_header
 * @return RCODE value (0-15, common values 0-5 per RFC 1035)
 */
#define RCODE(x)           ((x)->hb4 & HB4_RCODE)

/**
 * @def SET_RCODE
 * @brief Set RCODE field in DNS header
 * 
 * Sets the 4-bit response code in header byte 4 while preserving other flags
 * (RA, AD, CD). Called when constructing responses to indicate success (NOERROR),
 * name errors (NXDOMAIN), server failures (SERVFAIL), etc.
 * 
 * @param x Pointer to struct dns_header
 * @param code RCODE value to set (NOERROR, NXDOMAIN, SERVFAIL, etc.)
 * 
 * @see NOERROR, NXDOMAIN, SERVFAIL, FORMERR, NOTIMP, REFUSED constants
 */
#define SET_RCODE(x, code) (x)->hb4 = ((x)->hb4 & ~HB4_RCODE) | code

/**
 * @def GETSHORT
 * @brief Extract 16-bit value from DNS packet and advance pointer
 * 
 * Reads a 16-bit unsigned integer from a DNS packet buffer in network byte order
 * (big-endian) and converts to host byte order. The pointer is automatically
 * advanced by 2 bytes. Used throughout rfc1035.c for parsing DNS packet fields.
 * 
 * This macro performs safe type conversion through unsigned char* to avoid
 * alignment issues and strict aliasing violations. Works correctly regardless
 * of host endianness.
 * 
 * @param s Output variable to receive the 16-bit value (u16)
 * @param cp Pointer into packet buffer (unsigned char*), advanced by 2 bytes
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = packet;
 * u16 qdcount;
 * GETSHORT(qdcount, p);  // p now points 2 bytes further
 * @endcode
 * 
 * @warning No bounds checking performed. Use CHECK_LEN before calling.
 * @see PUTSHORT for writing 16-bit values
 * @see GETLONG for 32-bit values
 */
#define GETSHORT(s, cp) { \
	unsigned char *t_cp = (unsigned char *)(cp); \
	(s) = ((u16)t_cp[0] << 8) \
	    | ((u16)t_cp[1]) \
	    ; \
	(cp) += 2; \
}

/**
 * @def GETLONG
 * @brief Extract 32-bit value from DNS packet and advance pointer
 * 
 * Reads a 32-bit unsigned integer from a DNS packet buffer in network byte order
 * (big-endian) and converts to host byte order. The pointer is automatically
 * advanced by 4 bytes. Used for TTL fields and other 32-bit DNS data.
 * 
 * This macro performs safe type conversion through unsigned char* to avoid
 * alignment issues and strict aliasing violations. Works correctly regardless
 * of host endianness.
 * 
 * @param l Output variable to receive the 32-bit value (u32)
 * @param cp Pointer into packet buffer (unsigned char*), advanced by 4 bytes
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = rdata;
 * u32 ttl;
 * GETLONG(ttl, p);  // Read TTL field, p now points 4 bytes further
 * @endcode
 * 
 * @warning No bounds checking performed. Use CHECK_LEN before calling.
 * @see PUTLONG for writing 32-bit values
 * @see GETSHORT for 16-bit values
 */
#define GETLONG(l, cp) { \
	unsigned char *t_cp = (unsigned char *)(cp); \
	(l) = ((u32)t_cp[0] << 24) \
	    | ((u32)t_cp[1] << 16) \
	    | ((u32)t_cp[2] << 8) \
	    | ((u32)t_cp[3]) \
	    ; \
	(cp) += 4; \
}

/**
 * @def PUTSHORT
 * @brief Write 16-bit value to DNS packet and advance pointer
 * 
 * Writes a 16-bit unsigned integer to a DNS packet buffer in network byte order
 * (big-endian), converting from host byte order. The pointer is automatically
 * advanced by 2 bytes. Used throughout rfc1035.c for constructing DNS responses.
 * 
 * This macro performs safe type conversion and byte ordering regardless of host
 * endianness. Writes most significant byte first (big-endian/network order).
 * 
 * @param s Value to write (u16)
 * @param cp Pointer into packet buffer (unsigned char*), advanced by 2 bytes
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = response_buffer;
 * u16 ancount = 1;
 * PUTSHORT(ancount, p);  // Write answer count, p now points 2 bytes further
 * @endcode
 * 
 * @warning No bounds checking performed. Ensure sufficient buffer space.
 * @see GETSHORT for reading 16-bit values
 * @see PUTLONG for 32-bit values
 */
#define PUTSHORT(s, cp) { \
	u16 t_s = (u16)(s); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += 2; \
}

/**
 * @def PUTLONG
 * @brief Write 32-bit value to DNS packet and advance pointer
 * 
 * Writes a 32-bit unsigned integer to a DNS packet buffer in network byte order
 * (big-endian), converting from host byte order. The pointer is automatically
 * advanced by 4 bytes. Used for TTL fields and other 32-bit DNS data.
 * 
 * This macro performs safe type conversion and byte ordering regardless of host
 * endianness. Writes most significant byte first (big-endian/network order).
 * 
 * @param l Value to write (u32)
 * @param cp Pointer into packet buffer (unsigned char*), advanced by 4 bytes
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char *p = rdata;
 * u32 ttl = 3600;  // 1 hour
 * PUTLONG(ttl, p);  // Write TTL field, p now points 4 bytes further
 * @endcode
 * 
 * @warning No bounds checking performed. Ensure sufficient buffer space.
 * @see GETLONG for reading 32-bit values
 * @see PUTSHORT for 16-bit values
 */
#define PUTLONG(l, cp) { \
	u32 t_l = (u32)(l); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += 4; \
}

/**
 * @def CHECK_LEN
 * @brief Verify sufficient buffer space for DNS packet parsing
 * 
 * Validates that a read or write operation of specified length will not exceed
 * the packet buffer bounds. This is a critical safety check used throughout
 * rfc1035.c to prevent buffer overflows when parsing untrusted DNS packets.
 * 
 * Calculates the offset from start of packet (header) to current position (pp)
 * plus the requested length (len) and ensures it doesn't exceed packet length (plen).
 * 
 * @param header Pointer to start of DNS packet (struct dns_header*)
 * @param pp Current parse position in packet (unsigned char*)
 * @param plen Total packet length in bytes (size_t)
 * @param len Number of bytes to read/write (size_t)
 * @return Non-zero (true) if operation is safe, 0 (false) if would overflow
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header*)packet;
 * unsigned char *p = packet + sizeof(struct dns_header);
 * size_t packet_len = recv_len;
 * 
 * if (CHECK_LEN(header, p, packet_len, 2)) {
 *   u16 value;
 *   GETSHORT(value, p);  // Safe to read 2 bytes
 * } else {
 *   return FORMERR;  // Packet truncated or malformed
 * }
 * @endcode
 * 
 * @warning This check must be performed before every GETSHORT, GETLONG, or
 *          direct buffer read to prevent buffer overflow vulnerabilities.
 * @see ADD_RDLEN for combined check and pointer advance
 */
#define CHECK_LEN(header, pp, plen, len) \
    ((size_t)((pp) - (unsigned char *)(header) + (len)) <= (plen))

/**
 * @def ADD_RDLEN
 * @brief Safely advance pointer if sufficient space available
 * 
 * Combines CHECK_LEN validation with pointer advancement. Checks if advancing
 * the pointer by 'len' bytes would exceed packet bounds. If safe, advances the
 * pointer and returns 1 (success). If unsafe, returns 0 without advancing pointer.
 * 
 * Typically used when skipping over RDATA sections of known length during DNS
 * packet parsing. Prevents buffer overflows from malformed RDLENGTH fields.
 * 
 * @param header Pointer to start of DNS packet (struct dns_header*)
 * @param pp Current parse position in packet (unsigned char*), advanced by len if safe
 * @param plen Total packet length in bytes (size_t)
 * @param len Number of bytes to skip (size_t)
 * @return 1 if pointer was advanced (safe), 0 if would overflow (unsafe)
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dns_header *header = (struct dns_header*)packet;
 * unsigned char *p = packet + sizeof(struct dns_header);
 * u16 rdlength;
 * GETSHORT(rdlength, p);  // Read RDATA length field
 * 
 * if (!ADD_RDLEN(header, p, packet_len, rdlength)) {
 *   return FORMERR;  // RDLENGTH would exceed packet bounds
 * }
 * // p now points past RDATA section
 * @endcode
 * 
 * @warning Essential for preventing buffer overflow from malicious RDLENGTH values.
 * @see CHECK_LEN for validation without pointer advance
 */
#define ADD_RDLEN(header, pp, plen, len) \
  (!CHECK_LEN(header, pp, plen, len) ? 0 : (((pp) += (len)), 1))

/**
 * @def NAME_ESCAPE
 * @brief Escape character for presentation format domain names
 * 
 * Character value (1, control character) used as escape prefix in dnsmasq's internal
 * presentation format for domain names. Allows representation of non-printable
 * characters and special characters in domain names.
 * 
 * ENCODING SCHEME:
 * 
 * Non-printable or special characters in domain names are encoded as two-byte
 * sequences: NAME_ESCAPE followed by (original_char + 1). The +1 offset ensures
 * that the encoding of ASCII NUL (\0) doesn't contain an embedded NUL, which
 * would prematurely terminate C strings.
 * 
 * Example: A domain containing byte 0x00 is stored as: 0x01 0x01 (NAME_ESCAPE followed by 0+1)
 * 
 * RESTRICTIONS:
 * 
 * NAME_ESCAPE value chosen to be:
 * - Not '.' (0x2E) which separates labels
 * - Not '\0' (0x00) which terminates C strings
 * - Not printable (!isprint()) to avoid confusion with actual domain content
 * 
 * This escape mechanism is internal to dnsmasq and not part of the DNS wire format.
 * Conversion between wire format and presentation format happens in extract_name()
 * and domain name processing functions in rfc1035.c and domain.c.
 * 
 * @see rfc1035.c extract_name() for wire-to-presentation conversion
 * @see domain.c for presentation format domain name handling
 */
#define NAME_ESCAPE 1
