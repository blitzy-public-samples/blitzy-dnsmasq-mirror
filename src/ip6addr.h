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
 * @file ip6addr.h
 * @brief IPv6 address manipulation macros for portable address classification
 *
 * DETAILED PURPOSE:
 * 
 * This header file provides portable IPv6 address classification and comparison macros
 * that abstract platform-specific differences in struct in6_addr implementations. Different
 * operating systems and C libraries may define struct in6_addr with varying internal
 * representations (s6_addr byte array, __in6_u union, etc.), making direct byte-level
 * access non-portable. These macros provide a consistent interface for IPv6 address
 * manipulation across all supported platforms (Linux, BSD, macOS, Solaris, Android).
 *
 * The macros defined here handle special IPv6 address types used extensively in dnsmasq's
 * DHCPv6, Router Advertisement, and SLAAC implementations. Specifically, the file provides
 * checks for Unique Local Addresses (ULA, RFC 4193 fd00::/8) and link-local addresses
 * (fe80::/10), including special-case tests for all-zero host portions which indicate
 * network prefixes rather than specific host addresses. These prefix checks are critical
 * for DHCPv6 address pool management and Router Advertisement prefix information options.
 *
 * All macros operate directly on const uint32_t pointer casts of the IPv6 address structure,
 * treating the 128-bit address as four 32-bit words in network byte order. This approach
 * ensures efficient comparison operations while maintaining portability across different
 * struct in6_addr definitions. The macros use htonl() for constant values to ensure correct
 * byte ordering on both big-endian and little-endian systems.
 *
 * KEY RESPONSIBILITIES:
 * - IN6_IS_ADDR_ULA: Identify Unique Local Addresses (RFC 4193 fd00::/8 prefix)
 * - IN6_IS_ADDR_ULA_ZERO: Identify ULA prefix with all-zero host portion (fd00::/8 network)
 * - IN6_IS_ADDR_LINK_LOCAL_ZERO: Identify link-local prefix with all-zero host (fe80::/10 network)
 *
 * DEPENDENCIES:
 * - Includes: None directly (included by files that have <netinet/in.h> for struct in6_addr)
 * - Called by: dhcp6.c (DHCPv6 address validation), radv.c (Router Advertisement prefix checks),
 *              slaac.c (SLAAC address generation), network.c (interface address classification)
 * - Calls: htonl() macro for host-to-network byte order conversion
 * - External: Requires struct in6_addr definition from <netinet/in.h> to be included first
 *
 * DATA STRUCTURES:
 * - None defined (operates on struct in6_addr passed as const pointer)
 * - Assumes struct in6_addr is 128 bits (16 bytes) accessible as uint32_t array
 *
 * COMPILE-TIME OPTIONS:
 * - None (macros are unconditionally defined for all platforms)
 * - Platform-neutral implementation works on Linux, BSD, Solaris, Android, macOS
 *
 * THREADING/CONCURRENCY:
 * - Thread-safe: All macros are pure functions with no side effects
 * - Re-entrant: No global state accessed, safe for use in signal handlers
 * - Single-process model: Used within dnsmasq's event-driven architecture
 * - No locking required: Read-only operations on caller-provided addresses
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/DHCP_V6.md for DHCPv6 address classification usage
 * @see RFC 4193 for Unique Local IPv6 Unicast Addresses specification
 * @see RFC 4291 Section 2.5.6 for link-local address format
 */


/**
 * @def IN6_IS_ADDR_ULA(a)
 * @brief Check if IPv6 address is a Unique Local Address (ULA)
 *
 * @detailed
 * Determines whether the provided IPv6 address falls within the Unique Local Address
 * (ULA) range defined by RFC 4193. ULA addresses use the fd00::/8 prefix and are
 * analogous to IPv4 private addresses (RFC 1918). This macro tests only the most
 * significant byte (first 8 bits) of the address to match the 0xfd prefix, allowing
 * both fd00::/8 and fdff::/8 ranges. ULA addresses are not routable on the global
 * Internet and are intended for local communications within a site or organization.
 *
 * The implementation casts the address pointer to uint32_t array and examines the
 * first 32-bit word in network byte order. By masking with 0xff000000 and comparing
 * to 0xfd000000, it efficiently checks the first byte without platform-specific
 * byte array access. This approach works correctly on both big-endian and little-endian
 * systems due to htonl() byte order conversion.
 *
 * Used extensively in dhcp6.c for DHCPv6 address pool validation, ensuring that
 * ULA ranges are properly handled for private network deployments. Also used in
 * radv.c for Router Advertisement prefix filtering and slaac.c for address
 * autoconfiguration decisions.
 *
 * @param a Pointer to struct in6_addr to test. Must not be NULL. The address
 *          is treated as read-only and cast to const uint32_t pointer for
 *          efficient word-level access.
 *
 * @return Non-zero (true) if address is within fd00::/8 ULA range, zero (false) otherwise.
 *         Specifically returns the result of equality comparison (typically 1 for match).
 *
 * @note Platform portability: Works on all systems regardless of struct in6_addr internal
 *       representation (s6_addr byte array, __in6_u union, etc.) by using uint32_t cast.
 * @note Performance: Single memory read of 32-bit word plus mask and compare operations.
 * @note RFC 4193 defines ULA with L bit, but this macro accepts all fd00::/8 addresses
 *       regardless of L bit value in the 8th bit position.
 *
 * @warning Caller must ensure pointer 'a' is non-NULL and points to valid struct in6_addr.
 *          No NULL checking is performed (would require function call overhead).
 * @warning Does not distinguish between locally assigned (L=1, fd00::/8) and future
 *          centrally assigned (L=0, fc00::/8) ULA addresses - only fd00::/8 matches.
 *
 * @see IN6_IS_ADDR_ULA_ZERO for checking ULA prefix with all-zero host portion
 * @see dhcp6.c dhcp6_reply() for DHCPv6 address validation usage
 * @see RFC 4193 Section 3 for Unique Local IPv6 Unicast Addresses definition
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr addr;
 * inet_pton(AF_INET6, "fd12:3456:789a:1::1", &addr);
 * if (IN6_IS_ADDR_ULA(&addr)) {
 *     // Address is ULA, handle as private address
 *     syslog(LOG_DEBUG, "DHCPv6 request for ULA address");
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4193 Section 3: Unique Local IPv6 Unicast Addresses use fc00::/7 prefix
 * - Implementation matches fd00::/8 subset (L=1, locally assigned)
 * - Does not match fc00::/8 range (L=0, reserved for future central assignment)
 *
 * THREAD SAFETY:
 * - Fully re-entrant: No global state, pure function of input argument
 * - Signal-safe: Safe to use in signal handlers (no system calls)
 * - Const-correct: Input address not modified, read-only operation
 */
#define IN6_IS_ADDR_ULA(a) \
        ((((__const uint32_t *) (a))[0] & htonl (0xff000000))                 \
         == htonl (0xfd000000))

/**
 * @def IN6_IS_ADDR_ULA_ZERO(a)
 * @brief Check if IPv6 address is exactly fd00:: (ULA prefix with all-zero host)
 *
 * @detailed
 * Tests whether the provided IPv6 address is exactly fd00:0000:0000:0000:0000:0000:0000:0000
 * (abbreviated as fd00::), representing a Unique Local Address prefix with all bits in the
 * host portion set to zero. This specific address format is used to denote ULA network
 * prefixes in DHCPv6 configuration and Router Advertisement prefix options, distinguishing
 * network identifiers from actual host addresses within the ULA range.
 *
 * The macro performs four 32-bit word comparisons: the first word must be exactly 0xfd000000
 * (matching only fd00::/8 with no subnet or interface ID bits set), and the remaining three
 * words must all be zero. This strict equality check ensures the address represents a prefix
 * boundary rather than any specific host within the ULA space. Unlike IN6_IS_ADDR_ULA which
 * matches any address in the range, this macro matches only the canonical prefix address.
 *
 * Critical for DHCPv6 address pool configuration validation (dhcp6.c) where fd00:: may be
 * used as a placeholder or default value. Also used in radv.c to identify default ULA
 * prefix announcements in Router Advertisement messages, and in configuration parsing
 * (option.c) to detect unspecified or wildcard ULA prefix entries.
 *
 * @param a Pointer to struct in6_addr to test. Must not be NULL. The address is
 *          examined as four consecutive 32-bit words in network byte order, requiring
 *          natural alignment for efficient access on most architectures.
 *
 * @return Non-zero (true) if address is exactly fd00::, zero (false) otherwise.
 *         Returns result of logical AND of four equality comparisons (1 if all match).
 *
 * @note Strict equality: This macro matches ONLY fd00::, not fd01:: or fdXX:: variants.
 *       For general ULA detection including all host addresses, use IN6_IS_ADDR_ULA instead.
 * @note Configuration usage: Commonly appears in DHCPv6 prefix delegation defaults where
 *       fd00:: signals "use ULA addressing" without specifying exact subnet.
 * @note Performance: Four 32-bit memory reads plus four comparisons and one logical AND,
 *       typically 5-10 CPU cycles on modern architectures with branch prediction.
 *
 * @warning Does not match fd00::1 or any non-zero host portion - only exact fd00:: matches.
 * @warning Does not match fc00:: (L=0 bit) or other ULA prefixes like fd12:: or fdff::.
 * @warning Pointer 'a' must be naturally aligned for uint32_t access on strict-alignment
 *          architectures (struct in6_addr typically provides this alignment).
 *
 * @see IN6_IS_ADDR_ULA for general ULA range detection (any fd00::/8 address)
 * @see IN6_IS_ADDR_LINK_LOCAL_ZERO for analogous link-local prefix check (fe80::)
 * @see dhcp6.c lease allocation for DHCPv6 prefix validation
 * @see RFC 4193 Section 3.1 for ULA prefix format specification
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr prefix;
 * inet_pton(AF_INET6, "fd00::", &prefix);
 * if (IN6_IS_ADDR_ULA_ZERO(&prefix)) {
 *     // This is the ULA prefix boundary address, not a host address
 *     my_syslog(LOG_WARNING, "DHCPv6 pool starts at ULA prefix boundary");
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4193 Section 3.1: ULA prefix format is fd00::/8 for locally assigned
 * - Implementation checks for canonical prefix address with no subnet/interface ID bits
 * - Used to identify prefix boundaries in DHCPv6 Prefix Delegation (RFC 3633)
 *
 * THREAD SAFETY:
 * - Fully re-entrant: Pure function with no side effects or global state
 * - Signal-safe: Can be used in signal handlers (no blocking operations)
 * - Const-correct: Input address is read-only, no modifications performed
 * - Cache-friendly: Sequential memory access pattern for four 32-bit words
 */
#define IN6_IS_ADDR_ULA_ZERO(a) \
        (((__const uint32_t *) (a))[0] == htonl (0xfd000000)                        \
         && ((__const uint32_t *) (a))[1] == 0                                \
         && ((__const uint32_t *) (a))[2] == 0                                \
         && ((__const uint32_t *) (a))[3] == 0)

/**
 * @def IN6_IS_ADDR_LINK_LOCAL_ZERO(a)
 * @brief Check if IPv6 address is exactly fe80:: (link-local prefix with all-zero host)
 *
 * @detailed
 * Tests whether the provided IPv6 address is exactly fe80:0000:0000:0000:0000:0000:0000:0000
 * (abbreviated as fe80::), representing the link-local address prefix with all host portion
 * bits set to zero. Link-local addresses (RFC 4291 Section 2.5.6) use the fe80::/10 prefix
 * and are valid only within a single network link, never routed beyond the local network
 * segment. This specific all-zero form indicates the prefix boundary rather than an actual
 * host interface address.
 *
 * The macro performs strict equality testing of all four 32-bit words: the first word must
 * be exactly 0xfe800000 (matching fe80::/10 with no subnet ID bits set), and words 2-4
 * must all be zero. This distinguishes the canonical prefix address from actual link-local
 * host addresses like fe80::1 or fe80::abcd:ef01:2345:6789. Link-local addresses normally
 * include an interface identifier in the lower 64 bits, so fe80:: without an interface ID
 * represents an invalid or placeholder configuration.
 *
 * Used primarily in DHCPv6 (dhcp6.c) and Router Advertisement (radv.c) code to validate
 * that link-local prefixes are properly configured before advertising or assigning addresses.
 * Also appears in network interface monitoring (network.c, netlink.c) to detect default or
 * unconfigured link-local prefix announcements. The fe80:: address itself is never assigned
 * to an interface but may appear in configuration as a wildcard or prefix placeholder.
 *
 * @param a Pointer to struct in6_addr to test. Must not be NULL. The address is interpreted
 *          as four consecutive 32-bit words in network byte order. Pointer must have natural
 *          uint32_t alignment (struct in6_addr guarantees this on all supported platforms).
 *
 * @return Non-zero (true) if address is exactly fe80::, zero (false) otherwise.
 *         Returns logical AND of four equality tests (1 when all four words match).
 *
 * @note Link-local scope: fe80::/10 addresses are never routed, valid only on local link.
 * @note RFC 4291: Link-local addresses normally have 64-bit interface identifier in lower half,
 *       so fe80:: without interface ID is unusual and typically indicates uninitialized state.
 * @note Comparison with fe80::1: The macro does NOT match fe80::1 (common default gateway),
 *       only the exact prefix boundary fe80:: with all zeros.
 * @note Performance: Identical cost to IN6_IS_ADDR_ULA_ZERO (four word comparisons),
 *       typically completes in 5-10 CPU cycles with modern branch prediction.
 *
 * @warning Does not match fe80::1, fe80::dead:beef, or any non-zero interface identifier.
 * @warning Does not match other link-local variants like fe81:: (outside fe80::/10 range).
 * @warning Pointer 'a' must be non-NULL and properly aligned for uint32_t access.
 * @warning This address is not normally assigned to interfaces; detection usually indicates
 *          configuration error or placeholder value in DHCPv6/RA settings.
 *
 * @see IN6_IS_ADDR_ULA_ZERO for analogous ULA prefix check (fd00::)
 * @see radv.c for Router Advertisement link-local prefix validation
 * @see dhcp6.c for DHCPv6 link-local address range validation
 * @see RFC 4291 Section 2.5.6 for link-local address format specification
 * @see RFC 4862 for IPv6 Stateless Address Autoconfiguration using link-local
 *
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr link_local_prefix;
 * inet_pton(AF_INET6, "fe80::", &link_local_prefix);
 * if (IN6_IS_ADDR_LINK_LOCAL_ZERO(&link_local_prefix)) {
 *     // This is the link-local prefix boundary, invalid for actual host
 *     my_syslog(LOG_WARNING, "Link-local prefix fe80:: has no interface identifier");
 * }
 * @endcode
 *
 * RFC COMPLIANCE:
 * - RFC 4291 Section 2.5.6: Link-local addresses use fe80::/10 prefix
 * - RFC 4862 Section 5.3: Link-local addresses have 64-bit interface identifier
 * - Implementation checks for prefix boundary without interface ID (unusual case)
 * - Normal link-local addresses would be fe80::interface_id, not fe80:: exactly
 *
 * SIDE EFFECTS:
 * - None: Pure read-only comparison operation
 *
 * THREAD SAFETY:
 * - Fully re-entrant: No shared state, pure function of input argument
 * - Signal-safe: Can be safely called from signal handlers (no system calls)
 * - Const-correct: Input address is not modified, read-only access
 * - Lock-free: No synchronization primitives required
 * - Cache-friendly: Sequential access to four consecutive 32-bit words
 */
#define IN6_IS_ADDR_LINK_LOCAL_ZERO(a) \
        (((__const uint32_t *) (a))[0] == htonl (0xfe800000)                  \
         && ((__const uint32_t *) (a))[1] == 0                                \
         && ((__const uint32_t *) (a))[2] == 0                                \
         && ((__const uint32_t *) (a))[3] == 0)
