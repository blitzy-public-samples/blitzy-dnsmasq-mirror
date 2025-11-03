/* ipset.c is Copyright (c) 2013 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

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
 * @file ipset.c
 * @brief Linux ipset integration for DNS-resolved address insertion
 *
 * DETAILED PURPOSE:
 * This module provides automatic insertion of DNS-resolved addresses into Linux kernel
 * ipsets, enabling firewall and routing policy enforcement based on domain names. When
 * dnsmasq resolves a DNS query for domains configured with --ipset option, the resulting
 * IP addresses are automatically added to named ipsets via the kernel's Netlink interface.
 * This allows network administrators to create dynamic firewall rules and routing policies
 * that track domain name resolution results. The implementation supports both modern
 * Netlink-based ipset protocol (kernel 2.6.32+) and legacy raw socket protocol for older
 * kernels, with automatic version detection and fallback.
 *
 * KEY RESPONSIBILITIES:
 * - ipset_init() - Initialize Netlink socket connection to ipset kernel module
 * - add_to_ipset() - Add or remove IPv4/IPv6 addresses to/from named ipset
 * - new_add_to_ipset() - Netlink-based ipset manipulation (modern kernels)
 * - old_add_to_ipset() - Raw socket ipset manipulation (legacy kernels)
 * - add_attr() - Construct Netlink attribute messages for ipset protocol
 *
 * DEPENDENCIES:
 * - dnsmasq.h - Primary header with daemon structure, network types, utility functions
 * - Linux Netlink API (linux/netlink.h) - Kernel communication for modern ipset
 * - Linux ipset kernel module - Must be loaded for ipset functionality to work
 * - Requires HAVE_IPSET and HAVE_LINUX_NETWORK compile-time flags
 *
 * DATA STRUCTURES:
 * - struct my_nlattr (lines 56-59) - Netlink attribute header for ipset messages
 * - struct my_nfgenmsg (lines 61-65) - Netfilter generic message header
 * - Global ipset_sock - File descriptor for Netlink or raw socket to ipset
 * - Global buffer - Message construction buffer for Netlink protocol
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_IPSET - Enables entire ipset integration feature (required)
 * - HAVE_LINUX_NETWORK - Linux-specific networking support (required)
 * - Entire file is conditionally compiled only when both flags are defined
 * - Without these flags, ipset functionality is unavailable
 *
 * THREADING/CONCURRENCY:
 * - Single-threaded design consistent with dnsmasq's event-driven architecture
 * - Uses global state (ipset_sock, buffer) which is safe in single-threaded context
 * - Netlink socket operations are synchronous within event loop processing
 * - No locking required as called from main thread during DNS response processing
 *
 * @copyright Copyright (c) 2013 Jason A. Donenfeld <Jason@zx2c4.com>
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#if defined(HAVE_IPSET) && defined(HAVE_LINUX_NETWORK)

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

/* We want to be able to compile against old header files
   Kernel version is handled at run-time. */

#define NFNL_SUBSYS_IPSET 6

#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_CMD_ADD 9
#define IPSET_CMD_DEL 10
#define IPSET_MAXNAMELEN 32
#define IPSET_PROTOCOL 6

#ifndef NFNETLINK_V0
#define NFNETLINK_V0    0
#endif

#ifndef NLA_F_NESTED
#define NLA_F_NESTED		(1 << 15)
#endif

#ifndef NLA_F_NET_BYTEORDER
#define NLA_F_NET_BYTEORDER	(1 << 14)
#endif

/**
 * @struct my_nlattr
 * @brief Netlink attribute header for ipset protocol messages
 *
 * This structure defines the header format for Netlink attributes used in ipset
 * communication. Netlink attributes follow a Type-Length-Value (TLV) encoding where
 * this header precedes the actual attribute data. Used to construct nested attribute
 * structures for IPSET_CMD_ADD and IPSET_CMD_DEL operations.
 *
 * LIFECYCLE:
 * - Stack-allocated as pointers into message buffer during add_attr() calls
 * - Not dynamically allocated; represents existing buffer regions
 * - Lifetime limited to single ipset operation message construction
 * - No explicit allocation or deallocation required
 *
 * MEMORY LAYOUT:
 * - Total size: 4 bytes (2 bytes length + 2 bytes type)
 * - Alignment: Natural alignment on 4-byte boundary via NL_ALIGN() macro
 * - Payload follows immediately after this header at NL_ALIGN(sizeof(struct my_nlattr))
 *
 * USAGE PATTERNS:
 * - add_attr() casts buffer regions to this type to set length and type fields
 * - Nested attributes created by setting NLA_F_NESTED flag in nla_type
 * - Used for IPSET_ATTR_PROTOCOL, IPSET_ATTR_SETNAME, IPSET_ATTR_DATA, IPSET_ATTR_IP
 */
struct my_nlattr {
        __u16           nla_len;   /**< Attribute length including header and payload, NL_ALIGN'd */
        __u16           nla_type;  /**< Attribute type (IPSET_ATTR_*), may include NLA_F_NESTED flag */
};

/**
 * @struct my_nfgenmsg
 * @brief Netfilter generic message header for ipset Netlink protocol
 *
 * This structure defines the generic Netfilter message header that follows the Netlink
 * message header (struct nlmsghdr) in ipset protocol messages. It specifies the address
 * family and protocol version for the ipset operation. Part of the NFNETLINK subsystem
 * used by ipset for kernel communication.
 *
 * LIFECYCLE:
 * - Embedded within message buffer immediately after struct nlmsghdr
 * - Initialized once per ipset add/delete operation in new_add_to_ipset()
 * - Stack-allocated as pointer into buffer, not separately allocated
 * - Lifetime limited to single message transmission
 *
 * MEMORY LAYOUT:
 * - Total size: 4 bytes (1 byte family + 1 byte version + 2 bytes resource id)
 * - Position: Immediately after nlmsghdr at offset NL_ALIGN(sizeof(struct nlmsghdr))
 * - Alignment: Natural alignment via NL_ALIGN() positioning in buffer
 * - Followed by Netlink attributes for ipset-specific data
 *
 * USAGE PATTERNS:
 * - nfgen_family set to AF_INET or AF_INET6 based on address type
 * - version always set to NFNETLINK_V0 (0) for compatibility
 * - res_id set to 0 (unused by ipset protocol)
 * - Accessed as cast pointer into buffer in new_add_to_ipset() lines 123-127
 */
struct my_nfgenmsg {
        __u8  nfgen_family;  /**< Address family: AF_INET or AF_INET6 for IPv4/IPv6 addresses */
        __u8  version;       /**< Netfilter netlink version: always NFNETLINK_V0 (0) */
        __be16    res_id;    /**< Resource ID: set to 0, unused by ipset protocol */
};


/* data structure size in here is fixed */
#define BUFF_SZ 256

#define NL_ALIGN(len) (((len)+3) & ~(3))
static const struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
static int ipset_sock, old_kernel;
static char *buffer;

/**
 * @brief Add Netlink attribute to ipset message
 *
 * @detailed
 * Appends a Netlink attribute to an ipset protocol message under construction. Creates
 * a struct my_nlattr header at the current end of the message, copies the attribute
 * payload data, and updates the message length. All lengths are aligned to 4-byte
 * boundaries per Netlink protocol requirements. Used to build complex nested attribute
 * structures for IPSET_CMD_ADD and IPSET_CMD_DEL messages.
 *
 * @param nlh Netlink message header being constructed, nlmsg_len updated with attribute size
 * @param type Attribute type identifier (IPSET_ATTR_PROTOCOL, IPSET_ATTR_SETNAME, etc.), may include flag bits
 * @param len Length of attribute payload data in bytes, not including header
 * @param data Pointer to attribute payload data to be copied, must be valid for len bytes
 *
 * @return void (no return value)
 *
 * @note Assumes sufficient space in buffer pointed to by nlh for attribute header and data
 * @note Applies NL_ALIGN() padding to all lengths per Netlink protocol specification
 * @note Attribute header placed at NL_ALIGN(nlh->nlmsg_len), data at NL_ALIGN(sizeof(struct my_nlattr)) offset
 *
 * @warning No bounds checking performed, caller must ensure buffer has BUFF_SZ (256) bytes available
 * @warning Buffer overflow possible if excessive attributes added, stay within BUFF_SZ limit
 *
 * @see new_add_to_ipset() for usage constructing complete ipset messages
 * @see struct my_nlattr for attribute header format
 *
 * EXAMPLE USAGE:
 * @code
 * struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
 * nlh->nlmsg_len = NL_ALIGN(sizeof(struct nlmsghdr));
 * uint8_t proto = IPSET_PROTOCOL;
 * add_attr(nlh, IPSET_ATTR_PROTOCOL, sizeof(proto), &proto);
 * add_attr(nlh, IPSET_ATTR_SETNAME, strlen("blacklist") + 1, "blacklist");
 * @endcode
 *
 * SIDE EFFECTS:
 * - Modifies buffer contents at nlh + nlmsg_len offset
 * - Updates nlh->nlmsg_len by adding NL_ALIGN(payload_len) bytes
 * - Copies len bytes from data pointer into message buffer
 *
 * THREAD SAFETY:
 * - Not thread-safe: modifies global buffer state
 * - Safe in dnsmasq's single-threaded event loop context
 * - Re-entrant safe if different nlh pointers and buffers used
 */
static inline void add_attr(struct nlmsghdr *nlh, uint16_t type, size_t len, const void *data)
{
  struct my_nlattr *attr = (void *)nlh + NL_ALIGN(nlh->nlmsg_len);
  uint16_t payload_len = NL_ALIGN(sizeof(struct my_nlattr)) + len;
  attr->nla_type = type;
  attr->nla_len = payload_len;
  memcpy((void *)attr + NL_ALIGN(sizeof(struct my_nlattr)), data, len);
  nlh->nlmsg_len += NL_ALIGN(payload_len);
}

/**
 * @brief Initialize Netlink connection to ipset kernel module
 *
 * @detailed
 * Establishes communication channel with Linux kernel ipset subsystem. Detects kernel
 * version to determine whether to use modern Netlink protocol (kernel 2.6.32+) or
 * legacy raw socket protocol (older kernels). For modern kernels, creates AF_NETLINK
 * socket with NETLINK_NETFILTER protocol and binds to kernel, allocating message buffer.
 * For legacy kernels, creates AF_INET raw socket with IPPROTO_RAW. Terminates dnsmasq
 * with error if socket creation or binding fails, as ipset functionality was explicitly
 * requested via configuration.
 *
 * @return void (no return value on success, terminates process on failure via die())
 *
 * @note Must be called during dnsmasq initialization before any DNS resolution occurs
 * @note Requires ipset kernel module to be loaded (modprobe ip_set)
 * @note Sets global old_kernel flag based on daemon->kernel_version comparison
 * @note Sets global ipset_sock file descriptor for subsequent add_to_ipset() calls
 * @note Allocates global buffer (BUFF_SZ = 256 bytes) for Netlink message construction
 *
 * @warning Calls die() to terminate dnsmasq if socket creation fails
 * @warning Requires CAP_NET_ADMIN capability for Netlink socket creation
 * @warning Legacy mode (old_kernel) only supports IPv4 addresses, not IPv6
 *
 * @see add_to_ipset() for address insertion using initialized socket
 * @see die() in dnsmasq.c for fatal error handling
 *
 * EXAMPLE USAGE:
 * @code
 * // Called from dnsmasq.c main() initialization sequence
 * if (daemon->ipset_names)
 *   ipset_init();
 * // Now ipset_sock is ready for add_to_ipset() operations
 * @endcode
 *
 * RFC COMPLIANCE:
 * N/A - Linux-specific kernel interface, not RFC-defined protocol
 *
 * SIDE EFFECTS:
 * - Sets global old_kernel flag (1 for kernel < 2.6.32, 0 otherwise)
 * - Sets global ipset_sock file descriptor (retained for daemon lifetime)
 * - Allocates global buffer via safe_malloc() for Netlink messages
 * - Binds Netlink socket to kernel, establishing persistent connection
 * - Terminates process via die() if initialization fails
 *
 * THREAD SAFETY:
 * - Not thread-safe: sets global state (old_kernel, ipset_sock, buffer)
 * - Safe in dnsmasq's single-threaded initialization context
 * - Must complete before event loop processes any DNS queries
 */
void ipset_init(void)
{
  old_kernel = (daemon->kernel_version < KERNEL_VERSION(2,6,32));
  
  if (old_kernel && (ipset_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) != -1)
    return;
  
  if (!old_kernel && 
      (buffer = safe_malloc(BUFF_SZ)) &&
      (ipset_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)) != -1 &&
      (bind(ipset_sock, (struct sockaddr *)&snl, sizeof(snl)) != -1))
    return;
  
  die (_("failed to create IPset control socket: %s"), NULL, EC_MISC);
}

/**
 * @brief Add or remove IP address from ipset using Netlink protocol (modern kernels)
 *
 * @detailed
 * Constructs and sends a Netlink message to add or delete an IPv4 or IPv6 address from
 * a named ipset in the kernel. Uses NFNETLINK IPSET subsystem protocol with nested
 * attributes to specify set name, protocol version, and address data. Builds complete
 * Netlink message in global buffer with proper alignment, sends via ipset_sock, and
 * retries on EINTR. Supports both IPv4 (AF_INET) and IPv6 (AF_INET6) address families.
 * This is the modern ipset implementation for kernels 2.6.32 and later.
 *
 * @param setname Name of ipset to modify, must exist in kernel (max IPSET_MAXNAMELEN-1 chars)
 * @param ipaddr IP address to add or remove, union supports both IPv4 (addr4) and IPv6 (addr6)
 * @param af Address family: AF_INET for IPv4 or AF_INET6 for IPv6
 * @param remove Operation flag: 0 to add address (IPSET_CMD_ADD), non-zero to remove (IPSET_CMD_DEL)
 *
 * @return 0 on success, -1 on failure with errno set
 * @retval 0 Address successfully added to or removed from ipset
 * @retval -1 Operation failed: setname too long (ENAMETOOLONG), or Netlink send error
 *
 * @note Requires ipset_init() called first to establish ipset_sock and allocate buffer
 * @note Set must already exist in kernel (created via ipset create command)
 * @note Uses retry_send() to handle interrupted system calls (EINTR)
 * @note Message construction uses nested attributes: DATA contains IP which contains address
 *
 * @warning Setname length not validated by kernel if within IPSET_MAXNAMELEN, may fail silently
 * @warning No verification that address was actually added, relies on errno check
 * @warning Netlink socket must have CAP_NET_ADMIN capability
 *
 * @see add_to_ipset() for public API with flags parameter and error logging
 * @see old_add_to_ipset() for legacy kernel implementation
 * @see add_attr() for Netlink attribute construction helper
 *
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * inet_pton(AF_INET, "192.0.2.1", &addr.addr4);
 * if (new_add_to_ipset("blacklist", &addr, AF_INET, 0) == 0)
 *   // Address 192.0.2.1 successfully added to blacklist ipset
 * @endcode
 *
 * RFC COMPLIANCE:
 * N/A - Linux-specific Netlink protocol, not RFC-defined
 *
 * SIDE EFFECTS:
 * - Modifies global buffer contents (zeroed and rebuilt for each call)
 * - Sends Netlink message to kernel via ipset_sock, modifying kernel ipset state
 * - Sets errno on failure (ENAMETOOLONG, or sendto() errors)
 * - May block on sendto() (typically non-blocking, but depends on socket buffer)
 *
 * THREAD SAFETY:
 * - Not thread-safe: uses global buffer for message construction
 * - Safe in dnsmasq's single-threaded event loop context
 * - Re-entrant only if called with different buffer (not the case here)
 */
static int new_add_to_ipset(const char *setname, const union all_addr *ipaddr, int af, int remove)
{
  struct nlmsghdr *nlh;
  struct my_nfgenmsg *nfg;
  struct my_nlattr *nested[2];
  uint8_t proto;
  int addrsz = (af == AF_INET6) ? IN6ADDRSZ : INADDRSZ;

  if (strlen(setname) >= IPSET_MAXNAMELEN) 
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  
  memset(buffer, 0, BUFF_SZ);

  nlh = (struct nlmsghdr *)buffer;
  nlh->nlmsg_len = NL_ALIGN(sizeof(struct nlmsghdr));
  nlh->nlmsg_type = (remove ? IPSET_CMD_DEL : IPSET_CMD_ADD) | (NFNL_SUBSYS_IPSET << 8);
  nlh->nlmsg_flags = NLM_F_REQUEST;
  
  nfg = (struct my_nfgenmsg *)(buffer + nlh->nlmsg_len);
  nlh->nlmsg_len += NL_ALIGN(sizeof(struct my_nfgenmsg));
  nfg->nfgen_family = af;
  nfg->version = NFNETLINK_V0;
  nfg->res_id = htons(0);
  
  proto = IPSET_PROTOCOL;
  add_attr(nlh, IPSET_ATTR_PROTOCOL, sizeof(proto), &proto);
  add_attr(nlh, IPSET_ATTR_SETNAME, strlen(setname) + 1, setname);
  nested[0] = (struct my_nlattr *)(buffer + NL_ALIGN(nlh->nlmsg_len));
  nlh->nlmsg_len += NL_ALIGN(sizeof(struct my_nlattr));
  nested[0]->nla_type = NLA_F_NESTED | IPSET_ATTR_DATA;
  nested[1] = (struct my_nlattr *)(buffer + NL_ALIGN(nlh->nlmsg_len));
  nlh->nlmsg_len += NL_ALIGN(sizeof(struct my_nlattr));
  nested[1]->nla_type = NLA_F_NESTED | IPSET_ATTR_IP;
  add_attr(nlh, 
	   (af == AF_INET ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER,
	   addrsz, ipaddr);
  nested[1]->nla_len = (void *)buffer + NL_ALIGN(nlh->nlmsg_len) - (void *)nested[1];
  nested[0]->nla_len = (void *)buffer + NL_ALIGN(nlh->nlmsg_len) - (void *)nested[0];
	
  while (retry_send(sendto(ipset_sock, buffer, nlh->nlmsg_len, 0,
			   (struct sockaddr *)&snl, sizeof(snl))));
								    
  return errno == 0 ? 0 : -1;
}

/**
 * @brief Add or remove IPv4 address from ipset using raw socket protocol (legacy kernels)
 *
 * @detailed
 * Manipulates ipsets on older Linux kernels (< 2.6.32) using raw socket getsockopt/setsockopt
 * interface. First queries kernel via getsockopt (SOL_IP, option 83) to retrieve ipset index
 * by name, then adds or removes the IPv4 address via setsockopt with the same option number.
 * This is the legacy ipset protocol replaced by Netlink in kernel 2.6.32. Only supports IPv4
 * addresses; IPv6 requires modern Netlink protocol. Uses hard-coded protocol version 3 and
 * operation codes 0x101 (add) and 0x102 (remove).
 *
 * @param setname Name of ipset to modify, must exist in kernel (max sizeof name field - 1 chars)
 * @param ipaddr IP address to add or remove, only addr4.s_addr IPv4 field used (IPv6 unsupported)
 * @param remove Operation flag: 0 to add address (op 0x101), non-zero to remove (op 0x102)
 *
 * @return 0 on success, -1 on failure with errno set
 * @retval 0 Address successfully added to or removed from ipset
 * @retval -1 Operation failed: setname too long (ENAMETOOLONG), ipset not found, or permission denied
 *
 * @note Only supports IPv4 addresses, IPv6 results in EAFNOSUPPORT from caller
 * @note Requires ipset_init() called first to create ipset_sock raw socket
 * @note Set must already exist in kernel (created via ipset command)
 * @note Hard-coded for ipset protocol version 3 (req_adt_get.version = 3)
 * @note Uses SOL_IP socket option 83 for both query and manipulation
 *
 * @warning Deprecated protocol: only used for kernel versions < 2.6.32
 * @warning IPv6 completely unsupported in legacy protocol
 * @warning Operation codes 0x10 (query), 0x101 (add), 0x102 (remove) are magic numbers
 * @warning No capability enforcement in code, relies on kernel permission checks
 *
 * @see add_to_ipset() for public API that selects old vs new implementation
 * @see new_add_to_ipset() for modern Netlink-based implementation
 *
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * inet_pton(AF_INET, "198.51.100.1", &addr.addr4);
 * if (old_add_to_ipset("whitelist", &addr, 0) == 0)
 *   // Address 198.51.100.1 added to whitelist on legacy kernel
 * @endcode
 *
 * RFC COMPLIANCE:
 * N/A - Linux-specific raw socket protocol, not RFC-defined
 *
 * SIDE EFFECTS:
 * - Queries kernel via getsockopt() to retrieve ipset index (read-only kernel query)
 * - Modifies kernel ipset state via setsockopt() (add or remove address)
 * - Sets errno on failure (ENAMETOOLONG, ENOENT for missing set, EPERM, etc.)
 * - IP address converted from network byte order (ntohl) for raw socket protocol
 *
 * THREAD SAFETY:
 * - Thread-safe: uses only stack-local structures (req_adt_get, req_adt)
 * - Safe in dnsmasq's single-threaded event loop context
 * - Uses global ipset_sock but socket operations are atomic at kernel level
 */
static int old_add_to_ipset(const char *setname, const union all_addr *ipaddr, int remove)
{
  socklen_t size;
  struct ip_set_req_adt_get {
    unsigned op;
    unsigned version;
    union {
      char name[IPSET_MAXNAMELEN];
      uint16_t index;
    } set;
    char typename[IPSET_MAXNAMELEN];
  } req_adt_get;
  struct ip_set_req_adt {
    unsigned op;
    uint16_t index;
    uint32_t ip;
  } req_adt;
  
  if (strlen(setname) >= sizeof(req_adt_get.set.name)) 
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  
  req_adt_get.op = 0x10;
  req_adt_get.version = 3;
  strcpy(req_adt_get.set.name, setname);
  size = sizeof(req_adt_get);
  if (getsockopt(ipset_sock, SOL_IP, 83, &req_adt_get, &size) < 0)
    return -1;
  req_adt.op = remove ? 0x102 : 0x101;
  req_adt.index = req_adt_get.set.index;
  req_adt.ip = ntohl(ipaddr->addr4.s_addr);
  if (setsockopt(ipset_sock, SOL_IP, 83, &req_adt, sizeof(req_adt)) < 0)
    return -1;
  
  return 0;
}

/**
 * @brief Add or remove IP address from named ipset (public API)
 *
 * @detailed
 * Public interface for inserting DNS-resolved addresses into Linux kernel ipsets. Determines
 * address family from flags parameter, selects appropriate protocol implementation based on
 * kernel version (Netlink for modern, raw socket for legacy), and logs errors on failure.
 * This is the main entry point called by dnsmasq's DNS resolution code when --ipset option
 * is configured. Automatically rejects IPv6 addresses on legacy kernels (< 2.6.32) with
 * EAFNOSUPPORT error. Provides unified error logging via my_syslog() for troubleshooting.
 *
 * @param setname Name of target ipset in kernel, must exist (created via ipset create command)
 * @param ipaddr IP address to add or remove, union supports IPv4 addr4 and IPv6 addr6 members
 * @param flags Address family flags: F_IPV6 for IPv6, 0 for IPv4 (from DNS query result)
 * @param remove Operation mode: 0 to add address, non-zero to remove address from set
 *
 * @return 0 on success, -1 on failure with errno set and error logged
 * @retval 0 Address successfully added to or removed from ipset
 * @retval -1 Operation failed: IPv6 on legacy kernel (EAFNOSUPPORT), setname invalid, or protocol error
 *
 * @note Called from DNS response processing when domain matches --ipset configuration
 * @note Requires ipset_init() called during dnsmasq initialization
 * @note Logs all failures to syslog at LOG_ERR level with setname and strerror(errno)
 * @note Legacy kernels (< 2.6.32) reject IPv6 addresses before attempting operation
 *
 * @warning Blocking operation: sendto() for Netlink or setsockopt() may block briefly
 * @warning No validation that setname exists in kernel before attempting operation
 * @warning Error logged but not propagated beyond return code, DNS resolution continues
 *
 * @see ipset_init() for initialization of ipset socket connection
 * @see new_add_to_ipset() for Netlink protocol implementation (modern kernels)
 * @see old_add_to_ipset() for raw socket implementation (legacy kernels)
 * @see my_syslog() in log.c for error logging
 *
 * EXAMPLE USAGE:
 * @code
 * // After DNS resolution of example.com to 203.0.113.1
 * union all_addr resolved_addr;
 * inet_pton(AF_INET, "203.0.113.1", &resolved_addr.addr4);
 * if (add_to_ipset("blocked_domains", &resolved_addr, 0, 0) == 0)
 *   // example.com's IP now in blocked_domains ipset for firewall rules
 * @endcode
 *
 * EXAMPLE USAGE (IPv6):
 * @code
 * union all_addr resolved_addr6;
 * inet_pton(AF_INET6, "2001:db8::1", &resolved_addr6.addr6);
 * if (add_to_ipset("allowed_v6", &resolved_addr6, F_IPV6, 0) == -1)
 *   // Error logged to syslog if legacy kernel or other failure
 * @endcode
 *
 * RFC COMPLIANCE:
 * N/A - Linux-specific kernel integration, not RFC-defined protocol
 *
 * SIDE EFFECTS:
 * - Modifies Linux kernel ipset contents (adds or removes IP address)
 * - Logs error message to syslog via my_syslog() on failure
 * - Sets errno on failure (EAFNOSUPPORT for IPv6 on old kernel, or protocol errors)
 * - Does not affect DNS response sent to client (ipset failure doesn't block DNS)
 *
 * THREAD SAFETY:
 * - Not thread-safe: calls old_add_to_ipset or new_add_to_ipset which use global state
 * - Safe in dnsmasq's single-threaded event loop architecture
 * - Called during DNS response processing in main event thread
 */
int add_to_ipset(const char *setname, const union all_addr *ipaddr, int flags, int remove)
{
  int ret = 0, af = AF_INET;

  if (flags & F_IPV6)
    {
      af = AF_INET6;
      /* old method only supports IPv4 */
      if (old_kernel)
	{
	  errno = EAFNOSUPPORT ;
	  ret = -1;
	}
    }
  
  if (ret != -1) 
    ret = old_kernel ? old_add_to_ipset(setname, ipaddr, remove) : new_add_to_ipset(setname, ipaddr, af, remove);

  if (ret == -1)
     my_syslog(LOG_ERR, _("failed to update ipset %s: %s"), setname, strerror(errno));

  return ret;
}

#endif
