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
 * @file dnsmasq.h
 * @brief Primary type definitions and function prototypes for dnsmasq daemon
 *
 * DETAILED PURPOSE:
 * =================
 * This is the central header file for dnsmasq, defining all shared data structures,
 * function prototypes, macros, and constants used across the entire codebase. Every
 * C source file in dnsmasq includes this header, making it the definitive contract
 * between modules. This header establishes the runtime type system for dnsmasq's
 * single-process, event-driven architecture.
 *
 * The file defines the complete type hierarchy for dnsmasq's core services:
 * - DNS forwarding and caching (struct server, struct frec, struct crec)
 * - DHCPv4/v6 address allocation (struct dhcp_lease, struct dhcp_context, struct dhcp_config)
 * - Network interface management (struct irec, struct listener, struct iname)
 * - Configuration and runtime state (extern struct daemon - the global state container)
 * - Protocol-specific structures for DNS, DHCP, DNSSEC, TFTP, Router Advertisement
 *
 * This header also provides platform abstraction types (union all_addr, union mysockaddr)
 * that allow IPv4/IPv6 dual-stack operation throughout the codebase without conditional
 * compilation at call sites.
 *
 * KEY RESPONSIBILITIES:
 * =====================
 * - Define struct daemon (global daemon state container with ~100 members) at line 1099
 * - Define network address abstractions (union all_addr line 303, union mysockaddr line 669)
 * - Define DNS subsystem types (struct server line 575, struct frec line 744, struct crec line 465)
 * - Define DHCP subsystem types (struct dhcp_lease line 799, struct dhcp_context line 994)
 * - Define event system constants (EVENT_RELOAD, EVENT_TERM, etc. lines 175-200)
 * - Define runtime option flags (OPT_* constants lines 211-282)
 * - Declare external function prototypes for all public APIs across all modules
 * - Provide utility macros (option_bool, countof, MIN) for code consistency
 *
 * DEPENDENCIES:
 * =============
 * Includes: config.h (compile-time feature configuration), ip6addr.h (IPv6 utilities),
 *           metrics.h (Prometheus metrics), dns-protocol.h, dhcp-protocol.h, dhcp6-protocol.h,
 *           radv-protocol.h (protocol-specific packet structures)
 * Included By: ALL C source files in dnsmasq (dnsmasq.c, forward.c, cache.c, dhcp.c, etc.)
 * External: Extensive system headers for networking (sys/socket.h, netinet/in.h, arpa/inet.h),
 *           process management (unistd.h, signal.h), and platform-specific headers
 *
 * DATA STRUCTURES (Key Structures with Line Numbers):
 * ====================================================
 * struct event_desc (line 171) - Async event queue descriptors for signal-to-event conversion
 * union all_addr (line 303) - Universal address container for IPv4/IPv6/CNAME/DNSSEC data
 * struct crec (line 465) - DNS cache record with hash chain, LRU list, TTL, RR data
 * struct serverfd (line 555) - File descriptor tracking for upstream DNS servers
 * struct server (line 575) - Upstream DNS server with domain specificity and health metrics
 * struct irec (line 633) - Interface record for network interface enumeration
 * struct listener (line 641) - Socket listener with poll fd and protocol type
 * struct frec (line 744) - Forward record tracking DNS query transaction lifecycle
 * struct dhcp_lease (line 799) - DHCP lease state with MAC, IP, hostname, expiry timestamp
 * struct dhcp_config (line 860) - Static DHCP host configuration (reservations)
 * struct dhcp_context (line 994) - DHCP address pool/range configuration
 * extern struct daemon (line 1099) - Global daemon state accessed via global pointer
 *
 * Additional structures: struct bogus_addr (337), struct doctor (344), struct mx_srv_record (349),
 * struct naptr (356), struct txt_record (372), struct ptr_record (380), struct cname (385),
 * struct ds_config (391), struct addrlist (404), struct auth_zone (414), struct host_record (429),
 * struct interface_name (445), struct blockdata (460), struct randfd (563), struct rebind_domain (616),
 * struct ipsets (621), struct allowlist (627), struct iname (649), struct mysubnet (657),
 * struct resolvc (664), plus DHCPv6-specific structures if HAVE_DHCP6 enabled
 *
 * COMPILE-TIME OPTIONS:
 * =====================
 * Affected by numerous HAVE_* feature gates from config.h:
 * - HAVE_DHCP: Includes DHCPv4 structures (struct dhcp_lease, dhcp_context, dhcp_config)
 * - HAVE_DHCP6: Includes DHCPv6 and Router Advertisement structures
 * - HAVE_DNSSEC: Includes DNSSEC validation structures (key, ds fields in union all_addr)
 * - HAVE_TFTP: Includes TFTP server structures  
 * - HAVE_AUTH: Includes authoritative DNS structures (struct auth_zone)
 * - HAVE_DBUS: Enables D-Bus control interface flag (OPT_DBUS)
 * - HAVE_UBUS: Enables ubus control interface flag (OPT_UBUS)
 * - HAVE_CONNTRACK: Enables connection tracking integration
 * - HAVE_SCRIPT/HAVE_LUASCRIPT: Enables lease-change script structures
 * - Platform-specific: HAVE_LINUX_NETWORK, HAVE_BSD_NETWORK, HAVE_SOLARIS_NETWORK
 *
 * THREADING/CONCURRENCY:
 * ======================
 * All structures defined in this header are designed for single-threaded, event-driven
 * operation using poll()-based event loop (see dnsmasq.c event_loop()). The global
 * struct daemon pointer provides shared state accessed by all modules without locking.
 * Signal handlers use async-signal-safe operations only, queuing events via self-pipe
 * pattern for processing in main event loop. No pthread synchronization primitives used.
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * @see docs/ARCHITECTURE.md for system architecture overview
 * @see config.h for compile-time configuration constants and feature gates
 */

#define COPYRIGHT "Copyright (c) 2000-2022 Simon Kelley"

/* We do defines that influence behavior of stdio.h, so complain
   if included too early. */
#ifdef _STDIO_H
#  error "Header file stdio.h included too early!"
#endif 

#ifndef NO_LARGEFILE
/* Ensure we can use files >2GB (log files may grow this big) */
#  define _LARGEFILE_SOURCE 1
#  define _FILE_OFFSET_BITS 64
#endif

/* Get linux C library versions and define _GNU_SOURCE for kFreeBSD. */
#if defined(__linux__) || defined(__GLIBC__)
#  ifndef __ANDROID__
#      define _GNU_SOURCE
#  endif
#  include <features.h> 
#endif

/* Need these defined early */
#if defined(__sun) || defined(__sun__)
#  define _XPG4_2
#  define __EXTENSIONS__
#endif

#if (defined(__GNUC__) && __GNUC__ >= 3) || defined(__clang__)
#define ATTRIBUTE_NORETURN __attribute__ ((noreturn))
#else
#define ATTRIBUTE_NORETURN
#endif

/* get these before config.h  for IPv6 stuff... */
#include <sys/types.h> 
#include <sys/socket.h>

#ifdef __APPLE__
/* Define before netinet/in.h to select API. OSX Lion onwards. */
#  define __APPLE_USE_RFC_3542
#endif
#include <netinet/in.h>

/* Also needed before config.h. */
#include <getopt.h>

#include "config.h"
#include "ip6addr.h"
#include "metrics.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define countof(x)      (long)(sizeof(x) / sizeof(x[0]))
#define MIN(a,b)        ((a) < (b) ? (a) : (b))

#include "dns-protocol.h"
#include "dhcp-protocol.h"
#ifdef HAVE_DHCP6
#include "dhcp6-protocol.h"
#include "radv-protocol.h"
#endif

#define gettext_noop(S) (S)
#ifndef LOCALEDIR
#  define _(S) (S)
#else
#  include <libintl.h>
#  include <locale.h>   
#  define _(S) gettext(S)
#endif

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#if defined(HAVE_SOLARIS_NETWORK)
#  include <sys/sockio.h>
#endif
#include <poll.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/un.h>
#include <limits.h>
#include <net/if.h>
#if defined(HAVE_SOLARIS_NETWORK) && !defined(ifr_mtu)
/* Some solaris net/if./h omit this. */
#  define ifr_mtu  ifr_ifru.ifru_metric
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <stddef.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__sun__) || defined (__sun) || defined (__ANDROID__)
#  include <netinet/if_ether.h>
#else
#  include <net/ethernet.h>
#endif
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <syslog.h>
#include <dirent.h>
#ifndef HAVE_LINUX_NETWORK
#  include <net/if_dl.h>
#endif

#if defined(HAVE_LINUX_NETWORK)
#include <linux/version.h>
#include <linux/sockios.h>
#include <linux/capability.h>
/* There doesn't seem to be a universally-available 
   userspace header for these. */
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, cap_user_data_t data);
#define LINUX_CAPABILITY_VERSION_1  0x19980330
#define LINUX_CAPABILITY_VERSION_2  0x20071026
#define LINUX_CAPABILITY_VERSION_3  0x20080522

#include <sys/prctl.h>
#elif defined(HAVE_SOLARIS_NETWORK)
#include <priv.h>
#endif

/* Backwards compat with 2.83 */
#if defined(HAVE_NETTLEHASH)
#  define HAVE_CRYPTOHASH
#endif
#if defined(HAVE_DNSSEC) || defined(HAVE_CRYPTOHASH)
#  include <nettle/nettle-meta.h>
#endif

/* daemon is function in the C library.... */
#define daemon dnsmasq_daemon

#define ADDRSTRLEN INET6_ADDRSTRLEN

/**
 * @struct event_desc
 * @brief Asynchronous event descriptor for signal-to-event conversion
 *
 * Event descriptors are used in dnsmasq's signal handling system to safely queue
 * events from signal handler context to the main event loop via self-pipe pattern.
 * Signal handlers (which must use only async-signal-safe functions) write event_desc
 * structures to a pipe, which the main poll() loop reads and processes.
 *
 * LIFECYCLE: Stack-allocated in signal handlers, written to event pipe, read by
 * event loop in dnsmasq.c event_loop(). Not dynamically allocated.
 *
 * MEMORY LAYOUT: 12 bytes on most platforms (3 × 4-byte integers). Kept small
 * for efficient pipe I/O.
 *
 * USAGE PATTERN: Signal handler calls async_event() passing event type and optional
 * data, which constructs event_desc and writes to self-pipe. Main loop reads from
 * pipe and dispatches to appropriate handler based on event field.
 *
 * @var event_desc::event
 * Event type code (EVENT_RELOAD, EVENT_TERM, EVENT_ALARM, etc.). Determines which
 * handler function is called in main event loop. See EVENT_* constants below.
 *
 * @var event_desc::data
 * Optional event-specific data payload. For EVENT_CHILD, contains child PID. For
 * EVENT_ALARM, contains alarm type. For EVENT_NEWADDR/EVENT_NEWROUTE, unused.
 *
 * @var event_desc::msg_sz
 * Size of additional message data if event carries variable-length payload.
 * Typically 0 for most event types.
 *
 * @see dnsmasq.c async_event() for event queuing from signal context
 * @see dnsmasq.c event_loop() for event dispatch
 */
struct event_desc {
  int event, data, msg_sz;
};

/** @def EVENT_RELOAD
 * @brief Configuration reload signal (SIGHUP received)
 * Triggers re-reading of configuration files, /etc/hosts, and upstream server list.
 * Handled in dnsmasq.c sig_handler() → event_loop() → clear_cache_and_reload().
 */
#define EVENT_RELOAD     1

/** @def EVENT_DUMP
 * @brief Cache dump signal (SIGUSR1 received)
 * Triggers dumping of cache statistics and contents to syslog for debugging.
 */
#define EVENT_DUMP       2

/** @def EVENT_ALARM
 * @brief Timer expiry alarm (SIGALRM received)
 * Used for periodic tasks like lease expiry checks, upstream server health checks.
 */
#define EVENT_ALARM      3

/** @def EVENT_TERM
 * @brief Termination signal (SIGTERM or SIGINT received)
 * Initiates graceful shutdown, flushing lease file and releasing resources.
 */
#define EVENT_TERM       4

/** @def EVENT_CHILD
 * @brief Child process completion (SIGCHLD received)
 * Handles completion of helper scripts (lease-change, auth-zone update) and TCP children.
 */
#define EVENT_CHILD      5

/** @def EVENT_REOPEN
 * @brief Log file rotation (SIGUSR2 received)
 * Closes and reopens log files for logrotate integration.
 */
#define EVENT_REOPEN     6

/** @def EVENT_EXITED
 * @brief Helper script exited normally
 * Queued when lease-change script completes successfully.
 */
#define EVENT_EXITED     7

/** @def EVENT_KILLED
 * @brief Helper script terminated by signal
 * Indicates script was killed (SIGKILL, SIGSEGV, etc.).
 */
#define EVENT_KILLED     8

/** @def EVENT_EXEC_ERR
 * @brief Helper script exec() failed
 * Script binary not found or not executable.
 */
#define EVENT_EXEC_ERR   9

/** @def EVENT_PIPE_ERR
 * @brief Event pipe communication failure
 * Self-pipe used for signal-to-event conversion experienced I/O error.
 */
#define EVENT_PIPE_ERR   10

/** @def EVENT_USER_ERR
 * @brief Failed to drop privileges to configured user
 * Unable to switch to user specified by --user option.
 */
#define EVENT_USER_ERR   11

/** @def EVENT_CAP_ERR
 * @brief Linux capability manipulation failed
 * capset() failed when dropping capabilities after initialization (Linux only).
 */
#define EVENT_CAP_ERR    12

/** @def EVENT_PIDFILE
 * @brief PID file creation failed
 * Unable to write daemon PID to configured PID file location.
 */
#define EVENT_PIDFILE    13

/** @def EVENT_HUSER_ERR
 * @brief Helper process user switch failed
 * Unable to drop privileges in helper/script process.
 */
#define EVENT_HUSER_ERR  14

/** @def EVENT_GROUP_ERR
 * @brief Failed to set supplementary groups
 * setgroups() failed when dropping privileges.
 */
#define EVENT_GROUP_ERR  15

/** @def EVENT_DIE
 * @brief Fatal error requiring immediate termination
 * Unrecoverable error condition encountered, must exit.
 */
#define EVENT_DIE        16

/** @def EVENT_LOG_ERR
 * @brief Logging system failure
 * Unable to write to syslog or log file.
 */
#define EVENT_LOG_ERR    17

/** @def EVENT_FORK_ERR
 * @brief Process fork() failed
 * Unable to create child process for TCP query or helper script.
 */
#define EVENT_FORK_ERR   18

/** @def EVENT_LUA_ERR
 * @brief Lua script execution error (if HAVE_LUASCRIPT)
 * Lua lease-change script encountered runtime error.
 */
#define EVENT_LUA_ERR    19

/** @def EVENT_TFTP_ERR
 * @brief TFTP server error (if HAVE_TFTP)
 * TFTP file transfer encountered error condition.
 */
#define EVENT_TFTP_ERR   20

/** @def EVENT_INIT
 * @brief Initialization complete event
 * Signals successful daemon startup, triggers post-init actions.
 */
#define EVENT_INIT       21

/** @def EVENT_NEWADDR
 * @brief Network interface address change detected
 * Triggers re-enumeration of interface addresses, listener reconfiguration.
 * Generated by netlink (Linux) or routing socket (BSD) monitoring.
 */
#define EVENT_NEWADDR    22

/** @def EVENT_NEWROUTE
 * @brief Network routing table change detected
 * May affect upstream server reachability, triggers connectivity checks.
 */
#define EVENT_NEWROUTE   23

/** @def EVENT_TIME_ERR
 * @brief System time error detected
 * System clock moved backwards or forward unexpectedly, affects lease timing.
 */
#define EVENT_TIME_ERR   24

/** @def EVENT_SCRIPT_LOG
 * @brief Script output logging event
 * Carries script stdout/stderr output for logging to dnsmasq log.
 */
#define EVENT_SCRIPT_LOG 25

/** @def EVENT_TIME
 * @brief Periodic time-based event
 * Triggers time-dependent housekeeping (lease expiry, cache TTL decrements).
 */
#define EVENT_TIME       26

/** @def EC_GOOD
 * @brief Exit code for successful termination
 * Daemon exited cleanly without errors.
 */
#define EC_GOOD        0

/** @def EC_BADCONF
 * @brief Exit code for configuration error
 * Configuration file syntax error or invalid option combination detected.
 */
#define EC_BADCONF     1

/** @def EC_BADNET
 * @brief Exit code for network initialization failure
 * Unable to bind sockets, enumerate interfaces, or establish network connectivity.
 */
#define EC_BADNET      2

/** @def EC_FILE
 * @brief Exit code for file I/O error
 * Unable to read configuration file, write lease file, or access required files.
 */
#define EC_FILE        3

/** @def EC_NOMEM
 * @brief Exit code for memory allocation failure
 * malloc() or related allocation function failed, insufficient memory.
 */
#define EC_NOMEM       4

/** @def EC_MISC
 * @brief Exit code for miscellaneous errors
 * Catch-all for errors not covered by other exit codes.
 */
#define EC_MISC        5

/** @def EC_INIT_OFFSET
 * @brief Offset for initialization-specific exit codes
 * Initialization errors add this offset to error type for diagnostic purposes.
 */
#define EC_INIT_OFFSET 10

/* Runtime Option Flags (stored in daemon->options[] bit array)
 * These flags control runtime behavior and are set by command-line options
 * or configuration file directives. Accessed via option_bool(OPT_*) macro.
 */

/** @def OPT_BOGUSPRIV
 * @brief Filter reverse lookups for private IP ranges (--bogus-priv)
 * Prevents forwarding of reverse DNS queries for RFC1918 private addresses.
 */
#define OPT_BOGUSPRIV      0

/** @def OPT_FILTER
 * @brief Enable DNS query filtering (--filterwin2k)
 * Filters problematic Windows queries (SOA, SRV lookups).
 */
#define OPT_FILTER         1

/** @def OPT_LOG
 * @brief Enable query logging (--log-queries)
 * Logs all DNS queries to syslog or log file for auditing.
 */
#define OPT_LOG            2

/** @def OPT_SELFMX
 * @brief Return self as MX record (--selfmx)
 * Returns local machine as mail exchanger for specified domains.
 */
#define OPT_SELFMX         3

/** @def OPT_NO_HOSTS
 * @brief Don't read /etc/hosts (--no-hosts)
 * Disables parsing of hosts file for local name resolution.
 */
#define OPT_NO_HOSTS       4

/** @def OPT_NO_POLL
 * @brief Don't poll /etc/resolv.conf for changes (--no-poll)
 * Disables monitoring of resolv.conf for upstream server updates.
 */
#define OPT_NO_POLL        5

/** @def OPT_DEBUG
 * @brief Enable debug mode (--no-daemon --log-queries)
 * Run in foreground with verbose logging for debugging.
 */
#define OPT_DEBUG          6

/** @def OPT_ORDER
 * @brief Return /etc/hosts entries in order (--no-hosts-override)
 * Prevents /etc/hosts from overriding upstream DNS results.
 */
#define OPT_ORDER          7

/** @def OPT_NO_RESOLV
 * @brief Don't read /etc/resolv.conf (--no-resolv)
 * Requires explicit server configuration via --server option.
 */
#define OPT_NO_RESOLV      8

/** @def OPT_EXPAND
 * @brief Expand simple names with domain (--expand-hosts)
 * Appends domain to single-label hostnames from /etc/hosts.
 */
#define OPT_EXPAND         9

/** @def OPT_LOCALMX
 * @brief Generate MX records for local names (--localmx)
 * Automatically creates MX records pointing to local machine.
 */
#define OPT_LOCALMX        10

/** @def OPT_NO_NEG
 * @brief Disable negative caching (--no-negcache)
 * Don't cache NXDOMAIN/NODATA responses, always forward.
 */
#define OPT_NO_NEG         11

/** @def OPT_NODOTS_LOCAL
 * @brief Never forward names without dots (--domain-needed)
 * Treat dotless queries as local-only, never forward to upstream.
 */
#define OPT_NODOTS_LOCAL   12

/** @def OPT_NOWILD
 * @brief Bind only to specified interfaces (--bind-interfaces)
 * Explicit interface binding instead of wildcard listening.
 */
#define OPT_NOWILD         13

/** @def OPT_ETHERS
 * @brief Read /etc/ethers for MAC-to-IP mappings (--read-ethers)
 * Enables static DHCP host configuration from ethers file.
 */
#define OPT_ETHERS         14

/** @def OPT_RESOLV_DOMAIN
 * @brief Use resolv.conf domain for name expansion (--domain from resolv.conf)
 */
#define OPT_RESOLV_DOMAIN  15

/** @def OPT_NO_FORK
 * @brief Run in foreground (--no-daemon)
 * Don't daemonize, useful for systemd/supervisor integration.
 */
#define OPT_NO_FORK        16

/** @def OPT_AUTHORITATIVE
 * @brief Act as authoritative DNS server (--auth-server)
 * Enable authoritative mode for configured zones (requires HAVE_AUTH).
 */
#define OPT_AUTHORITATIVE  17

/** @def OPT_LOCALISE
 * @brief Localise queries to subnet (--localise-queries)
 * Return different answers based on query source subnet.
 */
#define OPT_LOCALISE       18

/** @def OPT_DBUS
 * @brief Enable D-Bus control interface (--enable-dbus)
 * Allows runtime control via D-Bus methods (requires HAVE_DBUS).
 */
#define OPT_DBUS           19

/** @def OPT_DHCP_FQDN
 * @brief Add domain to DHCP hostnames (--dhcp-fqdn)
 * Return fully-qualified domain names in DHCP responses.
 */
#define OPT_DHCP_FQDN      20

/** @def OPT_NO_PING
 * @brief Skip ping check before DHCP allocation (--no-ping)
 * Disable address conflict detection via ICMP echo (faster but less safe).
 */
#define OPT_NO_PING        21

/** @def OPT_LEASE_RO
 * @brief Treat lease database as read-only (--leasefile-ro)
 * Don't rewrite lease file on changes (flash-friendly).
 */
#define OPT_LEASE_RO       22

/** @def OPT_ALL_SERVERS
 * @brief Query all upstream servers (--all-servers)
 * Send queries to all configured upstreams in parallel, use fastest response.
 */
#define OPT_ALL_SERVERS    23

/** @def OPT_RELOAD
 * @brief Reload in progress flag (internal)
 * Set during SIGHUP configuration reload processing.
 */
#define OPT_RELOAD         24

/** @def OPT_LOCAL_REBIND
 * @brief Allow rebinding to local networks (--rebind-localhost-ok)
 * Permit upstream responses pointing to RFC1918/localhost addresses.
 */
#define OPT_LOCAL_REBIND   25

/** @def OPT_TFTP_SECURE
 * @brief Enable TFTP secure mode (--tftp-secure)
 * Restrict TFTP file access to specified root directory only.
 */
#define OPT_TFTP_SECURE    26

/** @def OPT_TFTP_NOBLOCK
 * @brief Use non-blocking TFTP I/O (--tftp-no-blocksize)
 * Disable TFTP blocksize negotiation for compatibility.
 */
#define OPT_TFTP_NOBLOCK   27

/** @def OPT_LOG_OPTS
 * @brief Log DHCP options (--log-dhcp)
 * Log DHCP option details for all DHCP transactions.
 */
#define OPT_LOG_OPTS       28

/** @def OPT_TFTP_APREF_IP
 * @brief Prefer IP address in TFTP replies (--tftp-unique-root=ip)
 * Use client IP address to determine TFTP root directory.
 */
#define OPT_TFTP_APREF_IP  29

/** @def OPT_NO_OVERRIDE
 * @brief Don't override upstream TTLs (--no-override)
 * Preserve original TTL values from upstream responses.
 */
#define OPT_NO_OVERRIDE    30

/** @def OPT_NO_REBIND
 * @brief Block DNS rebinding attacks (--stop-dns-rebind)
 * Reject upstream responses with private IP addresses.
 */
#define OPT_NO_REBIND      31

/** @def OPT_ADD_MAC
 * @brief Add MAC address to DNS queries (--add-mac)
 * Include client MAC in EDNS0 extension for upstream (RFC 7871 variant).
 */
#define OPT_ADD_MAC        32

/** @def OPT_DNSSEC_PROXY
 * @brief Proxy DNSSEC data without validation (--proxy-dnssec)
 * Forward DNSSEC records upstream without local validation.
 */
#define OPT_DNSSEC_PROXY   33

/** @def OPT_CONSEC_ADDR
 * @brief Allocate consecutive DHCP addresses (--dhcp-sequential-ip)
 * Assign DHCP addresses sequentially instead of pseudo-randomly.
 */
#define OPT_CONSEC_ADDR    34

/** @def OPT_CONNTRACK
 * @brief Use Linux conntrack for client identification (--conntrack)
 * Query netfilter conntrack for original client address (NAT scenarios).
 */
#define OPT_CONNTRACK      35

/** @def OPT_FQDN_UPDATE
 * @brief Update DNS from DHCP hostnames (--dhcp-client-update)
 * Allow clients to set their own hostnames in DNS via DHCP FQDN option.
 */
#define OPT_FQDN_UPDATE    36

/** @def OPT_RA
 * @brief Enable IPv6 Router Advertisement (--enable-ra)
 * Send Router Advertisement messages for stateless IPv6 configuration.
 */
#define OPT_RA             37

/** @def OPT_TFTP_LC
 * @brief Convert TFTP filenames to lowercase (--tftp-lowercase)
 * Normalize TFTP requests to lowercase for case-insensitive filesystems.
 */
#define OPT_TFTP_LC        38

/** @def OPT_CLEVERBIND
 * @brief Clever socket binding (--bind-dynamic)
 * Dynamically adapt to interface changes without restart.
 */
#define OPT_CLEVERBIND     39

/** @def OPT_TFTP
 * @brief TFTP server enabled (--enable-tftp)
 * Activate built-in TFTP server for network booting (requires HAVE_TFTP).
 */
#define OPT_TFTP           40

/** @def OPT_CLIENT_SUBNET
 * @brief Include client subnet in queries (--add-subnet)
 * Add EDNS0 client subnet extension per RFC 7871.
 */
#define OPT_CLIENT_SUBNET  41

/** @def OPT_QUIET_DHCP
 * @brief Suppress routine DHCPv4 logging (--quiet-dhcp)
 * Log only DHCP errors, not routine DISCOVER/OFFER/REQUEST/ACK.
 */
#define OPT_QUIET_DHCP     42

/** @def OPT_QUIET_DHCP6
 * @brief Suppress routine DHCPv6 logging (--quiet-dhcp6)
 * Log only DHCPv6 errors, not routine transactions.
 */
#define OPT_QUIET_DHCP6    43

/** @def OPT_QUIET_RA
 * @brief Suppress Router Advertisement logging (--quiet-ra)
 * Don't log routine RA transmissions.
 */
#define OPT_QUIET_RA       44

/** @def OPT_DNSSEC_VALID
 * @brief Enable DNSSEC validation (--dnssec)
 * Validate DNSSEC signatures on responses (requires HAVE_DNSSEC).
 */
#define OPT_DNSSEC_VALID   45

/** @def OPT_DNSSEC_TIME
 * @brief Check DNSSEC signature timestamps (--dnssec-check-unsigned)
 * Validate RRSIG inception/expiration times.
 */
#define OPT_DNSSEC_TIME    46

/** @def OPT_DNSSEC_DEBUG
 * @brief Enable DNSSEC debug logging (--dnssec-debug)
 * Log detailed DNSSEC validation steps for troubleshooting.
 */
#define OPT_DNSSEC_DEBUG   47

/** @def OPT_DNSSEC_IGN_NS
 * @brief Ignore missing DNSSEC for some domains (--dnssec-no-timecheck)
 * Allow unsigned responses from configured domains.
 */
#define OPT_DNSSEC_IGN_NS  48

/** @def OPT_LOCAL_SERVICE
 * @brief Accept DNS queries only from local subnets (--local-service)
 * Reject queries from non-local addresses for security.
 */
#define OPT_LOCAL_SERVICE  49

/** @def OPT_LOOP_DETECT
 * @brief Enable DNS forwarding loop detection (--loop-detect)
 * Detect and break forwarding loops in DNS configuration.
 */
#define OPT_LOOP_DETECT    50

/** @def OPT_EXTRALOG
 * @brief Enable extra logging (--log-facility with local facility)
 * Provide additional diagnostic logging beyond normal verbosity.
 */
#define OPT_EXTRALOG       51

/** @def OPT_TFTP_NO_FAIL
 * @brief Don't fail if TFTP root doesn't exist (--tftp-no-fail)
 * Start even if TFTP root directory is missing or inaccessible.
 */
#define OPT_TFTP_NO_FAIL   52

/** @def OPT_SCRIPT_ARP
 * @brief Call script on ARP table changes (--script-arp)
 * Invoke lease-change script for ARP-derived address assignments.
 */
#define OPT_SCRIPT_ARP     53

/** @def OPT_MAC_B64
 * @brief Encode MAC addresses as base64 (--add-mac=base64)
 * Use base64 encoding for MAC in EDNS0 extension instead of hex.
 */
#define OPT_MAC_B64        54

/** @def OPT_MAC_HEX
 * @brief Encode MAC addresses as hex (--add-mac=hex)
 * Use hexadecimal encoding for MAC in EDNS0 extension.
 */
#define OPT_MAC_HEX        55

/** @def OPT_TFTP_APREF_MAC
 * @brief Prefer MAC address in TFTP replies (--tftp-unique-root=mac)
 * Use client MAC address to determine TFTP root directory.
 */
#define OPT_TFTP_APREF_MAC 56

/** @def OPT_RAPID_COMMIT
 * @brief Enable DHCPv6 rapid commit (--dhcp-rapid-commit)
 * Use 2-message rapid commit instead of 4-message DHCPv6 exchange.
 */
#define OPT_RAPID_COMMIT   57

/** @def OPT_UBUS
 * @brief Enable ubus control interface (--enable-ubus)
 * Allow runtime control via OpenWrt ubus (requires HAVE_UBUS).
 */
#define OPT_UBUS           58

/** @def OPT_IGNORE_CLID
 * @brief Ignore DHCP client identifier (--dhcp-ignore-clid)
 * Use only MAC address for DHCP lease lookup, ignore client-id option.
 */
#define OPT_IGNORE_CLID    59

/** @def OPT_SINGLE_PORT
 * @brief Use single port for upstream queries (--single-port)
 * Reuse one source port instead of randomizing (reduces security).
 */
#define OPT_SINGLE_PORT    60

/** @def OPT_LEASE_RENEW
 * @brief Send proactive lease renewal reminders (--dhcp-broadcast=tag:...)
 * Broadcast renewal reminders before lease expiry.
 */
#define OPT_LEASE_RENEW    61

/** @def OPT_LOG_DEBUG
 * @brief Enable debug-level logging (--log-debug)
 * Log MS_DEBUG priority messages for detailed troubleshooting.
 */
#define OPT_LOG_DEBUG      62

/** @def OPT_UMBRELLA
 * @brief Enable Cisco Umbrella integration (--umbrella)
 * Add Umbrella device identification to DNS queries.
 */
#define OPT_UMBRELLA       63

/** @def OPT_UMBRELLA_DEVID
 * @brief Include device ID in Umbrella queries (internal)
 * Append device identifier to Umbrella EDNS0 extension.
 */
#define OPT_UMBRELLA_DEVID 64

/** @def OPT_CMARK_ALST_EN
 * @brief Enable connection mark tracking (--connmark-allowlist-enable)
 * Use netfilter connection marks for policy routing (requires HAVE_CONNTRACK).
 */
#define OPT_CMARK_ALST_EN  65

/** @def OPT_QUIET_TFTP
 * @brief Suppress routine TFTP logging (--quiet-tftp)
 * Log only TFTP errors, not successful transfers.
 */
#define OPT_QUIET_TFTP     66

/** @def OPT_FILTER_A
 * @brief Filter IPv4 A records (--filter-A)
 * Remove A records from responses for IPv6-only enforcement.
 */
#define OPT_FILTER_A       67

/** @def OPT_FILTER_AAAA
 * @brief Filter IPv6 AAAA records (--filter-AAAA)
 * Remove AAAA records from responses for IPv4-only enforcement.
 */
#define OPT_FILTER_AAAA    68

/** @def OPT_STRIP_ECS
 * @brief Strip EDNS client subnet from responses (--strip-ecs)
 * Remove client subnet data from upstream responses before caching.
 */
#define OPT_STRIP_ECS      69

/** @def OPT_STRIP_MAC
 * @brief Strip MAC address from responses (--strip-mac)
 * Remove MAC address EDNS extension from upstream responses.
 */
#define OPT_STRIP_MAC      70

/** @def OPT_LAST
 * @brief Sentinel value marking end of option range
 * Total number of runtime option flags (71). Used for bit array sizing.
 */
#define OPT_LAST           71

/** @def OPTION_BITS
 * @brief Bits per unsigned int (typically 32)
 * Number of option flags that fit in one unsigned int array element.
 */
#define OPTION_BITS (sizeof(unsigned int)*8)

/** @def OPTION_SIZE
 * @brief Size of daemon->options[] bit array
 * Number of unsigned ints needed to store OPT_LAST option flags.
 * Calculated as ceiling(OPT_LAST / OPTION_BITS).
 */
#define OPTION_SIZE ( (OPT_LAST/OPTION_BITS)+((OPT_LAST%OPTION_BITS)!=0) )

/** @def option_var(x)
 * @brief Get array element containing option flag x
 * Maps option number to specific unsigned int in daemon->options[] array.
 * @param x Option flag constant (OPT_* value)
 * @return Reference to unsigned int containing the flag's bit
 */
#define option_var(x) (daemon->options[(x) / OPTION_BITS])

/** @def option_val(x)
 * @brief Get bit mask for option flag x
 * Calculates bit position within unsigned int for specified option.
 * @param x Option flag constant (OPT_* value)
 * @return Bit mask with single bit set corresponding to option
 */
#define option_val(x) ((1u) << ((x) % OPTION_BITS))

/** @def option_bool(x)
 * @brief Test if option flag x is set
 * Primary macro for checking runtime option state throughout codebase.
 * @param x Option flag constant (OPT_* value)
 * @return Non-zero if option is enabled, zero if disabled
 * 
 * EXAMPLE USAGE:
 * @code
 * if (option_bool(OPT_LOG))
 *   log_query(F_CONFIG, "example.com", NULL, NULL);
 * @endcode
 */
#define option_bool(x) (option_var(x) & option_val(x))

/** @def MS_TFTP
 * @brief Syslog facility flag for TFTP messages
 * Uses LOG_USER facility. Messages tagged for TFTP subsystem identification.
 */
#define MS_TFTP   LOG_USER

/** @def MS_DHCP
 * @brief Syslog facility flag for DHCP messages
 * Uses LOG_DAEMON facility. Messages tagged for DHCP subsystem identification.
 */
#define MS_DHCP   LOG_DAEMON

/** @def MS_SCRIPT
 * @brief Syslog facility flag for script execution messages
 * Uses LOG_MAIL facility. Messages tagged for lease-change script output.
 */
#define MS_SCRIPT LOG_MAIL

/** @def MS_DEBUG
 * @brief Syslog facility flag for debug messages
 * Uses LOG_NEWS facility. Messages suppressed unless OPT_LOG_DEBUG is set.
 * Provides verbose diagnostic output for troubleshooting.
 */
#define MS_DEBUG  LOG_NEWS

/**
 * @union all_addr
 * @brief Universal address container for IPv4/IPv6/DNS resource record data
 *
 * This union provides a common storage type for diverse address and DNS data formats
 * throughout dnsmasq. Most commonly used for IPv4/IPv6 addresses, but also stores
 * CNAME targets, DNSSEC keys/signatures, SRV records, and logging metadata. The union
 * is sized to sizeof(struct in6_addr) = 16 bytes to minimize memory usage in cache
 * entries while accommodating all address families.
 *
 * LIFECYCLE: Typically embedded in struct crec (cache records) and other structures.
 * Not directly allocated. Lifetime matches containing structure.
 *
 * MEMORY LAYOUT: 16 bytes (size of IPv6 address). All variants fit within this size
 * constraint. Fields beyond 16 bytes use pointers to external storage (e.g., blockdata).
 *
 * USAGE PATTERN: Discriminated union - containing struct determines which member is
 * valid. For struct crec, flags field (F_IPV4, F_IPV6, F_CNAME, F_DNSKEY, F_DS, etc.)
 * indicates active variant. Access appropriate member based on type flags.
 *
 * @var all_addr::addr4
 * IPv4 address storage (4 bytes). Active when F_IPV4 flag set in containing structure.
 * Standard struct in_addr from <netinet/in.h>.
 *
 * @var all_addr::addr6
 * IPv6 address storage (16 bytes). Active when F_IPV6 flag set. Sized to fit the union
 * exactly (no padding). Standard struct in6_addr from <netinet/in.h>.
 *
 * @var all_addr::cname
 * CNAME resource record data. Active when F_CNAME flag set in cache record.
 *
 * @var all_addr::cname.target
 * Union discriminating between pointer to target cache record (cname.target.cache) or
 * pointer to target domain name string (cname.target.name). Discriminated by is_name_ptr.
 *
 * @var all_addr::cname.uid
 * Unique identifier for CNAME chain tracking. Used for loop detection (CNAME_CHAIN limit).
 *
 * @var all_addr::cname.is_name_ptr
 * Discriminator flag: non-zero if target.name points to string, zero if target.cache
 * points to struct crec. Determines how to interpret target union member.
 *
 * @var all_addr::key
 * DNSKEY resource record data (DNSSEC public key). Active when F_DNSKEY flag set.
 *
 * @var all_addr::key.keydata
 * Pointer to block-chained storage (struct blockdata) holding actual key bytes. Key
 * data stored externally to fit within 16-byte union size constraint.
 *
 * @var all_addr::key.keylen
 * Length of key data in bytes (stored in keydata blockdata chain).
 *
 * @var all_addr::key.flags
 * DNSKEY flags field from RFC 4034: bit 7 = Zone Key, bit 15 = Secure Entry Point (SEP).
 *
 * @var all_addr::key.keytag
 * DNSKEY key tag (16-bit identifier) calculated per RFC 4034 algorithm. Used for
 * matching DNSKEY to RRSIG and DS records.
 *
 * @var all_addr::key.algo
 * DNSSEC algorithm number: 5=RSA/SHA-1, 8=RSA/SHA-256, 13=ECDSA-P256, 15=Ed25519.
 *
 * @var all_addr::ds
 * DS (Delegation Signer) resource record data. Active when F_DS flag set. Links parent
 * zone to child zone DNSKEY in DNSSEC chain of trust.
 *
 * @var all_addr::ds.keydata
 * Pointer to blockdata holding digest bytes. Digest of child DNSKEY computed using
 * specified digest algorithm (SHA-1, SHA-256, etc.).
 *
 * @var all_addr::ds.keylen
 * Length of digest data in bytes (typically 20 for SHA-1, 32 for SHA-256).
 *
 * @var all_addr::ds.keytag
 * Key tag of child DNSKEY this DS record refers to. Must match DNSKEY keytag.
 *
 * @var all_addr::ds.algo
 * DNSSEC algorithm of child DNSKEY (same values as key.algo).
 *
 * @var all_addr::ds.digest
 * Digest algorithm type: 1=SHA-1, 2=SHA-256, 4=SHA-384. Determines hash function used.
 *
 * @var all_addr::srv
 * SRV resource record data (service location per RFC 2782). Active for SRV records.
 *
 * @var all_addr::srv.target
 * Pointer to blockdata holding target hostname (domain name of service endpoint).
 *
 * @var all_addr::srv.targetlen
 * Length of target hostname in bytes.
 *
 * @var all_addr::srv.srvport
 * TCP/UDP port number of service (0-65535).
 *
 * @var all_addr::srv.priority
 * SRV priority value (0-65535). Lower values preferred. Clients try servers in
 * priority order.
 *
 * @var all_addr::srv.weight
 * SRV weight for load balancing among same-priority servers. Higher weights get
 * proportionally more traffic.
 *
 * @var all_addr::log
 * Logging metadata for query logging (not stored in cache). Used transiently by
 * log_query() for formatting log messages with DNSSEC/error details.
 *
 * @var all_addr::log.keytag
 * DNSSEC key tag for logging (identifies which key was used/failed validation).
 *
 * @var all_addr::log.algo
 * DNSSEC algorithm for logging.
 *
 * @var all_addr::log.digest
 * DNSSEC digest type for logging.
 *
 * @var all_addr::log.rcode
 * DNS response code for error logging (NXDOMAIN=3, SERVFAIL=2, etc.).
 *
 * @var all_addr::log.ede
 * Extended DNS Error code (RFC 8914) for detailed error reporting in logs.
 *
 * @see struct crec for primary usage in DNS cache entries
 * @see cache.c for cache record manipulation using union all_addr
 */
union all_addr {
  struct in_addr addr4;
  struct in6_addr addr6;
  struct {
    union {
      struct crec *cache;
      char *name;
    } target;
    unsigned int uid;
    int is_name_ptr;  /* disciminates target union */
  } cname;
  struct {
    struct blockdata *keydata;
    unsigned short keylen, flags, keytag;
    unsigned char algo;
  } key; 
  struct {
    struct blockdata *keydata;
    unsigned short keylen, keytag;
    unsigned char algo;
    unsigned char digest; 
  } ds;
  struct {
    struct blockdata *target;
    unsigned short targetlen, srvport, priority, weight;
  } srv;
  /* for log_query */
  struct {
    unsigned short keytag, algo, digest, rcode;
    int ede;
  } log;
};


/**
 * @struct bogus_addr
 * @brief IP address to treat as bogus (return NXDOMAIN)
 *
 * Implements --bogus-nxdomain directive for ad-blocking and malware protection.
 * Upstream responses containing these addresses replaced with NXDOMAIN, preventing
 * clients from reaching specified addresses. Supports prefix matching for ranges.
 *
 * @var bogus_addr::is6 - 1 if IPv6 address, 0 if IPv4
 * @var bogus_addr::prefix - Prefix length for CIDR matching (e.g., 24 for /24)
 * @var bogus_addr::addr - IP address or prefix to mark as bogus
 * @var bogus_addr::next - Next entry in bogus address list
 */
struct bogus_addr {
  int is6, prefix;
  union all_addr addr;
  struct bogus_addr *next;
};

/**
 * @struct doctor
 * @brief DNS doctor rule for rewriting DNS responses in-flight
 *
 * Implements --alias directive modifying DNS A/AAAA responses. Rewrites addresses
 * matching input range to output addresses. Enables NAT-aware DNS for split-horizon
 * configurations where public IPs must be rewritten to private IPs.
 *
 * @var doctor::in - Start of input address range to match
 * @var doctor::end - End of input address range (inclusive)
 * @var doctor::out - Output address base for rewriting
 * @var doctor::mask - Network mask for address transformation
 * @var doctor::next - Next doctoring rule in chain
 */
struct doctor {
  struct in_addr in, end, out, mask;
  struct doctor *next;
};

/**
 * @struct mx_srv_record
 * @brief MX (Mail Exchanger) or SRV (Service) resource record
 *
 * Authoritative MX and SRV records configured via --mx-host and --srv-host directives.
 * MX records direct email delivery. SRV records (RFC 2782) advertise service locations
 * (e.g., _ldap._tcp.example.com pointing to ldap servers).
 *
 * @var mx_srv_record::name - Owner name (domain for MX, service.proto.domain for SRV)
 * @var mx_srv_record::target - Target hostname (mail server or service endpoint)
 * @var mx_srv_record::issrv - 1 if SRV record, 0 if MX record
 * @var mx_srv_record::srvport - Port number for SRV records (ignored for MX)
 * @var mx_srv_record::priority - Priority (lower value = higher priority), RFC 2782
 * @var mx_srv_record::weight - Weight for load balancing among same-priority records
 * @var mx_srv_record::offset - Byte offset in packet for on-the-fly construction
 * @var mx_srv_record::next - Next MX/SRV record in list
 */
struct mx_srv_record {
  char *name, *target;
  int issrv, srvport, priority, weight;
  unsigned int offset;
  struct mx_srv_record *next;
};

/**
 * @struct naptr
 * @brief NAPTR (Naming Authority Pointer) record for ENUM and dynamic delegation
 *
 * NAPTR records (RFC 3403) support ENUM (E.164 telephone number mapping to URIs) and
 * dynamic service discovery. Complex rewriting rules with regexp patterns enable
 * sophisticated URI transformations for telephony and service location.
 *
 * @var naptr::name - Owner domain name (e.g., 1.2.3.4.5.6.7.8.9.0.1.e164.arpa)
 * @var naptr::replace - Replacement string (used if regexp empty)
 * @var naptr::regexp - POSIX extended regexp for substitution (format: "!pattern!replacement!")
 * @var naptr::services - Service field (e.g., "E2U+sip" for SIP telephony)
 * @var naptr::flags - Flags controlling terminal behavior ("U"=terminal URI, "S"=SRV lookup)
 * @var naptr::order - Processing order (lower processed first), RFC 3403 Section 4.1
 * @var naptr::pref - Preference among same-order records (lower = higher preference)
 * @var naptr::next - Next NAPTR record in list
 */
struct naptr {
  char *name, *replace, *regexp, *services, *flags;
  unsigned int order, pref;
  struct naptr *next;
};

#ifndef NO_ID
/** @def TXT_STAT_CACHESIZE - TXT record query returns cache size statistic */
#define TXT_STAT_CACHESIZE     1
/** @def TXT_STAT_INSERTS - TXT record query returns cache insertion count */
#define TXT_STAT_INSERTS       2
/** @def TXT_STAT_EVICTIONS - TXT record query returns cache eviction count (LRU) */
#define TXT_STAT_EVICTIONS     3
/** @def TXT_STAT_MISSES - TXT record query returns cache miss count */
#define TXT_STAT_MISSES        4
/** @def TXT_STAT_HITS - TXT record query returns cache hit count */
#define TXT_STAT_HITS          5
/** @def TXT_STAT_AUTH - TXT record query returns authoritative record count */
#define TXT_STAT_AUTH          6
/** @def TXT_STAT_SERVERS - TXT record query returns upstream server list */
#define TXT_STAT_SERVERS       7
#endif

/**
 * @struct txt_record
 * @brief TXT resource record for arbitrary text data
 *
 * TXT records configured via --txt-record directive. Support arbitrary text strings
 * for SPF (email sender validation), DKIM (email signing keys), domain verification,
 * and dynamic statistics export (cache_make_stat() for TXT_STAT_* queries).
 *
 * @var txt_record::name - Owner name (domain for TXT record)
 * @var txt_record::txt - TXT record data bytes (may contain non-ASCII, length-prefixed)
 * @var txt_record::class - DNS class (typically IN=1)
 * @var txt_record::len - Length of txt data in bytes
 * @var txt_record::stat - If non-zero, TXT_STAT_* constant for dynamic statistic generation
 * @var txt_record::next - Next TXT record in list
 */
struct txt_record {
  char *name;
  unsigned char *txt;
  unsigned short class, len;
  int stat;
  struct txt_record *next;
};

/**
 * @struct ptr_record
 * @brief PTR resource record for reverse DNS lookups
 *
 * PTR records map IP addresses to hostnames (reverse DNS). Configured via --ptr-record
 * directive or generated automatically from --host-record with reverse DNS enabled.
 * Essential for services requiring reverse DNS validation (email, SSH).
 *
 * @var ptr_record::name - Reverse DNS name (e.g., 1.0.0.127.in-addr.arpa for 127.0.0.1)
 * @var ptr_record::ptr - Target hostname (canonical name for this address)
 * @var ptr_record::next - Next PTR record in list
 */
struct ptr_record {
  char *name, *ptr;
  struct ptr_record *next;
};

/**
 * @struct cname
 * @brief CNAME (Canonical Name) record for DNS aliasing
 *
 * CNAME records create aliases pointing to canonical names. Configured via --cname
 * directive. Enables multiple names resolving to same target. CNAME chains followed
 * transparently up to CNAME_CHAIN limit (10) with loop detection.
 *
 * @var cname::ttl - Time-to-live for this CNAME record (seconds)
 * @var cname::flag - Processing flags (wildcard handling, etc.)
 * @var cname::alias - Alias name (queried name that triggers CNAME response)
 * @var cname::target - Target canonical name (what alias points to)
 * @var cname::next - Next CNAME in configuration list
 * @var cname::targetp - Target pointer for chain traversal (runtime resolved)
 */
struct cname {
  int ttl, flag;
  char *alias, *target;
  struct cname *next, *targetp;
}; 

/**
 * @struct ds_config
 * @brief DNSSEC DS (Delegation Signer) record configuration
 *
 * DS records establish DNSSEC chain of trust from parent zone to child zone. Configured
 * via --trust-anchor directive or trust-anchors.conf. Essential for DNSSEC validation -
 * root DS record (KSK) anchors entire validation chain. Contains hash of child's DNSKEY.
 *
 * @var ds_config::name - Zone name this DS record signs (e.g., "." for root)
 * @var ds_config::digest - Digest bytes (hash of child DNSKEY), dynamically allocated
 * @var ds_config::digestlen - Length of digest in bytes (varies by digest_type)
 * @var ds_config::class - DNS class (typically IN=1)
 * @var ds_config::algo - DNSSEC algorithm number (8=RSA/SHA-256, 13=ECDSA P-256, 15=Ed25519)
 * @var ds_config::keytag - Key tag identifying DNSKEY in child zone (collision-resistant ID)
 * @var ds_config::digest_type - Digest algorithm (1=SHA-1, 2=SHA-256, 4=SHA-384)
 * @var ds_config::next - Next DS configuration in trust anchor list
 */
struct ds_config {
  char *name, *digest;
  int digestlen, class, algo, keytag, digest_type;
  struct ds_config *next;
};

/** @def ADDRLIST_LITERAL - Address from literal config (not dynamic) */
#define ADDRLIST_LITERAL  1
/** @def ADDRLIST_IPV6 - Entry contains IPv6 address (not IPv4) */
#define ADDRLIST_IPV6     2
/** @def ADDRLIST_REVONLY - Address for reverse DNS only (no forward) */
#define ADDRLIST_REVONLY  4
/** @def ADDRLIST_PREFIX - Entry represents prefix/subnet (not single address) */
#define ADDRLIST_PREFIX   8
/** @def ADDRLIST_WILDCARD - Wildcard address matching enabled */
#define ADDRLIST_WILDCARD 16
/** @def ADDRLIST_DECLINED - Address declined by DHCP client (temporarily unavailable) */
#define ADDRLIST_DECLINED 32

/**
 * @struct addrlist
 * @brief Generic address list entry (IPv4/IPv6) with flags
 *
 * Versatile address container used for interface addresses, host record addresses,
 * DHCPv6 static assignments, and DHCP declined addresses. Flags control interpretation
 * (literal vs wildcard, forward vs reverse-only, single address vs prefix).
 *
 * @var addrlist::addr - IP address (IPv4 or IPv6 per ADDRLIST_IPV6 flag)
 * @var addrlist::flags - Bitfield of ADDRLIST_* flags controlling interpretation
 * @var addrlist::prefixlen - Prefix length if ADDRLIST_PREFIX set (CIDR notation)
 * @var addrlist::decline_time - Timestamp when address declined (ADDRLIST_DECLINED only)
 * @var addrlist::next - Next address in list
 */
struct addrlist {
  union all_addr addr;
  int flags, prefixlen;
  time_t decline_time;
  struct addrlist *next;
};

/** @def AUTH6 - Authoritative zone serves IPv6 (AAAA) records */
#define AUTH6     1
/** @def AUTH4 - Authoritative zone serves IPv4 (A) records */
#define AUTH4     2

/**
 * @struct auth_zone
 * @brief Authoritative DNS zone configuration
 *
 * Defines DNS zones where dnsmasq acts as authoritative nameserver (--auth-zone directive).
 * Responds authoritatively with SOA, NS, A/AAAA records for specified domains without
 * forwarding queries upstream. Enables local DNS authority for private networks or
 * split-horizon configurations.
 *
 * @var auth_zone::domain - Zone domain name (e.g., "example.local")
 * @var auth_zone::interface_names - Embedded struct list of interface names serving zone
 * @var auth_zone::subnet - Subnet list defining zone scope (queries from these subnets answered)
 * @var auth_zone::exclude - Excluded subnet list (queries from these denied)
 * @var auth_zone::next - Next authoritative zone in list
 */
struct auth_zone {
  char *domain;
  struct auth_name_list {
    char *name;
    int flags;
    struct auth_name_list *next;
  } *interface_names;
  struct addrlist *subnet;
  struct addrlist *exclude;
  struct auth_zone *next;
};

/** @def HR_6 - Host record includes IPv6 address (AAAA record) */
#define HR_6 1
/** @def HR_4 - Host record includes IPv4 address (A record) */
#define HR_4 2

/**
 * @struct host_record
 * @brief Static host A/AAAA record configuration
 *
 * Configured via --host-record directive. Creates A and/or AAAA records for specified
 * names pointing to configured addresses. More powerful than /etc/hosts: supports
 * multiple names per address, dual-stack (IPv4+IPv6), custom TTL, reverse DNS generation.
 *
 * @var host_record::ttl - Time-to-live for this host record (seconds, 0 = local_ttl default)
 * @var host_record::flags - HR_4 and/or HR_6 indicating address families present
 * @var host_record::names - Embedded struct list of hostnames mapping to these addresses
 * @var host_record::addr - IPv4 address (if HR_4 set)
 * @var host_record::addr6 - IPv6 address (if HR_6 set)
 * @var host_record::next - Next host record in list
 */
struct host_record {
  int ttl, flags;
  struct name_list {
    char *name;
    struct name_list *next;
  } *names;
  struct in_addr addr;
  struct in6_addr addr6;
  struct host_record *next;
};

/** @def IN4 - Interface serves IPv4 */
#define IN4  1
/** @def IN6 - Interface serves IPv6 */
#define IN6  2
/** @def INP4 - Interface has IPv4 address for local queries */
#define INP4 4
/** @def INP6 - Interface has IPv6 address for local queries */
#define INP6 8

/**
 * @struct interface_name
 * @brief Domain-to-interface binding for selective DNS resolution
 *
 * Implements --interface-name directive mapping domains to network interfaces. Queries
 * for specified domain answered with interface address. Enables DNS-based interface
 * discovery and split-horizon DNS where different interfaces serve different domains.
 *
 * @var interface_name::name - Domain name to associate with interface
 * @var interface_name::intr - Interface name (e.g., "eth0", "wlan0")
 * @var interface_name::flags - IN4/IN6/INP4/INP6 indicating protocol support
 * @var interface_name::proto4 - IPv4 protocol address (if INP4 set)
 * @var interface_name::proto6 - IPv6 protocol address (if INP6 set)
 * @var interface_name::addr - Address list for this interface binding
 * @var interface_name::next - Next interface-name mapping
 */
struct interface_name {
  char *name; /* domain name */
  char *intr; /* interface name */
  int flags;
  struct in_addr proto4;
  struct in6_addr proto6;
  struct addrlist *addr;
  struct interface_name *next;
};

/**
 * @union bigname
 * @brief Large name buffer with freelist management
 *
 * MAXDNAME (1024 byte) buffer for domain name operations. Allocated from freelist to
 * avoid repeated malloc/free overhead for temporary name buffers. Used throughout DNS
 * packet parsing and construction for name decompression and manipulation.
 *
 * @var bigname::name - Character array for domain name storage (MAXDNAME bytes)
 * @var bigname::next - Next entry in freelist when buffer unused
 */
union bigname {
  char name[MAXDNAME];
  union bigname *next; /* freelist */
};

/**
 * @struct blockdata
 * @brief Block-chained storage for variable-length DNS data
 *
 * Blockdata provides efficient storage for variable-length data (DNSSEC keys, long
 * domain names) that exceed inline storage capacity. Data is stored in fixed-size
 * blocks (KEYBLOCK_LEN bytes each) linked in a chain, avoiding large single allocations.
 *
 * LIFECYCLE: Allocated by blockdata_alloc(), freed by blockdata_free(). Reference-counted
 * to allow sharing between cache entries. Typically referenced from union all_addr.key.keydata
 * or all_addr.ds.keydata for DNSSEC record storage.
 *
 * MEMORY LAYOUT: Fixed-size blocks minimize fragmentation. Block size (KEYBLOCK_LEN = 40)
 * chosen to balance allocation overhead vs. fragmentation for typical DNSSEC key sizes.
 *
 * USAGE PATTERN: Used for DNSSEC DNSKEY/DS/RRSIG storage, long CNAME chains, SRV targets.
 * Caller manages lifecycle, must free when last reference removed.
 *
 * @var blockdata::next
 * Pointer to next block in chain, or NULL for last block. Blocks traversed sequentially
 * to reconstruct full data.
 *
 * @var blockdata::key
 * Fixed-size data payload (KEYBLOCK_LEN = 40 bytes from config.h). Contains chunk of
 * stored data. Last block may be partially filled.
 *
 * @see blockdata.c for allocation/deallocation implementation
 * @see union all_addr.key.keydata and all_addr.ds.keydata for primary usage
 */
struct blockdata {
  struct blockdata *next;
  unsigned char key[KEYBLOCK_LEN];
};

/**
 * @struct crec
 * @brief DNS cache record storing resource record data with TTL and metadata
 *
 * The crec (cache record) is the fundamental unit of dnsmasq's DNS cache. Each crec
 * stores one resource record (RR) with associated metadata for cache management. Cache
 * records are organized in a hash table for fast lookup and an LRU (Least Recently Used)
 * doubly-linked list for eviction. The cache can hold A/AAAA addresses, CNAME chains,
 * negative responses (NXDOMAIN/NODATA), DNSSEC keys, and other DNS record types.
 *
 * LIFECYCLE:
 * - Allocated from freelist by cache_insert() in cache.c
 * - Inserted into hash table (via hash_next) and LRU list (via next/prev)
 * - Expires when current time > ttd (time to die) or evicted when cache full
 * - Freed by cache_scan() during expiry or cache_unlink() during eviction
 * - Returns to freelist for reuse (not deallocated to OS)
 *
 * MEMORY LAYOUT: Variable size depending on name length:
 * - SIZEOF_BARE_CREC: Minimum size excluding name storage
 * - If name fits in SMALLDNAME (50 bytes): embedded in sname[50]
 * - If name exceeds SMALLDNAME: pointer to union bigname or heap string (F_BIGNAME/F_NAMEP)
 * - Optimization reduces memory for majority of DNS names (<50 chars)
 *
 * USAGE PATTERN:
 * 1. Query cache via cache_lookup(name, now, flags) - searches hash table
 * 2. On miss, forward query upstream, receive response
 * 3. Insert response via cache_insert(name, addr, now, ttl, flags) - adds to cache
 * 4. On hit, return cached data if not expired (now < ttd)
 * 5. Periodic cache_scan() removes expired entries and enforces size limits
 *
 * @var crec::next
 * Forward pointer in LRU doubly-linked list. Most recently used at list head, least
 * recently used at tail. Updated on every cache hit to move record to head (LRU promotion).
 *
 * @var crec::prev
 * Backward pointer in LRU doubly-linked list. Enables O(1) removal from list during
 * eviction or expiry.
 *
 * @var crec::hash_next
 * Pointer to next record in hash collision chain. Hash table uses chaining for collision
 * resolution. NULL terminates chain. Hash function based on DNS name.
 *
 * @var crec::addr
 * Union holding actual resource record data. Variant determined by flags field:
 * - F_IPV4: addr.addr4 holds IPv4 address (struct in_addr)
 * - F_IPV6: addr.addr6 holds IPv6 address (struct in6_addr)
 * - F_CNAME: addr.cname holds CNAME target (cache pointer or name string)
 * - F_DNSKEY: addr.key holds DNSSEC public key data
 * - F_DS: addr.ds holds DNSSEC delegation signer data
 * - F_SRV: addr.srv holds SRV record (priority, weight, port, target)
 *
 * @var crec::ttd
 * Time To Die - absolute timestamp (seconds since epoch) when cache entry expires.
 * Compared against current time in cache_lookup(). Expired entries (now > ttd) treated
 * as cache miss. Set to now + TTL at insertion time. For F_IMMORTAL entries (hosts file),
 * ttd not checked (never expires).
 *
 * @var crec::uid
 * Multi-purpose identifier field:
 * - For DNSKEY/DS records (F_DNSKEY, F_DS): Stores DNS class (typically IN=1)
 * - For F_HOSTS entries: Index identifying source (SRC_HOSTS, SRC_CONFIG, SRC_AH)
 * - For CNAME chains: UID for loop detection tracking
 * - For other records: Typically UID_NONE (0)
 *
 * @var crec::flags
 * Bit field combining multiple flag constants (F_* defines below) indicating:
 * - Record type: F_IPV4, F_IPV6, F_CNAME, F_DNSKEY, F_DS, F_SRV, F_NXDOMAIN
 * - Source: F_HOSTS (from /etc/hosts), F_DHCP (from DHCP), F_CONFIG (config file)
 * - Direction: F_FORWARD (name→addr), F_REVERSE (addr→name)
 * - Properties: F_IMMORTAL (never expires), F_NEG (negative cache), F_DNSSECOK (validated)
 * - Name storage: F_NAMEP (heap pointer), F_BIGNAME (bigname union), neither (inline sname)
 *
 * @var crec::name
 * Discriminated union for DNS name storage optimized for common case (names <50 bytes):
 * - sname[SMALLDNAME]: Inline storage for short names (SMALLDNAME=50 from config.h)
 * - bname: Pointer to union bigname for names 50-255 bytes (F_BIGNAME flag set)
 * - namep: Pointer to heap-allocated string for very long names (F_NAMEP flag set)
 * Flags field discriminates which variant is active. Most names fit inline (no alloc).
 *
 * @see cache.c cache_insert() for cache record creation
 * @see cache.c cache_lookup() for cache query with hash table + LRU
 * @see cache.c cache_scan() for TTL expiry and LRU eviction
 * @see union all_addr for resource record data variants
 * @see config.h CACHESIZ for default cache size (150 entries)
 * @see config.h SMALLDNAME for inline name threshold (50 bytes)
 */
struct crec { 
  struct crec *next, *prev, *hash_next;
  union all_addr addr;
  time_t ttd; /* time to die */
  /* used as class if DNSKEY/DS, index to source for F_HOSTS */
  unsigned int uid; 
  unsigned int flags;
  union {
    char sname[SMALLDNAME];
    union bigname *bname;
    char *namep;
  } name;
};

/** @def SIZEOF_BARE_CREC
 * @brief Minimum crec size excluding name storage
 * Size calculation for crec with sname excluded. Used for memory accounting.
 */
#define SIZEOF_BARE_CREC (sizeof(struct crec) - SMALLDNAME)

/** @def SIZEOF_POINTER_CREC
 * @brief crec size when using pointer-based name storage (F_NAMEP or F_BIGNAME)
 */
#define SIZEOF_POINTER_CREC (sizeof(struct crec) + sizeof(char *) - SMALLDNAME)

/* Cache Record Flags (struct crec.flags bit field) */

/** @def F_IMMORTAL - Never expire (from /etc/hosts or static config) */
#define F_IMMORTAL  (1u<<0)
/** @def F_NAMEP - name.namep points to heap-allocated string */
#define F_NAMEP     (1u<<1)
/** @def F_REVERSE - Reverse lookup (PTR record: addr→name) */
#define F_REVERSE   (1u<<2)
/** @def F_FORWARD - Forward lookup (A/AAAA record: name→addr) */
#define F_FORWARD   (1u<<3)
/** @def F_DHCP - Entry from DHCP lease (dynamic hostname) */
#define F_DHCP      (1u<<4)
/** @def F_NEG - Negative cache entry (NXDOMAIN or NODATA) */
#define F_NEG       (1u<<5)
/** @def F_HOSTS - Entry from /etc/hosts file */
#define F_HOSTS     (1u<<6)
/** @def F_IPV4 - IPv4 address (addr.addr4 valid) */
#define F_IPV4      (1u<<7)
/** @def F_IPV6 - IPv6 address (addr.addr6 valid) */
#define F_IPV6      (1u<<8)
/** @def F_BIGNAME - name.bname points to union bigname (50-255 byte names) */
#define F_BIGNAME   (1u<<9)
/** @def F_NXDOMAIN - Negative cache: domain does not exist */
#define F_NXDOMAIN  (1u<<10)
/** @def F_CNAME - CNAME record (addr.cname valid) */
#define F_CNAME     (1u<<11)
/** @def F_DNSKEY - DNSSEC DNSKEY record (addr.key valid) */
#define F_DNSKEY    (1u<<12)
/** @def F_CONFIG - Entry from config file (static configuration) */
#define F_CONFIG    (1u<<13)
/** @def F_DS - DNSSEC DS record (addr.ds valid) */
#define F_DS        (1u<<14)
/** @def F_DNSSECOK - DNSSEC validation succeeded (secure) */
#define F_DNSSECOK  (1u<<15)
/** @def F_UPSTREAM - Cached from upstream server response */
#define F_UPSTREAM  (1u<<16)
/** @def F_RRNAME - Resource record name (not address record) */
#define F_RRNAME    (1u<<17)
/** @def F_SERVER - Server record in cache */
#define F_SERVER    (1u<<18)
/** @def F_QUERY - Active query in progress */
#define F_QUERY     (1u<<19)
/** @def F_NOERR - Response was NOERROR (not NXDOMAIN/SERVFAIL) */
#define F_NOERR     (1u<<20)
/** @def F_AUTH - From authoritative zone (local authority) */
#define F_AUTH      (1u<<21)
/** @def F_DNSSEC - DNSSEC-related record (DNSKEY/DS/RRSIG) */
#define F_DNSSEC    (1u<<22)
/** @def F_KEYTAG - DNSSEC key tag stored in uid field */
#define F_KEYTAG    (1u<<23)
/** @def F_SECSTAT - DNSSEC security status indicator */
#define F_SECSTAT   (1u<<24)
/** @def F_NO_RR - No resource records found (NODATA response) */
#define F_NO_RR     (1u<<25)
/** @def F_IPSET - Add to ipset when resolved (Linux ipset integration) */
#define F_IPSET     (1u<<26)
/** @def F_NOEXTRA - Don't add to extra/additional section */
#define F_NOEXTRA   (1u<<27)
/** @def F_DOMAINSRV - Domain-specific server record */
#define F_DOMAINSRV (1u<<28)
/** @def F_RCODE - DNS response code stored */
#define F_RCODE     (1u<<29)
/** @def F_SRV - SRV record (addr.srv valid) */
#define F_SRV       (1u<<30)

/** @def UID_NONE - uid field unused (zero) */
#define UID_NONE      0
/** @def SRC_CONFIG - F_CONFIG source from configuration file */
#define SRC_CONFIG    1
/** @def SRC_HOSTS - F_CONFIG source from /etc/hosts */
#define SRC_HOSTS     2
/** @def SRC_AH - F_CONFIG source from authoritative hosts */
#define SRC_AH        3


/* struct sockaddr is not large enough to hold any address,
   and specifically not big enough to hold an IPv6 address.
   Blech. Roll our own. */
union mysockaddr {
  struct sockaddr sa;
  struct sockaddr_in in;
  struct sockaddr_in6 in6;
};

/* bits in flag param to IPv6 callbacks from iface_enumerate() */
#define IFACE_TENTATIVE   1
#define IFACE_DEPRECATED  2
#define IFACE_PERMANENT   4


/* The actual values here matter, since we sort on them to get records in the order
   IPv6 addr, IPv4 addr, all zero return, resolvconf servers, upstream server, no-data return  */
#define SERV_LITERAL_ADDRESS    1  /* addr is the answer, or NoDATA is the answer, depending on the next four flags */
#define SERV_USE_RESOLV         2  /* forward this domain in the normal way */
#define SERV_ALL_ZEROS          4  /* return all zeros for A and AAAA */
#define SERV_4ADDR              8  /* addr is IPv4 */
#define SERV_6ADDR             16  /* addr is IPv6 */
#define SERV_HAS_SOURCE        32  /* source address defined */
#define SERV_FOR_NODOTS        64  /* server for names with no domain part only */
#define SERV_WARNED_RECURSIVE 128  /* avoid warning spam */
#define SERV_FROM_DBUS        256  /* 1 if source is DBus */
#define SERV_MARK             512  /* for mark-and-delete and log code */
#define SERV_WILDCARD        1024  /* domain has leading '*' */ 
#define SERV_FROM_RESOLV     2048  /* 1 for servers from resolv, 0 for command line. */
#define SERV_FROM_FILE       4096  /* read from --servers-file */
#define SERV_LOOP            8192  /* server causes forwarding loop */
#define SERV_DO_DNSSEC      16384  /* Validate DNSSEC when using this server */
#define SERV_GOT_TCP        32768  /* Got some data from the TCP connection */

/**
 * @struct serverfd
 * @brief File descriptor wrapper for upstream DNS server sockets
 *
 * Tracks socket file descriptors used for communicating with upstream DNS servers.
 * Multiple servers may share sockets based on interface binding requirements.
 *
 * LIFECYCLE: Allocated during server initialization, persists for daemon lifetime.
 * Freed only on reconfiguration or shutdown.
 *
 * @var serverfd::fd - Socket file descriptor for DNS queries
 * @var serverfd::source_addr - Local address bound to this socket
 * @var serverfd::interface - Interface name this socket is bound to
 * @var serverfd::ifindex - Numeric interface index for socket binding
 * @var serverfd::used - Reference count: number of servers using this fd
 * @var serverfd::preallocated - Flag: socket preallocated during init
 * @var serverfd::next - Next fd in linked list
 */
struct serverfd {
  int fd;
  union mysockaddr source_addr;
  char interface[IF_NAMESIZE+1];
  unsigned int ifindex, used, preallocated;
  struct serverfd *next;
};

/**
 * @struct randfd
 * @brief Randomized file descriptor for DNS query source port randomization
 *
 * Provides per-server randomized source ports for DNS cache poisoning prevention.
 * Maintains pool of sockets with random source ports for query security.
 *
 * @var randfd::serv - Server this randomized fd is allocated to
 * @var randfd::fd - Socket file descriptor with random source port
 * @var randfd::refcount - Active query count using this fd (0xffff = overflow)
 */
struct randfd {
  struct server *serv;
  int fd;
  unsigned short refcount; /* refcount == 0xffff means overflow record. */
};

/**
 * @struct randfd_list
 * @brief List node for managing randomized file descriptor pool
 * @var randfd_list::rfd - Pointer to randfd structure
 * @var randfd_list::next - Next node in list
 */
struct randfd_list {
  struct randfd *rfd;
  struct randfd_list *next;
};

/**
 * @struct server
 * @brief Upstream DNS server configuration with health tracking and statistics
 *
 * Each server record represents one upstream DNS server (or group of servers for
 * a specific domain). Servers can be global (for all queries) or domain-specific
 * (for queries matching configured domain suffix). Health metrics track failures
 * and successes for intelligent server selection and failover.
 *
 * LIFECYCLE:
 * - Created during configuration parsing by option.c read_opts()
 * - Linked into daemon->servers list
 * - Updated during SIGHUP reload if configuration changes
 * - Persists for daemon lifetime or until removed by reload
 * - Query statistics and timestamps updated on every query/response
 *
 * MEMORY LAYOUT: ~200 bytes per server. Typical deployment: 2-5 servers = 1KB total.
 *
 * USAGE PATTERN:
 * 1. Query arrives → forward.c forward_query() searches daemon->servers list
 * 2. If domain-specific servers match query domain, use those; else use global
 * 3. Select server based on health (lowest failed_queries, most recent success)
 * 4. Send query via server->addr, increment queries counter
 * 5. On timeout/error: increment failed_queries, try next server
 * 6. On success: reset failed_queries, update forwardtime (last successful response)
 * 7. Periodic health check rotates through servers (FORWARD_TEST interval)
 *
 * @var server::flags
 * Server type and behavior flags:
 * - SERV_LITERAL_ADDRESS: Return literal address without forwarding
 * - SERV_NO_ADDR: Return NXDOMAIN for this domain
 * - SERV_USE_RESOLV: Server from /etc/resolv.conf (monitor for changes)
 * - SERV_FROM_DBUS: Server configured via D-Bus interface
 * - SERV_DO_DNSSEC: Forward with DNSSEC DO bit set
 * - SERV_HAS_DOMAIN: Domain-specific server (not global)
 * - SERV_FOR_NODOTS: Only for queries without dots
 *
 * @var server::domain_len
 * Length of domain suffix string in bytes. Zero for global servers (match all queries).
 * Used for fast domain matching without strlen().
 *
 * @var server::domain
 * Domain suffix this server handles (e.g., "example.com"). NULL for global servers
 * that handle all queries. Queries ending with this suffix are routed to this server.
 *
 * @var server::next
 * Next server in daemon->servers linked list. List traversed sequentially during
 * server selection in forward_query().
 *
 * @var server::serial
 * Serial number for tracking server list changes during reload. Incremented on
 * each configuration reload to identify stale servers.
 *
 * @var server::arrayposn
 * Position in daemon->serverarray[] sorted array. Used for binary search during
 * server selection for performance optimization.
 *
 * @var server::last_server
 * Index of last server tried for load distribution. Implements round-robin within
 * same-health servers.
 *
 * @var server::addr
 * Upstream server socket address (IPv4 or IPv6). Queries sent to this address.
 * Union mysockaddr allows dual-stack without conditional compilation.
 *
 * @var server::source_addr
 * Local source address for queries to this server. Used for interface-specific
 * server binding (--server=1.2.3.4@eth0).
 *
 * @var server::interface
 * Interface name for source address binding (e.g., "eth0"). Empty string if not
 * bound to specific interface.
 *
 * @var server::ifindex
 * Numeric interface index corresponding to interface name. Used for socket binding
 * via SO_BINDTODEVICE (Linux) or equivalent.
 *
 * @var server::sfd
 * Pointer to serverfd managing socket for this server. Multiple servers may share
 * socket if interface binding identical.
 *
 * @var server::tcpfd
 * TCP socket file descriptor for this server. Created on-demand when UDP response
 * truncated (TC bit set), reused for subsequent TCP queries to same server.
 *
 * @var server::edns_pktsz
 * EDNS0 buffer size negotiated with this server. Starts at EDNS_PKTSZ (4096),
 * reduced if server sends truncated responses even with EDNS0. Adaptive sizing.
 *
 * @var server::pktsz_reduced
 * Timestamp when edns_pktsz was last reduced. Used for timeout-based retry with
 * larger size after UDP_TEST_TIME seconds.
 *
 * @var server::queries
 * Total queries sent to this server since daemon start or last reload. Monotonically
 * increasing. Used for load balancing and statistics (SIGUSR1 dump).
 *
 * @var server::failed_queries
 * Count of consecutive query failures (timeouts, SERVFAIL). Reset to zero on first
 * successful response. High failed_queries deprioritizes server in selection.
 * Implements automatic failover to healthier servers.
 *
 * @var server::forwardtime
 * Timestamp of last successful query response from this server. Used to calculate
 * server health: recent success preferred over old success. Drives FORWARD_TEST
 * periodic retry of failed servers.
 *
 * @var server::forwardcount
 * Number of successful queries since last health check cycle (FORWARD_TEST queries).
 * Reset periodically to ensure all servers tried, preventing starvation of recovered
 * servers.
 *
 * @var server::uid
 * Unique identifier for loop detection (if HAVE_LOOP compiled). Detects forwarding
 * loops where query cycles through dnsmasq instances.
 *
 * @see forward.c forward_query() for server selection algorithm using health metrics
 * @see forward.c server_send() for query transmission and error handling
 * @see option.c for server configuration parsing from --server options
 * @see config.h FORWARD_TEST and FORWARD_TIME for health check intervals
 */
struct server {
  u16 flags, domain_len;
  char *domain;
  struct server *next;
  int serial, arrayposn;
  int last_server;
  union mysockaddr addr, source_addr;
  char interface[IF_NAMESIZE+1];
  unsigned int ifindex; /* corresponding to interface, above */
  struct serverfd *sfd; 
  int tcpfd, edns_pktsz;
  time_t pktsz_reduced;
  unsigned int queries, failed_queries;
  time_t forwardtime;
  int forwardcount;
#ifdef HAVE_LOOP
  u32 uid;
#endif
};

/* First four fields must match struct server in next three definitions.. */
struct serv_addr4 {
  u16 flags, domain_len;
  char *domain;
  struct server *next;
  struct in_addr addr;
};

struct serv_addr6 {
  u16 flags, domain_len;
  char *domain;
  struct server *next;
  struct in6_addr addr;
};

/**
 * @struct serv_local
 * @brief Local domain configuration for authoritative responses
 *
 * Defines domains answered locally without upstream forwarding. Used for --local directive.
 * Queries matching these domains generate immediate responses from local data (hosts files,
 * DHCP leases, static records) without consulting upstream servers.
 *
 * @var serv_local::flags - Server flags indicating local response characteristics
 * @var serv_local::domain_len - Length of domain string in bytes (optimization)
 * @var serv_local::domain - Domain name string for local authority
 * @var serv_local::next - Next local domain configuration (reuses server list structure)
 */
struct serv_local {
  u16 flags, domain_len;
  char *domain;
  struct server *next;
};

/**
 * @struct rebind_domain
 * @brief DNS rebinding attack protection exception domain
 *
 * Configures domains excluded from DNS rebinding protection (--stop-dns-rebind with exceptions).
 * Rebinding protection blocks responses containing private/local addresses to prevent attacks
 * where external attacker-controlled DNS returns local addresses. Exception domains allow
 * legitimate local DNS responses for specified domains.
 *
 * @var rebind_domain::domain - Domain name exempt from rebind protection
 * @var rebind_domain::next - Next exception domain in linked list
 */
struct rebind_domain {
  char *domain;
  struct rebind_domain *next;
};

/**
 * @struct ipsets
 * @brief Linux ipset integration configuration for resolved addresses
 *
 * Defines ipset(s) to add resolved addresses to (--ipset directive). When dnsmasq resolves
 * queries for specified domain, adds resulting A/AAAA addresses to configured Linux ipset(s).
 * Enables firewall rules based on DNS resolution (block/allow traffic to dynamically resolved
 * addresses, QoS policies, traffic shaping).
 *
 * @var ipsets::sets - NULL-terminated array of ipset names to update with resolved addresses
 * @var ipsets::domain - Domain pattern for matching queries (suffix match)
 * @var ipsets::next - Next ipset configuration in list
 */
struct ipsets {
  char **sets;
  char *domain;
  struct ipsets *next;
};

/**
 * @struct allowlist
 * @brief Linux conntrack mark-based query filtering
 *
 * Implements query filtering based on netfilter connection tracking marks (--dhcp-host with
 * net: identifier). Queries from connections with matching conntrack mark (after masking)
 * are associated with specified DHCP network tags. Enables DHCP policy based on firewall
 * classification of client connections.
 *
 * @var allowlist::mark - Expected conntrack mark value (after masking)
 * @var allowlist::mask - Bitmask applied to connection mark before comparison
 * @var allowlist::patterns - NULL-terminated array of network tag patterns to apply
 * @var allowlist::next - Next allowlist rule in chain
 */
struct allowlist {
  u32 mark, mask;
  char **patterns;
  struct allowlist *next;
};

/**
 * @struct irec
 * @brief Interface record with address and service capabilities
 *
 * Represents a network interface discovered by dnsmasq with its address, netmask, and
 * capabilities. Each interface can serve DNS, DHCP, and/or TFTP based on configuration
 * and flags. List of irec structures maintained by network.c from interface enumeration
 * (Linux netlink, BSD routing sockets, or SIOCGIFCONF ioctl).
 *
 * @var irec::addr - Interface address (IPv4 or IPv6) as sockaddr union
 * @var irec::netmask - IPv4 netmask (only valid for IPv4 addresses)
 * @var irec::tftp_ok - Non-zero if TFTP server enabled on this interface
 * @var irec::dhcp_ok - Non-zero if DHCP server enabled on this interface
 * @var irec::mtu - Interface MTU (Maximum Transmission Unit) in bytes
 * @var irec::done - Processing completion flag (internal state)
 * @var irec::warned - Warning issued flag (avoid duplicate warnings)
 * @var irec::dad - Duplicate Address Detection in progress (IPv6)
 * @var irec::dns_auth - DNS authoritative on this interface
 * @var irec::index - OS interface index number (for setsockopt IPV6_PKTINFO)
 * @var irec::multicast_done - Multicast group joined flag
 * @var irec::found - Interface found during enumeration scan
 * @var irec::label - Interface label/alias indicator
 * @var irec::name - Interface name string (e.g., "eth0", "wlan0")
 * @var irec::next - Next interface record in linked list
 */
struct irec {
  union mysockaddr addr;
  struct in_addr netmask; /* only valid for IPv4 */
  int tftp_ok, dhcp_ok, mtu, done, warned, dad, dns_auth, index, multicast_done, found, label;
  char *name; 
  struct irec *next;
};

/**
 * @struct listener
 * @brief Socket listener for DNS/TCP/TFTP services
 *
 * Represents a listening socket bound to specific address for DNS, TCP DNS, or TFTP service.
 * Multiple listeners created for wildcard (0.0.0.0/::) and interface-specific bindings.
 * Poll loop monitors all listener file descriptors for incoming connections/packets.
 *
 * @var listener::fd - UDP DNS socket file descriptor (main DNS service)
 * @var listener::tcpfd - TCP DNS socket file descriptor (-1 if TCP disabled)
 * @var listener::tftpfd - TFTP UDP socket file descriptor (-1 if TFTP disabled)
 * @var listener::used - Reference count or usage flag (managed by network.c)
 * @var listener::addr - Socket bind address (sockaddr union)
 * @var listener::iface - Associated interface record (NULL for wildcard listeners)
 * @var listener::next - Next listener in linked list
 */
struct listener {
  int fd, tcpfd, tftpfd, used;
  union mysockaddr addr;
  struct irec *iface; /* only sometimes valid for non-wildcard */
  struct listener *next;
};

/**
 * @struct iname
 * @brief Interface and address parameters from command line
 *
 * Stores interface names and addresses specified via --interface, --listen-address, or
 * --except-interface command-line options. Used during startup to filter which interfaces
 * dnsmasq binds to. After processing, used flag indicates interface was found and configured.
 *
 * @var iname::name - Interface name string (e.g., "eth0") or NULL if address-only
 * @var iname::addr - Specific address to bind (if provided)
 * @var iname::used - Flag indicating this interface/address was successfully bound
 * @var iname::next - Next interface specification in list
 */
struct iname {
  char *name;
  union mysockaddr addr;
  int used;
  struct iname *next;
};

/**
 * @struct mysubnet
 * @brief Subnet parameters from command line
 *
 * Represents subnet specification from --dhcp-range or related directives. Defines network
 * address and prefix/mask length for subnet-based configuration and address allocation.
 *
 * @var mysubnet::addr - Subnet network address (base address)
 * @var mysubnet::addr_used - Flag indicating address field is valid
 * @var mysubnet::mask - Prefix length (CIDR notation, e.g., 24 for /24) or old-style netmask
 */
struct mysubnet {
  union mysockaddr addr;
  int addr_used;
  int mask;
};

/**
 * @struct resolvc
 * @brief Resolv-file parameters from command line
 *
 * Tracks /etc/resolv.conf or alternate resolution configuration files (--resolv-file directive).
 * Monitors file modification time to detect changes and reload upstream servers. Supports
 * multiple resolv files and dynamic reconfiguration via SIGHUP or inotify.
 *
 * @var resolvc::next - Next resolv configuration file in list
 * @var resolvc::is_default - Non-zero if this is the default /etc/resolv.conf
 * @var resolvc::logged - Non-zero if file access errors already logged (avoid spam)
 * @var resolvc::mtime - File modification time (last known) for change detection
 * @var resolvc::ino - File inode number for change detection (handles file replacement)
 * @var resolvc::name - File path string
 */
struct resolvc {
  struct resolvc *next;
  int is_default, logged;
  time_t mtime;
  ino_t ino;
  char *name;
#ifdef HAVE_INOTIFY
  int wd; /* inotify watch descriptor */
  char *file; /* pointer to file part if path */
#endif
};

/* adn-hosts parms from command-line (also dhcp-hostsfile and dhcp-optsfile and dhcp-hostsdir*/
/** @def AH_DIR - Hostsfile entry is a directory (scan for files) */
#define AH_DIR      1
/** @def AH_INACTIVE - Hostsfile temporarily inactive (parsing error, inaccessible) */
#define AH_INACTIVE 2
/** @def AH_WD_DONE - Inotify watch descriptor setup completed */
#define AH_WD_DONE  4
/** @def AH_HOSTS - Hostsfile for DNS hosts entries (--addn-hosts, /etc/hosts) */
#define AH_HOSTS    8
/** @def AH_DHCP_HST - Hostsfile for DHCP host configuration (--dhcp-hostsfile) */
#define AH_DHCP_HST 16
/** @def AH_DHCP_OPT - Hostsfile for DHCP options configuration (--dhcp-optsfile) */
#define AH_DHCP_OPT 32

/**
 * @struct hostsfile
 * @brief Hosts file or directory tracking for DNS and DHCP data
 *
 * Tracks additional hosts files (--addn-hosts), DHCP hosts files (--dhcp-hostsfile),
 * DHCP options files (--dhcp-optsfile), and directories containing such files. Monitors
 * files for changes using inotify (Linux) or periodic polling, reloading data when modified.
 * Enables dynamic host/DHCP configuration without daemon restart.
 *
 * LIFECYCLE:
 * - Created during option parsing (option.c) for each --addn-hosts, --dhcp-hostsfile, etc.
 * - If directory (AH_DIR), expanded to multiple entries for contained files
 * - Inotify watch registered if HAVE_INOTIFY compiled (Linux)
 * - Files periodically checked for modifications, reloaded on change
 * - Persists for daemon lifetime
 *
 * @var hostsfile::next - Next hosts file in linked list
 * @var hostsfile::flags - AH_* flags indicating type and state (AH_DIR, AH_HOSTS, AH_DHCP_HST, etc.)
 * @var hostsfile::fname - File or directory path string
 * @var hostsfile::wd - Inotify watch descriptor (Linux only, if HAVE_INOTIFY)
 * @var hostsfile::index - Unique index for this hostsfile, used in cache entries for logging correlation
 */
struct hostsfile {
  struct hostsfile *next;
  int flags;
  char *fname;
#ifdef HAVE_INOTIFY
  int wd; /* inotify watch descriptor */
#endif
  unsigned int index; /* matches to cache entries for logging */
};

/* packet-dump flags */
#define DUMP_QUERY         0x0001
#define DUMP_REPLY         0x0002
#define DUMP_UP_QUERY      0x0004 
#define DUMP_UP_REPLY      0x0008
#define DUMP_SEC_QUERY     0x0010
#define DUMP_SEC_REPLY     0x0020
#define DUMP_BOGUS         0x0040 
#define DUMP_SEC_BOGUS     0x0080
#define DUMP_DHCP          0x1000
#define DUMP_DHCPV6        0x2000
#define DUMP_RA            0x4000
#define DUMP_TFTP          0x8000

/* DNSSEC status values. */
#define STAT_SECURE             0x10000
#define STAT_INSECURE           0x20000
#define STAT_BOGUS              0x30000
#define STAT_NEED_DS            0x40000
#define STAT_NEED_KEY           0x50000
#define STAT_TRUNCATED          0x60000
#define STAT_SECURE_WILDCARD    0x70000
#define STAT_OK                 0x80000
#define STAT_ABANDONED          0x90000

#define DNSSEC_FAIL_NYV         0x0001 /* key not yet valid */
#define DNSSEC_FAIL_EXP         0x0002 /* key expired */
#define DNSSEC_FAIL_INDET       0x0004 /* indetermined */
#define DNSSEC_FAIL_NOKEYSUP    0x0008 /* no supported key algo. */
#define DNSSEC_FAIL_NOSIG       0x0010 /* No RRsigs */
#define DNSSEC_FAIL_NOZONE      0x0020 /* No Zone bit set */
#define DNSSEC_FAIL_NONSEC      0x0040 /* No NSEC */
#define DNSSEC_FAIL_NODSSUP     0x0080 /* no supported DS algo. */
#define DNSSEC_FAIL_NOKEY       0x0100 /* no DNSKEY */

#define STAT_ISEQUAL(a, b)  (((a) & 0xffff0000) == (b))

#define FREC_NOREBIND           1
#define FREC_CHECKING_DISABLED  2
#define FREC_NO_CACHE           4
#define FREC_DNSKEY_QUERY       8
#define FREC_DS_QUERY          16
#define FREC_AD_QUESTION       32
#define FREC_DO_QUESTION       64
#define FREC_ADDED_PHEADER    128
#define FREC_TEST_PKTSZ       256
#define FREC_HAS_EXTRADATA    512
/** @def FREC_HAS_PHEADER - Forward record has saved packet header (for DNSSEC) */
#define FREC_HAS_PHEADER     1024

/** @def HASH_SIZE - SHA-256 digest size for query hashing (32 bytes) */
#define HASH_SIZE 32 /* SHA-256 digest size */

/**
 * @struct frec
 * @brief Forward record tracking DNS query transaction lifecycle
 *
 * Forward records (frec) track in-flight DNS queries from clients through dnsmasq to
 * upstream servers and back. Each frec maintains query state including original client,
 * selected upstream server, query ID randomization (for cache poisoning prevention),
 * and timeout tracking. For DNSSEC queries, frec tracks validation dependencies.
 *
 * LIFECYCLE:
 * - Pre-allocated freelist of FTABSIZ (150 default) frec structures at daemon start
 * - Allocated by allocate_frec() when query arrives, marked in-use by setting sentto
 * - Persists while query outstanding to upstream (typically 0.01-2 seconds)
 * - Freed by free_frec() when response received or query times out
 * - Returns to freelist for reuse (not deallocated to OS)
 * - FTABSIZ limits concurrent outstanding queries
 *
 * MEMORY LAYOUT: ~150 bytes base + DNSSEC fields if compiled. Total pool ~22KB for
 * FTABSIZ=150. Small memory footprint enables handling hundreds of concurrent queries.
 *
 * USAGE PATTERN:
 * 1. Client query arrives → forward.c receive_query()
 * 2. Allocate frec, save client source address and original query ID
 * 3. Randomize query ID (new_id) for cache poisoning prevention
 * 4. Select upstream server → forward_query(), set frec->sentto
 * 5. Send query to upstream with new_id
 * 6. Response arrives → reply_query() matches by new_id
 * 7. Restore original ID, forward response to client
 * 8. Free frec back to pool
 *
 * @var frec::frec_src
 * Embedded struct holding client source information. May chain multiple sources if
 * query forwarded from multiple clients (identical queries coalesced).
 *
 * @var frec_src::source
 * Original client socket address (IPv4/IPv6). Response sent back to this address.
 *
 * @var frec_src::dest
 * Destination address client query was sent to (dnsmasq listen address). Needed for
 * multi-homed configurations to send response from correct source address.
 *
 * @var frec_src::iface
 * Interface index query arrived on. Used for interface-specific responses.
 *
 * @var frec_src::log_id
 * Unique identifier for query logging correlation (ties query and response logs).
 *
 * @var frec_src::fd
 * File descriptor to send response on (UDP socket or TCP connection).
 *
 * @var frec_src::orig_id
 * Original DNS query ID from client packet. Restored before forwarding response back.
 * Randomized to new_id when forwarding upstream for security.
 *
 * @var frec_src::next
 * Next client source if multiple clients sent identical query. Allows single upstream
 * query to satisfy multiple clients (query coalescing).
 *
 * @var frec::sentto
 * Pointer to struct server query was sent to. NULL indicates frec is free (available
 * in freelist). Non-NULL marks frec as allocated/in-use. Checked by allocate_frec()
 * when searching for free frec.
 *
 * @var frec::rfds
 * List of randomized file descriptors used for this query. Provides source port
 * randomization for cache poisoning resistance (birthday attack mitigation).
 *
 * @var frec::new_id
 * Randomized DNS query ID used in upstream query. Different from orig_id to prevent
 * query ID prediction attacks. Generated by rand16() from util.c.
 *
 * @var frec::forwardall
 * Flag for --all-servers mode: query sent to all upstream servers in parallel, use
 * fastest response. Non-zero count of servers query sent to.
 *
 * @var frec::flags
 * Query processing flags: FREC_HAS_PHEADER (saved packet header for DNSSEC),
 * FREC_DO_QUESTION (DNSSEC DO bit set), FREC_CHECKING_DISABLED (CD bit set).
 *
 * @var frec::time
 * Timestamp when query forwarded to upstream. Used for timeout detection (TIMEOUT
 * seconds from config.h). Stale frecs with time < now - TIMEOUT are freed.
 *
 * @var frec::hash
 * SHA-256 hash of DNS question section (HASH_SIZE=32 bytes). Used for query matching
 * and loop detection. Calculated by hash-questions.c for cache poisoning prevention.
 *
 * @var frec::class
 * DNS class of query (typically IN=1). Stored for DNSSEC validation context when
 * HAVE_DNSSEC compiled.
 *
 * @var frec::work_counter
 * DNSSEC work limiter preventing excessive validation queries. Incremented for each
 * validation step, query aborted if exceeds DNSSEC_WORK limit (50 default).
 *
 * @var frec::stash
 * Saved DNS response packet (blockdata chain) while DNSSEC validation in progress.
 * Response held until validation completes or fails.
 *
 * @var frec::stash_len
 * Length of stashed response packet in bytes.
 *
 * @var frec::dependent
 * Pointer to frec representing dependent DNSSEC query (DNSKEY/DS lookup). This frec
 * is blocked waiting for dependent query to complete before validation proceeds.
 *
 * @var frec::next_dependent
 * Next frec in list of dependents. Multiple queries may depend on same DNSKEY fetch.
 *
 * @var frec::blocking_query
 * Pointer to frec that is blocking this query. Inverse of dependent relationship.
 * This frec waits for blocking_query to complete.
 *
 * @var frec::next
 * Next frec in linked list. Used for freelist chain (when sentto==NULL) or hash
 * collision chain during query lookup.
 *
 * @see forward.c allocate_frec() for forward record allocation from freelist
 * @see forward.c free_frec() for forward record deallocation back to freelist
 * @see forward.c forward_query() for query forwarding using frec
 * @see forward.c reply_query() for response matching by new_id using frec
 * @see config.h FTABSIZ for maximum concurrent queries (freelist size)
 * @see config.h TIMEOUT for query timeout in seconds
 */
struct frec {
  struct frec_src {
    union mysockaddr source;
    union all_addr dest;
    unsigned int iface, log_id;
    int fd;
    unsigned short orig_id;
    struct frec_src *next;
  } frec_src;
  struct server *sentto; /* NULL means free */
  struct randfd_list *rfds;
  unsigned short new_id;
  int forwardall, flags;
  time_t time;
  unsigned char *hash[HASH_SIZE];
#ifdef HAVE_DNSSEC 
  int class, work_counter;
  struct blockdata *stash; /* Saved reply, whilst we validate */
  size_t stash_len;
  struct frec *dependent; /* Query awaiting internally-generated DNSKEY or DS query */
  struct frec *next_dependent; /* list of above. */
  struct frec *blocking_query; /* Query which is blocking us. */
#endif
  struct frec *next;
};

/* flags in top of length field for DHCP-option tables */
#define OT_ADDR_LIST    0x8000
#define OT_RFC1035_NAME 0x4000
#define OT_INTERNAL     0x2000
#define OT_NAME         0x1000
#define OT_CSTRING      0x0800
#define OT_DEC          0x0400 
#define OT_TIME         0x0200

/* actions in the daemon->helper RPC */
#define ACTION_DEL           1
#define ACTION_OLD_HOSTNAME  2
#define ACTION_OLD           3
#define ACTION_ADD           4
#define ACTION_TFTP          5
#define ACTION_ARP           6
#define ACTION_ARP_DEL       7
#define ACTION_RELAY_SNOOP   8

/** @def LEASE_NEW - Newly created lease, not yet persisted to lease file */
#define LEASE_NEW            1  /* newly created */
/** @def LEASE_CHANGED - Lease modified, needs write to lease file */
#define LEASE_CHANGED        2  /* modified */
/** @def LEASE_AUX_CHANGED - CLID or expiry changed, lease file update needed */
#define LEASE_AUX_CHANGED    4  /* CLID or expiry changed */
/** @def LEASE_AUTH_NAME - Hostname from config file (authoritative), not client */
#define LEASE_AUTH_NAME      8  /* hostname came from config, not from client */
/** @def LEASE_USED - Lease used this DHCPv6 transaction (prevents duplicate assignment) */
#define LEASE_USED          16  /* used this DHCPv6 transaction */
/** @def LEASE_NA - IPv6 IA_NA (non-temporary address) per RFC 3315 Section 10 */
#define LEASE_NA            32  /* IPv6 no-temporary lease */
/** @def LEASE_TA - IPv6 IA_TA (temporary address) per RFC 3315 Section 10 */
#define LEASE_TA            64  /* IPv6 temporary lease */
/** @def LEASE_HAVE_HWADDR - Hardware address (MAC) populated in lease record */
#define LEASE_HAVE_HWADDR  128  /* Have set hwaddress */
/** @def LEASE_EXP_CHANGED - Lease expiry time changed (RENEW/REBIND), update file */
#define LEASE_EXP_CHANGED  256  /* Lease expiry time changed */

/**
 * @struct dhcp_lease
 * @brief DHCP lease tracking client IP address assignment and expiry
 *
 * Central lease tracking structure storing DHCPv4 and DHCPv6 address allocations.
 * Leases persist across daemon restarts via lease database file (typically
 * /var/lib/misc/dnsmasq.leases). Each lease uniquely identified by client identifier
 * (CLID for DHCPv6) or MAC address (DHCPv4). Expired leases freed for reallocation.
 *
 * LIFECYCLE:
 * - Created by lease_allocate() when client performs DHCP handshake (DISCOVER/REQUEST)
 * - Persisted to lease file by lease_update_file() on LEASE_NEW or LEASE_CHANGED
 * - Updated on RENEW/REBIND (extends expiry time, sets LEASE_EXP_CHANGED)
 * - Hostname updated from DHCP option 12 (hostname) or option 81 (FQDN)
 * - Expired leases detected by lease_expire(), freed for reuse
 * - RELEASE message immediately expires lease
 * - Deleted explicitly by lease_delete() or implicitly on expiry
 * - Survives daemon restart if lease file read successfully
 *
 * MEMORY LAYOUT: ~150 bytes base + clid length + hostname length + extradata.
 * Typical 50 active leases consume ~10KB. MAXLEASES (1000 default) limits total.
 *
 * USAGE PATTERN:
 * 1. Client DISCOVER → dhcp.c allocate_address()
 * 2. Find free IP from dhcp_context range
 * 3. Create lease via lease_allocate(), save client CLID and MAC
 * 4. Send OFFER with allocated address
 * 5. Client REQUEST → lease confirmed
 * 6. lease_update_file() persists to disk atomically
 * 7. Lease active until expires timestamp (typically T1=50%, T2=87.5% of lease time)
 * 8. Client RENEW extends expiry, sets LEASE_EXP_CHANGED
 * 9. On expiry, lease freed by lease_expire() for reallocation
 *
 * @var dhcp_lease::clid_len
 * Length of client identifier (CLID) in bytes. DHCPv6 DUID length (variable, typically
 * 14-30 bytes). DHCPv4 may use option 61 CLID. Zero if no CLID provided.
 *
 * @var dhcp_lease::clid
 * Client identifier bytes. DHCPv6 DUID per RFC 3315 Section 9 (DUID-LLT, DUID-EN,
 * DUID-LL). DHCPv4 option 61 if provided. Dynamically allocated, freed with lease.
 *
 * @var dhcp_lease::hostname
 * Client hostname from DHCP option 12 (hostname) or option 81 (FQDN), or static
 * assignment from dhcp-host config. Registered in DNS cache if --dhcp-fqdn enabled.
 * NULL if client provides no hostname.
 *
 * @var dhcp_lease::fqdn
 * Fully qualified domain name if different from hostname. Used when domain appended.
 *
 * @var dhcp_lease::old_hostname
 * Previous hostname before client changed it. Allows DNS cache cleanup of stale name.
 * Freed after cache purged.
 *
 * @var dhcp_lease::flags
 * Bitfield of LEASE_* flags: LEASE_NEW, LEASE_CHANGED, LEASE_AUX_CHANGED control
 * lease file persistence. LEASE_AUTH_NAME marks hostname from config (authoritative).
 * LEASE_NA/LEASE_TA distinguish IPv6 address types.
 *
 * @var dhcp_lease::expires
 * Absolute timestamp when lease expires (time_t seconds since epoch). Client must
 * RENEW before expiry or address reclaimed. For HAVE_BROKEN_RTC (embedded without
 * RTC), uses relative seconds stored in length field.
 *
 * @var dhcp_lease::length
 * Lease duration in seconds for systems with HAVE_BROKEN_RTC (no real-time clock).
 * Used instead of absolute expires timestamp. Recalculated on each daemon start.
 *
 * @var dhcp_lease::hwaddr_len
 * Hardware address length in bytes (6 for Ethernet MAC, 0 if unavailable).
 *
 * @var dhcp_lease::hwaddr_type
 * Hardware address type per RFC 1700 ARP hardware types (1=Ethernet, 6=IEEE 802,
 * 32=InfiniBand). Matches DHCP option htype field.
 *
 * @var dhcp_lease::hwaddr
 * Hardware address bytes (MAC address for Ethernet). DHCP_CHADDR_MAX (16) bytes max.
 * Used for DHCPv4 lease lookup if CLID absent.
 *
 * @var dhcp_lease::addr
 * Allocated IPv4 address (DHCPv4 lease). Network byte order. Zero if DHCPv6-only.
 *
 * @var dhcp_lease::override
 * Override address from dhcp-host config. Takes precedence over dynamic allocation.
 *
 * @var dhcp_lease::giaddr
 * Gateway IP address (relay agent) for DHCP relay scenarios. Zero if direct client.
 *
 * @var dhcp_lease::extradata
 * Variable-length extra data storage for vendor-specific options, user class, etc.
 * Dynamically allocated byte array.
 *
 * @var dhcp_lease::extradata_len
 * Current used length of extradata in bytes.
 *
 * @var dhcp_lease::extradata_size
 * Allocated size of extradata buffer (may exceed len for reallocation efficiency).
 *
 * @var dhcp_lease::last_interface
 * Interface index lease last seen on. Tracks client mobility across interfaces.
 *
 * @var dhcp_lease::new_interface
 * New interface index if client moved. Saved during lease update.
 *
 * @var dhcp_lease::new_prefixlen
 * New prefix length if client moved to different subnet.
 *
 * @var dhcp_lease::addr6
 * Allocated IPv6 address (DHCPv6 IA_NA or IA_TA lease). 128-bit address.
 *
 * @var dhcp_lease::iaid
 * DHCPv6 Identity Association Identifier (IAID) per RFC 3315 Section 10. Client-chosen
 * unique identifier for this IA (typically interface-specific).
 *
 * @var dhcp_lease::slaac_address
 * Linked list of SLAAC (Stateless Address Autoconfiguration) addresses associated with
 * this lease. RFC 4862 addresses formed from RA prefix + client EUI-64.
 *
 * @var dhcp_lease::vendorclass_count
 * Count of vendor class options received. Used for vendor-specific processing.
 *
 * @var dhcp_lease::next
 * Next lease in linked list. All leases chained for iteration and search.
 *
 * @see lease.c lease_allocate() for creating new DHCP leases
 * @see lease.c lease_update_file() for atomic lease file persistence
 * @see lease.c lease_expire() for expired lease reclamation
 * @see dhcp.c dhcp_reply() for DHCPv4 lease assignment in protocol handler
 * @see dhcp6.c dhcp6_reply() for DHCPv6 lease assignment in protocol handler
 * @see config.h MAXLEASES for maximum concurrent leases (1000 default)
 */
struct dhcp_lease {
  int clid_len;          /* length of client identifier */
  unsigned char *clid;   /* clientid */
  char *hostname, *fqdn; /* name from client-hostname option or config */
  char *old_hostname;    /* hostname before it moved to another lease */
  int flags;
  time_t expires;        /* lease expiry */
#ifdef HAVE_BROKEN_RTC
  unsigned int length;
#endif
  int hwaddr_len, hwaddr_type;
  unsigned char hwaddr[DHCP_CHADDR_MAX]; 
  struct in_addr addr, override, giaddr;
  unsigned char *extradata;
  unsigned int extradata_len, extradata_size;
  int last_interface;
  int new_interface;     /* save possible originated interface */
  int new_prefixlen;     /* and its prefix length */
#ifdef HAVE_DHCP6
  struct in6_addr addr6;
  unsigned int iaid;
  struct slaac_address {
    struct in6_addr addr;
    time_t ping_time;
    int backoff; /* zero -> confirmed */
    struct slaac_address *next;
  } *slaac_address;
  int vendorclass_count;
#endif
  struct dhcp_lease *next;
};

/**
 * @struct dhcp_netid
 * @brief Tag identifier for conditional DHCP configuration
 *
 * Network tags enable conditional DHCP configuration based on client properties
 * (vendor class, user class, MAC address range, etc.). Tags assigned to clients
 * via dhcp-match directives, then referenced in dhcp-option, dhcp-range, dhcp-host
 * to apply configuration selectively. Supports complex boolean logic (AND/OR/NOT).
 *
 * @var dhcp_netid::net
 * Tag name string (e.g., "vendor:MSFT", "mac:00:11:22:*:*:*", "set:blue").
 *
 * @var dhcp_netid::next
 * Next tag in linked list. Clients may match multiple tags simultaneously.
 */
struct dhcp_netid {
  char *net;
  struct dhcp_netid *next;
};

/**
 * @struct dhcp_netid_list
 * @brief List of network tag sets for AND/OR logic
 *
 * Wrapper structure enabling complex tag matching logic. Each list element
 * represents a set of tags ANDed together. Multiple list elements ORed together.
 * Example: (tag1 AND tag2) OR (tag3 AND tag4).
 *
 * @var dhcp_netid_list::list
 * Pointer to tag set (tags ANDed together).
 *
 * @var dhcp_netid_list::next
 * Next alternative tag set (ORed with this set).
 */
struct dhcp_netid_list {
  struct dhcp_netid *list;
  struct dhcp_netid_list *next;
};

/**
 * @struct tag_if
 * @brief Conditional tag assignment (if-set directive)
 *
 * Implements conditional tag assignment: assign 'tag' if all tags in 'set' are
 * present. Enables tag dependencies and hierarchical classification. Example:
 * "tag-if=set:ipxe,tag:BIOS" assigns 'ipxe' tag if 'BIOS' tag already present.
 *
 * @var tag_if::set
 * List of required tags (all must be present for assignment).
 *
 * @var tag_if::tag
 * Tag to assign if condition met.
 *
 * @var tag_if::next
 * Next conditional tag rule in chain.
 */
struct tag_if {
  struct dhcp_netid_list *set;
  struct dhcp_netid *tag;
  struct tag_if *next;
};

/**
 * @struct delay_config
 * @brief DHCP OFFER delay configuration for network boot coordination
 *
 * Delays DHCP OFFER responses to specific clients (by tag) to coordinate with
 * proxy DHCP servers (PXE boot scenarios). Allows proper PXE protocol sequencing
 * where PXE client needs both DHCP offer and proxy offer before selecting.
 *
 * @var delay_config::delay
 * Delay in seconds before sending OFFER to tagged clients.
 *
 * @var delay_config::netid
 * Tag identifying clients subject to delay.
 *
 * @var delay_config::next
 * Next delay rule in chain.
 */
struct delay_config {
  int delay;
  struct dhcp_netid *netid;
  struct delay_config *next;
};

/**
 * @struct hwaddr_config
 * @brief Hardware address (MAC) configuration with wildcard support
 *
 * MAC address specification for dhcp-host static assignments. Supports wildcard
 * matching (e.g., 00:11:22:*:*:* matches any device from OUI 00:11:22). Enables
 * bulk configuration for device classes without enumerating every MAC.
 *
 * @var hwaddr_config::hwaddr_len
 * Hardware address length in bytes (6 for Ethernet).
 *
 * @var hwaddr_config::hwaddr_type
 * Hardware type per RFC 1700 (1=Ethernet, 6=IEEE 802).
 *
 * @var hwaddr_config::hwaddr
 * MAC address bytes. Wildcarded bytes set to zero.
 *
 * @var hwaddr_config::wildcard_mask
 * Bitmask indicating wildcarded bytes (bit N set = byte N wildcarded).
 *
 * @var hwaddr_config::next
 * Next MAC address alternative. Allows multiple MACs per dhcp-host entry.
 */
struct hwaddr_config {
  int hwaddr_len, hwaddr_type;
  unsigned char hwaddr[DHCP_CHADDR_MAX];
  unsigned int wildcard_mask;
  struct hwaddr_config *next;
};

/**
 * @struct dhcp_config
 * @brief Static DHCP host configuration (dhcp-host directive)
 *
 * Static reservations assigning fixed IP addresses, hostnames, and lease times to
 * specific clients identified by MAC address, client ID, or existing hostname. Takes
 * precedence over dynamic address pool allocation. Configured via dhcp-host directives
 * in configuration file or /etc/ethers integration.
 *
 * LIFECYCLE:
 * - Created by option.c one_opt() when parsing dhcp-host directives
 * - Persists for daemon lifetime (static configuration)
 * - Matched against incoming DHCP requests by lookup_dhcp_config()
 * - Applied before dynamic address allocation from dhcp_context pools
 *
 * @var dhcp_config::flags
 * Bitfield of CONFIG_* flags indicating which fields are configured and entry source.
 *
 * @var dhcp_config::clid_len
 * Client identifier length if matching by CLID (DHCPv6 DUID or DHCPv4 option 61).
 *
 * @var dhcp_config::clid
 * Client identifier bytes for CLID-based matching. Dynamically allocated.
 *
 * @var dhcp_config::hostname
 * Assigned hostname for client. Registered in DNS if --dhcp-fqdn enabled.
 *
 * @var dhcp_config::domain
 * Domain name to append to hostname for FQDN construction.
 *
 * @var dhcp_config::netid
 * Tags to apply to matching clients. Enables tag-based conditional configuration.
 *
 * @var dhcp_config::filter
 * Required tags for this configuration to apply (tag-based filtering).
 *
 * @var dhcp_config::addr6
 * IPv6 address(es) to assign for DHCPv6 static reservations (linked list).
 *
 * @var dhcp_config::addr
 * IPv4 address to assign for DHCPv4 static reservation. Overrides dynamic pool.
 *
 * @var dhcp_config::decline_time
 * Timestamp when address was declined by client (DHCPDECLINE). Address blocked for
 * reuse until decline_time expires (prevents assigning problematic addresses).
 *
 * @var dhcp_config::lease_time
 * Custom lease time in seconds for this client. Overrides default lease time.
 *
 * @var dhcp_config::hwaddr
 * MAC address(es) for matching (linked list, supports wildcards via hwaddr_config).
 *
 * @var dhcp_config::next
 * Next static configuration entry in linked list.
 *
 * @see option.c parse_dhcp_host() for dhcp-host directive parsing
 * @see dhcp-common.c config_has_mac() for MAC-based config lookup
 * @see lease.c lease_update_from_configs() for applying configs to leases
 */
struct dhcp_config {
  unsigned int flags;
  int clid_len;          /* length of client identifier */
  unsigned char *clid;   /* clientid */
  char *hostname, *domain;
  struct dhcp_netid_list *netid;
  struct dhcp_netid *filter;
#ifdef HAVE_DHCP6
  struct addrlist *addr6;
#endif
  struct in_addr addr;
  time_t decline_time;
  unsigned int lease_time;
  struct hwaddr_config *hwaddr;
  struct dhcp_config *next;
};

/** @def have_config - Test if dhcp_config has specific flag set */
#define have_config(config, mask) ((config) && ((config)->flags & (mask))) 

/** @def CONFIG_DISABLE - Config entry disabled (ignore client) */
#define CONFIG_DISABLE           1
/** @def CONFIG_CLID - Client identified by CLID (not MAC address) */
#define CONFIG_CLID              2
/** @def CONFIG_TIME - Custom lease time specified for this client */
#define CONFIG_TIME              8
/** @def CONFIG_NAME - Hostname specified in configuration */
#define CONFIG_NAME             16
/** @def CONFIG_ADDR - IPv4 address specified (static assignment) */
#define CONFIG_ADDR             32
/** @def CONFIG_NOCLID - Ignore client's CLID, match by MAC only */
#define CONFIG_NOCLID          128
/** @def CONFIG_FROM_ETHERS - Entry created from /etc/ethers file */
#define CONFIG_FROM_ETHERS     256    /* entry created by /etc/ethers */
/** @def CONFIG_ADDR_HOSTS - Address added from /etc/hosts file */
#define CONFIG_ADDR_HOSTS      512    /* address added by from /etc/hosts */
/** @def CONFIG_DECLINED - Address declined by client (DHCPDECLINE), temporarily blocked */
#define CONFIG_DECLINED       1024    /* address declined by client */
/** @def CONFIG_BANK - Entry from dhcp-hostsfile (bulk configuration file) */
#define CONFIG_BANK           2048    /* from dhcp hosts file */
/** @def CONFIG_ADDR6 - IPv6 address specified (DHCPv6 static assignment) */
#define CONFIG_ADDR6          4096
/** @def CONFIG_ADDR6_HOSTS - IPv6 address added from /etc/hosts file */
#define CONFIG_ADDR6_HOSTS   16384    /* address added by from /etc/hosts */

/**
 * @struct dhcp_opt
 * @brief DHCP option configuration and encoding
 *
 * Represents configured DHCP option to send to clients (--dhcp-option directive). Supports
 * all DHCP option types (addresses, strings, hex, encapsulation). Options can be conditional
 * based on network tags, vendor class, or other matching criteria.
 *
 * @var dhcp_opt::opt - DHCP option number (1-255, RFC 2132 defines standard options)
 * @var dhcp_opt::len - Option data length in bytes
 * @var dhcp_opt::flags - DHOPT_* flags controlling option behavior and encoding
 * @var dhcp_opt::u - Union for option-specific data (encapsulation ID, wildcard mask, or vendor class)
 * @var dhcp_opt::val - Option value byte array (format depends on option type)
 * @var dhcp_opt::netid - Network tag list for conditional option delivery
 * @var dhcp_opt::next - Next DHCP option in list
 */
struct dhcp_opt {
  int opt, len, flags;
  union {
    int encap;
    unsigned int wildcard_mask;
    unsigned char *vendor_class;
  } u;
  unsigned char *val;
  struct dhcp_netid *netid;
  struct dhcp_opt *next;
};

/** @def DHOPT_ADDR - Option value is IP address(es) */
#define DHOPT_ADDR               1
/** @def DHOPT_STRING - Option value is string */
#define DHOPT_STRING             2
/** @def DHOPT_ENCAPSULATE - Option encapsulates other options (RFC 3046 relay agent) */
#define DHOPT_ENCAPSULATE        4
/** @def DHOPT_ENCAP_MATCH - Match encapsulated option */
#define DHOPT_ENCAP_MATCH        8
/** @def DHOPT_FORCE - Force option even if client doesn't request */
#define DHOPT_FORCE             16
/** @def DHOPT_BANK - Option in separate option bank (not main options) */
#define DHOPT_BANK              32
/** @def DHOPT_ENCAP_DONE - Encapsulation processing completed */
#define DHOPT_ENCAP_DONE        64
/** @def DHOPT_MATCH - Option used for matching criteria */
#define DHOPT_MATCH            128
/** @def DHOPT_VENDOR - Vendor-specific option */
#define DHOPT_VENDOR           256
/** @def DHOPT_HEX - Option value in hexadecimal format */
#define DHOPT_HEX              512
/** @def DHOPT_VENDOR_MATCH - Match on vendor class */
#define DHOPT_VENDOR_MATCH    1024
/** @def DHOPT_RFC3925 - RFC 3925 vendor-identifying vendor option */
#define DHOPT_RFC3925         2048
/** @def DHOPT_TAGOK - Option delivery controlled by network tags */
#define DHOPT_TAGOK           4096
/** @def DHOPT_ADDR6 - Option value is IPv6 address(es) */
#define DHOPT_ADDR6           8192
/** @def DHOPT_VENDOR_PXE - PXE vendor-specific option */
#define DHOPT_VENDOR_PXE     16384

/**
 * @struct dhcp_boot
 * @brief PXE/network boot configuration for DHCP
 *
 * Configures PXE network boot parameters (--dhcp-boot directive). Specifies boot filename,
 * TFTP server name/address, and next-server for PXE clients. Can be conditional based on
 * network tags for different boot images per client class.
 *
 * @var dhcp_boot::file - Boot filename (DHCP option 67, bootp file field)
 * @var dhcp_boot::sname - Server name (DHCP sname field, may override TFTP server)
 * @var dhcp_boot::tftp_sname - TFTP server name (alternative server for file retrieval)
 * @var dhcp_boot::next_server - Next-server address (DHCP siaddr field, typically TFTP server)
 * @var dhcp_boot::netid - Network tag list for conditional boot configuration
 * @var dhcp_boot::next - Next boot configuration in list
 */
struct dhcp_boot {
  char *file, *sname, *tftp_sname;
  struct in_addr next_server;
  struct dhcp_netid *netid;
  struct dhcp_boot *next;
};

/**
 * @struct dhcp_match_name
 * @brief Hostname pattern matching for network tag assignment
 *
 * Matches DHCP client hostnames to assign network tags (--dhcp-match=set directive with
 * hostname matching). Supports wildcard patterns for flexible client classification based
 * on naming conventions.
 *
 * @var dhcp_match_name::name - Hostname pattern (may include wildcards)
 * @var dhcp_match_name::wildcard - Non-zero if pattern contains wildcards
 * @var dhcp_match_name::netid - Network tag to assign on pattern match
 * @var dhcp_match_name::next - Next match rule in list
 */
struct dhcp_match_name {
  char *name;
  int wildcard;
  struct dhcp_netid *netid;
  struct dhcp_match_name *next;
};

/**
 * @struct pxe_service
 * @brief PXE menu service configuration
 *
 * Defines PXE boot menu entry (--pxe-service directive) with service type, menu text, and
 * boot image. Enables PXE boot menu with multiple boot options presented to client. Supports
 * standard PXE service types (Linux, Windows, diagnostics, etc.).
 *
 * @var pxe_service::CSA - Client System Architecture (0=x86, 6=EFI IA32, 7=EFI BC, 9=EFI x64)
 * @var pxe_service::type - PXE service type (0=bootstrap, 1=install, 2=menu, etc.)
 * @var pxe_service::menu - Menu text displayed to user
 * @var pxe_service::basename - Boot file basename (combined with path to form full filename)
 * @var pxe_service::sname - Server name for boot file retrieval
 * @var pxe_service::server - Boot server address
 * @var pxe_service::netid - Network tag list for conditional menu entry
 * @var pxe_service::next - Next PXE service in menu
 */
struct pxe_service {
  unsigned short CSA, type; 
  char *menu, *basename, *sname;
  struct in_addr server;
  struct dhcp_netid *netid;
  struct pxe_service *next;
};

/** @def DHCP_PXE_DEF_VENDOR - Default PXE vendor class identifier */
#define DHCP_PXE_DEF_VENDOR      "PXEClient"

/** @def MATCH_VENDOR - Match on vendor class identifier (option 60) */
#define MATCH_VENDOR     1
/** @def MATCH_USER - Match on user class (option 77) */
#define MATCH_USER       2
/** @def MATCH_CIRCUIT - Match on circuit ID (option 82 sub-option 1) */
#define MATCH_CIRCUIT    3
/** @def MATCH_REMOTE - Match on remote ID (option 82 sub-option 2) */
#define MATCH_REMOTE     4
/** @def MATCH_SUBSCRIBER - Match on subscriber ID (option 82 sub-option 6) */
#define MATCH_SUBSCRIBER 5

/**
 * @struct dhcp_vendor
 * @brief Vendor class, user class, or relay agent information matching
 *
 * Configures matching rules for DHCP vendor class (option 60), user class (option 77),
 * or relay agent information (option 82 sub-options). Assigns network tags based on
 * client-provided identification for conditional DHCP configuration.
 *
 * @var dhcp_vendor::len - Match data length in bytes
 * @var dhcp_vendor::match_type - MATCH_* constant indicating match type (vendor, user, circuit, etc.)
 * @var dhcp_vendor::enterprise - Enterprise number for vendor-specific options (RFC 3925)
 * @var dhcp_vendor::data - Match data bytes (exact or substring match depending on configuration)
 * @var dhcp_vendor::netid - Network tag (embedded, not pointer) assigned on successful match
 * @var dhcp_vendor::next - Next vendor match rule in list
 */
struct dhcp_vendor {
  int len, match_type;
  unsigned int enterprise;
  char *data;
  struct dhcp_netid netid;
  struct dhcp_vendor *next;
};

/**
 * @struct dhcp_pxe_vendor
 * @brief PXE-specific vendor class configuration
 *
 * Configures PXE vendor class identifiers for PXE client identification. Clients sending
 * matching vendor class receive PXE-specific DHCP options and boot configuration.
 *
 * @var dhcp_pxe_vendor::data - PXE vendor class string (e.g., "PXEClient")
 * @var dhcp_pxe_vendor::next - Next PXE vendor configuration
 */
struct dhcp_pxe_vendor {
  char *data;
  struct dhcp_pxe_vendor *next;
};

/**
 * @struct dhcp_mac
 * @brief MAC address pattern matching for network tag assignment
 *
 * Matches DHCP client MAC addresses to assign network tags (--dhcp-mac directive). Supports
 * MAC address masks for subnet or vendor OUI matching. Enables client classification based
 * on hardware addresses.
 *
 * @var dhcp_mac::mask - Bitmask applied to MAC address for pattern matching (0xFFFFFF00 for OUI)
 * @var dhcp_mac::hwaddr_len - Hardware address length in bytes (6 for Ethernet)
 * @var dhcp_mac::hwaddr_type - Hardware type (1=Ethernet, ARPHRD_* constants)
 * @var dhcp_mac::hwaddr - Hardware address bytes to match (after masking)
 * @var dhcp_mac::netid - Network tag (embedded) assigned on successful match
 * @var dhcp_mac::next - Next MAC match rule in list
 */
  struct dhcp_mac *next;
};

/**
 * @struct dhcp_bridge
 * @brief DHCP relay bridge interface configuration
 *
 * Configures interfaces for DHCP relay/bridge operation (--bridge-interface directive).
 * Enables DHCP packet relaying between network segments, forwarding client requests from
 * one interface to DHCP servers on another interface. Supports DHCP relay agent functionality.
 *
 * @var dhcp_bridge::iface - Interface name (IF_NAMESIZE+1 bytes, e.g., "br0", "eth1")
 * @var dhcp_bridge::alias - Alias interface for bridging (interface pair for relay)
 * @var dhcp_bridge::next - Next bridge configuration in list
 */
struct dhcp_bridge {
  char iface[IF_NAMESIZE];
  struct dhcp_bridge *alias, *next;
};

/**
 * @struct cond_domain
 * @brief Conditional domain configuration with address range
 *
 * Defines domain suffix to append to hostnames based on client address range or interface
 * (--domain directive with address range or interface). Enables split-DNS where different
 * subnets receive different domain suffixes, supporting multi-tenant or segmented networks.
 *
 * @var cond_domain::domain - Domain suffix to append (e.g., "internal.example.com")
 * @var cond_domain::prefix - Text prefix prepended to domain name (for synthesized names)
 * @var cond_domain::interface - Interface name if domain tied to specific interface
 * @var cond_domain::al - Address list defining scope of this domain configuration
 * @var cond_domain::start - IPv4 range start address
 * @var cond_domain::end - IPv4 range end address
 * @var cond_domain::start6 - IPv6 range start address
 * @var cond_domain::end6 - IPv6 range end address
 * @var cond_domain::is6 - Non-zero if IPv6 range (vs IPv4)
 * @var cond_domain::indexed - Domain includes interface index in name
 * @var cond_domain::prefixlen - Prefix length for address range (CIDR notation)
 * @var cond_domain::next - Next conditional domain in list
 */
struct cond_domain {
  char *domain, *prefix; /* prefix is text-prefix on domain name */
  char *interface;       /* These two set when domain comes from interface. */
  struct addrlist *al;
  struct in_addr start, end;
  struct in6_addr start6, end6;
  int is6, indexed, prefixlen;
  struct cond_domain *next;
}; 

/**
 * @struct ra_interface
 * @brief IPv6 Router Advertisement interface configuration
 *
 * Configures parameters for IPv6 Router Advertisement transmission on specific interface
 * (--enable-ra directive with interface-specific options). Defines RA interval, router
 * lifetime, priority, and MTU for stateless IPv6 autoconfiguration (SLAAC).
 *
 * @var ra_interface::name - Interface name for RA transmission
 * @var ra_interface::mtu_name - Interface name for MTU discovery (may differ from RA interface)
 * @var ra_interface::interval - RA transmission interval in seconds (default 600, RFC 4861)
 * @var ra_interface::lifetime - Router lifetime advertised to clients in seconds
 * @var ra_interface::prio - Router priority (low/medium/high for default router selection)
 * @var ra_interface::mtu - MTU value advertised in RA MTU option (0 = no MTU option)
 * @var ra_interface::next - Next RA interface configuration in list
 */
struct ra_interface {
  char *name;
  char *mtu_name;
  int interval, lifetime, prio, mtu;
  struct ra_interface *next;
};

/**
 * @struct dhcp_context
 * @brief DHCP address pool/range configuration for dynamic lease allocation
 *
 * Defines an address range or subnet from which DHCP leases dynamically allocated.
 * Corresponds to dhcp-range directive in configuration. Multiple contexts may exist
 * for different interfaces, VLANs, or IPv4/IPv6. Context selection based on client
 * interface and gateway address (relay agent).
 *
 * LIFECYCLE:
 * - Created by option.c parse_dhcp_range() when parsing dhcp-range directives
 * - Dynamic contexts created on interface address changes (CONTEXT_TEMPLATE)
 * - Persists for daemon lifetime (static) or until interface reconfiguration (dynamic)
 * - Matched by address_available() for lease allocation eligibility
 * - CONTEXT_CONSTRUCTED contexts built from templates, CONTEXT_GC marked for cleanup
 *
 * USAGE PATTERN:
 * 1. Client DISCOVER arrives on interface
 * 2. Identify applicable dhcp_context by interface and relay giaddr
 * 3. Check context not full (allocated < (end - start))
 * 4. Allocate address from context range (start to end)
 * 5. Create lease with context parameters (lease_time, netmask, router)
 *
 * @var dhcp_context::lease_time
 * Lease duration in seconds for addresses from this range. Sent as DHCP option 51.
 * Clients RENEW at T1 (50% of lease_time) and REBIND at T2 (87.5%).
 *
 * @var dhcp_context::addr_epoch
 * Epoch counter incremented on interface address changes. Marks contexts as stale.
 *
 * @var dhcp_context::netmask
 * Subnet mask for this address range. Sent as DHCP option 1.
 *
 * @var dhcp_context::broadcast
 * Broadcast address for subnet. Sent as DHCP option 28.
 *
 * @var dhcp_context::local
 * Local dnsmasq address on this subnet (interface address). Used as default router.
 *
 * @var dhcp_context::router
 * Router address to advertise (DHCP option 3). May differ from local if relayed.
 *
 * @var dhcp_context::start
 * Start of DHCPv4 address range (first allocatable address, inclusive).
 *
 * @var dhcp_context::end
 * End of DHCPv4 address range (last allocatable address, inclusive). Pool size = end - start + 1.
 *
 * @var dhcp_context::start6
 * Start of DHCPv6 address range (first allocatable IPv6 address).
 *
 * @var dhcp_context::end6
 * End of DHCPv6 address range (last allocatable IPv6 address).
 *
 * @var dhcp_context::local6
 * Local IPv6 address on this interface. Link-local or global unicast.
 *
 * @var dhcp_context::prefix
 * IPv6 prefix length (e.g., 64 for /64 subnet). Used for Router Advertisement prefix info.
 *
 * @var dhcp_context::if_index
 * Interface index this context bound to. Links context to specific network interface.
 *
 * @var dhcp_context::valid
 * IPv6 valid lifetime in seconds (RFC 4861). Advertised in RA prefix information option.
 *
 * @var dhcp_context::preferred
 * IPv6 preferred lifetime in seconds (RFC 4861). Must be <= valid lifetime.
 *
 * @var dhcp_context::saved_valid
 * Saved valid lifetime for context updates without disrupting existing leases.
 *
 * @var dhcp_context::ra_time
 * Next Router Advertisement transmission time. RA sent periodically per RFC 4861.
 *
 * @var dhcp_context::ra_short_period_start
 * Start of RA short period (rapid RAs after interface up per RFC 4861 Section 6.2.4).
 *
 * @var dhcp_context::address_lost_time
 * Timestamp when interface address lost. Triggers deprecation of dependent leases.
 *
 * @var dhcp_context::template_interface
 * Interface name for CONTEXT_TEMPLATE contexts. New addresses on interface spawn contexts.
 *
 * @var dhcp_context::flags
 * Bitfield of CONTEXT_* flags controlling context behavior and state.
 *
 * @var dhcp_context::netid
 * Embedded tag for tag-based context selection. Matches client tags.
 *
 * @var dhcp_context::filter
 * Required tags for context eligibility. Client must have all filter tags.
 *
 * @var dhcp_context::next
 * Next context in global linked list. All contexts chained.
 *
 * @var dhcp_context::current
 * Current context in iteration during lease allocation search.
 *
 * @see dhcp.c address_available() for context-based address allocation
 * @see option.c parse_dhcp_range() for context creation from dhcp-range directive
 * @see network.c iface_check() for dynamic context creation on interface changes
 */
struct dhcp_context {
  unsigned int lease_time, addr_epoch;
  struct in_addr netmask, broadcast;
  struct in_addr local, router;
  struct in_addr start, end; /* range of available addresses */
#ifdef HAVE_DHCP6
  struct in6_addr start6, end6; /* range of available addresses */
  struct in6_addr local6;
  int prefix, if_index;
  unsigned int valid, preferred, saved_valid;
  time_t ra_time, ra_short_period_start, address_lost_time;
  char *template_interface;
#endif
  int flags;
  struct dhcp_netid netid, *filter;
  struct dhcp_context *next, *current;
};

/**
 * @struct shared_network
 * @brief Shared network identifier for DHCP relay scenarios
 *
 * Maps interface addresses to shared network segments in complex topologies with
 * multiple subnets on one physical network. Enables proper context selection when
 * relay agent giaddr doesn't match any local interface address.
 *
 * @var shared_network::if_index
 * Interface index for this shared network mapping.
 *
 * @var shared_network::match_addr
 * IPv4 address to match (relay giaddr or interface address).
 *
 * @var shared_network::shared_addr
 * Shared network identifier address (maps to dhcp_context).
 *
 * @var shared_network::match_addr6
 * IPv6 address to match for DHCPv6 relay scenarios.
 *
 * @var shared_network::shared_addr6
 * Shared IPv6 network identifier. Zero for IPv6 entries (matched differently).
 *
 * @var shared_network::next
 * Next shared network mapping in list.
 */
struct shared_network {
  int if_index;
  struct in_addr match_addr, shared_addr;
#ifdef HAVE_DHCP6
  /* shared_addr == 0 for IP6 entries. */
  struct in6_addr match_addr6, shared_addr6;
#endif
  struct shared_network *next;
};

/** @def CONTEXT_STATIC - Context from static dhcp-range config (not dynamic template) */
#define CONTEXT_STATIC         (1u<<0)
/** @def CONTEXT_NETMASK - Netmask explicitly configured in dhcp-range */
#define CONTEXT_NETMASK        (1u<<1)
/** @def CONTEXT_BRDCAST - Broadcast address explicitly configured */
#define CONTEXT_BRDCAST        (1u<<2)
/** @def CONTEXT_PROXY - Proxy DHCP mode (PXE boot info only, no address allocation) */
#define CONTEXT_PROXY          (1u<<3)
/** @def CONTEXT_RA_ROUTER - Send Router Advertisement for this context */
#define CONTEXT_RA_ROUTER      (1u<<4)
/** @def CONTEXT_RA_DONE - Router Advertisement already sent this period */
#define CONTEXT_RA_DONE        (1u<<5)
/** @def CONTEXT_RA_NAME - Include RDNSS (Recursive DNS Server) in RA */
#define CONTEXT_RA_NAME        (1u<<6)
/** @def CONTEXT_RA_STATELESS - RA indicates stateless DHCPv6 (SLAAC for addressing) */
#define CONTEXT_RA_STATELESS   (1u<<7)
/** @def CONTEXT_DHCP - Context provides DHCP service (address allocation) */
#define CONTEXT_DHCP           (1u<<8)
/** @def CONTEXT_DEPRECATE - Context deprecated (interface address lost), expire leases */
#define CONTEXT_DEPRECATE      (1u<<9)
/** @def CONTEXT_TEMPLATE - Template context creates new contexts per interface address */
#define CONTEXT_TEMPLATE       (1u<<10)    /* create contexts using addresses */
/** @def CONTEXT_CONSTRUCTED - Context dynamically constructed from template */
#define CONTEXT_CONSTRUCTED    (1u<<11)
/** @def CONTEXT_GC - Context marked for garbage collection (cleanup on next pass) */
#define CONTEXT_GC             (1u<<12)
/** @def CONTEXT_RA - Context configured for Router Advertisement transmission */
#define CONTEXT_RA             (1u<<13)
/** @def CONTEXT_CONF_USED - Context referenced in configuration (not orphaned) */
#define CONTEXT_CONF_USED      (1u<<14)
/** @def CONTEXT_USED - Context actively used this configuration cycle */
#define CONTEXT_USED           (1u<<15)
/** @def CONTEXT_OLD - Context from previous configuration (before SIGHUP reload) */
#define CONTEXT_OLD            (1u<<16)
/** @def CONTEXT_V6 - IPv6 context (DHCPv6 or RA), not IPv4 */
#define CONTEXT_V6             (1u<<17)
/** @def CONTEXT_RA_OFF_LINK - RA prefix marked off-link (not for SLAAC) */
#define CONTEXT_RA_OFF_LINK    (1u<<18)
/** @def CONTEXT_SETLEASE - Set lease time explicitly from this context */
#define CONTEXT_SETLEASE       (1u<<19)

/**
 * @struct ping_result
 * @brief ICMP ping result for DHCP address conflict detection
 *
 * Records results of ICMP echo (ping) probes sent to IP addresses before DHCP allocation
 * (--ping-wait option, PING_WAIT seconds). If ping reply received, address considered in-use,
 * skipped for allocation to avoid IP conflicts. Hash enables fast conflict lookup.
 *
 * @var ping_result::addr - IPv4 address that was pinged
 * @var ping_result::time - Timestamp when ping result recorded (for expiry)
 * @var ping_result::hash - Hash of address for fast conflict detection lookup
 * @var ping_result::next - Next ping result in hash chain
 */
struct ping_result {
  struct in_addr addr;
  time_t time;
  unsigned int hash;
  struct ping_result *next;
};

/**
 * @struct tftp_file
 * @brief TFTP file handle with reference counting
 *
 * Represents open file being served via TFTP. Reference-counted to support concurrent
 * transfers of same file to multiple clients. File kept open while transfers active,
 * closed when refcount reaches zero. Tracks inode/device for stale file detection.
 *
 * @var tftp_file::refcount - Active transfer count (file closed when reaches 0)
 * @var tftp_file::fd - Open file descriptor for reading file data
 * @var tftp_file::size - Total file size in bytes (for TFTP size option)
 * @var tftp_file::dev - Device number (for detecting file deletion/replacement)
 * @var tftp_file::inode - Inode number (for detecting file deletion/replacement)
 * @var tftp_file::filename - Flexible array member holding null-terminated filename path
 */
struct tftp_file {
  int refcount, fd;
  off_t size;
  dev_t dev;
  ino_t inode;
  char filename[];
};

/**
 * @struct tftp_transfer
 * @brief Active TFTP file transfer state machine
 *
 * Tracks state of single TFTP transfer session per RFC 1350. Maintains block number,
 * timeout/retry state, socket, peer address, and file reference. Transfer proceeds
 * block-by-block with acknowledgments until complete or timeout. Supports block size
 * negotiation (blksize option) and netascii translation mode.
 *
 * @var tftp_transfer::sockfd - UDP socket for this transfer (one socket per transfer)
 * @var tftp_transfer::timeout - Absolute time when transfer times out (inactivity expiry)
 * @var tftp_transfer::backoff - Exponential backoff counter for retransmissions
 * @var tftp_transfer::block - Current block number being transferred (starts at 1)
 * @var tftp_transfer::blocksize - Negotiated block size in bytes (512 default, up to 65464)
 * @var tftp_transfer::expansion - Buffer expansion factor for netascii conversion
 * @var tftp_transfer::offset - Current file offset in bytes (block * blocksize)
 * @var tftp_transfer::peer - Client socket address (destination for packets)
 * @var tftp_transfer::source - Source address for binding/routing (multi-homed configs)
 * @var tftp_transfer::if_index - Interface index for packet transmission
 * @var tftp_transfer::opt_blocksize - Client requested blksize option
 * @var tftp_transfer::opt_transize - Client requested transfer size option
 * @var tftp_transfer::netascii - Non-zero if netascii mode (vs octet mode), perform CRLF conversion
 * @var tftp_transfer::carrylf - Line-feed carry flag for netascii conversion across blocks
 * @var tftp_transfer::file - Pointer to tftp_file being transferred (refcounted)
 * @var tftp_transfer::next - Next active transfer in linked list
 */
struct tftp_transfer {
  int sockfd;
  time_t timeout;
  int backoff;
  unsigned int block, blocksize, expansion;
  off_t offset;
  union mysockaddr peer;
  union all_addr source;
  int if_index;
  char opt_blocksize, opt_transize, netascii, carrylf;
  struct tftp_file *file;
  struct tftp_transfer *next;
};

/**
 * @struct addr_list
 * @brief Simple IPv4 address linked list
 *
 * Generic linked list of IPv4 addresses used in various contexts (bogus addresses,
 * server addresses, allowed addresses). Provides basic address set functionality.
 *
 * @var addr_list::addr - IPv4 address (struct in_addr)
 * @var addr_list::next - Next address in list
 */
struct addr_list {
  struct in_addr addr;
  struct addr_list *next;
};

/**
 * @struct tftp_prefix
 * @brief TFTP root directory prefix per interface
 *
 * Configures interface-specific TFTP root directory (--tftp-root with interface specification).
 * Enables serving different files to clients on different network segments, supporting
 * multi-tenant or segregated PXE boot environments.
 *
 * @var tftp_prefix::interface - Interface name for this TFTP root binding
 * @var tftp_prefix::prefix - Root directory path prefix for TFTP file access
 * @var tftp_prefix::missing - Error flag: prefix directory inaccessible
 * @var tftp_prefix::next - Next TFTP prefix configuration
 */
struct tftp_prefix {
  char *interface;
  char *prefix;
  int missing;
  struct tftp_prefix *next;
};

/**
 * @struct dhcp_relay
 * @brief DHCP relay agent configuration
 *
 * Configures DHCP relay operation (--dhcp-relay directive), forwarding DHCP requests from
 * clients to remote DHCP servers and relaying responses back. Supports DHCPv4 and DHCPv6
 * relay per RFC 3046 and RFC 6221. Enables centralized DHCP servers serving multiple
 * subnets without server on each subnet.
 *
 * @var dhcp_relay::local - Local relay agent address (giaddr for DHCPv4, link-address for DHCPv6)
 * @var dhcp_relay::server - DHCP server address to forward requests to
 * @var dhcp_relay::interface - Allowed interface for replies from server, DHCPv6 multicast dest
 * @var dhcp_relay::iface_index - Working field: interface where request arrived for response routing
 * @var dhcp_relay::port - Relay destination port number
 * @var dhcp_relay::snoop_records - Embedded struct list of prefix delegation snooping records (HAVE_SCRIPT)
 * @var dhcp_relay::next - Next relay configuration
 */
struct dhcp_relay {
  union all_addr local, server;
  char *interface; /* Allowable interface for replies from server, and dest for IPv6 multicast */
  int iface_index; /* working - interface in which requests arrived, for return */
  int port;        /* Port of relay we forward to. */
#ifdef HAVE_SCRIPT
  struct snoop_record {
    struct in6_addr client, prefix;
    int prefix_len;
    struct snoop_record *next;
  } *snoop_records;
#endif
  struct dhcp_relay *next;
};

/**
 * @struct daemon
 * @brief Global daemon state container accessed by all modules
 *
 * Central repository for all dnsmasq runtime state, configuration, and data structures.
 * Single global instance declared extern, allocated in dnsmasq.c, populated by option.c
 * read_opts(). Accessed via global 'daemon' pointer throughout codebase. Contains:
 * - Configuration from command-line and files (~100 options via options[] bitfield)
 * - DNS subsystem state (servers, cache, frec forward records)
 * - DHCP subsystem state (contexts, leases, configs)
 * - Network state (interfaces, listeners, file descriptors)
 * - TFTP, D-Bus, ubus integration state
 *
 * LIFECYCLE:
 * - Allocated once in dnsmasq.c main() via my_malloc(sizeof(struct daemon))
 * - Initialized to zero
 * - Populated by option.c read_opts() parsing command-line and config files
 * - Modified throughout daemon lifetime by subsystems
 * - Never freed (daemon lifetime = process lifetime)
 * - Survives SIGHUP configuration reload (some fields updated, most preserved)
 *
 * MEMORY LAYOUT: ~2KB base struct + dynamically allocated lists (servers, leases,
 * caches). Typical memory footprint 5-20MB depending on configuration.
 *
 * THREAD SAFETY: NOT thread-safe. Dnsmasq uses single-process event-driven model.
 * All access from main event loop thread only. Signal handlers use self-pipe pattern
 * to defer work to main loop, avoiding direct daemon struct access from signal context.
 *
 * USAGE PATTERN:
 * - All modules include dnsmasq.h declaring 'extern struct daemon *daemon'
 * - Access fields directly: daemon->options[OPT_BOGUSPRIV]
 * - Configuration checked via option_bool(option) macro
 * - Lists traversed: for (serv = daemon->servers; serv; serv = serv->next)
 *
 * CONFIGURATION CATEGORIES (by member group):
 * - DNS Configuration: servers, cachesize, local_ttl, auth_zones
 * - DHCP Configuration: dhcp contexts, dhcp_conf hosts, dhcp_opts
 * - Network Configuration: if_names interfaces, port, query_port
 * - File paths: lease_file, log_file, dump_file, timestamp_file
 * - Integration: dbus_name, ubus_name, luascript, lease_change_command
 *
 * @var daemon::options
 * Bitfield array of OPT_* runtime option flags (150+ boolean options). Each OPT_*
 * constant is index into this array. Checked via option_bool(OPT_XXX) macro. Set by
 * command-line flags (--flag) and config file directives. Controls every major feature.
 *
 * @var daemon::default_resolv
 * Default resolv.conf file descriptor and state for system resolver discovery.
 *
 * @var daemon::resolv_files
 * Linked list of resolv.conf-format files providing upstream DNS server addresses.
 * Monitored for changes, reloaded on modification.
 *
 * @var daemon::last_resolv
 * Timestamp of last resolv.conf reload. Used to detect file modifications.
 *
 * @var daemon::servers_file
 * Path to servers file (alternate format for upstream server list).
 *
 * @var daemon::mxnames
 * Linked list of MX and SRV records for authoritative DNS responses.
 *
 * @var daemon::naptr
 * NAPTR (Naming Authority Pointer) records for ENUM support.
 *
 * @var daemon::txt
 * TXT records for authoritative DNS and dhcp-option responses.
 *
 * @var daemon::rr
 * Generic resource records (RR) for authoritative responses.
 *
 * @var daemon::ptr
 * PTR records for reverse DNS lookups (IP to hostname).
 *
 * @var daemon::host_records
 * Head of host_record linked list (address records from --host-record directives).
 *
 * @var daemon::host_records_tail
 * Tail of host_record list for O(1) append operations.
 *
 * @var daemon::cnames
 * CNAME (canonical name) records for DNS aliasing.
 *
 * @var daemon::auth_zones
 * Authoritative DNS zones served by dnsmasq (--auth-zone directive).
 *
 * @var daemon::int_names
 * Interface name patterns for interface-specific operations.
 *
 * @var daemon::mxtarget
 * Default MX target hostname for MX record generation.
 *
 * @var daemon::add_subnet4
 * IPv4 subnets for EDNS0 client subnet extension (--add-subnet).
 *
 * @var daemon::add_subnet6
 * IPv6 subnets for EDNS0 client subnet extension.
 *
 * @var daemon::lease_file
 * Path to DHCP lease database file (typically /var/lib/misc/dnsmasq.leases).
 *
 * @var daemon::username
 * Username to drop privileges to after initialization (default: dnsmasq or nobody).
 *
 * @var daemon::groupname
 * Group name to drop privileges to.
 *
 * @var daemon::scriptuser
 * Username for lease-change script execution (may differ from daemon username).
 *
 * @var daemon::luascript
 * Path to Lua script for lease events (HAVE_LUASCRIPT).
 *
 * @var daemon::authserver
 * Authoritative DNS server hostname for SOA record mname.
 *
 * @var daemon::hostmaster
 * Hostmaster email for SOA record rname (@ replaced with .).
 *
 * @var daemon::authinterface
 * Interfaces for authoritative DNS (--auth-server directive).
 *
 * @var daemon::secondary_forward_server
 * Secondary forward servers list for redundancy.
 *
 * @var daemon::group_set
 * Flag indicating group explicitly set (not defaulted).
 *
 * @var daemon::osport
 * Outgoing source port for queries (0 = random).
 *
 * @var daemon::domain_suffix
 * Default domain suffix appended to unqualified hostnames.
 *
 * @var daemon::cond_domain
 * Conditional domains (domain-specific upstream servers).
 *
 * @var daemon::synth_domains
 * Synthetic domains for special responses.
 *
 * @var daemon::runfile
 * Path to PID file (typically /var/run/dnsmasq.pid).
 *
 * @var daemon::lease_change_command
 * Script to execute on DHCP lease events (add/old/del).
 *
 * @var daemon::if_names
 * Interfaces to listen on (--interface directive). NULL = all interfaces.
 *
 * @var daemon::if_addrs
 * Specific addresses to bind to (--listen-address).
 *
 * @var daemon::if_except
 * Interfaces to exclude (--except-interface).
 *
 * @var daemon::dhcp_except
 * Interfaces to exclude from DHCP (--no-dhcp-interface).
 *
 * @var daemon::auth_peers
 * Peer interfaces for authoritative DNS zone transfers.
 *
 * @var daemon::tftp_interfaces
 * Interfaces enabled for TFTP service (--enable-tftp=interface).
 *
 * @var daemon::bogus_addr
 * IP addresses to treat as bogus (return NXDOMAIN). Anti-ad blocking lists.
 *
 * @var daemon::ignore_addr
 * IP addresses to ignore in upstream responses (never cache).
 *
 * @var daemon::servers
 * Head of upstream DNS server linked list (struct server). Populated from resolv.conf,
 * --server directives, and domain-specific servers. Primary data structure for DNS
 * forwarding decisions. Servers selected by forward.c forward_query().
 *
 * @var daemon::servers_tail
 * Tail of servers list for O(1) append.
 *
 * @var daemon::local_domains
 * Servers list for local-only domains (never forwarded upstream).
 *
 * @var daemon::serverarray
 * Sorted array of server pointers for binary search (performance optimization).
 *
 * @var daemon::no_rebind
 * Domains that should not trigger DNS rebind protection.
 *
 * @var daemon::server_has_wildcard
 * Flag indicating at least one server has wildcard domain.
 *
 * @var daemon::serverarraysz
 * Allocated size of serverarray.
 *
 * @var daemon::serverarrayhwm
 * High water mark (count) of serverarray.
 *
 * @var daemon::ipsets
 * Linux ipset integration (--ipset directive). Resolved IPs added to ipset.
 *
 * @var daemon::nftsets
 * nftables set integration (--nftset directive). Modern replacement for ipset.
 *
 * @var daemon::allowlist_mask
 * Bitmask for allowlist filtering (security feature).
 *
 * @var daemon::allowlists
 * Allowlist configurations for domain filtering.
 *
 * @var daemon::log_fac
 * Syslog facility (LOG_DAEMON, LOG_LOCAL0-7). Set by --log-facility.
 *
 * @var daemon::log_file
 * Path to log file if logging to file (--log-file). NULL = syslog only.
 *
 * @var daemon::max_logs
 * Maximum queued log messages before blocking (asynchronous logging).
 *
 * @var daemon::cachesize
 * DNS cache size (number of crec entries). Default CACHESIZ (150). Set by --cache-size.
 *
 * @var daemon::ftabsize
 * Forward table size (number of frec entries). Default FTABSIZ (150). Max concurrent queries.
 *
 * @var daemon::port
 * DNS listen port (default 53). Set by --port=N or --port=0 to disable DNS.
 *
 * @var daemon::query_port
 * Fixed source port for upstream queries (0 = random). Set by --query-port.
 *
 * @var daemon::min_port
 * Minimum port for random source port range (--min-port).
 *
 * @var daemon::max_port
 * Maximum port for random source port range (--max-port).
 *
 * @var daemon::local_ttl
 * TTL for /etc/hosts and --host-record entries (default 0 = no caching).
 *
 * @var daemon::neg_ttl
 * TTL for negative cache entries (NXDOMAIN, NODATA). Default 3600 seconds.
 *
 * @var daemon::max_ttl
 * Maximum TTL cap for cached records. Prevents excessively long caching.
 *
 * @var daemon::min_cache_ttl
 * Minimum TTL floor for cached records. Extends short TTLs.
 *
 * @var daemon::max_cache_ttl
 * Maximum TTL ceiling for cached records (overrides upstream TTL).
 *
 * @var daemon::auth_ttl
 * TTL for authoritative DNS responses.
 *
 * @var daemon::dhcp_ttl
 * TTL for DHCP-sourced DNS records (dynamically registered hostnames).
 *
 * @var daemon::use_dhcp_ttl
 * Control use of DHCP lease time as DNS TTL.
 *
 * @var daemon::dns_client_id
 * DNS client identifier string (--dns-rr-id) for tracking.
 *
 * @var daemon::umbrella_org
 * Cisco Umbrella organization ID (--umbrella).
 *
 * @var daemon::umbrella_asset
 * Cisco Umbrella asset tag.
 *
 * @var daemon::umbrella_device
 * Cisco Umbrella device identifier (8 bytes).
 *
 * @var daemon::addn_hosts
 * Additional hosts files beyond /etc/hosts (--addn-hosts).
 *
 * @var daemon::dhcp
 * Head of DHCPv4 context list (address ranges for lease allocation).
 *
 * @var daemon::dhcp6
 * Head of DHCPv6 context list (IPv6 address ranges and RA configs).
 *
 * @var daemon::ra_interfaces
 * Router Advertisement interface configurations.
 *
 * @var daemon::dhcp_conf
 * DHCP static host configurations (dhcp-host directives).
 *
 * @var daemon::dhcp_opts
 * DHCPv4 options to send to clients (dhcp-option directives).
 *
 * @var daemon::dhcp_match
 * DHCPv4 option matching rules (dhcp-match directives).
 *
 * @var daemon::dhcp_opts6
 * DHCPv6 options to send to clients.
 *
 * @var daemon::dhcp_match6
 * DHCPv6 option matching rules.
 *
 * @var daemon::dhcp_name_match
 * DHCP matching by hostname.
 *
 * @var daemon::dhcp_pxe_vendors
 * PXE vendor-specific configurations.
 *
 * @var daemon::dhcp_vendors
 * DHCP vendor class handling.
 *
 * @var daemon::dhcp_macs
 * DHCP MAC address matching configurations.
 *
 * @var daemon::boot_config
 * DHCP boot configurations (PXE boot server and filename).
 *
 * @var daemon::pxe_services
 * PXE service menu entries for network boot.
 *
 * @var daemon::tag_if
 * Conditional tag assignments (tag-if directives).
 *
 * @var daemon::override_relays
 * DHCP relay override configurations.
 *
 * @var daemon::relay4
 * DHCPv4 relay configurations.
 *
 * @var daemon::relay6
 * DHCPv6 relay configurations.
 *
 * @var daemon::delay_conf
 * DHCP OFFER delay configurations for PXE coordination.
 *
 * @var daemon::override
 * Override mode flag (DHCP relay behavior modification).
 *
 * @var daemon::enable_pxe
 * PXE boot service enabled flag.
 *
 * @var daemon::doing_ra
 * Router Advertisement transmission active flag.
 *
 * @var daemon::doing_dhcp6
 * DHCPv6 service active flag.
 *
 * @var daemon::dhcp_ignore
 * Tags causing DHCP IGNORE for matching clients.
 *
 * @var daemon::dhcp_ignore_names
 * Hostname patterns causing DHCP IGNORE.
 *
 * @var daemon::dhcp_gen_names
 * Generate hostnames for DHCP clients without provided names.
 *
 * @var daemon::force_broadcast
 * Tags forcing broadcast DHCP responses (broken clients).
 *
 * @var daemon::bootp_dynamic
 * Enable dynamic BOOTP (RFC 951) address allocation.
 *
 * @var daemon::dhcp_hosts_file
 * Bulk DHCP host configurations from file (--dhcp-hostsfile).
 *
 * @var daemon::dhcp_opts_file
 * Bulk DHCP options from file (--dhcp-optsfile).
 *
 * @var daemon::dynamic_dirs
 * Directories to monitor for dynamic host/option files (inotify).
 *
 * @var daemon::dhcp_max
 * Maximum concurrent DHCP leases (MAXLEASES default 1000).
 *
 * @var daemon::tftp_max
 * Maximum concurrent TFTP transfers (TFTP_MAX_CONNECTIONS default 50).
 *
 * @var daemon::tftp_mtu
 * TFTP MTU size for packet sizing.
 *
 * @var daemon::dhcp_server_port
 * DHCP server listen port (default 67).
 *
 * @var daemon::dhcp_client_port
 * DHCP client port (default 68).
 *
 * @var daemon::start_tftp_port
 * Start of TFTP port range (default 69).
 *
 * @var daemon::end_tftp_port
 * End of TFTP port range.
 *
 * @var daemon::min_leasetime
 * Minimum DHCP lease time in seconds (prevents too-short leases).
 *
 * @var daemon::doctors
 * DNS doctoring rules (modify DNS responses in-flight).
 *
 * @var daemon::edns_pktsz
 * EDNS0 packet size (UDP payload size advertised). Default EDNS_PKTSZ (4096).
 *
 * @var daemon::tftp_prefix
 * TFTP root directory prefix (chroot-style path restriction).
 *
 * @var daemon::if_prefix
 * Per-interface TFTP prefix overrides.
 *
 * @var daemon::duid_enterprise
 * DHCPv6 DUID enterprise number (DUID-EN construction).
 *
 * @var daemon::duid_config_len
 * Length of configured DUID.
 *
 * @var daemon::duid_config
 * Configured DHCPv6 DUID bytes.
 *
 * @var daemon::dbus_name
 * D-Bus service name for control interface (org.freedesktop.NetworkManager.dnsmasq).
 *
 * @var daemon::ubus_name
 * ubus object name for control interface (OpenWrt).
 *
 * @var daemon::dump_file
 * Packet dump file path (--dumpfile for debugging).
 *
 * @var daemon::dump_mask
 * Packet dump mask (which packet types to dump).
 *
 * @var daemon::soa_sn
 * SOA serial number for authoritative zones.
 *
 * @var daemon::soa_refresh
 * SOA refresh timer (secondary zone refresh interval).
 *
 * @var daemon::soa_retry
 * SOA retry timer (secondary retry after failed refresh).
 *
 * @var daemon::soa_expiry
 * SOA expiry timer (secondary zone expiration).
 *
 * @var daemon::metrics
 * Prometheus metrics counters array (--enable-metrics).
 *
 * @var daemon::ds
 * DNSSEC DS (Delegation Signer) configuration.
 *
 * @var daemon::timestamp_file
 * DNSSEC timestamp file for time validation (HAVE_BROKEN_RTC).
 *
 * @var daemon::packet
 * Global DNS packet buffer (dynamically allocated, typically 4096+ bytes).
 * Reused across queries to avoid repeated allocation. NOT thread-safe.
 *
 * @var daemon::packet_buff_sz
 * Allocated size of packet buffer.
 *
 * @var daemon::namebuff
 * DNS name buffer (MAXDNAME=1024 bytes). Scratch space for name operations.
 *
 * @var daemon::workspacename
 * Additional workspace buffer for DNSSEC and conntrack operations.
 *
 * @var daemon::keyname
 * DNSSEC key name buffer (MAXDNAME bytes).
 *
 * @var daemon::rr_status
 * DNSSEC validation status array (per-RR security status).
 *
 * @var daemon::rr_status_sz
 * Allocated size of rr_status array.
 *
 * @var daemon::dnssec_no_time_check
 * Disable DNSSEC timestamp validation (embedded systems).
 *
 * @var daemon::back_to_the_future
 * Flag indicating system time jumped backwards (affects DNSSEC).
 *
 * @var daemon::frec_list
 * Head of forward record (frec) freelist. Pre-allocated frecs for query tracking.
 *
 * @var daemon::free_frec_src
 * Freelist of frec_src structures (client source tracking).
 *
 * @var daemon::frec_src_count
 * Count of allocated frec_src structures.
 *
 * @var daemon::sfds
 * Server file descriptors (sockets for upstream queries).
 *
 * @var daemon::interfaces
 * Interface record list (struct irec) tracking all network interfaces.
 *
 * @var daemon::listeners
 * Listener sockets (DNS, DHCP, TFTP) for incoming requests.
 *
 * @var daemon::srv_save
 * Saved server pointer for retransmission (DoD = Dial-on-Demand).
 *
 * @var daemon::packet_len
 * Saved packet length for retransmission.
 *
 * @var daemon::fd_save
 * Saved file descriptor for retransmission.
 *
 * @var daemon::tcp_pids
 * PIDs of forked TCP helper processes (MAX_PROCS=20 limit).
 *
 * @var daemon::tcp_pipes
 * Pipes for communication with TCP helper processes.
 *
 * @var daemon::pipe_to_parent
 * Pipe file descriptor for TCP child to parent communication.
 *
 * @var daemon::numrrand
 * Number of random sockets for source port randomization.
 *
 * @var daemon::randomsocks
 * Array of random sockets (source port randomization pool).
 *
 * @var daemon::rfl_spare
 * Spare randfd_list entries for allocation.
 *
 * @var daemon::rfl_poll
 * randfd_list entries currently in poll set.
 *
 * @var daemon::v6pktinfo
 * IPv6 packet info socket option level (IPV6_RECVPKTINFO).
 *
 * @var daemon::interface_addrs
 * Complete list of interface addresses and prefix lengths.
 *
 * @var daemon::log_id
 * Current transaction log ID for query/response correlation.
 *
 * @var daemon::log_display_id
 * Display log ID for logging (may differ from log_id).
 *
 * @var daemon::log_source_addr
 * Source address for logging context.
 *
 * @var daemon::dhcpfd
 * DHCP server socket file descriptor (UDP port 67).
 *
 * @var daemon::helperfd
 * Helper process pipe file descriptor (lease-change script communication).
 *
 * @var daemon::pxefd
 * PXE proxy DHCP socket (port 4011).
 *
 * @var daemon::inotifyfd
 * inotify file descriptor for monitoring dynamic config files (Linux).
 *
 * @var daemon::netlinkfd
 * Netlink socket for interface monitoring (Linux).
 *
 * @var daemon::kernel_version
 * Linux kernel version (affects netlink API compatibility).
 *
 * @var daemon::dhcp_raw_fd
 * Raw socket for DHCP (BSD systems, no netlink).
 *
 * @var daemon::dhcp_icmp_fd
 * ICMP socket for DHCP ping-before-offer (BSD).
 *
 * @var daemon::routefd
 * Routing socket for interface monitoring (BSD).
 *
 * @var daemon::dhcp_packet
 * DHCP packet iovec for scatter-gather I/O.
 *
 * @var daemon::dhcp_buff
 * Primary DHCP packet buffer.
 *
 * @var daemon::dhcp_buff2
 * Secondary DHCP buffer (for packet construction).
 *
 * @var daemon::dhcp_buff3
 * Tertiary DHCP buffer (relay scenarios).
 *
 * @var daemon::ping_results
 * Ping results cache for DHCP ping-before-offer conflict detection.
 *
 * @var daemon::lease_stream
 * FILE* stream for lease file I/O (atomic writes).
 *
 * @var daemon::bridges
 * DHCP bridge configurations for relay scenarios.
 *
 * @var daemon::shared_networks
 * Shared network configurations for complex topologies.
 *
 * @var daemon::duid_len
 * DHCPv6 DUID length.
 *
 * @var daemon::duid
 * DHCPv6 DUID bytes (server identifier).
 *
 * @var daemon::outpacket
 * DHCPv6 outgoing packet iovec.
 *
 * @var daemon::dhcp6fd
 * DHCPv6 socket file descriptor (UDP port 547).
 *
 * @var daemon::icmp6fd
 * ICMPv6 socket for Router Advertisement and neighbor discovery.
 *
 * @var daemon::free_snoops
 * Freelist of snoop_record structures (DHCPv6 snooping).
 *
 * @var daemon::dbus
 * D-Bus connection handle (void* avoids dbus.h dependency).
 *
 * @var daemon::watches
 * D-Bus watch list for event integration.
 *
 * @var daemon::ubus
 * ubus context handle (void* avoids ubus.h dependency).
 *
 * @var daemon::tftp_trans
 * Active TFTP transfers list.
 *
 * @var daemon::tftp_done_trans
 * Completed TFTP transfers pending cleanup.
 *
 * @var daemon::addrbuff
 * Address string buffer (inet_ntop scratch space).
 *
 * @var daemon::addrbuff2
 * Second address buffer (allocated only if OPT_EXTRALOG enabled).
 *
 * @var daemon::dumpfd
 * Packet dump file descriptor (HAVE_DUMPFILE debugging).
 *
 * @see dnsmasq.c main() for daemon allocation and initialization
 * @see option.c read_opts() for daemon configuration population
 * @see forward.c for DNS forwarding using daemon->servers and daemon->frec_list
 * @see cache.c for DNS caching using daemon->cachesize
 * @see dhcp.c for DHCP server using daemon->dhcp contexts and leases
 */
extern struct daemon {
  /* datastuctures representing the command-line and 
     config file arguments. All set (including defaults)
     in option.c */

  unsigned int options[OPTION_SIZE];
  struct resolvc default_resolv, *resolv_files;
  time_t last_resolv;
  char *servers_file;
  struct mx_srv_record *mxnames;
  struct naptr *naptr;
  struct txt_record *txt, *rr;
  struct ptr_record *ptr;
  struct host_record *host_records, *host_records_tail;
  struct cname *cnames;
  struct auth_zone *auth_zones;
  struct interface_name *int_names;
  char *mxtarget;
  struct mysubnet *add_subnet4;
  struct mysubnet *add_subnet6;
  char *lease_file;
  char *username, *groupname, *scriptuser;
  char *luascript;
  char *authserver, *hostmaster;
  struct iname *authinterface;
  struct name_list *secondary_forward_server;
  int group_set, osport;
  char *domain_suffix;
  struct cond_domain *cond_domain, *synth_domains;
  char *runfile; 
  char *lease_change_command;
  struct iname *if_names, *if_addrs, *if_except, *dhcp_except, *auth_peers, *tftp_interfaces;
  struct bogus_addr *bogus_addr, *ignore_addr;
  struct server *servers, *servers_tail, *local_domains, **serverarray;
  struct rebind_domain *no_rebind;
  int server_has_wildcard;
  int serverarraysz, serverarrayhwm;
  struct ipsets *ipsets, *nftsets;
  u32 allowlist_mask;
  struct allowlist *allowlists;
  int log_fac; /* log facility */
  char *log_file; /* optional log file */
  int max_logs;  /* queue limit */
  int cachesize, ftabsize;
  int port, query_port, min_port, max_port;
  unsigned long local_ttl, neg_ttl, max_ttl, min_cache_ttl, max_cache_ttl, auth_ttl, dhcp_ttl, use_dhcp_ttl;
  char *dns_client_id;
  u32 umbrella_org;
  u32 umbrella_asset;
  u8 umbrella_device[8];
  struct hostsfile *addn_hosts;
  struct dhcp_context *dhcp, *dhcp6;
  struct ra_interface *ra_interfaces;
  struct dhcp_config *dhcp_conf;
  struct dhcp_opt *dhcp_opts, *dhcp_match, *dhcp_opts6, *dhcp_match6;
  struct dhcp_match_name *dhcp_name_match;
  struct dhcp_pxe_vendor *dhcp_pxe_vendors;
  struct dhcp_vendor *dhcp_vendors;
  struct dhcp_mac *dhcp_macs;
  struct dhcp_boot *boot_config;
  struct pxe_service *pxe_services;
  struct tag_if *tag_if; 
  struct addr_list *override_relays;
  struct dhcp_relay *relay4, *relay6;
  struct delay_config *delay_conf;
  int override;
  int enable_pxe;
  int doing_ra, doing_dhcp6;
  struct dhcp_netid_list *dhcp_ignore, *dhcp_ignore_names, *dhcp_gen_names; 
  struct dhcp_netid_list *force_broadcast, *bootp_dynamic;
  struct hostsfile *dhcp_hosts_file, *dhcp_opts_file, *dynamic_dirs;
  int dhcp_max, tftp_max, tftp_mtu;
  int dhcp_server_port, dhcp_client_port;
  int start_tftp_port, end_tftp_port; 
  unsigned int min_leasetime;
  struct doctor *doctors;
  unsigned short edns_pktsz;
  char *tftp_prefix; 
  struct tftp_prefix *if_prefix; /* per-interface TFTP prefixes */
  unsigned int duid_enterprise, duid_config_len;
  unsigned char *duid_config;
  char *dbus_name;
  char *ubus_name;
  char *dump_file;
  int dump_mask;
  unsigned long soa_sn, soa_refresh, soa_retry, soa_expiry;
  u32 metrics[__METRIC_MAX];
#ifdef HAVE_DNSSEC
  struct ds_config *ds;
  char *timestamp_file;
#endif

  /* globally used stuff for DNS */
  char *packet; /* packet buffer */
  int packet_buff_sz; /* size of above */
  char *namebuff; /* MAXDNAME size buffer */
#if (defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)) || defined(HAVE_DNSSEC)
  /* CONNTRACK UBUS code uses this buffer, as well as DNSSEC code. */
  char *workspacename;
#endif
#ifdef HAVE_DNSSEC
  char *keyname; /* MAXDNAME size buffer */
  unsigned long *rr_status; /* ceiling in TTL from DNSSEC or zero for insecure */
  int rr_status_sz;
  int dnssec_no_time_check;
  int back_to_the_future;
#endif
  struct frec *frec_list;
  struct frec_src *free_frec_src;
  int frec_src_count;
  struct serverfd *sfds;
  struct irec *interfaces;
  struct listener *listeners;
  struct server *srv_save; /* Used for resend on DoD */
  size_t packet_len;       /*      "        "        */
  int    fd_save;          /*      "        "        */
  pid_t tcp_pids[MAX_PROCS];
  int tcp_pipes[MAX_PROCS];
  int pipe_to_parent;
  int numrrand;
  struct randfd *randomsocks;
  struct randfd_list *rfl_spare, *rfl_poll;
  int v6pktinfo; 
  struct addrlist *interface_addrs; /* list of all addresses/prefix lengths associated with all local interfaces */
  int log_id, log_display_id; /* ids of transactions for logging */
  union mysockaddr *log_source_addr;

  /* DHCP state */
  int dhcpfd, helperfd, pxefd; 
#ifdef HAVE_INOTIFY
  int inotifyfd;
#endif
#if defined(HAVE_LINUX_NETWORK)
  int netlinkfd, kernel_version;
#elif defined(HAVE_BSD_NETWORK)
  int dhcp_raw_fd, dhcp_icmp_fd, routefd;
#endif
  struct iovec dhcp_packet;
  char *dhcp_buff, *dhcp_buff2, *dhcp_buff3;
  struct ping_result *ping_results;
  FILE *lease_stream;
  struct dhcp_bridge *bridges;
  struct shared_network *shared_networks;
#ifdef HAVE_DHCP6
  int duid_len;
  unsigned char *duid;
  struct iovec outpacket;
  int dhcp6fd, icmp6fd;
#  ifdef HAVE_SCRIPT
  struct snoop_record *free_snoops;
#  endif
#endif
  
  /* DBus stuff */
  /* void * here to avoid depending on dbus headers outside dbus.c */
  void *dbus;
#ifdef HAVE_DBUS
  struct watch *watches;
#endif

  /* UBus stuff */
#ifdef HAVE_UBUS
  /* void * here to avoid depending on ubus headers outside ubus.c */
  void *ubus;
#endif

  /* TFTP stuff */
  struct tftp_transfer *tftp_trans, *tftp_done_trans;

  /* utility string buffer, hold max sized IP address as string */
  char *addrbuff;
  char *addrbuff2; /* only allocated when OPT_EXTRALOG */

#ifdef HAVE_DUMPFILE
  /* file for packet dumps. */
  int dumpfd;
#endif
} *daemon;

/* cache.c */
void cache_init(void);
void next_uid(struct crec *crecp);
void log_query(unsigned int flags, char *name, union all_addr *addr, char *arg, unsigned short type); 
char *record_source(unsigned int index);
int cache_find_non_terminal(char *name, time_t now);
struct crec *cache_find_by_addr(struct crec *crecp,
				union all_addr *addr, time_t now, 
				unsigned int prot);
struct crec *cache_find_by_name(struct crec *crecp, 
				char *name, time_t now, unsigned int prot);
void cache_end_insert(void);
void cache_start_insert(void);
int cache_recv_insert(time_t now, int fd);
struct crec *cache_insert(char *name, union all_addr *addr, unsigned short class, 
			  time_t now, unsigned long ttl, unsigned int flags);
void cache_reload(void);
void cache_add_dhcp_entry(char *host_name, int prot, union all_addr *host_address, time_t ttd);
struct in_addr a_record_from_hosts(char *name, time_t now);
void cache_unhash_dhcp(void);
void dump_cache(time_t now);
#ifndef NO_ID
int cache_make_stat(struct txt_record *t);
#endif
char *cache_get_name(struct crec *crecp);
char *cache_get_cname_target(struct crec *crecp);
struct crec *cache_enumerate(int init);
int read_hostsfile(char *filename, unsigned int index, int cache_size, 
		   struct crec **rhash, int hashsz);

/* blockdata.c */
void blockdata_init(void);
void blockdata_report(void);
struct blockdata *blockdata_alloc(char *data, size_t len);
void *blockdata_retrieve(struct blockdata *block, size_t len, void *data);
struct blockdata *blockdata_read(int fd, size_t len);
void blockdata_write(struct blockdata *block, size_t len, int fd);
void blockdata_free(struct blockdata *blocks);

/* domain.c */
char *get_domain(struct in_addr addr);
char *get_domain6(struct in6_addr *addr);
int is_name_synthetic(int flags, char *name, union all_addr *addr);
int is_rev_synth(int flag, union all_addr *addr, char *name);

/* rfc1035.c */
int extract_name(struct dns_header *header, size_t plen, unsigned char **pp, 
                 char *name, int isExtract, int extrabytes);
unsigned char *skip_name(unsigned char *ansp, struct dns_header *header, size_t plen, int extrabytes);
unsigned char *skip_questions(struct dns_header *header, size_t plen);
unsigned char *skip_section(unsigned char *ansp, int count, struct dns_header *header, size_t plen);
unsigned int extract_request(struct dns_header *header, size_t qlen, 
			       char *name, unsigned short *typep);
void setup_reply(struct dns_header *header, unsigned int flags, int ede);
int extract_addresses(struct dns_header *header, size_t qlen, char *name,
		      time_t now, struct ipsets *ipsets, struct ipsets *nftsets, int is_sign,
                      int check_rebind, int no_cache_dnssec, int secure, int *doctored);
#if defined(HAVE_CONNTRACK) && defined(HAVE_UBUS)
void report_addresses(struct dns_header *header, size_t len, u32 mark);
#endif
size_t answer_request(struct dns_header *header, char *limit, size_t qlen,  
		      struct in_addr local_addr, struct in_addr local_netmask, 
		      time_t now, int ad_reqd, int do_bit, int have_pseudoheader);
int check_for_bogus_wildcard(struct dns_header *header, size_t qlen, char *name, 
			     time_t now);
int check_for_ignored_address(struct dns_header *header, size_t qlen);
int check_for_local_domain(char *name, time_t now);
size_t resize_packet(struct dns_header *header, size_t plen, 
		  unsigned char *pheader, size_t hlen);
int add_resource_record(struct dns_header *header, char *limit, int *truncp,
			int nameoffset, unsigned char **pp, unsigned long ttl, 
			int *offset, unsigned short type, unsigned short class, char *format, ...);
int in_arpa_name_2_addr(char *namein, union all_addr *addrp);
int private_net(struct in_addr addr, int ban_localhost);

/* auth.c */
#ifdef HAVE_AUTH
size_t answer_auth(struct dns_header *header, char *limit, size_t qlen, 
		   time_t now, union mysockaddr *peer_addr, int local_query,
		   int do_bit, int have_pseudoheader);
int in_zone(struct auth_zone *zone, char *name, char **cut);
#endif

/* dnssec.c */
#ifdef HAVE_DNSSEC
size_t dnssec_generate_query(struct dns_header *header, unsigned char *end, char *name, int class, int type, int edns_pktsz);
int dnssec_validate_by_ds(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int class);
int dnssec_validate_ds(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int class);
int dnssec_validate_reply(time_t now, struct dns_header *header, size_t plen, char *name, char *keyname, int *class,
			  int check_unsigned, int *neganswer, int *nons, int *nsec_ttl);
int dnskey_keytag(int alg, int flags, unsigned char *key, int keylen);
size_t filter_rrsigs(struct dns_header *header, size_t plen);
int setup_timestamp(void);
int errflags_to_ede(int status);
#endif

/* hash_questions.c */
void hash_questions_init(void);
unsigned char *hash_questions(struct dns_header *header, size_t plen, char *name);

/* crypto.c */
const struct nettle_hash *hash_find(char *name);
int hash_init(const struct nettle_hash *hash, void **ctxp, unsigned char **digestp);
int verify(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
	   unsigned char *digest, size_t digest_len, int algo);
char *ds_digest_name(int digest);
char *algo_digest_name(int algo);
char *nsec3_digest_name(int digest);

/* util.c */
void rand_init(void);
unsigned short rand16(void);
u32 rand32(void);
u64 rand64(void);
int legal_hostname(char *name);
char *canonicalise(char *in, int *nomem);
unsigned char *do_rfc1035_name(unsigned char *p, char *sval, char *limit);
void *safe_malloc(size_t size);
void safe_strncpy(char *dest, const char *src, size_t size);
void safe_pipe(int *fd, int read_noblock);
void *whine_malloc(size_t size);
int sa_len(union mysockaddr *addr);
int sockaddr_isequal(const union mysockaddr *s1, const union mysockaddr *s2);
int hostname_order(const char *a, const char *b);
int hostname_isequal(const char *a, const char *b);
int hostname_issubdomain(char *a, char *b);
time_t dnsmasq_time(void);
int netmask_length(struct in_addr mask);
int is_same_net(struct in_addr a, struct in_addr b, struct in_addr mask);
int is_same_net_prefix(struct in_addr a, struct in_addr b, int prefix);
int is_same_net6(struct in6_addr *a, struct in6_addr *b, int prefixlen);
u64 addr6part(struct in6_addr *addr);
void setaddr6part(struct in6_addr *addr, u64 host);
int retry_send(ssize_t rc);
void prettyprint_time(char *buf, unsigned int t);
int prettyprint_addr(union mysockaddr *addr, char *buf);
int parse_hex(char *in, unsigned char *out, int maxlen, 
	      unsigned int *wildcard_mask, int *mac_type);
int memcmp_masked(unsigned char *a, unsigned char *b, int len, 
		  unsigned int mask);
int expand_buf(struct iovec *iov, size_t size);
char *print_mac(char *buff, unsigned char *mac, int len);
int read_write(int fd, unsigned char *packet, int size, int rw);
void close_fds(long max_fd, int spare1, int spare2, int spare3);
int wildcard_match(const char* wildcard, const char* match);
int wildcard_matchn(const char* wildcard, const char* match, int num);
#ifdef HAVE_LINUX_NETWORK
int kernel_version(void);
#endif

/* log.c */
void die(char *message, char *arg1, int exit_code) ATTRIBUTE_NORETURN;
int log_start(struct passwd *ent_pw, int errfd);
int log_reopen(char *log_file);

void my_syslog(int priority, const char *format, ...);

void set_log_writer(void);
void check_log_writer(int force);
void flush_log(void);

/* option.c */
void read_opts (int argc, char **argv, char *compile_opts);
char *option_string(int prot, unsigned int opt, unsigned char *val, 
		    int opt_len, char *buf, int buf_len);
void reread_dhcp(void);
void read_servers_file(void);
void set_option_bool(unsigned int opt);
void reset_option_bool(unsigned int opt);
struct hostsfile *expand_filelist(struct hostsfile *list);
char *parse_server(char *arg, union mysockaddr *addr, 
		   union mysockaddr *source_addr, char *interface, u16 *flags);
int option_read_dynfile(char *file, int flags);

/* forward.c */
void reply_query(int fd, time_t now);
void receive_query(struct listener *listen, time_t now);
unsigned char *tcp_request(int confd, time_t now,
			   union mysockaddr *local_addr, struct in_addr netmask, int auth_dns);
void server_gone(struct server *server);
int send_from(int fd, int nowild, char *packet, size_t len, 
	       union mysockaddr *to, union all_addr *source,
	       unsigned int iface);
void resend_query(void);
int allocate_rfd(struct randfd_list **fdlp, struct server *serv);
void free_rfds(struct randfd_list **fdlp);

/* network.c */
int indextoname(int fd, int index, char *name);
int local_bind(int fd, union mysockaddr *addr, char *intname, unsigned int ifindex, int is_tcp);
void pre_allocate_sfds(void);
int reload_servers(char *fname);
void check_servers(int no_loop_call);
int enumerate_interfaces(int reset);
void create_wildcard_listeners(void);
void create_bound_listeners(int dienow);
void warn_bound_listeners(void);
void warn_wild_labels(void);
void warn_int_names(void);
int is_dad_listeners(void);
int iface_check(int family, union all_addr *addr, char *name, int *auth);
int loopback_exception(int fd, int family, union all_addr *addr, char *name);
int label_exception(int index, int family, union all_addr *addr);
int fix_fd(int fd);
int tcp_interface(int fd, int af);
int set_ipv6pktinfo(int fd);
#ifdef HAVE_DHCP6
void join_multicast(int dienow);
#endif
#if defined(HAVE_LINUX_NETWORK) || defined(HAVE_BSD_NETWORK)
void newaddress(time_t now);
#endif


/* dhcp.c */
#ifdef HAVE_DHCP
void dhcp_init(void);
void dhcp_packet(time_t now, int pxe_fd);
struct dhcp_context *address_available(struct dhcp_context *context, 
				       struct in_addr taddr,
				       struct dhcp_netid *netids);
struct dhcp_context *narrow_context(struct dhcp_context *context, 
				    struct in_addr taddr,
				    struct dhcp_netid *netids);
struct ping_result *do_icmp_ping(time_t now, struct in_addr addr,
				 unsigned int hash, int loopback);
int address_allocate(struct dhcp_context *context,
		     struct in_addr *addrp, unsigned char *hwaddr, int hw_len,
		     struct dhcp_netid *netids, time_t now, int loopback);
void dhcp_read_ethers(void);
struct dhcp_config *config_find_by_address(struct dhcp_config *configs, struct in_addr addr);
char *host_from_dns(struct in_addr addr);
#endif

/* lease.c */
#ifdef HAVE_DHCP
void lease_update_file(time_t now);
void lease_update_dns(int force);
void lease_init(time_t now);
struct dhcp_lease *lease4_allocate(struct in_addr addr);
#ifdef HAVE_DHCP6
struct dhcp_lease *lease6_allocate(struct in6_addr *addrp, int lease_type);
struct dhcp_lease *lease6_find(unsigned char *clid, int clid_len, 
			       int lease_type, unsigned int iaid, struct in6_addr *addr);
void lease6_reset(void);
struct dhcp_lease *lease6_find_by_client(struct dhcp_lease *first, int lease_type,
					 unsigned char *clid, int clid_len, unsigned int iaid);
struct dhcp_lease *lease6_find_by_addr(struct in6_addr *net, int prefix, u64 addr);
u64 lease_find_max_addr6(struct dhcp_context *context);
void lease_ping_reply(struct in6_addr *sender, unsigned char *packet, char *interface);
void lease_update_slaac(time_t now);
void lease_set_iaid(struct dhcp_lease *lease, unsigned int iaid);
void lease_make_duid(time_t now);
#endif
void lease_set_hwaddr(struct dhcp_lease *lease, const unsigned char *hwaddr,
		      const unsigned char *clid, int hw_len, int hw_type,
		      int clid_len, time_t now, int force);
void lease_set_hostname(struct dhcp_lease *lease, const char *name, int auth, char *domain, char *config_domain);
void lease_set_expires(struct dhcp_lease *lease, unsigned int len, time_t now);
void lease_set_interface(struct dhcp_lease *lease, int interface, time_t now);
struct dhcp_lease *lease_find_by_client(unsigned char *hwaddr, int hw_len, int hw_type,  
					unsigned char *clid, int clid_len);
struct dhcp_lease *lease_find_by_addr(struct in_addr addr);
struct in_addr lease_find_max_addr(struct dhcp_context *context);
void lease_prune(struct dhcp_lease *target, time_t now);
void lease_update_from_configs(void);
int do_script_run(time_t now);
void rerun_scripts(void);
void lease_find_interfaces(time_t now);
#ifdef HAVE_SCRIPT
void lease_add_extradata(struct dhcp_lease *lease, unsigned char *data, 
			 unsigned int len, int delim);
#endif
#endif

/* rfc2131.c */
#ifdef HAVE_DHCP
size_t dhcp_reply(struct dhcp_context *context, char *iface_name, int int_index,
		  size_t sz, time_t now, int unicast_dest, int loopback,
		  int *is_inform, int pxe, struct in_addr fallback, time_t recvtime);
unsigned char *extended_hwaddr(int hwtype, int hwlen, unsigned char *hwaddr, 
			       int clid_len, unsigned char *clid, int *len_out);
#endif

/* dnsmasq.c */
#ifdef HAVE_DHCP
int make_icmp_sock(void);
int icmp_ping(struct in_addr addr);
int delay_dhcp(time_t start, int sec, int fd, uint32_t addr, unsigned short id);
#endif
void queue_event(int event);
void send_alarm(time_t event, time_t now);
void send_event(int fd, int event, int data, char *msg);
void clear_cache_and_reload(time_t now);

/* netlink.c */
#ifdef HAVE_LINUX_NETWORK
char *netlink_init(void);
void netlink_multicast(void);
#endif

/* bpf.c */
#ifdef HAVE_BSD_NETWORK
void init_bpf(void);
void send_via_bpf(struct dhcp_packet *mess, size_t len,
		  struct in_addr iface_addr, struct ifreq *ifr);
void route_init(void);
void route_sock(void);
#endif

/* bpf.c or netlink.c */
int iface_enumerate(int family, void *parm, int (callback)());

/* dbus.c */
#ifdef HAVE_DBUS
char *dbus_init(void);
void check_dbus_listeners(void);
void set_dbus_listeners(void);
#  ifdef HAVE_DHCP
void emit_dbus_signal(int action, struct dhcp_lease *lease, char *hostname);
#  endif
#endif

/* ubus.c */
#ifdef HAVE_UBUS
char *ubus_init(void);
void set_ubus_listeners(void);
void check_ubus_listeners(void);
void ubus_event_bcast(const char *type, const char *mac, const char *ip, const char *name, const char *interface);
#  ifdef HAVE_CONNTRACK
void ubus_event_bcast_connmark_allowlist_refused(u32 mark, const char *name);
void ubus_event_bcast_connmark_allowlist_resolved(u32 mark, const char *pattern, const char *ip, u32 ttl);
#  endif
#endif

/* ipset.c */
#ifdef HAVE_IPSET
void ipset_init(void);
int add_to_ipset(const char *setname, const union all_addr *ipaddr, int flags, int remove);
#endif

/* nftset.c */
#ifdef HAVE_NFTSET
void nftset_init(void);
int add_to_nftset(const char *setpath, const union all_addr *ipaddr, int flags, int remove);
#endif

/* pattern.c */
#ifdef HAVE_CONNTRACK
int is_valid_dns_name(const char *value);
int is_valid_dns_name_pattern(const char *value);
int is_dns_name_matching_pattern(const char *name, const char *pattern);
#endif

/* helper.c */
#if defined(HAVE_SCRIPT)
int create_helper(int event_fd, int err_fd, uid_t uid, gid_t gid, long max_fd);
void helper_write(void);
void queue_script(int action, struct dhcp_lease *lease, 
		  char *hostname, time_t now);
#ifdef HAVE_TFTP
void queue_tftp(off_t file_len, char *filename, union mysockaddr *peer);
#endif
void queue_arp(int action, unsigned char *mac, int maclen,
	       int family, union all_addr *addr);
int helper_buf_empty(void);
#ifdef HAVE_DHCP6
void queue_relay_snoop(struct in6_addr *client, int if_index, struct in6_addr *prefix, int prefix_len);
#endif
#endif

/* tftp.c */
#ifdef HAVE_TFTP
void tftp_request(struct listener *listen, time_t now);
void check_tftp_listeners(time_t now);
int do_tftp_script_run(void);
#endif

/* conntrack.c */
#ifdef HAVE_CONNTRACK
int get_incoming_mark(union mysockaddr *peer_addr, union all_addr *local_addr,
		      int istcp, unsigned int *markp);
#endif

/* dhcp6.c */
#ifdef HAVE_DHCP6
void dhcp6_init(void);
void dhcp6_packet(time_t now);
struct dhcp_context *address6_allocate(struct dhcp_context *context,  unsigned char *clid, int clid_len, int temp_addr,
				       unsigned int iaid, int serial, struct dhcp_netid *netids, int plain_range, struct in6_addr *ans);
struct dhcp_context *address6_available(struct dhcp_context *context, 
					struct in6_addr *taddr,
					struct dhcp_netid *netids,
					int plain_range);
struct dhcp_context *address6_valid(struct dhcp_context *context, 
				    struct in6_addr *taddr,
				    struct dhcp_netid *netids,
				    int plain_range);
struct dhcp_config *config_find_by_address6(struct dhcp_config *configs, struct in6_addr *net, 
					    int prefix, struct in6_addr *addr);
void make_duid(time_t now);
void dhcp_construct_contexts(time_t now);
void get_client_mac(struct in6_addr *client, int iface, unsigned char *mac, 
		    unsigned int *maclenp, unsigned int *mactypep, time_t now);
#endif
  
/* rfc3315.c */
#ifdef HAVE_DHCP6
unsigned short dhcp6_reply(struct dhcp_context *context, int interface, char *iface_name,  
			   struct in6_addr *fallback, struct in6_addr *ll_addr, struct in6_addr *ula_addr,
			   size_t sz, struct in6_addr *client_addr, time_t now);
int relay_upstream6(int iface_index, ssize_t sz, struct in6_addr *peer_address, 
		     u32 scope_id, time_t now);

int relay_reply6( struct sockaddr_in6 *peer, ssize_t sz, char *arrival_interface);
#  ifdef HAVE_SCRIPT
int do_snoop_script_run(void);
#  endif
#endif

/* dhcp-common.c */
#ifdef HAVE_DHCP
void dhcp_common_init(void);
ssize_t recv_dhcp_packet(int fd, struct msghdr *msg);
struct dhcp_netid *run_tag_if(struct dhcp_netid *tags);
struct dhcp_netid *option_filter(struct dhcp_netid *tags, struct dhcp_netid *context_tags,
				 struct dhcp_opt *opts);
int match_netid(struct dhcp_netid *check, struct dhcp_netid *pool, int tagnotneeded);
char *strip_hostname(char *hostname);
void log_tags(struct dhcp_netid *netid, u32 xid);
int match_bytes(struct dhcp_opt *o, unsigned char *p, int len);
void dhcp_update_configs(struct dhcp_config *configs);
void display_opts(void);
int lookup_dhcp_opt(int prot, char *name);
int lookup_dhcp_len(int prot, int val);
struct dhcp_config *find_config(struct dhcp_config *configs,
				struct dhcp_context *context,
				unsigned char *clid, int clid_len,
				unsigned char *hwaddr, int hw_len, 
				int hw_type, char *hostname,
				struct dhcp_netid *filter);
int config_has_mac(struct dhcp_config *config, unsigned char *hwaddr, int len, int type);
#ifdef HAVE_LINUX_NETWORK
char *whichdevice(void);
int bind_dhcp_devices(char *bound_device);
#endif
#  ifdef HAVE_DHCP6
void display_opts6(void);
#  endif
void log_context(int family, struct dhcp_context *context);
void log_relay(int family, struct dhcp_relay *relay);
#endif

/* outpacket.c */
#ifdef HAVE_DHCP6
void end_opt6(int container);
void reset_counter(void);
int save_counter(int newval);
void *expand(size_t headroom);
int new_opt6(int opt);
void *put_opt6(void *data, size_t len);
void put_opt6_long(unsigned int val);
void put_opt6_short(unsigned int val);
void put_opt6_char(unsigned int val);
void put_opt6_string(char *s);
#endif

/* radv.c */
#ifdef HAVE_DHCP6
void ra_init(time_t now);
void icmp6_packet(time_t now);
time_t periodic_ra(time_t now);
void ra_start_unsolicited(time_t now, struct dhcp_context *context);
#endif

/* slaac.c */ 
#ifdef HAVE_DHCP6
void slaac_add_addrs(struct dhcp_lease *lease, time_t now, int force);
time_t periodic_slaac(time_t now, struct dhcp_lease *leases);
void slaac_ping_reply(struct in6_addr *sender, unsigned char *packet, char *interface, struct dhcp_lease *leases);
#endif

/* loop.c */
#ifdef HAVE_LOOP
void loop_send_probes(void);
int detect_loop(char *query, int type);
#endif

/* inotify.c */
#ifdef HAVE_INOTIFY
void inotify_dnsmasq_init(void);
int inotify_check(time_t now);
void set_dynamic_inotify(int flag, int total_size, struct crec **rhash, int revhashsz);
#endif

/* poll.c */
void poll_reset(void);
int poll_check(int fd, short event);
void poll_listen(int fd, short event);
int do_poll(int timeout);

/* rrfilter.c */
size_t rrfilter(struct dns_header *header, size_t plen, int mode);
u16 *rrfilter_desc(int type);
int expand_workspace(unsigned char ***wkspc, int *szp, int new);
/* modes. */
#define RRFILTER_EDNS0   0
#define RRFILTER_DNSSEC  1
#define RRFILTER_A       2
#define RRFILTER_AAAA    3
/* edns0.c */
unsigned char *find_pseudoheader(struct dns_header *header, size_t plen,
				   size_t *len, unsigned char **p, int *is_sign, int *is_last);
size_t add_pseudoheader(struct dns_header *header, size_t plen, unsigned char *limit, 
			unsigned short udp_sz, int optno, unsigned char *opt, size_t optlen, int set_do, int replace);
size_t add_do_bit(struct dns_header *header, size_t plen, unsigned char *limit);
size_t add_edns0_config(struct dns_header *header, size_t plen, unsigned char *limit, 
			union mysockaddr *source, time_t now, int *cacheable);
int check_source(struct dns_header *header, size_t plen, unsigned char *pseudoheader, union mysockaddr *peer);

/* arp.c */
int find_mac(union mysockaddr *addr, unsigned char *mac, int lazy, time_t now);
int do_arp_script_run(void);

/* dump.c */
#ifdef HAVE_DUMPFILE
void dump_init(void);
void dump_packet(int mask, void *packet, size_t len, union mysockaddr *src,
		 union mysockaddr *dst, int port);
#endif

/* domain-match.c */
void build_server_array(void);
int lookup_domain(char *qdomain, int flags, int *lowout, int *highout);
int filter_servers(int seed, int flags, int *lowout, int *highout);
int is_local_answer(time_t now, int first, char *name);
size_t make_local_answer(int flags, int gotname, size_t size, struct dns_header *header,
			 char *name, char *limit, int first, int last, int ede);
int server_samegroup(struct server *a, struct server *b);
#ifdef HAVE_DNSSEC
int dnssec_server(struct server *server, char *keyname, int *firstp, int *lastp);
#endif
void mark_servers(int flag);
void cleanup_servers(void);
int add_update_server(int flags,
		      union mysockaddr *addr,
		      union mysockaddr *source_addr,
		      const char *interface,
		      const char *domain,
		      union all_addr *local_addr); 
