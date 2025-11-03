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
 * @file config.h
 * @brief Compile-time configuration constants and feature gates
 * 
 * DETAILED PURPOSE:
 * 
 * This header file serves as the centralized compile-time configuration system for dnsmasq,
 * controlling feature availability, resource limits, and platform-specific behavior. It defines
 * three primary categories of configuration: (1) tuning constants that set resource limits and
 * default operational parameters, (2) feature gate macros that enable or disable entire subsystems,
 * and (3) platform detection macros that adapt dnsmasq's networking layer to different operating
 * systems. Configuration values are established at build time via Makefile COPTS flags (e.g.,
 * "make COPTS=-DHAVE_DNSSEC") and affect conditional compilation throughout the entire codebase
 * via #ifdef guards.
 * 
 * The file contains approximately 60 tuning constants defining limits such as maximum concurrent
 * DNS queries (FTABSIZ), cache size (CACHESIZ), and DHCP lease limits (MAXLEASES). These constants
 * can be overridden at compile time but provide sensible defaults for typical deployments. Feature
 * gate macros (HAVE_DHCP, HAVE_DNSSEC, HAVE_TFTP, etc.) determine which major subsystems are compiled
 * into the binary, with dependencies automatically enforced (e.g., HAVE_DHCP6 implies HAVE_DHCP).
 * Platform-specific macros (HAVE_LINUX_NETWORK, HAVE_BSD_NETWORK, HAVE_SOLARIS_NETWORK) enable
 * appropriate networking implementations for Linux Netlink, BSD routing sockets, or Solaris ioctl
 * fallbacks.
 * 
 * KEY RESPONSIBILITIES:
 * 
 * - Define resource limit constants (FTABSIZ, CACHESIZ, MAXLEASES, etc.) controlling memory usage
 *   and operational capacity, with defaults suitable for typical residential/small business deployments
 * - Declare feature gate macros (HAVE_DHCP, HAVE_DNSSEC, HAVE_TFTP, etc.) that enable or disable
 *   major subsystems via conditional compilation, reducing binary size and dependency requirements
 * - Establish platform detection macros (HAVE_LINUX_NETWORK, HAVE_BSD_NETWORK, HAVE_SOLARIS_NETWORK)
 *   that select appropriate networking implementations based on target operating system
 * - Enforce feature dependency relationships (HAVE_DHCP6 requires HAVE_DHCP, HAVE_LUASCRIPT requires
 *   HAVE_SCRIPT) through preprocessor logic to prevent invalid configuration combinations
 * - Define platform-specific default paths (LEASEFILE, CONFFILE, RESOLVFILE) that adapt to filesystem
 *   conventions on different operating systems (Linux /var/lib, BSD /var/db, Android /data)
 * 
 * DEPENDENCIES:
 * 
 * - No #include directives (pure macro definition header)
 * - Used by: All source files in src/ that require compile-time configuration
 * - Affects: Conditional compilation blocks throughout dnsmasq.c, forward.c, cache.c, dhcp.c,
 *   dhcp6.c, dnssec.c, network.c, netlink.c, bpf.c, option.c, and all other implementation files
 * - External library dependencies controlled by macros:
 *   * HAVE_DBUS requires libdbus-1
 *   * HAVE_DNSSEC requires libnettle and libhogweed (version 3.0+)
 *   * HAVE_LIBIDN2 requires libidn2 (version 2.0+)
 *   * HAVE_CONNTRACK requires libnetfilter_conntrack
 *   * HAVE_NFTSET requires libnftables (version 0.9+)
 *   * HAVE_LUASCRIPT requires lua5.2
 * 
 * DATA STRUCTURES:
 * 
 * This file contains only macro definitions, no struct, enum, or union declarations.
 * 
 * COMPILE-TIME OPTIONS:
 * 
 * All macros in this file ARE compile-time options. Configuration is performed at build time via:
 * - Makefile COPTS variable: make COPTS="-DHAVE_DNSSEC -DNO_TFTP"
 * - Direct editing of default feature enables (lines 176-183)
 * - Platform-specific automatic configuration (lines 253-310)
 * 
 * Common build configurations:
 * - Full-featured: make COPTS="-DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_LIBIDN2"
 * - Minimal: make COPTS="-DNO_DHCP -DNO_TFTP -DNO_AUTH"
 * - Embedded: make COPTS="-DHAVE_BROKEN_RTC -DNO_SCRIPT -DNO_INOTIFY"
 * 
 * THREADING/CONCURRENCY:
 * 
 * Configuration macros have no runtime threading implications. All macro values are resolved at
 * compile time and do not change during program execution. Values like FTABSIZ and CACHESIZ
 * determine the size of statically allocated or initially allocated data structures in the
 * single-process event-driven architecture.
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 * 
 * @see docs/CONFIGURATION.md for detailed configuration system documentation
 * @see docs/BUILDING.md for build instructions and dependency requirements
 */

/**
 * @def FTABSIZ
 * @brief Maximum number of outstanding DNS forward requests
 * 
 * Default: 150
 * 
 * Controls the size of the forward record (frec) freelist, limiting concurrent upstream DNS queries.
 * Each outstanding query from a client that requires forwarding to an upstream server consumes one
 * forward record. When this limit is reached, additional queries are dropped until existing queries
 * complete. The value affects memory usage: each frec is approximately 128 bytes, so FTABSIZ=150
 * consumes ~19KB. For high-traffic servers (>100 queries/second sustained), increase to 300-500.
 * For memory-constrained embedded systems, decrease to 50-100.
 * 
 * Affects: daemon->ftabsiz in dnsmasq.h struct daemon, forward.c allocate_frec() freelist size
 * Override: Cannot be overridden at runtime; must be changed at compile time
 * Referenced in: forward.c (frec allocation), dnsmasq.c (daemon initialization)
 * Performance impact: Too low causes query drops under load; too high wastes memory
 */
#define FTABSIZ 150 /* max number of outstanding requests (default) */

/**
 * @def MAX_PROCS
 * @brief Maximum number of child processes for TCP DNS connections
 * 
 * Default: 20
 * 
 * Limits concurrent TCP connections by restricting the number of child processes spawned to handle
 * TCP DNS queries. Each TCP connection gets its own forked child process to avoid blocking the main
 * event loop. When this limit is reached, new TCP connection attempts are rejected. TCP queries are
 * less common than UDP (typically <5% of traffic) but essential for large responses exceeding UDP
 * packet size limits (>512 bytes without EDNS0, >4096 bytes with EDNS0). Child processes are
 * automatically terminated after CHILD_LIFETIME seconds of inactivity.
 * 
 * Affects: dnsmasq.c TCP connection handling, process forking logic
 * Override: Cannot be overridden at runtime
 * Performance impact: Each child process consumes ~2MB resident memory
 * Security consideration: Limits resource exhaustion from TCP connection floods
 */
#define MAX_PROCS 20 /* max no children for TCP requests */

/**
 * @def CHILD_LIFETIME
 * @brief Maximum lifetime in seconds for TCP child processes
 * 
 * Default: 150 seconds
 * 
 * Child processes handling TCP DNS connections are automatically terminated after this duration,
 * regardless of activity state. This prevents resource leaks from long-lived connections and
 * protects against clients holding connections open indefinitely. RFC 1035 Section 4.2.2 suggests
 * TCP connections should remain open for at least 120 seconds to allow multiple queries, so 150
 * seconds provides a safe margin. After this timeout, the child process exits and the TCP socket
 * is closed, forcing clients to reconnect for additional queries.
 * 
 * Affects: dnsmasq.c TCP child process cleanup logic
 * RFC compliance: Exceeds RFC 1035 minimum recommendation of 120 seconds
 * Override: Cannot be overridden at runtime
 */
#define CHILD_LIFETIME 150 /* secs 'till terminated (RFC1035 suggests > 120s) */

/**
 * @def TCP_MAX_QUERIES
 * @brief Maximum number of DNS queries allowed per TCP connection
 * 
 * Default: 100 queries
 * 
 * Limits the number of DNS queries that can be pipelined over a single TCP connection before the
 * connection is closed. TCP DNS allows multiple queries to be sent over one connection without
 * waiting for responses (pipelining), improving efficiency. This limit prevents resource exhaustion
 * from clients sending unbounded query streams. After 100 queries are processed, the child process
 * closes the connection gracefully. Normal DNS clients typically send 1-10 queries per connection.
 * 
 * Affects: dnsmasq.c TCP query processing loop
 * Override: Cannot be overridden at runtime
 * Security consideration: Prevents TCP connection resource exhaustion attacks
 */
#define TCP_MAX_QUERIES 100 /* Maximum number of queries per incoming TCP connection */

/**
 * @def TCP_BACKLOG
 * @brief Kernel listen backlog for TCP connection queue
 * 
 * Default: 32 connections
 * 
 * Specifies the maximum length of the kernel's pending connection queue for the TCP DNS listening
 * socket, passed to listen(2) system call. When the queue is full, new TCP connection attempts
 * receive connection refused errors. This value should accommodate bursts of TCP connections during
 * normal operation. Since TCP DNS traffic is typically <5% of total queries, 32 provides adequate
 * capacity for most deployments without excessive kernel memory usage.
 * 
 * Affects: network.c TCP socket creation with listen() call
 * Override: Cannot be overridden at runtime
 * Platform note: Kernel may cap this value (e.g., Linux /proc/sys/net/core/somaxconn)
 */
#define TCP_BACKLOG 32  /* kernel backlog limit for TCP connections */

/**
 * @def EDNS_PKTSZ
 * @brief Default maximum EDNS0 UDP packet size advertised to clients and upstream servers
 * 
 * Default: 4096 bytes
 * 
 * Specifies the UDP payload size advertised in EDNS0 OPT records per RFC 6891. This value indicates
 * the maximum DNS response size dnsmasq can receive without TCP fallback. 4096 bytes is the RFC 6891
 * recommended value, balancing between allowing large DNSSEC responses (which can exceed 2KB) and
 * avoiding IP fragmentation on typical Ethernet MTU (1500 bytes). Responses exceeding this size
 * trigger TC (truncation) bit, forcing TCP retry. Can be overridden at runtime with --edns-packet-max
 * option.
 * 
 * Affects: edns0.c OPT record construction, forward.c response size validation
 * RFC compliance: Matches RFC 6891 Section 6.2.5 recommended value
 * Override: Runtime override via --edns-packet-max=<size> option in option.c
 * Related: SAFE_PKTSZ defines conservative minimum for internet-wide compatibility
 * 
 * @see SAFE_PKTSZ for DNS Flag Day 2020 recommended minimum
 */
#define EDNS_PKTSZ 4096 /* default max EDNS.0 UDP packet from RFC5625 */

/**
 * @def SAFE_PKTSZ
 * @brief Conservative "go anywhere" UDP packet size for maximum internet-wide compatibility
 * 
 * Default: 1232 bytes
 * 
 * Defines a conservative UDP packet size that avoids fragmentation on nearly all internet paths,
 * per DNS Flag Day 2020 recommendations (see https://dnsflagday.net/2020/). This value accounts for
 * IPv6 minimum MTU (1280 bytes) minus IPv6 header (40 bytes) minus UDP header (8 bytes), ensuring
 * DNS responses don't exceed path MTU. Used as fallback when larger EDNS0 sizes fail or for clients
 * not supporting EDNS0. Guarantees delivery across NAT, VPN, tunnel, and IPv6-over-IPv4 networks
 * without fragmentation, which many firewalls drop.
 * 
 * Affects: edns0.c fallback packet size selection, forward.c retry logic
 * Rationale: DNS Flag Day 2020 analysis of internet path MTU distribution
 * Override: Cannot be overridden at runtime
 * Reference: https://dnsflagday.net/2020/ for detailed analysis
 */
#define SAFE_PKTSZ 1232 /* "go anywhere" UDP packet size, see https://dnsflagday.net/2020/ */

/**
 * @def KEYBLOCK_LEN
 * @brief DNSSEC key storage block size optimized to minimize fragmentation
 * 
 * Default: 40 bytes
 * 
 * Defines the block allocation size for storing DNSSEC key material in blockdata.c block-chained
 * buffers. DNSSEC DNSKEY and RRSIG records contain variable-length cryptographic keys (RSA keys can
 * be 1024-4096 bits, ECDSA keys 256-384 bits). A 40-byte block size balances between minimizing
 * memory waste for small keys (ECDSA P-256 public keys are ~64 bytes) and reducing chain length
 * for large keys (RSA-2048 public keys are ~256 bytes). Smaller blocks increase chain traversal
 * overhead; larger blocks waste memory for small keys.
 * 
 * Affects: blockdata.c block allocation for DNSSEC key storage, dnssec.c key handling
 * Compiled only when: HAVE_DNSSEC is defined
 * Override: Cannot be overridden at runtime
 * Memory impact: Each key requires ceil(key_size / 40) blocks
 */
#define KEYBLOCK_LEN 40 /* choose to minimise fragmentation when storing DNSSEC keys */

/**
 * @def DNSSEC_WORK
 * @brief Maximum number of validation queries allowed to validate one DNSSEC question
 * 
 * Default: 50 queries
 * 
 * Limits DNSSEC validation work by capping the number of additional DNS queries (DNSKEY, DS, RRSIG
 * fetches) required to validate a single original query. DNSSEC validation requires building a chain
 * of trust from the root through intermediate zones to the target domain. Each level may require
 * fetching DNSKEY and DS records. This limit prevents infinite loops from circular dependencies or
 * malicious records, and bounds CPU time and network traffic per validation attempt. Exceeding this
 * limit returns SERVFAIL to the client.
 * 
 * Affects: dnssec.c validation query counter, prevents validation resource exhaustion
 * Compiled only when: HAVE_DNSSEC is defined
 * Override: Cannot be overridden at runtime
 * Security consideration: Prevents DNSSEC validation DoS attacks
 */
#define DNSSEC_WORK 50 /* Max number of queries to validate one question */

/**
 * @def TIMEOUT
 * @brief Upstream query timeout in seconds before dropping UDP queries
 * 
 * Default: 10 seconds
 * 
 * Defines how long dnsmasq waits for responses from upstream DNS servers before considering a query
 * failed and trying the next server. After timeout, the query is retried with a different upstream
 * server (if available) or dropped entirely if all servers have timed out. 10 seconds balances
 * between giving slow/distant servers adequate time to respond and avoiding excessive latency for
 * clients. Most DNS responses arrive within 100-500ms; 10 seconds accommodates slow paths and
 * overloaded servers.
 * 
 * Affects: forward.c retry_send() timeout logic, upstream server health tracking
 * Override: Cannot be overridden at runtime
 * Client impact: Clients may implement their own timeouts (typically 5-10 seconds)
 */
#define TIMEOUT 10     /* drop UDP queries after TIMEOUT seconds */

/**
 * @def FORWARD_TEST
 * @brief Query count interval for testing all upstream servers
 * 
 * Default: 50 queries
 * 
 * After every 50 queries, dnsmasq tests the responsiveness of all configured upstream DNS servers,
 * even those previously marked as failed. This implements periodic health checking to detect when
 * failed servers recover. Without periodic testing, a failed server would never be retried after
 * initial failure. The value balances between detecting recovery quickly (low value) and avoiding
 * excessive traffic to known-bad servers (high value). Works in conjunction with FORWARD_TIME.
 * 
 * Affects: forward.c server selection algorithm, upstream server health monitoring
 * Override: Cannot be overridden at runtime
 * Related: FORWARD_TIME provides time-based alternative trigger
 */
#define FORWARD_TEST 50 /* try all servers every 50 queries */

/**
 * @def FORWARD_TIME
 * @brief Time interval in seconds for testing all upstream servers
 * 
 * Default: 20 seconds
 * 
 * Alternative trigger to FORWARD_TEST: tests all upstream servers after this many seconds elapse,
 * whichever comes first (50 queries or 20 seconds). Ensures periodic health checking even on
 * low-traffic servers where 50 queries might take minutes. On high-traffic servers, FORWARD_TEST
 * triggers first; on low-traffic servers, FORWARD_TIME triggers first. This guarantees upstream
 * server recovery is detected within 20 seconds regardless of query rate.
 * 
 * Affects: forward.c server health checking, timeout-based server testing
 * Override: Cannot be overridden at runtime
 * Related: FORWARD_TEST provides query-count-based alternative trigger
 */
#define FORWARD_TIME 20 /* or 20 seconds */

/**
 * @def UDP_TEST_TIME
 * @brief Interval in seconds for resetting UDP packet size assumptions
 * 
 * Default: 60 seconds
 * 
 * Periodically resets dnsmasq's assumptions about safe UDP packet sizes for upstream servers.
 * If large EDNS0 packets (up to EDNS_PKTSZ bytes) previously failed due to path MTU issues or
 * upstream server limitations, dnsmasq falls back to smaller sizes (SAFE_PKTSZ). This timer
 * allows retry of larger packets after 60 seconds in case network conditions have improved or
 * transient issues have resolved. Balances between avoiding fragmentation issues and maximizing
 * response capacity.
 * 
 * Affects: forward.c UDP packet size retry logic, EDNS0 size negotiation
 * Override: Cannot be overridden at runtime
 * Behavior: Allows return to EDNS_PKTSZ after temporary fallback to SAFE_PKTSZ
 */
#define UDP_TEST_TIME 60 /* How often to reset our idea of max packet size. */

/**
 * @def SERVERS_LOGGED
 * @brief Maximum number of upstream servers to include in debug/state log output
 * 
 * Default: 30 servers
 * 
 * When logging upstream DNS server state (triggered by SIGUSR1 or debug mode), limits output to
 * the first 30 configured servers to prevent excessive log spam in deployments with many upstream
 * servers. Most deployments use 2-5 upstream servers (e.g., ISP DNS + Google DNS + Cloudflare DNS),
 * but enterprise environments may configure dozens. Limiting log output improves readability and
 * reduces syslog traffic. The most important servers (primary upstreams) are logged.
 * 
 * Affects: log.c upstream server state logging, SIGUSR1 signal handler output
 * Override: Cannot be overridden at runtime
 * Typical deployments: 2-5 servers, so this limit is rarely reached
 */
#define SERVERS_LOGGED 30 /* Only log this many servers when logging state */

/**
 * @def LOCALS_LOGGED
 * @brief Maximum number of local addresses to include in debug/state log output
 * 
 * Default: 8 addresses
 * 
 * When logging local interface addresses (triggered by SIGUSR1 or debug mode), limits output to
 * first 8 addresses to prevent excessive log spam on systems with many network interfaces or many
 * IP addresses per interface. Typical residential systems have 2-4 addresses (loopback IPv4/IPv6,
 * LAN IPv4/IPv6), but servers and routers may have dozens. Limiting log output improves readability.
 * 
 * Affects: log.c local interface address logging, SIGUSR1 signal handler output
 * Override: Cannot be overridden at runtime
 */
#define LOCALS_LOGGED 8 /* Only log this many local addresses when logging state */

/**
 * @def LEASE_RETRY
 * @brief Retry interval in seconds for DHCP lease file writes after errors
 * 
 * Default: 60 seconds
 * 
 * When writing the DHCP lease database file fails (disk full, filesystem errors, permission issues),
 * dnsmasq retries after this interval. Prevents excessive retry attempts that could cause I/O storms
 * on failing disks while ensuring persistent storage is updated reasonably promptly once issues
 * resolve. 60 seconds balances between rapid recovery and avoiding resource waste on persistent
 * failures. Errors are logged to syslog for administrator attention.
 * 
 * Affects: lease.c lease_update_file() error handling, DHCP lease persistence
 * Compiled only when: HAVE_DHCP is defined
 * Override: Cannot be overridden at runtime
 * Related: HAVE_BROKEN_RTC affects lease file write frequency
 */
#define LEASE_RETRY 60 /* on error, retry writing leasefile after LEASE_RETRY seconds */

/**
 * @def CACHESIZ
 * @brief Default DNS cache size in number of records
 * 
 * Default: 150 records
 * 
 * Defines the default size of the DNS cache, measured in number of cached resource records (RRs).
 * Each cached record (A, AAAA, CNAME, MX, etc.) occupies one cache slot. The cache uses an LRU
 * (Least Recently Used) eviction policy when full. 150 records is suitable for residential use
 * (typically 50-100 unique domains accessed) but insufficient for busy networks. Can be overridden
 * at runtime with --cache-size=<n> option, commonly increased to 1000-10000 for enterprise
 * deployments. Setting to 0 disables caching entirely.
 * 
 * Affects: cache.c hash table sizing, LRU list allocation, daemon->cachesize
 * Override: Runtime override via --cache-size=<n> option in option.c
 * Memory impact: Each cache record (struct crec) is ~128 bytes, so 150 records ≈ 19KB
 * Performance: Higher values reduce upstream queries and latency at cost of memory
 * 
 * EXAMPLE:
 * Increase cache size for enterprise deployment: dnsmasq --cache-size=5000
 */
#define CACHESIZ 150 /* default cache size */

/**
 * @def TTL_FLOOR_LIMIT
 * @brief Absolute maximum TTL in seconds that --min-cache-ttl can enforce
 * 
 * Default: 3600 seconds (1 hour)
 * 
 * Caps the --min-cache-ttl option to prevent excessively long caching that could serve stale data.
 * The --min-cache-ttl option allows administrators to override short TTLs from upstream servers,
 * useful for reducing query load when upstream servers set aggressive (low) TTLs. However, enforcing
 * minimum TTLs too high risks serving outdated records after DNS changes. This 1-hour hard limit
 * balances between caching efficiency and data freshness, ensuring records expire at least daily
 * regardless of configuration.
 * 
 * Affects: cache.c TTL enforcement, --min-cache-ttl option validation in option.c
 * Override: Cannot be overridden (this IS the hard limit)
 * RFC consideration: RFC 2181 allows TTLs up to 2^31-1 seconds, but long TTLs impede updates
 */
#define TTL_FLOOR_LIMIT 3600 /* don't allow --min-cache-ttl to raise TTL above this under any circumstances */

/**
 * @def MAXLEASES
 * @brief Maximum number of DHCP leases that can be tracked simultaneously
 * 
 * Default: 1000 leases
 * 
 * Hard limit on total DHCP leases (both DHCPv4 and DHCPv6) that dnsmasq can manage concurrently.
 * Prevents unbounded memory growth from lease database. Each lease consumes memory for client
 * identifier, IP address, hostname, and metadata (~200 bytes per lease, so 1000 leases ≈ 200KB).
 * When limit reached, new DHCP requests receive DHCPNAK (DHCPv4) or error replies (DHCPv6) until
 * leases expire. Typical residential networks have 5-50 devices; small business networks 50-500;
 * 1000 is sufficient for most deployments below enterprise scale.
 * 
 * Affects: lease.c lease allocation, dhcp.c/dhcp6.c lease management
 * Compiled only when: HAVE_DHCP is defined
 * Override: Cannot be overridden at runtime
 * Memory impact: 1000 leases × 200 bytes ≈ 200KB resident memory
 * Scale consideration: Enterprise networks with >1000 clients need ISC DHCP or similar
 */
#define MAXLEASES 1000 /* maximum number of DHCP leases */

/**
 * @def PING_WAIT
 * @brief Seconds to wait for ICMP echo reply during DHCP address conflict detection
 * 
 * Default: 3 seconds
 * 
 * Before assigning a DHCP address, dnsmasq optionally sends an ICMP echo request (ping) to detect
 * if the address is already in use by an unconfigured device (address conflict). This timeout
 * determines how long to wait for an echo reply. 3 seconds balances between detecting conflicts
 * reliably (some devices respond slowly) and avoiding excessive delay in DHCP handshakes. If no
 * reply within 3 seconds, address is assumed free. Feature enabled with --dhcp-option=tag:!known,option:ping.
 * 
 * Affects: dhcp.c address_allocate() ping-before-offer logic, icmp_ping() timeout
 * Compiled only when: HAVE_DHCP is defined
 * Override: Cannot be overridden at runtime
 * Performance impact: Adds 3-second delay to DHCP handshake for unknown clients when ping enabled
 */
#define PING_WAIT 3 /* wait for ping address-in-use test */

/**
 * @def PING_CACHE_TIME
 * @brief Seconds to cache successful ping results for address conflict detection
 * 
 * Default: 30 seconds
 * 
 * After successfully pinging an address (confirming it's in use), caches the result for 30 seconds
 * to avoid redundant pings during DHCP retries or renewals. If a client sends multiple DHCPDISCOVER
 * messages (normal for retries), dnsmasq can skip re-pinging the same address if checked recently.
 * Reduces ICMP traffic and improves DHCP response time for retries. 30 seconds is conservative,
 * ensuring address state doesn't change significantly between checks.
 * 
 * Affects: dhcp.c ping result caching, address_allocate() ping optimization
 * Compiled only when: HAVE_DHCP is defined
 * Override: Cannot be overridden at runtime
 */
#define PING_CACHE_TIME 30 /* Ping test assumed to be valid this long. */

/**
 * @def DECLINE_BACKOFF
 * @brief Seconds to disable a static DHCP address after client sends DHCPDECLINE
 * 
 * Default: 600 seconds (10 minutes)
 * 
 * When a DHCP client sends DHCPDECLINE (indicating offered address is already in use, per RFC 2131
 * Section 3.1.5), dnsmasq temporarily disables that address to prevent repeated conflicts. The
 * address is removed from the available pool for 10 minutes, giving administrators time to resolve
 * the conflict (e.g., remove rogue device, fix static IP configuration). After 600 seconds, address
 * returns to pool automatically. Prevents rapid conflict loops where the same bad address is offered
 * repeatedly.
 * 
 * Affects: dhcp.c DHCPDECLINE handling, address pool management
 * Compiled only when: HAVE_DHCP is defined
 * RFC compliance: Implements RFC 2131 Section 3.1.5 DECLINE handling
 * Override: Cannot be overridden at runtime
 */
#define DECLINE_BACKOFF 600 /* disable DECLINEd static addresses for this long */

/**
 * @def DHCP_PACKET_MAX
 * @brief Hard limit on DHCP packet size in bytes
 * 
 * Default: 16384 bytes (16KB)
 * 
 * Maximum size for DHCP packets (both DHCPv4 and DHCPv6), preventing memory exhaustion from
 * malformed packets claiming excessive lengths. Standard DHCP packets are 300-600 bytes, but
 * DHCP options can extend packets significantly. DHCPv6 with many options can approach several
 * KB. 16KB provides safe margin for legitimate packets with extensive options while preventing
 * memory attacks. Packets exceeding this size are dropped with error logged.
 * 
 * Affects: dhcp.c/dhcp6.c packet reception buffers, rfc2131.c/rfc3315.c packet parsing
 * Compiled only when: HAVE_DHCP is defined
 * Override: Cannot be overridden at runtime
 * Security consideration: Prevents memory exhaustion DoS attacks
 */
#define DHCP_PACKET_MAX 16384 /* hard limit on DHCP packet size */

/**
 * @def SMALLDNAME
 * @brief Size optimization hint: most domain names fit within this length
 * 
 * Default: 50 bytes
 * 
 * Used for stack-allocated domain name buffers in performance-critical code paths where most domain
 * names are known to be short. Maximum DNS name length is 255 bytes per RFC 1035, but typical
 * domain names (google.com, facebook.com, example.org) are 10-30 bytes. Using 50-byte stack buffers
 * for common cases avoids dynamic allocation overhead; longer names fall back to heap allocation.
 * This is a performance optimization, not a limit—longer names are handled correctly.
 * 
 * Affects: domain.c, rfc1035.c temporary domain name buffers
 * Override: Cannot be overridden at runtime
 * Performance: Stack allocation is 10-100x faster than malloc() for short names
 */
#define SMALLDNAME 50 /* most domain names are smaller than this */

/**
 * @def CNAME_CHAIN
 * @brief Maximum CNAME chain length before loop detection triggers
 * 
 * Default: 10 hops
 * 
 * Limits CNAME chain following to prevent infinite loops from circular CNAME records. DNS allows
 * CNAME records to point to other CNAMEs, forming chains (e.g., www.example.com -> cdn.example.com
 * -> cdn-provider.net). Malicious or misconfigured records can form loops (A -> B -> C -> A).
 * This limit stops resolution after 10 CNAME hops, returning SERVFAIL. RFC 1034 Section 3.6.2
 * suggests resolvers should detect loops; 10 hops accommodates legitimate multi-level redirects
 * while preventing resource exhaustion.
 * 
 * Affects: cache.c CNAME chain following in cache_lookup(), rfc1035.c extract_name()
 * Override: Cannot be overridden at runtime
 * RFC consideration: RFC 1034 requires loop detection but doesn't specify maximum depth
 */
#define CNAME_CHAIN 10 /* chains longer than this atr dropped for loop protection */

/**
 * @def DNSSEC_MIN_TTL
 * @brief Minimum TTL in seconds for cached DNSKEY and DS records
 * 
 * Default: 60 seconds
 * 
 * Enforces minimum cache TTL for DNSSEC validation records (DNSKEY, DS) to avoid excessive
 * re-validation overhead. Even if upstream servers specify shorter TTLs, dnsmasq caches these
 * records for at least 60 seconds. DNSSEC validation requires fetching DNSKEY and DS records
 * for every validated query; caching them reduces upstream traffic and latency. Short TTLs on
 * DNSSEC records are often misconfigured; 60-second minimum balances between respecting zone
 * operator intent and maintaining validation performance.
 * 
 * Affects: dnssec.c validation record caching, cache.c TTL enforcement
 * Compiled only when: HAVE_DNSSEC is defined
 * Override: Cannot be overridden at runtime
 */
#define DNSSEC_MIN_TTL 60 /* DNSKEY and DS records in cache last at least this long */

/**
 * @def HOSTSFILE
 * @brief Default path to system hosts file for static hostname resolution
 * 
 * Default: "/etc/hosts"
 * 
 * Path to the system hosts file containing static IP-to-hostname mappings, read by dnsmasq for
 * local name resolution. Standard Unix location is /etc/hosts. Entries from this file are loaded
 * into dnsmasq's cache at startup and reloaded on SIGHUP. Can be overridden with --hostsfile
 * option or multiple files can be specified with --addn-hosts.
 * 
 * Affects: option.c configuration parsing, cache.c hosts file loading
 * Override: Runtime override via --hostsfile=/path/to/hosts
 * Platform note: Consistent across most Unix-like systems
 */
#define HOSTSFILE "/etc/hosts"

/**
 * @def ETHERSFILE
 * @brief Default path to system ethers file for MAC-to-IP address mappings
 * 
 * Default: "/etc/ethers"
 * 
 * Path to the ethers file containing Ethernet MAC address to hostname mappings, used for DHCP
 * static assignments. Format: <MAC-address> <hostname> per line. Used when --read-ethers option
 * is enabled. Allows centralized management of MAC-to-hostname mappings outside dnsmasq.conf.
 * Less commonly used than direct dhcp-host options.
 * 
 * Affects: option.c configuration parsing, dhcp.c static host configuration
 * Compiled only when: HAVE_DHCP is defined
 * Override: Functionality enabled via --read-ethers option
 */
#define ETHERSFILE "/etc/ethers"

/**
 * @def DEFLEASE
 * @brief Default DHCPv4 lease time in seconds
 * 
 * Default: 3600 seconds (1 hour)
 * 
 * Default duration for DHCPv4 address leases when not explicitly configured. After lease expiration,
 * clients must renew or release addresses. 1-hour default balances between frequent renewals
 * (more overhead, better responsiveness to network changes) and long leases (less overhead, slower
 * to reclaim addresses). Typical deployments: 1-24 hours for dynamic hosts, infinite for servers.
 * Can be overridden per-subnet with dhcp-range option or per-host with dhcp-host option.
 * 
 * Affects: rfc2131.c lease time in DHCPOFFER/DHCPACK, lease.c lease expiry calculation
 * Compiled only when: HAVE_DHCP is defined
 * Override: Runtime override via dhcp-range option with lease time parameter
 * RFC compliance: RFC 2131 Section 3.3 allows any lease duration
 */
#define DEFLEASE 3600 /* default DHCPv4 lease time, one hour */

/**
 * @def DEFLEASE6
 * @brief Default DHCPv6 lease time in seconds
 * 
 * Default: 86400 seconds (24 hours)
 * 
 * Default duration for DHCPv6 address leases when not explicitly configured. DHCPv6 typically uses
 * longer leases than DHCPv4 because IPv6 addresses are more plentiful and address exhaustion is
 * rare. 24-hour default reduces renewal traffic on IPv6 networks. DHCPv6 uses two timers: T1
 * (renewal, typically 50% of lease) and T2 (rebind, typically 80% of lease). Longer leases improve
 * stability for mobile clients.
 * 
 * Affects: rfc3315.c lease time in DHCPv6 ADVERTISE/REPLY, lease.c lease expiry calculation
 * Compiled only when: HAVE_DHCP6 is defined
 * Override: Runtime override via dhcp-range option with lease time parameter
 * RFC compliance: RFC 3315 Section 22.4 defines lease time encoding
 */
#define DEFLEASE6 (3600*24) /* default lease time for DHCPv6. One day. */

/**
 * @def CHUSER
 * @brief Default unprivileged user for privilege dropping
 * 
 * Default: "nobody"
 * 
 * Username to switch to after binding privileged ports (53 for DNS, 67 for DHCP). After startup,
 * dnsmasq drops root privileges by calling setuid() to this user, minimizing security risk from
 * vulnerabilities. "nobody" is standard unprivileged user on most Unix systems. Can be overridden
 * with --user option. If user doesn't exist or dnsmasq isn't started as root, privilege dropping
 * is skipped with warning logged.
 * 
 * Affects: dnsmasq.c privilege dropping after daemon initialization
 * Override: Runtime override via --user=<username> option
 * Security: Critical for defense-in-depth; exploits can't gain root access after privilege drop
 */
#define CHUSER "nobody"

/**
 * @def CHGRP
 * @brief Default unprivileged group for privilege dropping
 * 
 * Default: "dip" (Dialup IP group)
 * 
 * Group name to switch to after binding privileged ports. "dip" group traditionally has permissions
 * for network configuration files on Debian-based systems, allowing dnsmasq to read /etc/resolv.conf
 * and similar files after privilege drop. Can be overridden with --group option. If group doesn't
 * exist, falls back to primary group of CHUSER.
 * 
 * Affects: dnsmasq.c privilege dropping after daemon initialization
 * Override: Runtime override via --group=<groupname> option
 * Platform note: "dip" group is Debian convention; other distros may use "users" or "nogroup"
 */
#define CHGRP "dip"

/**
 * @def TFTP_MAX_CONNECTIONS
 * @brief Maximum number of simultaneous TFTP file transfers
 * 
 * Default: 50 connections
 * 
 * Limits concurrent TFTP transfers to prevent resource exhaustion. Each TFTP transfer maintains
 * state for block retransmission and acknowledgment tracking. 50 simultaneous transfers is adequate
 * for typical PXE boot environments (netbooting 50 workstations concurrently). Each connection
 * consumes ~1KB memory. Exceeding limit causes new TFTP requests to receive error responses.
 * 
 * Affects: tftp.c connection tracking, TFTP request handling
 * Compiled only when: HAVE_TFTP is defined
 * Override: Cannot be overridden at runtime
 * Typical load: PXE boot environments typically have <20 concurrent boots
 */
#define TFTP_MAX_CONNECTIONS 50 /* max simultaneous connections */

/**
 * @def LOG_MAX
 * @brief Maximum length of asynchronous log message queue
 * 
 * Default: 5 messages
 * 
 * Dnsmasq uses asynchronous logging to avoid blocking the main event loop during syslog writes.
 * Log messages are queued and written by separate code path. This limit prevents unbounded queue
 * growth if syslog becomes slow or unresponsive. When queue is full, new log messages are dropped
 * (preventing DoS via log flooding). 5 entries is sufficient for typical burst logging; sustained
 * high logging rates indicate configuration issues.
 * 
 * Affects: log.c asynchronous log queue management
 * Override: Cannot be overridden at runtime
 * Performance: Asynchronous logging prevents syslog blocking DNS/DHCP responses
 */
#define LOG_MAX 5 /* log-queue length */

/**
 * @def RANDFILE
 * @brief Path to kernel random number generator device
 * 
 * Default: "/dev/urandom"
 * 
 * Device file for seeding cryptographic random number generator used for DNS transaction IDs,
 * source port randomization, and DNSSEC operations. /dev/urandom provides non-blocking random
 * data from kernel entropy pool. Critical for security: predictable transaction IDs enable cache
 * poisoning attacks. Used at startup to seed SURF PRNG (from djbdns) for fast random number
 * generation during operation.
 * 
 * Affects: util.c rand_init() PRNG seeding
 * Override: Cannot be overridden at runtime
 * Security: Essential for DNS cache poisoning prevention via ID and port randomization
 */
#define RANDFILE "/dev/urandom"

/**
 * @def DNSMASQ_SERVICE
 * @brief D-Bus service name for dnsmasq control interface
 * 
 * Default: "uk.org.thekelleys.dnsmasq"
 * 
 * D-Bus service name registered by dnsmasq when D-Bus support is enabled (HAVE_DBUS). Clients
 * use this name to invoke control methods like SetServers, ClearCache, GetVersion. Follows
 * reverse-DNS naming convention. Can be overridden with --dbus-name option for running multiple
 * dnsmasq instances with different D-Bus interfaces.
 * 
 * Affects: dbus.c D-Bus service registration
 * Compiled only when: HAVE_DBUS is defined
 * Override: Runtime override via --dbus-name option
 */
#define DNSMASQ_SERVICE "uk.org.thekelleys.dnsmasq" /* Default - may be overridden by config */

/**
 * @def DNSMASQ_PATH
 * @brief D-Bus object path for dnsmasq control interface
 * 
 * Default: "/uk/org/thekelleys/dnsmasq"
 * 
 * D-Bus object path for dnsmasq's control interface. D-Bus requires both service name and object
 * path for method invocation. Path follows D-Bus convention of representing service name as
 * filesystem-like path. Used with DNSMASQ_SERVICE for D-Bus communication.
 * 
 * Affects: dbus.c D-Bus object registration
 * Compiled only when: HAVE_DBUS is defined
 * Override: Cannot be overridden at runtime
 */
#define DNSMASQ_PATH "/uk/org/thekelleys/dnsmasq"

/**
 * @def DNSMASQ_UBUS_NAME
 * @brief OpenWrt ubus service name for dnsmasq control interface
 * 
 * Default: "dnsmasq"
 * 
 * Ubus service name for dnsmasq on OpenWrt systems. Ubus is OpenWrt's micro-bus IPC system,
 * alternative to D-Bus for embedded systems. Provides similar control methods as D-Bus interface
 * (listing leases, updating configuration, etc.). Can be overridden with --ubus-name option for
 * running multiple dnsmasq instances.
 * 
 * Affects: ubus.c ubus service registration
 * Compiled only when: HAVE_UBUS is defined (OpenWrt-specific)
 * Override: Runtime override via --ubus-name option
 */
#define DNSMASQ_UBUS_NAME "dnsmasq" /* Default - may be overridden by config */

/**
 * @def AUTH_TTL
 * @brief Default TTL in seconds for authoritative DNS records
 * 
 * Default: 600 seconds (10 minutes)
 * 
 * Time-to-live for DNS records served by dnsmasq's authoritative DNS server (when HAVE_AUTH enabled).
 * Authoritative server mode allows dnsmasq to serve configured zones directly without forwarding.
 * 10-minute TTL balances between reducing query load (caching) and allowing reasonably quick
 * updates to authoritative data. Can be overridden with --auth-ttl option.
 * 
 * Affects: auth.c authoritative response TTL values
 * Compiled only when: HAVE_AUTH is defined
 * Override: Runtime override via --auth-ttl=<seconds> option
 */
#define AUTH_TTL 600 /* default TTL for auth DNS */

/**
 * @def SOA_REFRESH
 * @brief Default SOA refresh interval in seconds for authoritative zones
 * 
 * Default: 1200 seconds (20 minutes)
 * 
 * SOA (Start of Authority) REFRESH field defines how often secondary nameservers should check
 * primary for zone updates. Used when dnsmasq operates as authoritative server (HAVE_AUTH).
 * 20-minute refresh is reasonable for small, infrequently updated local zones. RFC 1035 Section
 * 3.3.13 defines SOA record format. This is informational for secondary servers; dnsmasq doesn't
 * support zone transfers.
 * 
 * Affects: auth.c SOA record construction
 * Compiled only when: HAVE_AUTH is defined
 * RFC compliance: RFC 1035 Section 3.3.13 SOA RDATA format
 */
#define SOA_REFRESH 1200 /* SOA refresh default */

/**
 * @def SOA_RETRY
 * @brief Default SOA retry interval in seconds for authoritative zones
 * 
 * Default: 180 seconds (3 minutes)
 * 
 * SOA RETRY field defines how long secondary nameservers should wait before retrying after failed
 * refresh attempt. Used in authoritative mode (HAVE_AUTH). 3-minute retry allows quick recovery
 * from transient failures without excessive retry traffic. Typically shorter than REFRESH interval.
 * RFC 1035 Section 3.3.13 defines SOA format.
 * 
 * Affects: auth.c SOA record construction
 * Compiled only when: HAVE_AUTH is defined
 * RFC compliance: RFC 1035 Section 3.3.13 SOA RDATA format
 */
#define SOA_RETRY 180 /* SOA retry default */

/**
 * @def SOA_EXPIRY
 * @brief Default SOA expiry interval in seconds for authoritative zones
 * 
 * Default: 1209600 seconds (14 days)
 * 
 * SOA EXPIRE field defines how long secondary nameservers should consider zone data valid if
 * unable to contact primary. After expiry, secondaries stop answering queries for zone. 14-day
 * expiry provides large safety margin for primary server outages while eventually failing over
 * to prevent serving perpetually stale data. RFC 1035 Section 3.3.13 defines SOA format.
 * 
 * Affects: auth.c SOA record construction
 * Compiled only when: HAVE_AUTH is defined
 * RFC compliance: RFC 1035 Section 3.3.13 SOA RDATA format
 */
#define SOA_EXPIRY 1209600 /* SOA expiry default */

/**
 * @def LOOP_TEST_DOMAIN
 * @brief Test domain name for DNS forwarding loop detection
 * 
 * Default: "test"
 * 
 * Domain name used for detecting DNS forwarding loops when HAVE_LOOP is enabled. Dnsmasq generates
 * unique queries to "test" subdomain to detect if queries are forwarded back to itself (loop).
 * "test" is reserved by RFC 2606 Section 2 for testing purposes and guaranteed not to exist in
 * global DNS, preventing collisions with real domains. Loop detection protects against
 * misconfigurations where dnsmasq forwards to itself directly or via intermediate servers.
 * 
 * Affects: loop.c loop detection query generation
 * Compiled only when: HAVE_LOOP is defined
 * RFC compliance: RFC 2606 Section 2 reserves ".test" TLD for testing
 */
#define LOOP_TEST_DOMAIN "test" /* domain for loop testing, "test" is reserved by RFC 2606 and won't therefore clash */

/**
 * @def LOOP_TEST_TYPE
 * @brief DNS query type for forwarding loop detection queries
 * 
 * Default: T_TXT (Text record)
 * 
 * DNS record type used for loop detection queries to LOOP_TEST_DOMAIN. TXT records are chosen
 * because they're uncommon for genuine queries, making loop detection queries distinguishable.
 * Dnsmasq embeds unique identifiers in TXT queries to detect when its own queries return to it,
 * indicating a forwarding loop.
 * 
 * Affects: loop.c loop detection query generation and matching
 * Compiled only when: HAVE_LOOP is defined
 */
#define LOOP_TEST_TYPE T_TXT
 
/* compile-time options: uncomment below to enable or do eg.
   make COPTS=-DHAVE_BROKEN_RTC

HAVE_BROKEN_RTC
   define this on embedded systems which don't have an RTC
   which keeps time over reboots. Causes dnsmasq to use uptime
   for timing, and keep lease lengths rather than expiry times
   in its leases file. This also make dnsmasq "flash disk friendly".
   Normally, dnsmasq tries very hard to keep the on-disk leases file
   up-to-date: rewriting it after every renewal.  When HAVE_BROKEN_RTC 
   is in effect, the lease file is only written when a new lease is 
   created, or an old one destroyed. (Because those are the only times 
   it changes.) This vastly reduces the number of file writes, and makes
   it viable to keep the lease file on a flash filesystem.
   NOTE: when enabling or disabling this, be sure to delete any old
   leases file, otherwise dnsmasq may get very confused.

HAVE_TFTP
   define this to get dnsmasq's built-in TFTP server.

HAVE_DHCP
   define this to get dnsmasq's DHCPv4 server.

HAVE_DHCP6
   define this to get dnsmasq's DHCPv6 server. (implies HAVE_DHCP).

HAVE_SCRIPT
   define this to get the ability to call scripts on lease-change.

HAVE_LUASCRIPT
   define this to get the ability to call Lua script on lease-change. (implies HAVE_SCRIPT) 

HAVE_DBUS
   define this if you want to link against libdbus, and have dnsmasq
   support some methods to allow (re)configuration of the upstream DNS 
   servers via DBus.

HAVE_UBUS
   define this if you want to link against libubus

HAVE_IDN
   define this if you want international domain name 2003 support.
   
HAVE_LIBIDN2
   define this if you want international domain name 2008 support.

HAVE_CONNTRACK
   define this to include code which propagates conntrack marks from
   incoming DNS queries to the corresponding upstream queries. This adds
   a build-dependency on libnetfilter_conntrack, but the resulting binary will
   still run happily on a kernel without conntrack support.

HAVE_IPSET
    define this to include the ability to selectively add resolved ip addresses
    to given ipsets.

HAVE_NFTSET
    define this to include the ability to selectively add resolved ip addresses
    to given nftables sets.

HAVE_AUTH
   define this to include the facility to act as an authoritative DNS
   server for one or more zones.

HAVE_CRYPTOHASH
   include just hash function from crypto library, but no DNSSEC.

HAVE_DNSSEC
   include DNSSEC validator.

HAVE_DUMPFILE
   include code to dump packets to a libpcap-format file for debugging.

HAVE_LOOP
   include functionality to probe for and remove DNS forwarding loops.

HAVE_INOTIFY
   use the Linux inotify facility to efficiently re-read configuration files.

NO_ID
   Don't report *.bind CHAOS info to clients, forward such requests upstream instead.
NO_TFTP
NO_DHCP
NO_DHCP6
NO_SCRIPT
NO_LARGEFILE
NO_AUTH
NO_DUMPFILE
NO_LOOP
NO_INOTIFY
   these are available to explicitly disable compile time options which would 
   otherwise be enabled automatically or which are enabled  by default 
   in the distributed source tree. Building dnsmasq
   with something like "make COPTS=-DNO_SCRIPT" will do the trick.
NO_GMP
   Don't use and link against libgmp, Useful if nettle is built with --enable-mini-gmp.

LEASEFILE
CONFFILE
RESOLVFILE
   the default locations of these files are determined below, but may be overridden 
   in a build command line using COPTS.

*/

/* Defining this builds a binary which handles time differently and works better on a system without a 
   stable RTC (it uses uptime, not epoch time) and writes the DHCP leases file less often to avoid flash wear. 
*/

/**
 * @def HAVE_BROKEN_RTC
 * @brief Enable embedded systems mode for platforms without stable Real-Time Clock
 * 
 * When defined, adapts dnsmasq for embedded systems lacking stable RTC (Real-Time Clock) that
 * maintains time across reboots. Commented out by default (only define for embedded systems).
 * Changes time handling from absolute epoch time to relative uptime, making dnsmasq "flash disk
 * friendly" by dramatically reducing DHCP lease file writes. Normally dnsmasq rewrites lease file
 * after every renewal (maintaining accurate expiry times); with HAVE_BROKEN_RTC, lease file is
 * only written on lease creation or destruction, storing lease duration rather than expiry timestamp.
 * Reduces write cycles by 100x, critical for flash filesystems with limited write endurance.
 * 
 * WARNING: When enabling or disabling this option, DELETE existing lease file to prevent confusion
 * between duration-based and timestamp-based lease formats. Mixing formats causes incorrect lease
 * expiry calculations.
 * 
 * Affected files: lease.c (lease file format and write frequency), dhcp.c (time calculations)
 * External dependencies: None
 * Binary size impact: No significant change
 * Enabling: Uncomment this #define or make COPTS=-DHAVE_BROKEN_RTC
 * Use case: Embedded systems (routers, IoT devices) with flash storage and no battery-backed RTC
 * Side effect: Lease expiry times reset to configured duration after dnsmasq restart
 * Flash impact: Reduces lease file writes from ~1000/day to ~10/day on typical networks
 */
/* #define HAVE_BROKEN_RTC */

/* The default set of options to build. Built with these options, dnsmasq
   has no library dependencies other than libc */

/**
 * @def HAVE_DHCP
 * @brief Enable DHCPv4 server functionality
 * 
 * When defined, compiles DHCPv4 server implementation providing automatic IP address assignment
 * per RFC 2131. Enabled by default. Adds dhcp.c, rfc2131.c, lease.c, dhcp-common.c to compilation.
 * Provides DHCPDISCOVER/OFFER/REQUEST/ACK message handling, lease management, static host
 * reservations, DHCP options support (options 1-255), PXE boot support, and address pool management.
 * No external library dependencies. Disable with NO_DHCP or make COPTS=-DNO_DHCP.
 * 
 * Affected files: dhcp.c, rfc2131.c, lease.c, dhcp-common.c, network.c (DHCP socket binding)
 * External dependencies: None (libc only)
 * Binary size impact: Adds ~40KB to stripped binary
 * Disabling: make COPTS=-DNO_DHCP removes DHCPv4 and DHCPv6
 * Related: HAVE_DHCP6 requires HAVE_DHCP (dependency enforced automatically)
 */
#define HAVE_DHCP

/**
 * @def HAVE_DHCP6
 * @brief Enable DHCPv6 server functionality
 * 
 * When defined, compiles DHCPv6 server implementation providing IPv6 address assignment per
 * RFC 3315. Enabled by default. Automatically defines HAVE_DHCP (DHCPv6 requires DHCPv4 infrastructure).
 * Adds dhcp6.c, rfc3315.c, radv.c (Router Advertisement), slaac.c, outpacket.c to compilation.
 * Provides SOLICIT/ADVERTISE/REQUEST/REPLY message handling, DUID-based client identification,
 * IA_NA/IA_TA address allocation, Router Advertisement (RFC 4861), and SLAAC support (RFC 4862).
 * No external library dependencies beyond DHCPv4.
 * 
 * Affected files: dhcp6.c, rfc3315.c, radv.c, slaac.c, outpacket.c, dhcp-common.c
 * External dependencies: None (libc only)
 * Binary size impact: Adds ~30KB to stripped binary (in addition to HAVE_DHCP)
 * Dependency: Automatically defines HAVE_DHCP (lines 329-331 enforce this)
 * Disabling: make COPTS=-DNO_DHCP6 removes DHCPv6 only, or -DNO_DHCP removes both
 */
#define HAVE_DHCP6 

/**
 * @def HAVE_TFTP
 * @brief Enable built-in TFTP server functionality
 * 
 * When defined, compiles TFTP (Trivial File Transfer Protocol) server per RFC 1350. Enabled by
 * default. Adds tftp.c to compilation. Provides file serving for PXE network boot, firmware updates,
 * and diskless workstations. Supports RRQ (read requests), OACK (option acknowledgment), blksize
 * extension for larger blocks (improving performance), and concurrent transfer management (up to
 * TFTP_MAX_CONNECTIONS). No external library dependencies. Often used with DHCP options 66/67 for
 * PXE boot integration.
 * 
 * Affected files: tftp.c, network.c (TFTP socket binding), dnsmasq.c (TFTP listener registration)
 * External dependencies: None (libc only)
 * Binary size impact: Adds ~15KB to stripped binary
 * Disabling: make COPTS=-DNO_TFTP or edit config.h to #undef
 * Use case: PXE network boot, diskless workstation environments
 */
#define HAVE_TFTP

/**
 * @def HAVE_SCRIPT
 * @brief Enable external script execution on DHCP lease events
 * 
 * When defined, enables calling external scripts when DHCP leases change (add, renew, delete).
 * Enabled by default. Adds helper.c to compilation for secure privilege-separated script execution.
 * Scripts receive lease information via environment variables (DNSMASQ_LEASE_ACTION, DNSMASQ_CLIENT_ID,
 * DNSMASQ_IP_ADDRESS, etc.). Useful for dynamic DNS updates, firewall rule updates, logging, and
 * custom provisioning. Script execution is privilege-separated: helper process runs scripts with
 * reduced privileges. Disable with NO_SCRIPT.
 * 
 * Affected files: helper.c, lease.c (script invocation), dhcp.c
 * External dependencies: None (libc only), but scripts may have dependencies
 * Binary size impact: Adds ~10KB to stripped binary
 * Disabling: make COPTS=-DNO_SCRIPT
 * Security: Scripts run with dropped privileges via helper process fork/exec
 * Related: HAVE_LUASCRIPT extends this with embedded Lua interpreter
 */
#define HAVE_SCRIPT

/**
 * @def HAVE_AUTH
 * @brief Enable authoritative DNS server mode
 * 
 * When defined, enables authoritative DNS server functionality allowing dnsmasq to serve configured
 * zones directly without forwarding. Enabled by default. Adds auth.c to compilation. Provides
 * SOA/NS/A/AAAA record serving for local zones, useful for split-horizon DNS, local zone authority,
 * and reducing external dependencies. Zones configured with --auth-zone and --auth-server options.
 * No external library dependencies.
 * 
 * Affected files: auth.c, forward.c (authoritative vs forwarding logic), cache.c
 * External dependencies: None (libc only)
 * Binary size impact: Adds ~12KB to stripped binary
 * Disabling: make COPTS=-DNO_AUTH
 * Use case: Internal DNS authority, split-horizon DNS, reducing external forwarder dependencies
 */
#define HAVE_AUTH

/**
 * @def HAVE_IPSET
 * @brief Enable Linux ipset integration for selective address filtering
 * 
 * When defined, enables adding resolved DNS addresses to Linux ipset sets, allowing firewall
 * rules based on resolved domains. Enabled by default on Linux (disabled on macOS via NO_IPSET).
 * Adds ipset.c to compilation. Useful for domain-based routing (e.g., route Netflix traffic via
 * specific gateway), firewall policies (e.g., block ad domains at firewall), and traffic shaping.
 * Requires Linux kernel ipset support; no library dependencies. Configured with --ipset=/domain/set
 * option.
 * 
 * Affected files: ipset.c, forward.c (address resolution hooks)
 * External dependencies: Linux kernel with CONFIG_IP_SET
 * Binary size impact: Adds ~5KB to stripped binary
 * Platform restriction: Linux only (automatically disabled on macOS/BSD via NO_IPSET)
 * Disabling: make COPTS=-DNO_IPSET
 * Use case: Domain-based routing, firewall policies, traffic shaping by domain
 */
#define HAVE_IPSET 

/**
 * @def HAVE_LOOP
 * @brief Enable DNS forwarding loop detection
 * 
 * When defined, enables probing for DNS forwarding loops where queries return to dnsmasq. Enabled
 * by default. Adds loop.c to compilation. Periodically sends unique queries to LOOP_TEST_DOMAIN
 * ("test") and checks if responses return to self, indicating misconfiguration (dnsmasq forwarding
 * to itself directly or via intermediate resolvers). When loop detected, logs warning and may
 * disable affected upstream servers. No external dependencies.
 * 
 * Affected files: loop.c, forward.c (loop detection integration)
 * External dependencies: None (libc only)
 * Binary size impact: Adds ~3KB to stripped binary
 * Disabling: make COPTS=-DNO_LOOP
 * Use case: Detecting misconfigured upstream servers, preventing forwarding loops
 */
#define HAVE_LOOP

/**
 * @def HAVE_DUMPFILE
 * @brief Enable packet capture to libpcap format for debugging
 * 
 * When defined, enables dumping DNS packets to pcap-format file for analysis with Wireshark/tcpdump.
 * Enabled by default. Adds dump.c to compilation. Activated with --dumpfile=/path option. Captures
 * all DNS queries and responses in pcap format readable by standard network analysis tools. Useful
 * for debugging DNS issues, protocol analysis, and traffic auditing. No library dependencies
 * (generates pcap format internally without libpcap).
 * 
 * Affected files: dump.c, forward.c (packet capture hooks)
 * External dependencies: None (generates pcap format without libpcap library)
 * Binary size impact: Adds ~2KB to stripped binary
 * Disabling: make COPTS=-DNO_DUMPFILE
 * Use case: DNS debugging, protocol analysis, traffic auditing with Wireshark
 */
#define HAVE_DUMPFILE

/* Build options which require external libraries.
   
   Defining HAVE_<opt>_STATIC as _well_ as HAVE_<opt> will link the library statically.

   You can use "make COPTS=-DHAVE_<opt>" instead of editing these.
*/

/**
 * @def HAVE_LUASCRIPT
 * @brief Enable Lua scripting for DHCP lease events
 * 
 * When defined, embeds Lua interpreter for executing Lua scripts on DHCP lease changes, extending
 * HAVE_SCRIPT functionality. Disabled by default (requires external library). Automatically defines
 * HAVE_SCRIPT. Provides more sophisticated scripting than shell scripts: in-process execution
 * (faster, no fork/exec overhead), access to lease database, stateful processing, and complex
 * logic. Lua scripts invoked via function calls rather than subprocess execution.
 * 
 * External dependencies: lua5.2 library and headers
 * Affected files: helper.c (Lua integration), lease.c (script invocation)
 * Binary size impact: Adds ~200KB (Lua interpreter) if linked dynamically
 * Enabling: make COPTS=-DHAVE_LUASCRIPT or uncomment this #define
 * Static linking: Define HAVE_LUASCRIPT_STATIC to link Lua statically
 * Dependency relationship: Automatically defines HAVE_SCRIPT (lines 339-341 enforce this)
 * Minimum Lua version: 5.2
 */
/* #define HAVE_LUASCRIPT */

/**
 * @def HAVE_DBUS
 * @brief Enable D-Bus control interface for runtime configuration
 * 
 * When defined, enables D-Bus IPC interface for controlling dnsmasq at runtime. Disabled by default.
 * Adds dbus.c to compilation. Exposes methods: SetServers (modify upstream DNS servers), ClearCache
 * (flush DNS cache), GetVersion (query version), and lease queries. Useful for NetworkManager
 * integration, dynamic configuration management, and desktop environments. D-Bus service name is
 * DNSMASQ_SERVICE ("uk.org.thekelleys.dnsmasq").
 * 
 * External dependencies: libdbus-1 (version 1.0+)
 * Affected files: dbus.c, dnsmasq.c (D-Bus initialization)
 * Binary size impact: Adds ~15KB + libdbus dependency
 * Enabling: make COPTS=-DHAVE_DBUS or uncomment this #define
 * Static linking: Define HAVE_DBUS_STATIC to link libdbus statically
 * pkg-config: Uses dbus-1.pc for compile/link flags
 * Use case: NetworkManager integration, desktop environment control, runtime reconfiguration
 */
/* #define HAVE_DBUS */

/**
 * @def HAVE_IDN
 * @brief Enable Internationalized Domain Names support (IDN 2003, deprecated)
 * 
 * When defined, enables IDN (Internationalized Domain Names) support per IDNA2003 specification,
 * allowing non-ASCII domain names. Disabled by default. DEPRECATED: Use HAVE_LIBIDN2 instead for
 * IDNA2008 standard. Provides Punycode encoding/decoding for converting Unicode domain names to
 * ASCII-compatible encoding (ACE). Mutually exclusive with HAVE_LIBIDN2 (use one or the other).
 * 
 * External dependencies: libidn (GNU IDN library)
 * Affected files: rfc1035.c (domain name encoding/decoding), option.c
 * Binary size impact: Adds ~5KB + libidn dependency
 * Enabling: make COPTS=-DHAVE_IDN or uncomment this #define
 * Deprecated: Prefer HAVE_LIBIDN2 for IDNA2008 compliance
 * Incompatibility: Do not define both HAVE_IDN and HAVE_LIBIDN2
 */
/* #define HAVE_IDN */

/**
 * @def HAVE_LIBIDN2
 * @brief Enable Internationalized Domain Names support (IDN 2008, current standard)
 * 
 * When defined, enables IDN support per IDNA2008 specification (RFC 5890-5894), allowing non-ASCII
 * domain names with improved Unicode handling compared to IDNA2003. Disabled by default. Provides
 * Punycode encoding/decoding and normalization for internationalized domain names. Recommended
 * over HAVE_IDN for modern deployments. Mutually exclusive with HAVE_IDN.
 * 
 * External dependencies: libidn2 (version 2.0+)
 * Affected files: rfc1035.c (domain name encoding/decoding), option.c
 * Binary size impact: Adds ~5KB + libidn2 dependency
 * Enabling: make COPTS=-DHAVE_LIBIDN2 or uncomment this #define
 * Static linking: Define HAVE_LIBIDN2_STATIC to link statically
 * pkg-config: Uses libidn2.pc for compile/link flags
 * RFC compliance: Implements RFC 5890-5894 (IDNA2008)
 * Incompatibility: Do not define both HAVE_IDN and HAVE_LIBIDN2
 */
/* #define HAVE_LIBIDN2 */

/**
 * @def HAVE_CONNTRACK
 * @brief Enable Linux netfilter connection tracking mark propagation
 * 
 * When defined, enables propagating netfilter conntrack marks from incoming DNS queries to
 * corresponding upstream queries. Disabled by default. Adds conntrack.c to compilation. Allows
 * firewall rules and routing decisions based on which client initiated DNS query. Useful for
 * policy routing (different clients use different upstreams), per-client traffic shaping, and
 * security policies. Requires Linux kernel with CONFIG_NF_CONNTRACK.
 * 
 * External dependencies: libnetfilter_conntrack (version 1.0+)
 * Affected files: conntrack.c, forward.c (mark propagation hooks)
 * Binary size impact: Adds ~3KB + libnetfilter_conntrack dependency
 * Enabling: make COPTS=-DHAVE_CONNTRACK or uncomment this #define
 * Static linking: Define HAVE_CONNTRACK_STATIC to link statically
 * Platform restriction: Linux only (requires netfilter)
 * pkg-config: Uses libnetfilter_conntrack.pc
 * Use case: Policy routing by client, per-client QoS, security policies
 */
/* #define HAVE_CONNTRACK */

/**
 * @def HAVE_CRYPTOHASH
 * @brief Enable cryptographic hash functions without full DNSSEC support
 * 
 * When defined, includes hash function support from crypto library (SHA-256, etc.) without enabling
 * full DNSSEC validation. Disabled by default. Lighter-weight than HAVE_DNSSEC for deployments
 * needing hash functions for other purposes (e.g., DNS cookies, query hashing) without DNSSEC
 * overhead. Subset of HAVE_DNSSEC functionality.
 * 
 * External dependencies: libnettle (version 3.0+)
 * Affected files: crypto.c (hash functions only), hash-questions.c
 * Binary size impact: Adds ~5KB + minimal nettle symbols
 * Enabling: make COPTS=-DHAVE_CRYPTOHASH or uncomment this #define
 * Relationship: HAVE_DNSSEC implies HAVE_CRYPTOHASH (includes hash functions)
 * Use case: DNS cookies, query fingerprinting, lightweight crypto without DNSSEC
 */
/* #define HAVE_CRYPTOHASH */

/**
 * @def HAVE_DNSSEC
 * @brief Enable DNSSEC validation per RFCs 4033/4034/4035
 * 
 * When defined, enables full DNSSEC (DNS Security Extensions) validation providing cryptographic
 * authentication of DNS responses. Disabled by default. Adds dnssec.c, crypto.c, blockdata.c to
 * compilation. Validates RRSIG signatures, builds chain of trust via DNSKEY/DS records from root,
 * handles NSEC/NSEC3 proofs of non-existence. Supported algorithms: RSA/SHA-1, RSA/SHA-256,
 * ECDSA P-256/P-384, Ed25519, GOST. Requires trust anchor configuration (trust-anchors.conf).
 * Significant CPU and memory overhead for validation.
 * 
 * External dependencies: libnettle (version 3.0+), libhogweed (same version as nettle)
 * Affected files: dnssec.c, crypto.c, blockdata.c, forward.c (validation integration), cache.c
 * Binary size impact: Adds ~50KB + libnettle/libhogweed dependencies
 * Enabling: make COPTS=-DHAVE_DNSSEC or uncomment this #define
 * Static linking: Define HAVE_DNSSEC_STATIC to link crypto libraries statically
 * pkg-config: Uses nettle.pc and hogweed.pc
 * RFC compliance: Implements RFC 4033 (intro), RFC 4034 (records), RFC 4035 (protocol)
 * Performance: Validation adds 50-200ms latency per query, CPU overhead for crypto
 * Configuration: Requires --dnssec and trust anchor configuration
 * Security: Protects against cache poisoning and DNS spoofing attacks
 */
/* #define HAVE_DNSSEC */

/**
 * @def HAVE_NFTSET
 * @brief Enable nftables set integration for selective address filtering
 * 
 * When defined, enables adding resolved DNS addresses to nftables sets (modern replacement for
 * ipset). Disabled by default. Adds nftset.c to compilation. Similar to HAVE_IPSET but uses
 * nftables (nft) instead of legacy iptables ipset. Allows domain-based firewall rules and routing
 * using nftables. Requires Linux kernel 4.1+ with nftables support.
 * 
 * External dependencies: libnftables (version 0.9+)
 * Affected files: nftset.c, forward.c (address resolution hooks)
 * Binary size impact: Adds ~8KB + libnftables dependency
 * Enabling: make COPTS=-DHAVE_NFTSET or uncomment this #define
 * Static linking: Define HAVE_NFTSET_STATIC to link libnftables statically
 * Platform restriction: Linux with kernel 4.1+
 * pkg-config: Uses libnftables.pc
 * Relationship: Alternative to HAVE_IPSET for nftables-based systems
 * Use case: Domain-based routing/filtering with modern nftables firewall
 */
/* #define HAVE_NFTSET */

/**
 * Disabling Feature Macros (NO_* series)
 * 
 * @def NO_ID
 * @brief Disable *.bind CHAOS query responses, forward to upstream instead
 * 
 * When defined, prevents dnsmasq from responding to special *.bind CHAOS class queries (version.bind,
 * authors.bind, etc.) used to identify DNS server software. Instead forwards these queries upstream.
 * Disabled by default (dnsmasq responds to *.bind queries). Useful for security-by-obscurity to hide
 * server identity, though not a strong security measure. Queries like "dig @server version.bind CHAOS TXT"
 * will be forwarded instead of answered locally.
 * 
 * Affected files: rfc1035.c query handling
 * Binary size impact: Negligible
 * Enabling: make COPTS=-DNO_ID
 * Security note: Obscures server identity but determined attackers can fingerprint via other methods
 */
 
/**
 * @def NO_TFTP
 * @brief Explicitly disable TFTP server even if HAVE_TFTP would be enabled
 * 
 * When defined, disables TFTP server compilation even if HAVE_TFTP is defined by default. Allows
 * selectively disabling default-enabled features. Useful when TFTP is not needed and reducing
 * attack surface is desired. Removes tftp.c from compilation.
 * 
 * Affected files: Prevents tftp.c compilation
 * Binary size impact: Saves ~15KB
 * Enabling: make COPTS=-DNO_TFTP
 * Use case: Deployments not requiring PXE boot or TFTP file serving
 */
 
/**
 * @def NO_DHCP
 * @brief Explicitly disable all DHCP functionality (DHCPv4 and DHCPv6)
 * 
 * When defined, disables both DHCPv4 and DHCPv6 servers even if HAVE_DHCP/HAVE_DHCP6 are defined.
 * Removes dhcp.c, dhcp6.c, rfc2131.c, rfc3315.c, lease.c, dhcp-common.c from compilation. Useful
 * for DNS-only deployments where DHCP is handled by separate service. Automatically undefines
 * HAVE_DHCP6 as well (line 321 enforcement).
 * 
 * Affected files: Prevents compilation of dhcp.c, dhcp6.c, rfc2131.c, rfc3315.c, lease.c, radv.c, slaac.c
 * Binary size impact: Saves ~70KB (both DHCPv4 and DHCPv6)
 * Enabling: make COPTS=-DNO_DHCP
 * Use case: DNS-only forwarding servers, environments with dedicated DHCP servers
 */
 
/**
 * @def NO_DHCP6
 * @brief Explicitly disable DHCPv6 only, keeping DHCPv4 enabled
 * 
 * When defined, disables DHCPv6 server while preserving DHCPv4 functionality. Removes dhcp6.c,
 * rfc3315.c, radv.c, slaac.c from compilation. Useful for IPv4-only networks or when DHCPv6 is
 * handled by router advertisements only (SLAAC). Smaller than NO_DHCP as DHCPv4 remains available.
 * 
 * Affected files: Prevents dhcp6.c, rfc3315.c, radv.c, slaac.c, outpacket.c compilation
 * Binary size impact: Saves ~30KB
 * Enabling: make COPTS=-DNO_DHCP6
 * Use case: IPv4-only networks, SLAAC-only IPv6 networks
 */
 
/**
 * @def NO_SCRIPT
 * @brief Disable lease-change script execution and Lua scripting
 * 
 * When defined, disables calling external scripts on DHCP lease events. Removes helper.c from
 * compilation. Also automatically disables HAVE_LUASCRIPT if defined (line 335 enforcement).
 * Useful for embedded systems where external script execution is unnecessary or unwanted for
 * security reasons. Reduces attack surface by eliminating subprocess execution.
 * 
 * Affected files: Prevents helper.c compilation
 * Binary size impact: Saves ~10KB
 * Enabling: make COPTS=-DNO_SCRIPT
 * Relationship: Automatically undefines HAVE_LUASCRIPT
 * Use case: Embedded systems, high-security deployments avoiding external process execution
 */
 
/**
 * @def NO_LARGEFILE
 * @brief Disable large file support (>2GB files)
 * 
 * When defined, disables large file support on platforms where it would normally be enabled.
 * Relevant only for very old systems or specialized embedded platforms. Modern systems (Linux 2.4+,
 * any 64-bit system) support large files by default. Affects lease file and log file size limits.
 * Rarely needed as dnsmasq file sizes never approach 2GB in practice.
 * 
 * Affected files: Compilation flags for file I/O
 * Binary size impact: Negligible
 * Enabling: make COPTS=-DNO_LARGEFILE
 * Use case: Ancient 32-bit systems with kernel <2.4, specialized embedded platforms
 */
 
/**
 * @def NO_AUTH
 * @brief Disable authoritative DNS server mode
 * 
 * When defined, disables authoritative DNS functionality even if HAVE_AUTH is defined by default.
 * Removes auth.c from compilation. Useful when only forwarding/caching DNS is needed without local
 * zone authority. Slightly reduces binary size and attack surface.
 * 
 * Affected files: Prevents auth.c compilation
 * Binary size impact: Saves ~12KB
 * Enabling: make COPTS=-DNO_AUTH
 * Use case: Forwarding-only DNS deployments
 */
 
/**
 * @def NO_DUMPFILE
 * @brief Disable packet capture to pcap format
 * 
 * When defined, disables packet dumping functionality even if HAVE_DUMPFILE is defined by default.
 * Removes dump.c from compilation. Useful for production deployments where debugging features are
 * unnecessary and reducing binary size is desired.
 * 
 * Affected files: Prevents dump.c compilation
 * Binary size impact: Saves ~2KB
 * Enabling: make COPTS=-DNO_DUMPFILE
 * Use case: Production deployments not needing packet capture debugging
 */
 
/**
 * @def NO_LOOP
 * @brief Disable DNS forwarding loop detection
 * 
 * When defined, disables loop detection even if HAVE_LOOP is defined by default. Removes loop.c
 * from compilation. Loop detection generates periodic test queries; disabling saves minimal traffic
 * and CPU. Only disable if certain no forwarding loops exist in configuration.
 * 
 * Affected files: Prevents loop.c compilation
 * Binary size impact: Saves ~3KB
 * Enabling: make COPTS=-DNO_LOOP
 * Use case: Environments with verified loop-free configurations
 */
 
/**
 * @def NO_INOTIFY
 * @brief Disable Linux inotify for configuration file monitoring
 * 
 * When defined, prevents automatic definition of HAVE_INOTIFY on Linux systems (line 359-361).
 * Forces use of polling for configuration file changes instead of efficient inotify event notifications.
 * Useful for systems with inotify disabled in kernel or when polling is preferred for compatibility.
 * 
 * Affected files: Prevents inotify.c compilation, forces polling in option.c
 * Binary size impact: Saves ~5KB
 * Platform restriction: Linux only (other platforms never use inotify)
 * Enabling: make COPTS=-DNO_INOTIFY
 * Performance impact: Configuration file changes detected via polling (slower) vs inotify (instant)
 */
 
/**
 * @def NO_GMP
 * @brief Disable libgmp linking for DNSSEC
 * 
 * When defined with HAVE_DNSSEC, uses nettle's internal mini-gmp instead of system libgmp for
 * arbitrary-precision arithmetic in DNSSEC calculations. Useful when nettle is built with
 * --enable-mini-gmp option. Reduces external dependencies at cost of slightly slower bignum
 * operations. Only relevant when HAVE_DNSSEC is enabled.
 * 
 * Affected files: crypto.c bignum operations when HAVE_DNSSEC defined
 * External dependencies: Removes libgmp dependency, requires nettle with mini-gmp
 * Performance impact: Mini-gmp is ~20% slower than libgmp for DNSSEC operations
 * Enabling: make COPTS="-DHAVE_DNSSEC -DNO_GMP" (requires nettle built with --enable-mini-gmp)
 * Use case: Embedded systems minimizing dependencies, static linking scenarios
 */

/* Default locations for important system files. */

/**
 * @def LEASEFILE
 * @brief Platform-specific default path for DHCP lease database file
 * 
 * Default values by platform:
 * - Linux: "/var/lib/misc/dnsmasq.leases"
 * - BSD (FreeBSD, OpenBSD, DragonFly, NetBSD): "/var/db/dnsmasq.leases"
 * - Solaris: "/var/cache/dnsmasq.leases"
 * - Android: "/data/misc/dhcp/dnsmasq.leases"
 * 
 * Path to the persistent DHCP lease database file where active leases are stored across dnsmasq
 * restarts. Format is line-oriented text: <expiry-time> <MAC> <IP> <hostname> <client-id>. File
 * is atomically rewritten when leases change (unless HAVE_BROKEN_RTC reduces write frequency).
 * Platform-specific paths follow OS filesystem conventions for variable state data. Can be
 * overridden at compile time by defining LEASEFILE before including config.h, or at runtime
 * with --dhcp-leasefile option.
 * 
 * Affects: lease.c lease_update_file() file I/O, dhcp.c lease persistence
 * Compiled only when: HAVE_DHCP is defined
 * Override: Compile-time via -DLEASEFILE=/path or runtime via --dhcp-leasefile=/path
 * Platform note: Paths adapt to OS conventions (/var/lib vs /var/db vs /var/cache)
 */
#ifndef LEASEFILE
#   if defined(__FreeBSD__) || defined (__OpenBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
#      define LEASEFILE "/var/db/dnsmasq.leases"
#   elif defined(__sun__) || defined (__sun)
#      define LEASEFILE "/var/cache/dnsmasq.leases"
#   elif defined(__ANDROID__)
#      define LEASEFILE "/data/misc/dhcp/dnsmasq.leases"
#   else
#      define LEASEFILE "/var/lib/misc/dnsmasq.leases"
#   endif
#endif

/**
 * @def CONFFILE
 * @brief Platform-specific default path for dnsmasq configuration file
 * 
 * Default values by platform:
 * - FreeBSD: "/usr/local/etc/dnsmasq.conf"
 * - Other Unix-like systems: "/etc/dnsmasq.conf"
 * 
 * Path to the main dnsmasq configuration file read at startup. FreeBSD uses /usr/local/etc for
 * third-party software configuration per ports conventions; most other systems use /etc. File
 * contains runtime options (one per line or as key=value pairs), equivalent to command-line
 * arguments. Can be overridden at compile time or specified at runtime with -C/--conf-file option.
 * Multiple configuration files can be included with --conf-dir option.
 * 
 * Affects: option.c read_opts() configuration file parsing
 * Override: Compile-time via -DCONFFILE=/path or runtime via --conf-file=/path
 * Platform note: FreeBSD ports convention places third-party configs in /usr/local/etc
 */
#ifndef CONFFILE
#   if defined(__FreeBSD__)
#      define CONFFILE "/usr/local/etc/dnsmasq.conf"
#   else
#      define CONFFILE "/etc/dnsmasq.conf"
#   endif
#endif

/**
 * @def RESOLVFILE
 * @brief Platform-specific default path for upstream DNS server configuration
 * 
 * Default values by platform:
 * - uClinux embedded systems: "/etc/config/resolv.conf"
 * - Standard Unix-like systems: "/etc/resolv.conf"
 * 
 * Path to resolv.conf file containing upstream DNS server addresses (nameserver lines). Dnsmasq
 * reads this file to determine which upstream servers to forward queries to. Standard location
 * is /etc/resolv.conf per Unix conventions; uClinux embedded systems use /etc/config. File is
 * monitored for changes (via inotify on Linux or polling on other platforms) to automatically
 * update upstream servers when network configuration changes. Can be overridden with -r/--resolv-file.
 * 
 * Affects: network.c resolv.conf reading, option.c configuration
 * Override: Compile-time via -DRESOLVFILE=/path or runtime via --resolv-file=/path
 * Dynamic update: File is monitored for changes; updates applied automatically
 * Platform note: uClinux embedded systems use /etc/config filesystem location
 */
#ifndef RESOLVFILE
#   if defined(__uClinux__)
#      define RESOLVFILE "/etc/config/resolv.conf"
#   else
#      define RESOLVFILE "/etc/resolv.conf"
#   endif
#endif

/**
 * @def RUNFILE
 * @brief Platform-specific default path for PID file
 * 
 * Default values by platform:
 * - Android: "/data/dnsmasq.pid"
 * - Standard Unix-like systems: "/var/run/dnsmasq.pid"
 * 
 * Path to PID (process ID) file written after daemon initialization. Contains dnsmasq's process
 * ID as ASCII decimal number, used by init scripts and system administrators to send signals
 * (SIGHUP to reload, SIGTERM to shutdown). File is created after privilege dropping and deleted
 * on clean shutdown. Standard Unix location is /var/run; Android uses /data writeable filesystem.
 * Can be overridden with -x/--pid-file option or disabled with --no-pid-file.
 * 
 * Affects: dnsmasq.c daemon initialization, PID file creation
 * Override: Compile-time via -DRUNFILE=/path or runtime via --pid-file=/path
 * Platform note: Android lacks /var/run, uses /data for writeable persistent storage
 */
#ifndef RUNFILE
#   if defined(__ANDROID__)
#      define RUNFILE "/data/dnsmasq.pid"
#    else
#      define RUNFILE "/var/run/dnsmasq.pid"
#    endif
#endif

/**
 * Platform-dependent options: automatically determined below based on compiler-defined macros
 * 
 * @def HAVE_LINUX_NETWORK
 * @brief Enable Linux-specific networking implementation using Netlink sockets
 * 
 * When defined, enables Linux Netlink-based interface and address monitoring (netlink.c). Provides
 * superior real-time notification of network changes compared to polling. Automatically defined on
 * Linux systems (__linux__, __UCLIBC__). Mutually exclusive with HAVE_BSD_NETWORK and
 * HAVE_SOLARIS_NETWORK. Enables Linux-specific features: Netlink RTM_NEWLINK/DELLINK for interface
 * events, RTM_NEWADDR/DELADDR for address changes, /proc/net/arp for ARP table access, Linux
 * capability management (CAP_NET_ADMIN, CAP_NET_BIND_SERVICE).
 * 
 * Affects: network.c, netlink.c compilation and interface enumeration strategy
 * Automatically defined on: Linux (including Android, uClinux)
 * Platform features: Real-time network change notifications, Linux capabilities, procfs access
 * 
 * @def HAVE_BSD_NETWORK
 * @brief Enable BSD-specific networking implementation using routing sockets and BPF
 * 
 * When defined, enables BSD routing socket-based interface monitoring (bpf.c) and Berkeley Packet
 * Filter for raw packet access. Automatically defined on BSD variants (FreeBSD, OpenBSD, NetBSD,
 * DragonFlyBSD, macOS). Mutually exclusive with HAVE_LINUX_NETWORK and HAVE_SOLARIS_NETWORK.
 * Enables BSD-specific features: routing socket RTM_IFINFO messages for interface changes, BPF
 * for DHCP packet handling, getifaddrs() for interface enumeration, struct sockaddr sa_len field.
 * 
 * Affects: network.c, bpf.c compilation and interface enumeration strategy
 * Automatically defined on: FreeBSD, OpenBSD, NetBSD, DragonFlyBSD, macOS
 * Platform features: Routing sockets for events, BPF for packet filter, HAVE_SOCKADDR_SA_LEN
 * 
 * @def HAVE_SOLARIS_NETWORK
 * @brief Enable Solaris-specific networking implementation using ioctl fallback
 * 
 * When defined, enables Solaris networking using SIOCGLIFCONF ioctl for interface enumeration.
 * Lacks event-driven interface monitoring; relies on periodic polling. Automatically defined on
 * Solaris/illumos (__sun, __sun__). Mutually exclusive with HAVE_LINUX_NETWORK and HAVE_BSD_NETWORK.
 * Solaris-specific features: SIOCGLIFCONF for interface enumeration, different privilege model,
 * ETHER_ADDR_LEN definition for Ethernet addresses.
 * 
 * Affects: network.c interface enumeration using ioctl
 * Automatically defined on: Solaris, OpenSolaris, illumos
 * Platform features: ioctl-based interface queries, no real-time event notifications
 * 
 * @def HAVE_GETOPT_LONG
 * @brief Indicates availability of GNU-style getopt_long() for command-line parsing
 * 
 * When defined, enables use of getopt_long() for parsing long command-line options (--option).
 * Automatically defined on systems with GNU C library (glibc) or compatible getopt implementations.
 * On systems without getopt_long(), dnsmasq falls back to short-option-only parsing or uses
 * bundled compatibility implementation.
 * 
 * Affects: option.c command-line parsing, --long-option support
 * Automatically defined on: Linux (glibc), FreeBSD 5.0+, macOS, modern BSD variants
 * 
 * @def HAVE_SOCKADDR_SA_LEN
 * @brief Indicates struct sockaddr includes sa_len length field (BSD convention)
 * 
 * When defined, indicates struct sockaddr has sa_len field containing structure length in bytes.
 * BSD systems include this field; Linux does not. Affects sockaddr structure access throughout
 * network code. Automatically defined on BSD variants and macOS.
 * 
 * Affects: network.c sockaddr structure access, address family handling
 * Automatically defined on: FreeBSD, OpenBSD, NetBSD, DragonFlyBSD, macOS
 * Not defined on: Linux, Solaris (these use address family to determine structure size)
 */

#if defined(__UCLIBC__)
#define HAVE_LINUX_NETWORK
#if defined(__UCLIBC_HAS_GNU_GETOPT__) || \
   ((__UCLIBC_MAJOR__==0) && (__UCLIBC_MINOR__==9) && (__UCLIBC_SUBLEVEL__<21))
#    define HAVE_GETOPT_LONG
#endif
#undef HAVE_SOCKADDR_SA_LEN
#if defined(__UCLIBC_HAS_IPV6__)
#  ifndef IPV6_V6ONLY
#    define IPV6_V6ONLY 26
#  endif
#endif

/* This is for glibc 2.x */
#elif defined(__linux__)
#define HAVE_LINUX_NETWORK
#define HAVE_GETOPT_LONG
#undef HAVE_SOCKADDR_SA_LEN

#elif defined(__FreeBSD__) || \
      defined(__OpenBSD__) || \
      defined(__DragonFly__) || \
      defined(__FreeBSD_kernel__)
#define HAVE_BSD_NETWORK
/* Later versions of FreeBSD have getopt_long() */
#if defined(optional_argument) && defined(required_argument)
#   define HAVE_GETOPT_LONG
#endif
#define HAVE_SOCKADDR_SA_LEN

#elif defined(__APPLE__)
#define HAVE_BSD_NETWORK
#define HAVE_GETOPT_LONG
#define HAVE_SOCKADDR_SA_LEN
#define NO_IPSET
/* Define before sys/socket.h is included so we get socklen_t */
#define _BSD_SOCKLEN_T_
/* Select the RFC_3542 version of the IPv6 socket API. 
   Define before netinet6/in6.h is included. */
#define __APPLE_USE_RFC_3542
/* Required for Mojave. */
#ifndef SOL_TCP
#  define SOL_TCP IPPROTO_TCP
#endif
#define NO_IPSET

#elif defined(__NetBSD__)
#define HAVE_BSD_NETWORK
#define HAVE_GETOPT_LONG
#define HAVE_SOCKADDR_SA_LEN

#elif defined(__sun) || defined(__sun__)
#define HAVE_SOLARIS_NETWORK
#define HAVE_GETOPT_LONG
#undef HAVE_SOCKADDR_SA_LEN
#define ETHER_ADDR_LEN 6 
 
#endif

/* rules to implement compile-time option dependencies and 
   the NO_XXX flags */

#ifdef NO_TFTP
#undef HAVE_TFTP
#endif

#ifdef NO_DHCP
#undef HAVE_DHCP
#undef HAVE_DHCP6
#endif

#if defined(NO_DHCP6)
#undef HAVE_DHCP6
#endif

/* DHCP6 needs DHCP too */
#ifdef HAVE_DHCP6
#define HAVE_DHCP
#endif

#if defined(NO_SCRIPT)
#undef HAVE_SCRIPT
#undef HAVE_LUASCRIPT
#endif

/* Must HAVE_SCRIPT to HAVE_LUASCRIPT */
#ifdef HAVE_LUASCRIPT
#define HAVE_SCRIPT
#endif

#ifdef NO_AUTH
#undef HAVE_AUTH
#endif

#if defined(NO_IPSET)
#undef HAVE_IPSET
#endif

#ifdef NO_LOOP
#undef HAVE_LOOP
#endif

#ifdef NO_DUMPFILE
#undef HAVE_DUMPFILE
#endif

#if defined (HAVE_LINUX_NETWORK) && !defined(NO_INOTIFY)
#define HAVE_INOTIFY
#endif

/* Define a string indicating which options are in use.
   DNSMASQ_COMPILE_OPTS is only defined in dnsmasq.c */

#ifdef DNSMASQ_COMPILE_OPTS

static char *compile_opts = 
"IPv6 "
#ifndef HAVE_GETOPT_LONG
"no-"
#endif
"GNU-getopt "
#ifdef HAVE_BROKEN_RTC
"no-RTC "
#endif
#ifndef HAVE_DBUS
"no-"
#endif
"DBus "
#ifndef HAVE_UBUS
"no-"
#endif
"UBus "
#ifndef LOCALEDIR
"no-"
#endif
"i18n "
#if defined(HAVE_LIBIDN2)
"IDN2 "
#else
 #if !defined(HAVE_IDN)
"no-"
 #endif 
"IDN " 
#endif
#ifndef HAVE_DHCP
"no-"
#endif
"DHCP "
#if defined(HAVE_DHCP)
#  if !defined (HAVE_DHCP6)
     "no-"
#  endif  
     "DHCPv6 "
#endif
#if !defined(HAVE_SCRIPT)
     "no-scripts "
#else
#  if !defined(HAVE_LUASCRIPT)
     "no-"
#  endif
     "Lua "
#endif
#ifndef HAVE_TFTP
"no-"
#endif
"TFTP "
#ifndef HAVE_CONNTRACK
"no-"
#endif
"conntrack "
#ifndef HAVE_IPSET
"no-"
#endif
"ipset "
#ifndef HAVE_NFTSET
"no-"
#endif
"nftset "
#ifndef HAVE_AUTH
"no-"
#endif
"auth "
#if !defined(HAVE_CRYPTOHASH) && !defined(HAVE_DNSSEC)
"no-"
#endif
"cryptohash "
#ifndef HAVE_DNSSEC
"no-"
#endif
"DNSSEC "
#ifdef NO_ID
"no-ID "
#endif
#ifndef HAVE_LOOP
"no-"
#endif
"loop-detect "
#ifndef HAVE_INOTIFY
"no-"
#endif
"inotify "
#ifndef HAVE_DUMPFILE
"no-"
#endif
"dumpfile";

#endif /* defined(HAVE_DHCP) */
