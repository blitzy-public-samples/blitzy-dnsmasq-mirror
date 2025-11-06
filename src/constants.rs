// Copyright (c) 2000-2022 Simon Kelley
// Copyright (c) 2024 Blitzy Platform (Rust translation)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

//! Compile-time constants module
//!
//! This module defines all resource limits, buffer sizes, default values, and timeout durations
//! translated from C's config.h macros. It provides centralized configuration values used across
//! all dnsmasq subsystems, replacing C preprocessor #define directives with type-safe Rust const
//! declarations.
//!
//! # Overview
//!
//! Constants are organized into functional categories:
//! - **DNS Configuration**: Cache sizes, packet limits, domain name limits
//! - **DHCP Configuration**: Lease limits, timeout values, ping settings
//! - **Process Limits**: TCP child processes, connection limits
//! - **Network Buffers**: Packet buffer sizes, TFTP block sizes
//! - **Timeout Values**: Query timeouts, retry intervals
//! - **File Paths**: Platform-specific default paths for config, lease, and PID files
//! - **Protocol Constants**: DHCP cookies, BOOTP message types, DNS record sizes
//!
//! # C Source Reference
//!
//! Translated from: `src/config.h` (lines 1-1921)
//!
//! Each constant includes documentation referencing:
//! - Original C macro name and value
//! - Purpose and impact on system behavior
//! - Tuning guidance for different deployment sizes
//! - Whether the value can be overridden at runtime via configuration options
//!
//! # Platform-Specific Constants
//!
//! File path constants vary by target operating system using Rust's `cfg` attributes:
//! - Linux: `/var/lib/misc/dnsmasq.leases`, `/etc/dnsmasq.conf`
//! - BSD (FreeBSD, OpenBSD, DragonFly, NetBSD): `/var/db/dnsmasq.leases`, `/usr/local/etc/dnsmasq.conf` (FreeBSD only)
//! - Solaris: `/var/cache/dnsmasq.leases`
//! - Android: `/data/misc/dhcp/dnsmasq.leases`, `/data/dnsmasq.pid`
//! - uClinux: `/etc/config/resolv.conf`

use std::time::Duration;

// =============================================================================
// DNS Configuration Constants
// =============================================================================

/// Maximum number of outstanding DNS forward requests (C: FTABSIZ)
///
/// Controls the size of the forward record (frec) pool, limiting concurrent upstream DNS queries.
/// Each outstanding query from a client that requires forwarding to an upstream server consumes
/// one forward record. When this limit is reached, additional queries are dropped until existing
/// queries complete.
///
/// **Memory Impact**: Each frec is approximately 128 bytes, so 150 records ≈ 19KB
///
/// **Tuning Guidance**:
/// - Residential/Small Business (default): 150
/// - High-traffic servers (>100 queries/second): 300-500
/// - Memory-constrained embedded: 50-100
///
/// **Runtime Override**: Cannot be overridden at runtime
///
/// **C Reference**: `config.h` line 116
pub const MAX_FORWARD_REQUESTS: usize = 150;

/// Default DNS cache size in number of records (C: CACHESIZ)
///
/// Defines the default size of the DNS cache, measured in number of cached resource records (RRs).
/// Each cached record (A, AAAA, CNAME, MX, etc.) occupies one cache slot. The cache uses an LRU
/// (Least Recently Used) eviction policy when full.
///
/// **Memory Impact**: Each cache record (struct crec) is ~128 bytes, so 150 records ≈ 19KB
///
/// **Tuning Guidance**:
/// - Residential (default): 150 (covers 50-100 unique domains)
/// - Small business: 500-1000
/// - Enterprise: 5000-10000
/// - Disable caching: 0
///
/// **Runtime Override**: Yes, via `--cache-size=<n>` option
///
/// **C Reference**: `config.h` line 423
pub const DEFAULT_CACHE_SIZE: usize = 150;

/// Default maximum EDNS0 UDP packet size advertised (C: EDNS_PKTSZ)
///
/// Specifies the UDP payload size advertised in EDNS0 OPT records per RFC 6891. This value
/// indicates the maximum DNS response size dnsmasq can receive without TCP fallback. 4096 bytes
/// is the RFC 6891 recommended value, balancing between allowing large DNSSEC responses and
/// avoiding IP fragmentation on typical Ethernet MTU (1500 bytes).
///
/// **RFC Compliance**: Matches RFC 6891 Section 6.2.5 recommended value
///
/// **Runtime Override**: Yes, via `--edns-packet-max=<size>` option
///
/// **Related**: See `SAFE_PKTSZ` for DNS Flag Day 2020 recommended minimum
///
/// **C Reference**: `config.h` line 213
pub const EDNS_PACKET_SIZE: usize = 4096;

/// Standard DNS UDP packet size without EDNS0 (C: PACKETSZ)
///
/// The maximum size of a DNS message when EDNS0 is not used, as defined by RFC 1035. This is the
/// traditional DNS/UDP payload size limit that all DNS implementations must support. Responses
/// exceeding this size require either EDNS0 (to advertise larger UDP buffer) or TCP fallback.
///
/// **RFC Compliance**: RFC 1035 Section 2.3.4 (512 byte UDP message limit)
///
/// **Historical Note**: This limit was established in 1987 to ensure reliable delivery over
/// diverse network conditions when IP fragmentation was less reliable.
///
/// **C Reference**: `config.h` line 214 (using PACKETSZ from arpa/nameser.h, typically 512)
pub const DNS_PACKET_SIZE: usize = 512;

/// Safe minimum EDNS0 packet size per DNS Flag Day 2020 (C: SAFE_PKTSZ)
///
/// The minimum EDNS0 UDP payload size recommended by DNS Flag Day 2020 (May 1, 2020) to ensure
/// DNSSEC responses and other large DNS responses can be delivered without fragmentation issues.
/// This value (1232 bytes) is chosen to fit within typical Ethernet MTU (1500 bytes) after
/// accounting for IPv4/IPv6 and UDP headers, avoiding IP fragmentation.
///
/// **Calculation**: 1500 (Ethernet MTU) - 40 (IPv6 header) - 8 (UDP header) - 20 (safety margin) = 1232
///
/// **RFC Compliance**: Aligns with RFC 8906 (DNS Flag Day 2020) recommendations
///
/// **C Reference**: `config.h` line 222
pub const SAFE_PKTSZ: usize = 1232;

/// Minimum DNS packet size to accept (C: MIN_PACKETSZ)
///
/// The absolute minimum size of a DNS query packet that dnsmasq will process. Packets smaller
/// than this are rejected as malformed. This prevents processing of incomplete DNS headers.
///
/// **DNS Header Size**: 12 bytes (fixed DNS header per RFC 1035)
///
/// **C Reference**: Derived from DNS protocol requirements (DNS header minimum)
pub const MIN_PACKETSZ: usize = 12;

/// Maximum domain name length including terminating zero (C: MAXDNAME)
///
/// The maximum length of a fully-qualified domain name (FQDN) in wire format, including all
/// labels, dots, and the terminating zero-length label. This value (1025 bytes) is derived from
/// RFC 1035's maximum DNS message size (512 bytes) and allows for worst-case name encoding with
/// maximum compression pointer depth.
///
/// **RFC Compliance**: RFC 1035 Section 2.3.4 (maximum label length 63, maximum name length 255)
///
/// **Wire Format**: 255 bytes for name + overhead for compression pointer handling
///
/// **Implementation Note**: The C code historically used 1024, but recent versions use 1025 to
/// accommodate the NULL terminator in string operations.
///
/// **C Reference**: `config.h` line 227
pub const MAX_DOMAIN_NAME: usize = 1025;

/// Maximum CNAME chain depth to follow (C: CNAME_CHAIN)
///
/// Limits the number of CNAME records followed when resolving a query to prevent infinite loops
/// and denial-of-service attacks. RFC 1034 does not specify a limit, but most implementations
/// use 8-16 as a reasonable balance between supporting legitimate CNAME chains and preventing abuse.
///
/// **Security**: Prevents CNAME loop attacks where malicious actors create circular CNAME records
///
/// **RFC Reference**: RFC 1034 Section 3.6.2 (CNAME processing)
///
/// **C Reference**: `config.h` line 573
pub const CNAME_CHAIN: usize = 16;

/// TTL floor minimum allowed value (C: TTL_FLOOR_LIMIT)
///
/// The maximum value that can be specified for the --min-cache-ttl option, which sets a minimum
/// TTL for cached records. This prevents administrators from setting excessively long minimum TTLs
/// that would cause dnsmasq to serve stale data for extended periods.
///
/// **Default Behavior**: No minimum TTL (honor upstream TTLs exactly)
///
/// **Security Note**: Setting high min-cache-ttl can delay propagation of DNS changes, including
/// security-related changes like revoking compromised certificates via DNS
///
/// **C Reference**: `config.h` line 436
pub const TTL_FLOOR_LIMIT: u32 = 86400; // 1 day in seconds

// =============================================================================
// DHCP Configuration Constants
// =============================================================================

/// Default maximum number of DHCP leases (C: MAXLEASES)
///
/// The maximum number of active DHCP leases supported simultaneously. This limit applies to the
/// lease database size and affects memory allocation for the lease table. Each lease record tracks
/// a MAC address, IP address, hostname, lease expiration time, and client identifier.
///
/// **Memory Impact**: Each lease (struct dhcp_lease) is ~256 bytes, so 1000 leases ≈ 250KB
///
/// **Tuning Guidance**:
/// - Home network: 50-100
/// - Small office (default): 1000
/// - Enterprise/ISP: 10000-100000 (requires recompilation)
///
/// **Runtime Override**: Yes, via `--dhcp-lease-max=<n>` option
///
/// **Related**: Must not exceed the size of the configured DHCP range
///
/// **C Reference**: `config.h` line 454
pub const MAX_DHCP_LEASES: usize = 1000;

/// Seconds to wait for ICMP echo reply before allocating address (C: PING_WAIT)
///
/// Before offering an IP address, dnsmasq sends an ICMP echo (ping) to the address to detect if
/// it's already in use by an unconfigured device. This value specifies the timeout in seconds
/// to wait for a ping response before considering the address available.
///
/// **Purpose**: Prevent IP address conflicts with statically configured devices not in lease database
///
/// **Tuning Guidance**:
/// - Fast networks: 1-2 seconds
/// - Default: 3 seconds
/// - Wireless/high-latency: 5 seconds
/// - Disable conflict detection: 0 seconds (not recommended)
///
/// **Runtime Override**: No (compile-time only)
///
/// **C Reference**: `config.h` line 469
pub const DHCP_PING_WAIT: u64 = 3;

/// Seconds to cache ping results for address conflict detection (C: PING_CACHE_TIME)
///
/// After successfully pinging an address, cache the result to avoid redundant pings for the same
/// address within this time window. This improves performance during DHCP discovery storms or
/// rapid client reconnections.
///
/// **C Reference**: `config.h` line 478
pub const PING_CACHE_TIME: u64 = 30;

/// Seconds before an address declined by a client can be reused (C: DECLINE_BACKOFF)
///
/// When a DHCP client sends a DHCPDECLINE message (indicating address conflict), dnsmasq marks
/// that address as unavailable for this duration. This prevents immediately re-offering the
/// problematic address to another client.
///
/// **RFC Compliance**: RFC 2131 Section 3.1.5 (DHCPDECLINE handling)
///
/// **C Reference**: `config.h` line 489
pub const DECLINE_BACKOFF: u64 = 600; // 10 minutes

/// Maximum DHCP packet size including IP and UDP headers (C: DHCP_PACKET_MAX)
///
/// The largest DHCP packet that dnsmasq will process, including IP and UDP headers. This covers
/// the maximum DHCP message size (576 bytes per RFC 2131) plus additional space for options.
///
/// **RFC Compliance**: RFC 2131 mandates support for 576-byte DHCP messages minimum
///
/// **C Reference**: `config.h` line 555 (IP_MAXPACKET value, typically 65535)
pub const DHCP_PACKET_MAX: usize = 65535;

/// Default DHCP lease time in seconds (C: DEFLEASE, DEFLEASE6)
///
/// The default lease duration when not explicitly configured via --dhcp-range option. After this
/// time expires, clients must renew (at T1) or rebind (at T2) to maintain their IP address
/// assignment.
///
/// **DHCPv4**: 1 hour (3600 seconds)
/// **DHCPv6**: 4 hours (14400 seconds) - longer due to DHCPv6 stateless autoconfiguration fallback
///
/// **RFC Compliance**: RFC 2131 Section 3.3 recommends lease times between 1 hour and 1 week
///
/// **Runtime Override**: Yes, via `--dhcp-range` option's lease time parameter
///
/// **C Reference**: `config.h` lines 617, 625
pub const DEFLEASE: LeaseTime = 3600; // 1 hour for DHCPv4
pub const DEFLEASE6: LeaseTime = 14400; // 4 hours for DHCPv6

/// Interval in seconds between lease database retry attempts (C: LEASE_RETRY)
///
/// When lease file writing fails (disk full, permission denied), dnsmasq retries after this interval.
/// This prevents tight retry loops while ensuring lease state is persisted reasonably quickly.
///
/// **C Reference**: `config.h` line 443
pub const LEASE_RETRY: u64 = 60;

/// Retry interval in seconds for lease file persistence (used in Rust conversion)
///
/// This constant provides the same value as LEASE_RETRY but with explicit naming for Rust code.
pub const LEASE_RETRY_INTERVAL_SECS: u64 = LEASE_RETRY;

/// Maximum hardware address length in DHCP packets (C: DHCP_CHADDR_MAX)
///
/// Size of the chaddr (client hardware address) field in DHCP packets per RFC 2131. This
/// accommodates Ethernet MAC addresses (6 bytes) with room for other link-layer address types.
///
/// **RFC Compliance**: RFC 2131 Section 2 (BOOTP message format, chaddr field is 16 bytes)
///
/// **C Reference**: `config.h` or DHCP protocol definition
pub const DHCP_CHADDR_MAX: usize = 16;

/// DHCP magic cookie value (C: DHCP_COOKIE or inline constant)
///
/// The 4-byte magic cookie that identifies the start of DHCP options in the BOOTP vendor extensions
/// area. This value (99.130.83.99 in decimal) is defined in RFC 2131 and RFC 1497.
///
/// **RFC Compliance**: RFC 2131 Section 3, RFC 1497 Section 3
///
/// **Wire Format**: 0x63825363 (big-endian: 99, 130, 83, 99)
pub const DHCP_COOKIE: u32 = 0x63825363;

/// BOOTP/DHCP request (client to server) message type (C: BOOTREQUEST)
///
/// Value for the 'op' field in DHCP/BOOTP messages sent from client to server.
///
/// **RFC Reference**: RFC 2131 Section 2 (BOOTP message format)
pub const BOOTREQUEST: u8 = 1;

/// BOOTP/DHCP reply (server to client) message type (C: BOOTREPLY)
///
/// Value for the 'op' field in DHCP/BOOTP messages sent from server to client.
///
/// **RFC Reference**: RFC 2131 Section 2 (BOOTP message format)
pub const BOOTREPLY: u8 = 2;

// =============================================================================
// Process Limits
// =============================================================================

/// Maximum number of concurrent TCP DNS child processes (C: MAX_PROCS)
///
/// dnsmasq forks a child process for each TCP DNS connection to handle the blocking I/O. This
/// limit prevents resource exhaustion from TCP connection flooding attacks. When the limit is
/// reached, new TCP connections are rejected until existing children terminate.
///
/// **Security**: Prevents fork-bomb DoS attacks via TCP DNS floods
///
/// **Memory Impact**: Each child process ~1-2MB (minimal, mostly shared text segment)
///
/// **Tuning Guidance**:
/// - Low-traffic (default): 20
/// - High-traffic servers: 50-100
/// - Memory-constrained embedded: 5-10
///
/// **C Reference**: `config.h` line 142
pub const MAX_TCP_PROCESSES: usize = 20;

/// Maximum lifetime of a TCP child process in seconds (C: CHILD_LIFETIME)
///
/// Maximum time a TCP DNS child process is allowed to run before being forcibly terminated. This
/// prevents resource leaks from clients that open TCP connections but never close them properly.
///
/// **Implementation Note**: The C code uses this as seconds; Rust code should use Duration
///
/// **C Reference**: `config.h` line 151
pub const TCP_CHILD_LIFETIME: u64 = 150;

/// Maximum number of queries a single TCP connection can send (C: TCP_MAX_QUERIES)
///
/// Limits the number of DNS queries that can be pipelined over a single TCP connection before
/// forcing the client to reconnect. This prevents indefinite resource consumption from a single
/// long-lived TCP connection.
///
/// **RFC Compliance**: RFC 7766 Section 6.2.1 (TCP connection management)
///
/// **C Reference**: `config.h` line 159
pub const TCP_MAX_QUERIES: usize = 100;

/// TCP listen backlog queue size (C: TCP_BACKLOG)
///
/// Maximum number of pending TCP connections in the kernel's SYN queue before accept() is called.
/// This should be sized based on expected TCP connection rate, not total concurrent connections.
///
/// **Tuning Guidance**: Increase if seeing SYN drops under load (check `netstat -s`)
///
/// **C Reference**: `config.h` line 168
pub const TCP_BACKLOG: i32 = 5;

// =============================================================================
// Network Buffer Sizes
// =============================================================================

/// General packet buffer size for network I/O (C: DNSMASQ_PACKETSZ)
///
/// Size of general-purpose packet buffers used throughout dnsmasq for DNS and DHCP packet
/// processing. This must be large enough to handle the largest possible EDNS0 DNS response.
///
/// **C Reference**: `config.h` line 231 (uses EDNS_PKTSZ value)
pub const PACKET_BUFFER_SIZE: usize = 4096;

/// TFTP block size in bytes (C: TFTP_MAX_SIZE)
///
/// Size of TFTP data blocks per RFC 1350. Standard TFTP uses 512-byte blocks. This can be
/// increased via TFTP blocksize option (RFC 2348) for better performance on modern networks.
///
/// **RFC Compliance**: RFC 1350 Section 2 (TFTP packet format, 512 bytes data max)
///
/// **Runtime Override**: Yes, via TFTP blksize option negotiation (RFC 2348)
///
/// **C Reference**: Derived from TFTP RFC 1350 specification
pub const TFTP_BLOCK_SIZE: usize = 512;

/// Maximum number of concurrent TFTP connections (C: TFTP_MAX_CONNECTIONS)
///
/// Limits the number of simultaneous TFTP file transfers to prevent resource exhaustion. Each
/// TFTP connection maintains transfer state including file descriptor, block number, and retry timers.
///
/// **Memory Impact**: Each TFTP transfer ~8KB (state + buffers)
///
/// **Tuning Guidance**:
/// - PXE boot server: 50-100 (many clients boot simultaneously)
/// - Occasional firmware updates: 10-20
///
/// **C Reference**: `config.h` line 715
pub const TFTP_MAX_CONNECTIONS: usize = 50;

// =============================================================================
// Timeout Values
// =============================================================================

/// Timeout in seconds for upstream DNS query (C: TIMEOUT)
///
/// Maximum time to wait for a response from an upstream DNS server before giving up and returning
/// SERVFAIL to the client. This applies to each individual upstream server attempt.
///
/// **Tuning Guidance**:
/// - Fast networks: 5 seconds
/// - Default: 10 seconds
/// - High-latency/satellite: 20-30 seconds
///
/// **C Reference**: `config.h` line 321
pub const FORWARD_TIMEOUT: u64 = 10;

/// Maximum idle timeout for TCP DNS connections in seconds (C: TCP_MAX_TIMEOUT)
///
/// Maximum time a TCP DNS connection can remain idle before being closed. This prevents resource
/// exhaustion from clients that open TCP connections but never send data or close cleanly.
///
/// **C Reference**: Derived from TCP_CHILD_LIFETIME and typical TCP timeout practices
pub const TCP_MAX_TIMEOUT: u64 = 120;

/// TFTP block timeout in seconds (C: TFTP_TIMEOUT or inline constant)
///
/// Time to wait for TFTP ACK before retransmitting a data block. TFTP uses stop-and-wait protocol,
/// so this timeout directly affects transfer speed over lossy links.
///
/// **RFC Compliance**: RFC 1350 recommends timeout and retransmission
///
/// **C Reference**: Derived from TFTP implementation, typically 2 seconds
pub const TFTP_TIMEOUT: u64 = 2;

/// Number of queries between upstream server availability tests (C: FORWARD_TEST)
///
/// After sending this many queries, dnsmasq tests whether previously failed upstream servers have
/// recovered by sending them test queries. This implements automatic failover and recovery.
///
/// **C Reference**: `config.h` line 339
pub const FORWARD_TEST_INTERVAL: usize = 50;

/// Time interval in seconds for forward server availability tests (C: FORWARD_TIME)
///
/// Minimum time between test queries to failed upstream servers, preventing excessive test traffic.
///
/// **C Reference**: `config.h` line 348
pub const FORWARD_TIME: u64 = 20;

/// UDP server test time in seconds (C: UDP_TEST_TIME)
///
/// Interval for testing UDP upstream server availability after failure detection.
///
/// **C Reference**: `config.h` line 356
pub const UDP_TEST_TIME: u64 = 60;

/// Number of random source port sockets for DNS queries (C: RANDOM_SOCKS)
///
/// dnsmasq uses multiple bound sockets with random source ports for upstream queries to improve
/// security against DNS spoofing attacks (增加entropy in transaction IDs and source ports).
///
/// **Security**: Provides ~13 bits of entropy (4 sockets × 16 bits/port = 13 bits effective)
///
/// **C Reference**: `config.h` line 176
pub const RANDOM_SOURCE_PORTS: usize = 4;

/// Number of upstream servers to log at startup (C: SERVERS_LOGGED)
///
/// Maximum number of upstream DNS server addresses to display in startup logs. This prevents
/// excessive log spam when many upstream servers are configured.
///
/// **C Reference**: `config.h` line 363
pub const SERVERS_LOGGED: usize = 30;

/// Number of local addresses to log at startup (C: LOCALS_LOGGED)
///
/// Maximum number of local listening addresses to display in startup logs.
///
/// **C Reference**: `config.h` line 373
pub const LOCALS_LOGGED: usize = 8;

// =============================================================================
// DNSSEC Configuration
// =============================================================================

/// DNSSEC crypto work buffer size in KiB (C: KEYBLOCK_LEN)
///
/// Size of buffer used for DNSSEC cryptographic operations (signature verification, key processing).
/// This must be large enough to handle the largest DNSKEY/RRSIG records.
///
/// **C Reference**: `config.h` line 240
pub const KEYBLOCK_LEN: usize = 1024; // KiB

/// Maximum DNSSEC validation work units (C: DNSSEC_WORK)
///
/// Limits the amount of computational work spent on DNSSEC validation for a single query to
/// prevent DoS attacks via complex DNSSEC configurations requiring excessive signature verifications.
///
/// **Security**: Prevents algorithmic complexity attacks on DNSSEC validator
///
/// **C Reference**: `config.h` line 252
pub const DNSSEC_WORK: usize = 50;

// =============================================================================
// Authoritative DNS Configuration
// =============================================================================

/// Default TTL for authoritative DNS responses in seconds (C: AUTH_TTL)
///
/// Time-to-live value for records served from dnsmasq's authoritative zones when not explicitly
/// specified. This determines how long downstream resolvers will cache these records.
///
/// **C Reference**: `config.h` line 768
pub const AUTH_TTL: u32 = 600; // 10 minutes

/// SOA record REFRESH interval in seconds (C: SOA_REFRESH)
///
/// Suggests to secondary nameservers how often to check for zone updates. Not used by dnsmasq as
/// a primary (it doesn't support AXFR/IXFR), but required in SOA records for RFC compliance.
///
/// **RFC Compliance**: RFC 1035 Section 3.3.13 (SOA RDATA format)
///
/// **C Reference**: `config.h` line 776
pub const SOA_REFRESH: u32 = 1200; // 20 minutes

/// SOA record RETRY interval in seconds (C: SOA_RETRY)
///
/// Suggests to secondary nameservers how long to wait before retrying after a failed zone transfer.
///
/// **C Reference**: `config.h` line 784
pub const SOA_RETRY: u32 = 180; // 3 minutes

/// SOA record EXPIRE interval in seconds (C: SOA_EXPIRY)
///
/// Tells secondary nameservers when to discard zone data if unable to contact primary.
///
/// **C Reference**: `config.h` line 792
pub const SOA_EXPIRY: u32 = 1209600; // 2 weeks

// =============================================================================
// Logging Configuration
// =============================================================================

/// Maximum asynchronous log event queue size (C: LOG_MAX)
///
/// Size of the log event queue for asynchronous syslog writes. When this fills, logging blocks
/// until queue space becomes available, preventing log loss at the cost of performance.
///
/// **C Reference**: `config.h` line 736
pub const LOG_MAX: usize = 150;

// =============================================================================
// Platform-Specific Default File Paths
// =============================================================================

/// Default DHCP lease database file path (platform-specific)
///
/// Location where dnsmasq persists DHCP lease state. This file is atomically updated using
/// rename() to ensure consistency across crashes and power failures.
///
/// **File Format**: Plain text, one lease per line with tab-separated fields
/// **Compatibility**: Byte-for-byte compatible with C version for seamless upgrades
///
/// **C Reference**: `config.h` lines 1567-1625
#[cfg(target_os = "linux")]
pub const DEFAULT_LEASE_FILE: &str = "/var/lib/misc/dnsmasq.leases";

#[cfg(target_os = "android")]
pub const DEFAULT_LEASE_FILE: &str = "/data/misc/dhcp/dnsmasq.leases";

#[cfg(any(target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
pub const DEFAULT_LEASE_FILE: &str = "/var/db/dnsmasq.leases";

#[cfg(target_os = "freebsd")]
pub const DEFAULT_LEASE_FILE: &str = "/var/db/dnsmasq.leases";

#[cfg(target_os = "solaris")]
pub const DEFAULT_LEASE_FILE: &str = "/var/cache/dnsmasq.leases";

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "solaris"
)))]
pub const DEFAULT_LEASE_FILE: &str = "/var/lib/misc/dnsmasq.leases";

/// Default configuration file path (platform-specific)
///
/// Primary configuration file location. Users can override with --conf-file command-line option.
///
/// **C Reference**: `config.h` lines 1635-1655
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const DEFAULT_CONFIG_FILE: &str = "/etc/dnsmasq.conf";

#[cfg(target_os = "freebsd")]
pub const DEFAULT_CONFIG_FILE: &str = "/usr/local/etc/dnsmasq.conf";

#[cfg(any(target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
pub const DEFAULT_CONFIG_FILE: &str = "/etc/dnsmasq.conf";

#[cfg(target_os = "macos")]
pub const DEFAULT_CONFIG_FILE: &str = "/opt/local/etc/dnsmasq.conf";

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
)))]
pub const DEFAULT_CONFIG_FILE: &str = "/etc/dnsmasq.conf";

/// Default PID file path (platform-specific)
///
/// Location where dnsmasq writes its process ID for init system integration and process management.
///
/// **C Reference**: `config.h` lines 1702-1715
#[cfg(target_os = "android")]
pub const DEFAULT_PID_FILE: &str = "/data/dnsmasq.pid";

#[cfg(not(target_os = "android"))]
pub const DEFAULT_PID_FILE: &str = "/var/run/dnsmasq.pid";

/// Default resolv.conf file path (platform-specific)
///
/// Location of system resolver configuration file that dnsmasq monitors for upstream server changes.
///
/// **C Reference**: `config.h` lines 1665-1685
#[cfg(all(target_os = "linux", target_env = "uclibc"))]
pub const DEFAULT_RESOLV_FILE: &str = "/etc/config/resolv.conf";

#[cfg(not(all(target_os = "linux", target_env = "uclibc")))]
pub const DEFAULT_RESOLV_FILE: &str = "/etc/resolv.conf";

/// Default hosts file path (platform-specific)
///
/// Location of system hosts file that dnsmasq reads for static DNS entries.
///
/// **C Reference**: `config.h` line 581
pub const HOSTSFILE: &str = "/etc/hosts";

/// Default ethers file path for DHCP static assignments
///
/// Maps MAC addresses to IP addresses for static DHCP assignments (--read-ethers option).
///
/// **C Reference**: `config.h` line 590
pub const ETHERSFILE: &str = "/etc/ethers";

/// Default random seed file for transaction ID generation
///
/// Used to seed the random number generator for DNS transaction IDs and source ports.
///
/// **Security**: Should be protected from unauthorized read access
///
/// **C Reference**: `config.h` line 747
pub const RANDFILE: &str = "/dev/urandom";

// =============================================================================
// Integration Constants
// =============================================================================

/// D-Bus service name for NetworkManager integration (C: DNSMASQ_SERVICE)
///
/// The D-Bus service name that dnsmasq registers when --enable-dbus option is used, allowing
/// NetworkManager and other system components to dynamically configure DNS settings.
///
/// **C Reference**: `config.h` line 753
pub const DNSMASQ_SERVICE: &str = "uk.org.thekelleys.dnsmasq";

/// D-Bus object path (C: DNSMASQ_PATH)
///
/// The D-Bus object path for dnsmasq's control interface.
///
/// **C Reference**: `config.h` line 754
pub const DNSMASQ_PATH: &str = "/uk/org/thekelleys/dnsmasq";

/// OpenWrt ubus object name (C: DNSMASQ_UBUS_NAME)
///
/// The ubus object name that dnsmasq registers on OpenWrt systems for integration with procd
/// and LuCI web interface.
///
/// **C Reference**: `config.h` line 760
pub const DNSMASQ_UBUS_NAME: &str = "dnsmasq";

// =============================================================================
// Version Information
// =============================================================================

/// dnsmasq version string
///
/// The version identifier for this dnsmasq implementation. In the C version, this is typically
/// defined by the build system and extracted by bld/get-version script from VERSION file.
///
/// **Note**: This should ideally be populated from Cargo.toml version at build time using
/// env!("CARGO_PKG_VERSION") in actual implementation.
///
/// **C Reference**: Defined by build system, injected via -DVERSION="x.y"
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// =============================================================================
// DHCPv6 and Router Advertisement Constants
// =============================================================================

/// Router Advertisement context name flag (C: CONTEXT_RA_NAME)
///
/// Bit flag indicating that a DHCPv6 context should advertise DNS names via RDNSS option in
/// Router Advertisements per RFC 6106.
///
/// **RFC Compliance**: RFC 6106 (IPv6 Router Advertisement Options for DNS Configuration)
///
/// **C Reference**: Derived from dnsmasq.h context flags (typically 0x40 or similar bit position)
pub const CONTEXT_RA_NAME: u32 = 0x0040;

/// Context marked as old/deprecated flag (C: CONTEXT_OLD)
///
/// Bit flag indicating that a DHCP context is deprecated and should not be used for new leases,
/// but existing leases can be renewed. Used during configuration reload when ranges change.
///
/// **C Reference**: Derived from dnsmasq.h context flags
pub const CONTEXT_OLD: u32 = 0x0100;

/// Option flag to suppress DHCPv6 lease operations logging (C: OPT_QUIET_DHCP6)
///
/// Configuration option bit to suppress DHCPv6 lease allocation logging, reducing log verbosity
/// in DHCPv6-heavy environments.
///
/// **C Reference**: Derived from dnsmasq.h daemon option flags
pub const OPT_QUIET_DHCP6: u32 = 0x0400;

/// Default Router Advertisement interval in seconds (C: RA_INTERVAL_DEFAULT)
///
/// Default time between unsolicited Router Advertisement messages per RFC 4861. Routers send
/// periodic RAs to advertise their presence and network configuration parameters.
///
/// **RFC Compliance**: RFC 4861 Section 6.2.1 recommends 200-600 seconds
///
/// **Tuning Guidance**:
/// - Fast network convergence: 30-60 seconds
/// - Default: 600 seconds (10 minutes)
/// - Battery-conscious: 1800 seconds (30 minutes)
///
/// **C Reference**: Derived from radv.c or radv-protocol.h, typical value 600
pub const RA_INTERVAL_DEFAULT: u32 = 600;

// =============================================================================
// DNS Protocol Constants
// =============================================================================

/// Size of fixed portion of DNS resource record (C: RRFIXEDSZ)
///
/// The size in bytes of the fixed fields in a DNS resource record, excluding the variable-length
/// name and RDATA fields. This consists of TYPE (2 bytes), CLASS (2 bytes), TTL (4 bytes), and
/// RDLENGTH (2 bytes) = 10 bytes total.
///
/// **RFC Compliance**: RFC 1035 Section 3.2.1 (RR format)
///
/// **Wire Format**: TYPE (16-bit) + CLASS (16-bit) + TTL (32-bit) + RDLENGTH (16-bit) = 10 bytes
///
/// **C Reference**: Typically defined in arpa/nameser.h as RRFIXEDSZ = 10
pub const RRFIXEDSZ: usize = 10;

// =============================================================================
// Type Aliases
// =============================================================================

/// Type alias for DHCP lease time values in seconds
///
/// Represents lease duration in seconds as a 64-bit unsigned integer. Using a type alias improves
/// code clarity and allows for easier refactoring if lease time representation needs to change.
///
/// **Range**: 0 to 2^64-1 seconds (effectively unlimited for practical purposes)
///
/// **Special Values**:
/// - 0: Infinite lease (never expires)
/// - 0xFFFFFFFF: Often used to signal infinite in DHCPv4 protocol
pub type LeaseTime = u64;

// =============================================================================
// Exit Codes
// =============================================================================

/// Exit status codes for the dnsmasq process
///
/// These exit codes are returned to the operating system when dnsmasq terminates, allowing
/// init systems and monitoring tools to determine the reason for termination.
///
/// **C Reference**: Derived from dnsmasq.c main() function exit paths
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Successful termination (normal shutdown via SIGTERM)
    Success = 0,

    /// Configuration file error (parse failure, invalid options)
    BadConfig = 1,

    /// Network initialization failure (cannot bind ports, invalid interface)
    BadNet = 2,

    /// File operation error (cannot read/write lease file, hosts file)
    FileError = 3,

    /// Memory allocation failure (out of memory)
    NoMemory = 4,

    /// Initialization error (privilege drop failure, PID file error)
    InitError = 5,

    /// Miscellaneous error (catchall for other failures)
    Misc = 6,
}

impl ExitCode {
    /// Convert ExitCode to i32 for process exit status
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Check if exit code indicates success
    pub const fn is_success(self) -> bool {
        matches!(self, ExitCode::Success)
    }
}

// =============================================================================
// User and Group Constants
// =============================================================================

/// Default user to drop privileges to after initialization (C: CHUSER)
///
/// After binding to privileged ports (<1024), dnsmasq drops privileges to this user if running
/// as root and no explicit user is specified via --user option.
///
/// **Security**: Running as non-root user limits impact of potential security vulnerabilities
///
/// **C Reference**: `config.h` line 644
pub const CHUSER: &str = "nobody";

/// Default group to drop privileges to after initialization (C: CHGRP)
///
/// Group to switch to when dropping privileges. If not explicitly set, uses primary group of CHUSER.
///
/// **C Reference**: `config.h` line 670
pub const CHGRP: &str = "dip";

// =============================================================================
// Helper Functions for Duration Conversion
// =============================================================================

/// Convert a timeout constant to std::time::Duration
///
/// Helper function to convert compile-time second constants to Duration types for use with
/// Tokio timers and async timeout operations.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use dnsmasq::constants::{FORWARD_TIMEOUT, timeout_duration};
///
/// let timeout = timeout_duration(FORWARD_TIMEOUT);
/// assert_eq!(timeout, Duration::from_secs(10));
/// ```
#[inline]
pub const fn timeout_duration(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

/// Convert lease time to Duration
///
/// Convenience function specifically for lease time conversions, maintaining type safety.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use dnsmasq::constants::{DEFLEASE, lease_duration};
///
/// let lease = lease_duration(DEFLEASE);
/// assert_eq!(lease, Duration::from_secs(3600));
/// ```
#[inline]
pub const fn lease_duration(seconds: LeaseTime) -> Duration {
    Duration::from_secs(seconds)
}

// =============================================================================
// Compile-Time Feature Checks
// =============================================================================

/// Check if DHCP support is compiled in
///
/// Returns true if the `dhcp` Cargo feature is enabled, corresponding to C's HAVE_DHCP macro.
///
/// # Examples
///
/// ```
/// use dnsmasq::constants::has_dhcp;
///
/// if has_dhcp() {
///     println!("DHCP support is enabled");
/// }
/// ```
#[inline]
pub const fn has_dhcp() -> bool {
    cfg!(feature = "dhcp")
}

/// Check if DNSSEC support is compiled in
///
/// Returns true if the `dnssec` Cargo feature is enabled, corresponding to C's HAVE_DNSSEC macro.
#[inline]
pub const fn has_dnssec() -> bool {
    cfg!(feature = "dnssec")
}

/// Check if TFTP support is compiled in
///
/// Returns true if the `tftp` Cargo feature is enabled, corresponding to C's HAVE_TFTP macro.
#[inline]
pub const fn has_tftp() -> bool {
    cfg!(feature = "tftp")
}

/// Check if DHCPv6 support is compiled in
///
/// Returns true if the `dhcp-v6` Cargo feature is enabled, corresponding to C's HAVE_DHCP6 macro.
#[inline]
pub const fn has_dhcp6() -> bool {
    cfg!(feature = "dhcp-v6")
}

/// Check if D-Bus support is compiled in
///
/// Returns true if the `dbus` Cargo feature is enabled, corresponding to C's HAVE_DBUS macro.
#[inline]
pub const fn has_dbus() -> bool {
    cfg!(feature = "dbus")
}

// =============================================================================
// Documentation and Usage Notes
// =============================================================================

/// # Tuning Guidelines
///
/// This module provides sensible defaults suitable for typical residential and small business
/// deployments. For specialized deployments, consider the following tuning recommendations:
///
/// ## Embedded/IoT Devices (Limited Memory <64MB RAM)
/// - `DEFAULT_CACHE_SIZE`: 50-100
/// - `MAX_FORWARD_REQUESTS`: 50-100
/// - `MAX_DHCP_LEASES`: 50-100
/// - `MAX_TCP_PROCESSES`: 5-10
/// - Consider disabling DNSSEC (saves ~500KB)
///
/// ## Enterprise/ISP (High Traffic >1000 queries/sec)
/// - `DEFAULT_CACHE_SIZE`: 5000-10000
/// - `MAX_FORWARD_REQUESTS`: 300-500
/// - `MAX_DHCP_LEASES`: 10000+ (requires recompilation in C, configurable in Rust)
/// - `MAX_TCP_PROCESSES`: 50-100
/// - Enable multiple dnsmasq instances with SO_REUSEPORT
///
/// ## Public Resolver (Internet-facing)
/// - `DEFAULT_CACHE_SIZE`: 10000+
/// - `FORWARD_TIMEOUT`: 20-30 (accommodate slow authoritative servers)
/// - `MAX_TCP_PROCESSES`: 100+
/// - Implement rate limiting and abuse prevention
/// - Enable DNSSEC validation
///
/// ## Configuration Override
///
/// Most constants have runtime overrides via command-line options or dnsmasq.conf:
/// - `DEFAULT_CACHE_SIZE`: `--cache-size=<n>`
/// - `EDNS_PACKET_SIZE`: `--edns-packet-max=<size>`
/// - `MAX_DHCP_LEASES`: `--dhcp-lease-max=<n>`
/// - `FORWARD_TIMEOUT`: Implicitly controlled by upstream server responsiveness
///
/// Some constants are compile-time only and require recompilation to change:
/// - `MAX_FORWARD_REQUESTS` (FTABSIZ in C)
/// - `MAX_TCP_PROCESSES` (MAX_PROCS in C)
/// - `MAX_DOMAIN_NAME` (MAXDNAME in C)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_constants() {
        assert_eq!(DNS_PACKET_SIZE, 512);
        assert_eq!(EDNS_PACKET_SIZE, 4096);
        assert!(EDNS_PACKET_SIZE > DNS_PACKET_SIZE);
        assert!(SAFE_PKTSZ > DNS_PACKET_SIZE);
        assert!(SAFE_PKTSZ < EDNS_PACKET_SIZE);
    }

    #[test]
    fn test_dhcp_constants() {
        assert_eq!(DEFLEASE, 3600); // 1 hour
        assert_eq!(DEFLEASE6, 14400); // 4 hours
        assert!(DEFLEASE6 > DEFLEASE); // DHCPv6 leases are longer
        assert_eq!(DHCP_COOKIE, 0x63825363);
        assert_eq!(BOOTREQUEST, 1);
        assert_eq!(BOOTREPLY, 2);
    }

    #[test]
    fn test_timeout_durations() {
        assert_eq!(timeout_duration(10), Duration::from_secs(10));
        assert_eq!(lease_duration(3600), Duration::from_secs(3600));
    }

    #[test]
    fn test_exit_codes() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::BadConfig.as_i32(), 1);
        assert!(ExitCode::Success.is_success());
        assert!(!ExitCode::BadConfig.is_success());
    }

    #[test]
    fn test_resource_limits() {
        assert!(MAX_FORWARD_REQUESTS > 0);
        assert!(DEFAULT_CACHE_SIZE > 0);
        assert!(MAX_DHCP_LEASES > 0);
        assert!(MAX_TCP_PROCESSES > 0);
    }

    #[test]
    fn test_file_paths_exist() {
        // Ensure platform-specific paths are defined
        assert!(!DEFAULT_LEASE_FILE.is_empty());
        assert!(!DEFAULT_CONFIG_FILE.is_empty());
        assert!(!DEFAULT_PID_FILE.is_empty());
        assert!(!DEFAULT_RESOLV_FILE.is_empty());
    }
}
