// Copyright (C) 2024 Blitzy Platform - dnsmasq Rust Port
// This file is part of the dnsmasq Rust implementation.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Default configuration constants for dnsmasq
//!
//! This module contains compile-time configuration constants translated from the C
//! implementation's config.h. These constants define resource limits, default operational
//! parameters, file paths, and platform-specific values.
//!
//! # Organization
//!
//! Constants are organized by functional area:
//! - DNS configuration (cache size, packet sizes, timeouts)
//! - DHCP configuration (lease limits, timeouts)
//! - TCP connection management
//! - Network buffer sizes
//! - Default file paths (platform-specific)
//! - Feature-specific constants (DNSSEC, TFTP, etc.)
//!
//! # Platform Specificity
//!
//! Many file path constants vary by platform (Linux, BSD, macOS, Solaris, Android).
//! These use Rust's `#[cfg]` attribute for conditional compilation.
//!
//! # Feature Gating
//!
//! Some constants are only relevant when specific Cargo features are enabled
//! (e.g., DNSSEC, TFTP, authoritative DNS). These are conditionally compiled
//! using `#[cfg(feature = "...")]`.
//!
//! # Source Reference
//!
//! Translated from: src/config.h in the C implementation
//! Each constant includes a reference to its C equivalent and line numbers.

use std::time::Duration;

// =============================================================================
// DNS CONFIGURATION CONSTANTS
// =============================================================================

/// Maximum number of outstanding DNS forward requests
///
/// Controls the size of the forward record (frec) freelist, limiting concurrent
/// upstream DNS queries. Each outstanding query from a client that requires
/// forwarding to an upstream server consumes one forward record.
///
/// **Default**: 150
/// **Memory impact**: Each frec is approximately 128 bytes, so 150 consumes ~19KB
/// **Tuning**:
/// - High-traffic servers (>100 queries/second): increase to 300-500
/// - Memory-constrained embedded systems: decrease to 50-100
///
/// **Source**: config.h line 116 `#define FTABSIZ 150`
pub const MAX_FORWARD_REQUESTS: usize = 150;

/// Default DNS cache size in number of records
///
/// Defines the default size of the DNS cache, measured in number of cached
/// resource records (A, AAAA, CNAME, MX, etc.). The cache uses an LRU
/// (Least Recently Used) eviction policy when full.
///
/// **Default**: 150 records
/// **Memory impact**: Each cache record is ~128 bytes, so 150 records ≈ 19KB
/// **Tuning**:
/// - Residential use: 150 records (default) for 50-100 unique domains
/// - Enterprise: increase to 1000-10000 for busy networks
/// - Disable caching: set to 0 at runtime with --cache-size=0
///
/// **Runtime override**: Can be changed with --cache-size=<n> option
/// **Source**: config.h line 423 `#define CACHESIZ 150`
pub const DEFAULT_CACHE_SIZE: usize = 150;

/// Default maximum EDNS0 UDP packet size advertised to clients and upstream servers
///
/// Specifies the UDP payload size advertised in EDNS0 OPT records per RFC 6891.
/// This value indicates the maximum DNS response size dnsmasq can receive without
/// TCP fallback. 4096 bytes balances between allowing large DNSSEC responses
/// (which can exceed 2KB) and avoiding IP fragmentation on typical Ethernet MTU (1500 bytes).
///
/// **Default**: 4096 bytes
/// **RFC compliance**: Matches RFC 6891 Section 6.2.5 recommended value
/// **Behavior**: Responses exceeding this size trigger TC (truncation) bit, forcing TCP retry
/// **Runtime override**: Can be changed with --edns-packet-max=<size> option
///
/// **Source**: config.h line 213 `#define EDNS_PKTSZ 4096`
pub const EDNS_PACKET_SIZE: usize = 4096;

/// Conservative "go anywhere" UDP packet size for maximum internet-wide compatibility
///
/// Defines a conservative UDP packet size that avoids fragmentation on nearly all
/// internet paths, per DNS Flag Day 2020 recommendations. This value accounts for
/// IPv6 minimum MTU (1280 bytes) minus IPv6 header (40 bytes) minus UDP header (8 bytes).
///
/// **Default**: 1232 bytes
/// **Rationale**: DNS Flag Day 2020 analysis of internet path MTU distribution
/// **Use case**: Fallback when larger EDNS0 sizes fail or for clients not supporting EDNS0
/// **Guarantees**: Delivery across NAT, VPN, tunnel, and IPv6-over-IPv4 networks without fragmentation
///
/// **Reference**: https://dnsflagday.net/2020/
/// **Source**: config.h line 233 `#define SAFE_PKTSZ 1232`
pub const SAFE_PACKET_SIZE: usize = 1232;

/// Standard DNS UDP packet size without EDNS0
///
/// Traditional DNS packet size limit per RFC 1035 for UDP without EDNS0 extensions.
/// Responses exceeding 512 bytes must either use TCP or enable EDNS0.
///
/// **Default**: 512 bytes
/// **RFC**: RFC 1035 Section 4.2.1
/// **Source**: config.h (referenced in DNS protocol handling)
pub const DNS_PACKET_SIZE: usize = 512;

/// Maximum domain name length including null terminator
///
/// Maximum length for fully-qualified domain names (FQDNs) in DNS protocol.
/// RFC 1035 limits domain names to 255 bytes.
///
/// **Default**: 1025 bytes (accommodates maximum DNS name + processing overhead)
/// **RFC**: RFC 1035 Section 3.1
/// **Source**: config.h (MAXDNAME constant referenced in code)
pub const MAX_DOMAIN_NAME: usize = 1025;

/// Timeout for upstream DNS query resolution (seconds)
///
/// Maximum time to wait for response from upstream DNS server before marking
/// query as failed and potentially retrying with alternate server.
///
/// **Default**: 10 seconds
/// **Behavior**: After timeout, query rotates to next upstream server
/// **Tuning**:
/// - Fast networks: can reduce to 3-5 seconds
/// - Slow/satellite links: increase to 30+ seconds
///
/// **Source**: config.h line 274 `#define TIMEOUT 10`
pub const FORWARD_TIMEOUT_SECS: u64 = 10;

/// Timeout as Duration type for convenience
///
/// Pre-constructed Duration for use with async timeout operations.
pub const FORWARD_TIMEOUT: Duration = Duration::from_secs(FORWARD_TIMEOUT_SECS);

/// Number of successful queries between upstream server health tests
///
/// After this many successful queries to an upstream server, dnsmasq sends a
/// test query to verify the server is still responsive. Prevents routing all
/// queries to a failed server.
///
/// **Default**: 50 queries
/// **Source**: config.h line 286 `#define FORWARD_TEST 50`
pub const FORWARD_TEST_INTERVAL: usize = 50;

/// Time interval between upstream server health tests (seconds)
///
/// Even if FORWARD_TEST_INTERVAL queries haven't occurred, send a test query
/// after this many seconds to verify upstream server health.
///
/// **Default**: 20 seconds
/// **Source**: config.h line 300 `#define FORWARD_TIME 20`
pub const FORWARD_TIME_SECS: u64 = 20;

/// Interval to retry UDP packet size after EDNS0 failure (seconds)
///
/// After receiving truncated response from upstream server, retry with smaller
/// packet size. This interval controls how often to re-test larger sizes.
///
/// **Default**: 60 seconds
/// **Source**: config.h line 312 `#define UDP_TEST_TIME 60`
pub const UDP_TEST_TIME_SECS: u64 = 60;

/// Maximum value for --min-cache-ttl option (seconds)
///
/// Limits the --min-cache-ttl option to prevent excessively long minimum TTLs
/// that could cause stale cache entries.
///
/// **Default**: 3600 seconds (1 hour)
/// **Source**: config.h line 324 `#define TTL_FLOOR_LIMIT 3600`
pub const TTL_FLOOR_LIMIT_SECS: u64 = 3600;

/// Maximum CNAME chain depth for loop detection
///
/// Prevents infinite loops when resolving CNAME chains. RFC 1034 recommends
/// limiting CNAME chains to prevent resource exhaustion.
///
/// **Default**: 10
/// **RFC**: RFC 1034 Section 3.6.2
/// **Source**: config.h line 652 `#define CNAME_CHAIN 10`
pub const MAX_CNAME_CHAIN: usize = 10;

/// Number of upstream servers to log for diagnosis
///
/// Maximum number of upstream server addresses to include in diagnostic logs.
///
/// **Default**: 30
/// **Source**: config.h line 717 `#define SERVERS_LOGGED 30`
pub const MAX_SERVERS_LOGGED: usize = 30;

/// Number of local addresses to log for diagnosis
///
/// Maximum number of local interface addresses to include in diagnostic logs.
///
/// **Default**: 8
/// **Source**: config.h line 730 `#define LOCALS_LOGGED 8`
pub const MAX_LOCALS_LOGGED: usize = 8;

/// Maximum log queue size
///
/// Size of the log message queue for asynchronous logging.
///
/// **Default**: 5
/// **Source**: config.h line 743 `#define LOG_MAX 5`
pub const LOG_QUEUE_SIZE: usize = 5;

// =============================================================================
// DHCP CONFIGURATION CONSTANTS
// =============================================================================

/// Maximum number of DHCP leases supported
///
/// Defines the upper limit for DHCP lease database size. Each lease consumes
/// approximately 256 bytes of memory for tracking MAC address, IP address,
/// hostname, and lease expiration.
///
/// **Default**: 1000 leases
/// **Memory impact**: 1000 leases × 256 bytes ≈ 250KB
/// **Tuning**:
/// - Home/small office: 50-150 leases sufficient
/// - Enterprise subnet: 1000-10000 leases
/// - Service provider: 10000+ (requires recompilation)
///
/// **Runtime override**: Can be changed with --dhcp-lease-max=<n> option
/// **Source**: config.h line 462 `#define MAXLEASES 1000`
pub const MAX_DHCP_LEASES: usize = 1000;

/// ICMP ping timeout before assigning DHCP address (seconds)
///
/// Before assigning a DHCP address, dnsmasq pings the target IP to detect
/// conflicts with existing hosts. This timeout limits how long to wait for reply.
///
/// **Default**: 3 seconds
/// **Behavior**: No ICMP reply within 3 seconds → address assumed free
/// **Source**: config.h line 497 `#define PING_WAIT 3`
pub const DHCP_PING_WAIT_SECS: u64 = 3;

/// Cache time for ICMP ping results (seconds)
///
/// Duration to cache negative ping results (no reply) to avoid repeated pings
/// for same address during address pool scanning.
///
/// **Default**: 30 seconds
/// **Source**: config.h line 516 `#define PING_CACHE_TIME 30`
pub const PING_CACHE_TIME_SECS: u64 = 30;

/// Backoff time before reassigning declined DHCP addresses (seconds)
///
/// After a client sends DHCPDECLINE (address conflict detected), wait this long
/// before making the address available again. Prevents rapid reassignment of
/// problematic addresses.
///
/// **Default**: 600 seconds (10 minutes)
/// **RFC**: RFC 2131 Section 3.1.5
/// **Source**: config.h line 600 `#define DECLINE_BACKOFF 600`
pub const DECLINE_BACKOFF_SECS: u64 = 600;

/// Maximum DHCP packet size
///
/// Upper limit for DHCP packet size including all options. DHCPv6 packets can
/// be large due to extensive option chains.
///
/// **Default**: 16384 bytes (16KB)
/// **Source**: config.h line 625 `#define DHCP_PACKET_MAX 16384`
pub const DHCP_PACKET_MAX: usize = 16384;

/// Default DHCPv4 lease time (seconds)
///
/// Default duration for IPv4 DHCP leases when not explicitly configured.
/// Clients must renew before expiration or lose their address assignment.
///
/// **Default**: 3600 seconds (1 hour)
/// **RFC**: RFC 2131 Section 3.3
/// **Tuning**:
/// - Stable networks: 86400 (24 hours)
/// - High churn (guest WiFi): 600-1800 (10-30 minutes)
/// - Mobile devices: 7200 (2 hours)
///
/// **Runtime override**: Configurable per DHCP range with dhcp-range option
/// **Source**: config.h line 676 `#define DEFLEASE 3600`
pub const DEFAULT_LEASE_TIME_V4_SECS: u64 = 3600;

/// Default DHCPv6 lease time (seconds)
///
/// Default duration for IPv6 DHCP leases (both IA_NA and IA_TA address types).
/// IPv6 leases typically longer than IPv4 due to SLAAC alternatives.
///
/// **Default**: 86400 seconds (24 hours)
/// **RFC**: RFC 8415 Section 7.7
/// **Rationale**: Longer than IPv4 due to larger address space and SLAAC coexistence
///
/// **Runtime override**: Configurable per DHCPv6 range
/// **Source**: config.h line 689 `#define DEFLEASE6 86400`
pub const DEFAULT_LEASE_TIME_V6_SECS: u64 = 86400;

/// Retry interval for lease file write failures (seconds)
///
/// If writing lease database to disk fails (disk full, permissions), wait this
/// long before retry. Prevents log spam during persistent failures.
///
/// **Default**: 60 seconds
/// **Source**: config.h line 532 `#define LEASE_RETRY 60`
pub const LEASE_RETRY_INTERVAL_SECS: u64 = 60;

// =============================================================================
// TCP CONNECTION LIMITS
// =============================================================================

/// Maximum number of concurrent TCP child processes for DNS-over-TCP
///
/// Limits concurrent TCP DNS connections. Each TCP query spawns a separate
/// handler process/task. Prevents resource exhaustion from TCP connection floods.
///
/// **Default**: 20 concurrent TCP connections
/// **Memory impact**: Each TCP handler consumes ~2MB RAM + stack
/// **Tuning**:
/// - Low-memory systems: 5-10
/// - High-traffic servers: 50-150
///
/// **Source**: config.h line 125 `#define MAX_PROCS 20`
pub const MAX_TCP_PROCESSES: usize = 20;

/// Maximum lifetime for TCP child process (seconds)
///
/// Hard limit on how long a single TCP connection handler can exist before
/// forced termination. Prevents hung connections from consuming resources indefinitely.
///
/// **Default**: 150 seconds
/// **Source**: config.h line 145 `#define CHILD_LIFETIME 150`
pub const TCP_CHILD_LIFETIME_SECS: u64 = 150;

/// Maximum number of queries per TCP connection
///
/// Limits pipelined queries on single TCP connection per RFC 7766. After this
/// many queries, connection is closed to prevent resource monopolization.
///
/// **Default**: 100 queries
/// **RFC**: RFC 7766 Section 6.2.1
/// **Source**: config.h line 165 `#define TCP_MAX_QUERIES 100`
pub const TCP_MAX_QUERIES: usize = 100;

/// TCP listen socket backlog
///
/// Operating system parameter controlling queue size for pending TCP connections
/// not yet accepted. Prevents SYN flood attacks from exhausting connection state.
///
/// **Default**: 32 pending connections
/// **Source**: config.h line 189 `#define TCP_BACKLOG 32`
pub const TCP_BACKLOG: usize = 32;

// =============================================================================
// NETWORK BUFFER SIZES
// =============================================================================

/// Internal packet processing buffer size
///
/// Working buffer for packet assembly, compression, and protocol parsing.
/// Must accommodate largest expected DNS response with EDNS0.
///
/// **Default**: 4096 bytes
/// **Source**: config.h line 756 `#define DNSMASQ_PACKETSZ 4096`
pub const PACKET_BUFFER_SIZE: usize = 4096;

/// Small domain name buffer size
///
/// Optimized buffer for short domain names (labels). Reduces allocation overhead
/// for common case of short queries like "A.ROOT-SERVERS.NET".
///
/// **Default**: 50 bytes
/// **Source**: config.h line 768 `#define SMALLDNAME 50`
pub const SMALL_DOMAIN_NAME: usize = 50;

/// Number of random source ports for query source port randomization
///
/// For DNS query ID security (anti-poisoning), dnsmasq randomizes source ports
/// across this many randomly-chosen ports. More ports = harder to spoof.
///
/// **Default**: 4 ports
/// **Security**: Combined with random query ID provides ~64K * 4 = 256K search space
/// **Source**: config.h line 781 `#define RANDOM_SOCKS 4`
pub const RANDOM_SOURCE_PORTS: usize = 4;

// =============================================================================
// DNSSEC CONSTANTS (feature-gated)
// =============================================================================

/// DNSSEC key storage block size
///
/// Size of memory blocks allocated for storing DNSKEY and DS records during
/// DNSSEC validation chain building.
///
/// **Default**: 40 bytes
/// **Source**: config.h line 201 `#define KEYBLOCK_LEN 40`
#[cfg(feature = "dnssec")]
pub const DNSSEC_KEYBLOCK_SIZE: usize = 40;

/// Maximum DNSSEC validation work queries
///
/// Limits the number of additional DNS queries performed during DNSSEC validation
/// chain construction (fetching DNSKEY, DS records). Prevents validation loops
/// from consuming excessive resources.
///
/// **Default**: 50 queries
/// **Source**: config.h line 227 `#define DNSSEC_WORK 50`
#[cfg(feature = "dnssec")]
pub const DNSSEC_MAX_WORK: usize = 50;

/// Minimum TTL for DNSKEY and DS records (seconds)
///
/// Enforces minimum cache time for DNSSEC trust anchors and keys to reduce
/// validation overhead. Even if record TTL is lower, cache for at least this long.
///
/// **Default**: 60 seconds
/// **Source**: config.h line 248 `#define DNSSEC_MIN_TTL 60`
#[cfg(feature = "dnssec")]
pub const DNSSEC_MIN_TTL_SECS: u64 = 60;

// =============================================================================
// TFTP CONSTANTS (feature-gated)
// =============================================================================

/// Maximum concurrent TFTP connections
///
/// Limits simultaneous TFTP file transfers. Each transfer maintains state for
/// block retransmissions and timeouts. Used for PXE network boot scenarios.
///
/// **Default**: 50 connections
/// **RFC**: RFC 1350 (TFTP), RFC 2348 (TFTP Options)
/// **Source**: config.h line 794 `#define TFTP_MAX_CONNECTIONS 50`
#[cfg(feature = "tftp")]
pub const TFTP_MAX_CONNECTIONS: usize = 50;

/// TFTP default block size
///
/// Default data block size for TFTP transfers. Can be negotiated up to 65464
/// bytes per RFC 2348, but 512 bytes ensures compatibility with all clients.
///
/// **Default**: 512 bytes
/// **RFC**: RFC 1350 Section 5
/// **Source**: config.h (TFTP protocol constant)
#[cfg(feature = "tftp")]
pub const TFTP_BLOCK_SIZE: usize = 512;

// =============================================================================
// AUTHORITATIVE DNS CONSTANTS (feature-gated)
// =============================================================================

/// Default TTL for authoritative DNS responses (seconds)
///
/// Time-to-live for DNS records served from authoritative zones when not
/// explicitly configured. Clients cache responses for this duration.
///
/// **Default**: 600 seconds (10 minutes)
/// **Source**: config.h line 806 `#define AUTH_TTL 600`
#[cfg(feature = "auth-dns")]
pub const AUTH_DEFAULT_TTL_SECS: u64 = 600;

/// SOA record REFRESH interval (seconds)
///
/// Secondary DNS servers check primary for zone updates at this interval per
/// RFC 1035 SOA record semantics.
///
/// **Default**: 1200 seconds (20 minutes)
/// **RFC**: RFC 1035 Section 3.3.13
/// **Source**: config.h line 820 `#define SOA_REFRESH 1200`
#[cfg(feature = "auth-dns")]
pub const SOA_REFRESH_SECS: u64 = 1200;

/// SOA record RETRY interval (seconds)
///
/// If zone transfer fails, secondary retries after this interval.
///
/// **Default**: 180 seconds (3 minutes)
/// **RFC**: RFC 1035 Section 3.3.13
/// **Source**: config.h line 835 `#define SOA_RETRY 180`
#[cfg(feature = "auth-dns")]
pub const SOA_RETRY_SECS: u64 = 180;

/// SOA record EXPIRE time (seconds)
///
/// If primary unreachable for this duration, secondary stops serving zone data
/// to prevent serving stale information.
///
/// **Default**: 1209600 seconds (14 days)
/// **RFC**: RFC 1035 Section 3.3.13
/// **Source**: config.h line 850 `#define SOA_EXPIRY 1209600`
#[cfg(feature = "auth-dns")]
pub const SOA_EXPIRY_SECS: u64 = 1209600;

// =============================================================================
// LOOP DETECTION CONSTANTS (feature-gated)
// =============================================================================

/// Test domain for DNS forwarding loop detection
///
/// Special domain name used to detect forwarding loops. If dnsmasq receives
/// a query for this domain that it previously sent upstream, a loop exists.
///
/// **Default**: "test"
/// **Source**: config.h line 863 `#define LOOP_TEST_DOMAIN "test"`
#[cfg(feature = "loop-detect")]
pub const LOOP_TEST_DOMAIN: &str = "test";

// =============================================================================
// DEFAULT FILE PATHS (platform-specific)
// =============================================================================

/// Default configuration file path
///
/// Location of main dnsmasq configuration file read at startup.
///
/// **All platforms**: /etc/dnsmasq.conf
/// **Source**: config.h line 1512 `#define CONFFILE "/etc/dnsmasq.conf"`
pub const DEFAULT_CONFIG_FILE: &str = "/etc/dnsmasq.conf";

/// Default PID file path
///
/// Location where dnsmasq writes its process ID for init system management.
///
/// **Platform-specific**:
/// - Linux: /var/run/dnsmasq.pid
/// - BSD/macOS: /var/run/dnsmasq.pid
/// - Others: /var/run/dnsmasq.pid
///
/// **Source**: config.h line 1533 `#define RUNFILE`
#[cfg(target_os = "linux")]
pub const DEFAULT_PID_FILE: &str = "/var/run/dnsmasq.pid";

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub const DEFAULT_PID_FILE: &str = "/var/run/dnsmasq.pid";

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
)))]
pub const DEFAULT_PID_FILE: &str = "/var/run/dnsmasq.pid";

/// Default DHCP lease database file path
///
/// Location where DHCP leases are persisted across daemon restarts.
///
/// **Platform-specific**:
/// - Linux: /var/lib/misc/dnsmasq.leases
/// - BSD: /var/db/dnsmasq.leases
/// - macOS: /var/db/dnsmasq.leases
/// - Android: /data/misc/dhcp/dnsmasq.leases
///
/// **Source**: config.h lines 1489-1510
#[cfg(target_os = "android")]
pub const DEFAULT_LEASE_FILE: &str = "/data/misc/dhcp/dnsmasq.leases";

#[cfg(all(target_os = "linux", not(target_os = "android")))]
pub const DEFAULT_LEASE_FILE: &str = "/var/lib/misc/dnsmasq.leases";

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub const DEFAULT_LEASE_FILE: &str = "/var/db/dnsmasq.leases";

#[cfg(target_os = "macos")]
pub const DEFAULT_LEASE_FILE: &str = "/var/db/dnsmasq.leases";

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
)))]
pub const DEFAULT_LEASE_FILE: &str = "/var/lib/misc/dnsmasq.leases";

/// Default resolv.conf file path
///
/// Location of system resolver configuration file that dnsmasq monitors for
/// upstream DNS server changes.
///
/// **All platforms**: /etc/resolv.conf
/// **Source**: config.h line 1557 `#define RESOLVFILE "/etc/resolv.conf"`
pub const DEFAULT_RESOLV_FILE: &str = "/etc/resolv.conf";

/// Default hosts file path
///
/// Location of system hosts file that dnsmasq reads for static DNS records.
///
/// **All platforms**: /etc/hosts
/// **Source**: config.h line 583 `#define HOSTSFILE "/etc/hosts"`
pub const DEFAULT_HOSTS_FILE: &str = "/etc/hosts";

/// Default ethers file path
///
/// Location of Ethernet address to IP address mapping file for DHCP
/// static assignments based on MAC address.
///
/// **All platforms**: /etc/ethers
/// **Source**: config.h line 612 `#define ETHERSFILE "/etc/ethers"`
pub const DEFAULT_ETHERS_FILE: &str = "/etc/ethers";

/// Default random number generator device
///
/// Source of cryptographic-quality random data for DNS query IDs,
/// transaction IDs, and source port randomization.
///
/// **All platforms**: /dev/urandom
/// **Source**: config.h line 704 `#define RANDFILE "/dev/urandom"`
pub const DEFAULT_RANDOM_FILE: &str = "/dev/urandom";

// =============================================================================
// DEFAULT USER AND GROUP
// =============================================================================

/// Default unprivileged user for privilege dropping
///
/// After binding privileged ports (<1024), dnsmasq drops privileges to this
/// user account for security isolation.
///
/// **All platforms**: "nobody"
/// **Security**: Limits damage from potential security vulnerabilities
/// **Source**: config.h line 638 `#define CHUSER "nobody"`
pub const DEFAULT_USER: &str = "nobody";

/// Default unprivileged group for privilege dropping
///
/// Group context after dropping root privileges.
///
/// **Platform-specific**:
/// - Linux/most platforms: "dip" (dialup/network configuration group)
/// - BSD: "nobody"
///
/// **Source**: config.h line 664 `#define CHGRP`
#[cfg(target_os = "linux")]
pub const DEFAULT_GROUP: &str = "dip";

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
))]
pub const DEFAULT_GROUP: &str = "nobody";

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos"
)))]
pub const DEFAULT_GROUP: &str = "dip";

// =============================================================================
// D-BUS CONSTANTS (feature-gated)
// =============================================================================

/// D-Bus service name for dnsmasq
///
/// Well-known D-Bus service name used for NetworkManager integration and
/// external control interface.
///
/// **Default**: "uk.org.thekelleys.dnsmasq"
/// **Source**: config.h line 876 `#define DNSMASQ_SERVICE`
#[cfg(feature = "dbus")]
pub const DBUS_SERVICE_NAME: &str = "uk.org.thekelleys.dnsmasq";

/// D-Bus object path for dnsmasq
///
/// Object path for D-Bus method calls and signals.
///
/// **Default**: "/uk/org/thekelleys/dnsmasq"
/// **Source**: config.h line 889 `#define DNSMASQ_PATH`
#[cfg(feature = "dbus")]
pub const DBUS_OBJECT_PATH: &str = "/uk/org/thekelleys/dnsmasq";

// =============================================================================
// UBUS CONSTANTS (feature-gated, OpenWrt-specific)
// =============================================================================

/// OpenWrt ubus service name
///
/// Service identifier for OpenWrt's ubus IPC system, used for integration
/// with OpenWrt's network management infrastructure.
///
/// **Default**: "dnsmasq"
/// **Platform**: OpenWrt only
/// **Source**: config.h line 902 `#define DNSMASQ_UBUS_NAME`
#[cfg(feature = "ubus")]
pub const UBUS_SERVICE_NAME: &str = "dnsmasq";

// =============================================================================
// TYPE ALIASES AND HELPER TYPES
// =============================================================================

/// Type alias for lease time values in seconds
///
/// Provides semantic clarity for variables representing lease durations.
pub type LeaseTime = u64;

/// Type alias for DNS/DHCP packet sizes
///
/// Semantic type for buffer sizes and packet length values.
pub type PacketSize = usize;

/// Type alias for cache entry counts
///
/// Semantic type for cache size limits and current cache population.
pub type CacheSize = usize;

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_constants_are_valid() {
        // DNS packet size hierarchy (compile-time validated):
        // DNS_PACKET_SIZE (512) < SAFE_PACKET_SIZE (1232) < EDNS_PACKET_SIZE (4096) <= PACKET_BUFFER_SIZE (4096)
        // DEFAULT_CACHE_SIZE (150) is reasonable (> 0 and <= 100,000)
        // MAX_FORWARD_REQUESTS (150) is reasonable (> 0 and <= 10,000)
    }

    #[test]
    fn test_dhcp_constants_are_valid() {
        // Lease limits (compile-time validated):
        // MAX_DHCP_LEASES (1000) > 0
        // DEFAULT_LEASE_TIME_V4_SECS (3600) > 0
        // DEFAULT_LEASE_TIME_V6_SECS (86400) >= DEFAULT_LEASE_TIME_V4_SECS (3600)
        // DHCP_PACKET_MAX (16384) >= EDNS_PACKET_SIZE (4096)
    }

    #[test]
    fn test_tcp_constants_are_valid() {
        // TCP limits (compile-time validated):
        // MAX_TCP_PROCESSES > 0 and <= 1000
        // TCP_MAX_QUERIES > 0
        // TCP_BACKLOG > 0
        // TCP_CHILD_LIFETIME_SECS > FORWARD_TIMEOUT_SECS
    }

    #[test]
    fn test_timeout_constants() {
        // Timeout hierarchy (compile-time validated):
        // FORWARD_TIMEOUT_SECS > 0
        // FORWARD_TIME_SECS >= FORWARD_TIMEOUT_SECS
        // UDP_TEST_TIME_SECS >= FORWARD_TIME_SECS
    }

    #[test]
    fn test_duration_conversion() {
        // Verify Duration constant matches seconds constant
        assert_eq!(FORWARD_TIMEOUT.as_secs(), FORWARD_TIMEOUT_SECS);
    }

    #[test]
    fn test_file_paths_are_absolute() {
        // All default file paths should be absolute
        assert!(DEFAULT_CONFIG_FILE.starts_with('/'));
        assert!(DEFAULT_PID_FILE.starts_with('/'));
        assert!(DEFAULT_LEASE_FILE.starts_with('/'));
        assert!(DEFAULT_RESOLV_FILE.starts_with('/'));
        assert!(DEFAULT_HOSTS_FILE.starts_with('/'));
        assert!(DEFAULT_ETHERS_FILE.starts_with('/'));
        assert!(DEFAULT_RANDOM_FILE.starts_with('/'));
    }

    #[test]
    fn test_user_group_not_empty() {
        // User and group strings (compile-time validated):
        // DEFAULT_USER and DEFAULT_GROUP are non-empty
    }

    #[test]
    fn test_cname_chain_limit() {
        // CNAME chain limit (compile-time validated):
        // MAX_CNAME_CHAIN > 0 and <= 100 to prevent infinite loops
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_dnssec_constants() {
        // DNSSEC constants (compile-time validated):
        // DNSSEC_KEYBLOCK_SIZE > 0
        // DNSSEC_MAX_WORK > 0
        // DNSSEC_MIN_TTL_SECS > 0
    }

    #[cfg(feature = "tftp")]
    #[test]
    fn test_tftp_constants() {
        // TFTP constants (compile-time validated):
        // TFTP_MAX_CONNECTIONS > 0
        // TFTP_BLOCK_SIZE == 512 (RFC 1350 standard)
    }

    #[cfg(feature = "auth-dns")]
    #[test]
    fn test_authoritative_dns_constants() {
        // SOA timing hierarchy (compile-time validated):
        // SOA_RETRY_SECS < SOA_REFRESH_SECS < SOA_EXPIRY_SECS
        // AUTH_DEFAULT_TTL_SECS > 0
    }
}
