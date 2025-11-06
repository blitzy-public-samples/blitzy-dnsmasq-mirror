// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Compile-time configuration constants and default values
//!
//! This module contains compile-time configuration constants refactored from C's config.h,
//! defining resource limits, timeout values, network parameters, DNSSEC settings, and
//! default file paths. All C macros are converted to type-safe Rust const items.
//!
//! # Purpose
//!
//! This module serves as the centralized compile-time configuration system for dnsmasq,
//! controlling feature availability, resource limits, and platform-specific behavior.
//! It defines three primary categories of configuration:
//!
//! 1. **Tuning Constants**: Resource limits and default operational parameters
//! 2. **Timeout Values**: All timeout durations using std::time::Duration for type safety
//! 3. **Default Paths**: File system paths for configuration, leases, and hosts files
//!
//! # Memory Safety
//!
//! All constants use appropriate Rust types (usize, u16, Duration, &str) eliminating
//! the preprocessor magic and integer overflow risks from C macros. Duration types
//! prevent time-unit confusion (seconds vs milliseconds).
//!
//! # Configuration Categories
//!
//! ## DNS Configuration
//! - `FTABSIZ`: Maximum outstanding DNS forward requests
//! - `CACHESIZ`: Default DNS cache size
//! - `EDNS_PKTSZ`: Default EDNS0 UDP packet size
//! - `SAFE_PKTSZ`: Conservative UDP packet size
//! - `CNAME_CHAIN`: Maximum CNAME chain length
//!
//! ## DHCP Configuration  
//! - `MAXLEASES`: Maximum number of DHCP leases
//! - `DEFLEASE`: Default DHCPv4 lease time
//! - `DEFLEASE6`: Default DHCPv6 lease time
//! - `PING_WAIT`: Ping timeout for address conflict detection
//!
//! ## Network Configuration
//! - `TCP_BACKLOG`: Kernel TCP listen queue size
//! - `TCP_MAX_QUERIES`: Max queries per TCP connection
//! - `MAX_PROCS`: Maximum TCP child processes
//!
//! ## DNSSEC Configuration
//! - `KEYBLOCK_LEN`: DNSSEC key storage block size
//! - `DNSSEC_WORK`: Maximum validation queries per question
//! - `DNSSEC_MIN_TTL`: Minimum TTL for DNSSEC records
//!
//! ## File Paths
//! - `HOSTSFILE`: System hosts file path
//! - `ETHERSFILE`: System ethers file path
//! - `DEFLEASE`: Default lease file path (runtime configurable)
//!
//! # Examples
//!
//! ```rust
//! use dnsmasq::core::config::{FTABSIZ, TIMEOUT, HOSTSFILE};
//! use std::time::Duration;
//!
//! // Use resource limits
//! let forward_table = Vec::with_capacity(FTABSIZ);
//!
//! // Use timeout values
//! let query_timeout = TIMEOUT;
//! assert_eq!(query_timeout, Duration::from_secs(10));
//!
//! // Use file paths
//! let hosts_path = HOSTSFILE;
//! ```

use std::time::Duration;

/// Software version string
///
/// Version string for dnsmasq Rust implementation, matching C version 2.90.0.
/// This constant is used for version reporting in logs, D-Bus interface, and
/// DNS version.bind CHAOS queries.
pub const VERSION: &str = "2.90.0-rust";

/// Maximum number of outstanding DNS forward requests (default: 150)
///
/// Controls the size of the forward record (frec) freelist, limiting concurrent
/// upstream DNS queries. Each outstanding query from a client that requires
/// forwarding to an upstream server consumes one forward record. When this limit
/// is reached, additional queries are dropped until existing queries complete.
///
/// # Memory Impact
///
/// Each frec is approximately 128 bytes, so FTABSIZ=150 consumes ~19KB.
///
/// # Tuning Guidance
///
/// - High-traffic servers (>100 queries/sec): Increase to 300-500
/// - Embedded systems: Decrease to 50-100
/// - Default (residential): 150 is adequate
///
/// # Performance
///
/// Too low causes query drops under load; too high wastes memory.
pub const FTABSIZ: usize = 150;

/// Maximum number of child processes for TCP DNS connections (default: 20)
///
/// Limits concurrent TCP connections by restricting the number of child processes
/// spawned to handle TCP DNS queries. Each TCP connection gets its own forked child
/// process (or async task in Rust) to avoid blocking the main event loop.
///
/// # Resource Usage
///
/// Each child process consumes ~2MB resident memory in C implementation.
/// Rust async tasks consume significantly less (~KB range).
///
/// # Security
///
/// Limits resource exhaustion from TCP connection floods.
pub const MAX_PROCS: usize = 20;

/// Maximum lifetime for TCP child processes (default: 150 seconds)
///
/// Child processes handling TCP DNS connections are automatically terminated after
/// this duration, regardless of activity state. This prevents resource leaks from
/// long-lived connections.
///
/// # RFC Compliance
///
/// RFC 1035 Section 4.2.2 suggests TCP connections should remain open for at least
/// 120 seconds. This 150-second value provides a safe margin.
pub const CHILD_LIFETIME: Duration = Duration::from_secs(150);

/// Maximum number of DNS queries allowed per TCP connection (default: 100)
///
/// Limits the number of DNS queries that can be pipelined over a single TCP
/// connection before the connection is closed. This prevents resource exhaustion
/// from clients sending unbounded query streams.
///
/// # Normal Usage
///
/// Typical DNS clients send 1-10 queries per connection.
///
/// # Security
///
/// Prevents TCP connection resource exhaustion attacks.
pub const TCP_MAX_QUERIES: usize = 100;

/// Kernel listen backlog for TCP connection queue (default: 32)
///
/// Specifies the maximum length of the kernel's pending connection queue for the
/// TCP DNS listening socket, passed to listen(2) system call.
///
/// # Platform Note
///
/// Kernel may cap this value (e.g., Linux /proc/sys/net/core/somaxconn).
pub const TCP_BACKLOG: i32 = 32;

/// Default maximum EDNS0 UDP packet size (default: 4096 bytes)
///
/// Specifies the UDP payload size advertised in EDNS0 OPT records per RFC 6891.
/// This value indicates the maximum DNS response size dnsmasq can receive without
/// TCP fallback.
///
/// # RFC Compliance
///
/// 4096 bytes is the RFC 6891 recommended value, balancing between allowing large
/// DNSSEC responses and avoiding IP fragmentation on typical Ethernet MTU (1500 bytes).
///
/// # Runtime Override
///
/// Can be overridden with --edns-packet-max=<size> option.
pub const EDNS_PKTSZ: usize = 4096;

/// Conservative "go anywhere" UDP packet size (default: 1232 bytes)
///
/// Defines a conservative UDP packet size that avoids fragmentation on nearly all
/// internet paths, per DNS Flag Day 2020 recommendations.
///
/// # Calculation
///
/// IPv6 minimum MTU (1280 bytes) - IPv6 header (40 bytes) - UDP header (8 bytes) = 1232
///
/// # Use Case
///
/// Used as fallback when larger EDNS0 sizes fail or for clients not supporting EDNS0.
/// Guarantees delivery across NAT, VPN, tunnel, and IPv6-over-IPv4 networks without
/// fragmentation, which many firewalls drop.
///
/// # Reference
///
/// See <https://dnsflagday.net/2020/> for detailed analysis
pub const SAFE_PKTSZ: usize = 1232;

/// DNSSEC key storage block size (default: 40 bytes)
///
/// Defines the block allocation size for storing DNSSEC key material in block-chained
/// buffers. Balances between minimizing memory waste for small keys (ECDSA P-256 keys
/// are ~64 bytes) and reducing chain length for large keys (RSA-2048 keys are ~256 bytes).
///
/// # Memory Impact
///
/// Each key requires ceil(key_size / 40) blocks.
///
/// # Feature Gate
///
/// Only used when DNSSEC support is enabled.
pub const KEYBLOCK_LEN: usize = 40;

/// Maximum validation queries per DNSSEC question (default: 50)
///
/// Limits DNSSEC validation work by capping the number of additional DNS queries
/// (DNSKEY, DS, RRSIG fetches) required to validate a single original query.
///
/// # Purpose
///
/// Prevents infinite loops from circular dependencies or malicious records, and
/// bounds CPU time and network traffic per validation attempt.
///
/// # Behavior
///
/// Exceeding this limit returns SERVFAIL to the client.
///
/// # Security
///
/// Prevents DNSSEC validation DoS attacks.
pub const DNSSEC_WORK: usize = 50;

/// Upstream query timeout before dropping UDP queries (default: 10 seconds)
///
/// Defines how long dnsmasq waits for responses from upstream DNS servers before
/// considering a query failed and trying the next server.
///
/// # Typical Response Times
///
/// Most DNS responses arrive within 100-500ms. This 10-second timeout accommodates
/// slow paths and overloaded servers.
///
/// # Client Impact
///
/// Clients may implement their own timeouts (typically 5-10 seconds).
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Query count interval for testing all upstream servers (default: 50)
///
/// After every 50 queries, dnsmasq tests the responsiveness of all configured
/// upstream DNS servers, even those previously marked as failed. This implements
/// periodic health checking to detect when failed servers recover.
pub const FORWARD_TEST: usize = 50;

/// Time interval for testing all upstream servers (default: 20 seconds)
///
/// Alternative trigger to FORWARD_TEST: tests all upstream servers after this
/// many seconds elapse, whichever comes first (50 queries or 20 seconds).
///
/// # Purpose
///
/// Ensures periodic health checking even on low-traffic servers where 50 queries
/// might take minutes.
pub const FORWARD_TIME: Duration = Duration::from_secs(20);

/// Interval for resetting UDP packet size assumptions (default: 60 seconds)
///
/// Periodically resets dnsmasq's assumptions about safe UDP packet sizes for
/// upstream servers. Allows retry of larger packets after 60 seconds in case
/// network conditions have improved or transient issues have resolved.
pub const UDP_TEST_TIME: Duration = Duration::from_secs(60);

/// Maximum upstream servers to include in debug/state logs (default: 30)
///
/// When logging upstream DNS server state (triggered by SIGUSR1 or debug mode),
/// limits output to the first 30 configured servers to prevent excessive log spam.
///
/// # Typical Deployments
///
/// Most deployments use 2-5 upstream servers, so this limit is rarely reached.
pub const SERVERS_LOGGED: usize = 30;

/// Maximum local addresses to include in debug/state logs (default: 8)
///
/// When logging local interface addresses (triggered by SIGUSR1 or debug mode),
/// limits output to first 8 addresses to prevent excessive log spam.
pub const LOCALS_LOGGED: usize = 8;

/// Retry interval for DHCP lease file writes after errors (default: 60 seconds)
///
/// When writing the DHCP lease database file fails (disk full, filesystem errors,
/// permission issues), dnsmasq retries after this interval.
///
/// # Purpose
///
/// Balances between rapid recovery and avoiding resource waste on persistent failures.
pub const LEASE_RETRY: Duration = Duration::from_secs(60);

/// Default DNS cache size in number of records (default: 150)
///
/// Defines the default size of the DNS cache, measured in number of cached resource
/// records (RRs). The cache uses an LRU (Least Recently Used) eviction policy when full.
///
/// # Memory Impact
///
/// Each cache record (struct crec) is ~128 bytes, so 150 records ≈ 19KB.
///
/// # Tuning Guidance
///
/// - Residential: 150 (default)
/// - Enterprise: 1000-10000
/// - Disable caching: 0
///
/// # Runtime Override
///
/// Can be overridden with --cache-size=<n> option.
///
/// # Example
///
/// ```bash
/// dnsmasq --cache-size=5000
/// ```
pub const CACHESIZ: usize = 150;

/// Absolute maximum TTL for --min-cache-ttl option (default: 3600 seconds / 1 hour)
///
/// Caps the --min-cache-ttl option to prevent excessively long caching that could
/// serve stale data. This 1-hour hard limit balances between caching efficiency
/// and data freshness.
///
/// # RFC Consideration
///
/// RFC 2181 allows TTLs up to 2^31-1 seconds, but long TTLs impede updates.
pub const TTL_FLOOR_LIMIT: u32 = 3600;

/// Maximum number of DHCP leases (default: 1000)
///
/// Hard limit on total DHCP leases (both DHCPv4 and DHCPv6) that dnsmasq can
/// manage concurrently. Prevents unbounded memory growth from lease database.
///
/// # Memory Impact
///
/// 1000 leases × 200 bytes ≈ 200KB resident memory.
///
/// # Scale Consideration
///
/// - Residential: 5-50 devices
/// - Small business: 50-500 devices
/// - Enterprise (>1000): Consider ISC DHCP or similar
pub const MAXLEASES: usize = 1000;

/// ICMP echo reply timeout for DHCP address conflict detection (default: 3 seconds)
///
/// Before assigning a DHCP address, dnsmasq optionally sends an ICMP echo request
/// (ping) to detect if the address is already in use. This timeout determines how
/// long to wait for an echo reply.
///
/// # Performance Impact
///
/// Adds 3-second delay to DHCP handshake for unknown clients when ping-before-offer
/// is enabled.
///
/// # Feature Enablement
///
/// Enabled with --dhcp-option=tag:!known,option:ping
pub const PING_WAIT: Duration = Duration::from_secs(3);

/// Cache duration for successful ping results (default: 30 seconds)
///
/// After successfully pinging an address (confirming it's in use), caches the
/// result for 30 seconds to avoid redundant pings during DHCP retries or renewals.
pub const PING_CACHE_TIME: Duration = Duration::from_secs(30);

/// Disable duration for declined static DHCP addresses (default: 600 seconds / 10 minutes)
///
/// When a DHCP client sends DHCPDECLINE (indicating offered address is already in
/// use, per RFC 2131 Section 3.1.5), dnsmasq temporarily disables that address to
/// prevent repeated conflicts.
///
/// # RFC Compliance
///
/// Implements RFC 2131 Section 3.1.5 DECLINE handling.
pub const DECLINE_BACKOFF: Duration = Duration::from_secs(600);

/// Hard limit on DHCP packet size (default: 16384 bytes / 16KB)
///
/// Maximum size for DHCP packets (both DHCPv4 and DHCPv6), preventing memory
/// exhaustion from malformed packets claiming excessive lengths.
///
/// # Typical Sizes
///
/// Standard DHCP packets are 300-600 bytes, but options can extend to several KB.
///
/// # Security
///
/// Prevents memory exhaustion DoS attacks.
pub const DHCP_PACKET_MAX: usize = 16384;

/// Stack buffer size for common domain names (default: 50 bytes)
///
/// Used for stack-allocated domain name buffers in performance-critical code paths
/// where most domain names are known to be short. Maximum DNS name length is 255
/// bytes per RFC 1035, but typical domain names are 10-30 bytes.
///
/// # Performance
///
/// Stack allocation is 10-100x faster than heap allocation for short names.
/// Longer names fall back to heap allocation.
pub const SMALLDNAME: usize = 50;

/// Maximum CNAME chain length before loop detection (default: 10)
///
/// Limits CNAME chain following to prevent infinite loops from circular CNAME
/// records. Malicious or misconfigured records can form loops (A -> B -> C -> A).
///
/// # RFC Consideration
///
/// RFC 1034 requires loop detection but doesn't specify maximum depth. 10 hops
/// accommodates legitimate multi-level redirects.
pub const CNAME_CHAIN: usize = 10;

/// Minimum TTL for cached DNSKEY and DS records (default: 60 seconds)
///
/// Enforces minimum cache TTL for DNSSEC validation records to avoid excessive
/// re-validation overhead. Even if upstream servers specify shorter TTLs,
/// dnsmasq caches these records for at least 60 seconds.
///
/// # Purpose
///
/// DNSSEC validation requires fetching DNSKEY and DS records for every validated
/// query; caching them reduces upstream traffic and latency.
pub const DNSSEC_MIN_TTL: Duration = Duration::from_secs(60);

/// Default path to system hosts file (default: "/etc/hosts")
///
/// Path to the system hosts file containing static IP-to-hostname mappings,
/// read by dnsmasq for local name resolution.
///
/// # Runtime Override
///
/// Can be overridden with --hostsfile=/path/to/hosts or multiple files with --addn-hosts.
///
/// # Platform Note
///
/// Consistent across most Unix-like systems.
pub const HOSTSFILE: &str = "/etc/hosts";

/// Default path to system ethers file (default: "/etc/ethers")
///
/// Path to the ethers file containing Ethernet MAC address to hostname mappings,
/// used for DHCP static assignments.
///
/// # Format
///
/// <MAC-address> <hostname> per line
///
/// # Feature Enablement
///
/// Used when --read-ethers option is enabled.
pub const ETHERSFILE: &str = "/etc/ethers";

/// Default DHCPv4 lease time (default: 3600 seconds / 1 hour)
///
/// Default duration for DHCPv4 address leases when not explicitly configured.
/// After lease expiration, clients must renew or release addresses.
///
/// # Typical Deployments
///
/// - Dynamic hosts: 1-24 hours
/// - Servers: Infinite
///
/// # Runtime Override
///
/// Can be overridden per-subnet with dhcp-range option or per-host with dhcp-host option.
///
/// # RFC Compliance
///
/// RFC 2131 Section 3.3 allows any lease duration.
pub const DEFLEASE: u32 = 3600;

/// Default DHCPv6 lease time (default: 86400 seconds / 24 hours)
///
/// Default duration for DHCPv6 address leases when not explicitly configured.
/// DHCPv6 typically uses longer leases than DHCPv4 because IPv6 addresses are
/// more plentiful and address exhaustion is rare.
///
/// # DHCPv6 Timers
///
/// - T1 (renewal): Typically 50% of lease
/// - T2 (rebind): Typically 80% of lease
///
/// # Runtime Override
///
/// Can be overridden with dhcp-range option.
///
/// # RFC Compliance
///
/// RFC 3315 Section 22.4 defines lease time encoding.
pub const DEFLEASE6: u32 = 3600 * 24;

/// Maximum simultaneous TFTP file transfers (default: 50)
///
/// Limits concurrent TFTP transfers to prevent resource exhaustion. Each TFTP
/// transfer maintains state for block retransmission and acknowledgment tracking.
///
/// # Typical Usage
///
/// PXE boot environments typically have <20 concurrent boots. 50 provides adequate
/// capacity.
///
/// # Resource Usage
///
/// Each connection consumes ~1KB memory.
pub const TFTP_MAX_CONNECTIONS: usize = 50;

/// Default TTL for authoritative DNS records (default: 600 seconds / 10 minutes)
///
/// Time-to-live for DNS records served by dnsmasq's authoritative DNS server
/// (when auth support is enabled). Balances between reducing query load (caching)
/// and allowing reasonably quick updates to authoritative data.
///
/// # Runtime Override
///
/// Can be overridden with --auth-ttl=<seconds> option.
pub const AUTH_TTL: Duration = Duration::from_secs(600);

/// Default SOA refresh interval for authoritative zones (default: 1200 seconds / 20 minutes)
///
/// SOA (Start of Authority) REFRESH field defines how often secondary nameservers
/// should check primary for zone updates. Used when dnsmasq operates as authoritative server.
///
/// # RFC Compliance
///
/// RFC 1035 Section 3.3.13 defines SOA record format.
///
/// # Note
///
/// This is informational for secondary servers; dnsmasq doesn't support zone transfers.
pub const SOA_REFRESH: Duration = Duration::from_secs(1200);

/// Default SOA retry interval for authoritative zones (default: 180 seconds / 3 minutes)
///
/// SOA RETRY field defines how long secondary nameservers should wait before
/// retrying after failed refresh attempt.
///
/// # RFC Compliance
///
/// RFC 1035 Section 3.3.13 defines SOA record format.
pub const SOA_RETRY: Duration = Duration::from_secs(180);

/// Default SOA expiry interval for authoritative zones (default: 1209600 seconds / 14 days)
///
/// SOA EXPIRE field defines how long secondary nameservers should consider zone
/// data valid if unable to contact primary. After expiry, secondaries stop
/// answering queries for zone.
///
/// # RFC Compliance
///
/// RFC 1035 Section 3.3.13 defines SOA record format.
pub const SOA_EXPIRY: Duration = Duration::from_secs(1209600);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constant() {
        assert!(!VERSION.is_empty());
        assert!(VERSION.contains("2.90"));
    }

    #[test]
    fn test_resource_limits() {
        // Verify sensible resource limits
        assert!(FTABSIZ > 0);
        assert!(CACHESIZ > 0);
        assert!(MAXLEASES > 0);
        assert!(MAX_PROCS > 0);
    }

    #[test]
    fn test_timeout_durations() {
        // Verify timeout constants use Duration
        assert_eq!(TIMEOUT.as_secs(), 10);
        assert_eq!(FORWARD_TIME.as_secs(), 20);
        assert_eq!(UDP_TEST_TIME.as_secs(), 60);
        assert_eq!(CHILD_LIFETIME.as_secs(), 150);
    }

    #[test]
    fn test_packet_sizes() {
        // Verify packet size relationships
        assert!(EDNS_PKTSZ > SAFE_PKTSZ);
        assert_eq!(EDNS_PKTSZ, 4096);
        assert_eq!(SAFE_PKTSZ, 1232);
    }

    #[test]
    fn test_dhcp_constants() {
        // Verify DHCP configuration
        assert_eq!(DEFLEASE, 3600); // 1 hour
        assert_eq!(DEFLEASE6, 86400); // 24 hours
        assert!(DEFLEASE6 > DEFLEASE); // DHCPv6 leases longer than DHCPv4
        assert_eq!(PING_WAIT.as_secs(), 3);
        assert_eq!(DECLINE_BACKOFF.as_secs(), 600);
    }

    #[test]
    fn test_dnssec_constants() {
        // Verify DNSSEC configuration
        assert_eq!(KEYBLOCK_LEN, 40);
        assert_eq!(DNSSEC_WORK, 50);
        assert_eq!(DNSSEC_MIN_TTL.as_secs(), 60);
    }

    #[test]
    fn test_file_paths() {
        // Verify default file paths
        assert_eq!(HOSTSFILE, "/etc/hosts");
        assert_eq!(ETHERSFILE, "/etc/ethers");
    }

    #[test]
    fn test_tcp_configuration() {
        // Verify TCP settings
        assert_eq!(TCP_BACKLOG, 32);
        assert_eq!(TCP_MAX_QUERIES, 100);
        assert_eq!(MAX_PROCS, 20);
    }

    #[test]
    fn test_auth_constants() {
        // Verify authoritative DNS settings
        assert_eq!(AUTH_TTL.as_secs(), 600);
        assert_eq!(SOA_REFRESH.as_secs(), 1200);
        assert_eq!(SOA_RETRY.as_secs(), 180);
        assert_eq!(SOA_EXPIRY.as_secs(), 1209600);
    }

    #[test]
    fn test_cname_chain_limit() {
        // Verify CNAME chain protection
        assert_eq!(CNAME_CHAIN, 10);
        assert!(CNAME_CHAIN > 0); // Must allow at least some chaining
        assert!(CNAME_CHAIN < 100); // But not infinite
    }

    #[test]
    fn test_cache_ttl_limits() {
        // Verify TTL constraints
        assert_eq!(TTL_FLOOR_LIMIT, 3600);
        assert!(DNSSEC_MIN_TTL.as_secs() < TTL_FLOOR_LIMIT as u64);
    }
}
