// Copyright (c) 2000-2024 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Metric type definitions for Prometheus export
//!
//! This module defines the type-safe metric identification system for dnsmasq's
//! Prometheus metrics export functionality. It provides a strongly-typed enum
//! replacing the C implementation's anonymous integer enum, ensuring compile-time
//! safety for metric identification throughout the Rust codebase.
//!
//! # Overview
//!
//! The `MetricId` enum defines all operational metrics tracked by dnsmasq when
//! the prometheus-metrics feature is enabled. Metrics include:
//!
//! - **DNS cache operations**: Insertions and LRU evictions
//! - **DNS query statistics**: Forwarding, authoritative answers, local answers
//! - **DHCP message counts**: All DHCPv4 message types (DISCOVER, OFFER, REQUEST, ACK, etc.)
//! - **Legacy protocol support**: BOOTP and PXE boot requests
//! - **Lease management**: IPv4/IPv6 lease allocations and pruning
//!
//! # Architecture
//!
//! This module is designed for zero-cost abstraction compared to the C implementation:
//! - Enum variants compile to integer discriminants matching C enum values
//! - `Copy` trait enables efficient pass-by-value semantics
//! - `Hash` trait allows use as HashMap keys in metrics collectors
//! - Match exhaustiveness checking prevents missing metric cases at compile time
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::monitoring::types::MetricId;
//!
//! // Type-safe metric identification
//! let metric = MetricId::DnsQueriesForwarded;
//!
//! // Convert to Prometheus metric name
//! let name = metric.to_prometheus_name();
//! assert_eq!(name, "dns_queries_forwarded_total");
//!
//! // Iterate over all metrics
//! for metric in MetricId::all() {
//!     println!("{}: {}", metric.as_str(), metric.to_prometheus_name());
//! }
//! ```
//!
//! # C Interoperability
//!
//! This Rust enum maintains semantic equivalence with the C implementation:
//! - C: `src/metrics.h` anonymous enum with METRIC_* constants
//! - Rust: `MetricId` enum with named variants
//! - C: `get_metric_name(int)` function
//! - Rust: `MetricId::to_prometheus_name()` method
//! - C: `__METRIC_MAX` sentinel value
//! - Rust: `MetricId::all()` iterator method
//!
//! # Thread Safety
//!
//! All methods are inherently thread-safe as they operate on immutable data or
//! perform pure computations. The enum itself is `Copy`, so no shared mutable
//! state exists.

/// Metric identifier enum for Prometheus export
///
/// Defines symbolic constants for all operational metrics tracked by dnsmasq.
/// Each variant corresponds to a specific metric counter that monotonically
/// increases during daemon operation.
///
/// # Metric Categories
///
/// ## DNS Metrics (5 variants)
/// - Cache operations: insertions and evictions
/// - Query routing: forwarded, authoritative, and local answers
///
/// ## DHCP Message Metrics (10 variants)
/// - All DHCPv4 message types per RFC 2131
/// - Covers full DORA (Discover-Offer-Request-Ack) cycle
/// - Includes error cases (DECLINE, NAK)
///
/// ## Legacy Protocol Metrics (2 variants)
/// - BOOTP: Legacy DHCP predecessor support
/// - PXE: Pre-boot execution environment requests
///
/// ## DNS Resolution Metrics (1 variant)
/// - NOANSWER: Queries returning NXDOMAIN or NODATA
///
/// ## Lease Management Metrics (4 variants)
/// - Separate tracking for DHCPv4 and DHCPv6
/// - Allocation: New leases created
/// - Pruning: Expired leases removed
///
/// # Ordering
///
/// The enum variant order matches the C implementation's enum definition for
/// consistency during migration. While Rust enums don't require stable ordering,
/// this alignment simplifies cross-reference with C documentation and debugging.
///
/// # Derive Traits
///
/// - `Debug`: Human-readable debug output (e.g., "DnsQueriesForwarded")
/// - `Clone`: Explicit cloning (typically not needed due to `Copy`)
/// - `Copy`: Cheap bitwise copying for pass-by-value
/// - `PartialEq`/`Eq`: Equality comparison for testing and deduplication
/// - `Hash`: HashMap key usage in metrics collectors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricId {
    /// DNS cache insertions counter
    ///
    /// Tracks successful additions of resource records to the DNS cache.
    /// Incremented when cache_insert() successfully stores a new RR in the
    /// hash table or updates an existing entry with fresh data.
    ///
    /// **Incremented by**: `dns::cache::Cache::insert()`
    /// **C source**: `cache.c`
    DnsCacheInserted,

    /// DNS cache evictions counter
    ///
    /// Tracks removal of live (non-expired) cache entries due to cache size
    /// limits. Incremented during LRU eviction when the cache reaches maximum
    /// capacity and must free space for new entries.
    ///
    /// **Incremented by**: `dns::cache::Cache::evict_lru()`
    /// **C source**: `cache.c`
    DnsCacheLiveFreed,

    /// DNS queries forwarded to upstream servers counter
    ///
    /// Tracks queries sent to upstream DNS servers after cache misses or for
    /// domains requiring external resolution. Incremented for each query
    /// forwarded via UDP or TCP to configured upstream resolvers.
    ///
    /// **Incremented by**: `dns::forwarder::Forwarder::forward_query()`
    /// **C source**: `forward.c`
    DnsQueriesForwarded,

    /// DNS authoritative answers counter
    ///
    /// Tracks queries answered from local authoritative zones when auth feature
    /// is enabled. Incremented when dnsmasq serves as authoritative nameserver
    /// for configured zones.
    ///
    /// **Incremented by**: `dns::auth::AuthoritativeResponder::answer()`
    /// **C source**: `auth.c`
    /// **Requires**: `auth` Cargo feature
    DnsAuthAnswered,

    /// DNS local answers counter
    ///
    /// Tracks queries answered from local sources:
    /// - /etc/hosts entries
    /// - --address configuration directives
    /// - --server domain-specific routing
    /// - Other local configurations without cache or forwarding
    ///
    /// **Incremented by**: `dns::forwarder::Forwarder::answer_locally()`
    /// **C source**: `forward.c`
    DnsLocalAnswered,

    /// BOOTP requests counter (legacy protocol)
    ///
    /// Tracks BOOTP protocol requests (DHCP predecessor). Incremented when
    /// the op field is BOOTREQUEST in received packets. Maintained for
    /// compatibility with legacy network boot environments.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::process_bootp()`
    /// **C source**: `rfc2131.c`
    Bootp,

    /// PXE boot requests counter
    ///
    /// Tracks Pre-boot Execution Environment requests for network boot.
    /// Incremented when DHCP option 93 (client system architecture) is
    /// present in DHCP requests, indicating PXE firmware.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::process_pxe()`
    /// **C source**: `rfc2131.c`
    Pxe,

    /// DHCPACK messages sent counter
    ///
    /// Tracks DHCP acknowledgment messages confirming lease allocation or
    /// renewal. Sent in response to DHCPREQUEST messages when the requested
    /// address is valid and available.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::send_ack()`
    /// **C source**: `rfc2131.c`
    DhcpAck,

    /// DHCPDECLINE messages received counter
    ///
    /// Tracks client rejection of offered IP addresses due to address
    /// conflicts detected via ARP. Indicates that the offered address is
    /// already in use on the network.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::handle_decline()`
    /// **C source**: `rfc2131.c`
    DhcpDecline,

    /// DHCPDISCOVER messages received counter
    ///
    /// Tracks initial broadcast requests from DHCP clients seeking address
    /// allocation. First message in the DORA (Discover-Offer-Request-Ack)
    /// sequence.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::handle_discover()`
    /// **C source**: `rfc2131.c`
    DhcpDiscover,

    /// DHCPINFORM messages received counter
    ///
    /// Tracks requests from clients with manually configured IP addresses
    /// seeking additional configuration parameters (DNS servers, routes, etc.)
    /// without requesting address allocation.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::handle_inform()`
    /// **C source**: `rfc2131.c`
    DhcpInform,

    /// DHCPNAK messages sent counter
    ///
    /// Tracks negative acknowledgments rejecting client DHCPREQUEST due to
    /// invalid requested address, lease expiry, or configuration mismatch.
    /// Forces client to restart DORA sequence.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::send_nak()`
    /// **C source**: `rfc2131.c`
    DhcpNak,

    /// DHCPOFFER messages sent counter
    ///
    /// Tracks offers of IP addresses sent in response to DHCPDISCOVER.
    /// Incremented when an available address is found in the configured
    /// address pools.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::send_offer()`
    /// **C source**: `rfc2131.c`
    DhcpOffer,

    /// DHCPRELEASE messages received counter
    ///
    /// Tracks client notifications of lease termination, allowing early
    /// reclamation of addresses. Clients should send RELEASE when gracefully
    /// shutting down or releasing addresses.
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::handle_release()`
    /// **C source**: `rfc2131.c`
    DhcpRelease,

    /// DHCPREQUEST messages received counter
    ///
    /// Tracks client requests to:
    /// - Accept offered addresses (after DHCPOFFER)
    /// - Renew existing leases (T1 timer expiry)
    /// - Rebind leases (T2 timer expiry)
    ///
    /// **Incremented by**: `dhcp::v4::handler::Handler::handle_request()`
    /// **C source**: `rfc2131.c`
    DhcpRequest,

    /// DNS queries with no answer counter
    ///
    /// Tracks queries that resulted in:
    /// - NXDOMAIN: Name does not exist
    /// - NODATA: Name exists but no records of requested type
    ///
    /// Used for negative caching statistics and query analysis.
    ///
    /// **Incremented by**: `dns::forwarder::Forwarder::record_noanswer()`
    /// **C source**: `forward.c`
    Noanswer,

    /// DHCPv4 leases allocated counter
    ///
    /// Tracks successful IPv4 address allocations from configured address
    /// pools. Incremented when new DHCPv4 lease is created or existing
    /// lease is reused after expiry.
    ///
    /// **Incremented by**: `dhcp::lease::LeaseManager::allocate_v4()`
    /// **C source**: `lease.c`
    LeasesAllocated4,

    /// DHCPv4 leases pruned counter
    ///
    /// Tracks removal of expired or released DHCPv4 leases from the lease
    /// database. Incremented during periodic lease cleanup operations.
    ///
    /// **Incremented by**: `dhcp::lease::LeaseManager::prune_expired_v4()`
    /// **C source**: `lease.c`
    LeasesPruned4,

    /// DHCPv6 leases allocated counter
    ///
    /// Tracks successful IPv6 address or prefix allocations from configured
    /// ranges. Incremented when new DHCPv6 lease is created for:
    /// - IA_NA: Non-temporary addresses
    /// - IA_TA: Temporary addresses
    /// - IA_PD: Prefix delegation
    ///
    /// **Incremented by**: `dhcp::lease::LeaseManager::allocate_v6()`
    /// **C source**: `lease.c`
    LeasesAllocated6,

    /// DHCPv6 leases pruned counter
    ///
    /// Tracks removal of expired or released DHCPv6 leases from the lease
    /// database. Incremented during periodic lease cleanup operations.
    ///
    /// **Incremented by**: `dhcp::lease::LeaseManager::prune_expired_v6()`
    /// **C source**: `lease.c`
    LeasesPruned6,
}

impl MetricId {
    /// Returns the enum variant name as a string
    ///
    /// Provides the Rust enum variant name in CamelCase format. Useful for
    /// debugging, logging, and internal metric identification.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::monitoring::types::MetricId;
    ///
    /// let metric = MetricId::DnsQueriesForwarded;
    /// assert_eq!(metric.as_str(), "DnsQueriesForwarded");
    ///
    /// let metric = MetricId::DhcpAck;
    /// assert_eq!(metric.as_str(), "DhcpAck");
    /// ```
    ///
    /// # Returns
    ///
    /// Static string slice containing the enum variant name. The returned
    /// string has `'static` lifetime and requires no allocation.
    pub fn as_str(&self) -> &'static str {
        match self {
            MetricId::DnsCacheInserted => "DnsCacheInserted",
            MetricId::DnsCacheLiveFreed => "DnsCacheLiveFreed",
            MetricId::DnsQueriesForwarded => "DnsQueriesForwarded",
            MetricId::DnsAuthAnswered => "DnsAuthAnswered",
            MetricId::DnsLocalAnswered => "DnsLocalAnswered",
            MetricId::Bootp => "Bootp",
            MetricId::Pxe => "Pxe",
            MetricId::DhcpAck => "DhcpAck",
            MetricId::DhcpDecline => "DhcpDecline",
            MetricId::DhcpDiscover => "DhcpDiscover",
            MetricId::DhcpInform => "DhcpInform",
            MetricId::DhcpNak => "DhcpNak",
            MetricId::DhcpOffer => "DhcpOffer",
            MetricId::DhcpRelease => "DhcpRelease",
            MetricId::DhcpRequest => "DhcpRequest",
            MetricId::Noanswer => "Noanswer",
            MetricId::LeasesAllocated4 => "LeasesAllocated4",
            MetricId::LeasesPruned4 => "LeasesPruned4",
            MetricId::LeasesAllocated6 => "LeasesAllocated6",
            MetricId::LeasesPruned6 => "LeasesPruned6",
        }
    }

    /// Converts metric ID to Prometheus metric name
    ///
    /// Returns the metric name in Prometheus text exposition format:
    /// - Lowercase letters and digits
    /// - Underscores separating words
    /// - `_total` suffix for counter metrics (per Prometheus best practices)
    ///
    /// This method replaces the C implementation's `get_metric_name()` function,
    /// providing compile-time guaranteed correct metric naming.
    ///
    /// # Prometheus Naming Conventions
    ///
    /// All returned names conform to Prometheus requirements:
    /// - Start with a letter or underscore
    /// - Contain only `[a-z0-9_]` characters
    /// - Counter metrics end with `_total`
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::monitoring::types::MetricId;
    ///
    /// let metric = MetricId::DnsQueriesForwarded;
    /// assert_eq!(metric.to_prometheus_name(), "dns_queries_forwarded_total");
    ///
    /// let metric = MetricId::DhcpDiscover;
    /// assert_eq!(metric.to_prometheus_name(), "dhcp_discover_total");
    ///
    /// let metric = MetricId::LeasesAllocated6;
    /// assert_eq!(metric.to_prometheus_name(), "leases_allocated_6_total");
    /// ```
    ///
    /// # Returns
    ///
    /// Static string slice containing the Prometheus-formatted metric name.
    /// The returned string has `'static` lifetime and requires no allocation.
    ///
    /// # C Interoperability
    ///
    /// Equivalent to C function: `const char* get_metric_name(int metric_id)`
    /// defined in `src/metrics.h` and implemented in `src/metrics.c`.
    pub fn to_prometheus_name(&self) -> &'static str {
        match self {
            MetricId::DnsCacheInserted => "dns_cache_inserted_total",
            MetricId::DnsCacheLiveFreed => "dns_cache_live_freed_total",
            MetricId::DnsQueriesForwarded => "dns_queries_forwarded_total",
            MetricId::DnsAuthAnswered => "dns_auth_answered_total",
            MetricId::DnsLocalAnswered => "dns_local_answered_total",
            MetricId::Bootp => "bootp_total",
            MetricId::Pxe => "pxe_total",
            MetricId::DhcpAck => "dhcp_ack_total",
            MetricId::DhcpDecline => "dhcp_decline_total",
            MetricId::DhcpDiscover => "dhcp_discover_total",
            MetricId::DhcpInform => "dhcp_inform_total",
            MetricId::DhcpNak => "dhcp_nak_total",
            MetricId::DhcpOffer => "dhcp_offer_total",
            MetricId::DhcpRelease => "dhcp_release_total",
            MetricId::DhcpRequest => "dhcp_request_total",
            MetricId::Noanswer => "noanswer_total",
            MetricId::LeasesAllocated4 => "leases_allocated_4_total",
            MetricId::LeasesPruned4 => "leases_pruned_4_total",
            MetricId::LeasesAllocated6 => "leases_allocated_6_total",
            MetricId::LeasesPruned6 => "leases_pruned_6_total",
        }
    }

    /// Returns an iterator over all metric IDs
    ///
    /// Provides a type-safe replacement for the C implementation's `__METRIC_MAX`
    /// sentinel value. Useful for:
    /// - Initializing metric collectors with all metrics
    /// - Generating metric documentation
    /// - Exporting complete metric sets
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::monitoring::types::MetricId;
    /// use std::collections::HashMap;
    ///
    /// // Initialize metric counters
    /// let mut counters = HashMap::new();
    /// for metric in MetricId::all() {
    ///     counters.insert(*metric, 0u64);
    /// }
    ///
    /// // Export all metrics
    /// for metric in MetricId::all() {
    ///     println!("{} 0", metric.to_prometheus_name());
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// Slice containing all 20 metric IDs in definition order. The returned
    /// slice has `'static` lifetime as it references a constant array.
    ///
    /// # C Interoperability
    ///
    /// Replaces C pattern:
    /// ```c
    /// for (int i = 0; i < __METRIC_MAX; i++) {
    ///     const char *name = get_metric_name(i);
    ///     // ... process metric
    /// }
    /// ```
    ///
    /// Rust equivalent:
    /// ```rust,ignore
    /// for metric in MetricId::all() {
    ///     let name = metric.to_prometheus_name();
    ///     // ... process metric
    /// }
    /// ```
    ///
    /// # Performance
    ///
    /// Zero-cost abstraction: returns a reference to a static array, no
    /// runtime allocation or computation required.
    pub fn all() -> &'static [MetricId] {
        &[
            MetricId::DnsCacheInserted,
            MetricId::DnsCacheLiveFreed,
            MetricId::DnsQueriesForwarded,
            MetricId::DnsAuthAnswered,
            MetricId::DnsLocalAnswered,
            MetricId::Bootp,
            MetricId::Pxe,
            MetricId::DhcpAck,
            MetricId::DhcpDecline,
            MetricId::DhcpDiscover,
            MetricId::DhcpInform,
            MetricId::DhcpNak,
            MetricId::DhcpOffer,
            MetricId::DhcpRelease,
            MetricId::DhcpRequest,
            MetricId::Noanswer,
            MetricId::LeasesAllocated4,
            MetricId::LeasesPruned4,
            MetricId::LeasesAllocated6,
            MetricId::LeasesPruned6,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_str_returns_variant_names() {
        assert_eq!(MetricId::DnsCacheInserted.as_str(), "DnsCacheInserted");
        assert_eq!(MetricId::DnsQueriesForwarded.as_str(), "DnsQueriesForwarded");
        assert_eq!(MetricId::DhcpAck.as_str(), "DhcpAck");
        assert_eq!(MetricId::LeasesAllocated4.as_str(), "LeasesAllocated4");
    }

    #[test]
    fn test_to_prometheus_name_follows_conventions() {
        // Verify lowercase with underscores
        assert_eq!(
            MetricId::DnsCacheInserted.to_prometheus_name(),
            "dns_cache_inserted_total"
        );
        assert_eq!(
            MetricId::DnsQueriesForwarded.to_prometheus_name(),
            "dns_queries_forwarded_total"
        );

        // Verify _total suffix for counters
        assert!(MetricId::DhcpAck.to_prometheus_name().ends_with("_total"));
        assert!(MetricId::Bootp.to_prometheus_name().ends_with("_total"));

        // Verify numeric suffixes preserved
        assert_eq!(
            MetricId::LeasesAllocated4.to_prometheus_name(),
            "leases_allocated_4_total"
        );
        assert_eq!(
            MetricId::LeasesPruned6.to_prometheus_name(),
            "leases_pruned_6_total"
        );
    }

    #[test]
    fn test_all_returns_complete_metric_set() {
        let all_metrics = MetricId::all();

        // Verify count matches C implementation (20 metrics)
        assert_eq!(all_metrics.len(), 20);

        // Verify no duplicates
        use std::collections::HashSet;
        let unique_metrics: HashSet<_> = all_metrics.iter().collect();
        assert_eq!(unique_metrics.len(), 20);

        // Verify all categories present
        assert!(all_metrics.contains(&MetricId::DnsCacheInserted));
        assert!(all_metrics.contains(&MetricId::DhcpDiscover));
        assert!(all_metrics.contains(&MetricId::Bootp));
        assert!(all_metrics.contains(&MetricId::Pxe));
        assert!(all_metrics.contains(&MetricId::Noanswer));
        assert!(all_metrics.contains(&MetricId::LeasesAllocated4));
        assert!(all_metrics.contains(&MetricId::LeasesAllocated6));
    }

    #[test]
    fn test_prometheus_names_are_unique() {
        use std::collections::HashSet;

        let names: HashSet<_> = MetricId::all()
            .iter()
            .map(|m| m.to_prometheus_name())
            .collect();

        // All metric names must be unique
        assert_eq!(names.len(), 20);
    }

    #[test]
    fn test_enum_traits() {
        let metric1 = MetricId::DnsQueriesForwarded;
        let metric2 = MetricId::DnsQueriesForwarded;
        let metric3 = MetricId::DhcpAck;

        // Test Copy
        let copied = metric1;
        assert_eq!(copied, metric1);

        // Test Clone
        let cloned = metric1.clone();
        assert_eq!(cloned, metric1);

        // Test PartialEq
        assert_eq!(metric1, metric2);
        assert_ne!(metric1, metric3);

        // Test Hash (can be used as HashMap key)
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(metric1, 42);
        assert_eq!(map.get(&metric2), Some(&42));

        // Test Debug
        let debug_str = format!("{:?}", metric1);
        assert!(debug_str.contains("DnsQueriesForwarded"));
    }

    #[test]
    fn test_dhcp_message_types_complete() {
        // Verify all DHCPv4 message types present (RFC 2131)
        let dhcp_metrics = [
            MetricId::DhcpDiscover,
            MetricId::DhcpOffer,
            MetricId::DhcpRequest,
            MetricId::DhcpAck,
            MetricId::DhcpNak,
            MetricId::DhcpDecline,
            MetricId::DhcpRelease,
            MetricId::DhcpInform,
        ];

        for metric in &dhcp_metrics {
            assert!(MetricId::all().contains(metric));
        }
    }

    #[test]
    fn test_dns_metrics_complete() {
        // Verify all DNS operation types present
        let dns_metrics = [
            MetricId::DnsCacheInserted,
            MetricId::DnsCacheLiveFreed,
            MetricId::DnsQueriesForwarded,
            MetricId::DnsAuthAnswered,
            MetricId::DnsLocalAnswered,
        ];

        for metric in &dns_metrics {
            assert!(MetricId::all().contains(metric));
        }
    }

    #[test]
    fn test_lease_metrics_complete() {
        // Verify all lease tracking metrics present (v4 and v6)
        let lease_metrics = [
            MetricId::LeasesAllocated4,
            MetricId::LeasesPruned4,
            MetricId::LeasesAllocated6,
            MetricId::LeasesPruned6,
        ];

        for metric in &lease_metrics {
            assert!(MetricId::all().contains(metric));
        }
    }
}
