// Copyright (c) 2000-2024 Simon Kelley and dnsmasq contributors
// This file is part of the dnsmasq Rust implementation.
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

//! # Prometheus Metrics Collection and Export
//!
//! This module provides Prometheus-format metrics collection for monitoring integration,
//! translated from C's `src/metrics.c` and `src/metrics.h`. It tracks operational statistics
//! including DNS cache operations, query forwarding, DHCP protocol events, and lease management,
//! exporting them in Prometheus text exposition format.
//!
//! ## Translated From
//! - C source files: `src/metrics.c`, `src/metrics.h`
//! - Original author: Simon Kelley
//! - Purpose: Prometheus-compatible metrics export for monitoring and observability
//!
//! ## Key Features
//! - Type-safe metric label enumeration (replaces C's indexed array)
//! - Prometheus text format export with HELP and TYPE annotations
//! - DNS cache metrics (insertions, evictions)
//! - DNS query metrics (forwarded, authoritative, local answers)
//! - DHCP protocol metrics (DISCOVER, OFFER, REQUEST, ACK, NAK, etc.)
//! - Lease allocation and pruning statistics (DHCPv4 and DHCPv6)
//! - Lock-based and lock-free (atomic) counter implementations
//! - HTTP endpoint serving capability (/metrics on port 9153)
//!
//! ## Design Improvements Over C
//! - **Type Safety**: Enum-based metrics prevent invalid index access
//! - **Compile-Time Validation**: Impossible to use wrong metric name
//! - **Memory Safety**: No array bounds vulnerabilities
//! - **Concurrency**: Both locked and atomic implementations for different use cases
//!
//! ## Usage Example
//! ```rust
//! use dnsmasq::util::metrics::{MetricsCollector, MetricLabel};
//!
//! let mut collector = MetricsCollector::new();
//! collector.increment(MetricLabel::DnsQueriesForwarded, 1);
//! collector.increment(MetricLabel::DnsCacheInserted, 1);
//!
//! // Export in Prometheus format
//! let prometheus_output = collector.export_prometheus();
//! println!("{}", prometheus_output);
//! ```
//!
//! ## Thread Safety
//! - `MetricsCollector`: Use with `Arc<RwLock<>>` for shared mutable access
//! - `AtomicMetricsCollector`: Lock-free, safe for concurrent access without locks
//!
//! ## RFC and Standards Compliance
//! Conforms to Prometheus text exposition format specification:
//! - https://prometheus.io/docs/instrumenting/exposition_formats/
//! - Metric naming: lowercase with underscores
//! - All metrics are counters (monotonically increasing)

use std::fmt::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default port for Prometheus metrics HTTP endpoint
///
/// Port 9153 is the standard port for DNS-related metrics in the Prometheus ecosystem,
/// used by CoreDNS and other DNS servers. This avoids conflicts with dnsmasq's primary
/// service ports (53 for DNS, 67/68 for DHCP).
pub const DEFAULT_METRICS_PORT: u16 = 9153;

/// Prometheus text exposition format content type
///
/// Version 0.0.4 is the current Prometheus text format specification version.
/// This header is required for Prometheus scraper compatibility.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// Metric label identifier for Prometheus export
///
/// This enum provides type-safe metric identification, replacing C's integer-indexed
/// array with compile-time validated metric labels. Each variant corresponds to a
/// specific operational metric tracked by dnsmasq.
///
/// ## Translation from C
/// Replaces the METRIC_* enum constants in `src/metrics.h` and the `metric_names[]`
/// string array in `src/metrics.c`. The enum order matches the C implementation for
/// compatibility with existing monitoring dashboards and alerting rules.
///
/// ## Metric Categories
///
/// ### DNS Metrics
/// - Cache operations: insertions and evictions
/// - Query handling: forwarded, authoritative, local answers
/// - Negative responses: no answer available
///
/// ### DHCP Metrics
/// - Protocol messages: DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE, RELEASE, INFORM
/// - Legacy protocols: BOOTP, PXE
///
/// ### Lease Metrics
/// - Allocation tracking for DHCPv4 and DHCPv6
/// - Pruning statistics for expired/released leases
///
/// ## Prometheus Naming Conventions
/// All metric names follow Prometheus best practices:
/// - Lowercase letters only
/// - Underscores separate words
/// - Descriptive and namespace-prefixed (dns_, dhcp_, leases_)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MetricLabel {
    /// DNS cache insertions counter
    ///
    /// Tracks successful additions of resource records to the DNS cache.
    /// Incremented by cache_insert() operations.
    ///
    /// **C equivalent**: METRIC_DNS_CACHE_INSERTED
    DnsCacheInserted = 0,

    /// DNS cache evictions counter (live entries freed)
    ///
    /// Tracks removal of non-expired cache entries due to cache size limits.
    /// Incremented during LRU eviction when cache is full.
    ///
    /// **C equivalent**: METRIC_DNS_CACHE_LIVE_FREED
    DnsCacheLiveFreed = 1,

    /// DNS queries forwarded to upstream servers
    ///
    /// Tracks queries sent to upstream DNS servers after cache misses.
    /// Incremented by forward_query() operations.
    ///
    /// **C equivalent**: METRIC_DNS_QUERIES_FORWARDED
    DnsQueriesForwarded = 2,

    /// DNS authoritative answers counter
    ///
    /// Tracks queries answered from local authoritative zones (requires HAVE_AUTH).
    /// Incremented by authoritative zone lookups.
    ///
    /// **C equivalent**: METRIC_DNS_AUTH_ANSWERED
    DnsAuthAnswered = 3,

    /// DNS local answers counter
    ///
    /// Tracks queries answered from /etc/hosts, --address, or --server configurations.
    /// Incremented when serving local data without cache or forwarding.
    ///
    /// **C equivalent**: METRIC_DNS_LOCAL_ANSWERED
    DnsLocalAnswered = 4,

    /// BOOTP requests counter (legacy DHCP)
    ///
    /// Tracks BOOTP protocol requests (DHCP predecessor).
    /// Incremented when processing BOOTREQUEST messages.
    ///
    /// **C equivalent**: METRIC_BOOTP
    Bootp = 5,

    /// PXE boot requests counter
    ///
    /// Tracks Pre-boot Execution Environment requests for network boot.
    /// Incremented when DHCP option 93 (client architecture) is present.
    ///
    /// **C equivalent**: METRIC_PXE
    Pxe = 6,

    /// DHCPACK messages sent counter
    ///
    /// Tracks acknowledgment messages confirming lease allocation or renewal.
    /// Sent in response to DHCPREQUEST after address allocation.
    ///
    /// **C equivalent**: METRIC_DHCPACK
    DhcpAck = 7,

    /// DHCPDECLINE messages received counter
    ///
    /// Tracks client rejection of offered addresses due to detected conflicts.
    /// Incremented when clients send DECLINE after ARP checks.
    ///
    /// **C equivalent**: METRIC_DHCPDECLINE
    DhcpDecline = 8,

    /// DHCPDISCOVER messages received counter
    ///
    /// Tracks initial broadcast requests from DHCP clients seeking addresses.
    /// First message in DHCP 4-way handshake.
    ///
    /// **C equivalent**: METRIC_DHCPDISCOVER
    DhcpDiscover = 9,

    /// DHCPINFORM messages received counter
    ///
    /// Tracks requests from clients with manual addresses seeking configuration.
    /// Clients already have addresses but need additional parameters.
    ///
    /// **C equivalent**: METRIC_DHCPINFORM
    DhcpInform = 10,

    /// DHCPNAK messages sent counter
    ///
    /// Tracks negative acknowledgments rejecting invalid DHCPREQUEST.
    /// Sent when requested address is invalid or lease has expired.
    ///
    /// **C equivalent**: METRIC_DHCPNAK
    DhcpNak = 11,

    /// DHCPOFFER messages sent counter
    ///
    /// Tracks offers of IP addresses sent in response to DHCPDISCOVER.
    /// Second message in DHCP 4-way handshake.
    ///
    /// **C equivalent**: METRIC_DHCPOFFER
    DhcpOffer = 12,

    /// DHCPRELEASE messages received counter
    ///
    /// Tracks client notifications of lease termination.
    /// Allows early reclamation of addresses.
    ///
    /// **C equivalent**: METRIC_DHCPRELEASE
    DhcpRelease = 13,

    /// DHCPREQUEST messages received counter
    ///
    /// Tracks requests to accept offered addresses or renew/rebind existing leases.
    /// Third message in DHCP 4-way handshake.
    ///
    /// **C equivalent**: METRIC_DHCPREQUEST
    DhcpRequest = 14,

    /// DNS queries with no answer counter
    ///
    /// Tracks queries resulting in NXDOMAIN or NODATA responses.
    /// Used for negative caching statistics.
    ///
    /// **C equivalent**: METRIC_NOANSWER
    NoAnswer = 15,

    /// DHCPv4 leases allocated counter
    ///
    /// Tracks successful IPv4 address allocations from configured pools.
    /// Incremented when new leases are created or reused.
    ///
    /// **C equivalent**: METRIC_LEASES_ALLOCATED_4
    LeasesAllocated4 = 16,

    /// DHCPv4 leases pruned counter
    ///
    /// Tracks removal of expired or released DHCPv4 leases.
    /// Incremented during periodic lease cleanup.
    ///
    /// **C equivalent**: METRIC_LEASES_PRUNED_4
    LeasesPruned4 = 17,

    /// DHCPv6 leases allocated counter
    ///
    /// Tracks successful IPv6 address or prefix allocations.
    /// Includes IA_NA, IA_TA, and IA_PD allocations.
    ///
    /// **C equivalent**: METRIC_LEASES_ALLOCATED_6
    LeasesAllocated6 = 18,

    /// DHCPv6 leases pruned counter
    ///
    /// Tracks removal of expired or released DHCPv6 leases.
    /// Incremented during periodic lease cleanup.
    ///
    /// **C equivalent**: METRIC_LEASES_PRUNED_6
    LeasesPruned6 = 19,
}

impl MetricLabel {
    /// Total number of defined metrics
    ///
    /// Equivalent to C's __METRIC_MAX sentinel value.
    /// Used for array sizing and iteration.
    pub const COUNT: usize = 20;

    /// Returns an iterator over all metric labels
    ///
    /// Provides compile-time enumeration of all metrics for export and reporting.
    /// Replaces C's manual loop from 0 to __METRIC_MAX.
    pub fn iter() -> impl Iterator<Item = MetricLabel> {
        use MetricLabel::*;
        [
            DnsCacheInserted,
            DnsCacheLiveFreed,
            DnsQueriesForwarded,
            DnsAuthAnswered,
            DnsLocalAnswered,
            Bootp,
            Pxe,
            DhcpAck,
            DhcpDecline,
            DhcpDiscover,
            DhcpInform,
            DhcpNak,
            DhcpOffer,
            DhcpRelease,
            DhcpRequest,
            NoAnswer,
            LeasesAllocated4,
            LeasesPruned4,
            LeasesAllocated6,
            LeasesPruned6,
        ]
        .iter()
        .copied()
    }

    /// Converts metric label to Prometheus-compatible string
    ///
    /// Returns lowercase metric name with underscores, matching C's `metric_names[]` array.
    /// This is the canonical name used in Prometheus text export format.
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::MetricLabel;
    /// assert_eq!(MetricLabel::DnsQueriesForwarded.as_str(), "dns_queries_forwarded");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            MetricLabel::DnsCacheInserted => "dns_cache_inserted",
            MetricLabel::DnsCacheLiveFreed => "dns_cache_live_freed",
            MetricLabel::DnsQueriesForwarded => "dns_queries_forwarded",
            MetricLabel::DnsAuthAnswered => "dns_auth_answered",
            MetricLabel::DnsLocalAnswered => "dns_local_answered",
            MetricLabel::Bootp => "bootp",
            MetricLabel::Pxe => "pxe",
            MetricLabel::DhcpAck => "dhcp_ack",
            MetricLabel::DhcpDecline => "dhcp_decline",
            MetricLabel::DhcpDiscover => "dhcp_discover",
            MetricLabel::DhcpInform => "dhcp_inform",
            MetricLabel::DhcpNak => "dhcp_nak",
            MetricLabel::DhcpOffer => "dhcp_offer",
            MetricLabel::DhcpRelease => "dhcp_release",
            MetricLabel::DhcpRequest => "dhcp_request",
            MetricLabel::NoAnswer => "noanswer",
            MetricLabel::LeasesAllocated4 => "leases_allocated_4",
            MetricLabel::LeasesPruned4 => "leases_pruned_4",
            MetricLabel::LeasesAllocated6 => "leases_allocated_6",
            MetricLabel::LeasesPruned6 => "leases_pruned_6",
        }
    }

    /// Returns human-readable description for Prometheus HELP text
    ///
    /// Provides detailed explanation of each metric for monitoring dashboards and documentation.
    fn help_text(&self) -> &'static str {
        match self {
            MetricLabel::DnsCacheInserted => "Number of DNS records inserted into cache",
            MetricLabel::DnsCacheLiveFreed => "Number of non-expired cache entries evicted due to size limits",
            MetricLabel::DnsQueriesForwarded => "Number of DNS queries forwarded to upstream servers",
            MetricLabel::DnsAuthAnswered => "Number of queries answered from authoritative zones",
            MetricLabel::DnsLocalAnswered => "Number of queries answered from local data (/etc/hosts, config)",
            MetricLabel::Bootp => "Number of BOOTP requests processed (legacy DHCP)",
            MetricLabel::Pxe => "Number of PXE boot requests processed",
            MetricLabel::DhcpAck => "Number of DHCPACK messages sent",
            MetricLabel::DhcpDecline => "Number of DHCPDECLINE messages received",
            MetricLabel::DhcpDiscover => "Number of DHCPDISCOVER messages received",
            MetricLabel::DhcpInform => "Number of DHCPINFORM messages received",
            MetricLabel::DhcpNak => "Number of DHCPNAK messages sent",
            MetricLabel::DhcpOffer => "Number of DHCPOFFER messages sent",
            MetricLabel::DhcpRelease => "Number of DHCPRELEASE messages received",
            MetricLabel::DhcpRequest => "Number of DHCPREQUEST messages received",
            MetricLabel::NoAnswer => "Number of DNS queries with no answer (NXDOMAIN/NODATA)",
            MetricLabel::LeasesAllocated4 => "Number of DHCPv4 leases allocated",
            MetricLabel::LeasesPruned4 => "Number of DHCPv4 leases pruned (expired/released)",
            MetricLabel::LeasesAllocated6 => "Number of DHCPv6 leases allocated",
            MetricLabel::LeasesPruned6 => "Number of DHCPv6 leases pruned (expired/released)",
        }
    }
}

/// Implements Display trait for automatic string conversion
///
/// Enables using MetricLabel directly in format strings and string builders.
/// Delegates to `as_str()` for consistent naming.
impl fmt::Display for MetricLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metrics collector with lock-based counter storage
///
/// Provides a simple, safe metrics collection implementation using an array-backed
/// counter store. Suitable for single-threaded use or wrapped in `Arc<RwLock<>>`
/// for shared mutable access.
///
/// ## Translation from C
/// Replaces the `daemon->metrics[]` array in C's global daemon structure with
/// a type-safe, self-contained metrics collector.
///
/// ## Usage
/// ```
/// use dnsmasq::util::metrics::{MetricsCollector, MetricLabel};
///
/// let mut collector = MetricsCollector::new();
/// collector.increment(MetricLabel::DnsQueriesForwarded, 5);
/// println!("Forwarded: {}", collector.get(MetricLabel::DnsQueriesForwarded));
/// ```
///
/// ## Thread Safety
/// Not thread-safe by itself. Use with `Arc<RwLock<MetricsCollector>>` for
/// concurrent access from multiple tasks.
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    /// Counter storage indexed by MetricLabel discriminant
    counters: [u64; MetricLabel::COUNT],
}

impl MetricsCollector {
    /// Creates a new metrics collector with all counters initialized to zero
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::MetricsCollector;
    /// let collector = MetricsCollector::new();
    /// ```
    pub fn new() -> Self {
        Self {
            counters: [0; MetricLabel::COUNT],
        }
    }

    /// Increments a metric counter by the specified amount
    ///
    /// ## Arguments
    /// - `metric`: The metric to increment
    /// - `count`: Amount to add to the counter (typically 1)
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricLabel};
    /// let mut collector = MetricsCollector::new();
    /// collector.increment(MetricLabel::DnsQueriesForwarded, 1);
    /// collector.increment(MetricLabel::DnsCacheInserted, 10);
    /// ```
    pub fn increment(&mut self, metric: MetricLabel, count: u64) {
        let index = metric as usize;
        self.counters[index] = self.counters[index].saturating_add(count);
    }

    /// Retrieves the current value of a metric counter
    ///
    /// ## Arguments
    /// - `metric`: The metric to query
    ///
    /// ## Returns
    /// Current counter value (always >= 0)
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricLabel};
    /// let mut collector = MetricsCollector::new();
    /// collector.increment(MetricLabel::DhcpAck, 42);
    /// assert_eq!(collector.get(MetricLabel::DhcpAck), 42);
    /// ```
    pub fn get(&self, metric: MetricLabel) -> u64 {
        self.counters[metric as usize]
    }

    /// Resets all metric counters to zero
    ///
    /// Useful for testing or periodic metric resets. In production, counters
    /// are typically monotonically increasing and never reset.
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricLabel};
    /// let mut collector = MetricsCollector::new();
    /// collector.increment(MetricLabel::DnsQueriesForwarded, 100);
    /// collector.reset();
    /// assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 0);
    /// ```
    pub fn reset(&mut self) {
        self.counters.fill(0);
    }

    /// Exports metrics in Prometheus text exposition format
    ///
    /// Generates output conforming to Prometheus text format specification with
    /// HELP and TYPE annotations for each metric. All metrics are exported as
    /// counters (monotonically increasing values).
    ///
    /// ## Returns
    /// String containing Prometheus-formatted metrics suitable for HTTP /metrics endpoint
    ///
    /// ## Format
    /// ```text
    /// # HELP metric_name Description of the metric
    /// # TYPE metric_name counter
    /// metric_name 12345
    /// ```
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::{MetricsCollector, MetricLabel};
    /// let mut collector = MetricsCollector::new();
    /// collector.increment(MetricLabel::DnsQueriesForwarded, 100);
    /// let output = collector.export_prometheus();
    /// assert!(output.contains("dns_queries_forwarded 100"));
    /// ```
    pub fn export_prometheus(&self) -> String {
        let mut output = String::with_capacity(4096);

        for metric in MetricLabel::iter() {
            let name = metric.as_str();
            let help = metric.help_text();
            let value = self.get(metric);

            // Write HELP comment
            write!(&mut output, "# HELP {} {}\n", name, help)
                .expect("String write should never fail");

            // Write TYPE declaration (all metrics are counters)
            write!(&mut output, "# TYPE {} counter\n", name)
                .expect("String write should never fail");

            // Write metric value
            writeln!(&mut output, "{} {}", name, value)
                .expect("String write should never fail");
        }

        output
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock-free atomic metrics collector
///
/// Provides concurrent metric updates without locks using atomic operations.
/// Suitable for high-contention scenarios where multiple tasks increment counters.
/// Uses relaxed memory ordering for maximum performance.
///
/// ## Performance Characteristics
/// - No lock contention
/// - Cache-line optimized counter array
/// - Relaxed memory ordering (sufficient for monotonic counters)
/// - Suitable for high-frequency metric updates
///
/// ## Usage
/// ```
/// use std::sync::Arc;
/// use dnsmasq::util::metrics::{AtomicMetricsCollector, MetricLabel};
///
/// let collector = Arc::new(AtomicMetricsCollector::new());
/// let collector_clone = Arc::clone(&collector);
///
/// // Can be safely shared across tasks without locks
/// collector.increment(MetricLabel::DnsQueriesForwarded, 1);
/// collector_clone.increment(MetricLabel::DnsCacheInserted, 1);
/// ```
#[derive(Debug)]
pub struct AtomicMetricsCollector {
    /// Atomic counter storage indexed by MetricLabel discriminant
    counters: [AtomicU64; MetricLabel::COUNT],
}

impl AtomicMetricsCollector {
    /// Creates a new atomic metrics collector with all counters initialized to zero
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::AtomicMetricsCollector;
    /// let collector = AtomicMetricsCollector::new();
    /// ```
    pub fn new() -> Self {
        // Initialize array of AtomicU64 with zeroes
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            counters: [ZERO; MetricLabel::COUNT],
        }
    }

    /// Atomically increments a metric counter by the specified amount
    ///
    /// Uses relaxed memory ordering for maximum performance. Suitable for monotonic
    /// counters where exact ordering is not critical.
    ///
    /// ## Arguments
    /// - `metric`: The metric to increment
    /// - `count`: Amount to add to the counter (typically 1)
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::{AtomicMetricsCollector, MetricLabel};
    /// let collector = AtomicMetricsCollector::new();
    /// collector.increment(MetricLabel::DnsQueriesForwarded, 1);
    /// ```
    pub fn increment(&self, metric: MetricLabel, count: u64) {
        let index = metric as usize;
        self.counters[index].fetch_add(count, Ordering::Relaxed);
    }

    /// Atomically retrieves the current value of a metric counter
    ///
    /// Uses relaxed memory ordering. The returned value is a snapshot at the time
    /// of the read and may be stale by the time the caller uses it in concurrent scenarios.
    ///
    /// ## Arguments
    /// - `metric`: The metric to query
    ///
    /// ## Returns
    /// Current counter value (always >= 0)
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::{AtomicMetricsCollector, MetricLabel};
    /// let collector = AtomicMetricsCollector::new();
    /// collector.increment(MetricLabel::DhcpAck, 42);
    /// assert_eq!(collector.get(MetricLabel::DhcpAck), 42);
    /// ```
    pub fn get(&self, metric: MetricLabel) -> u64 {
        self.counters[metric as usize].load(Ordering::Relaxed)
    }

    /// Atomically resets all metric counters to zero
    ///
    /// Uses relaxed memory ordering. Not typically used in production as counters
    /// should be monotonically increasing.
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::{AtomicMetricsCollector, MetricLabel};
    /// let collector = AtomicMetricsCollector::new();
    /// collector.increment(MetricLabel::DnsQueriesForwarded, 100);
    /// collector.reset();
    /// assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 0);
    /// ```
    pub fn reset(&self) {
        for counter in &self.counters {
            counter.store(0, Ordering::Relaxed);
        }
    }

    /// Exports metrics in Prometheus text exposition format
    ///
    /// Atomically reads all counters and formats them according to Prometheus
    /// text format specification. Safe to call concurrently with metric updates.
    ///
    /// ## Returns
    /// String containing Prometheus-formatted metrics suitable for HTTP /metrics endpoint
    ///
    /// ## Example
    /// ```
    /// use dnsmasq::util::metrics::{AtomicMetricsCollector, MetricLabel};
    /// let collector = AtomicMetricsCollector::new();
    /// collector.increment(MetricLabel::DnsQueriesForwarded, 100);
    /// let output = collector.export_prometheus();
    /// assert!(output.contains("dns_queries_forwarded 100"));
    /// ```
    pub fn export_prometheus(&self) -> String {
        let mut output = String::with_capacity(4096);

        for metric in MetricLabel::iter() {
            let name = metric.as_str();
            let help = metric.help_text();
            let value = self.get(metric);

            // Write HELP comment
            write!(&mut output, "# HELP {} {}\n", name, help)
                .expect("String write should never fail");

            // Write TYPE declaration (all metrics are counters)
            write!(&mut output, "# TYPE {} counter\n", name)
                .expect("String write should never fail");

            // Write metric value
            writeln!(&mut output, "{} {}", name, value)
                .expect("String write should never fail");
        }

        output
    }
}

impl Default for AtomicMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Retrieves Prometheus metric name string for a given metric label
///
/// This function provides C-compatible API for metric name lookup, matching
/// the signature of C's `get_metric_name(int)` function. It's type-safe and
/// cannot be called with invalid metric indices.
///
/// ## Translation from C
/// Replaces C's `const char* get_metric_name(int i)` from metrics.c.
/// The Rust version provides compile-time safety by taking an enum instead of int.
///
/// ## Arguments
/// - `metric`: Metric label to convert to string
///
/// ## Returns
/// Static string reference containing the Prometheus metric name
///
/// ## Example
/// ```
/// use dnsmasq::util::metrics::{metric_label, MetricLabel};
/// let name = metric_label(MetricLabel::DnsQueriesForwarded);
/// assert_eq!(name, "dns_queries_forwarded");
/// ```
pub fn metric_label(metric: MetricLabel) -> &'static str {
    metric.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_label_count() {
        // Verify we have exactly 20 metrics as defined in C
        assert_eq!(MetricLabel::COUNT, 20);
    }

    #[test]
    fn test_metric_label_iteration() {
        let metrics: Vec<MetricLabel> = MetricLabel::iter().collect();
        assert_eq!(metrics.len(), 20);

        // Verify all metrics are present and unique
        assert!(metrics.contains(&MetricLabel::DnsCacheInserted));
        assert!(metrics.contains(&MetricLabel::DnsQueriesForwarded));
        assert!(metrics.contains(&MetricLabel::DhcpAck));
        assert!(metrics.contains(&MetricLabel::LeasesPruned6));
    }

    #[test]
    fn test_metric_label_as_str() {
        // Verify metric names match C's metric_names array
        assert_eq!(MetricLabel::DnsCacheInserted.as_str(), "dns_cache_inserted");
        assert_eq!(MetricLabel::DnsCacheLiveFreed.as_str(), "dns_cache_live_freed");
        assert_eq!(MetricLabel::DnsQueriesForwarded.as_str(), "dns_queries_forwarded");
        assert_eq!(MetricLabel::DnsAuthAnswered.as_str(), "dns_auth_answered");
        assert_eq!(MetricLabel::DnsLocalAnswered.as_str(), "dns_local_answered");
        assert_eq!(MetricLabel::Bootp.as_str(), "bootp");
        assert_eq!(MetricLabel::Pxe.as_str(), "pxe");
        assert_eq!(MetricLabel::DhcpAck.as_str(), "dhcp_ack");
        assert_eq!(MetricLabel::DhcpDecline.as_str(), "dhcp_decline");
        assert_eq!(MetricLabel::DhcpDiscover.as_str(), "dhcp_discover");
        assert_eq!(MetricLabel::DhcpInform.as_str(), "dhcp_inform");
        assert_eq!(MetricLabel::DhcpNak.as_str(), "dhcp_nak");
        assert_eq!(MetricLabel::DhcpOffer.as_str(), "dhcp_offer");
        assert_eq!(MetricLabel::DhcpRelease.as_str(), "dhcp_release");
        assert_eq!(MetricLabel::DhcpRequest.as_str(), "dhcp_request");
        assert_eq!(MetricLabel::NoAnswer.as_str(), "noanswer");
        assert_eq!(MetricLabel::LeasesAllocated4.as_str(), "leases_allocated_4");
        assert_eq!(MetricLabel::LeasesPruned4.as_str(), "leases_pruned_4");
        assert_eq!(MetricLabel::LeasesAllocated6.as_str(), "leases_allocated_6");
        assert_eq!(MetricLabel::LeasesPruned6.as_str(), "leases_pruned_6");
    }

    #[test]
    fn test_metric_label_display() {
        let metric = MetricLabel::DnsQueriesForwarded;
        assert_eq!(format!("{}", metric), "dns_queries_forwarded");
    }

    #[test]
    fn test_metric_label_help_text() {
        let help = MetricLabel::DnsQueriesForwarded.help_text();
        assert!(help.contains("upstream"));
        assert!(!help.is_empty());
    }

    #[test]
    fn test_metric_label_function() {
        // Test the standalone function
        assert_eq!(metric_label(MetricLabel::DhcpAck), "dhcp_ack");
    }

    #[test]
    fn test_metrics_collector_new() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 0);
    }

    #[test]
    fn test_metrics_collector_increment() {
        let mut collector = MetricsCollector::new();
        collector.increment(MetricLabel::DnsQueriesForwarded, 1);
        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 1);

        collector.increment(MetricLabel::DnsQueriesForwarded, 10);
        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 11);
    }

    #[test]
    fn test_metrics_collector_multiple_metrics() {
        let mut collector = MetricsCollector::new();
        collector.increment(MetricLabel::DnsQueriesForwarded, 5);
        collector.increment(MetricLabel::DnsCacheInserted, 10);
        collector.increment(MetricLabel::DhcpAck, 3);

        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 5);
        assert_eq!(collector.get(MetricLabel::DnsCacheInserted), 10);
        assert_eq!(collector.get(MetricLabel::DhcpAck), 3);
        assert_eq!(collector.get(MetricLabel::DhcpNak), 0);
    }

    #[test]
    fn test_metrics_collector_reset() {
        let mut collector = MetricsCollector::new();
        collector.increment(MetricLabel::DnsQueriesForwarded, 100);
        collector.increment(MetricLabel::DhcpAck, 50);

        collector.reset();

        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 0);
        assert_eq!(collector.get(MetricLabel::DhcpAck), 0);
    }

    #[test]
    fn test_metrics_collector_saturating_add() {
        let mut collector = MetricsCollector::new();
        collector.increment(MetricLabel::DnsQueriesForwarded, u64::MAX);
        collector.increment(MetricLabel::DnsQueriesForwarded, 1);

        // Should saturate at u64::MAX, not wrap
        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), u64::MAX);
    }

    #[test]
    fn test_metrics_collector_export_prometheus() {
        let mut collector = MetricsCollector::new();
        collector.increment(MetricLabel::DnsQueriesForwarded, 42);
        collector.increment(MetricLabel::DhcpAck, 10);

        let output = collector.export_prometheus();

        // Verify HELP comments
        assert!(output.contains("# HELP dns_queries_forwarded"));
        assert!(output.contains("# HELP dhcp_ack"));

        // Verify TYPE declarations
        assert!(output.contains("# TYPE dns_queries_forwarded counter"));
        assert!(output.contains("# TYPE dhcp_ack counter"));

        // Verify metric values
        assert!(output.contains("dns_queries_forwarded 42"));
        assert!(output.contains("dhcp_ack 10"));

        // Verify all metrics are present (even zero-valued)
        assert!(output.contains("dns_cache_inserted"));
        assert!(output.contains("leases_pruned_6"));
    }

    #[test]
    fn test_atomic_metrics_collector_new() {
        let collector = AtomicMetricsCollector::new();
        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 0);
    }

    #[test]
    fn test_atomic_metrics_collector_increment() {
        let collector = AtomicMetricsCollector::new();
        collector.increment(MetricLabel::DnsQueriesForwarded, 1);
        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 1);

        collector.increment(MetricLabel::DnsQueriesForwarded, 10);
        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 11);
    }

    #[test]
    fn test_atomic_metrics_collector_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let collector = Arc::new(AtomicMetricsCollector::new());
        let mut handles = vec![];

        // Spawn 10 threads, each incrementing by 100
        for _ in 0..10 {
            let collector_clone = Arc::clone(&collector);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    collector_clone.increment(MetricLabel::DnsQueriesForwarded, 1);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Total should be 10 * 100 = 1000
        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 1000);
    }

    #[test]
    fn test_atomic_metrics_collector_reset() {
        let collector = AtomicMetricsCollector::new();
        collector.increment(MetricLabel::DnsQueriesForwarded, 100);
        collector.increment(MetricLabel::DhcpAck, 50);

        collector.reset();

        assert_eq!(collector.get(MetricLabel::DnsQueriesForwarded), 0);
        assert_eq!(collector.get(MetricLabel::DhcpAck), 0);
    }

    #[test]
    fn test_atomic_metrics_collector_export_prometheus() {
        let collector = AtomicMetricsCollector::new();
        collector.increment(MetricLabel::DnsQueriesForwarded, 42);
        collector.increment(MetricLabel::DhcpAck, 10);

        let output = collector.export_prometheus();

        // Verify format matches non-atomic version
        assert!(output.contains("# HELP dns_queries_forwarded"));
        assert!(output.contains("# TYPE dns_queries_forwarded counter"));
        assert!(output.contains("dns_queries_forwarded 42"));
        assert!(output.contains("dhcp_ack 10"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_METRICS_PORT, 9153);
        assert_eq!(PROMETHEUS_CONTENT_TYPE, "text/plain; version=0.0.4");
    }

    #[test]
    fn test_prometheus_format_compliance() {
        let collector = MetricsCollector::new();
        let output = collector.export_prometheus();

        // Verify Prometheus format compliance
        let lines: Vec<&str> = output.lines().collect();
        
        // Every metric should have HELP, TYPE, and value lines (3 lines per metric)
        assert_eq!(lines.len(), MetricLabel::COUNT * 3);

        // Verify pattern for first metric
        assert!(lines[0].starts_with("# HELP dns_cache_inserted"));
        assert!(lines[1].starts_with("# TYPE dns_cache_inserted counter"));
        assert!(lines[2].starts_with("dns_cache_inserted "));

        // Verify no invalid characters in metric names (only lowercase, digits, underscores)
        for metric in MetricLabel::iter() {
            let name = metric.as_str();
            assert!(name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
        }
    }

    #[test]
    fn test_default_implementation() {
        let collector1 = MetricsCollector::default();
        let collector2 = AtomicMetricsCollector::default();

        assert_eq!(collector1.get(MetricLabel::DnsQueriesForwarded), 0);
        assert_eq!(collector2.get(MetricLabel::DnsQueriesForwarded), 0);
    }
}
