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
 * @file metrics.c
 * @brief Prometheus-format metrics export for monitoring integration
 * 
 * DETAILED PURPOSE:
 * 
 * This file provides support for Prometheus-compatible metrics collection and export,
 * enabling integration with modern monitoring and observability systems. It maintains
 * string labels corresponding to the metric enumeration defined in metrics.h, which
 * are used to export operational statistics in Prometheus text format. When the
 * HAVE_METRICS compile-time option is enabled, dnsmasq can serve metrics over HTTP
 * at an endpoint (typically /metrics on port 9153), providing real-time visibility
 * into DNS forwarding, caching, DHCP operations, and system health.
 * 
 * The metrics system tracks counters for key operations including DNS cache insertions
 * and evictions, query forwarding counts, authoritative and local answer counts, DHCP
 * message type frequencies (DISCOVER, OFFER, REQUEST, ACK, NAK, etc.), lease allocation
 * and pruning statistics for both DHCPv4 and DHCPv6, and various operational events.
 * These metrics enable operators to monitor dnsmasq performance, detect anomalies,
 * configure alerting rules, and analyze usage patterns over time.
 * 
 * KEY RESPONSIBILITIES:
 * - get_metric_name() - Retrieve human-readable metric label for given metric index
 * - metric_names[] - Maintain canonical string labels for all metrics in sync with metrics.h enum
 * - Provide mapping between internal metric enum values and Prometheus-compatible label strings
 * 
 * DEPENDENCIES:
 * 
 * Includes:
 * - dnsmasq.h - Primary header providing daemon state structure with metrics[] array
 * - metrics.h (via dnsmasq.h) - Defines METRIC_* enum constants for metric indices
 * 
 * Called by:
 * - Metrics export functions (when HAVE_METRICS enabled) to format Prometheus text output
 * - HTTP server endpoint handler serving /metrics requests
 * - Monitoring and observability infrastructure integrations
 * 
 * Calls:
 * - None (pure data and accessor function)
 * 
 * DATA STRUCTURES:
 * - metric_names[] - Array of const char* strings at lines 19-40, indexed by METRIC_* enum values
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_METRICS - Enables metrics collection and export functionality throughout dnsmasq
 * - HAVE_DHCP - When enabled, includes DHCP-related metric labels (BOOTP, PXE, DHCP message types)
 * - HAVE_AUTH - When enabled, includes authoritative DNS answer metric (dns_auth_answered)
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Metrics are stored in the global daemon structure
 * and accessed from the main event loop. The metric_names array is read-only after initialization,
 * making get_metric_name() safe to call without synchronization. Metric counter increments occur
 * in the main event loop thread, ensuring atomic updates without requiring locks.
 * 
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

/**
 * @brief Prometheus-compatible metric label strings indexed by METRIC_* enum values
 * 
 * This array provides the canonical string labels for all metrics exported in Prometheus
 * text format. Each entry corresponds to a metric type defined in the METRIC_* enum in
 * metrics.h. The array is indexed using enum values (e.g., METRIC_DNS_CACHE_INSERTED = 0
 * maps to "dns_cache_inserted"). This mapping ensures consistent metric naming across
 * different dnsmasq deployments and aligns with Prometheus naming conventions (lowercase
 * with underscores).
 * 
 * DNS Metrics:
 * - dns_cache_inserted: Count of DNS records inserted into cache
 * - dns_cache_live_freed: Count of cache entries evicted before expiry
 * - dns_queries_forwarded: Count of DNS queries forwarded to upstream servers
 * - dns_auth_answered: Count of queries answered from authoritative zones (HAVE_AUTH)
 * - dns_local_answered: Count of queries answered from /etc/hosts or local data
 * 
 * DHCP Metrics:
 * - bootp: Count of BOOTP requests processed (legacy DHCP)
 * - pxe: Count of PXE boot requests processed
 * - dhcp_ack: Count of DHCPACK messages sent
 * - dhcp_decline: Count of DHCPDECLINE messages received
 * - dhcp_discover: Count of DHCPDISCOVER messages received
 * - dhcp_inform: Count of DHCPINFORM messages received
 * - dhcp_nak: Count of DHCPNAK messages sent (lease rejections)
 * - dhcp_offer: Count of DHCPOFFER messages sent
 * - dhcp_release: Count of DHCPRELEASE messages received
 * - dhcp_request: Count of DHCPREQUEST messages received
 * 
 * Operational Metrics:
 * - noanswer: Count of queries with no answer available
 * - leases_allocated_4: Count of DHCPv4 leases allocated
 * - leases_pruned_4: Count of DHCPv4 leases reclaimed/expired
 * - leases_allocated_6: Count of DHCPv6 leases allocated
 * - leases_pruned_6: Count of DHCPv6 leases reclaimed/expired
 * 
 * CRITICAL: This array must be kept in sync with the enum in metrics.h. When adding
 * or removing metrics, update both files simultaneously to prevent index mismatches.
 * The comment at the top of metrics.h reminds developers of this requirement.
 * 
 * @see metrics.h for corresponding METRIC_* enum definitions
 * @see get_metric_name() for accessor function
 * @see struct daemon.metrics[] in dnsmasq.h for counter storage (line 1185)
 */
const char * metric_names[] = {
    "dns_cache_inserted",
    "dns_cache_live_freed",
    "dns_queries_forwarded",
    "dns_auth_answered",
    "dns_local_answered",
    "bootp",
    "pxe",
    "dhcp_ack",
    "dhcp_decline",
    "dhcp_discover",
    "dhcp_inform",
    "dhcp_nak",
    "dhcp_offer",
    "dhcp_release",
    "dhcp_request",
    "noanswer",
    "leases_allocated_4",
    "leases_pruned_4",
    "leases_allocated_6",
    "leases_pruned_6",
};

/**
 * @brief Retrieve Prometheus-compatible label string for a given metric index
 * 
 * @detailed
 * This accessor function provides safe retrieval of metric label strings by index,
 * enabling Prometheus text format export. It performs a simple array lookup in the
 * metric_names[] array using the provided metric index (typically a METRIC_* enum
 * value from metrics.h). The returned string is used as the metric name in Prometheus
 * output lines (e.g., "dns_cache_inserted 1234"). This function is called during
 * metrics export to format each counter value with its corresponding label.
 * 
 * @param i The metric index to look up, should be a value from the METRIC_* enum
 *          (0 <= i < __METRIC_MAX). Values outside this range will cause undefined
 *          behavior (array out-of-bounds access). Caller must ensure valid index.
 * 
 * @return Pointer to a constant string containing the Prometheus-compatible metric
 *         label. The returned string is statically allocated and must not be modified
 *         or freed by the caller. Returns NULL or garbage if index is out of bounds
 *         (no bounds checking performed for performance).
 * 
 * @note This function performs no bounds checking for performance reasons. Callers
 *       must ensure the index parameter is valid (0 <= i < __METRIC_MAX). Invalid
 *       indices will result in undefined behavior, potentially returning garbage
 *       pointers or causing segmentation faults.
 * 
 * @warning No validation of the input parameter is performed. Passing invalid indices
 *          will cause array out-of-bounds access. This is acceptable because all
 *          callers are internal to dnsmasq and use compile-time METRIC_* enum constants.
 * 
 * @see metrics.h for METRIC_* enum definitions and valid index values
 * @see metric_names[] array documentation for complete list of labels
 * @see struct daemon.metrics[] in dnsmasq.h (line 1185) for counter storage
 * 
 * EXAMPLE USAGE:
 * @code
 * // During Prometheus metrics export
 * for (int i = 0; i < __METRIC_MAX; i++) {
 *     const char *label = get_metric_name(i);
 *     fprintf(fd, "%s %u\n", label, daemon->metrics[i]);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE:
 * Conforms to Prometheus text format specification for metric naming conventions
 * (lowercase with underscores, no special characters). See Prometheus documentation
 * at https://prometheus.io/docs/instrumenting/exposition_formats/
 * 
 * SIDE EFFECTS:
 * None. This is a pure function performing read-only array access with no global
 * state modifications, I/O operations, or memory allocation.
 * 
 * THREAD SAFETY:
 * Thread-safe. The metric_names[] array is read-only after initialization, and
 * this function performs only a simple read access with no locking required.
 * Safe to call from any context in dnsmasq's single-threaded event loop.
 * However, dnsmasq is single-threaded, so thread safety is not a practical concern.
 */
const char* get_metric_name(int i) {
    return metric_names[i];
}
