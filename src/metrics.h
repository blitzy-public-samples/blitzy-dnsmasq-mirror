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
 * @file metrics.h
 * @brief Metric label definitions for Prometheus export
 *
 * DETAILED PURPOSE:
 * This header file defines the enumeration constants used to identify metrics
 * exported in Prometheus format by dnsmasq when compiled with HAVE_METRICS enabled.
 * Each enum value corresponds to a specific operational metric tracked by the daemon,
 * including DNS cache operations, query forwarding statistics, DHCP message counts,
 * and lease allocation tracking. The enum values serve as indices into metric name
 * and metadata arrays defined in metrics.c, ensuring type-safe metric identification
 * throughout the codebase. This design allows the metrics subsystem to maintain
 * consistent labeling and formatting while enabling efficient metric updates during
 * runtime operations.
 *
 * KEY RESPONSIBILITIES:
 * - Define enumeration constants for all tracked metrics (DNS, DHCP, cache operations)
 * - Provide symbolic names matching Prometheus naming conventions (lowercase, underscores)
 * - Maintain synchronization with metric name strings in metrics.c
 * - Declare metric name accessor function for runtime metric label retrieval
 * - Support compile-time metric configuration via HAVE_METRICS flag
 *
 * DEPENDENCIES:
 * This header is included by:
 * - metrics.c (metric export implementation, label string definitions)
 * - cache.c (DNS cache metric updates)
 * - forward.c (DNS forwarding metric updates)
 * - dhcp.c (DHCP message metric updates)
 * - rfc2131.c (DHCPv4 protocol metric updates)
 * - rfc3315.c (DHCPv6 protocol metric updates)
 * - lease.c (lease allocation/pruning metric updates)
 * 
 * This header includes: None (self-contained definitions)
 *
 * DATA STRUCTURES:
 * - enum (anonymous, lines 18-41): Metric identifier enumeration with DNS, DHCP, 
 *   and lease tracking constants, terminated by __METRIC_MAX sentinel value
 *
 * COMPILE-TIME OPTIONS:
 * - HAVE_METRICS: When defined, enables Prometheus metrics export functionality
 *   throughout dnsmasq. If undefined, metric tracking code is excluded at compile
 *   time, and this header's definitions are unused. Metrics are exported via HTTP
 *   on a configurable port (default 9153) in Prometheus text exposition format.
 *
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Metric updates occur synchronously
 * within the main event loop as operations complete (cache insertions, query
 * forwarding, DHCP message processing). No concurrent access protection required
 * as all metric increments occur in the same execution context. Metric export
 * via HTTP occurs in response to client requests handled by the main event loop.
 *
 * @note Metric enum values must remain synchronized with the metric name and
 * metadata arrays in metrics.c. Adding or reordering enum values requires
 * corresponding updates to the string arrays to maintain correct metric labeling.
 *
 * @note Prometheus naming conventions require lowercase metric names with
 * underscores separating words. Counter metrics should use the _total suffix
 * per Prometheus best practices (e.g., dns_queries_forwarded_total).
 *
 * @see metrics.c for metric name strings, HELP text, and TYPE declarations
 * @see docs/CONFIGURATION.md for HAVE_METRICS compile-time option documentation
 *
 * @copyright Copyright (c) 2000-2022 Simon Kelley
 * @license GPL-2.0-or-later
 */

/* If you modify this list, please keep the labels in metrics.c in sync. */

/**
 * @brief Metric identifier enumeration for Prometheus export
 *
 * Defines symbolic constants for all operational metrics tracked by dnsmasq
 * when compiled with HAVE_METRICS. Each enum value serves as an index into
 * the metric name and metadata arrays in metrics.c, enabling type-safe metric
 * identification and updates throughout the codebase. The enumeration includes
 * DNS cache operations, query forwarding statistics, DHCP message type counts,
 * and lease allocation/pruning counters for both IPv4 and IPv6.
 *
 * The enum values are used as array indices in metrics.c to access corresponding
 * metric names (lowercase with underscores per Prometheus conventions), HELP text
 * descriptions, and TYPE declarations (counter, gauge, histogram). All metrics
 * defined here are counters that monotonically increase during daemon operation.
 *
 * @note The order of enum values must match the order of metric name strings in
 * the metrics.c arrays. Adding, removing, or reordering values requires synchronized
 * updates to metrics.c to prevent metric label mismatches.
 *
 * @note __METRIC_MAX serves as a sentinel value indicating the total count of
 * defined metrics. It is used for array sizing and bounds checking in metrics.c.
 *
 * @see metrics.c for metric name string definitions and Prometheus metadata
 * @see get_metric_name() for runtime metric name retrieval
 */
enum {
  METRIC_DNS_CACHE_INSERTED,      /**< DNS cache insertions counter - tracks successful 
                                       additions of resource records to the DNS cache,
                                       incremented by cache_insert() in cache.c */
  
  METRIC_DNS_CACHE_LIVE_FREED,    /**< DNS cache evictions counter - tracks removal of
                                       live (non-expired) cache entries due to cache size
                                       limits, incremented during LRU eviction in cache.c */
  
  METRIC_DNS_QUERIES_FORWARDED,   /**< DNS queries forwarded to upstream servers counter -
                                       tracks queries sent to upstream DNS servers after
                                       cache misses, incremented by forward_query() in
                                       forward.c */
  
  METRIC_DNS_AUTH_ANSWERED,       /**< DNS authoritative answers counter - tracks queries
                                       answered from local authoritative zones when
                                       HAVE_AUTH is enabled, incremented by auth.c */
  
  METRIC_DNS_LOCAL_ANSWERED,      /**< DNS local answers counter - tracks queries answered
                                       from /etc/hosts, --address, --server configurations,
                                       or other local sources without cache or forwarding,
                                       incremented in forward.c */
  
  METRIC_BOOTP,                    /**< BOOTP requests counter (legacy) - tracks BOOTP
                                       protocol requests (DHCP predecessor), incremented
                                       when op field is BOOTREQUEST in rfc2131.c */
  
  METRIC_PXE,                      /**< PXE boot requests counter - tracks Pre-boot
                                       Execution Environment requests for network boot,
                                       incremented when option 93 (client architecture)
                                       is present in DHCP requests, processed in rfc2131.c */
  
  METRIC_DHCPACK,                  /**< DHCPACK messages sent counter - tracks DHCP
                                       acknowledgment messages confirming lease allocation
                                       or renewal, sent in response to DHCPREQUEST,
                                       incremented in rfc2131.c dhcp_reply() */
  
  METRIC_DHCPDECLINE,              /**< DHCPDECLINE messages received counter - tracks
                                       client rejection of offered IP addresses due to
                                       address conflicts detected via ARP, incremented
                                       in rfc2131.c when processing DECLINE messages */
  
  METRIC_DHCPDISCOVER,             /**< DHCPDISCOVER messages received counter - tracks
                                       initial broadcast requests from DHCP clients seeking
                                       address allocation, incremented in rfc2131.c
                                       dhcp_reply() when processing DISCOVER messages */
  
  METRIC_DHCPINFORM,               /**< DHCPINFORM messages received counter - tracks
                                       requests from clients with manually configured
                                       addresses seeking additional configuration parameters,
                                       incremented in rfc2131.c dhcp_reply() */
  
  METRIC_DHCPNAK,                  /**< DHCPNAK messages sent counter - tracks negative
                                       acknowledgments rejecting client DHCPREQUEST due to
                                       invalid requested address or lease expiry, sent by
                                       rfc2131.c dhcp_reply() */
  
  METRIC_DHCPOFFER,                /**< DHCPOFFER messages sent counter - tracks offers
                                       of IP addresses sent in response to DHCPDISCOVER,
                                       incremented in rfc2131.c dhcp_reply() when address
                                       is available for allocation */
  
  METRIC_DHCPRELEASE,              /**< DHCPRELEASE messages received counter - tracks
                                       client notifications of lease termination, allowing
                                       early reclamation of addresses, incremented in
                                       rfc2131.c dhcp_reply() */
  
  METRIC_DHCPREQUEST,              /**< DHCPREQUEST messages received counter - tracks
                                       client requests to accept offered addresses (after
                                       OFFER) or renew/rebind existing leases, incremented
                                       in rfc2131.c dhcp_reply() */
  
  METRIC_NOANSWER,                 /**< DNS queries with no answer counter - tracks queries
                                       that resulted in NXDOMAIN (name does not exist) or
                                       NODATA (name exists but no records of requested type),
                                       used for negative caching statistics */
  
  METRIC_LEASES_ALLOCATED_4,       /**< DHCPv4 leases allocated counter - tracks successful
                                       IPv4 address allocations from configured address pools,
                                       incremented in lease.c when new DHCPv4 lease is created
                                       or existing lease is reused */
  
  METRIC_LEASES_PRUNED_4,          /**< DHCPv4 leases pruned counter - tracks removal of
                                       expired or released DHCPv4 leases from the lease
                                       database, incremented during periodic lease cleanup
                                       in lease.c */
  
  METRIC_LEASES_ALLOCATED_6,       /**< DHCPv6 leases allocated counter - tracks successful
                                       IPv6 address or prefix allocations from configured
                                       ranges, incremented in lease.c when new DHCPv6 lease
                                       is created for IA_NA, IA_TA, or IA_PD */
  
  METRIC_LEASES_PRUNED_6,          /**< DHCPv6 leases pruned counter - tracks removal of
                                       expired or released DHCPv6 leases from the lease
                                       database, incremented during periodic lease cleanup
                                       in lease.c */
  
  __METRIC_MAX,                    /**< Sentinel value indicating total metric count -
                                       used for array sizing in metrics.c and bounds
                                       checking during metric updates, not a valid metric
                                       identifier, always keep as last enum value */
};

/**
 * @brief Retrieve Prometheus metric name string for given metric identifier
 *
 * @detailed
 * Translates a metric identifier enum value into its corresponding Prometheus
 * metric name string. The function performs array lookup in the metric name
 * table defined in metrics.c, returning lowercase metric names with underscores
 * conforming to Prometheus naming conventions. Used during HTTP metric export
 * to format metric labels in the Prometheus text exposition format.
 *
 * @param metric_id Metric identifier from the metric enumeration (0 to __METRIC_MAX-1),
 *                  typically one of METRIC_DNS_*, METRIC_DHCP*, or METRIC_LEASES_*
 *                  constants. Values outside valid range may return NULL or undefined
 *                  behavior depending on implementation.
 *
 * @return Pointer to constant string containing Prometheus metric name in lowercase
 *         with underscores (e.g., "dns_cache_inserted_total", "dhcp_discover_total"),
 *         or NULL if metric_id is invalid or out of range. Returned string has static
 *         storage duration and must not be freed by caller.
 *
 * @note Metric names follow Prometheus naming conventions: lowercase letters, digits,
 * and underscores only, with _total suffix for counter metrics. The _total suffix
 * is included in the returned string for all counter metrics.
 *
 * @warning The function does not validate metric_id bounds in all implementations.
 * Passing values >= __METRIC_MAX may result in array out-of-bounds access. Callers
 * should ensure metric_id is a valid enum value.
 *
 * @see metrics.c for metric name string array implementation
 * @see METRIC_DNS_CACHE_INSERTED and related enum constants for valid metric_id values
 *
 * EXAMPLE USAGE:
 * @code
 * int metric = METRIC_DNS_QUERIES_FORWARDED;
 * const char *name = get_metric_name(metric);
 * if (name)
 *   printf("Metric name: %s\n", name); // Prints "dns_queries_forwarded_total"
 * @endcode
 *
 * RFC COMPLIANCE:
 * Not applicable - Prometheus text exposition format is defined by Prometheus
 * documentation, not IETF RFCs. Format specification available at:
 * https://prometheus.io/docs/instrumenting/exposition_formats/
 *
 * SIDE EFFECTS:
 * None - pure function performing read-only array lookup with no global state
 * modifications.
 *
 * THREAD SAFETY:
 * Thread-safe for reading as metric name strings have static storage duration.
 * In dnsmasq's single-process event-driven architecture, concurrent access is
 * not a concern as all metric operations occur in the main event loop context.
 */
const char* get_metric_name(int);
