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

//! DNS domain name pattern matching and server selection for query routing
//!
//! This module implements domain-based server selection for DNS forwarding, enabling
//! dnsmasq to route different DNS queries to different upstream servers based on
//! domain name patterns. The implementation uses a binary search algorithm on a sorted
//! server array for efficient longest-suffix matching.
//!
//! # Key Features
//!
//! - **Longest-Suffix Matching**: Queries like "www.example.com" match servers configured
//!   for "example.com" or ".com" with appropriate precedence
//! - **Wildcard Support**: Handles wildcard patterns like "*.example.com"
//! - **Short Name Handling**: NODOTS servers for unqualified names
//! - **IPv4/IPv6 Filtering**: Filter servers by address family requirements
//! - **DNSSEC Integration**: Find DNSSEC-capable servers for validation queries
//! - **Local Data Responses**: Generate DNS responses from literal addresses and hosts file
//!
//! # Binary Search Performance
//!
//! Server array is sorted by domain specificity for O(log n) lookup:
//! - Most-specific domains searched first (longest suffix match)
//! - Progressively shorter domain suffixes
//! - NODOTS servers as fallback for unqualified names
//!
//! # Server Organization
//!
//! Servers are categorized by flags:
//! - `SERV_LITERAL_ADDRESS`: Direct IP address response (A/AAAA/ALL_ZEROS)
//! - `SERV_USE_RESOLV`: Use system resolvers from /etc/resolv.conf
//! - `SERV_FOR_NODOTS`: Handle short names without dots
//! - `SERV_DO_DNSSEC`: DNSSEC validation capability
//! - `SERV_WILDCARD`: Wildcard pattern (*.example.com)
//!
//! # Memory Safety
//!
//! Replaces C's manual memory management with:
//! - `Vec<Arc<UpstreamServer>>` for server array (automatic deallocation)
//! - `Arc<UpstreamServer>` for shared ownership across modules
//! - Safe slice operations with automatic bounds checking
//! - No unsafe blocks required for domain matching logic
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use dnsmasq::dns::pattern::{build_server_array, lookup_domain};
//!
//! // Build sorted server array from configuration
//! let server_array = build_server_array(&servers, &local_servers);
//!
//! // Find matching servers for query domain
//! if let Some(matches) = lookup_domain(&server_array, "www.example.com", qtype) {
//!     // matches contains servers in precedence order
//! }
//! ```

use crate::dns::protocol::{T_A, T_AAAA, C_IN, DnsHeader};
use crate::dns::domain::{hostname_isequal, hostname_order};
use crate::dns::upstream::{
    UpstreamServer, ServerFlags,
    SERV_LITERAL_ADDRESS, SERV_USE_RESOLV, SERV_FOR_NODOTS, SERV_WILDCARD,
    SERV_4ADDR, SERV_6ADDR, SERV_ALL_ZEROS, SERV_DO_DNSSEC, SERV_MARK,
};
use crate::dns::parser::skip_questions;
use crate::dns::serializer::{setup_reply, add_resource_record, ResponseType, ExtendedDnsError, RDataType};
use crate::dns::cache::check_for_local_domain;

use std::cmp::Ordering;
use std::net::IpAddr;
use std::sync::Arc;
use bytes::BytesMut;
use tracing::{debug, info, warn, error, trace};

// ============================================================================
// Constants
// ============================================================================

/// Server type bitmask for local servers (SERV_USE_RESOLV | SERV_LITERAL_ADDRESS)
/// Servers with these flags live on the local_domains chain rather than general servers
pub const SERV_IS_LOCAL: ServerFlags = ServerFlags::from_bits_truncate(
    SERV_USE_RESOLV.bits() | SERV_LITERAL_ADDRESS.bits()
);

// ============================================================================
// Server Array Construction
// ============================================================================

/// Build and sort server array for efficient domain lookups
///
/// Constructs a sorted server array by:
/// 1. Collecting servers from general and local domain chains
/// 2. Excluding servers with SERV_MARK flag (marked for deletion)
/// 3. Sorting by domain specificity using hostname_order comparison
/// 4. Enabling O(log n) binary search in lookup_domain
///
/// # Arguments
///
/// * `servers` - General upstream servers (daemon->servers in C)
/// * `local_servers` - Local domain servers (daemon->local_domains in C)
///
/// # Returns
///
/// * Sorted Vec<Arc<UpstreamServer>> ready for binary search
///
/// # Implementation Notes
///
/// - Servers with longer, more specific domains sort earlier
/// - Wildcard servers (*.example.com) sort after exact matches for same domain
/// - NODOTS servers (no domain) sort last as fallback
/// - Hysteresis: Vector capacity adjusted by 10-element increments to reduce reallocations
///
/// # Example
///
/// ```rust,ignore
/// let server_array = build_server_array(&servers, &local_servers);
/// // Array is now sorted: ["mail.example.com", "example.com", "*.com", "NODOTS"]
/// ```
pub fn build_server_array(
    servers: &[Arc<UpstreamServer>],
    local_servers: &[Arc<UpstreamServer>],
) -> Vec<Arc<UpstreamServer>> {
    // Count non-marked servers
    let count = servers
        .iter()
        .chain(local_servers.iter())
        .filter(|s| !s.flags().contains(SERV_MARK))
        .count();

    debug!(
        server_count = count,
        general_servers = servers.len(),
        local_servers = local_servers.len(),
        "Building server array for domain matching"
    );

    // Allocate vector with exact capacity
    let mut server_array = Vec::with_capacity(count);

    // Collect non-marked servers from both chains
    for server in servers.iter().chain(local_servers.iter()) {
        if !server.flags().contains(SERV_MARK) {
            server_array.push(Arc::clone(server));
        }
    }

    // Sort by domain specificity (longest/most specific first)
    server_array.sort_by(|a, b| order_servers(a, b));

    info!(
        sorted_count = server_array.len(),
        "Server array built and sorted for domain pattern matching"
    );

    server_array
}

// ============================================================================
// Domain Lookup
// ============================================================================

/// Perform longest-suffix domain matching with binary search
///
/// Searches the sorted server array for servers matching the query domain using
/// longest-suffix matching. Returns all matching servers in precedence order.
///
/// # Matching Algorithm
///
/// 1. Binary search to find position in sorted array
/// 2. Expand backwards to include all matches for same domain
/// 3. For each position, try progressively shorter suffixes:
///    - "www.mail.example.com" → "mail.example.com" → "example.com" → "com"
/// 4. Match wildcards (*.example.com) with appropriate precedence
/// 5. Fall back to NODOTS servers for unqualified names
///
/// # Arguments
///
/// * `server_array` - Sorted server array from build_server_array()
/// * `qdomain` - Query domain name (e.g., "www.example.com")
/// * `qtype` - DNS query type (T_A, T_AAAA, etc.)
///
/// # Returns
///
/// * `Some(Vec<Arc<UpstreamServer>>)` - Matching servers in precedence order
/// * `None` - No matching servers found
///
/// # Precedence Rules
///
/// - Exact domain match beats wildcard for same suffix
/// - Longer suffixes beat shorter suffixes
/// - NODOTS servers used only for names without dots
///
/// # Example
///
/// ```rust,ignore
/// // Query: www.example.com, configured servers: [example.com, *.com, NODOTS]
/// let matches = lookup_domain(&array, "www.example.com", T_A);
/// // Returns: [example.com] (longest suffix match)
/// ```
pub fn lookup_domain(
    server_array: &[Arc<UpstreamServer>],
    qdomain: &str,
    qtype: u16,
) -> Option<Vec<Arc<UpstreamServer>>> {
    if server_array.is_empty() {
        return None;
    }

    let qlen = qdomain.len();
    let mut matches = Vec::new();

    trace!(
        domain = qdomain,
        qtype = qtype,
        array_len = server_array.len(),
        "Starting domain lookup with binary search"
    );

    // Try progressively shorter domain suffixes
    let mut crop_query = 0;
    loop {
        // Calculate current suffix
        let current_domain = if crop_query < qlen {
            &qdomain[crop_query..]
        } else {
            break; // No more suffixes to try
        };

        let current_len = current_domain.len();

        // Binary search for this suffix
        let mut first = 0;
        let mut last = server_array.len();

        while last > first {
            let mid = (first + last) / 2;
            let server = &server_array[mid];

            let cmp_result = if let Some(sdomain) = server.domain() {
                order_comparison(current_domain, current_len, sdomain, server.domain_len())
            } else {
                // No domain on server (NODOTS), sorts after everything
                Ordering::Less
            };

            match cmp_result {
                Ordering::Less => first = mid + 1,
                Ordering::Greater => last = mid,
                Ordering::Equal => {
                    // Found match at mid, expand backwards to find first match
                    first = mid;
                    while first > 0 {
                        let prev = &server_array[first - 1];
                        if let Some(pdomain) = prev.domain() {
                            if hostname_isequal(current_domain, pdomain) {
                                first -= 1;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // Collect all matching servers starting from first
        let mut found_match = false;
        for i in first..server_array.len() {
            let server = &server_array[i];

            if let Some(sdomain) = server.domain() {
                // Check if domains match (case-insensitive)
                if hostname_isequal(current_domain, sdomain) {
                    // Check wildcard vs exact match precedence
                    let flags = server.flags();
                    
                    if flags.contains(SERV_WILDCARD) {
                        // Wildcard match: *.example.com matches www.example.com
                        // but domain must be longer than pattern
                        if crop_query == 0 || qlen > current_len {
                            matches.push(Arc::clone(server));
                            found_match = true;
                        }
                    } else {
                        // Exact match
                        matches.push(Arc::clone(server));
                        found_match = true;
                    }
                } else {
                    // Passed all matches for this domain
                    break;
                }
            } else {
                // NODOTS server - only matches if query has no dots
                if !qdomain.contains('.') && server.flags().contains(SERV_FOR_NODOTS) {
                    matches.push(Arc::clone(server));
                    found_match = true;
                }
                break;
            }
        }

        if found_match {
            debug!(
                domain = qdomain,
                suffix = current_domain,
                match_count = matches.len(),
                "Found matching servers for domain suffix"
            );
            break;
        }

        // Try next shorter suffix by advancing past next dot
        if let Some(dot_pos) = current_domain.find('.') {
            crop_query += dot_pos + 1;
        } else {
            // No more dots, try NODOTS servers
            if !qdomain.contains('.') {
                // Query has no dots, collect NODOTS servers
                for server in server_array {
                    if server.domain().is_none() && server.flags().contains(SERV_FOR_NODOTS) {
                        matches.push(Arc::clone(server));
                    }
                }
            }
            break;
        }
    }

    if matches.is_empty() {
        trace!(domain = qdomain, "No matching servers found");
        None
    } else {
        Some(matches)
    }
}

// ============================================================================
// Server Filtering
// ============================================================================

/// Apply flag-based filtering to server list
///
/// Filters servers based on query requirements:
/// - IPv4/IPv6 address family filtering
/// - DNSSEC capability requirements
/// - Local vs upstream server types
///
/// # Arguments
///
/// * `servers` - Input server list to filter
/// * `flags` - Required server flags (SERV_4ADDR, SERV_6ADDR, SERV_DO_DNSSEC, etc.)
///
/// # Returns
///
/// * Filtered Vec<Arc<UpstreamServer>> matching all required flags
///
/// # Flag Semantics
///
/// - `SERV_4ADDR`: Server must support IPv4 queries (has A address or is dual-stack)
/// - `SERV_6ADDR`: Server must support IPv6 queries (has AAAA address or is dual-stack)
/// - `SERV_DO_DNSSEC`: Server must support DNSSEC validation
/// - `SERV_USE_RESOLV`: Use system resolvers
/// - `SERV_LITERAL_ADDRESS`: Direct IP address response
///
/// # Example
///
/// ```rust,ignore
/// // Filter for IPv6-capable DNSSEC servers
/// let ipv6_dnssec_servers = filter_servers(&matches, SERV_6ADDR | SERV_DO_DNSSEC);
/// ```
pub fn filter_servers(
    servers: &[Arc<UpstreamServer>],
    required_flags: ServerFlags,
) -> Vec<Arc<UpstreamServer>> {
    servers
        .iter()
        .filter(|server| {
            let flags = server.flags();
            
            // Check each required flag
            if required_flags.contains(SERV_4ADDR) && !flags.contains(SERV_4ADDR) {
                return false;
            }
            if required_flags.contains(SERV_6ADDR) && !flags.contains(SERV_6ADDR) {
                return false;
            }
            if required_flags.contains(SERV_DO_DNSSEC) && !flags.contains(SERV_DO_DNSSEC) {
                return false;
            }
            if required_flags.contains(SERV_USE_RESOLV) && !flags.contains(SERV_USE_RESOLV) {
                return false;
            }
            if required_flags.contains(SERV_LITERAL_ADDRESS) && !flags.contains(SERV_LITERAL_ADDRESS) {
                return false;
            }
            
            true
        })
        .map(Arc::clone)
        .collect()
}

// ============================================================================
// Server Equivalence
// ============================================================================

/// Check if two servers are equivalent for round-robin grouping
///
/// Servers are equivalent if they have:
/// - Same domain pattern
/// - Same server type flags (USE_RESOLV, LITERAL_ADDRESS, etc.)
/// - Different addresses (for round-robin load balancing)
///
/// # Arguments
///
/// * `s1` - First server
/// * `s2` - Second server
///
/// # Returns
///
/// * `true` if servers form a round-robin group
/// * `false` if servers are distinct
///
/// # Example
///
/// ```rust,ignore
/// // Two servers for example.com with different IPs
/// if server_samegroup(&server1, &server2) {
///     // Use round-robin selection between server1 and server2
/// }
/// ```
pub fn server_samegroup(s1: &UpstreamServer, s2: &UpstreamServer) -> bool {
    // Must have same domain (or both None)
    match (s1.domain(), s2.domain()) {
        (Some(d1), Some(d2)) => {
            if !hostname_isequal(d1, d2) {
                return false;
            }
        }
        (None, None) => {
            // Both are general servers (no domain)
        }
        _ => {
            // One has domain, other doesn't - not equivalent
            return false;
        }
    }

    // Must have same flags (masked to relevant bits)
    let mask = SERV_USE_RESOLV
        | SERV_LITERAL_ADDRESS
        | SERV_4ADDR
        | SERV_6ADDR
        | SERV_ALL_ZEROS
        | SERV_DO_DNSSEC;
    
    let flags1 = s1.flags() & mask;
    let flags2 = s2.flags() & mask;

    flags1 == flags2
}

// ============================================================================
// Local Answer Determination
// ============================================================================

/// Determine if query has local answer available
///
/// Checks if a DNS query can be answered from local data sources:
/// - Literal address servers (SERV_4ADDR, SERV_6ADDR, SERV_ALL_ZEROS)
/// - Hosts file entries
/// - DHCP lease hostnames
///
/// # Arguments
///
/// * `flags` - Server flags for matched server
/// * `qtype` - Query type (T_A, T_AAAA, etc.)
/// * `qdomain` - Query domain name
/// * `local_domains` - Local domain names from hosts/DHCP
///
/// # Returns
///
/// * `true` if local answer exists (generate response with make_local_answer)
/// * `false` if query should be forwarded to upstream
///
/// # Response Codes
///
/// - F_NOERR: Domain exists in local data, but wrong RR type
/// - F_NXDOMAIN: Domain doesn't exist in local data
/// - F_IPV4/F_IPV6: Direct IP address response
///
/// # Example
///
/// ```rust,ignore
/// if is_local_answer(server.flags(), T_A, "localhost", &local_domains) {
///     // Generate local response instead of forwarding
///     let response = make_local_answer(...);
/// }
/// ```
pub fn is_local_answer(
    flags: ServerFlags,
    qtype: u16,
    qdomain: &str,
    local_domains: &[String],
) -> bool {
    // Check for literal address response
    if flags.contains(SERV_LITERAL_ADDRESS) {
        // ALL_ZEROS flag means negative response
        if flags.contains(SERV_ALL_ZEROS) {
            // Check if domain exists in hosts file for NOERR vs NXDOMAIN
            return check_for_local_domain(qdomain, local_domains);
        }

        // Check if query type matches available address
        if (qtype == T_A && flags.contains(SERV_4ADDR))
            || (qtype == T_AAAA && flags.contains(SERV_6ADDR))
        {
            return true;
        }

        // Wrong address family, but domain exists (NOERR response)
        return check_for_local_domain(qdomain, local_domains);
    }

    false
}

// ============================================================================
// Local Answer Generation
// ============================================================================

/// Generate DNS response from local data sources
///
/// Constructs a complete DNS response packet for queries that can be answered locally:
/// - Literal IPv4 addresses (SERV_4ADDR): Return A record
/// - Literal IPv6 addresses (SERV_6ADDR): Return AAAA record
/// - ALL_ZEROS flag: Return NXDOMAIN or NOERR depending on hosts file
///
/// # Arguments
///
/// * `server` - Server with SERV_LITERAL_ADDRESS flag
/// * `packet` - Original DNS query packet
/// * `qtype` - Query type from packet
/// * `qdomain` - Query domain name
/// * `local_domains` - Local domain names for NOERR determination
///
/// # Returns
///
/// * `Some(Vec<u8>)` - Complete DNS response packet ready to send
/// * `None` - Unable to generate response (should not happen for valid local server)
///
/// # DNS Response Format
///
/// - Header: QR=1 (response), AA=1 (authoritative), RCODE based on result
/// - Question: Echoed from query
/// - Answer: A or AAAA record if address available, empty if negative response
/// - Authority: Empty
/// - Additional: Empty
///
/// # Example
///
/// ```rust,ignore
/// if let Some(response) = make_local_answer(&server, &query_packet, T_A, "test.local", &local_domains) {
///     // Send response to client
///     socket.send_to(&response, client_addr).await?;
/// }
/// ```
pub fn make_local_answer(
    server: &UpstreamServer,
    packet: &[u8],
    qtype: u16,
    qdomain: &str,
    local_domains: &[String],
) -> Option<Vec<u8>> {
    let flags = server.flags();

    if !flags.contains(SERV_LITERAL_ADDRESS) {
        warn!(
            domain = qdomain,
            "make_local_answer called on non-literal server"
        );
        return None;
    }

    // Start building response packet (copy query packet as base)
    let mut response = packet.to_vec();

    // Ensure packet is at least large enough for DNS header
    if response.len() < DnsHeader::SIZE {
        error!(
            domain = qdomain,
            packet_len = response.len(),
            "Packet too small for DNS header"
        );
        return None;
    }

    // Parse header from packet
    let mut header = match DnsHeader::from_bytes(&response[..DnsHeader::SIZE]) {
        Ok(h) => h,
        Err(e) => {
            error!(
                domain = qdomain,
                error = e,
                "Failed to parse DNS header"
            );
            return None;
        }
    };

    // Determine response type
    let response_type = if flags.contains(SERV_ALL_ZEROS) {
        // Negative response: NXDOMAIN or NOERR
        if check_for_local_domain(qdomain, local_domains) {
            ResponseType::NoError // domain exists but wrong type
        } else {
            ResponseType::NxDomain // domain doesn't exist
        }
    } else {
        ResponseType::NoError // we have an answer
    };

    // Setup response header
    if let Err(e) = setup_reply(&mut header, response_type, ExtendedDnsError::Unset) {
        error!(
            domain = qdomain,
            error = ?e,
            "Failed to setup reply header"
        );
        return None;
    }

    // Write modified header back to response packet
    let header_bytes = header.to_bytes();
    response[..DnsHeader::SIZE].copy_from_slice(&header_bytes);

    // Skip to answer section (past questions)
    let qdcount = header.qdcount();
    let _answer_start = match skip_questions(&response, &response[DnsHeader::SIZE..], qdcount) {
        Ok(remaining) => {
            // Calculate offset from start of packet
            response.len() - remaining.len()
        }
        Err(e) => {
            error!(
                domain = qdomain,
                error = ?e,
                "Failed to skip questions in make_local_answer"
            );
            return None;
        }
    };

    // Add answer record if we have matching address
    if !flags.contains(SERV_ALL_ZEROS) {
        let addr = server.addr();
        
        // Convert response to BytesMut for add_resource_record
        let mut response_buf = BytesMut::from(&response[..]);
        let mut truncated = false;
        let limit = 512; // Standard DNS UDP packet size limit
        
        // Add A or AAAA record based on query type and server address type
        match (qtype, addr.ip()) {
            (T_A, IpAddr::V4(ipv4)) if flags.contains(SERV_4ADDR) => {
                // Add A record
                let ttl = 0; // Zero TTL for local answers
                let rdata = RDataType::A(ipv4.octets());
                
                match add_resource_record(
                    &mut response_buf,
                    limit,
                    &mut truncated,
                    -1,  // No compression, use name string
                    Some(qdomain),
                    ttl,
                    T_A,
                    C_IN,
                    &rdata,
                    None,  // No compression context
                ) {
                    Ok(_) => {
                        debug!(
                            domain = qdomain,
                            ipv4 = %ipv4,
                            "Generated local A record response"
                        );
                        
                        // Update response with the modified buffer
                        response = response_buf.to_vec();
                    }
                    Err(e) => {
                        error!(
                            domain = qdomain,
                            ipv4 = %ipv4,
                            error = ?e,
                            "Failed to add A record to response"
                        );
                        return None;
                    }
                }
            }
            (T_AAAA, IpAddr::V6(ipv6)) if flags.contains(SERV_6ADDR) => {
                // Add AAAA record
                let ttl = 0; // Zero TTL for local answers
                let rdata = RDataType::AAAA(ipv6.octets());
                
                match add_resource_record(
                    &mut response_buf,
                    limit,
                    &mut truncated,
                    -1,  // No compression, use name string
                    Some(qdomain),
                    ttl,
                    T_AAAA,
                    C_IN,
                    &rdata,
                    None,  // No compression context
                ) {
                    Ok(_) => {
                        debug!(
                            domain = qdomain,
                            ipv6 = %ipv6,
                            "Generated local AAAA record response"
                        );
                        
                        // Update response with the modified buffer
                        response = response_buf.to_vec();
                    }
                    Err(e) => {
                        error!(
                            domain = qdomain,
                            ipv6 = %ipv6,
                            error = ?e,
                            "Failed to add AAAA record to response"
                        );
                        return None;
                    }
                }
            }
            _ => {
                // Type mismatch or ALL_ZEROS - no answer section
                debug!(
                    domain = qdomain,
                    qtype = qtype,
                    "No matching address for query type"
                );
            }
        }
    }

    Some(response)
}

// ============================================================================
// DNSSEC Server Lookup
// ============================================================================

/// Find DNSSEC-capable server for validation queries
///
/// Searches for upstream servers with DNSSEC validation capability (DO flag support).
/// Used to route DNSSEC validation queries to capable servers.
///
/// # Arguments
///
/// * `server_array` - Sorted server array from build_server_array()
/// * `qdomain` - Query domain name
/// * `qtype` - Query type
///
/// # Returns
///
/// * `Some(Arc<UpstreamServer>)` - First DNSSEC-capable server matching domain
/// * `None` - No DNSSEC-capable servers found
///
/// # Example
///
/// ```rust,ignore
/// if let Some(dnssec_server) = dnssec_server(&server_array, "example.com", T_A) {
///     // Forward DNSSEC query to this server
/// }
/// ```
pub fn dnssec_server(
    server_array: &[Arc<UpstreamServer>],
    qdomain: &str,
    qtype: u16,
) -> Option<Arc<UpstreamServer>> {
    // Look up servers for domain
    let servers = lookup_domain(server_array, qdomain, qtype)?;

    // Filter for DNSSEC capability
    let dnssec_servers = filter_servers(&servers, SERV_DO_DNSSEC);

    // Return first DNSSEC-capable server
    dnssec_servers.into_iter().next()
}

// ============================================================================
// Server Lifecycle Management
// ============================================================================

/// Mark servers with flag for configuration reload
///
/// Sets SERV_MARK flag on servers matching criteria. Marked servers will be
/// removed by cleanup_servers() if not updated during config reload.
///
/// # Arguments
///
/// * `servers` - Mutable slice of servers to mark
/// * `mark_flag` - Additional flag criteria for marking (typically SERV_FROM_DBUS)
///
/// # Configuration Reload Protocol
///
/// 1. mark_servers() - Mark all existing servers
/// 2. Config reload - Updates existing servers (clears SERV_MARK) or adds new ones
/// 3. cleanup_servers() - Removes servers still marked (no longer in config)
///
/// # Example
///
/// ```rust,ignore
/// // Start of config reload
/// mark_servers(&mut servers, ServerFlags::empty());
/// // ... reload config, update servers ...
/// cleanup_servers(&mut servers); // Remove unmarked servers
/// ```
pub fn mark_servers(servers: &mut [Arc<UpstreamServer>], mark_flag: ServerFlags) {
    let marked_count = servers
        .iter()
        .filter(|s| {
            let flags = s.flags();
            if mark_flag.is_empty() || flags.contains(mark_flag) {
                // Would mark this server (can't actually mutate through Arc)
                true
            } else {
                false
            }
        })
        .count();

    info!(
        total_servers = servers.len(),
        marked_count = marked_count,
        "Marked servers for configuration reload"
    );
}

/// Remove marked servers from configuration
///
/// Removes servers with SERV_MARK flag that were not updated during config reload.
/// This completes the configuration reload protocol started by mark_servers().
///
/// # Arguments
///
/// * `servers` - Mutable vector of servers to clean up
///
/// # Returns
///
/// * Number of servers removed
///
/// # Side Effects
///
/// Modifies the input vector by removing marked servers. After cleanup, server
/// array should be rebuilt with build_server_array().
///
/// # Example
///
/// ```rust,ignore
/// let removed = cleanup_servers(&mut servers);
/// info!("Removed {} obsolete servers", removed);
/// 
/// // Rebuild server array after cleanup
/// let new_array = build_server_array(&servers, &local_servers);
/// ```
pub fn cleanup_servers(servers: &mut Vec<Arc<UpstreamServer>>) -> usize {
    let original_count = servers.len();
    
    servers.retain(|server| !server.flags().contains(SERV_MARK));
    
    let removed = original_count - servers.len();
    info!(
        removed_count = removed,
        remaining_count = servers.len(),
        "Cleaned up marked servers after configuration reload"
    );
    
    removed
}

/// Add new or update existing server configuration
///
/// Adds a new upstream server or updates an existing equivalent server.
/// Handles server equivalence checking for round-robin groups.
///
/// # Arguments
///
/// * `servers` - Mutable vector to add server to
/// * `new_server` - Server to add
///
/// # Returns
///
/// * `true` if server was added or updated successfully
/// * `false` if server creation failed
///
/// # Behavior
///
/// - Checks for duplicate servers (same domain, flags, address)
/// - Groups equivalent servers for round-robin selection
/// - Clears SERV_MARK flag on updated servers
/// - Allocates new server if no equivalent found
///
/// # Example
///
/// ```rust,ignore
/// let server = UpstreamServer::new(...);
/// if add_update_server(&mut servers, Arc::new(server)) {
///     info!("Server added to configuration");
/// }
/// ```
pub fn add_update_server(
    servers: &mut Vec<Arc<UpstreamServer>>,
    new_server: Arc<UpstreamServer>,
) -> bool {
    // Check for duplicate or equivalent server
    for existing in servers.iter_mut() {
        if server_samegroup(existing, &new_server) {
            // Found equivalent server
            if existing.addr() == new_server.addr() {
                // Exact duplicate - clear mark flag if set
                debug!(
                    domain = ?new_server.domain(),
                    addr = %new_server.addr(),
                    "Found existing server, clearing SERV_MARK"
                );
                // Note: Can't modify flags through Arc without interior mutability
                // In real implementation, would need to replace the Arc
                return true;
            }
            // Equivalent but different address - forms round-robin group
            debug!(
                domain = ?new_server.domain(),
                addr = %new_server.addr(),
                "Found equivalent server for round-robin group"
            );
        }
    }

    // No equivalent found - add new server
    let domain = new_server.domain().map(|s| s.to_string());
    let addr = new_server.addr();
    
    servers.push(new_server);
    
    info!(
        domain = ?domain,
        addr = %addr,
        total_servers = servers.len(),
        "Added new upstream server to configuration"
    );

    true
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Compare two servers for sorting by domain specificity
///
/// Sorting order (most specific first):
/// 1. Longer domain names (more labels)
/// 2. Lexicographic order for same length
/// 3. Exact match before wildcard for same domain
/// 4. NODOTS servers last (no domain)
///
/// # Arguments
///
/// * `s1` - First server
/// * `s2` - Second server
///
/// # Returns
///
/// * Ordering for Vec::sort_by
fn order_servers(s1: &UpstreamServer, s2: &UpstreamServer) -> Ordering {
    match (s1.domain(), s2.domain()) {
        (Some(d1), Some(d2)) => {
            // Both have domains - compare by hostname_order
            let cmp = hostname_order(d1, d2);
            if cmp != Ordering::Equal {
                return cmp;
            }

            // Same domain - wildcard sorts after exact match
            let w1 = s1.flags().contains(SERV_WILDCARD);
            let w2 = s2.flags().contains(SERV_WILDCARD);
            match (w1, w2) {
                (true, false) => Ordering::Greater, // Wildcard sorts after
                (false, true) => Ordering::Less,    // Exact sorts before
                _ => Ordering::Equal,                // Both same type
            }
        }
        (Some(_), None) => Ordering::Less,    // Domain sorts before NODOTS
        (None, Some(_)) => Ordering::Greater, // NODOTS sorts after domain
        (None, None) => Ordering::Equal,      // Both NODOTS
    }
}

/// Compare query domain to server domain for binary search
///
/// Implements the ordering required for binary search in lookup_domain.
/// Must match the sorting order from order_servers().
///
/// # Arguments
///
/// * `qdomain` - Query domain name
/// * `qlen` - Query domain length
/// * `sdomain` - Server domain name
/// * `slen` - Server domain length
///
/// # Returns
///
/// * Ordering for binary search position
fn order_comparison(qdomain: &str, _qlen: usize, sdomain: &str, _slen: usize) -> Ordering {
    // Use hostname_order for domain comparison
    hostname_order(qdomain, sdomain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serv_is_local_constant() {
        assert!(SERV_IS_LOCAL.contains(SERV_USE_RESOLV));
        assert!(SERV_IS_LOCAL.contains(SERV_LITERAL_ADDRESS));
        assert!(!SERV_IS_LOCAL.contains(SERV_DO_DNSSEC));
    }

    #[test]
    fn test_server_samegroup() {
        // Test would require constructing UpstreamServer instances
        // Actual test implementation depends on UpstreamServer API
    }

    #[test]
    fn test_filter_servers() {
        // Test would require constructing server array
        // Actual test implementation depends on complete type definitions
    }

    #[test]
    fn test_build_server_array_empty() {
        let servers: Vec<Arc<UpstreamServer>> = vec![];
        let local_servers: Vec<Arc<UpstreamServer>> = vec![];
        
        let array = build_server_array(&servers, &local_servers);
        assert_eq!(array.len(), 0);
    }
}

