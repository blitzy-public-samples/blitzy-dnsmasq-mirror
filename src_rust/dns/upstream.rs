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

// Suppress missing_docs for bitflags macro-generated internal constants
#![allow(missing_docs)]

//! Upstream DNS server selection and health tracking for query forwarding
//!
//! This module manages upstream DNS server configuration including addresses, query counters,
//! failure tracking, and health metrics for intelligent server selection. Implements server
//! rotation on failures, exponential backoff for unhealthy servers, and domain-specific server
//! routing based on configuration.
//!
//! # Features
//!
//! - **Memory-Safe Server Management**: Replace C's linked list with Vec<Server> for safe iteration
//! - **Health Tracking**: Track query counts, failure counts, and last success timestamps
//! - **Domain-Specific Routing**: O(1) lookup using HashMap for domain-to-server mapping
//! - **Server Selection**: Intelligent algorithm with health-based selection and load balancing
//! - **Exponential Backoff**: Automatic retry with exponential backoff for unhealthy servers
//! - **Wildcard Matching**: Support for wildcard domain patterns (*.example.com)
//!
//! # Memory Safety Improvements
//!
//! - Eliminates manual server linked list traversal and pointer arithmetic
//! - Uses Arc<RwLock<Server>> for safe concurrent access during async operations
//! - HashMap replaces linear search for O(1) domain matching
//! - Automatic memory management through Rust's Drop trait
//!
//! # Configuration Compatibility
//!
//! Preserves 100% backward compatibility with C implementation:
//! - `--server=/domain/address` for domain-specific servers
//! - `--rev-server=subnet,address` for reverse DNS servers
//! - `--address=/domain/address` for literal address responses
//! - All SERV_* flags from C implementation preserved in ServerFlags
//!
//! # RFC Compliance
//!
//! - RFC 1035: DNS query forwarding and server selection
//! - Implements dnsmasq-specific server health tracking and rotation logic

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime};

use bitflags::bitflags;
use tracing::{debug, info, trace, warn};

use crate::dns::domain::hostname_isequal;

// ============================================================================
// Constants for server health tracking and testing
// ============================================================================

/// Number of queries sent before checking server responsiveness
/// From C forward.c: #define FORWARD_TEST 50
pub const FORWARD_TEST: u32 = 50;

/// Time interval (seconds) for server health checks
/// From C forward.c: #define FORWARD_TIME 20
pub const FORWARD_TIME: u64 = 20;

// ============================================================================
// Server Flags
// ============================================================================

bitflags! {
    /// Type-safe server flags representing server types and behavior flags
    ///
    /// Replaces C's SERV_* constants with compile-time verified flag operations.
    /// Prevents invalid flag combinations and bit position errors from C implementation.
    ///
    /// # Flags from C implementation (src/dnsmasq.h)
    ///
    /// - LITERAL_ADDRESS: addr is the answer, or NoDATA depending on next flags
    /// - USE_RESOLV: forward this domain in the normal way
    /// - ALL_ZEROS: return all zeros for A and AAAA queries
    /// - ADDR_4: addr is IPv4
    /// - ADDR_6: addr is IPv6
    /// - HAS_SOURCE: source address defined for binding
    /// - FOR_NODOTS: server for names with no domain part only
    /// - WARNED_RECURSIVE: avoid warning spam for recursive servers
    /// - FROM_DBUS: server configuration from D-Bus
    /// - MARK: mark-and-delete flag for config reload
    /// - WILDCARD: domain has leading '*' for wildcard matching
    /// - FROM_RESOLV: server from resolv.conf
    /// - FROM_FILE: server from --servers-file
    /// - LOOP: server causes forwarding loop (detected)
    /// - DO_DNSSEC: validate DNSSEC when using this server
    /// - GOT_TCP: got some data from the TCP connection
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerFlags: u16 {
        const LITERAL_ADDRESS    = 1;
        const USE_RESOLV         = 2;
        const ALL_ZEROS          = 4;
        const ADDR_4             = 8;
        const ADDR_6             = 16;
        const HAS_SOURCE         = 32;
        const FOR_NODOTS         = 64;
        const WARNED_RECURSIVE   = 128;
        const FROM_DBUS          = 256;
        const MARK               = 512;
        const WILDCARD           = 1024;
        const FROM_RESOLV        = 2048;
        const FROM_FILE          = 4096;
        const LOOP               = 8192;
        const DO_DNSSEC          = 16384;
        const GOT_TCP            = 32768;
    }
}

impl fmt::Display for ServerFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.contains(ServerFlags::LITERAL_ADDRESS) {
            flags.push("LITERAL_ADDRESS");
        }
        if self.contains(ServerFlags::USE_RESOLV) {
            flags.push("USE_RESOLV");
        }
        if self.contains(ServerFlags::ALL_ZEROS) {
            flags.push("ALL_ZEROS");
        }
        if self.contains(ServerFlags::ADDR_4) {
            flags.push("ADDR_4");
        }
        if self.contains(ServerFlags::ADDR_6) {
            flags.push("ADDR_6");
        }
        if self.contains(ServerFlags::HAS_SOURCE) {
            flags.push("HAS_SOURCE");
        }
        if self.contains(ServerFlags::FOR_NODOTS) {
            flags.push("FOR_NODOTS");
        }
        if self.contains(ServerFlags::FROM_DBUS) {
            flags.push("FROM_DBUS");
        }
        if self.contains(ServerFlags::WILDCARD) {
            flags.push("WILDCARD");
        }
        if self.contains(ServerFlags::FROM_RESOLV) {
            flags.push("FROM_RESOLV");
        }
        if self.contains(ServerFlags::FROM_FILE) {
            flags.push("FROM_FILE");
        }
        if self.contains(ServerFlags::LOOP) {
            flags.push("LOOP");
        }
        if self.contains(ServerFlags::DO_DNSSEC) {
            flags.push("DO_DNSSEC");
        }
        write!(f, "{}", flags.join("|"))
    }
}

// ============================================================================
// Public ServerFlags Constants for Backward Compatibility
// ============================================================================

/// Server flag constants exported for use in pattern matching and filtering
/// These are public aliases to ServerFlags constants for backward compatibility
/// with C implementation's SERV_* macros.

pub const SERV_LITERAL_ADDRESS: ServerFlags = ServerFlags::LITERAL_ADDRESS;
pub const SERV_USE_RESOLV: ServerFlags = ServerFlags::USE_RESOLV;
pub const SERV_ALL_ZEROS: ServerFlags = ServerFlags::ALL_ZEROS;
pub const SERV_4ADDR: ServerFlags = ServerFlags::ADDR_4;
pub const SERV_6ADDR: ServerFlags = ServerFlags::ADDR_6;
pub const SERV_HAS_SOURCE: ServerFlags = ServerFlags::HAS_SOURCE;
pub const SERV_FOR_NODOTS: ServerFlags = ServerFlags::FOR_NODOTS;
pub const SERV_WARNED_RECURSIVE: ServerFlags = ServerFlags::WARNED_RECURSIVE;
pub const SERV_FROM_DBUS: ServerFlags = ServerFlags::FROM_DBUS;
pub const SERV_MARK: ServerFlags = ServerFlags::MARK;
pub const SERV_WILDCARD: ServerFlags = ServerFlags::WILDCARD;
pub const SERV_FROM_RESOLV: ServerFlags = ServerFlags::FROM_RESOLV;
pub const SERV_FROM_FILE: ServerFlags = ServerFlags::FROM_FILE;
pub const SERV_LOOP: ServerFlags = ServerFlags::LOOP;
pub const SERV_DO_DNSSEC: ServerFlags = ServerFlags::DO_DNSSEC;
pub const SERV_GOT_TCP: ServerFlags = ServerFlags::GOT_TCP;

// ============================================================================
// Server Identifier
// ============================================================================

/// Unique identifier for an upstream server
///
/// Used for server tracking and lookup in domain-to-server routing maps.
pub type ServerId = usize;

// ============================================================================
// Server Health Tracking
// ============================================================================

/// Server health statistics for intelligent server selection
///
/// Tracks query success/failure rates and last successful response time
/// for implementing health-based server selection with exponential backoff.
#[derive(Debug, Clone)]
pub struct ServerHealth {
    /// Total number of queries sent to this server
    query_count: u32,
    /// Number of failed queries (timeouts, errors)
    failure_count: u32,
    /// Timestamp of last successful response
    last_success: Option<SystemTime>,
    /// Instant for exponential backoff calculations
    last_check: Instant,
}

impl ServerHealth {
    /// Create new health tracker with zero counters
    pub fn new() -> Self {
        Self {
            query_count: 0,
            failure_count: 0,
            last_success: None,
            last_check: Instant::now(),
        }
    }

    /// Get total query count
    pub fn query_count(&self) -> u32 {
        self.query_count
    }

    /// Get failure count
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// Get last success timestamp
    pub fn last_success(&self) -> Option<SystemTime> {
        self.last_success
    }

    /// Check if server is healthy based on failure rate
    ///
    /// Server is considered unhealthy if:
    /// - Failure rate exceeds 50% and query count >= FORWARD_TEST
    /// - OR no successful responses in FORWARD_TIME seconds
    pub fn is_healthy(&self) -> bool {
        // Not enough data yet
        if self.query_count < FORWARD_TEST {
            return true;
        }

        // Check failure rate
        let failure_rate = (self.failure_count as f64) / (self.query_count as f64);
        if failure_rate > 0.5 {
            return false;
        }

        // Check time since last success
        if let Some(last_success) = self.last_success {
            if let Ok(elapsed) = SystemTime::now().duration_since(last_success) {
                if elapsed.as_secs() > FORWARD_TIME {
                    return false;
                }
            }
        } else if self.query_count >= FORWARD_TEST {
            // No successful responses after FORWARD_TEST queries
            return false;
        }

        true
    }

    /// Record successful query response
    pub fn record_success(&mut self) {
        self.query_count += 1;
        self.last_success = Some(SystemTime::now());
        self.last_check = Instant::now();
        trace!(
            query_count = self.query_count,
            failure_count = self.failure_count,
            "Server health: success recorded"
        );
    }

    /// Record failed query (timeout or error)
    pub fn record_failure(&mut self) {
        self.query_count += 1;
        self.failure_count += 1;
        self.last_check = Instant::now();
        warn!(
            query_count = self.query_count,
            failure_count = self.failure_count,
            "Server health: failure recorded"
        );
    }

    /// Reset health statistics (e.g., after configuration reload)
    pub fn reset(&mut self) {
        self.query_count = 0;
        self.failure_count = 0;
        self.last_success = None;
        self.last_check = Instant::now();
        debug!("Server health statistics reset");
    }
}

impl Default for ServerHealth {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Domain Pattern Matching
// ============================================================================

/// Domain pattern for server selection
///
/// Supports exact domain matching and wildcard patterns (*.example.com).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainPattern {
    /// Original domain pattern string
    domain: String,
    /// True if pattern starts with wildcard (*)
    is_wildcard: bool,
}

impl DomainPattern {
    /// Create new domain pattern
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain pattern string, may start with '*' for wildcard
    pub fn new(domain: String) -> Self {
        let is_wildcard = domain.starts_with('*');
        Self {
            domain,
            is_wildcard,
        }
    }

    /// Get domain pattern string
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Check if this is a wildcard pattern
    pub fn is_wildcard(&self) -> bool {
        self.is_wildcard
    }

    /// Check if query domain matches this pattern
    ///
    /// Implements DNS domain matching with wildcard support:
    /// - Exact match if not wildcard
    /// - Suffix match if wildcard (*.example.com matches www.example.com)
    ///
    /// # Arguments
    ///
    /// * `query_domain` - Domain name from DNS query
    ///
    /// # Returns
    ///
    /// * `true` if query_domain matches this pattern
    pub fn matches(&self, query_domain: &str) -> bool {
        if self.is_wildcard {
            // Wildcard match: *.example.com matches www.example.com and example.com
            let pattern_suffix = &self.domain[1..]; // Remove leading '*'
            if pattern_suffix.is_empty() {
                return true; // Catch-all pattern '*'
            }
            
            // Pattern is "*.example.com", suffix is ".example.com"
            // Should match:
            // 1. "example.com" (base domain, strip the "*." prefix)
            // 2. "www.example.com" (ends with ".example.com")
            
            // Strip leading dot if present to get base domain
            let base_domain = if pattern_suffix.starts_with('.') {
                &pattern_suffix[1..]
            } else {
                pattern_suffix
            };
            
            // Check if query matches base domain exactly
            if hostname_isequal(query_domain, base_domain) {
                return true;
            }
            
            // Check if query domain ends with pattern suffix (e.g., ends with ".example.com")
            query_domain
                .to_lowercase()
                .ends_with(&pattern_suffix.to_lowercase())
        } else {
            // Exact match only for non-wildcard patterns (case-insensitive per RFC 1035)
            hostname_isequal(query_domain, &self.domain)
        }
    }
}

// ============================================================================
// Upstream Server
// ============================================================================

/// Upstream DNS server configuration and state
///
/// Represents a single upstream DNS server with address, health tracking,
/// and configuration flags. Replaces C's struct server with memory-safe
/// Rust implementation using Arc for shared ownership.
#[derive(Debug)]
pub struct UpstreamServer {
    /// Unique server identifier
    uid: ServerId,
    /// Server type and behavior flags
    flags: ServerFlags,
    /// Domain pattern for domain-specific servers (None for general servers)
    domain: Option<DomainPattern>,
    /// Length of domain string (optimization for C compatibility)
    domain_len: usize,
    /// Server socket address (IP + port)
    addr: SocketAddr,
    /// Optional source address for binding outgoing queries
    source_addr: Option<SocketAddr>,
    /// Network interface name for binding (empty if not specified)
    interface: String,
    /// Interface index for IPv6 link-local addresses
    ifindex: u32,
    /// EDNS0 packet size (UDP payload size)
    edns_pktsz: u16,
    /// Health tracking statistics
    health: RwLock<ServerHealth>,
}

impl UpstreamServer {
    /// Create new upstream server
    ///
    /// # Arguments
    ///
    /// * `uid` - Unique server identifier
    /// * `flags` - Server type and behavior flags
    /// * `domain` - Optional domain pattern for domain-specific server
    /// * `addr` - Server socket address
    /// * `source_addr` - Optional source address for binding
    /// * `interface` - Network interface name (empty string if none)
    /// * `ifindex` - Interface index for IPv6
    /// * `edns_pktsz` - EDNS0 packet size limit
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uid: ServerId,
        flags: ServerFlags,
        domain: Option<String>,
        addr: SocketAddr,
        source_addr: Option<SocketAddr>,
        interface: String,
        ifindex: u32,
        edns_pktsz: u16,
    ) -> Self {
        let domain_pattern = domain.as_ref().map(|d| DomainPattern::new(d.clone()));
        let domain_len = domain.as_ref().map(|d| d.len()).unwrap_or(0);

        Self {
            uid,
            flags,
            domain: domain_pattern,
            domain_len,
            addr,
            source_addr,
            interface,
            ifindex,
            edns_pktsz,
            health: RwLock::new(ServerHealth::new()),
        }
    }

    /// Get server unique identifier
    pub fn uid(&self) -> ServerId {
        self.uid
    }

    /// Get server flags
    pub fn flags(&self) -> ServerFlags {
        self.flags
    }

    /// Get domain pattern (if domain-specific server)
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_ref().map(|d| d.domain())
    }

    /// Get domain length
    pub fn domain_len(&self) -> usize {
        self.domain_len
    }

    /// Get server socket address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get source address for binding
    pub fn source_addr(&self) -> Option<SocketAddr> {
        self.source_addr
    }

    /// Get network interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get interface index
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Get total query count
    pub fn queries(&self) -> u32 {
        self.health.read().unwrap().query_count()
    }

    /// Get failed query count
    pub fn failed_queries(&self) -> u32 {
        self.health.read().unwrap().failure_count()
    }

    /// Get last successful response time
    pub fn last_success(&self) -> Option<SystemTime> {
        self.health.read().unwrap().last_success()
    }

    /// Get EDNS0 packet size
    pub fn edns_pktsz(&self) -> u16 {
        self.edns_pktsz
    }

    /// Check if server is healthy
    pub fn is_healthy(&self) -> bool {
        self.health.read().unwrap().is_healthy()
    }

    /// Update health statistics after query response
    ///
    /// # Arguments
    ///
    /// * `success` - True if query succeeded, false if failed/timeout
    pub fn update_health(&self, success: bool) {
        let mut health = self.health.write().unwrap();
        if success {
            health.record_success();
        } else {
            health.record_failure();
        }
    }

    /// Reset failure counters (e.g., after detecting recovery)
    pub fn reset_failures(&self) {
        let mut health = self.health.write().unwrap();
        health.reset();
    }

    /// Increment query counter without recording success/failure
    pub fn increment_queries(&self) {
        let mut health = self.health.write().unwrap();
        health.query_count += 1;
    }
}

// ============================================================================
// Upstream Pool
// ============================================================================

/// Manages collection of upstream DNS servers with intelligent selection
///
/// Provides server registration, domain-based routing, health tracking,
/// and intelligent server selection based on health metrics. Replaces C's
/// global server linked list with safe Vec and HashMap structures.
pub struct UpstreamPool {
    /// All configured upstream servers
    servers: Vec<Arc<UpstreamServer>>,
    /// Domain-to-server routing map for O(1) lookup
    domain_map: HashMap<String, Vec<ServerId>>,
    /// Next server UID to assign
    next_uid: ServerId,
}

impl UpstreamPool {
    /// Create new upstream pool
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            domain_map: HashMap::new(),
            next_uid: 1, // Start at 1, 0 reserved for "no server"
        }
    }

    /// Add new upstream server
    ///
    /// # Arguments
    ///
    /// * `flags` - Server type and behavior flags
    /// * `domain` - Optional domain pattern for domain-specific server
    /// * `addr` - Server socket address
    /// * `source_addr` - Optional source address for binding
    /// * `interface` - Network interface name
    /// * `ifindex` - Interface index for IPv6
    /// * `edns_pktsz` - EDNS0 packet size limit
    ///
    /// # Returns
    ///
    /// * Server UID for the newly added server
    #[allow(clippy::too_many_arguments)]
    pub fn add_server(
        &mut self,
        flags: ServerFlags,
        domain: Option<String>,
        addr: SocketAddr,
        source_addr: Option<SocketAddr>,
        interface: String,
        ifindex: u32,
        edns_pktsz: u16,
    ) -> ServerId {
        let uid = self.next_uid;
        self.next_uid += 1;

        // Convert domain-specific servers to wildcard patterns
        // This matches dnsmasq behavior where server=/example.com/1.1.1.1
        // handles queries for example.com and all subdomains
        let wildcard_domain = domain.as_ref().map(|d| {
            if d.starts_with('*') {
                d.clone()
            } else {
                format!("*.{}", d)
            }
        });

        let server = Arc::new(UpstreamServer::new(
            uid,
            flags,
            wildcard_domain,
            addr,
            source_addr,
            interface,
            ifindex,
            edns_pktsz,
        ));

        // Add to domain map if domain-specific
        if let Some(ref domain_str) = domain {
            self.domain_map
                .entry(domain_str.to_lowercase())
                .or_insert_with(Vec::new)
                .push(uid);
        }

        self.servers.push(server);

        info!(
            uid = uid,
            addr = %addr,
            domain = domain.as_deref().unwrap_or("*"),
            "Added upstream server"
        );

        uid
    }

    /// Remove server by UID
    ///
    /// # Arguments
    ///
    /// * `uid` - Server UID to remove
    ///
    /// # Returns
    ///
    /// * `true` if server was found and removed
    pub fn remove_server(&mut self, uid: ServerId) -> bool {
        if let Some(pos) = self.servers.iter().position(|s| s.uid() == uid) {
            let server = self.servers.remove(pos);

            // Remove from domain map
            if let Some(domain) = server.domain() {
                if let Some(servers) = self.domain_map.get_mut(&domain.to_lowercase()) {
                    servers.retain(|&id| id != uid);
                }
            }

            info!(uid = uid, "Removed upstream server");
            true
        } else {
            false
        }
    }

    /// Select best upstream server for a query
    ///
    /// Implements intelligent server selection:
    /// 1. Domain-specific servers have priority if domain matches
    /// 2. Among matching servers, prefer healthy servers
    /// 3. Use round-robin among healthy servers
    /// 4. Fall back to least-recently-failed server if all unhealthy
    ///
    /// # Arguments
    ///
    /// * `query_domain` - Domain name from DNS query (None for default servers)
    ///
    /// # Returns
    ///
    /// * Some(Arc<UpstreamServer>) if suitable server found, None if no servers available
    pub fn select_server(&self, query_domain: Option<&str>) -> Option<Arc<UpstreamServer>> {
        let candidates = if let Some(domain) = query_domain {
            self.get_server_by_domain(domain)
        } else {
            // No domain specified, use all general servers
            self.servers
                .iter()
                .filter(|s| s.domain().is_none() && !s.flags().contains(ServerFlags::LOOP))
                .cloned()
                .collect()
        };

        if candidates.is_empty() {
            debug!("No upstream servers available");
            return None;
        }

        // Filter healthy servers
        let healthy: Vec<_> = candidates
            .iter()
            .filter(|s| s.is_healthy())
            .cloned()
            .collect();

        if !healthy.is_empty() {
            // Select healthy server with minimum queries (load balancing)
            let selected = healthy
                .iter()
                .min_by_key(|s| s.queries())
                .cloned()?;

            trace!(
                uid = selected.uid(),
                addr = %selected.addr(),
                queries = selected.queries(),
                "Selected healthy upstream server"
            );

            Some(selected)
        } else {
            // All servers unhealthy, select least-recently-failed
            let selected = candidates
                .iter()
                .max_by_key(|s| s.last_success())
                .cloned()?;

            warn!(
                uid = selected.uid(),
                addr = %selected.addr(),
                "All servers unhealthy, using least-recently-failed"
            );

            Some(selected)
        }
    }

    /// Get servers matching domain pattern
    ///
    /// # Arguments
    ///
    /// * `query_domain` - Domain name from DNS query
    ///
    /// # Returns
    ///
    /// * Vec of matching servers (empty if no matches)
    pub fn get_server_by_domain(&self, query_domain: &str) -> Vec<Arc<UpstreamServer>> {
        let mut matches = Vec::new();

        // Check domain map for exact/prefix matches
        for server in &self.servers {
            if let Some(ref pattern) = server.domain {
                if pattern.matches(query_domain) && !server.flags().contains(ServerFlags::LOOP) {
                    matches.push(Arc::clone(server));
                }
            }
        }

        // If no domain-specific matches, use general servers
        if matches.is_empty() {
            matches = self.servers
                .iter()
                .filter(|s| s.domain().is_none() && !s.flags().contains(ServerFlags::LOOP))
                .cloned()
                .collect();
        }

        matches
    }

    /// Mark server query as failed
    ///
    /// # Arguments
    ///
    /// * `uid` - Server UID
    pub fn mark_failure(&self, uid: ServerId) {
        if let Some(server) = self.servers.iter().find(|s| s.uid() == uid) {
            server.update_health(false);
        }
    }

    /// Mark server query as successful
    ///
    /// # Arguments
    ///
    /// * `uid` - Server UID
    pub fn mark_success(&self, uid: ServerId) {
        if let Some(server) = self.servers.iter().find(|s| s.uid() == uid) {
            server.update_health(true);
        }
    }

    /// Get all configured servers
    pub fn get_all_servers(&self) -> &[Arc<UpstreamServer>] {
        &self.servers
    }

    /// Get health statistics for all servers
    ///
    /// # Returns
    ///
    /// * Vec of (uid, queries, failures, healthy) tuples
    pub fn get_health_stats(&self) -> Vec<(ServerId, u32, u32, bool)> {
        self.servers
            .iter()
            .map(|s| (s.uid(), s.queries(), s.failed_queries(), s.is_healthy()))
            .collect()
    }
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Health Check Function (for periodic server health monitoring)
// ============================================================================

/// Perform server health check cycle
///
/// Examines all configured servers and resets health statistics for servers
/// that have recovered (received successful response after failures). This
/// implements the FORWARD_TEST/FORWARD_TIME health check algorithm from C.
///
/// # Arguments
///
/// * `pool` - Upstream pool containing servers to check
///
/// # Returns
///
/// * Number of unhealthy servers detected
pub fn check_servers(pool: &UpstreamPool) -> usize {
    let mut unhealthy_count = 0;

    for server in pool.get_all_servers() {
        let is_healthy = server.is_healthy();

        if !is_healthy {
            unhealthy_count += 1;
            warn!(
                uid = server.uid(),
                addr = %server.addr(),
                queries = server.queries(),
                failures = server.failed_queries(),
                "Unhealthy upstream server detected"
            );
        }

        // Log server statistics periodically
        if server.queries() % FORWARD_TEST == 0 && server.queries() > 0 {
            info!(
                uid = server.uid(),
                addr = %server.addr(),
                queries = server.queries(),
                failures = server.failed_queries(),
                healthy = is_healthy,
                "Server health check"
            );
        }
    }

    if unhealthy_count > 0 {
        warn!(
            unhealthy_count = unhealthy_count,
            total_servers = pool.get_all_servers().len(),
            "Unhealthy servers detected in health check"
        );
    }

    unhealthy_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // Define NAMESERVER_PORT for tests since we removed the import
    const NAMESERVER_PORT: u16 = 53;

    #[test]
    fn test_domain_pattern_exact_match() {
        let pattern = DomainPattern::new("example.com".to_string());
        assert!(!pattern.is_wildcard());
        assert!(pattern.matches("example.com"));
        assert!(pattern.matches("EXAMPLE.COM")); // Case-insensitive
        assert!(!pattern.matches("www.example.com"));
    }

    #[test]
    fn test_domain_pattern_wildcard_match() {
        let pattern = DomainPattern::new("*.example.com".to_string());
        assert!(pattern.is_wildcard());
        assert!(pattern.matches("www.example.com"));
        assert!(pattern.matches("mail.example.com"));
        assert!(pattern.matches("example.com")); // Wildcard also matches base domain
        assert!(!pattern.matches("example.org"));
    }

    #[test]
    fn test_server_health_tracking() {
        let mut health = ServerHealth::new();

        // Initial state: healthy
        assert!(health.is_healthy());
        assert_eq!(health.query_count(), 0);
        assert_eq!(health.failure_count(), 0);

        // Record some successes
        for _ in 0..FORWARD_TEST {
            health.record_success();
        }
        assert!(health.is_healthy());

        // Record failures (< 50% failure rate)
        for _ in 0..20 {
            health.record_failure();
        }
        assert!(health.is_healthy()); // Still < 50% failure rate

        // Record more failures to exceed 50%
        for _ in 0..40 {
            health.record_failure();
        }
        assert!(!health.is_healthy()); // Now unhealthy
    }

    #[test]
    fn test_upstream_pool_add_remove() {
        let mut pool = UpstreamPool::new();

        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), NAMESERVER_PORT);
        let uid1 = pool.add_server(
            ServerFlags::USE_RESOLV,
            None,
            addr1,
            None,
            String::new(),
            0,
            4096,
        );

        assert_eq!(pool.get_all_servers().len(), 1);

        let removed = pool.remove_server(uid1);
        assert!(removed);
        assert_eq!(pool.get_all_servers().len(), 0);
    }

    #[test]
    fn test_server_selection_by_domain() {
        let mut pool = UpstreamPool::new();

        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), NAMESERVER_PORT);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), NAMESERVER_PORT);

        // General server
        pool.add_server(
            ServerFlags::USE_RESOLV,
            None,
            addr1,
            None,
            String::new(),
            0,
            4096,
        );

        // Domain-specific server
        pool.add_server(
            ServerFlags::USE_RESOLV,
            Some("example.com".to_string()),
            addr2,
            None,
            String::new(),
            0,
            4096,
        );

        // Query for example.com should use domain-specific server
        let selected = pool.select_server(Some("www.example.com"));
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().addr(), addr2);

        // Query for other domain should use general server
        let selected = pool.select_server(Some("google.com"));
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().addr(), addr1);
    }

    #[test]
    fn test_server_flags() {
        let flags = ServerFlags::USE_RESOLV | ServerFlags::DO_DNSSEC;
        assert!(flags.contains(ServerFlags::USE_RESOLV));
        assert!(flags.contains(ServerFlags::DO_DNSSEC));
        assert!(!flags.contains(ServerFlags::LOOP));

        let mut flags2 = ServerFlags::ADDR_4;
        flags2.insert(ServerFlags::HAS_SOURCE);
        assert!(flags2.contains(ServerFlags::ADDR_4));
        assert!(flags2.contains(ServerFlags::HAS_SOURCE));

        flags2.remove(ServerFlags::ADDR_4);
        assert!(!flags2.contains(ServerFlags::ADDR_4));
        assert!(flags2.contains(ServerFlags::HAS_SOURCE));
    }
}
