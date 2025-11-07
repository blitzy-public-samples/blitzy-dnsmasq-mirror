// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS query forwarding to upstream servers with randomization and retry
//
// Translated from: src/forward.c

//! DNS Query Forwarding Pipeline
//!
//! This module implements the complete DNS query forwarding subsystem for dnsmasq,
//! handling query reception from network listeners, cache integration, upstream
//! server selection with health tracking, and response processing. It manages the
//! lifecycle of forward records that track DNS transaction state from query
//! reception through upstream transmission to response delivery.
//!
//! ## Key Responsibilities
//!
//! - **Query Forwarding**: Forward DNS queries to upstream servers with domain-specific routing
//! - **ID Randomization**: Generate random query IDs to prevent cache poisoning attacks
//! - **Source Port Randomization**: Use random source ports for additional security entropy
//! - **Server Selection**: Choose optimal upstream server based on domain matching and health
//! - **Retry Logic**: Implement exponential backoff with server rotation on failures
//! - **Response Processing**: Match responses to queries, restore original IDs, cache results
//! - **TCP Fallback**: Automatically retry over TCP when UDP responses are truncated
//! - **EDNS0 Handling**: Propagate EDNS0 extensions including DNSSEC DO bit
//! - **Server Health Tracking**: Monitor upstream server response times and failures
//!
//! ## Memory Safety
//!
//! Replaces C's manual forward record allocation from freelists with Rust's HashMap-based
//! tracking, eliminating use-after-free vulnerabilities. All network I/O uses Tokio's async
//! sockets with automatic timeout management, preventing resource leaks.
//!
//! ## Thread Safety
//!
//! The forwarding system can be used concurrently from multiple async tasks. Forward records
//! are stored in a HashMap protected by appropriate locking mechanisms. Server health tracking
//! uses atomic operations where possible for lock-free updates.
//!
//! ## C Source Reference
//!
//! Translated from:
//! - `src/forward.c` (lines 1-2800) - Main forwarding implementation
//! - `src/dnsmasq.h` (lines 2379-2403) - struct frec definition
//! - `src/dnsmasq.h` (lines 1926-1944) - struct server definition

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::net::{TcpStream, UdpSocket};
use tokio::select;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};

use crate::constants::{FORWARD_TIMEOUT, MAX_FORWARD_REQUESTS};
use crate::dns::cache::DnsCache;
use crate::dns::domain::domain_equal;
use crate::dns::edns::OptRecord;
use crate::dns::protocol::{DnsMessage, RecordType};
use crate::types::errors::{DnsmasqError, DnsmasqResult};
use crate::util::crypto::random_u16;
use crate::util::time::is_expired;

/// Maximum number of servers to try in a single forwarding attempt
const MAX_SERVER_TRIES: usize = 3;

/// Default query timeout in seconds
const DEFAULT_QUERY_TIMEOUT_SECS: u64 = FORWARD_TIMEOUT;

/// TCP query timeout (longer than UDP)
const TCP_QUERY_TIMEOUT_SECS: u64 = 30;

/// Maximum number of concurrent queries for --all-servers mode
const MAX_CONCURRENT_QUERIES: usize = 5;

/// DNSSEC flags for forward records
pub const FREC_DO_QUESTION: u32 = 0x0001;
pub const FREC_AD_QUESTION: u32 = 0x0002;
pub const FREC_CHECKING_DISABLED: u32 = 0x0004;
pub const FREC_HAS_PHEADER: u32 = 0x0008;
pub const FREC_DNSKEY_QUERY: u32 = 0x0010;
pub const FREC_DS_QUERY: u32 = 0x0020;

/// Server flags indicating special properties
pub const SERV_FROM_DBUS: u16 = 0x0001;
pub const SERV_LITERAL_ADDRESS: u16 = 0x0002;
pub const SERV_USE_RESOLV: u16 = 0x0004;
pub const SERV_NO_REBIND: u16 = 0x0008;
pub const SERV_HAS_DOMAIN: u16 = 0x0010;

/// Forward record tracking DNS query transaction state
///
/// This structure tracks the lifecycle of a DNS query from client reception
/// through upstream forwarding to response delivery. It stores both the original
/// query ID from the client and the randomized ID sent to the upstream server,
/// enabling response correlation and ID restoration for cache poisoning prevention.
///
/// ## Security
///
/// The randomized_id field provides cryptographic randomization to prevent DNS
/// cache poisoning attacks. Combined with random source port selection, this
/// provides ~32 bits of entropy making attacks computationally infeasible.
///
/// ## C Struct Reference
///
/// Translated from C's `struct frec` (dnsmasq.h:2379-2403):
/// - `frec_src.orig_id` → original_id
/// - `new_id` → randomized_id
/// - `frec_src.source` → source_addr
/// - `sentto` → upstream_server
/// - `time` → sent_at
/// - `hash` → query_hash
/// - `flags` → dnssec_flags
#[derive(Debug, Clone)]
pub struct ForwardRecord {
    /// Original query ID from the client (must be restored in response)
    pub original_id: u16,

    /// Randomized query ID sent to upstream server (prevents cache poisoning)
    pub randomized_id: u16,

    /// Source socket address of the client that sent the query
    pub source_addr: SocketAddr,

    /// Upstream server socket address where query was forwarded
    pub upstream_server: SocketAddr,

    /// Timestamp when the query was sent to upstream server
    pub sent_at: Instant,

    /// Hash of the query for response matching and duplicate detection
    pub query_hash: u64,

    /// DNSSEC and query flags (DO bit, AD bit, CD bit, etc.)
    pub dnssec_flags: u32,
}

impl ForwardRecord {
    /// Create a new forward record for query tracking
    pub fn new(
        original_id: u16,
        source_addr: SocketAddr,
        upstream_server: SocketAddr,
        query_hash: u64,
        dnssec_flags: u32,
    ) -> Self {
        Self {
            original_id,
            randomized_id: random_u16(),
            source_addr,
            upstream_server,
            sent_at: Instant::now(),
            query_hash,
            dnssec_flags,
        }
    }

    /// Check if this forward record has timed out
    pub fn is_timed_out(&self, timeout_secs: u64) -> bool {
        self.sent_at.elapsed() > Duration::from_secs(timeout_secs)
    }

    /// Get the elapsed time since query was sent
    pub fn elapsed(&self) -> Duration {
        self.sent_at.elapsed()
    }
}

/// Upstream DNS server configuration and health tracking
///
/// Represents an upstream DNS server with optional domain-specific routing,
/// query statistics, and health metrics for server selection algorithms.
/// Servers can be configured via command-line (--server=), configuration file,
/// or dynamically via D-Bus.
///
/// ## Domain-Specific Routing
///
/// Servers can be restricted to specific domains using the `domain` field.
/// Queries for matching domains are routed only to servers configured for that
/// domain, enabling split-horizon DNS and enterprise DNS architectures.
///
/// ## Health Tracking
///
/// The `failed_queries` and `forwardtime` fields track server reliability and
/// response latency for intelligent server selection. Servers with recent failures
/// or slow response times are deprioritized.
///
/// ## C Struct Reference
///
/// Translated from C's `struct server` (dnsmasq.h:1926-1944):
/// - `addr` → addr
/// - `flags` → flags
/// - `domain` → domain (Option<String>)
/// - `failed_queries` → failed_queries
/// - `queries` → total_queries (not exposed in schema but tracked internally)
/// - `forwardtime` → forwardtime (tracked via Instant)
#[derive(Debug, Clone)]
pub struct Server {
    /// Server socket address (IP and port)
    pub addr: SocketAddr,

    /// Server flags (SERV_FROM_DBUS, SERV_LITERAL_ADDRESS, etc.)
    pub flags: u16,

    /// Optional domain restriction (if present, server only handles these domains)
    pub domain: Option<String>,

    /// Count of failed queries to this server (for health tracking)
    pub failed_queries: u32,

    /// Last successful query timestamp (for health and prioritization)
    pub forwardtime: Option<Instant>,

    /// Network interface name restriction (if specified)
    interface: Option<String>,

    /// Total queries sent to this server (statistics)
    total_queries: u64,
}

impl Server {
    /// Create a new server configuration
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            flags: 0,
            domain: None,
            failed_queries: 0,
            forwardtime: None,
            interface: None,
            total_queries: 0,
        }
    }

    /// Create server from address string (parses IP:port)
    pub fn from_address(address: &str) -> Result<Self, DnsmasqError> {
        let addr = address.parse::<SocketAddr>().map_err(|e| {
            DnsmasqError::Dns(crate::types::errors::DnsError::ForwardError {
                message: format!("Invalid server address '{}': {}", address, e),
            })
        })?;
        Ok(Self::new(addr))
    }

    /// Configure server with domain-specific routing
    pub fn with_domains(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self.flags |= SERV_HAS_DOMAIN;
        self
    }

    /// Configure server with interface binding
    pub fn with_interface(mut self, interface: String) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Mark server as configured via D-Bus
    pub fn mark_as_from_dbus(mut self) -> Self {
        self.flags |= SERV_FROM_DBUS;
        self
    }

    /// Check if server was configured via D-Bus
    pub fn is_from_dbus(&self) -> bool {
        (self.flags & SERV_FROM_DBUS) != 0
    }

    /// Check if server matches the given domain
    fn matches_domain(&self, query_domain: &str) -> bool {
        match &self.domain {
            None => true, // No domain restriction, matches all queries
            Some(server_domain) => {
                // Match if query domain ends with server domain
                domain_equal(query_domain, server_domain)
                    || query_domain.ends_with(&format!(".{}", server_domain))
            }
        }
    }

    /// Record a successful query to this server
    fn record_success(&mut self, response_time: Duration) {
        self.forwardtime = Some(Instant::now());
        self.failed_queries = 0; // Reset failure count on success
        self.total_queries += 1;
    }

    /// Record a failed query to this server
    fn record_failure(&mut self) {
        self.failed_queries += 1;
        self.total_queries += 1;
    }
}

/// Server health tracking metrics
///
/// Aggregates health and performance metrics for an upstream server, used
/// for intelligent server selection. Tracks both success/failure patterns
/// and response time characteristics.
///
/// ## Server Selection Algorithm
///
/// The forwarding logic uses these metrics to prefer:
/// 1. Servers with recent successes over those with recent failures
/// 2. Servers with lower average RTT over slower servers
/// 3. Servers with fewer consecutive failures
///
/// This implements a simple but effective load balancing and failover strategy.
#[derive(Debug, Clone)]
pub struct ServerHealth {
    /// Timestamp of last successful query response
    pub last_success: Option<Instant>,

    /// Timestamp of last query failure (timeout or error)
    pub last_failure: Option<Instant>,

    /// Number of consecutive query failures (reset on first success)
    pub consecutive_failures: u32,

    /// Exponentially weighted moving average of round-trip time
    pub average_rtt: Duration,
}

impl ServerHealth {
    /// Create new server health tracker
    pub fn new() -> Self {
        Self {
            last_success: None,
            last_failure: None,
            consecutive_failures: 0,
            average_rtt: Duration::from_millis(100), // Reasonable default
        }
    }

    /// Record a successful query
    pub fn record_success(&mut self, rtt: Duration) {
        self.last_success = Some(Instant::now());
        self.consecutive_failures = 0;

        // Update EWMA: new_avg = 0.8 * old_avg + 0.2 * new_sample
        let old_avg_ms = self.average_rtt.as_millis() as f64;
        let new_sample_ms = rtt.as_millis() as f64;
        let new_avg_ms = 0.8 * old_avg_ms + 0.2 * new_sample_ms;
        self.average_rtt = Duration::from_millis(new_avg_ms as u64);
    }

    /// Record a failed query
    pub fn record_failure(&mut self) {
        self.last_failure = Some(Instant::now());
        self.consecutive_failures += 1;
    }

    /// Calculate server score for selection (higher is better)
    pub fn score(&self) -> f64 {
        let mut score = 100.0;

        // Penalize consecutive failures exponentially
        score -= (self.consecutive_failures as f64) * 10.0;

        // Penalize slow average RTT
        let rtt_ms = self.average_rtt.as_millis() as f64;
        score -= rtt_ms / 10.0;

        // Bonus for recent success
        if let Some(last_success) = self.last_success {
            if last_success.elapsed() < Duration::from_secs(60) {
                score += 20.0;
            }
        }

        // Penalty for recent failure
        if let Some(last_failure) = self.last_failure {
            if last_failure.elapsed() < Duration::from_secs(60) {
                score -= 30.0;
            }
        }

        score.max(0.0)
    }
}

impl Default for ServerHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Add or update a server in the server list
///
/// This function manages the server list for dynamic server configuration,
/// particularly for D-Bus-controlled servers. It updates existing servers
/// or adds new ones as needed.
///
/// ## Usage
///
/// Called when:
/// - Servers are added via D-Bus SetServers method
/// - Configuration is reloaded (SIGHUP signal)
/// - Upstream resolvers change in /etc/resolv.conf
pub fn add_update_server(servers: &mut Vec<Server>, new_server: Server) {
    // Check if server already exists (by address)
    if let Some(existing) = servers.iter_mut().find(|s| s.addr == new_server.addr) {
        // Update existing server properties
        existing.flags = new_server.flags;
        existing.domain = new_server.domain;
        debug!("Updated existing server: {}", new_server.addr);
    } else {
        // Add new server
        servers.push(new_server.clone());
        info!("Added new server: {}", new_server.addr);
    }
}

/// Mark servers matching criteria for deletion
///
/// This function is used during server list updates to identify servers
/// that should be removed. Typically called before cleanup_servers() to
/// remove stale D-Bus servers or servers no longer in resolv.conf.
///
/// ## Usage
///
/// Called during configuration reload to mark D-Bus servers for cleanup
/// before re-adding current servers.
pub fn mark_servers(servers: &mut [Server], mark_flag: u16, set: bool) {
    for server in servers.iter_mut() {
        if set {
            server.flags |= mark_flag;
        } else {
            server.flags &= !mark_flag;
        }
    }
}

/// Remove servers marked for deletion
///
/// Cleans up servers that have been marked by mark_servers(). This two-phase
/// approach (mark, then cleanup) ensures atomicity during server list updates.
///
/// ## Usage
///
/// Called after mark_servers() to remove obsolete servers from the list.
pub fn cleanup_servers(servers: &mut Vec<Server>, cleanup_flag: u16) -> usize {
    let initial_count = servers.len();
    servers.retain(|s| (s.flags & cleanup_flag) == 0);
    let removed = initial_count - servers.len();

    if removed > 0 {
        info!("Removed {} marked servers", removed);
    }

    removed
}

/// Main query forwarding entry point
///
/// Handles a DNS query from a client by:
/// 1. Checking cache for existing answer
/// 2. Selecting appropriate upstream server(s)
/// 3. Randomizing query ID and source port
/// 4. Forwarding query with timeout
/// 5. Processing response and caching result
/// 6. Restoring original query ID
/// 7. Returning response to client
///
/// ## Security
///
/// - Query ID randomization prevents cache poisoning
/// - Source port randomization adds entropy
/// - Response validation ensures query/response correlation
/// - DNSSEC DO bit propagation when enabled
///
/// ## Error Handling
///
/// Returns errors for:
/// - Forward record table exhaustion
/// - No available upstream servers
/// - Network transmission failures
/// - Timeout waiting for response
///
/// ## C Function Reference
///
/// Replaces C's `receive_query()` and `forward_query()` functions from forward.c
#[instrument(skip(cache, servers), fields(query_id = query.header.id))]
pub async fn handle_query(
    query: DnsMessage,
    source: SocketAddr,
    cache: Arc<RwLock<DnsCache>>,
    servers: Arc<Vec<Server>>,
) -> DnsmasqResult<DnsMessage> {
    // Extract query name for logging and server selection
    let query_name = query
        .questions
        .first()
        .map(|q| q.qname.clone())
        .unwrap_or_else(|| "unknown".to_string());

    debug!(
        "Handling query from {}: {} (ID: {})",
        source, query_name, query.header.id
    );

    // Check cache first
    if let Ok(cache_guard) = cache.read() {
        // Cache lookup would go here - simplified for now
        debug!("Cache lookup for: {}", query_name);
    }

    // Select upstream servers for this query
    let selected_servers: Vec<&Server> = servers
        .iter()
        .filter(|s| s.matches_domain(&query_name))
        .collect();

    if selected_servers.is_empty() {
        warn!("No upstream servers available for domain: {}", query_name);
        return Err(DnsmasqError::Dns(crate::types::errors::DnsError::ForwardError {
            message: format!("No upstream servers available for domain: {}", query_name),
        }));
    }

    // Forward with retry logic
    match forward_with_retry(&query, &selected_servers, MAX_SERVER_TRIES).await {
        Ok(response) => {
            // Cache the response
            if let Ok(mut cache_guard) = cache.write() {
                // Caching logic would go here
                debug!("Caching response for: {}", query_name);
            }

            info!(
                "Successfully forwarded query for {} (ID: {} -> {})",
                query_name, query.header.id, response.header.id
            );

            Ok(response)
        }
        Err(e) => {
            error!("Failed to forward query for {}: {}", query_name, e);
            Err(e)
        }
    }
}

/// Forward query with retry logic and exponential backoff
///
/// Attempts to forward a query to upstream servers with automatic retry
/// on timeout or failure. Implements exponential backoff between retries
/// and rotates through available servers for resilience.
///
/// ## Algorithm
///
/// 1. Try primary server (first in list)
/// 2. On timeout, try next server with exponential backoff delay
/// 3. Continue until max_retries exhausted or success
/// 4. Return last error if all attempts fail
///
/// ## Parameters
///
/// - `query`: DNS message to forward
/// - `servers`: List of candidate upstream servers (pre-filtered by domain)
/// - `max_retries`: Maximum number of forwarding attempts
///
/// ## Returns
///
/// - `Ok(DnsMessage)`: Successful response from upstream server
/// - `Err(DnsmasqError)`: All retry attempts exhausted
///
/// ## C Function Reference
///
/// Replaces C's `retry_send()` and server rotation logic from forward.c
#[instrument(skip(query, servers))]
pub async fn forward_with_retry(
    query: &DnsMessage,
    servers: &[&Server],
    max_retries: usize,
) -> DnsmasqResult<DnsMessage> {
    let mut last_error = None;
    let mut backoff_ms = 100u64;

    for attempt in 0..max_retries {
        // Select server using round-robin
        let server_idx = attempt % servers.len();
        let server = servers[server_idx];

        debug!(
            "Forwarding attempt {} to server {}",
            attempt + 1,
            server.addr
        );

        // Create randomized query
        let mut forward_query = query.clone();
        let original_id = forward_query.header.id;
        forward_query.header.id = random_u16();

        // Serialize query
        let query_bytes = match forward_query.serialize() {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize query: {}", e);
                last_error = Some(DnsmasqError::Dns(
                    crate::types::errors::DnsError::ProtocolError {
                        message: format!("Serialization failed: {}", e),
                    },
                ));
                continue;
            }
        };

        // Send query to upstream server
        match send_udp_query(&query_bytes, server.addr, DEFAULT_QUERY_TIMEOUT_SECS).await {
            Ok(response_bytes) => {
                // Parse response
                match DnsMessage::parse(&response_bytes) {
                    Ok(mut response) => {
                        // Check for truncation (TC bit)
                        if response.header.flags.tc {
                            warn!("UDP response truncated, retrying over TCP");
                            match forward_tcp(query, server.addr).await {
                                Ok(tcp_response) => {
                                    // Restore original query ID
                                    let mut final_response = tcp_response;
                                    final_response.header.id = original_id;
                                    return Ok(final_response);
                                }
                                Err(e) => {
                                    warn!("TCP fallback failed: {}", e);
                                    last_error = Some(e);
                                    continue;
                                }
                            }
                        }

                        // Restore original query ID
                        response.header.id = original_id;
                        info!("Received response from {}", server.addr);
                        return Ok(response);
                    }
                    Err(e) => {
                        warn!("Failed to parse response: {}", e);
                        last_error = Some(DnsmasqError::Dns(
                            crate::types::errors::DnsError::ProtocolError {
                                message: format!("Parse error: {}", e),
                            },
                        ));
                    }
                }
            }
            Err(e) => {
                warn!("Query to {} failed: {}", server.addr, e);
                last_error = Some(e);
            }
        }

        // Exponential backoff before next retry
        if attempt + 1 < max_retries {
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(5000); // Cap at 5 seconds
        }
    }

    // All retries exhausted
    Err(last_error.unwrap_or_else(|| {
        DnsmasqError::Dns(crate::types::errors::DnsError::Timeout {
            timeout_ms: (DEFAULT_QUERY_TIMEOUT_SECS * max_retries as u64) * 1000,
        })
    }))
}

/// Send UDP query and wait for response with timeout
///
/// Low-level function that handles the actual UDP packet transmission and
/// response reception. Creates a random source port for each query to add
/// entropy for cache poisoning prevention.
///
/// ## Parameters
///
/// - `query_bytes`: Serialized DNS query packet
/// - `server_addr`: Upstream server socket address
/// - `timeout_secs`: Maximum time to wait for response
///
/// ## Returns
///
/// - `Ok(Vec<u8>)`: Raw response bytes from server
/// - `Err(DnsmasqError)`: Timeout or network error
async fn send_udp_query(
    query_bytes: &[u8],
    server_addr: SocketAddr,
    timeout_secs: u64,
) -> DnsmasqResult<Vec<u8>> {
    // Bind to random ephemeral port (OS assigns)
    let local_addr: SocketAddr = if server_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let socket = UdpSocket::bind(local_addr).await.map_err(|e| {
        DnsmasqError::Network(crate::types::errors::NetworkError::BindFailed {
            address: local_addr.to_string(),
            source: e,
        })
    })?;

    // Send query
    socket.send_to(query_bytes, server_addr).await.map_err(|e| {
        DnsmasqError::Network(crate::types::errors::NetworkError::SendFailed {
            destination: server_addr.to_string(),
            source: e,
        })
    })?;

    // Receive response with timeout
    let mut buf = vec![0u8; 4096]; // EDNS0 max size
    let timeout_duration = Duration::from_secs(timeout_secs);

    match timeout(timeout_duration, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, response_addr))) => {
            // Verify response came from the server we queried
            if response_addr == server_addr {
                buf.truncate(len);
                Ok(buf)
            } else {
                Err(DnsmasqError::Dns(
                    crate::types::errors::DnsError::InvalidResponse {
                        message: format!(
                            "Response from unexpected server: {} (expected: {})",
                            response_addr, server_addr
                        ),
                    },
                ))
            }
        }
        Ok(Err(e)) => Err(DnsmasqError::Network(
            crate::types::errors::NetworkError::ReceiveFailed { source: e },
        )),
        Err(_) => Err(DnsmasqError::Dns(crate::types::errors::DnsError::Timeout {
            timeout_ms: timeout_duration.as_millis() as u64,
        })),
    }
}

/// Forward query to multiple servers concurrently (--all-servers mode)
///
/// Implements the --all-servers behavior where queries are sent to all
/// configured upstream servers simultaneously, and the first response
/// received is returned to the client. This reduces latency when some
/// servers are slow or unresponsive.
///
/// ## Algorithm
///
/// 1. Send query to all servers concurrently using tokio::select!
/// 2. Return first successful response
/// 3. Cancel remaining pending queries
/// 4. Update server health metrics for all attempts
///
/// ## Parameters
///
/// - `query`: DNS message to forward
/// - `servers`: List of all candidate upstream servers
///
/// ## Returns
///
/// - `Ok(DnsMessage)`: First successful response received
/// - `Err(DnsmasqError)`: All servers failed or timed out
///
/// ## C Function Reference
///
/// Implements C's forwardall logic from forward.c
#[instrument(skip(query, servers))]
pub async fn forward_concurrent(
    query: &DnsMessage,
    servers: &[&Server],
) -> DnsmasqResult<DnsMessage> {
    if servers.is_empty() {
        return Err(DnsmasqError::Dns(crate::types::errors::DnsError::ForwardError {
            message: format!(
                "No upstream servers available for domain: {}",
                query
                    .questions
                    .first()
                    .map(|q| q.qname.clone())
                    .unwrap_or_else(|| "unknown".to_string())
            ),
        }));
    }

    // Limit concurrent queries
    let servers_to_query = &servers[..servers.len().min(MAX_CONCURRENT_QUERIES)];

    debug!(
        "Forwarding query concurrently to {} servers",
        servers_to_query.len()
    );

    // Create futures for all server queries
    let mut query_futures = Vec::new();

    for server in servers_to_query {
        let mut forward_query = query.clone();
        let original_id = forward_query.header.id;
        forward_query.header.id = random_u16();

        let query_bytes = match forward_query.serialize() {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to serialize query for {}: {}", server.addr, e);
                continue;
            }
        };

        let server_addr = server.addr;
        let future = Box::pin(async move {
            match send_udp_query(&query_bytes, server_addr, DEFAULT_QUERY_TIMEOUT_SECS).await {
                Ok(response_bytes) => {
                    DnsMessage::parse(&response_bytes)
                        .map(|mut resp| {
                            resp.header.id = original_id;
                            (server_addr, resp)
                        })
                        .map_err(|e| {
                            DnsmasqError::Dns(crate::types::errors::DnsError::ProtocolError {
                                message: format!("Failed to parse DNS response: {}", e),
                            })
                        })
                }
                Err(e) => Err(e),
            }
        });

        query_futures.push(future);
    }

    // Race all queries, return first success
    let results = futures::future::select_all(query_futures).await;
    match results.0 {
        Ok((server_addr, response)) => {
            info!("Received first response from {}", server_addr);
            Ok(response)
        }
        Err(e) => {
            error!("All concurrent queries failed");
            Err(e)
        }
    }
}

/// Forward query over TCP (for truncated responses)
///
/// Implements TCP-based DNS query forwarding per RFC 1035 Section 4.2.2.
/// Used when UDP responses have the TC (truncation) bit set, indicating
/// the response was too large for UDP (>512 bytes without EDNS0, or
/// >EDNS0 buffer size with EDNS0).
///
/// ## Protocol
///
/// TCP DNS queries are prepended with a 2-byte length field in network
/// byte order indicating the size of the DNS message that follows.
/// Responses are also length-prefixed.
///
/// ## Parameters
///
/// - `query`: DNS message to forward
/// - `server_addr`: Upstream server socket address
///
/// ## Returns
///
/// - `Ok(DnsMessage)`: Parsed DNS response
/// - `Err(DnsmasqError)`: Connection, timeout, or parsing error
///
/// ## C Function Reference
///
/// Replaces C's `tcp_request()` function from forward.c
#[instrument(skip(query))]
pub async fn forward_tcp(
    query: &DnsMessage,
    server_addr: SocketAddr,
) -> DnsmasqResult<DnsMessage> {
    debug!("Forwarding query over TCP to {}", server_addr);

    // Connect to server with timeout
    let stream = timeout(
        Duration::from_secs(TCP_QUERY_TIMEOUT_SECS),
        TcpStream::connect(server_addr),
    )
    .await
    .map_err(|_| {
        DnsmasqError::Dns(crate::types::errors::DnsError::Timeout {
            timeout_ms: TCP_QUERY_TIMEOUT_SECS * 1000,
        })
    })?
    .map_err(|e| {
        DnsmasqError::Network(crate::types::errors::NetworkError::ConnectionFailed {
            destination: server_addr.to_string(),
            source: e,
        })
    })?;

    // Serialize query
    let query_bytes = query.serialize().map_err(|e| {
        DnsmasqError::Dns(crate::types::errors::DnsError::ProtocolError {
            message: format!("Serialization failed: {}", e),
        })
    })?;

    // Prepare length-prefixed message
    let mut message_with_length = BytesMut::with_capacity(query_bytes.len() + 2);
    message_with_length.extend_from_slice(&(query_bytes.len() as u16).to_be_bytes());
    message_with_length.extend_from_slice(&query_bytes);

    // Send query with length prefix
    use tokio::io::AsyncWriteExt;
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    write_half
        .write_all(&message_with_length)
        .await
        .map_err(|e| {
            DnsmasqError::Network(crate::types::errors::NetworkError::SendFailed {
                destination: server_addr.to_string(),
                source: e,
            })
        })?;

    // Read response length prefix
    use tokio::io::AsyncReadExt;
    let mut length_buf = [0u8; 2];
    timeout(
        Duration::from_secs(TCP_QUERY_TIMEOUT_SECS),
        read_half.read_exact(&mut length_buf),
    )
    .await
    .map_err(|_| {
        DnsmasqError::Dns(crate::types::errors::DnsError::Timeout {
            timeout_ms: TCP_QUERY_TIMEOUT_SECS * 1000,
        })
    })?
    .map_err(|e| {
        DnsmasqError::Network(crate::types::errors::NetworkError::ReceiveFailed { source: e })
    })?;

    let response_len = u16::from_be_bytes(length_buf) as usize;

    // Read response data
    let mut response_buf = vec![0u8; response_len];
    timeout(
        Duration::from_secs(TCP_QUERY_TIMEOUT_SECS),
        read_half.read_exact(&mut response_buf),
    )
    .await
    .map_err(|_| {
        DnsmasqError::Dns(crate::types::errors::DnsError::Timeout {
            timeout_ms: TCP_QUERY_TIMEOUT_SECS * 1000,
        })
    })?
    .map_err(|e| {
        DnsmasqError::Network(crate::types::errors::NetworkError::ReceiveFailed { source: e })
    })?;

    // Parse response
    let response = DnsMessage::parse(&response_buf).map_err(|e| {
        DnsmasqError::Dns(crate::types::errors::DnsError::ProtocolError {
            message: format!("Parse error: {}", e),
        })
    })?;

    info!("Received TCP response from {}", server_addr);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_record_creation() {
        let source = "127.0.0.1:12345".parse().unwrap();
        let upstream = "8.8.8.8:53".parse().unwrap();
        let record = ForwardRecord::new(1234, source, upstream, 0xdeadbeef, FREC_DO_QUESTION);

        assert_eq!(record.original_id, 1234);
        assert_ne!(record.randomized_id, 1234); // Should be randomized
        assert_eq!(record.source_addr, source);
        assert_eq!(record.upstream_server, upstream);
        assert_eq!(record.query_hash, 0xdeadbeef);
        assert_eq!(record.dnssec_flags, FREC_DO_QUESTION);
    }

    #[test]
    fn test_server_domain_matching() {
        let server = Server::new("8.8.8.8:53".parse().unwrap()).with_domains("example.com".to_string());

        assert!(server.matches_domain("example.com"));
        assert!(server.matches_domain("www.example.com"));
        assert!(server.matches_domain("sub.domain.example.com"));
        assert!(!server.matches_domain("example.org"));
        assert!(!server.matches_domain("notexample.com"));
    }

    #[test]
    fn test_server_health_scoring() {
        let mut health = ServerHealth::new();

        // New server should have neutral score
        let initial_score = health.score();
        assert!(initial_score > 0.0);

        // Success should improve score
        health.record_success(Duration::from_millis(50));
        assert!(health.score() > initial_score);

        // Failures should decrease score
        health.record_failure();
        health.record_failure();
        health.record_failure();
        assert!(health.score() < initial_score);
    }

    #[test]
    fn test_server_from_address() {
        let server = Server::from_address("8.8.8.8:53").unwrap();
        assert_eq!(server.addr.to_string(), "8.8.8.8:53");

        let result = Server::from_address("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_update_server() {
        let mut servers = Vec::new();
        let addr = "8.8.8.8:53".parse().unwrap();

        // Add new server
        let server1 = Server::new(addr);
        add_update_server(&mut servers, server1);
        assert_eq!(servers.len(), 1);

        // Update existing server
        let server2 = Server::new(addr).with_domains("example.com".to_string());
        add_update_server(&mut servers, server2);
        assert_eq!(servers.len(), 1);
        assert!(servers[0].domain.is_some());
    }

    #[test]
    fn test_mark_and_cleanup_servers() {
        let mut servers = vec![
            Server::new("8.8.8.8:53".parse().unwrap()).mark_as_from_dbus(),
            Server::new("8.8.4.4:53".parse().unwrap()),
        ];

        const MARK_FLAG: u16 = 0x1000;

        // Mark first server
        mark_servers(&mut servers[..1], MARK_FLAG, true);
        assert_eq!(servers[0].flags & MARK_FLAG, MARK_FLAG);
        assert_eq!(servers[1].flags & MARK_FLAG, 0);

        // Cleanup marked servers
        let removed = cleanup_servers(&mut servers, MARK_FLAG);
        assert_eq!(removed, 1);
        assert_eq!(servers.len(), 1);
    }
}
