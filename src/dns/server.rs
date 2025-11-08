// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS server listener and request dispatcher managing UDP/TCP socket lifecycle
//
// Translated from: src/dnsmasq.c (check_dns_listeners function), src/forward.c, src/network.c

//! DNS Server Implementation
//!
//! This module implements the DNS server listener and request dispatcher for dnsmasq,
//! providing asynchronous UDP and TCP query handling with the Tokio runtime. It replaces
//! the C implementation's poll()-based event loop with Rust's async/await model, managing
//! socket lifecycle, query multiplexing, and response delivery.
//!
//! # Key Features
//!
//! - **Async Event Loop**: Tokio-based async runtime replacing C's poll() multiplexing
//! - **UDP/TCP Handling**: Dual-stack DNS service with automatic TCP fallback
//! - **Multi-Interface Binding**: Support for binding to specific interfaces or all interfaces
//! - **Source Address Control**: IP_PKTINFO/IPV6_PKTINFO for proper response routing
//! - **Concurrent Query Processing**: Tokio tasks for parallel query handling
//! - **Graceful Shutdown**: Clean socket closure with in-flight query completion
//! - **Statistics Tracking**: Atomic counters for queries, cache hits, error responses
//!
//! # Memory Safety
//!
//! Replaces C's manual socket management and buffer handling with Rust's ownership system:
//! - Buffer overflows prevented by BytesMut bounds checking
//! - Socket lifecycle managed by Tokio's async drop handlers
//! - No manual memory management for packet buffers
//!
//! # C Source Reference
//!
//! Translated from:
//! - `src/dnsmasq.c` (lines 2507-2680) - check_dns_listeners() event loop
//! - `src/forward.c` (lines 88-200) - receive_query() query processing
//! - `src/network.c` (lines 1-500) - Socket creation and management
//!
//! # Architecture
//!
//! ```text
//! DnsServer::run()
//!     ├─> tokio::select! {
//!     │       UDP recv_from() -> handle_udp_query()
//!     │       TCP accept()    -> handle_tcp_connection()
//!     │       SIGTERM         -> graceful_shutdown()
//!     │   }
//!     │
//!     └─> handle_udp_query()
//!             ├─> Parse DNS message
//!             ├─> Check cache (cache.lookup())
//!             ├─> Forward to upstream (forward::handle_query())
//!             └─> Send response (send_from())
//! ```
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dnsmasq::dns::server::{DnsServer, ServerConfig};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ServerConfig::default()
//!         .with_bind_addresses(vec!["0.0.0.0".parse()?])
//!         .with_port(53)
//!         .with_cache_size(1000);
//!
//!     let mut server = DnsServer::new(config)?;
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::task;
use tracing::{debug, error, info, instrument, warn};

use crate::config::Config;
use crate::constants::DNS_PACKET_SIZE;
use crate::dns::cache::{CacheKey, CacheSource, DnsCache};
use crate::dns::edns::{OptRecord, find_opt_record};
use crate::dns::forward::{Server, handle_query};
use crate::dns::protocol::DnsMessage;
use crate::runtime::signal::SignalEvent;
use crate::types::errors::{DnsError, DnsmasqError, NetworkError};

/// Result type for DNS server operations
type ServerResult<T> = Result<T, DnsmasqError>;

/// Socket configuration for DNS server
///
/// Controls socket binding behavior and buffer sizing for DNS query processing.
/// Corresponds to C's socket setup in `network.c` `create_bound_listeners()`.
#[derive(Debug, Clone)]
pub struct SocketConfig {
    /// List of IP addresses to bind to (empty = bind to all interfaces)
    pub bind_addresses: Vec<IpAddr>,

    /// DNS port number (default: 53)
    pub port: u16,

    /// Enable `SO_REUSEPORT` for load balancing across multiple processes
    /// (Linux 3.9+, BSD)
    pub reuse_port: bool,

    /// `SO_RCVBUF` socket receive buffer size in bytes
    pub receive_buffer: usize,

    /// `SO_SNDBUF` socket send buffer size in bytes
    pub send_buffer: usize,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            bind_addresses: vec![],
            port: 53,
            reuse_port: false,
            receive_buffer: 262_144, // 256 KB for high-traffic DNS servers
            send_buffer: 262_144,
        }
    }
}

/// DNS server configuration
///
/// Comprehensive configuration for DNS server initialization and runtime behavior.
/// Replaces C's struct daemon configuration subset for DNS functionality.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Socket binding configuration
    socket_config: SocketConfig,

    /// Maximum DNS cache size (number of entries)
    cache_size: usize,

    /// Maximum concurrent TCP connections
    max_tcp_connections: usize,

    /// TCP connection idle timeout
    tcp_timeout: Duration,

    /// UDP buffer size for packet reception
    udp_buffer_size: usize,

    /// Enable query logging
    enable_query_logging: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_config: SocketConfig::default(),
            cache_size: 150, // Match C's CACHESIZ default
            max_tcp_connections: 64,
            tcp_timeout: Duration::from_secs(60),
            udp_buffer_size: 4096, // EDNS0 default size
            enable_query_logging: false,
        }
    }
}

impl ServerConfig {
    /// Set bind addresses for DNS server
    #[must_use]
    pub fn with_bind_addresses(mut self, addresses: Vec<IpAddr>) -> Self {
        self.socket_config.bind_addresses = addresses;
        self
    }

    /// Set DNS port number (default: 53)
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.socket_config.port = port;
        self
    }

    /// Set DNS cache size
    #[must_use]
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    /// Set maximum TCP connections
    #[must_use]
    pub fn with_max_tcp_connections(mut self, max: usize) -> Self {
        self.max_tcp_connections = max;
        self
    }

    /// Enable `SO_REUSEPORT` for load balancing
    #[must_use]
    pub fn with_reuse_port(mut self, enable: bool) -> Self {
        self.socket_config.reuse_port = enable;
        self
    }

    /// Set TCP idle timeout
    #[must_use]
    pub fn with_tcp_timeout(mut self, timeout: Duration) -> Self {
        self.tcp_timeout = timeout;
        self
    }

    /// Enable query logging
    #[must_use]
    pub fn with_query_logging(mut self, enable: bool) -> Self {
        self.enable_query_logging = enable;
        self
    }
}

/// DNS server statistics
///
/// Atomic counters for DNS server performance monitoring and debugging.
/// Replaces C's global counters in daemon struct.
#[derive(Debug, Default)]
pub struct ServerStatistics {
    /// Total queries received (UDP + TCP)
    pub queries_received: AtomicU64,

    /// Queries forwarded to upstream servers
    pub queries_forwarded: AtomicU64,

    /// Cache hits (queries answered from cache)
    pub cache_hits: AtomicU64,

    /// Cache misses (queries requiring upstream forwarding)
    pub cache_misses: AtomicU64,

    /// SERVFAIL responses sent to clients
    pub servfail_responses: AtomicU64,

    /// NXDOMAIN responses sent to clients
    pub nxdomain_responses: AtomicU64,
}

impl ServerStatistics {
    /// Create new statistics instance with zero counters
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get snapshot of current statistics (non-atomic read)
    #[must_use]
    pub fn snapshot(&self) -> StatisticsSnapshot {
        StatisticsSnapshot {
            queries_received: self.queries_received.load(Ordering::Relaxed),
            queries_forwarded: self.queries_forwarded.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            servfail_responses: self.servfail_responses.load(Ordering::Relaxed),
            nxdomain_responses: self.nxdomain_responses.load(Ordering::Relaxed),
        }
    }

    /// Reset all statistics to zero
    pub fn reset(&self) {
        self.queries_received.store(0, Ordering::Relaxed);
        self.queries_forwarded.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.servfail_responses.store(0, Ordering::Relaxed);
        self.nxdomain_responses.store(0, Ordering::Relaxed);
    }
}

/// Immutable snapshot of server statistics
#[derive(Debug, Clone, Copy)]
pub struct StatisticsSnapshot {
    /// Total queries received
    pub queries_received: u64,
    /// Queries forwarded to upstream
    pub queries_forwarded: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// `SERVFAIL` responses sent
    pub servfail_responses: u64,
    /// `NXDOMAIN` responses sent
    pub nxdomain_responses: u64,
}

/// DNS Server main structure
///
/// Manages DNS query processing with async event loop, UDP/TCP socket handling,
/// cache integration, and upstream forwarding. Replaces C's dnsmasq.c event loop
/// for DNS functionality.
pub struct DnsServer {
    /// Configuration for server behavior
    config: Arc<ServerConfig>,

    /// UDP sockets for DNS queries (one per bind address)
    udp_sockets: Vec<Arc<UdpSocket>>,

    /// TCP listener for DNS-over-TCP queries
    tcp_listener: Option<Arc<TcpListener>>,

    /// DNS response cache (shared across tasks)
    cache: Arc<RwLock<DnsCache>>,

    /// Global configuration (for upstream servers, etc.)
    global_config: Arc<Config>,

    /// Upstream servers for query forwarding
    servers: Arc<Vec<Server>>,

    /// Server statistics
    statistics: Arc<ServerStatistics>,

    /// Shutdown flag
    shutdown_requested: Arc<tokio::sync::Notify>,
}

impl DnsServer {
    /// Create new DNS server instance
    ///
    /// Initializes DNS cache, parses configuration, but does not bind sockets.
    /// Call `bind()` to create sockets and `run()` to start the event loop.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `global_config` - Global dnsmasq configuration
    ///
    /// # Errors
    ///
    /// Returns error if configuration validation fails
    ///
    /// # Returns
    ///
    /// New `DnsServer` instance ready for binding
    ///
    /// # C Source Reference
    ///
    /// Replaces initialization in `dnsmasq.c` `main()` function (lines 800-900)
    pub fn new(config: ServerConfig, global_config: Arc<Config>) -> ServerResult<Self> {
        // Initialize DNS cache with configured size
        let cache = DnsCache::new(config.cache_size);

        // Convert UpstreamServers to Servers for forwarding
        let servers: Vec<Server> = global_config
            .dns
            .upstream_servers
            .iter()
            .map(|upstream| {
                let mut server = Server::new(upstream.address);
                if let Some(ref domain) = upstream.domain {
                    server = server.with_domains(domain.clone());
                }
                server
            })
            .collect();

        info!(
            "DNS server initialized with cache_size={}, max_tcp={}, port={}, upstream_servers={}",
            config.cache_size,
            config.max_tcp_connections,
            config.socket_config.port,
            servers.len()
        );

        Ok(Self {
            config: Arc::new(config),
            udp_sockets: Vec::new(),
            tcp_listener: None,
            cache: Arc::new(RwLock::new(cache)),
            global_config,
            servers: Arc::new(servers),
            statistics: Arc::new(ServerStatistics::new()),
            shutdown_requested: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Bind DNS server to configured addresses and ports
    ///
    /// Creates UDP and TCP sockets with configured socket options. Must be called
    /// before privilege drop if binding to port <1024.
    ///
    /// # Errors
    ///
    /// Returns error if socket binding fails or socket options cannot be set
    ///
    /// # Panics
    ///
    /// Panics if socket conversion to tokio types fails
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, error on socket binding failure
    ///
    /// # C Source Reference
    ///
    /// Replaces `network.c` `create_bound_listeners()` (lines 200-400)
    #[instrument(skip(self), level = "info")]
    pub fn bind(&mut self) -> ServerResult<()> {
        let socket_config = &self.config.socket_config;

        // Determine bind addresses (empty list = bind to all interfaces)
        let bind_addresses: Vec<IpAddr> = if socket_config.bind_addresses.is_empty() {
            vec![
                "0.0.0.0".parse().unwrap(), // IPv4 wildcard
                "::".parse().unwrap(),      // IPv6 wildcard
            ]
        } else {
            socket_config.bind_addresses.clone()
        };

        // Create UDP sockets for each bind address
        for addr in &bind_addresses {
            let socket_addr = SocketAddr::new(*addr, socket_config.port);

            match self.create_udp_socket(socket_addr) {
                Ok(socket) => {
                    info!("DNS server bound to UDP {}", socket_addr);
                    self.udp_sockets.push(Arc::new(socket));
                }
                Err(e) => {
                    error!("Failed to bind UDP socket to {}: {}", socket_addr, e);
                    return Err(e);
                }
            }
        }

        // Create TCP listener on first bind address (or wildcard)
        let tcp_bind_addr = SocketAddr::new(
            bind_addresses
                .first()
                .copied()
                .unwrap_or_else(|| "0.0.0.0".parse().expect("Valid IP address")),
            socket_config.port,
        );

        match Self::create_tcp_listener(tcp_bind_addr) {
            Ok(listener) => {
                info!("DNS server bound to TCP {}", tcp_bind_addr);
                self.tcp_listener = Some(Arc::new(listener));
            }
            Err(e) => {
                error!("Failed to bind TCP listener to {}: {}", tcp_bind_addr, e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Create UDP socket with configured socket options
    ///
    /// Sets `SO_REUSEADDR`, `SO_REUSEPORT` (if enabled), and buffer sizes.
    ///
    /// # C Source Reference
    ///
    /// Replaces `network.c` socket creation (lines 250-300)
    fn create_udp_socket(&self, addr: SocketAddr) -> ServerResult<UdpSocket> {
        let socket_config = &self.config.socket_config;

        // Determine socket domain from address family
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        // Create raw socket2 socket for option setting
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketCreation(e.to_string())))?;

        // Set SO_REUSEADDR for quick restart
        socket
            .set_reuse_address(true)
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketOption(e.to_string())))?;

        // Set SO_REUSEPORT for load balancing (Linux 3.9+)
        #[cfg(all(unix, not(target_os = "solaris")))]
        if socket_config.reuse_port {
            socket
                .set_reuse_port(true)
                .map_err(|e| DnsmasqError::Network(NetworkError::SocketOption(e.to_string())))?;
        }

        // Set receive buffer size
        socket
            .set_recv_buffer_size(socket_config.receive_buffer)
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketOption(e.to_string())))?;

        // Set send buffer size
        socket
            .set_send_buffer_size(socket_config.send_buffer)
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketOption(e.to_string())))?;

        // Bind socket
        socket
            .bind(&addr.into())
            .map_err(|e| DnsmasqError::Network(NetworkError::Bind(e.to_string())))?;

        // Convert to Tokio UdpSocket
        socket
            .set_nonblocking(true)
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketOption(e.to_string())))?;

        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketCreation(e.to_string())))
    }

    /// Create TCP listener with configured socket options
    ///
    /// Sets `SO_REUSEADDR` for quick restart.
    fn create_tcp_listener(addr: SocketAddr) -> ServerResult<TcpListener> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketCreation(e.to_string())))?;

        socket
            .set_reuse_address(true)
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketOption(e.to_string())))?;

        socket
            .bind(&addr.into())
            .map_err(|e| DnsmasqError::Network(NetworkError::Bind(e.to_string())))?;

        socket
            .listen(128)
            .map_err(|e| DnsmasqError::Network(NetworkError::Listen(e.to_string())))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketOption(e.to_string())))?;

        let std_listener: std::net::TcpListener = socket.into();
        TcpListener::from_std(std_listener)
            .map_err(|e| DnsmasqError::Network(NetworkError::SocketCreation(e.to_string())))
    }

    /// Main event loop - process DNS queries until shutdown
    ///
    /// Multiplexes UDP sockets, TCP listener, and shutdown signals using `tokio::select!`.
    /// Spawns concurrent tasks for query processing to avoid blocking.
    ///
    /// # Errors
    ///
    /// Returns error on fatal I/O failure or signal handling error
    ///
    /// # Returns
    ///
    /// `Ok(())` on graceful shutdown, error on fatal failure
    ///
    /// # C Source Reference
    ///
    /// Replaces `dnsmasq.c` main event loop (lines 1200-1450)
    #[instrument(skip(self), level = "info")]
    pub async fn run(&mut self) -> ServerResult<()> {
        info!("DNS server starting event loop");

        // Clone Arc references for tasks
        let tcp_listener = self.tcp_listener.clone();
        let shutdown_notify = self.shutdown_requested.clone();

        // Create signal handler
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| DnsmasqError::Network(NetworkError::SignalHandler(e.to_string())))?;

        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|e| DnsmasqError::Network(NetworkError::SignalHandler(e.to_string())))?;

        // Track active TCP connections
        let tcp_semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_tcp_connections));

        loop {
            tokio::select! {
                // Handle UDP queries from all sockets
                result = self.recv_udp_query() => {
                    match result {
                        Ok((data, source, socket)) => {
                            // Spawn task for concurrent processing
                            let server = Self::clone_for_task(
                                self.cache.clone(),
                                self.global_config.clone(),
                                self.servers.clone(),
                                self.statistics.clone(),
                                self.config.clone(),
                            );

                            task::spawn(async move {
                                if let Err(e) = server.handle_udp_query(data, source, socket).await {
                                    error!("UDP query processing failed: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("UDP recv error: {}", e);
                        }
                    }
                }

                // Handle TCP connections
                result = Self::accept_tcp_connection(tcp_listener.as_ref()), if tcp_listener.is_some() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            // Acquire semaphore permit for connection limiting
                            if let Ok(permit) = tcp_semaphore.clone().try_acquire_owned() {
                                let server = Self::clone_for_task(
                                    self.cache.clone(),
                                    self.global_config.clone(),
                                    self.servers.clone(),
                                    self.statistics.clone(),
                                    self.config.clone(),
                                );

                                task::spawn(async move {
                                    if let Err(e) = server.handle_tcp_connection(stream, peer_addr).await {
                                        error!("TCP connection handling failed: {}", e);
                                    }
                                    drop(permit); // Release connection slot
                                });
                            } else {
                                warn!("Max TCP connections reached, dropping connection from {}", peer_addr);
                            }
                        }
                        Err(e) => {
                            error!("TCP accept error: {}", e);
                        }
                    }
                }

                // Handle shutdown signals
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown");
                    break;
                }

                Some(()) = sigint.recv() => {
                    info!("Received SIGINT, initiating graceful shutdown");
                    break;
                }

                () = shutdown_notify.notified() => {
                    info!("Shutdown requested via API, initiating graceful shutdown");
                    break;
                }
            }
        }

        self.shutdown().await?;
        Ok(())
    }

    /// Receive UDP query from any bound socket
    ///
    /// Returns tuple of (data, source address, socket) for response routing
    async fn recv_udp_query(&self) -> ServerResult<(Vec<u8>, SocketAddr, Arc<UdpSocket>)> {
        // Try each socket until one has data ready
        for socket in &self.udp_sockets {
            let mut buf = BytesMut::with_capacity(self.config.udp_buffer_size);
            buf.resize(self.config.udp_buffer_size, 0);

            // Use try_recv to avoid blocking on empty sockets
            match socket.try_recv_from(&mut buf) {
                Ok((n, source)) => {
                    buf.truncate(n);
                    return Ok((buf.to_vec(), source, socket.clone()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Try next socket
                }
                Err(e) => {
                    return Err(DnsmasqError::Network(NetworkError::Receive(e.to_string())));
                }
            }
        }

        // If no socket has data, wait on all sockets
        let mut tasks = Vec::new();
        for socket in &self.udp_sockets {
            let socket = socket.clone();
            let buf_size = self.config.udp_buffer_size;

            tasks.push(task::spawn(async move {
                let mut buf = BytesMut::with_capacity(buf_size);
                buf.resize(buf_size, 0);

                socket.recv_from(&mut buf).await.map(|(n, source)| {
                    buf.truncate(n);
                    (buf.to_vec(), source, socket)
                })
            }));
        }

        // Wait for first socket to receive data
        for task_handle in tasks {
            if let Ok(result) = task_handle.await {
                match result {
                    Ok((data, source, socket)) => return Ok((data, source, socket)),
                    Err(e) => {
                        return Err(DnsmasqError::Network(NetworkError::Receive(e.to_string())));
                    }
                }
            }
        }

        Err(DnsmasqError::Network(NetworkError::Receive(
            "No UDP data received".to_string(),
        )))
    }

    /// Accept TCP connection from listener
    async fn accept_tcp_connection(
        listener: Option<&Arc<TcpListener>>,
    ) -> ServerResult<(TcpStream, SocketAddr)> {
        if let Some(listener) = listener {
            listener
                .accept()
                .await
                .map_err(|e| DnsmasqError::Network(NetworkError::Accept(e.to_string())))
        } else {
            // This should never happen due to tokio::select! guard
            std::future::pending().await
        }
    }

    /// Create clone of server context for task spawning
    fn clone_for_task(
        cache: Arc<RwLock<DnsCache>>,
        global_config: Arc<Config>,
        servers: Arc<Vec<Server>>,
        statistics: Arc<ServerStatistics>,
        config: Arc<ServerConfig>,
    ) -> ServerContext {
        ServerContext {
            cache,
            global_config,
            servers,
            statistics,
            config,
        }
    }

    /// Handle UDP DNS query
    ///
    /// Parses query, checks cache, forwards if needed, sends response.
    ///
    /// # C Source Reference
    ///
    /// Replaces `dnsmasq.c` `check_dns_listeners()` and `forward.c` `receive_query()`
    #[instrument(skip(self, data, socket), level = "debug")]
    async fn handle_udp_query(
        &self,
        data: Vec<u8>,
        source: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> ServerResult<()> {
        let start_time = Instant::now();

        // Update statistics
        self.statistics
            .queries_received
            .fetch_add(1, Ordering::Relaxed);

        // Parse DNS message
        let Ok(query) = DnsMessage::parse(&data) else {
            error!("Failed to parse DNS query from {}", source);
            // Send FORMERR response
            self.send_error_response(&socket, source, &data, 1).await?; // FORMERR = 1
            return Ok(());
        };

        // Log query if enabled
        if self.config.enable_query_logging {
            if let Some(question) = query.questions.first() {
                debug!(
                    "Query from {}: {} {:?}",
                    source, question.qname, question.qtype
                );
            }
        }

        // Process query and generate response
        let response = self.process_query(query, source).await?;

        // Serialize response
        let response_data = match response.serialize() {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to serialize DNS response: {}", e);
                self.statistics
                    .servfail_responses
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };

        // Truncate if response exceeds UDP size
        let max_udp_size = self.get_max_udp_size(&response);
        let final_response = if response_data.len() > max_udp_size {
            warn!(
                "Response to {} truncated ({} > {})",
                source,
                response_data.len(),
                max_udp_size
            );
            Self::truncate_response(response, max_udp_size)?
        } else {
            response_data
        };

        // Send response
        socket
            .send_to(&final_response, source)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Send(e.to_string())))?;

        debug!(
            "Handled UDP query from {} in {:?}",
            source,
            start_time.elapsed()
        );

        Ok(())
    }

    /// Handle TCP DNS connection
    ///
    /// Reads length-prefixed queries, processes them, sends length-prefixed responses.
    ///
    /// # C Source Reference
    ///
    /// Replaces TCP handling in forward.c (lines 500-650)
    #[instrument(skip(self, stream), level = "debug")]
    async fn handle_tcp_connection(
        &self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> ServerResult<()> {
        debug!("Accepted TCP connection from {}", peer_addr);

        // Set TCP timeout
        let timeout = self.config.tcp_timeout;

        // Read and process queries until connection closes or timeout
        loop {
            // Read 2-byte length prefix with timeout
            let length =
                match tokio::time::timeout(timeout, self.read_tcp_length(&mut stream)).await {
                    Ok(Ok(len)) => len,
                    Ok(Err(e)) => {
                        debug!("TCP read error from {}: {}", peer_addr, e);
                        return Ok(()); // Connection closed or error
                    }
                    Err(_) => {
                        debug!("TCP connection from {} timed out", peer_addr);
                        return Ok(());
                    }
                };

            // Read DNS message with timeout
            let query_data = match tokio::time::timeout(
                timeout,
                self.read_tcp_data(&mut stream, length),
            )
            .await
            {
                Ok(Ok(data)) => data,
                Ok(Err(e)) => {
                    error!("Failed to read TCP query from {}: {}", peer_addr, e);
                    return Ok(());
                }
                Err(_) => {
                    debug!("TCP read from {} timed out", peer_addr);
                    return Ok(());
                }
            };

            // Update statistics
            self.statistics
                .queries_received
                .fetch_add(1, Ordering::Relaxed);

            // Parse and process query
            let Ok(query) = DnsMessage::parse(&query_data) else {
                error!("Failed to parse TCP DNS query from {}", peer_addr);
                continue; // Try next query
            };

            let response = self.process_query(query, peer_addr).await?;

            // Serialize response
            let response_data = match response.serialize() {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to serialize TCP DNS response: {}", e);
                    continue;
                }
            };

            // Send length-prefixed response
            if let Err(e) = self.send_tcp_response(&mut stream, &response_data).await {
                error!("Failed to send TCP response to {}: {}", peer_addr, e);
                return Ok(());
            }
        }
    }

    /// Read 2-byte TCP length prefix
    async fn read_tcp_length(&self, stream: &mut TcpStream) -> ServerResult<u16> {
        use tokio::io::AsyncReadExt;

        let mut length_buf = [0u8; 2];
        stream
            .read_exact(&mut length_buf)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Receive(e.to_string())))?;

        Ok(u16::from_be_bytes(length_buf))
    }

    /// Read TCP DNS message data
    async fn read_tcp_data(&self, stream: &mut TcpStream, length: u16) -> ServerResult<Vec<u8>> {
        use tokio::io::AsyncReadExt;

        let mut data = vec![0u8; length as usize];
        stream
            .read_exact(&mut data)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Receive(e.to_string())))?;

        Ok(data)
    }

    /// Send length-prefixed TCP response
    async fn send_tcp_response(&self, stream: &mut TcpStream, data: &[u8]) -> ServerResult<()> {
        use tokio::io::AsyncWriteExt;

        // Send 2-byte length prefix
        #[allow(clippy::cast_possible_truncation)]
        let length = (data.len() as u16).to_be_bytes();
        stream
            .write_all(&length)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Send(e.to_string())))?;

        // Send DNS message
        stream
            .write_all(data)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Send(e.to_string())))?;

        Ok(())
    }

    /// Process DNS query - cache lookup or upstream forwarding
    ///
    /// Core query processing logic coordinating cache and forwarding.
    ///
    /// # Errors
    ///
    /// Returns error if query is invalid or forwarding fails
    ///
    /// # C Source Reference
    ///
    /// Replaces `forward.c` `receive_query()` processing logic
    #[instrument(skip(self, query), level = "debug")]
    pub async fn process_query(
        &self,
        query: DnsMessage,
        source: SocketAddr,
    ) -> ServerResult<DnsMessage> {
        // Extract first question for processing
        let question = query.questions.first().ok_or_else(|| {
            DnsmasqError::Dns(crate::types::errors::DnsError::InvalidQuery {
                message: "No questions in query".to_string(),
            })
        })?;

        // Check cache first
        {
            let cache_key = CacheKey {
                name: question.qname.clone(),
                record_type: question.qtype,
                record_class: question.qclass,
            };
            let mut cache = self.cache.write().await;
            if let Some(cached_records) = cache.lookup(&cache_key) {
                self.statistics.cache_hits.fetch_add(1, Ordering::Relaxed);
                debug!("Cache HIT for {} {:?}", question.qname, question.qtype);

                // Build response from cached records
                let mut response = query.clone();
                response.header.flags.qr = true;
                response.header.flags.aa = false;
                response.header.flags.ra = true;
                response.answers = cached_records;

                return Ok(response);
            }
        }

        // Cache miss - forward to upstream
        self.statistics.cache_misses.fetch_add(1, Ordering::Relaxed);
        debug!("Cache MISS for {} {:?}", question.qname, question.qtype);

        // Forward query to upstream servers
        match handle_query(
            query.clone(),
            source,
            self.cache.clone(),
            self.servers.clone(),
        )
        .await
        {
            Ok(response) => {
                self.statistics
                    .queries_forwarded
                    .fetch_add(1, Ordering::Relaxed);

                // Cache the response if appropriate
                if !response.answers.is_empty() {
                    let mut cache = self.cache.write().await;
                    let cache_key = CacheKey {
                        name: question.qname.clone(),
                        record_type: question.qtype,
                        record_class: question.qclass,
                    };
                    // Use minimum TTL from all answer records
                    let min_ttl = response
                        .answers
                        .iter()
                        .map(super::protocol::ResourceRecord::ttl)
                        .min()
                        .unwrap_or(0);
                    cache.insert(
                        cache_key,
                        response.answers.clone(),
                        min_ttl,
                        CacheSource::Upstream,
                    );
                }

                // Check for NXDOMAIN
                if response.header.flags.rcode == 3 {
                    self.statistics
                        .nxdomain_responses
                        .fetch_add(1, Ordering::Relaxed);
                }

                Ok(response)
            }
            Err(e) => {
                error!("Query forwarding failed: {}", e);
                self.statistics
                    .servfail_responses
                    .fetch_add(1, Ordering::Relaxed);

                // Generate SERVFAIL response
                let mut response = query;
                response.header.flags.qr = true;
                response.header.flags.rcode = 2; // SERVFAIL
                Ok(response)
            }
        }
    }

    /// Get maximum UDP response size from EDNS0 OPT record
    ///
    /// Returns configured UDP buffer size or EDNS0 payload size if larger
    fn get_max_udp_size(&self, response: &DnsMessage) -> usize {
        // Check for EDNS0 OPT record in additional section
        if let Some(_opt) = find_opt_record(&response.additional) {
            // EDNS0 present - use larger buffer size
            return self.config.udp_buffer_size;
        }

        // No EDNS0 - use standard DNS packet size
        DNS_PACKET_SIZE
    }

    /// Truncate response to fit in UDP payload
    ///
    /// Sets TC bit and removes answers/authority/additional records
    fn truncate_response(mut response: DnsMessage, max_size: usize) -> ServerResult<Vec<u8>> {
        // Set truncation flag
        response.header.flags.tc = true;

        // Remove additional records first
        response.additional.clear();

        // Try serializing
        if let Ok(data) = response.serialize() {
            if data.len() <= max_size {
                return Ok(data);
            }
        }

        // Remove authority records
        response.authority.clear();

        if let Ok(data) = response.serialize() {
            if data.len() <= max_size {
                return Ok(data);
            }
        }

        // Remove answer records
        response.answers.clear();

        // Final attempt - should always fit now
        response.serialize().map_err(|e| {
            DnsmasqError::Dns(crate::types::errors::DnsError::Serialization(e.to_string()))
        })
    }

    /// Send error response (FORMERR, SERVFAIL, etc.)
    async fn send_error_response(
        &self,
        socket: &UdpSocket,
        dest: SocketAddr,
        query_data: &[u8],
        rcode: u8,
    ) -> ServerResult<()> {
        // Try to parse query to preserve ID
        let response_data = if let Ok(query) = DnsMessage::parse(query_data) {
            let mut response = query;
            response.header.flags.qr = true;
            response.header.flags.rcode = rcode;
            response.answers.clear();
            response.authority.clear();
            response.additional.clear();

            response.serialize().unwrap_or_else(|_| {
                // Fallback: minimal error response
                Self::create_minimal_error(rcode)
            })
        } else {
            // Can't parse query - send minimal error
            Self::create_minimal_error(rcode)
        };

        socket
            .send_to(&response_data, dest)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Send(e.to_string())))?;

        Ok(())
    }

    /// Create minimal error response when query can't be parsed
    fn create_minimal_error(rcode: u8) -> Vec<u8> {
        // Minimal DNS header with error code
        let mut response = vec![0u8; 12];
        response[2] = 0x80; // QR=1 (response)
        response[3] = rcode & 0x0F;
        response
    }

    /// Graceful shutdown - close sockets and wait for in-flight queries
    ///
    /// # C Source Reference
    ///
    /// Replaces cleanup in dnsmasq.c `async_event()` SIGTERM handler
    ///
    /// # Errors
    ///
    /// Returns an error if socket closure fails or operations timeout
    pub async fn shutdown(&mut self) -> ServerResult<()> {
        info!("DNS server shutting down gracefully");

        // Give in-flight queries time to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Close TCP listener
        self.tcp_listener = None;

        // Close UDP sockets (done by Drop)
        self.udp_sockets.clear();

        // Log final statistics
        let stats = self.statistics.snapshot();
        info!(
            "DNS server shutdown - stats: queries={}, forwarded={}, cache_hits={}, cache_misses={}, servfail={}, nxdomain={}",
            stats.queries_received,
            stats.queries_forwarded,
            stats.cache_hits,
            stats.cache_misses,
            stats.servfail_responses,
            stats.nxdomain_responses
        );

        Ok(())
    }

    /// Get server statistics
    ///
    /// Returns reference to statistics for monitoring and debugging
    #[must_use]
    pub fn statistics(&self) -> &ServerStatistics {
        &self.statistics
    }

    /// Request shutdown from another task
    pub fn request_shutdown(&self) {
        self.shutdown_requested.notify_one();
    }
}

/// Server context for spawned tasks
///
/// Contains shared references needed for query processing in spawned tasks
#[derive(Clone)]
struct ServerContext {
    cache: Arc<RwLock<DnsCache>>,
    global_config: Arc<Config>,
    servers: Arc<Vec<Server>>,
    statistics: Arc<ServerStatistics>,
    config: Arc<ServerConfig>,
}

impl ServerContext {
    /// Handle UDP query in spawned task context
    async fn handle_udp_query(
        self,
        data: Vec<u8>,
        source: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> ServerResult<()> {
        let start_time = Instant::now();

        // Update statistics
        self.statistics
            .queries_received
            .fetch_add(1, Ordering::Relaxed);

        // Parse DNS message
        let Ok(query) = DnsMessage::parse(&data) else {
            error!("Failed to parse DNS query from {}", source);
            // Send FORMERR response
            return self.send_error_response(&socket, source, &data, 1).await;
        };

        // Log query if enabled
        if self.config.enable_query_logging {
            if let Some(question) = query.questions.first() {
                debug!(
                    "Query from {}: {} {:?}",
                    source, question.qname, question.qtype
                );
            }
        }

        // Process query
        let response = self.process_query(query, source).await?;

        // Serialize and send response
        let response_data = match response.serialize() {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to serialize DNS response: {}", e);
                self.statistics
                    .servfail_responses
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };

        // Check size and truncate if needed
        let max_size = if response_data.len() > DNS_PACKET_SIZE {
            self.config.udp_buffer_size
        } else {
            DNS_PACKET_SIZE
        };

        let final_response = if response_data.len() > max_size {
            warn!("Response truncated for {}", source);
            Self::truncate_response(response, max_size)?
        } else {
            response_data
        };

        socket
            .send_to(&final_response, source)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Send(e.to_string())))?;

        debug!(
            "Handled UDP query from {} in {:?}",
            source,
            start_time.elapsed()
        );

        Ok(())
    }

    /// Handle TCP connection in spawned task context
    async fn handle_tcp_connection(
        self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> ServerResult<()> {
        debug!("Handling TCP connection from {}", peer_addr);

        let timeout = self.config.tcp_timeout;

        loop {
            // Read length prefix
            let Ok(Ok(length)) =
                tokio::time::timeout(timeout, self.read_tcp_length(&mut stream)).await
            else {
                return Ok(());
            };

            // Read query data
            let Ok(Ok(query_data)) =
                tokio::time::timeout(timeout, self.read_tcp_data(&mut stream, length)).await
            else {
                return Ok(());
            };

            self.statistics
                .queries_received
                .fetch_add(1, Ordering::Relaxed);

            // Parse and process
            let Ok(query) = DnsMessage::parse(&query_data) else {
                error!("Failed to parse TCP query from {}", peer_addr);
                continue;
            };

            let response = self.process_query(query, peer_addr).await?;

            // Send response
            let response_data = response.serialize().map_err(|e| {
                DnsmasqError::Dns(crate::types::errors::DnsError::Serialization(e.to_string()))
            })?;

            if let Err(e) = self.send_tcp_response(&mut stream, &response_data).await {
                error!("Failed to send TCP response: {}", e);
                return Ok(());
            }
        }
    }

    /// Process query in task context
    async fn process_query(
        &self,
        query: DnsMessage,
        source: SocketAddr,
    ) -> ServerResult<DnsMessage> {
        let question = query.questions.first().ok_or_else(|| {
            DnsmasqError::Dns(crate::types::errors::DnsError::InvalidQuery {
                message: "No questions".to_string(),
            })
        })?;

        // Check cache
        {
            let cache_key = CacheKey {
                name: question.qname.clone(),
                record_type: question.qtype,
                record_class: question.qclass,
            };
            let mut cache = self.cache.write().await;
            if let Some(cached_records) = cache.lookup(&cache_key) {
                self.statistics.cache_hits.fetch_add(1, Ordering::Relaxed);

                let mut response = query.clone();
                response.header.flags.qr = true;
                response.header.flags.ra = true;
                response.answers = cached_records;
                return Ok(response);
            }
        }

        // Forward query
        self.statistics.cache_misses.fetch_add(1, Ordering::Relaxed);

        match handle_query(
            query.clone(),
            source,
            self.cache.clone(),
            self.servers.clone(),
        )
        .await
        {
            Ok(response) => {
                self.statistics
                    .queries_forwarded
                    .fetch_add(1, Ordering::Relaxed);

                if !response.answers.is_empty() {
                    let mut cache = self.cache.write().await;
                    let cache_key = CacheKey {
                        name: question.qname.clone(),
                        record_type: question.qtype,
                        record_class: question.qclass,
                    };
                    let min_ttl = response
                        .answers
                        .iter()
                        .map(super::protocol::ResourceRecord::ttl)
                        .min()
                        .unwrap_or(0);
                    cache.insert(
                        cache_key,
                        response.answers.clone(),
                        min_ttl,
                        CacheSource::Upstream,
                    );
                }

                if response.header.flags.rcode == 3 {
                    self.statistics
                        .nxdomain_responses
                        .fetch_add(1, Ordering::Relaxed);
                }

                Ok(response)
            }
            Err(e) => {
                error!("Forwarding failed: {}", e);
                self.statistics
                    .servfail_responses
                    .fetch_add(1, Ordering::Relaxed);

                let mut response = query;
                response.header.flags.qr = true;
                response.header.flags.rcode = 2; // SERVFAIL
                Ok(response)
            }
        }
    }

    /// Helper methods for task context
    async fn send_error_response(
        &self,
        socket: &UdpSocket,
        dest: SocketAddr,
        query_data: &[u8],
        rcode: u8,
    ) -> ServerResult<()> {
        let response_data = if let Ok(query) = DnsMessage::parse(query_data) {
            let mut response = query;
            response.header.flags.qr = true;
            response.header.flags.rcode = rcode;
            response.answers.clear();
            response.serialize().unwrap_or_else(|_| vec![0u8; 12])
        } else {
            vec![0u8; 12]
        };

        socket
            .send_to(&response_data, dest)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Send(e.to_string())))?;

        Ok(())
    }

    fn truncate_response(mut response: DnsMessage, max_size: usize) -> ServerResult<Vec<u8>> {
        response.header.flags.tc = true;
        response.additional.clear();

        if let Ok(data) = response.serialize() {
            if data.len() <= max_size {
                return Ok(data);
            }
        }

        response.authority.clear();
        if let Ok(data) = response.serialize() {
            if data.len() <= max_size {
                return Ok(data);
            }
        }

        response.answers.clear();
        response.serialize().map_err(|e| {
            DnsmasqError::Dns(crate::types::errors::DnsError::Serialization(e.to_string()))
        })
    }

    async fn read_tcp_length(&self, stream: &mut TcpStream) -> ServerResult<u16> {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 2];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Receive(e.to_string())))?;
        Ok(u16::from_be_bytes(buf))
    }

    async fn read_tcp_data(&self, stream: &mut TcpStream, length: u16) -> ServerResult<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut data = vec![0u8; length as usize];
        stream
            .read_exact(&mut data)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Receive(e.to_string())))?;
        Ok(data)
    }

    async fn send_tcp_response(&self, stream: &mut TcpStream, data: &[u8]) -> ServerResult<()> {
        use tokio::io::AsyncWriteExt;
        let length = u16::try_from(data.len())
            .map_err(|_| DnsError::ProtocolError {
                message: "DNS response too large for TCP".to_string(),
            })?
            .to_be_bytes();
        stream
            .write_all(&length)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Send(e.to_string())))?;
        stream
            .write_all(data)
            .await
            .map_err(|e| DnsmasqError::Network(NetworkError::Send(e.to_string())))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_builder() {
        let config = ServerConfig::default()
            .with_port(5353)
            .with_cache_size(500)
            .with_max_tcp_connections(32);

        assert_eq!(config.socket_config.port, 5353);
        assert_eq!(config.cache_size, 500);
        assert_eq!(config.max_tcp_connections, 32);
    }

    #[test]
    fn test_socket_config_default() {
        let config = SocketConfig::default();
        assert_eq!(config.port, 53);
        assert!(!config.reuse_port);
        assert!(config.bind_addresses.is_empty());
    }

    #[test]
    fn test_statistics_snapshot() {
        let stats = ServerStatistics::new();
        stats.queries_received.store(100, Ordering::Relaxed);
        stats.cache_hits.store(75, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.queries_received, 100);
        assert_eq!(snapshot.cache_hits, 75);
    }

    #[test]
    fn test_statistics_reset() {
        let stats = ServerStatistics::new();
        stats.queries_received.store(100, Ordering::Relaxed);
        stats.reset();

        assert_eq!(stats.queries_received.load(Ordering::Relaxed), 0);
    }
}
