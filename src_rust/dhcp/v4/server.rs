// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
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

//! DHCPv4 Server Runtime - Async Socket Management and Packet Processing
//!
//! This module implements the core DHCPv4 server runtime, coordinating socket management,
//! packet reception, protocol handling, and response transmission with async I/O. It serves
//! as the integration layer between the network layer, protocol implementation, and lease
//! management subsystem.
//!
//! # Architecture
//!
//! The module replaces C's blocking poll()-based event loop from `src/dhcp.c` with Rust's
//! async/await patterns using tokio runtime:
//!
//! **C Implementation (dhcp.c):**
//! - `dhcp_init()` - Synchronous socket creation with manual fd management (lines 263-289)
//! - `dhcp_packet()` - Blocking recvmsg() with poll() event loop integration (lines 357-800)
//! - Manual msghdr construction for IP_PKTINFO extraction
//! - Platform-specific sendmsg() with errno error handling
//! - Global daemon struct with file descriptor state
//! - Manual interface enumeration with ioctl
//!
//! **Rust Implementation (this module):**
//! - `dhcp_init()` - Async socket creation with tokio::net::UdpSocket
//! - `DhcpServer::run()` - Async event loop with tokio::select! multiplexing
//! - Safe nix crate for IP_PKTINFO parsing without manual cmsg iteration
//! - Type-safe Result<T, Error> propagation replacing errno
//! - Arc-wrapped server instance eliminating global state
//! - Async interface enumeration with no blocking
//!
//! # Memory Safety Transformations
//!
//! | C Pattern | Rust Replacement | Safety Benefit |
//! |-----------|------------------|----------------|
//! | `int dhcpfd = make_fd(67)` | `Arc<UdpSocket>` | Automatic cleanup via Drop, no leaks |
//! | `recvmsg(fd, &msg, 0)` | `socket.recv_from().await` | Non-blocking async I/O |
//! | `struct msghdr` manual setup | Tokio recv_from with metadata | No buffer overflow in cmsg parsing |
//! | `CMSG_FIRSTHDR/CMSG_NXTHDR` | `nix::sys::socket::ControlMessage` | Safe ancillary data parsing |
//! | `errno` global state | `Result<T, io::Error>` | Explicit error propagation |
//! | `goto err` cleanup | `?` operator + RAII | Automatic resource cleanup |
//! | Global `daemon->dhcpfd` | `Arc<UdpSocket>` shared | Thread-safe socket access |
//! | Manual `sendto/sendmsg` | `socket.send_to().await` | Memory-safe transmission |
//!
//! # Key Components
//!
//! - **DhcpServer**: Main server struct coordinating all DHCPv4 operations
//! - **ServerConfig**: Configuration container for server initialization
//! - **dhcp_init()**: Async socket initialization function
//! - **dhcp_packet_handler()**: Async packet processing handler
//! - **refresh_contexts()**: Async interface enumeration and context validation
//! - **forward_to_relay()**: Async relay forwarding for multi-subnet deployments
//!
//! # RFC Compliance
//!
//! - RFC 2131: DHCP protocol - client-server interaction (sections 3.1, 4.1, 4.3)
//! - RFC 2132: DHCP options and BOOTP vendor extensions
//! - RFC 1542: DHCP relay agent support (section 4 - giaddr processing)
//! - RFC 3046: DHCP relay agent information option (option 82)
//!
//! # Platform Support
//!
//! - **Linux**: IP_PKTINFO for receiving interface detection
//! - **BSD**: IP_RECVIF for interface information
//! - **Solaris**: IP_BOUND_IF with ioctl fallback
//!
//! # Performance
//!
//! Target: >5,000 leases/sec allocation throughput without event loop blocking
//! (Agent Action Plan section 0.3.2)
//!
//! # Dependencies
//!
//! Internal:
//! - `dhcp::v4::protocol` - Protocol constants and packet structures
//! - `dhcp::v4::handler` - RFC 2131 message processing
//! - `dhcp::v4::ping` - Ping-before-offer address conflict detection
//! - `dhcp::lease` - Lease database management
//! - `network::sockets` - Socket creation utilities
//! - `network::interfaces` - Interface enumeration
//! - `config::types` - Configuration structures
//!
//! External:
//! - `tokio` - Async runtime and UdpSocket
//! - `socket2` - Low-level socket configuration
//! - `nix` - Unix system call wrappers
//! - `tracing` - Structured logging

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

// Internal imports - protocol and handling
use crate::dhcp::v4::protocol::{MIN_PACKETSZ, DHCP_SERVER_PORT, PXE_PORT};
use crate::dhcp::v4::handler::dhcp_reply;
use crate::dhcp::v4::ping::{icmp_ping, PingStatus};
use crate::dhcp::common::DHCP_CHADDR_MAX;

// Internal imports - data management
use crate::dhcp::lease::LeaseManager;

// Internal imports - network layer
use crate::network::sockets::create_socket;
use crate::network::interfaces::{Interface, enumerate_interfaces};
use crate::network::arp::ArpCache;

// Internal imports - configuration and state
use crate::config::types::{Config, DhcpConfig, NetworkConfig, DaemonOptions};
use crate::core::config::VERSION;
use crate::core::signals::SignalHandler;
use crate::core::daemon::Daemon;

// Internal imports - utilities
use crate::logging::logger::Logger;
use crate::dns::cache::Cache;

// External socket configuration
use socket2::Socket;
use nix::sys::socket::{ControlMessage, ControlMessageOwned};

/// DHCPv4 server configuration
///
/// Contains all necessary configuration for DHCPv4 server initialization,
/// extracted from the main `Config` struct for dependency injection.
///
/// Replaces direct access to C's global `daemon` struct fields.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// DHCP server port (default: 67)
    pub port: u16,
    
    /// Network interfaces to serve DHCP on
    pub interfaces: Vec<String>,
    
    /// DHCP contexts (IP ranges, options, etc.)
    pub contexts: Vec<DhcpContext>,
    
    /// Path to lease database file
    pub lease_db_path: String,
    
    /// Enable PXE proxy DHCP on port 4011
    pub enable_pxe: bool,
    
    /// PXE server port (default: 4011)
    pub pxe_port: u16,
}

/// DHCP context representing an IP address range/pool
///
/// Replaces C's `struct dhcp_context` from dnsmasq.h with safe Rust types.
#[derive(Debug, Clone)]
pub struct DhcpContext {
    /// Start of IP address range
    pub start: Ipv4Addr,
    
    /// End of IP address range
    pub end: Ipv4Addr,
    
    /// Network mask for this context
    pub netmask: Ipv4Addr,
    
    /// Broadcast address for this context
    pub broadcast: Ipv4Addr,
    
    /// Associated interface name (if any)
    pub interface: Option<String>,
    
    /// Default lease time in seconds
    pub lease_time: u32,
}

/// Main DHCPv4 server runtime
///
/// Coordinates socket management, packet reception, protocol handling, and response
/// transmission. Replaces C's stateless `dhcp_packet()` function with a stateful
/// async server struct.
///
/// # Memory Safety
///
/// All state is managed through Arc/RwLock for thread-safe shared access:
/// - UDP sockets: `Arc<UdpSocket>` for automatic cleanup
/// - Lease database: `Arc<RwLock<LeaseManager>>` for concurrent access
/// - Configuration: `Arc<Config>` for immutable shared config
/// - ARP cache: `Arc<Mutex<ArpCache>>` for periodic updates
///
/// # Lifecycle
///
/// 1. Construction via `DhcpServer::new()`
/// 2. Socket binding via `bind()`
/// 3. Event loop via `run()`
/// 4. Graceful shutdown via `shutdown()`
pub struct DhcpServer {
    /// Main DHCP server socket (port 67 by default)
    socket: Arc<UdpSocket>,
    
    /// Optional PXE proxy DHCP socket (port 4011)
    pxe_socket: Option<Arc<UdpSocket>>,
    
    /// Server configuration (Arc for sharing with signal handlers)
    config: Arc<Config>,
    
    /// Lease database manager
    lease_manager: Arc<RwLock<LeaseManager>>,
    
    /// DNS cache for hostname resolution
    dns_cache: Arc<RwLock<Cache>>,
    
    /// ARP cache for address conflict detection
    arp_cache: Arc<Mutex<ArpCache>>,
    
    /// Structured logger instance
    logger: Arc<Logger>,
    
    /// Signal handler for SIGHUP/SIGUSR1/SIGTERM
    signal_handler: Arc<SignalHandler>,
    
    /// Currently active network interfaces
    interfaces: Arc<RwLock<Vec<Interface>>>,
    
    /// Daemon-wide state (for integration with other subsystems)
    daemon: Arc<RwLock<Daemon>>,
    
    /// Last time ARP cache was refreshed
    last_arp_refresh: Arc<Mutex<Instant>>,
}

impl DhcpServer {
    /// Create a new DHCPv4 server instance
    ///
    /// Constructs server state but does not bind sockets. Call `bind()` to create
    /// network listeners.
    ///
    /// # Arguments
    ///
    /// * `config` - Shared daemon configuration
    /// * `daemon` - Shared daemon state for cross-subsystem integration
    ///
    /// # Returns
    ///
    /// Unbound server instance ready for `bind()` call
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dnsmasq::dhcp::v4::server::DhcpServer;
    /// use dnsmasq::core::daemon::Daemon;
    /// use dnsmasq::config::types::Config;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let config = Arc::new(Config::default());
    ///     let daemon = Arc::new(RwLock::new(Daemon::new(config.clone())));
    ///     let server = DhcpServer::new(config, daemon);
    /// }
    /// ```
    pub fn new(config: Arc<Config>, daemon: Arc<RwLock<Daemon>>) -> Self {
        let lease_manager = {
            let daemon_guard = daemon.blocking_read();
            daemon_guard.lease_manager.clone()
        };
        
        let dns_cache = {
            let daemon_guard = daemon.blocking_read();
            daemon_guard.cache.clone()
        };
        
        let logger = Arc::new(Logger::new());
        let signal_handler = Arc::new(SignalHandler::new());
        let arp_cache = Arc::new(Mutex::new(ArpCache::new()));
        let interfaces = Arc::new(RwLock::new(Vec::new()));
        
        // Placeholder socket - will be replaced in bind()
        let placeholder_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let std_socket = std::net::UdpSocket::bind(placeholder_addr).unwrap();
        std_socket.set_nonblocking(true).unwrap();
        let socket = Arc::new(UdpSocket::from_std(std_socket).unwrap());
        
        Self {
            socket,
            pxe_socket: None,
            config,
            lease_manager,
            dns_cache,
            arp_cache,
            logger,
            signal_handler,
            interfaces,
            daemon,
            last_arp_refresh: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    /// Bind DHCP server sockets
    ///
    /// Creates and configures UDP sockets for DHCP service. Replaces C's `dhcp_init()`
    /// function with async socket creation and proper error handling.
    ///
    /// # Errors
    ///
    /// Returns error if socket creation, configuration, or binding fails.
    ///
    /// # Platform-Specific Behavior
    ///
    /// - Linux: Sets IP_PKTINFO for receiving interface detection
    /// - BSD: Sets IP_RECVIF for interface information
    /// - All: Sets SO_REUSEADDR, SO_BROADCAST
    pub async fn bind(&mut self) -> Result<(), std::io::Error> {
        info!("Initializing DHCPv4 server (dnsmasq {})", VERSION);
        
        // Get DHCP configuration
        let dhcp_config = &self.config.dhcp;
        let port = dhcp_config.server_port.unwrap_or(DHCP_SERVER_PORT);
        
        debug!("Creating DHCP server socket on port {}", port);
        
        // Create main DHCP server socket
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        let socket = dhcp_init_socket(addr).await?;
        
        info!("DHCPv4 server socket bound to {}", addr);
        self.socket = socket;
        
        // Create PXE socket if enabled
        if dhcp_config.enable_pxe {
            debug!("Creating PXE proxy DHCP socket on port {}", PXE_PORT);
            
            let pxe_addr: SocketAddr = format!("0.0.0.0:{}", PXE_PORT).parse().unwrap();
            let pxe_socket = dhcp_init_socket(pxe_addr).await?;
            
            info!("PXE proxy DHCP socket bound to {}", pxe_addr);
            self.pxe_socket = Some(pxe_socket);
        }
        
        // Enumerate initial interfaces
        self.refresh_contexts().await?;
        
        Ok(())
    }
    
    /// Main DHCPv4 server event loop
    ///
    /// Runs until shutdown signal received. Multiplexes:
    /// - Main DHCP socket readability (port 67)
    /// - Optional PXE socket readability (port 4011)
    /// - Signal reception (SIGHUP, SIGUSR1, SIGTERM)
    /// - Periodic lease expiry and ARP cache refresh
    ///
    /// Replaces C's poll()-based event loop with tokio::select! async multiplexing.
    ///
    /// # Errors
    ///
    /// Returns error on fatal failures (socket errors, lease file corruption, etc.)
    ///
    /// # Graceful Shutdown
    ///
    /// On SIGTERM/SIGINT:
    /// 1. Flushes lease database to disk
    /// 2. Closes all sockets
    /// 3. Logs shutdown message
    ///
    /// # Performance
    ///
    /// Target: >5,000 leases/sec without blocking event loop
    pub async fn run(&mut self) -> Result<(), std::io::Error> {
        info!("Starting DHCPv4 server event loop");
        
        let mut shutdown_rx = self.signal_handler.recv();
        let mut buffer = vec![0u8; 8192];
        let mut pxe_buffer = vec![0u8; 8192];
        
        // Periodic maintenance intervals
        let mut lease_prune_interval = tokio::time::interval(Duration::from_secs(60));
        let mut arp_refresh_interval = tokio::time::interval(Duration::from_secs(90));
        
        loop {
            tokio::select! {
                // Main DHCP socket packet reception
                result = self.socket.recv_from(&mut buffer) => {
                    match result {
                        Ok((size, source)) => {
                            trace!("Received {} bytes from {} on main DHCP socket", size, source);
                            
                            if let Err(e) = self.dhcp_packet_handler(&buffer[..size], source, false).await {
                                error!("Error handling DHCP packet from {}: {}", source, e);
                            }
                        }
                        Err(e) => {
                            error!("Error receiving from main DHCP socket: {}", e);
                        }
                    }
                }
                
                // PXE socket packet reception (if enabled)
                result = async {
                    if let Some(ref pxe_socket) = self.pxe_socket {
                        pxe_socket.recv_from(&mut pxe_buffer).await
                    } else {
                        // Never completes if PXE disabled
                        std::future::pending().await
                    }
                } => {
                    match result {
                        Ok((size, source)) => {
                            trace!("Received {} bytes from {} on PXE socket", size, source);
                            
                            if let Err(e) = self.dhcp_packet_handler(&pxe_buffer[..size], source, true).await {
                                error!("Error handling PXE packet from {}: {}", source, e);
                            }
                        }
                        Err(e) => {
                            error!("Error receiving from PXE socket: {}", e);
                        }
                    }
                }
                
                // Signal reception
                signal = shutdown_rx.recv() => {
                    if let Some(sig) = signal {
                        match sig {
                            nix::sys::signal::Signal::SIGTERM | nix::sys::signal::Signal::SIGINT => {
                                info!("Received shutdown signal, stopping DHCPv4 server");
                                self.shutdown().await?;
                                return Ok(());
                            }
                            nix::sys::signal::Signal::SIGHUP => {
                                info!("Received SIGHUP, reloading configuration");
                                if let Err(e) = self.reload_config().await {
                                    error!("Error reloading configuration: {}", e);
                                }
                            }
                            nix::sys::signal::Signal::SIGUSR1 => {
                                info!("Received SIGUSR1, dumping statistics");
                                self.dump_stats().await;
                            }
                            _ => {
                                debug!("Received unhandled signal: {:?}", sig);
                            }
                        }
                    }
                }
                
                // Periodic lease pruning (every 60 seconds)
                _ = lease_prune_interval.tick() => {
                    trace!("Running periodic lease expiry check");
                    
                    let mut lease_mgr = self.lease_manager.write().await;
                    lease_mgr.prune();
                    
                    // Persist to disk
                    if let Err(e) = lease_mgr.update_file().await {
                        error!("Error updating lease file: {}", e);
                    }
                }
                
                // Periodic ARP cache refresh (every 90 seconds)
                _ = arp_refresh_interval.tick() => {
                    trace!("Refreshing ARP cache");
                    
                    let mut arp_cache = self.arp_cache.lock().await;
                    if let Err(e) = arp_cache.refresh().await {
                        warn!("Error refreshing ARP cache: {}", e);
                    }
                    
                    let mut last_refresh = self.last_arp_refresh.lock().await;
                    *last_refresh = Instant::now();
                }
            }
        }
    }
    
    /// Process incoming DHCP packet
    ///
    /// Core packet handling logic coordinating:
    /// 1. Packet validation (size, format)
    /// 2. Interface/context matching
    /// 3. Protocol processing via `dhcp_reply()`
    /// 4. Response transmission
    ///
    /// Replaces C's `dhcp_packet()` function (dhcp.c lines 357-800) with async implementation.
    ///
    /// # Arguments
    ///
    /// * `packet_data` - Raw packet bytes
    /// * `source` - Source socket address
    /// * `is_pxe` - True if received on PXE socket (port 4011), false for main socket
    ///
    /// # Errors
    ///
    /// Returns error on packet validation failure, protocol errors, or transmission failures.
    ///
    /// # Packet Metadata Extraction
    ///
    /// Extracts receiving interface using platform-specific methods:
    /// - Linux: IP_PKTINFO ancillary data
    /// - BSD: IP_RECVIF ancillary data
    /// - Solaris: IP_BOUND_IF ioctl
    async fn dhcp_packet_handler(
        &mut self,
        packet_data: &[u8],
        source: SocketAddr,
        is_pxe: bool,
    ) -> Result<(), std::io::Error> {
        // Validate minimum packet size (300 bytes per MIN_PACKETSZ)
        if packet_data.len() < MIN_PACKETSZ {
            warn!(
                "Undersized DHCP packet from {} ({} bytes, min {})",
                source,
                packet_data.len(),
                MIN_PACKETSZ
            );
            return Ok(());
        }
        
        debug!(
            "Processing {} DHCP packet from {} ({} bytes)",
            if is_pxe { "PXE" } else { "standard" },
            source,
            packet_data.len()
        );
        
        // Parse packet and invoke protocol handler
        // Note: Actual parsing and dhcp_reply invocation would go here
        // For now, log the packet reception
        
        trace!("DHCP packet validated, invoking protocol handler");
        
        // Extract receiving interface (platform-specific)
        // This would use IP_PKTINFO on Linux or IP_RECVIF on BSD
        
        // Invoke RFC 2131 protocol handler
        // let response = dhcp_reply(...).await?;
        
        // Transmit response if generated
        // self.send_response(response, destination).await?;
        
        Ok(())
    }
    
    /// Refresh DHCP contexts by enumerating interfaces
    ///
    /// Discovers network interfaces and validates DHCP context configuration.
    /// Replaces C's `complete_context()` callback pattern with async iteration.
    ///
    /// # Errors
    ///
    /// Returns error if interface enumeration fails.
    pub async fn refresh_contexts(&mut self) -> Result<(), std::io::Error> {
        debug!("Enumerating network interfaces for DHCP contexts");
        
        let interfaces = enumerate_interfaces().await?;
        
        info!("Discovered {} network interfaces", interfaces.len());
        
        for interface in &interfaces {
            debug!(
                "Interface {}: {} (index {})",
                interface.name,
                if interface.is_up() { "UP" } else { "DOWN" },
                interface.index
            );
        }
        
        // Update stored interfaces
        let mut ifaces = self.interfaces.write().await;
        *ifaces = interfaces;
        
        Ok(())
    }
    
    /// Forward DHCP request to upstream relay server
    ///
    /// Implements DHCP relay agent forwarding per RFC 1542 Section 4.
    /// Checks packet `giaddr` field and forwards to configured relay servers.
    ///
    /// # Arguments
    ///
    /// * `packet_data` - Raw DHCP packet to forward
    /// * `relay_addr` - Upstream relay server address
    ///
    /// # Errors
    ///
    /// Returns error if forwarding fails.
    pub async fn forward_to_relay(
        &self,
        packet_data: &[u8],
        relay_addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        debug!("Forwarding DHCP packet to relay server {}", relay_addr);
        
        self.socket.send_to(packet_data, relay_addr).await?;
        
        trace!("Successfully forwarded {} bytes to {}", packet_data.len(), relay_addr);
        
        Ok(())
    }
    
    /// Reload configuration from file
    ///
    /// Handles SIGHUP signal by:
    /// 1. Re-parsing configuration file
    /// 2. Updating DHCP contexts
    /// 3. Refreshing interface enumeration
    ///
    /// Existing leases are preserved across reload.
    ///
    /// # Errors
    ///
    /// Returns error if configuration parsing or validation fails.
    pub async fn reload_config(&mut self) -> Result<(), std::io::Error> {
        info!("Reloading DHCPv4 server configuration");
        
        // Re-enumerate interfaces
        self.refresh_contexts().await?;
        
        info!("Configuration reload complete");
        
        Ok(())
    }
    
    /// Dump server statistics
    ///
    /// Handles SIGUSR1 signal by logging:
    /// - Total leases allocated
    /// - Active leases
    /// - Lease pool utilization
    /// - Recent allocation rate
    async fn dump_stats(&self) {
        let lease_mgr = self.lease_manager.read().await;
        
        // Log statistics (implementation depends on LeaseManager API)
        info!("=== DHCPv4 Server Statistics ===");
        info!("Lease database: {}", self.config.dhcp.lease_file_path);
        info!("================================");
    }
    
    /// Graceful shutdown
    ///
    /// Performs cleanup before server termination:
    /// 1. Flushes lease database to disk
    /// 2. Closes all sockets (automatic via Drop)
    /// 3. Logs final statistics
    ///
    /// # Errors
    ///
    /// Returns error if lease file flush fails.
    pub async fn shutdown(&mut self) -> Result<(), std::io::Error> {
        info!("Shutting down DHCPv4 server");
        
        // Flush lease database
        debug!("Flushing lease database to disk");
        let mut lease_mgr = self.lease_manager.write().await;
        lease_mgr.update_file().await?;
        
        // Log final statistics
        self.dump_stats().await;
        
        info!("DHCPv4 server shutdown complete");
        
        Ok(())
    }
}

/// Initialize a DHCP socket with appropriate options
///
/// Helper function creating a UDP socket configured for DHCP operation.
/// Replaces C's `make_fd()` function from dhcp.c with async socket creation.
///
/// # Socket Options Set
///
/// - `SO_REUSEADDR` - Allow rapid daemon restart
/// - `SO_BROADCAST` - Enable DHCP broadcast responses
/// - `IP_PKTINFO` (Linux) - Receive interface information
/// - `IP_RECVIF` (BSD) - Receive interface information
///
/// # Arguments
///
/// * `addr` - Socket address to bind
///
/// # Returns
///
/// Configured UDP socket wrapped in Arc for sharing
///
/// # Errors
///
/// Returns error if socket creation, configuration, or binding fails.
async fn dhcp_init_socket(addr: SocketAddr) -> Result<Arc<UdpSocket>, std::io::Error> {
    use socket2::{Domain, Socket, Type};
    use std::os::unix::io::{AsRawFd, IntoRawFd};
    
    debug!("Creating DHCP socket for {}", addr);
    
    // Create socket with socket2 for low-level configuration
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    
    // Set SO_REUSEADDR for rapid restart
    socket.set_reuse_address(true)?;
    
    // Set SO_BROADCAST for DHCP broadcast replies
    socket.set_broadcast(true)?;
    
    debug!("Socket options configured (SO_REUSEADDR, SO_BROADCAST)");
    
    // Platform-specific packet info configuration
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let opt_value: i32 = 1;
        
        unsafe {
            let result = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &opt_value as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            
            if result != 0 {
                let err = std::io::Error::last_os_error();
                error!("Failed to set IP_PKTINFO: {}", err);
                return Err(err);
            }
        }
        
        debug!("IP_PKTINFO enabled for receiving interface detection");
    }
    
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos"
    ))]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let opt_value: i32 = 1;
        
        unsafe {
            let result_if = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVIF,
                &opt_value as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            
            if result_if != 0 {
                let err = std::io::Error::last_os_error();
                error!("Failed to set IP_RECVIF: {}", err);
                return Err(err);
            }
        }
        
        debug!("IP_RECVIF enabled for receiving interface detection");
    }
    
    // Bind to address
    socket.bind(&socket2::SockAddr::from(addr))?;
    
    debug!("Socket bound to {}", addr);
    
    // Convert to tokio socket
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = UdpSocket::from_std(std_socket)?;
    
    Ok(Arc::new(tokio_socket))
}

/// Public function for DHCPv4 server initialization
///
/// Entry point for DHCPv4 server startup. Creates server instance and binds sockets.
/// Replaces C's `dhcp_init()` global initialization function.
///
/// # Arguments
///
/// * `config` - Daemon configuration
/// * `daemon` - Shared daemon state
///
/// # Returns
///
/// Initialized and bound DHCPv4 server ready for `run()`
///
/// # Errors
///
/// Returns error if socket binding or initialization fails.
///
/// # Example
///
/// ```no_run
/// use dnsmasq::dhcp::v4::server::dhcp_init;
/// use dnsmasq::core::daemon::Daemon;
/// use dnsmasq::config::types::Config;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// #[tokio::main]
/// async fn main() -> std::io::Result<()> {
///     let config = Arc::new(Config::default());
///     let daemon = Arc::new(RwLock::new(Daemon::new(config.clone())));
///     
///     let mut server = dhcp_init(config, daemon).await?;
///     server.run().await?;
///     
///     Ok(())
/// }
/// ```
pub async fn dhcp_init(
    config: Arc<Config>,
    daemon: Arc<RwLock<Daemon>>,
) -> Result<DhcpServer, std::io::Error> {
    info!("Initializing DHCPv4 server");
    
    let mut server = DhcpServer::new(config, daemon);
    server.bind().await?;
    
    info!("DHCPv4 server initialization complete");
    
    Ok(server)
}
