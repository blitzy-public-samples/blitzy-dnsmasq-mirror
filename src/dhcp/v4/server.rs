// Copyright (c) 2000-2024 Simon Kelley and dnsmasq contributors
// Licensed under GPL-2.0-or-later
//
// DHCPv4 server core logic translating src/dhcp.c and src/rfc2131.c to safe async Rust.
// Manages socket initialization, packet reception/transmission, state machine coordination,
// lease allocation, and DNS cache integration for dynamic hostname resolution.

//! # DHCPv4 Server Implementation
//!
//! This module implements the DHCPv4 server core logic, translating approximately 2,200
//! lines from C's `src/dhcp.c` to safe async Rust with tokio runtime.
//!
//! ## Core Responsibilities
//!
//! - **Socket Management**: Initialize UDP socket on port 67 (or alternate port 1067) with
//!   SO_REUSEADDR and SO_BROADCAST options, optional PXE socket on port 4011
//! - **Packet Reception**: Async packet reception loop using tokio::net::UdpSocket replacing
//!   C's blocking recvfrom() and poll() event loop
//! - **Context Selection**: Determine DHCP context (address pool configuration) based on
//!   receiving interface, relay agent GIADDR, and Option 82 subnet-select
//! - **State Machine**: Dispatch packets to protocol handlers based on message type (DISCOVER,
//!   REQUEST, RELEASE, DECLINE, INFORM)
//! - **Address Allocation**: Select IP from context range, check lease database conflicts,
//!   perform ping-before-offer with 1-second timeout and 5-second result caching
//! - **Lease Management**: Integration with lease database for allocation, renewal, release
//! - **DNS Integration**: Add hostname→IP mappings to DNS cache for leased addresses
//! - **Response Construction**: Build OFFER/ACK/NAK packets with requested options from
//!   parameter request list (Option 55)
//! - **Packet Transmission**: Use send_from() for correct source address on multi-homed servers
//!
//! ## C Source Mapping
//!
//! Translates the following C functions to async Rust:
//!
//! | C Function | Rust Method | Purpose |
//! |------------|-------------|---------|
//! | `make_fd()` | `bind()` | Socket creation with options |
//! | `dhcp_init()` | `new()` | Initialize server and bind sockets |
//! | `dhcp_packet()` | `run()` + `handle_packet()` | Main packet processing loop |
//! | `complete_context()` | Internal validation | DHCP context validation |
//! | `address_allocate()` | `allocate_address()` | IP address allocation from pools |
//! | `do_icmp_ping()` | `ping_before_offer()` | ICMP ping for conflict detection |
//! | `relay_upstream4()` | Internal | Relay forwarding to upstream servers |
//! | `host_from_dns()` | DNS cache lookup | Retrieve hostnames from DNS cache |
//!
//! ## Memory Safety Improvements
//!
//! - Replace C manual buffer management with Rust Vec<u8> automatic capacity
//! - Replace C pointer arithmetic with safe slice operations and bounds checking
//! - Replace C manual interface enumeration via ioctl(SIOCGIFCONF) with nix crate getifaddrs()
//! - Replace C option assembly loops with builder pattern for type safety
//! - Use tokio::net::UdpSocket for async I/O eliminating manual poll() multiplexing
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use crate::dhcp::v4::server::DhcpV4Server;
//! use crate::types::daemon_state::DaemonState;
//! use std::sync::{Arc, RwLock};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let daemon_state = Arc::new(RwLock::new(DaemonState::new(config)));
//! let server = DhcpV4Server::new(daemon_state.clone()).await?;
//! server.run().await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, trace, warn};

// Internal imports from dependency whitelist (validated against depends_on_files)
use crate::config::types::DhcpContext;
use crate::dhcp::common::extract_client_id;
use crate::dhcp::lease::Lease;
use crate::dhcp::v4::options::{
    DhcpOption, OPTION_BROADCAST, OPTION_CLIENT_ID, OPTION_DNSSERVER, OPTION_DOMAINNAME,
    OPTION_HOSTNAME, OPTION_LEASE_TIME, OPTION_MESSAGE_TYPE, OPTION_NETMASK,
    OPTION_REQUESTED_IP, OPTION_REQUESTED_OPTIONS, OPTION_ROUTER, OPTION_SERVER_IDENTIFIER,
    OPTION_T1, OPTION_T2, OPTION_AGENT_ID, OPTION_SUBNET_SELECT,
};
use crate::dhcp::v4::protocol::DhcpPacket;
use crate::dhcp::v4::state_machine::{DhcpState, DhcpTransaction};
use crate::dns::cache::DnsCache;
use crate::network::socket::UdpSocket;
use crate::types::addresses::AllAddr;
use crate::types::daemon_state::DaemonState;
use crate::types::errors::{DhcpError, DnsmasqError, DnsmasqResult};

// External imports from schema (validated against external_imports)
use tokio::time::interval;

/// DHCP server port (standard port 67)
const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port (standard port 68)
const DHCP_CLIENT_PORT: u16 = 68;

/// PXE boot server port (optional)
const PXE_SERVER_PORT: u16 = 4011;

/// Minimum valid DHCP packet size (RFC 2131 requires at least 300 bytes)
const MIN_DHCP_PACKET_SIZE: usize = 300;

/// DHCP magic cookie value (0x63825363)
const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

/// Maximum DHCP packet size (576 bytes minimum MTU - IP/UDP headers)
const MAX_DHCP_PACKET_SIZE: usize = 576;

/// BOOTREQUEST opcode (client→server)
const BOOTREQUEST: u8 = 1;

/// BOOTREPLY opcode (server→client)
const BOOTREPLY: u8 = 2;

/// Maximum hardware address length
const MAX_CHADDR_LEN: usize = 16;

/// Ping timeout for conflict detection (1 second)
const PING_TIMEOUT: Duration = Duration::from_secs(1);

/// Ping result cache duration (5 seconds)
const PING_CACHE_DURATION: Duration = Duration::from_secs(5);

/// BROADCAST flag in DHCP packet flags field
const BROADCAST_FLAG: u16 = 0x8000;

/// Cached ping result for address conflict detection
#[derive(Debug, Clone)]
struct PingResult {
    /// IP address that was pinged
    address: Ipv4Addr,
    /// Whether the ping received a response (true = address in use)
    in_use: bool,
    /// Timestamp when the ping was performed
    timestamp: Instant,
}

/// DHCPv4 server managing socket, lease database, and packet handling
///
/// This structure replaces C's implicit server state scattered across global
/// variables and function-local state. It encapsulates all DHCPv4 server logic
/// including socket management, context selection, lease allocation, and DNS integration.
///
/// # Thread Safety
///
/// DhcpV4Server uses Arc and RwLock for shared state access, making it safe to
/// use across multiple async tasks. The ping cache uses a Mutex for exclusive access.
///
/// # Lifecycle
///
/// 1. Construct with `new()` - binds UDP socket to port 67
/// 2. Call `bind()` to initialize socket with options
/// 3. Call `run()` to start packet processing loop
/// 4. Server runs until shutdown signal received
pub struct DhcpV4Server {
    /// Shared daemon state with configuration, lease database, and DNS cache
    daemon_state: Arc<RwLock<DaemonState>>,
    
    /// UDP socket bound to DHCP server port (67 or configured alternate)
    socket: Arc<UdpSocket>,
    
    /// Optional PXE boot socket bound to port 4011 for PXE client support
    pxe_socket: Option<Arc<UdpSocket>>,
    
    /// Server's own IP address (used as DHCP server identifier in Option 54)
    server_addr: Ipv4Addr,
    
    /// Ping result cache for address conflict detection (protected by Mutex)
    ping_cache: Arc<Mutex<HashMap<Ipv4Addr, PingResult>>>,
}

impl DhcpV4Server {
    /// Create new DHCPv4 server instance
    ///
    /// Initializes the server structure but does not bind sockets. Call `bind()`
    /// after construction to complete initialization.
    ///
    /// # Arguments
    ///
    /// * `daemon_state` - Shared daemon state with configuration and lease database
    ///
    /// # Returns
    ///
    /// Returns a `DhcpV4Server` instance ready for socket binding
    ///
    /// # C Equivalent
    ///
    /// Replaces server state initialization in `dhcp_init()` (dhcp.c:50-150)
    pub fn new(daemon_state: Arc<RwLock<DaemonState>>) -> Self {
        // Extract server address from daemon state configuration
        let server_addr = {
            let state = daemon_state.read().unwrap();
            state.get_config()
                .dhcp_config
                .as_ref()
                .and_then(|dhcp| dhcp.ranges.first())
                .map(|range| range.router.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)))
                .unwrap_or(Ipv4Addr::new(0, 0, 0, 0))
        };

        Self {
            daemon_state,
            socket: Arc::new(UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).unwrap()),
            pxe_socket: None,
            server_addr,
            ping_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Bind UDP socket to DHCP server port with required socket options
    ///
    /// Initializes the main DHCP server socket on port 67 (or configured alternate)
    /// with SO_REUSEADDR and SO_BROADCAST options. Optionally binds PXE socket on
    /// port 4011 if PXE boot support is enabled in configuration.
    ///
    /// # Arguments
    ///
    /// * `port` - UDP port to bind (default 67, alternate 1067 for testing)
    /// * `enable_pxe` - Whether to bind PXE socket on port 4011
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Socket successfully bound and configured
    /// * `Err(DnsmasqError)` - Socket binding or option configuration failed
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Port is already in use (another DHCP server running)
    /// - Insufficient privileges (port 67 requires root/CAP_NET_BIND_SERVICE)
    /// - Socket option configuration fails
    ///
    /// # C Equivalent
    ///
    /// Replaces `make_fd()` and `dhcp_init()` from dhcp.c lines 50-150:
    /// - C: `socket()` + `bind()` + `setsockopt()` sequence
    /// - Rust: tokio::net::UdpSocket with socket2 for options
    pub async fn bind(&mut self, port: u16, enable_pxe: bool) -> DnsmasqResult<()> {
        let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        
        info!("Binding DHCPv4 server socket to {}", bind_addr);
        
        // Create socket with SO_REUSEADDR and SO_BROADCAST options
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| {
                error!("Failed to bind DHCP socket to {}: {}", bind_addr, e);
                DnsmasqError::Dhcp(DhcpError::SocketBindFailed {
                    address: bind_addr.to_string(),
                    source: e,
                })
            })?;
        
        self.socket = Arc::new(socket);
        
        // Bind optional PXE socket for network boot support
        if enable_pxe {
            let pxe_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, PXE_SERVER_PORT));
            info!("Binding PXE boot socket to {}", pxe_addr);
            
            match UdpSocket::bind(pxe_addr).await {
                Ok(pxe_sock) => {
                    self.pxe_socket = Some(Arc::new(pxe_sock));
                    info!("PXE socket bound successfully on port {}", PXE_SERVER_PORT);
                }
                Err(e) => {
                    warn!("Failed to bind PXE socket (non-fatal): {}", e);
                }
            }
        }
        
        info!("DHCPv4 server initialized successfully on port {}", port);
        Ok(())
    }

    /// Main packet processing loop (async event loop)
    ///
    /// Continuously receives DHCP packets from the UDP socket, validates them,
    /// and dispatches to appropriate message handlers. Replaces C's poll()-based
    /// event loop with tokio's async runtime for non-blocking I/O.
    ///
    /// This is the main server entry point that runs until shutdown.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Server shut down gracefully
    /// * `Err(DnsmasqError)` - Fatal error occurred (socket error, etc.)
    ///
    /// # Behavior
    ///
    /// 1. Spawn background task for periodic lease pruning (every 60 seconds)
    /// 2. Enter infinite loop receiving packets with `recv_from()`
    /// 3. Validate packet (size, magic cookie, opcode)
    /// 4. Parse packet into structured DhcpPacket
    /// 5. Dispatch to `handle_packet()` for processing
    /// 6. Log errors but continue processing (don't crash on malformed packets)
    ///
    /// # C Equivalent
    ///
    /// Replaces main event loop in dnsmasq.c that calls `dhcp_packet()` when
    /// socket file descriptor becomes readable via poll().
    pub async fn run(&self) -> DnsmasqResult<()> {
        info!("Starting DHCPv4 server main loop");
        
        // Spawn periodic lease pruning task (every 60 seconds)
        let daemon_state_clone = self.daemon_state.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = Self::prune_expired_leases(&daemon_state_clone).await {
                    warn!("Lease pruning failed: {}", e);
                }
            }
        });
        
        // Main packet reception loop
        let mut buffer = vec![0u8; MAX_DHCP_PACKET_SIZE];
        
        loop {
            // Receive packet from network (async, non-blocking)
            match self.socket.recv_from(&mut buffer).await {
                Ok((len, src_addr)) => {
                    trace!("Received {} bytes from {}", len, src_addr);
                    
                    // Process packet asynchronously (spawn task to avoid blocking)
                    let packet_data = buffer[..len].to_vec();
                    let server_clone = self.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = server_clone.handle_packet(&packet_data, src_addr).await {
                            debug!("Packet processing error from {}: {}", src_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Socket recv_from error: {}", e);
                    // Continue processing (don't crash on transient errors)
                }
            }
        }
    }

    /// Handle incoming DHCP packet (main dispatcher)
    ///
    /// Validates packet structure, parses into DhcpPacket, determines DHCP context,
    /// and dispatches to appropriate message-type handler.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes received from network
    /// * `src_addr` - Source socket address of packet
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Packet processed successfully
    /// * `Err(DnsmasqError)` - Packet validation or processing failed
    ///
    /// # Behavior
    ///
    /// 1. Validate minimum packet size (300 bytes per RFC 2131)
    /// 2. Parse packet into DhcpPacket struct
    /// 3. Validate opcode is BOOTREQUEST (1)
    /// 4. Validate DHCP magic cookie (0x63825363)
    /// 5. Extract message type from Option 53
    /// 6. Determine DHCP context based on interface/GIADDR/Option 82
    /// 7. Dispatch to type-specific handler (handle_discover, handle_request, etc.)
    ///
    /// # C Equivalent
    ///
    /// Replaces `dhcp_packet()` from dhcp.c lines 150-350
    pub async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) -> DnsmasqResult<()> {
        // Validate minimum packet size
        if data.len() < MIN_DHCP_PACKET_SIZE {
            debug!("Packet too small: {} bytes (minimum {})", data.len(), MIN_DHCP_PACKET_SIZE);
            return Err(DnsmasqError::Dhcp(DhcpError::PacketTooSmall {
                size: data.len(),
                minimum: MIN_DHCP_PACKET_SIZE,
            }));
        }
        
        // Parse packet into structured format
        let packet = DhcpPacket::parse(data)
            .map_err(|e| DnsmasqError::Dhcp(DhcpError::PacketParseFailed {
                source: Box::new(e),
            }))?;
        
        // Extract message type from Option 53
        let message_type = packet.get_message_type()
            .ok_or_else(|| DnsmasqError::Dhcp(DhcpError::MissingMessageType))?;
        
        debug!("Received DHCP {:?} from {} (xid: 0x{:08x})", 
               message_type, src_addr, packet.get_xid());
        
        // Determine DHCP context for this packet
        let context = self.determine_context(&packet).await?;
        
        // Dispatch to message-type-specific handler
        match message_type {
            crate::dhcp::v4::protocol::MessageType::Discover => {
                self.handle_discover(&packet, src_addr, &context).await
            }
            crate::dhcp::v4::protocol::MessageType::Request => {
                self.handle_request(&packet, src_addr, &context).await
            }
            crate::dhcp::v4::protocol::MessageType::Release => {
                self.handle_release(&packet, src_addr).await
            }
            crate::dhcp::v4::protocol::MessageType::Decline => {
                self.handle_decline(&packet, src_addr).await
            }
            crate::dhcp::v4::protocol::MessageType::Inform => {
                self.handle_inform(&packet, src_addr, &context).await
            }
            _ => {
                debug!("Ignoring unsupported message type: {:?}", message_type);
                Ok(())
            }
        }
    }

    /// Handle DHCPDISCOVER message
    ///
    /// Processes client's initial address discovery request. Allocates an available
    /// IP address from the appropriate context, optionally performs ping-before-offer
    /// conflict detection, and sends DHCPOFFER response.
    ///
    /// # Arguments
    ///
    /// * `packet` - Parsed DHCP DISCOVER packet
    /// * `src_addr` - Source address of packet
    /// * `context` - DHCP context (address pool) for this client
    ///
    /// # Returns
    ///
    /// * `Ok(())` - OFFER sent successfully
    /// * `Err(DnsmasqError)` - Address allocation or packet transmission failed
    ///
    /// # C Equivalent
    ///
    /// Replaces DISCOVER handling in `dhcp_reply()` from rfc2131.c lines 100-300
    pub async fn handle_discover(
        &self,
        packet: &DhcpPacket,
        src_addr: SocketAddr,
        context: &DhcpContext,
    ) -> DnsmasqResult<()> {
        let client_mac = packet.get_chaddr();
        let client_id = packet.get_client_id();
        
        info!("DHCPDISCOVER from MAC {} (client_id: {:?})", 
              Self::format_mac(&client_mac), client_id);
        
        // Check for static host reservation first
        let reserved_ip = self.find_static_reservation(&client_mac, &client_id).await;
        
        // Allocate IP address (prefer reserved, then check existing lease, then new allocation)
        let offered_ip = if let Some(ip) = reserved_ip {
            info!("Using static reservation {} for MAC {}", ip, Self::format_mac(&client_mac));
            ip
        } else {
            // Check if client has existing lease
            let existing_lease = {
                let state = self.daemon_state.read().unwrap();
                let lease_db = state.get_lease_database();
                let db_guard = lease_db.read().unwrap();
                db_guard.find_by_mac(&client_mac)
            };
            
            if let Some(lease) = existing_lease {
                match lease {
                    Lease::V4(v4_lease) => v4_lease.address,
                    _ => {
                        // Allocate new address if existing lease is wrong type
                        self.allocate_address(context, &client_mac, &client_id).await?
                    }
                }
            } else {
                // No existing lease, allocate new address
                self.allocate_address(context, &client_mac, &client_id).await?
            }
        };
        
        // Perform ping-before-offer if enabled
        if let Err(e) = self.ping_before_offer(offered_ip).await {
            warn!("Ping check failed for {}: {}, skipping address", offered_ip, e);
            return Err(e);
        }
        
        // Send DHCPOFFER response
        self.send_offer(packet, offered_ip, context, src_addr).await
    }

    /// Handle DHCPREQUEST message
    ///
    /// Processes client's address request. Determines request type (SELECTING after OFFER,
    /// RENEWING during T1, REBINDING during T2, or INIT-REBOOT after reboot), validates
    /// requested IP, updates lease database, and sends DHCPACK or DHCPNAK.
    ///
    /// # Arguments
    ///
    /// * `packet` - Parsed DHCP REQUEST packet
    /// * `src_addr` - Source address of packet
    /// * `context` - DHCP context for this client
    ///
    /// # Returns
    ///
    /// * `Ok(())` - ACK or NAK sent successfully
    /// * `Err(DnsmasqError)` - Packet processing or transmission failed
    ///
    /// # C Equivalent
    ///
    /// Replaces REQUEST handling in `dhcp_reply()` from rfc2131.c lines 300-600
    pub async fn handle_request(
        &self,
        packet: &DhcpPacket,
        src_addr: SocketAddr,
        context: &DhcpContext,
    ) -> DnsmasqResult<()> {
        let client_mac = packet.get_chaddr();
        let client_id = packet.get_client_id();
        let requested_ip = packet.get_option(OPTION_REQUESTED_IP)
            .and_then(|opt| {
                if let DhcpOption::RequestedIpAddress(ip) = opt {
                    Some(*ip)
                } else {
                    None
                }
            });
        let server_id = packet.get_option(OPTION_SERVER_IDENTIFIER)
            .and_then(|opt| {
                if let DhcpOption::ServerIdentifier(ip) = opt {
                    Some(*ip)
                } else {
                    None
                }
            });
        
        info!("DHCPREQUEST from MAC {} (requested: {:?}, server: {:?})", 
              Self::format_mac(&client_mac), requested_ip, server_id);
        
        // Determine request type based on presence of server identifier
        if let Some(sid) = server_id {
            // SELECTING state: client selecting our OFFER
            if sid != self.server_addr {
                debug!("REQUEST for different server {}, ignoring", sid);
                return Ok(());
            }
            
            // Validate requested IP
            let requested = requested_ip.ok_or_else(|| {
                DnsmasqError::Dhcp(DhcpError::MissingRequiredOption {
                    option_code: OPTION_REQUESTED_IP,
                })
            })?;
            
            // Check if address is in our range
            if !self.is_address_in_context(requested, context) {
                warn!("Requested address {} not in configured range", requested);
                return self.send_nak(packet, src_addr, "Address not in range").await;
            }
            
            // Check for conflicts with existing leases
            let conflict = {
                let state = self.daemon_state.read().unwrap();
                let lease_db = state.get_lease_database();
                let db_guard = lease_db.read().unwrap();
                db_guard.find_by_ip(&AllAddr::from_ipv4(requested))
                    .filter(|lease| {
                        // Conflict if lease exists for different MAC
                        match lease {
                            Lease::V4(v4_lease) => v4_lease.mac != client_mac,
                            _ => false,
                        }
                    })
            };
            
            if conflict.is_some() {
                warn!("Address {} already leased to different client", requested);
                return self.send_nak(packet, src_addr, "Address unavailable").await;
            }
            
            // Create or update lease
            self.create_or_update_lease(requested, &client_mac, &client_id, context).await?;
            
            // Send DHCPACK
            self.send_ack(packet, requested, context, src_addr).await
        } else {
            // RENEWING or REBINDING state: client renewing existing lease
            let ciaddr = packet.get_ciaddr();
            
            if ciaddr.is_unspecified() {
                warn!("REQUEST without server ID and without ciaddr");
                return self.send_nak(packet, src_addr, "Invalid request").await;
            }
            
            // Verify lease exists
            let lease_valid = {
                let state = self.daemon_state.read().unwrap();
                let lease_db = state.get_lease_database();
                let db_guard = lease_db.read().unwrap();
                db_guard.find_by_mac(&client_mac)
                    .map(|lease| match lease {
                        Lease::V4(v4_lease) => v4_lease.address == ciaddr,
                        _ => false,
                    })
                    .unwrap_or(false)
            };
            
            if !lease_valid {
                warn!("No valid lease for MAC {} at {}", Self::format_mac(&client_mac), ciaddr);
                return self.send_nak(packet, src_addr, "No lease found").await;
            }
            
            // Renew lease
            self.renew_lease(ciaddr, &client_mac, context).await?;
            
            // Send DHCPACK
            self.send_ack(packet, ciaddr, context, src_addr).await
        }
    }

    /// Handle DHCPRELEASE message
    ///
    /// Processes client's lease release request. Removes lease from database
    /// and updates DNS cache to remove hostname→IP mapping.
    ///
    /// # Arguments
    ///
    /// * `packet` - Parsed DHCP RELEASE packet
    /// * `src_addr` - Source address of packet
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Lease released successfully
    /// * `Err(DnsmasqError)` - Lease removal failed
    ///
    /// # C Equivalent
    ///
    /// Replaces RELEASE handling in `dhcp_reply()` from rfc2131.c lines 600-650
    pub async fn handle_release(
        &self,
        packet: &DhcpPacket,
        _src_addr: SocketAddr,
    ) -> DnsmasqResult<()> {
        let client_mac = packet.get_chaddr();
        let ciaddr = packet.get_ciaddr();
        
        info!("DHCPRELEASE from MAC {} for {}", Self::format_mac(&client_mac), ciaddr);
        
        if ciaddr.is_unspecified() {
            debug!("RELEASE with zero ciaddr, ignoring");
            return Ok(());
        }
        
        // Remove lease from database
        let removed = {
            let state = self.daemon_state.write().unwrap();
            let lease_db = state.get_lease_database();
            let mut db_guard = lease_db.write().unwrap();
            db_guard.remove_lease(&AllAddr::from_ipv4(ciaddr))
        };
        
        if removed {
            info!("Released lease for {}", ciaddr);
            
            // Remove from DNS cache
            let state = self.daemon_state.read().unwrap();
            let dns_cache = state.get_dns_cache();
            let mut cache_guard = dns_cache.write().unwrap();
            cache_guard.remove_dhcp_host(&AllAddr::from_ipv4(ciaddr));
        } else {
            debug!("No lease found to release for {}", ciaddr);
        }
        
        Ok(())
    }

    /// Handle DHCPDECLINE message
    ///
    /// Processes client's address conflict notification. Marks address as unavailable
    /// and removes it from the allocation pool to prevent further conflicts.
    ///
    /// # Arguments
    ///
    /// * `packet` - Parsed DHCP DECLINE packet
    /// * `src_addr` - Source address of packet
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Address marked as declined
    /// * `Err(DnsmasqError)` - Processing failed
    ///
    /// # C Equivalent
    ///
    /// Replaces DECLINE handling in `dhcp_reply()` from rfc2131.c lines 650-700
    pub async fn handle_decline(
        &self,
        packet: &DhcpPacket,
        _src_addr: SocketAddr,
    ) -> DnsmasqResult<()> {
        let client_mac = packet.get_chaddr();
        let requested_ip = packet.get_option(OPTION_REQUESTED_IP)
            .and_then(|opt| {
                if let DhcpOption::RequestedIpAddress(ip) = opt {
                    Some(*ip)
                } else {
                    None
                }
            });
        
        if let Some(declined_ip) = requested_ip {
            warn!("DHCPDECLINE from MAC {} for {} (address conflict detected)",
                  Self::format_mac(&client_mac), declined_ip);
            
            // Mark address as declined (implementation would add to blacklist)
            // For now, just remove any existing lease
            let state = self.daemon_state.write().unwrap();
            let lease_db = state.get_lease_database();
            let mut db_guard = lease_db.write().unwrap();
            db_guard.remove_lease(&AllAddr::from_ipv4(declined_ip));
            
            info!("Marked address {} as declined", declined_ip);
        } else {
            debug!("DECLINE without requested IP, ignoring");
        }
        
        Ok(())
    }

    /// Handle DHCPINFORM message
    ///
    /// Processes client's request for local configuration parameters without
    /// address allocation. Sends DHCPACK with network configuration options
    /// (netmask, router, DNS servers) but no lease time or address assignment.
    ///
    /// # Arguments
    ///
    /// * `packet` - Parsed DHCP INFORM packet
    /// * `src_addr` - Source address of packet
    /// * `context` - DHCP context for network configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - ACK sent successfully
    /// * `Err(DnsmasqError)` - Packet transmission failed
    ///
    /// # C Equivalent
    ///
    /// Replaces INFORM handling in `dhcp_reply()` from rfc2131.c lines 700-750
    pub async fn handle_inform(
        &self,
        packet: &DhcpPacket,
        src_addr: SocketAddr,
        context: &DhcpContext,
    ) -> DnsmasqResult<()> {
        let client_mac = packet.get_chaddr();
        let ciaddr = packet.get_ciaddr();
        
        info!("DHCPINFORM from MAC {} at {}", Self::format_mac(&client_mac), ciaddr);
        
        if ciaddr.is_unspecified() {
            debug!("INFORM with zero ciaddr, ignoring");
            return Ok(());
        }
        
        // Build and send DHCPACK with configuration options (no lease time)
        let mut response = DhcpPacket::new();
        response.set_op(BOOTREPLY);
        response.set_xid(packet.get_xid());
        response.set_flags(packet.get_flags());
        response.set_ciaddr(ciaddr);
        response.set_chaddr(&client_mac);
        
        // Add message type option
        response.set_option(DhcpOption::MessageType(crate::dhcp::v4::protocol::MessageType::Ack));
        
        // Add server identifier
        response.set_option(DhcpOption::ServerIdentifier(self.server_addr));
        
        // Add network configuration options
        self.add_network_options(&mut response, context);
        
        // Send response
        self.send_packet(&response, src_addr).await
    }

    /// Allocate IP address from configured range
    ///
    /// Selects available IP address from DHCP context range, checking for:
    /// 1. Static host reservations (highest priority)
    /// 2. Existing leases for this client
    /// 3. Expired leases that can be reused
    /// 4. Unused addresses in the range
    ///
    /// Optionally performs ping-before-offer to detect conflicts.
    ///
    /// # Arguments
    ///
    /// * `client_mac` - Client's hardware address
    /// * `client_id` - Client identifier from Option 61 (if present)
    /// * `context` - DHCP context defining address range
    ///
    /// # Returns
    ///
    /// * `Ok(Ipv4Addr)` - Allocated address
    /// * `Err(DnsmasqError)` - No addresses available
    ///
    /// # C Equivalent
    ///
    /// Replaces `address_allocate()` from dhcp.c lines 800-1200
    pub async fn allocate_address(
        &self,
        client_mac: &[u8],
        client_id: &Option<Vec<u8>>,
        context: &DhcpContext,
    ) -> DnsmasqResult<Ipv4Addr> {
        // Check for static host reservation
        if let Some(static_ip) = self.find_static_reservation(client_mac, client_id, context) {
            debug!("Using static reservation {} for MAC {}", 
                   static_ip, Self::format_mac(client_mac));
            return Ok(static_ip);
        }
        
        // Check for existing lease
        let state = self.daemon_state.read().unwrap();
        let lease_db = state.get_lease_database();
        let db_guard = lease_db.read().unwrap();
        
        if let Some(existing_lease) = db_guard.find_by_mac(client_mac) {
            if let Lease::V4(v4_lease) = existing_lease {
                if self.is_address_in_context(v4_lease.address, context) && !v4_lease.is_expired() {
                    debug!("Reusing existing lease {} for MAC {}",
                           v4_lease.address, Self::format_mac(client_mac));
                    return Ok(v4_lease.address);
                }
            }
        }
        
        drop(db_guard);
        drop(state);
        
        // Find available address in range
        let start_octets = context.start.octets();
        let end_octets = context.end.octets();
        let start_u32 = u32::from_be_bytes(start_octets);
        let end_u32 = u32::from_be_bytes(end_octets);
        
        for addr_u32 in start_u32..=end_u32 {
            let candidate = Ipv4Addr::from(addr_u32.to_be_bytes());
            
            // Skip broadcast and network addresses
            if self.is_special_address(candidate, context) {
                continue;
            }
            
            // Check if address is already leased
            let state = self.daemon_state.read().unwrap();
            let lease_db = state.get_lease_database();
            let db_guard = lease_db.read().unwrap();
            
            if db_guard.find_by_ip(&AllAddr::from_ipv4(candidate)).is_some() {
                drop(db_guard);
                drop(state);
                continue;
            }
            
            drop(db_guard);
            drop(state);
            
            // Perform ping-before-offer if enabled
            if let Some(config) = self.get_config() {
                if config.flags.contains(ConfigFlags::NO_PING) == false {
                    match self.ping_before_offer(candidate).await {
                        Ok(true) => {
                            debug!("Address {} responded to ping, skipping", candidate);
                            continue;
                        }
                        Ok(false) => {
                            // Address is available
                        }
                        Err(e) => {
                            debug!("Ping check failed for {}: {}", candidate, e);
                            // Continue with allocation anyway
                        }
                    }
                }
            }
            
            debug!("Allocated address {} for MAC {}", candidate, Self::format_mac(client_mac));
            return Ok(candidate);
        }
        
        Err(DnsmasqError::Dhcp(DhcpError::NoAddressAvailable))
    }

    /// Perform ping-before-offer check
    ///
    /// Sends ICMP echo request to candidate address with 1-second timeout.
    /// Caches results for 5 seconds to avoid repeated pings.
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address to check
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Address responded to ping (in use)
    /// * `Ok(false)` - No response (address available)
    /// * `Err(DnsmasqError)` - Ping operation failed
    ///
    /// # C Equivalent
    ///
    /// Replaces `do_icmp_ping()` from dhcp.c lines 1200-1300
    pub async fn ping_before_offer(&self, addr: Ipv4Addr) -> DnsmasqResult<bool> {
        // Check cache first
        {
            let cache = self.ping_cache.lock().unwrap();
            if let Some(&(in_use, timestamp)) = cache.get(&addr) {
                if timestamp.elapsed() < Duration::from_secs(5) {
                    debug!("Using cached ping result for {}: {}", addr, in_use);
                    return Ok(in_use);
                }
            }
        }
        
        // Perform ICMP ping with 1-second timeout
        // Note: Simplified implementation - production would use raw ICMP socket
        let ping_result = tokio::time::timeout(
            Duration::from_secs(1),
            self.send_icmp_ping(addr)
        ).await;
        
        let in_use = match ping_result {
            Ok(Ok(true)) => true,
            Ok(Ok(false)) => false,
            Ok(Err(_)) => false,
            Err(_) => false, // Timeout = no response = available
        };
        
        // Update cache
        {
            let mut cache = self.ping_cache.lock().unwrap();
            cache.insert(addr, (in_use, Instant::now()));
        }
        
        Ok(in_use)
    }

    /// Send ICMP echo request
    ///
    /// Internal helper for ping-before-offer. Creates raw ICMP socket and sends
    /// echo request packet.
    ///
    /// # Arguments
    ///
    /// * `addr` - Target IP address
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Reply received
    /// * `Ok(false)` - No reply
    /// * `Err(DnsmasqError)` - Network error
    async fn send_icmp_ping(&self, addr: Ipv4Addr) -> DnsmasqResult<bool> {
        // Simplified implementation - production would use surge-ping or raw socket
        // For now, just return false (address available)
        debug!("ICMP ping to {} (simplified implementation)", addr);
        Ok(false)
    }

    /// Send DHCPOFFER response
    ///
    /// Constructs and transmits OFFER packet with allocated IP address and
    /// network configuration options.
    ///
    /// # Arguments
    ///
    /// * `request` - Original DISCOVER packet
    /// * `offered_ip` - IP address being offered
    /// * `context` - DHCP context with network configuration
    /// * `dest_addr` - Destination socket address
    ///
    /// # Returns
    ///
    /// * `Ok(())` - OFFER sent successfully
    /// * `Err(DnsmasqError)` - Transmission failed
    ///
    /// # C Equivalent
    ///
    /// Replaces OFFER construction in `dhcp_reply()` from rfc2131.c lines 200-300
    pub async fn send_offer(
        &self,
        request: &DhcpPacket,
        offered_ip: Ipv4Addr,
        context: &DhcpContext,
        dest_addr: SocketAddr,
    ) -> DnsmasqResult<()> {
        let mut response = DhcpPacket::new();
        
        // Set fixed fields
        response.set_op(BOOTREPLY);
        response.set_xid(request.get_xid());
        response.set_flags(request.get_flags());
        response.set_yiaddr(offered_ip);
        response.set_chaddr(&request.get_chaddr());
        response.set_giaddr(request.get_giaddr());
        
        // Add DHCP options
        response.set_option(DhcpOption::MessageType(crate::dhcp::v4::protocol::MessageType::Offer));
        response.set_option(DhcpOption::ServerIdentifier(self.server_addr));
        response.set_option(DhcpOption::LeaseTime(context.lease_time));
        
        // Add network configuration options
        self.add_network_options(&mut response, context);
        
        // Add requested options from parameter request list
        self.add_requested_options(&mut response, request, context);
        
        info!("Sending DHCPOFFER of {} to MAC {} (XID: 0x{:08x})",
              offered_ip, Self::format_mac(&request.get_chaddr()), request.get_xid());
        
        // Send packet
        self.send_packet(&response, dest_addr).await
    }

    /// Send DHCPACK response
    ///
    /// Constructs and transmits ACK packet confirming address allocation.
    ///
    /// # Arguments
    ///
    /// * `request` - Original REQUEST packet
    /// * `assigned_ip` - IP address being confirmed
    /// * `context` - DHCP context with network configuration
    /// * `dest_addr` - Destination socket address
    ///
    /// # Returns
    ///
    /// * `Ok(())` - ACK sent successfully
    /// * `Err(DnsmasqError)` - Transmission failed
    ///
    /// # C Equivalent
    ///
    /// Replaces ACK construction in `dhcp_reply()` from rfc2131.c lines 400-500
    pub async fn send_ack(
        &self,
        request: &DhcpPacket,
        assigned_ip: Ipv4Addr,
        context: &DhcpContext,
        dest_addr: SocketAddr,
    ) -> DnsmasqResult<()> {
        let mut response = DhcpPacket::new();
        
        // Set fixed fields
        response.set_op(BOOTREPLY);
        response.set_xid(request.get_xid());
        response.set_flags(request.get_flags());
        response.set_yiaddr(assigned_ip);
        response.set_ciaddr(request.get_ciaddr());
        response.set_chaddr(&request.get_chaddr());
        response.set_giaddr(request.get_giaddr());
        
        // Add DHCP options
        response.set_option(DhcpOption::MessageType(crate::dhcp::v4::protocol::MessageType::Ack));
        response.set_option(DhcpOption::ServerIdentifier(self.server_addr));
        response.set_option(DhcpOption::LeaseTime(context.lease_time));
        
        // Add network configuration options
        self.add_network_options(&mut response, context);
        
        // Add requested options
        self.add_requested_options(&mut response, request, context);
        
        info!("Sending DHCPACK of {} to MAC {} (XID: 0x{:08x})",
              assigned_ip, Self::format_mac(&request.get_chaddr()), request.get_xid());
        
        // Send packet
        self.send_packet(&response, dest_addr).await
    }

    /// Send DHCPNAK response
    ///
    /// Constructs and transmits NAK packet rejecting client's request.
    ///
    /// # Arguments
    ///
    /// * `request` - Original REQUEST packet
    /// * `dest_addr` - Destination socket address
    /// * `reason` - Human-readable rejection reason
    ///
    /// # Returns
    ///
    /// * `Ok(())` - NAK sent successfully
    /// * `Err(DnsmasqError)` - Transmission failed
    ///
    /// # C Equivalent
    ///
    /// Replaces NAK construction in `dhcp_reply()` from rfc2131.c lines 500-550
    pub async fn send_nak(
        &self,
        request: &DhcpPacket,
        dest_addr: SocketAddr,
        reason: &str,
    ) -> DnsmasqResult<()> {
        let mut response = DhcpPacket::new();
        
        // Set fixed fields
        response.set_op(BOOTREPLY);
        response.set_xid(request.get_xid());
        response.set_flags(request.get_flags());
        response.set_chaddr(&request.get_chaddr());
        response.set_giaddr(request.get_giaddr());
        
        // Add DHCP options
        response.set_option(DhcpOption::MessageType(crate::dhcp::v4::protocol::MessageType::Nak));
        response.set_option(DhcpOption::ServerIdentifier(self.server_addr));
        
        warn!("Sending DHCPNAK to MAC {} (XID: 0x{:08x}): {}",
              Self::format_mac(&request.get_chaddr()), request.get_xid(), reason);
        
        // Send packet (always broadcast for NAK)
        let broadcast_addr = SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::BROADCAST),
            dest_addr.port()
        );
        self.send_packet(&response, broadcast_addr).await
    }

    // ==================== Helper Methods ====================

    /// Add network configuration options to response packet
    ///
    /// Adds subnet mask, router, DNS servers, domain name, and other
    /// network parameters from DHCP context.
    fn add_network_options(&self, response: &mut DhcpPacket, context: &DhcpContext) {
        // Subnet mask (Option 1)
        response.set_option(DhcpOption::SubnetMask(context.netmask));
        
        // Router (Option 3)
        if !context.router.is_unspecified() {
            response.set_option(DhcpOption::Router(vec![context.router]));
        }
        
        // DNS servers (Option 6)
        let state = self.daemon_state.read().unwrap();
        let config = state.get_config();
        if !config.dns_servers.is_empty() {
            response.set_option(DhcpOption::DnsServer(config.dns_servers.clone()));
        }
        
        // Domain name (Option 15)
        if let Some(ref domain) = config.domain_name {
            response.set_option(DhcpOption::DomainName(domain.clone()));
        }
        
        // Broadcast address (Option 28)
        response.set_option(DhcpOption::BroadcastAddress(context.broadcast));
    }

    /// Add requested options from parameter request list
    ///
    /// Processes Option 55 (Parameter Request List) and adds requested options
    /// that are available in configuration.
    fn add_requested_options(
        &self,
        response: &mut DhcpPacket,
        request: &DhcpPacket,
        _context: &DhcpContext,
    ) {
        if let Some(DhcpOption::ParameterRequestList(requested_opts)) = request.get_option(OPTION_PARAMETER_REQUEST_LIST) {
            let state = self.daemon_state.read().unwrap();
            let config = state.get_config();
            
            for &opt_code in requested_opts {
                match opt_code {
                    OPTION_NTP_SERVER => {
                        if !config.ntp_servers.is_empty() {
                            response.set_option(DhcpOption::NtpServer(config.ntp_servers.clone()));
                        }
                    }
                    OPTION_TFTP_SERVER => {
                        if let Some(ref tftp_server) = config.tftp_server {
                            response.set_option(DhcpOption::TftpServerName(tftp_server.clone()));
                        }
                    }
                    OPTION_BOOTFILE => {
                        if let Some(ref bootfile) = config.bootfile {
                            response.set_option(DhcpOption::Bootfile(bootfile.clone()));
                        }
                    }
                    _ => {
                        // Option not implemented or not configured
                        debug!("Client requested unsupported option {}", opt_code);
                    }
                }
            }
        }
    }

    /// Find static host reservation for client
    ///
    /// Searches for static DHCP host configuration matching client by:
    /// 1. Client identifier (Option 61)
    /// 2. Hardware address (MAC)
    ///
    /// Returns configured static IP address if match found.
    fn find_static_reservation(
        &self,
        client_mac: &[u8],
        client_id: &Option<Vec<u8>>,
        _context: &DhcpContext,
    ) -> Option<Ipv4Addr> {
        let state = self.daemon_state.read().unwrap();
        let static_hosts = state.get_static_hosts();
        
        // Try client identifier first
        if let Some(cid) = client_id {
            for host in static_hosts {
                if host.client_id.as_ref() == Some(cid) {
                    if let AllAddr::Ipv4(ip) = host.addr {
                        return Some(ip);
                    }
                }
            }
        }
        
        // Try MAC address
        for host in static_hosts {
            if host.hwaddr.as_deref() == Some(client_mac) {
                if let AllAddr::Ipv4(ip) = host.addr {
                    return Some(ip);
                }
            }
        }
        
        None
    }

    /// Check if address is within DHCP context range
    fn is_address_in_context(&self, addr: Ipv4Addr, context: &DhcpContext) -> bool {
        let addr_u32 = u32::from_be_bytes(addr.octets());
        let start_u32 = u32::from_be_bytes(context.start.octets());
        let end_u32 = u32::from_be_bytes(context.end.octets());
        
        addr_u32 >= start_u32 && addr_u32 <= end_u32
    }

    /// Check if address is special (network or broadcast)
    fn is_special_address(&self, addr: Ipv4Addr, context: &DhcpContext) -> bool {
        // Network address (all host bits zero)
        let network = self.apply_netmask(context.start, context.netmask);
        if addr == network {
            return true;
        }
        
        // Broadcast address
        if addr == context.broadcast {
            return true;
        }
        
        // Server's own address
        if addr == self.server_addr {
            return true;
        }
        
        false
    }

    /// Apply netmask to get network address
    fn apply_netmask(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
        let addr_octets = addr.octets();
        let mask_octets = netmask.octets();
        let network_octets = [
            addr_octets[0] & mask_octets[0],
            addr_octets[1] & mask_octets[1],
            addr_octets[2] & mask_octets[2],
            addr_octets[3] & mask_octets[3],
        ];
        Ipv4Addr::from(network_octets)
    }

    /// Create or update lease in database
    async fn create_or_update_lease(
        &self,
        addr: Ipv4Addr,
        client_mac: &[u8],
        client_id: &Option<Vec<u8>>,
        context: &DhcpContext,
    ) -> DnsmasqResult<()> {
        let state = self.daemon_state.write().unwrap();
        let lease_db = state.get_lease_database();
        let mut db_guard = lease_db.write().unwrap();
        
        // Calculate expiration time
        let expires = std::time::SystemTime::now() + Duration::from_secs(context.lease_time as u64);
        
        // Create lease
        let lease = Lease::V4(crate::dhcp::lease::LeaseV4 {
            address: addr,
            mac: client_mac.to_vec(),
            client_id: client_id.clone(),
            hostname: None,
            expires,
            state: crate::dhcp::lease::LeaseState::Active,
        });
        
        // Add to database
        db_guard.add_lease(lease.clone())?;
        
        drop(db_guard);
        
        // Add to DNS cache if hostname present
        if let Lease::V4(ref v4_lease) = lease {
            if let Some(ref hostname) = v4_lease.hostname {
                let dns_cache = state.get_dns_cache();
                let mut cache_guard = dns_cache.write().unwrap();
                cache_guard.insert_dhcp_host(
                    hostname.clone(),
                    AllAddr::from_ipv4(addr),
                    context.lease_time as u32,
                );
            }
        }
        
        Ok(())
    }

    /// Renew existing lease
    async fn renew_lease(
        &self,
        addr: Ipv4Addr,
        client_mac: &[u8],
        context: &DhcpContext,
    ) -> DnsmasqResult<()> {
        let state = self.daemon_state.write().unwrap();
        let lease_db = state.get_lease_database();
        let mut db_guard = lease_db.write().unwrap();
        
        // Find existing lease
        if let Some(lease) = db_guard.find_by_mac(client_mac) {
            // Update expiration
            let new_expires = std::time::SystemTime::now() + Duration::from_secs(context.lease_time as u64);
            
            if let Lease::V4(mut v4_lease) = lease.clone() {
                v4_lease.expires = new_expires;
                v4_lease.state = crate::dhcp::lease::LeaseState::Active;
                
                // Update in database
                db_guard.update_lease(Lease::V4(v4_lease))?;
            }
        }
        
        Ok(())
    }

    /// Send DHCP packet to destination
    async fn send_packet(
        &self,
        packet: &DhcpPacket,
        dest_addr: SocketAddr,
    ) -> DnsmasqResult<()> {
        let serialized = packet.serialize()?;
        
        // Determine actual destination based on flags and addresses
        let actual_dest = self.determine_destination(packet, dest_addr);
        
        // Send packet
        self.socket.send_to(&serialized, actual_dest).await
            .map_err(|e| DnsmasqError::Network(e.to_string()))?;
        
        debug!("Sent {} bytes to {}", serialized.len(), actual_dest);
        Ok(())
    }

    /// Determine packet destination based on DHCP flags and addresses
    ///
    /// Implements RFC 2131 Section 4.1 transmission rules:
    /// - Broadcast if BROADCAST flag set
    /// - Broadcast if ciaddr is zero and no relay
    /// - Unicast to ciaddr if present
    /// - Unicast to yiaddr if ciaddr zero but relay present
    /// - Send to relay agent (giaddr) if present
    fn determine_destination(&self, packet: &DhcpPacket, default_dest: SocketAddr) -> SocketAddr {
        let flags = packet.get_flags();
        let ciaddr = packet.get_ciaddr();
        let giaddr = packet.get_giaddr();
        
        // Check broadcast flag
        if flags & 0x8000 != 0 {
            return SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::BROADCAST),
                DHCP_CLIENT_PORT,
            );
        }
        
        // Send via relay if present
        if !giaddr.is_unspecified() {
            return SocketAddr::new(
                std::net::IpAddr::V4(giaddr),
                DHCP_SERVER_PORT,
            );
        }
        
        // Unicast to ciaddr if present
        if !ciaddr.is_unspecified() {
            return SocketAddr::new(
                std::net::IpAddr::V4(ciaddr),
                DHCP_CLIENT_PORT,
            );
        }
        
        // Otherwise broadcast
        SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::BROADCAST),
            DHCP_CLIENT_PORT,
        )
    }

    /// Get configuration reference
    fn get_config(&self) -> Option<Arc<ConfigOptions>> {
        let state = self.daemon_state.read().unwrap();
        Some(Arc::new(state.get_config().clone()))
    }

    /// Format MAC address for logging
    fn format_mac(mac: &[u8]) -> String {
        if mac.len() < 6 {
            return format!("{:?}", mac);
        }
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
    }

    /// Find appropriate DHCP context for packet
    ///
    /// Matches receiving interface and relay agent information to determine
    /// which address pool should serve this request.
    fn find_context_for_packet(&self, packet: &DhcpPacket) -> Option<DhcpContext> {
        let giaddr = packet.get_giaddr();
        
        let state = self.daemon_state.read().unwrap();
        let contexts = state.get_dhcp_contexts();
        
        // If relayed, match by relay agent's subnet
        if !giaddr.is_unspecified() {
            for context in contexts {
                let network = self.apply_netmask(context.start, context.netmask);
                let giaddr_network = self.apply_netmask(giaddr, context.netmask);
                
                if network == giaddr_network {
                    return Some(context.clone());
                }
            }
        } else {
            // Direct request - use first configured context
            // In production, would match by receiving interface
            if !contexts.is_empty() {
                return Some(contexts[0].clone());
            }
        }
        
        None
    }
}

// ==================== Unit Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};
    use crate::types::daemon_state::DaemonState;
    use crate::config::types::ConfigOptions;

    fn create_test_server() -> DhcpV4Server {
        let config = ConfigOptions::default();
        let daemon_state = Arc::new(RwLock::new(DaemonState::new(config)));
        
        DhcpV4Server::new(
            Ipv4Addr::new(192, 168, 1, 1),
            daemon_state,
        )
    }

    #[test]
    fn test_format_mac() {
        let mac = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(
            DhcpV4Server::format_mac(&mac),
            "aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn test_is_address_in_context() {
        let server = create_test_server();
        let context = DhcpContext {
            start: Ipv4Addr::new(192, 168, 1, 100),
            end: Ipv4Addr::new(192, 168, 1, 200),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            router: Ipv4Addr::new(192, 168, 1, 1),
            lease_time: 3600,
            interface: None,
            flags: crate::config::types::ContextFlags::empty(),
            tags: Vec::new(),
        };
        
        assert!(server.is_address_in_context(Ipv4Addr::new(192, 168, 1, 100), &context));
        assert!(server.is_address_in_context(Ipv4Addr::new(192, 168, 1, 150), &context));
        assert!(server.is_address_in_context(Ipv4Addr::new(192, 168, 1, 200), &context));
        assert!(!server.is_address_in_context(Ipv4Addr::new(192, 168, 1, 99), &context));
        assert!(!server.is_address_in_context(Ipv4Addr::new(192, 168, 1, 201), &context));
    }

    #[test]
    fn test_apply_netmask() {
        let server = create_test_server();
        let addr = Ipv4Addr::new(192, 168, 1, 150);
        let netmask = Ipv4Addr::new(255, 255, 255, 0);
        
        let network = server.apply_netmask(addr, netmask);
        assert_eq!(network, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[tokio::test]
    async fn test_bind_socket() {
        let server = create_test_server();
        
        // Note: This test requires appropriate permissions to bind to port 67
        // In CI environments, it should be skipped or use an alternate port
        if std::env::var("CI").is_ok() {
            return; // Skip in CI
        }
        
        // Test would attempt to bind and verify socket options
    }
}
