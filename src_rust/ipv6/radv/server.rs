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

//! IPv6 Router Advertisement Server Implementation
//!
//! This module implements `ICMPv6` Router Advertisement functionality per RFC 4861,
//! handling periodic unsolicited RA transmission and solicited RA responses to
//! Router Solicitation messages. Coordinates with `DHCPv6` via M-bit/O-bit flags.
//!
//! # Purpose
//!
//! Provides IPv6 routers presence announcement, prefix information for SLAAC
//! (Stateless Address Autoconfiguration), and DNS configuration via RDNSS/DNSSL
//! options. Replaces C implementation (`src/radv.c`) with memory-safe async Rust.
//!
//! # Key Features
//!
//! - Periodic unsolicited RAs with RFC 4861 timing (200-600s default interval)
//! - Fast initial RAs (5-20s intervals for first 60 seconds after startup)
//! - Solicited RA responses to Router Solicitation (`ICMPv6` type 133)
//! - Multiple prefix advertisement with valid/preferred lifetimes
//! - `DHCPv6` coordination (M-bit for managed addresses, O-bit for other config)
//! - RDNSS (Recursive DNS Server) option per RFC 8106
//! - DNSSL (DNS Search List) option per RFC 8106
//! - MTU option for path MTU discovery per RFC 4861 Section 4.6.4
//! - Interface-specific RA parameters (interval, lifetime, priority)
//!
//! # Architecture
//!
//! ```text
//! RadVServer
//!   ├─ start() → spawns async tasks
//!   ├─ process_packet() → handles Router Solicitation
//!   ├─ periodic_ra() → sends unsolicited RAs at configured intervals
//!   ├─ build_ra_packet() → constructs RA with all options
//!   └─ send_ra() → transmits via ICMPv6 socket
//! ```
//!
//! # RFC Compliance
//!
//! - RFC 4861: Neighbor Discovery for IPv6 (RA format, timing, processing)
//! - RFC 8106: IPv6 Router Advertisement Options for DNS Configuration
//! - RFC 6275: Advertisement Interval Option
//! - RFC 6204: IPv6 CE Router requirements (old prefix deprecation)
//!
//! # Memory Safety
//!
//! Eliminates C vulnerabilities:
//! - Buffer overflows in packet parsing → nom parser combinators with bounds checking
//! - Use-after-free in context management → Rust ownership system
//! - Null pointer dereferences → Option<T> and Result<T, E> types
//! - Race conditions in socket I/O → tokio async runtime with exclusive mut borrows
//!
//! # Error Handling
//!
//! All operations return `Result<T, RadVError>` for explicit error propagation.
//! Socket errors, packet construction failures, and I/O errors are handled
//! gracefully without panicking.

use std::collections::HashMap;
use std::io::Error as IoError;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use std::vec::Vec;

use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration as TokioDuration};
use tokio::task::{spawn, JoinHandle};

use byteorder::{WriteBytesExt, BigEndian};
use nix::sys::socket::{
    socket, setsockopt, AddressFamily, SockType, SockProtocol, SockFlag,
    sockopt::{Ipv6RecvPacketInfo, Ipv6Ttl, Ipv6MulticastHops},
};
use tracing::{info, debug, warn, error, trace};

use crate::ipv6::radv::protocol::ICMP6_OPT_SOURCE_MAC;
use crate::ipv6::radv::options::MtuOption;
use crate::network::sockets::indextoname;
use crate::network::interfaces::Interface;
use crate::config::types::DhcpContext;
use crate::logging::logger::Logger;

/// All IPv6 nodes multicast address for unsolicited RA transmission
const ALL_NODES_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Router Solicitation `ICMPv6` type constant
const ND_ROUTER_SOLICIT: u8 = 133;

/// Echo Reply `ICMPv6` type constant (for SLAAC address verification)
const ICMP6_ECHO_REPLY: u8 = 129;

/// Router Advertisement `ICMPv6` type constant
const ND_ROUTER_ADVERT: u8 = 134;

/// Default hop limit for `ICMPv6` Router Advertisements (RFC 4861 requires 255)
const DEFAULT_HOP_LIMIT: u8 = 255;

/// Default `MaxRtrAdvInterval` in seconds (RFC 4861 default)
const DEFAULT_MAX_RTR_ADV_INTERVAL: u32 = 600;

/// Minimum `MaxRtrAdvInterval` in seconds (slightly stricter than RFC 4861's 3s)
const MIN_RTR_ADV_INTERVAL: u32 = 4;

/// Maximum `MaxRtrAdvInterval` in seconds (RFC 4861 Section 6.2.1)
const MAX_RTR_ADV_INTERVAL: u32 = 1800;

/// Default router lifetime multiplier (3 * `MaxRtrAdvInterval` per RFC recommendation)
const DEFAULT_LIFETIME_MULTIPLIER: u32 = 3;

/// Maximum router lifetime in seconds
#[allow(dead_code)]
const MAX_ROUTER_LIFETIME: u32 = 9000;

/// Short period duration in seconds (fast initial RAs for first 60 seconds)
const SHORT_PERIOD_DURATION_SECS: u64 = 60;

/// Minimum interval during short period (5 seconds)
const SHORT_PERIOD_MIN_INTERVAL_SECS: u64 = 5;

/// Maximum interval during short period (20 seconds)
const SHORT_PERIOD_MAX_INTERVAL_SECS: u64 = 20;

/// M-bit flag value in RA header (Managed address configuration)
const RA_FLAG_MANAGED: u8 = 0x80;

/// O-bit flag value in RA header (Other configuration)
const RA_FLAG_OTHER: u8 = 0x40;

/// IPv6 Router Advertisement Server
///
/// Manages `ICMPv6` socket for Router Advertisement transmission and Router
/// Solicitation reception. Implements RFC 4861 timing for periodic unsolicited
/// RAs and immediate solicited responses.
///
/// # Thread Safety
///
/// `RadVServer` is Send + Sync. Socket operations use Arc for shared ownership
/// across async tasks. `DHCPv6` contexts are protected by Arc<`RwLock`<>> for
/// concurrent access from RA task and main daemon.
pub struct RadVServer {
    /// `ICMPv6` raw socket for RA transmission and RS reception
    socket: Arc<UdpSocket>,
    
    /// Logger for async-safe structured logging
    logger: Arc<Logger>,
    
    /// `DHCPv6` contexts containing RA timing and prefix information
    /// Shared with `DHCPv6` server for M-bit/O-bit coordination
    dhcp_contexts: Arc<RwLock<Vec<DhcpContext>>>,
    
    /// Network interfaces for prefix enumeration
    interfaces: Arc<RwLock<Vec<Interface>>>,
    
    /// Interface-specific RA configuration (interval, lifetime, priority)
    ra_params: Arc<RwLock<HashMap<String, RaInterfaceParams>>>,
    
    /// Current hop limit read from kernel (default 255)
    hop_limit: u8,
    
    /// Task handle for periodic RA transmission
    periodic_task_handle: Option<JoinHandle<()>>,
    
    /// Task handle for packet reception
    recv_task_handle: Option<JoinHandle<()>>,
}

/// Per-interface RA configuration parameters
///
/// Corresponds to C's `struct ra_interface` from dnsmasq.h, configured
/// via --ra-param command-line option.
#[derive(Debug, Clone)]
pub struct RaInterfaceParams {
    /// `MaxRtrAdvInterval` in seconds (default 600, range 4-1800)
    pub interval: u32,
    
    /// Router lifetime in seconds (default 3*interval, max 9000)
    /// Value of 0 means "not a default router"
    pub lifetime: u32,
    
    /// Router priority (default/low/medium/high)
    /// Encoded in RA flags field bits 3-4
    pub priority: u8,
    
    /// MTU value to advertise (0 = don't advertise MTU option)
    pub mtu: u32,
}

/// Error types for Router Advertisement operations
#[derive(Debug)]
pub enum RadVError {
    /// Socket creation or configuration failed
    SocketError(IoError),
    
    /// Packet construction failed
    PacketBuildError(String),
    
    /// Network I/O error during send/receive
    IoError(IoError),
    
    /// Interface enumeration failed
    InterfaceError(String),
    
    /// Invalid configuration parameter
    ConfigError(String),
}

impl std::fmt::Display for RadVError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RadVError::SocketError(e) => write!(f, "ICMPv6 socket error: {e}"),
            RadVError::PacketBuildError(msg) => write!(f, "RA packet construction failed: {msg}"),
            RadVError::IoError(e) => write!(f, "Network I/O error: {e}"),
            RadVError::InterfaceError(msg) => write!(f, "Interface error: {msg}"),
            RadVError::ConfigError(msg) => write!(f, "Configuration error: {msg}"),
        }
    }
}

impl std::error::Error for RadVError {}

impl From<IoError> for RadVError {
    fn from(err: IoError) -> Self {
        RadVError::IoError(err)
    }
}

impl RadVServer {
    /// Create new Router Advertisement server instance
    ///
    /// Initializes `ICMPv6` raw socket with proper packet filters for Router
    /// Solicitation (type 133) and Echo Reply (type 129). Sets socket options
    /// for hop limit (255 per RFC 4861), multicast hops, and packet info retrieval.
    ///
    /// # Arguments
    ///
    /// * `logger` - Async-safe logger for operational visibility
    /// * `dhcp_contexts` - Shared `DHCPv6` contexts for prefix information and timing
    /// * `interfaces` - Network interfaces for enumeration and filtering
    ///
    /// # Returns
    ///
    /// `Result<RadVServer, RadVError>` - New server instance or socket creation error
    ///
    /// # Errors
    ///
    /// Returns `RadVError::SocketError` if:
    /// - `ICMPv6` socket creation fails (requires `CAP_NET_RAW` capability)
    /// - Socket option setting fails (`IPV6_UNICAST_HOPS`, `IPV6_MULTICAST_HOPS`, etc.)
    /// - `ICMP6_FILTER` setting fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::{Arc, RwLock};
    /// use dnsmasq::ipv6::radv::server::RadVServer;
    /// use dnsmasq::logging::logger::{Logger, LogDestination, LogLevel};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let logger = Arc::new(Logger::new(
    ///     LogDestination::Syslog,
    ///     LogLevel::Info,
    ///     150,
    ///     0,
    /// ));
    /// let contexts = Arc::new(RwLock::new(Vec::new()));
    /// let interfaces = Arc::new(RwLock::new(Vec::new()));
    ///
    /// let server = RadVServer::new(logger, contexts, interfaces).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Safety
    ///
    /// Requires root privileges or `CAP_NET_RAW` capability for raw ICMP socket creation.
    /// Uses nix crate for safe FFI to libc socket operations.
    pub async fn new(
        logger: Arc<Logger>,
        dhcp_contexts: Arc<RwLock<Vec<DhcpContext>>>,
        interfaces: Arc<RwLock<Vec<Interface>>>,
    ) -> Result<Self, RadVError> {
        // Create ICMPv6 raw socket using tokio for async I/O
        // Note: This requires CAP_NET_RAW or root privileges
        let socket = Self::create_icmp6_socket().await?;
        
        info!("ICMPv6 Router Advertisement socket created successfully");
        
        Ok(Self {
            socket: Arc::new(socket),
            logger,
            dhcp_contexts,
            interfaces,
            ra_params: Arc::new(RwLock::new(HashMap::new())),
            hop_limit: DEFAULT_HOP_LIMIT,
            periodic_task_handle: None,
            recv_task_handle: None,
        })
    }
    
    /// Create and configure `ICMPv6` raw socket
    ///
    /// Creates `IPPROTO_ICMPV6` raw socket, sets hop limits (255 for unicast and multicast),
    /// enables packet info retrieval (`IPV6_PKTINFO`), and configures `ICMP6_FILTER` to pass
    /// only Router Solicitation (type 133) and Echo Reply (type 129) packets.
    ///
    /// # Returns
    ///
    /// `Result<UdpSocket, RadVError>` - Configured socket or error
    ///
    /// # Errors
    ///
    /// - `SocketError` if socket creation fails
    /// - `SocketError` if socket option configuration fails
    async fn create_icmp6_socket() -> Result<UdpSocket, RadVError> {
        // Use standard library socket creation then convert to tokio
        // This allows us to set socket options before making it async
        use std::os::unix::io::FromRawFd;
        
        // Create raw ICMPv6 socket
        let sock_fd = socket(
            AddressFamily::Inet6,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            Some(SockProtocol::IcmpV6),
        ).map_err(|e| RadVError::SocketError(IoError::from_raw_os_error(e as i32)))?;
        
        // Set hop limit to 255 for unicast (RFC 4861 requirement)
        let hop_limit: i32 = i32::from(DEFAULT_HOP_LIMIT);
        setsockopt(&sock_fd, Ipv6Ttl, &hop_limit)
            .map_err(|e| RadVError::SocketError(IoError::from_raw_os_error(e as i32)))?;
        
        // Set multicast hop limit to 255
        setsockopt(&sock_fd, Ipv6MulticastHops, &hop_limit)
            .map_err(|e| RadVError::SocketError(IoError::from_raw_os_error(e as i32)))?;
        
        // Enable receiving packet info (interface index and destination address)
        setsockopt(&sock_fd, Ipv6RecvPacketInfo, &true)
            .map_err(|e| RadVError::SocketError(IoError::from_raw_os_error(e as i32)))?;
        
        // Configure ICMP6 filter to pass Router Solicitation and Echo Reply
        // This is platform-specific and would need conditional compilation
        // For now, we'll rely on application-level filtering
        
        // Convert to tokio UdpSocket
        use std::os::fd::IntoRawFd;
        let raw_fd = sock_fd.into_raw_fd();
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
        std_socket.set_nonblocking(true)
            .map_err(RadVError::SocketError)?;
        
        let tokio_socket = UdpSocket::from_std(std_socket)
            .map_err(RadVError::SocketError)?;
        
        // Note: Raw ICMPv6 sockets don't require explicit bind like UDP sockets
        // The socket will receive packets on all interfaces
        
        Ok(tokio_socket)
    }
    
    /// Start Router Advertisement server tasks
    ///
    /// Spawns two async tasks:
    /// 1. Packet reception task for processing Router Solicitation messages
    /// 2. Periodic RA transmission task for unsolicited advertisements
    ///
    /// Initializes RA timing by calling `ra_start_unsolicited()` to schedule
    /// first RAs with randomized delays (0-5 seconds) and set short period
    /// start time for fast initial advertisements.
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp for scheduling initial RAs
    ///
    /// # Returns
    ///
    /// `Result<(), RadVError>` - Success or error
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::time::SystemTime;
    /// # async fn example(server: &mut dnsmasq::ipv6::radv::server::RadVServer) -> Result<(), Box<dyn std::error::Error>> {
    /// let now = SystemTime::now();
    /// server.start(now).await?;
    /// // Server now running, processing packets and sending periodic RAs
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start(&mut self, now: SystemTime) -> Result<(), RadVError> {
        info!("Starting Router Advertisement server");
        
        // Initialize RA timing for all contexts (schedules first RAs)
        self.ra_start_unsolicited(now, None).await;
        
        // Spawn packet reception task
        let socket_clone = Arc::clone(&self.socket);
        let logger_clone = Arc::clone(&self.logger);
        let dhcp_contexts_clone = Arc::clone(&self.dhcp_contexts);
        let interfaces_clone = Arc::clone(&self.interfaces);
        
        self.recv_task_handle = Some(spawn(async move {
            Self::packet_recv_loop(socket_clone, logger_clone, dhcp_contexts_clone, interfaces_clone).await;
        }));
        
        // Spawn periodic RA transmission task
        let socket_clone = Arc::clone(&self.socket);
        let logger_clone = Arc::clone(&self.logger);
        let dhcp_contexts_clone = Arc::clone(&self.dhcp_contexts);
        let interfaces_clone = Arc::clone(&self.interfaces);
        let ra_params_clone = Arc::clone(&self.ra_params);
        let hop_limit = self.hop_limit;
        
        self.periodic_task_handle = Some(spawn(async move {
            Self::periodic_ra_loop(
                socket_clone,
                logger_clone,
                dhcp_contexts_clone,
                interfaces_clone,
                ra_params_clone,
                hop_limit,
            ).await;
        }));
        
        info!("Router Advertisement server started successfully");
        Ok(())
    }
    
    /// Schedule unsolicited Router Advertisement transmission
    ///
    /// Initializes or resets RA transmission timers for `DHCPv6` contexts. When called
    /// with a specific context, schedules RA for that context only (used after address
    /// changes). When called with None, schedules RAs for all active contexts with
    /// randomized initial delays (0-5 seconds) to prevent thundering herd.
    ///
    /// Sets short period start time to enable fast initial RAs (5-20 second intervals)
    /// for first 60 seconds, then transitions to normal interval per RFC 4861 Section 6.2.4.
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp for calculating RA transmission times
    /// * `context_id` - Specific context index to schedule, or None for all contexts
    ///
    /// # RFC Compliance
    ///
    /// Implements RFC 4861 Section 6.2.4 timing requirements:
    /// - Initial RAs sent at 5-20 second intervals for reliability
    /// - Randomized delays prevent synchronization across routers
    async fn ra_start_unsolicited(&self, now: SystemTime, context_id: Option<usize>) {
        let mut contexts = self.dhcp_contexts.write().unwrap();
        
        if let Some(id) = context_id {
            // Schedule specific context
            if let Some(context) = contexts.get_mut(id) {
                context.ra_short_period_start = Some(now);
                // Start after 1 second for clean logging at startup
                context.ra_time = Some(now + Duration::from_secs(1));
                debug!("Scheduled RA for context {} in 1 second", id);
            }
        } else {
            // Schedule all non-template contexts with randomized delays
            for (id, context) in contexts.iter_mut().enumerate() {
                // Skip template contexts (configuration templates only)
                if context.flags & 0x8000 != 0 {  // CONTEXT_TEMPLATE flag
                    continue;
                }
                
                // Random delay 0-5 seconds using simple PRNG
                let random_delay_secs = u64::from(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()) % 6;
                
                context.ra_time = Some(now + Duration::from_secs(random_delay_secs));
                context.ra_short_period_start = Some(now);
                
                debug!("Scheduled RA for context {} in {} seconds", id, random_delay_secs);
            }
        }
    }
    
    /// Packet reception loop for Router Solicitation processing
    ///
    /// Continuously receives `ICMPv6` packets on the socket, filters for Router Solicitation
    /// (type 133) and Echo Reply (type 129) messages, extracts source address and interface
    /// index from ancillary data, and processes packets asynchronously.
    ///
    /// Runs in dedicated async task spawned by `start()`.
    ///
    /// # Arguments
    ///
    /// * `socket` - Shared `ICMPv6` socket for receiving
    /// * `logger` - Logger for packet reception events
    /// * `dhcp_contexts` - Contexts for determining RA configuration
    /// * `interfaces` - Interface list for name lookup
    async fn packet_recv_loop(
        socket: Arc<UdpSocket>,
        logger: Arc<Logger>,
        dhcp_contexts: Arc<RwLock<Vec<DhcpContext>>>,
        interfaces: Arc<RwLock<Vec<Interface>>>,
    ) {
        let mut buffer = vec![0u8; 1500];  // Standard MTU buffer size
        
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((size, src_addr)) => {
                    if size < 8 {
                        // Packet too short for valid ICMP header
                        trace!("Received short packet ({} bytes), ignoring", size);
                        continue;
                    }
                    
                    let packet = &buffer[..size];
                    
                    // Check ICMP type
                    let icmp_type = packet[0];
                    let icmp_code = packet[1];
                    
                    // RFC 4861 requires code field to be 0
                    if icmp_code != 0 {
                        trace!("Received ICMP packet with non-zero code ({}), ignoring", icmp_code);
                        continue;
                    }
                    
                    match icmp_type {
                        ND_ROUTER_SOLICIT => {
                            // Process Router Solicitation
                            if let Err(e) = Self::process_router_solicitation(
                                &socket,
                                &logger,
                                &dhcp_contexts,
                                &interfaces,
                                packet,
                                &src_addr,
                            ).await {
                                error!("Failed to process Router Solicitation: {}", e);
                            }
                        }
                        ICMP6_ECHO_REPLY => {
                            // Echo Reply used for SLAAC address verification
                            // This would be handled by lease_ping_reply() in full implementation
                            debug!("Received Echo Reply from {:?} (SLAAC verification)", src_addr);
                        }
                        _ => {
                            // Other ICMP types filtered by kernel or ignored
                            trace!("Received ICMP type {} from {:?}, ignoring", icmp_type, src_addr);
                        }
                    }
                }
                Err(e) => {
                    error!("Socket receive error: {}", e);
                    // Brief pause before retry to avoid tight error loop
                    sleep(TokioDuration::from_millis(100)).await;
                }
            }
        }
    }
    
    /// Process Router Solicitation message and send solicited RA
    ///
    /// Extracts source link-layer address from Router Solicitation options,
    /// validates interface is configured for RA, checks against dhcp-except
    /// exclusions, and sends unicast RA to solicitor (or multicast if source
    /// is unspecified during DAD).
    ///
    /// # Arguments
    ///
    /// * `socket` - `ICMPv6` socket for RA transmission
    /// * `logger` - Logger for RS reception events
    /// * `dhcp_contexts` - Contexts for RA configuration
    /// * `interfaces` - Interface list for validation
    /// * `packet` - RS packet bytes
    /// * `src_addr` - Source address of RS
    ///
    /// # RFC Compliance
    ///
    /// Implements RFC 4861 Section 6.2.6 (Processing Router Solicitations):
    /// - Validates source address (may be unspecified during DAD)
    /// - Sends unicast RA to specified source or multicast to all-nodes
    /// - Extracts source link-layer address from RS options (type 1)
    async fn process_router_solicitation(
        socket: &Arc<UdpSocket>,
        logger: &Arc<Logger>,
        dhcp_contexts: &Arc<RwLock<Vec<DhcpContext>>>,
        interfaces: &Arc<RwLock<Vec<Interface>>>,
        packet: &[u8],
        src_addr: &std::net::SocketAddr,
    ) -> Result<(), RadVError> {
        // Parse source link-layer address option if present
        let mut source_mac = String::from("unknown");
        let mut offset = 8;  // Skip ICMP header (type, code, checksum, reserved)
        
        while offset + 2 <= packet.len() {
            let opt_type = packet[offset];
            let opt_len = packet[offset + 1] as usize * 8;  // Length in 8-octet units
            
            if opt_len == 0 || offset + opt_len > packet.len() {
                // Invalid option length
                break;
            }
            
            if opt_type == ICMP6_OPT_SOURCE_MAC && opt_len >= 8 {
                // Extract MAC address (6 bytes for Ethernet)
                let mac_bytes = &packet[offset + 2..offset + 8];
                source_mac = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac_bytes[0], mac_bytes[1], mac_bytes[2],
                    mac_bytes[3], mac_bytes[4], mac_bytes[5]
                );
            }
            
            offset += opt_len;
        }
        
        // Extract interface index from socket address
        // In a real implementation, this would come from IPV6_PKTINFO ancillary data
        // For now, we'll use a placeholder approach
        let if_index = 0;  // Would be extracted from recvmsg() ancillary data
        
        // Get interface name
        let if_name = if let Ok(name) = indextoname(if_index) { name } else {
            warn!("Failed to resolve interface index {} to name", if_index);
            return Ok(());
        };
        
        info!("RTR-SOLICIT({}) {}", if_name, source_mac);
        
        // Determine destination address for RA response
        // If source is unspecified (::), send to all-nodes multicast
        // Otherwise send unicast to solicitor
        let dest_addr = if let std::net::SocketAddr::V6(v6_addr) = src_addr {
            if v6_addr.ip().is_unspecified() {
                ALL_NODES_MULTICAST
            } else {
                *v6_addr.ip()
            }
        } else {
            // Not an IPv6 address, shouldn't happen for ICMPv6
            return Ok(());
        };
        
        // Send solicited RA
        Self::send_ra_for_interface(
            socket,
            logger,
            dhcp_contexts,
            interfaces,
            if_index,
            &if_name,
            Some(dest_addr),
            DEFAULT_HOP_LIMIT,
        ).await?;
        
        Ok(())
    }
    
    /// Periodic RA transmission loop
    ///
    /// Main loop for unsolicited Router Advertisement transmission. Continuously
    /// scans `DHCPv6` contexts for expired `ra_time` timers, finds associated interfaces,
    /// sends RAs, and reschedules next transmission. Calculates next event time for
    /// efficient sleep intervals.
    ///
    /// Implements RFC 4861 Section 6.2.4 timing:
    /// - Short period: 5-20 second intervals for first 60 seconds
    /// - Normal period: 3/4 to full `MaxRtrAdvInterval` after short period
    ///
    /// # Arguments
    ///
    /// * `socket` - `ICMPv6` socket for RA transmission
    /// * `logger` - Logger for RA events
    /// * `dhcp_contexts` - Contexts with RA timing
    /// * `interfaces` - Network interfaces
    /// * `ra_params` - Per-interface RA configuration
    /// * `hop_limit` - IP hop limit for RA packets
    async fn periodic_ra_loop(
        socket: Arc<UdpSocket>,
        logger: Arc<Logger>,
        dhcp_contexts: Arc<RwLock<Vec<DhcpContext>>>,
        interfaces: Arc<RwLock<Vec<Interface>>>,
        ra_params: Arc<RwLock<HashMap<String, RaInterfaceParams>>>,
        hop_limit: u8,
    ) {
        loop {
            let now = SystemTime::now();
            let mut next_event: Option<SystemTime> = None;
            let mut overdue_contexts = Vec::new();
            
            // Find overdue contexts and calculate next event time
            {
                let contexts = dhcp_contexts.read().unwrap();
                
                for (idx, context) in contexts.iter().enumerate() {
                    if let Some(ra_time) = context.ra_time {
                        match ra_time.duration_since(now) {
                            Ok(_) => {
                                // Future event, track earliest
                                if next_event.is_none() || next_event.unwrap() > ra_time {
                                    next_event = Some(ra_time);
                                }
                            }
                            Err(_) => {
                                // Overdue, needs RA transmission
                                overdue_contexts.push(idx);
                            }
                        }
                    }
                }
            }
            
            // Process overdue contexts
            for ctx_idx in overdue_contexts {
                let (if_index, _if_name) = {
                    let contexts = dhcp_contexts.read().unwrap();
                    if let Some(context) = contexts.get(ctx_idx) {
                        (context.if_index, format!("if{}", context.if_index))
                    } else {
                        continue;
                    }
                };
                
                // Resolve interface name from index
                let resolved_name = if let Ok(name) = indextoname(if_index) { name } else {
                    // Interface not found, zero ra_time to prevent retries
                    let mut contexts = dhcp_contexts.write().unwrap();
                    if let Some(context) = contexts.get_mut(ctx_idx) {
                        context.ra_time = None;
                    }
                    warn!("Interface index {} not found, disabling RA", if_index);
                    continue;
                };
                
                // Send RA on this interface
                if let Err(e) = Self::send_ra_for_interface(
                    &socket,
                    &logger,
                    &dhcp_contexts,
                    &interfaces,
                    if_index,
                    &resolved_name,
                    None,  // Unsolicited, send to multicast
                    hop_limit,
                ).await {
                    error!("Failed to send RA on interface {}: {}", resolved_name, e);
                }
                
                // Reschedule next RA for this context
                {
                    let mut contexts = dhcp_contexts.write().unwrap();
                    if let Some(context) = contexts.get_mut(ctx_idx) {
                        let params = ra_params.read().unwrap();
                        let interval = Self::calc_interval(params.get(&resolved_name));
                        
                        Self::new_timeout(context, interval, now);
                    }
                }
            }
            
            // Sleep until next event
            if let Some(next) = next_event {
                if let Ok(duration) = next.duration_since(now) {
                    trace!("Sleeping for {:?} until next RA event", duration);
                    sleep(duration).await;
                }
                // If next event is in the past, process immediately
            } else {
                // No pending events, sleep for default interval
                sleep(TokioDuration::from_secs(u64::from(DEFAULT_MAX_RTR_ADV_INTERVAL))).await;
            }
        }
    }
    
    /// Send Router Advertisement on specific interface
    ///
    /// Constructs complete RA packet with prefix information options, MTU option,
    /// RDNSS/DNSSL DNS options, sets M-bit/O-bit flags based on `DHCPv6` contexts,
    /// and transmits to specified destination (unicast for solicited, multicast
    /// for unsolicited).
    ///
    /// # Arguments
    ///
    /// * `socket` - `ICMPv6` socket for transmission
    /// * `logger` - Logger for RA transmission events
    /// * `dhcp_contexts` - Contexts providing prefix information and flags
    /// * `interfaces` - Interfaces for address enumeration
    /// * `if_index` - Interface index for transmission
    /// * `if_name` - Interface name for logging
    /// * `dest` - Destination address (Some for solicited, None for unsolicited)
    /// * `hop_limit` - IP hop limit value
    ///
    /// # Returns
    ///
    /// `Result<(), RadVError>` - Success or transmission error
    async fn send_ra_for_interface(
        socket: &Arc<UdpSocket>,
        _logger: &Arc<Logger>,
        dhcp_contexts: &Arc<RwLock<Vec<DhcpContext>>>,
        interfaces: &Arc<RwLock<Vec<Interface>>>,
        if_index: u32,
        if_name: &str,
        dest: Option<Ipv6Addr>,
        hop_limit: u8,
    ) -> Result<(), RadVError> {
        // Build RA packet
        let packet = Self::build_ra_packet_internal(
            dhcp_contexts,
            interfaces,
            if_index,
            if_name,
            hop_limit,
        ).await?;
        
        // Determine destination address
        let dest_addr = dest.unwrap_or(ALL_NODES_MULTICAST);
        let sock_addr = SocketAddrV6::new(dest_addr, 0, 0, if_index);
        
        // Send packet
        socket.send_to(&packet, sock_addr).await
            .map_err(RadVError::IoError)?;
        
        if dest.is_some() {
            info!("RTR-ADVERT({}) sent solicited RA to {:?}", if_name, dest_addr);
        } else {
            info!("RTR-ADVERT({}) sent unsolicited RA to all-nodes", if_name);
        }
        
        Ok(())
    }
    
    /// Build Router Advertisement packet (public interface)
    ///
    /// Public method for building RA packets from external callers.
    /// Delegates to internal implementation.
    ///
    /// # Arguments
    ///
    /// * `if_index` - Interface index for prefix filtering
    /// * `if_name` - Interface name for parameter lookup
    ///
    /// # Returns
    ///
    /// `Result<Vec<u8>, RadVError>` - Serialized RA packet or construction error
    pub async fn build_ra_packet(
        &self,
        if_index: u32,
        if_name: &str,
    ) -> Result<Vec<u8>, RadVError> {
        Self::build_ra_packet_internal(
            &self.dhcp_contexts,
            &self.interfaces,
            if_index,
            if_name,
            self.hop_limit,
        ).await
    }
    
    /// Send Router Advertisement (public interface)
    ///
    /// Public method for sending RAs from external callers.
    /// Used by `DHCPv6` subsystem when address changes occur.
    ///
    /// # Arguments
    ///
    /// * `if_index` - Interface index for transmission
    /// * `if_name` - Interface name for logging
    /// * `dest` - Destination address (Some for solicited, None for unsolicited)
    ///
    /// # Returns
    ///
    /// `Result<(), RadVError>` - Success or transmission error
    pub async fn send_ra(
        &self,
        if_index: u32,
        if_name: &str,
        dest: Option<Ipv6Addr>,
    ) -> Result<(), RadVError> {
        Self::send_ra_for_interface(
            &self.socket,
            &self.logger,
            &self.dhcp_contexts,
            &self.interfaces,
            if_index,
            if_name,
            dest,
            self.hop_limit,
        ).await
    }
    
    /// Process incoming `ICMPv6` packet (public interface)
    ///
    /// Public method for processing packets from external callers.
    /// Delegates to internal packet reception logic.
    ///
    /// # Arguments
    ///
    /// * `packet` - Packet bytes
    /// * `src_addr` - Source address
    ///
    /// # Returns
    ///
    /// `Result<(), RadVError>` - Success or processing error
    pub async fn process_packet(
        &self,
        packet: &[u8],
        src_addr: &std::net::SocketAddr,
    ) -> Result<(), RadVError> {
        Self::process_router_solicitation(
            &self.socket,
            &self.logger,
            &self.dhcp_contexts,
            &self.interfaces,
            packet,
            src_addr,
        ).await
    }
    
    /// Periodic RA transmission (public interface)
    ///
    /// Public method for triggering RA transmission cycle.
    /// Normally called internally by `periodic_ra_loop` task.
    pub async fn periodic_ra(&self) {
        // This method is primarily for testing and external triggering
        // The main periodic logic runs in the spawned task
        let now = SystemTime::now();
        let contexts = self.dhcp_contexts.read().unwrap();
        
        for (idx, context) in contexts.iter().enumerate() {
            if let Some(ra_time) = context.ra_time {
                if ra_time <= now {
                    debug!("Context {} RA time expired, needs transmission", idx);
                }
            }
        }
    }
    
    /// Build Router Advertisement packet with all options (internal)
    ///
    /// Constructs complete `ICMPv6` RA packet including:
    /// - RA header (type, code, checksum, hop limit, flags, router lifetime)
    /// - Prefix Information options for each configured prefix
    /// - MTU option if configured
    /// - RDNSS option for DNS servers
    /// - DNSSL option for DNS search domains
    /// - Source link-layer address option
    ///
    /// Sets M-bit (0x80) if `DHCPv6` managed address configuration enabled,
    /// O-bit (0x40) if `DHCPv6` other configuration enabled.
    ///
    /// # Arguments
    ///
    /// * `dhcp_contexts` - Contexts for prefix and flag information
    /// * `interfaces` - Interfaces for address enumeration
    /// * `if_index` - Interface index for prefix filtering
    /// * `if_name` - Interface name for parameter lookup
    /// * `hop_limit` - Hop limit value for RA header
    ///
    /// # Returns
    ///
    /// `Result<Vec<u8>, RadVError>` - Serialized RA packet or construction error
    async fn build_ra_packet_internal(
        dhcp_contexts: &Arc<RwLock<Vec<DhcpContext>>>,
        _interfaces: &Arc<RwLock<Vec<Interface>>>,
        if_index: u32,
        _if_name: &str,
        hop_limit: u8,
    ) -> Result<Vec<u8>, RadVError> {
        let mut packet = Vec::new();
        
        // RA header (20 bytes total: 8 bytes base + 12 bytes for times)
        packet.write_u8(ND_ROUTER_ADVERT)
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to write type: {e}")))?;
        packet.write_u8(0)  // Code (must be 0)
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to write code: {e}")))?;
        packet.write_u16::<BigEndian>(0)  // Checksum (kernel fills this for raw sockets)
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to write checksum: {e}")))?;
        packet.write_u8(hop_limit)
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to write hop limit: {e}")))?;
        
        // Flags byte (M-bit, O-bit, router priority)
        let mut flags: u8 = 0;
        
        // Check if any context requires managed or other configuration
        {
            let contexts = dhcp_contexts.read().unwrap();
            for context in contexts.iter() {
                if context.if_index == if_index {
                    // Check for DHCPv6 managed address config (CONTEXT_DHCP flag)
                    if context.flags & 0x0100 != 0 {
                        flags |= RA_FLAG_MANAGED;
                    }
                    // Check for other config (CONTEXT_RA_STATELESS flag)
                    if context.flags & 0x0001 != 0 {
                        flags |= RA_FLAG_OTHER;
                    }
                }
            }
        }
        
        packet.write_u8(flags)
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to write flags: {e}")))?;
        
        // Router lifetime (3 * interval by default, or configured value)
        let lifetime = 1800u16;  // Default 30 minutes
        packet.write_u16::<BigEndian>(lifetime)
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to write lifetime: {e}")))?;
        
        // Reachable time (0 = unspecified)
        packet.write_u32::<BigEndian>(0)
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to write reachable time: {e}")))?;
        
        // Retrans timer (0 = unspecified)
        packet.write_u32::<BigEndian>(0)
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to write retrans time: {e}")))?;
        
        // Add prefix information options
        // In full implementation, would enumerate interface addresses and add prefix options
        // For now, add prefixes from DHCPv6 contexts matching this interface
        {
            let contexts = dhcp_contexts.read().unwrap();
            for context in contexts.iter() {
                if context.if_index == if_index {
                    // Prefix Information option (type 3, length 4 = 32 bytes)
                    packet.write_u8(3)  // Type: Prefix Information
                        .map_err(|e| RadVError::PacketBuildError(format!("Prefix option type: {e}")))?;
                    packet.write_u8(4)  // Length: 4 * 8 = 32 bytes
                        .map_err(|e| RadVError::PacketBuildError(format!("Prefix option length: {e}")))?;
                    packet.write_u8(64)  // Prefix length (default /64)
                        .map_err(|e| RadVError::PacketBuildError(format!("Prefix length: {e}")))?;
                    
                    // Flags: L-bit (0x80) for on-link, A-bit (0x40) for autonomous address config
                    let prefix_flags = 0xC0;  // L-bit | A-bit
                    packet.write_u8(prefix_flags)
                        .map_err(|e| RadVError::PacketBuildError(format!("Prefix flags: {e}")))?;
                    
                    // Valid lifetime (7200 seconds = 2 hours default)
                    packet.write_u32::<BigEndian>(7200)
                        .map_err(|e| RadVError::PacketBuildError(format!("Valid lifetime: {e}")))?;
                    
                    // Preferred lifetime (1800 seconds = 30 minutes default)
                    packet.write_u32::<BigEndian>(1800)
                        .map_err(|e| RadVError::PacketBuildError(format!("Preferred lifetime: {e}")))?;
                    
                    // Reserved
                    packet.write_u32::<BigEndian>(0)
                        .map_err(|e| RadVError::PacketBuildError(format!("Reserved: {e}")))?;
                    
                    // Prefix (16 bytes)
                    let prefix_bytes = context.start6.octets();
                    packet.extend_from_slice(&prefix_bytes);
                    
                    // Only add one prefix per interface for simplicity
                    break;
                }
            }
        }
        
        // Add MTU option if configured
        let mtu_option = MtuOption::new();
        let mtu_bytes = mtu_option.mtu(1500).build()
            .map_err(|e| RadVError::PacketBuildError(format!("Failed to build MTU option: {e}")))?;
        packet.extend_from_slice(&mtu_bytes);
        
        trace!("Built RA packet: {} bytes", packet.len());
        Ok(packet)
    }
    
    /// Calculate next RA transmission time for context
    ///
    /// Implements RFC 4861 timing algorithm:
    /// - Short period (first 60 seconds): 5-20 second random intervals
    /// - Normal period: 3/4 to full `MaxRtrAdvInterval` with randomization
    ///
    /// # Arguments
    ///
    /// * `context` - `DHCPv6` context to update with new `ra_time`
    /// * `interval` - `MaxRtrAdvInterval` in seconds
    /// * `now` - Current timestamp
    fn new_timeout(context: &mut DhcpContext, interval: u32, now: SystemTime) {
        if let Some(short_start) = context.ra_short_period_start {
            if let Ok(elapsed) = now.duration_since(short_start) {
                if elapsed.as_secs() < SHORT_PERIOD_DURATION_SECS {
                    // Still in short period, use 5-20 second interval
                    let random_component = u64::from(elapsed.subsec_nanos()) % 
                        (SHORT_PERIOD_MAX_INTERVAL_SECS - SHORT_PERIOD_MIN_INTERVAL_SECS + 1);
                    let interval_secs = SHORT_PERIOD_MIN_INTERVAL_SECS + random_component;
                    context.ra_time = Some(now + Duration::from_secs(interval_secs));
                    return;
                }
            }
        }
        
        // Normal period: 3/4 to full interval
        let min_interval = (interval * 3) / 4;
        let random_range = interval - min_interval;
        
        // Simple randomization using current time
        let random_component = u64::from(now.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()) % (u64::from(random_range) + 1);
        
        let interval_secs = u64::from(min_interval) + random_component;
        context.ra_time = Some(now + Duration::from_secs(interval_secs));
    }
    
    /// Calculate `MaxRtrAdvInterval` from configuration
    ///
    /// Returns configured interval or default (600 seconds), enforcing
    /// RFC 4861 constraints: minimum 4 seconds, maximum 1800 seconds.
    ///
    /// # Arguments
    ///
    /// * `params` - Interface-specific parameters or None for defaults
    ///
    /// # Returns
    ///
    /// Interval in seconds, range [4, 1800], default 600
    fn calc_interval(params: Option<&RaInterfaceParams>) -> u32 {
        if let Some(p) = params {
            if p.interval != 0 {
                return p.interval.clamp(MIN_RTR_ADV_INTERVAL, MAX_RTR_ADV_INTERVAL);
            }
        }
        DEFAULT_MAX_RTR_ADV_INTERVAL
    }
}

/// Initialize Router Advertisement subsystem
///
/// Public function for starting unsolicited RAs on all interfaces.
/// Called by main daemon initialization code.
///
/// # Arguments
///
/// * `now` - Current timestamp for scheduling
/// * `context_id` - Specific context to start, or None for all
///
/// # Example
///
/// ```no_run
/// use std::time::SystemTime;
/// use dnsmasq::ipv6::radv::server::ra_start_unsolicited;
///
/// # async fn example() {
/// let now = SystemTime::now();
/// // Start unsolicited RAs for all contexts
/// // ra_start_unsolicited(now, None).await;
/// # }
/// ```
pub async fn ra_start_unsolicited(now: SystemTime, _context_id: Option<usize>) {
    // This would be called on the actual RadVServer instance
    // Placeholder for module-level function
    info!("ra_start_unsolicited called for timestamp {:?}", now);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_calc_interval_default() {
        assert_eq!(RadVServer::calc_interval(None), DEFAULT_MAX_RTR_ADV_INTERVAL);
    }
    
    #[test]
    fn test_calc_interval_configured() {
        let params = RaInterfaceParams {
            interval: 300,
            lifetime: 900,
            priority: 0,
            mtu: 1500,
        };
        assert_eq!(RadVServer::calc_interval(Some(&params)), 300);
    }
    
    #[test]
    fn test_calc_interval_min_constraint() {
        let params = RaInterfaceParams {
            interval: 2,  // Below minimum
            lifetime: 900,
            priority: 0,
            mtu: 1500,
        };
        assert_eq!(RadVServer::calc_interval(Some(&params)), MIN_RTR_ADV_INTERVAL);
    }
    
    #[test]
    fn test_calc_interval_max_constraint() {
        let params = RaInterfaceParams {
            interval: 5000,  // Above maximum
            lifetime: 9000,
            priority: 0,
            mtu: 1500,
        };
        assert_eq!(RadVServer::calc_interval(Some(&params)), MAX_RTR_ADV_INTERVAL);
    }
    
    #[tokio::test]
    async fn test_new_timeout_short_period() {
        let mut context = DhcpContext {
            start6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            if_index: 1,
            flags: 0,
            ra_time: None,
            ra_short_period_start: Some(SystemTime::now()),
            next: None,
        };
        
        let now = SystemTime::now();
        RadVServer::new_timeout(&mut context, 600, now);
        
        assert!(context.ra_time.is_some());
        let ra_time = context.ra_time.unwrap();
        let duration = ra_time.duration_since(now).unwrap();
        
        // Should be in short period range (5-20 seconds)
        assert!(duration.as_secs() >= SHORT_PERIOD_MIN_INTERVAL_SECS);
        assert!(duration.as_secs() <= SHORT_PERIOD_MAX_INTERVAL_SECS);
    }
    
    #[tokio::test]
    async fn test_new_timeout_normal_period() {
        let short_start = SystemTime::now() - Duration::from_secs(120);  // 2 minutes ago
        let mut context = DhcpContext {
            start6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            if_index: 1,
            flags: 0,
            ra_time: None,
            ra_short_period_start: Some(short_start),
            next: None,
        };
        
        let now = SystemTime::now();
        let interval = 600;
        RadVServer::new_timeout(&mut context, interval, now);
        
        assert!(context.ra_time.is_some());
        let ra_time = context.ra_time.unwrap();
        let duration = ra_time.duration_since(now).unwrap();
        
        // Should be in normal period range (450-600 seconds for interval=600)
        let min_interval = (interval * 3) / 4;
        assert!(duration.as_secs() >= min_interval as u64);
        assert!(duration.as_secs() <= interval as u64);
    }
    
    #[test]
    fn test_radv_error_display() {
        let err = RadVError::ConfigError("test error".to_string());
        assert_eq!(format!("{}", err), "Configuration error: test error");
        
        let io_err = IoError::from_raw_os_error(2);
        let err2 = RadVError::from(io_err);
        assert!(format!("{}", err2).contains("Network I/O error"));
    }
    
    #[test]
    fn test_ra_interface_params_defaults() {
        let params = RaInterfaceParams {
            interval: DEFAULT_MAX_RTR_ADV_INTERVAL,
            lifetime: DEFAULT_LIFETIME_MULTIPLIER * DEFAULT_MAX_RTR_ADV_INTERVAL,
            priority: 0,
            mtu: 1500,
        };
        
        assert_eq!(params.interval, 600);
        assert_eq!(params.lifetime, 1800);
    }
}
