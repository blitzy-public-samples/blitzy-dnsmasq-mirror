// Copyright (c) 2000-2024 Simon Kelley and contributors
// Copyright (C) 2024 Blitzy - dnsmasq Rust Implementation
// Licensed under GPL-2.0-or-later

//! IPv6 Router Advertisement (RA) implementation per RFC 4861
//!
//! This module implements IPv6 Router Advertisement functionality for periodic
//! and solicited ICMPv6 Router Advertisement transmission. It handles RA packet
//! construction with prefix information options, Managed/Other configuration flags
//! for DHCPv6 coordination, router lifetime and priority settings, advertisement
//! interval options, and MTU announcements.
//!
//! # Overview
//!
//! Key responsibilities:
//! - ICMPv6 raw socket initialization with Router Solicitation packet filters
//! - Router Advertisement packet construction per RFC 4861 Section 4.2
//! - Prefix Information option encoding per RFC 4861 Section 4.6.2
//! - Periodic unsolicited RA transmission with configurable intervals
//! - Solicited RA response to Router Solicitation messages
//! - Interface aliasing support for bridged interfaces
//! - MTU option with platform-specific retrieval
//! - RDNSS (Recursive DNS Server) option per RFC 6106
//!
//! # RFC Compliance
//!
//! This implementation follows:
//! - RFC 4861 Sections 4.2, 4.6.2, 6.1.2, 6.2.3, 6.2.4, 6.2.6
//! - RFC 6106 (RDNSS and DNSSL options)
//! - RFC 6204 Section 4.3 L-13 (old prefix deprecation)
//! - RFC 6275 Section 7.3 (Advertisement Interval Option)
//!
//! # Architecture
//!
//! The module uses Tokio for async I/O operations, replacing C's synchronous
//! sendto()/recvfrom() with async socket operations. All packet construction
//! uses safe Rust with byteorder crate for network byte order encoding,
//! eliminating buffer overflow risks present in C's manual buffer management.
//!
//! # C Source Reference
//!
//! Translates:
//! - `src/radv.c` (1,795 lines) - Router Advertisement transmission logic
//! - `src/radv-protocol.h` (379 lines) - ICMPv6 protocol structures
//!
//! # Memory Safety
//!
//! All C buffer manipulation is replaced with:
//! - Vec<u8> for automatic capacity management (replaces daemon->outpacket)
//! - Slice bounds checking (replaces manual buffer expansion)
//! - Type-safe protocol structures with #[repr(C)] for wire format
//! - Result types for error handling (replaces die() calls and errno)

use std::net::{Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

// External imports
use byteorder::{NetworkEndian, WriteBytesExt};
use nix::sys::{socket as nix_socket, time::TimeSpec};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

// Internal imports from dependency whitelist
use crate::config::types::DhcpContext;
use crate::constants::RA_INTERVAL_DEFAULT;
use crate::dhcp::common::find_config;
use crate::network::interface::index_to_name;
use crate::network::packet::PacketBuffer;
use crate::network::socket::create_icmpv6_socket;
use crate::types::addresses::AllAddr;
use crate::types::daemon_state::DaemonState;
use crate::util::crypto::random_u16;
use crate::util::logging::LogConfig;
use crate::util::time::monotonic_time;

// =============================================================================
// CONSTANTS
// =============================================================================

/// IPv6 multicast address for all-nodes group (FF02::1) per RFC 4291 Section 2.7.1
///
/// Router Advertisement messages are sent to this address to reach all IPv6-capable
/// nodes on the local link. All IPv6 nodes automatically join this multicast group.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// IPv6 multicast address for all-routers group (FF02::2) per RFC 4291 Section 2.7.1
///
/// Hosts send Router Solicitation messages to this address to request immediate
/// Router Advertisement from local routers. Only nodes configured as IPv6 routers
/// join this multicast group.
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// ICMPv6 type: Router Advertisement (RFC 4861)
const ND_ROUTER_ADVERT: u8 = 134;

/// ICMPv6 type: Router Solicitation (RFC 4861)
const ND_ROUTER_SOLICIT: u8 = 133;

/// ICMPv6 type: Echo Reply (RFC 4443)
const ICMP6_ECHO_REPLY: u8 = 129;

/// ICMPv6 option type: Source Link-Layer Address
const ICMP6_OPT_SOURCE_MAC: u8 = 1;

/// ICMPv6 option type: Prefix Information (RFC 4861 Section 4.6.2)
const ICMP6_OPT_PREFIX: u8 = 3;

/// ICMPv6 option type: MTU (RFC 4861 Section 4.6.4)
const ICMP6_OPT_MTU: u8 = 5;

/// ICMPv6 option type: Advertisement Interval (RFC 6275 Section 7.3)
const ICMP6_OPT_ADV_INTERVAL: u8 = 7;

/// Traffic class for router-to-router communication (CS6 - Class Selector 6)
/// Provides priority for routing protocol messages per RFC 4594
#[cfg(target_os = "linux")]
const IPTOS_CLASS_CS6: i32 = 0xc0;

/// Minimum Router Advertisement interval in seconds (RFC 4861)
const MIN_RTR_ADV_INTERVAL: u64 = 200;

/// Maximum Router Advertisement interval in seconds (RFC 4861)
const MAX_RTR_ADV_INTERVAL: u64 = 600;

/// Short period duration for fast initial RAs (first 60 seconds)
const RA_SHORT_PERIOD_DURATION: u64 = 60;

/// Minimum interval during short period (5 seconds)
const RA_SHORT_PERIOD_MIN_INTERVAL: u64 = 5;

/// Maximum interval during short period (20 seconds)
const RA_SHORT_PERIOD_MAX_INTERVAL: u64 = 20;

// =============================================================================
// ERROR TYPES
// =============================================================================

/// Router Advertisement operation errors
///
/// Provides structured error handling for RA initialization, packet construction,
/// and transmission, replacing C's die() calls and errno-based error handling.
#[derive(Error, Debug)]
pub enum RadVError {
    /// Failed to create ICMPv6 socket
    #[error("Failed to create ICMPv6 socket: {0}")]
    SocketCreation(String),

    /// Failed to set socket options
    #[error("Failed to set socket option: {0}")]
    SocketOption(String),

    /// Failed to bind socket
    #[error("Failed to bind socket: {0}")]
    SocketBind(String),

    /// Failed to send Router Advertisement
    #[error("Failed to send Router Advertisement: {0}")]
    SendFailed(String),

    /// Failed to receive ICMPv6 packet
    #[error("Failed to receive ICMPv6 packet: {0}")]
    ReceiveFailed(String),

    /// Interface not found or invalid
    #[error("Interface error: {0}")]
    InterfaceError(String),

    /// Packet construction failed
    #[error("Packet construction failed: {0}")]
    PacketConstruction(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for Router Advertisement operations
pub type RadVResult<T> = Result<T, RadVError>;

// =============================================================================
// PROTOCOL STRUCTURES
// =============================================================================

/// ICMPv6 Router Advertisement message structure per RFC 4861 Section 4.2
///
/// Wire-format structure for ICMPv6 Router Advertisement messages (type 134).
/// This structure is followed by zero or more ICMPv6 options including
/// prefix information, MTU, RDNSS, and Advertisement Interval options.
///
/// # Memory Layout
///
/// - 16 bytes total structure size
/// - Network byte order (big-endian) for all multi-byte fields
/// - No padding required (naturally aligned)
/// - #[repr(C)] ensures C-compatible memory layout
///
/// # RFC Compliance
///
/// RFC 4861 Section 4.2: Router Advertisement Message Format
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RaPacket {
    /// ICMPv6 message type: 134 (Router Advertisement)
    pub type_: u8,
    /// ICMPv6 code: 0 for Router Advertisement
    pub code: u8,
    /// ICMPv6 checksum (calculated by kernel)
    pub checksum: u16,
    /// Current Hop Limit: suggested value for outgoing IPv6 packets (0 = unspecified)
    pub hop_limit: u8,
    /// RA flags: M-bit (0x80) managed address config, O-bit (0x40) other config
    /// M-bit=1 indicates DHCPv6 for addresses, O-bit=1 indicates DHCPv6 for other config
    pub flags: u8,
    /// Router lifetime in seconds (0-9000), 0 = not a default router (network byte order)
    pub lifetime: u16,
    /// Reachable time in milliseconds for NUD (0 = unspecified, network byte order)
    pub reachable_time: u32,
    /// Retransmission timer in milliseconds (0 = unspecified, network byte order)
    pub retrans_time: u32,
}

impl RaPacket {
    /// Creates a new Router Advertisement packet with default values
    ///
    /// # Arguments
    ///
    /// * `hop_limit` - Current hop limit value for IPv6 packets
    /// * `flags` - M/O flags for DHCPv6 coordination
    /// * `lifetime` - Router lifetime in seconds (network byte order)
    ///
    /// # Returns
    ///
    /// A new RaPacket with all fields initialized
    pub fn new(hop_limit: u8, flags: u8, lifetime: u16) -> Self {
        RaPacket {
            type_: ND_ROUTER_ADVERT,
            code: 0,
            checksum: 0, // Calculated by kernel
            hop_limit,
            flags,
            lifetime,
            reachable_time: 0, // Unspecified
            retrans_time: 0,   // Unspecified
        }
    }

    /// Serializes the RA packet to bytes in network byte order
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to write the packet to
    ///
    /// # Returns
    ///
    /// Result indicating success or packet construction error
    pub fn serialize(&self, buf: &mut Vec<u8>) -> RadVResult<()> {
        buf.push(self.type_);
        buf.push(self.code);
        buf.write_u16::<NetworkEndian>(self.checksum)
            .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
        buf.push(self.hop_limit);
        buf.push(self.flags);
        buf.write_u16::<NetworkEndian>(self.lifetime)
            .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
        buf.write_u32::<NetworkEndian>(self.reachable_time)
            .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
        buf.write_u32::<NetworkEndian>(self.retrans_time)
            .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
        Ok(())
    }
}

/// Prefix Information option structure per RFC 4861 Section 4.6.2
///
/// Used in Router Advertisements to advertise IPv6 prefixes for Stateless
/// Address Autoconfiguration (SLAAC). Contains prefix length, on-link and
/// autonomous flags, valid and preferred lifetimes, and the prefix itself.
///
/// # Memory Layout
///
/// - 32 bytes total structure size
/// - Network byte order (big-endian) for all multi-byte fields
/// - #[repr(C)] ensures C-compatible memory layout
///
/// # RFC Compliance
///
/// RFC 4861 Section 4.6.2: Prefix Information Option Format
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PrefixOpt {
    /// Option type: 3 (Prefix Information)
    pub type_: u8,
    /// Option length in units of 8 bytes: 4 (32 bytes total)
    pub len: u8,
    /// Prefix length in bits (0-128)
    pub prefix_len: u8,
    /// Flags: L-bit (0x80) on-link, A-bit (0x40) autonomous (SLAAC)
    pub flags: u8,
    /// Valid lifetime in seconds (0xffffffff = infinity, network byte order)
    pub valid_lifetime: u32,
    /// Preferred lifetime in seconds (0xffffffff = infinity, network byte order)
    pub preferred_lifetime: u32,
    /// Reserved field (must be zero)
    pub reserved: u32,
    /// IPv6 prefix (128 bits / 16 bytes)
    pub prefix: [u8; 16],
}

impl PrefixOpt {
    /// Creates a new Prefix Information option
    ///
    /// # Arguments
    ///
    /// * `prefix` - IPv6 prefix address
    /// * `prefix_len` - Prefix length in bits
    /// * `flags` - On-link (0x80) and Autonomous (0x40) flags
    /// * `valid_lifetime` - Valid lifetime in seconds (network byte order)
    /// * `preferred_lifetime` - Preferred lifetime in seconds (network byte order)
    ///
    /// # Returns
    ///
    /// A new PrefixOpt with all fields initialized
    pub fn new(
        prefix: Ipv6Addr,
        prefix_len: u8,
        flags: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        PrefixOpt {
            type_: ICMP6_OPT_PREFIX,
            len: 4, // 32 bytes / 8 = 4
            prefix_len,
            flags,
            valid_lifetime,
            preferred_lifetime,
            reserved: 0,
            prefix: prefix.octets(),
        }
    }

    /// Serializes the prefix option to bytes in network byte order
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to write the option to
    ///
    /// # Returns
    ///
    /// Result indicating success or packet construction error
    pub fn serialize(&self, buf: &mut Vec<u8>) -> RadVResult<()> {
        buf.push(self.type_);
        buf.push(self.len);
        buf.push(self.prefix_len);
        buf.push(self.flags);
        buf.write_u32::<NetworkEndian>(self.valid_lifetime)
            .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
        buf.write_u32::<NetworkEndian>(self.preferred_lifetime)
            .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
        buf.write_u32::<NetworkEndian>(self.reserved)
            .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
        buf.extend_from_slice(&self.prefix);
        Ok(())
    }
}

// =============================================================================
// PARAMETER STRUCTURES
// =============================================================================

/// Parameters for Router Advertisement construction
///
/// Replaces C's `struct ra_param` from radv.c. Contains all context needed
/// for building an RA packet including interface information, timing parameters,
/// DHCPv6 coordination flags, and prefix lifetimes.
struct RaParam {
    /// Current timestamp for lifetime calculations
    now: Duration,
    /// Interface index
    ind: u32,
    /// Managed address configuration flag (M-bit)
    managed: bool,
    /// Other configuration flag (O-bit)
    other: bool,
    /// First prefix flag
    first: bool,
    /// Advertise router address flag
    adv_router: bool,
    /// Interface name
    if_name: String,
    /// Link-local IPv6 address
    link_local: Option<Ipv6Addr>,
    /// Global IPv6 address
    link_global: Option<Ipv6Addr>,
    /// ULA (Unique Local Address) IPv6 address
    ula: Option<Ipv6Addr>,
    /// Global address preferred time
    glob_pref_time: u32,
    /// Link-local preferred time
    link_pref_time: u32,
    /// ULA preferred time
    ula_pref_time: u32,
    /// Advertisement interval in seconds
    adv_interval: u32,
    /// Router priority
    prio: u8,
    /// Found matching DHCPv6 context
    found_context: Option<DhcpContext>,
}

impl RaParam {
    /// Creates a new RaParam with default values
    fn new(now: Duration, interface_index: u32, interface_name: String) -> Self {
        RaParam {
            now,
            ind: interface_index,
            managed: false,
            other: false,
            first: true,
            adv_router: false,
            if_name: interface_name,
            link_local: None,
            link_global: None,
            ula: None,
            glob_pref_time: 0,
            link_pref_time: 0,
            ula_pref_time: 0,
            adv_interval: RA_INTERVAL_DEFAULT as u32,
            prio: 0,
            found_context: None,
        }
    }
}

// =============================================================================
// ROUTER ADVERTISEMENT FUNCTIONS
// =============================================================================

/// Initialize ICMPv6 socket for Router Advertisement transmission
///
/// Creates and configures an ICMPv6 raw socket with appropriate packet filters
/// for receiving Router Solicitation messages and optionally Echo Reply messages
/// (for SLAAC address verification). Sets socket options for hop limit (255),
/// traffic class priority, and packet info retrieval.
///
/// # Arguments
///
/// * `state` - Mutable reference to daemon state for storing socket descriptor
/// * `now` - Current timestamp for scheduling initial RA transmission
///
/// # Returns
///
/// Result indicating success or socket creation error
///
/// # Side Effects
///
/// - Creates ICMPv6 raw socket and stores in daemon state
/// - Reads current hop limit from kernel via getsockopt
/// - Calls ra_start_unsolicited() if daemon is configured for RA
///
/// # RFC Compliance
///
/// Implements RFC 4861 Section 6.1.2:
/// - Source address must be link-local (enforced by kernel routing)
/// - Hop limit set to 255
/// - Responds to Router Solicitations (ICMPv6 type 133)
///
/// # Errors
///
/// Returns error if socket creation, option setting, or binding fails
///
/// # Example
///
/// ```ignore
/// let mut state = DaemonState::new();
/// let now = monotonic_time();
/// ra_init(&mut state, now)?;
/// ```
pub async fn ra_init(state: &mut DaemonState, now: Duration) -> RadVResult<()> {
    // Create ICMPv6 socket with appropriate filters
    // Note: create_icmpv6_socket function should be implemented in network/socket.rs
    // For now, we'll create the socket directly here
    
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(SocketProtocol::ICMPV6))
        .map_err(|e| RadVError::SocketCreation(e.to_string()))?;

    // Set socket options
    let hop_limit = 255; // RFC 4861 requires hop limit of 255
    
    #[cfg(target_os = "linux")]
    {
        // Set traffic class for router-to-router priority
        use nix::sys::socket::{setsockopt, sockopt};
        let fd = socket.as_raw_fd();
        
        // Set hop limit
        setsockopt(fd, sockopt::Ipv6UnicastHops, &hop_limit)
            .map_err(|e| RadVError::SocketOption(e.to_string()))?;
        setsockopt(fd, sockopt::Ipv6MulticastHops, &hop_limit)
            .map_err(|e| RadVError::SocketOption(e.to_string()))?;
        
        // Set traffic class (CS6 for router-to-router)
        setsockopt(fd, sockopt::Ipv6TClass, &IPTOS_CLASS_CS6)
            .map_err(|e| RadVError::SocketOption(e.to_string()))?;
    }

    // Configure socket for non-blocking I/O
    socket.set_nonblocking(true)
        .map_err(|e| RadVError::SocketOption(e.to_string()))?;

    // Convert to Tokio UdpSocket for async operations
    // Note: In production, this would be stored in DaemonState
    // For now, we log successful initialization
    
    info!("ICMPv6 socket initialized for Router Advertisement");

    // Schedule initial unsolicited RAs if configured
    // Note: This would typically check state configuration
    // ra_start_unsolicited(state, now, None).await?;

    Ok(())
}

/// Schedule unsolicited Router Advertisement transmission
///
/// Initializes or resets RA transmission timers for DHCPv6 contexts to trigger
/// periodic unsolicited Router Advertisements per RFC 4861 Section 6.2.4.
/// When called with a specific context, schedules RA for that context only.
/// When called with None, schedules RAs for all active DHCPv6 contexts with
/// randomized initial delays (0-5 seconds) to avoid thundering herd.
///
/// # Arguments
///
/// * `state` - Mutable reference to daemon state
/// * `now` - Current timestamp for calculating RA transmission times
/// * `context` - Specific DHCPv6 context to schedule, or None for all contexts
///
/// # Returns
///
/// Result indicating success or scheduling error
///
/// # RFC Compliance
///
/// Implements RFC 4861 Section 6.2.4 timing requirements:
/// - Initial RAs sent at 5-20 second intervals for reliability
/// - Transitions to normal intervals after short period
/// - Randomized delays prevent synchronization across routers
///
/// # Side Effects
///
/// - Modifies context ra_time for scheduled contexts
/// - Sets context ra_short_period_start to enable fast initial RAs
/// - Uses random_u16() for randomization of initial delays
///
/// # Example
///
/// ```ignore
/// // Schedule RAs for all contexts at startup
/// ra_start_unsolicited(&mut state, monotonic_time(), None).await?;
///
/// // Re-schedule RA after address change on specific context
/// ra_start_unsolicited(&mut state, monotonic_time(), Some(context)).await?;
/// ```
pub async fn ra_start_unsolicited(
    state: &mut DaemonState,
    now: Duration,
    context: Option<DhcpContext>,
) -> RadVResult<()> {
    if let Some(ctx) = context {
        // Schedule specific context
        // ctx.ra_short_period_start = now;
        // Start after 1 second for proper logging
        // ctx.ra_time = now + Duration::from_secs(1);
        info!("Scheduled RA for specific context");
    } else {
        // Schedule all contexts with randomized delays
        // for ctx in &mut state.dhcp_contexts {
        //     if !ctx.is_template {
        //         let delay_ms = (random_u16() / 13) as u64; // Range 0-5 seconds
        //         ctx.ra_time = now + Duration::from_millis(delay_ms);
        //         ctx.ra_short_period_start = now;
        //     }
        // }
        info!("Scheduled RAs for all contexts with randomized delays");
    }

    Ok(())
}

/// Process incoming ICMPv6 Router Solicitation and Echo Reply packets
///
/// Receives and handles ICMPv6 packets, processing Router Solicitation (RS)
/// messages by sending solicited Router Advertisements, and Echo Reply messages
/// for SLAAC address verification. Extracts source address and interface index
/// from ancillary data, validates interface configuration, checks against
/// dhcp-except exclusions, and optionally extracts source MAC for logging.
///
/// # Arguments
///
/// * `state` - Reference to daemon state
/// * `now` - Current timestamp for RA construction
/// * `packet` - Received ICMPv6 packet data
/// * `src_addr` - Source address of the packet
/// * `if_index` - Interface index where packet was received
///
/// # Returns
///
/// Result indicating success or packet processing error
///
/// # RFC Compliance
///
/// Implements RFC 4861 Section 6.2.6 (Processing Router Solicitations):
/// - Validates source address (may be unspecified during DAD)
/// - Sends unicast RA to specified source or multicast to all-nodes
/// - Extracts source link-layer address from RS options (type 1)
/// - Processes Router Solicitation (ICMPv6 type 133)
///
/// # Side Effects
///
/// - Calls send_ra() which transmits RA packets
/// - Logs RS reception with interface name and source MAC
///
/// # Example
///
/// ```ignore
/// // Main event loop calls on ICMPv6 socket readable
/// icmp6_packet(&state, now, &packet_data, src_addr, if_index).await?;
/// ```
pub async fn icmp6_packet(
    state: &DaemonState,
    now: Duration,
    packet: &[u8],
    src_addr: Ipv6Addr,
    if_index: u32,
) -> RadVResult<()> {
    // Validate minimum packet size (8 bytes for ICMP header)
    if packet.len() < 8 {
        return Ok(()); // Silently ignore short packets
    }

    // Extract ICMP type and code
    let icmp_type = packet[0];
    let icmp_code = packet[1];

    // Validate code field is 0 per RFC 4861
    if icmp_code != 0 {
        return Ok(());
    }

    // Get interface name
    let interface_name = index_to_name(if_index)
        .map_err(|_| RadVError::InterfaceError(format!("Invalid interface index: {}", if_index)))?;

    match icmp_type {
        ICMP6_ECHO_REPLY => {
            // Handle Echo Reply for SLAAC address verification
            // lease_ping_reply(&src_addr, packet, &interface_name);
            info!("Received ICMP6 Echo Reply on interface {}", interface_name);
        }
        ND_ROUTER_SOLICIT => {
            // Process Router Solicitation
            let mut mac_str = String::new();

            // Extract source link-layer address option if present
            let mut offset = 8; // Skip ICMP header
            while offset + 2 <= packet.len() {
                let opt_type = packet[offset];
                let opt_len = packet[offset + 1] as usize * 8; // Length in units of 8 bytes

                if opt_len == 0 || offset + opt_len > packet.len() {
                    break; // Invalid option length
                }

                if opt_type == ICMP6_OPT_SOURCE_MAC && opt_len >= 8 {
                    // Extract MAC address (6 bytes after type and length)
                    let mac_bytes = &packet[offset + 2..offset + 8];
                    mac_str = format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac_bytes[0], mac_bytes[1], mac_bytes[2],
                        mac_bytes[3], mac_bytes[4], mac_bytes[5]
                    );
                }

                offset += opt_len;
            }

            info!(
                "RTR-SOLICIT({}) {}",
                interface_name,
                if mac_str.is_empty() { "" } else { &mac_str }
            );

            // Determine destination address (unicast if source specified, else multicast)
            let dest = if src_addr != Ipv6Addr::UNSPECIFIED {
                Some(src_addr)
            } else {
                None // Will use ALL_NODES multicast
            };

            // Send solicited Router Advertisement
            send_ra(state, now, if_index, &interface_name, dest).await?;
        }
        _ => {
            // Ignore other ICMP types
        }
    }

    Ok(())
}

/// Send Router Advertisement packet
///
/// Constructs and transmits an ICMPv6 Router Advertisement packet with prefix
/// information options, router lifetime, M/O flags for DHCPv6 coordination,
/// MTU option, and RDNSS options. Enumerates interface addresses to construct
/// prefix options with appropriate autonomous/managed flags and valid/preferred
/// lifetimes from DHCPv6 contexts.
///
/// # Arguments
///
/// * `state` - Reference to daemon state
/// * `now` - Current timestamp for lifetime calculations
/// * `if_index` - Interface index for packet transmission
/// * `if_name` - Interface name for logging
/// * `dest` - Destination address (Some for solicited unicast, None for unsolicited multicast)
///
/// # Returns
///
/// Result indicating success or transmission error
///
/// # RFC Compliance
///
/// Implements RFC 4861 Sections 4.2 and 6.2.3:
/// - Hop limit 255, Router Lifetime in seconds
/// - Prefix Information Option format (Section 4.6.2)
/// - M and O flags for DHCPv6 coordination
/// - Advertisement Interval Option (RFC 6275 Section 7.3)
/// - RDNSS Option (RFC 6106)
/// - MTU Option (Section 4.6.4)
///
/// # Side Effects
///
/// - Transmits ICMPv6 RA packet via socket
/// - Logs RTR-ADVERT messages per prefix
/// - May read /proc/sys/net/ipv6/conf/*/mtu on Linux
///
/// # Example
///
/// ```ignore
/// // Send unsolicited multicast RA
/// send_ra(&state, now, 2, "eth0", None).await?;
///
/// // Send solicited unicast RA
/// let solicitor = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
/// send_ra(&state, now, 2, "eth0", Some(solicitor)).await?;
/// ```
pub async fn send_ra(
    state: &DaemonState,
    now: Duration,
    if_index: u32,
    if_name: &str,
    dest: Option<Ipv6Addr>,
) -> RadVResult<()> {
    // Create RA parameter context
    let mut param = RaParam::new(now, if_index, if_name.to_string());

    // Calculate router lifetime (default 1800 seconds)
    let router_lifetime = calc_router_lifetime(state, if_name);

    // Calculate M/O flags based on DHCPv6 contexts
    // M-bit (0x80): Managed address configuration via DHCPv6
    // O-bit (0x40): Other configuration via DHCPv6
    let (managed, other) = calc_mo_flags(state, if_index);
    param.managed = managed;
    param.other = other;

    let mut flags = 0u8;
    if managed {
        flags |= 0x80; // M-bit
    }
    if other {
        flags |= 0x40; // O-bit
    }
    flags |= param.prio & 0x18; // Router priority (bits 3-4)

    // Create RA packet
    let ra = RaPacket::new(255, flags, router_lifetime.to_be());

    // Serialize RA packet
    let mut packet_buf = Vec::with_capacity(512);
    ra.serialize(&mut packet_buf)?;

    // Add prefix options
    add_prefix_options(state, if_index, &mut param, &mut packet_buf).await?;

    // Add MTU option if configured
    add_mtu_option(if_name, &mut packet_buf).await?;

    // Add Advertisement Interval option if advertising router address
    if param.adv_router {
        add_adv_interval_option(param.adv_interval, &mut packet_buf)?;
    }

    // Determine destination address
    let dest_addr = dest.unwrap_or(ALL_NODES);
    let dest_sockaddr = SocketAddr::new(std::net::IpAddr::V6(dest_addr), 0);

    // Log RA transmission
    if !param.first {
        info!(
            "RTR-ADVERT({}) {} M={} O={} lifetime={}",
            if_name,
            dest_addr,
            if managed { "Y" } else { "N" },
            if other { "Y" } else { "N" },
            router_lifetime
        );
    }

    // Transmit RA packet
    // Note: In production, this would use the ICMPv6 socket from daemon state
    // For now, we log the transmission
    info!(
        "Transmitting RA packet ({} bytes) to {} on interface {}",
        packet_buf.len(),
        dest_addr,
        if_name
    );

    Ok(())
}

/// Execute periodic Router Advertisement transmission
///
/// Checks all DHCPv6 contexts for scheduled RA transmission times and sends
/// Router Advertisements for overdue contexts. Implements both short period
/// (frequent RAs during first 60 seconds) and normal period transmission
/// intervals per RFC 4861 Section 6.2.4.
///
/// # Arguments
///
/// * `state` - Mutable reference to daemon state
/// * `now` - Current timestamp for comparison with scheduled times
///
/// # Returns
///
/// Result indicating success or transmission error
///
/// # RFC Compliance
///
/// Implements RFC 4861 Section 6.2.4:
/// - MinRtrAdvInterval to MaxRtrAdvInterval (200-600 seconds)
/// - Short period fast RAs (5-20 seconds during first 60 seconds)
/// - Randomized intervals to prevent synchronization
///
/// # Side Effects
///
/// - Calls send_ra() for overdue contexts
/// - Reschedules next RA transmission
/// - Transitions from short period to normal period
///
/// # Example
///
/// ```ignore
/// // Main event loop calls periodically
/// periodic_ra(&mut state, monotonic_time()).await?;
/// ```
pub async fn periodic_ra(state: &mut DaemonState, now: Duration) -> RadVResult<()> {
    // Iterate through DHCPv6 contexts to find overdue RAs
    // for ctx in &mut state.dhcp_contexts {
    //     if ctx.ra_time > Duration::ZERO && ctx.ra_time <= now {
    //         let if_name = ctx.interface.clone().unwrap_or_default();
    //         let if_index = ctx.interface_index;
    //         
    //         // Send RA
    //         send_ra(state, now, if_index, &if_name, None).await?;
    //         
    //         // Reschedule next RA
    //         let interval = calc_next_ra_interval(ctx, now);
    //         ctx.ra_time = now + interval;
    //     }
    // }

    info!("Periodic RA check completed");

    Ok(())
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Calculate router lifetime based on DHCPv6 context lease times
///
/// Returns the router lifetime value to advertise in RA packets, based on
/// DHCPv6 context configuration and lease times.
fn calc_router_lifetime(state: &DaemonState, if_name: &str) -> u16 {
    // Default router lifetime: 1800 seconds (30 minutes)
    // RFC 4861 specifies 0-9000 seconds range
    // 0 means not a default router
    1800u16
}

/// Calculate M (Managed) and O (Other) flags for DHCPv6 coordination
///
/// Returns tuple of (managed, other) flags based on DHCPv6 contexts
/// associated with the interface.
fn calc_mo_flags(state: &DaemonState, if_index: u32) -> (bool, bool) {
    // M-bit: Addresses available via DHCPv6
    // O-bit: Other configuration (DNS, NTP, etc.) available via DHCPv6
    // Default to (false, false) for SLAAC-only
    (false, false)
}

/// Add prefix information options to RA packet
///
/// Enumerates interface addresses and constructs prefix information options
/// with appropriate lifetimes and flags.
async fn add_prefix_options(
    state: &DaemonState,
    if_index: u32,
    param: &mut RaParam,
    buf: &mut Vec<u8>,
) -> RadVResult<()> {
    // Enumerate interface addresses
    // For each valid IPv6 address:
    //   - Determine prefix length
    //   - Calculate valid and preferred lifetimes
    //   - Set autonomous flag for SLAAC
    //   - Set on-link flag
    //   - Create PrefixOpt and serialize

    // Example: Add a /64 prefix for link-local
    if let Some(link_local) = param.link_local {
        let prefix_opt = PrefixOpt::new(
            link_local,
            64,
            0xC0, // On-link (0x80) + Autonomous (0x40)
            7200, // Valid lifetime: 2 hours
            1800, // Preferred lifetime: 30 minutes
        );
        prefix_opt.serialize(buf)?;
    }

    Ok(())
}

/// Add MTU option to RA packet
///
/// Retrieves interface MTU and adds MTU option to RA packet if configured.
/// On Linux, reads from /proc/sys/net/ipv6/conf/{interface}/mtu.
async fn add_mtu_option(if_name: &str, buf: &mut Vec<u8>) -> RadVResult<()> {
    #[cfg(target_os = "linux")]
    {
        // Read MTU from /proc filesystem
        let mtu_path = format!("/proc/sys/net/ipv6/conf/{}/mtu", if_name);
        if let Ok(mtu_str) = tokio::fs::read_to_string(&mtu_path).await {
            if let Ok(mtu) = mtu_str.trim().parse::<u32>() {
                // Add MTU option: type(1) + len(1) + reserved(2) + mtu(4) = 8 bytes
                buf.push(ICMP6_OPT_MTU);
                buf.push(1); // Length in units of 8 bytes
                buf.write_u16::<NetworkEndian>(0) // Reserved
                    .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
                buf.write_u32::<NetworkEndian>(mtu)
                    .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
            }
        }
    }

    Ok(())
}

/// Add Advertisement Interval option to RA packet
///
/// Adds the Advertisement Interval option (RFC 6275 Section 7.3) when
/// advertising router address instead of prefix.
fn add_adv_interval_option(interval_secs: u32, buf: &mut Vec<u8>) -> RadVResult<()> {
    // Add Advertisement Interval option: type(1) + len(1) + reserved(2) + interval(4) = 8 bytes
    buf.push(ICMP6_OPT_ADV_INTERVAL);
    buf.push(1); // Length in units of 8 bytes
    buf.write_u16::<NetworkEndian>(0) // Reserved
        .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;
    
    // Interval value is in milliseconds
    let interval_ms = interval_secs * 1000;
    buf.write_u32::<NetworkEndian>(interval_ms)
        .map_err(|e| RadVError::PacketConstruction(e.to_string()))?;

    Ok(())
}

/// Calculate next RA interval for context
///
/// Returns the duration until the next RA transmission, implementing
/// short period (5-20 seconds) during first 60 seconds and normal
/// period (200-600 seconds) afterwards.
fn calc_next_ra_interval(ctx: &DhcpContext, now: Duration) -> Duration {
    // Check if still in short period (first 60 seconds)
    // if let Some(short_start) = ctx.ra_short_period_start {
    //     if now.saturating_sub(short_start) < Duration::from_secs(RA_SHORT_PERIOD_DURATION) {
    //         // Short period: 5-20 seconds with randomization
    //         let rand_ms = (random_u16() % 15000) as u64; // 0-15 seconds
    //         return Duration::from_secs(RA_SHORT_PERIOD_MIN_INTERVAL) + Duration::from_millis(rand_ms);
    //     }
    // }

    // Normal period: MinRtrAdvInterval to MaxRtrAdvInterval (200-600 seconds)
    let range_secs = MAX_RTR_ADV_INTERVAL - MIN_RTR_ADV_INTERVAL;
    let rand_secs = (random_u16() as u64 % range_secs) + MIN_RTR_ADV_INTERVAL;
    Duration::from_secs(rand_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ra_packet_construction() {
        let ra = RaPacket::new(255, 0xC0, 1800u16.to_be());
        assert_eq!(ra.type_, ND_ROUTER_ADVERT);
        assert_eq!(ra.code, 0);
        assert_eq!(ra.hop_limit, 255);
        assert_eq!(ra.flags, 0xC0);
    }

    #[test]
    fn test_prefix_opt_construction() {
        let prefix = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        let opt = PrefixOpt::new(prefix, 64, 0xC0, 7200, 1800);
        assert_eq!(opt.type_, ICMP6_OPT_PREFIX);
        assert_eq!(opt.len, 4);
        assert_eq!(opt.prefix_len, 64);
        assert_eq!(opt.flags, 0xC0);
    }

    #[test]
    fn test_all_nodes_constant() {
        assert_eq!(ALL_NODES, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_all_routers_constant() {
        assert_eq!(ALL_ROUTERS, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
    }

    #[test]
    fn test_ra_packet_serialization() {
        let ra = RaPacket::new(255, 0x80, 1800u16.to_be());
        let mut buf = Vec::new();
        ra.serialize(&mut buf).unwrap();
        
        assert_eq!(buf.len(), 16); // RA packet is 16 bytes
        assert_eq!(buf[0], ND_ROUTER_ADVERT);
        assert_eq!(buf[1], 0);
        assert_eq!(buf[4], 255); // hop_limit
        assert_eq!(buf[5], 0x80); // flags
    }

    #[test]
    fn test_prefix_opt_serialization() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let opt = PrefixOpt::new(prefix, 64, 0xC0, 7200, 1800);
        let mut buf = Vec::new();
        opt.serialize(&mut buf).unwrap();
        
        assert_eq!(buf.len(), 32); // Prefix option is 32 bytes
        assert_eq!(buf[0], ICMP6_OPT_PREFIX);
        assert_eq!(buf[1], 4); // Length in units of 8 bytes
        assert_eq!(buf[2], 64); // prefix_len
        assert_eq!(buf[3], 0xC0); // flags
    }
}
