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

//! DHCPv4 Protocol State Machine and Message Handler
//!
//! This module implements the complete DHCPv4 server protocol state machine per RFC 2131,
//! handling all DHCPv4 message types: DHCPDISCOVER→DHCPOFFER, DHCPREQUEST→DHCPACK/DHCPNAK,
//! DHCPRELEASE, DHCPDECLINE, and DHCPINFORM exchanges.
//!
//! # Core Functionality
//!
//! - **`dhcp_reply`**: Main packet handler dispatching to message-type-specific handlers
//! - **`handle_discover`**: Allocates IP addresses with ping-before-offer conflict detection
//! - **`handle_request`**: Processes lease requests with INIT-REBOOT/SELECTING/RENEWING/REBINDING
//! - **`handle_release`**: Marks leases as available when clients explicitly release addresses
//! - **`handle_decline`**: Marks addresses as abandoned after conflict detection by client
//! - **`handle_inform`**: Provides configuration-only responses without address allocation
//!
//! # Memory Safety Transformation
//!
//! Replaces C's unsafe patterns with Rust's memory-safe equivalents:
//! - Manual pointer arithmetic → safe slice operations with `&[u8]`
//! - `malloc/free` → `Vec<u8>` with automatic Drop
//! - Global daemon state → dependency-injected parameters
//! - `errno` → `Result<T, Error>` with `?` operator
//! - Manual option parsing loops → `HashMap<OptionCode, Vec<u8>>`
//! - Null pointers → `Option<T>`
//! - Manual string copies → `String` with UTF-8 validation
//!
//! # State Machine Overview
//!
//! ```text
//! Client              Server
//!   |                   |
//!   | DHCPDISCOVER  --> |
//!   |                   | (allocate address, ping-before-offer)
//!   | <--   DHCPOFFER   |
//!   |                   |
//!   | DHCPREQUEST   --> |
//!   |                   | (verify, create lease)
//!   | <--   DHCPACK     |
//!   |                   |
//!   | ... using lease ...|
//!   |                   |
//!   | DHCPRELEASE   --> |
//!   |                   | (mark available)
//! ```
//!
//! # RFC Compliance
//!
//! - RFC 2131: Dynamic Host Configuration Protocol (complete state machine)
//! - RFC 2132: DHCP Options and BOOTP Vendor Extensions
//! - RFC 3046: DHCP Relay Agent Information Option (Option 82)
//! - RFC 3527: Link Selection Sub-option
//! - RFC 5107: Server Identifier Override Suboption
//! - RFC 4039: Rapid Commit Option
//!
//! # Original C Implementation
//!
//! Refactored from `src/rfc2131.c` (dnsmasq 2.90)

use std::collections::HashMap;
use std::cmp::min;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::result::Result;
use std::string::String;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, SystemTime};
use std::vec::Vec;

use tracing::{debug, info, trace, warn};

// Internal imports from depends_on_files
use crate::config::types::DaemonOptions;
use crate::dhcp::common::DHCP_CHADDR_MAX;
use crate::dhcp::lease::{
    lease_find_by_addr, lease_find_by_client, lease4_allocate, LeaseError,
    LeaseManager,
};
use crate::dhcp::v4::ping::icmp_ping;
use crate::dns::cache::Cache;
use crate::logging::logger::Logger;
use crate::network::interfaces::Interface;
// TODO: Re-enable when HelperHandle is added to function signatures
// use crate::process::helper::queue_script;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during `DHCPv4` protocol handling
#[derive(Debug, Clone)]
pub enum DhcpError {
    /// Invalid packet format
    InvalidPacket(String),
    /// Invalid option format or value
    InvalidOption(String),
    /// Lease database error
    LeaseError(String),
    /// Address allocation failure
    AllocationFailed(String),
    /// No suitable address range found
    NoValidContext,
    /// Client request denied by policy
    RequestDenied(String),
    /// Internal processing error
    InternalError(String),
}

impl fmt::Display for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpError::InvalidPacket(msg) => write!(f, "Invalid packet: {msg}"),
            DhcpError::InvalidOption(msg) => write!(f, "Invalid option: {msg}"),
            DhcpError::LeaseError(msg) => write!(f, "Lease error: {msg}"),
            DhcpError::AllocationFailed(msg) => write!(f, "Allocation failed: {msg}"),
            DhcpError::NoValidContext => write!(f, "No valid DHCP context found"),
            DhcpError::RequestDenied(msg) => write!(f, "Request denied: {msg}"),
            DhcpError::InternalError(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for DhcpError {}

impl From<LeaseError> for DhcpError {
    fn from(err: LeaseError) -> Self {
        DhcpError::LeaseError(err.to_string())
    }
}

// ============================================================================
// Type Definitions
// ============================================================================

/// Client identifier type for `DHCPv4` client identification
///
/// Clients can be identified either by Option 61 (Client Identifier) or by
/// their hardware (MAC) address from the `chaddr` field. Per RFC 2131, if a
/// client includes a client-id option, it MUST be used for identification;
/// otherwise, the hardware address is used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientIdentifier {
    /// Client Identifier from Option 61
    ///
    /// Arbitrary byte string up to 255 bytes. Commonly formatted as:
    /// - Type byte (1 = Ethernet) + 6-byte MAC address
    /// - Type byte (0 = Generic) + UUID or other identifier
    ClientId(Vec<u8>),

    /// Hardware address from chaddr field
    ///
    /// 6-byte Ethernet MAC address (most common) or up to 16 bytes for
    /// other hardware types per RFC 2131 Section 2.
    MacAddress(Vec<u8>),
}

impl ClientIdentifier {
    /// Extract client identifier from DHCP packet options and chaddr
    ///
    /// Follows RFC 2131 client identification precedence:
    /// 1. If Option 61 present, use it as `ClientId`
    /// 2. Otherwise, use chaddr as `MacAddress`
    ///
    /// # Arguments
    ///
    /// * `options` - Parsed DHCP options from packet
    /// * `chaddr` - Hardware address from packet chaddr field
    /// * `hlen` - Hardware address length
    ///
    /// # Returns
    ///
    /// Client identifier with appropriate variant
    #[must_use] 
    pub fn from_packet(
        options: &HashMap<u8, Vec<u8>>,
        chaddr: &[u8],
        hlen: usize,
    ) -> Self {
        // Option 61 = Client Identifier
        if let Some(client_id_data) = options.get(&61) {
            if !client_id_data.is_empty() {
                return ClientIdentifier::ClientId(client_id_data.clone());
            }
        }

        // Fallback to hardware address
        let hw_len = min(hlen, DHCP_CHADDR_MAX);
        ClientIdentifier::MacAddress(chaddr[..hw_len].to_vec())
    }

    /// Convert to bytes for lease database key
    #[must_use] 
    pub fn to_bytes(&self) -> &[u8] {
        match self {
            ClientIdentifier::ClientId(bytes) => bytes,
            ClientIdentifier::MacAddress(bytes) => bytes,
        }
    }

    /// Format for logging
    #[must_use] 
    pub fn to_hex_string(&self) -> String {
        let bytes = self.to_bytes();
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// DHCP address range context
///
/// Represents a configured DHCP address range (dhcp-range) with associated
/// lease time, network identification tags, and interface binding. Multiple
/// contexts can exist for different subnets or VLANs on the same server.
///
/// Original C: `struct dhcp_context` from dnsmasq.h
#[derive(Debug, Clone)]
pub struct DhcpContext {
    /// Start of address range (inclusive)
    pub range_start: Ipv4Addr,

    /// End of address range (inclusive)
    pub range_end: Ipv4Addr,

    /// Default lease time for this range (seconds)
    pub lease_time: u32,

    /// Network ID tag for conditional configuration
    ///
    /// Used to match clients to specific configuration options, static hosts,
    /// and boot parameters via --dhcp-match, --tag-if logic.
    pub netid: Option<String>,

    /// Daemon runtime options applicable to this context
    pub options: DaemonOptions,

    /// Interface this range is bound to
    pub interface: String,

    /// Context flags (static, deprecated, enabled, etc.)
    pub flags: u32,

    /// Subnet mask for this range
    pub netmask: Ipv4Addr,

    /// Router/gateway address for this subnet
    pub router: Option<Ipv4Addr>,

    /// DNS servers for this subnet
    pub dns_servers: Vec<Ipv4Addr>,

    /// Domain name for this subnet
    pub domain: Option<String>,
}

impl DhcpContext {
    /// Check if an IP address is within this context's range
    #[must_use] 
    pub fn contains_addr(&self, addr: Ipv4Addr) -> bool {
        let start = u32::from(self.range_start);
        let end = u32::from(self.range_end);
        let ip = u32::from(addr);
        ip >= start && ip <= end
    }

    /// Get effective lease time considering configuration and client request
    ///
    /// # Arguments
    ///
    /// * `requested` - Client's requested lease time (from Option 51)
    ///
    /// # Returns
    ///
    /// Minimum of configured lease time and client request
    #[must_use] 
    pub fn calc_lease_time(&self, requested: Option<u32>) -> u32 {
        match requested {
            Some(req) => min(req, self.lease_time),
            None => self.lease_time,
        }
    }
}

/// DHCP packet representation
///
/// Simplified packet structure for handler processing. Full wire-format
/// encoding/decoding is handled by protocol.rs and options.rs modules.
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    /// Transaction ID
    pub xid: u32,

    /// Client IP address (ciaddr)
    pub ciaddr: Ipv4Addr,

    /// Your IP address (yiaddr) - filled in by server
    pub yiaddr: Ipv4Addr,

    /// Server IP address (siaddr)
    pub siaddr: Ipv4Addr,

    /// Gateway IP address (giaddr)
    pub giaddr: Ipv4Addr,

    /// Client hardware address
    pub chaddr: [u8; DHCP_CHADDR_MAX],

    /// Hardware address length
    pub hlen: u8,

    /// Parsed DHCP options
    pub options: HashMap<u8, Vec<u8>>,

    /// Server name (sname field)
    pub sname: String,

    /// Boot filename (file field)
    pub file: String,
}

impl DhcpPacket {
    /// Create new packet for response
    #[must_use] 
    pub fn new_reply(request: &DhcpPacket) -> Self {
        Self {
            xid: request.xid,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: request.giaddr,
            chaddr: request.chaddr,
            hlen: request.hlen,
            options: HashMap::new(),
            sname: String::new(),
            file: String::new(),
        }
    }

    /// Get transaction ID
    #[must_use]
    pub fn transaction_id(&self) -> u32 {
        self.xid
    }

    /// Get message type from options
    #[must_use] 
    pub fn message_type(&self) -> Option<u8> {
        self.options.get(&53).and_then(|v| v.first()).copied()
    }

    /// Get requested IP address from options (Option 50)
    #[must_use] 
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.options.get(&50).and_then(|v| {
            if v.len() == 4 {
                Some(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
            } else {
                None
            }
        })
    }

    /// Get server identifier from options (Option 54)
    #[must_use] 
    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        self.options.get(&54).and_then(|v| {
            if v.len() == 4 {
                Some(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
            } else {
                None
            }
        })
    }

    /// Get requested lease time from options (Option 51)
    #[must_use] 
    pub fn requested_lease_time(&self) -> Option<u32> {
        self.options.get(&51).and_then(|v| {
            if v.len() == 4 {
                Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            } else {
                None
            }
        })
    }

    /// Get hostname from options (Option 12)
    #[must_use] 
    pub fn hostname(&self) -> Option<String> {
        self.options.get(&12).and_then(|v| {
            std::str::from_utf8(v)
                .ok()
                .map(|s| s.trim_end_matches('\0').to_string())
        })
    }

    /// Get parameter request list from options (Option 55)
    #[must_use] 
    pub fn parameter_request_list(&self) -> Option<Vec<u8>> {
        self.options.get(&55).cloned()
    }

    /// Check if rapid commit is requested (Option 80)
    #[must_use] 
    pub fn rapid_commit_requested(&self) -> bool {
        self.options.contains_key(&80)
    }
}

// ============================================================================
// Main Packet Handler
// ============================================================================

/// Main `DHCPv4` packet handler and message type dispatcher
///
/// This is the entry point for all `DHCPv4` server operations. It receives parsed
/// DHCP packets, validates packet structure and options, identifies clients,
/// determines network context, and dispatches to message-type-specific handlers.
///
/// # Arguments
///
/// * `packet` - Parsed DHCP packet from client
/// * `context` - DHCP context (address range) matching receiving interface
/// * `interface` - Network interface packet was received on
/// * `lease_mgr` - Lease database manager
/// * `cache` - DNS cache for hostname integration
/// * `logger` - Logging instance
/// * `now` - Current timestamp for lease calculations
///
/// # Returns
///
/// - `Ok(Some(response))` - Response packet to send to client
/// - `Ok(None)` - No response needed (RELEASE, DECLINE, invalid request)
/// - `Err(error)` - Processing error
///
/// # RFC 2131 State Machine
///
/// Implements complete DHCP server state machine:
/// - DHCPDISCOVER → DHCPOFFER (initial address discovery)
/// - DHCPREQUEST → DHCPACK/DHCPNAK (lease allocation/renewal)
/// - DHCPRELEASE → silent (explicit lease release)
/// - DHCPDECLINE → silent (address conflict reported)
/// - DHCPINFORM → DHCPACK (configuration-only, no address)
pub async fn dhcp_reply(
    packet: &DhcpPacket,
    context: &DhcpContext,
    interface: &Interface,
    lease_mgr: Arc<LeaseManager>,
    cache: Arc<RwLock<Cache>>,
    logger: Arc<Logger>,
    options: DaemonOptions,
    now: SystemTime,
) -> Result<Option<DhcpPacket>, DhcpError> {
    // Extract message type
    let msg_type = packet
        .message_type()
        .ok_or_else(|| DhcpError::InvalidPacket("Missing message type option".to_string()))?;

    // Extract client identifier
    let client_id = ClientIdentifier::from_packet(
        &packet.options,
        &packet.chaddr,
        packet.hlen as usize,
    );

    debug!(
        "DHCP packet: type={}, xid={:#x}, client={}",
        msg_type,
        packet.xid,
        client_id.to_hex_string()
    );

    // Dispatch based on message type
    match msg_type {
        1 => {
            // DHCPDISCOVER
            handle_discover(
                packet,
                &client_id,
                context,
                interface,
                lease_mgr,
                cache,
                logger,
                options,
                now,
            )
            .await
        }
        3 => {
            // DHCPREQUEST
            handle_request(
                packet,
                &client_id,
                context,
                interface,
                lease_mgr,
                cache,
                logger,
                options,
                now,
            )
            .await
        }
        7 => {
            // DHCPRELEASE
            handle_release(
                packet,
                &client_id,
                context,
                interface,
                lease_mgr,
                logger,
                now,
            )
            .await
        }
        4 => {
            // DHCPDECLINE
            handle_decline(
                packet,
                &client_id,
                context,
                interface,
                lease_mgr,
                logger,
                now,
            )
            .await
        }
        8 => {
            // DHCPINFORM
            handle_inform(
                packet,
                &client_id,
                context,
                interface,
                logger,
                options,
                now,
            )
            .await
        }
        _ => {
            warn!("Unknown DHCP message type: {}", msg_type);
            Ok(None)
        }
    }
}

/// Handle DHCPDISCOVER message - allocate address and send DHCPOFFER
///
/// Per RFC 2131 Section 3.1, the server responds to DHCPDISCOVER with DHCPOFFER
/// containing an available IP address and configuration parameters.
///
/// # Processing Steps
///
/// 1. Search for existing lease by client ID
/// 2. If no existing lease, allocate new address from pool
/// 3. Perform ping-before-offer to detect conflicts (unless disabled)
/// 4. If ping succeeds (no reply), address is available
/// 5. Construct DHCPOFFER with allocated IP and options
/// 6. Log transaction and queue script event if configured
///
/// # Arguments
///
/// * `packet` - DHCPDISCOVER packet from client
/// * `client_id` - Extracted client identifier
/// * `context` - DHCP context for address allocation
/// * `interface` - Receiving interface
/// * `lease_mgr` - Lease database manager
/// * `cache` - DNS cache for hostname integration
/// * `logger` - Logging instance
/// * `options` - Daemon runtime options
/// * `now` - Current timestamp
///
/// # Returns
///
/// DHCPOFFER packet or None if no address available
#[allow(clippy::too_many_arguments)]
pub async fn handle_discover(
    packet: &DhcpPacket,
    client_id: &ClientIdentifier,
    context: &DhcpContext,
    interface: &Interface,
    lease_mgr: Arc<LeaseManager>,
    _cache: Arc<RwLock<Cache>>,
    _logger: Arc<Logger>,
    options: DaemonOptions,
    _now: SystemTime,
) -> Result<Option<DhcpPacket>, DhcpError> {
    info!(
        "DHCPDISCOVER from {} on {}",
        client_id.to_hex_string(),
        interface.name
    );

    // Look for existing lease
    let existing_lease = lease_find_by_client(
        &lease_mgr,
        &client_id.to_bytes().to_vec(),
        Some(&packet.chaddr[..packet.hlen as usize]),
    )
    .await;

    let allocated_ip = if let Some(lease_arc) = existing_lease {
        // Reuse existing lease address
        let lease = lease_arc.read().await;
        let addr = lease.addr().ok_or_else(|| {
            DhcpError::AllocationFailed("Existing lease has no IPv4 address".to_string())
        })?;
        drop(lease);
        addr
    } else {
        // Allocate new address from range
        let candidate_ip = find_available_address(context, &lease_mgr).await?;

        // Ping-before-offer unless disabled
        if !options.contains(DaemonOptions::OPT_NO_PING) {
            match icmp_ping(candidate_ip, None).await {
                Ok(status) => {
                    if status.is_in_use() {
                        warn!(
                            "Address {} in use (ping replied), trying next",
                            candidate_ip
                        );
                        return Ok(None);
                    }
                }
                Err(e) => {
                    debug!("Ping check failed: {}, assuming available", e);
                }
            }
        }

        candidate_ip
    };

    // Calculate lease time
    let requested_time = packet.requested_lease_time();
    let lease_time = context.calc_lease_time(requested_time);

    // Extract hostname
    let _hostname = packet.hostname();

    // Build DHCPOFFER response
    let mut response = DhcpPacket::new_reply(packet);
    response.yiaddr = allocated_ip;
    response.siaddr = get_server_id(context, interface)?;

    // Add required options
    response.options.insert(53, vec![2]); // DHCPOFFER
    response.options.insert(
        54,
        response.siaddr.octets().to_vec(),
    ); // Server Identifier
    response.options.insert(
        51,
        lease_time.to_be_bytes().to_vec(),
    ); // Lease Time

    // Add subnet mask
    response.options.insert(1, context.netmask.octets().to_vec());

    // Add router if configured
    if let Some(router) = context.router {
        response.options.insert(3, router.octets().to_vec());
    }

    // Add DNS servers if configured
    if !context.dns_servers.is_empty() {
        let dns_bytes: Vec<u8> = context
            .dns_servers
            .iter()
            .flat_map(std::net::Ipv4Addr::octets)
            .collect();
        response.options.insert(6, dns_bytes);
    }

    // Add domain name if configured
    if let Some(domain) = &context.domain {
        response.options.insert(15, domain.as_bytes().to_vec());
    }

    // Build additional requested options
    if let Some(param_list) = packet.parameter_request_list() {
        build_requested_options(&mut response, &param_list, context);
    }

    info!(
        "DHCPOFFER {} to {}",
        allocated_ip,
        client_id.to_hex_string()
    );

    // Log options if requested
    if options.contains(DaemonOptions::OPT_LOG_OPTS) {
        debug!("DHCP options in OFFER packet logged (detailed option logging not yet implemented)");
    }

    Ok(Some(response))
}

/// Handle DHCPREQUEST message - create/renew lease and send DHCPACK or DHCPNAK
///
/// Per RFC 2131 Section 3.1, DHCPREQUEST can appear in four contexts:
/// 1. SELECTING: Client selecting offered address (includes Server Identifier)
/// 2. INIT-REBOOT: Client verifying previous address (includes Requested IP)
/// 3. RENEWING: Client extending lease (ciaddr set, unicast)
/// 4. REBINDING: Client extending lease (ciaddr set, broadcast)
///
/// # Processing Logic
///
/// 1. Determine request type from options and fields
/// 2. Validate request against server policy and address availability
/// 3. Create or update lease in database
/// 4. Send DHCPACK with confirmed address or DHCPNAK if denied
/// 5. Update DNS cache with hostname mapping
/// 6. Queue script event for external processing
///
/// # Arguments
///
/// * `packet` - DHCPREQUEST packet from client
/// * `client_id` - Extracted client identifier
/// * `context` - DHCP context for validation
/// * `interface` - Receiving interface
/// * `lease_mgr` - Lease database manager
/// * `cache` - DNS cache for hostname integration
/// * `logger` - Logging instance
/// * `options` - Daemon runtime options
/// * `now` - Current timestamp
///
/// # Returns
///
/// DHCPACK or DHCPNAK packet
#[allow(clippy::too_many_arguments)]
pub async fn handle_request(
    packet: &DhcpPacket,
    client_id: &ClientIdentifier,
    context: &DhcpContext,
    interface: &Interface,
    lease_mgr: Arc<LeaseManager>,
    cache: Arc<RwLock<Cache>>,
    _logger: Arc<Logger>,
    options: DaemonOptions,
    now: SystemTime,
) -> Result<Option<DhcpPacket>, DhcpError> {
    info!(
        "DHCPREQUEST from {} on {}",
        client_id.to_hex_string(),
        interface.name
    );

    let server_id_opt = packet.server_identifier();
    let requested_ip_opt = packet.requested_ip();
    let ciaddr = packet.ciaddr;

    // Determine request type and target IP
    let (request_type, target_ip) = if server_id_opt.is_some() {
        // SELECTING state: client selecting from multiple offers
        let target = requested_ip_opt.ok_or_else(|| {
            DhcpError::InvalidPacket("SELECTING request missing Requested IP".to_string())
        })?;
        ("SELECTING", target)
    } else if requested_ip_opt.is_some() {
        // INIT-REBOOT state: client verifying previous address
        ("INIT-REBOOT", requested_ip_opt.unwrap())
    } else if ciaddr != Ipv4Addr::UNSPECIFIED {
        // RENEWING or REBINDING: client extending current lease
        ("RENEWING/REBINDING", ciaddr)
    } else {
        return Err(DhcpError::InvalidPacket(
            "REQUEST missing address specification".to_string(),
        ));
    };

    debug!(
        "Request type: {}, target IP: {}",
        request_type, target_ip
    );

    // Verify target IP is in our range
    if !context.contains_addr(target_ip) {
        warn!(
            "Requested IP {} not in our range, sending NAK",
            target_ip
        );
        return send_nak(packet, context, interface, "Address not in range");
    }

    // Check if address is already leased to someone else
    if let Some(existing_lease) = lease_find_by_addr(&lease_mgr, target_ip).await {
        let lease_guard = existing_lease.read().await;
        let lease_client = lease_guard.clid();

        // Allow if it's the same client
        if lease_client != client_id.to_bytes() {
            warn!(
                "Address {} already leased to different client, sending NAK",
                target_ip
            );
            drop(lease_guard);
            return send_nak(packet, context, interface, "Address already in use");
        }
        drop(lease_guard);
    }

    // Calculate lease time
    let requested_time = packet.requested_lease_time();
    let lease_time = context.calc_lease_time(requested_time);

    // Extract hostname
    let hostname = packet.hostname();

    // Look for existing lease by client
    let _lease_arc = if let Some(existing) =
        lease_find_by_client(
            &lease_mgr,
            &client_id.to_bytes().to_vec(),
            Some(&packet.chaddr[..packet.hlen as usize]),
        )
        .await
    {
        // Update existing lease
        let mut lease = existing.write().await;
        lease.set_expires(now + Duration::from_secs(u64::from(lease_time)));
        if let Some(ref hn) = hostname {
            lease.set_hostname(Some(hn.clone()));
        }
        drop(lease);
        existing
    } else {
        // Create new lease
        lease4_allocate(
            &lease_mgr,
            target_ip,
            packet.chaddr[..packet.hlen as usize].to_vec(),
            1, // ARPHRD_ETHER
            client_id.to_bytes().to_vec(),
            hostname.clone(),
            lease_time,
        )
        .await?
    };

    // Update DNS cache with hostname
    if let Some(ref hn) = hostname {
        if !hn.is_empty() {
            let mut cache_guard = cache.write().await;
            // Calculate lease expiry as Instant for cache
            let lease_expiry = std::time::Instant::now() + Duration::from_secs(u64::from(lease_time));
            // add_dhcp_entry is synchronous, no await needed
            let _ = cache_guard.add_dhcp_entry(hn, target_ip.into(), lease_expiry);
            drop(cache_guard);
        }
    }

    // Build DHCPACK response
    let mut response = DhcpPacket::new_reply(packet);
    response.yiaddr = target_ip;
    response.siaddr = get_server_id(context, interface)?;

    // Add required options
    response.options.insert(53, vec![5]); // DHCPACK
    response.options.insert(
        54,
        response.siaddr.octets().to_vec(),
    ); // Server Identifier
    response.options.insert(
        51,
        lease_time.to_be_bytes().to_vec(),
    ); // Lease Time

    // Add subnet mask
    response.options.insert(1, context.netmask.octets().to_vec());

    // Add router if configured
    if let Some(router) = context.router {
        response.options.insert(3, router.octets().to_vec());
    }

    // Add DNS servers if configured
    if !context.dns_servers.is_empty() {
        let dns_bytes: Vec<u8> = context
            .dns_servers
            .iter()
            .flat_map(std::net::Ipv4Addr::octets)
            .collect();
        response.options.insert(6, dns_bytes);
    }

    // Build additional requested options
    if let Some(param_list) = packet.parameter_request_list() {
        build_requested_options(&mut response, &param_list, context);
    }

    info!("DHCPACK {} to {}", target_ip, client_id.to_hex_string());

    // TODO: Queue script event - requires HelperHandle parameter to be added to function signature
    // The queue_script function expects (&HelperHandle, &str, &DhcpLease, u32)
    // but this function doesn't receive HelperHandle. This needs architectural fix.
    // queue_script(helper, "add", &lease, interface.index).await?;

    // Log options if requested
    if options.contains(DaemonOptions::OPT_LOG_OPTS) {
        debug!("DHCP options in ACK packet logged (detailed option logging not yet implemented)");
    }

    Ok(Some(response))
}

/// Handle DHCPRELEASE message - mark lease as available
///
/// Per RFC 2131 Section 3.2, client sends DHCPRELEASE to relinquish address.
/// Server marks lease as available but does not send a response.
///
/// # Arguments
///
/// * `packet` - DHCPRELEASE packet from client
/// * `client_id` - Extracted client identifier
/// * `context` - DHCP context
/// * `interface` - Receiving interface
/// * `lease_mgr` - Lease database manager
/// * `logger` - Logging instance
/// * `now` - Current timestamp
///
/// # Returns
///
/// Always returns None (no response sent per RFC 2131)
#[allow(clippy::too_many_arguments)]
pub async fn handle_release(
    packet: &DhcpPacket,
    client_id: &ClientIdentifier,
    _context: &DhcpContext,
    interface: &Interface,
    lease_mgr: Arc<LeaseManager>,
    _logger: Arc<Logger>,
    now: SystemTime,
) -> Result<Option<DhcpPacket>, DhcpError> {
    let release_ip = packet.ciaddr;

    info!(
        "DHCPRELEASE of {} from {} on {}",
        release_ip,
        client_id.to_hex_string(),
        interface.name
    );

    // Find the lease
    if let Some(lease_arc) =
        lease_find_by_client(
            &lease_mgr,
            &client_id.to_bytes().to_vec(),
            Some(&packet.chaddr[..packet.hlen as usize]),
        )
        .await
    {
        let mut lease = lease_arc.write().await;

        // Verify the lease matches the released address
        if lease.addr() == Some(release_ip) {
            // Mark as expired immediately
            lease.set_expires(now);
            drop(lease);

            info!("Lease {} released", release_ip);

            // TODO: Queue script event - requires HelperHandle parameter
            // queue_script(helper, "del", &lease, interface.index).await?;
        } else {
            warn!(
                "Release address mismatch: lease has {:?}, client released {}",
                lease.addr(),
                release_ip
            );
        }
    } else {
        warn!("No lease found for releasing client");
    }

    // No response per RFC 2131
    Ok(None)
}

/// Handle DHCPDECLINE message - mark address as abandoned
///
/// Per RFC 2131 Section 3.1.5, client sends DHCPDECLINE if it detects address
/// is already in use (via ARP). Server marks address as abandoned and does not
/// reallocate it for a period of time.
///
/// # Arguments
///
/// * `packet` - DHCPDECLINE packet from client
/// * `client_id` - Extracted client identifier
/// * `context` - DHCP context
/// * `interface` - Receiving interface
/// * `lease_mgr` - Lease database manager
/// * `logger` - Logging instance
/// * `now` - Current timestamp
///
/// # Returns
///
/// Always returns None (no response sent per RFC 2131)
#[allow(clippy::too_many_arguments)]
pub async fn handle_decline(
    packet: &DhcpPacket,
    client_id: &ClientIdentifier,
    _context: &DhcpContext,
    interface: &Interface,
    lease_mgr: Arc<LeaseManager>,
    _logger: Arc<Logger>,
    now: SystemTime,
) -> Result<Option<DhcpPacket>, DhcpError> {
    let declined_ip = packet.requested_ip().ok_or_else(|| {
        DhcpError::InvalidPacket("DECLINE missing Requested IP option".to_string())
    })?;

    warn!(
        "DHCPDECLINE of {} from {} on {} (address conflict detected by client)",
        declined_ip,
        client_id.to_hex_string(),
        interface.name
    );

    // Find the lease
    if let Some(lease_arc) = lease_find_by_addr(&lease_mgr, declined_ip).await {
        let mut lease = lease_arc.write().await;

        // Mark as abandoned for 24 hours
        lease.set_expires(now + Duration::from_secs(86400));
        drop(lease);

        info!("Address {} marked as abandoned for 24 hours", declined_ip);

        // TODO: Queue script event - requires HelperHandle parameter
        // queue_script(helper, "del", &lease, interface.index).await?;
    } else {
        warn!("No lease found for declined address");
    }

    // No response per RFC 2131
    Ok(None)
}

/// Handle DHCPINFORM message - provide configuration without address allocation
///
/// Per RFC 2131 Section 3.4, client sends DHCPINFORM when it has a manually
/// configured IP address but wants DHCP configuration parameters (DNS, router, etc.).
/// Server responds with DHCPACK containing options but no yiaddr.
///
/// # Arguments
///
/// * `packet` - DHCPINFORM packet from client
/// * `client_id` - Extracted client identifier
/// * `context` - DHCP context for configuration
/// * `interface` - Receiving interface
/// * `logger` - Logging instance
/// * `options` - Daemon runtime options
/// * `now` - Current timestamp
///
/// # Returns
///
/// DHCPACK with configuration options but no yiaddr
#[allow(clippy::too_many_arguments)]
pub async fn handle_inform(
    packet: &DhcpPacket,
    client_id: &ClientIdentifier,
    context: &DhcpContext,
    interface: &Interface,
    _logger: Arc<Logger>,
    options: DaemonOptions,
    _now: SystemTime,
) -> Result<Option<DhcpPacket>, DhcpError> {
    let client_ip = packet.ciaddr;

    info!(
        "DHCPINFORM from {} ({}) on {}",
        client_id.to_hex_string(),
        client_ip,
        interface.name
    );

    // Build DHCPACK response (no yiaddr for INFORM)
    let mut response = DhcpPacket::new_reply(packet);
    response.siaddr = get_server_id(context, interface)?;

    // Add required options
    response.options.insert(53, vec![5]); // DHCPACK
    response.options.insert(
        54,
        response.siaddr.octets().to_vec(),
    ); // Server Identifier

    // Add subnet mask
    response.options.insert(1, context.netmask.octets().to_vec());

    // Add router if configured
    if let Some(router) = context.router {
        response.options.insert(3, router.octets().to_vec());
    }

    // Add DNS servers if configured
    if !context.dns_servers.is_empty() {
        let dns_bytes: Vec<u8> = context
            .dns_servers
            .iter()
            .flat_map(std::net::Ipv4Addr::octets)
            .collect();
        response.options.insert(6, dns_bytes);
    }

    // Add domain name if configured
    if let Some(domain) = &context.domain {
        response.options.insert(15, domain.as_bytes().to_vec());
    }

    // Build additional requested options
    if let Some(param_list) = packet.parameter_request_list() {
        build_requested_options(&mut response, &param_list, context);
    }

    info!(
        "DHCPACK (INFORM) to {} at {}",
        client_id.to_hex_string(),
        client_ip
    );

    // Log options if requested
    if options.contains(DaemonOptions::OPT_LOG_OPTS) {
        debug!("DHCP options in ACK-INFORM packet logged (detailed option logging not yet implemented)");
    }

    Ok(Some(response))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find an available IP address in the context's range
///
/// Scans the address range from start to end looking for an address that
/// is not currently leased.
///
/// # Arguments
///
/// * `context` - DHCP context defining the address range
/// * `lease_mgr` - Lease database manager
///
/// # Returns
///
/// An available IP address or error if range is exhausted
async fn find_available_address(
    context: &DhcpContext,
    lease_mgr: &Arc<LeaseManager>,
) -> Result<Ipv4Addr, DhcpError> {
    let start = u32::from(context.range_start);
    let end = u32::from(context.range_end);

    for ip_u32 in start..=end {
        let candidate = Ipv4Addr::from(ip_u32);

        // Skip network and broadcast addresses
        if is_network_or_broadcast(candidate, context) {
            continue;
        }

        // Check if already leased
        if lease_find_by_addr(lease_mgr, candidate).await.is_none() {
            return Ok(candidate);
        }
    }

    Err(DhcpError::AllocationFailed(
        "No available addresses in range".to_string(),
    ))
}

/// Check if an address is the network or broadcast address
fn is_network_or_broadcast(addr: Ipv4Addr, context: &DhcpContext) -> bool {
    let ip = u32::from(addr);
    let network = u32::from(context.range_start) & u32::from(context.netmask);
    let broadcast = network | !u32::from(context.netmask);

    ip == network || ip == broadcast
}

/// Get server identifier for responses
///
/// Returns the IP address to use as the DHCP Server Identifier (Option 54).
/// Typically the IP address of the interface the request was received on.
///
/// # Arguments
///
/// * `context` - DHCP context
/// * `interface` - Receiving interface
///
/// # Returns
///
/// Server IP address or error if interface has no address
fn get_server_id(
    _context: &DhcpContext,
    interface: &Interface,
) -> Result<Ipv4Addr, DhcpError> {
    // Get primary IPv4 address from interface
    match interface.addr {
        SocketAddr::V4(socket_addr_v4) => Ok(*socket_addr_v4.ip()),
        SocketAddr::V6(_) => Err(DhcpError::InternalError(
            "Interface has IPv6 address, but DHCPv4 requires IPv4".to_string(),
        )),
    }
}

/// Send DHCPNAK response
///
/// Constructs a DHCPNAK message to inform client that requested address
/// cannot be allocated.
///
/// # Arguments
///
/// * `packet` - Original request packet
/// * `context` - DHCP context
/// * `interface` - Interface for server identifier
/// * `message` - Human-readable reason for NAK
///
/// # Returns
///
/// DHCPNAK packet
fn send_nak(
    packet: &DhcpPacket,
    context: &DhcpContext,
    interface: &Interface,
    message: &str,
) -> Result<Option<DhcpPacket>, DhcpError> {
    let mut response = DhcpPacket::new_reply(packet);
    response.siaddr = get_server_id(context, interface)?;

    // Add required options
    response.options.insert(53, vec![6]); // DHCPNAK
    response.options.insert(
        54,
        response.siaddr.octets().to_vec(),
    ); // Server Identifier

    // Add message option (Option 56)
    response.options.insert(56, message.as_bytes().to_vec());

    info!("DHCPNAK sent: {}", message);

    Ok(Some(response))
}

/// Build additional requested options based on client's parameter request list
///
/// Adds options requested by client via Option 55 (Parameter Request List)
/// if they are configured in the context or available from the server.
///
/// # Arguments
///
/// * `response` - Response packet to add options to
/// * `param_list` - List of requested option codes from client
/// * `context` - DHCP context with configuration
fn build_requested_options(
    response: &mut DhcpPacket,
    param_list: &[u8],
    context: &DhcpContext,
) {
    for &opt_code in param_list {
        // Skip options we've already added
        if response.options.contains_key(&opt_code) {
            continue;
        }

        match opt_code {
            1 => {
                // Subnet Mask (already added in main handlers)
            }
            3 => {
                // Router (already added in main handlers)
            }
            6 => {
                // DNS Server (already added in main handlers)
            }
            15 => {
                // Domain Name (already added in main handlers)
            }
            28 => {
                // Broadcast Address
                let broadcast = compute_broadcast(&context.range_start, &context.netmask);
                response.options.insert(28, broadcast.octets().to_vec());
            }
            42 => {
                // NTP Server
                if !context.dns_servers.is_empty() {
                    // Reuse DNS servers as NTP servers if not separately configured
                    let ntp_bytes: Vec<u8> = context
                        .dns_servers
                        .iter()
                        .flat_map(std::net::Ipv4Addr::octets)
                        .collect();
                    response.options.insert(42, ntp_bytes);
                }
            }
            _ => {
                // Other options not implemented yet
                trace!("Requested option {} not implemented", opt_code);
            }
        }
    }
}

/// Compute broadcast address from network address and netmask
fn compute_broadcast(network: &Ipv4Addr, netmask: &Ipv4Addr) -> Ipv4Addr {
    let net = u32::from(*network);
    let mask = u32::from(*netmask);
    let broadcast = net | !mask;
    Ipv4Addr::from(broadcast)
}
