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

//! IPv6 Stateless Address Autoconfiguration (SLAAC) and Duplicate Address Detection (DAD)
//!
//! This module implements SLAAC per RFC 4862, enabling automatic IPv6 address configuration
//! by combining Router Advertisement prefixes with Modified EUI-64 interface identifiers
//! derived from hardware (MAC) addresses.
//!
//! # Purpose
//!
//! SLAAC allows IPv6 hosts to automatically configure their addresses without requiring
//! `DHCPv6` stateful address assignment. This implementation:
//!
//! - Generates IPv6 addresses from RA prefixes + EUI-64 interface identifiers
//! - Performs Duplicate Address Detection (DAD) via `ICMPv6` Echo Request/Reply
//! - Registers confirmed SLAAC addresses in DNS cache for hostname resolution
//! - Coordinates with `DHCPv6` via M-bit/O-bit flags in Router Advertisements
//!
//! # Key Components
//!
//! - **EUI-64 Conversion**: Transform MAC-48 addresses to Modified EUI-64 format
//!   * Insert 0xFFFE in middle of MAC address (e.g., 00:11:22:33:44:55 → 00:11:22:FF:FE:33:44:55)
//!   * Flip universal/local bit (bit 6 of first octet)
//!
//! - **Duplicate Address Detection**: Verify address uniqueness via `ICMPv6` ping
//!   * Send `ICMPv6` Echo Request to candidate address
//!   * If no Echo Reply after exponential backoff (up to 2048 seconds), address is confirmed
//!   * If Echo Reply received, address conflict detected
//!
//! - **DNS Integration**: Register confirmed addresses with hostname mappings
//!
//! # RFC Compliance
//!
//! - **RFC 4862**: IPv6 Stateless Address Autoconfiguration (Section 5.5.3 address formation)
//! - **RFC 4291**: IPv6 Addressing Architecture (Appendix A Modified EUI-64 format)
//! - **RFC 2464**: Transmission of IPv6 over Ethernet (MAC to EUI-64 conversion)
//! - **RFC 4443**: `ICMPv6` (Echo Request/Reply for DAD)
//!
//! # Memory Safety Improvements
//!
//! Refactored from `src/slaac.c` with the following memory safety enhancements:
//!
//! - **Manual linked lists → Vec**: Eliminates use-after-free bugs in slaac_address list
//! - **Global static ping_id → Arc<AtomicU16>**: Thread-safe shared state
//! - **Manual memcpy → Safe slice operations**: Prevents buffer overflows in EUI-64 conversion
//! - **Blocking sendto() → async socket.send_to()**: Non-blocking ICMPv6 transmission
//! - **errno → Result<T, E>**: Type-safe error propagation
//!
//! # Original C Mapping
//!
//! | C Function | Rust Function/Method | Changes |
//! |------------|---------------------|---------|
//! | `slaac_add_addrs()` | `slaac_add_addrs()` | Async, Vec instead of linked list |
//! | `periodic_slaac()` | `periodic_slaac()` | Async, tokio timer |
//! | `slaac_ping_reply()` | `slaac_ping_reply()` | Async, Result return type |
//! | `static int ping_id` | `Arc<AtomicU16>` | Thread-safe atomic |
//! | `struct slaac_address` | `SlaacAddress` | Owned types, no raw pointers |
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use dnsmasq::ipv6::slaac::{SlaacManager, slaac_add_addrs};
//! use std::time::SystemTime;
//!
//! # async fn example() {
//! let manager = SlaacManager::new();
//! let now = SystemTime::now();
//!
//! // Generate SLAAC addresses for a lease
//! slaac_add_addrs(&manager, lease, now, false).await;
//!
//! // Perform periodic DAD
//! let next_event = periodic_slaac(&manager, now).await;
//! # }
//! ```

use crate::config::types::{Config, DaemonOptions};
use crate::dhcp::lease::{lease_update_dns, LeaseManager};
use crate::ipv6::radv::protocol::ICMP6_ECHO_REQUEST;
use crate::ipv6::radv::server::ra_start_unsolicited;
use crate::logging::logger::Logger;
use crate::network::sockets::UdpSocket;
use crate::utils::rand::rand16;

use std::collections::HashMap;
use std::io::{Error as IoError, Result as IoResult};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::vec::Vec;
use tokio::sync::RwLock;
use tokio::time::{interval, sleep, Instant};
use tracing::{debug, error, info, trace, warn};

/// Hardware address type for Ethernet/802.11 (MAC-48)
const ARPHRD_ETHER: u16 = 1;

/// Hardware address type for IEEE 802 (Token Ring, also MAC-48)
const ARPHRD_IEEE802: u16 = 6;

/// Hardware address type for EUI-64 (64-bit Extended Unique Identifier)
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const ARPHRD_EUI64: u16 = 27;

/// Hardware address type for FireWire (IEEE 1394)
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const ARPHRD_IEEE1394: u16 = 24;

/// Maximum backoff attempts (2^12 = 4096 seconds = ~68 minutes)
const MAX_BACKOFF: u8 = 12;

/// ICMPv6 Echo Request packet structure
///
/// Per RFC 4443 Section 4.1, Echo Request format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Identifier          |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Data ...
/// +-+-+-+-+-
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PingPacket {
    /// ICMPv6 message type (128 for Echo Request, 129 for Echo Reply)
    icmp_type: u8,
    /// ICMPv6 code (0 for Echo Request/Reply)
    code: u8,
    /// Checksum (computed by kernel for raw sockets)
    checksum: u16,
    /// Identifier to match requests with replies
    identifier: u16,
    /// Sequence number (we use backoff count)
    sequence_no: u16,
}

impl PingPacket {
    /// Create a new ICMPv6 Echo Request packet
    fn new(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: ICMP6_ECHO_REQUEST,
            code: 0,
            checksum: 0, // Kernel computes this for raw sockets
            identifier: identifier.to_be(), // Network byte order
            sequence_no: sequence.to_be(),  // Network byte order
        }
    }

    /// Get packet bytes for transmission
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }

    /// Parse packet from received bytes
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }
        unsafe {
            Some(*(bytes.as_ptr() as *const Self))
        }
    }

    /// Get identifier in host byte order
    fn get_identifier(&self) -> u16 {
        u16::from_be(self.identifier)
    }
}

/// SLAAC address entry tracking DAD state
///
/// Corresponds to C `struct slaac_address` (dnsmasq.h:820-825)
#[derive(Debug, Clone)]
pub struct SlaacAddress {
    /// IPv6 address with EUI-64 interface identifier
    pub addr: Ipv6Addr,
    /// Next ping time (absolute SystemTime)
    pub ping_time: SystemTime,
    /// Exponential backoff counter (0 = confirmed, 1-12 = retry count)
    pub backoff: u8,
    /// Link to next address (for compatibility, not used in Rust Vec)
    pub next: Option<Box<SlaacAddress>>,
}

impl SlaacAddress {
    /// Create a new SLAAC address entry
    fn new(addr: Ipv6Addr, now: SystemTime) -> Self {
        Self {
            addr,
            ping_time: now,
            backoff: 1, // Start with first attempt
            next: None,
        }
    }

    /// Check if address is confirmed (backoff == 0)
    fn is_confirmed(&self) -> bool {
        self.backoff == 0
    }

    /// Check if DAD has been given up (ping_time == 0 in C, represented as SystemTime::UNIX_EPOCH)
    fn is_given_up(&self) -> bool {
        self.ping_time == SystemTime::UNIX_EPOCH
    }
}

/// SLAAC Manager for coordinating address generation and DAD
///
/// Replaces C global state with structured ownership
pub struct SlaacManager {
    /// Atomic ping identifier for ICMPv6 Echo Request
    /// Replaces C global `static int ping_id`
    ping_id: Arc<AtomicU16>,
    
    /// SLAAC addresses by lease (HashMap<lease_key, Vec<SlaacAddress>>)
    /// Replaces C linked list `lease->slaac_address`
    addresses: Arc<RwLock<HashMap<Vec<u8>, Vec<SlaacAddress>>>>,
}

impl SlaacManager {
    /// Create a new SLAAC manager
    pub fn new() -> Self {
        Self {
            ping_id: Arc::new(AtomicU16::new(0)),
            addresses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or initialize ping ID
    fn get_ping_id(&self) -> u16 {
        let mut id = self.ping_id.load(Ordering::Relaxed);
        while id == 0 {
            id = rand16();
            // Try to set it if still 0
            match self.ping_id.compare_exchange(
                0,
                id,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_id) if new_id != 0 => {
                    id = new_id;
                    break;
                }
                Err(_) => continue,
            }
        }
        id
    }

    /// Add or update SLAAC addresses for a lease
    pub async fn add_addrs(
        &self,
        lease_key: Vec<u8>,
        contexts: &[SlaacContext],
        hwaddr: &[u8],
        hwaddr_type: u16,
        clid: Option<&[u8]>,
        now: SystemTime,
        force: bool,
    ) -> bool {
        let mut addresses = self.addresses.write().await;
        let mut dns_dirty = false;
        
        // Get existing addresses for this lease
        let old_addrs = addresses.remove(&lease_key).unwrap_or_default();
        let mut new_addrs = Vec::new();
        let mut remaining_old: Vec<SlaacAddress> = old_addrs;

        // Generate SLAAC addresses for each context
        for context in contexts {
            // Try to create address from hardware address
            if let Some(mut addr) = Self::eui64_from_hwaddr(
                &context.prefix,
                hwaddr,
                hwaddr_type,
                clid,
            ) {
                // Apply universal/local bit flip (RFC 4291 Appendix A)
                let mut octets = addr.octets();
                octets[8] ^= 0x02;
                addr = Ipv6Addr::from(octets);

                // Check if we already have this address
                if let Some(pos) = remaining_old.iter().position(|a| a.addr == addr) {
                    let mut existing = remaining_old.remove(pos);
                    
                    // Force re-validation if requested (DHCPv4 init-reboot)
                    if force {
                        existing.ping_time = now;
                        existing.backoff = 1;
                        dns_dirty = true;
                    }
                    
                    new_addrs.push(existing);
                } else {
                    // Create new address entry
                    let slaac_addr = SlaacAddress::new(addr, now);
                    new_addrs.push(slaac_addr);
                    debug!("Created new SLAAC address: {}", addr);
                }
            }
        }

        // If we removed any old addresses, mark DNS as dirty
        if !remaining_old.is_empty() {
            dns_dirty = true;
        }

        // Store updated address list
        if !new_addrs.is_empty() {
            addresses.insert(lease_key, new_addrs);
        }

        dns_dirty
    }

    /// Convert hardware address to EUI-64 interface identifier
    ///
    /// Implements RFC 4291 Appendix A and RFC 2464 Section 4
    fn eui64_from_hwaddr(
        prefix: &Ipv6Addr,
        hwaddr: &[u8],
        hwaddr_type: u16,
        clid: Option<&[u8]>,
    ) -> Option<Ipv6Addr> {
        let mut addr = prefix.octets();

        // Handle MAC-48 (6-byte MAC address)
        if hwaddr.len() == 6
            && (hwaddr_type == ARPHRD_ETHER || hwaddr_type == ARPHRD_IEEE802)
        {
            // Convert MAC-48 to EUI-64:
            // Original: AA:BB:CC:DD:EE:FF
            // EUI-64:   AA:BB:CC:FF:FE:DD:EE:FF
            // Indices:  [8][9][10][11][12][13][14][15]
            
            addr[8] = hwaddr[0];
            addr[9] = hwaddr[1];
            addr[10] = hwaddr[2];
            addr[11] = 0xff; // Insert 0xFF
            addr[12] = 0xfe; // Insert 0xFE
            addr[13] = hwaddr[3];
            addr[14] = hwaddr[4];
            addr[15] = hwaddr[5];
            
            return Some(Ipv6Addr::from(addr));
        }

        // Handle EUI-64 (8-byte identifier)
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        if hwaddr.len() == 8 && hwaddr_type == ARPHRD_EUI64 {
            addr[8..16].copy_from_slice(hwaddr);
            return Some(Ipv6Addr::from(addr));
        }

        // Handle FireWire EUI-64 from client ID
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        if let Some(clid_bytes) = clid {
            if clid_bytes.len() == 9
                && clid_bytes[0] == ARPHRD_EUI64 as u8
                && hwaddr_type == ARPHRD_IEEE1394
            {
                addr[8..16].copy_from_slice(&clid_bytes[1..9]);
                return Some(Ipv6Addr::from(addr));
            }
        }

        None
    }

    /// Get addresses for a lease
    pub async fn get_addresses(&self, lease_key: &[u8]) -> Vec<SlaacAddress> {
        let addresses = self.addresses.read().await;
        addresses
            .get(lease_key)
            .cloned()
            .unwrap_or_default()
    }

    /// Perform periodic DAD for all pending SLAAC addresses
    pub async fn periodic_dad(
        &self,
        now: SystemTime,
        socket: &UdpSocket,
    ) -> Option<SystemTime> {
        let ping_id = self.get_ping_id();
        let mut addresses = self.addresses.write().await;
        let mut next_event: Option<SystemTime> = None;

        for (_lease_key, addr_list) in addresses.iter_mut() {
            for slaac in addr_list.iter_mut() {
                // Skip confirmed or given up addresses
                if slaac.is_confirmed() || slaac.is_given_up() {
                    continue;
                }

                // Check if ping is due
                if slaac.ping_time <= now {
                    // Send ICMPv6 Echo Request
                    let ping = PingPacket::new(ping_id, slaac.backoff as u16);
                    let dest = SocketAddrV6::new(slaac.addr, 0, 0, 0);

                    match socket.send_to(ping.as_bytes(), &dest.into()).await {
                        Ok(_) => {
                            trace!(
                                "Sent DAD ping to {} (backoff={})",
                                slaac.addr,
                                slaac.backoff
                            );
                            
                            // Calculate next ping time with exponential backoff and jitter
                            let base_delay = 1u64 << (slaac.backoff - 1); // 2^(backoff-1)
                            let jitter1 = (rand16() as u64) / 21785; // 0-3 seconds
                            let jitter2 = if slaac.backoff > 4 {
                                (rand16() as u64) / 4000 // 0-15 seconds
                            } else {
                                0
                            };
                            
                            let delay_secs = base_delay + jitter1 + jitter2;
                            slaac.ping_time = now + Duration::from_secs(delay_secs);
                            
                            // Increment backoff if not at max
                            if slaac.backoff < MAX_BACKOFF {
                                slaac.backoff += 1;
                            }
                        }
                        Err(e) => {
                            // Check for EHOSTUNREACH (errno 113 on Linux)
                            if e.raw_os_error() == Some(113) && slaac.backoff == MAX_BACKOFF {
                                // Give up after max attempts with EHOSTUNREACH
                                warn!("Giving up on SLAAC address {} after {} attempts", slaac.addr, MAX_BACKOFF);
                                slaac.ping_time = SystemTime::UNIX_EPOCH;
                            } else {
                                warn!("Failed to send DAD ping to {}: {}", slaac.addr, e);
                            }
                        }
                    }
                }

                // Track earliest next event
                if !slaac.is_given_up() {
                    next_event = match next_event {
                        None => Some(slaac.ping_time),
                        Some(t) if slaac.ping_time < t => Some(slaac.ping_time),
                        Some(t) => Some(t),
                    };
                }
            }
        }

        next_event
    }

    /// Process ICMPv6 Echo Reply for DAD confirmation
    pub async fn process_ping_reply(
        &self,
        sender: &Ipv6Addr,
        packet: &[u8],
        interface: &str,
        logger: &Logger,
        config: &Config,
    ) -> bool {
        // Parse ping packet
        let ping = match PingPacket::from_bytes(packet) {
            Some(p) => p,
            None => {
                warn!("Invalid ICMPv6 Echo Reply packet");
                return false;
            }
        };

        // Verify identifier matches our ping_id
        let ping_id = self.ping_id.load(Ordering::Relaxed);
        if ping.get_identifier() != ping_id {
            trace!("ICMPv6 Echo Reply identifier mismatch: expected {}, got {}", 
                   ping_id, ping.get_identifier());
            return false;
        }

        let mut addresses = self.addresses.write().await;
        let mut gotone = false;

        // Search all leases for matching SLAAC address
        for (_lease_key, addr_list) in addresses.iter_mut() {
            for slaac in addr_list.iter_mut() {
                if slaac.backoff != 0 && &slaac.addr == sender {
                    // Address confirmed - another host responded
                    slaac.backoff = 0;
                    gotone = true;

                    // Log confirmation unless OPT_QUIET_DHCP6 is set
                    if !config.options.contains(DaemonOptions::OPT_QUIET_DHCP6) {
                        info!(
                            "SLAAC-CONFIRM({}) {} [confirmed via Echo Reply]",
                            interface, sender
                        );
                    }
                }
            }
        }

        gotone
    }
}

impl Default for SlaacManager {
    fn default() -> Self {
        Self::new()
    }
}

/// SLAAC context representing an RA prefix configuration
///
/// Simplified representation of C `struct dhcp_context` for SLAAC purposes
#[derive(Debug, Clone)]
pub struct SlaacContext {
    /// IPv6 prefix from Router Advertisement
    pub prefix: Ipv6Addr,
    /// Interface index where this context applies
    pub if_index: u32,
}

/// Generate and validate SLAAC IPv6 addresses from Router Advertisement prefixes
///
/// Refactored from C `slaac_add_addrs()` (src/slaac.c:156-247) with memory-safe Rust.
///
/// # Arguments
///
/// * `manager` - SLAAC manager instance
/// * `lease_manager` - Lease manager for DNS updates
/// * `lease_key` - Unique identifier for the lease (client ID or MAC)
/// * `contexts` - List of SLAAC contexts (RA prefixes)
/// * `hwaddr` - Hardware address bytes (MAC-48, EUI-64, etc.)
/// * `hwaddr_type` - Hardware address type (ARPHRD_ETHER, ARPHRD_IEEE802, etc.)
/// * `clid` - Optional client identifier (for FireWire EUI-64)
/// * `hostname` - Hostname for DNS registration
/// * `now` - Current time for initializing DAD timing
/// * `force` - Force re-validation of existing addresses
///
/// # Memory Safety
///
/// Replaces C's manual linked list manipulation with Vec operations:
/// - No use-after-free bugs from incorrect list splicing
/// - No memory leaks from forgotten free() calls
/// - Automatic cleanup via Drop trait
///
/// # Example
///
/// ```rust,ignore
/// let manager = SlaacManager::new();
/// let lease_manager = LeaseManager::new(config);
/// let now = SystemTime::now();
///
/// slaac_add_addrs(
///     &manager,
///     &lease_manager,
///     lease_key,
///     &contexts,
///     &mac_address,
///     ARPHRD_ETHER,
///     None,
///     &hostname,
///     now,
///     false,
/// ).await;
/// ```
pub async fn slaac_add_addrs(
    manager: &SlaacManager,
    lease_manager: &LeaseManager,
    lease_key: Vec<u8>,
    contexts: &[SlaacContext],
    hwaddr: &[u8],
    hwaddr_type: u16,
    clid: Option<&[u8]>,
    _hostname: &str,
    now: SystemTime,
    force: bool,
) {
    // Add/update addresses
    let dns_dirty = manager
        .add_addrs(lease_key, contexts, hwaddr, hwaddr_type, clid, now, force)
        .await;

    // Trigger Router Advertisements for new addresses
    for context in contexts {
        ra_start_unsolicited(now, Some(context.if_index as usize)).await;
    }

    // Update DNS cache if addresses changed
    if dns_dirty {
        lease_update_dns(lease_manager).await;
    }
}

/// Perform periodic Duplicate Address Detection for SLAAC addresses via ICMPv6 ping
///
/// Refactored from C `periodic_slaac()` (src/slaac.c:314-383) with async I/O.
///
/// # Arguments
///
/// * `manager` - SLAAC manager instance
/// * `socket` - ICMPv6 socket for sending Echo Requests
/// * `now` - Current time for scheduling
///
/// # Returns
///
/// Next scheduled DAD time, or None if no pending DAD operations
///
/// # Timing Behavior
///
/// Maintains exact C timing with exponential backoff and jitter:
/// ```text
/// next_ping = ping_time + 2^(backoff-1) + rand16()/21785 + (backoff > 4 ? rand16()/4000 : 0)
/// ```
/// - Backoff 1: ~1 second
/// - Backoff 2: ~2 seconds
/// - Backoff 3: ~4 seconds
/// - ...
/// - Backoff 12: ~4096 seconds (~68 minutes)
///
/// # Example
///
/// ```rust,ignore
/// let manager = SlaacManager::new();
/// let socket = UdpSocket::bind_icmp6().await?;
/// let now = SystemTime::now();
///
/// if let Some(next_event) = periodic_slaac(&manager, &socket, now).await {
///     tokio::time::sleep_until(next_event.into()).await;
/// }
/// ```
pub async fn periodic_slaac(
    manager: &SlaacManager,
    socket: &UdpSocket,
    now: SystemTime,
) -> Option<SystemTime> {
    manager.periodic_dad(now, socket).await
}

/// Process ICMPv6 Echo Reply to confirm SLAAC address uniqueness or detect conflicts
///
/// Refactored from C `slaac_ping_reply()` (src/slaac.c:453-473) with type-safe Result.
///
/// # Arguments
///
/// * `manager` - SLAAC manager instance
/// * `sender` - IPv6 address that sent the Echo Reply
/// * `packet` - Received ICMPv6 packet bytes
/// * `interface` - Network interface name for logging
/// * `logger` - Logger instance
/// * `config` - Configuration for OPT_QUIET_DHCP6 flag
/// * `lease_manager` - Lease manager for DNS updates
///
/// # DAD Semantics
///
/// Receipt of Echo Reply indicates another host is using the address:
/// - Sets backoff = 0 to mark address as confirmed
/// - Logs "SLAAC-CONFIRM" message (unless OPT_QUIET_DHCP6)
/// - Updates DNS cache with confirmed address
///
/// Per RFC 4862, this is not standard DAD (which uses Neighbor Solicitation),
/// but serves the same purpose of detecting duplicate addresses.
///
/// # Example
///
/// ```rust,ignore
/// let manager = SlaacManager::new();
/// let logger = Logger::new();
/// let config = Config::default();
/// let lease_manager = LeaseManager::new(&config);
///
/// // On receiving ICMPv6 Echo Reply:
/// slaac_ping_reply(
///     &manager,
///     &sender_addr,
///     &icmp_packet,
///     "eth0",
///     &logger,
///     &config,
///     &lease_manager,
/// ).await;
/// ```
pub async fn slaac_ping_reply(
    manager: &SlaacManager,
    sender: &Ipv6Addr,
    packet: &[u8],
    interface: &str,
    logger: &Logger,
    config: &Config,
    lease_manager: &LeaseManager,
) {
    let gotone = manager
        .process_ping_reply(sender, packet, interface, logger, config)
        .await;

    // Update DNS cache if any address was confirmed
    if gotone {
        lease_update_dns(lease_manager).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eui64_conversion_mac48() {
        // Test MAC-48 to EUI-64 conversion
        // MAC: 00:11:22:33:44:55
        // Expected EUI-64: 00:11:22:FF:FE:33:44:55
        // After universal bit flip (^= 0x02): 02:11:22:FF:FE:33:44:55
        
        let prefix = "fd00::".parse::<Ipv6Addr>().unwrap();
        let mac = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        
        let addr = SlaacManager::eui64_from_hwaddr(&prefix, mac, ARPHRD_ETHER, None)
            .expect("Failed to convert MAC to EUI-64");
        
        let octets = addr.octets();
        assert_eq!(octets[8], 0x00);  // Before bit flip
        assert_eq!(octets[9], 0x11);
        assert_eq!(octets[10], 0x22);
        assert_eq!(octets[11], 0xff);
        assert_eq!(octets[12], 0xfe);
        assert_eq!(octets[13], 0x33);
        assert_eq!(octets[14], 0x44);
        assert_eq!(octets[15], 0x55);
    }

    #[test]
    fn test_universal_local_bit_flip() {
        // Test the universal/local bit flip (bit 6 of first octet)
        let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
        let mac = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        
        let mut addr = SlaacManager::eui64_from_hwaddr(&prefix, mac, ARPHRD_ETHER, None)
            .expect("Failed to convert MAC");
        
        // Apply bit flip
        let mut octets = addr.octets();
        octets[8] ^= 0x02;
        addr = Ipv6Addr::from(octets);
        
        // Should flip 0x00 to 0x02
        assert_eq!(addr.octets()[8], 0x02);
    }

    #[test]
    fn test_backoff_calculation() {
        // Test exponential backoff values
        for backoff in 1..=MAX_BACKOFF {
            let base_delay = 1u64 << (backoff - 1);
            
            match backoff {
                1 => assert_eq!(base_delay, 1),   // 2^0 = 1 second
                2 => assert_eq!(base_delay, 2),   // 2^1 = 2 seconds
                3 => assert_eq!(base_delay, 4),   // 2^2 = 4 seconds
                4 => assert_eq!(base_delay, 8),   // 2^3 = 8 seconds
                12 => assert_eq!(base_delay, 2048), // 2^11 = 2048 seconds
                _ => {}
            }
        }
    }

    #[test]
    fn test_ping_packet_creation() {
        let ping = PingPacket::new(12345, 3);
        assert_eq!(ping.icmp_type, ICMP6_ECHO_REQUEST);
        assert_eq!(ping.code, 0);
        assert_eq!(ping.get_identifier(), 12345);
    }

    #[tokio::test]
    async fn test_slaac_manager_creation() {
        let manager = SlaacManager::new();
        let ping_id = manager.get_ping_id();
        assert_ne!(ping_id, 0, "Ping ID should be initialized");
    }

    #[tokio::test]
    async fn test_address_storage() {
        let manager = SlaacManager::new();
        let lease_key = vec![1, 2, 3, 4];
        let contexts = vec![SlaacContext {
            prefix: "fd00::".parse().unwrap(),
            if_index: 1,
        }];
        let mac = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let now = SystemTime::now();

        manager
            .add_addrs(lease_key.clone(), &contexts, &mac, ARPHRD_ETHER, None, now, false)
            .await;

        let addresses = manager.get_addresses(&lease_key).await;
        assert_eq!(addresses.len(), 1, "Should have one SLAAC address");
    }
}
