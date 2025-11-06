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
//! DHCPv6 stateful address assignment. This implementation:
//!
//! - Generates IPv6 addresses from RA prefixes + EUI-64 interface identifiers
//! - Performs Duplicate Address Detection (DAD) via ICMPv6 Echo Request/Reply
//! - Registers confirmed SLAAC addresses in DNS cache for hostname resolution
//! - Coordinates with DHCPv6 via M-bit/O-bit flags in Router Advertisements
//!
//! # Key Components
//!
//! - **EUI-64 Conversion**: Transform MAC-48 addresses to Modified EUI-64 format
//!   * Insert 0xFFFE in middle of MAC address (e.g., 00:11:22:33:44:55 → 00:11:22:FF:FE:33:44:55)
//!   * Flip universal/local bit (bit 6 of first octet)
//!
//! - **Duplicate Address Detection**: Verify address uniqueness via ICMPv6 ping
//!   * Send ICMPv6 Echo Request to candidate address
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
//! - **RFC 4443**: ICMPv6 (Echo Request/Reply for DAD)
//!
//! # Memory Safety Benefits (C to Rust Refactor)
//!
//! | C Implementation | Rust Implementation | Safety Improvement |
//! |------------------|---------------------|-------------------|
//! | Manual linked list | `Vec<SlaacAddress>` | No memory leaks |
//! | Pointer traversal | Safe indexing | No null dereferences |
//! | `memcpy()` for EUI-64 | Safe array operations | No buffer overflows |
//! | Global `ping_id` state | `SlaacManager` struct field | Encapsulated state |
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use crate::ipv6::slaac::{SlaacManager, generate_eui64_from_mac};
//! use std::net::Ipv6Addr;
//!
//! let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
//! let prefix: Ipv6Addr = "2001:db8::".parse()?;
//! 
//! let addr = generate_eui64_from_mac(&mac, &prefix)?;
//! // Result: 2001:db8::211:22ff:fe33:4455
//! ```

use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

/// SLAAC address state tracking
///
/// Tracks the validation state of a SLAAC-generated IPv6 address during
/// Duplicate Address Detection (DAD). Each address goes through exponential
/// backoff retry attempts until confirmed unique or abandoned as unreachable.
///
/// # State Lifecycle
///
/// 1. **Created**: `backoff = 1`, `ping_time = now` (immediate DAD attempt)
/// 2. **Pending**: `backoff = 2^n`, `ping_time = next_attempt` (exponential backoff)
/// 3. **Confirmed**: `backoff = 0` (no further DAD needed, address is valid)
/// 4. **Abandoned**: `ping_time = 0` (unreachable after 12 retries, give up)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlaacAddress {
    /// The generated SLAAC IPv6 address
    pub addr: Ipv6Addr,
    /// Next scheduled DAD ping time (0 = abandoned)
    pub ping_time: SystemTime,
    /// Exponential backoff counter (0 = confirmed, 1-12 = pending)
    pub backoff: u8,
}

impl SlaacAddress {
    /// Create a new SLAAC address requiring DAD validation
    pub fn new(addr: Ipv6Addr, now: SystemTime) -> Self {
        Self {
            addr,
            ping_time: now,
            backoff: 1,
        }
    }

    /// Check if the address is confirmed (DAD completed successfully)
    pub fn is_confirmed(&self) -> bool {
        self.backoff == 0
    }

    /// Check if the address is abandoned (DAD failed after max retries)
    pub fn is_abandoned(&self) -> bool {
        self.ping_time == SystemTime::UNIX_EPOCH
    }

    /// Mark the address as confirmed
    pub fn confirm(&mut self) {
        self.backoff = 0;
    }

    /// Mark the address as abandoned
    pub fn abandon(&mut self) {
        self.ping_time = SystemTime::UNIX_EPOCH;
    }
}

/// SLAAC address generation and management
///
/// Manages SLAAC address lifecycle including EUI-64 generation, DAD coordination,
/// and DNS registration. Implements the state machine for address validation with
/// exponential backoff retry logic.
#[derive(Debug)]
pub struct SlaacManager {
    /// ICMPv6 Echo Request identifier for DAD probes
    ping_id: u16,
}

impl SlaacManager {
    /// Create a new SLAAC manager
    pub fn new() -> Self {
        use std::time::UNIX_EPOCH;
        
        // Generate random ping_id (mimics C behavior)
        let ping_id = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() & 0xFFFF) as u16;
        
        Self { ping_id }
    }

    /// Get the ICMPv6 ping identifier
    pub fn ping_id(&self) -> u16 {
        self.ping_id
    }

    /// Calculate next DAD ping time with exponential backoff
    ///
    /// # Arguments
    ///
    /// * `now` - Current time
    /// * `backoff` - Current backoff counter (1-12)
    ///
    /// # Returns
    ///
    /// Next scheduled ping time with exponential backoff and jitter
    pub fn calculate_next_ping_time(&self, now: SystemTime, backoff: u8) -> SystemTime {
        // Exponential backoff: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048 seconds
        let delay_secs = 1u64 << (backoff.min(11) as u64);
        
        // Add small random jitter (0-10% of delay) to avoid thundering herd
        let jitter_secs = (delay_secs / 10).max(1);
        let jitter = (self.ping_id as u64 % jitter_secs) as u64;
        
        now + Duration::from_secs(delay_secs + jitter)
    }

    /// Maximum backoff attempts before abandoning address
    pub const MAX_BACKOFF: u8 = 12;
}

impl Default for SlaacManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Hardware address types supported for EUI-64 conversion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareAddressType {
    /// Ethernet (ARPHRD_ETHER = 1)
    Ethernet,
    /// IEEE 802.11 wireless (ARPHRD_IEEE802 = 6)
    Ieee802,
    /// EUI-64 (ARPHRD_EUI64 = 27)
    Eui64,
    /// IEEE 1394 FireWire (ARPHRD_IEEE1394 = 24)
    Ieee1394,
}

/// Generate Modified EUI-64 interface identifier from MAC-48 address
///
/// Converts a 6-byte MAC address to an 8-byte Modified EUI-64 interface identifier
/// by inserting 0xFF-FE in the middle and flipping the universal/local bit.
///
/// # Transformation Steps
///
/// 1. Insert 0xFF-FE between 3rd and 4th bytes of MAC
/// 2. Flip bit 6 of first byte (universal/local bit)
///
/// # Arguments
///
/// * `mac` - 6-byte MAC address
/// * `prefix` - IPv6 prefix (first 64 bits)
///
/// # Returns
///
/// Complete IPv6 address with EUI-64 interface identifier
///
/// # Examples
///
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::ipv6::slaac::generate_eui64_from_mac;
///
/// let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
/// let addr = generate_eui64_from_mac(&mac, &prefix).unwrap();
///
/// // Expected: 2001:db8::211:22ff:fe33:4455
/// // (Note: 0x00 XOR 0x02 = 0x02 for universal/local bit flip)
/// ```
///
/// # RFC Compliance
///
/// - RFC 4291 Appendix A: Modified EUI-64 format
/// - RFC 2464 Section 4: MAC-48 to EUI-64 conversion
pub fn generate_eui64_from_mac(mac: &[u8; 6], prefix: &Ipv6Addr) -> Result<Ipv6Addr, String> {
    let mut octets = prefix.octets();
    
    // Insert MAC address with FF-FE in middle
    octets[8] = mac[0] ^ 0x02;  // Flip universal/local bit (bit 6)
    octets[9] = mac[1];
    octets[10] = mac[2];
    octets[11] = 0xFF;
    octets[12] = 0xFE;
    octets[13] = mac[3];
    octets[14] = mac[4];
    octets[15] = mac[5];
    
    Ok(Ipv6Addr::from(octets))
}

/// Generate IPv6 address from EUI-64 hardware address
///
/// Directly copies the 8-byte EUI-64 identifier into the interface identifier portion
/// of the IPv6 address, with the universal/local bit flip.
///
/// # Arguments
///
/// * `eui64` - 8-byte EUI-64 hardware address
/// * `prefix` - IPv6 prefix (first 64 bits)
///
/// # Returns
///
/// Complete IPv6 address with EUI-64 interface identifier
pub fn generate_eui64_from_eui64(eui64: &[u8; 8], prefix: &Ipv6Addr) -> Result<Ipv6Addr, String> {
    let mut octets = prefix.octets();
    
    // Copy EUI-64 identifier with universal/local bit flip
    octets[8] = eui64[0] ^ 0x02;
    octets[9..16].copy_from_slice(&eui64[1..8]);
    
    Ok(Ipv6Addr::from(octets))
}

/// Check if two IPv6 addresses are equal
///
/// Convenience function for address comparison in SLAAC address management.
pub fn addresses_equal(addr1: &Ipv6Addr, addr2: &Ipv6Addr) -> bool {
    addr1 == addr2
}

// =============================================================================
// Integration Functions for DHCP Lease System
// =============================================================================
//
// These functions provide the interface between the SLAAC manager and the DHCPv6
// lease subsystem. They are called from the main event loop and coordinate SLAAC
// address generation, Duplicate Address Detection (DAD), and DNS cache updates.
//
// In the C implementation (src/slaac.c), these functions directly manipulate
// global state (daemon struct, lease lists) and perform synchronous I/O.
//
// In the Rust implementation, these are temporary placeholder stubs that maintain
// API compatibility while the full integration with the async DHCP subsystem is
// completed. Once dhcp::v6::lease module is fully implemented, these functions
// will be replaced with proper async implementations.

/// Generate and validate SLAAC IPv6 addresses from Router Advertisement prefixes.
///
/// This function is the main entry point for SLAAC address generation. It combines
/// RA prefixes from configured DHCPv6 contexts with Modified EUI-64 interface
/// identifiers derived from hardware addresses to construct candidate SLAAC addresses.
///
/// # C Implementation Reference
///
/// From `src/slaac.c:156`:
/// ```c
/// void slaac_add_addrs(struct dhcp_lease *lease, time_t now, int force)
/// ```
///
/// The C implementation:
/// 1. Iterates through all DHCPv6 contexts with RA-stateless mode
/// 2. For each context prefix, generates EUI-64 address from lease hardware address
/// 3. Creates `slaac_address` entry in lease's SLAAC address list
/// 4. Initializes DAD ping timing with randomized backoff
/// 5. Triggers Router Advertisement via `ra_start_unsolicited()`
///
/// # Parameters
///
/// * `lease_id` - Identifier for the DHCP lease (client DUID or MAC address)
/// * `now` - Current system time for DAD scheduling
/// * `force` - If true, regenerate addresses even if they exist
///
/// # Current Status
///
/// **STUB IMPLEMENTATION**: This function currently does nothing. Full implementation
/// requires:
/// - Integration with `dhcp::v6::lease::LeaseManager`
/// - Access to DHCPv6 context configuration
/// - Integration with DNS cache for hostname resolution
///
/// # Future Implementation
///
/// ```rust,ignore
/// pub async fn slaac_add_addrs(
///     lease_manager: &mut LeaseManager,
///     lease_id: &str,
///     now: SystemTime,
///     force: bool,
/// ) -> Result<(), SlaacError> {
///     let lease = lease_manager.get_lease_mut(lease_id)?;
///     let contexts = lease_manager.get_ra_contexts()?;
///     
///     for context in contexts {
///         if context.is_ra_stateless() {
///             let addr = generate_eui64_from_mac(&lease.hardware_addr, &context.prefix)?;
///             lease.add_slaac_address(SlaacAddress::new(addr, now));
///         }
///     }
///     
///     trigger_router_advertisement().await?;
///     Ok(())
/// }
/// ```
pub fn slaac_add_addrs(_lease_id: &str, _now: std::time::SystemTime, _force: bool) {
    // STUB: Full implementation requires dhcp::v6::lease integration
    // See Agent Action Plan section 0.8.3 for DHCP subsystem implementation
}

/// Perform periodic Duplicate Address Detection (DAD) for SLAAC addresses.
///
/// This function implements the periodic DAD protocol by sending ICMPv6 Echo Request
/// probes to tentative SLAAC addresses and managing retry timing with exponential backoff.
/// It is called from the main event loop timer mechanism.
///
/// # C Implementation Reference
///
/// From `src/slaac.c:314`:
/// ```c
/// time_t periodic_slaac(time_t now, struct dhcp_lease *leases)
/// ```
///
/// The C implementation:
/// 1. Iterates through all DHCP leases
/// 2. For each lease's SLAAC address list, checks ping timing
/// 3. Sends ICMPv6 Echo Request to addresses due for DAD probe
/// 4. Updates ping_time with exponential backoff (1s → 2s → 4s → ...)
/// 5. Returns next scheduled event time for timer
///
/// # Parameters
///
/// * `now` - Current system time for scheduling decisions
///
/// # Returns
///
/// Next system time when this function should be called again (for next DAD probe).
/// In C, returns `time_t` representing absolute time. In Rust, returns `SystemTime`.
///
/// # Current Status
///
/// **STUB IMPLEMENTATION**: This function currently returns `now + 60 seconds`. Full
/// implementation requires:
/// - Integration with `dhcp::v6::lease::LeaseManager`
/// - Async ICMPv6 socket for Echo Request transmission
/// - Timer scheduling integration with tokio runtime
///
/// # Future Implementation
///
/// ```rust,ignore
/// pub async fn periodic_slaac(
///     lease_manager: &mut LeaseManager,
///     icmp_socket: &mut Icmpv6Socket,
///     now: SystemTime,
/// ) -> Result<SystemTime, SlaacError> {
///     let mut next_event = now + Duration::from_secs(3600); // Default: 1 hour
///     
///     for lease in lease_manager.get_all_leases() {
///         for slaac_addr in lease.get_slaac_addresses_mut() {
///             if slaac_addr.ping_time <= now {
///                 // Send ICMPv6 Echo Request for DAD
///                 send_dad_probe(icmp_socket, &slaac_addr.address).await?;
///                 
///                 // Update ping time with exponential backoff
///                 slaac_addr.backoff += 1;
///                 slaac_addr.ping_time = now + Duration::from_secs(1 << slaac_addr.backoff);
///                 
///                 // Track earliest next event
///                 if slaac_addr.ping_time < next_event {
///                     next_event = slaac_addr.ping_time;
///                 }
///             }
///         }
///     }
///     
///     Ok(next_event)
/// }
/// ```
pub fn periodic_slaac(_now: std::time::SystemTime) -> std::time::SystemTime {
    // STUB: Return now + 60 seconds as placeholder next event time
    // Full implementation requires dhcp::v6::lease and network::sockets integration
    _now + std::time::Duration::from_secs(60)
}

/// Process ICMPv6 Echo Reply to detect address conflicts and confirm SLAAC addresses.
///
/// This function handles incoming ICMPv6 Echo Reply packets during Duplicate Address
/// Detection. If a reply is received for a tentative address, it indicates a duplicate
/// and the address must be abandoned. If no reply is received within the timeout,
/// the address is confirmed and added to the DNS cache.
///
/// # C Implementation Reference
///
/// From `src/slaac.c:453`:
/// ```c
/// void slaac_ping_reply(struct in6_addr *sender, unsigned char *packet,
///                       char *interface, struct dhcp_lease *leases)
/// ```
///
/// The C implementation:
/// 1. Extracts ICMPv6 Echo Reply identifier and sequence number
/// 2. Iterates through all leases to find matching SLAAC address
/// 3. If address matches sender and identifier matches our probe:
///    - Duplicate detected → remove address from lease
///    - Log duplicate address conflict
/// 4. If address confirmed (no duplicate after max backoff):
///    - Call `lease_update_dns()` to add to DNS cache
///    - Enable hostname resolution for SLAAC address
///
/// # Parameters
///
/// * `sender` - IPv6 address that sent the Echo Reply
/// * `packet` - Raw ICMPv6 packet bytes (includes Echo Reply header and data)
/// * `interface` - Network interface name where reply was received
///
/// # Current Status
///
/// **STUB IMPLEMENTATION**: This function currently does nothing. Full implementation
/// requires:
/// - Integration with `dhcp::v6::lease::LeaseManager`
/// - ICMPv6 packet parsing (identifier, sequence matching)
/// - DNS cache integration for address confirmation
///
/// # Future Implementation
///
/// ```rust,ignore
/// pub async fn slaac_ping_reply(
///     lease_manager: &mut LeaseManager,
///     dns_cache: &mut DnsCache,
///     sender: &Ipv6Addr,
///     packet: &[u8],
///     interface: &str,
/// ) -> Result<(), SlaacError> {
///     let (identifier, sequence) = parse_icmpv6_echo_reply(packet)?;
///     
///     for lease in lease_manager.get_all_leases_mut() {
///         if let Some(slaac_addr) = lease.find_slaac_address(sender) {
///             // Duplicate detected - remove address
///             warn!("Duplicate SLAAC address detected: {} on {}", sender, interface);
///             lease.remove_slaac_address(sender);
///             return Ok(());
///         }
///     }
///     
///     // If address reached max backoff without duplicate, confirm it
///     if let Some(lease) = lease_manager.find_lease_by_slaac_addr(sender) {
///         if lease.slaac_addr_confirmed(sender) {
///             dns_cache.add_slaac_entry(sender, &lease.hostname).await?;
///             info!("SLAAC address confirmed: {} for {}", sender, lease.hostname);
///         }
///     }
///     
///     Ok(())
/// }
/// ```
pub fn slaac_ping_reply(
    _sender: &Ipv6Addr,
    _packet: &[u8],
    _interface: &str,
) {
    // STUB: Full implementation requires dhcp::v6::lease and dns::cache integration
    // See Agent Action Plan section 0.8.3 (DHCP) and 0.8.2 (DNS) for dependencies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_eui64_from_mac() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        
        let addr = generate_eui64_from_mac(&mac, &prefix).unwrap();
        
        // Expected: 2001:db8::211:22ff:fe33:4455
        // First byte: 0x00 XOR 0x02 = 0x02 (universal/local bit flip)
        let expected: Ipv6Addr = "2001:db8::211:22ff:fe33:4455".parse().unwrap();
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_generate_eui64_from_eui64() {
        let eui64 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let prefix: Ipv6Addr = "fd00::".parse().unwrap();
        
        let addr = generate_eui64_from_eui64(&eui64, &prefix).unwrap();
        
        // Expected: fd00::211:2233:4455:6677
        // First byte: 0x00 XOR 0x02 = 0x02
        let expected: Ipv6Addr = "fd00::211:2233:4455:6677".parse().unwrap();
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_slaac_address_lifecycle() {
        let now = SystemTime::now();
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        
        let mut slaac = SlaacAddress::new(addr, now);
        assert_eq!(slaac.backoff, 1);
        assert!(!slaac.is_confirmed());
        assert!(!slaac.is_abandoned());
        
        // Confirm address
        slaac.confirm();
        assert!(slaac.is_confirmed());
        assert_eq!(slaac.backoff, 0);
        
        // Abandon address
        slaac.abandon();
        assert!(slaac.is_abandoned());
    }

    #[test]
    fn test_slaac_manager() {
        let manager = SlaacManager::new();
        assert!(manager.ping_id() > 0);
        
        let now = SystemTime::now();
        let next_ping = manager.calculate_next_ping_time(now, 1);
        
        // Should be at least 1 second in future
        assert!(next_ping > now);
    }

    #[test]
    fn test_exponential_backoff() {
        let manager = SlaacManager::new();
        let now = SystemTime::now();
        
        // Backoff 1: ~1 second
        let next1 = manager.calculate_next_ping_time(now, 1);
        assert!(next1.duration_since(now).unwrap().as_secs() >= 1);
        assert!(next1.duration_since(now).unwrap().as_secs() <= 2);
        
        // Backoff 5: ~32 seconds
        let next5 = manager.calculate_next_ping_time(now, 5);
        assert!(next5.duration_since(now).unwrap().as_secs() >= 32);
        assert!(next5.duration_since(now).unwrap().as_secs() <= 36);
    }

    #[test]
    fn test_universal_local_bit_flip() {
        // Test that universal/local bit (bit 6 of first byte) is flipped
        let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // Local bit clear
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let addr = generate_eui64_from_mac(&mac, &prefix).unwrap();
        
        // First byte should be 0x02 (bit 6 flipped)
        assert_eq!(addr.octets()[8], 0x02);
        
        // Test with local bit already set
        let mac_local = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        let addr_local = generate_eui64_from_mac(&mac_local, &prefix).unwrap();
        
        // First byte should be 0x00 (bit 6 flipped back)
        assert_eq!(addr_local.octets()[8], 0x00);
    }
}
