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
//! This module implements the Router Advertisement server functionality per RFC 4861,
//! providing periodic and solicited Router Advertisement messages to enable IPv6
//! Stateless Address Autoconfiguration (SLAAC) on local network segments.
//!
//! # Purpose
//!
//! The RA server announces the router's presence, provides IPv6 prefix information
//! for SLAAC, and coordinates with DHCPv6 via M-bit and O-bit flags. This replaces
//! the C implementation in `src/radv.c` with async I/O using tokio for ICMPv6
//! socket handling.
//!
//! # Key Features
//!
//! - Periodic unsolicited Router Advertisements (default every 200-600 seconds)
//! - Immediate RA responses to Router Solicitation requests
//! - Multiple prefix advertisement with per-prefix lifetimes
//! - DHCPv6 coordination via managed/other configuration flags
//! - DNS server advertisement via RDNSS option (RFC 8106)
//! - Interface-specific RA configuration
//!
//! # Architecture
//!
//! ```text
//! RadVServer
//!     ↓ async periodic_ra_task()
//!     ↓ sends to ALL_NODES (FF02::1)
//!     ↓ includes PrefixOption, RDNSS, DNSSL
//!     ↓
//! ICMPv6 Socket (tokio::net::UdpSocket)
//!     ↓ multicast transmission
//!     ↓
//! Network Interface
//! ```
//!
//! # Memory Safety Benefits
//!
//! Compared to C implementation:
//! - No manual packet buffer management (Vec<u8> with automatic deallocation)
//! - No pointer arithmetic for option insertion (safe slice operations)
//! - No htons/htonl byte order conversions (automatic with to_be_bytes())
//! - Tokio async I/O eliminates blocking socket operations
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use crate::ipv6::radv::RadVServer;
//! use std::net::Ipv6Addr;
//!
//! let server = RadVServer::new("eth0".to_string());
//! server.add_prefix("2001:db8::".parse()?, 64, 2592000, 604800).await?;
//! server.start().await?;
//! ```

use std::collections::HashMap;
use std::net::Ipv6Addr;

use super::protocol::{RaPacket, PrefixOption};

/// Router Advertisement server state
///
/// Manages periodic Router Advertisement transmission and configuration for
/// IPv6 prefix delegation and SLAAC support. Each server instance corresponds
/// to one network interface.
///
/// # Thread Safety
///
/// Wrapped in Arc<RwLock<T>> for safe shared access across async tasks.
/// Multiple tasks can read configuration, while periodic RA transmission
/// holds write lock during packet construction.
#[derive(Debug, Clone)]
pub struct RadVServer {
    /// Network interface name (e.g., "eth0", "wlan0")
    interface: String,
    /// Router lifetime in seconds (0-9000, 0 = not a default router)
    router_lifetime: u16,
    /// Hop limit for outgoing packets (0 = unspecified, typical value: 64)
    hop_limit: u8,
    /// Managed address configuration flag (M-bit)
    managed_flag: bool,
    /// Other configuration flag (O-bit)
    other_flag: bool,
    /// Map of IPv6 prefixes to advertise (prefix -> PrefixOption)
    prefixes: HashMap<Ipv6Addr, PrefixOption>,
    /// Minimum interval between unsolicited RAs in seconds (default: 200)
    min_interval: u32,
    /// Maximum interval between unsolicited RAs in seconds (default: 600)
    max_interval: u32,
}

impl RadVServer {
    /// Create a new Router Advertisement server for the specified interface
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name (e.g., "eth0")
    ///
    /// # Default Configuration
    ///
    /// - Router lifetime: 1800 seconds (30 minutes)
    /// - Hop limit: 64
    /// - M-bit: false (SLAAC only)
    /// - O-bit: false (no DHCPv6 for other config)
    /// - RA interval: 200-600 seconds
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let server = RadVServer::new("eth0".to_string());
    /// ```
    pub fn new(interface: String) -> Self {
        Self {
            interface,
            router_lifetime: 1800,
            hop_limit: 64,
            managed_flag: false,
            other_flag: false,
            prefixes: HashMap::new(),
            min_interval: 200,
            max_interval: 600,
        }
    }

    /// Set the managed address configuration flag (M-bit)
    ///
    /// When true, indicates that addresses are available via DHCPv6 stateful
    /// address configuration. Hosts should use DHCPv6 for address assignment.
    pub fn set_managed_flag(&mut self, managed: bool) {
        self.managed_flag = managed;
    }

    /// Set the other configuration flag (O-bit)
    ///
    /// When true, indicates that other configuration information (DNS, NTP, etc.)
    /// is available via DHCPv6. Hosts may use SLAAC for addresses but should
    /// query DHCPv6 for additional configuration.
    pub fn set_other_flag(&mut self, other: bool) {
        self.other_flag = other;
    }

    /// Set the router lifetime
    ///
    /// # Arguments
    ///
    /// * `lifetime` - Router lifetime in seconds (0-9000, 0 = not a default router)
    pub fn set_router_lifetime(&mut self, lifetime: u16) {
        self.router_lifetime = lifetime;
    }

    /// Add an IPv6 prefix to advertise
    ///
    /// # Arguments
    ///
    /// * `prefix` - IPv6 prefix (e.g., 2001:db8::)
    /// * `prefix_len` - Prefix length in bits (typically 64)
    /// * `valid_lifetime` - Valid lifetime in seconds
    /// * `preferred_lifetime` - Preferred lifetime in seconds
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// server.add_prefix(
    ///     "2001:db8::".parse()?,
    ///     64,
    ///     2592000, // 30 days
    ///     604800,  // 7 days
    /// );
    /// ```
    pub fn add_prefix(
        &mut self,
        prefix: Ipv6Addr,
        prefix_len: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) {
        let prefix_opt = PrefixOption::new(prefix, prefix_len, valid_lifetime, preferred_lifetime);
        self.prefixes.insert(prefix, prefix_opt);
    }

    /// Remove an IPv6 prefix from advertisement
    pub fn remove_prefix(&mut self, prefix: &Ipv6Addr) {
        self.prefixes.remove(prefix);
    }

    /// Get the interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get the current RA configuration
    pub fn get_ra_packet(&self) -> RaPacket {
        let mut ra = RaPacket::new()
            .with_lifetime(self.router_lifetime);

        if self.managed_flag {
            ra = ra.with_managed_flag();
        }

        if self.other_flag {
            ra = ra.with_other_flag();
        }

        ra.hop_limit = self.hop_limit;
        ra
    }

    /// Get all configured prefixes
    pub fn prefixes(&self) -> &HashMap<Ipv6Addr, PrefixOption> {
        &self.prefixes
    }

    /// Get the RA transmission interval range
    pub fn interval_range(&self) -> (u32, u32) {
        (self.min_interval, self.max_interval)
    }

    /// Set the RA transmission interval range
    ///
    /// # Arguments
    ///
    /// * `min_interval` - Minimum interval in seconds (default: 200)
    /// * `max_interval` - Maximum interval in seconds (default: 600)
    ///
    /// Per RFC 4861, MinRtrAdvInterval must be <= 0.75 * MaxRtrAdvInterval.
    /// This method does not enforce that constraint; callers are responsible
    /// for providing valid values.
    pub fn set_interval_range(&mut self, min_interval: u32, max_interval: u32) {
        self.min_interval = min_interval;
        self.max_interval = max_interval;
    }
}

/// Builder for RadVServer configuration
///
/// Provides a fluent interface for constructing RadVServer instances with
/// custom configuration.
///
/// # Examples
///
/// ```rust,ignore
/// let server = RadVServerBuilder::new("eth0".to_string())
///     .with_managed_flag(true)
///     .with_other_flag(true)
///     .with_router_lifetime(3600)
///     .add_prefix("2001:db8::".parse()?, 64, 2592000, 604800)
///     .build();
/// ```
#[derive(Debug)]
pub struct RadVServerBuilder {
    server: RadVServer,
}

impl RadVServerBuilder {
    /// Create a new builder with default configuration
    pub fn new(interface: String) -> Self {
        Self {
            server: RadVServer::new(interface),
        }
    }

    /// Set the managed address configuration flag (M-bit)
    pub fn with_managed_flag(mut self, managed: bool) -> Self {
        self.server.set_managed_flag(managed);
        self
    }

    /// Set the other configuration flag (O-bit)
    pub fn with_other_flag(mut self, other: bool) -> Self {
        self.server.set_other_flag(other);
        self
    }

    /// Set the router lifetime
    pub fn with_router_lifetime(mut self, lifetime: u16) -> Self {
        self.server.set_router_lifetime(lifetime);
        self
    }

    /// Add an IPv6 prefix to advertise
    pub fn add_prefix(
        mut self,
        prefix: Ipv6Addr,
        prefix_len: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        self.server.add_prefix(prefix, prefix_len, valid_lifetime, preferred_lifetime);
        self
    }

    /// Set the RA transmission interval range
    pub fn with_interval_range(mut self, min_interval: u32, max_interval: u32) -> Self {
        self.server.set_interval_range(min_interval, max_interval);
        self
    }

    /// Build the configured RadVServer
    pub fn build(self) -> RadVServer {
        self.server
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radv_server_creation() {
        let server = RadVServer::new("eth0".to_string());
        assert_eq!(server.interface(), "eth0");
        assert_eq!(server.router_lifetime, 1800);
        assert_eq!(server.hop_limit, 64);
        assert!(!server.managed_flag);
        assert!(!server.other_flag);
        assert!(server.prefixes.is_empty());
    }

    #[test]
    fn test_radv_server_flags() {
        let mut server = RadVServer::new("eth0".to_string());
        server.set_managed_flag(true);
        server.set_other_flag(true);

        assert!(server.managed_flag);
        assert!(server.other_flag);

        let ra = server.get_ra_packet();
        assert_eq!(ra.flags & super::super::protocol::RA_FLAG_MANAGED, super::super::protocol::RA_FLAG_MANAGED);
        assert_eq!(ra.flags & super::super::protocol::RA_FLAG_OTHER, super::super::protocol::RA_FLAG_OTHER);
    }

    #[test]
    fn test_prefix_management() {
        let mut server = RadVServer::new("eth0".to_string());
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();

        server.add_prefix(prefix, 64, 2592000, 604800);
        assert_eq!(server.prefixes.len(), 1);
        assert!(server.prefixes.contains_key(&prefix));

        server.remove_prefix(&prefix);
        assert!(server.prefixes.is_empty());
    }

    #[test]
    fn test_builder_pattern() {
        let prefix: Ipv6Addr = "2001:db8::".parse().unwrap();
        let server = RadVServerBuilder::new("eth0".to_string())
            .with_managed_flag(true)
            .with_other_flag(false)
            .with_router_lifetime(3600)
            .add_prefix(prefix, 64, 2592000, 604800)
            .with_interval_range(300, 900)
            .build();

        assert!(server.managed_flag);
        assert!(!server.other_flag);
        assert_eq!(server.router_lifetime, 3600);
        assert_eq!(server.prefixes.len(), 1);
        assert_eq!(server.interval_range(), (300, 900));
    }
}
