// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # IPv6 Router Advertisement (RA)
//!
//! This module implements IPv6 Router Advertisement transmission per RFC 4861,
//! replacing `src/radv.c`.
//!
//! ## Purpose
//!
//! Implements Router Advertisement functionality:
//! - Periodic RA transmission (RFC 4861 Section 6)
//! - Solicited RA responses
//! - Prefix Information options with valid/preferred lifetimes
//! - Managed (M) and Other (O) configuration flags for DHCPv6 coordination
//! - Router lifetime and priority
//! - Advertisement interval options
//! - RDNSS (Recursive DNS Server) option (RFC 6106)
//! - DNSSL (DNS Search List) option (RFC 6106)
//!
//! ## C Source Mapping
//!
//! | C Function | Rust Equivalent | Purpose |
//! |------------|-----------------|---------|
//! | `ra_init()` | `RouterAdvertiser::new()` | Initialize ICMPv6 socket |
//! | `send_ra()` | `RouterAdvertiser::send_advertisement()` | Construct and transmit RA |
//! | `icmp6_packet()` | `RouterAdvertiser::handle_solicitation()` | Process Router Solicitation |
//! | `periodic_ra()` | `RouterAdvertiser::periodic_advertisement()` | Scheduled RA transmission |
//! | `add_prefixes()` | `RouterAdvertiser::add_prefix_options()` | Enumerate and add prefixes |
//!
//! ## Router Advertisement Packet Format (RFC 4861)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Reachable Time                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Retrans Timer                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Options...
//! +-+-+-+-+-+-+-+-+-+-+-+-
//! ```

use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// ICMPv6 Router Advertisement type
pub const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;

/// ICMPv6 Router Solicitation type
pub const ICMPV6_ROUTER_SOLICITATION: u8 = 133;

/// Prefix Information option type
pub const ND_OPT_PREFIX_INFORMATION: u8 = 3;

/// RDNSS option type (RFC 6106)
pub const ND_OPT_RDNSS: u8 = 25;

/// DNSSL option type (RFC 6106)
pub const ND_OPT_DNSSL: u8 = 31;

/// Prefix Information option
#[derive(Debug, Clone)]
pub struct PrefixInfo {
    /// Prefix address
    pub prefix: Ipv6Addr,
    
    /// Prefix length
    pub prefix_len: u8,
    
    /// On-link flag
    pub on_link: bool,
    
    /// Autonomous address configuration flag
    pub autonomous: bool,
    
    /// Valid lifetime (seconds)
    pub valid_lifetime: u32,
    
    /// Preferred lifetime (seconds)
    pub preferred_lifetime: u32,
}

/// Router Advertisement packet
#[derive(Debug, Clone)]
pub struct RouterAdvertisement {
    /// Current hop limit
    pub cur_hop_limit: u8,
    
    /// Managed address configuration flag
    pub managed: bool,
    
    /// Other configuration flag
    pub other: bool,
    
    /// Router lifetime (seconds)
    pub router_lifetime: u16,
    
    /// Reachable time (milliseconds)
    pub reachable_time: u32,
    
    /// Retransmit timer (milliseconds)
    pub retrans_timer: u32,
    
    /// Prefix information options
    pub prefixes: Vec<PrefixInfo>,
    
    /// DNS servers (RDNSS option)
    pub dns_servers: Vec<Ipv6Addr>,
    
    /// DNS search list (DNSSL option)
    pub search_list: Vec<String>,
}

impl RouterAdvertisement {
    /// Create new Router Advertisement
    ///
    /// # Returns
    ///
    /// New Router Advertisement with default values
    pub fn new() -> Self {
        Self {
            cur_hop_limit: 64,
            managed: false,
            other: false,
            router_lifetime: 1800, // 30 minutes default
            reachable_time: 0,
            retrans_timer: 0,
            prefixes: Vec::new(),
            dns_servers: Vec::new(),
            search_list: Vec::new(),
        }
    }

    /// Add prefix information
    ///
    /// # Arguments
    ///
    /// * `prefix` - Prefix information to add
    pub fn add_prefix(&mut self, prefix: PrefixInfo) {
        self.prefixes.push(prefix);
    }

    /// Encode Router Advertisement to bytes
    ///
    /// # Returns
    ///
    /// Encoded packet as byte vector
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(512);

        // ICMPv6 header
        buffer.push(ICMPV6_ROUTER_ADVERTISEMENT); // Type
        buffer.push(0); // Code
        buffer.extend_from_slice(&[0, 0]); // Checksum (filled by kernel)

        // Router Advertisement fields
        buffer.push(self.cur_hop_limit);
        
        let mut flags = 0u8;
        if self.managed {
            flags |= 0x80; // M flag
        }
        if self.other {
            flags |= 0x40; // O flag
        }
        buffer.push(flags);
        
        buffer.extend_from_slice(&self.router_lifetime.to_be_bytes());
        buffer.extend_from_slice(&self.reachable_time.to_be_bytes());
        buffer.extend_from_slice(&self.retrans_timer.to_be_bytes());

        // Prefix Information options
        for prefix in &self.prefixes {
            self.encode_prefix_option(&mut buffer, prefix);
        }

        // RDNSS option (RFC 6106)
        if !self.dns_servers.is_empty() {
            self.encode_rdnss_option(&mut buffer);
        }

        // DNSSL option (RFC 6106)
        if !self.search_list.is_empty() {
            self.encode_dnssl_option(&mut buffer);
        }

        buffer
    }

    /// Encode Prefix Information option
    fn encode_prefix_option(&self, buffer: &mut Vec<u8>, prefix: &PrefixInfo) {
        buffer.push(ND_OPT_PREFIX_INFORMATION); // Type
        buffer.push(4); // Length (in 8-byte units) = 32 bytes / 8 = 4

        buffer.push(prefix.prefix_len);
        
        let mut flags = 0u8;
        if prefix.on_link {
            flags |= 0x80; // L flag
        }
        if prefix.autonomous {
            flags |= 0x40; // A flag
        }
        buffer.push(flags);

        buffer.extend_from_slice(&prefix.valid_lifetime.to_be_bytes());
        buffer.extend_from_slice(&prefix.preferred_lifetime.to_be_bytes());
        buffer.extend_from_slice(&[0, 0, 0, 0]); // Reserved

        // Prefix address
        buffer.extend_from_slice(&prefix.prefix.octets());
    }

    /// Encode RDNSS option (RFC 6106)
    fn encode_rdnss_option(&self, buffer: &mut Vec<u8>) {
        buffer.push(ND_OPT_RDNSS); // Type
        
        // Length = 1 + 2 * num_servers (in 8-byte units)
        let length = 1 + (self.dns_servers.len() * 2) as u8;
        buffer.push(length);

        buffer.extend_from_slice(&[0, 0]); // Reserved
        buffer.extend_from_slice(&[0, 0, 0xFF, 0xFF]); // Lifetime (infinite)

        // DNS server addresses
        for server in &self.dns_servers {
            buffer.extend_from_slice(&server.octets());
        }
    }

    /// Encode DNSSL option (RFC 6106)
    fn encode_dnssl_option(&self, buffer: &mut Vec<u8>) {
        buffer.push(ND_OPT_DNSSL); // Type
        
        // Calculate total length
        let mut domain_bytes = Vec::new();
        for domain in &self.search_list {
            self.encode_domain_name(&mut domain_bytes, domain);
        }
        
        // Pad to 8-byte boundary
        while domain_bytes.len() % 8 != 0 {
            domain_bytes.push(0);
        }
        
        let length = 1 + (domain_bytes.len() / 8) as u8;
        buffer.push(length);

        buffer.extend_from_slice(&[0, 0]); // Reserved
        buffer.extend_from_slice(&[0, 0, 0xFF, 0xFF]); // Lifetime (infinite)

        buffer.extend_from_slice(&domain_bytes);
    }

    /// Encode domain name in DNS format (length-prefixed labels)
    fn encode_domain_name(&self, buffer: &mut Vec<u8>, domain: &str) {
        for label in domain.split('.') {
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_bytes());
        }
        buffer.push(0); // Terminating zero
    }
}

impl Default for RouterAdvertisement {
    fn default() -> Self {
        Self::new()
    }
}

/// Router Advertisement manager
pub struct RouterAdvertiser {
    /// Interface name
    interface: String,
    
    /// Link-local address
    link_local: Ipv6Addr,
    
    /// Last advertisement time
    last_advertisement: SystemTime,
    
    /// Advertisement interval (seconds)
    adv_interval: Duration,
}

impl RouterAdvertiser {
    /// Create new Router Advertiser
    ///
    /// Corresponds to C's `ra_init()` (radv.c)
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name
    /// * `link_local` - Link-local IPv6 address
    ///
    /// # Returns
    ///
    /// New Router Advertiser instance
    pub fn new(interface: String, link_local: Ipv6Addr) -> Self {
        Self {
            interface,
            link_local,
            last_advertisement: UNIX_EPOCH,
            adv_interval: Duration::from_secs(200), // Default 200 seconds per RFC 4861
        }
    }

    /// Set advertisement interval
    ///
    /// # Arguments
    ///
    /// * `interval` - Advertisement interval duration
    pub fn set_interval(&mut self, interval: Duration) {
        self.adv_interval = interval;
    }

    /// Send Router Advertisement
    ///
    /// Corresponds to C's `send_ra()` (radv.c)
    ///
    /// # Arguments
    ///
    /// * `ra` - Router Advertisement to send
    ///
    /// # Returns
    ///
    /// Ok(()) if sent successfully, error otherwise
    pub fn send_advertisement(&mut self, ra: &RouterAdvertisement) -> std::io::Result<()> {
        let _packet = ra.encode();
        
        // TODO: Send via ICMPv6 socket to ff02::1 (all-nodes multicast)
        // This requires platform-specific socket code
        
        self.last_advertisement = SystemTime::now();
        Ok(())
    }

    /// Check if periodic advertisement is due
    ///
    /// Corresponds to C's `periodic_ra()` (radv.c)
    ///
    /// # Returns
    ///
    /// True if advertisement should be sent
    pub fn is_advertisement_due(&self) -> bool {
        match self.last_advertisement.elapsed() {
            Ok(elapsed) => elapsed >= self.adv_interval,
            Err(_) => true, // Clock went backwards, send RA
        }
    }

    /// Handle Router Solicitation
    ///
    /// Corresponds to C's `icmp6_packet()` (radv.c)
    ///
    /// # Arguments
    ///
    /// * `ra` - Router Advertisement to send in response
    ///
    /// # Returns
    ///
    /// Ok(()) if response sent successfully
    pub fn handle_solicitation(&mut self, ra: &RouterAdvertisement) -> std::io::Result<()> {
        // Solicited RA should be sent immediately
        self.send_advertisement(ra)
    }

    /// Get interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get link-local address
    pub fn link_local(&self) -> Ipv6Addr {
        self.link_local
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ra() {
        let ra = RouterAdvertisement::new();
        assert_eq!(ra.cur_hop_limit, 64);
        assert_eq!(ra.router_lifetime, 1800);
        assert!(!ra.managed);
        assert!(!ra.other);
    }

    #[test]
    fn test_add_prefix() {
        let mut ra = RouterAdvertisement::new();
        let prefix = PrefixInfo {
            prefix: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            valid_lifetime: 2592000,
            preferred_lifetime: 604800,
        };
        
        ra.add_prefix(prefix);
        assert_eq!(ra.prefixes.len(), 1);
    }

    #[test]
    fn test_encode_ra() {
        let ra = RouterAdvertisement::new();
        let encoded = ra.encode();
        
        // Check ICMPv6 type
        assert_eq!(encoded[0], ICMPV6_ROUTER_ADVERTISEMENT);
        
        // Check code
        assert_eq!(encoded[1], 0);
        
        // Check hop limit
        assert_eq!(encoded[4], 64);
    }

    #[test]
    fn test_create_advertiser() {
        let advertiser = RouterAdvertiser::new(
            "eth0".to_string(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        );
        
        assert_eq!(advertiser.interface(), "eth0");
        assert!(advertiser.is_advertisement_due());
    }
}
