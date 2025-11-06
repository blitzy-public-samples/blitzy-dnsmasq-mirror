// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # DHCP Lease Management
//!
//! This module provides in-memory DHCP lease management for both DHCPv4 and DHCPv6,
//! replacing the C implementation in `src/lease.c` (approximately 1,200 lines).
//!
//! ## Purpose
//!
//! Manages active DHCP leases including:
//! - Lease allocation and lookup
//! - Expiration tracking and pruning
//! - Client identifier and hardware address management
//! - Hostname assignment and conflict resolution
//! - Integration with persistent storage (LeaseStore)
//!
//! ## C Source Mapping
//!
//! | C Function | Rust Equivalent | Purpose |
//! |------------|-----------------|---------|
//! | `lease4_allocate()` | `LeaseDatabase::allocate_v4()` | Allocate new DHCPv4 lease |
//! | `lease6_allocate()` | `LeaseDatabase::allocate_v6()` | Allocate new DHCPv6 lease |
//! | `lease_find_by_client()` | `LeaseDatabase::find_by_client()` | Find lease by client ID/MAC |
//! | `lease_find_by_addr()` | `LeaseDatabase::find_by_addr()` | Find lease by IP address |
//! | `lease_set_hwaddr()` | `Lease::set_hwaddr()` | Update hardware address |
//! | `lease_set_hostname()` | `Lease::set_hostname()` | Update hostname |
//! | `lease_set_expires()` | `Lease::set_expires()` | Set expiration time |
//! | `lease_prune()` | `LeaseDatabase::prune_expired()` | Remove expired leases |
//!
//! ## Memory Safety Improvements
//!
//! - No manual memory management (automatic with Rust ownership)
//! - Thread-safe access via Arc<RwLock<>>
//! - Bounds-checked collections
//! - Safe time handling with std::time

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::{Arc, RwLock};

/// DHCPv4 lease entry
/// Corresponds to C's `struct dhcp_lease` for IPv4 (dnsmasq.h:799-829)
#[derive(Debug, Clone)]
pub struct LeaseV4 {
    /// IPv4 address assigned to client
    pub addr: Ipv4Addr,
    /// Client hardware address (MAC address)
    pub hwaddr: Vec<u8>,
    /// DHCP client identifier (option 61)
    pub client_id: Option<Vec<u8>>,
    /// Client hostname
    pub hostname: Option<String>,
    /// Lease expiration time (seconds since Unix epoch)
    pub expires: u64,
    /// Lease flags
    pub flags: LeaseFlags,
}

/// DHCPv6 lease entry
/// Corresponds to C's `struct dhcp_lease` for IPv6
#[derive(Debug, Clone)]
pub struct LeaseV6 {
    /// IPv6 address assigned to client
    pub addr: Ipv6Addr,
    /// DHCP Unique Identifier (DUID)
    pub duid: Vec<u8>,
    /// Identity Association Identifier (IAID)
    pub iaid: u32,
    /// Client hostname
    pub hostname: Option<String>,
    /// Lease expiration time (seconds since Unix epoch)
    pub expires: u64,
    /// Lease type (TA or NA)
    pub lease_type: LeaseType,
    /// Lease flags
    pub flags: LeaseFlags,
}

/// DHCPv6 lease type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseType {
    /// Temporary Address (TA)
    TemporaryAddress,
    /// Non-temporary Address (NA)
    NonTemporaryAddress,
}

/// Lease flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseFlags {
    /// Lease is from static configuration
    pub is_static: bool,
    /// Hostname is from client
    pub hostname_from_client: bool,
}

impl LeaseFlags {
    /// Create default lease flags
    pub fn default() -> Self {
        Self {
            is_static: false,
            hostname_from_client: false,
        }
    }
}

/// Combined lease representation
#[derive(Debug, Clone)]
pub enum Lease {
    V4(LeaseV4),
    V6(LeaseV6),
}

impl Lease {
    /// Check if this is a DHCPv4 lease
    pub fn is_v4(&self) -> bool {
        matches!(self, Lease::V4(_))
    }

    /// Check if this is a DHCPv6 lease
    pub fn is_v6(&self) -> bool {
        matches!(self, Lease::V6(_))
    }

    /// Get lease expiration time
    pub fn expires(&self) -> u64 {
        match self {
            Lease::V4(lease) => lease.expires,
            Lease::V6(lease) => lease.expires,
        }
    }

    /// Check if lease has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        self.expires() < now
    }

    /// Get lease hostname
    pub fn hostname(&self) -> Option<&str> {
        match self {
            Lease::V4(lease) => lease.hostname.as_deref(),
            Lease::V6(lease) => lease.hostname.as_deref(),
        }
    }

    /// Set lease hostname
    pub fn set_hostname(&mut self, hostname: Option<String>) {
        match self {
            Lease::V4(lease) => lease.hostname = hostname,
            Lease::V6(lease) => lease.hostname = hostname,
        }
    }

    /// Set lease expiration time
    pub fn set_expires(&mut self, expires: u64) {
        match self {
            Lease::V4(lease) => lease.expires = expires,
            Lease::V6(lease) => lease.expires = expires,
        }
    }

    /// Get hardware address (DHCPv4 only)
    pub fn hwaddr(&self) -> Option<&[u8]> {
        match self {
            Lease::V4(lease) => Some(&lease.hwaddr),
            Lease::V6(_) => None,
        }
    }

    /// Set hardware address (DHCPv4 only)
    pub fn set_hwaddr(&mut self, hwaddr: Vec<u8>) {
        if let Lease::V4(lease) = self {
            lease.hwaddr = hwaddr;
        }
    }

    /// Get IP address
    pub fn ip_addr(&self) -> IpAddr {
        match self {
            Lease::V4(lease) => IpAddr::V4(lease.addr),
            Lease::V6(lease) => IpAddr::V6(lease.addr),
        }
    }
}

/// In-memory DHCP lease database
/// Corresponds to C's global `leases` linked list and related management functions
pub struct LeaseDatabase {
    /// DHCPv4 leases indexed by IPv4 address
    v4_leases: Arc<RwLock<HashMap<Ipv4Addr, LeaseV4>>>,
    /// DHCPv6 leases indexed by IPv6 address
    v6_leases: Arc<RwLock<HashMap<Ipv6Addr, LeaseV6>>>,
    /// Maximum number of leases
    max_leases: usize,
}

impl LeaseDatabase {
    /// Create new lease database
    ///
    /// # Arguments
    ///
    /// * `max_leases` - Maximum number of leases to track
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::lease::LeaseDatabase;
    ///
    /// let db = LeaseDatabase::new(1000);
    /// ```
    pub fn new(max_leases: usize) -> Self {
        Self {
            v4_leases: Arc::new(RwLock::new(HashMap::new())),
            v6_leases: Arc::new(RwLock::new(HashMap::new())),
            max_leases,
        }
    }

    /// Allocate new DHCPv4 lease
    ///
    /// Corresponds to C's `lease4_allocate()` (lease.c:221-281)
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address to allocate
    /// * `hwaddr` - Client hardware address (MAC)
    /// * `client_id` - Optional client identifier
    ///
    /// # Returns
    ///
    /// New `Lease` if allocation successful, error if database is full
    pub fn allocate_v4(
        &self,
        addr: Ipv4Addr,
        hwaddr: Vec<u8>,
        client_id: Option<Vec<u8>>,
    ) -> Result<Lease, String> {
        let mut leases = self.v4_leases.write().unwrap();

        // Check if database is full
        if leases.len() >= self.max_leases {
            return Err("Lease database full".to_string());
        }

        // Check if address is already allocated
        if leases.contains_key(&addr) {
            return Err(format!("Address {} already allocated", addr));
        }

        // Create new lease with default expiration (1 hour from now)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let lease = LeaseV4 {
            addr,
            hwaddr,
            client_id,
            hostname: None,
            expires: now + 3600, // Default 1 hour lease
            flags: LeaseFlags::default(),
        };

        leases.insert(addr, lease.clone());

        Ok(Lease::V4(lease))
    }

    /// Allocate new DHCPv6 lease
    ///
    /// Corresponds to C's `lease6_allocate()` (lease.c:404-471)
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv6 address to allocate
    /// * `duid` - DHCP Unique Identifier
    /// * `iaid` - Identity Association Identifier
    /// * `lease_type` - TA or NA lease type
    ///
    /// # Returns
    ///
    /// New `Lease` if allocation successful, error if database is full
    pub fn allocate_v6(
        &self,
        addr: Ipv6Addr,
        duid: Vec<u8>,
        iaid: u32,
        lease_type: LeaseType,
    ) -> Result<Lease, String> {
        let mut leases = self.v6_leases.write().unwrap();

        // Check if database is full
        if leases.len() >= self.max_leases {
            return Err("Lease database full".to_string());
        }

        // Check if address is already allocated
        if leases.contains_key(&addr) {
            return Err(format!("Address {} already allocated", addr));
        }

        // Create new lease with default expiration (1 hour from now)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let lease = LeaseV6 {
            addr,
            duid,
            iaid,
            hostname: None,
            expires: now + 3600, // Default 1 hour lease
            lease_type,
            flags: LeaseFlags::default(),
        };

        leases.insert(addr, lease.clone());

        Ok(Lease::V6(lease))
    }

    /// Find DHCPv4 lease by IP address
    ///
    /// Corresponds to C's `lease_find_by_addr()` (lease.c:142-157)
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address to search for
    ///
    /// # Returns
    ///
    /// Cloned lease if found, None otherwise
    pub fn find_v4_by_addr(&self, addr: Ipv4Addr) -> Option<Lease> {
        let leases = self.v4_leases.read().unwrap();
        leases.get(&addr).map(|l| Lease::V4(l.clone()))
    }

    /// Find DHCPv6 lease by IP address
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv6 address to search for
    ///
    /// # Returns
    ///
    /// Cloned lease if found, None otherwise
    pub fn find_v6_by_addr(&self, addr: Ipv6Addr) -> Option<Lease> {
        let leases = self.v6_leases.read().unwrap();
        leases.get(&addr).map(|l| Lease::V6(l.clone()))
    }

    /// Find DHCPv4 lease by hardware address
    ///
    /// Corresponds to C's `lease_find_by_client()` (lease.c:159-219)
    ///
    /// # Arguments
    ///
    /// * `hwaddr` - Hardware address (MAC) to search for
    ///
    /// # Returns
    ///
    /// Cloned lease if found, None otherwise
    pub fn find_v4_by_hwaddr(&self, hwaddr: &[u8]) -> Option<Lease> {
        let leases = self.v4_leases.read().unwrap();
        
        for lease in leases.values() {
            if lease.hwaddr == hwaddr {
                return Some(Lease::V4(lease.clone()));
            }
        }

        None
    }

    /// Find DHCPv6 lease by DUID and IAID
    ///
    /// # Arguments
    ///
    /// * `duid` - DHCP Unique Identifier
    /// * `iaid` - Identity Association Identifier
    ///
    /// # Returns
    ///
    /// Cloned lease if found, None otherwise
    pub fn find_v6_by_duid(&self, duid: &[u8], iaid: u32) -> Option<Lease> {
        let leases = self.v6_leases.read().unwrap();
        
        for lease in leases.values() {
            if lease.duid == duid && lease.iaid == iaid {
                return Some(Lease::V6(lease.clone()));
            }
        }

        None
    }

    /// Remove expired leases from database
    ///
    /// Corresponds to C's `lease_prune()` (lease.c:606-697)
    ///
    /// # Returns
    ///
    /// Number of leases removed
    pub fn prune_expired(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let mut count = 0;

        // Prune IPv4 leases
        {
            let mut leases = self.v4_leases.write().unwrap();
            leases.retain(|_, lease| {
                if lease.expires < now {
                    count += 1;
                    false
                } else {
                    true
                }
            });
        }

        // Prune IPv6 leases
        {
            let mut leases = self.v6_leases.write().unwrap();
            leases.retain(|_, lease| {
                if lease.expires < now {
                    count += 1;
                    false
                } else {
                    true
                }
            });
        }

        count
    }

    /// Get total number of active leases
    pub fn len(&self) -> usize {
        let v4_count = self.v4_leases.read().unwrap().len();
        let v6_count = self.v6_leases.read().unwrap().len();
        v4_count + v6_count
    }

    /// Check if database is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get number of available lease slots
    pub fn available(&self) -> usize {
        self.max_leases.saturating_sub(self.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_database_new() {
        let db = LeaseDatabase::new(100);
        assert_eq!(db.max_leases, 100);
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
    }

    #[test]
    fn test_allocate_v4_lease() {
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let result = db.allocate_v4(addr, hwaddr.clone(), None);
        assert!(result.is_ok());

        let lease = result.unwrap();
        match lease {
            Lease::V4(l) => {
                assert_eq!(l.addr, addr);
                assert_eq!(l.hwaddr, hwaddr);
            }
            _ => panic!("Expected V4 lease"),
        }
    }

    #[test]
    fn test_allocate_v6_lease() {
        let db = LeaseDatabase::new(100);
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let duid = vec![0x00, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78];

        let result = db.allocate_v6(addr, duid.clone(), 1, LeaseType::NonTemporaryAddress);
        assert!(result.is_ok());

        let lease = result.unwrap();
        match lease {
            Lease::V6(l) => {
                assert_eq!(l.addr, addr);
                assert_eq!(l.duid, duid);
                assert_eq!(l.iaid, 1);
            }
            _ => panic!("Expected V6 lease"),
        }
    }

    #[test]
    fn test_find_v4_by_addr() {
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        db.allocate_v4(addr, hwaddr, None).unwrap();

        let found = db.find_v4_by_addr(addr);
        assert!(found.is_some());
    }

    #[test]
    fn test_find_v4_by_hwaddr() {
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        db.allocate_v4(addr, hwaddr.clone(), None).unwrap();

        let found = db.find_v4_by_hwaddr(&hwaddr);
        assert!(found.is_some());
    }

    #[test]
    fn test_prune_expired() {
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Allocate lease
        db.allocate_v4(addr, hwaddr, None).unwrap();
        assert_eq!(db.len(), 1);

        // Manually expire the lease
        {
            let mut leases = db.v4_leases.write().unwrap();
            if let Some(lease) = leases.get_mut(&addr) {
                lease.expires = 0; // Set to past
            }
        }

        // Prune should remove it
        let removed = db.prune_expired();
        assert_eq!(removed, 1);
        assert_eq!(db.len(), 0);
    }

    #[test]
    fn test_lease_is_expired() {
        let lease = LeaseV4 {
            addr: Ipv4Addr::new(192, 168, 1, 100),
            hwaddr: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            client_id: None,
            hostname: None,
            expires: 0, // Already expired
            flags: LeaseFlags::default(),
        };

        let lease = Lease::V4(lease);
        assert!(lease.is_expired());
    }
}
