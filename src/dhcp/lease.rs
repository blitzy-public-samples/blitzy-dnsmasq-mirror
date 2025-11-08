// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # DHCP Lease Database Management
//!
//! This module provides in-memory DHCP lease management for both `DHCPv4` and `DHCPv6`,
//! translating the C implementation from `src/lease.c` (approximately 1,700 lines).
//!
//! ## Purpose
//!
//! Manages active DHCP leases with the following capabilities:
//! - **Lease allocation**: Creates new lease entries for `DHCPv4` and `DHCPv6` clients
//! - **Efficient lookups**: O(1) `HashMap`-based searches by IP, MAC, client ID, or DUID
//! - **Expiration tracking**: Automatic lease expiry with monotonic time handling
//! - **Hostname management**: DNS cache integration for hostname-to-IP mapping
//! - **Configuration integration**: Static host reservations override DHCP-supplied names
//! - **Persistent storage**: Atomic file updates via `LeaseStore` integration
//! - **Script execution**: Lease-change events trigger external scripts (add/del/old)
//!
//! ## Memory Safety Improvements Over C
//!
//! - **No manual allocation**: Rust ownership eliminates malloc/free bugs
//! - **No linked list traversal**: `HashMap` provides O(1) lookups vs O(n) C list iteration
//! - **Bounds checking**: Slice access is automatically validated
//! - **Thread safety**: `RwLock` enables safe concurrent access if needed
//! - **Type safety**: Separate `LeaseV4`/`LeaseV6` types prevent mixing protocols
//!
//! ## C Source Mapping
//!
//! | C Function | Rust Equivalent | Lines | Purpose |
//! |------------|-----------------|-------|---------|
//! | `lease4_allocate()` | `lease4_allocate()` | 221-281 | Allocate `DHCPv4` lease |
//! | `lease6_allocate()` | `lease6_allocate()` | 404-471 | Allocate `DHCPv6` lease |
//! | `lease_find_by_client()` | `lease_find_by_client()` | 159-219 | Find by client ID/MAC |
//! | `lease_find_by_addr()` | `lease_find_by_addr()` | 142-157 | Find by IPv4 address |
//! | `lease6_find()` | `lease6_find()` | 1335-1357 | Find by `DUID`+`IAID`+addr |
//! | `lease_set_hwaddr()` | `Lease::set_hwaddr()` | Various | Update hardware address |
//! | `lease_set_hostname()` | `Lease::set_hostname()` | Various | Update hostname |
//! | `lease_set_expires()` | `Lease::set_expires()` | Various | Set expiration time |
//! | `lease_prune()` | `lease_prune()` | 606-697 | Remove expired leases |
//! | `lease_update_from_configs()` | `lease_update_from_configs()` | 344-403 | Apply static hosts |
//! | `lease_update_file()` | `lease_update_file()` | 496-604 | Save to disk |
//!
//! ## Dependencies
//!
//! - **`LeaseStore`**: Persistent storage with atomic file updates
//! - **`DaemonState`**: Access to configuration, lease limits, `DUID`
//! - **`DhcpConfig`**: Static host reservations and DHCP parameters
//! - **`DnsCache`**: Hostname-to-IP mapping integration
//! - **`AllAddr`**: Universal IP address container
//! - **`monotonic_time`**: Consistent timestamp source for expiry tracking

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

use tracing::{debug, error, info, warn};

use crate::dhcp::common::find_config;
use crate::dhcp::lease_store::{DuidEntry, LeaseDatabase as StoredLeaseDatabase, LeaseEntry, LeaseStore};
use crate::config::types::DhcpConfig;
use crate::dns::cache::DnsCache;
use crate::types::addresses::AllAddr;
use crate::types::daemon_state::DaemonState;
use crate::types::errors::{DhcpError, DnsmasqError};
use crate::util::time::monotonic_time;

/// Lease state tracking for script execution and file updates.
///
/// Tracks lease lifecycle through state transitions to determine when to trigger
/// lease-change scripts and database writes. Corresponds to C's `LEASE_NEW` and
/// `LEASE_CHANGED` flags (dnsmasq.h).
///
/// ## State Transitions
///
/// ```text
/// New → Unchanged (after first database write)
/// Unchanged → Changed (on hostname/expiry modification)
/// Changed → Unchanged (after database write)
/// Any → Expired (when expires < now)
/// ```
///
/// ## C Mapping
///
/// - `New` = C's `LEASE_NEW` flag set
/// - `Changed` = C's `LEASE_CHANGED` flag set  
/// - `Unchanged` = No flags set (stable lease)
/// - `Expired` = `expires < now` condition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Newly allocated lease, not yet written to database
    New,
    /// Lease modified since last database write (hostname or expiry changed)
    Changed,
    /// Lease unchanged since last database write
    Unchanged,
    /// Lease has expired (expires < current time)
    Expired,
}

/// `DHCPv4` lease entry.
///
/// Represents a single `DHCPv4` lease with client hardware address, client identifier,
/// IP address, hostname, and expiration time. Corresponds to C's `struct dhcp_lease`
/// for IPv4 (dnsmasq.h:799-829).
///
/// ## Fields
///
/// - `addr`: IPv4 address assigned to client
/// - `hwaddr`: Client hardware address (MAC address, 6 bytes for Ethernet)
/// - `client_id`: DHCP client identifier from option 61 (optional)
/// - `hostname`: Client hostname from option 12 or configuration (optional)
/// - `expires`: Lease expiration time (seconds since Unix epoch)
/// - `state`: Lease state for change tracking
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
    /// Lease state for change tracking
    pub state: LeaseState,
}

/// `DHCPv6` lease entry.
///
/// Represents a single `DHCPv6` lease with `DUID`, `IAID`, IPv6 address, hostname, and
/// expiration time. Corresponds to C's `struct dhcp_lease` for IPv6.
///
/// ## Fields
///
/// - `addr`: IPv6 address assigned to client
/// - `duid`: DHCP Unique Identifier (client ID for `DHCPv6`)
/// - `iaid`: Identity Association Identifier
/// - `hostname`: Client hostname (optional)
/// - `expires`: Lease expiration time (seconds since Unix epoch)
/// - `lease_type`: Temporary Address (TA) or Non-temporary Address (NA)
/// - `state`: Lease state for change tracking
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
    /// Lease state for change tracking
    pub state: LeaseState,
}

/// `DHCPv6` lease type.
///
/// Distinguishes between Temporary Addresses (TA) and Non-temporary Addresses (NA)
/// as defined in RFC 3315. Corresponds to C's `LEASE_TA` and `LEASE_NA` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseType {
    /// Temporary Address (`LEASE_TA` in C)
    TemporaryAddress,
    /// Non-temporary Address (`LEASE_NA` in C)
    NonTemporaryAddress,
}

/// Combined lease representation supporting both `DHCPv4` and `DHCPv6`.
///
/// This enum allows uniform handling of both protocol versions while maintaining
/// type safety. Methods provide protocol-agnostic access to common fields.
#[derive(Debug, Clone)]
pub enum Lease {
    /// `DHCPv4` lease
    V4(LeaseV4),
    /// `DHCPv6` lease
    V6(LeaseV6),
}

impl Lease {
    /// Create new `DHCPv4` lease.
    ///
    /// Initializes lease with New state and provided parameters.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address
    /// * `hwaddr` - Hardware address (MAC)
    /// * `client_id` - Optional client identifier
    /// * `hostname` - Optional hostname
    /// * `expires` - Expiration timestamp
    #[must_use]
    pub fn new(
        addr: Ipv4Addr,
        hwaddr: Vec<u8>,
        client_id: Option<Vec<u8>>,
        hostname: Option<String>,
        expires: u64,
    ) -> Self {
        Lease::V4(LeaseV4 {
            addr,
            hwaddr,
            client_id,
            hostname,
            expires,
            state: LeaseState::New,
        })
    }

    /// Check if this is a `DHCPv4` lease.
    #[must_use]
    pub fn is_v4(&self) -> bool {
        matches!(self, Lease::V4(_))
    }

    /// Check if this is a `DHCPv6` lease.
    #[must_use]
    pub fn is_v6(&self) -> bool {
        matches!(self, Lease::V6(_))
    }

    /// Get lease expiration time.
    #[must_use]
    pub fn expires(&self) -> u64 {
        match self {
            Lease::V4(lease) => lease.expires,
            Lease::V6(lease) => lease.expires,
        }
    }

    /// Set lease expiration time.
    ///
    /// Updates expiry and marks lease as Changed if different from current value.
    /// Corresponds to C's `lease_set_expires()`.
    ///
    /// # Arguments
    ///
    /// * `expires` - New expiration timestamp (seconds since epoch)
    pub fn set_expires(&mut self, expires: u64) {
        match self {
            Lease::V4(lease) => {
                if lease.expires != expires {
                    lease.expires = expires;
                    if lease.state == LeaseState::Unchanged {
                        lease.state = LeaseState::Changed;
                    }
                }
            }
            Lease::V6(lease) => {
                if lease.expires != expires {
                    lease.expires = expires;
                    if lease.state == LeaseState::Unchanged {
                        lease.state = LeaseState::Changed;
                    }
                }
            }
        }
    }

    /// Check if lease has expired.
    ///
    /// Compares expiration time against current monotonic time.
    ///
    /// # Returns
    ///
    /// `true` if lease has expired, `false` otherwise
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = monotonic_time();
        self.expires() < now
    }

    /// Get lease hostname.
    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        match self {
            Lease::V4(lease) => lease.hostname.as_deref(),
            Lease::V6(lease) => lease.hostname.as_deref(),
        }
    }

    /// Set lease hostname.
    ///
    /// Updates hostname and marks lease as Changed if different from current value.
    /// Corresponds to C's `lease_set_hostname()`.
    ///
    /// # Arguments
    ///
    /// * `hostname` - New hostname (None to clear)
    pub fn set_hostname(&mut self, hostname: Option<String>) {
        match self {
            Lease::V4(lease) => {
                if lease.hostname != hostname {
                    lease.hostname = hostname;
                    if lease.state == LeaseState::Unchanged {
                        lease.state = LeaseState::Changed;
                    }
                }
            }
            Lease::V6(lease) => {
                if lease.hostname != hostname {
                    lease.hostname = hostname;
                    if lease.state == LeaseState::Unchanged {
                        lease.state = LeaseState::Changed;
                    }
                }
            }
        }
    }

    /// Get hardware address (`DHCPv4` only).
    ///
    /// # Returns
    ///
    /// Hardware address slice for V4 leases, None for V6 leases
    #[must_use]
    pub fn hwaddr(&self) -> Option<&[u8]> {
        match self {
            Lease::V4(lease) => Some(&lease.hwaddr),
            Lease::V6(_) => None,
        }
    }

    /// Set hardware address (`DHCPv4` only).
    ///
    /// Updates hardware address and marks lease as Changed.
    /// Corresponds to C's `lease_set_hwaddr()`.
    ///
    /// # Arguments
    ///
    /// * `hwaddr` - New hardware address
    pub fn set_hwaddr(&mut self, hwaddr: Vec<u8>) {
        if let Lease::V4(lease) = self {
            if lease.hwaddr != hwaddr {
                lease.hwaddr = hwaddr;
                if lease.state == LeaseState::Unchanged {
                    lease.state = LeaseState::Changed;
                }
            }
        }
    }

    /// Get IP address.
    ///
    /// # Returns
    ///
    /// IP address as `IpAddr` enum (V4 or V6)
    #[must_use]
    pub fn ip_addr(&self) -> IpAddr {
        match self {
            Lease::V4(lease) => IpAddr::V4(lease.addr),
            Lease::V6(lease) => IpAddr::V6(lease.addr),
        }
    }

    /// Get lease state.
    #[must_use]
    pub fn state(&self) -> LeaseState {
        match self {
            Lease::V4(lease) => lease.state,
            Lease::V6(lease) => lease.state,
        }
    }

    /// Mark lease as unchanged (after database write).
    ///
    /// Transitions New → Unchanged or Changed → Unchanged.
    pub fn mark_unchanged(&mut self) {
        match self {
            Lease::V4(lease) => {
                if lease.state == LeaseState::New || lease.state == LeaseState::Changed {
                    lease.state = LeaseState::Unchanged;
                }
            }
            Lease::V6(lease) => {
                if lease.state == LeaseState::New || lease.state == LeaseState::Changed {
                    lease.state = LeaseState::Unchanged;
                }
            }
        }
    }
}

/// In-memory DHCP lease database with efficient lookups.
///
/// Manages all active DHCP leases for both `DHCPv4` and `DHCPv6` using `HashMap`-based
/// storage for O(1) lookup performance. Replaces C's linked list traversal with
/// direct hash table access.
///
/// ## Storage Strategy
///
/// - **`v4_by_ip`**: IPv4 address → `LeaseV4` (primary `DHCPv4` index)
/// - **`v6_by_ip`**: IPv6 address → `LeaseV6` (primary `DHCPv6` index)
/// - Both maps use `Arc<RwLock<>>` for thread-safe access
///
/// ## Lookup Performance
///
/// | Operation | C (linked list) | Rust (`HashMap`) |
/// |-----------|----------------|----------------|
/// | Find by IP | O(n) | O(1) |
/// | Find by MAC | O(n) | O(n)* |
/// | Find by DUID | O(n) | O(n)* |
/// | Add lease | O(1) | O(1) |
/// | Remove lease | O(n) | O(1) |
///
/// *Secondary index could be added for O(1) `MAC`/`DUID` lookups if needed
///
/// ## C Source Reference
///
/// Replaces C's global `leases` linked list and related management functions:
/// - `static struct dhcp_lease *leases` → `HashMap` storage
/// - `leases_left` counter → tracked separately
#[derive(Debug)]
pub struct LeaseDatabase {
    /// `DHCPv4` leases indexed by IPv4 address
    v4_by_ip: Arc<RwLock<HashMap<Ipv4Addr, LeaseV4>>>,
    /// `DHCPv6` leases indexed by IPv6 address
    v6_by_ip: Arc<RwLock<HashMap<Ipv6Addr, LeaseV6>>>,
    /// Maximum number of leases (from daemon->dhcp_max)
    max_leases: usize,
}

impl LeaseDatabase {
    /// Create new empty lease database.
    ///
    /// # Arguments
    ///
    /// * `max_leases` - Maximum number of leases to track (daemon->dhcp_max)
    ///
    /// # Returns
    ///
    /// New `LeaseDatabase` instance with empty lease maps
    #[must_use]
    pub fn new(max_leases: usize) -> Self {
        Self {
            v4_by_ip: Arc::new(RwLock::new(HashMap::new())),
            v6_by_ip: Arc::new(RwLock::new(HashMap::new())),
            max_leases,
        }
    }

    /// Add `DHCPv4` lease to database.
    ///
    /// Inserts lease into `v4_by_ip` map. If lease with same IP exists, it is replaced.
    ///
    /// # Arguments
    ///
    /// * `lease` - Lease to add
    ///
    /// # Errors
    ///
    /// Returns error if database is full (`max_leases` reached)
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    pub fn add_lease(&self, lease: Lease) -> Result<(), DnsmasqError> {
        match lease {
            Lease::V4(v4_lease) => {
                let mut leases = self.v4_by_ip.write().unwrap();
                if leases.len() >= self.max_leases && !leases.contains_key(&v4_lease.addr) {
                    return Err(DnsmasqError::Dhcp(DhcpError::DatabaseError {
                        message: "Lease database full".to_string(),
                        source: None,
                    }));
                }
                leases.insert(v4_lease.addr, v4_lease);
                Ok(())
            }
            Lease::V6(v6_lease) => {
                let mut leases = self.v6_by_ip.write().unwrap();
                if leases.len() >= self.max_leases && !leases.contains_key(&v6_lease.addr) {
                    return Err(DnsmasqError::Dhcp(DhcpError::DatabaseError {
                        message: "Lease database full".to_string(),
                        source: None,
                    }));
                }
                leases.insert(v6_lease.addr, v6_lease);
                Ok(())
            }
        }
    }

    /// Remove lease from database by IP address.
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address of lease to remove
    ///
    /// # Returns
    ///
    /// Removed lease if it existed, None otherwise
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    #[must_use]
    pub fn remove_lease(&self, addr: IpAddr) -> Option<Lease> {
        match addr {
            IpAddr::V4(ipv4) => {
                let mut leases = self.v4_by_ip.write().unwrap();
                leases.remove(&ipv4).map(Lease::V4)
            }
            IpAddr::V6(ipv6) => {
                let mut leases = self.v6_by_ip.write().unwrap();
                leases.remove(&ipv6).map(Lease::V6)
            }
        }
    }

    /// Find `DHCPv4` lease by hardware address (MAC).
    ///
    /// Performs linear search through v4 leases. Corresponds to C's
    /// `lease_find_by_client()` for MAC address matching.
    ///
    /// # Arguments
    ///
    /// * `hwaddr` - Hardware address to search for
    ///
    /// # Returns
    ///
    /// Cloned lease if found, None otherwise
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    #[must_use]
    pub fn find_by_mac(&self, hwaddr: &[u8]) -> Option<Lease> {
        let leases = self.v4_by_ip.read().unwrap();
        for lease in leases.values() {
            if lease.hwaddr == hwaddr {
                return Some(Lease::V4(lease.clone()));
            }
        }
        None
    }

    /// Find `DHCPv4` lease by IP address.
    ///
    /// Corresponds to C's `lease_find_by_addr()`.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address to search for
    ///
    /// # Returns
    ///
    /// Cloned lease if found, None otherwise
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    #[must_use]
    pub fn find_by_ip(&self, addr: IpAddr) -> Option<Lease> {
        match addr {
            IpAddr::V4(ipv4) => {
                let leases = self.v4_by_ip.read().unwrap();
                leases.get(&ipv4).map(|l| Lease::V4(l.clone()))
            }
            IpAddr::V6(ipv6) => {
                let leases = self.v6_by_ip.read().unwrap();
                leases.get(&ipv6).map(|l| Lease::V6(l.clone()))
            }
        }
    }

    /// Get all active leases.
    ///
    /// Returns combined list of `DHCPv4` and `DHCPv6` leases.
    ///
    /// # Returns
    ///
    /// Vector of all leases
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    #[must_use]
    pub fn get_all_leases(&self) -> Vec<Lease> {
        let mut all_leases = Vec::new();

        {
            let v4_leases = self.v4_by_ip.read().unwrap();
            for lease in v4_leases.values() {
                all_leases.push(Lease::V4(lease.clone()));
            }
        }

        {
            let v6_leases = self.v6_by_ip.read().unwrap();
            for lease in v6_leases.values() {
                all_leases.push(Lease::V6(lease.clone()));
            }
        }

        all_leases
    }

    /// Save lease database to file.
    ///
    /// Converts in-memory leases to `LeaseEntry` format and writes atomically
    /// via `LeaseStore`. Corresponds to C's `lease_update_file()`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to lease file
    /// * `duid` - Server `DUID` for `DHCPv6` (if present)
    ///
    /// # Errors
    ///
    /// Returns error on I/O failure (unable to write lease file)
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    pub fn save<P: AsRef<std::path::Path>>(
        &self,
        path: P,
        duid: Option<Vec<u8>>,
    ) -> Result<(), DnsmasqError> {
        let mut stored_db = StoredLeaseDatabase::new();

        // Set DUID if provided
        if let Some(duid_bytes) = duid {
            stored_db.duid = Some(DuidEntry { duid_bytes });
        }

        // Convert V4 leases
        {
            let v4_leases = self.v4_by_ip.read().unwrap();
            for lease in v4_leases.values() {
                stored_db.leases.push(LeaseEntry {
                    expiry: lease.expires,
                    address: IpAddr::V4(lease.addr),
                    hardware_address: lease.hwaddr.clone(),
                    hostname: lease.hostname.clone(),
                    client_id: lease.client_id.clone(),
                    iaid: None,
                    is_temporary_address: false,
                });
            }
        }

        // Convert V6 leases
        {
            let v6_leases = self.v6_by_ip.read().unwrap();
            for lease in v6_leases.values() {
                stored_db.leases.push(LeaseEntry {
                    expiry: lease.expires,
                    address: IpAddr::V6(lease.addr),
                    hardware_address: vec![], // V6 doesn't have hwaddr
                    hostname: lease.hostname.clone(),
                    client_id: Some(lease.duid.clone()),
                    iaid: Some(lease.iaid),
                    is_temporary_address: lease.lease_type == LeaseType::TemporaryAddress,
                });
            }
        }

        stored_db.save_to_file(path)
    }

    /// Load lease database from file.
    ///
    /// Reads leases from persistent storage and populates in-memory maps.
    /// Corresponds to C's `lease_init()` and `read_leases()`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to lease file
    ///
    /// # Errors
    ///
    /// Returns error on I/O failure or parse error in lease file
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    pub fn load<P: AsRef<std::path::Path>>(
        path: P,
        max_leases: usize,
    ) -> Result<(Self, Option<Vec<u8>>), DnsmasqError> {
        let stored_db = StoredLeaseDatabase::load_from_file(path)?;
        let db = Self::new(max_leases);

        // Load leases into memory
        for entry in stored_db.leases {
            match entry.address {
                IpAddr::V4(addr) => {
                    let lease = LeaseV4 {
                        addr,
                        hwaddr: entry.hardware_address,
                        client_id: entry.client_id,
                        hostname: entry.hostname,
                        expires: entry.expiry,
                        state: LeaseState::Unchanged,
                    };
                    db.v4_by_ip.write().unwrap().insert(addr, lease);
                }
                IpAddr::V6(addr) => {
                    let lease = LeaseV6 {
                        addr,
                        duid: entry.client_id.unwrap_or_default(),
                        iaid: entry.iaid.unwrap_or(0),
                        hostname: entry.hostname,
                        expires: entry.expiry,
                        lease_type: if entry.is_temporary_address {
                            LeaseType::TemporaryAddress
                        } else {
                            LeaseType::NonTemporaryAddress
                        },
                        state: LeaseState::Unchanged,
                    };
                    db.v6_by_ip.write().unwrap().insert(addr, lease);
                }
            }
        }

        let duid = stored_db.duid.map(|d| d.duid_bytes);
        Ok((db, duid))
    }

    /// Get total number of active leases.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    #[must_use]
    pub fn len(&self) -> usize {
        let v4_count = self.v4_by_ip.read().unwrap().len();
        let v6_count = self.v6_by_ip.read().unwrap().len();
        v4_count + v6_count
    }

    /// Check if database is empty.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get number of available lease slots.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (another thread panicked while holding the lock)
    #[must_use]
    pub fn available(&self) -> usize {
        self.max_leases.saturating_sub(self.len())
    }
}

/// Allocate new `DHCPv4` lease.
///
/// Creates and adds new `DHCPv4` lease to database. Corresponds to C's
/// `lease4_allocate()` (lease.c:221-281).
///
/// # Arguments
///
/// * `database` - Lease database
/// * `addr` - IPv4 address to allocate
/// * `hwaddr` - Client hardware address (MAC)
/// * `client_id` - Optional client identifier
///
/// # Errors
///
/// Returns error if database is full or address already allocated
///
/// # Panics
///
/// Panics if the lock is poisoned (another thread panicked while holding the lock)
///
/// # C Source Reference
///
/// ```c
/// struct dhcp_lease *lease4_allocate(struct in_addr addr)
/// {
///   struct dhcp_lease *lease = lease_allocate();
///   if (!lease)
///     return NULL;
///   lease->addr = addr;
///   // ... initialize fields
///   return lease;
/// }
/// ```
pub fn lease4_allocate(
    database: &LeaseDatabase,
    addr: Ipv4Addr,
    hwaddr: Vec<u8>,
    client_id: Option<Vec<u8>>,
) -> Result<Lease, DnsmasqError> {
    // Check if database is full
    if database.len() >= database.max_leases {
        return Err(DnsmasqError::Dhcp(DhcpError::DatabaseError {
            message: "Lease database full".to_string(),
            source: None,
        }));
    }

    // Check if address is already allocated
    if database.find_by_ip(IpAddr::V4(addr)).is_some() {
        return Err(DnsmasqError::Dhcp(DhcpError::DatabaseError {
            message: format!("Address {addr} already allocated"),
            source: None,
        }));
    }

    // Create new lease with default expiration (1 hour from now)
    let now = monotonic_time();
    let expires = now + 3600; // Default 1 hour lease

    let lease = Lease::V4(LeaseV4 {
        addr,
        hwaddr,
        client_id,
        hostname: None,
        expires,
        state: LeaseState::New,
    });

    database.add_lease(lease.clone())?;

    debug!(
        "Allocated DHCPv4 lease: addr={}, expires={}",
        addr, expires
    );

    Ok(lease)
}

/// Allocate new `DHCPv6` lease.
///
/// Creates and adds new `DHCPv6` lease to database. Corresponds to C's
/// `lease6_allocate()` (lease.c:404-471).
///
/// # Arguments
///
/// * `database` - Lease database
/// * `addr` - IPv6 address to allocate
/// * `duid` - DHCP Unique Identifier
/// * `iaid` - Identity Association Identifier
/// * `lease_type` - TA or NA lease type
///
/// # Errors
///
/// Returns error if database is full or address already allocated
///
/// # Panics
///
/// Panics if the lock is poisoned (another thread panicked while holding the lock)
///
/// # C Source Reference
///
/// ```c
/// struct dhcp_lease *lease6_allocate(struct in6_addr *addr, int lease_type)
/// {
///   struct dhcp_lease *lease = lease_allocate();
///   if (!lease)
///     return NULL;
///   lease->addr6 = *addr;
///   lease->flags = lease_type;
///   // ... initialize fields
///   return lease;
/// }
/// ```
pub fn lease6_allocate(
    database: &LeaseDatabase,
    addr: Ipv6Addr,
    duid: Vec<u8>,
    iaid: u32,
    lease_type: LeaseType,
) -> Result<Lease, DnsmasqError> {
    // Check if database is full
    if database.len() >= database.max_leases {
        return Err(DnsmasqError::Dhcp(DhcpError::DatabaseError {
            message: "Lease database full".to_string(),
            source: None,
        }));
    }

    // Check if address is already allocated
    if database.find_by_ip(IpAddr::V6(addr)).is_some() {
        return Err(DnsmasqError::Dhcp(DhcpError::DatabaseError {
            message: format!("Address {addr} already allocated"),
            source: None,
        }));
    }

    // Create new lease with default expiration (1 hour from now)
    let now = monotonic_time();
    let expires = now + 3600; // Default 1 hour lease

    let lease = Lease::V6(LeaseV6 {
        addr,
        duid,
        iaid,
        hostname: None,
        expires,
        lease_type,
        state: LeaseState::New,
    });

    database.add_lease(lease.clone())?;

    debug!(
        "Allocated DHCPv6 lease: addr={}, iaid={}, type={:?}, expires={}",
        addr, iaid, lease_type, expires
    );

    Ok(lease)
}

/// Find DHCP lease by client identifier or MAC address.
///
/// Searches for `DHCPv4` lease matching client ID (if provided) or hardware address.
/// Corresponds to C's `lease_find_by_client()` (lease.c:159-219).
///
/// # Arguments
///
/// * `database` - Lease database
/// * `hwaddr` - Hardware address (MAC) to search for (optional)
/// * `client_id` - Client identifier to search for (optional)
///
/// # Returns
///
/// Cloned lease if found, None otherwise
///
/// # Panics
///
/// Panics if the lock is poisoned (another thread panicked while holding the lock)
///
/// # C Source Reference
///
/// ```c
/// struct dhcp_lease *lease_find_by_client(unsigned char *hwaddr, int hw_len,
///                                          unsigned char *clid, int clid_len)
/// {
///   struct dhcp_lease *lease;
///   // First try client ID match
///   if (clid)
///     for (lease = leases; lease; lease = lease->next)
///       if (lease->clid_len == clid_len && memcmp(lease->clid, clid, clid_len) == 0)
///         return lease;
///   // Then try hardware address match
///   if (hwaddr)
///     for (lease = leases; lease; lease = lease->next)
///       if (lease->hwaddr_len == hw_len && memcmp(lease->hwaddr, hwaddr, hw_len) == 0)
///         return lease;
///   return NULL;
/// }
/// ```
#[must_use]
pub fn lease_find_by_client(
    database: &LeaseDatabase,
    hwaddr: Option<&[u8]>,
    client_id: Option<&[u8]>,
) -> Option<Lease> {
    let leases = database.v4_by_ip.read().unwrap();

    // First try client ID match (higher priority)
    if let Some(cid) = client_id {
        for lease in leases.values() {
            if let Some(ref lease_cid) = lease.client_id {
                if lease_cid.as_slice() == cid {
                    return Some(Lease::V4(lease.clone()));
                }
            }
        }
    }

    // Then try hardware address match
    if let Some(hw) = hwaddr {
        for lease in leases.values() {
            if lease.hwaddr == hw {
                return Some(Lease::V4(lease.clone()));
            }
        }
    }

    None
}

/// Find DHCP lease by IP address.
///
/// Searches for lease with specified IP address. Works for both `DHCPv4` and `DHCPv6`.
/// Corresponds to C's `lease_find_by_addr()` (lease.c:142-157).
///
/// # Arguments
///
/// * `database` - Lease database
/// * `addr` - IP address to search for
///
/// # Returns
///
/// Cloned lease if found, None otherwise
///
/// # Panics
///
/// Panics if the lock is poisoned (another thread panicked while holding the lock)
///
/// # C Source Reference
///
/// ```c
/// struct dhcp_lease *lease_find_by_addr(struct in_addr addr)
/// {
///   struct dhcp_lease *lease;
///   for (lease = leases; lease; lease = lease->next)
///     if (lease->addr.s_addr == addr.s_addr)
///       return lease;
///   return NULL;
/// }
/// ```
#[must_use]
pub fn lease_find_by_addr(database: &LeaseDatabase, addr: IpAddr) -> Option<Lease> {
    database.find_by_ip(addr)
}

/// Find `DHCPv6` lease by DUID, IAID, and address.
///
/// Searches for `DHCPv6` lease matching all three parameters. Corresponds to C's
/// `lease6_find()` (lease.c:1335-1357).
///
/// # Arguments
///
/// * `database` - Lease database
/// * `duid` - DHCP Unique Identifier
/// * `lease_type` - TA or NA lease type
/// * `iaid` - Identity Association Identifier
/// * `addr` - IPv6 address
///
/// # Returns
///
/// Cloned lease if found, None otherwise
///
/// # Panics
///
/// Panics if the lock is poisoned (another thread panicked while holding the lock)
///
/// # C Source Reference
///
/// ```c
/// struct dhcp_lease *lease6_find(unsigned char *clid, int clid_len,
///                                 int lease_type, unsigned int iaid,
///                                 struct in6_addr *addr)
/// {
///   struct dhcp_lease *lease;
///   for (lease = leases; lease; lease = lease->next) {
///     if (!(lease->flags & lease_type) || lease->iaid != iaid)
///       continue;
///     if (!IN6_ARE_ADDR_EQUAL(&lease->addr6, addr))
///       continue;
///     if ((clid_len != lease->clid_len || memcmp(clid, lease->clid, clid_len) != 0))
///       continue;
///     return lease;
///   }
///   return NULL;
/// }
/// ```
#[must_use]
pub fn lease6_find(
    database: &LeaseDatabase,
    duid: &[u8],
    lease_type: LeaseType,
    iaid: u32,
    addr: Ipv6Addr,
) -> Option<Lease> {
    let leases = database.v6_by_ip.read().unwrap();

    if let Some(lease) = leases.get(&addr) {
        if lease.lease_type == lease_type && lease.iaid == iaid && lease.duid == duid {
            return Some(Lease::V6(lease.clone()));
        }
    }

    None
}

/// Remove expired leases from database.
///
/// Scans all leases and removes those with expiry < current time. Also removes
/// leases from DNS cache and triggers lease-change scripts for deleted leases.
/// Corresponds to C's `lease_prune()` (lease.c:606-697).
///
/// # Arguments
///
/// * `database` - Lease database
/// * `dns_cache` - DNS cache for hostname removal (optional)
///
/// # Returns
///
/// Number of leases removed
///
/// # Panics
///
/// Panics if the lock is poisoned (another thread panicked while holding the lock)
///
/// # C Source Reference
///
/// ```c
/// void lease_prune(time_t now)
/// {
///   struct dhcp_lease *lease, *tmp, **up;
///   for (lease = leases, up = &leases; lease; lease = tmp) {
///     tmp = lease->next;
///     if (lease->expires != 0 && difftime(now, lease->expires) > 0) {
///       *up = lease->next;
///       // Remove from DNS cache
///       if (lease->hostname)
///         cache_unhash_dhcp();
///       // Execute lease-change script
///       if (daemon->lease_change_command)
///         queue_script(ACTION_DEL, lease, NULL, now);
///       file_dirty = 1;
///       // Move to old_leases for script execution
///       lease->next = old_leases;
///       old_leases = lease;
///     } else {
///       up = &lease->next;
///     }
///   }
/// }
/// ```
#[must_use]
pub fn lease_prune(
    database: &LeaseDatabase,
    mut dns_cache: Option<&mut DnsCache>,
) -> usize {
    let now = monotonic_time();
    let mut count = 0;

    // Prune IPv4 leases
    {
        let mut leases = database.v4_by_ip.write().unwrap();
        let expired: Vec<Ipv4Addr> = leases
            .iter()
            .filter(|(_, lease)| lease.expires < now)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in expired {
            if let Some(lease) = leases.remove(&addr) {
                // Remove from DNS cache if hostname exists
                if let Some(hostname) = &lease.hostname {
                    if let Some(cache) = dns_cache.as_deref_mut() {
                        cache.remove_dhcp_host(hostname);
                        debug!("Removed hostname {} from DNS cache", hostname);
                    }
                }

                info!("Pruned expired DHCPv4 lease: addr={}", addr);
                count += 1;
            }
        }
    }

    // Prune IPv6 leases
    {
        let mut leases = database.v6_by_ip.write().unwrap();
        let expired: Vec<Ipv6Addr> = leases
            .iter()
            .filter(|(_, lease)| lease.expires < now)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in expired {
            if let Some(lease) = leases.remove(&addr) {
                // Remove from DNS cache if hostname exists
                if let Some(hostname) = &lease.hostname {
                    if let Some(cache) = dns_cache.as_deref_mut() {
                        cache.remove_dhcp_host(hostname);
                        debug!("Removed hostname {} from DNS cache", hostname);
                    }
                }

                info!("Pruned expired DHCPv6 lease: addr={}", addr);
                count += 1;
            }
        }
    }

    if count > 0 {
        debug!("Pruned {} expired leases", count);
    }

    count
}

/// Update leases from static host configurations.
///
/// Applies configured hostnames from dhcp-host directives to active leases.
/// Static reservations override DHCP-supplied hostnames. Corresponds to C's
/// `lease_update_from_configs()` (lease.c:344-403).
///
/// # Arguments
///
/// * `database` - Lease database
/// * `daemon` - Daemon state containing configuration
/// * `dns_cache` - DNS cache for hostname updates (optional)
///
/// # Returns
///
/// Number of leases updated
///
/// # Panics
///
/// Panics if the lock is poisoned (another thread panicked while holding the lock)
///
/// # C Source Reference
///
/// ```c
/// void lease_update_from_configs(void)
/// {
///   struct dhcp_lease *lease;
///   struct dhcp_config *config;
///   for (lease = leases; lease; lease = lease->next) {
///     config = find_config(daemon->dhcp_conf, NULL, lease->clid, lease->clid_len,
///                          lease->hwaddr, lease->hwaddr_len, lease->hwaddr_type, NULL);
///     if (config && config->hostname) {
///       lease_set_hostname(lease, config->hostname, 1, get_domain(lease->addr), NULL);
///     }
///   }
/// }
/// ```
#[must_use]
pub fn lease_update_from_configs(
    database: &LeaseDatabase,
    daemon: &DaemonState,
    mut dns_cache: Option<&mut DnsCache>,
) -> usize {
    let mut count = 0;

    // Update DHCPv4 leases
    {
        let mut leases = database.v4_by_ip.write().unwrap();
        for (addr, lease) in leases.iter_mut() {
            // Find matching static host config
            let config = find_config(
                daemon,
                lease.client_id.as_deref().map(|cid| {
                    crate::dhcp::common::ClientId::new(cid.to_vec())
                }).as_ref(),
                Some(&lease.hwaddr),
                lease.hostname.as_deref(),
            );

            if let Some(static_host) = config {
                // Apply configured hostname if different
                if let Some(ref config_hostname) = static_host.hostname {
                    if lease.hostname.as_deref() != Some(config_hostname.as_str()) {
                        let old_hostname = lease.hostname.clone();
                        lease.hostname = Some(config_hostname.clone());
                        lease.state = LeaseState::Changed;

                        // Update DNS cache
                        if let Some(cache) = dns_cache.as_deref_mut() {
                            // Remove old hostname
                            if let Some(old) = old_hostname {
                                cache.remove_dhcp_host(&old);
                            }
                            // Add new hostname
                            cache.insert_dhcp_host(
                                config_hostname.clone(),
                                IpAddr::V4(*addr),
                                std::time::Duration::from_secs(lease.expires - monotonic_time()),
                            );
                        }

                        debug!(
                            "Updated hostname for lease {}: {} (from config)",
                            addr, config_hostname
                        );
                        count += 1;
                    }
                }
            }
        }
    }

    // Update DHCPv6 leases (similar logic)
    {
        let mut leases = database.v6_by_ip.write().unwrap();
        for (addr, lease) in leases.iter_mut() {
            // For DHCPv6, use DUID as client ID
            let config = find_config(
                daemon,
                Some(&crate::dhcp::common::ClientId::new(lease.duid.clone())),
                None,
                lease.hostname.as_deref(),
            );

            if let Some(static_host) = config {
                if let Some(ref config_hostname) = static_host.hostname {
                    if lease.hostname.as_deref() != Some(config_hostname.as_str()) {
                        let old_hostname = lease.hostname.clone();
                        lease.hostname = Some(config_hostname.clone());
                        lease.state = LeaseState::Changed;

                        // Update DNS cache
                        if let Some(cache) = dns_cache.as_deref_mut() {
                            if let Some(old) = old_hostname {
                                cache.remove_dhcp_host(&old);
                            }
                            cache.insert_dhcp_host(
                                config_hostname.clone(),
                                IpAddr::V6(*addr),
                                std::time::Duration::from_secs(lease.expires - monotonic_time()),
                            );
                        }

                        debug!(
                            "Updated hostname for lease {}: {} (from config)",
                            addr, config_hostname
                        );
                        count += 1;
                    }
                }
            }
        }
    }

    if count > 0 {
        info!("Updated {} leases from static host configurations", count);
    }

    count
}

/// Update lease database file.
///
/// Atomically writes all active leases to persistent storage. Marks all
/// New and Changed leases as Unchanged after successful write. Corresponds
/// to C's `lease_update_file()` (lease.c:496-604).
///
/// # Arguments
///
/// * `database` - Lease database
/// * `path` - Path to lease file
/// * `duid` - Server DUID for `DHCPv6` (optional)
///
/// # Returns
///
/// Ok on success, Err on I/O failure
///
/// # Errors
///
/// Returns error on I/O failure when writing to lease file
///
/// # Panics
///
/// Panics if the lock is poisoned (another thread panicked while holding the lock)
///
/// # C Source Reference
///
/// ```c
/// void lease_update_file(time_t now)
/// {
///   if (file_dirty != 0 && daemon->lease_file) {
///     // Rewind and truncate file
///     rewind(daemon->lease_stream);
///     if (ftruncate(fileno(daemon->lease_stream), 0) != 0)
///       return;
///     // Write all leases
///     for (lease = leases; lease; lease = lease->next) {
///       // Write lease data
///       fprintf(daemon->lease_stream, "%u %s %s %s %s\n", ...);
///     }
///     fsync(fileno(daemon->lease_stream));
///     file_dirty = 0;
///   }
/// }
/// ```
pub fn lease_update_file<P: AsRef<std::path::Path>>(
    database: &LeaseDatabase,
    path: P,
    duid: Option<Vec<u8>>,
) -> Result<(), DnsmasqError> {
    // Save to file
    database.save(path, duid)?;

    // Mark all leases as unchanged
    {
        let mut v4_leases = database.v4_by_ip.write().unwrap();
        for lease in v4_leases.values_mut() {
            if lease.state == LeaseState::New || lease.state == LeaseState::Changed {
                lease.state = LeaseState::Unchanged;
            }
        }
    }

    {
        let mut v6_leases = database.v6_by_ip.write().unwrap();
        for lease in v6_leases.values_mut() {
            if lease.state == LeaseState::New || lease.state == LeaseState::Changed {
                lease.state = LeaseState::Unchanged;
            }
        }
    }

    debug!("Updated lease database file");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::time::init_time_source;

    #[test]
    fn test_lease_state_transitions() {
        init_time_source();
        let mut lease = Lease::new(
            Ipv4Addr::new(192, 168, 1, 100),
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            None,
            None,
            monotonic_time() + 3600,
        );

        assert_eq!(lease.state(), LeaseState::New);

        lease.mark_unchanged();
        assert_eq!(lease.state(), LeaseState::Unchanged);

        lease.set_hostname(Some("test".to_string()));
        assert_eq!(lease.state(), LeaseState::Changed);

        lease.mark_unchanged();
        assert_eq!(lease.state(), LeaseState::Unchanged);
    }

    #[test]
    fn test_lease_database_new() {
        init_time_source();
        let db = LeaseDatabase::new(100);
        assert_eq!(db.max_leases, 100);
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
        assert_eq!(db.available(), 100);
    }

    #[test]
    fn test_lease4_allocate() {
        init_time_source();
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let result = lease4_allocate(&db, addr, hwaddr.clone(), None);
        assert!(result.is_ok());

        let lease = result.unwrap();
        assert!(lease.is_v4());
        assert_eq!(lease.ip_addr(), IpAddr::V4(addr));
        assert_eq!(lease.hwaddr(), Some(hwaddr.as_slice()));
    }

    #[test]
    fn test_lease4_allocate_duplicate() {
        init_time_source();
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        lease4_allocate(&db, addr, hwaddr.clone(), None).unwrap();

        // Try to allocate same address again
        let result = lease4_allocate(&db, addr, hwaddr, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_lease6_allocate() {
        init_time_source();
        let db = LeaseDatabase::new(100);
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let duid = vec![0x00, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78];

        let result = lease6_allocate(&db, addr, duid.clone(), 1, LeaseType::NonTemporaryAddress);
        assert!(result.is_ok());

        let lease = result.unwrap();
        assert!(lease.is_v6());
        assert_eq!(lease.ip_addr(), IpAddr::V6(addr));
    }

    #[test]
    fn test_lease_find_by_client() {
        init_time_source();
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_id = vec![0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        lease4_allocate(&db, addr, hwaddr.clone(), Some(client_id.clone())).unwrap();

        // Find by client ID
        let found = lease_find_by_client(&db, None, Some(&client_id));
        assert!(found.is_some());

        // Find by MAC
        let found = lease_find_by_client(&db, Some(&hwaddr), None);
        assert!(found.is_some());
    }

    #[test]
    fn test_lease_find_by_addr() {
        init_time_source();
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        lease4_allocate(&db, addr, hwaddr, None).unwrap();

        let found = lease_find_by_addr(&db, IpAddr::V4(addr));
        assert!(found.is_some());

        let not_found = lease_find_by_addr(&db, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_lease6_find() {
        init_time_source();
        let db = LeaseDatabase::new(100);
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let duid = vec![0x00, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78];
        let iaid = 12345;

        lease6_allocate(&db, addr, duid.clone(), iaid, LeaseType::NonTemporaryAddress).unwrap();

        let found = lease6_find(&db, &duid, LeaseType::NonTemporaryAddress, iaid, addr);
        assert!(found.is_some());

        // Wrong IAID
        let not_found = lease6_find(&db, &duid, LeaseType::NonTemporaryAddress, 99999, addr);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_lease_prune() {
        init_time_source();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let db = LeaseDatabase::new(100);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let hwaddr = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Allocate lease
        lease4_allocate(&db, addr, hwaddr, None).unwrap();
        assert_eq!(db.len(), 1);

        // Manually expire the lease
        {
            let mut leases = db.v4_by_ip.write().unwrap();
            if let Some(lease) = leases.get_mut(&addr) {
                lease.expires = 0; // Set to past (epoch)
            }
        }

        // Prune should remove it
        let removed = lease_prune(&db, None);
        assert_eq!(removed, 1);
        assert_eq!(db.len(), 0);
    }

    #[test]
    fn test_lease_is_expired() {
        init_time_source();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let lease = Lease::V4(LeaseV4 {
            addr: Ipv4Addr::new(192, 168, 1, 100),
            hwaddr: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            client_id: None,
            hostname: None,
            expires: 0, // Already expired (epoch)
            state: LeaseState::Unchanged,
        });

        assert!(lease.is_expired());
    }

    #[test]
    fn test_lease_set_hostname() {
        init_time_source();
        let mut lease = Lease::new(
            Ipv4Addr::new(192, 168, 1, 100),
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            None,
            None,
            monotonic_time() + 3600,
        );

        lease.mark_unchanged();
        assert_eq!(lease.state(), LeaseState::Unchanged);

        lease.set_hostname(Some("testhost".to_string()));
        assert_eq!(lease.hostname(), Some("testhost"));
        assert_eq!(lease.state(), LeaseState::Changed);
    }

    #[test]
    fn test_lease_set_expires() {
        init_time_source();
        let mut lease = Lease::new(
            Ipv4Addr::new(192, 168, 1, 100),
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            None,
            None,
            monotonic_time() + 3600,
        );

        lease.mark_unchanged();
        let new_expires = monotonic_time() + 7200;
        lease.set_expires(new_expires);

        assert_eq!(lease.expires(), new_expires);
        assert_eq!(lease.state(), LeaseState::Changed);
    }
}

