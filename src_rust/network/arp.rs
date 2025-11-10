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

//! ARP table access for DHCP address conflict detection
//!
//! This module provides platform-independent ARP cache querying functionality used by
//! the DHCP server to implement ping-before-offer address conflict detection. Before
//! allocating an IP address from the DHCP pool, dnsmasq queries the ARP cache to
//! determine if the address is already in use on the local network.
//!
//! # Memory Safety Transformation
//!
//! All C manual memory management patterns are replaced with Rust's safe alternatives:
//! - `malloc/free` linked lists → `HashMap<IpAddr, ArpRecord>` with automatic Drop
//! - Manual pointer manipulation → safe HashMap operations with bounds checking
//! - Global static variables → `Arc<RwLock<ArpCache>>` for thread-safe shared state
//! - Manual time_t aging → `Instant` and `Duration` for safe time arithmetic
//! - Buffer overflow risks → bounds-checked arrays with `[u8; 16]`
//! - Synchronous /proc parsing → async Platform trait methods
//!
//! # Key Responsibilities
//!
//! - `find_mac()`: Primary public API - search ARP cache for MAC address of given IP
//! - `refresh()`: Reload ARP cache from kernel (called every 90 seconds)
//! - `process_script_events()`: Queue ARP change notifications for external scripts
//!
//! # Architecture
//!
//! The implementation maintains an in-memory cache of ARP entries to minimize expensive
//! kernel queries. The cache is refreshed at 90-second intervals and supports both
//! positive entries (IP→MAC mappings) and negative entries (addresses known to be
//! absent from ARP table).
//!
//! # Original C Implementation
//!
//! Refactored from `src/arp.c` (dnsmasq 2.90) with the following transformations:
//! - Linked list traversal → HashMap lookups (O(n) → O(1))
//! - Manual freelist → automatic memory management
//! - Synchronous polling → async refresh with tokio::time::interval
//! - Platform-specific parsing → unified Platform trait

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use tokio::sync::RwLock;

use tracing::{debug, trace, warn};

// Internal imports (ONLY from depends_on_files)
use crate::config::types::{Config, DaemonOptions};
use crate::dhcp::common::ACTION_ARP_DEL;
use crate::network::platform::{ArpEntry, Platform};
use crate::process::helper::{queue_arp, HelperHandle};

// ========== Constants ==========

/// Time interval in seconds between forced ARP cache reloads from kernel
///
/// The ARP cache is refreshed from the kernel at most once every INTERVAL seconds
/// (90 seconds) to minimize expensive system calls while keeping the cache reasonably
/// current. Queries within this window are served from the in-memory cache.
///
/// Original C: `#define INTERVAL 90` (line 88 in src/arp.c)
const INTERVAL: Duration = Duration::from_secs(90);

/// Address family constant for IPv4 (matches libc `AF_INET`)
const AF_INET: i32 = 2;

/// Address family constant for IPv6 (matches libc `AF_INET6`)  
const AF_INET6: i32 = 10;

/// Maximum hardware address length for DHCP (16 bytes per RFC 2131)
///
/// Most commonly 6 bytes for Ethernet MAC addresses, but RFC 2131 allows
/// up to 16 bytes for other hardware types.
///
/// Original C: `DHCP_CHADDR_MAX` from dnsmasq.h
const DHCP_CHADDR_MAX: usize = 16;

// ========== Type Definitions ==========

/// ARP record status enumeration
///
/// Replaces C's integer status codes (`ARP_MARK`, `ARP_FOUND`, `ARP_NEW`, `ARP_EMPTY`)
/// with type-safe enum for compiler-enforced correctness.
///
/// Original C: #define `ARP_MARK` 0, `ARP_FOUND` 1, `ARP_NEW` 2, `ARP_EMPTY` 3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpStatus {
    /// Temporary marker status during cache refresh sweep
    ///
    /// Entries are marked with this at the start of a kernel query, then confirmed
    /// as `ArpStatus::Found` if still present, or moved to old list if not reconfirmed.
    Mark,

    /// Status indicating ARP entry confirmed present in kernel cache
    ///
    /// Entry has been verified to exist in the kernel ARP table during the most recent
    /// refresh cycle. This is a positive, confirmed IP→MAC mapping.
    Found,

    /// Status indicating newly discovered ARP entry
    ///
    /// Entry was just added to cache during current refresh cycle. Used to trigger
    /// script notifications (`ACTION_ARP` event) for new IP→MAC mappings.
    New,

    /// Status indicating negative cache entry (no MAC address)
    ///
    /// This entry records that an IP address was queried but not found in the ARP table.
    /// Negative caching prevents repeated kernel queries for non-existent entries in lazy
    /// mode. hwlen is 0 for these entries.
    Empty,
}

/// Cached ARP table entry recording IP→MAC address mapping
///
/// Each `ArpRecord` represents one entry from the system ARP cache, storing the IP address,
/// corresponding hardware (MAC) address, address family (IPv4 or IPv6), and current status.
///
/// # Memory Layout
///
/// Total size approximately 48-64 bytes (safe Rust padding). No manual alignment required.
///
/// # Original C Structure
///
/// Replaces C's `struct arp_record` (lines 155-162 in src/arp.c):
/// ```c
/// struct arp_record {
///   unsigned short hwlen;
///   unsigned short status;
///   int family;
///   unsigned char hwaddr[DHCP_CHADDR_MAX];
///   union all_addr addr;
///   struct arp_record *next;
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ArpRecord {
    /// Hardware address length in bytes (typically 6 for Ethernet, 0 for negative entries)
    pub hwlen: usize,

    /// Entry status: Mark, Found, New, or Empty
    pub status: ArpStatus,

    /// Address family: `AF_INET` for IPv4, `AF_INET6` for IPv6
    pub family: i32,

    /// Hardware (MAC) address, up to `DHCP_CHADDR_MAX` (16) bytes
    pub hwaddr: [u8; DHCP_CHADDR_MAX],

    /// IP address (type-safe `IpAddr` replaces C's union `all_addr`)
    pub addr: IpAddr,

    /// Timestamp when this entry was last confirmed
    ///
    /// Used to track entry age for debugging. Not used in C implementation but
    /// useful for operational visibility.
    pub last_seen: Instant,
}

impl ArpRecord {
    /// Create a new ARP record with given parameters
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address (IPv4 or IPv6)
    /// * `hwaddr` - Hardware address bytes (typically 6 bytes for Ethernet)
    /// * `hwlen` - Length of hardware address
    /// * `status` - Initial status of the record
    ///
    /// # Returns
    ///
    /// New `ArpRecord` with family automatically determined from address type
    fn new(addr: IpAddr, hwaddr: &[u8], hwlen: usize, status: ArpStatus) -> Self {
        let family = match addr {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };

        let mut hwaddr_array = [0u8; DHCP_CHADDR_MAX];
        let copy_len = hwlen.min(DHCP_CHADDR_MAX).min(hwaddr.len());
        hwaddr_array[..copy_len].copy_from_slice(&hwaddr[..copy_len]);

        Self {
            hwlen,
            status,
            family,
            hwaddr: hwaddr_array,
            addr,
            last_seen: Instant::now(),
        }
    }

    /// Create a negative (empty) cache entry
    ///
    /// Used to record that an IP address was queried but not found in the ARP table.
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address that was not found
    fn new_empty(addr: IpAddr) -> Self {
        Self::new(addr, &[], 0, ArpStatus::Empty)
    }

    /// Update this record with new MAC address (converts Empty to New)
    ///
    /// # Arguments
    ///
    /// * `hwaddr` - New hardware address bytes
    /// * `hwlen` - Length of hardware address
    fn update_mac(&mut self, hwaddr: &[u8], hwlen: usize) {
        self.hwlen = hwlen;
        self.status = ArpStatus::New;
        let copy_len = hwlen.min(DHCP_CHADDR_MAX).min(hwaddr.len());
        self.hwaddr[..copy_len].copy_from_slice(&hwaddr[..copy_len]);
        self.last_seen = Instant::now();
    }

    /// Mark this record as confirmed during refresh cycle
    fn confirm(&mut self) {
        self.status = ArpStatus::Found;
        self.last_seen = Instant::now();
    }

    /// Mark this record for expiry check
    fn mark_for_check(&mut self) {
        if self.status != ArpStatus::Empty {
            self.status = ArpStatus::Mark;
        }
    }
}

/// ARP cache manager
///
/// Maintains an in-memory cache of ARP entries with periodic refresh from kernel.
/// Provides thread-safe access via Arc<`RwLock`<>> for async operations.
///
/// # Original C Implementation
///
/// Replaces C's global static variables (lines 164-165 in src/arp.c):
/// ```c
/// static struct arp_record *arps = NULL, *old = NULL, *freelist = NULL;
/// static time_t last = 0;
/// ```
pub struct ArpCache {
    /// Active ARP cache entries (IP address → record mapping)
    ///
    /// Replaces C's linked list `arps` with O(1) `HashMap` lookups
    entries: HashMap<IpAddr, ArpRecord>,

    /// Expired entries awaiting script notification
    ///
    /// Entries that were not confirmed during last refresh. Replaces C's `old` linked list.
    old_entries: Vec<ArpRecord>,

    /// Timestamp of last cache refresh from kernel
    ///
    /// Used to enforce INTERVAL (90 seconds) minimum between refreshes
    last_refresh: Instant,

    /// Configuration (for checking `OPT_SCRIPT_ARP` flag)
    config: Arc<Config>,
}

impl ArpCache {
    /// Create a new ARP cache
    ///
    /// # Arguments
    ///
    /// * `config` - Daemon configuration (for `OPT_SCRIPT_ARP` check)
    ///
    /// # Returns
    ///
    /// New `ArpCache` with empty entries
    #[must_use] 
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            entries: HashMap::new(),
            old_entries: Vec::new(),
            last_refresh: Instant::now().checked_sub(INTERVAL).unwrap(), // Allow immediate first refresh
            config,
        }
    }

    /// Search ARP cache for MAC address of given IP address
    ///
    /// Primary public API for ARP cache lookups. Searches the in-memory ARP cache for the
    /// MAC address corresponding to the specified IP address, automatically refreshing from
    /// kernel if cache is stale (older than INTERVAL seconds).
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address to look up (can be None for refresh-only mode)
    /// * `lazy` - If true, return negative cache entries; if false, only positive entries
    /// * `platform` - Platform implementation for kernel ARP enumeration
    ///
    /// # Returns
    ///
    /// - `Some((hwaddr, hwlen))` if entry found with MAC address
    /// - `None` if address not in ARP table or negative entry in non-lazy mode
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use dnsmasq::network::arp::ArpCache;
    /// # use dnsmasq::network::platform::create_platform;
    /// # use dnsmasq::config::types::Config;
    /// # use std::net::IpAddr;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Arc::new(Config::default());
    /// let mut cache = ArpCache::new(config);
    /// let platform = create_platform()?;
    ///
    /// let addr: IpAddr = "192.168.1.100".parse()?;
    /// if let Some((hwaddr, hwlen)) = cache.find_mac(Some(&addr), false, platform.as_ref()).await? {
    ///     println!("MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
    ///         hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    /// } else {
    ///     println!("Address not in ARP cache");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Original C Function
    ///
    /// Replaces `int find_mac(union mysockaddr *addr, unsigned char *mac, int lazy, time_t now)`
    /// (lines 398-491 in src/arp.c)
    pub async fn find_mac(
        &mut self,
        addr: Option<&IpAddr>,
        lazy: bool,
        platform: &dyn Platform,
    ) -> Result<Option<([u8; DHCP_CHADDR_MAX], usize)>, std::io::Error> {
        let now = Instant::now();
        let mut updated = false;

        // Retry loop (implements C's goto again pattern)
        loop {
            // If cache is fresh, search in memory
            if now.duration_since(self.last_refresh) < INTERVAL {
                // addr == None means refresh-only mode
                if addr.is_none() {
                    return Ok(None);
                }

                if let Some(addr_val) = addr {
                    if let Some(record) = self.entries.get(addr_val) {
                        // Only accept positive entries unless in lazy mode or after refresh
                        if record.status != ArpStatus::Empty || lazy || updated {
                            let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
                            if record.hwlen > 0 {
                                hwaddr[..record.hwlen].copy_from_slice(&record.hwaddr[..record.hwlen]);
                            }
                            return Ok(Some((hwaddr, record.hwlen)));
                        }
                    }
                }
            }

            // Not found or cache stale - refresh from kernel
            if !updated {
                updated = true;
                self.refresh(platform).await?;
                continue; // Retry lookup with fresh cache
            }

            // After refresh, still not found - create negative entry
            break;
        }

        // Record failure as negative cache entry to avoid repeated kernel queries
        if let Some(addr_val) = addr {
            trace!("Creating negative ARP cache entry for {}", addr_val);
            self.entries.insert(*addr_val, ArpRecord::new_empty(*addr_val));
        }

        Ok(None)
    }

    /// Refresh ARP cache from kernel
    ///
    /// Queries the platform-specific ARP table and updates the in-memory cache.
    /// Implements the cache refresh algorithm:
    /// 1. Mark all existing non-empty entries
    /// 2. Enumerate kernel ARP table via Platform trait
    /// 3. Confirm or create entries based on kernel data
    /// 4. Move unconfirmed entries to `old_entries` list
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform implementation for kernel ARP enumeration
    ///
    /// # Returns
    ///
    /// Result indicating success or I/O error from kernel query
    ///
    /// # Original C Function
    ///
    /// Replaces the refresh logic in `find_mac()` (lines 441-463 in src/arp.c)
    pub async fn refresh(&mut self, platform: &dyn Platform) -> Result<(), std::io::Error> {
        debug!("Refreshing ARP cache from kernel");

        // Mark all non-negative entries for confirmation
        for record in self.entries.values_mut() {
            record.mark_for_check();
        }

        // Enumerate kernel ARP table (may block on I/O, so use spawn_blocking)
        let arp_entries = platform
            .enumerate_arp()
            .await
            .map_err(std::io::Error::other)?;

        debug!("Kernel returned {} ARP entries", arp_entries.len());

        // Process each kernel ARP entry
        for kernel_entry in arp_entries {
            self.process_kernel_entry(kernel_entry);
        }

        // Move unconfirmed entries to old list
        let mut to_remove = Vec::new();
        for (ip, record) in &self.entries {
            if record.status == ArpStatus::Mark {
                to_remove.push(*ip);
            }
        }

        for ip in to_remove {
            if let Some(record) = self.entries.remove(&ip) {
                trace!("Moving expired ARP entry to old list: {} -> {:?}", ip, record.hwaddr);
                self.old_entries.push(record);
            }
        }

        self.last_refresh = Instant::now();

        debug!(
            "ARP cache refresh complete: {} active, {} expired",
            self.entries.len(),
            self.old_entries.len()
        );

        Ok(())
    }

    /// Process a single kernel ARP entry during refresh
    ///
    /// Implements the `filter_mac()` callback logic from C (lines 225-291 in src/arp.c)
    ///
    /// # Arguments
    ///
    /// * `kernel_entry` - ARP entry from kernel enumeration
    fn process_kernel_entry(&mut self, kernel_entry: ArpEntry) {
        // Reject oversized hardware addresses
        if kernel_entry.hwaddr_len as usize > DHCP_CHADDR_MAX {
            warn!(
                "Rejecting ARP entry with oversized hwaddr: {} bytes",
                kernel_entry.hwaddr_len
            );
            return;
        }

        let addr = kernel_entry.addr;
        let hwaddr = &kernel_entry.hwaddr[..kernel_entry.hwaddr_len as usize];
        let hwlen = kernel_entry.hwaddr_len as usize;

        trace!(
            "Processing kernel ARP entry: {} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            addr,
            hwaddr[0],
            hwaddr[1],
            hwaddr[2],
            hwaddr[3],
            hwaddr[4],
            hwaddr[5]
        );

        // Look for existing entry
        if let Some(record) = self.entries.get_mut(&addr) {
            // Skip newly created entries during this refresh cycle
            if record.status == ArpStatus::New {
                return;
            }

            // Check address family match
            if kernel_entry.family != record.family {
                return;
            }

            if record.status == ArpStatus::Empty {
                // Existing address was negative, now positive
                trace!("Converting negative ARP entry to positive: {}", addr);
                record.update_mac(hwaddr, hwlen);
            } else if record.hwlen == hwlen
                && record.hwaddr[..hwlen] == hwaddr[..hwlen]
            {
                // Existing entry matches - confirm
                trace!("Confirming existing ARP entry: {}", addr);
                record.confirm();
            } else {
                // MAC address mismatch - skip update (preserve existing)
                warn!(
                    "ARP entry MAC mismatch for {}: cache has {:?}, kernel has {:?}",
                    addr,
                    &record.hwaddr[..record.hwlen],
                    hwaddr
                );
            }
        } else {
            // New entry
            trace!("Creating new ARP entry: {}", addr);
            let record = ArpRecord::new(addr, hwaddr, hwlen, ArpStatus::New);
            self.entries.insert(addr, record);
        }
    }

    /// Process ARP change events for script notification
    ///
    /// Iterates through ARP cache changes (additions and deletions) and queues
    /// corresponding script notification events. Processes one entry per invocation
    /// to spread notification load across event loop iterations.
    ///
    /// # Arguments
    ///
    /// * `helper` - Helper task handle for queuing script events
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if an event was processed (call again for more)
    /// - `Ok(false)` if no events remain
    /// - `Err(_)` if script queuing failed
    ///
    /// # Original C Function
    ///
    /// Replaces `int do_arp_script_run(void)` (lines 562-592 in src/arp.c)
    pub async fn process_script_events(
        &mut self,
        helper: &HelperHandle,
    ) -> Result<bool, std::io::Error> {
        // Check if ARP scripts are enabled
        if !self.config.options.contains(DaemonOptions::OPT_SCRIPT_ARP) {
            // Still perform housekeeping even if scripts disabled
            return Ok(self.housekeep_without_scripts());
        }

        // Process old (deleted) entries first
        if let Some(record) = self.old_entries.pop() {
            trace!(
                "Queueing ARP delete event: {} -> {:?}",
                record.addr,
                &record.hwaddr[..record.hwlen]
            );

            // Queue ACTION_ARP_DEL event
            if let IpAddr::V4(addr4) = record.addr {
                queue_arp(
                    helper,
                    ACTION_ARP_DEL,
                    &record.hwaddr[..record.hwlen],
                    addr4,
                    0, // Interface index (not tracked in C implementation)
                )
                .await
                .map_err(|e| {
                    std::io::Error::other(
                        format!("Failed to queue ARP delete event: {e}"),
                    )
                })?;
            }

            return Ok(true); // More events may be pending
        }

        // Process new entries
        for record in self.entries.values_mut() {
            if record.status == ArpStatus::New {
                trace!(
                    "Queueing ARP add event: {} -> {:?}",
                    record.addr,
                    &record.hwaddr[..record.hwlen]
                );

                // Queue ACTION_ARP event (uses ACTION_ARP from dhcp::common)
                if let IpAddr::V4(addr4) = record.addr {
                    use crate::dhcp::common::ACTION_ARP;
                    queue_arp(
                        helper,
                        ACTION_ARP,
                        &record.hwaddr[..record.hwlen],
                        addr4,
                        0, // Interface index (not tracked in C implementation)
                    )
                    .await
                    .map_err(|e| {
                        std::io::Error::other(
                            format!("Failed to queue ARP add event: {e}"),
                        )
                    })?;
                }

                // Promote to confirmed status
                record.status = ArpStatus::Found;
                return Ok(true); // More events may be pending
            }
        }

        Ok(false) // No events pending
    }

    /// Perform housekeeping without script notifications
    ///
    /// Cleans up old entries and promotes new entries even when scripts are disabled
    ///
    /// # Returns
    ///
    /// true if housekeeping was performed, false if nothing to do
    fn housekeep_without_scripts(&mut self) -> bool {
        // Clear old entries
        if !self.old_entries.is_empty() {
            self.old_entries.clear();
            return true;
        }

        // Promote new entries to found
        let mut promoted = false;
        for record in self.entries.values_mut() {
            if record.status == ArpStatus::New {
                record.status = ArpStatus::Found;
                promoted = true;
            }
        }

        promoted
    }

    /// Get the number of active ARP cache entries
    ///
    /// Useful for monitoring and debugging
    #[must_use] 
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the number of expired entries awaiting script notification
    #[must_use] 
    pub fn old_entry_count(&self) -> usize {
        self.old_entries.len()
    }
}

// ========== Standalone Functions for API Compatibility ==========

/// Standalone `find_mac` function for API compatibility
///
/// Provides a simpler interface when you have a shared `ArpCache` instance
///
/// # Arguments
///
/// * `cache` - Shared ARP cache wrapped in Arc<`RwLock`<>>
/// * `addr` - IP address to look up
/// * `lazy` - If true, accept negative cache entries
/// * `platform` - Platform implementation for kernel queries
///
/// # Returns
///
/// MAC address and length if found, None otherwise
pub async fn find_mac(
    cache: Arc<RwLock<ArpCache>>,
    addr: Option<&IpAddr>,
    lazy: bool,
    platform: &dyn Platform,
) -> Result<Option<([u8; DHCP_CHADDR_MAX], usize)>, std::io::Error> {
    let mut cache_guard = cache.write().await;
    cache_guard.find_mac(addr, lazy, platform).await
}

/// Standalone refresh function for API compatibility
///
/// Refreshes the ARP cache from kernel
///
/// # Arguments
///
/// * `cache` - Shared ARP cache wrapped in Arc<`RwLock`<>>
/// * `platform` - Platform implementation for kernel queries
pub async fn refresh_cache(
    cache: Arc<RwLock<ArpCache>>,
    platform: &dyn Platform,
) -> Result<(), std::io::Error> {
    let mut cache_guard = cache.write().await;
    cache_guard.refresh(platform).await
}

/// Standalone script event processing function for API compatibility
///
/// Processes one ARP change event for script notification
///
/// # Arguments
///
/// * `cache` - Shared ARP cache wrapped in Arc<`RwLock`<>>
/// * `helper` - Helper task handle
///
/// # Returns
///
/// true if an event was processed (more may be pending), false if done
pub async fn do_arp_script_run(
    cache: Arc<RwLock<ArpCache>>,
    helper: &HelperHandle,
) -> Result<bool, std::io::Error> {
    let mut cache_guard = cache.write().await;
    cache_guard.process_script_events(helper).await
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_record_creation() {
        let addr: IpAddr = "192.168.1.100".parse().unwrap();
        let hwaddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let record = ArpRecord::new(addr, &hwaddr, 6, ArpStatus::New);

        assert_eq!(record.hwlen, 6);
        assert_eq!(record.status, ArpStatus::New);
        assert_eq!(record.family, AF_INET);
        assert_eq!(&record.hwaddr[..6], &hwaddr);
        assert_eq!(record.addr, addr);
    }

    #[test]
    fn test_arp_record_empty() {
        let addr: IpAddr = "192.168.1.100".parse().unwrap();
        let record = ArpRecord::new_empty(addr);

        assert_eq!(record.hwlen, 0);
        assert_eq!(record.status, ArpStatus::Empty);
        assert_eq!(record.addr, addr);
    }

    #[test]
    fn test_arp_record_update_mac() {
        let addr: IpAddr = "192.168.1.100".parse().unwrap();
        let mut record = ArpRecord::new_empty(addr);

        let hwaddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        record.update_mac(&hwaddr, 6);

        assert_eq!(record.hwlen, 6);
        assert_eq!(record.status, ArpStatus::New);
        assert_eq!(&record.hwaddr[..6], &hwaddr);
    }

    #[test]
    fn test_arp_cache_creation() {
        let config = Arc::new(Config::default());
        let cache = ArpCache::new(config);

        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.old_entry_count(), 0);
    }
}
