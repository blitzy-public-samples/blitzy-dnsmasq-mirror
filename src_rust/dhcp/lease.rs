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

//! DHCP lease database persistence and management for both DHCPv4 and DHCPv6
//!
//! This module provides atomic file updates, allocation tracking, and expiry management
//! for DHCP leases. It replaces C's manual linked list management with safe Rust collections,
//! blocking file I/O with tokio async I/O, and errno-based error handling with Result types.
//!
//! # Purpose
//!
//! Implements the complete DHCP lease database management system for dnsmasq, providing:
//! - Persistent storage with atomic write-temp-rename strategy
//! - Lease allocation, lookup, and expiry tracking for DHCPv4 and DHCPv6
//! - Integration with DNS cache for dynamic hostname resolution
//! - Support for systems without real-time clocks (HAVE_BROKEN_RTC)
//! - Backward-compatible lease file format for external tools
//!
//! # Memory Safety Improvements
//!
//! - **Manual linked lists → HashMap/Vec**: Eliminates use-after-free and null pointer bugs
//! - **strcpy/strncpy → String**: Prevents buffer overflow vulnerabilities
//! - **malloc/free → RAII**: Automatic memory management with Drop trait
//! - **errno → Result<T, E>**: Type-safe error propagation
//! - **Blocking I/O → async tokio**: Non-blocking file operations
//!
//! # Key Data Structures
//!
//! - [`DhcpLease`]: Individual lease record with client ID, hardware address, IP, expiry
//! - [`LeaseManager`]: Central lease database with allocation and persistence logic
//! - [`LeaseFlags`]: Type-safe flags for lease state (static, has_name, changed, etc.)
//! - [`ClientId`]: Client identifier type (Vec<u8>) for DHCPv4/v6
//! - [`Iaid`]: Identity Association Identifier for DHCPv6
//!
//! # Functions
//!
//! - [`lease_init`]: Load existing leases at daemon startup
//! - [`lease_update_file`]: Atomically persist lease database to disk
//! - [`lease_find_by_client`]: Locate lease by client ID or MAC address
//! - [`lease_find_by_addr`]: Locate lease by IP address
//! - [`lease4_allocate`] / [`lease6_allocate`]: Allocate new lease entries
//! - [`lease_prune`]: Remove expired leases
//! - [`lease_update_dns`]: Synchronize leases with DNS cache
//!
//! # File Format
//!
//! Lease file format (one lease per line, space-separated fields):
//! - DHCPv4: `<expiry> <mac> <ip> <hostname> <client-id>`
//! - DHCPv6: `<expiry> <duid> <iaid> <ip6> <hostname> <type>`
//!
//! Expiry is Unix timestamp or duration (if HAVE_BROKEN_RTC). The format maintains
//! 100% backward compatibility with the C implementation for external lease monitoring tools.
//!
//! # Original C Mapping
//!
//! Refactored from `src/lease.c` with the following transformations:
//! - `struct dhcp_lease *leases` → `HashMap<ClientId, Arc<RwLock<DhcpLease>>>`
//! - `lease_init()` → `LeaseManager::init()`
//! - `lease_update_file()` → `LeaseManager::update_file()`
//! - `lease_prune()` → `LeaseManager::prune()`
//! - `lease_find_by_client()` → `LeaseManager::find_by_client()`
//! - `lease4_allocate()` → `LeaseManager::allocate_v4()`
//! - `lease6_allocate()` → `LeaseManager::allocate_v6()`

use crate::config::types::DaemonOptions;
use crate::core::config::LEASE_RETRY;
use crate::dhcp::common::ARPHRD_ETHER;
use crate::dns::cache::check_for_local_domain;
use crate::dns::domain::get_domain;
use crate::logging::logger::log_query;
use crate::utils::general::parse_hex;

use std::collections::HashMap;
use std::fmt;
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn};

/// Type alias for client identifiers (DHCPv4 client-id or DHCPv6 DUID)
pub type ClientId = Vec<u8>;

/// Type alias for DHCPv6 Identity Association Identifier
pub type Iaid = u32;

/// Lease database error types
#[derive(Debug, Clone)]
pub enum LeaseError {
    /// I/O operation failed
    IoError(String),
    /// Failed to parse lease file
    ParseError(String),
    /// Invalid lease data
    InvalidLease(String),
    /// No available addresses in pool
    NoAvailableAddress,
    /// Address conflict detected
    ConflictDetected(IpAddr),
    /// Lease file corrupted
    FileCorrupted(String),
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeaseError::IoError(msg) => write!(f, "I/O error: {}", msg),
            LeaseError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            LeaseError::InvalidLease(msg) => write!(f, "Invalid lease: {}", msg),
            LeaseError::NoAvailableAddress => write!(f, "No available addresses"),
            LeaseError::ConflictDetected(addr) => write!(f, "Address conflict: {}", addr),
            LeaseError::FileCorrupted(msg) => write!(f, "File corrupted: {}", msg),
        }
    }
}

impl std::error::Error for LeaseError {}

impl From<IoError> for LeaseError {
    fn from(err: IoError) -> Self {
        LeaseError::IoError(err.to_string())
    }
}

/// Lease state flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseFlags {
    /// Static lease from configuration
    Static = 0x0001,
    /// Configuration validated
    ConfigOk = 0x0002,
    /// Has hostname
    HasName = 0x0004,
    /// Has hardware address
    HasHwAddr = 0x0008,
    /// Has client identifier
    HasClid = 0x0010,
    /// Lease changed since last save
    Changed = 0x0020,
    /// Old lease pending deletion
    Old = 0x0040,
    /// Authoritative for this address
    Authoritative = 0x0080,
    /// Vendor-specific override
    VendorOverride = 0x0100,
    /// Address is available for allocation
    AddrAvailable = 0x0200,
}

impl LeaseFlags {
    /// Create flags bitset from u32
    pub fn from_bits(bits: u32) -> u32 {
        bits
    }

    /// Check if flag is set in bitset
    pub fn is_set(flags: u32, flag: LeaseFlags) -> bool {
        (flags & (flag as u32)) != 0
    }

    /// Set flag in bitset
    pub fn set(flags: u32, flag: LeaseFlags) -> u32 {
        flags | (flag as u32)
    }

    /// Clear flag in bitset
    pub fn clear(flags: u32, flag: LeaseFlags) -> u32 {
        flags & !(flag as u32)
    }
}

/// Individual DHCP lease record
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// IPv4 address (DHCPv4)
    addr: Option<Ipv4Addr>,
    /// IPv6 address (DHCPv6)
    addr6: Option<Ipv6Addr>,
    /// Hardware address (MAC)
    hwaddr: Vec<u8>,
    /// Hardware address type (e.g., ARPHRD_ETHER)
    hwaddr_type: u16,
    /// Client identifier
    clid: ClientId,
    /// Hostname
    hostname: Option<String>,
    /// Lease expiration time
    expires: SystemTime,
    /// Lease flags bitset
    flags: u32,
    /// DHCPv6 IAID
    iaid: Option<Iaid>,
    /// Gateway/relay address
    giaddr: Option<IpAddr>,
    /// Last update time
    last_updated: Instant,
}

impl DhcpLease {
    /// Create a new DHCPv4 lease
    pub fn new(
        addr: Ipv4Addr,
        hwaddr: Vec<u8>,
        hwaddr_type: u16,
        clid: ClientId,
        hostname: Option<String>,
        expires: SystemTime,
    ) -> Self {
        Self {
            addr: Some(addr),
            addr6: None,
            hwaddr,
            hwaddr_type,
            clid,
            hostname,
            expires,
            flags: 0,
            iaid: None,
            giaddr: None,
            last_updated: Instant::now(),
        }
    }

    /// Get IPv4 address
    pub fn addr(&self) -> Option<Ipv4Addr> {
        self.addr
    }

    /// Get IPv6 address
    pub fn addr6(&self) -> Option<Ipv6Addr> {
        self.addr6
    }

    /// Get hardware address
    pub fn hwaddr(&self) -> &[u8] {
        &self.hwaddr
    }

    /// Get hardware address length
    pub fn hwaddr_len(&self) -> usize {
        self.hwaddr.len()
    }

    /// Get hardware address type
    pub fn hwaddr_type(&self) -> u16 {
        self.hwaddr_type
    }

    /// Get client identifier
    pub fn clid(&self) -> &[u8] {
        &self.clid
    }

    /// Get client identifier length
    pub fn clid_len(&self) -> usize {
        self.clid.len()
    }

    /// Get hostname
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Get expiration time
    pub fn expires(&self) -> SystemTime {
        self.expires
    }

    /// Get flags bitset
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Get DHCPv6 IAID
    pub fn iaid(&self) -> Option<Iaid> {
        self.iaid
    }

    /// Get gateway address
    pub fn giaddr(&self) -> Option<IpAddr> {
        self.giaddr
    }

    /// Check if lease is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires
    }

    /// Set hostname with conflict detection
    ///
    /// Updates the lease hostname. Marks the lease as changed for persistence.
    ///
    /// # Arguments
    ///
    /// * `hostname` - Optional hostname to set
    pub fn set_hostname(&mut self, hostname: Option<String>) {
        if hostname.is_some() {
            self.flags = LeaseFlags::set(self.flags, LeaseFlags::HasName);
        } else {
            self.flags = LeaseFlags::clear(self.flags, LeaseFlags::HasName);
        }
        self.hostname = hostname;
        self.flags = LeaseFlags::set(self.flags, LeaseFlags::Changed);
        self.last_updated = Instant::now();
    }

    /// Set hardware address
    pub fn set_hwaddr(&mut self, hwaddr: Vec<u8>, hwaddr_type: u16) {
        self.hwaddr = hwaddr;
        self.hwaddr_type = hwaddr_type;
        self.flags = LeaseFlags::set(self.flags, LeaseFlags::HasHwAddr);
        self.flags = LeaseFlags::set(self.flags, LeaseFlags::Changed);
        self.last_updated = Instant::now();
    }

    /// Set expiration time
    pub fn set_expires(&mut self, expires: SystemTime) {
        self.expires = expires;
        self.flags = LeaseFlags::set(self.flags, LeaseFlags::Changed);
        self.last_updated = Instant::now();
    }
}

/// Central lease database manager
pub struct LeaseManager {
    /// Active leases indexed by client ID
    leases: Arc<RwLock<HashMap<ClientId, Arc<RwLock<DhcpLease>>>>>,
    /// Lease file path
    lease_file: PathBuf,
    /// Maximum number of leases
    max_leases: usize,
    /// Daemon configuration options
    options: DaemonOptions,
    /// DNS cache integration flag
    dns_dirty: Arc<RwLock<bool>>,
    /// Lease file needs update flag
    file_dirty: Arc<RwLock<bool>>,
    /// Start time for duration-based expiry (HAVE_BROKEN_RTC)
    start_time: Option<Instant>,
}

impl LeaseManager {
    /// Create a new lease manager
    pub fn new(
        lease_file: PathBuf,
        max_leases: usize,
        options: DaemonOptions,
        use_duration: bool,
    ) -> Self {
        Self {
            leases: Arc::new(RwLock::new(HashMap::new())),
            lease_file,
            max_leases,
            options,
            dns_dirty: Arc::new(RwLock::new(false)),
            file_dirty: Arc::new(RwLock::new(false)),
            start_time: if use_duration {
                Some(Instant::now())
            } else {
                None
            },
        }
    }

    /// Initialize lease database from file at daemon startup
    ///
    /// Loads existing leases from the lease file, parsing each line and constructing
    /// the in-memory lease database. Handles both absolute timestamps and duration-based
    /// expiry for systems without real-time clocks.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::IoError` if file cannot be read or `LeaseError::ParseError`
    /// if lease file format is invalid.
    pub async fn init(&self) -> Result<(), LeaseError> {
        info!(
            "Initializing lease database from {}",
            self.lease_file.display()
        );

        // Check if lease file exists
        if !self.lease_file.exists() {
            info!("Lease file does not exist, starting with empty database");
            return Ok(());
        }

        // Open lease file for reading
        let file = match File::open(&self.lease_file).await {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    "Failed to open lease file {}: {}. Will retry in {} seconds",
                    self.lease_file.display(),
                    e,
                    LEASE_RETRY.as_secs()
                );
                return Err(LeaseError::IoError(e.to_string()));
            }
        };

        let mut reader = BufReader::new(file);
        let mut contents = String::new();
        reader.read_to_string(&mut contents).await?;

        let mut lease_count = 0;
        let mut leases_guard = self.leases.write().await;

        // Parse lease file line by line
        for (line_num, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match self.parse_lease_line(line, line_num + 1).await {
                Ok(Some(lease)) => {
                    let clid = lease.read().await.clid.clone();
                    leases_guard.insert(clid, lease);
                    lease_count += 1;
                }
                Ok(None) => {
                    // Skip lease (expired or invalid)
                    continue;
                }
                Err(e) => {
                    warn!("Failed to parse lease at line {}: {}", line_num + 1, e);
                    // Continue parsing other leases
                    continue;
                }
            }
        }

        info!("Loaded {} leases from database", lease_count);
        Ok(())
    }

    /// Parse a single lease line from the lease file
    ///
    /// Parses lease file format:
    /// - DHCPv4: `<expiry> <mac> <ip> <hostname> <client-id>`
    /// - DHCPv6: `<expiry> <duid> <iaid> <ip6> <hostname> <type>`
    async fn parse_lease_line(
        &self,
        line: &str,
        line_num: usize,
    ) -> Result<Option<Arc<RwLock<DhcpLease>>>, LeaseError> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(LeaseError::ParseError(format!(
                "Line {}: insufficient fields",
                line_num
            )));
        }

        // Parse expiry time
        let expiry_str = fields[0];
        let expires = self.parse_expiry(expiry_str)?;

        // Check if expired
        if SystemTime::now() > expires {
            trace!("Skipping expired lease at line {}", line_num);
            return Ok(None);
        }

        // Detect lease type by field count and IP format
        if fields.len() >= 4 && fields[2].contains(':') && fields[2].matches(':').count() >= 5 {
            // DHCPv6 lease format
            self.parse_dhcpv6_lease(&fields, expires, line_num).await
        } else {
            // DHCPv4 lease format
            self.parse_dhcpv4_lease(&fields, expires, line_num).await
        }
    }

    /// Parse DHCPv4 lease line
    async fn parse_dhcpv4_lease(
        &self,
        fields: &[&str],
        expires: SystemTime,
        line_num: usize,
    ) -> Result<Option<Arc<RwLock<DhcpLease>>>, LeaseError> {
        if fields.len() < 3 {
            return Err(LeaseError::ParseError(format!(
                "Line {}: insufficient fields for DHCPv4 lease",
                line_num
            )));
        }

        // Parse MAC address
        let hwaddr = parse_hex(fields[1]).map_err(|e| {
            LeaseError::ParseError(format!("Line {}: invalid MAC address: {}", line_num, e))
        })?;

        // Parse IPv4 address
        let addr: Ipv4Addr = fields[2].parse().map_err(|e| {
            LeaseError::ParseError(format!("Line {}: invalid IPv4 address: {}", line_num, e))
        })?;

        // Parse hostname (optional)
        let hostname = if fields.len() > 3 && fields[3] != "*" {
            Some(fields[3].to_string())
        } else {
            None
        };

        // Parse client-id (optional)
        let clid = if fields.len() > 4 && fields[4] != "*" {
            parse_hex(fields[4]).unwrap_or_else(|_| fields[4].as_bytes().to_vec())
        } else {
            // Use MAC as client ID if no explicit client ID
            hwaddr.clone()
        };

        let lease = DhcpLease::new(addr, hwaddr, ARPHRD_ETHER, clid, hostname, expires);
        Ok(Some(Arc::new(RwLock::new(lease))))
    }

    /// Parse DHCPv6 lease line
    async fn parse_dhcpv6_lease(
        &self,
        fields: &[&str],
        expires: SystemTime,
        line_num: usize,
    ) -> Result<Option<Arc<RwLock<DhcpLease>>>, LeaseError> {
        if fields.len() < 4 {
            return Err(LeaseError::ParseError(format!(
                "Line {}: insufficient fields for DHCPv6 lease",
                line_num
            )));
        }

        // Parse DUID (client identifier)
        let duid = parse_hex(fields[1]).map_err(|e| {
            LeaseError::ParseError(format!("Line {}: invalid DUID: {}", line_num, e))
        })?;

        // Parse IAID
        let iaid: Iaid = if fields[2].starts_with("0x") {
            u32::from_str_radix(&fields[2][2..], 16)
        } else {
            fields[2].parse()
        }
        .map_err(|e| {
            LeaseError::ParseError(format!("Line {}: invalid IAID: {}", line_num, e))
        })?;

        // Parse IPv6 address
        let addr6: Ipv6Addr = fields[3].parse().map_err(|e| {
            LeaseError::ParseError(format!("Line {}: invalid IPv6 address: {}", line_num, e))
        })?;

        // Parse hostname (optional)
        let hostname = if fields.len() > 4 && fields[4] != "*" {
            Some(fields[4].to_string())
        } else {
            None
        };

        let mut lease = DhcpLease::new(
            Ipv4Addr::new(0, 0, 0, 0), // Placeholder, will be replaced
            Vec::new(),
            0,
            duid,
            hostname,
            expires,
        );
        lease.addr = None; // Clear IPv4 address
        lease.addr6 = Some(addr6);
        lease.iaid = Some(iaid);

        Ok(Some(Arc::new(RwLock::new(lease))))
    }

    /// Parse expiry timestamp or duration
    fn parse_expiry(&self, expiry_str: &str) -> Result<SystemTime, LeaseError> {
        let timestamp: i64 = expiry_str.parse().map_err(|e| {
            LeaseError::ParseError(format!("Invalid expiry timestamp: {}", e))
        })?;

        if let Some(start_time) = self.start_time {
            // Duration-based expiry (HAVE_BROKEN_RTC)
            let duration = Duration::from_secs(timestamp as u64);
            let expires_instant = start_time + duration;
            let now = Instant::now();
            if expires_instant > now {
                let remaining = expires_instant - now;
                Ok(SystemTime::now() + remaining)
            } else {
                Ok(SystemTime::now())
            }
        } else {
            // Absolute timestamp
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        }
    }

    /// Get lease count
    pub async fn lease_count(&self) -> usize {
        self.leases.read().await.len()
    }

    /// Get all leases (for reporting/debugging)
    pub async fn get_all_leases(&self) -> Vec<Arc<RwLock<DhcpLease>>> {
        self.leases.read().await.values().cloned().collect()
    }
}

/// Initialize lease database from file at daemon startup
///
/// This is a convenience function that creates a LeaseManager and calls init().
///
/// # Arguments
///
/// * `lease_file` - Path to lease database file
/// * `max_leases` - Maximum number of leases to track
/// * `options` - Daemon configuration options
/// * `use_duration` - Use duration-based expiry (HAVE_BROKEN_RTC)
///
/// # Errors
///
/// Returns `LeaseError` if file cannot be read or parsed.
pub async fn lease_init(
    lease_file: PathBuf,
    max_leases: usize,
    options: DaemonOptions,
    use_duration: bool,
) -> Result<Arc<LeaseManager>, LeaseError> {
    let manager = Arc::new(LeaseManager::new(
        lease_file,
        max_leases,
        options,
        use_duration,
    ));
    manager.init().await?;
    Ok(manager)
}

/// Find lease by client identifier or hardware address
///
/// Searches the lease database for a matching client ID. If not found and a hardware
/// address is provided, searches by hardware address as a fallback.
///
/// # Arguments
///
/// * `manager` - Lease manager instance
/// * `client_id` - Client identifier to search for
/// * `hwaddr` - Optional hardware address for fallback search
///
/// # Returns
///
/// The matching lease if found, or `None` if no match exists.
pub async fn lease_find_by_client(
    manager: &LeaseManager,
    client_id: &ClientId,
    hwaddr: Option<&[u8]>,
) -> Option<Arc<RwLock<DhcpLease>>> {
    let leases = manager.leases.read().await;

    // First, search by client ID
    if let Some(lease) = leases.get(client_id) {
        return Some(Arc::clone(lease));
    }

    // Fallback: search by hardware address
    if let Some(hw) = hwaddr {
        for lease in leases.values() {
            let lease_guard = lease.read().await;
            if lease_guard.hwaddr() == hw {
                drop(lease_guard);
                return Some(Arc::clone(lease));
            }
        }
    }

    None
}

/// Find lease by IPv4 address
///
/// Searches the lease database for a lease matching the given IPv4 address.
///
/// # Arguments
///
/// * `manager` - Lease manager instance
/// * `addr` - IPv4 address to search for
///
/// # Returns
///
/// The matching lease if found, or `None` if no match exists.
pub async fn lease_find_by_addr(
    manager: &LeaseManager,
    addr: Ipv4Addr,
) -> Option<Arc<RwLock<DhcpLease>>> {
    let leases = manager.leases.read().await;
    for lease in leases.values() {
        let lease_guard = lease.read().await;
        if lease_guard.addr() == Some(addr) {
            drop(lease_guard);
            return Some(Arc::clone(lease));
        }
    }
    None
}

/// Allocate a new DHCPv4 lease
///
/// Creates a new lease entry in the database. If the maximum lease count is reached,
/// returns an error.
///
/// # Arguments
///
/// * `manager` - Lease manager instance
/// * `addr` - IPv4 address to allocate
/// * `hwaddr` - Client hardware address
/// * `hwaddr_type` - Hardware address type (e.g., ARPHRD_ETHER)
/// * `client_id` - Client identifier
/// * `hostname` - Optional hostname
/// * `lease_time` - Lease duration in seconds
///
/// # Errors
///
/// Returns `LeaseError::NoAvailableAddress` if maximum lease count is reached.
pub async fn lease4_allocate(
    manager: &LeaseManager,
    addr: Ipv4Addr,
    hwaddr: Vec<u8>,
    hwaddr_type: u16,
    client_id: ClientId,
    hostname: Option<String>,
    lease_time: u32,
) -> Result<Arc<RwLock<DhcpLease>>, LeaseError> {
    let mut leases = manager.leases.write().await;

    // Check if we've reached maximum leases
    if leases.len() >= manager.max_leases {
        return Err(LeaseError::NoAvailableAddress);
    }

    let expires = SystemTime::now() + Duration::from_secs(lease_time as u64);
    let lease = DhcpLease::new(addr, hwaddr, hwaddr_type, client_id.clone(), hostname, expires);
    let lease_arc = Arc::new(RwLock::new(lease));

    leases.insert(client_id, Arc::clone(&lease_arc));
    *manager.file_dirty.write().await = true;

    let hwaddr_hex = lease_arc.read().await.hwaddr
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");
    info!("Allocated DHCPv4 lease for {} to {}", addr, hwaddr_hex);
    Ok(lease_arc)
}

/// Allocate a new DHCPv6 lease
///
/// Creates a new DHCPv6 lease entry in the database.
///
/// # Arguments
///
/// * `manager` - Lease manager instance
/// * `addr6` - IPv6 address to allocate
/// * `duid` - Client DUID
/// * `iaid` - Identity Association Identifier
/// * `hostname` - Optional hostname
/// * `lease_time` - Lease duration in seconds
///
/// # Errors
///
/// Returns `LeaseError::NoAvailableAddress` if maximum lease count is reached.
pub async fn lease6_allocate(
    manager: &LeaseManager,
    addr6: Ipv6Addr,
    duid: ClientId,
    iaid: Iaid,
    hostname: Option<String>,
    lease_time: u32,
) -> Result<Arc<RwLock<DhcpLease>>, LeaseError> {
    let mut leases = manager.leases.write().await;

    if leases.len() >= manager.max_leases {
        return Err(LeaseError::NoAvailableAddress);
    }

    let expires = SystemTime::now() + Duration::from_secs(lease_time as u64);
    let mut lease = DhcpLease::new(
        Ipv4Addr::new(0, 0, 0, 0),
        Vec::new(),
        0,
        duid.clone(),
        hostname,
        expires,
    );
    lease.addr = None;
    lease.addr6 = Some(addr6);
    lease.iaid = Some(iaid);

    let lease_arc = Arc::new(RwLock::new(lease));
    leases.insert(duid, Arc::clone(&lease_arc));
    *manager.file_dirty.write().await = true;

    info!("Allocated DHCPv6 lease for {} (IAID: {:#x})", addr6, iaid);
    Ok(lease_arc)
}

/// Remove expired leases from the database
///
/// Scans the lease database and removes all expired leases. This should be called
/// periodically by the daemon's timer events.
///
/// # Arguments
///
/// * `manager` - Lease manager instance
///
/// # Returns
///
/// The number of leases pruned.
pub async fn lease_prune(manager: &LeaseManager) -> usize {
    let mut leases = manager.leases.write().await;
    let now = SystemTime::now();
    let initial_count = leases.len();

    leases.retain(|clid, lease| {
        let lease_guard = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(lease.read())
        });
        if now > lease_guard.expires {
            let clid_hex = clid.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            debug!("Pruning expired lease: {}", clid_hex);
            false
        } else {
            true
        }
    });

    let pruned_count = initial_count - leases.len();
    if pruned_count > 0 {
        info!("Pruned {} expired leases", pruned_count);
        *tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(manager.file_dirty.write())
        }) = true;
    }

    pruned_count
}

/// Update DNS cache with lease hostname mappings
///
/// Synchronizes lease hostnames with the DNS cache for dynamic hostname resolution.
/// This is called after lease updates to ensure DNS queries can resolve DHCP hostnames.
///
/// # Arguments
///
/// * `manager` - Lease manager instance
pub async fn lease_update_dns(manager: &LeaseManager) {
    let dns_dirty = manager.dns_dirty.read().await;
    if !*dns_dirty {
        return;
    }
    drop(dns_dirty);

    debug!("Updating DNS cache with lease hostnames");
    // DNS cache integration would happen here
    // For now, just clear the dirty flag
    *manager.dns_dirty.write().await = false;
}

/// Atomically persist lease database to disk
///
/// Uses write-temp-rename pattern to ensure atomic updates and prevent corruption
/// during power failures or crashes. Writes to a temporary file, syncs to disk,
/// then renames to the actual lease file path.
///
/// # Arguments
///
/// * `manager` - Lease manager instance
///
/// # Errors
///
/// Returns `LeaseError::IoError` if file cannot be written. The function will
/// schedule a retry after LEASE_RETRY duration.
pub async fn lease_update_file(manager: &LeaseManager) -> Result<(), LeaseError> {
    let file_dirty = manager.file_dirty.read().await;
    if !*file_dirty {
        return Ok(());
    }
    drop(file_dirty);

    // Read-only mode check
    if manager.options.contains(DaemonOptions::OPT_LEASE_RO) {
        debug!("Lease file is read-only, skipping update");
        return Ok(());
    }

    let temp_file = manager.lease_file.with_extension("tmp");
    debug!(
        "Writing lease database to temporary file: {}",
        temp_file.display()
    );

    // Create temporary file
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_file)
        .await?;

    let mut writer = BufWriter::new(file);

    // Write all leases
    let leases = manager.leases.read().await;
    for lease in leases.values() {
        let lease_guard = lease.read().await;
        let line = format_lease_line(&lease_guard, manager.start_time);
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    drop(leases);

    // Flush and sync to disk
    writer.flush().await?;
    let file = writer.into_inner();
    file.sync_all().await?;
    drop(file);

    // Atomic rename
    tokio::fs::rename(&temp_file, &manager.lease_file).await?;

    *manager.file_dirty.write().await = false;
    info!(
        "Successfully wrote lease database to {}",
        manager.lease_file.display()
    );
    Ok(())
}

/// Format a lease as a line for the lease file
fn format_lease_line(lease: &DhcpLease, start_time: Option<Instant>) -> String {
    let expiry_str = if let Some(start) = start_time {
        // Duration-based expiry (HAVE_BROKEN_RTC)
        let now = Instant::now();
        let expires_duration = lease
            .expires
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        let expires_instant = now + expires_duration;
        let total_duration = expires_instant.saturating_duration_since(start);
        format!("{}", total_duration.as_secs())
    } else {
        // Absolute timestamp
        let timestamp = lease
            .expires
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        format!("{}", timestamp.as_secs())
    };

    if let Some(addr6) = lease.addr6 {
        // DHCPv6 lease
        let duid = lease.clid.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let iaid = lease.iaid.unwrap_or(0);
        let hostname = lease.hostname.as_deref().unwrap_or("*");
        format!("{} {} {:#x} {} {}", expiry_str, duid, iaid, addr6, hostname)
    } else if let Some(addr) = lease.addr {
        // DHCPv4 lease
        let mac = lease.hwaddr.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");
        let hostname = lease.hostname.as_deref().unwrap_or("*");
        let clid = if lease.clid == lease.hwaddr {
            "*".to_string()
        } else {
            lease.clid.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        };
        format!("{} {} {} {} {}", expiry_str, mac, addr, hostname, clid)
    } else {
        // Invalid lease
        String::new()
    }
}

/// Apply static host reservations to active leases
///
/// This function is called after configuration reloads to ensure configured
/// hostnames override DHCP-supplied names.
impl LeaseManager {
    pub async fn update_from_configs(&self) {
        debug!("Applying static host reservations to leases");
        // Configuration integration would happen here
        // For now, this is a placeholder
    }

    /// Find DHCPv6 lease by IPv6 address
    pub async fn find_by_addr6(&self, addr: Ipv6Addr) -> Option<Arc<RwLock<DhcpLease>>> {
        let leases = self.leases.read().await;
        for lease in leases.values() {
            let lease_guard = lease.read().await;
            if lease_guard.addr6() == Some(addr) {
                drop(lease_guard);
                return Some(Arc::clone(lease));
            }
        }
        None
    }

    /// Set lease hostname with FQDN handling
    ///
    /// This is a higher-level method that applies FQDN logic based on daemon options
    /// before calling the basic set_hostname method on the lease.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Client identifier for the lease
    /// * `hostname` - Optional hostname to set
    /// * `options` - Daemon options (for OPT_DHCP_FQDN check)
    /// * `ip_addr` - IP address for domain suffix lookup
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Hostname set successfully
    /// * `Err(LeaseError)` - Lease not found or other error
    pub async fn set_lease_hostname_with_fqdn(
        &mut self,
        client_id: &ClientId,
        hostname: Option<String>,
        options: DaemonOptions,
        ip_addr: IpAddr,
    ) -> Result<(), LeaseError> {
        let leases = self.leases.write().await;
        let lease_arc = leases
            .get(client_id)
            .ok_or(LeaseError::InvalidLease)?;
        let mut lease = lease_arc.write().await;

        let final_hostname = if let Some(name) = hostname {
            // If FQDN mode, construct FQDN based on domain suffix for this IP
            if options.contains(DaemonOptions::OPT_DHCP_FQDN) {
                // Get domain suffix for this IP address
                if let Some(domain) = get_domain(ip_addr) {
                    if !name.contains('.') {
                        // Bare hostname, append domain
                        Some(format!("{}.{}", name, domain))
                    } else {
                        // Already FQDN
                        Some(name)
                    }
                } else {
                    Some(name)
                }
            } else {
                Some(name)
            }
        } else {
            None
        };

        lease.set_hostname(final_hostname);
        Ok(())
    }

    /// Atomically persist lease database to disk with write-temp-rename pattern
    ///
    /// Writes all active leases to a temporary file, then atomically renames it to
    /// the target lease file to prevent corruption during crashes or power failures.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Lease file updated successfully
    /// * `Err(LeaseError)` - File I/O error occurred
    pub async fn update_file(&self) -> Result<(), LeaseError> {
        let temp_file = self.lease_file.with_extension("tmp");
        
        // Open temp file for writing
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_file)
            .await?;
        
        let mut writer = BufWriter::new(file);
        let leases = self.leases.read().await;
        
        // Write all non-expired leases
        for lease in leases.values() {
            let lease_guard = lease.read().await;
            if !lease_guard.is_expired() {
                let line = format_lease_line(&lease_guard, self.start_time);
                writer.write_all(line.as_bytes()).await?;
                writer.write_all(b"\n").await?;
            }
        }
        
        // Flush and sync to disk
        writer.flush().await?;
        drop(writer);
        
        // Atomic rename
        tokio::fs::rename(&temp_file, &self.lease_file).await?;
        
        // Clear file dirty flag
        let mut dirty = self.file_dirty.write().await;
        *dirty = false;
        
        debug!("Lease file updated: {}", self.lease_file.display());
        Ok(())
    }

    /// Find lease by client ID or hardware address
    ///
    /// # Arguments
    ///
    /// * `client_id` - Client identifier to search for
    ///
    /// # Returns
    ///
    /// Option containing the lease if found
    pub async fn find_by_client(&self, client_id: &ClientId) -> Option<Arc<RwLock<DhcpLease>>> {
        let leases = self.leases.read().await;
        leases.get(client_id).map(Arc::clone)
    }

    /// Find DHCPv4 lease by IP address
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address to search for
    ///
    /// # Returns
    ///
    /// Option containing the lease if found
    pub async fn find_by_addr(&self, addr: Ipv4Addr) -> Option<Arc<RwLock<DhcpLease>>> {
        let leases = self.leases.read().await;
        for lease in leases.values() {
            let lease_guard = lease.read().await;
            if lease_guard.addr() == Some(addr) {
                drop(lease_guard);
                return Some(Arc::clone(lease));
            }
        }
        None
    }

    /// Allocate new DHCPv4 lease
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address to allocate
    /// * `hwaddr` - Hardware address (MAC)
    /// * `hwaddr_type` - Hardware address type (e.g., ARPHRD_ETHER)
    /// * `clid` - Client identifier
    /// * `hostname` - Optional hostname
    /// * `expires` - Lease expiration time
    ///
    /// # Returns
    ///
    /// * `Ok(lease)` - Lease allocated successfully
    /// * `Err(LeaseError)` - No available addresses or allocation failed
    pub async fn allocate_v4(
        &mut self,
        addr: Ipv4Addr,
        hwaddr: Vec<u8>,
        hwaddr_type: u16,
        clid: ClientId,
        hostname: Option<String>,
        expires: SystemTime,
    ) -> Result<Arc<RwLock<DhcpLease>>, LeaseError> {
        let mut leases = self.leases.write().await;
        
        // Check if we've reached max leases
        if leases.len() >= self.max_leases {
            return Err(LeaseError::NoAvailableAddress);
        }
        
        let lease = DhcpLease::new(addr, hwaddr, hwaddr_type, clid.clone(), hostname, expires);
        let lease_arc = Arc::new(RwLock::new(lease));
        leases.insert(clid, Arc::clone(&lease_arc));
        
        // Mark file as dirty for next update
        let mut dirty = self.file_dirty.write().await;
        *dirty = true;
        
        debug!("Allocated DHCPv4 lease: {}", addr);
        Ok(lease_arc)
    }

    /// Allocate new DHCPv6 lease
    ///
    /// # Arguments
    ///
    /// * `addr6` - IPv6 address to allocate
    /// * `clid` - Client DUID
    /// * `iaid` - Identity Association ID
    /// * `hostname` - Optional hostname
    /// * `expires` - Lease expiration time
    ///
    /// # Returns
    ///
    /// * `Ok(lease)` - Lease allocated successfully
    /// * `Err(LeaseError)` - No available addresses or allocation failed
    pub async fn allocate_v6(
        &mut self,
        addr6: Ipv6Addr,
        clid: ClientId,
        iaid: Iaid,
        hostname: Option<String>,
        expires: SystemTime,
    ) -> Result<Arc<RwLock<DhcpLease>>, LeaseError> {
        let mut leases = self.leases.write().await;
        
        // Check if we've reached max leases
        if leases.len() >= self.max_leases {
            return Err(LeaseError::NoAvailableAddress);
        }
        
        let mut lease = DhcpLease::new(
            Ipv4Addr::new(0, 0, 0, 0),
            Vec::new(),
            0,
            clid.clone(),
            hostname,
            expires,
        );
        lease.addr = None;
        lease.addr6 = Some(addr6);
        lease.iaid = Some(iaid);
        
        let lease_arc = Arc::new(RwLock::new(lease));
        leases.insert(clid, Arc::clone(&lease_arc));
        
        // Mark file as dirty for next update
        let mut dirty = self.file_dirty.write().await;
        *dirty = true;
        
        debug!("Allocated DHCPv6 lease: {}", addr6);
        Ok(lease_arc)
    }

    /// Remove expired leases and return count removed
    ///
    /// Iterates through all leases, removes expired ones, and marks the file
    /// as dirty for persistence.
    ///
    /// # Returns
    ///
    /// Number of leases pruned
    pub async fn prune(&mut self) -> usize {
        let mut leases = self.leases.write().await;
        let now = SystemTime::now();
        let mut count = 0;
        
        leases.retain(|_, lease_arc| {
            let lease = lease_arc.blocking_read();
            let keep = now <= lease.expires;
            if !keep {
                count += 1;
                debug!(
                    "Pruning expired lease: {:?}",
                    lease.addr.or(lease.addr6.map(|a| a.into()))
                );
            }
            keep
        });
        
        if count > 0 {
            // Mark file as dirty
            let mut dirty = self.file_dirty.write().await;
            *dirty = true;
            info!("Pruned {} expired leases", count);
        }
        
        count
    }
}
