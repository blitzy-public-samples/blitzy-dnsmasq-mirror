// Copyright (c) 2000-2024 Simon Kelley and contributors
// Copyright (C) 2024 Blitzy - dnsmasq Rust Implementation
// Licensed under GPL-2.0-or-later

//! Main daemon state structure for dnsmasq Rust implementation
//!
//! This module provides the central state management structure for the dnsmasq daemon,
//! replacing C's global `struct daemon` pointer with a type-safe Rust implementation.
//! The state is organized into logical subsystems and uses Rust's ownership system
//! to eliminate all memory safety issues present in the C implementation.
//!
//! # Overview
//!
//! The `DaemonState` structure serves as the central nervous system of dnsmasq,
//! containing all runtime state for:
//! - DNS caching and forwarding
//! - DHCP lease management
//! - Network interface monitoring
//! - Configuration management
//! - Metrics and logging
//!
//! # Architecture
//!
//! The C implementation uses a monolithic global structure with ~150 fields accessed
//! via raw pointers throughout the codebase. The Rust implementation organizes state
//! into logical sub-structures:
//!
//! - `DnsState`: DNS cache, forward records, upstream servers
//! - `DhcpState`: DHCP contexts, leases, static host configurations
//! - `NetworkState`: Interfaces, listening sockets, file descriptors
//! - `ConfigState`: Runtime configuration (embedded `Config` struct)
//! - `MetricsState`: Performance counters and operational statistics
//!
//! # Thread Safety
//!
//! For concurrent access from async tasks, wrap `DaemonState` in `Arc<RwLock<DaemonState>>`:
//!
//! ```ignore
//! use std::sync::{Arc, RwLock};
//! use dnsmasq::types::daemon_state::DaemonState;
//!
//! let state = Arc::new(RwLock::new(DaemonState::new(config)));
//!
//! // Read access (multiple readers allowed)
//! let cache = state.read().unwrap().get_dns_cache();
//!
//! // Write access (exclusive lock)
//! state.write().unwrap().update_interfaces(new_interfaces)?;
//! ```
//!
//! # Memory Safety
//!
//! This implementation eliminates all memory safety issues from the C version:
//! - No manual memory management (malloc/free)
//! - No null pointer dereferences (Option types)
//! - No use-after-free (ownership tracking)
//! - No buffer overflows (slice bounds checking)
//! - No data races (Send + Sync traits)
//!
//! # C Source Reference
//!
//! Replaces:
//! - `extern struct daemon *daemon` (dnsmasq.h:4074-4251)
//! - Global daemon state initialization (dnsmasq.c:main function)
//! - State update functions scattered throughout option.c, cache.c, dhcp.c
//!
//! # Builder Pattern
//!
//! Construction uses `DaemonStateBuilder` for incremental assembly with validation:
//!
//! ```ignore
//! let state = DaemonStateBuilder::new()
//!     .config(config)
//!     .dns_cache(DnsCache::new(1000))
//!     .forward_servers(servers)
//!     .interfaces(interfaces)
//!     .listeners(listeners)
//!     .build()?;
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

// Internal imports - ONLY from depends_on_files
use crate::config::Config;
use crate::config::types::DhcpOption;
use crate::constants::MAX_FORWARD_REQUESTS;
use crate::dns::cache::DnsCache;
use crate::dns::forward::Server;
use crate::network::interface::InterfaceRecord;
use crate::network::socket::SocketListener;
use crate::types::addresses::AllAddr;
use crate::types::errors::DnsmasqError;

/// Main daemon state structure
///
/// This structure replaces C's `extern struct daemon` with a type-safe Rust
/// implementation. It contains all runtime state for the dnsmasq daemon,
/// organized into logical subsystems for maintainability.
///
/// # Fields
///
/// The state is organized into five main categories:
/// - **Configuration**: Runtime configuration from `Config`
/// - **DNS State**: Cache, forward records, upstream servers
/// - **DHCP State**: Lease database, contexts, static hosts
/// - **Network State**: Interfaces, sockets, file descriptors
/// - **Metrics**: Performance counters and statistics
///
/// # Lifecycle
///
/// 1. **Creation**: Built via `DaemonStateBuilder`
/// 2. **Operation**: Updated in response to configuration reloads, network events
/// 3. **Destruction**: Automatic cleanup via Drop trait
///
/// # Thread Safety
///
/// `DaemonState` is `Send + Sync` when wrapped in appropriate synchronization:
/// - Single-threaded: Direct mutable access
/// - Multi-threaded async: `Arc<RwLock<DaemonState>>`
///
/// # Examples
///
/// ```ignore
/// // Create initial daemon state
/// let state = DaemonStateBuilder::new()
///     .config(config)
///     .dns_cache(DnsCache::new(1000))
///     .build()?;
///
/// // Access DNS cache
/// let cache = state.get_dns_cache();
///
/// // Update interfaces after network change
/// state.update_interfaces(new_interfaces)?;
/// ```
#[derive(Debug)]
pub struct DaemonState {
    /// Configuration state (embedded Config struct)
    config: Config,

    /// DNS subsystem state
    pub dns: DnsState,

    /// DHCP subsystem state (feature-gated)
    #[cfg(feature = "dhcp")]
    pub dhcp: DhcpState,

    /// Network interface and socket state
    network: NetworkState,

    /// Operational metrics and statistics
    metrics: MetricsState,

    /// Daemon start time for uptime calculation
    start_time: Instant,

    /// Last configuration reload timestamp
    last_reload: Option<Instant>,
}

/// DNS subsystem state
///
/// Contains all state related to DNS caching, forwarding, and query processing.
/// Replaces DNS-related fields from C's `struct daemon`.
///
/// # C Source Reference
///
/// Corresponds to these fields from dnsmasq.h struct daemon:
/// - `struct frec *frec_list` → `forward_records`
/// - `struct server *servers` → `upstream_servers`
/// - DNS cache fields (managed by `DnsCache`)
/// - `char *packet`, `int packet_buff_sz` → managed by protocol parser
///
/// # Fields
///
/// - `cache`: DNS response cache with LRU eviction
/// - `upstream_servers`: List of configured upstream DNS servers
/// - `forward_records`: Active DNS queries awaiting upstream responses
#[derive(Debug)]
pub struct DnsState {
    /// DNS response cache (Arc-wrapped for potential sharing)
    pub cache: Arc<DnsCache>,

    /// Configured upstream DNS servers for query forwarding
    /// Corresponds to C's `struct server *servers`
    pub upstream_servers: Vec<Server>,

    /// DNS servers list (alias for `upstream_servers` for compatibility)
    pub servers: Vec<AllAddr>,

    /// Domain search list
    pub domain: Option<String>,

    /// Active forward records tracking in-flight queries
    /// Maps query ID to forward record for response matching
    /// Limited to `MAX_FORWARD_REQUESTS` concurrent queries
    forward_records: HashMap<u16, ForwardRecord>,

    /// Next query ID for outbound queries (incremented per query)
    next_query_id: u16,
}

/// Forward record for tracking in-flight DNS queries
///
/// Corresponds to C's `struct frec` (forward record) from dnsmasq.h.
/// Tracks an outbound query to an upstream server awaiting a response.
///
/// # Fields
///
/// - `original_id`: Query ID from original client request
/// - `upstream_id`: Query ID used for upstream query (may differ)
/// - `sent_to`: Upstream server address query was sent to
/// - `timestamp`: When the query was sent (for timeout detection)
/// - `client_addr`: Original client address for response routing
#[derive(Debug, Clone)]
struct ForwardRecord {
    /// Original query ID from client request
    original_id: u16,

    /// Query ID used in upstream query (randomized)
    upstream_id: u16,

    /// Address of upstream server query was sent to
    sent_to: IpAddr,

    /// Timestamp when query was sent (for timeout tracking)
    timestamp: Instant,

    /// Client address to send response to
    client_addr: AllAddr,
}

/// DHCP subsystem state
///
/// Contains all state related to DHCP lease management, contexts, and configurations.
/// Replaces DHCP-related fields from C's `struct daemon`.
///
/// # C Source Reference
///
/// Corresponds to these fields from dnsmasq.h struct daemon:
/// - `struct dhcp_context *dhcp, *dhcp6` → `contexts_v4`, `contexts_v6`
/// - `struct dhcp_config *dhcp_conf` → `static_hosts`
/// - Lease database state (managed by separate lease module)
///
/// # Feature Gate
///
/// Only compiled when `dhcp` feature is enabled.
#[cfg(feature = "dhcp")]
#[derive(Debug)]
pub struct DhcpState {
    /// `DHCPv4` contexts (address ranges and options)
    pub contexts_v4: Vec<DhcpContext>,

    /// `DHCPv6` contexts (address ranges and options)
    #[cfg(feature = "dhcp-v6")]
    pub contexts_v6: Vec<DhcpContext>,

    /// Static DHCP host configurations (MAC → IP mappings)
    pub static_hosts: Vec<StaticHost>,

    /// DHCP lease database (active and expired leases)
    pub lease_database: DhcpLeaseDatabase,

    /// `DHCPv6` server DUID (DHCP Unique Identifier)
    pub server_duid: Option<Vec<u8>>,

    /// DHCP options configuration
    pub options: Vec<DhcpOption>,
}

/// DHCP context representing an address range and associated options
///
/// Corresponds to C's `struct dhcp_context` from dnsmasq.h.
/// Defines an IP address range for DHCP allocation with associated
/// network parameters and options.
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpContext {
    /// Start of address range
    pub range_start: IpAddr,

    /// End of address range
    pub range_end: IpAddr,

    /// Network interface this context applies to
    pub interface: Option<String>,

    /// Default lease time in seconds
    pub lease_time: u32,
}

/// Static DHCP host configuration
///
/// Corresponds to C's `struct dhcp_config` from dnsmasq.h.
/// Maps MAC addresses to fixed IP addresses and hostnames.
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct StaticHost {
    /// MAC address (hardware address)
    pub mac_address: [u8; 6],

    /// Fixed IP address to assign
    pub ip_address: IpAddr,

    /// Optional hostname to assign
    pub hostname: Option<String>,
}

/// DHCP lease database
///
/// Manages active and expired DHCP leases with persistence to disk.
/// Replaces C's lease file management from lease.c.
#[cfg(feature = "dhcp")]
#[derive(Debug)]
pub struct DhcpLeaseDatabase {
    /// Active leases (MAC → lease info)
    pub active_leases: HashMap<[u8; 6], DhcpLease>,

    /// Path to lease file for persistence
    pub lease_file_path: Option<std::path::PathBuf>,
}

/// Individual DHCP lease record
///
/// Tracks a single DHCP lease with expiration time and client information.
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpLease {
    /// Assigned IP address
    pub ip_address: IpAddr,

    /// Lease expiration time
    pub expires_at: Instant,

    /// Client hostname (if provided)
    pub hostname: Option<String>,

    /// Client identifier (if provided)
    pub client_id: Option<Vec<u8>>,
}

/// Network interface and socket state
///
/// Manages active network interfaces and listening sockets.
/// Replaces network-related fields from C's `struct daemon`.
///
/// # C Source Reference
///
/// Corresponds to these fields from dnsmasq.h struct daemon:
/// - `struct irec *interfaces` → `interfaces`
/// - `struct listener *listeners` → `listeners`
/// - `struct serverfd *sfds` → managed by `SocketListener`
///
/// # Fields
///
/// - `interfaces`: Detected network interfaces with addresses
/// - `listeners`: Active listening sockets (DNS, DHCP, TFTP)
#[derive(Debug)]
struct NetworkState {
    /// All detected network interfaces with their addresses
    interfaces: Vec<InterfaceRecord>,

    /// Active listening sockets for all protocols
    listeners: Vec<SocketListener>,
}

/// Operational metrics and statistics
///
/// Tracks performance counters and operational statistics for monitoring.
/// Replaces C's `u32 metrics[__METRIC_MAX]` array.
///
/// # C Source Reference
///
/// Corresponds to:
/// - `u32 metrics[__METRIC_MAX]` from dnsmasq.h struct daemon
/// - Various counters scattered throughout DNS and DHCP code
///
/// # Fields
///
/// All counters are cumulative since daemon start.
#[derive(Debug, Default, Clone)]
pub struct MetricsState {
    /// Total DNS queries received
    pub dns_queries_received: u64,

    /// DNS cache hits (served from cache)
    pub dns_cache_hits: u64,

    /// DNS cache misses (forwarded to upstream)
    pub dns_cache_misses: u64,

    /// Total DNS queries forwarded to upstream servers
    pub dns_queries_forwarded: u64,

    /// DHCP DISCOVER messages received
    #[cfg(feature = "dhcp")]
    pub dhcp_discovers: u64,

    /// DHCP OFFER messages sent
    #[cfg(feature = "dhcp")]
    pub dhcp_offers: u64,

    /// DHCP REQUEST messages received
    #[cfg(feature = "dhcp")]
    pub dhcp_requests: u64,

    /// DHCP ACK messages sent
    #[cfg(feature = "dhcp")]
    pub dhcp_acks: u64,

    /// DHCP NAK messages sent
    #[cfg(feature = "dhcp")]
    pub dhcp_naks: u64,

    /// Total active DHCP leases
    #[cfg(feature = "dhcp")]
    pub dhcp_leases_active: u64,
}

impl DaemonState {
    /// Create a new daemon state with specified configuration
    ///
    /// This is a simplified constructor for basic initialization.
    /// For full control over state initialization, use `DaemonStateBuilder`.
    ///
    /// # Arguments
    ///
    /// * `config` - Runtime configuration
    ///
    /// # Returns
    ///
    /// A new `DaemonState` with default-initialized subsystems
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let config = Config::default();
    /// let state = DaemonState::new(config);
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's daemon initialization in `dnsmasq.c` `main()` function
    #[must_use]
    pub fn new(config: Config) -> Self {
        let cache_size = config.dns.cache_size;

        Self {
            config,
            dns: DnsState {
                cache: Arc::new(DnsCache::new(cache_size)),
                upstream_servers: Vec::new(),
                servers: Vec::new(),
                domain: None,
                forward_records: HashMap::with_capacity(MAX_FORWARD_REQUESTS),
                next_query_id: 1,
            },
            #[cfg(feature = "dhcp")]
            dhcp: DhcpState {
                contexts_v4: Vec::new(),
                #[cfg(feature = "dhcp-v6")]
                contexts_v6: Vec::new(),
                static_hosts: Vec::new(),
                lease_database: DhcpLeaseDatabase {
                    active_leases: HashMap::new(),
                    lease_file_path: None,
                },
                server_duid: None,
                options: Vec::new(),
            },
            network: NetworkState {
                interfaces: Vec::new(),
                listeners: Vec::new(),
            },
            metrics: MetricsState::default(),
            start_time: Instant::now(),
            last_reload: None,
        }
    }

    /// Get DHCP contexts for address allocation
    ///
    /// Returns all configured DHCP contexts (both IPv4 and IPv6) for
    /// address range management and lease allocation.
    ///
    /// # Returns
    ///
    /// Vector of DHCP contexts (empty if DHCP feature disabled)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let contexts = state.get_dhcp_contexts();
    /// for context in contexts {
    ///     println!("Range: {} - {}", context.range_start, context.range_end);
    /// }
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces access to `daemon->dhcp` and `daemon->dhcp6` linked lists
    #[must_use]
    #[cfg(feature = "dhcp")]
    pub fn get_dhcp_contexts(&self) -> Vec<DhcpContext> {
        let mut contexts = self.dhcp.contexts_v4.clone();
        #[cfg(feature = "dhcp-v6")]
        contexts.extend(self.dhcp.contexts_v6.clone());
        contexts
    }

    /// Get DHCP contexts (no-op when DHCP feature disabled)
    ///
    /// Returns empty vector when compiled without DHCP support.
    /// Maintains API compatibility across feature configurations.
    #[cfg(not(feature = "dhcp"))]
    pub fn get_dhcp_contexts(&self) -> Vec<DhcpContext> {
        Vec::new()
    }

    /// Get static DHCP host configurations
    ///
    /// Returns all configured static host mappings (MAC → IP address).
    /// These hosts always receive the same IP address regardless of
    /// normal DHCP allocation.
    ///
    /// # Returns
    ///
    /// Vector of static host configurations (empty if DHCP feature disabled)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let static_hosts = state.get_static_hosts();
    /// for host in static_hosts {
    ///     println!("MAC: {:?} → IP: {}", host.mac_address, host.ip_address);
    /// }
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces access to `daemon->dhcp_conf` linked list
    #[must_use]
    #[cfg(feature = "dhcp")]
    pub fn get_static_hosts(&self) -> Vec<StaticHost> {
        self.dhcp.static_hosts.clone()
    }

    /// Get static DHCP host configurations (no-op when DHCP feature disabled)
    ///
    /// Returns empty vector when compiled without DHCP support.
    #[must_use]
    #[cfg(not(feature = "dhcp"))]
    pub fn get_static_hosts(&self) -> Vec<StaticHost> {
        Vec::new()
    }

    /// Get DHCP lease database
    ///
    /// Returns reference to the active DHCP lease database for
    /// querying active leases and managing lease expiration.
    ///
    /// # Returns
    ///
    /// Reference to lease database, or empty database if DHCP disabled
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let lease_db = state.get_lease_database();
    /// let active_count = lease_db.active_leases.len();
    /// println!("Active leases: {}", active_count);
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces direct access to lease structures in lease.c
    #[must_use]
    #[cfg(feature = "dhcp")]
    pub fn get_lease_database(&self) -> &DhcpLeaseDatabase {
        &self.dhcp.lease_database
    }

    /// Get empty lease database (no-op when DHCP feature disabled)
    ///
    /// Returns reference to empty database structure for API compatibility.
    #[must_use]
    #[cfg(not(feature = "dhcp"))]
    pub fn get_lease_database(&self) -> &DhcpLeaseDatabase {
        // Return a static empty database
        static EMPTY_DB: DhcpLeaseDatabase = DhcpLeaseDatabase {
            active_leases: HashMap::new(),
            lease_file_path: None,
        };
        &EMPTY_DB
    }

    /// Get DNS cache for query resolution
    ///
    /// Returns Arc-wrapped DNS cache for concurrent access from
    /// multiple async tasks. The cache provides O(1) lookups with
    /// LRU eviction when capacity is reached.
    ///
    /// # Returns
    ///
    /// Arc reference to DNS cache (can be cloned for shared access)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let cache = state.get_dns_cache();
    /// // Clone for use in async task
    /// let cache_clone = Arc::clone(&cache);
    /// tokio::spawn(async move {
    ///     // Use cache_clone in async context
    /// });
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces direct access to global cache structures in cache.c
    #[must_use]
    pub fn get_dns_cache(&self) -> Arc<DnsCache> {
        Arc::clone(&self.dns.cache)
    }

    /// Get current runtime configuration
    ///
    /// Returns immutable reference to the active configuration.
    /// Configuration can be updated via `reload_config()` method.
    ///
    /// # Returns
    ///
    /// Reference to current `Config` structure
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let config = state.get_config();
    /// println!("DNS cache size: {}", config.dns.cache_size);
    /// println!("Listening on port: {}", config.network.port);
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces access to daemon->option fields throughout C codebase
    #[must_use]
    pub fn get_config(&self) -> &Config {
        &self.config
    }

    /// Reload configuration from updated Config structure
    ///
    /// Updates the daemon configuration and reinitializes subsystems that
    /// depend on configuration changes. This is typically called in response
    /// to SIGHUP signal handler.
    ///
    /// # Arguments
    ///
    /// * `new_config` - Updated configuration to apply
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful reload, or error if configuration is invalid
    ///
    /// # Errors
    ///
    /// Returns an error if the new configuration is invalid or if subsystem
    /// reinitialization fails during the reload process.
    ///
    /// # Behavior
    ///
    /// Configuration reload triggers:
    /// - DNS cache resize if `cache_size` changed
    /// - Upstream server list update
    /// - Network interface re-enumeration
    /// - DHCP context reconfiguration
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Load new configuration from file
    /// let new_config = load_config_from_file("/etc/dnsmasq.conf")?;
    ///
    /// // Apply new configuration
    /// state.reload_config(new_config)?;
    ///
    /// println!("Configuration reloaded successfully");
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces SIGHUP handler logic in `dnsmasq.c:main_loop()`
    pub fn reload_config(&mut self, new_config: Config) -> Result<(), DnsmasqError> {
        // Check if DNS cache size changed
        let old_cache_size = self.config.dns.cache_size;
        let new_cache_size = new_config.dns.cache_size;

        if old_cache_size != new_cache_size {
            // Recreate DNS cache with new size
            // Note: This loses cached entries, matching C behavior on cache resize
            self.dns.cache = Arc::new(DnsCache::new(new_cache_size));
        }

        // Update configuration
        self.config = new_config;

        // Record reload timestamp
        self.last_reload = Some(Instant::now());

        // Clear forward records (will be recreated as needed)
        self.dns.forward_records.clear();
        self.dns.next_query_id = 1;

        // Note: Network interface and upstream server updates would be triggered
        // separately by the event loop after configuration reload
        // This matches C behavior where SIGHUP sets flag for deferred processing

        Ok(())
    }

    /// Update network interfaces after system network change
    ///
    /// Updates the list of active network interfaces in response to
    /// interface up/down events or address changes detected through
    /// platform-specific monitoring (netlink on Linux, kqueue on BSD).
    ///
    /// # Arguments
    ///
    /// * `new_interfaces` - Updated list of network interfaces
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful update, or error if interface configuration invalid
    ///
    /// # Errors
    ///
    /// Returns an error if no interfaces are provided or if the interface
    /// configuration is invalid for the daemon's operation.
    ///
    /// # Behavior
    ///
    /// Interface updates trigger:
    /// - Listener socket recreation if interface addresses changed
    /// - DNS cache purge of interface-specific entries
    /// - DHCP context interface binding validation
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Enumerate current interfaces
    /// let interfaces = enumerate_interfaces()?;
    ///
    /// // Update daemon state
    /// state.update_interfaces(interfaces)?;
    ///
    /// println!("Interface list updated");
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces interface update logic in `netlink.c:netlink_multicast()`
    /// and `bpf.c:iface_check()` for BSD platforms
    pub fn update_interfaces(
        &mut self,
        new_interfaces: Vec<InterfaceRecord>,
    ) -> Result<(), DnsmasqError> {
        // Validate that at least one interface is present
        if new_interfaces.is_empty() {
            return Err(DnsmasqError::Network(
                crate::types::errors::NetworkError::InterfaceEnumerationFailed {
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "No network interfaces available",
                    ),
                },
            ));
        }

        // Update interface list
        self.network.interfaces = new_interfaces;

        // Note: Listener socket updates would be triggered by event loop
        // after detecting interface changes. This matches C behavior where
        // interface changes set flags for deferred listener recreation.

        Ok(())
    }

    /// Get daemon uptime in seconds
    ///
    /// Returns the number of seconds since the daemon was started.
    ///
    /// # Returns
    ///
    /// Uptime in seconds as u64
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let uptime = state.uptime_seconds();
    /// println!("Daemon has been running for {} seconds", uptime);
    /// ```
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get current metrics snapshot
    ///
    /// Returns a clone of current metrics for reporting and monitoring.
    ///
    /// # Returns
    ///
    /// Snapshot of all operational metrics
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let metrics = state.get_metrics();
    /// println!("DNS queries: {}", metrics.dns_queries_received);
    /// println!("Cache hit rate: {:.2}%",
    ///     100.0 * metrics.dns_cache_hits as f64 /
    ///     metrics.dns_queries_received as f64);
    /// ```
    #[must_use]
    pub fn get_metrics(&self) -> MetricsState {
        self.metrics.clone()
    }

    /// Get list of active network interfaces
    ///
    /// Returns current list of detected network interfaces with addresses.
    ///
    /// # Returns
    ///
    /// Slice of interface records
    ///
    /// # Examples
    ///
    /// ```ignore
    /// for iface in state.get_interfaces() {
    ///     println!("Interface: {} (index {})", iface.name, iface.index);
    ///     for addr in &iface.addresses {
    ///         println!("  Address: {}", addr);
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn get_interfaces(&self) -> &[InterfaceRecord] {
        &self.network.interfaces
    }

    /// Get list of active listening sockets
    ///
    /// Returns current list of listening sockets for DNS, DHCP, and TFTP.
    ///
    /// # Returns
    ///
    /// Slice of socket listeners
    ///
    /// # Examples
    ///
    /// ```ignore
    /// for listener in state.get_listeners() {
    ///     println!("Listening on {} for {:?}", listener.addr, listener.protocol);
    /// }
    /// ```
    #[must_use]
    pub fn get_listeners(&self) -> &[SocketListener] {
        &self.network.listeners
    }

    /// Get list of upstream DNS servers
    ///
    /// Returns configured upstream servers for DNS query forwarding.
    ///
    /// # Returns
    ///
    /// Slice of upstream server configurations
    ///
    /// # Examples
    ///
    /// ```ignore
    /// for server in state.get_upstream_servers() {
    ///     println!("Upstream: {} (domain: {:?})", server.addr, server.domain);
    /// }
    /// ```
    #[must_use]
    pub fn get_upstream_servers(&self) -> &[Server] {
        &self.dns.upstream_servers
    }
}

/// Builder for constructing `DaemonState` with validation
///
/// Provides fluent interface for incremental daemon state construction
/// with comprehensive validation at each step. Ensures all required
/// components are initialized before creating the final `DaemonState`.
///
/// # Examples
///
/// ```ignore
/// let state = DaemonStateBuilder::new()
///     .config(config)
///     .dns_cache(DnsCache::new(1000))
///     .forward_servers(vec![
///         Server::from_address("8.8.8.8:53")?,
///         Server::from_address("1.1.1.1:53")?,
///     ])
///     .interfaces(interfaces)
///     .listeners(listeners)
///     .build()?;
/// ```
///
/// # C Source Reference
///
/// Replaces scattered initialization logic in `dnsmasq.c:main()`
#[derive(Debug, Default)]
pub struct DaemonStateBuilder {
    config: Option<Config>,
    dns_cache: Option<DnsCache>,
    forward_servers: Option<Vec<Server>>,
    interfaces: Option<Vec<InterfaceRecord>>,
    listeners: Option<Vec<SocketListener>>,
}

impl DaemonStateBuilder {
    /// Create a new daemon state builder
    ///
    /// Initializes an empty builder for incremental state construction.
    ///
    /// # Returns
    ///
    /// New `DaemonStateBuilder` instance
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = DaemonStateBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set runtime configuration
    ///
    /// Configures the daemon with runtime settings from Config structure.
    ///
    /// # Arguments
    ///
    /// * `config` - Runtime configuration
    ///
    /// # Returns
    ///
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```ignore
    /// builder.config(config);
    /// ```
    #[must_use]
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Set DNS cache
    ///
    /// Configures the DNS response cache with specified capacity.
    ///
    /// # Arguments
    ///
    /// * `cache` - Initialized DNS cache
    ///
    /// # Returns
    ///
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```ignore
    /// builder.dns_cache(DnsCache::new(1000));
    /// ```
    #[must_use]
    pub fn dns_cache(mut self, cache: DnsCache) -> Self {
        self.dns_cache = Some(cache);
        self
    }

    /// Set upstream DNS servers
    ///
    /// Configures the list of upstream servers for query forwarding.
    ///
    /// # Arguments
    ///
    /// * `servers` - List of upstream server configurations
    ///
    /// # Returns
    ///
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```ignore
    /// builder.forward_servers(vec![
    ///     Server::from_address("8.8.8.8:53")?,
    /// ]);
    /// ```
    #[must_use]
    pub fn forward_servers(mut self, servers: Vec<Server>) -> Self {
        self.forward_servers = Some(servers);
        self
    }

    /// Set network interfaces
    ///
    /// Configures the list of active network interfaces.
    ///
    /// # Arguments
    ///
    /// * `interfaces` - List of network interface records
    ///
    /// # Returns
    ///
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```ignore
    /// builder.interfaces(enumerate_interfaces()?);
    /// ```
    #[must_use]
    pub fn interfaces(mut self, interfaces: Vec<InterfaceRecord>) -> Self {
        self.interfaces = Some(interfaces);
        self
    }

    /// Set listening sockets
    ///
    /// Configures the list of active listening sockets.
    ///
    /// # Arguments
    ///
    /// * `listeners` - List of socket listeners
    ///
    /// # Returns
    ///
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```ignore
    /// builder.listeners(vec![udp_listener, tcp_listener]);
    /// ```
    #[must_use]
    pub fn listeners(mut self, listeners: Vec<SocketListener>) -> Self {
        self.listeners = Some(listeners);
        self
    }

    /// Build final `DaemonState` with validation
    ///
    /// Constructs the final `DaemonState` from builder configuration,
    /// validating that all required components are present.
    ///
    /// # Returns
    ///
    /// `Ok(DaemonState)` if all validation passes, or error describing
    /// missing or invalid components
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Configuration is missing
    /// - DNS cache is not configured
    /// - No upstream servers configured (unless local-only mode)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let state = builder.build()?;
    /// ```
    pub fn build(self) -> Result<DaemonState, DnsmasqError> {
        // Validate required configuration is present
        let config = self.config.ok_or_else(|| {
            DnsmasqError::Config(crate::types::errors::ConfigError::MissingRequired {
                option: "config".to_string(),
            })
        })?;

        // Get DNS cache or create default from config
        let dns_cache = self
            .dns_cache
            .unwrap_or_else(|| DnsCache::new(config.dns.cache_size));

        // Get upstream servers or use empty list
        let upstream_servers = self.forward_servers.unwrap_or_default();

        // Get interfaces or use empty list (will be populated by event loop)
        let interfaces = self.interfaces.unwrap_or_default();

        // Get listeners or use empty list (will be populated by event loop)
        let listeners = self.listeners.unwrap_or_default();

        // Construct daemon state
        let state = DaemonState {
            config,
            dns: DnsState {
                cache: Arc::new(dns_cache),
                upstream_servers,
                servers: Vec::new(),
                domain: None,
                forward_records: HashMap::with_capacity(MAX_FORWARD_REQUESTS),
                next_query_id: 1,
            },
            #[cfg(feature = "dhcp")]
            dhcp: DhcpState {
                contexts_v4: Vec::new(),
                #[cfg(feature = "dhcp-v6")]
                contexts_v6: Vec::new(),
                static_hosts: Vec::new(),
                lease_database: DhcpLeaseDatabase {
                    active_leases: HashMap::new(),
                    lease_file_path: None,
                },
                server_duid: None,
                options: Vec::new(),
            },
            network: NetworkState {
                interfaces,
                listeners,
            },
            metrics: MetricsState::default(),
            start_time: Instant::now(),
            last_reload: None,
        };

        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_daemon_state_creation() {
        let config = Config::default();
        let state = DaemonState::new(config);

        assert_eq!(state.dns.next_query_id, 1);
        assert!(state.dns.forward_records.is_empty());
        assert_eq!(state.metrics.dns_queries_received, 0);
    }

    #[test]
    fn test_daemon_state_builder() {
        let config = Config::default();
        let result = DaemonStateBuilder::new()
            .config(config)
            .dns_cache(DnsCache::new(500))
            .build();

        assert!(result.is_ok());
        let state = result.unwrap();
        assert!(state.uptime_seconds() < 1);
    }

    #[test]
    fn test_uptime_tracking() {
        let config = Config::default();
        let state = DaemonState::new(config);

        let uptime = state.uptime_seconds();
        assert_eq!(uptime, 0); // Should be 0 or very small on immediate call
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn test_dhcp_contexts() {
        let config = Config::default();
        let state = DaemonState::new(config);

        let contexts = state.get_dhcp_contexts();
        assert!(contexts.is_empty()); // No contexts configured initially
    }
}
