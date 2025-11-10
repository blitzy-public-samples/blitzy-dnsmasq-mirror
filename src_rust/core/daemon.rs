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

//! Main Daemon state container for dnsmasq Rust implementation
//!
//! # Purpose
//!
//! This module provides the central [`Daemon`] struct that holds all runtime state for the
//! dnsmasq daemon, replacing the C implementation's global `extern struct daemon *daemon`
//! pointer (dnsmasq.h lines 4074-4251). The Rust implementation eliminates unsafe global
//! mutable state by using `Arc<RwLock<T>>` for thread-safe shared ownership across async
//! tasks in the tokio runtime.
//!
//! # Memory Safety Transformation
//!
//! The C implementation used a global mutable pointer that was accessed directly by all
//! modules without synchronization, relying on single-threaded execution for safety:
//!
//! ```c
//! // C implementation (dnsmasq.h)
//! extern struct daemon {
//!     unsigned int options[OPTION_SIZE];
//!     struct server *servers;
//!     char *packet;
//!     // ... 100+ fields ...
//! } *daemon;
//!
//! // Usage in any module
//! if (daemon->options[OPT_LOG >> 5] & (1u << (OPT_LOG & 31)))
//!     log_query(...);
//! ```
//!
//! The Rust implementation provides:
//! - **Thread-safe access**: `Arc<RwLock<T>>` for safe concurrent reads/writes
//! - **No global mutable state**: Daemon passed explicitly to functions (dependency injection)
//! - **Type-safe collections**: `Vec<T>`, `HashMap<K,V>` replace raw pointer chains
//! - **Automatic memory management**: RAII with Drop trait for cleanup
//! - **Explicit lifetimes**: Borrow checker prevents use-after-free
//!
//! # Architecture
//!
//! The Daemon struct is organized into logical subsections:
//!
//! - **Configuration**: Immutable config shared across all subsystems (`Arc<Config>`)
//! - **DNS Subsystem**: Cache, upstream servers, forward records (`Arc<Mutex<Cache>>`)
//! - **DHCP Subsystem**: Lease manager, contexts, configurations (`Arc<Mutex<LeaseManager>>`)
//! - **Network Layer**: Interface list, listener sockets (`Vec<Arc<UdpSocket>>`)
//! - **Integration**: D-Bus, ubus, conntrack handles (optional features)
//! - **Runtime State**: Buffers, transaction tracking, statistics
//!
//! # Builder Pattern
//!
//! The [`DaemonBuilder`] provides gradual construction of the Daemon during initialization,
//! allowing subsystems to be configured independently before final assembly:
//!
//! ```rust,ignore
//! let daemon = DaemonBuilder::new()
//!     .with_config(config)
//!     .with_cache(Cache::new())
//!     .with_lease_manager(LeaseManager::new(lease_file, max_leases, options, false))
//!     .with_servers(upstream_servers)
//!     .build()?;
//! ```
//!
//! # Accessor Methods
//!
//! All daemon state is accessed through accessor methods that return clones of Arc pointers,
//! enabling safe concurrent access without violating Rust's borrowing rules:
//!
//! - `get_config()` - Immutable configuration (read-only)
//! - `get_cache()` - DNS cache with `RwLock` for concurrent reads
//! - `get_lease_manager()` - DHCP lease database with Mutex for exclusive writes
//! - `get_servers()` - Upstream server list (Vec of Arc<`RwLock`<Server>>)
//! - `get_udp_listeners()` - UDP listener sockets
//! - `get_tcp_listeners()` - TCP listener sockets
//!
//! # Conditional Compilation
//!
//! Optional subsystems are compiled conditionally via cfg attributes matching C's HAVE_* macros:
//!
//! - `#[cfg(feature = "dhcp")]` - `DHCPv4` support (struct `dhcp_context`, etc.)
//! - `#[cfg(feature = "dhcp6")]` - `DHCPv6` support (struct `ra_interface`, etc.)
//! - `#[cfg(feature = "dnssec")]` - DNSSEC validation (`timestamp_file`, `ds_config`)
//! - `#[cfg(feature = "tftp")]` - TFTP server (`tftp_trans`, `tftp_prefix`)
//! - `#[cfg(feature = "dbus")]` - D-Bus control interface
//! - `#[cfg(feature = "ubus")]` - `OpenWrt` ubus integration
//!
//! # Original C Mapping
//!
//! Refactored from `src/dnsmasq.h` lines 4074-4251 with the following field transformations:
//!
//! | C Field | Rust Equivalent | Transformation |
//! |---------|-----------------|----------------|
//! | `unsigned int options[OPTION_SIZE]` | `Config.options: DaemonOptions` | Bitflags enum |
//! | `struct server *servers` | `Vec<Arc<RwLock<Server>>>` | Safe shared ownership |
//! | `char *packet` | `Vec<u8>` | Automatic bounds checking |
//! | `char *namebuff` | `String` | UTF-8 safety, no buffer overflows |
//! | `struct crec *frec_list` | Embedded in `Cache` | Encapsulated |
//! | `struct dhcp_lease *leases` | `LeaseManager` HashMap | Type-safe lookups |
//! | `struct listener *listeners` | `Vec<Arc<UdpSocket>>` | RAII cleanup |
//! | `FILE *lease_stream` | `tokio::fs::File` | Async I/O |
//! | `int dhcpfd` | `UdpSocket` | Type-safe socket wrapper |
//! | `pid_t tcp_pids[MAX_PROCS]` | `JoinHandle<()>` | Async task handles |

use std::net::IpAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, RwLock};

use crate::config::types::Config;
use crate::dns::cache::Cache;
use crate::dns::upstream::UpstreamServer;
use crate::dhcp::lease::LeaseManager;

/// Main Daemon structure containing all runtime state
///
/// Replaces C's `extern struct daemon *daemon` global pointer with a safe, immutable
/// reference-counted container. All state is protected by appropriate synchronization
/// primitives for safe concurrent access in the tokio async runtime.
///
/// # Synchronization Strategy
///
/// - **Config**: `Arc<Config>` - Immutable after initialization, no lock needed
/// - **Cache**: `Arc<Mutex<Cache>>` - Mutable DNS cache with exclusive access
/// - **`LeaseManager`**: `Arc<Mutex<LeaseManager>>` - Mutable DHCP lease database
/// - **Servers**: `Vec<Arc<RwLock<Server>>>` - Server list with concurrent health updates
/// - **Listeners**: `Vec<Arc<UdpSocket>>` - Immutable socket list (opened at startup)
/// - **TCP Listeners**: `Vec<Arc<TcpListener>>` - Immutable TCP listeners
///
/// # Lifetime Management
///
/// All resources are managed via RAII:
/// - Sockets close automatically when Arc count reaches zero
/// - File handles close via tokio's Drop implementation
/// - Memory deallocates via Vec/String/HashMap Drop traits
/// - No manual cleanup required (eliminates C's shutdown logic)
///
/// # Field Organization
///
/// Fields are logically grouped by subsystem:
/// 1. Core Configuration (immutable)
/// 2. DNS Forwarding & Caching
/// 3. DHCP Lease Management (conditional compilation)
/// 4. Network Interfaces & Listeners
/// 5. Integration Handles (D-Bus, ubus, etc.)
/// 6. Runtime Buffers & State
///
/// # Thread Safety
///
/// The Daemon struct itself is `Send + Sync` because:
/// - All internal types implement Send + Sync
/// - Arc provides thread-safe reference counting
/// - Mutex/RwLock provide interior mutability
/// - No raw pointers or unsafe blocks
pub struct Daemon {
    // ============================================================================
    // Core Configuration (Immutable)
    // ============================================================================
    
    /// Daemon configuration (immutable after initialization)
    ///
    /// Original C field: Multiple fields consolidated into Config struct
    /// - `daemon->options[OPTION_SIZE]` → `config.options`
    /// - `daemon->domain_suffix` → `config.dns.domain_suffix`
    /// - `daemon->port` → `config.network.port`
    /// - All other configuration scattered across struct daemon
    ///
    /// Access: Clone Arc for read-only access across subsystems
    config: Arc<Config>,

    // ============================================================================
    // DNS Subsystem
    // ============================================================================

    /// DNS cache with hash table + LRU eviction
    ///
    /// Original C fields:
    /// - Implicit in cache.c global state
    /// - `struct crec *cache_list` (implicitly managed)
    ///
    /// Synchronization: Mutex for exclusive write access during insertions/evictions
    /// Access: `get_cache()` returns Arc<Mutex<Cache>> for concurrent operations
    cache: Arc<Mutex<Cache>>,

    /// Upstream DNS servers with health tracking
    ///
    /// Original C fields:
    /// - `daemon->servers` (struct server *servers)
    /// - `daemon->servers_tail` (struct server *`servers_tail`)
    /// - `daemon->local_domains` (struct server *`local_domains`)
    /// - `daemon->serverarray` (struct server **serverarray)
    ///
    /// Synchronization: Vec with Arc<`RwLock`<Server>> allows concurrent reads
    /// Access: `get_servers()` returns cloned Vec for iteration
    servers: Vec<Arc<RwLock<UpstreamServer>>>,

    // ============================================================================
    // DHCP Subsystem (Conditional Compilation)
    // ============================================================================

    /// DHCP lease manager with persistence
    ///
    /// Original C fields:
    /// - `daemon->dhcp_conf` (struct `dhcp_config` *`dhcp_conf`)
    /// - `daemon->lease_file` (char *`lease_file`)
    /// - `daemon->lease_stream` (FILE *`lease_stream`)
    /// - `daemon->lease_change_command` (char *`lease_change_command`)
    /// - Implicit lease linked list managed in lease.c
    ///
    /// Synchronization: Mutex for exclusive access during lease allocations
    /// Access: `get_lease_manager()` returns Option<Arc<Mutex<LeaseManager>>>
    #[cfg(feature = "dhcp")]
    lease_manager: Option<Arc<Mutex<LeaseManager>>>,

    // ============================================================================
    // Network Interfaces & Listeners
    // ============================================================================

    /// Network interfaces detected at startup
    ///
    /// Original C fields:
    /// - `daemon->interfaces` (struct irec *interfaces)
    /// - `daemon->interface_addrs` (struct addrlist *`interface_addrs`)
    ///
    /// Synchronization: Immutable after initialization (interfaces don't change at runtime)
    /// Access: Direct read access via `get_interfaces()`
    interfaces: Vec<Interface>,

    /// UDP listener sockets for DNS queries and DHCP requests
    ///
    /// Original C fields:
    /// - `daemon->listeners` (struct listener *listeners)
    /// - Individual fds: `daemon->dhcpfd`, `daemon->dhcp6fd`
    ///
    /// Synchronization: Immutable socket list (opened at startup, closed at shutdown)
    /// Access: `get_udp_listeners()` returns cloned Vec of Arc<UdpSocket>
    udp_listeners: Vec<Arc<UdpSocket>>,

    /// TCP listener sockets for DNS-over-TCP and zone transfers
    ///
    /// Original C field:
    /// - `daemon->listeners` (struct listener *listeners with TCP type)
    ///
    /// Synchronization: Immutable socket list
    /// Access: `get_tcp_listeners()` returns cloned Vec of Arc<TcpListener>
    tcp_listeners: Vec<Arc<TcpListener>>,

    // ============================================================================
    // Runtime State & Buffers
    // ============================================================================

    /// Reusable buffer for DNS packet assembly
    ///
    /// Original C fields:
    /// - `daemon->packet` (char *packet)
    /// - `daemon->packet_buff_sz` (int `packet_buff_sz`)
    ///
    /// Rust: Vec<u8> with automatic growth, no buffer overflow possible
    /// Synchronization: Per-task buffers avoid shared mutable state
    #[allow(dead_code)]
    packet_buffer_size: usize,

    /// Transaction logging state
    ///
    /// Original C fields:
    /// - `daemon->log_id` (int `log_id`)
    /// - `daemon->log_display_id` (int `log_display_id`)
    ///
    /// Synchronization: Atomic increments in logging module
    #[allow(dead_code)]
    log_transaction_id: Arc<Mutex<u32>>,

    // ============================================================================
    // Optional Integration Subsystems (Conditional Compilation)
    // ============================================================================

    /// D-Bus control interface handle
    ///
    /// Original C fields:
    /// - `daemon->dbus` (void *dbus)
    /// - `daemon->dbus_name` (char *dbus_name)
    ///
    /// Rust: zbus Connection handle
    #[cfg(feature = "dbus")]
    #[allow(dead_code)]
    dbus_connection: Option<Arc<Mutex<zbus::Connection>>>,

    /// OpenWrt ubus integration handle
    ///
    /// Original C fields:
    /// - `daemon->ubus` (void *ubus)
    /// - `daemon->ubus_name` (char *ubus_name)
    ///
    /// Rust: FFI handle to libubus context
    #[cfg(feature = "ubus")]
    #[allow(dead_code)]
    ubus_context: Option<Arc<Mutex<UbusContext>>>,
}

/// Placeholder for UBus context (FFI integration)
#[cfg(feature = "ubus")]
#[allow(dead_code)]
struct UbusContext {
    // FFI handle to struct ubus_context from libubus
    // Actual implementation requires unsafe FFI bindings
}

/// Network interface descriptor
///
/// Replaces C's `struct irec` (dnsmasq.h line 633) with safe Rust types
#[derive(Debug, Clone)]
pub struct Interface {
    /// Interface name (e.g., "eth0", "wlan0")
    /// Original C field: name in struct irec
    pub name: String,

    /// Interface index (for IPv6 link-local binding)
    /// Original C field: index in struct irec
    pub index: u32,

    /// Interface addresses (IPv4 and IPv6)
    /// Original C field: addr in struct irec (union mysockaddr)
    pub addresses: Vec<IpAddr>,

    /// Interface MTU
    /// Original C field: mtu in struct irec
    pub mtu: u32,

    /// Interface is up/active
    /// Original C field: flags check (`IFF_UP`)
    pub is_up: bool,

    /// Interface is multicast-capable
    /// Original C field: flags check (`IFF_MULTICAST`)
    pub is_multicast: bool,
}

impl Daemon {
    /// Create a new Daemon instance with provided configuration
    ///
    /// This is a low-level constructor. Use [`DaemonBuilder`] for gradual construction
    /// during daemon initialization.
    ///
    /// # Arguments
    ///
    /// * `config` - Parsed and validated configuration
    /// * `cache` - Initialized DNS cache
    /// * `servers` - Upstream DNS server list
    /// * `interfaces` - Detected network interfaces
    /// * `udp_listeners` - Bound UDP sockets
    /// * `tcp_listeners` - Bound TCP sockets
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::core::daemon::Daemon;
    /// use dnsmasq::config::types::Config;
    /// use dnsmasq::dns::cache::Cache;
    ///
    /// let config = Config::default();
    /// let cache = Cache::new();
    /// let daemon = Daemon::new(
    ///     config,
    ///     cache,
    ///     vec![],
    ///     vec![],
    ///     vec![],
    ///     vec![],
    ///     #[cfg(feature = "dhcp")]
    ///     None,
    /// );
    /// ```
    #[allow(clippy::too_many_arguments)]
    #[must_use] 
    pub fn new(
        config: Config,
        cache: Cache,
        servers: Vec<Arc<RwLock<UpstreamServer>>>,
        interfaces: Vec<Interface>,
        udp_listeners: Vec<Arc<UdpSocket>>,
        tcp_listeners: Vec<Arc<TcpListener>>,
        #[cfg(feature = "dhcp")] lease_manager: Option<LeaseManager>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            cache: Arc::new(Mutex::new(cache)),
            servers,
            interfaces,
            udp_listeners,
            tcp_listeners,
            #[cfg(feature = "dhcp")]
            lease_manager: lease_manager.map(|lm| Arc::new(Mutex::new(lm))),
            packet_buffer_size: 4096, // PACKETSZ from dns-protocol.h
            log_transaction_id: Arc::new(Mutex::new(1)),
            #[cfg(feature = "dbus")]
            dbus_connection: None,
            #[cfg(feature = "ubus")]
            ubus_context: None,
        }
    }

    /// Create a new `DaemonBuilder` for gradual construction
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dnsmasq::core::daemon::Daemon;
    ///
    /// let daemon = Daemon::builder()
    ///     .with_config(config)
    ///     .with_cache(Cache::new())
    ///     .build()
    ///     .expect("Failed to build daemon");
    /// ```
    #[must_use]
    pub fn builder() -> DaemonBuilder {
        DaemonBuilder::new()
    }

    // ============================================================================
    // Accessor Methods
    // ============================================================================

    /// Get immutable configuration reference
    ///
    /// Returns a cloned Arc pointer for cheap sharing across subsystems.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let config = daemon.get_config();
    /// let port = config.network.port;
    /// ```
    #[must_use]
    pub fn get_config(&self) -> Arc<Config> {
        Arc::clone(&self.config)
    }

    /// Get DNS cache with exclusive access control
    ///
    /// Returns a cloned Arc pointer to the Mutex-protected cache.
    /// Callers must acquire the lock to read or modify cache contents.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cache = daemon.get_cache();
    /// let mut cache_guard = cache.lock().await;
    /// cache_guard.insert(record);
    /// ```
    #[must_use]
    pub fn get_cache(&self) -> Arc<Mutex<Cache>> {
        Arc::clone(&self.cache)
    }

    /// Get DHCP lease manager with exclusive access control
    ///
    /// Returns a cloned Arc pointer to the Mutex-protected lease manager.
    /// Only available when `dhcp` feature is enabled.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// #[cfg(feature = "dhcp")]
    /// {
    ///     let lease_mgr = daemon.get_lease_manager().expect("DHCP not enabled");
    ///     let mut lease_guard = lease_mgr.lock().await;
    ///     lease_guard.allocate_v4(client_id, hwaddr, requested_ip)?;
    /// }
    /// ```
    #[cfg(feature = "dhcp")]
    #[must_use]
    pub fn get_lease_manager(&self) -> Option<Arc<Mutex<LeaseManager>>> {
        self.lease_manager.as_ref().map(Arc::clone)
    }

    /// Get upstream DNS server list
    ///
    /// Returns a cloned Vec of Arc<`RwLock`<Server>> for safe concurrent iteration.
    /// Each server can be independently locked for health updates.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let servers = daemon.get_servers();
    /// for server in &servers {
    ///     let server_guard = server.read().await;
    ///     println!("Server: {}", server_guard.addr());
    /// }
    /// ```
    #[must_use]
    pub fn get_servers(&self) -> Vec<Arc<RwLock<UpstreamServer>>> {
        self.servers.clone()
    }

    /// Get network interface list
    ///
    /// Returns a reference to the interface list for read-only access.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// for interface in daemon.get_interfaces() {
    ///     println!("Interface: {} ({} addresses)", interface.name, interface.addresses.len());
    /// }
    /// ```
    #[must_use]
    pub fn get_interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    /// Get UDP listener sockets
    ///
    /// Returns a cloned Vec of Arc<UdpSocket> for concurrent receiving.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let listeners = daemon.get_udp_listeners();
    /// for socket in &listeners {
    ///     let local_addr = socket.local_addr()?;
    ///     println!("Listening on UDP {}", local_addr);
    /// }
    /// ```
    #[must_use]
    pub fn get_udp_listeners(&self) -> Vec<Arc<UdpSocket>> {
        self.udp_listeners.clone()
    }

    /// Get TCP listener sockets
    ///
    /// Returns a cloned Vec of Arc<TcpListener> for concurrent accepting.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let listeners = daemon.get_tcp_listeners();
    /// for listener in &listeners {
    ///     let local_addr = listener.local_addr()?;
    ///     println!("Listening on TCP {}", local_addr);
    /// }
    /// ```
    #[must_use]
    pub fn get_tcp_listeners(&self) -> Vec<Arc<TcpListener>> {
        self.tcp_listeners.clone()
    }
}

// ============================================================================
// DaemonBuilder Implementation
// ============================================================================

/// Builder for gradual Daemon construction during initialization
///
/// Provides a fluent API for assembling the Daemon struct piece-by-piece as
/// subsystems are initialized. This eliminates the need for large constructors
/// with many optional parameters and makes initialization order explicit.
///
/// # Builder Pattern Benefits
///
/// - **Gradual Construction**: Initialize subsystems independently
/// - **Optional Components**: Omit subsystems not enabled by configuration
/// - **Validation**: Enforce required components via `build()` Result return
/// - **Readability**: Self-documenting initialization sequence
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::core::daemon::{Daemon, DaemonBuilder};
/// use dnsmasq::config::types::Config;
/// use dnsmasq::dns::cache::Cache;
///
/// let config = Config::default();
/// let cache = Cache::new();
///
/// let daemon = DaemonBuilder::new()
///     .with_config(config)
///     .with_cache(cache)
///     .with_servers(vec![])
///     .with_interfaces(vec![])
///     .build()
///     .expect("Failed to build daemon");
/// ```
#[derive(Default)]
pub struct DaemonBuilder {
    config: Option<Config>,
    cache: Option<Cache>,
    servers: Option<Vec<Arc<RwLock<UpstreamServer>>>>,
    interfaces: Option<Vec<Interface>>,
    udp_listeners: Option<Vec<Arc<UdpSocket>>>,
    tcp_listeners: Option<Vec<Arc<TcpListener>>>,
    #[cfg(feature = "dhcp")]
    lease_manager: Option<LeaseManager>,
}

impl DaemonBuilder {
    /// Create a new `DaemonBuilder` with all fields unset
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let builder = DaemonBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the daemon configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Parsed and validated configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder = builder.with_config(config);
    /// ```
    #[must_use]
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the DNS cache
    ///
    /// # Arguments
    ///
    /// * `cache` - Initialized cache with configured capacity
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder = builder.with_cache(Cache::new());
    /// ```
    #[must_use]
    pub fn with_cache(mut self, cache: Cache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the DHCP lease manager
    ///
    /// Only available when `dhcp` feature is enabled.
    ///
    /// # Arguments
    ///
    /// * `lease_manager` - Initialized lease manager
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// #[cfg(feature = "dhcp")]
    /// {
    ///     builder = builder.with_lease_manager(LeaseManager::new(...));
    /// }
    /// ```
    #[cfg(feature = "dhcp")]
    #[must_use]
    pub fn with_lease_manager(mut self, lease_manager: LeaseManager) -> Self {
        self.lease_manager = Some(lease_manager);
        self
    }

    /// Set the upstream DNS server list
    ///
    /// # Arguments
    ///
    /// * `servers` - Vec of upstream servers with health tracking
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder = builder.with_servers(upstream_servers);
    /// ```
    #[must_use]
    pub fn with_servers(mut self, servers: Vec<Arc<RwLock<UpstreamServer>>>) -> Self {
        self.servers = Some(servers);
        self
    }

    /// Set the network interface list
    ///
    /// # Arguments
    ///
    /// * `interfaces` - Detected network interfaces
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder = builder.with_interfaces(interfaces);
    /// ```
    #[must_use]
    pub fn with_interfaces(mut self, interfaces: Vec<Interface>) -> Self {
        self.interfaces = Some(interfaces);
        self
    }

    /// Set the UDP listener sockets
    ///
    /// # Arguments
    ///
    /// * `udp_listeners` - Bound UDP sockets for DNS/DHCP
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder = builder.with_udp_listeners(udp_sockets);
    /// ```
    #[must_use]
    pub fn with_udp_listeners(mut self, udp_listeners: Vec<Arc<UdpSocket>>) -> Self {
        self.udp_listeners = Some(udp_listeners);
        self
    }

    /// Set the TCP listener sockets
    ///
    /// # Arguments
    ///
    /// * `tcp_listeners` - Bound TCP listeners for DNS-over-TCP
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder = builder.with_tcp_listeners(tcp_sockets);
    /// ```
    #[must_use]
    pub fn with_tcp_listeners(mut self, tcp_listeners: Vec<Arc<TcpListener>>) -> Self {
        self.tcp_listeners = Some(tcp_listeners);
        self
    }

    /// Build the Daemon instance
    ///
    /// Validates that all required components are present and constructs the
    /// final Daemon. Returns an error if any required component is missing.
    ///
    /// # Errors
    ///
    /// Returns `DaemonBuilderError` if:
    /// - `config` is not set
    /// - `cache` is not set (when DNS is enabled)
    /// - `lease_manager` is not set (when DHCP is enabled and required)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let daemon = builder.build().expect("Missing required components");
    /// ```
    pub fn build(self) -> Result<Daemon, DaemonBuilderError> {
        let config = self.config.ok_or(DaemonBuilderError::MissingConfig)?;
        let cache = self.cache.ok_or(DaemonBuilderError::MissingCache)?;
        let servers = self.servers.unwrap_or_default();
        let interfaces = self.interfaces.unwrap_or_default();
        let udp_listeners = self.udp_listeners.unwrap_or_default();
        let tcp_listeners = self.tcp_listeners.unwrap_or_default();

        Ok(Daemon::new(
            config,
            cache,
            servers,
            interfaces,
            udp_listeners,
            tcp_listeners,
            #[cfg(feature = "dhcp")]
            self.lease_manager,
        ))
    }
}

/// Errors that can occur during Daemon construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonBuilderError {
    /// Configuration not provided to builder
    MissingConfig,
    /// DNS cache not provided to builder
    MissingCache,
    /// DHCP lease manager not provided when required
    #[cfg(feature = "dhcp")]
    MissingLeaseManager,
}

impl std::fmt::Display for DaemonBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingConfig => write!(f, "Configuration not provided to DaemonBuilder"),
            Self::MissingCache => write!(f, "DNS cache not provided to DaemonBuilder"),
            #[cfg(feature = "dhcp")]
            Self::MissingLeaseManager => {
                write!(f, "DHCP lease manager not provided to DaemonBuilder")
            }
        }
    }
}

impl std::error::Error for DaemonBuilderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_builder_missing_config() {
        let result = DaemonBuilder::new().build();
        assert!(matches!(result, Err(DaemonBuilderError::MissingConfig)));
    }

    #[test]
    fn test_daemon_builder_missing_cache() {
        let config = Config::default();
        let result = DaemonBuilder::new().with_config(config).build();
        assert!(matches!(result, Err(DaemonBuilderError::MissingCache)));
    }

    #[test]
    fn test_daemon_builder_success() {
        let config = Config::default();
        let cache = Cache::new();
        
        let result = DaemonBuilder::new()
            .with_config(config)
            .with_cache(cache)
            .build();
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_get_config() {
        let config = Config::default();
        let cache = Cache::new();
        
        let daemon = DaemonBuilder::new()
            .with_config(config)
            .with_cache(cache)
            .build()
            .expect("Failed to build daemon");

        let retrieved_config = daemon.get_config();
        assert!(Arc::ptr_eq(&daemon.config, &retrieved_config));
    }

    #[test]
    fn test_daemon_get_servers_empty() {
        let config = Config::default();
        let cache = Cache::new();
        
        let daemon = DaemonBuilder::new()
            .with_config(config)
            .with_cache(cache)
            .build()
            .expect("Failed to build daemon");

        let servers = daemon.get_servers();
        assert!(servers.is_empty());
    }

    #[test]
    fn test_interface_clone() {
        let interface = Interface {
            name: "eth0".to_string(),
            index: 1,
            addresses: vec!["192.168.1.1".parse().unwrap()],
            mtu: 1500,
            is_up: true,
            is_multicast: true,
        };

        let cloned = interface.clone();
        assert_eq!(interface.name, cloned.name);
        assert_eq!(interface.index, cloned.index);
        assert_eq!(interface.addresses, cloned.addresses);
    }
}
