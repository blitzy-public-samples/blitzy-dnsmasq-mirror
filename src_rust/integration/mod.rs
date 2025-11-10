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

//! External System Integrations
//!
//! This module provides safe Rust interfaces to external system services and control mechanisms.
//! It replaces the C implementation's platform-specific integrations (dbus.c, ubus.c, conntrack.c,
//! ipset.c, nftset.c, tables.c, inotify.c) with memory-safe abstractions that maintain functional
//! equivalence while eliminating manual pointer manipulation and FFI safety issues.
//!
//! # Architecture Overview
//!
//! The integration module is organized into platform-specific and feature-gated sub-modules:
//!
//! - **`dbus`**: D-Bus IPC control interface for systemd/desktop integration (Linux)
//! - **`ubus`**: OpenWrt micro-bus IPC for embedded router management (Linux/OpenWrt)
//! - **`conntrack`**: Linux connection tracking integration for advanced firewall rules
//! - **`ipset`**: Linux ipset firewall integration for efficient IP set management
//! - **`nftset`**: nftables set integration for modern Linux packet filtering
//! - **`pf_tables`**: BSD Packet Filter table integration for FreeBSD/OpenBSD/NetBSD
//! - **`inotify`**: Linux inotify file watching for configuration reload
//!
//! # Conditional Compilation
//!
//! All integrations are optional and controlled by Cargo feature flags matching the C
//! implementation's HAVE_* macros:
//!
//! | Feature Flag | C Macro | Platform | Purpose |
//! |--------------|---------|----------|---------|
//! | `dbus` | `HAVE_DBUS` | Linux | D-Bus control interface |
//! | `ubus` | `HAVE_UBUS` | Linux/OpenWrt | ubus control interface |
//! | `conntrack` | `HAVE_CONNTRACK` | Linux | Connection tracking |
//! | `ipset` | `HAVE_IPSET` | Linux | ipset firewall integration |
//! | `nftset` | `HAVE_NFTSET` | Linux | nftables integration |
//! | `ipset` + BSD | `HAVE_IPSET` on BSD | BSD | PF table integration |
//! | `inotify` | `HAVE_INOTIFY` | Linux | File watching |
//!
//! # Memory Safety
//!
//! This module wraps all FFI boundaries with safe Rust abstractions:
//!
//! - **No Raw Pointers Exposed**: All FFI calls are encapsulated in private functions
//! - **RAII Resource Management**: File descriptors and handles use Drop trait for cleanup
//! - **Type Safety**: Foreign types are wrapped in newtype patterns
//! - **Error Propagation**: All errors are converted to `crate::Result<T>`
//!
//! # Integration Manager
//!
//! The [`IntegrationManager`] struct provides a unified interface for managing all optional
//! integrations. It uses the builder pattern for construction and provides methods to check
//! availability and access individual integration handles.
//!
//! # Examples
//!
//! ```ignore
//! use dnsmasq::integration::{IntegrationManager, IntegrationManagerBuilder};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Build integration manager with desired integrations
//! let manager = IntegrationManagerBuilder::new()
//!     .with_dbus(true)      // Enable D-Bus if feature is enabled
//!     .with_inotify(true)   // Enable inotify if feature is enabled
//!     .build()?;
//!
//! // Check which integrations are available
//! if manager.has_dbus() {
//!     if let Some(dbus_interface) = manager.dbus() {
//!         // Use D-Bus interface...
//!     }
//! }
//!
//! if manager.has_inotify() {
//!     if let Some(watcher) = manager.inotify() {
//!         // Watch configuration files...
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use crate::Result;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

//
// ============================================================================
// MODULE DECLARATIONS (Conditional Compilation)
// ============================================================================
//

/// D-Bus control interface for systemd and desktop integration
///
/// Provides methods for external control of dnsmasq via D-Bus IPC. This replaces
/// the C implementation in dbus.c and uses the zbus crate for safe async D-Bus
/// communication.
///
/// **Enabled by**: `dbus` feature flag
/// **Platforms**: Linux (primarily), BSD (if D-Bus available)
/// **C Equivalent**: `HAVE_DBUS` macro, dbus.c
#[cfg(feature = "dbus")]
pub mod dbus;

/// OpenWrt ubus control interface for embedded router management
///
/// Provides methods for external control via OpenWrt's micro-bus IPC system.
/// This replaces the C implementation in ubus.c and uses FFI to libubus.
///
/// **Enabled by**: `ubus` feature flag
/// **Platforms**: Linux (OpenWrt specifically)
/// **C Equivalent**: `HAVE_UBUS` macro, ubus.c
#[cfg(feature = "ubus")]
pub mod ubus;

/// Linux connection tracking integration
///
/// Integrates with Linux netfilter conntrack for advanced firewall rule coordination.
/// This replaces the C implementation in conntrack.c and uses FFI to libnetfilter_conntrack.
///
/// **Enabled by**: `conntrack` feature flag + Linux platform
/// **Platforms**: Linux only
/// **C Equivalent**: `HAVE_CONNTRACK` macro, conntrack.c
#[cfg(all(feature = "conntrack", target_os = "linux"))]
pub mod conntrack;

/// Linux ipset firewall integration
///
/// Provides efficient IP address set management for firewall rules via Linux ipset.
/// This replaces the C implementation in ipset.c and uses netlink for communication.
///
/// **Enabled by**: `ipset` feature flag + Linux platform
/// **Platforms**: Linux only
/// **C Equivalent**: `HAVE_IPSET` macro, ipset.c
#[cfg(all(feature = "ipset", target_os = "linux"))]
pub mod ipset;

/// nftables set integration
///
/// Integrates with modern Linux nftables for packet filtering and set management.
/// This replaces the C implementation in nftset.c and uses FFI to libnftables.
///
/// **Enabled by**: `nftset` feature flag + Linux platform
/// **Platforms**: Linux only (kernel 3.13+)
/// **C Equivalent**: `HAVE_NFTSET` macro, nftset.c
#[cfg(all(feature = "nftset", target_os = "linux"))]
pub mod nftset;

/// BSD Packet Filter table integration
///
/// Integrates with BSD's PF (Packet Filter) for firewall table management on FreeBSD,
/// OpenBSD, and NetBSD. This replaces the C implementation in tables.c and uses ioctl
/// for PF communication.
///
/// **Enabled by**: `ipset` feature flag + BSD platform (reuses ipset flag for BSD PF)
/// **Platforms**: FreeBSD, OpenBSD, NetBSD
/// **C Equivalent**: `HAVE_IPSET` macro on BSD, tables.c
#[cfg(all(
    feature = "ipset",
    any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )
))]
pub mod pf_tables;

/// Linux inotify file watching
///
/// Monitors configuration files for changes using Linux inotify, enabling automatic
/// configuration reload. This replaces the C implementation in inotify.c and uses
/// the nix crate for safe inotify access.
///
/// **Enabled by**: `inotify` feature flag + Linux platform
/// **Platforms**: Linux only
/// **C Equivalent**: `HAVE_INOTIFY` macro, inotify.c
#[cfg(all(feature = "inotify", target_os = "linux"))]
pub mod inotify;

//
// ============================================================================
// RE-EXPORTS FOR ERGONOMIC ACCESS
// ============================================================================
//

// Re-export commonly used types from each integration module for convenience

#[cfg(feature = "dbus")]
pub use dbus::{DbusInterface, DbusError};

#[cfg(feature = "ubus")]
pub use ubus::{UbusManager, UbusError};

#[cfg(all(feature = "conntrack", target_os = "linux"))]
pub use conntrack::{ConntrackManager, ConntrackError};

#[cfg(all(feature = "ipset", target_os = "linux"))]
pub use ipset::{IpsetManager, IpsetError};

#[cfg(all(feature = "nftset", target_os = "linux"))]
pub use nftset::{NftsetManager, NftsetError};

#[cfg(all(
    feature = "ipset",
    any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )
))]
pub use pf_tables::{PfTableManager, PfError};

#[cfg(all(feature = "inotify", target_os = "linux"))]
pub use inotify::{InotifyWatcher, InotifyError};

//
// ============================================================================
// INTEGRATION MANAGER
// ============================================================================
//

/// Central manager for all optional system integrations
///
/// `IntegrationManager` provides a unified interface for managing and accessing all optional
/// external integrations. It aggregates handles to D-Bus, ubus, conntrack, ipset, nftables,
/// PF tables, and inotify, with each integration being optional based on compile-time feature
/// flags and runtime configuration.
///
/// # Design Pattern
///
/// Uses the builder pattern via [`IntegrationManagerBuilder`] for flexible construction.
/// Only integrations that are both:
/// 1. Enabled at compile time (via feature flags)
/// 2. Successfully initialized at runtime (via builder)
///
/// will be present in the manager.
///
/// # Thread Safety
///
/// `IntegrationManager` is designed to be shared across async tasks. Individual integration
/// handles may use interior mutability (Arc<Mutex<T>>) as needed.
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::integration::IntegrationManagerBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = IntegrationManagerBuilder::new()
///     .with_dbus(true)
///     .with_inotify(true)
///     .build()?;
///
/// // Check and use integrations
/// if manager.has_dbus() {
///     println!("D-Bus control interface is active");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct IntegrationManager {
    /// D-Bus control interface handle (if feature enabled and initialized)
    #[cfg(feature = "dbus")]
    dbus_interface: Option<DbusInterface>,

    /// `OpenWrt` ubus control interface handle (if feature enabled and initialized)
    #[cfg(feature = "ubus")]
    ubus_manager: Option<UbusManager>,

    /// Linux conntrack integration handle (if feature enabled and initialized)
    #[cfg(all(feature = "conntrack", target_os = "linux"))]
    conntrack_manager: Option<ConntrackManager>,

    /// Linux ipset integration handle (if feature enabled and initialized)
    #[cfg(all(feature = "ipset", target_os = "linux"))]
    ipset_manager: Option<IpsetManager>,

    /// nftables integration handle (if feature enabled and initialized)
    #[cfg(all(feature = "nftset", target_os = "linux"))]
    nftset_manager: Option<NftsetManager>,

    /// BSD PF table integration handle (if feature enabled and initialized)
    #[cfg(all(
        feature = "ipset",
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )
    ))]
    pf_table_manager: Option<PfTableManager>,

    /// Linux inotify file watcher handle (if feature enabled and initialized)
    #[cfg(all(feature = "inotify", target_os = "linux"))]
    inotify_watcher: Option<InotifyWatcher>,
}

impl IntegrationManager {
    /// Creates a new empty `IntegrationManager` with no integrations initialized
    ///
    /// This is primarily used internally by the builder. Most users should use
    /// [`IntegrationManagerBuilder`] instead.
    ///
    /// # Returns
    ///
    /// A new `IntegrationManager` with all optional integration handles set to `None`.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a builder for configuring and constructing an `IntegrationManager`
    ///
    /// # Returns
    ///
    /// A new [`IntegrationManagerBuilder`] instance for fluent configuration.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::integration::IntegrationManager;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = IntegrationManager::builder()
    ///     .with_dbus(true)
    ///     .with_inotify(true)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use] 
    pub fn builder() -> IntegrationManagerBuilder {
        IntegrationManagerBuilder::new()
    }

    //
    // Availability Checks
    //

    /// Checks if D-Bus integration is available and initialized
    ///
    /// # Returns
    ///
    /// `true` if the `dbus` feature is enabled and D-Bus was successfully initialized,
    /// `false` otherwise.
    #[cfg(feature = "dbus")]
    #[must_use] 
    pub fn has_dbus(&self) -> bool {
        self.dbus_interface.is_some()
    }

    /// Always returns false when D-Bus feature is disabled
    #[cfg(not(feature = "dbus"))]
    #[must_use] 
    pub fn has_dbus(&self) -> bool {
        false
    }

    /// Checks if ubus integration is available and initialized
    ///
    /// # Returns
    ///
    /// `true` if the `ubus` feature is enabled and ubus was successfully initialized,
    /// `false` otherwise.
    #[cfg(feature = "ubus")]
    #[must_use] 
    pub fn has_ubus(&self) -> bool {
        self.ubus_manager.is_some()
    }

    /// Always returns false when ubus feature is disabled
    #[cfg(not(feature = "ubus"))]
    #[must_use] 
    pub fn has_ubus(&self) -> bool {
        false
    }

    /// Checks if conntrack integration is available and initialized
    ///
    /// # Returns
    ///
    /// `true` if the `conntrack` feature is enabled on Linux and conntrack was
    /// successfully initialized, `false` otherwise.
    #[cfg(all(feature = "conntrack", target_os = "linux"))]
    #[must_use] 
    pub fn has_conntrack(&self) -> bool {
        self.conntrack_manager.is_some()
    }

    /// Always returns false when conntrack feature is disabled or not on Linux
    #[cfg(not(all(feature = "conntrack", target_os = "linux")))]
    #[must_use] 
    pub fn has_conntrack(&self) -> bool {
        false
    }

    /// Checks if ipset integration is available and initialized
    ///
    /// # Returns
    ///
    /// `true` if the `ipset` feature is enabled on Linux and ipset was successfully
    /// initialized, `false` otherwise.
    #[cfg(all(feature = "ipset", target_os = "linux"))]
    #[must_use] 
    pub fn has_ipset(&self) -> bool {
        self.ipset_manager.is_some()
    }

    /// Always returns false when ipset feature is disabled or not on Linux
    #[cfg(not(all(feature = "ipset", target_os = "linux")))]
    #[must_use] 
    pub fn has_ipset(&self) -> bool {
        false
    }

    /// Checks if nftables integration is available and initialized
    ///
    /// # Returns
    ///
    /// `true` if the `nftset` feature is enabled on Linux and nftables was successfully
    /// initialized, `false` otherwise.
    #[cfg(all(feature = "nftset", target_os = "linux"))]
    #[must_use] 
    pub fn has_nftset(&self) -> bool {
        self.nftset_manager.is_some()
    }

    /// Always returns false when nftset feature is disabled or not on Linux
    #[cfg(not(all(feature = "nftset", target_os = "linux")))]
    #[must_use] 
    pub fn has_nftset(&self) -> bool {
        false
    }

    /// Checks if PF table integration is available and initialized
    ///
    /// # Returns
    ///
    /// `true` if the `ipset` feature is enabled on BSD and PF tables were successfully
    /// initialized, `false` otherwise.
    #[cfg(all(
        feature = "ipset",
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )
    ))]
    pub fn has_pf_tables(&self) -> bool {
        self.pf_table_manager.is_some()
    }

    /// Always returns false when ipset feature is disabled or not on BSD
    #[cfg(not(all(
        feature = "ipset",
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )
    )))]
    #[must_use] 
    pub fn has_pf_tables(&self) -> bool {
        false
    }

    /// Checks if inotify integration is available and initialized
    ///
    /// # Returns
    ///
    /// `true` if the `inotify` feature is enabled on Linux and inotify was successfully
    /// initialized, `false` otherwise.
    #[cfg(all(feature = "inotify", target_os = "linux"))]
    #[must_use] 
    pub fn has_inotify(&self) -> bool {
        self.inotify_watcher.is_some()
    }

    /// Always returns false when inotify feature is disabled or not on Linux
    #[cfg(not(all(feature = "inotify", target_os = "linux")))]
    #[must_use] 
    pub fn has_inotify(&self) -> bool {
        false
    }

    //
    // Integration Handle Accessors
    //

    /// Gets a reference to the D-Bus interface handle
    ///
    /// # Returns
    ///
    /// `Some(&DbusInterface)` if D-Bus is available and initialized, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::integration::IntegrationManager;
    /// # let manager = IntegrationManager::new();
    /// if let Some(dbus) = manager.dbus() {
    ///     // Use D-Bus interface
    /// }
    /// ```
    #[cfg(feature = "dbus")]
    #[must_use] 
    pub fn dbus(&self) -> Option<&DbusInterface> {
        self.dbus_interface.as_ref()
    }

    /// Gets a reference to the ubus manager handle
    ///
    /// # Returns
    ///
    /// `Some(&UbusManager)` if ubus is available and initialized, `None` otherwise.
    #[cfg(feature = "ubus")]
    #[must_use] 
    pub fn ubus(&self) -> Option<&UbusManager> {
        self.ubus_manager.as_ref()
    }

    /// Gets a reference to the conntrack manager handle
    ///
    /// # Returns
    ///
    /// `Some(&ConntrackManager)` if conntrack is available and initialized, `None` otherwise.
    #[cfg(all(feature = "conntrack", target_os = "linux"))]
    #[must_use] 
    pub fn conntrack(&self) -> Option<&ConntrackManager> {
        self.conntrack_manager.as_ref()
    }

    /// Gets a reference to the ipset manager handle
    ///
    /// # Returns
    ///
    /// `Some(&IpsetManager)` if ipset is available and initialized, `None` otherwise.
    #[cfg(all(feature = "ipset", target_os = "linux"))]
    #[must_use] 
    pub fn ipset(&self) -> Option<&IpsetManager> {
        self.ipset_manager.as_ref()
    }

    /// Gets a reference to the nftables manager handle
    ///
    /// # Returns
    ///
    /// `Some(&NftsetManager)` if nftables is available and initialized, `None` otherwise.
    #[cfg(all(feature = "nftset", target_os = "linux"))]
    #[must_use] 
    pub fn nftset(&self) -> Option<&NftsetManager> {
        self.nftset_manager.as_ref()
    }

    /// Gets a reference to the PF table manager handle
    ///
    /// # Returns
    ///
    /// `Some(&PfTableManager)` if PF tables are available and initialized, `None` otherwise.
    #[cfg(all(
        feature = "ipset",
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )
    ))]
    pub fn pf_tables(&self) -> Option<&PfTableManager> {
        self.pf_table_manager.as_ref()
    }

    /// Gets a reference to the inotify watcher handle
    ///
    /// # Returns
    ///
    /// `Some(&InotifyWatcher)` if inotify is available and initialized, `None` otherwise.
    #[cfg(all(feature = "inotify", target_os = "linux"))]
    #[must_use] 
    pub fn inotify(&self) -> Option<&InotifyWatcher> {
        self.inotify_watcher.as_ref()
    }
}

impl Debug for IntegrationManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("IntegrationManager");

        #[cfg(feature = "dbus")]
        debug_struct.field("dbus", &self.has_dbus());

        #[cfg(feature = "ubus")]
        debug_struct.field("ubus", &self.has_ubus());

        #[cfg(all(feature = "conntrack", target_os = "linux"))]
        debug_struct.field("conntrack", &self.has_conntrack());

        #[cfg(all(feature = "ipset", target_os = "linux"))]
        debug_struct.field("ipset", &self.has_ipset());

        #[cfg(all(feature = "nftset", target_os = "linux"))]
        debug_struct.field("nftset", &self.has_nftset());

        #[cfg(all(
            feature = "ipset",
            any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )
        ))]
        debug_struct.field("pf_tables", &self.has_pf_tables());

        #[cfg(all(feature = "inotify", target_os = "linux"))]
        debug_struct.field("inotify", &self.has_inotify());

        debug_struct.finish()
    }
}

//
// ============================================================================
// INTEGRATION MANAGER BUILDER
// ============================================================================
//

/// Builder for constructing an [`IntegrationManager`] with optional integrations
///
/// `IntegrationManagerBuilder` provides a fluent interface for configuring which integrations
/// should be enabled at runtime. Each `with_*` method attempts to initialize the corresponding
/// integration if:
/// 1. The integration's feature flag is enabled at compile time
/// 2. The `enable` parameter is `true`
/// 3. The integration can be successfully initialized (e.g., system support is available)
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::integration::IntegrationManagerBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let manager = IntegrationManagerBuilder::new()
///     .with_dbus(true)       // Enable D-Bus if feature is compiled in
///     .with_inotify(true)    // Enable inotify if feature is compiled in
///     .with_conntrack(false) // Explicitly disable conntrack
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Builder pattern naturally uses flags for each feature
pub struct IntegrationManagerBuilder {
    /// Whether to enable D-Bus integration (if feature enabled)
    #[cfg(feature = "dbus")]
    enable_dbus: bool,

    /// Whether to enable ubus integration (if feature enabled)
    #[cfg(feature = "ubus")]
    enable_ubus: bool,

    /// Whether to enable conntrack integration (if feature enabled)
    #[cfg(all(feature = "conntrack", target_os = "linux"))]
    enable_conntrack: bool,

    /// Whether to enable ipset integration (if feature enabled)
    #[cfg(all(feature = "ipset", target_os = "linux"))]
    enable_ipset: bool,

    /// Whether to enable nftables integration (if feature enabled)
    #[cfg(all(feature = "nftset", target_os = "linux"))]
    enable_nftset: bool,

    /// Whether to enable PF table integration (if feature enabled)
    #[cfg(all(
        feature = "ipset",
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )
    ))]
    enable_pf_tables: bool,

    /// Whether to enable inotify integration (if feature enabled)
    #[cfg(all(feature = "inotify", target_os = "linux"))]
    enable_inotify: bool,

    /// Metrics collector for integrations that need metrics reporting
    #[cfg(all(feature = "ubus", feature = "prometheus-metrics"))]
    metrics: Option<Arc<crate::monitoring::metrics::MetricsCollector>>,

    /// Logger for integrations that need logging
    #[cfg(feature = "ubus")]
    logger: Option<Arc<crate::logging::logger::Logger>>,

    /// ubus object name to register
    #[cfg(feature = "ubus")]
    ubus_object_name: Option<String>,
}

impl IntegrationManagerBuilder {
    /// Creates a new builder with all integrations disabled by default
    ///
    /// # Returns
    ///
    /// A new `IntegrationManagerBuilder` with all integrations set to disabled.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures D-Bus integration
    ///
    /// # Parameters
    ///
    /// - `enable`: Whether to attempt D-Bus initialization during `build()`
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Note
    ///
    /// This method is only available when the `dbus` feature is enabled. If the feature
    /// is disabled, this method is a no-op.
    #[cfg(feature = "dbus")]
    #[must_use] 
    pub fn with_dbus(mut self, enable: bool) -> Self {
        self.enable_dbus = enable;
        self
    }

    /// No-op when dbus feature is disabled
    #[cfg(not(feature = "dbus"))]
    #[must_use] 
    pub fn with_dbus(self, _enable: bool) -> Self {
        self
    }

    /// Configures ubus integration
    ///
    /// # Parameters
    ///
    /// - `enable`: Whether to attempt ubus initialization during `build()`
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(feature = "ubus")]
    #[must_use] 
    pub fn with_ubus(mut self, enable: bool) -> Self {
        self.enable_ubus = enable;
        self
    }

    /// No-op when ubus feature is disabled
    #[cfg(not(feature = "ubus"))]
    #[must_use] 
    pub fn with_ubus(self, _enable: bool) -> Self {
        self
    }

    /// Configures conntrack integration
    ///
    /// # Parameters
    ///
    /// - `enable`: Whether to attempt conntrack initialization during `build()`
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(all(feature = "conntrack", target_os = "linux"))]
    #[must_use] 
    pub fn with_conntrack(mut self, enable: bool) -> Self {
        self.enable_conntrack = enable;
        self
    }

    /// No-op when conntrack feature is disabled or not on Linux
    #[cfg(not(all(feature = "conntrack", target_os = "linux")))]
    #[must_use] 
    pub fn with_conntrack(self, _enable: bool) -> Self {
        self
    }

    /// Configures ipset integration
    ///
    /// # Parameters
    ///
    /// - `enable`: Whether to attempt ipset initialization during `build()`
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(all(feature = "ipset", target_os = "linux"))]
    #[must_use] 
    pub fn with_ipset(mut self, enable: bool) -> Self {
        self.enable_ipset = enable;
        self
    }

    /// No-op when ipset feature is disabled or not on Linux
    #[cfg(not(all(feature = "ipset", target_os = "linux")))]
    #[must_use] 
    pub fn with_ipset(self, _enable: bool) -> Self {
        self
    }

    /// Configures nftables integration
    ///
    /// # Parameters
    ///
    /// - `enable`: Whether to attempt nftables initialization during `build()`
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(all(feature = "nftset", target_os = "linux"))]
    #[must_use] 
    pub fn with_nftset(mut self, enable: bool) -> Self {
        self.enable_nftset = enable;
        self
    }

    /// No-op when nftset feature is disabled or not on Linux
    #[cfg(not(all(feature = "nftset", target_os = "linux")))]
    #[must_use] 
    pub fn with_nftset(self, _enable: bool) -> Self {
        self
    }

    /// Configures PF table integration
    ///
    /// # Parameters
    ///
    /// - `enable`: Whether to attempt PF table initialization during `build()`
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(all(
        feature = "ipset",
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )
    ))]
    pub fn with_pf_tables(mut self, enable: bool) -> Self {
        self.enable_pf_tables = enable;
        self
    }

    /// No-op when ipset feature is disabled or not on BSD
    #[cfg(not(all(
        feature = "ipset",
        any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )
    )))]
    #[must_use] 
    pub fn with_pf_tables(self, _enable: bool) -> Self {
        self
    }

    /// Configures inotify integration
    ///
    /// # Parameters
    ///
    /// - `enable`: Whether to attempt inotify initialization during `build()`
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(all(feature = "inotify", target_os = "linux"))]
    #[must_use] 
    pub fn with_inotify(mut self, enable: bool) -> Self {
        self.enable_inotify = enable;
        self
    }

    /// No-op when inotify feature is disabled or not on Linux
    #[cfg(not(all(feature = "inotify", target_os = "linux")))]
    #[must_use] 
    pub fn with_inotify(self, _enable: bool) -> Self {
        self
    }

    /// Configures metrics collector for integrations
    ///
    /// # Parameters
    ///
    /// - `metrics`: Metrics collector to use for integrations that need metrics reporting
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(all(feature = "ubus", feature = "prometheus-metrics"))]
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<crate::monitoring::metrics::MetricsCollector>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// No-op when ubus or prometheus-metrics feature is disabled
    ///
    /// This variant accepts a generic parameter to avoid referencing types that
    /// don't exist when prometheus-metrics feature is disabled.
    #[cfg(not(all(feature = "ubus", feature = "prometheus-metrics")))]
    #[must_use]
    pub fn with_metrics<T>(self, _metrics: Arc<T>) -> Self {
        self
    }

    /// Configures logger for integrations
    ///
    /// # Parameters
    ///
    /// - `logger`: Logger to use for integrations that need logging
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(feature = "ubus")]
    #[must_use]
    pub fn with_logger(mut self, logger: Arc<crate::logging::logger::Logger>) -> Self {
        self.logger = Some(logger);
        self
    }

    /// No-op when ubus feature is disabled
    #[cfg(not(feature = "ubus"))]
    #[must_use]
    pub fn with_logger(self, _logger: Arc<crate::logging::logger::Logger>) -> Self {
        self
    }

    /// Configures ubus object name
    ///
    /// # Parameters
    ///
    /// - `name`: Name of the ubus object to register (e.g., "dnsmasq")
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[cfg(feature = "ubus")]
    #[must_use]
    pub fn with_ubus_object_name(mut self, name: impl Into<String>) -> Self {
        self.ubus_object_name = Some(name.into());
        self
    }

    /// No-op when ubus feature is disabled
    #[cfg(not(feature = "ubus"))]
    #[must_use]
    pub fn with_ubus_object_name(self, _name: impl Into<String>) -> Self {
        self
    }

    /// Constructs the [`IntegrationManager`] with configured integrations
    ///
    /// This method attempts to initialize each enabled integration. If an integration fails
    /// to initialize, it will be disabled (set to `None`) and a warning may be logged, but
    /// the build process will continue. This ensures graceful degradation when optional
    /// features are not supported by the system.
    ///
    /// # Errors
    ///
    /// Returns `crate::Error` if a critical initialization failure occurs that prevents
    /// the manager from being created. Most integration failures result in graceful
    /// degradation rather than errors.
    ///
    /// # Returns
    ///
    /// `Ok(IntegrationManager)` with successfully initialized integrations, or
    /// `Err(crate::Error)` if a critical initialization failure occurs.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::integration::IntegrationManagerBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let manager = IntegrationManagerBuilder::new()
    ///     .with_dbus(true)
    ///     .with_inotify(true)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Result<IntegrationManager> {
        // mut is needed when any integration feature is enabled
        #[allow(unused_mut)]
        let mut manager = IntegrationManager::new();

        // Initialize D-Bus if enabled
        #[cfg(feature = "dbus")]
        if self.enable_dbus {
            match dbus::init_dbus() {
                Ok(interface) => {
                    manager.dbus_interface = Some(interface);
                }
                Err(e) => {
                    // Log warning but continue - D-Bus is optional
                    eprintln!("Warning: Failed to initialize D-Bus integration: {e}");
                }
            }
        }

        // Initialize ubus if enabled
        #[cfg(feature = "ubus")]
        if self.enable_ubus {
            // Check that required dependencies are provided
            if let (Some(metrics), Some(logger), Some(object_name)) = 
                (self.metrics.as_ref(), self.logger.as_ref(), self.ubus_object_name.as_ref()) 
            {
                match ubus::init_ubus(object_name, Arc::clone(metrics), Arc::clone(logger)) {
                    Ok(ubus_mgr) => {
                        manager.ubus_manager = Some(ubus_mgr);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to initialize ubus integration: {e}");
                    }
                }
            } else {
                eprintln!("Warning: ubus enabled but missing required dependencies (metrics, logger, or object_name)");
            }
        }

        // Initialize conntrack if enabled
        #[cfg(all(feature = "conntrack", target_os = "linux"))]
        if self.enable_conntrack {
            match ConntrackManager::new() {
                Ok(conntrack_mgr) => {
                    manager.conntrack_manager = Some(conntrack_mgr);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to initialize conntrack integration: {e}");
                }
            }
        }

        // Initialize ipset if enabled
        #[cfg(all(feature = "ipset", target_os = "linux"))]
        if self.enable_ipset {
            match IpsetManager::new() {
                Ok(ipset_mgr) => {
                    manager.ipset_manager = Some(ipset_mgr);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to initialize ipset integration: {e}");
                }
            }
        }

        // Initialize nftables if enabled
        #[cfg(all(feature = "nftset", target_os = "linux"))]
        if self.enable_nftset {
            match NftsetManager::new() {
                Ok(nftset_mgr) => {
                    manager.nftset_manager = Some(nftset_mgr);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to initialize nftables integration: {e}");
                }
            }
        }

        // Initialize PF tables if enabled
        #[cfg(all(
            feature = "ipset",
            any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )
        ))]
        if self.enable_pf_tables {
            match PfTableManager::new() {
                Ok(pf_mgr) => {
                    manager.pf_table_manager = Some(pf_mgr);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to initialize PF table integration: {}", e);
                }
            }
        }

        // Initialize inotify if enabled
        #[cfg(all(feature = "inotify", target_os = "linux"))]
        if self.enable_inotify {
            match InotifyWatcher::new() {
                Ok(inotify_watcher) => {
                    manager.inotify_watcher = Some(inotify_watcher);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to initialize inotify integration: {e}");
                }
            }
        }

        Ok(manager)
    }
}

impl Debug for IntegrationManagerBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("IntegrationManagerBuilder");

        #[cfg(feature = "dbus")]
        debug_struct.field("enable_dbus", &self.enable_dbus);

        #[cfg(feature = "ubus")]
        debug_struct.field("enable_ubus", &self.enable_ubus);

        #[cfg(all(feature = "conntrack", target_os = "linux"))]
        debug_struct.field("enable_conntrack", &self.enable_conntrack);

        #[cfg(all(feature = "ipset", target_os = "linux"))]
        debug_struct.field("enable_ipset", &self.enable_ipset);

        #[cfg(all(feature = "nftset", target_os = "linux"))]
        debug_struct.field("enable_nftset", &self.enable_nftset);

        #[cfg(all(
            feature = "ipset",
            any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )
        ))]
        debug_struct.field("enable_pf_tables", &self.enable_pf_tables);

        #[cfg(all(feature = "inotify", target_os = "linux"))]
        debug_struct.field("enable_inotify", &self.enable_inotify);

        debug_struct.finish()
    }
}

//
// ============================================================================
// TESTS
// ============================================================================
//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_manager_new() {
        let manager = IntegrationManager::new();
        // All integrations should be disabled by default
        assert!(!manager.has_dbus());
        assert!(!manager.has_ubus());
        assert!(!manager.has_conntrack());
        assert!(!manager.has_ipset());
        assert!(!manager.has_nftset());
        assert!(!manager.has_pf_tables());
        assert!(!manager.has_inotify());
    }

    #[test]
    fn test_integration_manager_builder_default() {
        let builder = IntegrationManagerBuilder::new();
        let manager = builder.build().expect("Build should succeed");

        // All integrations should be disabled with default builder
        assert!(!manager.has_dbus());
        assert!(!manager.has_ubus());
        assert!(!manager.has_conntrack());
        assert!(!manager.has_ipset());
        assert!(!manager.has_nftset());
        assert!(!manager.has_pf_tables());
        assert!(!manager.has_inotify());
    }

    #[test]
    fn test_integration_manager_debug() {
        let manager = IntegrationManager::new();
        let debug_output = format!("{manager:?}");
        assert!(debug_output.contains("IntegrationManager"));
    }

    #[test]
    fn test_builder_method_chaining() {
        let _builder = IntegrationManagerBuilder::new()
            .with_dbus(true)
            .with_ubus(true)
            .with_conntrack(true)
            .with_ipset(true)
            .with_nftset(true)
            .with_pf_tables(true)
            .with_inotify(true);

        // This test just verifies that method chaining compiles and works
    }

    #[test]
    fn test_builder_graceful_degradation() {
        // Builder should succeed even if integrations fail to initialize
        let manager = IntegrationManagerBuilder::new()
            .with_dbus(true) // May fail if D-Bus not available
            .with_inotify(true) // May fail if not on Linux
            .build()
            .expect("Build should succeed even with failed integrations");

        // Manager should be created successfully, with failures resulting in None values
        // rather than build() returning an error
        let _ = manager;
    }
}
