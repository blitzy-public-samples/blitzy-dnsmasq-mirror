// Copyright (c) 2000-2024 Simon Kelley
// This file is part of the Rust port of dnsmasq.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.

//! External System Integration Module
//!
//! This module provides interfaces for integrating dnsmasq with external system services
//! and event notification frameworks. It organizes three distinct integration subsystems,
//! each conditionally compiled based on feature flags to maintain compatibility with the
//! C implementation's HAVE_* macros.
//!
//! # Integration Subsystems
//!
//! ## D-Bus Integration (`feature = "dbus"`)
//!
//! Provides runtime control and monitoring via D-Bus IPC, commonly used on desktop Linux
//! systems and servers with NetworkManager. The D-Bus interface allows external applications
//! to dynamically configure dnsmasq without restarting the daemon or sending SIGHUP signals.
//!
//! **Source**: Translated from `src/dbus.c`
//!
//! **Key Capabilities**:
//! - Runtime DNS server configuration (SetServers, SetServersEx methods)
//! - Cache management (ClearCache method)
//! - DHCP lease event notifications (DhcpLeaseAdded/Deleted/Updated signals)
//! - Metrics and status queries (GetVersion, GetMetrics methods)
//! - Integration with NetworkManager, systemd-resolved, and D-Bus aware management tools
//!
//! **D-Bus Specification Compliance**:
//! - Interface name: `uk.org.thekelleys.dnsmasq`
//! - Bus type: System bus
//! - Supports introspection via `org.freedesktop.DBus.Introspectable`
//! - Non-blocking integration with async event loop
//!
//! **Example Usage**:
//! ```rust,no_run
//! # #[cfg(feature = "dbus")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use dnsmasq_rs::integration::DbusInterface;
//!
//! // Connect to system D-Bus and export dnsmasq interface
//! let dbus = DbusInterface::connect("uk.org.thekelleys.dnsmasq").await?;
//!
//! // Emit DHCP lease added signal
//! let lease = dnsmasq_rs::integration::LeaseInfo {
//!     address: "192.168.1.100".parse()?,
//!     mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
//!     hostname: Some("client-device".to_string()),
//!     expiry: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
//! };
//! dbus.emit_lease_added(lease).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## OpenWrt ubus Integration (`feature = "ubus"`)
//!
//! Provides lightweight IPC for OpenWrt/LEDE embedded Linux distributions, offering
//! similar functionality to D-Bus but optimized for resource-constrained routers and
//! embedded devices. Uses OpenWrt's libubox blob binary format for efficient marshaling.
//!
//! **Source**: Translated from `src/ubus.c`
//!
//! **Key Capabilities**:
//! - Metrics export (DNS cache statistics, query counts, DHCP leases)
//! - DHCP lease event broadcasting to ubus subscribers
//! - Conntrack mark allowlist configuration (with `feature = "conntrack"`)
//! - Integration with LuCI web interface and OpenWrt management tools
//!
//! **Namespace**: `dnsmasq` (ubus object name)
//!
//! **Platform Note**: D-Bus and ubus are typically mutually exclusive in practice:
//! - D-Bus: Desktop Linux, servers, NetworkManager environments
//! - ubus: OpenWrt/LEDE embedded routers only
//!
//! **Example Usage**:
//! ```rust,no_run
//! # #[cfg(feature = "ubus")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use dnsmasq_rs::integration::{UbusContext, UbusMetrics};
//!
//! // Connect to system ubus daemon
//! let ubus = UbusContext::connect()?;
//!
//! // Broadcast DHCP lease event
//! let lease = /* lease info */;
//! ubus.broadcast_lease_event(&lease)?;
//!
//! // Export metrics for LuCI or monitoring tools
//! let metrics = UbusMetrics {
//!     cache_size: 150,
//!     cache_inserted: 1500,
//!     cache_misses: 25,
//! };
//! ubus.publish_metrics(&metrics)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## DHCP Script Execution (`feature = "scripts"`)
//!
//! Executes external scripts or Lua functions in response to DHCP lease events, TFTP
//! transfers, and ARP detections. Implements privilege separation architecture where
//! a separate helper process retains root privileges to execute scripts while the main
//! daemon runs unprivileged.
//!
//! **Source**: Translated from `src/helper.c`
//!
//! **Key Capabilities**:
//! - DHCP lease change notifications (add, renew, old, delete actions)
//! - TFTP transfer event notifications (file upload/download completion)
//! - ARP detection events (MAC address to IP mappings)
//! - Lua script integration (with `feature = "lua"`) for in-process event handling
//! - Environment variable injection (DNSMASQ_* variables) for script access to event data
//!
//! **Security Architecture**:
//! - Privilege separation: Main daemon drops privileges, helper retains root
//! - Validated communication: Helper validates all data from main process
//! - Script path immutability: Script path set before fork, cannot be altered at runtime
//! - Prevents compromised daemon from escalating privileges via helper
//!
//! **Supported Events**:
//! - `DhcpLeaseEvent`: Lease allocation, renewal, expiry, release
//! - `TftpEvent`: File transfer start, completion, error
//! - `ArpEvent`: ARP table entry detection
//!
//! **Example Usage**:
//! ```rust,no_run
//! # #[cfg(feature = "scripts")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use dnsmasq_rs::integration::{ScriptExecutor, ScriptEvent, LeaseAction};
//! use std::path::PathBuf;
//!
//! // Initialize script executor with path to lease-change script
//! let script_path = PathBuf::from("/etc/dnsmasq/lease-change.sh");
//! let executor = ScriptExecutor::new(script_path)?;
//!
//! // Queue DHCP lease event for asynchronous execution
//! let lease = /* lease details */;
//! executor.queue_lease_event(LeaseAction::Add, lease).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature Flag Organization
//!
//! The module uses Cargo feature flags to mirror the C implementation's compile-time
//! configuration macros (`HAVE_*`):
//!
//! | Cargo Feature | C Macro | Module | Purpose |
//! |---------------|---------|--------|---------|
//! | `dbus` | `HAVE_DBUS` | [`dbus`] | D-Bus IPC for desktop/server Linux |
//! | `ubus` | `HAVE_UBUS` | [`ubus`] | OpenWrt ubus IPC for embedded routers |
//! | `scripts` | `HAVE_SCRIPT` | [`scripts`] | External script execution for DHCP events |
//!
//! Each integration can be independently enabled or disabled at compile time, allowing
//! for minimal binary size on embedded systems or comprehensive integration on servers.
//!
//! # Module Coordination and Event Flow
//!
//! Integration modules coordinate with other dnsmasq subsystems to provide comprehensive
//! event notification and runtime control:
//!
//! **DHCP Lease Lifecycle**:
//! ```text
//! dhcp/lease.rs
//!     ↓ (lease change)
//! integration/scripts.rs → Execute script with environment variables
//!     ↓ (async notification)
//! integration/dbus.rs → Emit D-Bus signal (DhcpLeaseAdded)
//!     ↓ (async notification)
//! integration/ubus.rs → Broadcast ubus event
//! ```
//!
//! **DNS Server Configuration**:
//! ```text
//! D-Bus SetServers method
//!     ↓ (runtime config change)
//! dns/forward.rs → Update upstream server list
//!     ↓ (invalidate stale data)
//! dns/cache.rs → Clear cached responses
//! ```
//!
//! **Metrics Collection**:
//! ```text
//! util/metrics.rs → Collect statistics
//!     ↓ (query)
//! integration/dbus.rs → Export via GetMetrics method
//! integration/ubus.rs → Export via metrics ubus method
//! ```
//!
//! # Runtime Initialization Order
//!
//! The integration subsystems must be initialized in a specific order to ensure proper
//! operation (as documented in `main.rs`):
//!
//! 1. **Script Executor** (`scripts`): Initialize first, as DHCP subsystem depends on it
//!    for lease event notifications. Fork helper process and establish IPC pipe.
//!
//! 2. **ubus Context** (`ubus`): Initialize second on OpenWrt systems. Register methods
//!    and integrate socket with event loop.
//!
//! 3. **D-Bus Interface** (`dbus`): Initialize last on desktop/server systems. Connect
//!    to system bus, export interface, and register file descriptors with event loop.
//!
//! Note: D-Bus and ubus are mutually exclusive in practice (different target platforms),
//! but both can be compiled in for multi-platform binaries.
//!
//! # Platform Considerations
//!
//! **Desktop/Server Linux** (NetworkManager, systemd-resolved):
//! - Enable `feature = "dbus"` for D-Bus integration
//! - Enable `feature = "scripts"` for custom lease-change scripts
//! - Typical dependencies: `zbus`, `tokio`
//!
//! **OpenWrt/LEDE Embedded Routers**:
//! - Enable `feature = "ubus"` for LuCI and ubus integration
//! - Enable `feature = "scripts"` with `feature = "lua"` for efficient in-process events
//! - Disable `feature = "dbus"` to minimize binary size
//! - Requires libubox and libubus from OpenWrt SDK
//!
//! **Minimal Embedded Systems**:
//! - Disable all integration features for smallest binary size
//! - Rely on configuration file and SIGHUP for runtime control
//!
//! # Error Handling
//!
//! All integration subsystems return [`Result`] types with [`IntegrationError`] for
//! error propagation. Errors are non-fatal and logged; integration failures do not
//! terminate the main dnsmasq daemon.
//!
//! # Testing Support
//!
//! The [`test_utils`] module provides mock implementations for testing code that depends
//! on external integrations without requiring actual D-Bus daemon, ubus system, or
//! script execution capabilities.
//!
//! # Backward Compatibility
//!
//! This Rust implementation maintains 100% behavioral compatibility with the C version:
//! - D-Bus interface name and method signatures unchanged
//! - ubus object name and method signatures preserved
//! - Script environment variables identical to C implementation
//! - Event notification timing and ordering preserved
//! - No new features added beyond C version functionality

use thiserror::Error;

// ================================================================================================
// Module Declarations (Feature-Gated)
// ================================================================================================

/// D-Bus integration module for desktop/server Linux systems.
///
/// Provides IPC interface for NetworkManager and other D-Bus-aware management tools.
/// Exports methods under `uk.org.thekelleys.dnsmasq` interface on system bus.
///
/// **Compile-time requirement**: `feature = "dbus"` (mirrors C's `HAVE_DBUS`)
///
/// **Source**: Translated from `src/dbus.c`
#[cfg(feature = "dbus")]
pub mod dbus;

/// OpenWrt ubus integration module for embedded routers.
///
/// Provides lightweight IPC interface using OpenWrt's ubus system for resource-constrained
/// devices. Exports methods under `dnsmasq` namespace.
///
/// **Compile-time requirement**: `feature = "ubus"` (mirrors C's `HAVE_UBUS`)
///
/// **Platform**: OpenWrt/LEDE only
///
/// **Source**: Translated from `src/ubus.c`
#[cfg(feature = "ubus")]
pub mod ubus;

/// Script execution module for DHCP lease events and external script integration.
///
/// Implements privilege separation architecture with separate helper process for
/// executing lease-change scripts, TFTP event handlers, and ARP detection scripts.
/// Supports both shell scripts and Lua functions (with `feature = "lua"`).
///
/// **Compile-time requirement**: `feature = "scripts"` (mirrors C's `HAVE_SCRIPT`)
///
/// **Source**: Translated from `src/helper.c`
#[cfg(feature = "scripts")]
pub mod scripts;

// ================================================================================================
// Unified Error Type
// ================================================================================================

/// Unified error type for all integration subsystems.
///
/// This enum consolidates errors from D-Bus, ubus, and script execution subsystems,
/// providing a single error type for integration module consumers. Each variant is
/// feature-gated to match the corresponding subsystem's availability.
///
/// # Error Propagation
///
/// Integration errors are non-fatal and should be logged but not terminate the daemon:
///
/// ```rust,no_run
/// # use dnsmasq_rs::integration::IntegrationError;
/// # async fn emit_event() -> Result<(), IntegrationError> {
/// #     Ok(())
/// # }
/// # async fn example() {
/// match emit_event().await {
///     Ok(()) => {
///         // Event successfully emitted
///     }
///     Err(e) => {
///         // Log error but continue operation
///         tracing::warn!("Integration event failed: {}", e);
///     }
/// }
/// # }
/// ```
#[derive(Debug, Error)]
pub enum IntegrationError {
    /// D-Bus integration error (IPC communication, method invocation, signal emission).
    ///
    /// Occurs when D-Bus connection is lost, method calls fail, or signal emission is rejected.
    /// Common causes: D-Bus daemon not running, permission denied, invalid message format.
    #[cfg(feature = "dbus")]
    #[error("D-Bus error: {0}")]
    Dbus(#[from] dbus::DbusError),

    /// OpenWrt ubus integration error (context creation, method registration, event broadcast).
    ///
    /// Occurs when ubus daemon is unreachable, method registration fails, or event broadcast
    /// is rejected. Common on embedded systems when ubus daemon crashes or restarts.
    #[cfg(feature = "ubus")]
    #[error("ubus error: {0}")]
    Ubus(#[from] ubus::UbusError),

    /// Script execution error (fork failure, script timeout, I/O error, Lua error).
    ///
    /// Occurs when script executor cannot spawn helper process, script execution times out,
    /// script path is invalid, or Lua function execution fails. Does not indicate script
    /// exit code != 0 (that's logged separately).
    #[cfg(feature = "scripts")]
    #[error("Script execution error: {0}")]
    Script(#[from] scripts::ScriptError),
}

// ================================================================================================
// Public Re-exports (Feature-Gated)
// ================================================================================================

// D-Bus exports
#[cfg(feature = "dbus")]
pub use dbus::{DbusInterface, LeaseInfo, ServerSpec};

// ubus exports
#[cfg(feature = "ubus")]
pub use ubus::{UbusContext, UbusMetrics};

// Script execution exports
#[cfg(feature = "scripts")]
pub use scripts::{LeaseAction, ScriptError, ScriptEvent, ScriptExecutor};

// ================================================================================================
// Testing Utilities (Test-Only)
// ================================================================================================

/// Testing utilities for mocking integration subsystems.
///
/// Provides mock implementations of D-Bus, ubus, and script executor for unit testing
/// code that depends on integration functionality without requiring actual system services.
///
/// **Availability**: Only compiled with `#[cfg(test)]`
///
/// # Example
///
/// ```rust
/// # #[cfg(test)]
/// # mod tests {
/// use dnsmasq_rs::integration::test_utils::*;
///
/// #[tokio::test]
/// async fn test_dhcp_lease_notification() {
///     let mock_dbus = MockDbusInterface::new();
///     mock_dbus.expect_emit_lease_added()
///         .times(1)
///         .returning(|_| Ok(()));
///
///     // Test code that emits D-Bus signals
///     // ...
/// }
/// # }
/// ```
#[cfg(test)]
pub mod test_utils {
    //! Mock implementations for testing integration code.

    /// Mock D-Bus interface for testing without actual D-Bus daemon.
    #[cfg(feature = "dbus")]
    pub struct MockDbusInterface {
        // Mock state
    }

    #[cfg(feature = "dbus")]
    impl MockDbusInterface {
        /// Create new mock D-Bus interface.
        pub fn new() -> Self {
            Self {}
        }
    }

    /// Mock ubus context for testing without actual ubus daemon.
    #[cfg(feature = "ubus")]
    pub struct MockUbusContext {
        // Mock state
    }

    #[cfg(feature = "ubus")]
    impl MockUbusContext {
        /// Create new mock ubus context.
        pub fn new() -> Self {
            Self {}
        }
    }

    /// Mock script executor for testing without actual script execution.
    #[cfg(feature = "scripts")]
    pub struct MockScriptExecutor {
        // Mock state
    }

    #[cfg(feature = "scripts")]
    impl MockScriptExecutor {
        /// Create new mock script executor.
        pub fn new() -> Self {
            Self {}
        }
    }
}
