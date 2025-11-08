// dnsmasq-rs: Memory-safe Rust implementation of dnsmasq
// Copyright (c) 2000-2022 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! External system integration subsystem
//!
//! This module provides interfaces to external system services and IPC mechanisms,
//! replacing C implementations with safe Rust alternatives. It serves as the
//! organizational root for all external integration functionality.
//!
//! # Subsystems
//!
//! ## D-Bus Integration (feature = "dbus")
//! Desktop Linux integration via D-Bus for NetworkManager and system services.
//! Replaces `src/dbus.c` with async Rust using the zbus crate.
//!
//! Key capabilities:
//! - DHCP lease change signals
//! - DNS cache control methods
//! - Service status queries
//! - Configuration updates
//!
//! ## ubus Integration (feature = "ubus")
//! OpenWrt micro bus integration for embedded router deployments.
//! Replaces `src/ubus.c` with FFI bindings to libubus.
//!
//! Key capabilities:
//! - Metrics export for LuCI web interface
//! - DHCP lease queries
//! - Service monitoring
//!
//! ## Script Execution (feature = "scripts")
//! Privilege-separated script execution for DHCP and TFTP events.
//! Replaces `src/helper.c` with async Rust using tokio::process.
//!
//! Key capabilities:
//! - DHCP lease change notifications (add, del, old)
//! - TFTP transfer events
//! - ARP detection events
//! - Environment variable passing
//!
//! # Feature Flags
//!
//! The module uses Cargo feature flags to mirror the C version's HAVE_* macros:
//!
//! - `dbus`: Enable D-Bus integration (replaces HAVE_DBUS)
//! - `ubus`: Enable ubus integration (replaces HAVE_UBUS)
//! - `scripts`: Enable script execution (replaces HAVE_SCRIPT)
//!
//! These features can be independently enabled/disabled at compile time,
//! allowing for minimal builds on embedded systems or desktop-focused builds
//! with full integration.
//!
//! # Platform Considerations
//!
//! - **D-Bus**: Typically used on desktop Linux and servers with NetworkManager
//! - **ubus**: Only available on OpenWrt/LEDE embedded router distributions
//! - **Scripts**: Available on all platforms supporting POSIX process execution
//!
//! D-Bus and ubus are mutually exclusive in practice, as they target different
//! deployment scenarios.
//!
//! # Integration Workflow
//!
//! External integrations coordinate with other dnsmasq subsystems:
//!
//! ```text
//! DHCP Lease Change
//!       │
//!       ├──> Script Executor (queue event)
//!       │         │
//!       │         └──> Execute script with env vars
//!       │
//!       ├──> D-Bus Interface (emit signal)
//!       │         │
//!       │         └──> Broadcast DhcpLeaseAdded
//!       │
//!       └──> ubus Context (broadcast event)
//!                 │
//!                 └──> Send ubus event for OpenWrt
//! ```
//!
//! # Initialization Order
//!
//! From `main.rs`, integrations should be initialized in this order:
//!
//! 1. **Script Executor**: Needed immediately for DHCP events
//! 2. **ubus** (OpenWrt only): Early initialization for system integration
//! 3. **D-Bus** (desktop/server): Last, as it depends on system bus availability
//!
//! # Usage Examples
//!
//! ## D-Bus Integration
//!
//! ```rust,no_run
//! # #[cfg(feature = "dbus")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use dnsmasq::integration::dbus::{DbusInterface, LeaseInfo};
//! use dnsmasq::types::daemon_state::DaemonState;
//! use dnsmasq::config::types::Config;
//! use std::net::IpAddr;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! // Create daemon state and D-Bus interface
//! let state = Arc::new(RwLock::new(DaemonState::new(Config::default())));
//! let dbus = DbusInterface::new(state);
//!
//! // Create lease info
//! let lease = LeaseInfo {
//!     address: "192.168.1.100".parse::<IpAddr>()?,
//!     mac: "00:11:22:33:44:55".to_string(),
//!     hostname: "test-host".to_string(),
//!     expiry: 3600,
//!     client_id: vec![],
//!     iaid: 0,
//!     is_temporary: false,
//! };
//! // Add DHCP lease via D-Bus
//! dbus.add_dhcp_lease_impl(lease).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## ubus Integration
//!
//! ```rust,no_run
//! # #[cfg(all(feature = "ubus", feature = "dhcp"))]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use dnsmasq::integration::ubus::UbusContext;
//!
//! // Connect to ubus (OpenWrt only)
//! let mut ubus = UbusContext::connect("dnsmasq")?;
//!
//! // Broadcast lease event with individual fields
//! ubus.broadcast_lease_event(
//!     "dhcp.add",
//!     Some("00:11:22:33:44:55"),
//!     Some("192.168.1.100"),
//!     Some("test-host"),
//!     Some("eth0"),
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Script Execution
//!
//! ```rust,no_run
//! # #[cfg(feature = "scripts")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use dnsmasq::integration::scripts::{ScriptExecutor, LeaseAction};
//! use dnsmasq::dhcp::lease::Lease;
//!
//! // Create script executor
//! let executor = ScriptExecutor::new("/etc/dnsmasq-script.sh")?;
//!
//! # // Create a sample lease (in real code, this would come from DHCP server)
//! # let lease = Lease::new(
//! #     "192.168.1.100".parse()?,
//! #     vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
//! #     None,
//! #     Some("test-host".to_string()),
//! #     3600,
//! # );
//! // Queue lease event
//! executor.queue_lease_event(
//!     LeaseAction::Add,
//!     lease,
//!     Some("test-host".to_string()),
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! Each integration module defines its own error type:
//!
//! - `dbus::DbusError`: D-Bus connection and method call failures
//! - `ubus::UbusError`: ubus connection and FFI errors
//! - `scripts::ScriptError`: Script execution and timeout failures
//!
//! # Testing Support
//!
//! The module provides test utilities for mocking integrations in unit tests.
//! This allows testing DHCP and DNS subsystems without requiring actual system
//! services to be running.

// D-Bus integration module (desktop Linux, NetworkManager)
#[cfg(feature = "dbus")]
pub mod dbus;

// ubus integration module (OpenWrt embedded routers)
#[cfg(feature = "ubus")]
pub mod ubus;

// Script execution module (DHCP/TFTP event handlers)
#[cfg(feature = "scripts")]
pub mod scripts;

// Re-export key types for convenient access
#[cfg(feature = "dbus")]
pub use dbus::{DbusInterface, LeaseInfo as DbusLeaseInfo, ServerSpec};

#[cfg(feature = "ubus")]
pub use ubus::{UbusContext, UbusMetrics};

#[cfg(all(feature = "ubus", feature = "dhcp"))]
pub use ubus::UbusLease;

#[cfg(feature = "scripts")]
pub use scripts::{ArpAction, LeaseAction, ScriptError, ScriptEvent, ScriptExecutor};

/// Module initialization status
///
/// Tracks which integrations are available at runtime based on compiled features
/// and system availability.
#[derive(Debug, Clone, Default)]
pub struct IntegrationStatus {
    /// D-Bus integration available
    pub dbus_available: bool,

    /// ubus integration available
    pub ubus_available: bool,

    /// Script execution available
    pub scripts_available: bool,
}

impl IntegrationStatus {
    /// Create new integration status by detecting available subsystems
    #[must_use]
    pub fn detect() -> Self {
        Self {
            dbus_available: cfg!(feature = "dbus"),
            ubus_available: cfg!(feature = "ubus"),
            scripts_available: cfg!(feature = "scripts"),
        }
    }

    /// Check if any integrations are available
    #[must_use]
    pub fn has_any(&self) -> bool {
        self.dbus_available || self.ubus_available || self.scripts_available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_status_detect() {
        let status = IntegrationStatus::detect();

        // At least scripts should be available if the feature is enabled
        #[cfg(feature = "scripts")]
        assert!(status.scripts_available);

        #[cfg(not(feature = "scripts"))]
        assert!(!status.scripts_available);
    }

    #[test]
    fn test_integration_status_has_any() {
        let status = IntegrationStatus {
            dbus_available: false,
            ubus_available: false,
            scripts_available: true,
        };
        assert!(status.has_any());

        let status_none = IntegrationStatus {
            dbus_available: false,
            ubus_available: false,
            scripts_available: false,
        };
        assert!(!status_none.has_any());
    }
}
