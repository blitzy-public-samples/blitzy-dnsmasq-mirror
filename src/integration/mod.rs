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
//! use std::net::IpAddr;
//!
//! // Connect to D-Bus
//! let dbus = DbusInterface::connect().await?;
//!
//! // Emit lease added signal
//! let lease = LeaseInfo {
//!     mac_address: "00:11:22:33:44:55".to_string(),
//!     ip_address: "192.168.1.100".parse::<IpAddr>()?,
//!     hostname: Some("test-host".to_string()),
//!     expiry_time: Some(3600),
//! };
//! dbus.emit_lease_added(&lease).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## ubus Integration
//!
//! ```rust,no_run
//! # #[cfg(feature = "ubus")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use dnsmasq::integration::ubus::{UbusContext, UbusLease};
//! use std::net::IpAddr;
//!
//! // Connect to ubus (OpenWrt only)
//! let ubus = UbusContext::connect()?;
//!
//! // Broadcast lease event
//! let lease = UbusLease {
//!     mac_address: "00:11:22:33:44:55".to_string(),
//!     ip_address: "192.168.1.100".parse::<IpAddr>()?,
//!     hostname: Some("test-host".to_string()),
//!     expires: 3600,
//! };
//! ubus.broadcast_lease_event("lease_added", &lease)?;
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
//! use std::net::IpAddr;
//!
//! // Create script executor
//! let executor = ScriptExecutor::new("/etc/dnsmasq-script.sh")?;
//!
//! // Queue lease event
//! executor.queue_lease_event(
//!     LeaseAction::Add,
//!     "00:11:22:33:44:55".to_string(),
//!     "192.168.1.100".parse::<IpAddr>()?,
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
pub use ubus::{UbusContext, UbusLease, UbusMetrics};

#[cfg(feature = "scripts")]
pub use scripts::{LeaseAction, ScriptError, ScriptEvent, ScriptExecutor, ScriptResult};

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
    pub fn detect() -> Self {
        Self {
            dbus_available: cfg!(feature = "dbus"),
            ubus_available: cfg!(feature = "ubus"),
            scripts_available: cfg!(feature = "scripts"),
        }
    }
    
    /// Check if any integrations are available
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
