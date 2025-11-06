//! # dnsmasq - Lightweight DNS, DHCP, and TFTP server
//!
//! This is a memory-safe Rust implementation of dnsmasq, providing:
//! - DNS forwarding and caching
//! - DHCPv4 and DHCPv6 servers
//! - TFTP server
//! - Router Advertisement
//! - Authoritative DNS
//!
//! ## Architecture
//!
//! The implementation is organized into the following modules:
//! - `core`: Main daemon runtime and event loop
//! - `dns`: DNS protocol handling, caching, and forwarding
//! - `dhcp`: DHCPv4 and DHCPv6 servers
//! - `ipv6`: IPv6-specific services (RA, SLAAC)
//! - `network`: Network layer and platform abstractions
//! - `services`: Auxiliary services (TFTP)
//! - `integration`: External integrations (D-Bus, ubus, etc.)
//! - `config`: Configuration parsing and validation
//! - `process`: Process management and privilege handling
//! - `logging`: Logging infrastructure
//! - `monitoring`: Metrics and observability
//! - `utils`: Utility functions

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(dead_code)] // Allow during initial development

// Core modules
pub mod core;

// DNS subsystem
pub mod dns;

// DHCP subsystem
#[cfg(feature = "dhcp")]
pub mod dhcp;

// IPv6 services
pub mod ipv6;

// Network layer
pub mod network;

// Services
#[cfg(feature = "tftp")]
pub mod services;

// External integrations
pub mod integration;

// Configuration system
pub mod config;

// Process management
pub mod process;

// Logging
pub mod logging;

// Monitoring
#[cfg(feature = "prometheus-metrics")]
pub mod monitoring;

// Utilities
pub mod utils;

// FFI wrappers
pub mod ffi;

// Re-export commonly used types
pub use crate::core::daemon::Daemon;
pub use crate::config::types::Config;

/// Library version matching C implementation
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the dnsmasq runtime
///
/// This is the main entry point for library users.
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    logging::init()?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
