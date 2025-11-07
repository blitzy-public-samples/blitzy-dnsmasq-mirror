//! Common types and error handling for dnsmasq-rs
//!
//! This module provides shared types, error definitions, and type aliases used
//! throughout the dnsmasq-rs codebase.

pub mod addresses;
pub mod errors;

// Re-export commonly used error types and Result alias for convenience
pub use errors::{
    AuthError, ConfigError, DhcpError, DnsError, DnsmasqError, DnsmasqResult, DnssecError,
    LogError, NetworkError, SystemError, TftpError,
};

/// Daemon state placeholder (will be fully implemented)
pub struct DaemonState {
    /// Configuration
    pub config: String, // Placeholder
}
