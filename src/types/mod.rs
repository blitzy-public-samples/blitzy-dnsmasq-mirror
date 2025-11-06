//! Common types and error handling for dnsmasq-rs
//!
//! This module provides shared types, error definitions, and type aliases used
//! throughout the dnsmasq-rs codebase.

pub mod addresses;

use thiserror::Error;

/// Main error type for dnsmasq operations
#[derive(Error, Debug)]
pub enum DnsmasqError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Runtime error
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// DNS error
    #[error("DNS error: {0}")]
    Dns(String),

    /// DHCP error
    #[error("DHCP error: {0}")]
    Dhcp(String),
}

/// Result type alias for dnsmasq operations
pub type DnsmasqResult<T> = Result<T, DnsmasqError>;

/// Daemon state placeholder (will be fully implemented)
pub struct DaemonState {
    /// Configuration
    pub config: String, // Placeholder
}
