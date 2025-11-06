//! Configuration management for dnsmasq-rs
//!
//! This module handles configuration file parsing, command-line arguments,
//! and configuration validation.

use std::path::PathBuf;

/// Default configuration constants translated from C's config.h
pub mod defaults;

/// Main configuration structure
#[derive(Debug, Clone)]
pub struct Config {
    /// Whether to daemonize (fork to background)
    pub daemonize: bool,

    /// Debug mode (don't fork, verbose logging)
    pub debug: bool,

    /// User to drop privileges to
    pub user: Option<String>,

    /// Group to drop privileges to
    pub group: Option<String>,

    /// PID file path
    pub pid_file: Option<PathBuf>,

    /// Enable DNS server
    pub enable_dns: bool,

    /// Enable DHCP server
    pub enable_dhcp: bool,

    /// Enable TFTP server
    pub enable_tftp: bool,

    /// Listen address for all services
    pub listen_address: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            daemonize: false,
            debug: false,
            user: None,
            group: None,
            pid_file: None,
            enable_dns: true,
            enable_dhcp: false,
            enable_tftp: false,
            listen_address: None,
        }
    }
}

impl Config {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }
}
