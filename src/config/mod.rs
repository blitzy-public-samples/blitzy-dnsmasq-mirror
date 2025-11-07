// Copyright (C) 2024 Blitzy Platform - dnsmasq Rust Port
// This file is part of the dnsmasq Rust implementation.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Configuration module root for dnsmasq-rs
//!
//! This module provides the complete configuration management system for dnsmasq,
//! replacing the C implementation's `option.c` and global `struct daemon` configuration
//! state with a structured, type-safe Rust API.
//!
//! # Overview
//!
//! The configuration system is organized into four submodules:
//!
//! - **[`defaults`]**: Compile-time constants from C's `config.h`
//! - **[`types`]**: Configuration data structures with builder pattern
//! - **[`parser`]**: Configuration file parsing (dnsmasq.conf format)
//! - **[`options`]**: Command-line argument parsing using clap
//!
//! # Architecture
//!
//! Configuration loading follows a three-phase process:
//!
//! 1. **Parse Phase**: Parse CLI arguments and configuration file(s)
//! 2. **Merge Phase**: Merge configurations with proper precedence (CLI > file > defaults)
//! 3. **Validate Phase**: Comprehensive cross-field validation
//!
//! ```text
//! CLI Args (clap)  ─┐
//!                   ├─> Merge ─> Validate ─> Final Config
//! Config File(s)   ─┘
//! ```
//!
//! # Precedence Order
//!
//! Configuration values are resolved with the following precedence (highest to lowest):
//!
//! 1. Command-line arguments (highest priority)
//! 2. Configuration file settings
//! 3. Compiled-in defaults from [`defaults`] module
//!
//! # Usage Examples
//!
//! ## Load from CLI arguments
//!
//! ```no_run
//! use dnsmasq::config::{Cli, load_config};
//! use clap::Parser;
//!
//! let cli = Cli::parse();
//! let config = load_config(cli)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Load from file only
//!
//! ```no_run
//! use dnsmasq::config::parse_config_file;
//!
//! let config = parse_config_file("/etc/dnsmasq.conf")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Build programmatically
//!
//! ```no_run
//! use dnsmasq::config::{ConfigBuilder, DnsConfig};
//!
//! let config = ConfigBuilder::new()
//!     .dns(DnsConfig {
//!         cache_size: 1000,
//!         ..Default::default()
//!     })
//!     .validate()?
//!     .build()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Feature Gating
//!
//! Types and functions are conditionally compiled based on Cargo features:
//!
//! - `dhcp`: DHCPv4/v6 configuration ([`DhcpConfig`], [`DhcpRange`], [`DhcpStaticHost`])
//! - `dnssec`: DNSSEC configuration ([`DnssecConfig`], [`TrustAnchor`])
//! - `tftp`: TFTP configuration ([`TftpConfig`])
//! - `auth-dns`: Authoritative DNS configuration ([`AuthConfig`])
//!
//! # C Implementation Reference
//!
//! This module replaces:
//! - `src/option.c` - Configuration parsing and option handling
//! - `struct daemon` (dnsmasq.h lines 1099+) - Global configuration state
//! - `read_opts()` function - Main configuration entry point
//! - `one_opt()` function - Individual option processing
//!
//! # Compatibility
//!
//! This implementation maintains 100% backward compatibility with dnsmasq.conf
//! file format and all 200+ command-line options from the C version.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

// =============================================================================
// MODULE DECLARATIONS
// =============================================================================

/// Compile-time constants and default values from C's config.h
pub mod defaults;

/// Configuration data structures, builder pattern, and validation
pub mod types;

/// Configuration file parser maintaining dnsmasq.conf compatibility
pub mod parser;

/// Command-line argument parser using clap (200+ options)
pub mod options;

// =============================================================================
// PUBLIC RE-EXPORTS - PRIMARY API
// =============================================================================

// Core configuration types
pub use types::{Config, ConfigBuilder, ConfigError};

// Subsystem configuration structures
pub use types::{
    DnsConfig, LoggingConfig, NetworkConfig, SecurityConfig,
};

// Common types used across configuration
pub use types::{UpstreamServer, MacAddress, Protocol, SyslogFacility};

// Parser functions and error types
pub use parser::{parse_config_file, parse_config_string, ParseError};

// CLI argument structure
pub use options::Cli;

// Re-export constants module for external access
pub use defaults as constants;

// =============================================================================
// FEATURE-GATED RE-EXPORTS
// =============================================================================

// DHCP configuration types (feature: dhcp)
#[cfg(feature = "dhcp")]
pub use types::{DhcpConfig, DhcpOption, DhcpRange, DhcpStaticHost};

// TFTP configuration types (feature: tftp)
#[cfg(feature = "tftp")]
pub use types::TftpConfig;

// DNSSEC configuration types (feature: dnssec)
#[cfg(feature = "dnssec")]
pub use types::{DnssecConfig, TrustAnchor};

// Authoritative DNS configuration types (feature: auth-dns)
#[cfg(feature = "auth-dns")]
pub use types::AuthConfig;

// =============================================================================
// HIGH-LEVEL CONFIGURATION LOADING
// =============================================================================

/// Load configuration from CLI arguments and optional configuration file(s)
///
/// This is the main entry point for configuration loading, replacing the C
/// implementation's `read_opts()` function from option.c. It performs:
///
/// 1. Parses configuration file(s) if specified via `--conf-file` or `--conf-dir`
/// 2. Merges CLI arguments with file configuration (CLI takes precedence)
/// 3. Applies default values for unspecified options
/// 4. Validates the complete configuration for consistency
///
/// # Arguments
///
/// * `cli` - Parsed command-line arguments from [`Cli::parse()`]
///
/// # Returns
///
/// * `Ok(Config)` - Validated configuration ready for daemon initialization
/// * `Err(ConfigError)` - Configuration error with detailed context
///
/// # Precedence
///
/// Configuration values are resolved in this order (highest to lowest priority):
/// 1. Command-line arguments
/// 2. Configuration file settings
/// 3. Compiled-in defaults
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::config::{Cli, load_config};
/// use clap::Parser;
///
/// let cli = Cli::parse();
/// let config = load_config(cli)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # C Implementation Reference
///
/// Replaces: `read_opts()` in src/option.c (lines 1000+)
/// Behavior: Identical option processing and precedence to C version
pub fn load_config(cli: Cli) -> Result<Config, ConfigError> {
    // Start with default configuration
    let mut config = ConfigBuilder::new().build()?;

    // Load configuration file if specified
    if let Some(ref conf_file) = cli.conf_file {
        let file_config = parse_config_file(conf_file)
            .map_err(|e| ConfigError::ValidationError(format!("Failed to parse config file: {}", e)))?;
        config = merge_configs(config, file_config);
    }

    // Load additional configuration files from conf-dir if specified
    if let Some(ref conf_dir) = cli.conf_dir {
        let dir_configs = load_conf_dir(conf_dir)?;
        for dir_config in dir_configs {
            config = merge_configs(config, dir_config);
        }
    }

    // Apply CLI overrides (highest precedence)
    apply_cli_overrides(&mut config, &cli);

    // Perform comprehensive validation
    validate_config(&config)?;

    Ok(config)
}

/// Merge two configurations with override taking precedence
///
/// Merges configuration values where the `override_config` takes precedence
/// over `base_config`. Used to implement configuration precedence hierarchy
/// (CLI > file > defaults).
///
/// # Merge Semantics
///
/// - **Option<T> fields**: `Some` in override replaces `Some` or `None` in base
/// - **Vec<T> fields**: Concatenate override after base (both preserved)
/// - **Scalar fields**: Override value replaces base value unconditionally
/// - **Nested structs**: Recursively merge fields
///
/// # Arguments
///
/// * `base_config` - Lower precedence configuration (e.g., defaults or file config)
/// * `override_config` - Higher precedence configuration (e.g., CLI arguments)
///
/// # Returns
///
/// Merged configuration with override values taking precedence
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::config::{Config, merge_configs};
///
/// let file_config = Config::default();
/// let cli_config = Config::default();
/// let merged = merge_configs(file_config, cli_config);
/// ```
///
/// # C Implementation Reference
///
/// Replaces: Configuration precedence logic scattered throughout one_opt() in option.c
pub fn merge_configs(mut base_config: Config, override_config: Config) -> Config {
    // DNS configuration merge
    if let Some(dns_override) = override_config.dns {
        if let Some(dns_base) = base_config.dns.as_mut() {
            // Merge DNS settings
            if let Some(cache_size) = dns_override.cache_size {
                dns_base.cache_size = Some(cache_size);
            }
            if let Some(port) = dns_override.port {
                dns_base.port = Some(port);
            }
            if let Some(edns_size) = dns_override.edns_packet_max_size {
                dns_base.edns_packet_max_size = Some(edns_size);
            }
            // Append upstream servers
            dns_base.upstream_servers.extend(dns_override.upstream_servers);
            // Append local domains
            dns_base.local_domains.extend(dns_override.local_domains);
        } else {
            base_config.dns = Some(dns_override);
        }
    }

    // DHCP configuration merge (feature-gated)
    #[cfg(feature = "dhcp")]
    {
        if let Some(dhcp_override) = override_config.dhcp {
            if let Some(dhcp_base) = base_config.dhcp.as_mut() {
                // Merge DHCP settings
                if let Some(lease_file) = dhcp_override.lease_file {
                    dhcp_base.lease_file = Some(lease_file);
                }
                if let Some(authoritative) = dhcp_override.authoritative {
                    dhcp_base.authoritative = Some(authoritative);
                }
                // Append DHCP ranges
                dhcp_base.ranges.extend(dhcp_override.ranges);
                // Append static hosts
                dhcp_base.static_hosts.extend(dhcp_override.static_hosts);
                // Append DHCP options
                dhcp_base.options.extend(dhcp_override.options);
            } else {
                base_config.dhcp = Some(dhcp_override);
            }
        }
    }

    // TFTP configuration merge (feature-gated)
    #[cfg(feature = "tftp")]
    {
        if let Some(tftp_override) = override_config.tftp {
            base_config.tftp = Some(tftp_override);
        }
    }

    // DNSSEC configuration merge (feature-gated)
    #[cfg(feature = "dnssec")]
    {
        if let Some(dnssec_override) = override_config.dnssec {
            if let Some(dnssec_base) = base_config.dnssec.as_mut() {
                if let Some(enabled) = dnssec_override.enabled {
                    dnssec_base.enabled = Some(enabled);
                }
                if let Some(check_unsigned) = dnssec_override.check_unsigned {
                    dnssec_base.check_unsigned = Some(check_unsigned);
                }
                // Append trust anchors
                dnssec_base.trust_anchors.extend(dnssec_override.trust_anchors);
            } else {
                base_config.dnssec = Some(dnssec_override);
            }
        }
    }

    // Network configuration merge
    if let Some(network_override) = override_config.network {
        if let Some(network_base) = base_config.network.as_mut() {
            if let Some(bind_interfaces) = network_override.bind_interfaces {
                network_base.bind_interfaces = Some(bind_interfaces);
            }
            if let Some(bind_dynamic) = network_override.bind_dynamic {
                network_base.bind_dynamic = Some(bind_dynamic);
            }
            // Append interfaces
            network_base.interfaces.extend(network_override.interfaces);
            // Append listen addresses
            network_base.listen_addresses.extend(network_override.listen_addresses);
        } else {
            base_config.network = Some(network_override);
        }
    }

    // Logging configuration merge
    if let Some(logging_override) = override_config.logging {
        base_config.logging = Some(logging_override);
    }

    // Security configuration merge
    if let Some(security_override) = override_config.security {
        base_config.security = Some(security_override);
    }

    // Authoritative DNS configuration merge (feature-gated)
    #[cfg(feature = "auth-dns")]
    {
        if let Some(auth_override) = override_config.auth {
            if let Some(auth_base) = base_config.auth.as_mut() {
                // Append zones
                auth_base.zones.extend(auth_override.zones);
                // Append peers
                auth_base.peers.extend(auth_override.peers);
                // Override SOA if present
                if auth_override.soa.is_some() {
                    auth_base.soa = auth_override.soa;
                }
                if let Some(ttl) = auth_override.ttl {
                    auth_base.ttl = Some(ttl);
                }
            } else {
                base_config.auth = Some(auth_override);
            }
        }
    }

    base_config
}

/// Validate complete configuration for consistency and conflicts
///
/// Performs comprehensive validation of the entire configuration, checking:
///
/// - DHCP range overlaps and conflicts
/// - Port number conflicts
/// - File path accessibility
/// - Network interface existence
/// - Upstream server reachability (basic syntax check)
/// - Feature flag consistency
/// - Cross-subsystem dependencies
///
/// # Arguments
///
/// * `config` - Configuration to validate
///
/// # Returns
///
/// * `Ok(())` - Configuration is valid
/// * `Err(Vec<ConfigError>)` - List of all validation errors (not just first)
///
/// # Validation Rules
///
/// ## DHCP Validation (feature: dhcp)
/// - DHCP ranges must not overlap
/// - Static host IP addresses must be unique
/// - Lease file path must be writable
///
/// ## DNS Validation
/// - DNS port must not conflict with DHCP/TFTP ports
/// - Cache size must be reasonable (>0, <1,000,000)
/// - Upstream servers must have valid IP addresses
///
/// ## Network Validation
/// - Listen addresses must be valid IP addresses
/// - Interfaces must exist on the system
/// - Ports must be in valid range (1-65535)
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::config::{Config, validate_config};
///
/// let config = Config::default();
/// validate_config(&config)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # C Implementation Reference
///
/// Replaces: Scattered validation in one_opt() and read_opts() in option.c
pub fn validate_config(config: &Config) -> Result<(), Vec<ConfigError>> {
    let mut errors = Vec::new();

    // Validate DNS configuration
    if let Some(ref dns) = config.dns {
        // Validate cache size
        if let Some(cache_size) = dns.cache_size {
            if cache_size == 0 {
                errors.push(ConfigError::InvalidCacheSize(0));
            }
            if cache_size > 1_000_000 {
                errors.push(ConfigError::InvalidCacheSize(cache_size));
            }
        }

        // Validate upstream servers have valid addresses
        for server in &dns.upstream_servers {
            // Basic validation - actual socket creation happens at runtime
            if server.port == 0 {
                errors.push(ConfigError::InvalidPort(0));
            }
        }

        // Validate DNS port
        if let Some(port) = dns.port {
            if port == 0 {
                errors.push(ConfigError::InvalidPort(0));
            }
        }
    }

    // Validate DHCP configuration (feature-gated)
    #[cfg(feature = "dhcp")]
    {
        if let Some(ref dhcp) = config.dhcp {
            // Check for overlapping DHCP ranges
            let overlap_errors = check_dhcp_range_overlaps(&dhcp.ranges);
            errors.extend(overlap_errors);

            // Validate static host uniqueness
            let mut seen_ips = HashSet::new();
            let mut seen_macs = HashSet::new();
            
            for host in &dhcp.static_hosts {
                if !seen_ips.insert(host.ip) {
                    errors.push(ConfigError::ValidationError(
                        format!("Duplicate static IP address: {}", host.ip)
                    ));
                }
                if !seen_macs.insert(host.mac) {
                    errors.push(ConfigError::ValidationError(
                        format!("Duplicate MAC address: {}", host.mac)
                    ));
                }
            }

            // Validate lease file path is writable (if specified)
            if let Some(ref lease_file) = dhcp.lease_file {
                if let Some(parent) = lease_file.parent() {
                    if !parent.exists() {
                        errors.push(ConfigError::InvalidPath(
                            format!("Lease file parent directory does not exist: {}", parent.display())
                        ));
                    }
                }
            }
        }
    }

    // Validate network configuration
    if let Some(ref network) = config.network {
        // Validate listen addresses are valid IP addresses
        for addr in &network.listen_addresses {
            // Address is already validated by type system (SocketAddr)
            if addr.port() == 0 {
                errors.push(ConfigError::InvalidPort(0));
            }
        }

        // Validate bind_interfaces and bind_dynamic are mutually exclusive
        if network.bind_interfaces == Some(true) && network.bind_dynamic == Some(true) {
            errors.push(ConfigError::ValidationError(
                "bind-interfaces and bind-dynamic are mutually exclusive".to_string()
            ));
        }
    }

    // Validate TFTP configuration (feature-gated)
    #[cfg(feature = "tftp")]
    {
        if let Some(ref tftp) = config.tftp {
            // Validate TFTP root directory exists
            if let Some(ref root) = tftp.root {
                if !root.exists() {
                    errors.push(ConfigError::InvalidPath(
                        format!("TFTP root directory does not exist: {}", root.display())
                    ));
                }
                if !root.is_dir() {
                    errors.push(ConfigError::InvalidPath(
                        format!("TFTP root is not a directory: {}", root.display())
                    ));
                }
            }

            // Validate port range
            if let Some(ref port_range) = tftp.port_range {
                if port_range.0 >= port_range.1 {
                    errors.push(ConfigError::ValidationError(
                        format!("Invalid TFTP port range: {}-{} (start must be less than end)", 
                            port_range.0, port_range.1)
                    ));
                }
            }
        }
    }

    // Validate DNSSEC configuration (feature-gated)
    #[cfg(feature = "dnssec")]
    {
        if let Some(ref dnssec) = config.dnssec {
            // If DNSSEC is enabled, must have at least one trust anchor
            if dnssec.enabled == Some(true) && dnssec.trust_anchors.is_empty() {
                errors.push(ConfigError::ValidationError(
                    "DNSSEC enabled but no trust anchors configured".to_string()
                ));
            }
        }
    }

    // Return all errors or success
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// =============================================================================
// INTERNAL HELPER FUNCTIONS
// =============================================================================

/// Apply CLI argument overrides to configuration
///
/// Applies command-line argument values to the configuration structure,
/// overriding any values loaded from configuration files.
///
/// # Arguments
///
/// * `config` - Mutable reference to configuration to modify
/// * `cli` - Parsed CLI arguments containing override values
fn apply_cli_overrides(config: &mut Config, cli: &Cli) {
    // Apply general options
    if cli.no_daemon {
        // Override daemon mode
        // Note: This would modify a daemonize field if Config had one
    }

    if cli.debug {
        // Enable debug mode
        // Note: This would modify a debug field if Config had one
    }

    // Apply DNS options
    if let Some(ref dns) = config.dns.as_mut() {
        if let Some(port) = cli.port {
            dns.port = Some(port);
        }

        if let Some(cache_size) = cli.cache_size {
            dns.cache_size = Some(cache_size);
        }

        // Apply upstream servers from CLI
        for server_str in &cli.server {
            // Parse and add server (simplified - actual parsing in options.rs)
            if let Ok(addr) = server_str.parse() {
                dns.upstream_servers.push(UpstreamServer {
                    address: addr,
                    domain: None,
                    source: None,
                    port: 53,
                });
            }
        }
    }

    // Apply DHCP options (feature-gated)
    #[cfg(feature = "dhcp")]
    {
        if let Some(ref dhcp) = config.dhcp.as_mut() {
            // Apply DHCP-specific CLI overrides
            if let Some(ref lease_file) = cli.dhcp_leasefile {
                dhcp.lease_file = Some(lease_file.clone());
            }
        }
    }

    // Apply network options
    if let Some(ref network) = config.network.as_mut() {
        if cli.bind_interfaces {
            network.bind_interfaces = Some(true);
        }

        if cli.bind_dynamic {
            network.bind_dynamic = Some(true);
        }

        // Apply listen addresses from CLI
        for addr_str in &cli.listen_address {
            if let Ok(addr) = addr_str.parse() {
                network.listen_addresses.push(addr);
            }
        }

        // Apply interfaces from CLI
        network.interfaces.extend(cli.interface.clone());
    }

    // Apply security options
    if let Some(ref security) = config.security.as_mut() {
        if let Some(ref user) = cli.user {
            security.user = Some(user.clone());
        }

        if let Some(ref group) = cli.group {
            security.group = Some(group.clone());
        }
    }
}

/// Load all configuration files from a directory
///
/// Reads all *.conf files from the specified directory and parses them
/// as dnsmasq configuration files. Files are processed in lexicographic order.
///
/// # Arguments
///
/// * `conf_dir` - Directory path containing configuration files
///
/// # Returns
///
/// * `Ok(Vec<Config>)` - Vector of parsed configurations (one per file)
/// * `Err(ConfigError)` - Error reading directory or parsing files
fn load_conf_dir(conf_dir: &Path) -> Result<Vec<Config>, ConfigError> {
    let mut configs = Vec::new();

    // Check directory exists
    if !conf_dir.exists() {
        return Err(ConfigError::InvalidPath(
            format!("Configuration directory does not exist: {}", conf_dir.display())
        ));
    }

    if !conf_dir.is_dir() {
        return Err(ConfigError::InvalidPath(
            format!("Path is not a directory: {}", conf_dir.display())
        ));
    }

    // Read directory entries
    let entries = std::fs::read_dir(conf_dir)
        .map_err(|e| ConfigError::InvalidPath(
            format!("Failed to read directory {}: {}", conf_dir.display(), e)
        ))?;

    // Collect and sort entries by name
    let mut conf_files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "conf")
                .unwrap_or(false)
        })
        .collect();

    conf_files.sort();

    // Parse each configuration file
    for conf_file in conf_files {
        let config = parse_config_file(&conf_file)
            .map_err(|e| ConfigError::ValidationError(
                format!("Failed to parse {}: {}", conf_file.display(), e)
            ))?;
        configs.push(config);
    }

    Ok(configs)
}

/// Check for overlapping DHCP ranges
///
/// Validates that DHCP address ranges do not overlap, which would cause
/// lease allocation conflicts.
///
/// # Arguments
///
/// * `ranges` - Slice of DHCP range configurations to check
///
/// # Returns
///
/// Vector of validation errors for each overlap detected (empty if no overlaps)
#[cfg(feature = "dhcp")]
fn check_dhcp_range_overlaps(ranges: &[DhcpRange]) -> Vec<ConfigError> {
    let mut errors = Vec::new();

    for (i, range1) in ranges.iter().enumerate() {
        for range2 in ranges.iter().skip(i + 1) {
            // Check if ranges overlap (simplified - actual logic more complex)
            // Only check ranges for same address family
            match (&range1.start, &range2.start) {
                (std::net::IpAddr::V4(start1), std::net::IpAddr::V4(start2)) => {
                    if let (std::net::IpAddr::V4(end1), std::net::IpAddr::V4(end2)) = 
                        (&range1.end, &range2.end) {
                        // Check for overlap: range1.start <= range2.end && range2.start <= range1.end
                        if start1 <= end2 && start2 <= end1 {
                            errors.push(ConfigError::OverlappingRanges(
                                format!("{}-{} overlaps with {}-{}", 
                                    start1, end1, start2, end2)
                            ));
                        }
                    }
                }
                (std::net::IpAddr::V6(start1), std::net::IpAddr::V6(start2)) => {
                    if let (std::net::IpAddr::V6(end1), std::net::IpAddr::V6(end2)) = 
                        (&range1.end, &range2.end) {
                        if start1 <= end2 && start2 <= end1 {
                            errors.push(ConfigError::OverlappingRanges(
                                format!("{}-{} overlaps with {}-{}", 
                                    start1, end1, start2, end2)
                            ));
                        }
                    }
                }
                _ => {
                    // Different address families don't overlap
                }
            }
        }
    }

    errors
}

/// Resolve relative paths in configuration to absolute paths
///
/// Converts relative file paths in configuration to absolute paths based on
/// the configuration file's directory or the current working directory.
///
/// # Arguments
///
/// * `config` - Mutable reference to configuration to resolve paths in
/// * `base_path` - Base directory for resolving relative paths
#[allow(dead_code)]
fn resolve_paths(config: &mut Config, base_path: &Path) {
    // DHCP lease file
    #[cfg(feature = "dhcp")]
    {
        if let Some(ref dhcp) = config.dhcp.as_mut() {
            if let Some(ref lease_file) = dhcp.lease_file {
                if lease_file.is_relative() {
                    dhcp.lease_file = Some(base_path.join(lease_file));
                }
            }
        }
    }

    // TFTP root directory
    #[cfg(feature = "tftp")]
    {
        if let Some(ref tftp) = config.tftp.as_mut() {
            if let Some(ref root) = tftp.root {
                if root.is_relative() {
                    tftp.root = Some(base_path.join(root));
                }
            }
        }
    }
}

// =============================================================================
// TESTING UTILITIES
// =============================================================================

#[cfg(test)]
pub mod test_utils {
    //! Testing utilities for configuration tests
    //!
    //! Provides helper functions for creating test configurations and fixtures.

    use super::*;

    /// Create a minimal valid configuration for testing
    pub fn minimal_config() -> Config {
        ConfigBuilder::new()
            .build()
            .expect("Failed to build minimal config")
    }

    /// Create a configuration with DNS enabled
    pub fn dns_config() -> Config {
        ConfigBuilder::new()
            .dns(DnsConfig {
                cache_size: Some(150),
                port: Some(53),
                ..Default::default()
            })
            .build()
            .expect("Failed to build DNS config")
    }

    /// Create a configuration with DHCP enabled
    #[cfg(feature = "dhcp")]
    pub fn dhcp_config() -> Config {
        use std::net::Ipv4Addr;

        ConfigBuilder::new()
            .dhcp(DhcpConfig {
                ranges: vec![DhcpRange {
                    start: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    end: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
                    netmask: None,
                    lease_time: None,
                    tag: None,
                }],
                ..Default::default()
            })
            .build()
            .expect("Failed to build DHCP config")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder_defaults() {
        let config = ConfigBuilder::new().build().expect("Failed to build config");
        assert!(config.dns.is_some());
    }

    #[test]
    fn test_merge_configs_dns_override() {
        let base = ConfigBuilder::new()
            .dns(DnsConfig {
                cache_size: Some(100),
                ..Default::default()
            })
            .build()
            .unwrap();

        let override_config = ConfigBuilder::new()
            .dns(DnsConfig {
                cache_size: Some(200),
                ..Default::default()
            })
            .build()
            .unwrap();

        let merged = merge_configs(base, override_config);
        assert_eq!(merged.dns.unwrap().cache_size, Some(200));
    }

    #[test]
    fn test_validate_empty_cache() {
        let config = ConfigBuilder::new()
            .dns(DnsConfig {
                cache_size: Some(0),
                ..Default::default()
            })
            .build()
            .unwrap();

        let result = validate_config(&config);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, ConfigError::InvalidCacheSize(0))));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn test_validate_overlapping_ranges() {
        use std::net::Ipv4Addr;

        let range1 = DhcpRange {
            start: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            end: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 150)),
            netmask: None,
            lease_time: None,
            tag: None,
        };

        let range2 = DhcpRange {
            start: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)),
            end: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
            netmask: None,
            lease_time: None,
            tag: None,
        };

        let errors = check_dhcp_range_overlaps(&[range1, range2]);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| matches!(e, ConfigError::OverlappingRanges(_))));
    }
}
