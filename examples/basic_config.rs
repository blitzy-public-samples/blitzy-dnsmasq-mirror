// Copyright (C) 2024 Blitzy Platform - dnsmasq Rust Port
// This file is part of the dnsmasq Rust implementation.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Basic dnsmasq configuration example demonstrating programmatic config building
//!
//! This example demonstrates how to configure dnsmasq-rs programmatically using the
//! Rust configuration API, including:
//! - Building configuration with the ConfigBuilder pattern
//! - Setting up DNS forwarding with upstream servers and cache
//! - Configuring DHCP address ranges and lease settings
//! - Loading configuration from dnsmasq.conf files (100% backward compatible)
//! - Command-line argument parsing with clap
//! - Configuration validation and error handling
//! - Feature flag conditional compilation for optional subsystems
//!
//! # Source Reference
//!
//! This example replaces typical C usage patterns from:
//! - `src/option.c` - Configuration parsing (read_opts(), one_opt())
//! - `src/config.h` - Default values and compile-time constants
//! - `dnsmasq.conf.example` - Configuration file syntax and common patterns
//!
//! # Usage
//!
//! Run this example with:
//! ```bash
//! cargo run --example basic_config --features dhcp
//! ```
//!
//! With environment-based log filtering:
//! ```bash
//! RUST_LOG=debug cargo run --example basic_config --features dhcp
//! ```

use std::path::PathBuf;

use anyhow::Result;
use tracing::warn;
use tracing_subscriber::FmtSubscriber;

// Import configuration types and builders from dnsmasq
use dnsmasq::config::{
    ConfigBuilder,
    parse_config_file,
    Cli,
};

// Import default constants
use dnsmasq::config::defaults::DEFAULT_LEASE_TIME_V4_SECS;

// Feature-gated DHCP imports
#[cfg(feature = "dhcp")]
use dnsmasq::config::DhcpConfig;

fn main() -> Result<()> {
    // Initialize structured logging with environment-based filtering
    // RUST_LOG environment variable controls log level (e.g., RUST_LOG=debug)
    FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("=== dnsmasq-rs Basic Configuration Example ===\n");

    // =========================================================================
    // EXAMPLE 1: Programmatic Configuration with ConfigBuilder
    // =========================================================================
    println!("--- Example 1: Programmatic Configuration Building ---");
    
    // Create a new configuration builder
    let mut builder = ConfigBuilder::new();
    
    // Configure DNS settings
    println!("Configuring DNS forwarding...");
    let dns_config = dnsmasq::config::DnsConfig {
        // Set cache size for DNS records (LRU eviction when full)
        cache_size: 1000,
        
        // Add upstream DNS servers for query forwarding
        upstream_servers: vec![
            dnsmasq::config::UpstreamServer {
                address: "8.8.8.8:53".parse()?,
                domain: None,  // Used for all domains
                source: None,  // No specific source interface
                port: 53,
            },
            dnsmasq::config::UpstreamServer {
                address: "8.8.4.4:53".parse()?,
                domain: None,
                source: None,
                port: 53,
            },
        ],
        
        // TTL settings for cache management
        min_ttl: Some(300),      // Minimum cache TTL: 5 minutes
        max_ttl: Some(86400),    // Maximum cache TTL: 24 hours
        negative_ttl: 3600,      // Negative response cache: 1 hour
        
        // EDNS0 packet size for large responses (DNSSEC-friendly)
        edns_packet_size: 4096,
        
        // Additional DNS settings
        port: 53,
        domain_needed: false,    // Forward plain names without dots
        bogus_priv: false,       // Forward queries for private IP ranges
        no_resolv: false,        // Read /etc/resolv.conf for upstream servers
        no_poll: false,          // Poll resolv files for changes
        strict_order: false,     // Try upstream servers in order vs. fastest
        all_servers: false,      // Query all servers, not just first responding
        
        ..Default::default()
    };
    builder.dns(dns_config);
    println!("  ✓ DNS configured with 2 upstream servers (Google DNS)");
    println!("  ✓ Cache size: 1000 records");
    println!("  ✓ TTL range: 5 minutes to 24 hours");

    // Configure network settings
    println!("\nConfiguring network interfaces...");
    let network_config = dnsmasq::config::NetworkConfig {
        port: 53,                    // Standard DNS port
        bind_interfaces: true,       // Bind only to specified interfaces
        bind_dynamic: false,         // Don't bind to dynamic interfaces
        interfaces: vec![],          // Empty = bind to all interfaces
        listen_addresses: vec![],    // Empty = listen on all addresses
        except_interfaces: vec![],   // Interfaces to exclude
        no_dhcp_interfaces: vec![],  // Interfaces with DNS-only (no DHCP)
        
        ..Default::default()
    };
    builder.network(network_config);
    println!("  ✓ Network configured for port 53");
    println!("  ✓ Bind mode: interface binding enabled");

    // Configure DHCP (only if dhcp feature is enabled)
    #[cfg(feature = "dhcp")]
    {
        println!("\nConfiguring DHCP server...");
        let dhcp_config = DhcpConfig {
            // Define DHCP address range
            ranges: vec![
                dnsmasq::config::DhcpRange {
                    start: "192.168.1.50".parse()?,
                    end: "192.168.1.150".parse()?,
                    lease_time: std::time::Duration::from_secs(DEFAULT_LEASE_TIME_V4_SECS as u64),
                    netmask: Some("255.255.255.0".parse()?),
                    broadcast: None,
                    tags: vec![],
                },
            ],
            
            // Static host assignments
            static_hosts: vec![
                dnsmasq::config::DhcpStaticHost {
                    mac: "00:11:22:33:44:55".parse()?,
                    ip: "192.168.1.10".parse()?,
                    hostname: Some("server1".to_string()),
                    lease_time: None,  // Use default lease time
                    tags: vec![],
                },
            ],
            
            // DHCP options to send to clients
            options: vec![
                // Option 3: Router (default gateway)
                dnsmasq::config::DhcpOption {
                    tag: None,
                    code: 3,
                    value: dnsmasq::config::DhcpOptionValue::IpAddress("192.168.1.1".parse()?),
                    force: false,
                },
                // Option 6: DNS servers
                dnsmasq::config::DhcpOption {
                    tag: None,
                    code: 6,
                    value: dnsmasq::config::DhcpOptionValue::IpAddressList(vec![
                        "192.168.1.1".parse()?,
                    ]),
                    force: false,
                },
            ],
            
            // Lease file path for persistence
            lease_file: Some(PathBuf::from("/var/lib/dnsmasq/dnsmasq.leases")),
            
            // Additional DHCP settings
            authoritative: false,     // Not authoritative for subnet
            rapid_commit: false,      // DHCPv4 rapid commit
            
            ..Default::default()
        };
        builder.dhcp(dhcp_config);
        
        println!("  ✓ DHCP range: 192.168.1.50 - 192.168.1.150");
        println!("  ✓ Default lease time: {} seconds ({})", 
                 DEFAULT_LEASE_TIME_V4_SECS,
                 humanize_duration(std::time::Duration::from_secs(DEFAULT_LEASE_TIME_V4_SECS as u64)));
        println!("  ✓ Static host: 00:11:22:33:44:55 → 192.168.1.10 (server1)");
        println!("  ✓ Gateway: 192.168.1.1");
    }
    
    #[cfg(not(feature = "dhcp"))]
    {
        println!("\nDHCP configuration skipped (feature 'dhcp' not enabled)");
        warn!("To enable DHCP, rebuild with: cargo build --features dhcp");
    }

    // Validate and build the configuration
    println!("\nValidating configuration...");
    builder.validate()?;
    println!("  ✓ Configuration validation passed");
    
    let config = builder.build()?;
    println!("  ✓ Configuration built successfully");
    
    println!("\nFinal configuration summary:");
    println!("  - DNS cache size: {}", config.dns.cache_size);
    println!("  - Upstream servers: {}", config.dns.upstream_servers.len());
    println!("  - Listen port: {}", config.network.port);
    #[cfg(feature = "dhcp")]
    {
        println!("  - DHCP ranges: {}", config.dhcp.ranges.len());
        println!("  - Static hosts: {}", config.dhcp.static_hosts.len());
    }

    // =========================================================================
    // EXAMPLE 2: Loading Configuration from File
    // =========================================================================
    println!("\n\n--- Example 2: Loading from Configuration File ---");
    
    // Demonstrate loading from a dnsmasq.conf file (100% backward compatible)
    let conf_file_path = PathBuf::from("/etc/dnsmasq.conf");
    
    println!("Attempting to load configuration from: {}", conf_file_path.display());
    
    // Note: This will fail if the file doesn't exist, which is expected in most environments
    match parse_config_file(&conf_file_path) {
        Ok(loaded_config) => {
            println!("  ✓ Configuration loaded successfully from file");
            println!("  - DNS cache size: {}", loaded_config.dns.cache_size);
            println!("  - Upstream servers: {}", loaded_config.dns.upstream_servers.len());
        }
        Err(e) => {
            // This is expected if the file doesn't exist
            println!("  ℹ Configuration file not found (this is normal for examples)");
            println!("  Error: {}", e);
            println!("\n  To use file-based configuration:");
            println!("    1. Create /etc/dnsmasq.conf or specify path with --conf-file");
            println!("    2. Use dnsmasq.conf syntax (see dnsmasq.conf.example)");
            println!("    3. Example contents:");
            println!("       # Upstream DNS servers");
            println!("       server=8.8.8.8");
            println!("       server=1.1.1.1");
            println!("       # DNS cache size");
            println!("       cache-size=1000");
            println!("       # DHCP range (if dhcp feature enabled)");
            println!("       dhcp-range=192.168.1.50,192.168.1.150,12h");
        }
    }

    // =========================================================================
    // EXAMPLE 3: Command-Line Argument Parsing
    // =========================================================================
    println!("\n\n--- Example 3: Command-Line Argument Parsing ---");
    
    // Demonstrate CLI parsing (normally called with Cli::parse() from main args)
    // Here we simulate with hardcoded arguments
    println!("Simulating CLI arguments: dnsmasq --port=5353 --cache-size=2000");
    
    let simulated_cli = Cli::parse_from(&[
        "dnsmasq",
        "--port=5353",
        "--cache-size=2000",
        "--server=1.1.1.1",
    ]);
    
    println!("  ✓ CLI arguments parsed successfully");
    println!("  - Port: {:?}", simulated_cli.port);
    println!("  - Cache size: {:?}", simulated_cli.cache_size);
    println!("  - Servers: {:?}", simulated_cli.servers);
    
    println!("\nMerging CLI arguments with config builder...");
    let mut cli_builder = ConfigBuilder::new();
    
    // Apply CLI settings (CLI takes precedence over config file)
    let mut cli_dns_config = dnsmasq::config::DnsConfig::default();
    if let Some(cache_size) = simulated_cli.cache_size {
        cli_dns_config.cache_size = cache_size;
    }
    if let Some(port) = simulated_cli.port {
        cli_dns_config.port = port;
    }
    // Add servers from CLI
    for server_str in simulated_cli.servers.iter() {
        if let Ok(addr) = server_str.parse() {
            cli_dns_config.upstream_servers.push(dnsmasq::config::UpstreamServer {
                address: addr,
                domain: None,
                source: None,
                port: 53,
            });
        }
    }
    cli_builder.dns(cli_dns_config);
    
    let cli_config = cli_builder.build()?;
    println!("  ✓ CLI configuration built successfully");
    println!("  - Final DNS port: {}", cli_config.dns.port);
    println!("  - Final cache size: {}", cli_config.dns.cache_size);

    // =========================================================================
    // EXAMPLE 4: Error Handling and Validation
    // =========================================================================
    println!("\n\n--- Example 4: Configuration Validation and Error Handling ---");
    
    // Demonstrate validation catching invalid configurations
    println!("Testing invalid configuration (cache size = 0 with caching enabled)...");
    
    let mut invalid_builder = ConfigBuilder::new();
    let invalid_dns_config = dnsmasq::config::DnsConfig {
        cache_size: 0,  // Zero cache size
        ..Default::default()
    };
    invalid_builder.dns(invalid_dns_config);
    
    match invalid_builder.validate() {
        Ok(_) => println!("  ℹ Configuration accepted (cache-size=0 disables caching)"),
        Err(e) => println!("  ✗ Validation error: {}", e),
    }
    
    println!("\nDemonstrating type-safe configuration:");
    println!("  ✓ Port numbers validated at compile time (u16)");
    println!("  ✓ IP addresses validated at parse time (std::net::IpAddr)");
    println!("  ✓ Durations type-safe (std::time::Duration)");
    println!("  ✓ Paths type-safe (std::path::PathBuf)");
    println!("  ✓ Invalid states prevented by Rust's type system");

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n\n=== Configuration Examples Complete ===");
    println!("\nKey takeaways:");
    println!("  1. Use ConfigBuilder for programmatic configuration");
    println!("  2. Load from files with parse_config_file() for backward compatibility");
    println!("  3. Parse CLI args with Cli::parse() (command line takes precedence)");
    println!("  4. Validate with builder.validate() before build()");
    println!("  5. Use feature flags for conditional compilation of subsystems");
    println!("  6. Rust's type system prevents invalid configurations at compile time");
    
    println!("\nNext steps:");
    println!("  - See examples/dns_forwarding.rs for DNS-specific examples");
    println!("  - See examples/dhcp_server.rs for DHCP configuration");
    println!("  - See dnsmasq.conf.example for full configuration reference");
    println!("  - Run with RUST_LOG=debug for detailed logging");

    Ok(())
}

/// Helper function to format durations in human-readable format
fn humanize_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    
    if secs < 60 {
        format!("{} seconds", secs)
    } else if secs < 3600 {
        format!("{} minutes", secs / 60)
    } else if secs < 86400 {
        format!("{} hours", secs / 3600)
    } else {
        format!("{} days", secs / 86400)
    }
}
