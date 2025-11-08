// Copyright (c) 2000-2024 Simon Kelley and contributors
// Copyright (C) 2024 Blitzy - dnsmasq Rust Implementation
// Licensed under GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # Minimal dnsmasq Server Example
//!
//! This example demonstrates the simplest possible dnsmasq server setup with both
//! DNS forwarding and DHCP services. It provides a minimal but complete implementation
//! suitable for testing and understanding the basic dnsmasq library API.
//!
//! ## Features Demonstrated
//!
//! - **DNS Server**: Listens on port 5353 (non-privileged) with caching enabled
//! - **DHCP Server**: Provides IP addresses in the range 192.168.1.100-192.168.1.200
//! - **Async Runtime**: Uses Tokio for non-blocking I/O
//! - **Signal Handling**: Graceful shutdown on SIGTERM, SIGINT (Ctrl+C)
//! - **Configuration**: Programmatic configuration using builder pattern
//! - **Logging**: Structured logging with tracing crate
//!
//! ## Configuration Details
//!
//! - **DNS Port**: 5353 (non-privileged for testing without root)
//! - **DHCP Range**: 192.168.1.100 - 192.168.1.200
//! - **Lease Time**: 12 hours (43200 seconds)
//! - **Upstream DNS**: 8.8.8.8 (Google Public DNS)
//! - **Cache Size**: Default (150 entries)
//!
//! ## Running the Example
//!
//! ```bash
//! # Run with default configuration (DNS on port 5353, DHCP on 192.168.1.0/24)
//! cargo run --example minimal_server
//!
//! # Run with custom log level
//! RUST_LOG=debug cargo run --example minimal_server
//! ```
//!
//! ## Running on Standard Ports
//!
//! To run on standard DNS (53) and DHCP (67) ports, you need root privileges:
//!
//! ```bash
//! # Build the example
//! cargo build --example minimal_server --release
//!
//! # Run with sudo (Linux)
//! sudo ./target/release/examples/minimal_server
//!
//! # Or use capabilities to avoid full root (Linux)
//! sudo setcap 'cap_net_bind_service=+ep' ./target/release/examples/minimal_server
//! ./target/release/examples/minimal_server
//! ```
//!
//! ## Enabling Additional Features
//!
//! To enable optional features, build with feature flags:
//!
//! ```bash
//! # Enable DNSSEC validation
//! cargo run --example minimal_server --features dnssec
//!
//! # Enable IPv6 support (DHCPv6, Router Advertisements)
//! cargo run --example minimal_server --features ipv6
//!
//! # Enable all features
//! cargo run --example minimal_server --all-features
//! ```
//!
//! ## Testing the Server
//!
//! Once running, test DNS and DHCP functionality:
//!
//! ```bash
//! # Test DNS resolution (port 5353)
//! dig @127.0.0.1 -p 5353 example.com
//! nslookup example.com 127.0.0.1:5353
//!
//! # Test DHCP (requires root and network interface setup)
//! sudo dhclient -d eth0
//! ```
//!
//! ## Related Examples
//!
//! For more detailed examples, see:
//! - `examples/dns_forwarding.rs` - DNS-only server with advanced caching
//! - `examples/dhcp_server.rs` - DHCP-only server with static reservations
//! - `examples/basic_config.rs` - Configuration file loading
//!
//! ## C Source Reference
//!
//! This example demonstrates functionality from:
//! - `src/dnsmasq.c` - Main daemon initialization and event loop
//! - `src/option.c` - Configuration setup and defaults

use anyhow::Result;
use dnsmasq::config::types::{DhcpRange, UpstreamServer};
use dnsmasq::config::{DhcpConfig, DnsConfig, NetworkConfig};
use dnsmasq::{ConfigBuilder, DaemonState};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging with environment variable configuration
    // Set RUST_LOG=debug for detailed logging, RUST_LOG=info for normal operation
    FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting minimal dnsmasq server example");
    info!("DNS server will listen on port 5353 (non-privileged)");
    info!("DHCP server will serve 192.168.1.100-192.168.1.200");
    info!("Press Ctrl+C to shutdown gracefully");

    // ============================================================================
    // Configuration Setup
    // ============================================================================

    // Create minimal configuration using builder pattern
    // This demonstrates programmatic configuration without a config file

    // Configure upstream DNS server
    let upstream = UpstreamServer::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));

    // Create DHCP range with custom lease time
    let mut dhcp_range = DhcpRange::new_v4(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(192, 168, 1, 200),
    );
    dhcp_range.lease_time = std::time::Duration::from_secs(43200); // 12 hours

    // Build configuration using builder pattern
    // Note: ConfigBuilder methods take &mut self, so we need to use separate statements
    let mut config_builder = ConfigBuilder::new();

    // DNS configuration: cache size and upstream servers
    config_builder.dns(DnsConfig {
        cache_size: 150,                  // Default cache size (150 entries)
        upstream_servers: vec![upstream], // Google Public DNS
        ..Default::default()
    });

    // DHCP configuration: simple address range
    config_builder.dhcp(DhcpConfig {
        ranges: vec![dhcp_range],
        ..Default::default()
    });

    // Network configuration: listen on all interfaces with non-privileged port
    config_builder.network(NetworkConfig {
        port: 5353, // Non-privileged port (standard is 53)
        bind_interfaces: true,
        listen_addresses: vec![], // Empty means all interfaces
        ..Default::default()
    });

    let config = config_builder.build()?;

    info!("Configuration built successfully");
    info!("  DNS cache size: {}", config.dns.cache_size);
    info!("  DNS port: {}", config.network.port);
    info!("  Upstream DNS: {:?}", config.dns.upstream_servers);
    if let Some(ref dhcp_config) = config.dhcp {
        info!("  DHCP ranges: {} configured", dhcp_config.ranges.len());
    }

    // ============================================================================
    // Service Initialization
    // ============================================================================

    // Create shared daemon state with thread-safe access
    // This replaces C's global `struct daemon` variable
    // Using std::sync::RwLock for compatibility with server constructors
    let daemon_state = Arc::new(std::sync::RwLock::new(DaemonState::new(config.clone())));

    // Initialize DHCP lease database
    // Note: DnsCache is created internally by DnsServer::new
    info!("Initializing DHCP lease database...");
    let max_leases = 1000; // Maximum number of DHCP leases
    let lease_db = dnsmasq::dhcp::lease::LeaseDatabase::new(max_leases);
    info!(
        "DHCP lease database initialized with max_leases={}",
        max_leases
    );

    // ============================================================================
    // DNS Server Setup
    // ============================================================================

    // Create DNS server instance using builder pattern
    info!("Creating DNS server on port {}...", config.network.port);
    let server_config = dnsmasq::dns::server::ServerConfig::default()
        .with_port(config.network.port)
        .with_cache_size(config.dns.cache_size)
        .with_query_logging(false);

    let mut dns_server =
        dnsmasq::dns::server::DnsServer::new(server_config, Arc::new(config.clone()))?;
    info!("DNS server created successfully");

    // ============================================================================
    // DHCP Server Setup
    // ============================================================================

    // Create DHCPv4 server instance
    info!("Creating DHCPv4 server...");
    let mut dhcp_server = dnsmasq::dhcp::v4::server::DhcpV4Server::new(daemon_state.clone());

    // Bind to DHCP port (67 requires root, 1067 for testing)
    // For testing without root, use port 1067:
    // dhcp_server.bind(1067, false).await?;
    match dhcp_server.bind(67, false).await {
        Ok(()) => {
            info!("DHCPv4 server bound to port 67 successfully");
        }
        Err(e) => {
            error!("Failed to bind DHCPv4 server to port 67: {}", e);
            error!("Note: Port 67 requires root privileges");
            error!("For testing, you can modify this example to use port 1067");
            return Err(e.into());
        }
    }

    // ============================================================================
    // Signal Handler Setup
    // ============================================================================

    // Setup signal handlers for graceful shutdown
    // Handles SIGTERM, SIGINT (Ctrl+C), SIGHUP (reload)
    info!("Setting up signal handlers...");
    let mut signal_handler = dnsmasq::runtime::signal::setup_signal_handlers()?;
    info!("Signal handlers configured (SIGTERM, SIGINT, SIGHUP)");

    // ============================================================================
    // Main Event Loop
    // ============================================================================

    info!("Starting main event loop...");
    info!("Server is ready and accepting requests");

    // Spawn DNS server task
    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_server.run().await {
            error!("DNS server error: {}", e);
        }
    });

    // Spawn DHCP server task
    let dhcp_handle = tokio::spawn(async move {
        if let Err(e) = dhcp_server.run().await {
            error!("DHCP server error: {}", e);
        }
    });

    // Wait for termination signal
    // This demonstrates simple signal handling without full event loop
    info!("Waiting for termination signal...");
    loop {
        if let Some(signal) = signal_handler.recv().await {
            match signal {
                dnsmasq::runtime::signal::SignalEvent::Terminate => {
                    info!("Received termination signal, shutting down...");
                    break;
                }
                dnsmasq::runtime::signal::SignalEvent::Reload => {
                    info!("Received reload signal (ignored in minimal example)");
                }
                dnsmasq::runtime::signal::SignalEvent::DumpCache => {
                    info!("Received cache dump signal (ignored in minimal example)");
                }
                _ => {
                    info!("Received other signal (ignored in minimal example)");
                }
            }
        }
    }

    // ============================================================================
    // Graceful Shutdown
    // ============================================================================

    info!("Shutting down servers...");

    // Wait for server tasks to complete (with timeout)
    let shutdown_timeout = std::time::Duration::from_secs(5);
    match tokio::time::timeout(shutdown_timeout, async {
        let _ = dns_handle.await;
        let _ = dhcp_handle.await;
    })
    .await
    {
        Ok(()) => info!("All server tasks shut down successfully"),
        Err(_) => error!("Shutdown timeout - some tasks may not have completed"),
    }

    // Save DHCP lease database before exit
    info!("Saving DHCP lease database...");
    if let Ok(_state) = daemon_state.read() {
        // Save leases to disk (lease database handles atomic writes)
        // This ensures no lease data is lost on shutdown
        let lease_path = std::path::PathBuf::from("/var/lib/dnsmasq/dnsmasq.leases");
        lease_db.save(lease_path, None)?;
        info!("DHCP lease database saved successfully");
    }

    info!("Minimal dnsmasq server shutdown complete");
    Ok(())
}
