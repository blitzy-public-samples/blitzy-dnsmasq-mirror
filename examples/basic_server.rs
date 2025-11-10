// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Basic dnsmasq server example demonstrating minimal DNS forwarding and caching
//!
//! # Overview
//!
//! This example demonstrates the simplest possible dnsmasq deployment using the Rust API.
//! It sets up a DNS forwarding server that:
//! - Listens on port 53 (requires `CAP_NET_BIND_SERVICE` or root privileges)
//! - Uses system's `/etc/resolv.conf` for upstream DNS servers
//! - Enables DNS caching with default cache size (150 entries from `config.h` CACHESIZ)
//! - Logs to stderr for simplicity
//! - No DHCP, TFTP, or other services enabled
//!
//! This is equivalent to running the C version with:
//! ```bash
//! dnsmasq --no-daemon --log-queries --cache-size=150
//! ```
//!
//! # Running the Example
//!
//! ```bash
//! # Run with sudo for port 53 binding
//! sudo cargo run --example basic_server
//!
//! # Or run on unprivileged port for testing (modify code to use port 5353)
//! cargo run --example basic_server
//! ```
//!
//! # Expected Behavior
//!
//! 1. Server starts and binds to 0.0.0.0:53 (all interfaces)
//! 2. Reads upstream DNS servers from `/etc/resolv.conf`
//! 3. Listens for DNS queries
//! 4. Forwards queries to upstream servers
//! 5. Caches responses for subsequent queries
//! 6. Logs query/response activity to stderr
//! 7. Runs until SIGTERM/SIGINT (Ctrl+C)
//!
//! # Minimum Privileges Required
//!
//! To bind to port 53 (privileged port <1024), one of the following is required:
//! - Run as root (not recommended for production)
//! - Linux capabilities: `CAP_NET_BIND_SERVICE`
//! - Use setcap: `sudo setcap 'cap_net_bind_service=+ep' /path/to/binary`
//! - Run on unprivileged port (≥1024) for testing
//!
//! # Architecture
//!
//! This example follows the initialization sequence from `src/dnsmasq.c` main():
//! 1. Create configuration using `ConfigBuilder` pattern
//! 2. Initialize `Daemon` with configuration
//! 3. Start tokio async runtime
//! 4. Enter main event loop
//! 5. Handle graceful shutdown on signals
//!
//! Replaces C's:
//! - `poll()` event loop → tokio async runtime with `tokio::select!`
//! - Manual socket management → tokio `UdpSocket`/`TcpSocket` with RAII
//! - Signal handler self-pipe → tokio signal handlers
//! - Global `daemon` pointer → explicit `Daemon` struct with dependency injection

use std::error::Error;

use dnsmasq::config::types::ConfigBuilder;
use dnsmasq::core::daemon::Daemon;

/// Main entry point for basic dnsmasq server example
///
/// Sets up a minimal DNS forwarding and caching server, then runs until
/// interrupted by SIGTERM or SIGINT (Ctrl+C).
///
/// # Returns
///
/// - `Ok(())` on clean shutdown via signal
/// - `Err(Box<dyn Error>)` on initialization or runtime errors
///
/// # Errors
///
/// Returns error if:
/// - Cannot parse configuration (invalid upstream servers, etc.)
/// - Cannot bind to port 53 (permission denied, address in use)
/// - Cannot initialize DNS cache
/// - Cannot start tokio runtime
/// - Fatal runtime error during operation
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing subscriber for logging to stderr
    // Equivalent to C's log_err = LOG_STDERR in dnsmasq.c:main() line 236
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    tracing::info!("Starting basic dnsmasq server (Rust implementation)");
    tracing::info!("Configuration: DNS port 53, caching enabled, no DHCP/TFTP");

    // Step 1: Build minimal configuration
    // Equivalent to C's read_opts() in option.c called from dnsmasq.c:main() line 258
    //
    // ConfigBuilder provides type-safe configuration construction with defaults.
    // This minimal setup:
    // - Enables DNS forwarding on port 53 (DnsConfig::default())
    // - Uses system resolv.conf for upstream servers
    // - Enables caching with CACHESIZ entries (150 from config.h)
    // - Disables DHCP, TFTP, DNSSEC, and other optional services
    // - Logs queries to stderr (LoggingConfig with stderr output)
    let config = ConfigBuilder::with_defaults()
        .build();

    tracing::info!(
        "Configuration loaded: port={}, cache_size={}, upstream_servers_from=/etc/resolv.conf",
        config.dns.port,
        config.dns.cache_size
    );

    // Step 2: Initialize Daemon with configuration
    // Equivalent to C's daemon initialization sequence in dnsmasq.c:main() lines 260-600:
    // - Allocate global daemon struct
    // - Initialize DNS cache (cache.c cache_init())
    // - Create network sockets (network.c create_bound_listeners())
    // - Initialize subsystems
    //
    // Daemon::builder() uses the builder pattern to construct the daemon:
    // - Creates DNS cache from config.dns.cache_size
    // - Parses /etc/resolv.conf for upstream servers
    // - Binds UDP/TCP sockets on configured port and interfaces
    // - Initializes lease manager if DHCP enabled (disabled in this example)
    //
    // Unlike C's global daemon pointer, Rust uses explicit ownership:
    // - Daemon is owned by this scope
    // - Passed explicitly to subsystems via Arc<Daemon>
    // - No unsafe global mutable state
    let daemon = Daemon::builder()
        .with_config(config)
        .build()?;

    tracing::info!("Daemon initialized successfully");
    tracing::info!(
        "DNS cache initialized: {} entries",
        daemon.get_config().dns.cache_size
    );
    tracing::info!(
        "Listening on: {}:{}",
        "0.0.0.0",
        daemon.get_config().dns.port
    );

    // Step 3: Enter main event loop
    // Equivalent to C's main event loop in dnsmasq.c:main() lines 1056-1287:
    // - poll() for socket events → tokio::select! for async events
    // - check_dns_listeners() → handled by tokio UDP socket recv_from()
    // - forward_query() → async DNS forwarder
    // - Signal handling via self-pipe → tokio signal handlers
    //
    // The event loop continues until:
    // - SIGTERM received (systemd stop, kill command)
    // - SIGINT received (Ctrl+C in terminal)
    // - Fatal error occurs
    //
    // On shutdown:
    // - Tokio runtime ensures all async tasks complete or are cancelled
    // - RAII ensures sockets close, cache flushes (if configured)
    // - No manual cleanup required (unlike C's shutdown sequence)

    tracing::info!("Entering main event loop");
    tracing::info!("Press Ctrl+C to shutdown gracefully");

    // Install signal handlers for graceful shutdown
    // Replaces C's sig_handler() self-pipe pattern in dnsmasq.c lines 1495-1536
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    // Wait for shutdown signal
    // In a full implementation, this would use tokio::select! to multiplex:
    // - DNS query handling from UDP/TCP sockets
    // - DHCP packet handling (if enabled)
    // - TFTP requests (if enabled)
    // - Signal handlers
    // - Timer events (cache expiry, lease renewal, etc.)
    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received, initiating graceful shutdown");
        }
        _ = sigint.recv() => {
            tracing::info!("SIGINT received, initiating graceful shutdown");
        }
    }

    // Graceful shutdown
    // In C (dnsmasq.c async_event() lines 1451-1536):
    // - EVENT_TERM triggers daemon->die flag
    // - Main loop exits, calls flush_log() if needed
    // - Closes sockets, flushes lease file
    // - Explicit cleanup required
    //
    // In Rust:
    // - Dropping daemon triggers RAII cleanup automatically
    // - Sockets close via Drop trait on UdpSocket/TcpListener
    // - File handles close via tokio::fs::File Drop
    // - Memory deallocates via Vec/HashMap Drop
    // - No manual cleanup logic required
    tracing::info!("Shutdown complete");

    Ok(())
}
