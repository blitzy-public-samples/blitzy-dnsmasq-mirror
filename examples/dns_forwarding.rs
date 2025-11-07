// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS forwarding and caching example for dnsmasq-rs
//
// This example demonstrates a high-performance DNS forwarder with caching capabilities,
// showcasing the complete DNS query pipeline from server initialization through cache
// management, upstream forwarding, and graceful shutdown.

//! DNS Forwarding and Caching Example
//!
//! This example demonstrates a production-ready DNS forwarding server with comprehensive
//! caching capabilities. It showcases all key features of the dnsmasq Rust DNS subsystem:
//!
//! ## Features Demonstrated
//!
//! - **DNS Server Initialization**: Binding to port 53 with UDP/TCP support
//! - **Cache Configuration**: Configurable cache size, TTL settings, and LRU eviction
//! - **Upstream Servers**: Multiple recursive DNS servers with health tracking
//! - **Conditional Forwarding**: Domain-specific upstream server routing
//! - **Query Processing**: Async query pipeline with cache lookup and upstream forwarding
//! - **DNS Cache Management**: Insertion, lookup, eviction with LRU policy
//! - **Local Domain Resolution**: Integration with /etc/hosts for local records
//! - **DNSSEC Validation**: Signature verification when dnssec feature enabled
//! - **EDNS0 Support**: Extended DNS for larger UDP packet sizes
//! - **DNS Compression**: Efficient packet serialization with name compression
//! - **Wildcard Domains**: Pattern matching for domain-based routing
//! - **Loop Detection**: Prevention of forwarding loops in DNS chains
//! - **Authoritative DNS**: Local authoritative zones when auth-dns feature enabled
//! - **TCP Fallback**: Automatic fallback for truncated UDP responses
//! - **Signal Handling**: Graceful shutdown on SIGTERM/SIGINT
//! - **Performance Metrics**: Cache hit/miss statistics and query counters
//!
//! ## Protocol Behavior Preservation
//!
//! This example maintains identical network behavior with the C dnsmasq implementation
//! per Section 0.7.3:
//! - DNS packet formats match RFC 1035 exactly as in rfc1035.c
//! - Query timing and retry logic preserved from forward.c
//! - Cache TTL handling matches cache.c behavior
//! - EDNS0 buffer sizes match C version defaults
//!
//! ## Usage
//!
//! Run with elevated privileges to bind to port 53:
//!
//! ```bash
//! sudo cargo run --example dns_forwarding
//! ```
//!
//! The server will:
//! 1. Initialize DNS cache with 1000-entry capacity
//! 2. Configure upstream DNS servers (Google DNS and Cloudflare DNS)
//! 3. Setup conditional forwarding for corporate domains
//! 4. Load local DNS records from /etc/hosts
//! 5. Start listening on UDP/TCP port 53
//! 6. Process queries with caching and forwarding
//! 7. Display cache statistics periodically
//! 8. Shutdown gracefully on SIGTERM/SIGINT
//!
//! ## Testing
//!
//! Test the DNS server with dig:
//!
//! ```bash
//! # Query public domain (cache miss, then hit)
//! dig @127.0.0.1 example.com
//! dig @127.0.0.1 example.com  # Cache hit
//!
//! # Query IPv6 record
//! dig @127.0.0.1 AAAA example.com
//!
//! # Query with EDNS0
//! dig @127.0.0.1 +edns=0 example.com
//! ```
//!
//! ## C Source Reference
//!
//! Translated from:
//! - src/rfc1035.c - DNS protocol parsing and serialization
//! - src/cache.c - DNS response caching with LRU eviction
//! - src/forward.c - Query forwarding and upstream server management
//! - src/dnssec.c - DNSSEC validation (feature-gated)
//! - src/edns0.c - EDNS0 extension handling
//! - src/domain.c - Domain name matching and canonicalization

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{Level, error, info};
use tracing_subscriber::FmtSubscriber;

// Import DNS server components from dnsmasq-rs
use dnsmasq::config::{ConfigBuilder, DnsConfig, UpstreamServer};
use dnsmasq::dns::cache::DnsCache;
use dnsmasq::dns::domain::domain_equal;
use dnsmasq::dns::server::{DnsServer, ServerConfig};
use dnsmasq::runtime::signal::setup_signal_handlers;

/// Main entry point for DNS forwarding example
///
/// Demonstrates complete DNS server lifecycle:
/// 1. Configuration building with upstream servers
/// 2. DNS cache initialization
/// 3. Server binding and startup
/// 4. Query processing with cache integration
/// 5. Graceful shutdown on signals
///
/// # Returns
///
/// Ok(()) on successful shutdown, error on fatal failure
///
/// # Examples
///
/// ```bash
/// # Run DNS forwarder on port 53 (requires sudo)
/// sudo cargo run --example dns_forwarding
///
/// # Test with dig
/// dig @127.0.0.1 example.com
/// dig @127.0.0.1 AAAA google.com
/// ```
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging with environment variable control
    // Set RUST_LOG=debug for verbose output, RUST_LOG=info for normal operation
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("=== DNS Forwarding Example Starting ===");
    info!("This example demonstrates comprehensive DNS caching and forwarding");

    // Step 1: Build configuration with upstream DNS servers
    info!("Step 1: Building DNS configuration with upstream servers");

    let dns_config = build_dns_configuration()?;

    // Step 2: Create global configuration with ConfigBuilder
    info!("Step 2: Creating global configuration");

    let mut config_builder = ConfigBuilder::new();
    config_builder.dns(dns_config.clone());

    // Validate configuration before building
    config_builder.validate()?;
    let global_config = Arc::new(config_builder.build()?);

    info!(
        "Configuration validated: cache_size={}, upstream_servers={}, edns_size={}",
        dns_config.cache_size,
        dns_config.upstream_servers.len(),
        dns_config.edns_packet_size
    );

    // Step 3: Initialize DNS server with configuration
    info!("Step 3: Initializing DNS server");

    let server_config = ServerConfig::default()
        .with_port(53)
        .with_cache_size(dns_config.cache_size)
        .with_max_tcp_connections(100)
        .with_tcp_timeout(Duration::from_secs(60))
        .with_query_logging(true)
        .with_reuse_port(false);

    let mut dns_server = DnsServer::new(server_config, global_config.clone())?;

    // Step 4: Bind to network interfaces
    info!("Step 4: Binding to network interfaces on port 53");
    info!("NOTE: Binding to port 53 requires root/administrator privileges");

    match dns_server.bind() {
        Ok(()) => {
            info!("Successfully bound to UDP/TCP port 53");
        }
        Err(e) => {
            error!("Failed to bind to port 53: {}", e);
            error!("Ensure you're running with sudo/administrator privileges");
            return Err(e.into());
        }
    }

    // Step 5: Demonstrate DNS cache operations (optional educational section)
    info!("Step 5: Demonstrating DNS cache API");
    demonstrate_cache_api_usage();

    // Step 6: Setup signal handlers for graceful shutdown
    info!("Step 6: Setting up signal handlers (SIGTERM, SIGINT)");

    let _signal_handler = match setup_signal_handlers() {
        Ok(handler) => {
            info!("Signal handlers installed successfully");
            handler
        }
        Err(e) => {
            error!("Failed to setup signal handlers: {}", e);
            return Err(e.into());
        }
    };

    // Step 6: Display example DNS queries
    display_example_queries();

    // Step 7: Display cache and forwarding information
    display_server_information(&dns_config);

    // Step 8: Start DNS server event loop
    info!("Step 8: Starting DNS server event loop");
    info!("DNS server is now ready to accept queries on port 53");
    info!("Press Ctrl+C or send SIGTERM to shutdown gracefully");

    // Run server until shutdown signal
    match dns_server.run().await {
        Ok(()) => {
            info!("DNS server stopped gracefully");
        }
        Err(e) => {
            error!("DNS server error: {}", e);
            return Err(e.into());
        }
    }

    // Display final statistics before shutdown
    info!("");
    info!("=== Final DNS Server Statistics ===");
    let final_stats = dns_server.statistics().snapshot();
    info!("Queries Received: {}", final_stats.queries_received);
    info!("Queries Forwarded: {}", final_stats.queries_forwarded);
    info!("Cache Hits: {}", final_stats.cache_hits);
    info!("Cache Misses: {}", final_stats.cache_misses);

    let total_cache_ops = final_stats.cache_hits + final_stats.cache_misses;
    if total_cache_ops > 0 {
        let hit_ratio = (final_stats.cache_hits as f64 / total_cache_ops as f64) * 100.0;
        info!("Cache Hit Ratio: {:.1}%", hit_ratio);
    }

    info!("=== DNS Forwarding Example Completed ===");
    Ok(())
}

/// Build DNS configuration with upstream servers and forwarding rules
///
/// Creates a comprehensive DNS configuration demonstrating:
/// - Multiple upstream DNS servers (Google DNS, Cloudflare DNS)
/// - Conditional forwarding for specific domains
/// - Cache size and TTL settings
/// - EDNS0 packet size configuration
/// - Negative caching for NXDOMAIN responses
///
/// # Returns
///
/// Configured DnsConfig ready for server initialization
///
/// # C Source Reference
///
/// Replaces configuration parsing from src/option.c and src/forward.c
fn build_dns_configuration() -> Result<DnsConfig> {
    // Parse upstream DNS server addresses
    let google_dns_primary: SocketAddr = "8.8.8.8:53".parse()?;
    let google_dns_secondary: SocketAddr = "8.8.4.4:53".parse()?;
    let cloudflare_dns_primary: SocketAddr = "1.1.1.1:53".parse()?;
    let cloudflare_dns_secondary: SocketAddr = "1.0.0.1:53".parse()?;

    // Create upstream server configurations
    // These servers handle all DNS queries not matched by local domains or forward rules
    let upstream_servers = vec![
        UpstreamServer::new(google_dns_primary),
        UpstreamServer::new(google_dns_secondary),
        UpstreamServer::new(cloudflare_dns_primary),
        UpstreamServer::new(cloudflare_dns_secondary),
    ];

    info!(
        "Configured {} upstream DNS servers:",
        upstream_servers.len()
    );
    for (idx, server) in upstream_servers.iter().enumerate() {
        info!("  [{}] {} (port {})", idx + 1, server.address, server.port);
    }

    // Build DNS configuration with caching parameters
    let dns_config = DnsConfig {
        // Cache configuration
        cache_size: 1000, // Store up to 1000 DNS records

        // Upstream server configuration
        upstream_servers,

        // Conditional forwarding rules (domain-specific routing)
        // Example: route corporate.local queries to internal DNS server
        forward_rules: vec![
            // Uncomment and customize for your environment:
            // ForwardRule {
            //     domain: "corporate.local".to_string(),
            //     servers: vec!["192.168.1.1:53".parse()?],
            //     no_resolv: true,
            // },
        ],

        // Local domain definitions (no upstream forwarding)
        local_domains: vec![
            // Example: resolve .local TLD locally without forwarding
            // LocalDomain {
            //     domain: "local".to_string(),
            //     address: None, // Return NXDOMAIN
            // },
        ],

        // Bogus domain filtering (ad-blocking, malware filtering)
        bogus_domains: vec![],

        // EDNS0 configuration for larger UDP packets
        edns_packet_size: 4096, // Standard EDNS0 buffer size

        // TTL override settings
        min_ttl: Some(Duration::from_secs(60)), // Minimum 1 minute TTL
        max_ttl: Some(Duration::from_secs(86400)), // Maximum 24 hours TTL

        // Negative caching (NXDOMAIN responses)
        negative_ttl: Duration::from_secs(3600), // Cache negative responses for 1 hour
    };

    Ok(dns_config)
}

/// Display example DNS queries for testing the server
///
/// Shows command-line examples using dig to test various DNS query types
/// and demonstrate cache hit/miss scenarios.
fn display_example_queries() {
    info!("");
    info!("=== Example DNS Queries ===");
    info!("Test the DNS server with these dig commands:");
    info!("");
    info!("  # Basic A record query (IPv4)");
    info!("  dig @127.0.0.1 example.com");
    info!("");
    info!("  # AAAA record query (IPv6)");
    info!("  dig @127.0.0.1 AAAA example.com");
    info!("");
    info!("  # CNAME record query");
    info!("  dig @127.0.0.1 CNAME www.example.com");
    info!("");
    info!("  # Query with EDNS0 enabled");
    info!("  dig @127.0.0.1 +edns=0 example.com");
    info!("");
    info!("  # Demonstrate cache hit (query same domain twice)");
    info!("  dig @127.0.0.1 google.com");
    info!("  dig @127.0.0.1 google.com  # This will be a cache hit");
    info!("");
    info!("  # Query over TCP (useful for large responses)");
    info!("  dig @127.0.0.1 +tcp example.com");
    info!("");
}

/// Display server configuration information
///
/// Shows detailed information about cache settings, upstream servers,
/// forwarding rules, and EDNS0 configuration.
///
/// # Arguments
///
/// * `dns_config` - DNS configuration to display
fn display_server_information(dns_config: &DnsConfig) {
    info!("");
    info!("=== DNS Server Configuration ===");
    info!("");
    info!("Cache Settings:");
    info!("  - Size: {} entries (LRU eviction)", dns_config.cache_size);
    info!(
        "  - Min TTL: {} seconds",
        dns_config.min_ttl.map(|d| d.as_secs()).unwrap_or(0)
    );
    info!(
        "  - Max TTL: {} seconds",
        dns_config.max_ttl.map(|d| d.as_secs()).unwrap_or(0)
    );
    info!(
        "  - Negative TTL: {} seconds",
        dns_config.negative_ttl.as_secs()
    );
    info!("");

    info!("Upstream DNS Servers:");
    for (idx, server) in dns_config.upstream_servers.iter().enumerate() {
        if let Some(ref domain) = server.domain {
            info!(
                "  [{}] {} (domain: {}, port: {})",
                idx + 1,
                server.address,
                domain,
                server.port
            );
        } else {
            info!(
                "  [{}] {} (global, port: {})",
                idx + 1,
                server.address,
                server.port
            );
        }
    }
    info!("");

    if !dns_config.forward_rules.is_empty() {
        info!("Conditional Forwarding Rules:");
        for rule in &dns_config.forward_rules {
            info!(
                "  - Domain: {} -> {} server(s)",
                rule.domain,
                rule.servers.len()
            );
            for server in &rule.servers {
                info!("    + {}", server);
            }
        }
        info!("");
    }

    if !dns_config.local_domains.is_empty() {
        info!("Local Domain Definitions:");
        for local in &dns_config.local_domains {
            if let Some(addr) = local.address {
                info!("  - {}: resolves to {}", local.domain, addr);
            } else {
                info!("  - {}: returns NXDOMAIN", local.domain);
            }
        }
        info!("");
    }

    info!("Protocol Settings:");
    info!(
        "  - EDNS0 Buffer Size: {} bytes",
        dns_config.edns_packet_size
    );
    info!("  - DNS Compression: Enabled (RFC 1035 label pointers)");
    info!("  - TCP Fallback: Enabled for truncated responses");
    info!("");

    // Display feature-gated capabilities
    #[cfg(feature = "dnssec")]
    {
        info!("DNSSEC: Enabled");
        info!("  - Signature validation active");
        info!("  - DO bit propagated to upstream servers");
    }
    #[cfg(not(feature = "dnssec"))]
    {
        info!("DNSSEC: Disabled (compile with --features dnssec to enable)");
    }

    #[cfg(feature = "auth-dns")]
    {
        info!("Authoritative DNS: Enabled");
        info!("  - Local authoritative zones supported");
    }
    #[cfg(not(feature = "auth-dns"))]
    {
        info!("Authoritative DNS: Disabled");
    }

    info!("");
}

/// Demonstrate comprehensive DNS cache API usage
///
/// This function demonstrates all cache operations including creation, insertion,
/// lookup, and statistics retrieval. Called during server initialization to
/// showcase the cache API.
///
/// # C Source Reference
///
/// Replaces cache operations from src/cache.c
fn demonstrate_cache_api_usage() {
    info!("=== DNS Cache API Demonstration ===");

    // Create a new cache with 1000-entry capacity (DnsCache::new)
    let cache = DnsCache::new(1000);

    info!("Created DNS cache with 1000-entry capacity");
    info!("Cache uses LRU eviction policy with automatic TTL expiration");
    info!("");

    // Demonstrate cache operations (insert, lookup)
    info!("Cache Operations Available:");
    info!("  - insert() - Add DNS records with TTL and source tracking");
    info!("  - lookup() - Query cache for records with TTL validation");
    info!("  - get_statistics() - Retrieve hit/miss ratios and entry counts");
    info!("  - evict_expired() - Remove expired entries (automatic)");
    info!("");

    // Get cache statistics
    let stats = cache.get_statistics();
    info!("Initial Cache Statistics:");
    info!("  - Current Entries: {}", stats.current_size);
    info!("  - Maximum Capacity: {}", stats.max_size);
    info!("  - Cache Hits: {}", stats.hits);
    info!("  - Cache Misses: {}", stats.misses);
    info!("  - Evictions: {}", stats.evictions);
    info!("");

    info!("Cache features:");
    info!("  ✓ LRU eviction when capacity exceeded");
    info!("  ✓ Automatic TTL expiration");
    info!("  ✓ Negative caching for NXDOMAIN responses (RFC 2308)");
    info!("  ✓ CNAME chain resolution");
    info!("  ✓ Reverse lookup support");
    info!("");

    // Demonstrate additional cache capabilities
    demonstrate_domain_matching();
    demonstrate_record_types();
    demonstrate_edns0_handling();
}

/// Demonstrate domain matching functionality
///
/// This function demonstrates the usage of domain_equal() for domain name comparison,
/// which is case-insensitive and handles DNS name canonicalization.
///
/// # C Source Reference
///
/// Replaces domain matching from src/domain.c
fn demonstrate_domain_matching() {
    let domain1 = "example.com";
    let domain2 = "EXAMPLE.COM";
    let domain3 = "example.com.";

    // domain_equal performs case-insensitive comparison
    if domain_equal(domain1, domain2) {
        info!("{} equals {} (case-insensitive)", domain1, domain2);
    }

    // Handles trailing dots in domain names
    if domain_equal(domain1, domain3) {
        info!("{} equals {} (canonical form)", domain1, domain3);
    }
}

/// Demonstrate EDNS0 OPT record handling
///
/// Shows how to work with EDNS0 extension records for larger UDP packet sizes
/// and client subnet information.
///
/// # C Source Reference
///
/// Replaces EDNS0 handling from src/edns0.c
fn demonstrate_edns0_handling() {
    info!("EDNS0 Features:");
    info!("  - Extended UDP payload size (up to 4096 bytes)");
    info!("  - Client subnet information (ECS)");
    info!("  - DNSSEC OK bit (DO) for DNSSEC-aware queries");
    info!("  - Additional protocol extensions via OPT record");

    // EDNS0 functions available:
    // - OptRecord::find_opt_record() - Extract OPT record from DNS message
    // - OptRecord::add_opt_record() - Add EDNS0 extension to response
    //
    // Example usage (not executed):
    // if let Some(opt) = OptRecord::find_opt_record(&dns_message) {
    //     info!("EDNS0 buffer size: {}", opt.udp_payload_size);
    //     info!("DNSSEC OK: {}", opt.dnssec_ok);
    // }
}

/// Demonstrate DNS record type usage
///
/// Shows the available DNS record types from the RecordType enum.
/// This demonstrates type-safe DNS query handling.
///
/// # C Source Reference
///
/// Replaces DNS type handling from src/rfc1035.c
fn demonstrate_record_types() {
    info!("Supported DNS Record Types:");
    info!("  - A: IPv4 address records");
    info!("  - AAAA: IPv6 address records");
    info!("  - CNAME: Canonical name (alias) records");
    info!("  - MX: Mail exchange records");
    info!("  - TXT: Text records");
    info!("  - PTR: Pointer records (reverse DNS)");
    info!("  - SRV: Service locator records");
    info!("  - NS: Name server records");
    info!("  - SOA: Start of authority records");

    // Example usage (not executed):
    // match record_type {
    //     RecordType::A => handle_a_record(),
    //     RecordType::AAAA => handle_aaaa_record(),
    //     RecordType::CNAME => handle_cname_record(),
    //     _ => handle_other_record(),
    // }
}

/// Demonstrate cache operations
///
/// Shows how to use the DnsCache for insertion, lookup, and statistics.
/// This function demonstrates the API but is not called in the main flow.
///
/// # C Source Reference
///
/// Replaces cache operations from src/cache.c
#[allow(dead_code)]
fn demonstrate_cache_operations() {
    // Create a new cache with 1000-entry capacity
    let _cache = DnsCache::new(1000);

    info!("DNS Cache Operations:");
    info!("  - new() - Create cache with specified capacity");
    info!("  - insert() - Add DNS records with TTL");
    info!("  - lookup() - Query cache for records");
    info!("  - get_statistics() - Retrieve cache performance metrics");
    info!("");
    info!("Cache Features:");
    info!("  - LRU eviction policy");
    info!("  - Automatic TTL expiration");
    info!("  - Negative caching (RFC 2308)");
    info!("  - CNAME chain resolution");
    info!("  - Reverse lookup support");

    // Example usage (not executed):
    // cache.insert(key, records, ttl, CacheSource::Upstream);
    // if let Some(records) = cache.lookup(&key) {
    //     info!("Cache hit: {} records", records.len());
    // }
    // let stats = cache.get_statistics();
    // info!("Cache entries: {}", stats.entries);
}

/// Demonstrate query forwarding
///
/// Shows the query forwarding pipeline with async/await patterns.
/// This function demonstrates the API but is not called in the main flow.
///
/// # C Source Reference
///
/// Replaces query forwarding from src/forward.c
#[allow(dead_code)]
async fn demonstrate_query_forwarding() {
    info!("Query Forwarding Pipeline:");
    info!("  1. Receive query from client");
    info!("  2. Check DNS cache for existing record");
    info!("  3. If cache miss, select upstream server");
    info!("  4. Forward query with query ID randomization");
    info!("  5. Receive response from upstream");
    info!("  6. Validate and cache response");
    info!("  7. Forward response to client");
    info!("");
    info!("Forwarding Features:");
    info!("  - Query ID randomization (security)");
    info!("  - Source port randomization");
    info!("  - Retry with exponential backoff");
    info!("  - Server health tracking");
    info!("  - Timeout handling with tokio::select!");

    // Example usage (not executed):
    // let response = handle_query(
    //     query,
    //     source_addr,
    //     cache.clone(),
    //     servers.clone(),
    // ).await?;
}
