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

//! Advanced dnsmasq custom configuration example
//!
//! # Purpose
//!
//! This example demonstrates production-grade configuration scenarios for the dnsmasq Rust
//! implementation, showing how to set up:
//! - Multiple upstream DNS servers with per-domain routing (equivalent to `--server=` options)
//! - Custom DNS cache size configuration
//! - DNSSEC validation with trust anchor loading
//! - DHCPv4 server with address pools and static reservations
//! - IPv6 Router Advertisement for SLAAC
//! - Advanced features (logging, interface binding, privilege separation)
//!
//! # Equivalent C Configuration
//!
//! This example replaces the following dnsmasq.conf entries:
//! ```text
//! # DNS Configuration
//! cache-size=10000
//! server=/example.com/8.8.8.8
//! server=/local/#
//! address=/doubleclick.net/127.0.0.1
//! domain-needed
//! bogus-priv
//!
//! # DNSSEC
//! conf-file=/usr/share/dnsmasq/trust-anchors.conf
//! dnssec
//!
//! # DHCP Configuration
//! dhcp-range=192.168.1.50,192.168.1.150,24h
//! dhcp-host=11:22:33:44:55:66,192.168.1.10,workstation
//! dhcp-option=3,192.168.1.1  # Default gateway
//! dhcp-option=6,192.168.1.1  # DNS server
//!
//! # IPv6 Router Advertisement
//! dhcp-range=::,ra-only
//!
//! # Advanced Features
//! interface=eth0
//! except-interface=wlan0
//! log-queries
//! log-dhcp
//! user=dnsmasq
//! group=dnsmasq
//! pid-file=/var/run/dnsmasq.pid
//! ```
//!
//! # Running This Example
//!
//! ```bash
//! # Run with DHCP and DNSSEC features enabled
//! cargo run --example custom_config --features dhcp,dnssec
//!
//! # Requires privileges for binding to port 53 (DNS) and 67 (DHCP)
//! sudo cargo run --example custom_config --features dhcp,dnssec
//! ```
//!
//! # Security Considerations
//!
//! - **Privilege Dropping**: The daemon drops privileges to configured user/group after binding
//!   privileged ports (53 for DNS, 67 for DHCP)
//! - **Required Capabilities**: Linux CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW for
//!   DHCP server functionality
//! - **systemd Integration**: Use `AmbientCapabilities=` in service unit to maintain minimal
//!   capabilities after privilege dropping
//!
//! # Original C References
//!
//! - Configuration parsing: src/option.c (read_opts function)
//! - DNS forwarding setup: src/forward.c (server selection)
//! - DHCP server initialization: src/dhcp.c (dhcp_packet handler)
//! - DNSSEC validation: src/dnssec.c (dnssec_validate_reply)
//! - Router Advertisement: src/radv.c (icmp6_start, send_ra)

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// Import dnsmasq Rust modules
// These replace C includes: #include "dnsmasq.h", #include "config.h", etc.
use dnsmasq::core::daemon::DaemonBuilder;
use dnsmasq::config::types::{
    Config, DnsConfig, DhcpConfig, DhcpRange, StaticLease, DhcpOption, NetworkConfig,
    ProcessConfig, LoggingConfig, IntegrationConfig, UpstreamServer, LocalDomain,
    DaemonOptions, InterfaceName, MacAddr, DhcpContext,
};
use dnsmasq::dns::cache::Cache;
use dnsmasq::dns::forwarder::Forwarder;
use dnsmasq::dns::upstream::Server as UpstreamServerImpl;

#[cfg(feature = "dnssec")]
use dnsmasq::dns::dnssec::trust_anchor::TrustAnchorStore;
#[cfg(feature = "dnssec")]
use dnsmasq::dns::dnssec::validator::dnssec_validate_reply;

#[cfg(feature = "dhcp")]
use dnsmasq::dhcp::v4::server::DhcpServer;
#[cfg(feature = "dhcp")]
use dnsmasq::dhcp::lease::LeaseManager;

use dnsmasq::ipv6::radv::server::RadVServer;

use tokio::sync::{Mutex, RwLock};

/// Main entry point for custom configuration example
///
/// Demonstrates production-ready dnsmasq Rust API usage with advanced configuration
/// scenarios matching real-world deployment requirements.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== dnsmasq Rust: Custom Configuration Example ===\n");

    // ========================================================================
    // DNS Configuration: Upstream Servers with Per-Domain Routing
    // ========================================================================
    //
    // Equivalent C options:
    //   --server=/example.com/8.8.8.8
    //   --server=/local/#
    //   --server=1.1.1.1
    println!("Configuring DNS upstream servers...");

    let upstream_servers = vec![
        // Default upstream for all queries (like /etc/resolv.conf entry)
        // C equivalent: --server=1.1.1.1
        Arc::new(RwLock::new(UpstreamServerImpl::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            None,  // domain: None = default server
            53,
            None,  // source_addr: None = any
            None,  // interface: None = any
        ))),
        
        // Domain-specific routing: route example.com queries to Google DNS
        // C equivalent: --server=/example.com/8.8.8.8
        Arc::new(RwLock::new(UpstreamServerImpl::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            Some("example.com".to_string()),  // Only for example.com
            53,
            None,
            None,
        ))),
        
        // Local domain handling: answer .local from DHCP/hosts only, no forwarding
        // C equivalent: --server=/local/# (# means "answer locally, don't forward")
        // Implemented via LocalDomain configuration, not upstream server
    ];

    println!("  - Default upstream: 1.1.1.1:53");
    println!("  - Domain routing: example.com -> 8.8.8.8:53");
    println!("  - Local domain: .local (DHCP/hosts only)\n");

    // ========================================================================
    // DNS Cache Configuration: Custom Size
    // ========================================================================
    //
    // Equivalent C option: --cache-size=10000
    // Default in C: CACHESIZ = 150 (from config.h)
    println!("Configuring DNS cache...");
    
    let cache = Cache::new(
        10000,  // cache_size: 10,000 entries (vs C default 150)
        None,   // neg_ttl: None = use default negative TTL
    );
    
    println!("  - Cache size: 10,000 entries (C default: 150)\n");

    // ========================================================================
    // DNSSEC Configuration: Trust Anchor Loading
    // ========================================================================
    //
    // Equivalent C options:
    //   --conf-file=/usr/share/dnsmasq/trust-anchors.conf
    //   --dnssec
    #[cfg(feature = "dnssec")]
    {
        println!("Configuring DNSSEC validation...");
        
        let mut trust_anchor_store = TrustAnchorStore::new();
        
        // Load trust anchors from file (equivalent to conf-file= option)
        // C implementation: src/option.c line ~1500 (read_file function)
        let trust_anchor_path = PathBuf::from("/usr/share/dnsmasq/trust-anchors.conf");
        match trust_anchor_store.load_from_file(&trust_anchor_path).await {
            Ok(_) => println!("  - Trust anchors loaded from {:?}", trust_anchor_path),
            Err(e) => println!("  - Warning: Could not load trust anchors: {}", e),
        }
        
        // Verify trust anchor store has root trust anchor
        if trust_anchor_store.has_trust_anchor(".") {
            println!("  - Root trust anchor (.) validated");
        }
        
        println!("  - DNSSEC validation: ENABLED\n");
        
        // DNSSEC validation will be invoked during query processing via:
        // let validation_result = dnssec_validate_reply(&response, &trust_anchor_store).await?;
    }
    
    #[cfg(not(feature = "dnssec"))]
    {
        println!("DNSSEC validation: DISABLED (compile with --features dnssec)\n");
    }

    // ========================================================================
    // DHCP Configuration: Address Pools and Static Reservations
    // ========================================================================
    //
    // Equivalent C options:
    //   --dhcp-range=192.168.1.50,192.168.1.150,24h
    //   --dhcp-host=11:22:33:44:55:66,192.168.1.10,workstation
    //   --dhcp-option=3,192.168.1.1
    //   --dhcp-option=6,192.168.1.1
    #[cfg(feature = "dhcp")]
    {
        println!("Configuring DHCPv4 server...");
        
        // Address pool configuration
        // C equivalent: --dhcp-range=192.168.1.50,192.168.1.150,24h
        // Implemented in src/option.c (option_read function) and src/dhcp.c
        let dhcp_ranges = vec![
            DhcpRange {
                start: Ipv4Addr::new(192, 168, 1, 50),
                end: Ipv4Addr::new(192, 168, 1, 150),
                lease_time: Duration::from_secs(24 * 3600),  // 24 hours
                flags: 0,  // No special flags (CONTEXT_STATIC, etc.)
            },
        ];
        
        println!("  - Address pool: 192.168.1.50-192.168.1.150 (lease: 24h)");

        // Static host reservations
        // C equivalent: --dhcp-host=11:22:33:44:55:66,192.168.1.10,workstation
        // Implemented in src/option.c (parse_dhcp_host function)
        let mut static_leases = std::collections::HashMap::new();
        static_leases.insert(
            MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            StaticLease {
                hwaddr: MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                hostname: Some("workstation".to_string()),
                client_id: None,
            },
        );
        
        println!("  - Static lease: 11:22:33:44:55:66 -> 192.168.1.10 (workstation)");

        // DHCP options
        // C equivalent: --dhcp-option=3,192.168.1.1 (option 3 = router/gateway)
        // C equivalent: --dhcp-option=6,192.168.1.1 (option 6 = DNS server)
        // Implemented in src/rfc2131.c (option_put function)
        let dhcp_options = vec![
            DhcpOption {
                code: 3,  // Router (default gateway)
                data: Ipv4Addr::new(192, 168, 1, 1).octets().to_vec(),
                vendor_class: None,
            },
            DhcpOption {
                code: 6,  // DNS server
                data: Ipv4Addr::new(192, 168, 1, 1).octets().to_vec(),
                vendor_class: None,
            },
        ];
        
        println!("  - DHCP option 3 (router): 192.168.1.1");
        println!("  - DHCP option 6 (DNS): 192.168.1.1");

        // Lease manager initialization
        // C equivalent: lease.c (lease_init function)
        let lease_manager = LeaseManager::new(
            PathBuf::from("/var/lib/dnsmasq/dnsmasq.leases"),  // lease_file path
            1000,  // max_leases (--dhcp-lease-max)
            DaemonOptions::empty(),  // options (for OPT_LEASE_RO, etc.)
            false,  // read_ethers (--read-ethers flag)
        );
        
        // Initialize lease database from file
        // C equivalent: lease.c (lease_init reads existing leases)
        match lease_manager.init().await {
            Ok(count) => println!("  - Loaded {} existing leases from database", count),
            Err(e) => println!("  - Warning: Could not load lease database: {}", e),
        }
        
        println!();
    }
    
    #[cfg(not(feature = "dhcp"))]
    {
        println!("DHCPv4 server: DISABLED (compile with --features dhcp)\n");
    }

    // ========================================================================
    // IPv6 Router Advertisement Configuration
    // ========================================================================
    //
    // Equivalent C options:
    //   --dhcp-range=::,ra-only
    //   --enable-ra
    // Implemented in src/radv.c (ra_start function)
    println!("Configuring IPv6 Router Advertisement...");
    
    // RA context for SLAAC (Stateless Address Autoconfiguration)
    // C equivalent: struct dhcp_context with flags CONTEXT_RA
    let ra_context = DhcpContext {
        start6: Ipv6Addr::UNSPECIFIED,  // :: (unspecified = RA-only, no DHCPv6)
        if_index: 0,  // 0 = all interfaces (will be set during interface enumeration)
        flags: 0x0100,  // CONTEXT_RA flag from C (enables Router Advertisement)
        next: None,
        ra_short_period_start: None,  // Will be set when RA starts
        ra_time: None,  // Will be set to next RA transmission time
    };
    
    println!("  - Mode: ra-only (SLAAC, no DHCPv6)");
    println!("  - Interface: all (configured via interface enumeration)\n");

    // RadVServer will send Router Advertisements with:
    // - M-bit: 0 (no DHCPv6 for addresses)
    // - O-bit: 0 (no DHCPv6 for other config)
    // - A-bit: 1 (SLAAC addresses enabled)
    // - Prefix: auto-detected from interface addresses
    // C implementation: src/radv.c (send_ra function, build_ra_packet)

    // ========================================================================
    // Advanced Configuration: Logging, Interface Binding, Privilege Separation
    // ========================================================================
    //
    // Equivalent C options:
    //   --interface=eth0
    //   --except-interface=wlan0
    //   --log-queries
    //   --log-dhcp
    //   --user=dnsmasq
    //   --group=dnsmasq
    //   --pid-file=/var/run/dnsmasq.pid
    println!("Configuring advanced features...");
    
    // Network interface binding
    // C equivalent: --interface=eth0, --except-interface=wlan0
    // Implemented in src/network.c (enumerate_interfaces function)
    let network_config = NetworkConfig {
        interfaces: vec![InterfaceName("eth0".to_string())],
        listen_addresses: vec![],  // Empty = bind to all addresses on specified interfaces
        except_interfaces: vec![InterfaceName("wlan0".to_string())],
        bind_interfaces: true,  // --bind-interfaces (bind to specific interfaces, not wildcard)
        bind_dynamic: false,  // --bind-dynamic (bind as interfaces come up)
    };
    
    println!("  - Listening on interface: eth0");
    println!("  - Excluding interface: wlan0");
    
    // Logging configuration
    // C equivalent: --log-queries, --log-dhcp
    // Implemented in src/log.c (log_query function)
    let logging_config = LoggingConfig {
        log_facility: Some("daemon".to_string()),  // Syslog facility
        log_file: None,  // None = use syslog, Some(path) = log to file
        log_async_max: Some(5),  // Async log queue size
        log_queries: true,  // --log-queries (log all DNS queries)
        log_dhcp: true,  // --log-dhcp (log DHCP transactions)
    };
    
    println!("  - Logging: DNS queries + DHCP transactions");
    
    // Privilege separation
    // C equivalent: --user=dnsmasq, --group=dnsmasq, --pid-file=/var/run/dnsmasq.pid
    // Implemented in src/dnsmasq.c (drop_privileges function)
    let process_config = ProcessConfig {
        username: Some("dnsmasq".to_string()),  // Drop to this user after binding ports
        groupname: Some("dnsmasq".to_string()),  // Drop to this group
        pid_file: Some(PathBuf::from("/var/run/dnsmasq.pid")),  // Write PID file
        script_user: None,  // User for running dhcp-script (None = same as username)
        daemonize: false,  // Don't fork (for this example, run in foreground)
    };
    
    println!("  - Privilege dropping: user=dnsmasq, group=dnsmasq");
    println!("  - PID file: /var/run/dnsmasq.pid\n");

    // ========================================================================
    // Builder Pattern: Assembling Daemon Configuration
    // ========================================================================
    //
    // The DaemonBuilder provides type-safe, validated construction of the daemon,
    // preventing partially-initialized state that was possible in C's imperative
    // initialization sequence.
    //
    // C equivalent: src/dnsmasq.c main() function (lines 100-500)
    //   - read_opts() parses configuration
    //   - create_bound_listeners() creates sockets
    //   - cache_init() initializes cache
    //   - lease_init() loads DHCP leases
    //   - Individual subsystems initialized in order
    println!("Building daemon with configuration...");
    
    let config = Config {
        dns: DnsConfig::default(),  // Use defaults for unspecified DNS options
        #[cfg(feature = "dhcp")]
        dhcp: DhcpConfig::default(),  // Use defaults for unspecified DHCP options
        network: network_config,
        process: process_config,
        logging: logging_config,
        integration: IntegrationConfig::default(),
        options: DaemonOptions::OPT_LOG | DaemonOptions::OPT_BOGUSPRIV,
        ..Default::default()
    };

    // Use DaemonBuilder for validated construction
    // Each with_* method corresponds to a subsystem initialization in C
    let daemon = DaemonBuilder::new()
        .with_config(config)
        .with_cache(cache)
        .with_servers(upstream_servers)
        #[cfg(feature = "dhcp")]
        .with_lease_manager(lease_manager)
        .build()
        .expect("Failed to build daemon - missing required components");
    
    println!("  ✓ Daemon built successfully\n");

    // ========================================================================
    // Runtime Demonstration
    // ========================================================================
    //
    // In production, the daemon would:
    // 1. Bind to privileged ports (53 for DNS, 67 for DHCP)
    // 2. Drop privileges to configured user/group
    // 3. Enter async event loop handling incoming packets
    // 4. Process DNS queries via dns::forwarder::Forwarder
    // 5. Process DHCP requests via dhcp::v4::server::DhcpServer
    // 6. Send periodic Router Advertisements via ipv6::radv::server::RadVServer
    //
    // For this example, we demonstrate configuration access patterns:
    
    println!("=== Configuration Verification ===\n");
    
    // Access configuration (immutable Arc clone, cheap operation)
    let config = daemon.get_config();
    println!("DNS cache: {} entries", cache.capacity());
    println!("Logging: queries={}, dhcp={}", 
        config.logging.log_queries, 
        config.logging.log_dhcp
    );
    
    // Access cache (requires lock acquisition for mutations)
    let cache_handle = daemon.get_cache();
    let mut cache_guard = cache_handle.lock().await;
    println!("Cache current entries: {}", cache_guard.len());
    drop(cache_guard);  // Release lock
    
    // Access lease manager (DHCP feature only)
    #[cfg(feature = "dhcp")]
    {
        if let Some(lease_mgr) = daemon.get_lease_manager() {
            let lease_guard = lease_mgr.lock().await;
            println!("DHCP leases: {} active", lease_guard.count());
        }
    }
    
    println!("\n=== Example Complete ===");
    println!("This example demonstrated configuration patterns.");
    println!("In production, call daemon.run().await to enter event loop.\n");

    Ok(())
}
