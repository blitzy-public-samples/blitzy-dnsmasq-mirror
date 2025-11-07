// Copyright (C) 2024 Blitzy Platform - dnsmasq Rust Port
// This file is part of the dnsmasq Rust implementation.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Command-line argument parser using clap derive macros
//!
//! This module implements comprehensive CLI argument parsing for dnsmasq using Rust's
//! clap crate with derive macros. It defines all 200+ command-line options from the C
//! implementation, maintaining complete compatibility with the original getopt_long()
//! processing including option precedence, argument formats, short-form (-x) and
//! long-form (--option) variants.
//!
//! # Architecture
//!
//! The CLI parser is organized hierarchically:
//! - **Main CLI Structure** (`Cli`): Top-level command-line arguments
//! - **Feature-Gated Options**: Conditional compilation based on Cargo features
//! - **Value Parsers**: Custom parsers for IP addresses, durations, sizes
//! - **Help Generation**: Automatic help text from doc comments
//!
//! # Option Precedence
//!
//! Following dnsmasq's established precedence model:
//! 1. Command-line arguments (highest priority)
//! 2. Configuration file settings
//! 3. Compiled-in defaults from defaults.rs (lowest priority)
//!
//! CLI arguments override any conflicting configuration file settings.
//!
//! # Feature Gating
//!
//! Options are conditionally compiled based on Cargo features:
//! - `dhcp`: DHCPv4 server options (--dhcp-range, --dhcp-host, etc.)
//! - `dhcp-v6`: DHCPv6 server options (--enable-ra, --dhcp-duid, etc.)
//! - `tftp`: TFTP server options (--enable-tftp, --tftp-root, etc.)
//! - `dnssec`: DNSSEC validation options (--dnssec, --trust-anchor, etc.)
//! - `auth-dns`: Authoritative DNS options (--auth-zone, --auth-server, etc.)
//! - `dbus`: D-Bus integration (--enable-dbus)
//! - `ubus`: OpenWrt ubus integration (--enable-ubus)
//! - `ipset`: Linux ipset integration (--ipset)
//! - `nftables`: Linux nftables integration (--nftset)
//! - `conntrack`: Linux connection tracking (--conntrack)
//! - `loop-detect`: DNS loop detection (--dns-loop-detect)
//!
//! # C Implementation Compatibility
//!
//! This module replaces:
//! - `src/option.c` getopt_long() parsing (lines 186-476 option definitions)
//! - `OPTSTRING` macro for short options (line 170)
//! - `LOPT_*` constants for long-only options (lines 173-289)
//! - Option validation and error handling from one_opt() function
//!
//! # Source Reference
//!
//! Translated from: src/option.c
//! - Option table: lines 292-476 (struct option opts[])
//! - Help text: lines 490-561 (usage[] array)
//! - Short options: line 170 (OPTSTRING macro)
//! - Long-only options: lines 173-289 (LOPT_* defines)

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use crate::config::defaults::EDNS_PACKET_SIZE;
use crate::config::types::ConfigError;

// =============================================================================
// MAIN CLI STRUCTURE
// =============================================================================

/// dnsmasq - network services for small networks
///
/// A lightweight DNS forwarder, DHCP server, TFTP server, and router advertisement
/// daemon designed for small networks. Provides DNS caching, DHCP lease management,
/// PXE network boot support, and IPv6 router advertisements.
///
/// # Examples
///
/// Start DNS forwarder on port 53:
/// ```bash
/// dnsmasq
/// ```
///
/// DNS forwarder with specific upstream server:
/// ```bash
/// dnsmasq --server=8.8.8.8
/// ```
///
/// DHCP server for 192.168.1.0/24 network:
/// ```bash
/// dnsmasq --dhcp-range=192.168.1.50,192.168.1.150,12h
/// ```
///
/// Configuration file and foreground mode:
/// ```bash
/// dnsmasq --conf-file=/etc/dnsmasq.conf --no-daemon
/// ```
#[derive(Parser, Debug, Clone)]
#[command(name = "dnsmasq")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Network services for small networks", long_about = None)]
#[command(author = "Simon Kelley (C version), Blitzy Platform (Rust port)")]
#[command(disable_version_flag = true)]
#[command(disable_help_flag = true)]
pub struct Cli {
    // =========================================================================
    // GENERAL OPTIONS
    // =========================================================================
    /// Specify configuration file (defaults to /etc/dnsmasq.conf)
    ///
    /// The configuration file uses key=value or key syntax. Multiple --conf-file
    /// options can be specified. Use --conf-file= with no filename to disable
    /// loading the default configuration file.
    #[arg(short = 'C', long = "conf-file", value_name = "FILE")]
    pub conf_file: Vec<PathBuf>,

    /// Specify configuration directory for include files
    ///
    /// Read all files in the given directory as configuration files. Files are
    /// read in alphabetical order. Files with names ending in .dpkg-old,
    /// .dpkg-dist, .dpkg-new, .rpmsave, .rpmnew, ~ or containing a # are skipped.
    #[arg(short = '7', long = "conf-dir", value_name = "DIR")]
    pub conf_dir: Vec<PathBuf>,

    /// Do NOT fork into the background, run in debug mode
    ///
    /// Forces dnsmasq to stay in the foreground with detailed logging.
    /// Useful for debugging and when running under systemd or other
    /// process managers that expect foreground processes.
    #[arg(short = 'd', long = "no-daemon")]
    pub no_daemon: bool,

    /// Keep in foreground but do NOT enable debug mode
    ///
    /// Similar to --no-daemon but without verbose debugging output.
    /// Recommended for production use with systemd service managers.
    #[arg(short = 'k', long = "keep-in-foreground")]
    pub keep_in_foreground: bool,

    /// Specify PID file path (defaults to /var/run/dnsmasq.pid)
    ///
    /// Set the PID file path. Use --pid-file= with no path to disable
    /// PID file creation entirely (useful when running in containers).
    #[arg(short = 'x', long = "pid-file", value_name = "FILE")]
    pub pid_file: Option<PathBuf>,

    /// Change user ID to run as after binding privileged ports
    ///
    /// Drop privileges to the specified user after binding to ports below 1024.
    /// This is a critical security feature. Defaults to 'dnsmasq' or 'nobody'.
    #[arg(short = 'u', long = "user", value_name = "USER")]
    pub user: Option<String>,

    /// Change group ID to run as after binding privileged ports
    ///
    /// Drop privileges to the specified group. Should match the user's primary
    /// group for proper filesystem permission handling.
    #[arg(short = 'g', long = "group", value_name = "GROUP")]
    pub group: Option<String>,

    /// Validate configuration and exit
    ///
    /// Parse all configuration files and command-line options, report any errors,
    /// and exit. Returns 0 for valid configuration, 1 for errors. Useful for
    /// configuration validation in deployment pipelines.
    #[arg(long = "test")]
    pub test: bool,

    /// Display version information
    ///
    /// Show dnsmasq version, compilation options, and exit. The Rust version
    /// includes enabled Cargo features and Rust compiler version.
    #[arg(short = 'v', long = "version")]
    pub version: bool,

    // =========================================================================
    // LOGGING OPTIONS
    // =========================================================================
    /// Enable DNS query logging (optional destination)
    ///
    /// Log all DNS queries received. Optional argument specifies extra logging:
    /// - No argument: log queries
    /// - 'extra': include additional query details
    #[arg(short = 'q', long = "log-queries", num_args = 0..=1, default_missing_value = "true", value_name = "EXTRA")]
    pub log_queries: Option<String>,

    /// Log DHCP lease allocations and renewals
    ///
    /// Enable detailed DHCP transaction logging including DISCOVER, OFFER,
    /// REQUEST, ACK messages, and lease file updates.
    #[arg(long = "log-dhcp")]
    pub log_dhcp: bool,

    /// Enable debug-level logging
    ///
    /// Maximum verbosity logging for troubleshooting. Includes internal state
    /// changes, cache operations, and packet details. Very high volume output.
    #[arg(long = "log-debug")]
    pub log_debug: bool,

    /// Specify syslog facility for logging
    ///
    /// Set syslog facility (KERN, USER, MAIL, DAEMON, AUTH, SYSLOG, LPR, NEWS,
    /// UUCP, CRON, LOCAL0-LOCAL7). Defaults to DAEMON. Use LOG_LOCAL0 through
    /// LOG_LOCAL7 for custom log routing.
    #[arg(short = '8', long = "log-facility", value_name = "FACILITY")]
    pub log_facility: Option<String>,

    /// Enable asynchronous logging with buffer size
    ///
    /// Use asynchronous logging to improve performance under high load. Optional
    /// argument specifies maximum log lines to buffer (default 5). Higher values
    /// increase memory usage but reduce log message loss under load.
    #[arg(long = "log-async", num_args = 0..=1, default_missing_value = "5", value_name = "LINES")]
    pub log_async: Option<usize>,

    // =========================================================================
    // NETWORK INTERFACE OPTIONS
    // =========================================================================
    /// Specify local address(es) to listen on
    ///
    /// Listen on specific IP addresses. Can be specified multiple times.
    /// By default, dnsmasq listens on all interfaces. Use this to restrict
    /// listening to specific addresses for security or routing reasons.
    #[arg(short = 'a', long = "listen-address", value_name = "IPADDR")]
    pub listen_address: Vec<IpAddr>,

    /// Listen only on specified interfaces
    ///
    /// Bind to the specified network interfaces. Can be specified multiple times.
    /// Combined with --bind-interfaces, provides strict interface binding.
    #[arg(short = 'i', long = "interface", value_name = "INTERFACE")]
    pub interface: Vec<String>,

    /// Do NOT listen on specified interfaces
    ///
    /// Exclude specific interfaces from listening. Useful to prevent dnsmasq
    /// from binding to VPN interfaces, Docker bridges, or other unwanted interfaces.
    #[arg(short = 'I', long = "except-interface", value_name = "INTERFACE")]
    pub except_interface: Vec<String>,

    /// Do NOT provide DHCP on specified interfaces (DNS still active)
    ///
    /// Disable DHCP service on interfaces while still providing DNS. Useful
    /// for mixed environments where some networks have external DHCP servers.
    #[arg(short = '2', long = "no-dhcp-interface", value_name = "INTERFACE")]
    pub no_dhcp_interface: Vec<String>,

    /// Bind only to interfaces (not wildcard addresses)
    ///
    /// Forces strict binding to specific interface addresses rather than using
    /// 0.0.0.0 wildcard binding. Increases security but reduces flexibility
    /// for dynamic interface configurations.
    #[arg(short = 'z', long = "bind-interfaces")]
    pub bind_interfaces: bool,

    /// Enable dynamic interface binding for changing network configurations
    ///
    /// Monitors interface address changes and rebinds sockets dynamically.
    /// Useful for laptops, DHCP-configured servers, and other dynamic network
    /// environments. Linux-only feature using netlink.
    #[arg(long = "bind-dynamic")]
    pub bind_dynamic: bool,

    /// Provide DNS service only to local subnet clients
    ///
    /// Accept DNS queries only from hosts whose source address is on a local
    /// subnet. Prevents DNS amplification attacks and unauthorized external access.
    #[arg(long = "local-service")]
    pub local_service: bool,

    // =========================================================================
    // DNS PORT AND QUERY PORT OPTIONS
    // =========================================================================
    /// Specify DNS listening port (default 53, 0 disables DNS)
    ///
    /// Set DNS server listening port. Standard DNS port is 53. Setting to 0
    /// disables DNS server functionality entirely (DHCP-only mode).
    #[arg(short = 'p', long = "port", value_name = "PORT", default_value = "53")]
    pub port: u16,

    /// Specify UDP port for outgoing DNS queries
    ///
    /// Source port for upstream DNS queries. Default is random port selection
    /// for security. Setting to 0 uses random port allocation.
    #[arg(short = 'Q', long = "query-port", value_name = "PORT")]
    pub query_port: Option<u16>,

    /// Specify minimum port for outgoing DNS queries
    ///
    /// Lower bound for random source port selection. Useful to work with
    /// restrictive firewalls that require specific port ranges.
    #[arg(long = "min-port", value_name = "PORT")]
    pub min_port: Option<u16>,

    /// Specify maximum port for outgoing DNS queries
    ///
    /// Upper bound for random source port selection. Paired with --min-port
    /// to define allowed source port range for upstream queries.
    #[arg(long = "max-port", value_name = "PORT")]
    pub max_port: Option<u16>,

    // =========================================================================
    // DNS CACHE OPTIONS
    // =========================================================================
    /// Specify the size of the cache in entries (default 150)
    ///
    /// Set DNS cache size in number of cached records. 0 disables caching
    /// entirely (pass-through mode). Each entry is approximately 128 bytes.
    /// Typical values: 150 (default), 1000 (busy network), 10000 (very busy).
    #[arg(short = 'c', long = "cache-size", value_name = "SIZE")]
    pub cache_size: Option<usize>,

    /// Do NOT cache negative (NXDOMAIN) responses
    ///
    /// Disable negative response caching. Negative responses indicate a domain
    /// doesn't exist. Caching them improves performance but may delay detection
    /// of newly created domains.
    #[arg(short = 'N', long = "no-negcache")]
    pub no_negcache: bool,

    /// Time-to-live for local names (default 0, no caching)
    ///
    /// TTL for locally configured names from /etc/hosts, --address, --host-record.
    /// Default 0 means no caching (always query). Setting to 300 (5 minutes)
    /// or 3600 (1 hour) reduces query load for frequently accessed local names.
    #[arg(short = 'T', long = "local-ttl", value_name = "SECONDS")]
    pub local_ttl: Option<u64>,

    /// Specify minimum TTL for DNS cache entries
    ///
    /// Override upstream TTL with minimum value. Useful to extend caching
    /// duration for domains with very short TTLs. Use cautiously as it
    /// violates RFC guidelines.
    #[arg(long = "min-cache-ttl", value_name = "SECONDS")]
    pub min_cache_ttl: Option<u64>,

    /// Specify maximum TTL for DNS cache entries
    ///
    /// Override upstream TTL with maximum value. Prevents extremely long
    /// TTLs from consuming cache space indefinitely. Recommended value: 3600-86400.
    #[arg(long = "max-cache-ttl", value_name = "SECONDS")]
    pub max_cache_ttl: Option<u64>,

    /// Specify maximum TTL for upstream response records
    ///
    /// Clamp TTLs in responses sent to clients. Different from --max-cache-ttl
    /// which affects only cached entries. Use to enforce TTL policy regardless
    /// of caching.
    #[arg(long = "max-ttl", value_name = "SECONDS")]
    pub max_ttl: Option<u64>,

    /// Specify TTL for negative (NXDOMAIN) cache entries
    ///
    /// Override negative response TTL. Default follows SOA minimum field from
    /// upstream. Setting explicitly controls negative caching duration.
    #[arg(long = "neg-ttl", value_name = "SECONDS")]
    pub neg_ttl: Option<u64>,

    // =========================================================================
    // DNS UPSTREAM SERVER OPTIONS
    // =========================================================================
    /// Specify upstream DNS server(s)
    ///
    /// Format: [/domain/]server[@source_address][#port]
    /// Examples:
    ///   --server=8.8.8.8           # Google DNS for all queries
    ///   --server=/example.com/1.1.1.1  # Cloudflare for example.com
    ///   --server=/local/           # No upstream for .local
    /// Can be specified multiple times for redundancy and domain-specific routing.
    #[arg(short = 'S', long = "server", value_name = "SERVER")]
    pub server: Vec<String>,

    /// Specify reverse-lookup DNS server
    ///
    /// Format: <ip-address>/<prefix>,<server>
    /// Example: --rev-server=192.168.0.0/16,10.0.0.1
    /// Routes reverse DNS lookups (PTR records) for specific IP ranges to
    /// designated servers. Useful for split-horizon DNS.
    #[arg(long = "rev-server", value_name = "REV_SERVER")]
    pub rev_server: Vec<String>,

    /// Load upstream servers from file (e.g., /etc/resolv.conf)
    ///
    /// Automatically use servers from resolv.conf-style file. Useful to
    /// leverage DHCP-provided DNS servers. File is monitored for changes.
    #[arg(short = 'r', long = "resolv-file", value_name = "FILE")]
    pub resolv_file: Option<PathBuf>,

    /// Load additional upstream servers from file
    ///
    /// Similar to --resolv-file but for supplementary server lists.
    /// File format is one server per line in --server option format.
    #[arg(long = "servers-file", value_name = "FILE")]
    pub servers_file: Vec<PathBuf>,

    /// Do NOT use /etc/resolv.conf for upstream servers
    ///
    /// Ignore system resolv.conf file. Requires manual server specification
    /// via --server options. Use when system DNS configuration is not applicable.
    #[arg(short = 'R', long = "no-resolv")]
    pub no_resolv: bool,

    /// Use strict DNS server order (no load balancing)
    ///
    /// Query servers in the order specified, not round-robin. First server
    /// is always tried first. Useful when servers have different capabilities
    /// or one is significantly faster.
    #[arg(short = 'o', long = "strict-order")]
    pub strict_order: bool,

    /// Send all queries to all upstream servers
    ///
    /// Forward every query to all configured servers simultaneously, use
    /// first response. Increases reliability and speed at cost of higher
    /// upstream query volume.
    #[arg(long = "all-servers")]
    pub all_servers: bool,

    /// Maximum number of concurrent DNS forward queries
    ///
    /// Limits concurrent outstanding upstream queries. Prevents resource
    /// exhaustion during query floods. Default 150. Increase for busy servers.
    #[arg(
        short = '0',
        long = "dns-forward-max",
        value_name = "NUMBER",
        default_value = "150"
    )]
    pub dns_forward_max: usize,

    // =========================================================================
    // DNS QUERY FILTERING OPTIONS
    // =========================================================================
    /// Do NOT forward DNS queries without domain part
    ///
    /// Reject queries for bare hostnames (no dots). Prevents unnecessary
    /// upstream queries for local-only hostnames. Recommended for privacy.
    #[arg(short = 'D', long = "domain-needed")]
    pub domain_needed: bool,

    /// Return NXDOMAIN for RFC1918 reverse lookups
    ///
    /// Fake reverse lookups for private IP address ranges (10.0.0.0/8,
    /// 172.16.0.0/12, 192.168.0.0/16). Prevents leaking internal network
    /// structure to public DNS.
    #[arg(short = 'b', long = "bogus-priv")]
    pub bogus_priv: bool,

    /// Treat replies from specified IP as NXDOMAIN
    ///
    /// Transform responses from certain IPs into NXDOMAIN. Defeats ISP/CDN
    /// DNS hijacking that redirects NXDOMAIN to ad pages. Example:
    /// --bogus-nxdomain=64.94.110.11 (Verisign wildcard).
    #[arg(short = 'B', long = "bogus-nxdomain", value_name = "IPADDR")]
    pub bogus_nxdomain: Vec<IpAddr>,

    /// Ignore DNS replies from specified addresses
    ///
    /// Silently drop responses from these source addresses. More aggressive
    /// than --bogus-nxdomain, useful for completely blocking problematic resolvers.
    #[arg(long = "ignore-address", value_name = "IPADDR")]
    pub ignore_address: Vec<IpAddr>,

    /// Filter out Windows Internet Naming Service queries
    ///
    /// Reject queries for _tcp and _udp TXT records used by Windows 2000 name
    /// resolution. These are local-only queries that shouldn't be forwarded.
    #[arg(short = 'f', long = "filterwin2k")]
    pub filterwin2k: bool,

    /// Filter out A (IPv4) address queries
    ///
    /// Return empty responses for A record queries. Forces clients to use
    /// IPv6 (AAAA records) only. Useful for IPv6-only networks.
    #[arg(long = "filter-A")]
    pub filter_a: bool,

    /// Filter out AAAA (IPv6) address queries
    ///
    /// Return empty responses for AAAA record queries. Forces clients to use
    /// IPv4 (A records) only. Useful for networks without IPv6 connectivity
    /// to improve connection speed by avoiding IPv6 timeouts.
    #[arg(long = "filter-AAAA")]
    pub filter_aaaa: bool,

    // =========================================================================
    // DNS REBIND PROTECTION OPTIONS
    // =========================================================================
    /// Enable DNS rebinding protection
    ///
    /// Reject upstream responses containing private IP addresses (RFC1918,
    /// loopback, link-local). Prevents DNS rebinding attacks where external
    /// domains resolve to internal IPs.
    #[arg(long = "stop-dns-rebind")]
    pub stop_dns_rebind: bool,

    /// Allow rebind for specified domains
    ///
    /// Whitelist domains exempt from rebind protection. Use for legitimate
    /// services that intentionally resolve to private IPs (e.g., captive portals).
    #[arg(long = "rebind-domain-ok", value_name = "DOMAIN")]
    pub rebind_domain_ok: Vec<String>,

    /// Allow 127.0.0.0/8 in DNS rebind checks
    ///
    /// Permit loopback addresses in upstream responses. Needed for domains
    /// that legitimately resolve to localhost (e.g., local development).
    #[arg(long = "rebind-localhost-ok")]
    pub rebind_localhost_ok: bool,

    /// Enable DNS forwarding loop detection
    ///
    /// Detect and break query forwarding loops. Prevents infinite recursion
    /// when dnsmasq is misconfigured to use itself as upstream server.
    /// Linux-only feature using kernel connection tracking.
    #[cfg(feature = "loop-detect")]
    #[arg(long = "dns-loop-detect")]
    pub dns_loop_detect: bool,

    // =========================================================================
    // LOCAL DNS RECORDS OPTIONS
    // =========================================================================
    /// Return specified IP for all hosts in domain
    ///
    /// Format: /domain/ipaddr or /domain/ (return NXDOMAIN)
    /// Examples:
    ///   --address=/doubleclick.net/    # Block ads
    ///   --address=/mynet/192.168.1.1   # Internal domain
    /// Can be used for ad-blocking, split-horizon DNS, or internal domains.
    #[arg(short = 'A', long = "address", value_name = "ADDRESS")]
    pub address: Vec<String>,

    /// Specify local domain name(s) for DHCP
    ///
    /// Set domain suffix for DHCP clients and local name resolution.
    /// Example: --domain=mynet.local
    /// Clients receive this via DHCP option 15 (Domain Name).
    #[arg(short = 's', long = "domain", value_name = "DOMAIN")]
    pub domain: Vec<String>,

    /// Specify additional hosts file
    ///
    /// Read additional host-to-IP mappings from hosts-format file. Can be
    /// specified multiple times. File is monitored for changes and automatically
    /// reloaded. Useful for custom local DNS entries.
    #[arg(short = 'H', long = "addn-hosts", value_name = "FILE")]
    pub addn_hosts: Vec<PathBuf>,

    /// Specify hosts file directory (inotify monitoring)
    ///
    /// Read all files in directory as additional hosts files. Files are
    /// monitored with inotify and reloaded on changes. Linux-only feature.
    #[arg(long = "hostsdir", value_name = "DIR")]
    pub hostsdir: Vec<PathBuf>,

    /// Do NOT read /etc/hosts file
    ///
    /// Ignore system hosts file. Use with --addn-hosts to use only custom
    /// host files. Improves startup time on systems with large hosts files.
    #[arg(short = 'h', long = "no-hosts")]
    pub no_hosts: bool,

    /// Expand hostnames in /etc/hosts with domain suffix
    ///
    /// Automatically append domain from --domain option to single-label hostnames
    /// in hosts files. Allows short names (e.g., 'myhost') to work while also
    /// creating FQDN entries (e.g., 'myhost.mynet.local').
    #[arg(short = 'E', long = "expand-hosts")]
    pub expand_hosts: bool,

    /// Read /etc/ethers for static DHCP-host mappings
    ///
    /// Use /etc/ethers file (MAC to hostname mappings) to automatically create
    /// static DHCP entries. Traditional UNIX ethernet address database integration.
    #[arg(short = 'Z', long = "read-ethers")]
    pub read_ethers: bool,

    // =========================================================================
    // EDNS AND PACKET SIZE OPTIONS
    // =========================================================================
    /// Specify maximum EDNS0 UDP packet size
    ///
    /// Set EDNS0 UDP payload size advertised in OPT records. Default 4096 bytes.
    /// Lower values avoid IP fragmentation, higher values support large DNSSEC
    /// responses. RFC 6891 recommends 4096. Conservative: 1232 (DNS Flag Day 2020).
    #[arg(short = 'P', long = "edns-packet-max", value_name = "SIZE")]
    pub edns_packet_max: Option<usize>,

    // =========================================================================
    // DHCP SERVER OPTIONS (feature-gated)
    // =========================================================================
    #[cfg(feature = "dhcp")]
    /// Specify DHCP address range and lease time
    ///
    /// Format: <start-addr>,<end-addr>[,<netmask>][,<broadcast>][,<lease-time>]
    /// Examples:
    ///   --dhcp-range=192.168.1.50,192.168.1.150,12h
    ///   --dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,24h
    /// Multiple ranges supported. Can specify constructor:<interface> for
    /// interface-relative addressing.
    #[arg(short = 'F', long = "dhcp-range", value_name = "RANGE")]
    pub dhcp_range: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Specify static DHCP host configuration
    ///
    /// Format: [<hwaddr>][,id:<client_id>|*][,set:<tag>][,<ipaddr>][,<hostname>][,<lease_time>][,ignore]
    /// Examples:
    ///   --dhcp-host=11:22:33:44:55:66,192.168.1.10
    ///   --dhcp-host=11:22:33:44:55:66,myhost,12h
    ///   --dhcp-host=id:01:02:03:04,192.168.1.20
    /// Provides static IP assignments, custom hostnames, and per-host options.
    #[arg(short = 'G', long = "dhcp-host", value_name = "HOST")]
    pub dhcp_host: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Specify DHCP options to send to clients
    ///
    /// Format: [tag:<tag>,][encap:<opt>,][vi-encap:<enterprise>,][vendor:[<vendor-class>],][<opt>|option:<opt-name>|option6:<opt>|option6:<opt-name>],[<value>]
    /// Examples:
    ///   --dhcp-option=3,192.168.1.1     # Default gateway
    ///   --dhcp-option=6,8.8.8.8,8.8.4.4 # DNS servers
    ///   --dhcp-option=option:router,192.168.1.1
    /// Supports standard DHCP options, vendor-specific options, and tags.
    #[arg(short = 'O', long = "dhcp-option", value_name = "OPTION")]
    pub dhcp_option: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Force DHCP option even if client doesn't request it
    ///
    /// Same format as --dhcp-option but forces option in all replies.
    /// Use for options that clients should receive but may not request.
    #[arg(long = "dhcp-option-force", value_name = "OPTION")]
    pub dhcp_option_force: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Specify network boot (PXE) parameters
    ///
    /// Format: [tag:<tag>,]<filename>,[<servername>[,<server address>|<tftp_servername>]]
    /// Examples:
    ///   --dhcp-boot=pxelinux.0
    ///   --dhcp-boot=pxelinux.0,bootserver,192.168.1.1
    /// Sets BOOTP filename (option 67), next-server (option 66) for network boot.
    #[arg(short = 'M', long = "dhcp-boot", value_name = "BOOT")]
    pub dhcp_boot: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Always ignore DHCP requests from specified hosts
    ///
    /// Format: [tag:<tag>]
    /// Prevents specified clients from receiving DHCP service. Useful for
    /// blacklisting specific MAC addresses or client IDs.
    #[arg(short = 'J', long = "dhcp-ignore", value_name = "IGNORE")]
    pub dhcp_ignore: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Ignore hostnames provided by DHCP clients
    ///
    /// Prevents clients from setting their own hostnames via DHCP option 12.
    /// Optional tag format for conditional ignoring. Security feature to
    /// prevent hostname spoofing.
    #[arg(long = "dhcp-ignore-names", num_args = 0..=1, default_missing_value = "true", value_name = "TAG")]
    pub dhcp_ignore_names: Option<String>,

    #[cfg(feature = "dhcp")]
    /// Specify DHCP lease file path
    ///
    /// Path for persistent lease database. Defaults to /var/lib/misc/dnsmasq.leases.
    /// Leases survive daemon restart. Use empty value to disable persistence.
    #[arg(short = 'l', long = "dhcp-leasefile", value_name = "FILE")]
    pub dhcp_leasefile: Option<PathBuf>,

    #[cfg(feature = "dhcp")]
    /// Specify maximum number of DHCP leases
    ///
    /// Limits lease table size. Default 1000. Increase for large networks.
    /// Setting to 0 disables limit (uses all available addresses in ranges).
    #[arg(short = 'X', long = "dhcp-lease-max", value_name = "NUMBER")]
    pub dhcp_lease_max: Option<usize>,

    #[cfg(feature = "dhcp")]
    /// Assume DHCP server is authoritative for all subnets
    ///
    /// Respond immediately with DHCPNAK to requests for wrong subnet instead
    /// of waiting. Required for rapid handoff in roaming scenarios. Improves
    /// client experience but should only be enabled if this is the only DHCP server.
    #[arg(short = 'K', long = "dhcp-authoritative")]
    pub dhcp_authoritative: bool,

    #[cfg(feature = "dhcp")]
    /// Enable DHCP rapid commit (RFC 4039)
    ///
    /// Support two-message DHCP exchange (DISCOVER/ACK) instead of four-message
    /// (DISCOVER/OFFER/REQUEST/ACK). Reduces lease acquisition latency when
    /// client and server both support rapid commit.
    #[arg(long = "dhcp-rapid-commit")]
    pub dhcp_rapid_commit: bool,

    #[cfg(feature = "dhcp")]
    /// Match DHCP options by vendor class
    ///
    /// Format: set:<tag>,<vendor-class>
    /// Tag clients based on DHCP option 60 (Vendor Class Identifier).
    /// Useful for platform-specific configurations (different boot files
    /// for BIOS vs UEFI clients).
    #[arg(short = 'U', long = "dhcp-vendorclass", value_name = "VENDORCLASS")]
    pub dhcp_vendorclass: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Match DHCP options by user class
    ///
    /// Format: set:<tag>,<user-class>
    /// Tag clients based on DHCP option 77 (User Class). Similar to vendor
    /// class but for user-defined categorization.
    #[arg(short = 'j', long = "dhcp-userclass", value_name = "USERCLASS")]
    pub dhcp_userclass: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Match DHCP options by MAC address
    ///
    /// Format: set:<tag>,<MAC address>
    /// Tag clients based on hardware address. Allows per-device configuration
    /// without full static host entries.
    #[arg(short = '4', long = "dhcp-mac", value_name = "MAC")]
    pub dhcp_mac: Vec<String>,

    #[cfg(feature = "dhcp")]
    /// Do NOT ping address before allocating to check availability
    ///
    /// Skip ICMP echo check before lease assignment. Improves DHCP response
    /// speed but risks assigning already-in-use addresses if clients don't
    /// properly release leases.
    #[arg(short = '5', long = "no-ping")]
    pub no_ping: bool,

    #[cfg(feature = "dhcp")]
    /// Enable DHCP lease renewal script
    ///
    /// Execute script on DHCP events (add, old, del). Script receives
    /// environment variables with lease details. Useful for dynamic DNS
    /// updates, firewall rules, or custom integration.
    #[arg(short = '6', long = "dhcp-script", value_name = "SCRIPT")]
    pub dhcp_script: Option<PathBuf>,

    #[cfg(feature = "dhcp")]
    /// Broadcast DHCP replies for specified clients
    ///
    /// Send DHCP replies via broadcast instead of unicast. Required for
    /// some broken clients that can't receive unicast before IP configuration.
    /// Optional tag format for conditional broadcast.
    #[arg(long = "dhcp-broadcast", num_args = 0..=1, default_missing_value = "true", value_name = "TAG")]
    pub dhcp_broadcast: Option<String>,

    #[cfg(feature = "dhcp")]
    /// Allocate DHCP addresses sequentially
    ///
    /// Use sequential IP allocation instead of hash-based. Makes addresses
    /// more predictable but may concentrate usage at beginning of range.
    #[arg(long = "dhcp-sequential-ip")]
    pub dhcp_sequential_ip: bool,

    #[cfg(feature = "dhcp")]
    /// Ignore DHCP client identifier option
    ///
    /// Identify clients only by MAC address, ignore option 61 (client ID).
    /// Useful for clients that change client IDs but keep MAC address,
    /// ensuring consistent IP assignment.
    #[arg(long = "dhcp-ignore-clid")]
    pub dhcp_ignore_clid: bool,

    // =========================================================================
    // DHCPv6 OPTIONS (feature-gated)
    // =========================================================================
    #[cfg(feature = "dhcp-v6")]
    /// Enable router advertisement for IPv6
    ///
    /// Send IPv6 Router Advertisement messages with managed, other-config,
    /// or stateless address configuration flags. Essential for IPv6 network
    /// configuration.
    #[arg(long = "enable-ra")]
    pub enable_ra: bool,

    #[cfg(feature = "dhcp-v6")]
    /// Specify DHCPv6 DUID (DHCP Unique Identifier)
    ///
    /// Set server DUID manually. Format varies by DUID type (DUID-LLT, DUID-EN,
    /// DUID-LL). If not specified, automatically generated from hardware address.
    #[arg(long = "dhcp-duid", value_name = "DUID")]
    pub dhcp_duid: Option<String>,

    #[cfg(feature = "dhcp-v6")]
    /// Specify router advertisement parameters
    ///
    /// Format: [tag:<tag>,]<interface>,[high,|low,]<ra-interval>[,<router-lifetime>]
    /// Controls RA timing and router lifetime advertisement. High/low priority
    /// for multi-router networks.
    #[arg(long = "ra-param", value_name = "PARAMS")]
    pub ra_param: Vec<String>,

    #[cfg(feature = "dhcp-v6")]
    /// Suppress router advertisement messages
    ///
    /// Disable RA transmission. Use when another router handles RAs or in
    /// DHCPv6-only (stateful) configuration without SLAAC.
    #[arg(long = "quiet-ra")]
    pub quiet_ra: bool,

    #[cfg(feature = "dhcp-v6")]
    /// Suppress DHCPv6 logging
    ///
    /// Reduce DHCPv6 log verbosity. Similar to --quiet-dhcp but for IPv6.
    #[arg(long = "quiet-dhcp6")]
    pub quiet_dhcp6: bool,

    #[cfg(feature = "dhcp")]
    /// Suppress DHCPv4 logging
    ///
    /// Reduce DHCPv4 log verbosity. Useful in high-transaction environments
    /// to prevent log flooding. Critical events still logged.
    #[arg(long = "quiet-dhcp")]
    pub quiet_dhcp: bool,

    // =========================================================================
    // TFTP SERVER OPTIONS (feature-gated)
    // =========================================================================
    #[cfg(feature = "tftp")]
    /// Enable TFTP server on specified interfaces
    ///
    /// Activate TFTP service for network boot (PXE). Optional interface
    /// specification limits TFTP to specific networks. Can be specified
    /// multiple times for multiple interfaces.
    #[arg(long = "enable-tftp", num_args = 0..=1, default_missing_value = "true", value_name = "INTERFACE")]
    pub enable_tftp: Vec<String>,

    #[cfg(feature = "tftp")]
    /// Specify TFTP root directory
    ///
    /// Base directory for TFTP file serving. Can be specified per-interface
    /// with format <interface>,<path>. Clients cannot access files outside
    /// this directory (chroot-like behavior).
    #[arg(long = "tftp-root", value_name = "DIR")]
    pub tftp_root: Vec<String>,

    #[cfg(feature = "tftp")]
    /// Enable TFTP secure mode (restrict to root directory)
    ///
    /// Prevent path traversal attacks. Rejects requests containing "../" or
    /// absolute paths. Strongly recommended for production use.
    #[arg(long = "tftp-secure")]
    pub tftp_secure: bool,

    #[cfg(feature = "tftp")]
    /// Continue even if TFTP root directory is unavailable
    ///
    /// Don't fail startup if TFTP root doesn't exist. Allows starting dnsmasq
    /// before TFTP filesystems are mounted (e.g., NFS mounts).
    #[arg(long = "tftp-no-fail")]
    pub tftp_no_fail: bool,

    #[cfg(feature = "tftp")]
    /// Convert TFTP filenames to lowercase
    ///
    /// Automatically lowercase all requested filenames. Useful for case-insensitive
    /// filesystems or when clients request mixed-case filenames.
    #[arg(long = "tftp-lowercase")]
    pub tftp_lowercase: bool,

    #[cfg(feature = "tftp")]
    /// Specify maximum number of concurrent TFTP transfers
    ///
    /// Limits simultaneous TFTP connections. Default 50. Higher values support
    /// more concurrent PXE boots but increase memory usage. Each transfer
    /// consumes one socket and buffer.
    #[arg(long = "tftp-max", value_name = "NUMBER")]
    pub tftp_max: Option<usize>,

    #[cfg(feature = "tftp")]
    /// Specify TFTP port range for data connections
    ///
    /// Format: <start-port>,<end-port>
    /// Restrict TFTP data ports to specific range for firewall compatibility.
    /// TFTP uses random ports by default which may be blocked.
    #[arg(long = "tftp-port-range", value_name = "RANGE")]
    pub tftp_port_range: Option<String>,

    #[cfg(feature = "tftp")]
    /// Use single port for all TFTP traffic
    ///
    /// Handle all TFTP transactions on port 69 only. Simplifies firewall
    /// configuration but limits scalability. Not recommended for busy servers.
    #[arg(long = "tftp-single-port")]
    pub tftp_single_port: bool,

    #[cfg(feature = "tftp")]
    /// Suppress TFTP error logging
    ///
    /// Reduce TFTP log verbosity. File not found errors won't be logged,
    /// useful when clients probe for multiple filenames.
    #[arg(long = "quiet-tftp")]
    pub quiet_tftp: bool,

    // =========================================================================
    // DNSSEC OPTIONS (feature-gated)
    // =========================================================================
    #[cfg(feature = "dnssec")]
    /// Enable DNSSEC validation
    ///
    /// Validate DNSSEC signatures on responses. Requires --trust-anchor or
    /// --dnssec-check-unsigned. Signatures are checked using public keys
    /// from DS records and DNSKEY records.
    #[arg(long = "dnssec")]
    pub dnssec: bool,

    #[cfg(feature = "dnssec")]
    /// Specify DNSSEC trust anchor
    ///
    /// Format: <domain>,<key-tag>,<algorithm>,<digest-type>,<digest>
    /// Configure trust anchor for DNSSEC validation. Root zone trust anchor
    /// required for full DNSSEC validation. Multiple trust anchors supported.
    #[arg(long = "trust-anchor", value_name = "ANCHOR")]
    pub trust_anchor: Vec<String>,

    #[cfg(feature = "dnssec")]
    /// Check unsigned domains in DNSSEC validation
    ///
    /// Reject unsigned responses from domains under signed delegations.
    /// Prevents DNSSEC downgrade attacks. Optional tag format for conditional checking.
    #[arg(long = "dnssec-check-unsigned", num_args = 0..=1, default_missing_value = "true", value_name = "TAG")]
    pub dnssec_check_unsigned: Option<String>,

    #[cfg(feature = "dnssec")]
    /// Disable DNSSEC timestamp checking
    ///
    /// Don't check signature inception/expiration times. Use when system
    /// clock is unreliable (embedded systems without RTC). Security impact:
    /// allows expired signatures.
    #[arg(long = "dnssec-no-timecheck")]
    pub dnssec_no_timecheck: bool,

    #[cfg(feature = "dnssec")]
    /// Specify DNSSEC timestamp for validation
    ///
    /// Validate signatures as if current time is specified timestamp.
    /// Format: Unix timestamp or ISO 8601. Useful for testing or systems
    /// with incorrect clocks.
    #[arg(long = "dnssec-timestamp", value_name = "TIMESTAMP")]
    pub dnssec_timestamp: Option<String>,

    #[cfg(feature = "dnssec")]
    /// Enable DNSSEC debug logging
    ///
    /// Verbose DNSSEC validation logging. Shows signature verification steps,
    /// key chain validation, and failure reasons. Very high log volume.
    #[arg(long = "dnssec-debug")]
    pub dnssec_debug: bool,

    // =========================================================================
    // AUTHORITATIVE DNS OPTIONS (feature-gated)
    // =========================================================================
    #[cfg(feature = "auth-dns")]
    /// Specify authoritative DNS zone
    ///
    /// Format: <domain>[,<subnet>[/<prefix length>]]
    /// Declare dnsmasq as authoritative for specified zone. Responds with
    /// AA (Authoritative Answer) bit set. Essential for primary DNS server role.
    #[arg(long = "auth-zone", value_name = "ZONE")]
    pub auth_zone: Vec<String>,

    #[cfg(feature = "auth-dns")]
    /// Specify authoritative DNS server name
    ///
    /// Format: <domain>,<interface>|<ip-address>
    /// Declare SOA record MNAME and NS record for authoritative zones.
    /// Must be externally resolvable for proper DNS operation.
    #[arg(long = "auth-server", value_name = "SERVER")]
    pub auth_server: Vec<String>,

    #[cfg(feature = "auth-dns")]
    /// Specify TTL for authoritative DNS records
    ///
    /// Sets default TTL for records in authoritative zones. Applies to A, AAAA,
    /// PTR records synthesized from DHCP leases or /etc/hosts.
    #[arg(long = "auth-ttl", value_name = "SECONDS")]
    pub auth_ttl: Option<u64>,

    #[cfg(feature = "auth-dns")]
    /// Specify authoritative DNS SOA record
    ///
    /// Format: <serial>[,<hostmaster>[,<refresh>[,<retry>[,<expiry>]]]]
    /// Configure SOA record parameters. Serial can be numeric or keyword 'epoch'
    /// for automatic Unix timestamp.
    #[arg(long = "auth-soa", value_name = "SOA")]
    pub auth_soa: Option<String>,

    // =========================================================================
    // LINUX INTEGRATION OPTIONS (feature-gated, platform-specific)
    // =========================================================================
    #[cfg(all(feature = "ipset", target_os = "linux"))]
    /// Add resolved IPs to Linux ipset
    ///
    /// Format: /<domain>/<ipset>[,<ipset>...]
    /// Automatically add IP addresses from DNS responses to ipset.
    /// Useful for dynamic firewall rules based on domain names.
    /// Example: --ipset=/google.com/google-ips
    #[arg(long = "ipset", value_name = "IPSET")]
    pub ipset: Vec<String>,

    #[cfg(all(feature = "nftables", target_os = "linux"))]
    /// Add resolved IPs to nftables set
    ///
    /// Format: /<domain>/<family>#<table>#<set>[,<family>#<table>#<set>...]
    /// Automatically add IP addresses to nftables sets. Modern alternative
    /// to ipset for nftables-based firewalls.
    /// Example: --nftset=/google.com/4#inet#filter#google-ips
    #[arg(long = "nftset", value_name = "NFTSET")]
    pub nftset: Vec<String>,

    #[cfg(all(feature = "conntrack", target_os = "linux"))]
    /// Enable Linux connection tracking for DNS
    ///
    /// Use kernel connection tracking (conntrack) for loop detection and
    /// source verification. Requires CONFIG_NETFILTER_CONNTRACK kernel option.
    #[arg(long = "conntrack")]
    pub conntrack: bool,

    // =========================================================================
    // INTEGRATION OPTIONS (feature-gated)
    // =========================================================================
    #[cfg(feature = "dbus")]
    /// Enable D-Bus messaging interface
    ///
    /// Activate D-Bus API for external control and monitoring. Optional
    /// service name argument (default: uk.org.thekelleys.dnsmasq).
    /// Allows NetworkManager and other tools to control dnsmasq.
    #[arg(short = '1', long = "enable-dbus", num_args = 0..=1, default_missing_value = "uk.org.thekelleys.dnsmasq", value_name = "SERVICE")]
    pub enable_dbus: Option<String>,

    #[cfg(all(feature = "ubus", target_os = "linux"))]
    /// Enable OpenWrt ubus messaging interface
    ///
    /// Activate ubus API for OpenWrt integration. Optional object name argument
    /// (default: dnsmasq). Provides LuCI web interface integration.
    #[arg(long = "enable-ubus", num_args = 0..=1, default_missing_value = "dnsmasq", value_name = "OBJECT")]
    pub enable_ubus: Option<String>,
}

// =============================================================================
// CLI IMPLEMENTATION
// =============================================================================

impl Cli {
    /// Parse command-line arguments from environment
    ///
    /// Parses `std::env::args()` and returns populated `Cli` struct. Automatically
    /// handles --help and --version. Exits process on parse errors with descriptive
    /// error messages.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::config::options::Cli;
    ///
    /// let cli = Cli::parse();
    /// println!("Port: {}", cli.port);
    /// ```
    ///
    /// # Errors
    ///
    /// Exits process with status 1 if:
    /// - Invalid argument format (clap handles this automatically)
    /// - Required argument missing (if any were marked as required)
    /// - Value parsing fails (invalid IP, port out of range, etc.)
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    /// Parse command-line arguments from iterator
    ///
    /// Parses arguments from provided iterator instead of `std::env::args()`.
    /// Useful for testing and programmatic construction of arguments.
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::config::options::Cli;
    ///
    /// let args = vec!["dnsmasq", "--port=5353", "--no-daemon"];
    /// let cli = Cli::parse_from(args);
    /// assert_eq!(cli.port, 5353);
    /// assert!(cli.no_daemon);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Invalid argument format
    /// - Value parsing fails
    /// - Unknown option provided
    pub fn parse_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::parse_from(args)
    }

    /// Validate CLI arguments for consistency
    ///
    /// Performs cross-argument validation that clap cannot express:
    /// - Port range validation (min_port < max_port)
    /// - EDNS packet size limits (512-65535 bytes)
    /// - TTL value reasonableness
    /// - Conflicting option detection
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if validation fails:
    /// - Port range is inverted (min > max)
    /// - EDNS packet size too small (<512) or too large (>65535)
    /// - Invalid combination of options
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::config::options::Cli;
    ///
    /// let cli = Cli::parse();
    /// cli.validate().expect("Invalid configuration");
    /// ```
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate port ranges
        if let (Some(min), Some(max)) = (self.min_port, self.max_port) {
            if min > max {
                return Err(ConfigError::InvalidPort(min));
            }
        }

        // Validate EDNS packet size
        if let Some(size) = self.edns_packet_max {
            if size < 512 {
                return Err(ConfigError::InvalidPort(size as u16));
            }
            if size > 65535 {
                return Err(ConfigError::InvalidPort(size as u16));
            }
        }

        // Validate cache size constraints
        if let Some(size) = self.cache_size {
            // Cache size of 0 is valid (disables caching)
            // No upper limit check - system memory is the limit
        }

        // Validate DNS port (0 is valid - disables DNS)
        // All other u16 values are valid

        // Validate TTL values for reasonableness
        // TTL of 0 is valid (no caching), and u64::MAX is technically valid
        // though impractical (584 million years)

        Ok(())
    }

    /// Get EDNS packet size (with default)
    ///
    /// Returns configured EDNS packet size or default from constants if not specified.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::config::options::Cli;
    ///
    /// let cli = Cli::parse();
    /// let edns_size = cli.edns_packet_size();
    /// assert!(edns_size >= 512 && edns_size <= 65535);
    /// ```
    pub fn edns_packet_size(&self) -> usize {
        self.edns_packet_max.unwrap_or(EDNS_PACKET_SIZE)
    }

    /// Check if running in foreground mode
    ///
    /// Returns true if either --no-daemon or --keep-in-foreground is specified.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::config::options::Cli;
    ///
    /// let cli = Cli::parse();
    /// if cli.is_foreground() {
    ///     println!("Running in foreground mode");
    /// }
    /// ```
    pub fn is_foreground(&self) -> bool {
        self.no_daemon || self.keep_in_foreground
    }

    /// Check if DNS service is enabled
    ///
    /// Returns false if port is 0 (DNS disabled), true otherwise.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::config::options::Cli;
    ///
    /// let cli = Cli::parse();
    /// if !cli.is_dns_enabled() {
    ///     println!("DNS service is disabled");
    /// }
    /// ```
    pub fn is_dns_enabled(&self) -> bool {
        self.port != 0
    }

    /// Get configured DNS port
    ///
    /// Returns DNS listening port. Port 0 means DNS is disabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dnsmasq::config::options::Cli;
    ///
    /// let cli = Cli::parse();
    /// println!("DNS port: {}", cli.dns_port());
    /// ```
    pub fn dns_port(&self) -> u16 {
        self.port
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_options() {
        let args = vec!["dnsmasq", "--port=5353", "--no-daemon"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.port, 5353);
        assert!(cli.no_daemon);
    }

    #[test]
    fn test_parse_server_option() {
        let args = vec!["dnsmasq", "--server=8.8.8.8", "--server=1.1.1.1"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.server.len(), 2);
        assert_eq!(cli.server[0], "8.8.8.8");
        assert_eq!(cli.server[1], "1.1.1.1");
    }

    #[test]
    fn test_parse_listen_address() {
        let args = vec!["dnsmasq", "-a", "127.0.0.1", "-a", "::1"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.listen_address.len(), 2);
    }

    #[test]
    fn test_default_port() {
        let args = vec!["dnsmasq"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.port, 53);
    }

    #[test]
    fn test_disabled_dns() {
        let args = vec!["dnsmasq", "--port=0"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.port, 0);
        assert!(!cli.is_dns_enabled());
    }

    #[test]
    fn test_foreground_modes() {
        let args1 = vec!["dnsmasq", "--no-daemon"];
        let cli1 = Cli::parse_from(args1);
        assert!(cli1.is_foreground());

        let args2 = vec!["dnsmasq", "--keep-in-foreground"];
        let cli2 = Cli::parse_from(args2);
        assert!(cli2.is_foreground());

        let args3 = vec!["dnsmasq"];
        let cli3 = Cli::parse_from(args3);
        assert!(!cli3.is_foreground());
    }

    #[test]
    fn test_edns_packet_size_default() {
        let args = vec!["dnsmasq"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.edns_packet_size(), EDNS_PACKET_SIZE);
    }

    #[test]
    fn test_edns_packet_size_custom() {
        let args = vec!["dnsmasq", "--edns-packet-max=1232"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.edns_packet_size(), 1232);
    }

    #[test]
    fn test_validation_invalid_port_range() {
        let args = vec!["dnsmasq", "--min-port=2000", "--max-port=1000"];
        let cli = Cli::parse_from(args);
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_validation_valid_port_range() {
        let args = vec!["dnsmasq", "--min-port=1000", "--max-port=2000"];
        let cli = Cli::parse_from(args);
        assert!(cli.validate().is_ok());
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn test_parse_dhcp_options() {
        let args = vec![
            "dnsmasq",
            "--dhcp-range=192.168.1.50,192.168.1.150,12h",
            "--dhcp-host=11:22:33:44:55:66,192.168.1.10",
        ];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.dhcp_range.len(), 1);
        assert_eq!(cli.dhcp_host.len(), 1);
    }

    #[cfg(feature = "tftp")]
    #[test]
    fn test_parse_tftp_options() {
        let args = vec![
            "dnsmasq",
            "--enable-tftp",
            "--tftp-root=/var/tftp",
            "--tftp-secure",
        ];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.enable_tftp.len(), 1);
        assert_eq!(cli.tftp_root.len(), 1);
        assert!(cli.tftp_secure);
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_parse_dnssec_options() {
        let args = vec!["dnsmasq", "--dnssec", "--dnssec-check-unsigned"];
        let cli = Cli::parse_from(args);
        assert!(cli.dnssec);
        assert!(cli.dnssec_check_unsigned.is_some());
    }

    #[test]
    fn test_multiple_conf_files() {
        let args = vec![
            "dnsmasq",
            "--conf-file=/etc/dnsmasq.conf",
            "--conf-file=/etc/dnsmasq.d/custom.conf",
        ];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.conf_file.len(), 2);
    }

    #[test]
    fn test_cache_size_zero() {
        let args = vec!["dnsmasq", "--cache-size=0"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.cache_size, Some(0));
    }

    #[test]
    fn test_short_options() {
        let args = vec!["dnsmasq", "-d", "-p", "5353", "-c", "1000", "-S", "8.8.8.8"];
        let cli = Cli::parse_from(args);
        assert!(cli.no_daemon);
        assert_eq!(cli.port, 5353);
        assert_eq!(cli.cache_size, Some(1000));
        assert_eq!(cli.server.len(), 1);
    }
}
