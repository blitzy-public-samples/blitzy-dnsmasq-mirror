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

//! Default configuration values refactored from C implementation
//!
//! This module provides default configuration values matching the C implementation
//! from option.c's read_opts() initialization section (lines 6631-6664) and config.h
//! constant definitions. All defaults maintain exact value equivalence with the C
//! version for drop-in replacement compatibility.
//!
//! # Purpose
//!
//! Provides factory functions that construct configuration structs with default values
//! matching the C implementation's initialization logic from option.c and constants from
//! config.h. This ensures consistent behavior between C and Rust versions and eliminates
//! the need for conditional compilation macros by using Rust's cfg attributes.
//!
//! # Memory Safety Transformation
//!
//! - C macro definitions (#define) → Rust const items and functions
//! - Preprocessor conditionals (#ifdef) → cfg attributes (#[cfg(target_os = "...")])
//! - Global mutable daemon struct initialization → immutable default Config construction
//! - Manual string literals → PathBuf for type safety
//! - Integer time values → Duration for overflow protection and clarity
//!
//! # Default Values Source Mapping
//!
//! Each default value is documented with its source from the C implementation:
//!
//! - CACHESIZ (150) from config.h line 423 → cache_size
//! - FTABSIZ (150) from config.h line 116 → ftab_size
//! - NAMESERVER_PORT (53) from dns-protocol.h → port
//! - DHCP_CLIENT_PORT (68) from dhcp-protocol.h → dhcp_client_port
//! - DHCP_SERVER_PORT (67) from dhcp-protocol.h → dhcp_server_port
//! - RESOLVFILE ("/etc/resolv.conf") from config.h line 1616-1618 → resolv_file
//! - CHUSER ("nobody") from config.h line 685 → username
//! - RUNFILE ("/var/run/dnsmasq.pid") from config.h line 1642-1644 → pid_file
//! - MAXLEASES (1000) from config.h line 463 → lease_max
//! - TFTP_MAX_CONNECTIONS (50) from config.h line 720 → tftp_max_connections
//! - EDNS_PKTSZ (4096) from config.h line 213 → edns_packet_max
//! - AUTH_TTL (600) from config.h line 823 → auth_ttl
//! - SOA_REFRESH (1200) from config.h line 841 → soa_refresh
//! - SOA_RETRY (180) from config.h line 858 → soa_retry
//! - SOA_EXPIRY (1209600) from config.h line 875 → soa_expiry
//!
//! # Platform-Specific Defaults
//!
//! Platform-specific paths are handled using Rust's cfg attributes:
//!
//! - Android: `/etc/config/resolv.conf`, `/data/dnsmasq.pid`
//! - Standard Unix: `/etc/resolv.conf`, `/var/run/dnsmasq.pid`
//! - Linux: `/var/lib/misc/dnsmasq.leases`
//! - BSD/macOS: `/var/db/dnsmasq.leases`
//!
//! # Usage
//!
//! ```
//! use dnsmasq::config::defaults::default_config;
//!
//! // Get complete default configuration
//! let config = default_config();
//! assert_eq!(config.dns.port, 53);
//! assert_eq!(config.dns.cache_size, 150);
//!
//! // Get subsystem-specific defaults
//! let dns_config = default_dns_config();
//! let dhcp_config = default_dhcp_config();
//! ```

use std::path::PathBuf;
use std::time::Duration;

use super::types::{
    AuthConfig, Config, DhcpConfig, DnsConfig, IntegrationConfig, LoggingConfig, NetworkConfig,
    ProcessConfig, TftpConfig,
};
use crate::core::config::SOA_EXPIRY;
use crate::dhcp::v4::DHCP_CLIENT_PORT;
use crate::dns::protocol::NAMESERVER_PORT;

/// Creates complete default configuration matching C implementation
///
/// Returns a Config struct with all subsystem defaults initialized to match
/// the C implementation's daemon struct initialization from option.c lines 6631-6649.
/// This configuration provides sensible defaults for basic DNS forwarding and caching.
///
/// # Default Behavior
///
/// - DNS caching enabled with 150-entry cache (CACHESIZ)
/// - DNS listening on port 53 (NAMESERVER_PORT)
/// - DHCP disabled by default (no ranges configured)
/// - TFTP disabled by default
/// - Reads upstream servers from /etc/resolv.conf (platform-specific)
/// - Runs as user "nobody" if started as root
/// - Stores PID in /var/run/dnsmasq.pid (platform-specific)
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_config;
///
/// let config = default_config();
/// assert_eq!(config.dns.port, 53);
/// assert_eq!(config.dns.cache_size, 150);
/// assert_eq!(config.dns.ftab_size, 150);
/// assert_eq!(config.dhcp.lease_max, 1000);
/// ```
///
/// # Original C Source
///
/// From option.c lines 6631-6649:
/// ```c
/// daemon->cachesize = CACHESIZ;
/// daemon->ftabsize = FTABSIZ;
/// daemon->port = NAMESERVER_PORT;
/// daemon->dhcp_client_port = DHCP_CLIENT_PORT;
/// daemon->dhcp_server_port = DHCP_SERVER_PORT;
/// daemon->default_resolv.name = RESOLVFILE;
/// daemon->username = CHUSER;
/// daemon->runfile = RUNFILE;
/// daemon->dhcp_max = MAXLEASES;
/// daemon->tftp_max = TFTP_MAX_CONNECTIONS;
/// daemon->edns_pktsz = EDNS_PKTSZ;
/// daemon->auth_ttl = AUTH_TTL;
/// daemon->soa_refresh = SOA_REFRESH;
/// daemon->soa_retry = SOA_RETRY;
/// daemon->soa_expiry = SOA_EXPIRY;
/// ```
#[must_use]
pub fn default_config() -> Config {
    Config {
        dns: default_dns_config(),
        dhcp: default_dhcp_config(),
        network: default_network_config(),
        tftp: default_tftp_config(),
        process: default_process_config(),
        logging: default_logging_config(),
        integration: default_integration_config(),
        auth: default_auth_config(),
        options: super::types::DaemonOptions::empty(),
    }
}

/// Creates default DNS configuration matching C implementation
///
/// Returns DnsConfig with defaults from config.h and option.c initialization.
/// Matches C daemon->cachesize, daemon->ftabsize, daemon->port, daemon->edns_pktsz,
/// and daemon->default_resolv initialization from option.c lines 6632-6634, 6638, 6644.
///
/// # Default Values
///
/// - cache_size: 150 entries (CACHESIZ from config.h line 423)
/// - ftab_size: 150 max outstanding queries (FTABSIZ from config.h line 116)
/// - port: 53 (NAMESERVER_PORT from dns-protocol.h)
/// - edns_packet_max: 4096 bytes (EDNS_PKTSZ from config.h line 213)
/// - resolv_file: "/etc/resolv.conf" on Unix, "/etc/config/resolv.conf" on Android
///   (RESOLVFILE from config.h lines 1616-1618)
///
/// # Platform-Specific Behavior
///
/// Android systems use `/etc/config/resolv.conf` instead of `/etc/resolv.conf`
/// to match the C implementation's conditional path from config.h:
/// ```c
/// #ifdef __ANDROID__
/// #  define RESOLVFILE "/etc/config/resolv.conf"
/// #else
/// #  define RESOLVFILE "/etc/resolv.conf"
/// #endif
/// ```
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_dns_config;
///
/// let dns = default_dns_config();
/// assert_eq!(dns.cache_size, 150);
/// assert_eq!(dns.ftab_size, 150);
/// assert_eq!(dns.port, 53);
/// assert_eq!(dns.edns_packet_max, 4096);
/// ```
#[must_use]
pub fn default_dns_config() -> DnsConfig {
    // Platform-specific resolv file path (RESOLVFILE from config.h lines 1616-1618)
    #[cfg(target_os = "android")]
    let resolv_file = Some(PathBuf::from("/etc/config/resolv.conf"));
    #[cfg(not(target_os = "android"))]
    let resolv_file = Some(PathBuf::from("/etc/resolv.conf"));

    DnsConfig {
        upstream_servers: Vec::new(),
        local_domains: Vec::new(),
        cache_size: 150,        // CACHESIZ from config.h line 423
        ftab_size: 150,         // FTABSIZ from config.h line 116
        port: NAMESERVER_PORT,  // 53 from dns-protocol.h
        query_port: None,
        min_port: 1024,
        max_port: 65535,
        local_ttl: 0,
        neg_ttl: 300,
        max_ttl: 86400,
        min_cache_ttl: 0,
        max_cache_ttl: 86400,
        edns_packet_max: 4096, // EDNS_PKTSZ from config.h line 213
        resolv_file,           // RESOLVFILE from config.h lines 1616-1618
        servers_file: None,
        mx_names: Vec::new(),
        txt_records: Vec::new(),
        cname_records: Vec::new(),
        host_records: Vec::new(),
        bogus_addresses: Vec::new(),
        query_timeout: None,
    }
}

/// Creates default DHCP configuration matching C implementation
///
/// Returns DhcpConfig with defaults from config.h and option.c initialization.
/// Matches C daemon->dhcp_client_port, daemon->dhcp_server_port, daemon->dhcp_max,
/// and daemon->min_leasetime from option.c lines 6635-6636, 6642.
///
/// # Default Values
///
/// - client_port: 68 (DHCP_CLIENT_PORT from dhcp-protocol.h)
/// - server_port: 67 (DHCP_SERVER_PORT from dhcp-protocol.h)
/// - lease_max: 1000 (MAXLEASES from config.h line 463)
/// - min_lease_time: 120 seconds (C default from config.h)
/// - lease_file: Platform-specific default path:
///   - Android: "/data/misc/dhcp/dnsmasq.leases"
///   - Linux: "/var/lib/misc/dnsmasq.leases"
///   - BSD/macOS: "/var/db/dnsmasq.leases"
///
/// # DHCP Disabled by Default
///
/// No DHCP ranges are configured by default, so DHCP server functionality is
/// effectively disabled until ranges are added via configuration. This matches
/// the C implementation's behavior where DHCP only activates when ranges are
/// specified.
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_dhcp_config;
///
/// let dhcp = default_dhcp_config();
/// assert_eq!(dhcp.client_port, 68);
/// assert_eq!(dhcp.server_port, 67);
/// assert_eq!(dhcp.lease_max, 1000);
/// assert!(dhcp.dhcp_ranges.is_empty()); // DHCP disabled by default
/// ```
#[must_use]
pub fn default_dhcp_config() -> DhcpConfig {
    // Platform-specific lease file path (LEASEFILE from config.h lines 611-631)
    #[cfg(target_os = "android")]
    let lease_file = PathBuf::from("/data/misc/dhcp/dnsmasq.leases");
    #[cfg(all(
        not(target_os = "android"),
        any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "macos")
    ))]
    let lease_file = PathBuf::from("/var/db/dnsmasq.leases");
    #[cfg(all(
        not(target_os = "android"),
        not(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "macos"
        ))
    ))]
    let lease_file = PathBuf::from("/var/lib/misc/dnsmasq.leases");

    DhcpConfig {
        dhcp_ranges: Vec::new(),
        dhcp6_ranges: Vec::new(),
        static_leases: std::collections::HashMap::new(),
        dhcp_options: Vec::new(),
        dhcp6_options: Vec::new(),
        lease_file,
        lease_max: 1000,                             // MAXLEASES from config.h line 463
        server_port: 67,                             // DHCP_SERVER_PORT from dhcp-protocol.h
        client_port: DHCP_CLIENT_PORT,               // 68 from dhcp-protocol.h
        min_lease_time: Duration::from_secs(120),    // Default min lease time
        dhcp_script: None,
        authoritative: false,
        dhcp_hosts_files: Vec::new(),
        dhcp_opts_files: Vec::new(),
    }
}

/// Creates default TFTP configuration matching C implementation
///
/// Returns TftpConfig with defaults from config.h. Matches C daemon->tftp_max
/// initialization from option.c line 6643.
///
/// # Default Values
///
/// - tftp_max_connections: 50 (TFTP_MAX_CONNECTIONS from config.h line 720)
/// - tftp_root: None (TFTP disabled by default)
/// - All other options disabled
///
/// # TFTP Disabled by Default
///
/// TFTP server is disabled by default (tftp_root is None). This matches the
/// C implementation's behavior where TFTP only activates when --enable-tftp
/// is specified with a tftp-root directory.
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_tftp_config;
///
/// let tftp = default_tftp_config();
/// assert_eq!(tftp.tftp_max_connections, 50);
/// assert!(tftp.tftp_root.is_none()); // TFTP disabled by default
/// ```
#[must_use]
pub fn default_tftp_config() -> TftpConfig {
    TftpConfig {
        tftp_root: None,
        secure_mode: false,
        single_port: false,
        port_range: None,
        tftp_mtu: None,
        tftp_max_connections: 50, // TFTP_MAX_CONNECTIONS from config.h line 720
        lowercase: false,
        unique_root: false,
    }
}

/// Creates default authoritative DNS configuration matching C implementation
///
/// Returns AuthConfig with defaults from config.h. Matches C daemon->auth_ttl,
/// daemon->soa_refresh, daemon->soa_retry, daemon->soa_expiry initialization
/// from option.c lines 6646-6649.
///
/// # Default Values
///
/// - auth_ttl: 600 seconds (AUTH_TTL from config.h line 823)
/// - soa_refresh: 1200 seconds (SOA_REFRESH from config.h line 841)
/// - soa_retry: 180 seconds (SOA_RETRY from config.h line 858)
/// - soa_expiry: 1209600 seconds / 2 weeks (SOA_EXPIRY from config.h line 875)
/// - soa_serial: 1 (initial serial number)
///
/// # SOA Record Defaults
///
/// These defaults follow RFC 1035 recommendations for SOA record timing fields.
/// The expiry time of 2 weeks (1209600 seconds) defines the maximum time secondary
/// nameservers can serve stale zone data before expiring the zone.
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_auth_config;
///
/// let auth = default_auth_config();
/// assert_eq!(auth.auth_ttl, 600);
/// assert_eq!(auth.soa_refresh, 1200);
/// assert_eq!(auth.soa_retry, 180);
/// assert_eq!(auth.soa_expiry, 1209600);
/// ```
///
/// # Original C Source
///
/// From option.c lines 6646-6649:
/// ```c
/// daemon->auth_ttl = AUTH_TTL;
/// daemon->soa_refresh = SOA_REFRESH;
/// daemon->soa_retry = SOA_RETRY;
/// daemon->soa_expiry = SOA_EXPIRY;
/// ```
#[must_use]
pub fn default_auth_config() -> AuthConfig {
    AuthConfig {
        auth_zones: Vec::new(),
        auth_server: None,
        auth_ttl: 600,     // AUTH_TTL from config.h line 823
        soa_serial: 1,     // Initial serial number
        soa_refresh: 1200, // SOA_REFRESH from config.h line 841
        soa_retry: 180,    // SOA_RETRY from config.h line 858
        soa_expiry: SOA_EXPIRY.as_secs(), // 1209600 from config.h line 875
    }
}

/// Creates default network configuration matching C implementation
///
/// Returns NetworkConfig with defaults matching C daemon initialization.
/// By default, dnsmasq listens on all interfaces unless explicitly restricted.
///
/// # Default Behavior
///
/// - interfaces: Empty (listen on all interfaces)
/// - listen_addresses: Empty (listen on all addresses)
/// - except_interfaces: Empty (no interface restrictions)
/// - bind_interfaces: false (don't bind to specific interfaces)
/// - bind_dynamic: false (static interface binding)
///
/// # Interface Binding
///
/// The empty interface list means dnsmasq will listen on all available network
/// interfaces, matching the C implementation's default behavior. Users can restrict
/// this via configuration with --interface or --listen-address options.
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_network_config;
///
/// let network = default_network_config();
/// assert!(network.interfaces.is_empty());
/// assert!(network.listen_addresses.is_empty());
/// assert!(!network.bind_interfaces);
/// ```
#[must_use]
pub fn default_network_config() -> NetworkConfig {
    NetworkConfig {
        interfaces: Vec::new(),
        listen_addresses: Vec::new(),
        except_interfaces: Vec::new(),
        bind_interfaces: false,
        bind_dynamic: false,
    }
}

/// Creates default process configuration matching C implementation
///
/// Returns ProcessConfig with defaults from config.h. Matches C daemon->username
/// and daemon->runfile initialization from option.c lines 6640-6641.
///
/// # Default Values
///
/// - username: Some("nobody") (CHUSER from config.h line 685)
/// - groupname: None (inherit from username)
/// - pid_file: Platform-specific:
///   - Android: Some("/data/dnsmasq.pid")
///   - Standard Unix: Some("/var/run/dnsmasq.pid")
/// - daemonize: true (fork to background)
///
/// # Privilege Dropping
///
/// By default, dnsmasq drops privileges to user "nobody" after binding to privileged
/// ports. This matches the C implementation's CHUSER default from config.h line 685.
/// If dnsmasq is not started as root, the privilege drop is skipped at runtime.
///
/// # Platform-Specific PID File
///
/// Android systems use `/data/dnsmasq.pid` while standard Unix systems use
/// `/var/run/dnsmasq.pid`, matching the C implementation's conditional path
/// from config.h lines 1642-1644:
/// ```c
/// #ifdef __ANDROID__
/// #  define RUNFILE "/data/dnsmasq.pid"
/// #else
/// #  define RUNFILE "/var/run/dnsmasq.pid"
/// #endif
/// ```
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_process_config;
///
/// let process = default_process_config();
/// assert_eq!(process.username, Some("nobody".to_string()));
/// assert!(process.pid_file.is_some());
/// assert!(process.daemonize);
/// ```
///
/// # Original C Source
///
/// From option.c lines 6640-6641:
/// ```c
/// daemon->username = CHUSER;
/// daemon->runfile = RUNFILE;
/// ```
#[must_use]
pub fn default_process_config() -> ProcessConfig {
    // Platform-specific PID file path (RUNFILE from config.h lines 1642-1644)
    #[cfg(target_os = "android")]
    let pid_file = Some(PathBuf::from("/data/dnsmasq.pid"));
    #[cfg(not(target_os = "android"))]
    let pid_file = Some(PathBuf::from("/var/run/dnsmasq.pid"));

    ProcessConfig {
        username: Some("nobody".to_string()), // CHUSER from config.h line 685
        groupname: None,
        pid_file,                             // RUNFILE from config.h lines 1642-1644
        script_user: None,
        daemonize: true,
        change_dir: None,
    }
}

/// Creates default logging configuration matching C implementation
///
/// Returns LoggingConfig with defaults matching C daemon initialization.
/// By default, dnsmasq logs to syslog with facility LOG_DAEMON.
///
/// # Default Behavior
///
/// - Logging to syslog (facility: -1 indicates system default, LOG_DAEMON)
/// - No log file (syslog only)
/// - No async logging (synchronous syslog calls)
/// - Query logging disabled
/// - Standard verbosity (not debug mode)
///
/// # Syslog Configuration
///
/// The log_fac value of -1 matches C daemon->log_fac initialization from
/// option.c line 6645, which indicates use of the default syslog facility
/// (LOG_DAEMON). This can be overridden with --log-facility option.
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_logging_config;
///
/// let logging = default_logging_config();
/// assert_eq!(logging.log_fac, -1);
/// assert!(logging.log_file.is_none());
/// assert!(!logging.log_queries);
/// ```
#[must_use]
pub fn default_logging_config() -> LoggingConfig {
    LoggingConfig {
        log_fac: -1, // Default syslog facility (LOG_DAEMON), from option.c line 6645
        log_file: None,
        log_async: false,
        log_queries: false,
        log_debug: false,
    }
}

/// Creates default integration configuration matching C implementation
///
/// Returns IntegrationConfig with all optional integrations disabled by default.
/// Optional features (D-Bus, ubus, conntrack, ipset, nftables) are disabled unless
/// explicitly enabled via configuration.
///
/// # Default Behavior
///
/// - D-Bus: Disabled (enable with --enable-dbus)
/// - ubus: Disabled (OpenWrt-specific, enable with --enable-ubus)
/// - conntrack: Disabled (enable with --conntrack)
/// - ipset: Empty (no ipset rules configured)
/// - nftset: Empty (no nftables rules configured)
///
/// # Optional Features
///
/// All integration features are compile-time optional via Cargo features and
/// runtime optional via configuration. This matches the C implementation's
/// HAVE_* conditional compilation and runtime option flags.
///
/// # Example
///
/// ```
/// use dnsmasq::config::defaults::default_integration_config;
///
/// let integration = default_integration_config();
/// assert!(!integration.dbus_enabled);
/// assert!(!integration.ubus_enabled);
/// assert!(integration.ipsets.is_empty());
/// ```
#[must_use]
pub fn default_integration_config() -> IntegrationConfig {
    IntegrationConfig {
        dbus_enabled: false,
        dbus_service_name: None,
        ubus_enabled: false,
        ubus_socket: None,
        conntrack_enabled: false,
        ipsets: Vec::new(),
        nftsets: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_construction() {
        let config = default_config();
        assert_eq!(config.dns.port, 53);
        assert_eq!(config.dns.cache_size, 150);
        assert_eq!(config.dns.ftab_size, 150);
        assert_eq!(config.dhcp.lease_max, 1000);
        assert_eq!(config.tftp.tftp_max_connections, 50);
    }

    #[test]
    fn test_default_dns_config() {
        let dns = default_dns_config();
        assert_eq!(dns.cache_size, 150); // CACHESIZ
        assert_eq!(dns.ftab_size, 150); // FTABSIZ
        assert_eq!(dns.port, 53); // NAMESERVER_PORT
        assert_eq!(dns.edns_packet_max, 4096); // EDNS_PKTSZ
        assert!(dns.resolv_file.is_some());
    }

    #[test]
    fn test_default_dhcp_config() {
        let dhcp = default_dhcp_config();
        assert_eq!(dhcp.client_port, 68); // DHCP_CLIENT_PORT
        assert_eq!(dhcp.server_port, 67); // DHCP_SERVER_PORT
        assert_eq!(dhcp.lease_max, 1000); // MAXLEASES
        assert_eq!(dhcp.min_lease_time, Duration::from_secs(120));
        assert!(dhcp.dhcp_ranges.is_empty());
    }

    #[test]
    fn test_default_tftp_config() {
        let tftp = default_tftp_config();
        assert_eq!(tftp.tftp_max_connections, 50); // TFTP_MAX_CONNECTIONS
        assert!(tftp.tftp_root.is_none());
    }

    #[test]
    fn test_default_auth_config() {
        let auth = default_auth_config();
        assert_eq!(auth.auth_ttl, 600); // AUTH_TTL
        assert_eq!(auth.soa_refresh, 1200); // SOA_REFRESH
        assert_eq!(auth.soa_retry, 180); // SOA_RETRY
        assert_eq!(auth.soa_expiry, 1_209_600); // SOA_EXPIRY
    }

    #[test]
    fn test_default_process_config() {
        let process = default_process_config();
        assert_eq!(process.username, Some("nobody".to_string())); // CHUSER
        assert!(process.pid_file.is_some());
        assert!(process.daemonize);
    }

    #[test]
    fn test_platform_specific_paths() {
        let dns = default_dns_config();
        let process = default_process_config();
        let dhcp = default_dhcp_config();

        // Verify platform-specific paths are set (actual values depend on target_os)
        assert!(dns.resolv_file.is_some());
        assert!(process.pid_file.is_some());
        assert!(!dhcp.lease_file.as_os_str().is_empty());
    }

    #[test]
    fn test_duration_usage() {
        let dhcp = default_dhcp_config();
        // Verify Duration types are used correctly (members_accessed requirement)
        assert_eq!(dhcp.min_lease_time.as_secs(), 120);
    }
}
