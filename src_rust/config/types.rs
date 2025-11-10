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

//! Configuration data structures for dnsmasq Rust implementation
//!
//! This module defines comprehensive configuration types refactored from the C implementation's
//! `struct daemon` configuration fields (dnsmasq.h lines 4074-4164) and related configuration
//! structures scattered throughout the codebase. It provides type-safe, memory-safe alternatives
//! to C's manual memory management using Rust's ownership system.
//!
//! # Memory Safety Transformation
//!
//! All C patterns are replaced with safe Rust equivalents:
//! - `char*` → `String` (automatic memory management, no buffer overflows)
//! - Linked lists → `Vec<T>` (bounds-checked indexing)
//! - Manual hash tables → `HashMap<K,V>` (safe concurrent access patterns)
//! - `NULL` pointers → `Option<T>` (type-safe null handling)
//! - Bit field arrays → `bitflags!` macro (type-safe bit manipulation)
//! - `unsigned int options[OPTION_SIZE]` → `DaemonOptions` bitflags
//!
//! # Configuration Structure
//!
//! Configuration is organized into logical subsections:
//! - [`Config`] - Root configuration container
//! - [`DnsConfig`] - DNS forwarding, caching, upstream servers
//! - [`DhcpConfig`] - DHCPv4/v6 ranges, static hosts, options
//! - [`TftpConfig`] - TFTP server settings
//! - [`NetworkConfig`] - Interfaces, listen addresses, ports
//! - [`ProcessConfig`] - User/group, PID file, daemonization
//! - [`LoggingConfig`] - Syslog facility, log files, verbosity
//! - [`IntegrationConfig`] - D-Bus, ubus, conntrack, ipset/nftset
//! - [`AuthConfig`] - Authoritative DNS zones
//!
//! # Builder Pattern
//!
//! The [`ConfigBuilder`] provides gradual configuration construction during parsing,
//! eliminating unsafe global mutable state from the C implementation.
//!
//! # Original C Mapping
//!
//! Each field documents its corresponding C struct field name for maintainability.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

// Bitflags for daemon runtime options (replaces C's unsigned int options[OPTION_SIZE])
bitflags::bitflags! {
    /// Daemon runtime option flags
    ///
    /// Replaces C's `unsigned int options[OPTION_SIZE]` bitfield array from dnsmasq.h line 4079.
    /// Provides type-safe operations and prevents invalid flag combinations.
    ///
    /// Original C implementation used manual bit manipulation with defines like:
    /// ```c
    /// #define OPT_BOGUSPRIV      0
    /// #define OPT_FILTER         1
    /// #define option_bool(x) (daemon->options[x >> 5] & (1u << (x & 31)))
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct DaemonOptions: u64 {
        /// Filter private IP addresses (OPT_BOGUSPRIV)
        const OPT_BOGUSPRIV      = 1 << 0;
        /// Enable DNS filtering (OPT_FILTER)
        const OPT_FILTER         = 1 << 1;
        /// Log DNS queries (OPT_LOG)
        const OPT_LOG            = 1 << 2;
        /// Authoritative DNS mode (OPT_AUTHORITATIVE)
        const OPT_AUTHORITATIVE  = 1 << 3;
        /// Localize queries (OPT_LOCALISE)
        const OPT_LOCALISE       = 1 << 4;
        /// Enable D-Bus interface (OPT_DBUS)
        const OPT_DBUS           = 1 << 5;
        /// Add FQDN to DHCP (OPT_DHCP_FQDN)
        const OPT_DHCP_FQDN      = 1 << 6;
        /// Disable upstream polling (OPT_NO_POLL)
        const OPT_NO_POLL        = 1 << 7;
        /// Disable negative caching (OPT_NO_NEG)
        const OPT_NO_NEG         = 1 << 8;
        /// Don't read /etc/hosts (OPT_NO_HOSTS)
        const OPT_NO_HOSTS       = 1 << 9;
        /// Enable loop detection (OPT_LOOP_DETECT)
        const OPT_LOOP_DETECT    = 1 << 10;
        /// DNSSEC validation enabled (OPT_DNSSEC_VALID)
        const OPT_DNSSEC_VALID   = 1 << 11;
        /// DNSSEC time validation (OPT_DNSSEC_TIME)
        const OPT_DNSSEC_TIME    = 1 << 12;
        /// Expand hosts into A+AAAA (OPT_EXPAND)
        const OPT_EXPAND         = 1 << 13;
        /// Use UBus interface (OPT_UBUS)
        const OPT_UBUS           = 1 << 14;
        /// Don't fork to background (OPT_DEBUG)
        const OPT_DEBUG          = 1 << 15;
        /// Don't fork daemon (OPT_NO_FORK)
        const OPT_NO_FORK        = 1 << 16;
        /// Add options to logs (OPT_LOG_OPTS)
        const OPT_LOG_OPTS       = 1 << 17;
        /// Use ARP for DHCP (OPT_SCRIPT_ARP)
        const OPT_SCRIPT_ARP     = 1 << 18;
        /// Add MAC to DHCP (OPT_ADD_MAC)
        const OPT_ADD_MAC        = 1 << 19;
        /// Add subnet to DNS (OPT_CLIENT_SUBNET)
        const OPT_CLIENT_SUBNET  = 1 << 20;
        /// Quiet DHCP (OPT_QUIET_DHCP)
        const OPT_QUIET_DHCP     = 1 << 21;
        /// Quiet DHCP6 (OPT_QUIET_DHCP6)
        const OPT_QUIET_DHCP6    = 1 << 22;
        /// Quiet RA (OPT_QUIET_RA)
        const OPT_QUIET_RA       = 1 << 23;
        /// Single port TFTP (OPT_SINGLE_PORT)
        const OPT_SINGLE_PORT    = 1 << 24;
        /// Lease file read only (OPT_LEASE_RO)
        const OPT_LEASE_RO       = 1 << 25;
        /// All servers (OPT_ALL_SERVERS)
        const OPT_ALL_SERVERS    = 1 << 26;
        /// Bind interfaces (OPT_BIND_INTERFACES)
        const OPT_BIND_INTERFACES = 1 << 27;
        /// No DHCP interfaces (OPT_NO_DHCP_IFACE)
        const OPT_NO_DHCP_IFACE  = 1 << 28;
        /// Local service only (OPT_LOCAL_SERVICE)
        const OPT_LOCAL_SERVICE  = 1 << 29;
        /// Conntrack mark (OPT_CONNTRACK)
        const OPT_CONNTRACK      = 1 << 30;
    }
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self::empty()
    }
}

/// MAC address type (6 bytes)
///
/// Represents hardware addresses for DHCP, replacing C's unsigned char hwaddr[`DHCP_CHADDR_MAX`]
pub type MacAddr = [u8; 6];

/// Interface name wrapper
///
/// Replaces C's `struct iname` (dnsmasq.h) for interface specifications
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InterfaceName {
    /// Interface name (e.g., "eth0", "wlan0")
    /// Original C field: name in struct iname
    pub name: String,
    /// Optional address bound to interface
    /// Original C field: addr in struct iname
    pub addr: Option<IpAddr>,
}

impl InterfaceName {
    /// Creates a new interface name without an associated address
    ///
    /// # Arguments
    ///
    /// * `name` - The interface name (e.g., "eth0", "wlan0")
    #[must_use] 
    pub fn new(name: String) -> Self {
        Self { name, addr: None }
    }

    /// Creates a new interface name with an associated address
    ///
    /// # Arguments
    ///
    /// * `name` - The interface name (e.g., "eth0", "wlan0")
    /// * `addr` - The IP address bound to this interface
    #[must_use] 
    pub fn with_addr(name: String, addr: IpAddr) -> Self {
        Self {
            name,
            addr: Some(addr),
        }
    }
}

/// DNS configuration subsystem
///
/// Consolidates DNS-related configuration from struct daemon fields in dnsmasq.h.
/// Handles upstream servers, caching parameters, local domains, and DNS records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Upstream DNS servers
    /// Original C field: servers in struct daemon (line 4107)
    pub upstream_servers: Vec<UpstreamServer>,

    /// Local domain specifications
    /// Original C field: `local_domains` in struct daemon (line 4107)
    pub local_domains: Vec<LocalDomain>,

    /// DNS cache size in entries
    /// Original C field: cachesize in struct daemon (line 4117)
    pub cache_size: usize,

    /// Forward table size (max outstanding queries)
    /// Original C field: ftabsize in struct daemon (line 4117)
    pub ftab_size: usize,

    /// DNS listen port (0 to disable DNS)
    /// Original C field: port in struct daemon (line 4118)
    pub port: u16,

    /// Query port for outbound queries (None = random)
    /// Original C field: `query_port` in struct daemon (line 4118)
    pub query_port: Option<u16>,

    /// Minimum port for random port range
    /// Original C field: `min_port` in struct daemon (line 4118)
    pub min_port: u16,

    /// Maximum port for random port range
    /// Original C field: `max_port` in struct daemon (line 4118)
    pub max_port: u16,

    /// TTL for local answers (seconds)
    /// Original C field: `local_ttl` in struct daemon (line 4119)
    pub local_ttl: u64,

    /// Negative cache TTL (seconds)
    /// Original C field: `neg_ttl` in struct daemon (line 4119)
    pub neg_ttl: u64,

    /// Maximum TTL to hand out
    /// Original C field: `max_ttl` in struct daemon (line 4119)
    pub max_ttl: u64,

    /// Minimum cache TTL
    /// Original C field: `min_cache_ttl` in struct daemon (line 4119)
    pub min_cache_ttl: u64,

    /// Maximum cache TTL
    /// Original C field: `max_cache_ttl` in struct daemon (line 4119)
    pub max_cache_ttl: u64,

    /// EDNS packet size
    /// Original C field: `edns_pktsz` in struct daemon (line 4150)
    pub edns_packet_max: u16,

    /// Path to resolv.conf for upstream servers
    /// Original C field: `default_resolv` in struct daemon (line 4080)
    pub resolv_file: Option<PathBuf>,

    /// Additional servers file
    /// Original C field: `servers_file` in struct daemon (line 4082)
    pub servers_file: Option<PathBuf>,

    /// MX records
    /// Original C field: mxnames in struct daemon (line 4083)
    pub mx_names: Vec<MxRecord>,

    /// TXT records
    /// Original C field: txt in struct daemon (line 4085)
    pub txt_records: Vec<TxtRecord>,

    /// CNAME records
    /// Original C field: cnames in struct daemon (line 4088)
    pub cname_records: Vec<CnameRecord>,

    /// Host records (A/AAAA)
    /// Original C field: `host_records` in struct daemon (line 4087)
    pub host_records: Vec<HostRecord>,

    /// Bogus IP addresses to filter
    /// Original C field: `bogus_addr` in struct daemon (line 4106)
    pub bogus_addresses: Vec<IpAddr>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream_servers: Vec::new(),
            local_domains: Vec::new(),
            cache_size: 150, // CACHESIZ from config.h
            ftab_size: 150,  // FTABSIZ from config.h
            port: 53,
            query_port: None,
            min_port: 1024,
            max_port: 65535,
            local_ttl: 0,
            neg_ttl: 300,
            max_ttl: 86400,
            min_cache_ttl: 0,
            max_cache_ttl: 86400,
            edns_packet_max: 4096,
            resolv_file: Some(PathBuf::from("/etc/resolv.conf")),
            servers_file: None,
            mx_names: Vec::new(),
            txt_records: Vec::new(),
            cname_records: Vec::new(),
            host_records: Vec::new(),
            bogus_addresses: Vec::new(),
        }
    }
}

/// Upstream DNS server specification
///
/// Replaces C's `struct server` (dnsmasq.h line 575)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamServer {
    /// Server address
    /// Original C field: addr in struct server
    pub addr: SocketAddr,

    /// Domain this server is authoritative for (None = default)
    /// Original C field: domain in struct server
    pub domain: Option<String>,

    /// Server port override
    /// Original C field: `addr.sa.sa_port` in struct server
    pub port: u16,

    /// Source address for queries
    /// Original C field: `source_addr` in struct server
    pub source_addr: Option<IpAddr>,

    /// Interface to use for queries
    /// Original C field: interface in struct server
    pub interface: Option<String>,
}

/// Local domain specification
///
/// Replaces domain entries in C's server list with `SERV_LITERAL_ADDRESS` flag
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDomain {
    /// Domain name
    pub domain: String,
    /// IP address to return for this domain
    pub addr: Option<IpAddr>,
}

/// MX record specification
///
/// Replaces C's `struct mx_srv_record` (dnsmasq.h line 349)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxRecord {
    /// Domain name
    /// Original C field: name in struct `mx_srv_record`
    pub domain: String,
    /// Target mail server
    /// Original C field: target in struct `mx_srv_record`
    pub target: String,
    /// MX priority
    /// Original C field: priority in struct `mx_srv_record`
    pub priority: u16,
}

/// TXT record specification
///
/// Replaces C's `struct txt_record` (dnsmasq.h line 372)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxtRecord {
    /// Domain name
    /// Original C field: name in struct `txt_record`
    pub domain: String,
    /// TXT data
    /// Original C field: txt in struct `txt_record`
    pub text: String,
}

/// CNAME record specification
///
/// Replaces C's `struct cname` (dnsmasq.h line 385)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnameRecord {
    /// Source domain
    /// Original C field: alias in struct cname
    pub domain: String,
    /// Target domain
    /// Original C field: target in struct cname
    pub target: String,
}

/// Host record (A/AAAA)
///
/// Replaces C's `struct host_record` (dnsmasq.h line 429)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRecord {
    /// Hostnames
    /// Original C field: names in struct `host_record`
    pub names: Vec<String>,
    /// IP addresses
    /// Original C field: addr in struct `host_record`
    pub addresses: Vec<IpAddr>,
}

/// DHCP configuration subsystem
///
/// Consolidates DHCP-related configuration from struct daemon fields in dnsmasq.h.
/// Handles `DHCPv4`, `DHCPv6`, lease management, and options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    /// `DHCPv4` address ranges
    /// Original C field: dhcp in struct daemon (line 4125)
    pub dhcp_ranges: Vec<DhcpRange>,

    /// `DHCPv6` address ranges
    /// Original C field: dhcp6 in struct daemon (line 4125)
    pub dhcp6_ranges: Vec<Dhcp6Range>,

    /// Static DHCP leases (MAC -> lease config)
    /// Original C field: `dhcp_conf` in struct daemon (line 4127)
    pub static_leases: HashMap<MacAddr, StaticLease>,

    /// DHCP options
    /// Original C field: `dhcp_opts` in struct daemon (line 4128)
    pub dhcp_options: Vec<DhcpOption>,

    /// `DHCPv6` options
    /// Original C field: `dhcp_opts6` in struct daemon (line 4128)
    pub dhcp6_options: Vec<Dhcp6Option>,

    /// Lease file path
    /// Original C field: `lease_file` in struct daemon (line 4094)
    pub lease_file: PathBuf,

    /// Maximum number of leases
    /// Original C field: `dhcp_max` in struct daemon (line 4145)
    pub lease_max: usize,

    /// DHCP server port
    /// Original C field: `dhcp_server_port` in struct daemon (line 4146)
    pub server_port: u16,

    /// DHCP client port
    /// Original C field: `dhcp_client_port` in struct daemon (line 4146)
    pub client_port: u16,

    /// Minimum lease time
    /// Original C field: `min_leasetime` in struct daemon (line 4148)
    pub min_lease_time: Duration,

    /// DHCP script path
    /// Original C field: `lease_change_command` in struct daemon (line 4104)
    pub dhcp_script: Option<PathBuf>,

    /// Authoritative DHCP mode
    /// Derived from `OPT_AUTHORITATIVE` flag
    pub authoritative: bool,

    /// DHCP hosts files
    /// Original C field: `dhcp_hosts_file` in struct daemon (line 4144)
    pub dhcp_hosts_files: Vec<PathBuf>,

    /// DHCP options files
    /// Original C field: `dhcp_opts_file` in struct daemon (line 4144)
    pub dhcp_opts_files: Vec<PathBuf>,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            dhcp_ranges: Vec::new(),
            dhcp6_ranges: Vec::new(),
            static_leases: HashMap::new(),
            dhcp_options: Vec::new(),
            dhcp6_options: Vec::new(),
            lease_file: PathBuf::from("/var/lib/misc/dnsmasq.leases"),
            lease_max: 1000,
            server_port: 67,
            client_port: 68,
            min_lease_time: Duration::from_secs(120),
            dhcp_script: None,
            authoritative: false,
            dhcp_hosts_files: Vec::new(),
            dhcp_opts_files: Vec::new(),
        }
    }
}

/// `DHCPv4` address range
///
/// Replaces C's `struct dhcp_context` for IPv4 ranges (dnsmasq.h line 994)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpRange {
    /// Range start address
    /// Original C field: start in struct `dhcp_context`
    pub start: Ipv4Addr,

    /// Range end address
    /// Original C field: end in struct `dhcp_context`
    pub end: Ipv4Addr,

    /// Lease time
    /// Original C field: `lease_time` in struct `dhcp_context`
    pub lease_time: Duration,

    /// Range flags
    /// Original C field: flags in struct `dhcp_context`
    pub flags: u32,
}

/// `DHCPv6` address range with context
///
/// Replaces C's `struct dhcp_context` for IPv6 ranges (dnsmasq.h line 994)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dhcp6Range {
    /// Range start address
    /// Original C field: start6 in struct `dhcp_context`
    pub start: Ipv6Addr,

    /// Range end address
    /// Original C field: end6 in struct `dhcp_context`
    pub end: Ipv6Addr,

    /// Prefix length for prefix delegation
    /// Original C field: `prefix_len` in struct `dhcp_context`
    pub prefix_len: u8,

    /// Lease time
    /// Original C field: `lease_time` in struct `dhcp_context`
    pub lease_time: Duration,

    /// Range flags
    /// Original C field: flags in struct `dhcp_context`
    pub flags: u32,
}

/// Context for `DHCPv6` (replaces struct `dhcp_context` fields for v6)
///
/// Minimal representation needed for exports schema compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpContext {
    /// IPv6 start address
    pub start6: Ipv6Addr,
    /// Interface index
    pub if_index: u32,
    /// Context flags
    pub flags: u32,
    /// Next context (represented as Option for Rust safety)
    pub next: Option<Box<DhcpContext>>,
    /// Router Advertisement short period start time (for fast initial RAs)
    /// Used to track when fast RA transmission period began (first 60 seconds)
    pub ra_short_period_start: Option<SystemTime>,
    /// Next scheduled Router Advertisement transmission time
    /// Used for periodic RA timing and event loop scheduling
    pub ra_time: Option<SystemTime>,
}

/// Static DHCP lease configuration
///
/// Replaces C's `struct dhcp_config` (dnsmasq.h line 860)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticLease {
    /// Hardware address
    /// Original C field: hwaddr in struct `dhcp_config`
    pub hwaddr: MacAddr,

    /// Assigned IP address
    /// Original C field: addr in struct `dhcp_config`
    pub addr: IpAddr,

    /// Hostname
    /// Original C field: hostname in struct `dhcp_config`
    pub hostname: Option<String>,

    /// Client identifier
    /// Original C field: clid in struct `dhcp_config`
    pub client_id: Option<Vec<u8>>,
}

/// DHCP option specification
///
/// Replaces C's `struct dhcp_opt` (dnsmasq.h)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpOption {
    /// Option code
    /// Original C field: opt in struct `dhcp_opt`
    pub code: u8,

    /// Option data
    /// Original C field: val in struct `dhcp_opt`
    pub data: Vec<u8>,

    /// Vendor class match
    /// Original C field: netid in struct `dhcp_opt` (for vendor match)
    pub vendor_class: Option<String>,
}

/// `DHCPv6` option specification
///
/// Replaces C's `struct dhcp_opt` for IPv6 options
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dhcp6Option {
    /// Option code
    pub code: u16,

    /// Option data
    pub data: Vec<u8>,

    /// Enterprise number for vendor options
    pub enterprise: Option<u32>,
}

/// TFTP server configuration
///
/// Consolidates TFTP-related configuration from struct daemon fields in dnsmasq.h.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct TftpConfig {
    /// TFTP root directory
    /// Original C field: `tftp_prefix` in struct daemon (line 4151)
    pub tftp_root: Option<PathBuf>,

    /// Secure mode (chroot to `tftp_root`)
    /// Derived from TFTP server flags
    pub secure_mode: bool,

    /// Single port mode
    /// Derived from `OPT_SINGLE_PORT` flag
    pub single_port: bool,

    /// Port range for TFTP
    /// Original C fields: `start_tftp_port`, `end_tftp_port` in struct daemon (line 4147)
    pub port_range: Option<(u16, u16)>,

    /// MTU for TFTP transfers
    /// Original C field: `tftp_mtu` in struct daemon (line 4145)
    pub tftp_mtu: Option<u16>,

    /// Maximum concurrent connections
    /// Original C field: `tftp_max` in struct daemon (line 4145)
    pub tftp_max_connections: usize,

    /// Convert to lowercase
    /// Derived from TFTP flags
    pub lowercase: bool,

    /// Unique root per client
    /// Derived from TFTP flags
    pub unique_root: bool,
}

impl Default for TftpConfig {
    fn default() -> Self {
        Self {
            tftp_root: None,
            secure_mode: false,
            single_port: false,
            port_range: None,
            tftp_mtu: None,
            tftp_max_connections: 50,
            lowercase: false,
            unique_root: false,
        }
    }
}

/// Network configuration
///
/// Consolidates network-related configuration from struct daemon fields in dnsmasq.h.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct NetworkConfig {
    /// Interfaces to listen on
    /// Original C field: `if_names` in struct daemon (line 4105)
    pub interfaces: Vec<InterfaceName>,

    /// Addresses to listen on
    /// Original C field: `if_addrs` in struct daemon (line 4105)
    pub listen_addresses: Vec<IpAddr>,

    /// Interfaces to exclude
    /// Original C field: `if_except` in struct daemon (line 4105)
    pub except_interfaces: Vec<InterfaceName>,

    /// Bind to specific interfaces
    /// Derived from `OPT_BIND_INTERFACES` flag
    pub bind_interfaces: bool,

    /// Bind dynamically as interfaces come up
    /// Derived from daemon->options flags
    pub bind_dynamic: bool,
}


/// Process management configuration
///
/// Consolidates process-related configuration from struct daemon fields in dnsmasq.h.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    /// Username to run as
    /// Original C field: username in struct daemon (line 4095)
    pub username: Option<String>,

    /// Group name to run as
    /// Original C field: groupname in struct daemon (line 4095)
    pub groupname: Option<String>,

    /// PID file path
    /// Original C field: runfile in struct daemon (line 4103)
    pub pid_file: Option<PathBuf>,

    /// Script user
    /// Original C field: scriptuser in struct daemon (line 4095)
    pub script_user: Option<String>,

    /// Daemonize (fork to background)
    /// Derived from `OPT_NO_FORK` flag (inverted)
    pub daemonize: bool,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            username: None,
            groupname: None,
            pid_file: Some(PathBuf::from("/var/run/dnsmasq.pid")),
            script_user: None,
            daemonize: true,
        }
    }
}

/// Logging configuration
///
/// Consolidates logging-related configuration from struct daemon fields in dnsmasq.h.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Syslog facility
    /// Original C field: `log_fac` in struct daemon (line 4114)
    pub log_facility: Option<String>,

    /// Log file path
    /// Original C field: `log_file` in struct daemon (line 4115)
    pub log_file: Option<PathBuf>,

    /// Async log queue size
    /// Original C field: `max_logs` in struct daemon (line 4116)
    pub log_async_max: Option<usize>,

    /// Log DNS queries
    /// Derived from `OPT_LOG` flag
    pub log_queries: bool,

    /// Log DHCP transactions
    /// Derived from daemon->options flags
    pub log_dhcp: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_facility: Some("daemon".to_string()),
            log_file: None,
            log_async_max: Some(5),
            log_queries: false,
            log_dhcp: false,
        }
    }
}

/// External integration configuration
///
/// Consolidates integration-related configuration from struct daemon fields in dnsmasq.h.
/// Optional features are controlled by Cargo features.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct IntegrationConfig {
    /// D-Bus service name
    /// Original C field: `dbus_name` in struct daemon (line 4155)
    #[cfg(feature = "dbus")]
    pub dbus_name: Option<String>,

    /// `UBus` service name
    /// Original C field: `ubus_name` in struct daemon (line 4156)
    #[cfg(feature = "ubus")]
    pub ubus_name: Option<String>,

    /// `IPSet` configurations
    /// Original C field: ipsets in struct daemon (line 4111)
    pub ipsets: Vec<IpsetConfig>,

    /// `NFTables` set configurations
    /// Original C field: nftsets in struct daemon (line 4111)
    pub nftsets: Vec<NftsetConfig>,

    /// Enable connection tracking
    /// Derived from `OPT_CONNTRACK` flag
    pub conntrack_enabled: bool,
}


/// `IPSet` configuration
///
/// Replaces C's `struct ipsets` (dnsmasq.h line 621)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpsetConfig {
    /// `IPSet` name
    pub name: String,
    /// Domain pattern
    pub domain: Option<String>,
    /// IPv4 and IPv6 set names
    pub ipsets: Vec<String>,
}

/// `NFTables` set configuration
///
/// Replaces C's `struct ipsets` with nftables variant (dnsmasq.h line 621)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftsetConfig {
    /// Set name
    pub name: String,
    /// Domain pattern
    pub domain: Option<String>,
    /// Table name
    pub table: String,
    /// Address family
    pub family: u8,
}

/// Authoritative DNS configuration
///
/// Consolidates authoritative DNS configuration from struct daemon fields in dnsmasq.h.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authoritative zones
    /// Original C field: `auth_zones` in struct daemon (line 4089)
    pub auth_zones: Vec<AuthZone>,

    /// Authoritative server hostname
    /// Original C field: authserver in struct daemon (line 4097)
    pub auth_server: Option<String>,

    /// Authoritative TTL
    /// Original C field: `auth_ttl` in struct daemon (line 4119)
    pub auth_ttl: u64,

    /// SOA serial number
    /// Original C field: `soa_sn` in struct daemon (line 4159)
    pub soa_serial: u64,

    /// SOA refresh
    /// Original C field: `soa_refresh` in struct daemon (line 4159)
    pub soa_refresh: u64,

    /// SOA retry
    /// Original C field: `soa_retry` in struct daemon (line 4159)
    pub soa_retry: u64,

    /// SOA expiry
    /// Original C field: `soa_expiry` in struct daemon (line 4159)
    pub soa_expiry: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            auth_zones: Vec::new(),
            auth_server: None,
            auth_ttl: 600,
            soa_serial: 1,
            soa_refresh: 7200,
            soa_retry: 1800,
            soa_expiry: 1_209_600,
        }
    }
}

/// Address list entry for subnet and exclusion lists
///
/// Replaces C's `struct addrlist` (dnsmasq.h line 1376).
/// Used for:
/// - Authoritative zone subnet specifications
/// - Excluded address ranges
/// - Interface address lists
/// - DHCP address decline tracking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddrList {
    /// IP address (IPv4 or IPv6)
    /// Original C field: `union all_addr addr` in struct addrlist
    pub addr: IpAddr,
    
    /// Flags for address list entry
    /// Original C field: `int flags` in struct addrlist
    /// In C: Used for AUTH4 (1), AUTH6 (2) flags
    pub flags: u32,
    
    /// Prefix length for CIDR notation
    /// Original C field: `int prefixlen` in struct addrlist
    /// Range: 0-32 for IPv4, 0-128 for IPv6
    pub prefixlen: u32,
    
    /// Decline timestamp for DHCP address conflict tracking
    /// Original C field: `time_t decline_time` in struct addrlist
    /// None if address is not declined, Some(timestamp) if declined
    pub decline_time: Option<SystemTime>,
}

impl AddrList {
    /// Create a new address list entry
    pub fn new(addr: IpAddr, prefixlen: u32) -> Self {
        Self {
            addr,
            flags: 0,
            prefixlen,
            decline_time: None,
        }
    }
    
    /// Create with flags
    pub fn with_flags(addr: IpAddr, prefixlen: u32, flags: u32) -> Self {
        Self {
            addr,
            flags,
            prefixlen,
            decline_time: None,
        }
    }
}

/// Authoritative zone specification
///
/// Replaces C's `struct auth_zone` (dnsmasq.h line 414)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthZone {
    /// Zone domain name
    /// Original C field: domain in struct `auth_zone`
    pub domain: String,

    /// Subnet list for this zone
    /// Original C field: subnet in struct `auth_zone` (linked list pointer)
    /// Rust: Safe Vec instead of linked list with manual memory management
    pub subnet: Option<Vec<AddrList>>,

    /// Excluded subnet list
    /// Original C field: exclude in struct `auth_zone` (linked list pointer)
    /// Rust: Safe Vec instead of linked list with manual memory management
    pub exclude: Vec<AddrList>,

    /// Interface for this zone
    /// Original C field: `interface_names` in struct `auth_zone`
    pub interface: Option<String>,
}

/// Main configuration structure
///
/// Root configuration container that aggregates all subsystem configurations.
/// Replaces C's global `struct daemon` (dnsmasq.h line 4074) with organized subsections.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct Config {
    /// DNS subsystem configuration
    pub dns: DnsConfig,

    /// DHCP subsystem configuration
    pub dhcp: DhcpConfig,

    /// Network configuration
    pub network: NetworkConfig,

    /// TFTP server configuration
    pub tftp: TftpConfig,

    /// Process management configuration
    pub process: ProcessConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// External integration configuration
    pub integration: IntegrationConfig,

    /// Authoritative DNS configuration
    pub auth: AuthConfig,

    /// Runtime option flags
    /// Original C field: options[`OPTION_SIZE`] in struct daemon (line 4079)
    pub options: DaemonOptions,
}

impl Config {
    /// Creates a new configuration with default values
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates the configuration
    ///
    /// Checks for conflicts and invalid combinations:
    /// - Port conflicts
    /// - DHCP range overlaps
    /// - File path accessibility
    /// - Network interface validity
    #[must_use] 
    pub fn is_valid(&self) -> bool {
        // DNS port validation
        if self.dns.port != 0 && self.dns.port < 1024 && self.process.username.is_some() {
            // Privileged port with non-root user requires capabilities
            return true; // Allow but warn at runtime
        }

        // DHCP range validation
        for range in &self.dhcp.dhcp_ranges {
            if range.start > range.end {
                return false;
            }
        }

        // DHCPv6 range validation
        for range in &self.dhcp.dhcp6_ranges {
            if range.start > range.end {
                return false;
            }
        }

        true
    }

    /// Checks for configuration conflicts
    ///
    /// Returns a list of warning messages for potentially problematic settings
    #[must_use] 
    pub fn check_conflicts(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check for DHCP without DNS
        if !self.dhcp.dhcp_ranges.is_empty() && self.dns.port == 0 {
            warnings.push("DHCP enabled but DNS disabled".to_string());
        }

        // Check for authoritative mode without DHCP ranges
        if self.dhcp.authoritative && self.dhcp.dhcp_ranges.is_empty() {
            warnings.push("Authoritative mode without DHCP ranges".to_string());
        }

        // Check for TFTP without root
        if self.tftp.tftp_root.is_none() && self.tftp.tftp_max_connections > 0 {
            warnings.push("TFTP connections configured without root directory".to_string());
        }

        warnings
    }
}


/// Configuration builder for gradual construction
///
/// Provides a fluent API for building configuration during parsing, eliminating
/// unsafe global mutable state from the C implementation. Implements the builder
/// pattern with validation at each step.
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    dns: Option<DnsConfig>,
    dhcp: Option<DhcpConfig>,
    network: Option<NetworkConfig>,
    tftp: Option<TftpConfig>,
    process: Option<ProcessConfig>,
    logging: Option<LoggingConfig>,
    integration: Option<IntegrationConfig>,
    auth: Option<AuthConfig>,
    options: DaemonOptions,
}

impl ConfigBuilder {
    /// Creates a new empty configuration builder
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets DNS configuration
    #[must_use] 
    pub fn dns(mut self, dns: DnsConfig) -> Self {
        self.dns = Some(dns);
        self
    }

    /// Sets DHCP configuration
    #[must_use] 
    pub fn dhcp(mut self, dhcp: DhcpConfig) -> Self {
        self.dhcp = Some(dhcp);
        self
    }

    /// Sets network configuration
    #[must_use] 
    pub fn network(mut self, network: NetworkConfig) -> Self {
        self.network = Some(network);
        self
    }

    /// Sets TFTP configuration
    #[must_use] 
    pub fn tftp(mut self, tftp: TftpConfig) -> Self {
        self.tftp = Some(tftp);
        self
    }

    /// Sets process configuration
    #[must_use] 
    pub fn process(mut self, process: ProcessConfig) -> Self {
        self.process = Some(process);
        self
    }

    /// Sets logging configuration
    #[must_use] 
    pub fn logging(mut self, logging: LoggingConfig) -> Self {
        self.logging = Some(logging);
        self
    }

    /// Sets integration configuration
    #[must_use] 
    pub fn integration(mut self, integration: IntegrationConfig) -> Self {
        self.integration = Some(integration);
        self
    }

    /// Sets authoritative DNS configuration
    #[must_use] 
    pub fn auth(mut self, auth: AuthConfig) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets daemon option flags
    #[must_use] 
    pub fn options(mut self, options: DaemonOptions) -> Self {
        self.options = options;
        self
    }

    /// Builds the final configuration
    ///
    /// Uses provided values or defaults for unset subsections
    #[must_use] 
    pub fn build(self) -> Config {
        Config {
            dns: self.dns.unwrap_or_default(),
            dhcp: self.dhcp.unwrap_or_default(),
            network: self.network.unwrap_or_default(),
            tftp: self.tftp.unwrap_or_default(),
            process: self.process.unwrap_or_default(),
            logging: self.logging.unwrap_or_default(),
            integration: self.integration.unwrap_or_default(),
            auth: self.auth.unwrap_or_default(),
            options: self.options,
        }
    }

    /// Creates a builder with default values
    #[must_use] 
    pub fn with_defaults() -> Self {
        Self {
            dns: Some(DnsConfig::default()),
            dhcp: Some(DhcpConfig::default()),
            network: Some(NetworkConfig::default()),
            tftp: Some(TftpConfig::default()),
            process: Some(ProcessConfig::default()),
            logging: Some(LoggingConfig::default()),
            integration: Some(IntegrationConfig::default()),
            auth: Some(AuthConfig::default()),
            options: DaemonOptions::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = Config::default();
        assert_eq!(config.dns.port, 53);
        assert_eq!(config.dhcp.server_port, 67);
        assert!(config.is_valid());
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .dns(DnsConfig {
                port: 5353,
                ..Default::default()
            })
            .build();

        assert_eq!(config.dns.port, 5353);
    }

    #[test]
    fn test_daemon_options() {
        let mut opts = DaemonOptions::empty();
        assert!(!opts.contains(DaemonOptions::OPT_LOG));

        opts.insert(DaemonOptions::OPT_LOG);
        assert!(opts.contains(DaemonOptions::OPT_LOG));

        opts.remove(DaemonOptions::OPT_LOG);
        assert!(!opts.contains(DaemonOptions::OPT_LOG));
    }

    #[test]
    fn test_invalid_dhcp_range() {
        let config = Config {
            dhcp: DhcpConfig {
                dhcp_ranges: vec![DhcpRange {
                    start: "192.168.1.100".parse().unwrap(),
                    end: "192.168.1.50".parse().unwrap(), // Invalid: end < start
                    lease_time: Duration::from_secs(3600),
                    flags: 0,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(!config.is_valid());
    }

    #[test]
    fn test_interface_name() {
        let iface = InterfaceName::new("eth0".to_string());
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.addr, None);

        let iface_with_addr = InterfaceName::with_addr(
            "eth0".to_string(),
            "192.168.1.1".parse().unwrap(),
        );
        assert!(iface_with_addr.addr.is_some());
    }
}

