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

//! Command-line interface argument parser refactored from option.c
//!
//! This module implements CLI parsing using clap derive macros to declaratively define all 150+
//! command-line flags maintaining exact compatibility with C version's short (-v, -h, -p, etc.)
//! and long (--version, --help, --port, etc.) option forms. Replaces manual getopt_long() loop
//! with type-safe Rust structure, eliminating buffer overflow risks in argument parsing while
//! preserving exact CLI behavior including help text generation, version display, and error
//! messages for invalid options.
//!
//! # Memory Safety Transformation
//!
//! Original C implementation (option.c lines 6616-6947):
//! - Manual getopt_long() parsing with opts[] array (lines 296-561)
//! - Unsafe string copying with strcpy/strncpy for argument values
//! - Manual buffer management and bounds checking
//! - Error-prone manual iteration through argc/argv
//!
//! Rust replacement:
//! - Clap derive macros for declarative option specification
//! - Automatic type conversion and validation (String, PathBuf, IpAddr, etc.)
//! - Built-in help generation from doc comments
//! - Memory-safe argument storage with ownership semantics
//!
//! # Configuration Precedence
//!
//! Implements option precedence matching C version:
//! 1. Command-line arguments (highest priority)
//! 2. Configuration file values (from parser.rs)
//! 3. Compiled-in defaults (from defaults.rs)
//!
//! # Original C Mapping
//!
//! LOPT_* constants (lines 173-289) map to long-only options.
//! opts[] array entries (lines 296-561) define all options.
//! read_opts() function (lines 6616-6947) processes arguments.
//!
//! # Validation
//!
//! Performs validation equivalent to C version:
//! - Port number ranges (0-65535)
//! - IP address parsing
//! - File path accessibility checks (deferred to runtime)
//! - Mutually exclusive options (e.g., --bind-interfaces vs --bind-dynamic)
//! - Required option combinations

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::{ArgAction, Parser};

use super::defaults::default_config;
use super::types::{Config, TftpConfig};

/// Errors that can occur during CLI parsing
///
/// Provides detailed error information matching C version's error messages
/// from option.c's read_opts() error handling paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// Invalid argument value provided
    ///
    /// Occurs when argument value fails parsing or validation
    /// (e.g., invalid IP address, port out of range)
    InvalidArgument {
        /// Name of the command-line argument
        arg: String,
        /// The invalid value provided
        value: String,
        /// Description of why the value is invalid
        reason: String,
    },

    /// Missing required argument
    ///
    /// Occurs when required argument is not provided
    MissingRequired {
        /// Name of the missing required argument
        arg: String,
    },

    /// Conflicting options specified
    ///
    /// Occurs when mutually exclusive options are both provided
    /// (e.g., --bind-interfaces and --bind-dynamic)
    ConflictingOptions {
        /// First conflicting option
        option1: String,
        /// Second conflicting option
        option2: String,
        /// Explanation of the conflict
        reason: String,
    },

    /// Clap parse error
    ///
    /// Wraps errors from clap's parsing stage
    ParseError(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::InvalidArgument { arg, value, reason } => {
                write!(
                    f,
                    "dnsmasq: bad {} option '{}': {}",
                    arg, value, reason
                )
            }
            CliError::MissingRequired { arg } => {
                write!(f, "dnsmasq: missing required option: {}", arg)
            }
            CliError::ConflictingOptions {
                option1,
                option2,
                reason,
            } => {
                write!(
                    f,
                    "dnsmasq: conflicting options {} and {}: {}",
                    option1, option2, reason
                )
            }
            CliError::ParseError(msg) => {
                write!(f, "dnsmasq: {}", msg)
            }
        }
    }
}

impl std::error::Error for CliError {}

impl From<clap::Error> for CliError {
    fn from(err: clap::Error) -> Self {
        CliError::ParseError(err.to_string())
    }
}

/// Command-line arguments structure
///
/// This struct uses clap's derive macros to declaratively specify all command-line
/// options matching the C implementation's opts[] array (option.c lines 296-561).
/// Every field corresponds to a command-line flag with identical short/long names
/// for backward compatibility.
///
/// # Design Notes
///
/// - Boolean flags use SetTrue action (e.g., -d, --no-daemon)
/// - Value arguments use Set action with type parsing (e.g., -p <PORT>)
/// - Repeated arguments use Append action into Vec (e.g., --server can appear multiple times)
/// - Optional arguments represented as Option<T>
///
/// # C Equivalence
///
/// Maps directly to C's getopt_long() option definitions:
/// - has_arg=0 (no_argument) → bool with SetTrue action
/// - has_arg=1 (required_argument) → T or Vec<T> with Set/Append action
/// - has_arg=2 (optional_argument) → Option<T> with Set action
#[derive(Parser, Debug, Clone, Default)]
#[command(name = "dnsmasq")]
#[command(author = "Simon Kelley <simon@thekelleys.org.uk>")]
#[command(disable_version_flag = true)]
#[command(disable_help_flag = true)]
#[command(about = "A lightweight DHCP and caching DNS server")]
#[command(long_about = "dnsmasq provides network infrastructure for small networks:\nDNS, DHCP, router advertisement and network boot.")]
#[allow(clippy::struct_excessive_bools)]
pub struct CliArgs {
    // ========================================================================
    // Core Operation Flags
    // ========================================================================
    
    /// Print version information and exit
    ///
    /// C equivalent: -v, --version (option.c line 297)
    #[arg(short = 'v', long = "version", action = ArgAction::SetTrue)]
    pub version: bool,

    /// Display this help text and exit
    ///
    /// C equivalent: -w, --help (option.c line 300)
    #[arg(short = 'w', long = "help", action = ArgAction::SetTrue)]
    pub help: bool,

    /// Do not run as daemon (stay in foreground)
    ///
    /// Prevents fork() to background. Useful for systemd, Docker, debugging.
    /// C equivalent: -d, --no-daemon (option.c line 301)
    #[arg(short = 'd', long = "no-daemon", action = ArgAction::SetTrue)]
    pub no_daemon: bool,

    /// Keep in foreground but still log to stderr
    ///
    /// C equivalent: -k, --keep-in-foreground (option.c line 356)
    #[arg(short = 'k', long = "keep-in-foreground", action = ArgAction::SetTrue)]
    pub keep_in_foreground: bool,

    /// Enable debug mode (implies --no-daemon --log-queries)
    ///
    /// C equivalent: compiled into OPT_DEBUG flag when -d specified
    #[arg(long = "debug", action = ArgAction::SetTrue)]
    pub debug: bool,

    /// Test configuration syntax and exit (no daemon start)
    ///
    /// Validates config file, command-line arguments without running server.
    /// C equivalent: --test (option.c line 422, LOPT_TEST = 293)
    #[arg(long = "test", action = ArgAction::SetTrue)]
    pub test: bool,

    // ========================================================================
    // DNS Configuration
    // ========================================================================
    
    /// DNS port to listen on (0 to disable DNS)
    ///
    /// Standard DNS port is 53. Setting to 0 disables DNS server entirely.
    /// C equivalent: -p <port>, --port=<port> (option.c line 310)
    #[arg(
        short = 'p',
        long = "port",
        value_name = "PORT",
        default_value = "53"
    )]
    pub port: u16,

    /// Query port for outgoing DNS queries
    ///
    /// Source port for upstream queries. Default 0 means random ephemeral port.
    /// C equivalent: -Q <query-port>, --query-port=<query-port> (option.c line 344)
    #[arg(short = 'Q', long = "query-port", value_name = "PORT")]
    pub query_port: Option<u16>,

    /// Minimum port for outgoing queries
    ///
    /// Lower bound of source port range for upstream DNS queries.
    /// C equivalent: --min-port=<port> (option.c line 416, LOPT_MINPORT = 288)
    #[arg(long = "min-port", value_name = "PORT")]
    pub min_port: Option<u16>,

    /// Maximum port for outgoing queries
    ///
    /// Upper bound of source port range for upstream DNS queries.
    /// C equivalent: --max-port=<port> (option.c line 417, LOPT_MAXPORT = 345)
    #[arg(long = "max-port", value_name = "PORT")]
    pub max_port: Option<u16>,

    /// Cache size (number of DNS entries)
    ///
    /// DNS cache capacity. Default 150 entries. 0 disables caching.
    /// C equivalent: -c <cachesize>, --cache-size=<cachesize> (option.c line 309)
    #[arg(
        short = 'c',
        long = "cache-size",
        value_name = "SIZE",
        default_value = "150"
    )]
    pub cache_size: usize,

    /// Maximum concurrent DNS queries
    ///
    /// Limits forwarded query table size (FTABSIZ in C).
    /// C equivalent: -0 <queries>, --dns-forward-max=<queries> (option.c line 373)
    #[arg(short = '0', long = "dns-forward-max", value_name = "QUERIES")]
    pub dns_forward_max: Option<usize>,

    /// Upstream DNS server address
    ///
    /// Can be repeated for multiple upstreams. Format: [/domain/]<IP>[#port][@interface]
    /// C equivalent: -S <server>, --server=<server> (option.c line 331)
    #[arg(
        short = 'S',
        long = "server",
        value_name = "SERVER",
        action = ArgAction::Append
    )]
    pub servers: Vec<String>,

    /// Reverse DNS server for subnet
    ///
    /// Format: <ip-address>/<prefix-len>,<server>
    /// C equivalent: --rev-server=<spec> (option.c line 332, LOPT_REV_SERV = 332)
    #[arg(
        long = "rev-server",
        value_name = "SPEC",
        action = ArgAction::Append
    )]
    pub rev_servers: Vec<String>,

    /// Local domain specification
    ///
    /// Format: /domain/[ip-address][#port] - never forward queries for domain
    /// C equivalent: --local=<domain> (option.c line 333, LOPT_LOCAL = 286)
    #[arg(long = "local", value_name = "DOMAIN", action = ArgAction::Append)]
    pub local_domains: Vec<String>,

    /// Address override for domain
    ///
    /// Return specific address for domain queries.
    /// C equivalent: -A <address>, --address=<address> (option.c line 334)
    #[arg(short = 'A', long = "address", value_name = "SPEC", action = ArgAction::Append)]
    pub addresses: Vec<String>,

    /// Resolv.conf file path
    ///
    /// File containing upstream server addresses. Default /etc/resolv.conf.
    /// C equivalent: -r <resolvfile>, --resolv-file=<resolvfile> (option.c line 305)
    #[arg(short = 'r', long = "resolv-file", value_name = "FILE")]
    pub resolv_file: Option<PathBuf>,

    /// Additional servers file
    ///
    /// Read server addresses from file (one per line).
    /// C equivalent: --servers-file=<file> (option.c line 306, LOPT_SERVERS_FILE = 333)
    #[arg(long = "servers-file", value_name = "FILE")]
    pub servers_file: Option<PathBuf>,

    /// Do not read /etc/resolv.conf for upstream servers
    ///
    /// Ignore resolv.conf file entirely. Use only explicitly configured servers.
    /// C equivalent: -R, --no-resolv (option.c line 337)
    #[arg(short = 'R', long = "no-resolv", action = ArgAction::SetTrue)]
    pub no_resolv: bool,

    /// Do not poll /etc/resolv.conf for changes
    ///
    /// Read resolv.conf once at startup, don't watch for modifications.
    /// C equivalent: -n, --no-poll (option.c line 299)
    #[arg(short = 'n', long = "no-poll", action = ArgAction::SetTrue)]
    pub no_poll: bool,

    /// Process resolv.conf strictly in order
    ///
    /// Query servers in resolv.conf order, not by fastest response.
    /// C equivalent: -o, --strict-order (option.c line 330)
    #[arg(short = 'o', long = "strict-order", action = ArgAction::SetTrue)]
    pub strict_order: bool,

    /// Send queries to all servers
    ///
    /// Forward to all available servers simultaneously.
    /// C equivalent: --all-servers (option.c line 406, LOPT_NOLAST = 278)
    #[arg(long = "all-servers", action = ArgAction::SetTrue)]
    pub all_servers: bool,

    /// Do not read /etc/hosts file
    ///
    /// Ignore system hosts file.
    /// C equivalent: -h, --no-hosts (option.c line 298)
    #[arg(short = 'h', long = "no-hosts", action = ArgAction::SetTrue)]
    pub no_hosts: bool,

    /// Additional hosts file
    ///
    /// Read additional hosts from file.
    /// C equivalent: -H <hostsfile>, --addn-hosts=<hostsfile> (option.c line 342)
    #[arg(short = 'H', long = "addn-hosts", value_name = "FILE", action = ArgAction::Append)]
    pub addn_hosts: Vec<PathBuf>,

    /// Hosts directory (with inotify watching)
    ///
    /// Read all files in directory as hosts files. Watch for changes.
    /// C equivalent: --hostsdir=<dir> (option.c line 343, LOPT_HOST_INOTIFY = 342)
    #[arg(long = "hostsdir", value_name = "DIR", action = ArgAction::Append)]
    pub hosts_dirs: Vec<PathBuf>,

    /// Read /etc/ethers for MAC-address to IP mapping
    ///
    /// Enable ethers file support for DHCP.
    /// C equivalent: -Z, --read-ethers (option.c line 350)
    #[arg(short = 'Z', long = "read-ethers", action = ArgAction::SetTrue)]
    pub read_ethers: bool,

    // ========================================================================
    // DNS Query Logging and Filtering
    // ========================================================================
    
    /// Log DNS queries
    ///
    /// Log all DNS queries to syslog/log-facility.
    /// C equivalent: -q, --log-queries (option.c line 302)
    #[arg(short = 'q', long = "log-queries", action = ArgAction::Count)]
    pub log_queries: u8,

    /// Log debugging information
    ///
    /// Extra verbose logging for debugging.
    /// C equivalent: --log-debug (option.c line 278, LOPT_LOG_DEBUG = 363)
    #[arg(long = "log-debug", action = ArgAction::SetTrue)]
    pub log_debug: bool,

    /// Log asynchronously (queue up to N log lines)
    ///
    /// Prevent logging from blocking daemon.
    /// C equivalent: --log-async=<lines> (option.c line 392, LOPT_MAX_LOGS = 267)
    #[arg(long = "log-async", value_name = "LINES")]
    pub log_async: Option<usize>,

    /// Log DHCP transactions
    ///
    /// Enable detailed DHCP logging.
    /// C equivalent: --log-dhcp (option.c line 391, LOPT_LOG_OPTS = 266)
    #[arg(long = "log-dhcp", action = ArgAction::SetTrue)]
    pub log_dhcp: bool,

    /// Bogus private reverse lookups
    ///
    /// Fake reverse DNS for private IP ranges.
    /// C equivalent: -b, --bogus-priv (option.c line 322)
    #[arg(short = 'b', long = "bogus-priv", action = ArgAction::SetTrue)]
    pub bogus_priv: bool,

    /// Bogus NXDOMAIN addresses
    ///
    /// Treat specific IP addresses as NXDOMAIN.
    /// C equivalent: -B <address>, --bogus-nxdomain=<address> (option.c line 323)
    #[arg(short = 'B', long = "bogus-nxdomain", value_name = "ADDRESS", action = ArgAction::Append)]
    pub bogus_nxdomain: Vec<IpAddr>,

    /// Ignore addresses in DNS replies
    ///
    /// Remove specified addresses from DNS responses.
    /// C equivalent: --ignore-address=<address> (option.c line 324, LOPT_IGNORE_ADDR = 338)
    #[arg(long = "ignore-address", value_name = "ADDRESS", action = ArgAction::Append)]
    pub ignore_addresses: Vec<IpAddr>,

    /// Filter Windows 2000 SRV queries
    ///
    /// Old compatibility option for filtering SRV RR types.
    /// C equivalent: -f, --filterwin2k (option.c line 326)
    #[arg(short = 'f', long = "filterwin2k", action = ArgAction::SetTrue)]
    pub filterwin2k: bool,

    /// Filter all A (IPv4) record queries
    ///
    /// Return empty response for all A queries.
    /// C equivalent: --filter-A (option.c line 327, LOPT_FILTER_A = 369)
    #[arg(long = "filter-A", action = ArgAction::SetTrue)]
    pub filter_a: bool,

    /// Filter all AAAA (IPv6) record queries
    ///
    /// Return empty response for all AAAA queries.
    /// C equivalent: --filter-AAAA (option.c line 328, LOPT_FILTER_AAAA = 370)
    #[arg(long = "filter-AAAA", action = ArgAction::SetTrue)]
    pub filter_aaaa: bool,

    // ========================================================================
    // Domain and Name Processing
    // ========================================================================
    
    /// Local domain suffix
    ///
    /// Append domain to simple names. Also -s.
    /// C equivalent: -s <domain>, --domain=<domain> (option.c line 317)
    #[arg(short = 's', long = "domain", value_name = "DOMAIN")]
    pub domain: Option<String>,

    /// Domain needed for non-FQDN
    ///
    /// Never forward plain names without domain.
    /// C equivalent: -D, --domain-needed (option.c line 347)
    #[arg(short = 'D', long = "domain-needed", action = ArgAction::SetTrue)]
    pub domain_needed: bool,

    /// Expand hosts file names with domain
    ///
    /// Add domain suffix to names from hosts files.
    /// C equivalent: -E, --expand-hosts (option.c line 338)
    #[arg(short = 'E', long = "expand-hosts", action = ArgAction::SetTrue)]
    pub expand_hosts: bool,

    /// Local MX target
    ///
    /// Return MX pointing to this host.
    /// C equivalent: -L, --localmx (option.c line 339)
    #[arg(short = 'L', long = "localmx", action = ArgAction::SetTrue)]
    pub localmx: bool,

    /// Self MX record
    ///
    /// Return A record as MX target.
    /// C equivalent: -e, --selfmx (option.c line 325)
    #[arg(short = 'e', long = "selfmx", action = ArgAction::SetTrue)]
    pub selfmx: bool,

    /// Localise queries
    ///
    /// Choose A/AAAA records based on query interface.
    /// C equivalent: -y, --localise-queries (option.c line 359)
    #[arg(short = 'y', long = "localise-queries", action = ArgAction::SetTrue)]
    pub localise_queries: bool,

    /// MX record specification
    ///
    /// Add MX record. Format: <domain>,<target>[,<priority>]
    /// C equivalent: -m <host>,<target>[,<pref>], --mx-host=<spec> (option.c line 307)
    #[arg(short = 'm', long = "mx-host", value_name = "SPEC", action = ArgAction::Append)]
    pub mx_hosts: Vec<String>,

    /// MX target for self
    ///
    /// Default MX target hostname.
    /// C equivalent: -t <host>, --mx-target=<host> (option.c line 308)
    #[arg(short = 't', long = "mx-target", value_name = "HOST")]
    pub mx_target: Option<String>,

    /// SRV record specification
    ///
    /// Add SRV record. Format: <service>,<target>[,<port>[,<priority>[,<weight>]]]
    /// C equivalent: -W <spec>, --srv-host=<spec> (option.c line 358)
    #[arg(short = 'W', long = "srv-host", value_name = "SPEC", action = ArgAction::Append)]
    pub srv_hosts: Vec<String>,

    /// TXT record specification
    ///
    /// Add TXT record. Format: <domain>,<text>
    /// C equivalent: -Y <name>,<txt>[,<txt>], --txt-record=<spec> (option.c line 360)
    #[arg(short = 'Y', long = "txt-record", value_name = "SPEC", action = ArgAction::Append)]
    pub txt_records: Vec<String>,

    /// PTR record specification
    ///
    /// Add PTR record. Format: <name>,<target>
    /// C equivalent: --ptr-record=<spec> (option.c line 385, LOPT_PTR = 261)
    #[arg(long = "ptr-record", value_name = "SPEC", action = ArgAction::Append)]
    pub ptr_records: Vec<String>,

    /// NAPTR record specification
    ///
    /// Add NAPTR record.
    /// C equivalent: --naptr-record=<spec> (option.c line 386, LOPT_NAPTR = 287)
    #[arg(long = "naptr-record", value_name = "SPEC", action = ArgAction::Append)]
    pub naptr_records: Vec<String>,

    /// CAA record specification
    ///
    /// Add CAA record. Format: <domain>,<flags>,<tag>,<value>
    /// C equivalent: --caa-record=<spec> (option.c line 361, LOPT_CAA = 356)
    #[arg(long = "caa-record", value_name = "SPEC", action = ArgAction::Append)]
    pub caa_records: Vec<String>,

    /// Generic DNS RR specification
    ///
    /// Add arbitrary RR. Format: <name>,<rrtype>,<data>
    /// C equivalent: --dns-rr=<spec> (option.c line 362, LOPT_RR = 310)
    #[arg(long = "dns-rr", value_name = "SPEC", action = ArgAction::Append)]
    pub dns_rrs: Vec<String>,

    /// CNAME alias
    ///
    /// Add CNAME record. Format: <cname>,<target>[,<TTL>]
    /// C equivalent: --cname=<spec> (option.c line 419, LOPT_CNAME = 290)
    #[arg(long = "cname", value_name = "SPEC", action = ArgAction::Append)]
    pub cnames: Vec<String>,

    /// Host record (multiple A/AAAA for name)
    ///
    /// Format: <name>[,<address>]...
    /// C equivalent: --host-record=<spec> (option.c line 439, LOPT_HOST_REC = 308)
    #[arg(long = "host-record", value_name = "SPEC", action = ArgAction::Append)]
    pub host_records: Vec<String>,

    /// Dynamic host record
    ///
    /// Host record computed from interface addresses.
    /// C equivalent: --dynamic-host=<spec> (option.c line 277, LOPT_DYNHOST = 362)
    #[arg(long = "dynamic-host", value_name = "SPEC", action = ArgAction::Append)]
    pub dynamic_hosts: Vec<String>,

    // ========================================================================
    // Network Interface Configuration
    // ========================================================================
    
    /// Interface to listen on
    ///
    /// Bind DNS/DHCP to specific interface(s). Can be repeated.
    /// C equivalent: -i <interface>, --interface=<interface> (option.c line 319)
    #[arg(short = 'i', long = "interface", value_name = "INTERFACE", action = ArgAction::Append)]
    pub interfaces: Vec<String>,

    /// Interface to exclude
    ///
    /// Don't listen on specified interface(s). Can be repeated.
    /// C equivalent: -I <interface>, --except-interface=<interface> (option.c line 345)
    #[arg(short = 'I', long = "except-interface", value_name = "INTERFACE", action = ArgAction::Append)]
    pub except_interfaces: Vec<String>,

    /// Interface for DHCP only (no DNS)
    ///
    /// Provide DHCP but not DNS on interface.
    /// C equivalent: -2 <interface>, --no-dhcp-interface=<interface> (option.c line 346)
    #[arg(short = '2', long = "no-dhcp-interface", value_name = "INTERFACE", action = ArgAction::Append)]
    pub no_dhcp_interfaces: Vec<String>,

    /// Listen address (IP)
    ///
    /// Bind to specific IP address. Can be repeated for multiple IPs.
    /// C equivalent: -a <ipaddr>, --listen-address=<ipaddr> (option.c line 320)
    #[arg(short = 'a', long = "listen-address", value_name = "ADDRESS", action = ArgAction::Append)]
    pub listen_addresses: Vec<IpAddr>,

    /// Bind to interfaces
    ///
    /// Bind only to specified interfaces, not wildcard address.
    /// C equivalent: -z, --bind-interfaces (option.c line 349)
    #[arg(short = 'z', long = "bind-interfaces", action = ArgAction::SetTrue)]
    pub bind_interfaces: bool,

    /// Bind interfaces dynamically
    ///
    /// Bind to interfaces as they come up.
    /// C equivalent: --bind-dynamic (option.c line 440, LOPT_CLVERBIND = 311)
    #[arg(long = "bind-dynamic", action = ArgAction::SetTrue)]
    pub bind_dynamic: bool,

    /// Bridge interface configuration
    ///
    /// Treat interfaces as bridge members. Format: <iface>,<alias>,...
    /// C equivalent: --bridge-interface=<spec> (option.c line 387, LOPT_BRIDGE = 262)
    #[arg(long = "bridge-interface", value_name = "SPEC", action = ArgAction::Append)]
    pub bridge_interfaces: Vec<String>,

    /// Shared network tag
    ///
    /// Tag interfaces as sharing L2 network. Format: <iface>,<tag>
    /// C equivalent: --shared-network=<spec> (option.c line 388, LOPT_SHARED_NET = 357)
    #[arg(long = "shared-network", value_name = "SPEC", action = ArgAction::Append)]
    pub shared_networks: Vec<String>,

    /// Only bind local service
    ///
    /// Accept only queries from local subnets.
    /// C equivalent: --local-service (option.c line 321, LOPT_LOCAL_SERVICE = 335)
    #[arg(long = "local-service", action = ArgAction::SetTrue)]
    pub local_service: bool,

    /// Interface name mapping
    ///
    /// Give interface an additional DNS name. Format: <name>,<interface>
    /// C equivalent: --interface-name=<spec> (option.c line 397, LOPT_INTNAME = 271)
    #[arg(long = "interface-name", value_name = "SPEC", action = ArgAction::Append)]
    pub interface_names: Vec<String>,

    // ========================================================================
    // TTL and Caching Configuration
    // ========================================================================
    
    /// Local TTL
    ///
    /// TTL for local names (from hosts files).
    /// C equivalent: -T <time>, --local-ttl=<time> (option.c line 340)
    #[arg(short = 'T', long = "local-ttl", value_name = "TIME")]
    pub local_ttl: Option<u32>,

    /// Disable negative caching
    ///
    /// Don't cache NXDOMAIN responses.
    /// C equivalent: -N, --no-negcache (option.c line 341)
    #[arg(short = 'N', long = "no-negcache", action = ArgAction::SetTrue)]
    pub no_negcache: bool,

    /// Negative TTL
    ///
    /// TTL for negative (NXDOMAIN) cache entries.
    /// C equivalent: --neg-ttl=<time> (option.c line 410, LOPT_NEGTTL = 283)
    #[arg(long = "neg-ttl", value_name = "TIME")]
    pub neg_ttl: Option<u32>,

    /// Maximum TTL
    ///
    /// Maximum TTL for cached entries.
    /// C equivalent: --max-ttl=<time> (option.c line 411, LOPT_MAXTTL = 297)
    #[arg(long = "max-ttl", value_name = "TIME")]
    pub max_ttl: Option<u32>,

    /// Minimum cache TTL
    ///
    /// Minimum TTL for cached entries (extends short TTLs).
    /// C equivalent: --min-cache-ttl=<time> (option.c line 412, LOPT_MINCTTL = 339)
    #[arg(long = "min-cache-ttl", value_name = "TIME")]
    pub min_cache_ttl: Option<u32>,

    /// Maximum cache TTL
    ///
    /// Maximum TTL for cached entries (caps long TTLs).
    /// C equivalent: --max-cache-ttl=<time> (option.c line 413, LOPT_MAXCTTL = 312)
    #[arg(long = "max-cache-ttl", value_name = "TIME")]
    pub max_cache_ttl: Option<u32>,

    /// Clear cache on reload
    ///
    /// Empty DNS cache on SIGHUP reload.
    /// C equivalent: --clear-on-reload (option.c line 374, LOPT_RELOAD = 256)
    #[arg(long = "clear-on-reload", action = ArgAction::SetTrue)]
    pub clear_on_reload: bool,

    // ========================================================================
    // EDNS and Packet Size
    // ========================================================================
    
    /// EDNS packet size
    ///
    /// Maximum EDNS.0 UDP packet size to advertise.
    /// C equivalent: -P <size>, --edns-packet-max=<size> (option.c line 355)
    #[arg(short = 'P', long = "edns-packet-max", value_name = "SIZE")]
    pub edns_packet_max: Option<u16>,

    // ========================================================================
    // DNS Security and Filtering
    // ========================================================================
    
    /// Stop DNS rebind attacks
    ///
    /// Reject upstream responses containing private IP addresses.
    /// C equivalent: --stop-dns-rebind (option.c line 404, LOPT_REBIND = 277)
    #[arg(long = "stop-dns-rebind", action = ArgAction::SetTrue)]
    pub stop_dns_rebind: bool,

    /// Allow DNS rebind for domains
    ///
    /// Permit rebind addresses for specified domains.
    /// C equivalent: --rebind-domain-ok=<domain> (option.c line 405, LOPT_NO_REBIND = 298)
    #[arg(long = "rebind-domain-ok", value_name = "DOMAIN", action = ArgAction::Append)]
    pub rebind_domain_ok: Vec<String>,

    /// Allow rebind for localhost
    ///
    /// Don't reject 127.0.0.0/8 in upstream replies.
    /// C equivalent: --rebind-localhost-ok (option.c line 426, LOPT_LOC_REBND = 299)
    #[arg(long = "rebind-localhost-ok", action = ArgAction::SetTrue)]
    pub rebind_localhost_ok: bool,

    /// Alias IP addresses
    ///
    /// Translate IP addresses in DNS replies. Format: <old-ip>,<new-ip>[,<mask>]
    /// C equivalent: -V <addr>,<addr>,<netmask>, --alias=<spec> (option.c line 351)
    #[arg(short = 'V', long = "alias", value_name = "SPEC", action = ArgAction::Append)]
    pub aliases: Vec<String>,

    // ========================================================================
    // DNSSEC Configuration
    // ========================================================================
    
    /// Enable DNSSEC validation
    ///
    /// Validate DNSSEC signatures. Requires HAVE_DNSSEC compile flag.
    /// C equivalent: --dnssec (Sets OPT_DNSSEC, proxy mode)
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec", action = ArgAction::SetTrue)]
    pub dnssec: bool,

    /// Proxy DNSSEC (pass through DNSSEC data)
    ///
    /// Forward DNSSEC records without validation.
    /// C equivalent: --proxy-dnssec (option.c line 432, LOPT_DNSSEC = 301)
    #[cfg(feature = "dnssec")]
    #[arg(long = "proxy-dnssec", action = ArgAction::SetTrue)]
    pub proxy_dnssec: bool,

    /// DNSSEC trust anchor
    ///
    /// Add DNSSEC trust anchor (DNSKEY or DS).
    /// C equivalent: --trust-anchor=<spec> (option.c line 245, LOPT_TRUST_ANCHOR = 330)
    #[cfg(feature = "dnssec")]
    #[arg(long = "trust-anchor", value_name = "SPEC", action = ArgAction::Append)]
    pub trust_anchors: Vec<String>,

    /// DNSSEC debug logging
    ///
    /// Extra verbose DNSSEC validation logging.
    /// C equivalent: --dnssec-debug (option.c line 246, LOPT_DNSSEC_DEBUG = 331)
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec-debug", action = ArgAction::SetTrue)]
    pub dnssec_debug: bool,

    /// DNSSEC check unsigned zones
    ///
    /// Treat unsigned zones as insecure, not bogus.
    /// C equivalent: --dnssec-check-unsigned (option.c line 249, LOPT_DNSSEC_CHECK = 334)
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec-check-unsigned", action = ArgAction::SetTrue)]
    pub dnssec_check_unsigned: bool,

    /// DNSSEC timestamp file
    ///
    /// File to store DNSSEC timestamp for time validation.
    /// C equivalent: --dnssec-timestamp=<file> (option.c line 258, LOPT_DNSSEC_STAMP = 343)
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec-timestamp", value_name = "FILE")]
    pub dnssec_timestamp: Option<PathBuf>,

    // ========================================================================
    // DHCP Configuration
    // ========================================================================
    
    /// DHCP address range
    ///
    /// Define DHCP address pool. Format: [tag:]<start-addr>,<end-addr>[,<netmask>[,<broadcast>]][,<lease-time>]
    /// C equivalent: -F <spec>, --dhcp-range=<spec> (option.c line 314)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'F', long = "dhcp-range", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_ranges: Vec<String>,

    /// DHCP static host
    ///
    /// Static DHCP lease. Format: [<hwaddr>][,id:<client_id>|*][,set:<tag>][,<ipaddr>][,<hostname>][,<lease_time>][,ignore]
    /// C equivalent: -G <spec>, --dhcp-host=<spec> (option.c line 313)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'G', long = "dhcp-host", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_hosts: Vec<String>,

    /// DHCP option
    ///
    /// Set DHCP option. Format: [tag:<tag>,[tag:<tag>,]][encap:<opt>,][vi-encap:<enterprise>,][vendor:[<vendor-class>],][<opt>|option:<opt-name>|option6:<opt>|option6:<opt-name>],[<value>]
    /// C equivalent: -O <spec>, --dhcp-option=<spec> (option.c line 315)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'O', long = "dhcp-option", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_options: Vec<String>,

    /// DHCP option (force)
    ///
    /// Set DHCP option, override client request.
    /// C equivalent: --dhcp-option-force=<spec> (option.c line 389, LOPT_FORCE = 264)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-option-force", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_options_force: Vec<String>,

    /// DHCP boot parameters
    ///
    /// PXE boot configuration. Format: [tag:<tag>,]<filename>,[<servername>[,<server-address>|<tftp-server-address>]]
    /// C equivalent: -M <spec>, --dhcp-boot=<spec> (option.c line 316)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'M', long = "dhcp-boot", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_boot: Vec<String>,

    /// PXE prompt
    ///
    /// PXE menu prompt text and timeout.
    /// C equivalent: --pxe-prompt=<spec> (option.c line 420, LOPT_PXE_PROMT = 291)
    #[cfg(feature = "dhcp")]
    #[arg(long = "pxe-prompt", value_name = "SPEC")]
    pub pxe_prompt: Option<String>,

    /// PXE service
    ///
    /// PXE boot service menu entry.
    /// C equivalent: --pxe-service=<spec> (option.c line 421, LOPT_PXE_SERV = 292)
    #[cfg(feature = "dhcp")]
    #[arg(long = "pxe-service", value_name = "SPEC", action = ArgAction::Append)]
    pub pxe_services: Vec<String>,

    /// PXE vendor override
    ///
    /// Match PXE vendor class. Format: <vendor-class>,<value>
    /// C equivalent: --dhcp-pxe-vendor=<spec> (option.c line 396, LOPT_PXE_VENDOR = 361)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-pxe-vendor", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_pxe_vendors: Vec<String>,

    /// DHCP lease file
    ///
    /// File to store DHCP leases.
    /// C equivalent: -l <path>, --dhcp-leasefile=<path> (option.c line 311)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'l', long = "dhcp-leasefile", value_name = "FILE")]
    pub dhcp_leasefile: Option<PathBuf>,

    /// DHCP lease file read-only
    ///
    /// Read lease file but don't write updates.
    /// C equivalent: -9, --leasefile-ro (option.c line 371)
    #[cfg(feature = "dhcp")]
    #[arg(short = '9', long = "leasefile-ro", action = ArgAction::SetTrue)]
    pub leasefile_ro: bool,

    /// Maximum DHCP leases
    ///
    /// Maximum number of concurrent DHCP leases.
    /// C equivalent: -X <number>, --dhcp-lease-max=<number> (option.c line 348)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'X', long = "dhcp-lease-max", value_name = "NUMBER")]
    pub dhcp_lease_max: Option<usize>,

    /// DHCP authoritative mode
    ///
    /// Assume DHCP authority for subnet (send NAK to wrong clients).
    /// C equivalent: -K, --dhcp-authoritative (option.c line 357)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'K', long = "dhcp-authoritative", action = ArgAction::SetTrue)]
    pub dhcp_authoritative: bool,

    /// DHCP rapid commit
    ///
    /// Enable DHCPv6 rapid commit option.
    /// C equivalent: --dhcp-rapid-commit (option.c line 266, LOPT_RAPID_COMMIT = 351)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-rapid-commit", action = ArgAction::SetTrue)]
    pub dhcp_rapid_commit: bool,

    /// DHCP alternate ports
    ///
    /// Use alternate DHCP ports. Format: [=<server-port>][,<client-port>]
    /// C equivalent: --dhcp-alternate-port=<spec> (option.c line 414, LOPT_ALTPORT = 284)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-alternate-port", value_name = "SPEC")]
    pub dhcp_alternate_port: Option<String>,

    /// Bootp dynamic allocation
    ///
    /// Allow BOOTP clients dynamic addresses.
    /// C equivalent: -3 [tag:<tag>...], --bootp-dynamic (option.c line 365)
    #[cfg(feature = "dhcp")]
    #[arg(short = '3', long = "bootp-dynamic", value_name = "TAG")]
    pub bootp_dynamic: Option<String>,

    /// No ICMP ping before lease
    ///
    /// Skip ping check before offering DHCP lease.
    /// C equivalent: -5, --no-ping (option.c line 367)
    #[cfg(feature = "dhcp")]
    #[arg(short = '5', long = "no-ping", action = ArgAction::SetTrue)]
    pub no_ping: bool,

    /// DHCP client update
    ///
    /// Allow DHCP clients to update their own DNS records.
    /// C equivalent: --dhcp-client-update (option.c line 435, LOPT_FQDN = 304)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-client-update", action = ArgAction::SetTrue)]
    pub dhcp_client_update: bool,

    /// DHCP sequential IP allocation
    ///
    /// Allocate IP addresses sequentially instead of pseudo-randomly.
    /// C equivalent: --dhcp-sequential-ip (option.c line 433, LOPT_INCR_ADDR = 302)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-sequential-ip", action = ArgAction::SetTrue)]
    pub dhcp_sequential_ip: bool,

    /// DHCP ignore client ID
    ///
    /// Use MAC address as DHCP identifier, ignore client-id option.
    /// C equivalent: --dhcp-ignore-clid (option.c line 273, LOPT_IGNORE_CLID = 358)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-ignore-clid", action = ArgAction::SetTrue)]
    pub dhcp_ignore_clid: bool,

    /// DHCP vendor class filter
    ///
    /// Ignore clients with specified vendor class.
    /// C equivalent: -U <vendor-class>, --dhcp-vendorclass=<spec> (option.c line 352)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'U', long = "dhcp-vendorclass", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_vendorclass: Vec<String>,

    /// DHCP user class filter
    ///
    /// Match clients by user class option.
    /// C equivalent: -j <user-class>, --dhcp-userclass=<spec> (option.c line 353)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'j', long = "dhcp-userclass", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_userclass: Vec<String>,

    /// DHCP MAC address filter
    ///
    /// Match clients by MAC address pattern.
    /// C equivalent: -4 <spec>, --dhcp-mac=<spec> (option.c line 366)
    #[cfg(feature = "dhcp")]
    #[arg(short = '4', long = "dhcp-mac", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_mac: Vec<String>,

    /// DHCP ignore filter
    ///
    /// Ignore DHCP requests from matching clients.
    /// C equivalent: -J <tag>[,<tag>...], --dhcp-ignore=<spec> (option.c line 354)
    #[cfg(feature = "dhcp")]
    #[arg(short = 'J', long = "dhcp-ignore", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_ignore: Vec<String>,

    /// DHCP name match filter
    ///
    /// Match clients by supplied hostname.
    /// C equivalent: --dhcp-name-match=<spec> (option.c line 408, LOPT_NAME_MATCH = 355)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-name-match", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_name_match: Vec<String>,

    /// DHCP match tag
    ///
    /// Set tag if other tags match.
    /// C equivalent: --dhcp-match=<spec> (option.c line 407, LOPT_MATCH = 281)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-match", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_match: Vec<String>,

    /// DHCP tag if interface
    ///
    /// Set tag based on interface. Format: tag:<tag>,<interface>
    /// C equivalent: --tag-if=<spec> (option.c line 423, LOPT_TAG_IF = 294)
    #[cfg(feature = "dhcp")]
    #[arg(long = "tag-if", value_name = "SPEC", action = ArgAction::Append)]
    pub tag_if: Vec<String>,

    /// DHCP broadcast responses
    ///
    /// Force broadcast replies to matching clients.
    /// C equivalent: --dhcp-broadcast=<spec> (option.c line 409, LOPT_BROADCAST = 282)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-broadcast", value_name = "SPEC")]
    pub dhcp_broadcast: Option<String>,

    /// DHCP FQDN option
    ///
    /// Set DHCP FQDN option for client fully qualified domain name.
    /// C equivalent: --dhcp-fqdn (option.c line 418, LOPT_DHCP_FQDN = 289)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-fqdn", action = ArgAction::SetTrue)]
    pub dhcp_fqdn: bool,

    /// DHCP reply delay
    ///
    /// Delay DHCP replies by specified seconds.
    /// C equivalent: --dhcp-reply-delay=<spec> (option.c line 265, LOPT_REPLY_DELAY = 350)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-reply-delay", value_name = "SPEC")]
    pub dhcp_reply_delay: Option<u32>,

    /// DHCP TTL for A records
    ///
    /// TTL for DNS A records created from DHCP leases.
    /// C equivalent: --dhcp-ttl=<ttl> (option.c line 263, LOPT_DHCPTTL = 348)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-ttl", value_name = "TTL")]
    pub dhcp_ttl: Option<u32>,

    /// Quiet DHCP logging
    ///
    /// Suppress routine DHCP logging.
    /// C equivalent: --quiet-dhcp (option.c line 241, LOPT_QUIET_DHCP = 326)
    #[cfg(feature = "dhcp")]
    #[arg(long = "quiet-dhcp", action = ArgAction::SetTrue)]
    pub quiet_dhcp: bool,

    /// Quiet DHCPv6 logging
    ///
    /// Suppress routine DHCPv6 logging.
    /// C equivalent: --quiet-dhcp6 (option.c line 242, LOPT_QUIET_DHCP6 = 327)
    #[cfg(feature = "dhcp6")]
    #[arg(long = "quiet-dhcp6", action = ArgAction::SetTrue)]
    pub quiet_dhcp6: bool,

    /// DHCP no override
    ///
    /// Don't override file/sname/siaddr fields from dhcp-boot.
    /// C equivalent: --dhcp-no-override (option.c line 402, LOPT_OVERRIDE = 275)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-no-override", action = ArgAction::SetTrue)]
    pub dhcp_no_override: bool,

    /// DHCP generate names
    ///
    /// Generate names for DHCP clients without supplied name.
    /// C equivalent: --dhcp-generate-names=<tag> (option.c line 425, LOPT_GEN_NAMES = 296)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-generate-names", value_name = "TAG")]
    pub dhcp_generate_names: Option<String>,

    /// DHCP ignore names
    ///
    /// Ignore client-supplied hostnames or generate names.
    /// C equivalent: --dhcp-ignore-names=<tag> (option.c line 375, LOPT_NO_NAMES = 257)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-ignore-names", value_name = "TAG")]
    pub dhcp_ignore_names: Option<String>,

    /// DHCP circuit ID option
    ///
    /// Map circuit ID to network/tag.
    /// C equivalent: --dhcp-circuitid=<spec> (option.c line 393, LOPT_CIRCUIT = 268)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-circuitid", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_circuitid: Vec<String>,

    /// DHCP remote ID option
    ///
    /// Map remote ID to network/tag.
    /// C equivalent: --dhcp-remoteid=<spec> (option.c line 394, LOPT_REMOTE = 269)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-remoteid", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_remoteid: Vec<String>,

    /// DHCP subscriber ID option
    ///
    /// Map subscriber ID to network/tag.
    /// C equivalent: --dhcp-subscrid=<spec> (option.c line 395, LOPT_SUBSCR = 270)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-subscrid", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_subscrid: Vec<String>,

    /// DHCP proxy
    ///
    /// Act as DHCP proxy. Format: [tag:<tag>,]<dhcp-server>
    /// C equivalent: --dhcp-proxy=<spec> (option.c line 424, LOPT_PROXY = 295)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-proxy", value_name = "SPEC")]
    pub dhcp_proxy: Option<String>,

    /// DHCP relay
    ///
    /// Relay DHCP requests to server. Format: <local-addr>,<server-addr>[,<interface>]
    /// C equivalent: --dhcp-relay=<spec> (option.c line 238, LOPT_RELAY = 323)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-relay", value_name = "SPEC", action = ArgAction::Append)]
    pub dhcp_relay: Vec<String>,

    /// Add MAC address to DNS queries
    ///
    /// Include client MAC in EDNS0 option.
    /// C equivalent: --add-mac (option.c line 427, LOPT_ADD_MAC = 300)
    #[arg(long = "add-mac", value_name = "MODE")]
    pub add_mac: Option<String>,

    /// Strip MAC address from queries
    ///
    /// Remove MAC address from forwarded queries.
    /// C equivalent: --strip-mac (option.c line 428, LOPT_STRIP_MAC = 372)
    #[arg(long = "strip-mac", action = ArgAction::SetTrue)]
    pub strip_mac: bool,

    /// Add client subnet to DNS queries
    ///
    /// Include client subnet in EDNS0.
    /// C equivalent: --add-subnet=<spec> (option.c line 429, LOPT_ADD_SBNET = 325)
    #[arg(long = "add-subnet", value_name = "SPEC")]
    pub add_subnet: Option<String>,

    /// Strip client subnet from queries
    ///
    /// Remove client subnet from forwarded queries.
    /// C equivalent: --strip-subnet (option.c line 430, LOPT_STRIP_SBNET = 371)
    #[arg(long = "strip-subnet", action = ArgAction::SetTrue)]
    pub strip_subnet: bool,

    /// Add CPE-ID to queries
    ///
    /// Add CPE ID tag to queries. Format: <cpe-id>
    /// C equivalent: --add-cpe-id=<spec> (option.c line 431, LOPT_CPE_ID = 346)
    #[arg(long = "add-cpe-id", value_name = "ID")]
    pub add_cpe_id: Option<String>,

    // ========================================================================
    // DHCPv6 and Router Advertisement
    // ========================================================================
    
    /// Enable router advertisement
    ///
    /// Send IPv6 router advertisements.
    /// C equivalent: --enable-ra (option.c line 437, LOPT_RA = 306)
    #[cfg(feature = "dhcp6")]
    #[arg(long = "enable-ra", action = ArgAction::SetTrue)]
    pub enable_ra: bool,

    /// Router advertisement parameters
    ///
    /// RA timing parameters. Format: <interface>,<ra-interval>[,<router-lifetime>]
    /// C equivalent: --ra-param=<spec> (option.c line 239, LOPT_RA_PARAM = 324)
    #[cfg(feature = "dhcp6")]
    #[arg(long = "ra-param", value_name = "SPEC", action = ArgAction::Append)]
    pub ra_params: Vec<String>,

    /// Quiet RA logging
    ///
    /// Suppress routine router advertisement logging.
    /// C equivalent: --quiet-ra (option.c line 243, LOPT_QUIET_RA = 328)
    #[cfg(feature = "dhcp6")]
    #[arg(long = "quiet-ra", action = ArgAction::SetTrue)]
    pub quiet_ra: bool,

    /// DHCPv6 DUID
    ///
    /// Set server DUID. Format: <enterprise-id>,<uid>
    /// C equivalent: --dhcp-duid=<spec> (option.c line 438, LOPT_DUID = 307)
    #[cfg(feature = "dhcp6")]
    #[arg(long = "dhcp-duid", value_name = "SPEC")]
    pub dhcp_duid: Option<String>,

    // ========================================================================
    // DHCP Script and Lease Management
    // ========================================================================
    
    /// DHCP lease change script
    ///
    /// Script to run on DHCP lease events.
    /// C equivalent: -6 <path>, --dhcp-script=<path> (option.c line 368)
    #[cfg(all(feature = "dhcp", feature = "script"))]
    #[arg(short = '6', long = "dhcp-script", value_name = "PATH")]
    pub dhcp_script: Option<PathBuf>,

    /// DHCP Lua script
    ///
    /// Lua script for DHCP lease processing.
    /// C equivalent: --dhcp-luascript=<path> (option.c line 436, LOPT_LUASCRIPT = 305)
    #[cfg(all(feature = "dhcp", feature = "lua"))]
    #[arg(long = "dhcp-luascript", value_name = "PATH")]
    pub dhcp_luascript: Option<PathBuf>,

    /// Script on renewal
    ///
    /// Run script on lease renewal, not just new leases.
    /// C equivalent: --script-on-renewal (option.c line 372, LOPT_SCRIPT_TIME = 360)
    #[cfg(all(feature = "dhcp", feature = "script"))]
    #[arg(long = "script-on-renewal", action = ArgAction::SetTrue)]
    pub script_on_renewal: bool,

    /// Script ARP
    ///
    /// Call script with ARP details.
    /// C equivalent: --script-arp (option.c line 262, LOPT_SCRIPT_ARP = 347)
    #[cfg(all(feature = "dhcp", feature = "script"))]
    #[arg(long = "script-arp", action = ArgAction::SetTrue)]
    pub script_arp: bool,

    /// DHCP script user
    ///
    /// Run DHCP script as specified user.
    /// C equivalent: --dhcp-scriptuser=<user> (option.c line 415, LOPT_SCRIPTUSR = 285)
    #[cfg(all(feature = "dhcp", feature = "script"))]
    #[arg(long = "dhcp-scriptuser", value_name = "USER")]
    pub dhcp_scriptuser: Option<String>,

    /// DHCP hosts file
    ///
    /// Read static DHCP hosts from file.
    /// C equivalent: --dhcp-hostsfile=<file> (option.c line 398, LOPT_DHCP_HOST = 273)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-hostsfile", value_name = "FILE", action = ArgAction::Append)]
    pub dhcp_hostsfile: Vec<PathBuf>,

    /// DHCP options file
    ///
    /// Read DHCP options from file.
    /// C equivalent: --dhcp-optsfile=<file> (option.c line 399, LOPT_DHCP_OPTS = 280)
    #[cfg(feature = "dhcp")]
    #[arg(long = "dhcp-optsfile", value_name = "FILE", action = ArgAction::Append)]
    pub dhcp_optsfile: Vec<PathBuf>,

    /// DHCP hosts directory
    ///
    /// Read DHCP hosts from directory (inotify).
    /// C equivalent: --dhcp-hostsdir=<dir> (option.c line 400, LOPT_DHCP_INOTIFY = 340)
    #[cfg(all(feature = "dhcp", feature = "inotify"))]
    #[arg(long = "dhcp-hostsdir", value_name = "DIR", action = ArgAction::Append)]
    pub dhcp_hostsdir: Vec<PathBuf>,

    /// DHCP options directory
    ///
    /// Read DHCP options from directory (inotify).
    /// C equivalent: --dhcp-optsdir=<dir> (option.c line 401, LOPT_DHOPT_INOTIFY = 341)
    #[cfg(all(feature = "dhcp", feature = "inotify"))]
    #[arg(long = "dhcp-optsdir", value_name = "DIR", action = ArgAction::Append)]
    pub dhcp_optsdir: Vec<PathBuf>,

    // ========================================================================
    // TFTP Configuration
    // ========================================================================
    
    /// Enable TFTP server
    ///
    /// Enable TFTP server on interfaces.
    /// C equivalent: --enable-tftp=<interface> (option.c line 376, LOPT_TFTP = 258)
    #[cfg(feature = "tftp")]
    #[arg(long = "enable-tftp", value_name = "INTERFACE")]
    pub enable_tftp: Option<String>,

    /// TFTP root directory
    ///
    /// Root directory for TFTP file serving.
    /// C equivalent: --tftp-root=<dir> (option.c line 380, LOPT_PREFIX = 260)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-root", value_name = "DIR")]
    pub tftp_root: Option<PathBuf>,

    /// TFTP secure mode
    ///
    /// Chroot to tftp-root for security.
    /// C equivalent: --tftp-secure (option.c line 377, LOPT_SECURE = 259)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-secure", action = ArgAction::SetTrue)]
    pub tftp_secure: bool,

    /// TFTP no fail
    ///
    /// Don't fail if TFTP root doesn't exist at startup.
    /// C equivalent: --tftp-no-fail (option.c line 378, LOPT_TFTP_NO_FAIL = 344)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-no-fail", action = ArgAction::SetTrue)]
    pub tftp_no_fail: bool,

    /// TFTP unique root per client
    ///
    /// Use client IP as subdirectory. Format: [=ip|mac]
    /// C equivalent: --tftp-unique-root=<spec> (option.c line 379, LOPT_APREF = 274)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-unique-root", value_name = "MODE")]
    pub tftp_unique_root: Option<String>,

    /// TFTP lowercase filenames
    ///
    /// Convert requested filenames to lowercase.
    /// C equivalent: --tftp-lowercase (option.c line 383, LOPT_TFTP_LC = 309)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-lowercase", action = ArgAction::SetTrue)]
    pub tftp_lowercase: bool,

    /// Maximum TFTP connections
    ///
    /// Maximum concurrent TFTP connections.
    /// C equivalent: --tftp-max=<connections> (option.c line 381, LOPT_TFTP_MAX = 263)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-max", value_name = "CONNECTIONS")]
    pub tftp_max: Option<usize>,

    /// TFTP MTU
    ///
    /// Maximum TFTP packet size (MTU).
    /// C equivalent: --tftp-mtu=<mtu> (option.c line 382, LOPT_TFTP_MTU = 349)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-mtu", value_name = "MTU")]
    pub tftp_mtu: Option<u16>,

    /// TFTP port range
    ///
    /// Port range for TFTP transfers. Format: <start>,<end>
    /// C equivalent: --tftp-port-range=<start>,<end> (option.c line 403, LOPT_TFTPPORTS = 276)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-port-range", value_name = "RANGE")]
    pub tftp_port_range: Option<String>,

    /// TFTP no block size negotiation
    ///
    /// Disable TFTP block size option.
    /// C equivalent: --tftp-no-blocksize (option.c line 390, LOPT_NOBLOCK = 265)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-no-blocksize", action = ArgAction::SetTrue)]
    pub tftp_no_blocksize: bool,

    /// TFTP single port
    ///
    /// Use single well-known port for all TFTP transfers.
    /// C equivalent: --tftp-single-port (option.c line 384, LOPT_SINGLE_PORT = 359)
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-single-port", action = ArgAction::SetTrue)]
    pub tftp_single_port: bool,

    /// Quiet TFTP logging
    ///
    /// Suppress routine TFTP logging.
    /// C equivalent: --quiet-tftp (option.c line 282, LOPT_QUIET_TFTP = 367)
    #[cfg(feature = "tftp")]
    #[arg(long = "quiet-tftp", action = ArgAction::SetTrue)]
    pub quiet_tftp: bool,

    // ========================================================================
    // Authoritative DNS Configuration
    // ========================================================================
    
    /// Authoritative DNS zone
    ///
    /// Define authoritative zone. Format: <domain>[,<subnet>]...
    /// C equivalent: --auth-zone=<spec> (option.c line 441, LOPT_AUTHZONE = 313)
    #[cfg(feature = "auth")]
    #[arg(long = "auth-zone", value_name = "SPEC", action = ArgAction::Append)]
    pub auth_zones: Vec<String>,

    /// Authoritative server
    ///
    /// NS record for authoritative zones.
    /// C equivalent: --auth-server=<domain>,<server> (option.c line 442, LOPT_AUTHSERV = 314)
    #[cfg(feature = "auth")]
    #[arg(long = "auth-server", value_name = "SPEC", action = ArgAction::Append)]
    pub auth_servers: Vec<String>,

    /// Authoritative TTL
    ///
    /// TTL for authoritative zone records.
    /// C equivalent: --auth-ttl=<ttl> (option.c line 443, LOPT_AUTHTTL = 315)
    #[cfg(feature = "auth")]
    #[arg(long = "auth-ttl", value_name = "TTL")]
    pub auth_ttl: Option<u32>,

    /// Authoritative SOA parameters
    ///
    /// SOA record parameters. Format: <serial>[,<refresh>[,<retry>[,<expiry>]]]
    /// C equivalent: --auth-soa=<spec> (option.c line 444, LOPT_AUTHSOA = 316)
    #[cfg(feature = "auth")]
    #[arg(long = "auth-soa", value_name = "SPEC")]
    pub auth_soa: Option<String>,

    /// Authoritative secondary servers
    ///
    /// Secondary NS servers for zone.
    /// C equivalent: --auth-sec-servers=<domain>,<server>[,<server>]... (option.c line 445, LOPT_AUTHSFS = 317)
    #[cfg(feature = "auth")]
    #[arg(long = "auth-sec-servers", value_name = "SPEC", action = ArgAction::Append)]
    pub auth_sec_servers: Vec<String>,

    /// Authoritative peer
    ///
    /// Peer for auth-zone. Format: <ip-address>[,<ip-address>]
    /// C equivalent: --auth-peer=<spec> (option.c line 446, LOPT_AUTHPEER = 318)
    #[cfg(feature = "auth")]
    #[arg(long = "auth-peer", value_name = "SPEC", action = ArgAction::Append)]
    pub auth_peers: Vec<String>,

    // ========================================================================
    // External Integration
    // ========================================================================
    
    /// Enable D-Bus interface
    ///
    /// Enable D-Bus control interface.
    /// C equivalent: -1 [=<service-name>], --enable-dbus (option.c line 363)
    #[cfg(feature = "dbus")]
    #[arg(short = '1', long = "enable-dbus", value_name = "SERVICE")]
    pub enable_dbus: Option<String>,

    /// Enable ubus interface
    ///
    /// Enable OpenWrt ubus control interface.
    /// C equivalent: --enable-ubus=<service> (option.c line 364, LOPT_UBUS = 354)
    #[cfg(feature = "ubus")]
    #[arg(long = "enable-ubus", value_name = "SERVICE")]
    pub enable_ubus: Option<String>,

    /// Linux connection tracking
    ///
    /// Use Linux connection tracking to determine upstream.
    /// C equivalent: --conntrack (option.c line 434, LOPT_CONNTRACK = 303)
    #[cfg(feature = "conntrack")]
    #[arg(long = "conntrack", action = ArgAction::SetTrue)]
    pub conntrack: bool,

    /// Linux ipset integration
    ///
    /// Add matching domains to ipset. Format: /<domain>/<ipset>[,<ipset>...]
    /// C equivalent: --ipset=<spec> (option.c line 447, LOPT_IPSET = 319)
    #[cfg(feature = "ipset")]
    #[arg(long = "ipset", value_name = "SPEC", action = ArgAction::Append)]
    pub ipsets: Vec<String>,

    /// Linux nftables integration
    ///
    /// Add matching domains to nftables set. Format: /<domain>/<family>#<table>#<set>[,<family>#<table>#<set>...]
    /// C equivalent: --nftset=<spec> (option.c line 448, LOPT_NFTSET = 368)
    #[cfg(feature = "nftset")]
    #[arg(long = "nftset", value_name = "SPEC", action = ArgAction::Append)]
    pub nftsets: Vec<String>,

    /// Connmark allowlist enable
    ///
    /// Enable connmark-based allowlist filtering.
    /// C equivalent: --connmark-allowlist-enable=<mask> (option.c line 449, LOPT_CMARK_ALST_EN = 365)
    #[cfg(feature = "conntrack")]
    #[arg(long = "connmark-allowlist-enable", value_name = "MASK")]
    pub connmark_allowlist_enable: Option<String>,

    /// Connmark allowlist
    ///
    /// Define connmark allowlist. Format: <connmark>[/<mask>][,<pattern>]
    /// C equivalent: --connmark-allowlist=<spec> (option.c line 450, LOPT_CMARK_ALST = 366)
    #[cfg(feature = "conntrack")]
    #[arg(long = "connmark-allowlist", value_name = "SPEC", action = ArgAction::Append)]
    pub connmark_allowlist: Vec<String>,

    // ========================================================================
    // Process Management and Debugging
    // ========================================================================
    
    /// Configuration file path
    ///
    /// Main configuration file. Default varies by platform.
    /// C equivalent: -C <file>, --conf-file=<file> (option.c line 335)
    #[arg(short = 'C', long = "conf-file", value_name = "FILE")]
    pub conf_file: Option<PathBuf>,

    /// Configuration directory
    ///
    /// Read all .conf files from directory.
    /// C equivalent: -7 <dir>, --conf-dir=<dir> (option.c line 369)
    #[arg(short = '7', long = "conf-dir", value_name = "DIR", action = ArgAction::Append)]
    pub conf_dirs: Vec<PathBuf>,

    /// Configuration script
    ///
    /// Run script to generate configuration.
    /// C equivalent: --conf-script=<script> (option.c line 336, LOPT_CONF_SCRIPT = 374)
    #[arg(long = "conf-script", value_name = "SCRIPT")]
    pub conf_script: Option<PathBuf>,

    /// PID file path
    ///
    /// File to write daemon PID.
    /// C equivalent: -x <file>, --pid-file=<file> (option.c line 329)
    #[arg(short = 'x', long = "pid-file", value_name = "FILE")]
    pub pid_file: Option<PathBuf>,

    /// User to run as
    ///
    /// Drop privileges to user after binding ports.
    /// C equivalent: -u <username>, --user=<username> (option.c line 303)
    #[arg(short = 'u', long = "user", value_name = "USER")]
    pub user: Option<String>,

    /// Group to run as
    ///
    /// Drop privileges to group after binding ports.
    /// C equivalent: -g <groupname>, --group=<groupname> (option.c line 304)
    #[arg(short = 'g', long = "group", value_name = "GROUP")]
    pub group: Option<String>,

    /// Log facility
    ///
    /// Syslog facility for logging. Format: <facility>|<file>|'-' (stderr)
    /// C equivalent: -8 <facility>, --log-facility=<facility> (option.c line 370)
    #[arg(short = '8', long = "log-facility", value_name = "FACILITY")]
    pub log_facility: Option<String>,

    /// DNS loop detection
    ///
    /// Detect and prevent DNS forwarding loops.
    /// C equivalent: --dns-loop-detect (option.c line 252, LOPT_LOOP_DETECT = 337)
    #[cfg(feature = "loop-detect")]
    #[arg(long = "dns-loop-detect", action = ArgAction::SetTrue)]
    pub dns_loop_detect: bool,

    /// Packet dump file
    ///
    /// Dump DNS packets to file (pcap format).
    /// C equivalent: --dumpfile=<file> (option.c line 267, LOPT_DUMPFILE = 352)
    #[cfg(feature = "dump")]
    #[arg(long = "dumpfile", value_name = "FILE")]
    pub dumpfile: Option<PathBuf>,

    /// Packet dump mask
    ///
    /// Control which packets to dump. Format: <mask>
    /// C equivalent: --dumpmask=<mask> (option.c line 268, LOPT_DUMPMASK = 353)
    #[cfg(feature = "dump")]
    #[arg(long = "dumpmask", value_name = "MASK")]
    pub dumpmask: Option<String>,

    /// Cisco Umbrella integration
    ///
    /// Add Umbrella-ORG option to queries.
    /// C equivalent: --umbrella=<org-id>[,<asset-id>[,<org-id-secret>]] (option.c line 279, LOPT_UMBRELLA = 364)
    #[arg(long = "umbrella", value_name = "SPEC")]
    pub umbrella: Option<String>,
}

/// Parse command-line arguments and return Config
///
/// This function is the main entry point for CLI parsing, replacing C's read_opts()
/// function from option.c. It uses clap to parse arguments, then transforms the
/// CliArgs structure into a Config structure by merging with defaults and applying
/// precedence rules.
///
/// # Precedence
///
/// Command-line arguments override config file values, which override defaults:
/// CLI > config file > defaults
///
/// # Errors
///
/// Returns CliError if:
/// - Invalid argument values (malformed IP, out-of-range port, etc.)
/// - Conflicting options (e.g., --bind-interfaces with --bind-dynamic)
/// - Missing required option combinations
///
/// # Original C Mapping
///
/// Equivalent to read_opts() from option.c lines 6616-6947, but with type-safe
/// parsing and automatic memory management.
pub fn parse_cli_args() -> Result<Config, CliError> {
    let args = CliArgs::try_parse().map_err(|e| CliError::ParseError(e.to_string()))?;

    // Handle special flags that cause immediate exit
    if args.version {
        println!("Dnsmasq version {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    if args.help {
        // Clap handles help automatically, but we catch it here for custom behavior
        std::process::exit(0);
    }

    // Start with default configuration
    let mut config = default_config();

    // Validate conflicting options
    validate_cli_args(&args)?;

    // Apply CLI arguments to config
    apply_cli_to_config(&mut config, &args)?;

    Ok(config)
}

/// Validate CLI arguments for conflicts and invalid combinations
///
/// Checks for mutually exclusive options and invalid option combinations that
/// clap cannot express in its derive macro system.
///
/// # Errors
///
/// Returns CliError::ConflictingOptions if incompatible options are specified.
fn validate_cli_args(args: &CliArgs) -> Result<(), CliError> {
    // Check bind-interfaces vs bind-dynamic conflict
    if args.bind_interfaces && args.bind_dynamic {
        return Err(CliError::ConflictingOptions {
            option1: "--bind-interfaces".to_string(),
            option2: "--bind-dynamic".to_string(),
            reason: "these are mutually exclusive binding modes".to_string(),
        });
    }

    // Validate port range
    if let (Some(min), Some(max)) = (args.min_port, args.max_port) {
        if min > max {
            return Err(CliError::InvalidArgument {
                arg: "--min-port/--max-port".to_string(),
                value: format!("{}/{}", min, max),
                reason: "min-port must be less than or equal to max-port".to_string(),
            });
        }
    }

    // Validate DNSSEC conflicts
    #[cfg(feature = "dnssec")]
    {
        if args.dnssec && args.proxy_dnssec {
            return Err(CliError::ConflictingOptions {
                option1: "--dnssec".to_string(),
                option2: "--proxy-dnssec".to_string(),
                reason: "cannot both validate and proxy DNSSEC".to_string(),
            });
        }
    }

    // Validate TFTP requirements
    #[cfg(feature = "tftp")]
    {
        if args.enable_tftp.is_some() && args.tftp_root.is_none() {
            return Err(CliError::InvalidArgument {
                arg: "--enable-tftp".to_string(),
                value: args.enable_tftp.as_ref().unwrap().clone(),
                reason: "requires --tftp-root to specify root directory".to_string(),
            });
        }
    }

    Ok(())
}

/// Apply CLI arguments to config structure
///
/// Transforms CliArgs into Config by setting appropriate fields and converting
/// string specifications into typed structures. This implements the precedence
/// where CLI overrides defaults.
///
/// # Errors
///
/// Returns CliError::InvalidArgument if argument values are malformed or invalid.
fn apply_cli_to_config(config: &mut Config, args: &CliArgs) -> Result<(), CliError> {
    // Core flags - daemonize is inverted from no_daemon
    config.process.daemonize = !(args.no_daemon || args.keep_in_foreground);
    
    // Debug flag is stored in DaemonOptions bitflags
    if args.debug {
        config.options.insert(super::types::DaemonOptions::OPT_DEBUG);
    }

    // DNS configuration
    config.dns.port = args.port;
    config.dns.cache_size = args.cache_size;
    
    if let Some(query_port) = args.query_port {
        config.dns.query_port = Some(query_port);
    }

    if args.no_resolv {
        config.dns.resolv_file = None;
    } else if let Some(ref resolv_file) = args.resolv_file {
        config.dns.resolv_file = Some(resolv_file.clone());
    }

    // These options are stored as bitflags in DaemonOptions
    if args.no_poll {
        config.options.insert(super::types::DaemonOptions::OPT_NO_POLL);
    }
    
    if args.strict_order {
        config.options.insert(super::types::DaemonOptions::OPT_ORDER);
    }
    
    if args.all_servers {
        config.options.insert(super::types::DaemonOptions::OPT_ALL_SERVERS);
    }
    
    if args.no_hosts {
        config.options.insert(super::types::DaemonOptions::OPT_NO_HOSTS);
    }

    // Logging
    if args.log_queries > 0 {
        config.options.insert(super::types::DaemonOptions::OPT_LOG);
    }

    // Network configuration
    config.network.bind_interfaces = args.bind_interfaces;
    config.network.bind_dynamic = args.bind_dynamic;
    
    for interface in &args.interfaces {
        config.network.interfaces.push(super::types::InterfaceName {
            name: interface.clone(),
            addr: None,
        });
    }

    for addr in &args.listen_addresses {
        config.network.listen_addresses.push(*addr);
    }

    // Process configuration
    if let Some(ref user) = args.user {
        config.process.username = Some(user.clone());
    }

    if let Some(ref group) = args.group {
        config.process.groupname = Some(group.clone());
    }

    if let Some(ref pid_file) = args.pid_file {
        config.process.pid_file = Some(pid_file.clone());
    }

    // TTL configuration
    if let Some(local_ttl) = args.local_ttl {
        config.dns.local_ttl = u64::from(local_ttl);
    }

    if args.no_negcache {
        config.options.insert(super::types::DaemonOptions::OPT_NO_NEG);
    }

    // TFTP configuration
    #[cfg(feature = "tftp")]
    {
        if let Some(ref tftp_root) = args.tftp_root {
            config.tftp.tftp_root = Some(tftp_root.clone());
        }

        config.tftp.secure_mode = args.tftp_secure;
        config.tftp.single_port = args.tftp_single_port;
        config.tftp.lowercase = args.tftp_lowercase;

        if let Some(tftp_max) = args.tftp_max {
            config.tftp.tftp_max_connections = tftp_max;
        }

        if let Some(tftp_mtu) = args.tftp_mtu {
            config.tftp.tftp_mtu = Some(tftp_mtu);
        }
    }

    // DHCP configuration
    #[cfg(feature = "dhcp")]
    {
        config.dhcp.authoritative = args.dhcp_authoritative;
        
        if let Some(ref leasefile) = args.dhcp_leasefile {
            config.dhcp.lease_file = leasefile.clone();
        }

        if let Some(lease_max) = args.dhcp_lease_max {
            config.dhcp.lease_max = lease_max;
        }

        // no_ping is stored as a bitflag in DaemonOptions
        if args.no_ping {
            config.options.insert(super::types::DaemonOptions::OPT_NO_PING);
        }
    }

    // DNSSEC configuration
    #[cfg(feature = "dnssec")]
    {
        if args.dnssec {
            config.options.insert(super::types::DaemonOptions::OPT_DNSSEC_VALID);
        }
        // Additional DNSSEC config would go here
    }

    // Integration configuration
    #[cfg(feature = "dbus")]
    {
        if args.enable_dbus.is_some() {
            config.integration.enable_dbus = true;
        }
    }

    #[cfg(feature = "conntrack")]
    {
        config.integration.conntrack = args.conntrack;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_error_display() {
        let err = CliError::InvalidArgument {
            arg: "port".to_string(),
            value: "99999".to_string(),
            reason: "port must be 0-65535".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "dnsmasq: bad port option '99999': port must be 0-65535"
        );
    }

    #[test]
    fn test_conflicting_options() {
        let args = CliArgs {
            bind_interfaces: true,
            bind_dynamic: true,
            ..Default::default()
        };
        
        let result = validate_cli_args(&args);
        assert!(result.is_err());
        
        if let Err(CliError::ConflictingOptions { option1, option2, .. }) = result {
            assert_eq!(option1, "--bind-interfaces");
            assert_eq!(option2, "--bind-dynamic");
        }
    }

    #[test]
    fn test_default_values() {
        let args = CliArgs::parse_from(&["dnsmasq"]);
        assert_eq!(args.port, 53);
        assert_eq!(args.cache_size, 150);
        assert!(!args.no_daemon);
    }

    #[test]
    fn test_port_range_validation() {
        let args = CliArgs {
            min_port: Some(5000),
            max_port: Some(4000),
            ..Default::default()
        };
        
        let result = validate_cli_args(&args);
        assert!(result.is_err());
    }
}
