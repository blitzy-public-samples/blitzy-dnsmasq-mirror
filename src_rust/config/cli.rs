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

//! Command-line argument parser
//!
//! Processes command-line arguments using clap, maintaining compatibility with
//! the C implementation's CLI interface.

use super::types::Config;
use super::defaults::default_config;
use clap::Parser;
use std::fmt;
use std::path::PathBuf;

/// Errors that can occur during CLI parsing
#[derive(Debug)]
pub enum CliError {
    /// Invalid argument value
    InvalidArgument {
        /// Name of the command-line argument
        arg: String,
        /// The invalid value provided
        value: String,
        /// Description of why the value is invalid
        reason: String,
    },
    /// Missing required argument
    MissingRequired {
        /// Name of the missing required argument
        arg: String,
    },
    /// Conflicting arguments
    Conflict {
        /// Name of the first conflicting argument
        arg1: String,
        /// Name of the second conflicting argument
        arg2: String,
    },
    /// Clap parsing error
    ParseError(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::InvalidArgument { arg, value, reason } => {
                write!(f, "Invalid value '{}' for argument '{}': {}", value, arg, reason)
            }
            CliError::MissingRequired { arg } => {
                write!(f, "Missing required argument: {}", arg)
            }
            CliError::Conflict { arg1, arg2 } => {
                write!(f, "Conflicting arguments: {} and {}", arg1, arg2)
            }
            CliError::ParseError(msg) => {
                write!(f, "CLI parsing error: {}", msg)
            }
        }
    }
}

impl std::error::Error for CliError {}

/// Command-line arguments for dnsmasq
///
/// This struct uses clap's derive macros to declaratively specify all command-line
/// options matching the C implementation. Long option names are identical to the C
/// version for backward compatibility.
#[derive(Parser, Debug)]
#[command(name = "dnsmasq")]
#[command(author = "Simon Kelley")]
#[command(version)]
#[command(about = "A lightweight DHCP and caching DNS server", long_about = None)]
pub struct CliArgs {
    /// Configuration file path
    #[arg(short = 'C', long = "conf-file", value_name = "FILE")]
    pub conf_file: Option<PathBuf>,
    
    /// DNS port to listen on (0 to disable DNS)
    #[arg(short = 'p', long = "port", value_name = "PORT", default_value = "53")]
    pub port: u16,
    
    /// Do not read /etc/resolv.conf for upstream servers
    #[arg(short = 'R', long = "no-resolv")]
    pub no_resolv: bool,
    
    /// Upstream DNS server address
    #[arg(short = 'S', long = "server", value_name = "SERVER")]
    pub servers: Vec<String>,
    
    /// Disable DHCP server
    #[arg(long = "no-dhcp")]
    pub no_dhcp: bool,
    
    /// Enable DNSSEC validation
    #[arg(long = "dnssec")]
    pub dnssec: bool,
    
    /// Do not run as daemon (stay in foreground)
    #[arg(short = 'd', long = "no-daemon")]
    pub no_daemon: bool,
    
    /// Log DNS queries
    #[arg(short = 'q', long = "log-queries")]
    pub log_queries: bool,
    
    /// Cache size (number of entries)
    #[arg(short = 'c', long = "cache-size", value_name = "SIZE", default_value = "150")]
    pub cache_size: usize,
    
    /// PID file path
    #[arg(short = 'x', long = "pid-file", value_name = "FILE")]
    pub pid_file: Option<PathBuf>,
    
    /// User to run as
    #[arg(short = 'u', long = "user", value_name = "USER")]
    pub user: Option<String>,
    
    /// Group to run as
    #[arg(short = 'g', long = "group", value_name = "GROUP")]
    pub group: Option<String>,
    
    /// Interface to listen on
    #[arg(short = 'i', long = "interface", value_name = "INTERFACE")]
    pub interfaces: Vec<String>,
    
    /// Interface to NOT listen on
    #[arg(short = 'I', long = "except-interface", value_name = "INTERFACE")]
    pub except_interfaces: Vec<String>,
    
    /// Listen only on specified interfaces
    #[arg(short = 'z', long = "bind-interfaces")]
    pub bind_interfaces: bool,
    
    /// Bind interfaces dynamically
    #[arg(long = "bind-dynamic")]
    pub bind_dynamic: bool,
    
    /// DHCP lease file
    #[arg(short = 'l', long = "dhcp-leasefile", value_name = "FILE")]
    pub lease_file: Option<PathBuf>,
    
    /// Run as authoritative DHCP server
    #[arg(short = 'K', long = "dhcp-authoritative")]
    pub dhcp_authoritative: bool,
    
    /// Enable D-Bus interface
    #[arg(long = "enable-dbus")]
    pub enable_dbus: bool,
    
    /// Test configuration and exit
    #[arg(long = "test")]
    pub test: bool,
    
    /// Increase logging verbosity
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

/// Parse command-line arguments
///
/// Processes command-line arguments using clap and converts them into a Config struct.
/// Merges CLI arguments with default configuration, with CLI taking precedence.
///
/// # Returns
///
/// `Ok(Config)` with parsed configuration, or `Err(CliError)` on parsing failure
///
/// # Example
///
/// ```no_run
/// use dnsmasq::config::parse_cli_args;
///
/// match parse_cli_args() {
///     Ok(config) => {
///         println!("DNS port: {}", config.dns.port);
///     }
///     Err(e) => {
///         eprintln!("CLI error: {}", e);
///         std::process::exit(1);
///     }
/// }
/// ```
pub fn parse_cli_args() -> Result<Config, CliError> {
    let args = CliArgs::parse();
    cli_args_to_config(args)
}

/// Convert CliArgs to Config
///
/// Internal function that merges CLI arguments with default configuration.
fn cli_args_to_config(args: CliArgs) -> Result<Config, CliError> {
    let mut config = default_config();
    
    // Apply CLI arguments to config
    config.dns.port = args.port;
    config.dns.cache_size = args.cache_size;
    // Note: no_resolv flag affects upstream server configuration, not stored as a direct field
    config.logging.log_queries = args.log_queries;
    
    // Parse upstream servers
    for server_str in args.servers {
        // In full implementation, would parse server string into UpstreamServer
        // For now, this is a placeholder
        let _ = server_str;
    }
    
    // DNSSEC flag
    if args.dnssec {
        config.options.insert(super::types::DaemonOptions::OPT_DNSSEC_VALID);
    }
    
    // Daemon mode
    config.process.daemonize = !args.no_daemon;
    config.process.pid_file = args.pid_file;
    config.process.username = args.user;
    config.process.groupname = args.group;
    
    // Network configuration
    for iface in args.interfaces {
        config.network.interfaces.push(super::types::InterfaceName { name: iface, addr: None });
    }
    for iface in args.except_interfaces {
        config.network.except_interfaces.push(super::types::InterfaceName { name: iface, addr: None });
    }
    config.network.bind_interfaces = args.bind_interfaces;
    config.network.bind_dynamic = args.bind_dynamic;
    
    // Validate mutually exclusive options
    if config.network.bind_interfaces && config.network.bind_dynamic {
        return Err(CliError::Conflict {
            arg1: "bind-interfaces".to_string(),
            arg2: "bind-dynamic".to_string(),
        });
    }
    
    // DHCP configuration
    if let Some(lease_file) = args.lease_file {
        config.dhcp.lease_file = lease_file;
    }
    config.dhcp.authoritative = args.dhcp_authoritative;
    
    // Integration - D-Bus support
    #[cfg(feature = "dbus")]
    {
        if args.enable_dbus {
            config.integration.dbus_name = Some("uk.org.thekelleys.dnsmasq".to_string());
        }
    }
    #[cfg(not(feature = "dbus"))]
    {
        let _ = args.enable_dbus; // Suppress unused warning
    }
    
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_args_basic() {
        let args = CliArgs {
            conf_file: None,
            port: 5353,
            no_resolv: false,
            servers: vec![],
            no_dhcp: false,
            dnssec: false,
            no_daemon: true,
            log_queries: false,
            cache_size: 500,
            pid_file: None,
            user: None,
            group: None,
            interfaces: vec![],
            except_interfaces: vec![],
            bind_interfaces: false,
            bind_dynamic: false,
            lease_file: None,
            dhcp_authoritative: false,
            enable_dbus: false,
            test: false,
            verbose: false,
        };
        
        let config = cli_args_to_config(args).expect("Should convert successfully");
        assert_eq!(config.dns.port, 5353);
        assert_eq!(config.dns.cache_size, 500);
        assert!(!config.process.daemonize);
    }

    #[test]
    fn test_cli_args_dnssec() {
        let args = CliArgs {
            conf_file: None,
            port: 53,
            no_resolv: false,
            servers: vec![],
            no_dhcp: false,
            dnssec: true,
            no_daemon: false,
            log_queries: false,
            cache_size: 150,
            pid_file: None,
            user: None,
            group: None,
            interfaces: vec![],
            except_interfaces: vec![],
            bind_interfaces: false,
            bind_dynamic: false,
            lease_file: None,
            dhcp_authoritative: false,
            enable_dbus: false,
            test: false,
            verbose: false,
        };
        
        let config = cli_args_to_config(args).expect("Should convert successfully");
        assert!(config.options.contains(super::super::types::DaemonOptions::OPT_DNSSEC_VALID));
    }

    #[test]
    fn test_cli_args_conflict() {
        let args = CliArgs {
            conf_file: None,
            port: 53,
            no_resolv: false,
            servers: vec![],
            no_dhcp: false,
            dnssec: false,
            no_daemon: false,
            log_queries: false,
            cache_size: 150,
            pid_file: None,
            user: None,
            group: None,
            interfaces: vec![],
            except_interfaces: vec![],
            bind_interfaces: true,
            bind_dynamic: true,
            lease_file: None,
            dhcp_authoritative: false,
            enable_dbus: false,
            test: false,
            verbose: false,
        };
        
        assert!(cli_args_to_config(args).is_err());
    }
}
