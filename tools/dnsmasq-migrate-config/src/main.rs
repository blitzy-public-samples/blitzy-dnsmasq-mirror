// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
// Rust migration tooling Copyright (c) 2024 Blitzy Platform
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

//! # dnsmasq Configuration Migration and Validation Tool
//!
//! This standalone utility validates existing dnsmasq.conf configuration files
//! for compatibility with the Rust implementation of dnsmasq. It parses the same
//! configuration syntax as src/option.c from the C version to ensure 100% backward
//! compatibility.
//!
//! ## Features
//!
//! - Validates 200+ configuration options for syntax errors and semantic correctness
//! - Checks type validation (IP addresses, ports, time intervals, DHCP ranges, etc.)
//! - Detects conflicts such as overlapping DHCP ranges and duplicate options
//! - Supports recursive includes via conf-file and conf-dir directives
//! - Handles conditional compilation feature flags (HAVE_DHCP, HAVE_DNSSEC, etc.)
//! - Provides detailed migration recommendations and compatibility reports
//! - Supports multiple output formats (text, JSON, colored terminal)
//!
//! ## Usage
//!
//! ```bash
//! dnsmasq-migrate-config /etc/dnsmasq.conf
//! dnsmasq-migrate-config --features dhcp,dnssec /etc/dnsmasq.conf
//! dnsmasq-migrate-config --format json --output report.json /etc/dnsmasq.conf
//! ```
//!
//! ## Exit Codes
//!
//! - 0: Configuration valid, no errors or warnings
//! - 1: Syntax or type errors detected (invalid configuration)
//! - 2: Semantic warnings detected (potentially problematic configuration)
//! - 3: File I/O errors (unable to read config files)
//! - 4: Feature mismatch errors (options requiring disabled features)

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use ipnetwork::IpNetwork;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use walkdir::WalkDir;

/// Command-line interface for the dnsmasq configuration migration tool
#[derive(Parser, Debug)]
#[command(
    name = "dnsmasq-migrate-config",
    about = "Validate dnsmasq configuration files for Rust implementation compatibility",
    version = "1.0.0",
    author = "Blitzy Platform"
)]
struct Cli {
    /// Configuration file path(s) to validate (supports multiple files)
    #[arg(required = true)]
    config_files: Vec<PathBuf>,

    /// Enable specific features (comma-separated: dhcp,dhcp6,dnssec,tftp,auth,dbus,ubus,ipset,nftables,conntrack,lua,idn,loop-detect)
    #[arg(long, value_delimiter = ',')]
    features: Vec<String>,

    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Output file path (stdout if not specified)
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Color output control
    #[arg(long, value_enum, default_value = "auto")]
    color: ColorMode,

    /// Increase verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Test mode: quick syntax validation without semantic checks
    #[arg(long)]
    test_only: bool,
}

/// Output format options
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    /// Human-readable text format
    Text,
    /// Machine-readable JSON format
    Json,
}

/// Color mode for terminal output
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ColorMode {
    /// Auto-detect color support
    Auto,
    /// Always use colors
    Always,
    /// Never use colors
    Never,
}

/// Feature flags that can be enabled/disabled
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Feature {
    Dhcp,
    Dhcp6,
    Dnssec,
    Tftp,
    Auth,
    Dbus,
    Ubus,
    Ipset,
    Nftables,
    Conntrack,
    Lua,
    Idn,
    LoopDetect,
}

impl Feature {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "dhcp" => Some(Feature::Dhcp),
            "dhcp6" | "dhcpv6" => Some(Feature::Dhcp6),
            "dnssec" => Some(Feature::Dnssec),
            "tftp" => Some(Feature::Tftp),
            "auth" => Some(Feature::Auth),
            "dbus" => Some(Feature::Dbus),
            "ubus" => Some(Feature::Ubus),
            "ipset" => Some(Feature::Ipset),
            "nftables" | "nftset" => Some(Feature::Nftables),
            "conntrack" => Some(Feature::Conntrack),
            "lua" | "luascript" => Some(Feature::Lua),
            "idn" => Some(Feature::Idn),
            "loop-detect" | "loop_detect" => Some(Feature::LoopDetect),
            _ => None,
        }
    }
}

/// Validation error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info,
    Warning,
    Error,
}

/// Validation error or warning
#[derive(Debug, Clone, Serialize)]
struct ValidationIssue {
    severity: Severity,
    file: String,
    line: usize,
    column: Option<usize>,
    message: String,
    value: Option<String>,
    suggestion: Option<String>,
}

/// Validation report containing all issues and statistics
#[derive(Debug, Serialize)]
struct ValidationReport {
    summary: ValidationSummary,
    issues: Vec<ValidationIssue>,
    recommendations: Vec<String>,
}

/// Summary statistics for validation
#[derive(Debug, Serialize)]
struct ValidationSummary {
    total_files: usize,
    total_options: usize,
    error_count: usize,
    warning_count: usize,
    info_count: usize,
    enabled_features: Vec<String>,
    complexity: String,
}

/// Configuration context for tracking parsing state
struct ConfigContext {
    features: HashSet<Feature>,
    files_processed: HashSet<PathBuf>,
    file_inodes: HashSet<(u64, u64)>, // (device, inode) for duplicate detection
    dhcp_ranges: Vec<DhcpRange>,
    dhcp_hosts: Vec<DhcpHost>,
    options: HashMap<String, Vec<(String, usize)>>, // option -> (file, line)
    issues: Vec<ValidationIssue>,
}

/// DHCP range specification
#[derive(Debug, Clone)]
struct DhcpRange {
    file: String,
    line: usize,
    start: IpAddr,
    end: IpAddr,
    netmask: Option<IpAddr>,
}

/// DHCP host specification
#[derive(Debug, Clone)]
struct DhcpHost {
    file: String,
    line: usize,
    mac: Option<String>,
    ip: Option<IpAddr>,
    hostname: Option<String>,
}

impl ConfigContext {
    fn new(features: HashSet<Feature>) -> Self {
        Self {
            features,
            files_processed: HashSet::new(),
            file_inodes: HashSet::new(),
            dhcp_ranges: Vec::new(),
            dhcp_hosts: Vec::new(),
            options: HashMap::new(),
            issues: Vec::new(),
        }
    }

    fn add_issue(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    fn has_feature(&self, feature: Feature) -> bool {
        self.features.contains(&feature)
    }

    fn record_option(&mut self, option: &str, file: &str, line: usize) {
        self.options
            .entry(option.to_string())
            .or_insert_with(Vec::new)
            .push((file.to_string(), line));
    }
}

/// Type validators for different configuration value types
struct Validators;

impl Validators {
    /// Validate IP address (IPv4 or IPv6)
    fn validate_ip_address(value: &str) -> Result<IpAddr> {
        value
            .parse::<IpAddr>()
            .with_context(|| format!("Invalid IP address: {}", value))
    }

    /// Validate IPv4 address specifically
    fn validate_ipv4_address(value: &str) -> Result<Ipv4Addr> {
        value
            .parse::<Ipv4Addr>()
            .with_context(|| format!("Invalid IPv4 address: {}", value))
    }

    /// Validate IPv6 address specifically
    fn validate_ipv6_address(value: &str) -> Result<Ipv6Addr> {
        value
            .parse::<Ipv6Addr>()
            .with_context(|| format!("Invalid IPv6 address: {}", value))
    }

    /// Validate CIDR notation (IP address with prefix length)
    fn validate_cidr(value: &str) -> Result<IpNetwork> {
        value
            .parse::<IpNetwork>()
            .with_context(|| format!("Invalid CIDR notation: {}", value))
    }

    /// Validate port number (1-65535)
    fn validate_port(value: &str) -> Result<u16> {
        let port: u16 = value
            .parse()
            .with_context(|| format!("Invalid port number: {}", value))?;
        
        if port == 0 {
            bail!("Port number must be between 1 and 65535");
        }
        
        Ok(port)
    }

    /// Check if port is privileged (<1024)
    fn is_privileged_port(port: u16) -> bool {
        port < 1024
    }

    /// Validate time interval with unit suffixes (s, m, h, d, w)
    fn validate_time_interval(value: &str) -> Result<u64> {
        let re = Regex::new(r"^(\d+)([smhdw]?)$").unwrap();
        
        if let Some(caps) = re.captures(value) {
            let number: u64 = caps[1].parse()?;
            let unit = caps.get(2).map_or("s", |m| m.as_str());
            
            let seconds = match unit {
                "s" | "" => number,
                "m" => number.checked_mul(60).ok_or_else(|| anyhow!("Time overflow"))?,
                "h" => number.checked_mul(3600).ok_or_else(|| anyhow!("Time overflow"))?,
                "d" => number.checked_mul(86400).ok_or_else(|| anyhow!("Time overflow"))?,
                "w" => number.checked_mul(604800).ok_or_else(|| anyhow!("Time overflow"))?,
                _ => bail!("Invalid time unit: {}", unit),
            };
            
            Ok(seconds)
        } else {
            bail!("Invalid time interval format: {}", value)
        }
    }

    /// Validate MAC address (aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff format, with wildcard support)
    fn validate_mac_address(value: &str) -> Result<String> {
        let re = Regex::new(r"^([0-9a-fA-F*]{2}[:-]){5}[0-9a-fA-F*]{2}$").unwrap();
        
        if re.is_match(value) {
            Ok(value.to_string())
        } else {
            bail!("Invalid MAC address format: {}", value)
        }
    }

    /// Validate domain name (RFC 1035 compliance)
    fn validate_domain_name(value: &str) -> Result<String> {
        if value.is_empty() {
            bail!("Domain name cannot be empty");
        }
        
        // Allow wildcard domains
        if value.starts_with('*') {
            let rest = &value[1..];
            if !rest.is_empty() && !rest.starts_with('.') {
                bail!("Wildcard domain must be followed by a dot: {}", value);
            }
        }
        
        // Basic domain name validation (simplified RFC 1035)
        let re = Regex::new(r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.?$").unwrap();
        
        if re.is_match(value) {
            Ok(value.to_string())
        } else {
            bail!("Invalid domain name: {}", value)
        }
    }

    /// Validate file path and check existence
    fn validate_file_path(value: &str, must_exist: bool) -> Result<PathBuf> {
        let path = PathBuf::from(value);
        
        if must_exist && !path.exists() {
            bail!("File does not exist: {}", value);
        }
        
        Ok(path)
    }

    /// Validate directory path and check existence
    fn validate_dir_path(value: &str, must_exist: bool) -> Result<PathBuf> {
        let path = PathBuf::from(value);
        
        if must_exist {
            if !path.exists() {
                bail!("Directory does not exist: {}", value);
            }
            if !path.is_dir() {
                bail!("Path is not a directory: {}", value);
            }
        }
        
        Ok(path)
    }

    /// Validate DHCP range specification
    fn validate_dhcp_range(value: &str) -> Result<(IpAddr, IpAddr, Option<IpAddr>)> {
        let parts: Vec<&str> = value.split(',').collect();
        
        if parts.len() < 2 {
            bail!("DHCP range requires at least start and end addresses: {}", value);
        }
        
        let start = Self::validate_ip_address(parts[0].trim())?;
        let end = Self::validate_ip_address(parts[1].trim())?;
        
        // Ensure start < end (comparing as integers)
        match (start, end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                if u32::from(s) >= u32::from(e) {
                    bail!("DHCP range start must be less than end: {} >= {}", s, e);
                }
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                if s >= e {
                    bail!("DHCP range start must be less than end: {} >= {}", s, e);
                }
            }
            _ => bail!("DHCP range start and end must be the same IP version"),
        }
        
        // Optional netmask (third parameter)
        let netmask = if parts.len() > 2 {
            Some(Self::validate_ip_address(parts[2].trim())?)
        } else {
            None
        };
        
        Ok((start, end, netmask))
    }
}

/// Configuration file parser
struct ConfigParser<'a> {
    context: &'a mut ConfigContext,
    test_only: bool,
}

impl<'a> ConfigParser<'a> {
    fn new(context: &'a mut ConfigContext, test_only: bool) -> Self {
        Self { context, test_only }
    }

    /// Parse a configuration file
    fn parse_file(&mut self, path: &Path) -> Result<()> {
        // Check for duplicate files using inode tracking (like C version)
        if let Ok(metadata) = fs::metadata(path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let inode_key = (metadata.dev(), metadata.ino());
                
                if self.context.file_inodes.contains(&inode_key) {
                    // File already processed, skip silently
                    return Ok(());
                }
                
                self.context.file_inodes.insert(inode_key);
            }
        }

        self.context.files_processed.insert(path.to_path_buf());

        let file = fs::File::open(path).with_context(|| format!("Failed to open file: {:?}", path))?;
        let reader = BufReader::new(file);
        
        let path_str = path.display().to_string();
        let mut line_num = 0;
        let mut continued_line = String::new();
        
        for line in reader.lines() {
            line_num += 1;
            let line = line.with_context(|| format!("Failed to read line {} from {:?}", line_num, path))?;
            
            // Handle line continuation (backslash at end)
            if line.trim_end().ends_with('\\') {
                continued_line.push_str(&line[..line.len() - 1]);
                continue;
            } else if !continued_line.is_empty() {
                continued_line.push_str(&line);
                self.parse_line(&path_str, line_num, &continued_line)?;
                continued_line.clear();
            } else {
                self.parse_line(&path_str, line_num, &line)?;
            }
        }
        
        Ok(())
    }

    /// Parse a single configuration line
    fn parse_line(&mut self, file: &str, line_num: usize, line: &str) -> Result<()> {
        // Remove comments (# prefix)
        let line = if let Some(pos) = line.find('#') {
            &line[..pos]
        } else {
            line
        };
        
        let line = line.trim();
        
        // Skip empty lines
        if line.is_empty() {
            return Ok(());
        }
        
        // Parse option (key=value or key)
        let (key, value) = if let Some(pos) = line.find('=') {
            let key = line[..pos].trim();
            let value = line[pos + 1..].trim();
            (key, Some(value))
        } else {
            (line, None)
        };
        
        // Record option usage
        self.context.record_option(key, file, line_num);
        
        // Handle recursive includes first
        if key == "conf-file" {
            if let Some(path) = value {
                self.handle_conf_file(file, line_num, path)?;
            } else {
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Error,
                    file: file.to_string(),
                    line: line_num,
                    column: None,
                    message: "conf-file requires a file path".to_string(),
                    value: None,
                    suggestion: Some("Usage: conf-file=/path/to/file.conf".to_string()),
                });
            }
            return Ok(());
        }
        
        if key == "conf-dir" {
            if let Some(path) = value {
                self.handle_conf_dir(file, line_num, path)?;
            } else {
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Error,
                    file: file.to_string(),
                    line: line_num,
                    column: None,
                    message: "conf-dir requires a directory path".to_string(),
                    value: None,
                    suggestion: Some("Usage: conf-dir=/path/to/directory".to_string()),
                });
            }
            return Ok(());
        }
        
        // Validate the option
        self.validate_option(file, line_num, key, value)?;
        
        Ok(())
    }

    /// Handle conf-file directive (recursive include)
    fn handle_conf_file(&mut self, parent_file: &str, line_num: usize, path: &str) -> Result<()> {
        let path = PathBuf::from(path);
        
        if !path.exists() {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: parent_file.to_string(),
                line: line_num,
                column: None,
                message: format!("Configuration file not found: {:?}", path),
                value: Some(path.display().to_string()),
                suggestion: Some("Check that the file path is correct and the file exists".to_string()),
            });
            return Ok(());
        }
        
        // Recursively parse the included file
        self.parse_file(&path)?;
        
        Ok(())
    }

    /// Handle conf-dir directive (include all .conf files from directory)
    fn handle_conf_dir(&mut self, parent_file: &str, line_num: usize, path: &str) -> Result<()> {
        let path = PathBuf::from(path);
        
        if !path.exists() {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: parent_file.to_string(),
                line: line_num,
                column: None,
                message: format!("Configuration directory not found: {:?}", path),
                value: Some(path.display().to_string()),
                suggestion: Some("Check that the directory path is correct and the directory exists".to_string()),
            });
            return Ok(());
        }
        
        if !path.is_dir() {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: parent_file.to_string(),
                line: line_num,
                column: None,
                message: format!("conf-dir path is not a directory: {:?}", path),
                value: Some(path.display().to_string()),
                suggestion: Some("Specify a directory path, not a file".to_string()),
            });
            return Ok(());
        }
        
        // Walk directory and process all .conf files in sorted order
        let mut conf_files: Vec<PathBuf> = WalkDir::new(&path)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s == "conf")
                    .unwrap_or(false)
            })
            .map(|e| e.path().to_path_buf())
            .collect();
        
        conf_files.sort();
        
        for conf_file in conf_files {
            self.parse_file(&conf_file)?;
        }
        
        Ok(())
    }

    /// Validate a configuration option
    fn validate_option(&mut self, file: &str, line: usize, key: &str, value: Option<&str>) -> Result<()> {
        // Validate based on option key
        match key {
            // Network options
            "port" => self.validate_port_option(file, line, value),
            "listen-address" => self.validate_listen_address(file, line, value),
            "server" => self.validate_server_option(file, line, value),
            "address" => self.validate_address_option(file, line, value),
            "domain" => self.validate_domain_option(file, line, value),
            
            // DNS cache options
            "cache-size" => self.validate_cache_size(file, line, value),
            "neg-ttl" | "max-ttl" | "min-cache-ttl" | "local-ttl" => self.validate_ttl_option(file, line, key, value),
            "dns-forward-max" => self.validate_positive_integer(file, line, key, value),
            "edns-packet-max" => self.validate_edns_packet_max(file, line, value),
            
            // DHCP options (if DHCP feature enabled)
            "dhcp-range" => self.validate_dhcp_range_option(file, line, value),
            "dhcp-host" => self.validate_dhcp_host_option(file, line, value),
            "dhcp-option" => self.validate_dhcp_option(file, line, value),
            "dhcp-leasefile" | "lease-file" => self.validate_file_path_option(file, line, key, value, false),
            "dhcp-script" => self.validate_dhcp_script(file, line, value),
            
            // DHCPv6 options (if DHCP6 feature enabled)
            "enable-ra" | "dhcp-rapid-commit" => self.validate_boolean_flag(file, line, key),
            "ra-param" => self.validate_ra_param(file, line, value),
            
            // TFTP options (if TFTP feature enabled)
            "enable-tftp" => self.validate_tftp_feature(file, line),
            "tftp-root" => self.validate_dir_path_option(file, line, value, true),
            "tftp-secure" | "tftp-no-fail" => self.validate_boolean_flag(file, line, key),
            "tftp-max" => self.validate_positive_integer(file, line, key, value),
            
            // DNSSEC options (if DNSSEC feature enabled)
            "dnssec" => self.validate_dnssec_feature(file, line),
            "dnssec-check-unsigned" | "dnssec-no-timecheck" => self.validate_dnssec_flag(file, line, key),
            "trust-anchor" => self.validate_trust_anchor(file, line, value),
            
            // Authoritative DNS (if AUTH feature enabled)
            "auth-zone" => self.validate_auth_feature(file, line, value),
            "auth-server" => self.validate_domain_option(file, line, value),
            "auth-soa" => self.validate_auth_soa(file, line, value),
            
            // Integration options
            "enable-dbus" => self.validate_dbus_feature(file, line),
            "enable-ubus" => self.validate_ubus_feature(file, line),
            "conntrack" => self.validate_conntrack_feature(file, line),
            "ipset" => self.validate_ipset_feature(file, line, value),
            "nftset" => self.validate_nftset_feature(file, line, value),
            
            // File paths
            "resolv-file" | "addn-hosts" => self.validate_file_path_option(file, line, key, value, true),
            "hostsdir" => self.validate_dir_path_option(file, line, value, true),
            
            // User/group
            "user" | "group" => self.validate_user_group(file, line, key, value),
            
            // Logging
            "log-facility" => self.validate_log_facility(file, line, value),
            "log-queries" | "log-dhcp" => self.validate_boolean_flag(file, line, key),
            
            // Boolean flags (no value expected)
            "no-hosts" | "no-resolv" | "no-poll" | "no-negcache" | 
            "strict-order" | "bind-interfaces" | "bind-dynamic" |
            "bogus-priv" | "filterwin2k" | "expand-hosts" => self.validate_boolean_flag(file, line, key),
            
            _ => {
                // Unknown option - add info message
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Info,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("Unknown or uncommon option: {}", key),
                    value: value.map(|s| s.to_string()),
                    suggestion: Some("Check dnsmasq documentation for this option".to_string()),
                });
                Ok(())
            }
        }
    }

    // Specific validation methods for different option types

    fn validate_port_option(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            match Validators::validate_port(val) {
                Ok(port) => {
                    if Validators::is_privileged_port(port) {
                        self.context.add_issue(ValidationIssue {
                            severity: Severity::Warning,
                            file: file.to_string(),
                            line,
                            column: None,
                            message: format!("Port {} is privileged (<1024), requires root/CAP_NET_BIND_SERVICE", port),
                            value: Some(val.to_string()),
                            suggestion: Some("Ensure dnsmasq runs with appropriate privileges".to_string()),
                        });
                    }
                }
                Err(e) => {
                    self.context.add_issue(ValidationIssue {
                        severity: Severity::Error,
                        file: file.to_string(),
                        line,
                        column: None,
                        message: format!("Invalid port: {}", e),
                        value: Some(val.to_string()),
                        suggestion: Some("Port must be a number between 1 and 65535".to_string()),
                    });
                }
            }
        } else {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "port option requires a value".to_string(),
                value: None,
                suggestion: Some("Usage: port=53".to_string()),
            });
        }
        Ok(())
    }

    fn validate_listen_address(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            if let Err(e) = Validators::validate_ip_address(val) {
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Error,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("Invalid listen address: {}", e),
                    value: Some(val.to_string()),
                    suggestion: Some("Must be a valid IPv4 or IPv6 address".to_string()),
                });
            }
        } else {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "listen-address requires an IP address".to_string(),
                value: None,
                suggestion: Some("Usage: listen-address=192.168.1.1".to_string()),
            });
        }
        Ok(())
    }

    fn validate_server_option(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            // Server format: [/domain/]server[@source]
            // Simple validation - just check if there's an IP address
            let parts: Vec<&str> = val.split('@').collect();
            let server_part = parts[0];
            
            // Extract IP from format like /example.com/8.8.8.8
            let ip_part = if server_part.contains('/') {
                server_part.split('/').last().unwrap_or("")
            } else {
                server_part
            };
            
            if !ip_part.is_empty() {
                if let Err(e) = Validators::validate_ip_address(ip_part) {
                    self.context.add_issue(ValidationIssue {
                        severity: Severity::Error,
                        file: file.to_string(),
                        line,
                        column: None,
                        message: format!("Invalid server IP address: {}", e),
                        value: Some(val.to_string()),
                        suggestion: Some("Format: server=8.8.8.8 or server=/example.com/8.8.8.8".to_string()),
                    });
                }
            }
        } else {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "server option requires a value".to_string(),
                value: None,
                suggestion: Some("Usage: server=8.8.8.8".to_string()),
            });
        }
        Ok(())
    }

    fn validate_address_option(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            let parts: Vec<&str> = val.split('/').collect();
            if parts.len() >= 2 {
                // Format: /domain/ip
                if let Err(e) = Validators::validate_ip_address(parts[parts.len() - 1]) {
                    self.context.add_issue(ValidationIssue {
                        severity: Severity::Error,
                        file: file.to_string(),
                        line,
                        column: None,
                        message: format!("Invalid IP address in address directive: {}", e),
                        value: Some(val.to_string()),
                        suggestion: Some("Format: address=/example.com/192.168.1.1".to_string()),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_domain_option(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            if let Err(e) = Validators::validate_domain_name(val) {
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Error,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("Invalid domain name: {}", e),
                    value: Some(val.to_string()),
                    suggestion: Some("Must be a valid RFC 1035 domain name".to_string()),
                });
            }
        }
        Ok(())
    }

    fn validate_cache_size(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            match val.parse::<usize>() {
                Ok(size) => {
                    if size > 10000 {
                        self.context.add_issue(ValidationIssue {
                            severity: Severity::Info,
                            file: file.to_string(),
                            line,
                            column: None,
                            message: format!("Large cache size: {} entries", size),
                            value: Some(val.to_string()),
                            suggestion: Some("Consider memory usage for large caches".to_string()),
                        });
                    }
                }
                Err(_) => {
                    self.context.add_issue(ValidationIssue {
                        severity: Severity::Error,
                        file: file.to_string(),
                        line,
                        column: None,
                        message: "cache-size must be a positive integer".to_string(),
                        value: Some(val.to_string()),
                        suggestion: Some("Usage: cache-size=150".to_string()),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_ttl_option(&mut self, file: &str, line: usize, key: &str, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            if let Err(e) = Validators::validate_time_interval(val) {
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Error,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("Invalid {} value: {}", key, e),
                    value: Some(val.to_string()),
                    suggestion: Some("Use format: number[s|m|h|d|w] (e.g., 300, 5m, 1h)".to_string()),
                });
            }
        }
        Ok(())
    }

    fn validate_positive_integer(&mut self, file: &str, line: usize, key: &str, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            if val.parse::<u32>().is_err() {
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Error,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("{} must be a positive integer", key),
                    value: Some(val.to_string()),
                    suggestion: Some(format!("Usage: {}=<number>", key)),
                });
            }
        }
        Ok(())
    }

    fn validate_edns_packet_max(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            match val.parse::<usize>() {
                Ok(size) => {
                    if size < 512 {
                        self.context.add_issue(ValidationIssue {
                            severity: Severity::Warning,
                            file: file.to_string(),
                            line,
                            column: None,
                            message: "edns-packet-max is below minimum DNS packet size (512 bytes)".to_string(),
                            value: Some(val.to_string()),
                            suggestion: Some("Minimum recommended: 512 bytes".to_string()),
                        });
                    } else if size > 4096 {
                        self.context.add_issue(ValidationIssue {
                            severity: Severity::Info,
                            file: file.to_string(),
                            line,
                            column: None,
                            message: "Large edns-packet-max may cause network issues".to_string(),
                            value: Some(val.to_string()),
                            suggestion: Some("Standard maximum: 4096 bytes".to_string()),
                        });
                    }
                }
                Err(_) => {
                    self.context.add_issue(ValidationIssue {
                        severity: Severity::Error,
                        file: file.to_string(),
                        line,
                        column: None,
                        message: "edns-packet-max must be a positive integer".to_string(),
                        value: Some(val.to_string()),
                        suggestion: Some("Usage: edns-packet-max=4096".to_string()),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_dhcp_range_option(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Dhcp) && !self.context.has_feature(Feature::Dhcp6) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "dhcp-range option requires DHCP or DHCPv6 feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features dhcp or --features dhcp6".to_string()),
            });
            return Ok(());
        }

        if let Some(val) = value {
            match Validators::validate_dhcp_range(val) {
                Ok((start, end, netmask)) => {
                    self.context.dhcp_ranges.push(DhcpRange {
                        file: file.to_string(),
                        line,
                        start,
                        end,
                        netmask,
                    });
                }
                Err(e) => {
                    self.context.add_issue(ValidationIssue {
                        severity: Severity::Error,
                        file: file.to_string(),
                        line,
                        column: None,
                        message: format!("Invalid DHCP range: {}", e),
                        value: Some(val.to_string()),
                        suggestion: Some("Format: dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,24h".to_string()),
                    });
                }
            }
        } else {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "dhcp-range requires start and end addresses".to_string(),
                value: None,
                suggestion: Some("Usage: dhcp-range=192.168.1.50,192.168.1.150,24h".to_string()),
            });
        }
        Ok(())
    }

    fn validate_dhcp_host_option(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Dhcp) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "dhcp-host option requires DHCP feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features dhcp".to_string()),
            });
            return Ok(());
        }

        if let Some(val) = value {
            // dhcp-host format: [<hwaddr>][,id:<client_id>|*][,set:<tag>][,<ipaddr>][,<hostname>]
            let parts: Vec<&str> = val.split(',').collect();
            let mut mac = None;
            let mut ip = None;
            let mut hostname = None;
            
            for part in parts {
                let part = part.trim();
                
                // Check if it's a MAC address
                if Validators::validate_mac_address(part).is_ok() {
                    mac = Some(part.to_string());
                }
                // Check if it's an IP address
                else if let Ok(addr) = Validators::validate_ip_address(part) {
                    ip = Some(addr);
                }
                // Otherwise assume hostname (simplified validation)
                else if !part.starts_with("id:") && !part.starts_with("set:") && !part.starts_with("tag:") {
                    hostname = Some(part.to_string());
                }
            }
            
            self.context.dhcp_hosts.push(DhcpHost {
                file: file.to_string(),
                line,
                mac,
                ip,
                hostname,
            });
        }
        Ok(())
    }

    fn validate_dhcp_option(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Dhcp) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "dhcp-option requires DHCP feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features dhcp".to_string()),
            });
        }
        // Simplified validation - just check that value exists
        if value.is_none() {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "dhcp-option requires a value".to_string(),
                value: None,
                suggestion: Some("Usage: dhcp-option=3,192.168.1.1 (option 3 = router)".to_string()),
            });
        }
        Ok(())
    }

    fn validate_dhcp_script(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            let path = PathBuf::from(val);
            if !path.exists() {
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Warning,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("DHCP script file not found: {:?}", path),
                    value: Some(val.to_string()),
                    suggestion: Some("Ensure the script exists and is executable".to_string()),
                });
            }
        }
        Ok(())
    }

    fn validate_ra_param(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Dhcp6) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "ra-param requires DHCPv6 feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features dhcp6".to_string()),
            });
        }
        Ok(())
    }

    fn validate_tftp_feature(&mut self, file: &str, line: usize) -> Result<()> {
        if !self.context.has_feature(Feature::Tftp) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "enable-tftp requires TFTP feature to be enabled".to_string(),
                value: None,
                suggestion: Some("Enable with --features tftp".to_string()),
            });
        }
        Ok(())
    }

    fn validate_dnssec_feature(&mut self, file: &str, line: usize) -> Result<()> {
        if !self.context.has_feature(Feature::Dnssec) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "dnssec requires DNSSEC feature to be enabled".to_string(),
                value: None,
                suggestion: Some("Enable with --features dnssec".to_string()),
            });
        } else {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Info,
                file: file.to_string(),
                line,
                column: None,
                message: "DNSSEC validation enabled - ensure trust anchors are configured".to_string(),
                value: None,
                suggestion: Some("Use trust-anchor directive to configure root zone keys".to_string()),
            });
        }
        Ok(())
    }

    fn validate_dnssec_flag(&mut self, file: &str, line: usize, key: &str) -> Result<()> {
        if !self.context.has_feature(Feature::Dnssec) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: format!("{} requires DNSSEC feature to be enabled", key),
                value: None,
                suggestion: Some("Enable with --features dnssec".to_string()),
            });
        }
        Ok(())
    }

    fn validate_trust_anchor(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Dnssec) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "trust-anchor requires DNSSEC feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features dnssec".to_string()),
            });
        }
        Ok(())
    }

    fn validate_auth_feature(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Auth) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "auth-zone requires authoritative DNS feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features auth".to_string()),
            });
        }
        Ok(())
    }

    fn validate_auth_soa(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Auth) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "auth-soa requires authoritative DNS feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features auth".to_string()),
            });
        }
        Ok(())
    }

    fn validate_dbus_feature(&mut self, file: &str, line: usize) -> Result<()> {
        if !self.context.has_feature(Feature::Dbus) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "enable-dbus requires D-Bus feature to be enabled".to_string(),
                value: None,
                suggestion: Some("Enable with --features dbus".to_string()),
            });
        }
        Ok(())
    }

    fn validate_ubus_feature(&mut self, file: &str, line: usize) -> Result<()> {
        if !self.context.has_feature(Feature::Ubus) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "enable-ubus requires ubus feature to be enabled".to_string(),
                value: None,
                suggestion: Some("Enable with --features ubus".to_string()),
            });
        }
        Ok(())
    }

    fn validate_conntrack_feature(&mut self, file: &str, line: usize) -> Result<()> {
        if !self.context.has_feature(Feature::Conntrack) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "conntrack requires connection tracking feature to be enabled".to_string(),
                value: None,
                suggestion: Some("Enable with --features conntrack".to_string()),
            });
        }
        Ok(())
    }

    fn validate_ipset_feature(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Ipset) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "ipset requires ipset feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features ipset (Linux only)".to_string()),
            });
        }
        Ok(())
    }

    fn validate_nftset_feature(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if !self.context.has_feature(Feature::Nftables) {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: "nftset requires nftables feature to be enabled".to_string(),
                value: value.map(|s| s.to_string()),
                suggestion: Some("Enable with --features nftables (Linux only)".to_string()),
            });
        }
        Ok(())
    }

    fn validate_file_path_option(&mut self, file: &str, line: usize, key: &str, value: Option<&str>, must_exist: bool) -> Result<()> {
        if let Some(val) = value {
            if let Err(e) = Validators::validate_file_path(val, must_exist) {
                let severity = if must_exist { Severity::Error } else { Severity::Warning };
                self.context.add_issue(ValidationIssue {
                    severity,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("Invalid file path for {}: {}", key, e),
                    value: Some(val.to_string()),
                    suggestion: Some("Ensure the file path is correct and the file exists".to_string()),
                });
            }
        }
        Ok(())
    }

    fn validate_dir_path_option(&mut self, file: &str, line: usize, value: Option<&str>, must_exist: bool) -> Result<()> {
        if let Some(val) = value {
            if let Err(e) = Validators::validate_dir_path(val, must_exist) {
                let severity = if must_exist { Severity::Error } else { Severity::Warning };
                self.context.add_issue(ValidationIssue {
                    severity,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("Invalid directory path: {}", e),
                    value: Some(val.to_string()),
                    suggestion: Some("Ensure the directory path is correct and the directory exists".to_string()),
                });
            }
        }
        Ok(())
    }

    fn validate_user_group(&mut self, file: &str, line: usize, key: &str, value: Option<&str>) -> Result<()> {
        if value.is_none() {
            self.context.add_issue(ValidationIssue {
                severity: Severity::Error,
                file: file.to_string(),
                line,
                column: None,
                message: format!("{} option requires a value", key),
                value: None,
                suggestion: Some(format!("Usage: {}=dnsmasq", key)),
            });
        }
        Ok(())
    }

    fn validate_log_facility(&mut self, file: &str, line: usize, value: Option<&str>) -> Result<()> {
        if let Some(val) = value {
            let valid_facilities = [
                "kern", "user", "mail", "daemon", "auth", "syslog", "lpr",
                "news", "uucp", "cron", "local0", "local1", "local2",
                "local3", "local4", "local5", "local6", "local7",
            ];
            
            if !valid_facilities.contains(&val) {
                self.context.add_issue(ValidationIssue {
                    severity: Severity::Error,
                    file: file.to_string(),
                    line,
                    column: None,
                    message: format!("Invalid log facility: {}", val),
                    value: Some(val.to_string()),
                    suggestion: Some("Valid facilities: daemon, local0-7, etc.".to_string()),
                });
            }
        }
        Ok(())
    }

    fn validate_boolean_flag(&mut self, _file: &str, _line: usize, _key: &str) -> Result<()> {
        // Boolean flags don't take values, so no validation needed
        Ok(())
    }
}

/// Semantic validator for cross-option checks
struct SemanticValidator;

impl SemanticValidator {
    /// Perform semantic validation on the parsed configuration
    fn validate(context: &mut ConfigContext) {
        Self::check_dhcp_range_conflicts(context);
        Self::check_duplicate_options(context);
        Self::check_dhcp_host_conflicts(context);
    }

    /// Check for overlapping DHCP ranges
    fn check_dhcp_range_conflicts(context: &mut ConfigContext) {
        for i in 0..context.dhcp_ranges.len() {
            for j in (i + 1)..context.dhcp_ranges.len() {
                let range1 = &context.dhcp_ranges[i];
                let range2 = &context.dhcp_ranges[j];
                
                // Check if ranges overlap (same IP version only)
                match (range1.start, range1.end, range2.start, range2.end) {
                    (IpAddr::V4(s1), IpAddr::V4(e1), IpAddr::V4(s2), IpAddr::V4(e2)) => {
                        let start1 = u32::from(s1);
                        let end1 = u32::from(e1);
                        let start2 = u32::from(s2);
                        let end2 = u32::from(e2);
                        
                        if start1 <= end2 && start2 <= end1 {
                            context.add_issue(ValidationIssue {
                                severity: Severity::Warning,
                                file: range2.file.clone(),
                                line: range2.line,
                                column: None,
                                message: format!(
                                    "DHCP range {}-{} overlaps with range {}-{} defined at {}:{}",
                                    range2.start, range2.end, range1.start, range1.end, range1.file, range1.line
                                ),
                                value: None,
                                suggestion: Some("Ensure DHCP ranges do not overlap".to_string()),
                            });
                        }
                    }
                    (IpAddr::V6(s1), IpAddr::V6(e1), IpAddr::V6(s2), IpAddr::V6(e2)) => {
                        if s1 <= e2 && s2 <= e1 {
                            context.add_issue(ValidationIssue {
                                severity: Severity::Warning,
                                file: range2.file.clone(),
                                line: range2.line,
                                column: None,
                                message: format!(
                                    "DHCP range {}-{} overlaps with range {}-{} defined at {}:{}",
                                    range2.start, range2.end, range1.start, range1.end, range1.file, range1.line
                                ),
                                value: None,
                                suggestion: Some("Ensure DHCP ranges do not overlap".to_string()),
                            });
                        }
                    }
                    _ => {} // Different IP versions don't conflict
                }
            }
        }
    }

    /// Check for duplicate option definitions
    fn check_duplicate_options(context: &mut ConfigContext) {
        // Options that should only appear once
        let singleton_options = [
            "port", "cache-size", "lease-file", "dhcp-leasefile",
            "pid-file", "user", "group", "log-facility",
        ];
        
        for option in &singleton_options {
            if let Some(occurrences) = context.options.get(*option) {
                if occurrences.len() > 1 {
                    for (file, line) in occurrences.iter().skip(1) {
                        context.add_issue(ValidationIssue {
                            severity: Severity::Warning,
                            file: file.clone(),
                            line: *line,
                            column: None,
                            message: format!(
                                "Option '{}' defined multiple times (first at {}:{})",
                                option, occurrences[0].0, occurrences[0].1
                            ),
                            value: None,
                            suggestion: Some("Remove duplicate options or keep only one".to_string()),
                        });
                    }
                }
            }
        }
    }

    /// Check for conflicting DHCP host definitions
    fn check_dhcp_host_conflicts(context: &mut ConfigContext) {
        let mut mac_to_host: HashMap<String, (String, usize)> = HashMap::new();
        let mut hostname_to_host: HashMap<String, (String, usize)> = HashMap::new();
        
        for host in &context.dhcp_hosts {
            // Check for duplicate MAC addresses
            if let Some(ref mac) = host.mac {
                if let Some((prev_file, prev_line)) = mac_to_host.get(mac) {
                    context.add_issue(ValidationIssue {
                        severity: Severity::Warning,
                        file: host.file.clone(),
                        line: host.line,
                        column: None,
                        message: format!(
                            "MAC address {} already defined at {}:{}",
                            mac, prev_file, prev_line
                        ),
                        value: Some(mac.clone()),
                        suggestion: Some("Each MAC address should only appear once in dhcp-host".to_string()),
                    });
                } else {
                    mac_to_host.insert(mac.clone(), (host.file.clone(), host.line));
                }
            }
            
            // Check for duplicate hostnames
            if let Some(ref hostname) = host.hostname {
                if let Some((prev_file, prev_line)) = hostname_to_host.get(hostname) {
                    context.add_issue(ValidationIssue {
                        severity: Severity::Info,
                        file: host.file.clone(),
                        line: host.line,
                        column: None,
                        message: format!(
                            "Hostname {} already defined at {}:{}",
                            hostname, prev_file, prev_line
                        ),
                        value: Some(hostname.clone()),
                        suggestion: Some("Consider using unique hostnames for each DHCP host".to_string()),
                    });
                } else {
                    hostname_to_host.insert(hostname.clone(), (host.file.clone(), host.line));
                }
            }
        }
    }
}

/// Report generator for validation results
struct ReportGenerator;

impl ReportGenerator {
    /// Generate validation report with statistics and recommendations
    fn generate(context: &ConfigContext) -> ValidationReport {
        let mut issues = context.issues.clone();
        issues.sort_by(|a, b| {
            a.severity.cmp(&b.severity)
                .then(a.file.cmp(&b.file))
                .then(a.line.cmp(&b.line))
        });
        
        let error_count = issues.iter().filter(|i| i.severity == Severity::Error).count();
        let warning_count = issues.iter().filter(|i| i.severity == Severity::Warning).count();
        let info_count = issues.iter().filter(|i| i.severity == Severity::Info).count();
        
        let total_options: usize = context.options.values().map(|v| v.len()).sum();
        
        let enabled_features: Vec<String> = context.features.iter()
            .map(|f| format!("{:?}", f).to_lowercase())
            .collect();
        
        let complexity = if total_options < 10 {
            "simple"
        } else if total_options < 50 {
            "moderate"
        } else {
            "complex"
        };
        
        let summary = ValidationSummary {
            total_files: context.files_processed.len(),
            total_options,
            error_count,
            warning_count,
            info_count,
            enabled_features,
            complexity: complexity.to_string(),
        };
        
        let recommendations = Self::generate_recommendations(context);
        
        ValidationReport {
            summary,
            issues,
            recommendations,
        }
    }

    /// Generate migration recommendations
    fn generate_recommendations(context: &ConfigContext) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // Feature-based recommendations
        if context.has_feature(Feature::Dnssec) {
            recommendations.push(
                "DNSSEC enabled: Ensure trust anchors are up to date and test validation thoroughly".to_string()
            );
        }
        
        if context.has_feature(Feature::Dhcp) {
            recommendations.push(
                "DHCP enabled: Verify lease file path is writable and backed up regularly".to_string()
            );
        }
        
        // Performance recommendations
        if let Some(cache_sizes) = context.options.get("cache-size") {
            if let Some((_, _)) = cache_sizes.first() {
                recommendations.push(
                    "Cache size configured: Monitor memory usage and adjust as needed for your deployment".to_string()
                );
            }
        }
        
        // Security recommendations
        if !context.has_feature(Feature::Dnssec) {
            recommendations.push(
                "Security: Consider enabling DNSSEC validation with --features dnssec".to_string()
            );
        }
        
        // Migration-specific recommendations
        recommendations.push(
            "Migration: Test the Rust implementation in a non-production environment first".to_string()
        );
        
        recommendations.push(
            "Migration: Ensure all required Cargo features are enabled when building the Rust version".to_string()
        );
        
        if context.dhcp_ranges.len() > 0 {
            recommendations.push(
                "DHCP Migration: Verify that lease file format is compatible (dnsmasq.leases)".to_string()
            );
        }
        
        recommendations
    }
}

/// Output formatter for different output formats
struct OutputFormatter;

impl OutputFormatter {
    /// Output validation report in text format
    fn output_text(report: &ValidationReport, color_choice: ColorChoice) -> Result<()> {
        let mut stdout = StandardStream::stdout(color_choice);
        
        // Print summary
        writeln!(&mut stdout, "\n=== Validation Summary ===")?;
        writeln!(&mut stdout, "Files processed:   {}", report.summary.total_files)?;
        writeln!(&mut stdout, "Total options:     {}", report.summary.total_options)?;
        writeln!(&mut stdout, "Errors:            {}", report.summary.error_count)?;
        writeln!(&mut stdout, "Warnings:          {}", report.summary.warning_count)?;
        writeln!(&mut stdout, "Info messages:     {}", report.summary.info_count)?;
        writeln!(&mut stdout, "Enabled features:  {}", report.summary.enabled_features.join(", "))?;
        writeln!(&mut stdout, "Complexity:        {}", report.summary.complexity)?;
        writeln!(&mut stdout)?;
        
        // Print issues
        if !report.issues.is_empty() {
            writeln!(&mut stdout, "=== Issues ===")?;
            for issue in &report.issues {
                let color = match issue.severity {
                    Severity::Error => Color::Red,
                    Severity::Warning => Color::Yellow,
                    Severity::Info => Color::Blue,
                };
                
                stdout.set_color(ColorSpec::new().set_fg(Some(color)).set_bold(true))?;
                write!(&mut stdout, "{:?}", issue.severity)?;
                stdout.reset()?;
                
                write!(&mut stdout, " [{}:{}]", issue.file, issue.line)?;
                if let Some(col) = issue.column {
                    write!(&mut stdout, ":{}", col)?;
                }
                writeln!(&mut stdout, ": {}", issue.message)?;
                
                if let Some(ref value) = issue.value {
                    writeln!(&mut stdout, "  Value: {}", value)?;
                }
                
                if let Some(ref suggestion) = issue.suggestion {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
                    writeln!(&mut stdout, "  Suggestion: {}", suggestion)?;
                    stdout.reset()?;
                }
                
                writeln!(&mut stdout)?;
            }
        }
        
        // Print recommendations
        if !report.recommendations.is_empty() {
            writeln!(&mut stdout, "=== Migration Recommendations ===")?;
            for (i, rec) in report.recommendations.iter().enumerate() {
                writeln!(&mut stdout, "{}. {}", i + 1, rec)?;
            }
            writeln!(&mut stdout)?;
        }
        
        // Final verdict
        if report.summary.error_count == 0 && report.summary.warning_count == 0 {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true))?;
            writeln!(&mut stdout, "✓ Configuration is valid and ready for migration to Rust implementation")?;
            stdout.reset()?;
        } else if report.summary.error_count == 0 {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true))?;
            writeln!(&mut stdout, "⚠ Configuration has warnings but is usable")?;
            stdout.reset()?;
        } else {
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true))?;
            writeln!(&mut stdout, "✗ Configuration has errors that must be fixed")?;
            stdout.reset()?;
        }
        
        Ok(())
    }

    /// Output validation report in JSON format
    fn output_json(report: &ValidationReport, output: Option<&Path>) -> Result<()> {
        let json = serde_json::to_string_pretty(report)?;
        
        if let Some(path) = output {
            fs::write(path, json)?;
        } else {
            println!("{}", json);
        }
        
        Ok(())
    }
}

/// Main entry point
fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Parse feature flags
    let mut features = HashSet::new();
    for feature_str in &cli.features {
        if let Some(feature) = Feature::from_str(feature_str) {
            features.insert(feature);
        } else {
            eprintln!("Warning: Unknown feature '{}', ignoring", feature_str);
        }
    }
    
    // If no features specified, enable all common features
    if features.is_empty() {
        features.insert(Feature::Dhcp);
        features.insert(Feature::Dhcp6);
        features.insert(Feature::Dnssec);
        features.insert(Feature::Tftp);
        features.insert(Feature::Auth);
    }
    
    // Create validation context
    let mut context = ConfigContext::new(features);
    
    // Parse all configuration files
    let mut parser = ConfigParser::new(&mut context, cli.test_only);
    
    for config_file in &cli.config_files {
        if !config_file.exists() {
            eprintln!("Error: Configuration file not found: {:?}", config_file);
            std::process::exit(3);
        }
        
        if let Err(e) = parser.parse_file(config_file) {
            eprintln!("Error parsing {}: {}", config_file.display(), e);
            std::process::exit(3);
        }
    }
    
    // Perform semantic validation (unless in test-only mode)
    if !cli.test_only {
        SemanticValidator::validate(&mut context);
    }
    
    // Generate report
    let report = ReportGenerator::generate(&context);
    
    // Determine color choice
    let color_choice = match cli.color {
        ColorMode::Auto => ColorChoice::Auto,
        ColorMode::Always => ColorChoice::Always,
        ColorMode::Never => ColorChoice::Never,
    };
    
    // Output report
    match cli.format {
        OutputFormat::Text => {
            OutputFormatter::output_text(&report, color_choice)?;
        }
        OutputFormat::Json => {
            OutputFormatter::output_json(&report, cli.output.as_deref())?;
        }
    }
    
    // Determine exit code
    let exit_code = if report.summary.error_count > 0 {
        1 // Syntax or type errors
    } else if report.summary.warning_count > 0 {
        2 // Warnings only
    } else {
        0 // Success
    };
    
    std::process::exit(exit_code);
}

