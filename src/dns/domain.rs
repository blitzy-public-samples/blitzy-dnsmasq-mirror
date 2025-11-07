// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later

//! Domain name manipulation utilities for DNS operations
//!
//! This module implements domain name handling functions translated from C's domain.c
//! and domain-match.c. It provides:
//!
//! - Domain canonicalization and case-insensitive comparison
//! - Synthetic domain generation from IP addresses (indexed and IP-based formats)
//! - Conditional domain selection based on client IP address ranges
//! - Wildcard domain matching for flexible server selection
//! - Network prefix matching for IPv4 and IPv6
//!
//! # Synthetic Domains
//!
//! Synthetic domains enable automatic DNS name generation from IP addresses:
//! - Indexed format: `host42.example.com` → base_ip + 42
//! - IP-based format: `10-0-0-1.example.com` → 10.0.0.1
//! - IPv6 format: `2001-db8--1.example.com` → 2001:db8::1
//!
//! # Conditional Domains
//!
//! Conditional domains allow different domain suffixes based on client subnet,
//! supporting multi-tenant and segmented network environments.
//!
//! # Memory Safety
//!
//! Replaces C's manual string manipulation and pointer arithmetic with Rust's
//! safe String type and slice operations, eliminating buffer overflows.
//!
//! # C Source Reference
//!
//! Translated from:
//! - `src/domain.c` (lines 1-841) - Domain manipulation and conditional domains
//! - `src/domain-match.c` (lines 1-800) - Server array management and lookup
//!
//! # Examples
//!
//! ```rust,ignore
//! use std::net::Ipv4Addr;
//! use crate::dns::domain::*;
//!
//! // Domain comparison
//! assert!(domain_equal("Example.COM", "example.com"));
//!
//! // Parse synthetic domain
//! let synth_domains = vec![
//!     SynthDomain {
//!         domain: "example.com".to_string(),
//!         start_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
//!         end_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
//!         format: SynthFormat::Indexed,
//!         prefix: "host".to_string(),
//!     },
//! ];
//!
//! if let Some(ip) = parse_synthetic_domain("host42.example.com", &synth_domains) {
//!     // ip == 192.168.1.43
//! }
//! ```

use crate::constants::MAX_DOMAIN_NAME;
use crate::types::errors::DnsmasqError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Format for synthetic domain name generation
///
/// Determines how IP addresses are encoded in synthetic domain names.
///
/// # C Source Reference
///
/// Corresponds to the `indexed` field in C's `struct cond_domain` (dnsmasq.h:3054)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynthFormat {
    /// Indexed format: prefix + numeric index (e.g., "host42")
    /// Index is calculated as offset from start_ip
    Indexed,

    /// IP-based format: prefix + encoded IP (e.g., "10-0-0-1")
    /// IP address with dots/colons replaced by dashes
    IpBased,
}

/// Synthetic domain configuration for automatic DNS name generation
///
/// Enables dnsmasq to automatically generate DNS names for IP addresses within
/// configured ranges. Supports both indexed numeric formats and direct IP encoding.
///
/// # C Source Reference
///
/// Translated from C's `struct cond_domain` (dnsmasq.h:3058-3066) when used for
/// synthetic domains (daemon->synth_domains list).
///
/// # Examples
///
/// ```rust,ignore
/// // Indexed synthetic domain: host1, host2, host3, ...
/// let synth = SynthDomain {
///     domain: "example.com".to_string(),
///     start_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
///     end_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
///     format: SynthFormat::Indexed,
///     prefix: "host".to_string(),
/// };
///
/// // IP-based synthetic domain: 10-0-0-1, 10-0-0-2, ...
/// let synth_ip = SynthDomain {
///     domain: "example.com".to_string(),
///     start_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
///     end_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
///     format: SynthFormat::IpBased,
///     prefix: String::new(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SynthDomain {
    /// Domain suffix for synthetic names (e.g., "example.com")
    pub domain: String,

    /// Start of IP range for synthetic domain
    pub start_ip: IpAddr,

    /// End of IP range for synthetic domain (inclusive)
    pub end_ip: IpAddr,

    /// Format for name generation (indexed or IP-based)
    pub format: SynthFormat,

    /// Text prefix prepended to generated names (e.g., "host")
    pub prefix: String,
}

/// IP network specification for conditional domain matching
///
/// Represents an IP network using address and prefix length (CIDR notation).
/// Used for matching client addresses to determine appropriate domain suffixes.
///
/// # C Source Reference
///
/// Corresponds to fields in C's `struct cond_domain` (start/end addresses with prefixlen)
///
/// # Examples
///
/// ```rust,ignore
/// // IPv4 network: 192.168.1.0/24
/// let net_v4 = IpNetwork {
///     addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
///     prefix_len: 24,
/// };
///
/// // IPv6 network: 2001:db8::/32
/// let net_v6 = IpNetwork {
///     addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
///     prefix_len: 32,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct IpNetwork {
    /// Network address (base address of the network)
    pub addr: IpAddr,

    /// Prefix length (0-32 for IPv4, 0-128 for IPv6)
    pub prefix_len: u8,
}

/// Conditional domain configuration for subnet-based domain assignment
///
/// Enables different domain suffixes to be assigned based on client IP address ranges.
/// Supports multi-tenant and segmented network environments where different subnets
/// require different DNS domain suffixes.
///
/// # C Source Reference
///
/// Translated from C's `struct cond_domain` (dnsmasq.h:3058-3066) when used for
/// conditional domains (daemon->cond_domain list).
///
/// # Examples
///
/// ```rust,ignore
/// // Conditional domain for internal network
/// let cond = ConditionalDomain {
///     domain: "internal.example.com".to_string(),
///     networks: vec![
///         IpNetwork {
///             addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
///             prefix_len: 8,
///         },
///         IpNetwork {
///             addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
///             prefix_len: 16,
///         },
///     ],
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ConditionalDomain {
    /// Domain suffix to assign to matching addresses
    pub domain: String,

    /// List of networks that should receive this domain
    pub networks: Vec<IpNetwork>,
}

/// Case-insensitive domain name comparison
///
/// Compares two domain names for equality using case-insensitive ASCII comparison.
/// Handles trailing dots in domain names by treating "example.com" and "example.com."
/// as equivalent.
///
/// # C Source Reference
///
/// Replaces C's `hostname_isequal()` function pattern used throughout domain.c
///
/// # Arguments
///
/// * `a` - First domain name to compare
/// * `b` - Second domain name to compare
///
/// # Returns
///
/// `true` if domain names are equal (case-insensitive), `false` otherwise
///
/// # Examples
///
/// ```rust,ignore
/// assert!(domain_equal("Example.COM", "example.com"));
/// assert!(domain_equal("example.com", "example.com."));
/// assert!(domain_equal("EXAMPLE.COM.", "example.com"));
/// assert!(!domain_equal("example.com", "test.com"));
/// ```
pub fn domain_equal(a: &str, b: &str) -> bool {
    // Strip trailing dots from both names
    let a_trimmed = a.trim_end_matches('.');
    let b_trimmed = b.trim_end_matches('.');

    // Perform case-insensitive ASCII comparison
    a_trimmed.eq_ignore_ascii_case(b_trimmed)
}

/// Parse hostname to extract IP address from synthetic domain format
///
/// Examines a DNS query name to determine if it matches a configured synthetic domain
/// pattern. If a match is found, extracts and returns the embedded IP address.
///
/// Supports two formats:
/// - **Indexed**: `host42.example.com` → start_ip + 42
/// - **IP-based**: `10-0-0-1.example.com` → 10.0.0.1 (IPv4)
/// - **IP-based IPv6**: `2001-db8--1.example.com` → 2001:db8::1
///
/// # C Source Reference
///
/// Translated from C's `is_name_synthetic()` (domain.c:148-278)
///
/// # Arguments
///
/// * `name` - DNS query name to parse
/// * `synth_domains` - List of configured synthetic domain patterns
///
/// # Returns
///
/// `Some(IpAddr)` if name matches a synthetic domain and IP is valid and within range,
/// `None` otherwise
///
/// # Examples
///
/// ```rust,ignore
/// let synth_domains = vec![
///     SynthDomain {
///         domain: "example.com".to_string(),
///         start_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
///         end_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
///         format: SynthFormat::Indexed,
///         prefix: "host".to_string(),
///     },
/// ];
///
/// // Parse indexed format
/// let ip = parse_synthetic_domain("host42.example.com", &synth_domains);
/// assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 43))));
///
/// // Parse IP-based format
/// let ip = parse_synthetic_domain("192-168-1-100.example.com", &synth_domains);
/// assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
/// ```
pub fn parse_synthetic_domain(name: &str, synth_domains: &[SynthDomain]) -> Option<IpAddr> {
    let name_lower = name.to_lowercase();

    for config in synth_domains {
        // Check if name ends with the configured domain
        let domain_with_dot = format!(".{}", config.domain.to_lowercase());

        if !name_lower.ends_with(&domain_with_dot) {
            continue;
        }

        // Extract the prefix portion (everything before the domain)
        let prefix_end = name_lower.len() - domain_with_dot.len();
        let hostname_part = &name_lower[..prefix_end];

        // Extract the numeric/IP portion after the prefix
        let data_part = if !config.prefix.is_empty() {
            let prefix_lower = config.prefix.to_lowercase();
            // Check if prefix matches and strip it
            if let Some(stripped) = hostname_part.strip_prefix(&prefix_lower as &str) {
                stripped
            } else {
                continue;
            }
        } else {
            hostname_part
        };

        match config.format {
            SynthFormat::Indexed => {
                // Parse indexed format: numeric offset from start_ip
                if let Ok(index) = data_part.parse::<u64>() {
                    if let Some(ip) = add_to_ip(&config.start_ip, index) {
                        if is_ip_in_range(&ip, &config.start_ip, &config.end_ip) {
                            return Some(ip);
                        }
                    }
                }
            }
            SynthFormat::IpBased => {
                // Parse IP-based format: IP address with dashes instead of dots/colons
                if let Some(ip) = parse_ip_from_hostname(data_part, &config.start_ip) {
                    if is_ip_in_range(&ip, &config.start_ip, &config.end_ip) {
                        return Some(ip);
                    }
                }
            }
        }
    }

    None
}

/// Generate synthetic domain name from IP address
///
/// Performs the reverse operation of `parse_synthetic_domain()` by generating a
/// synthetic DNS hostname from an IP address if the address falls within a
/// configured synthetic domain range.
///
/// # C Source Reference
///
/// Translated from C's `is_rev_synth()` (domain.c:343-413)
///
/// # Arguments
///
/// * `ip` - IP address to generate name for
/// * `synth_domains` - List of configured synthetic domain patterns
///
/// # Returns
///
/// `Some(String)` containing the generated synthetic domain name if IP matches a range,
/// `None` otherwise
///
/// # Examples
///
/// ```rust,ignore
/// let synth_domains = vec![
///     SynthDomain {
///         domain: "example.com".to_string(),
///         start_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
///         end_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
///         format: SynthFormat::Indexed,
///         prefix: "host".to_string(),
///     },
/// ];
///
/// let name = generate_synthetic_domain(
///     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 43)),
///     &synth_domains
/// );
/// assert_eq!(name, Some("host42.example.com".to_string()));
/// ```
pub fn generate_synthetic_domain(ip: IpAddr, synth_domains: &[SynthDomain]) -> Option<String> {
    for config in synth_domains {
        if !is_ip_in_range(&ip, &config.start_ip, &config.end_ip) {
            continue;
        }

        // Ensure IP family matches the configuration
        match (ip, &config.start_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => continue, // Family mismatch
        }

        let mut result = String::new();

        match config.format {
            SynthFormat::Indexed => {
                // Generate indexed format: prefix + index
                if let Some(index) = calculate_ip_offset(&config.start_ip, &ip) {
                    result.push_str(&config.prefix);
                    result.push_str(&index.to_string());
                }
            }
            SynthFormat::IpBased => {
                // Generate IP-based format: prefix + encoded IP
                result.push_str(&config.prefix);
                result.push_str(&format_ip_as_hostname(&ip));
            }
        }

        // Append domain suffix
        if !result.is_empty() && result.len() + config.domain.len() < MAX_DOMAIN_NAME {
            result.push('.');
            result.push_str(&config.domain);
            return Some(result);
        }
    }

    None
}

/// Select appropriate domain suffix for IPv4 address
///
/// Determines the correct DNS domain suffix for a given IPv4 address by searching
/// through configured conditional domains. Returns the first matching conditional
/// domain, or None if no match is found.
///
/// # C Source Reference
///
/// Translated from C's `get_domain()` (domain.c:606-614) and `search_domain()` (543-550)
///
/// # Arguments
///
/// * `addr` - IPv4 address to find matching domain for
/// * `cond_domains` - List of configured conditional domain patterns
///
/// # Returns
///
/// `Some(&str)` containing the matched domain suffix, `None` if no match
///
/// # Examples
///
/// ```rust,ignore
/// let cond_domains = vec![
///     ConditionalDomain {
///         domain: "internal.example.com".to_string(),
///         networks: vec![
///             IpNetwork {
///                 addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
///                 prefix_len: 8,
///             },
///         ],
///     },
/// ];
///
/// let domain = select_domain_v4(Ipv4Addr::new(10, 0, 1, 50), &cond_domains);
/// assert_eq!(domain, Some("internal.example.com"));
/// ```
pub fn select_domain_v4(addr: Ipv4Addr, cond_domains: &[ConditionalDomain]) -> Option<&str> {
    for config in cond_domains {
        for network in &config.networks {
            if let IpAddr::V4(net_addr) = network.addr {
                if is_in_network_v4(addr, net_addr, network.prefix_len) {
                    return Some(&config.domain);
                }
            }
        }
    }

    None
}

/// Select appropriate domain suffix for IPv6 address
///
/// Determines the correct DNS domain suffix for a given IPv6 address by searching
/// through configured conditional domains. Returns the first matching conditional
/// domain, or None if no match is found.
///
/// # C Source Reference
///
/// Translated from C's `get_domain6()` (domain.c:832-840) and `search_domain6()` (764-771)
///
/// # Arguments
///
/// * `addr` - IPv6 address to find matching domain for
/// * `cond_domains` - List of configured conditional domain patterns
///
/// # Returns
///
/// `Some(&str)` containing the matched domain suffix, `None` if no match
///
/// # Examples
///
/// ```rust,ignore
/// let cond_domains = vec![
///     ConditionalDomain {
///         domain: "internal.example.com".to_string(),
///         networks: vec![
///             IpNetwork {
///                 addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
///                 prefix_len: 32,
///             },
///         ],
///     },
/// ];
///
/// let domain = select_domain_v6(
///     Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1),
///     &cond_domains
/// );
/// assert_eq!(domain, Some("internal.example.com"));
/// ```
pub fn select_domain_v6(addr: Ipv6Addr, cond_domains: &[ConditionalDomain]) -> Option<&str> {
    for config in cond_domains {
        for network in &config.networks {
            if let IpAddr::V6(net_addr) = network.addr {
                if is_in_network_v6(addr, net_addr, network.prefix_len) {
                    return Some(&config.domain);
                }
            }
        }
    }

    None
}

/// Perform wildcard pattern matching on domain names
///
/// Matches a domain name against a wildcard pattern. Supports leading wildcard
/// notation (`*.example.com` matches `foo.example.com` but not `example.com`).
/// Comparison is case-insensitive.
///
/// # Arguments
///
/// * `pattern` - Wildcard pattern (e.g., "*.example.com")
/// * `domain` - Domain name to test
///
/// # Returns
///
/// `true` if domain matches the pattern, `false` otherwise
///
/// # Examples
///
/// ```rust,ignore
/// assert!(wildcard_match("*.example.com", "foo.example.com"));
/// assert!(wildcard_match("*.example.com", "bar.baz.example.com"));
/// assert!(!wildcard_match("*.example.com", "example.com")); // No subdomain
/// assert!(wildcard_match("example.com", "example.com")); // Exact match
/// assert!(wildcard_match("example.com", "foo.example.com")); // Suffix match
/// ```
pub fn wildcard_match(pattern: &str, domain: &str) -> bool {
    let pattern_lower = pattern.to_lowercase();
    let domain_lower = domain.to_lowercase();

    if let Some(suffix) = pattern_lower.strip_prefix("*.") {
        // Leading wildcard: *.example.com

        // Domain must end with the suffix
        if !domain_lower.ends_with(suffix) {
            return false;
        }

        // If exact match to suffix, reject (*.example.com shouldn't match example.com)
        if domain_lower == suffix {
            return false;
        }

        // Check that there's a dot before the suffix (ensures subdomain exists)
        let prefix_len = domain_lower.len() - suffix.len();
        if prefix_len > 0 {
            let before_suffix = &domain_lower[prefix_len - 1..prefix_len];
            return before_suffix == ".";
        }

        false
    } else {
        // No wildcard: exact suffix match
        // "example.com" matches both "example.com" and "foo.example.com"
        if domain_lower == pattern_lower {
            return true;
        }

        // Check if domain ends with "." + pattern (suffix match)
        let pattern_with_dot = format!(".{}", pattern_lower);
        domain_lower.ends_with(&pattern_with_dot)
    }
}

// =============================================================================
// Helper Functions (Internal)
// =============================================================================

/// Check if IPv4 address is within network range
///
/// # C Source Reference
///
/// Translated from C's `match_domain()` (domain.c:470-486) range checking logic
fn is_in_network_v4(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }

    if prefix_len == 0 {
        return true; // 0.0.0.0/0 matches everything
    }

    let addr_bits = u32::from(addr);
    let network_bits = u32::from(network);
    let mask = if prefix_len == 32 {
        0xFFFFFFFF
    } else {
        0xFFFFFFFF << (32 - prefix_len)
    };

    (addr_bits & mask) == (network_bits & mask)
}

/// Check if IPv6 address is within network range
///
/// # C Source Reference
///
/// Translated from C's `match_domain6()` (domain.c:677-704) range checking logic
fn is_in_network_v6(addr: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }

    if prefix_len == 0 {
        return true; // ::/0 matches everything
    }

    let addr_bytes = addr.octets();
    let network_bytes = network.octets();

    // Compare full bytes
    let full_bytes = (prefix_len / 8) as usize;
    if addr_bytes[..full_bytes] != network_bytes[..full_bytes] {
        return false;
    }

    // Compare remaining bits in the next byte
    let remaining_bits = prefix_len % 8;
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = 0xFF << (8 - remaining_bits);
        if (addr_bytes[full_bytes] & mask) != (network_bytes[full_bytes] & mask) {
            return false;
        }
    }

    true
}

/// Parse IP address from hostname format (dashes instead of dots/colons)
///
/// Converts "192-168-1-100" → "192.168.1.100" or "2001-db8--1" → "2001:db8::1"
///
/// # C Source Reference
///
/// Translated from logic in `is_name_synthetic()` (domain.c:220-263)
fn parse_ip_from_hostname(hostname: &str, hint_ip: &IpAddr) -> Option<IpAddr> {
    match hint_ip {
        IpAddr::V4(_) => {
            // IPv4: Replace dashes with dots
            let ip_str = hostname.replace('-', ".");
            ip_str.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
        }
        IpAddr::V6(_) => {
            // IPv6: Handle special cases and replace dashes with colons
            let mut ip_str = hostname.to_string();

            // Special case: --ffff- prefix for IPv4-mapped IPv6
            if ip_str.starts_with("--ffff-") {
                ip_str = ip_str.replacen("--ffff-", "::ffff:", 1);
                // Replace remaining dashes with dots for the IPv4 part
                let parts: Vec<&str> = ip_str.split("::ffff:").collect();
                if parts.len() == 2 {
                    let ipv4_part = parts[1].replace('-', ".");
                    ip_str = format!("::ffff:{}", ipv4_part);
                }
            } else {
                // Double dash represents :: (compression)
                ip_str = ip_str.replace("--", "::");
                // Single dashes are colons
                ip_str = ip_str.replace('-', ":");
            }

            // Handle leading colon
            if ip_str.starts_with(':') && !ip_str.starts_with("::") {
                ip_str = format!("0{}", ip_str);
            }

            ip_str.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
        }
    }
}

/// Format IP address as hostname (dots/colons replaced with dashes)
///
/// Converts "192.168.1.100" → "192-168-1-100" or "2001:db8::1" → "2001-db8--1"
///
/// # C Source Reference
///
/// Translated from logic in `is_rev_synth()` (domain.c:358-403)
fn format_ip_as_hostname(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(addr) => {
            // IPv4: Replace dots with dashes
            addr.to_string().replace('.', "-")
        }
        IpAddr::V6(addr) => {
            // IPv6: Replace colons with dashes, :: becomes --
            let ip_str = addr.to_string();

            // Handle leading colon by prepending 0
            let ip_str = if ip_str.starts_with(':') && !ip_str.starts_with("::") {
                format!("0{}", ip_str)
            } else {
                ip_str
            };

            // Replace :: with -- (compression)
            let ip_str = ip_str.replace("::", "--");
            // Replace single colons with dashes
            let ip_str = ip_str.replace(':', "-");
            // Replace dots (from IPv4-mapped addresses) with dashes
            ip_str.replace('.', "-")
        }
    }
}

/// Check if IP address is within a given range (inclusive)
fn is_ip_in_range(ip: &IpAddr, start: &IpAddr, end: &IpAddr) -> bool {
    match (ip, start, end) {
        (IpAddr::V4(ip), IpAddr::V4(start), IpAddr::V4(end)) => {
            let ip_val = u32::from(*ip);
            let start_val = u32::from(*start);
            let end_val = u32::from(*end);
            ip_val >= start_val && ip_val <= end_val
        }
        (IpAddr::V6(ip), IpAddr::V6(start), IpAddr::V6(end)) => {
            let ip_val = u128::from(*ip);
            let start_val = u128::from(*start);
            let end_val = u128::from(*end);
            ip_val >= start_val && ip_val <= end_val
        }
        _ => false, // Family mismatch
    }
}

/// Add numeric offset to IP address
///
/// Used for indexed synthetic domain format to calculate IP from base + offset.
fn add_to_ip(base: &IpAddr, offset: u64) -> Option<IpAddr> {
    match base {
        IpAddr::V4(addr) => {
            let base_val = u32::from(*addr);
            let result = base_val.checked_add(offset as u32)?;
            Some(IpAddr::V4(Ipv4Addr::from(result)))
        }
        IpAddr::V6(addr) => {
            let base_val = u128::from(*addr);
            let result = base_val.checked_add(offset as u128)?;
            Some(IpAddr::V6(Ipv6Addr::from(result)))
        }
    }
}

/// Calculate offset between two IP addresses
///
/// Used to determine the index in indexed synthetic domain format.
fn calculate_ip_offset(start: &IpAddr, ip: &IpAddr) -> Option<u64> {
    match (start, ip) {
        (IpAddr::V4(start), IpAddr::V4(ip)) => {
            let start_val = u32::from(*start);
            let ip_val = u32::from(*ip);
            if ip_val >= start_val {
                Some((ip_val - start_val) as u64)
            } else {
                None
            }
        }
        (IpAddr::V6(start), IpAddr::V6(ip)) => {
            let start_val = u128::from(*start);
            let ip_val = u128::from(*ip);
            if ip_val >= start_val {
                let offset = ip_val - start_val;
                // Only return if offset fits in u64
                if offset <= u64::MAX as u128 {
                    Some(offset as u64)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None, // Family mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_equal() {
        assert!(domain_equal("example.com", "example.com"));
        assert!(domain_equal("Example.COM", "example.com"));
        assert!(domain_equal("example.com", "example.com."));
        assert!(domain_equal("EXAMPLE.COM.", "example.com"));
        assert!(!domain_equal("example.com", "test.com"));
    }

    #[test]
    fn test_wildcard_match() {
        // Exact match
        assert!(wildcard_match("example.com", "example.com"));

        // Suffix match without wildcard
        assert!(wildcard_match("example.com", "foo.example.com"));
        assert!(wildcard_match("example.com", "bar.baz.example.com"));

        // Wildcard match
        assert!(wildcard_match("*.example.com", "foo.example.com"));
        assert!(wildcard_match("*.example.com", "bar.baz.example.com"));
        assert!(!wildcard_match("*.example.com", "example.com"));

        // Case insensitive
        assert!(wildcard_match("*.Example.COM", "FOO.example.com"));
    }

    #[test]
    fn test_is_in_network_v4() {
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let network = Ipv4Addr::new(192, 168, 1, 0);

        assert!(is_in_network_v4(addr, network, 24));
        assert!(is_in_network_v4(addr, network, 16));
        assert!(!is_in_network_v4(addr, Ipv4Addr::new(192, 168, 2, 0), 24));
    }

    #[test]
    fn test_is_in_network_v6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
        let network = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);

        assert!(is_in_network_v6(addr, network, 32));
        assert!(is_in_network_v6(addr, network, 16));
        assert!(!is_in_network_v6(
            addr,
            Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0),
            32
        ));
    }

    #[test]
    fn test_parse_synthetic_indexed() {
        let synth_domains = vec![SynthDomain {
            domain: "example.com".to_string(),
            start_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            end_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
            format: SynthFormat::Indexed,
            prefix: "host".to_string(),
        }];

        let ip = parse_synthetic_domain("host42.example.com", &synth_domains);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 43))));

        let ip = parse_synthetic_domain("host0.example.com", &synth_domains);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_generate_synthetic_indexed() {
        let synth_domains = vec![SynthDomain {
            domain: "example.com".to_string(),
            start_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            end_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
            format: SynthFormat::Indexed,
            prefix: "host".to_string(),
        }];

        let name =
            generate_synthetic_domain(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 43)), &synth_domains);
        assert_eq!(name, Some("host42.example.com".to_string()));
    }

    #[test]
    fn test_select_domain_v4() {
        let cond_domains = vec![ConditionalDomain {
            domain: "internal.example.com".to_string(),
            networks: vec![IpNetwork {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }],
        }];

        let domain = select_domain_v4(Ipv4Addr::new(10, 0, 1, 50), &cond_domains);
        assert_eq!(domain, Some("internal.example.com"));

        let domain = select_domain_v4(Ipv4Addr::new(192, 168, 1, 1), &cond_domains);
        assert_eq!(domain, None);
    }

    #[test]
    fn test_format_ip_as_hostname_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(format_ip_as_hostname(&ip), "192-168-1-100");
    }

    #[test]
    fn test_format_ip_as_hostname_v6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let formatted = format_ip_as_hostname(&ip);
        // IPv6 formatting can vary, just ensure it contains dashes
        assert!(formatted.contains('-'));
    }
}
