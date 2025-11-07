// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
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

//! Domain name manipulation utilities for conditional domain assignment and synthetic domain generation
//!
//! This module provides memory-safe domain name manipulation utilities for dnsmasq's conditional
//! domain assignment and synthetic domain generation features. It replaces C's manual string
//! manipulation with Rust's immutable String operations, eliminating buffer overflow and
//! use-after-free vulnerabilities.
//!
//! # Features
//!
//! - **Synthetic Domain Parsing**: Parse synthetic domain names and extract embedded IP addresses
//!   - Indexed format: `host42.example.com` maps to offset 42 in IP range
//!   - Direct IP encoding: `192-168-1-100.example.com` encodes IP directly
//! - **Synthetic Domain Generation**: Generate synthetic domain names from IP addresses
//! - **Conditional Domain Lookup**: Retrieve appropriate domain suffix based on client IP address
//! - **Subnet Matching**: Match IP addresses against CIDR ranges for domain selection
//!
//! # Memory Safety
//!
//! This implementation eliminates several classes of vulnerabilities from the C version:
//! - **No buffer overflows**: String operations use safe Rust types with automatic bounds checking
//! - **No temporary modifications**: Uses String::replace and str::split instead of in-place char modifications
//! - **Safe arithmetic**: Uses checked_add and saturating operations to prevent integer overflow
//! - **Type-safe IP parsing**: Uses std::net types instead of manual inet_pton
//!
//! # Configuration Compatibility
//!
//! Preserves 100% backward compatibility with dnsmasq.conf options:
//! - `synth-domain` for synthetic domain configuration
//! - `domain` for conditional domain assignment
//! - Both indexed and direct IP encoding formats supported
//!
//! # RFC Compliance
//!
//! Implements dnsmasq-specific extensions not directly specified by RFCs:
//! - Synthetic domain generation for automatic DNS naming
//! - Conditional domain assignment based on client subnet
//! - Generated names comply with RFC 1035 DNS hostname syntax

use std::fmt::Write as FmtWrite;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use tracing::{debug, trace};

use crate::dns::protocol::MAXDNAME;
use crate::utils::general::{
    addr6part, hostname_isequal as util_hostname_isequal, is_same_net6, is_same_net_prefix,
    setaddr6part,
};

// Re-export hostname comparison functions from utils for backward compatibility
pub use crate::utils::general::{
    hostname_isequal, hostname_order,
};

/// Address flags for conditional domain configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrlistFlags {
    /// IPv4 address
    IPv4,
    /// IPv6 address
    IPv6,
}

/// Address list entry for interface-based conditional domain matching
#[derive(Debug, Clone)]
pub struct Addrlist {
    /// IP address (v4 or v6)
    pub addr: IpAddr,
    /// Prefix length for subnet matching (CIDR notation)
    pub prefixlen: u32,
    /// Address family flag
    pub flags: AddrlistFlags,
}

/// Conditional domain configuration
///
/// Represents a single conditional or synthetic domain configuration that determines
/// which domain suffix to apply based on IP address ranges or interface subnets.
#[derive(Debug, Clone)]
pub struct CondDomain {
    /// Domain suffix to apply when match conditions are met
    pub domain: String,
    /// Optional prefix for synthetic domain names (e.g., "host" in "host42.example.com")
    pub prefix: Option<String>,
    /// True if this is an indexed synthetic domain (host1, host2, etc.)
    pub indexed: bool,
    /// True if this is interface-based matching (match against interface subnets)
    pub interface: bool,
    /// True if this domain uses IPv6 addresses
    pub is6: bool,
    /// IPv4 start address for range-based matching
    pub start: Ipv4Addr,
    /// IPv4 end address for range-based matching
    pub end: Ipv4Addr,
    /// IPv6 start address for range-based matching
    pub start6: Ipv6Addr,
    /// IPv6 end address for range-based matching
    pub end6: Ipv6Addr,
    /// Prefix length for IPv6 prefix-based matching
    pub prefixlen: u32,
    /// Address list for interface-based matching
    pub al: Vec<Addrlist>,
}

/// Query type flags for synthetic domain parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryFlags {
    /// IPv4 query
    IPv4,
    /// IPv6 query
    IPv6,
}

/// Result of synthetic domain name parsing
#[derive(Debug, Clone)]
pub enum SynthDomainResult {
    /// Successfully parsed, contains extracted IP address
    Match(IpAddr),
    /// No match found
    NoMatch,
}

/// Validate DNS name pattern
///
/// Checks if a string is a valid DNS name pattern according to RFC 1035 Section 2.3.1.
/// Allows letters, digits, hyphens, dots, and asterisks (for wildcards).
///
/// # Arguments
///
/// * `name` - Name pattern to validate
///
/// # Returns
///
/// * `true` if the name is valid
/// * `false` if the name contains invalid characters or structure
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::is_valid_dns_name_pattern;
///
/// assert!(is_valid_dns_name_pattern("example.com"));
/// assert!(is_valid_dns_name_pattern("*.example.com"));
/// assert!(is_valid_dns_name_pattern("host1.example.com"));
/// assert!(!is_valid_dns_name_pattern("invalid_name.com")); // underscore not allowed in DNS
/// ```
pub fn is_valid_dns_name_pattern(name: &str) -> bool {
    if name.is_empty() || name.len() > MAXDNAME {
        return false;
    }

    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Check each character in the label
        for (i, c) in label.chars().enumerate() {
            match c {
                // Letters and digits always allowed
                'a'..='z' | 'A'..='Z' | '0'..='9' => continue,
                // Hyphens allowed but not at start or end
                '-' if i > 0 && i < label.len() - 1 => continue,
                // Asterisk allowed for wildcards (only at start of label)
                '*' if i == 0 => continue,
                // Everything else is invalid
                _ => return false,
            }
        }
    }

    true
}

/// Check if IPv4 address matches conditional domain criteria
///
/// Determines whether an IPv4 address satisfies the matching criteria defined in a
/// conditional domain configuration. Supports interface-based matching (address must be
/// in same subnet as configured interface addresses) and range-based matching (address
/// must fall within configured start-end range).
///
/// # Arguments
///
/// * `addr` - IPv4 address to test
/// * `c` - Conditional domain configuration
///
/// # Returns
///
/// * `true` if address matches domain criteria
/// * `false` otherwise
fn match_domain(addr: Ipv4Addr, c: &CondDomain) -> bool {
    if c.interface {
        // Interface-based matching: check if address is in any configured subnet
        for al in &c.al {
            if matches!(al.flags, AddrlistFlags::IPv4) {
                if let IpAddr::V4(al_addr) = al.addr {
                    if is_same_net_prefix(addr, al_addr, al.prefixlen) {
                        trace!(
                            "IPv4 address {} matches interface subnet {}/{} for domain {}",
                            addr,
                            al_addr,
                            al.prefixlen,
                            c.domain
                        );
                        return true;
                    }
                }
            }
        }
    } else if !c.is6 {
        // Range-based matching: check if address is within start-end range
        let addr_u32 = u32::from(addr);
        let start_u32 = u32::from(c.start);
        let end_u32 = u32::from(c.end);

        if addr_u32 >= start_u32 && addr_u32 <= end_u32 {
            trace!(
                "IPv4 address {} matches range {}-{} for domain {}",
                addr,
                c.start,
                c.end,
                c.domain
            );
            return true;
        }
    }

    false
}

/// Find matching conditional domain configuration for IPv4 address
///
/// Searches through a list of conditional domain configurations to find the first
/// one that matches the given IPv4 address. Uses first-match-wins policy.
///
/// # Arguments
///
/// * `addr` - IPv4 address to search for
/// * `domains` - Slice of conditional domain configurations
///
/// # Returns
///
/// * `Some(domain)` - Reference to first matching domain configuration
/// * `None` - No match found
fn search_domain<'a>(addr: Ipv4Addr, domains: &'a [CondDomain]) -> Option<&'a CondDomain> {
    domains.iter().find(|c| match_domain(addr, c))
}

/// Check if IPv6 address matches conditional domain criteria
///
/// Determines whether an IPv6 address satisfies the matching criteria defined in a
/// conditional domain configuration. Supports interface-based matching and range-based
/// matching with prefix validation.
///
/// # Arguments
///
/// * `addr` - IPv6 address to test
/// * `c` - Conditional domain configuration
///
/// # Returns
///
/// * `true` if address matches domain criteria
/// * `false` otherwise
fn match_domain6(addr: &Ipv6Addr, c: &CondDomain) -> bool {
    if c.interface {
        // Interface-based matching: check if address is in any configured subnet
        for al in &c.al {
            if matches!(al.flags, AddrlistFlags::IPv6) {
                if let IpAddr::V6(al_addr) = al.addr {
                    if is_same_net6(addr, &al_addr, al.prefixlen) {
                        trace!(
                            "IPv6 address {} matches interface subnet {}/{} for domain {}",
                            addr,
                            al_addr,
                            al.prefixlen,
                            c.domain
                        );
                        return true;
                    }
                }
            }
        }
    } else if c.is6 {
        // Range-based matching
        if c.prefixlen >= 64 {
            // For /64 or longer, check both network prefix and host portion
            let addrpart = addr6part(addr);
            let start_part = addr6part(&c.start6);
            let end_part = addr6part(&c.end6);

            if is_same_net6(addr, &c.start6, 64)
                && addrpart >= start_part
                && addrpart <= end_part
            {
                trace!(
                    "IPv6 address {} matches /64+ range for domain {}",
                    addr,
                    c.domain
                );
                return true;
            }
        } else {
            // For shorter prefixes, only check network prefix
            if is_same_net6(addr, &c.start6, c.prefixlen) {
                trace!(
                    "IPv6 address {} matches /{} prefix for domain {}",
                    addr,
                    c.prefixlen,
                    c.domain
                );
                return true;
            }
        }
    }

    false
}

/// Find matching conditional domain configuration for IPv6 address
///
/// Searches through a list of conditional domain configurations to find the first
/// one that matches the given IPv6 address. Uses first-match-wins policy.
///
/// # Arguments
///
/// * `addr` - IPv6 address to search for
/// * `domains` - Slice of conditional domain configurations
///
/// # Returns
///
/// * `Some(domain)` - Reference to first matching domain configuration
/// * `None` - No match found
fn search_domain6<'a>(addr: &Ipv6Addr, domains: &'a [CondDomain]) -> Option<&'a CondDomain> {
    domains.iter().find(|c| match_domain6(addr, c))
}

/// Parse synthetic domain name and extract IP address
///
/// Examines a DNS query name to determine if it matches any configured synthetic domain
/// pattern. If a match is found, extracts the embedded IP address and validates it against
/// the configured IP range. Supports indexed numeric format (host42.example.com) and
/// direct IP encoding (192-168-1-100.example.com).
///
/// This is a memory-safe replacement for C's is_name_synthetic which temporarily modifies
/// the input string. The Rust version uses immutable String operations (replace, split)
/// eliminating buffer overflow and use-after-free vulnerabilities.
///
/// # Arguments
///
/// * `flags` - Query type (IPv4 or IPv6)
/// * `name` - DNS query name to parse
/// * `synth_domains` - Slice of synthetic domain configurations to match against
///
/// # Returns
///
/// * `SynthDomainResult::Match(addr)` - Name matches synthetic pattern, contains extracted IP
/// * `SynthDomainResult::NoMatch` - Name does not match any synthetic domain pattern
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::{is_name_synthetic, QueryFlags, SynthDomainResult, CondDomain};
/// use std::net::{Ipv4Addr, IpAddr};
///
/// let synth_domains = vec![
///     CondDomain {
///         domain: "mydomain.com".to_string(),
///         prefix: None,
///         indexed: false,
///         interface: false,
///         is6: false,
///         start: Ipv4Addr::new(192, 168, 1, 1),
///         end: Ipv4Addr::new(192, 168, 1, 254),
///         start6: "::".parse().unwrap(),
///         end6: "::".parse().unwrap(),
///         prefixlen: 0,
///         al: vec![],
///     }
/// ];
///
/// let name = "192-168-1-100.mydomain.com";
/// let result = is_name_synthetic(QueryFlags::IPv4, name, &synth_domains);
/// match result {
///     SynthDomainResult::Match(addr) => {
///         // addr contains 192.168.1.100
///         assert!(matches!(addr, IpAddr::V4(_)));
///     }
///     SynthDomainResult::NoMatch => {
///         panic!("Should have matched");
///     }
/// }
/// ```
///
/// # Memory Safety
///
/// Unlike C version which modifies input string in-place, this function uses immutable
/// operations:
/// - String::replace instead of character-by-character modification
/// - str::split instead of manual tokenization
/// - IpAddr::from_str with safe parsing instead of inet_pton
pub fn is_name_synthetic(
    flags: QueryFlags,
    name: &str,
    synth_domains: &[CondDomain],
) -> SynthDomainResult {
    let is_ipv6 = matches!(flags, QueryFlags::IPv6);

    for c in synth_domains {
        // Case-insensitive prefix matching
        let prefix = c.prefix.as_deref().unwrap_or("");
        let name_lower = name.to_lowercase();
        
        if !name_lower.starts_with(&prefix.to_lowercase()) {
            continue;
        }

        let tail = &name[prefix.len()..];

        if c.indexed {
            // Indexed format: prefix + number + "." + domain
            // Example: host42.example.com
            
            // Find the numeric part
            let dot_pos = match tail.find('.') {
                Some(pos) => pos,
                None => continue,
            };

            let number_part = &tail[..dot_pos];
            let domain_part = &tail[dot_pos + 1..];

            // Check if domain matches
            if !util_hostname_isequal(domain_part, &c.domain) {
                continue;
            }

            // Parse the numeric index
            if is_ipv6 {
                // IPv6 indexed
                if !c.is6 {
                    continue;
                }

                let index = match number_part.parse::<u64>() {
                    Ok(idx) => idx,
                    Err(_) => continue,
                };

                let start_part = addr6part(&c.start6);
                let end_part = addr6part(&c.end6);

                if index <= end_part.saturating_sub(start_part) {
                    let mut result_addr = c.start6;
                    setaddr6part(&mut result_addr, start_part.saturating_add(index));
                    
                    debug!(
                        "Parsed indexed IPv6 synthetic domain: {} -> {}",
                        name, result_addr
                    );
                    return SynthDomainResult::Match(IpAddr::V6(result_addr));
                }
            } else {
                // IPv4 indexed
                if c.is6 {
                    continue;
                }

                let index = match number_part.parse::<u32>() {
                    Ok(idx) => idx,
                    Err(_) => continue,
                };

                let start_u32 = u32::from(c.start);
                let end_u32 = u32::from(c.end);

                if index <= end_u32.saturating_sub(start_u32) {
                    let result_u32 = start_u32.saturating_add(index);
                    let result_addr = Ipv4Addr::from(result_u32);
                    
                    debug!(
                        "Parsed indexed IPv4 synthetic domain: {} -> {}",
                        name, result_addr
                    );
                    return SynthDomainResult::Match(IpAddr::V4(result_addr));
                }
            }
        } else {
            // Direct IP encoding: prefix + encoded-IP + "." + domain
            // Example: 192-168-1-100.example.com or 2001-db8--1.example.com
            
            // Find where IP part ends by scanning for valid IP characters
            // Match C implementation: find first character that's NOT part of IP encoding
            let mut dot_pos = None;
            for (idx, ch) in tail.chars().enumerate() {
                let is_valid = match ch {
                    '0'..='9' | '-' => true,
                    'A'..='F' | 'a'..='f' if is_ipv6 => true,
                    '.' => {
                        // Found the separator dot
                        dot_pos = Some(idx);
                        break;
                    }
                    _ => false,
                };
                
                if !is_valid {
                    break;
                }
            }
            
            let dot_pos = match dot_pos {
                Some(pos) => pos,
                None => continue,
            };

            let ip_part = &tail[..dot_pos];
            let domain_part = &tail[dot_pos + 1..];

            // Check if domain matches
            if !util_hostname_isequal(domain_part, &c.domain) {
                continue;
            }

            // Decode the IP address
            let decoded_ip = if is_ipv6 {
                // IPv6: Handle IPv4-mapped addresses (--ffff- prefix)
                if ip_part.starts_with("--ffff-") {
                    // Convert --ffff-192-168-1-1 to ::ffff:192.168.1.1
                    let ipv4_part = &ip_part[7..]; // Skip --ffff-
                    let ipv4_str = ipv4_part.replace('-', ".");
                    
                    match Ipv4Addr::from_str(&ipv4_str) {
                        Ok(v4_addr) => {
                            let v6_addr = v4_addr.to_ipv6_mapped();
                            IpAddr::V6(v6_addr)
                        }
                        Err(_) => continue,
                    }
                } else {
                    // Regular IPv6: convert dashes to colons
                    let ipv6_str = ip_part.replace('-', ":");
                    
                    // Handle case where IPv6 starts with colon (prepend 0)
                    let ipv6_str = if ipv6_str.starts_with(':') {
                        format!("0{}", ipv6_str)
                    } else {
                        ipv6_str
                    };
                    
                    match Ipv6Addr::from_str(&ipv6_str) {
                        Ok(addr) => IpAddr::V6(addr),
                        Err(_) => continue,
                    }
                }
            } else {
                // IPv4: convert dashes to dots
                let ipv4_str = ip_part.replace('-', ".");
                match Ipv4Addr::from_str(&ipv4_str) {
                    Ok(addr) => IpAddr::V4(addr),
                    Err(_) => continue,
                }
            };

            // Validate the decoded IP is within the configured range
            let matches = match decoded_ip {
                IpAddr::V4(addr) => match_domain(addr, c),
                IpAddr::V6(addr) => match_domain6(&addr, c),
            };

            if matches {
                debug!("Parsed direct-encoded synthetic domain: {} -> {}", name, decoded_ip);
                return SynthDomainResult::Match(decoded_ip);
            }
        }
    }

    SynthDomainResult::NoMatch
}

/// Generate synthetic domain name from IP address (reverse synthesis)
///
/// Performs the reverse operation of is_name_synthetic by generating a synthetic DNS
/// hostname from an IP address if the address falls within a configured synthetic domain
/// range. Supports indexed format (prefix + index + domain) and direct IP encoding
/// (prefix + encoded-IP + domain).
///
/// This is a memory-safe replacement for C's is_rev_synth which uses unsafe buffer
/// operations. The Rust version uses String formatting and safe arithmetic.
///
/// # Arguments
///
/// * `flag` - Address family flag (IPv4 or IPv6)
/// * `addr` - IP address to generate name from
/// * `synth_domains` - Slice of synthetic domain configurations
///
/// # Returns
///
/// * `Some(name)` - Generated synthetic domain name
/// * `None` - Address does not match any synthetic domain range
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::{is_rev_synth, QueryFlags, CondDomain};
/// use std::net::{Ipv4Addr, IpAddr};
///
/// let synth_domains = vec![
///     CondDomain {
///         domain: "mydomain.com".to_string(),
///         prefix: Some("host".to_string()),
///         indexed: true,
///         interface: false,
///         is6: false,
///         start: Ipv4Addr::new(192, 168, 1, 1),
///         end: Ipv4Addr::new(192, 168, 1, 254),
///         start6: "::".parse().unwrap(),
///         end6: "::".parse().unwrap(),
///         prefixlen: 0,
///         al: vec![],
///     }
/// ];
///
/// let addr = Ipv4Addr::new(192, 168, 1, 100);
/// if let Some(name) = is_rev_synth(QueryFlags::IPv4, IpAddr::V4(addr), &synth_domains) {
///     // name might be "host99.mydomain.com" (indexed, 0-based: 100-1=99)
///     assert!(name.contains("mydomain.com"));
/// }
/// ```
///
/// # Memory Safety
///
/// Uses safe String formatting instead of C's strncat with MAXDNAME buffer management:
/// - String::with_capacity for efficient allocation
/// - write! macro for safe formatting
/// - No manual buffer size tracking or null terminator management
pub fn is_rev_synth(
    flag: QueryFlags,
    addr: IpAddr,
    synth_domains: &[CondDomain],
) -> Option<String> {
    match (flag, addr) {
        (QueryFlags::IPv4, IpAddr::V4(v4_addr)) => {
            // Search for matching synthetic domain
            let c = search_domain(v4_addr, synth_domains)?;

            let mut name = String::with_capacity(MAXDNAME);

            if c.indexed {
                // Indexed format: prefix + number + "." + domain
                let index = u32::from(v4_addr).saturating_sub(u32::from(c.start));
                
                if let Some(ref prefix) = c.prefix {
                    write!(&mut name, "{}{}", prefix, index).ok()?;
                } else {
                    write!(&mut name, "{}", index).ok()?;
                }
            } else {
                // Direct IP encoding: prefix + encoded-IP + "." + domain
                if let Some(ref prefix) = c.prefix {
                    name.push_str(prefix);
                }

                // Convert IP to string and replace dots with dashes
                let ip_str = v4_addr.to_string();
                name.push_str(&ip_str.replace('.', "-"));
            }

            // Append domain suffix
            name.push('.');
            name.push_str(&c.domain);

            debug!("Generated IPv4 synthetic domain: {} -> {}", v4_addr, name);
            Some(name)
        }
        (QueryFlags::IPv6, IpAddr::V6(v6_addr)) => {
            // Search for matching synthetic domain
            let c = search_domain6(&v6_addr, synth_domains)?;

            let mut name = String::with_capacity(MAXDNAME);

            if c.indexed {
                // Indexed format: prefix + number + "." + domain
                let index = addr6part(&v6_addr).saturating_sub(addr6part(&c.start6));
                
                if let Some(ref prefix) = c.prefix {
                    write!(&mut name, "{}{}", prefix, index).ok()?;
                } else {
                    write!(&mut name, "{}", index).ok()?;
                }
            } else {
                // Direct IP encoding: prefix + encoded-IP + "." + domain
                if let Some(ref prefix) = c.prefix {
                    name.push_str(prefix);
                }

                // Convert IPv6 to string and process
                let ip_str = v6_addr.to_string();

                // If no prefix and IPv6 starts with ":", prepend "0"
                // to make valid DNS name (can't start with dash)
                if c.prefix.is_none() && ip_str.starts_with(':') {
                    name.push('0');
                    let modified = ip_str.replacen(':', "", 1);
                    name.push_str(&modified.replace(':', "-").replace('.', "-"));
                } else {
                    // Replace colons and dots with dashes
                    name.push_str(&ip_str.replace(':', "-").replace('.', "-"));
                }
            }

            // Append domain suffix
            name.push('.');
            name.push_str(&c.domain);

            debug!("Generated IPv6 synthetic domain: {} -> {}", v6_addr, name);
            Some(name)
        }
        _ => None,
    }
}

/// Retrieve appropriate domain suffix for IPv4 address
///
/// Determines the correct DNS domain suffix to use for a given IPv4 address by searching
/// through configured conditional domains. If the address matches a conditional domain
/// (based on IP range or interface subnet), returns that domain's suffix. Otherwise,
/// returns the default domain suffix.
///
/// # Arguments
///
/// * `addr` - IPv4 address
/// * `cond_domains` - Slice of conditional domain configurations
/// * `default_domain` - Default domain suffix if no conditional match
///
/// # Returns
///
/// Domain suffix string (conditional or default)
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::{get_domain, CondDomain};
/// use std::net::Ipv4Addr;
///
/// let cond_domains = vec![
///     CondDomain {
///         domain: "internal.net".to_string(),
///         prefix: None,
///         indexed: false,
///         interface: false,
///         is6: false,
///         start: Ipv4Addr::new(10, 0, 1, 1),
///         end: Ipv4Addr::new(10, 0, 1, 254),
///         start6: "::".parse().unwrap(),
///         end6: "::".parse().unwrap(),
///         prefixlen: 0,
///         al: vec![],
///     }
/// ];
///
/// let addr = Ipv4Addr::new(10, 0, 1, 50);
/// let domain = get_domain(addr, &cond_domains, "example.com");
/// assert_eq!(domain, "internal.net"); // Matches conditional domain
///
/// let addr2 = Ipv4Addr::new(192, 168, 1, 1);
/// let domain2 = get_domain(addr2, &cond_domains, "example.com");
/// assert_eq!(domain2, "example.com"); // Falls back to default
/// ```
pub fn get_domain<'a>(
    addr: Ipv4Addr,
    cond_domains: &'a [CondDomain],
    default_domain: &'a str,
) -> &'a str {
    search_domain(addr, cond_domains)
        .map(|c| c.domain.as_str())
        .unwrap_or(default_domain)
}

/// Retrieve appropriate domain suffix for IPv6 address
///
/// Determines the correct DNS domain suffix to use for a given IPv6 address by searching
/// through configured conditional domains. If the address matches a conditional domain
/// (based on prefix range or interface subnet), returns that domain's suffix. Otherwise,
/// returns the default domain suffix.
///
/// # Arguments
///
/// * `addr` - Optional IPv6 address (None returns default domain)
/// * `cond_domains` - Slice of conditional domain configurations
/// * `default_domain` - Default domain suffix if no conditional match
///
/// # Returns
///
/// Domain suffix string (conditional or default)
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::{get_domain6, CondDomain};
/// use std::net::{Ipv4Addr, Ipv6Addr};
///
/// let cond_domains = vec![
///     CondDomain {
///         domain: "ipv6.net".to_string(),
///         prefix: None,
///         indexed: false,
///         interface: false,
///         is6: true,
///         start: Ipv4Addr::new(0, 0, 0, 0),
///         end: Ipv4Addr::new(0, 0, 0, 0),
///         start6: "2001:db8::1".parse().unwrap(),
///         end6: "2001:db8::ffff".parse().unwrap(),
///         prefixlen: 64,
///         al: vec![],
///     }
/// ];
///
/// let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
/// let domain = get_domain6(Some(&addr), &cond_domains, "example.com");
/// assert_eq!(domain, "ipv6.net"); // Matches conditional domain
///
/// // Get default domain
/// let default = get_domain6(None, &cond_domains, "example.com");
/// assert_eq!(default, "example.com"); // No address, returns default
/// ```
pub fn get_domain6<'a>(
    addr: Option<&Ipv6Addr>,
    cond_domains: &'a [CondDomain],
    default_domain: &'a str,
) -> &'a str {
    addr.and_then(|a| search_domain6(a, cond_domains))
        .map(|c| c.domain.as_str())
        .unwrap_or(default_domain)
}

/// Canonicalise a DNS domain name
///
/// Converts a DNS name to canonical form per RFC 4034 Section 6.2:
/// - Converts to lowercase for case-insensitive comparison
/// - Removes trailing dots
/// - Validates length constraints
/// - Returns normalized form suitable for comparison and storage
///
/// This is used for:
/// - DNS cache key normalization
/// - Domain name comparison
/// - DNSSEC canonical ordering
///
/// # Arguments
///
/// * `name` - Domain name to canonicalise
///
/// # Returns
///
/// * `Some(canonical_name)` - Canonicalised domain name
/// * `None` - Invalid domain name (too long, empty, etc.)
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::canonicalise;
///
/// assert_eq!(canonicalise("Example.COM."), Some("example.com".to_string()));
/// assert_eq!(canonicalise("TEST."), Some("test".to_string()));
/// assert_eq!(canonicalise("example.com"), Some("example.com".to_string()));
/// assert_eq!(canonicalise(""), None);
/// ```
///
/// # RFC Compliance
///
/// - RFC 4034 Section 6.2: Canonical DNS Name Order
/// - RFC 1035 Section 2.3.3: Domain name case-insensitivity
pub fn canonicalise(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }

    // Remove trailing dot if present
    let name = name.strip_suffix('.').unwrap_or(name);

    if name.is_empty() {
        return None;
    }

    // Check total length (253 bytes max for presentation format)
    if name.len() > 253 {
        return None;
    }

    // Convert to lowercase (DNS is case-insensitive)
    let canonical = name.to_lowercase();

    // Validate label structure
    for label in canonical.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }

        // Validate each character
        for (i, c) in label.chars().enumerate() {
            match c {
                'a'..='z' | '0'..='9' => continue,
                '-' if i > 0 && i < label.len() - 1 => continue,
                _ => return None,
            }
        }
    }

    Some(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_dns_name_pattern() {
        assert!(is_valid_dns_name_pattern("example.com"));
        assert!(is_valid_dns_name_pattern("test.example.com"));
        assert!(is_valid_dns_name_pattern("host-1.example.com"));
        assert!(is_valid_dns_name_pattern("*.example.com"));
        
        assert!(!is_valid_dns_name_pattern(""));
        assert!(!is_valid_dns_name_pattern("invalid_name.com"));
        assert!(!is_valid_dns_name_pattern("-invalid.com"));
        assert!(!is_valid_dns_name_pattern("invalid-.com"));
    }

    #[test]
    fn test_canonicalise() {
        assert_eq!(
            canonicalise("Example.COM"),
            Some("example.com".to_string())
        );
        assert_eq!(
            canonicalise("TEST.Example.COM."),
            Some("test.example.com".to_string())
        );
        assert_eq!(canonicalise("test."), Some("test".to_string()));
        assert_eq!(canonicalise(""), None);
        assert_eq!(canonicalise("."), None);
    }

    #[test]
    fn test_match_domain_ipv4_range() {
        let cond_domain = CondDomain {
            domain: "test.com".to_string(),
            prefix: None,
            indexed: false,
            interface: false,
            is6: false,
            start: Ipv4Addr::new(192, 168, 1, 1),
            end: Ipv4Addr::new(192, 168, 1, 100),
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            prefixlen: 0,
            al: vec![],
        };

        assert!(match_domain(Ipv4Addr::new(192, 168, 1, 50), &cond_domain));
        assert!(match_domain(Ipv4Addr::new(192, 168, 1, 1), &cond_domain));
        assert!(match_domain(Ipv4Addr::new(192, 168, 1, 100), &cond_domain));
        assert!(!match_domain(Ipv4Addr::new(192, 168, 1, 200), &cond_domain));
        assert!(!match_domain(Ipv4Addr::new(10, 0, 0, 1), &cond_domain));
    }

    #[test]
    fn test_search_domain() {
        let domains = vec![
            CondDomain {
                domain: "subnet1.com".to_string(),
                prefix: None,
                indexed: false,
                interface: false,
                is6: false,
                start: Ipv4Addr::new(192, 168, 1, 1),
                end: Ipv4Addr::new(192, 168, 1, 100),
                start6: Ipv6Addr::UNSPECIFIED,
                end6: Ipv6Addr::UNSPECIFIED,
                prefixlen: 0,
                al: vec![],
            },
            CondDomain {
                domain: "subnet2.com".to_string(),
                prefix: None,
                indexed: false,
                interface: false,
                is6: false,
                start: Ipv4Addr::new(10, 0, 0, 1),
                end: Ipv4Addr::new(10, 0, 0, 100),
                start6: Ipv6Addr::UNSPECIFIED,
                end6: Ipv6Addr::UNSPECIFIED,
                prefixlen: 0,
                al: vec![],
            },
        ];

        let result = search_domain(Ipv4Addr::new(192, 168, 1, 50), &domains);
        assert!(result.is_some());
        assert_eq!(result.unwrap().domain, "subnet1.com");

        let result = search_domain(Ipv4Addr::new(10, 0, 0, 50), &domains);
        assert!(result.is_some());
        assert_eq!(result.unwrap().domain, "subnet2.com");

        let result = search_domain(Ipv4Addr::new(172, 16, 0, 1), &domains);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_domain() {
        let domains = vec![CondDomain {
            domain: "subnet.com".to_string(),
            prefix: None,
            indexed: false,
            interface: false,
            is6: false,
            start: Ipv4Addr::new(192, 168, 1, 1),
            end: Ipv4Addr::new(192, 168, 1, 100),
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            prefixlen: 0,
            al: vec![],
        }];

        assert_eq!(
            get_domain(Ipv4Addr::new(192, 168, 1, 50), &domains, "default.com"),
            "subnet.com"
        );
        assert_eq!(
            get_domain(Ipv4Addr::new(10, 0, 0, 1), &domains, "default.com"),
            "default.com"
        );
    }

    #[test]
    fn test_is_rev_synth_ipv4_indexed() {
        let domains = vec![CondDomain {
            domain: "example.com".to_string(),
            prefix: Some("host".to_string()),
            indexed: true,
            interface: false,
            is6: false,
            start: Ipv4Addr::new(192, 168, 1, 1),
            end: Ipv4Addr::new(192, 168, 1, 100),
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            prefixlen: 0,
            al: vec![],
        }];

        let result = is_rev_synth(
            QueryFlags::IPv4,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            &domains,
        );
        assert_eq!(result, Some("host49.example.com".to_string()));
    }

    #[test]
    fn test_is_rev_synth_ipv4_direct() {
        let domains = vec![CondDomain {
            domain: "example.com".to_string(),
            prefix: Some("ip-".to_string()),
            indexed: false,
            interface: false,
            is6: false,
            start: Ipv4Addr::new(192, 168, 1, 1),
            end: Ipv4Addr::new(192, 168, 1, 100),
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            prefixlen: 0,
            al: vec![],
        }];

        let result = is_rev_synth(
            QueryFlags::IPv4,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            &domains,
        );
        assert_eq!(result, Some("ip-192-168-1-50.example.com".to_string()));
    }

    #[test]
    fn test_is_name_synthetic_ipv4_indexed() {
        let domains = vec![CondDomain {
            domain: "example.com".to_string(),
            prefix: Some("host".to_string()),
            indexed: true,
            interface: false,
            is6: false,
            start: Ipv4Addr::new(192, 168, 1, 1),
            end: Ipv4Addr::new(192, 168, 1, 100),
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            prefixlen: 0,
            al: vec![],
        }];

        let result = is_name_synthetic(QueryFlags::IPv4, "host49.example.com", &domains);
        match result {
            SynthDomainResult::Match(IpAddr::V4(addr)) => {
                assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 50));
            }
            _ => panic!("Expected Match"),
        }
    }

    #[test]
    fn test_is_name_synthetic_ipv4_direct() {
        let domains = vec![CondDomain {
            domain: "example.com".to_string(),
            prefix: Some("ip-".to_string()),
            indexed: false,
            interface: false,
            is6: false,
            start: Ipv4Addr::new(192, 168, 1, 1),
            end: Ipv4Addr::new(192, 168, 1, 100),
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            prefixlen: 0,
            al: vec![],
        }];

        let result = is_name_synthetic(QueryFlags::IPv4, "ip-192-168-1-50.example.com", &domains);
        match result {
            SynthDomainResult::Match(IpAddr::V4(addr)) => {
                assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 50));
            }
            _ => panic!("Expected Match"),
        }
    }
}
