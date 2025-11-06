// Copyright (c) 2024 dnsmasq-rs Contributors
// This file is part of the dnsmasq Rust rewrite project.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

//! String Manipulation and DNS Name Operations
//!
//! This module provides string utilities and DNS name operations translated from
//! the C implementation in `src/util.c`. It includes hostname validation, DNS name
//! encoding/decoding, wildcard matching, and socket address formatting.
//!
//! # Key Functionality
//!
//! - **Hostname Validation**: RFC-compliant validation of DNS hostnames
//! - **DNS Name Encoding**: Convert dotted names to DNS wire format
//! - **String Comparison**: Case-insensitive DNS name comparison
//! - **Wildcard Matching**: Glob-style pattern matching for domain names
//! - **Socket Formatting**: Human-readable socket address formatting
//!
//! # Source Mapping
//!
//! Translated from: `src/util.c` (string-related functions including:
//! - `legal_hostname()` → `is_legal_hostname()`
//! - `hostname_isequal()` → `hostname_equal()`
//! - `hostname_issubdomain()` → `is_subdomain()`
//! - `wildcard_match()` → `wildcard_match()`
//! - `to_wire()` → `encode_dns_name()`
//! - `prettyprint_addr()` → `format_socket_addr()`
//!
//! # Examples
//!
//! ```rust
//! use dnsmasq::util::string::{is_legal_hostname, hostname_equal, is_subdomain};
//!
//! // Validate hostname
//! assert!(is_legal_hostname("example.com"));
//! assert!(!is_legal_hostname("-invalid.com"));
//!
//! // Case-insensitive comparison
//! assert!(hostname_equal("Example.COM", "example.com"));
//!
//! // Subdomain checking
//! assert!(is_subdomain("sub.example.com", "example.com"));
//! ```

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Maximum length of a DNS label (63 bytes per RFC 1035)
const MAX_LABEL_LEN: usize = 63;

/// Maximum length of a fully qualified domain name (255 bytes per RFC 1035)
const MAX_DOMAIN_LEN: usize = 255;

/// Error types for string operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringError {
    /// DNS name exceeds maximum length
    NameTooLong,
    /// DNS label exceeds maximum length
    LabelTooLong,
    /// Invalid character in DNS name
    InvalidCharacter(char),
    /// Empty label in DNS name
    EmptyLabel,
    /// Invalid name format
    InvalidFormat(String),
}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringError::NameTooLong => write!(f, "DNS name exceeds 255 bytes"),
            StringError::LabelTooLong => write!(f, "DNS label exceeds 63 bytes"),
            StringError::InvalidCharacter(c) => write!(f, "Invalid character in DNS name: '{}'", c),
            StringError::EmptyLabel => write!(f, "Empty label in DNS name"),
            StringError::InvalidFormat(msg) => write!(f, "Invalid name format: {}", msg),
        }
    }
}

impl std::error::Error for StringError {}

/// Validate that a string is a legal DNS hostname.
///
/// Checks that the hostname contains only valid DNS characters (alphanumeric,
/// hyphen, underscore, and dot), doesn't start or end with a hyphen or underscore,
/// and has valid label structure.
///
/// # Arguments
///
/// * `name` - The hostname to validate
///
/// # Returns
///
/// `true` if the hostname is valid, `false` otherwise
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::string::is_legal_hostname;
///
/// assert!(is_legal_hostname("example.com"));
/// assert!(is_legal_hostname("sub-domain.example.com"));
/// assert!(!is_legal_hostname("-invalid.com"));
/// assert!(!is_legal_hostname(""));
/// ```
///
/// # Source
///
/// Translated from: `legal_hostname()` in `src/util.c`
pub fn is_legal_hostname(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // Split into labels and validate each
    let labels: Vec<&str> = name.split('.').collect();
    
    for label in labels {
        // Empty labels are invalid (e.g., "example..com")
        if label.is_empty() {
            return false;
        }
        
        // Get first and last characters
        let first_char = label.chars().next().unwrap(); // Safe because we checked is_empty
        let last_char = label.chars().last().unwrap();
        
        // Labels cannot start or end with hyphen or underscore
        if first_char == '-' || first_char == '_' {
            return false;
        }
        if last_char == '-' || last_char == '_' {
            return false;
        }
        
        // All characters must be alphanumeric, hyphen, or underscore
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                return false;
            }
        }
    }

    true
}

/// Compare two hostnames for equality (case-insensitive).
///
/// Performs case-insensitive comparison of DNS hostnames, matching the
/// behavior of the C implementation's `hostname_isequal()`.
///
/// # Arguments
///
/// * `a` - First hostname
/// * `b` - Second hostname
///
/// # Returns
///
/// `true` if hostnames are equal (case-insensitive), `false` otherwise
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::string::hostname_equal;
///
/// assert!(hostname_equal("Example.COM", "example.com"));
/// assert!(hostname_equal("test", "TEST"));
/// assert!(!hostname_equal("example.com", "example.org"));
/// ```
///
/// # Source
///
/// Translated from: `hostname_isequal()` in `src/util.c`
pub fn hostname_equal(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Check if one hostname is a subdomain of another.
///
/// Determines if `subdomain` is a subdomain of `domain`. For example,
/// "sub.example.com" is a subdomain of "example.com".
///
/// # Arguments
///
/// * `subdomain` - The potential subdomain
/// * `domain` - The parent domain
///
/// # Returns
///
/// `true` if `subdomain` is a subdomain of `domain`, `false` otherwise
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::string::is_subdomain;
///
/// assert!(is_subdomain("sub.example.com", "example.com"));
/// assert!(is_subdomain("deep.sub.example.com", "example.com"));
/// assert!(!is_subdomain("example.com", "example.com")); // Not a subdomain of itself
/// assert!(!is_subdomain("other.org", "example.com"));
/// ```
///
/// # Source
///
/// Translated from: `hostname_issubdomain()` in `src/util.c`
pub fn is_subdomain(subdomain: &str, domain: &str) -> bool {
    let subdomain_lower = subdomain.to_ascii_lowercase();
    let domain_lower = domain.to_ascii_lowercase();

    // Subdomain must be longer than domain
    if subdomain_lower.len() <= domain_lower.len() {
        return false;
    }

    // Check if subdomain ends with ".domain"
    if subdomain_lower.ends_with(&format!(".{}", domain_lower)) {
        return true;
    }

    false
}

/// Match a string against a wildcard pattern.
///
/// Supports glob-style wildcard matching with '*' matching any sequence of characters.
///
/// # Arguments
///
/// * `pattern` - The pattern to match against (may contain '*' wildcards)
/// * `text` - The text to match
///
/// # Returns
///
/// `true` if the text matches the pattern, `false` otherwise
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::string::wildcard_match;
///
/// assert!(wildcard_match("*.example.com", "sub.example.com"));
/// assert!(wildcard_match("test*", "test123"));
/// assert!(wildcard_match("*", "anything"));
/// assert!(!wildcard_match("*.com", "example.org"));
/// ```
///
/// # Source
///
/// Translated from: `wildcard_match()` in `src/util.c`
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    wildcard_match_impl(pattern.as_bytes(), text.as_bytes())
}

/// Internal implementation of wildcard matching using byte slices.
fn wildcard_match_impl(pattern: &[u8], text: &[u8]) -> bool {
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < text.len() {
        if p_idx < pattern.len() && (pattern[p_idx] == text[t_idx] || pattern[p_idx] == b'?') {
            // Characters match or pattern has '?'
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < pattern.len() && pattern[p_idx] == b'*' {
            // Wildcard '*' - remember position
            star_idx = Some(p_idx);
            match_idx = t_idx;
            p_idx += 1;
        } else if let Some(star) = star_idx {
            // Backtrack to last '*' and try matching one more character
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            // No match
            return false;
        }
    }

    // Consume remaining '*' in pattern
    while p_idx < pattern.len() && pattern[p_idx] == b'*' {
        p_idx += 1;
    }

    // Match if we've consumed entire pattern
    p_idx == pattern.len()
}

/// Encode a domain name into DNS wire format.
///
/// Converts a dotted domain name (e.g., "example.com") into DNS wire format
/// with length-prefixed labels (e.g., \x07example\x03com\x00).
///
/// # Arguments
///
/// * `name` - The domain name to encode
///
/// # Returns
///
/// A `Result` containing the encoded name as a `Vec<u8>`, or a `StringError`
///
/// # Errors
///
/// - `StringError::NameTooLong` if the name exceeds 255 bytes
/// - `StringError::LabelTooLong` if any label exceeds 63 bytes
/// - `StringError::EmptyLabel` if the name contains empty labels
///
/// # Examples
///
/// ```rust
/// use dnsmasq::util::string::encode_dns_name;
///
/// let encoded = encode_dns_name("example.com").unwrap();
/// // encoded = [7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]
/// ```
///
/// # Source
///
/// Translated from: `to_wire()` in `src/util.c`
pub fn encode_dns_name(name: &str) -> Result<Vec<u8>, StringError> {
    let mut result = Vec::with_capacity(name.len() + 2);
    
    if name.is_empty() {
        result.push(0); // Root domain
        return Ok(result);
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err(StringError::EmptyLabel);
        }

        if label.len() > MAX_LABEL_LEN {
            return Err(StringError::LabelTooLong);
        }

        // Add label length
        result.push(label.len() as u8);
        
        // Add label bytes
        result.extend_from_slice(label.as_bytes());
    }

    // Add terminating zero byte
    result.push(0);

    if result.len() > MAX_DOMAIN_LEN {
        return Err(StringError::NameTooLong);
    }

    Ok(result)
}

/// Format a socket address as a human-readable string.
///
/// Converts a `SocketAddr` into a human-readable string with IP address and port.
///
/// # Arguments
///
/// * `addr` - The socket address to format
///
/// # Returns
///
/// A string representation of the socket address
///
/// # Examples
///
/// ```rust
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use dnsmasq::util::string::format_socket_addr;
///
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
/// assert_eq!(format_socket_addr(&addr), "192.168.1.1:53");
/// ```
///
/// # Source
///
/// Translated from: `prettyprint_addr()` in `src/util.c`
pub fn format_socket_addr(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_legal_hostname() {
        // Valid hostnames
        assert!(is_legal_hostname("example.com"));
        assert!(is_legal_hostname("sub.example.com"));
        assert!(is_legal_hostname("my-server.example.com"));
        assert!(is_legal_hostname("my_server.example.com"));
        assert!(is_legal_hostname("server123.example.com"));

        // Invalid hostnames
        assert!(!is_legal_hostname("")); // Empty
        assert!(!is_legal_hostname("-invalid.com")); // Starts with hyphen
        assert!(!is_legal_hostname("_invalid.com")); // Starts with underscore
        assert!(!is_legal_hostname("invalid-.com")); // Ends with hyphen
        assert!(!is_legal_hostname("in valid.com")); // Contains space
        assert!(!is_legal_hostname("invalid@.com")); // Invalid character
    }

    #[test]
    fn test_hostname_equal() {
        assert!(hostname_equal("example.com", "example.com"));
        assert!(hostname_equal("Example.COM", "example.com"));
        assert!(hostname_equal("EXAMPLE.COM", "example.com"));
        assert!(!hostname_equal("example.com", "example.org"));
        assert!(!hostname_equal("sub.example.com", "example.com"));
    }

    #[test]
    fn test_is_subdomain() {
        assert!(is_subdomain("sub.example.com", "example.com"));
        assert!(is_subdomain("deep.sub.example.com", "example.com"));
        assert!(is_subdomain("a.b.c.d.example.com", "example.com"));
        
        assert!(!is_subdomain("example.com", "example.com")); // Same domain
        assert!(!is_subdomain("other.org", "example.com")); // Different domain
        assert!(!is_subdomain("example.com", "sub.example.com")); // Parent not subdomain
    }

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("*.example.com", "sub.example.com"));
        assert!(wildcard_match("*.example.com", "deep.sub.example.com"));
        assert!(wildcard_match("test*", "test"));
        assert!(wildcard_match("test*", "test123"));
        assert!(wildcard_match("*test", "mytest"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*c", "abc"));
        assert!(wildcard_match("a*c", "abxyzc"));

        assert!(!wildcard_match("*.com", "example.org"));
        assert!(!wildcard_match("test", "test123"));
        assert!(!wildcard_match("test*", "tes"));
    }

    #[test]
    fn test_encode_dns_name() {
        // Simple domain
        let encoded = encode_dns_name("example.com").unwrap();
        assert_eq!(encoded[0], 7); // Length of "example"
        assert_eq!(&encoded[1..8], b"example");
        assert_eq!(encoded[8], 3); // Length of "com"
        assert_eq!(&encoded[9..12], b"com");
        assert_eq!(encoded[12], 0); // Terminator

        // Root domain
        let encoded = encode_dns_name("").unwrap();
        assert_eq!(encoded, vec![0]);

        // Label too long
        let long_label = "a".repeat(64);
        assert!(matches!(
            encode_dns_name(&long_label),
            Err(StringError::LabelTooLong)
        ));
    }

    #[test]
    fn test_format_socket_addr() {
        // IPv4
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        assert_eq!(format_socket_addr(&addr), "192.168.1.1:53");

        // IPv6
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            53,
        );
        assert_eq!(format_socket_addr(&addr), "[2001:db8::1]:53");
    }
}
