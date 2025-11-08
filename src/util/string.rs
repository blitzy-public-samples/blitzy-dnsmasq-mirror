// Copyright (c) 2024 dnsmasq-rs Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//
// String manipulation utilities providing safe hostname validation, domain name
// canonicalization, IDN conversion, wildcard pattern matching, hexadecimal parsing,
// address formatting, and RFC 1035 DNS name encoding.
//
// Translated from src/util.c string-related functions to memory-safe Rust.

//! String manipulation utilities for DNS operations
//!
//! This module provides foundational string operations used throughout dnsmasq subsystems:
//! - RFC 1035/1123 hostname validation
//! - Case-insensitive DNS name comparison and subdomain checking
//! - DNS wire format encoding (length-prefixed labels)
//! - Internationalized Domain Name (IDN) to ASCII conversion
//! - Wildcard pattern matching for domain filters
//! - Hexadecimal parsing with wildcard support (for MAC addresses)
//! - Socket address formatting for logging
//! - Safe string operations eliminating buffer overflow vulnerabilities
//!
//! # Source Mapping from C
//!
//! - `legal_hostname()` → `is_legal_hostname()`
//! - `hostname_isequal()` → `hostname_equal()`
//! - `hostname_order()` → `hostname_cmp()`
//! - `hostname_issubdomain()` → `is_subdomain()`
//! - `wildcard_match()` → `wildcard_match()`
//! - `wildcard_matchn()` → `wildcard_match_prefix()`
//! - `parse_hex()` → `parse_hex_string()`
//! - `memcmp_masked()` → `compare_with_mask()`
//! - `prettyprint_addr()` → `format_socket_addr()`
//! - `do_rfc1035_name()` → `encode_dns_name()`
//! - `canonicalise()` → `canonicalize_hostname()`
//! - `expand_buf()` → `expand_buffer()`

use std::cmp::Ordering;
use std::net::SocketAddr;
use thiserror::Error;

/// Maximum total DNS domain name length per RFC 1035 (253 characters + 2 length bytes)
pub const MAX_DOMAIN_NAME_LENGTH: usize = 253;

/// Maximum DNS label length per RFC 1035 (63 characters)
pub const MAX_LABEL_LENGTH: usize = 63;

/// Recommended buffer size for DNS name encoding (256 bytes)
pub const DNS_NAME_BUFFER_SIZE: usize = 256;

/// Errors related to string validation and manipulation
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum StringError {
    /// String length is invalid (too short or too long)
    #[error("Invalid string length: {0}")]
    InvalidLength(String),

    /// Empty string where content is required
    #[error("Empty string not allowed")]
    EmptyString,

    /// String exceeds maximum allowed length
    #[error("String too long: {current} bytes (max {max})")]
    StringTooLong {
        /// Current length of the string
        current: usize,
        /// Maximum allowed length
        max: usize,
    },
}

/// Errors related to hexadecimal parsing
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Invalid hexadecimal digit encountered
    #[error("Invalid hex digit at position {position}: '{character}'")]
    InvalidHexDigit {
        /// Position in the input string
        position: usize,
        /// Invalid character found
        character: char,
    },

    /// Invalid format for hex string
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Wildcard mixed with hex digits in same byte
    #[error("Wildcard '*' cannot be mixed with hex digits in the same byte")]
    WildcardMixedWithHex,
}

/// Errors related to DNS name encoding
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DnsNameError {
    /// Label exceeds 63 bytes (RFC 1035 limit)
    #[error("Label too long: {length} bytes (max 63)")]
    LabelTooLong {
        /// Actual length of the label
        length: usize,
    },

    /// Total name exceeds 253 bytes (RFC 1035 limit)
    #[error("Name too long: {length} bytes (max 253)")]
    NameTooLong {
        /// Total length of the name
        length: usize,
    },

    /// Invalid character in domain name
    #[error("Invalid character in domain name: '{0}'")]
    InvalidCharacter(char),

    /// Empty label (consecutive dots or leading/trailing dot)
    #[error("Empty label in domain name")]
    EmptyLabel,
}

/// Errors related to IDN (Internationalized Domain Names) conversion
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum IdnError {
    /// IDN to ASCII conversion failed
    #[error("IDN conversion failed: {0}")]
    ConversionFailed(String),

    /// Invalid domain name for IDN processing
    #[error("Invalid name for IDN conversion")]
    InvalidName,
}

/// Validate hostname against RFC 952/1123 hostname rules
///
/// Validates that hostname conforms to strict hostname syntax: first label must contain
/// only alphanumeric characters, hyphens, and underscores (hyphens/underscores not at start).
/// This is stricter than general domain names and is used for DHCP hostnames.
/// Validates that no empty labels exist (consecutive dots, leading/trailing dots).
///
/// # Arguments
///
/// * `name` - Hostname or FQDN string to validate
///
/// # Returns
///
/// `true` if valid hostname per RFC 952/1123 rules, `false` otherwise
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::is_legal_hostname;
///
/// assert!(is_legal_hostname("my-server"));
/// assert!(is_legal_hostname("web1.example.com"));
/// assert!(!is_legal_hostname("-invalid"));
/// assert!(!is_legal_hostname("_underscore"));
/// ```
///
/// # RFC Compliance
///
/// RFC 952 (hostname syntax), RFC 1123 (allows leading digit)
#[must_use]
pub fn is_legal_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_DOMAIN_NAME_LENGTH {
        return false;
    }

    // Check for leading or trailing dots
    if name.starts_with('.') || name.ends_with('.') {
        return false;
    }

    // Check each label
    for label in name.split('.') {
        if label.is_empty() {
            // Empty label (consecutive dots)
            return false;
        }

        if label.len() > MAX_LABEL_LENGTH {
            return false;
        }

        // Check first label has valid hostname characters
        let mut is_first_char = true;
        for c in label.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' => {
                    is_first_char = false;
                }
                '-' | '_' if !is_first_char => {
                    // Hyphens and underscores allowed after first character
                }
                _ => {
                    return false;
                }
            }
        }
    }

    true
}

/// Safe string copy ensuring destination is always null-terminated
///
/// This is a Rust-safe alternative to C's `strncpy()` that guarantees null-termination.
/// Copies up to `max_len` characters from `src` to `dest` buffer.
///
/// # Arguments
///
/// * `dest` - Mutable destination string buffer
/// * `src` - Source string to copy
/// * `max_len` - Maximum number of bytes to copy
///
/// # Returns
///
/// `Ok(())` on success, `Err(StringError)` if string is too long
///
/// # Errors
///
/// Returns `StringError::StringTooLong` if the source string length is greater than or
/// equal to `max_len`.
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::util::string::safe_copy;
///
/// let mut buffer = String::with_capacity(64);
/// safe_copy(&mut buffer, "hostname", 64).unwrap();
/// ```
///
/// # Note
///
/// In Rust, this function is primarily for compatibility. Native Rust string operations
/// provide better safety guarantees.
pub fn safe_copy(dest: &mut String, src: &str, max_len: usize) -> Result<(), StringError> {
    if src.len() >= max_len {
        return Err(StringError::StringTooLong {
            current: src.len(),
            max: max_len,
        });
    }

    dest.clear();
    dest.push_str(src);
    Ok(())
}

/// Compare two hostnames for equality (case-insensitive)
///
/// Simple wrapper around `hostname_cmp()` returning `true` if hostnames are equal.
/// DNS names are case-insensitive per RFC 1035.
///
/// # Arguments
///
/// * `a` - First hostname string
/// * `b` - Second hostname string
///
/// # Returns
///
/// `true` if hostnames are equal (ignoring case), `false` otherwise
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::hostname_equal;
///
/// assert!(hostname_equal("Example.COM", "example.com"));
/// assert!(hostname_equal("test", "TEST"));
/// assert!(!hostname_equal("different", "names"));
/// ```
///
/// # RFC Compliance
///
/// RFC 1035 Section 3.1 (DNS names are case-insensitive)
#[must_use]
pub fn hostname_equal(a: &str, b: &str) -> bool {
    hostname_cmp(a, b) == Ordering::Equal
}

/// Compare two hostnames lexicographically (case-insensitive)
///
/// Performs case-insensitive lexicographic comparison of DNS hostnames, converting
/// uppercase ASCII characters to lowercase before comparison. Returns `Ordering` for
/// sorting and comparison operations.
///
/// # Arguments
///
/// * `a` - First hostname string
/// * `b` - Second hostname string
///
/// # Returns
///
/// `Ordering::Less` if a < b, `Ordering::Equal` if a == b, `Ordering::Greater` if a > b
///
/// # Examples
///
/// ```
/// use std::cmp::Ordering;
/// use dnsmasq::util::string::hostname_cmp;
///
/// assert_eq!(hostname_cmp("aaa.com", "bbb.com"), Ordering::Less);
/// assert_eq!(hostname_cmp("Example.COM", "example.com"), Ordering::Equal);
/// assert_eq!(hostname_cmp("zzz.com", "aaa.com"), Ordering::Greater);
/// ```
///
/// # RFC Compliance
///
/// RFC 1035 Section 3.1 (DNS names are case-insensitive)
#[must_use]
pub fn hostname_cmp(a: &str, b: &str) -> Ordering {
    let mut chars_a = a.chars();
    let mut chars_b = b.chars();

    loop {
        match (chars_a.next(), chars_b.next()) {
            (Some(c1), Some(c2)) => {
                let c1_lower = c1.to_ascii_lowercase();
                let c2_lower = c2.to_ascii_lowercase();

                match c1_lower.cmp(&c2_lower) {
                    Ordering::Equal => {}
                    other => return other,
                }
            }
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

/// Test if child is a subdomain of parent (case-insensitive)
///
/// Checks DNS hierarchy relationship by comparing hostnames from right to left.
/// Returns `true` if `child` is equal to or a subdomain of `parent`.
/// For example, "www.example.com" is a subdomain of "example.com".
///
/// # Arguments
///
/// * `child` - Domain name to test (potential subdomain)
/// * `parent` - Parent domain name
///
/// # Returns
///
/// `true` if child equals or is subdomain of parent, `false` otherwise
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::is_subdomain;
///
/// assert!(is_subdomain("www.example.com", "example.com"));
/// assert!(is_subdomain("example.com", "example.com")); // Equal counts as subdomain
/// assert!(!is_subdomain("example.org", "example.com"));
/// assert!(!is_subdomain("badexample.com", "example.com")); // Must be at label boundary
/// ```
///
/// # RFC Compliance
///
/// RFC 1035 Section 3.1 (DNS hierarchical namespace)
#[must_use]
pub fn is_subdomain(child: &str, parent: &str) -> bool {
    // Convert to lowercase for case-insensitive comparison
    let child_lower = child.to_lowercase();
    let parent_lower = parent.to_lowercase();

    // If child is shorter than parent, cannot be subdomain
    if child_lower.len() < parent_lower.len() {
        return false;
    }

    // If parent is empty, nothing can be subdomain
    if parent_lower.is_empty() {
        return false;
    }

    // If equal, it's a match
    if child_lower == parent_lower {
        return true;
    }

    // Check if child ends with parent and is preceded by a dot
    if child_lower.ends_with(&parent_lower) {
        let prefix_len = child_lower.len() - parent_lower.len();
        if prefix_len > 0 {
            // Must be preceded by a dot for valid subdomain
            return child_lower.as_bytes()[prefix_len - 1] == b'.';
        }
    }

    false
}

/// Match string against simple wildcard pattern
///
/// Compares string against pattern containing optional asterisk (*) wildcard.
/// Asterisk matches any remaining characters. Returns `true` if match successful.
/// This is simple wildcard matching, not full regex or glob patterns.
///
/// # Arguments
///
/// * `pattern` - Pattern string containing optional '*' wildcard
/// * `text` - String to test against pattern
///
/// # Returns
///
/// `true` if text matches pattern, `false` otherwise
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::wildcard_match;
///
/// assert!(wildcard_match("*.example.com", "www.example.com"));
/// assert!(wildcard_match("test*", "test123"));
/// assert!(wildcard_match("exact", "exact"));
/// assert!(!wildcard_match("abc", "def"));
/// ```
#[must_use]
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let mut pattern_chars = pattern.chars();
    let mut text_chars = text.chars();

    loop {
        match (pattern_chars.next(), text_chars.next()) {
            (Some('*'), _) | (None, None) => return true, // Wildcard matches rest or both exhausted
            (Some(p), Some(t)) if p == t => {}
            _ => return false, // Mismatch or other cases
        }
    }
}

/// Match string against wildcard pattern with length limit
///
/// Like `wildcard_match()` but compares at most `max_labels` characters, similar to
/// `strncmp()`. Returns `true` if the first `max_labels` characters match the pattern.
/// If characters are exhausted before mismatch or wildcard, returns `true`.
///
/// # Arguments
///
/// * `pattern` - Pattern string containing optional '*' wildcard
/// * `text` - String to test against pattern
/// * `max_labels` - Maximum number of characters to compare
///
/// # Returns
///
/// `true` if match successful within `max_labels` characters, `false` otherwise
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::wildcard_match_prefix;
///
/// assert!(wildcard_match_prefix("prefix*", "prefix-suffix", 6));
/// assert!(wildcard_match_prefix("test", "test123", 4));
/// ```
#[must_use]
pub fn wildcard_match_prefix(pattern: &str, text: &str, max_labels: usize) -> bool {
    let mut pattern_chars = pattern.chars();
    let mut text_chars = text.chars();
    let mut count = 0;

    while count < max_labels {
        match (pattern_chars.next(), text_chars.next()) {
            (Some('*'), _) | (None, None) => return true,
            (Some(p), Some(t)) if p == t => {
                count += 1;
            }
            _ => return false,
        }
    }

    true // Exhausted max_labels without mismatch
}

/// Parse hexadecimal string with optional wildcard support
///
/// Converts hex string (e.g., "01:23:45:67:89:ab") to byte array. Supports colon,
/// hyphen, or no separator. Handles '*' wildcard characters, returning separate
/// wildcard mask indicating which bytes are wildcards.
///
/// # Arguments
///
/// * `input` - Hex string to parse (with optional separators)
/// * `separator` - Expected separator character (or None for no separator)
///
/// # Returns
///
/// `Ok((bytes, wildcard_mask))` where `wildcard_mask` is `Some(mask)` if wildcards present,
/// `Err(ParseError)` on parse failure
///
/// # Errors
///
/// - `ParseError::InvalidFormat` - if hex string without separator has odd length
/// - `ParseError::InvalidHexDigit` - if non-hex character found (excluding wildcards)
///
/// # Panics
///
/// Panics if UTF-8 conversion fails on input chunks (should not occur with valid input
/// since we're only processing ASCII hex digits).
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::parse_hex_string;
///
/// let (bytes, mask) = parse_hex_string("01:02:*:04", Some(':')).unwrap();
/// assert_eq!(bytes, vec![0x01, 0x02, 0x00, 0x04]);
/// assert_eq!(mask, Some(vec![false, false, true, false]));
///
/// let (bytes2, mask2) = parse_hex_string("0a0b0c", None).unwrap();
/// assert_eq!(bytes2, vec![0x0a, 0x0b, 0x0c]);
/// assert_eq!(mask2, None);
/// ```
pub fn parse_hex_string(
    input: &str,
    separator: Option<char>,
) -> Result<(Vec<u8>, Option<Vec<bool>>), ParseError> {
    let mut bytes = Vec::new();
    let mut wildcard_mask = Vec::new();
    let mut has_wildcards = false;

    let parts: Vec<&str> = if let Some(sep) = separator {
        input.split(sep).collect()
    } else {
        // No separator - split into 2-character chunks
        if !input.len().is_multiple_of(2) {
            return Err(ParseError::InvalidFormat(
                "Hex string without separator must have even length".to_string(),
            ));
        }
        input
            .as_bytes()
            .chunks(2)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect()
    };

    for (pos, part) in parts.iter().enumerate() {
        if part.trim().is_empty() {
            continue;
        }

        if *part == "*" {
            bytes.push(0); // Placeholder for wildcard
            wildcard_mask.push(true);
            has_wildcards = true;
        } else {
            // Check for wildcards mixed with hex
            if part.contains('*') {
                return Err(ParseError::WildcardMixedWithHex);
            }

            // Parse hex digits
            let byte = u8::from_str_radix(part, 16).map_err(|_| ParseError::InvalidHexDigit {
                position: pos,
                character: part.chars().next().unwrap_or('?'),
            })?;

            bytes.push(byte);
            wildcard_mask.push(false);
        }
    }

    Ok((
        bytes,
        if has_wildcards {
            Some(wildcard_mask)
        } else {
            None
        },
    ))
}

/// Compare byte arrays with wildcard mask support
///
/// Compares arrays `a` and `b` byte-by-byte, skipping comparison where mask indicates
/// wildcard. Returns `true` if all non-wildcard bytes match.
///
/// # Arguments
///
/// * `a` - First byte array
/// * `b` - Second byte array
/// * `mask` - Boolean mask array (true = wildcard/skip comparison)
///
/// # Returns
///
/// `true` if all non-wildcard bytes match, `false` otherwise
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::compare_with_mask;
///
/// let mac1 = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
/// let mac2 = vec![0x01, 0xFF, 0x03, 0x04, 0x05, 0x06];
/// let mask = vec![false, true, false, false, false, false]; // Wildcard 2nd byte
///
/// assert!(compare_with_mask(&mac1, &mac2, &mask));
/// ```
#[must_use]
pub fn compare_with_mask(a: &[u8], b: &[u8], mask: &[bool]) -> bool {
    if a.len() != b.len() || a.len() != mask.len() {
        return false;
    }

    for i in 0..a.len() {
        if !mask[i] && a[i] != b[i] {
            return false;
        }
    }

    true
}

/// Format socket address as human-readable string
///
/// Converts `SocketAddr` (`IPv4` or `IPv6`) to string representation. For `IPv6` addresses,
/// uses standard bracket notation with port.
///
/// # Arguments
///
/// * `addr` - Socket address to format
///
/// # Returns
///
/// Formatted address string (e.g., "192.168.1.1:53" or "`[2001:db8::1]:53`")
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use dnsmasq::util::string::format_socket_addr;
///
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
/// assert_eq!(format_socket_addr(&addr), "192.168.1.1:53");
/// ```
#[must_use]
pub fn format_socket_addr(addr: &SocketAddr) -> String {
    // Rust's SocketAddr Display trait already handles this correctly
    addr.to_string()
}

/// Encode domain name in RFC 1035 wire format
///
/// Converts dot-separated domain name string to DNS wire format where each label
/// is prefixed by its length byte. For example, "example.com" becomes:
/// `[0x07, 'e','x','a','m','p','l','e', 0x03, 'c','o','m', 0x00]`
///
/// # Arguments
///
/// * `domain` - Dot-separated domain name string
///
/// # Returns
///
/// `Ok(Vec<u8>)` containing wire-format encoded name with terminating zero byte,
/// `Err(DnsNameError)` if validation fails
///
/// # Errors
///
/// - `DnsNameError::EmptyLabel` - if any label (between dots) is empty
/// - `DnsNameError::LabelTooLong` - if any label exceeds 63 characters
/// - `DnsNameError::InvalidCharacter` - if label contains non-alphanumeric, non-hyphen, non-underscore characters
/// - `DnsNameError::NameTooLong` - if total encoded name exceeds 255 bytes
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::encode_dns_name;
///
/// let encoded = encode_dns_name("example.com").unwrap();
/// assert_eq!(encoded[0], 7); // Length of "example"
/// assert_eq!(&encoded[1..8], b"example");
/// assert_eq!(encoded[8], 3); // Length of "com"
/// assert_eq!(&encoded[9..12], b"com");
/// assert_eq!(encoded[12], 0); // Terminating zero
/// ```
///
/// # RFC Compliance
///
/// RFC 1035 Section 3.1 (Name space definitions and DNS message format)
pub fn encode_dns_name(domain: &str) -> Result<Vec<u8>, DnsNameError> {
    let mut result = Vec::with_capacity(domain.len() + 2);
    let mut total_length = 0;

    // Split by dots and encode each label
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(DnsNameError::EmptyLabel);
        }

        let label_bytes = label.as_bytes();
        if label_bytes.len() > MAX_LABEL_LENGTH {
            return Err(DnsNameError::LabelTooLong {
                length: label_bytes.len(),
            });
        }

        // Check for invalid characters
        for &byte in label_bytes {
            if !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_' {
                return Err(DnsNameError::InvalidCharacter(byte as char));
            }
        }

        // Write length byte (safe: validated <= MAX_LABEL_LENGTH = 63)
        #[allow(clippy::cast_possible_truncation)]
        result.push(label_bytes.len() as u8);
        // Write label bytes
        result.extend_from_slice(label_bytes);

        total_length += 1 + label_bytes.len();
    }

    if total_length > MAX_DOMAIN_NAME_LENGTH {
        return Err(DnsNameError::NameTooLong {
            length: total_length,
        });
    }

    // Add terminating zero byte
    result.push(0);

    Ok(result)
}

/// Canonicalize hostname with optional IDN (Internationalized Domain Names) conversion
///
/// Converts domain name to canonical form suitable for DNS queries. For ASCII names,
/// returns the input string. For names with non-ASCII characters (when IDN support enabled),
/// converts to ASCII-compatible encoding (Punycode) per IDNA2008.
///
/// This function is feature-gated on the "idn" feature flag.
///
/// # Arguments
///
/// * `name` - Input domain name string (may contain non-ASCII if IDN support enabled)
///
/// # Returns
///
/// `Ok(String)` containing canonical ASCII domain name,
/// `Err(IdnError)` on invalid names or conversion failure
///
/// # Errors
///
/// Returns `IdnError::ConversionFailed` if the IDN to ASCII conversion fails due to:
/// - Invalid Unicode characters in the input
/// - Non-conformant domain name format
/// - Punycode encoding errors
///
/// # Examples
///
/// ```no_run
/// use dnsmasq::util::string::canonicalize_hostname;
///
/// let canon = canonicalize_hostname("münchen.de").unwrap();
/// // With IDN support: "xn--mnchen-3ya.de"
/// // Without IDN support: "münchen.de" (unchanged)
/// ```
///
/// # RFC Compliance
///
/// RFC 5890 (IDNA2008)
#[cfg(feature = "idn")]
pub fn canonicalize_hostname(name: &str) -> Result<String, IdnError> {
    // Check if name contains non-ASCII characters
    if name.is_ascii() {
        return Ok(name.to_string());
    }

    // Use idna crate for conversion
    idna::domain_to_ascii(name).map_err(|e| IdnError::ConversionFailed(e.to_string()))
}

/// Canonicalize hostname (IDN support disabled)
///
/// When the "idn" feature is not enabled, this function simply returns the input string
/// unchanged. Non-ASCII names will not be converted to Punycode.
#[cfg(not(feature = "idn"))]
pub fn canonicalize_hostname(name: &str) -> Result<String, IdnError> {
    Ok(name.to_string())
}

/// Expand buffer to at least specified size
///
/// Ensures vector has capacity for at least `required_size` bytes. If current capacity
/// is insufficient, reserves additional space. This function never shrinks the buffer.
///
/// # Arguments
///
/// * `buf` - Mutable reference to vector to expand
/// * `required_size` - Required minimum capacity in bytes
///
/// # Examples
///
/// ```
/// use dnsmasq::util::string::expand_buffer;
///
/// let mut buffer = Vec::with_capacity(64);
/// expand_buffer(&mut buffer, 1024);
/// assert!(buffer.capacity() >= 1024);
/// ```
///
/// # Note
///
/// In Rust, `Vec::reserve()` provides similar functionality with automatic growth.
/// This function is provided for API compatibility with the C version.
pub fn expand_buffer(buf: &mut Vec<u8>, required_size: usize) {
    if buf.capacity() < required_size {
        buf.reserve(required_size - buf.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_legal_hostname() {
        // Valid hostnames
        assert!(is_legal_hostname("example"));
        assert!(is_legal_hostname("example.com"));
        assert!(is_legal_hostname("my-server"));
        assert!(is_legal_hostname("web1"));
        assert!(is_legal_hostname("test.example.com"));

        // Invalid hostnames
        assert!(!is_legal_hostname(""));
        assert!(!is_legal_hostname("-invalid"));
        assert!(!is_legal_hostname("_underscore"));
        assert!(!is_legal_hostname("invalid..com"));
    }

    #[test]
    fn test_hostname_equal() {
        assert!(hostname_equal("example.com", "example.com"));
        assert!(hostname_equal("Example.COM", "example.com"));
        assert!(hostname_equal("TEST", "test"));
        assert!(!hostname_equal("different", "names"));
    }

    #[test]
    fn test_hostname_cmp() {
        assert_eq!(hostname_cmp("aaa", "bbb"), Ordering::Less);
        assert_eq!(hostname_cmp("bbb", "aaa"), Ordering::Greater);
        assert_eq!(hostname_cmp("test", "test"), Ordering::Equal);
        assert_eq!(hostname_cmp("Test", "test"), Ordering::Equal);
    }

    #[test]
    fn test_is_subdomain() {
        assert!(is_subdomain("www.example.com", "example.com"));
        assert!(is_subdomain("example.com", "example.com"));
        assert!(is_subdomain("sub.sub.example.com", "example.com"));
        assert!(!is_subdomain("example.org", "example.com"));
        assert!(!is_subdomain("badexample.com", "example.com"));
        assert!(!is_subdomain("short", "longer.name"));
    }

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("*.example.com", "www.example.com"));
        assert!(wildcard_match("test*", "test123"));
        assert!(wildcard_match("exact", "exact"));
        assert!(wildcard_match("*", "anything"));
        assert!(!wildcard_match("abc", "def"));
        assert!(!wildcard_match("test", "testing"));
    }

    #[test]
    fn test_wildcard_match_prefix() {
        assert!(wildcard_match_prefix("prefix*", "prefix-suffix", 6));
        assert!(wildcard_match_prefix("test", "test123", 4));
        assert!(wildcard_match_prefix("abc", "abc", 3));
        assert!(!wildcard_match_prefix("abc", "def", 3));
    }

    #[test]
    fn test_parse_hex_string() {
        // With colon separator
        let (bytes, mask) = parse_hex_string("01:02:03", Some(':')).unwrap();
        assert_eq!(bytes, vec![0x01, 0x02, 0x03]);
        assert_eq!(mask, None);

        // With wildcard
        let (bytes, mask) = parse_hex_string("01:*:03", Some(':')).unwrap();
        assert_eq!(bytes, vec![0x01, 0x00, 0x03]);
        assert_eq!(mask, Some(vec![false, true, false]));

        // Without separator
        let (bytes, mask) = parse_hex_string("0a0b0c", None).unwrap();
        assert_eq!(bytes, vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(mask, None);

        // Invalid hex
        assert!(parse_hex_string("0g", None).is_err());
    }

    #[test]
    fn test_compare_with_mask() {
        let a = vec![0x01, 0x02, 0x03, 0x04];
        let b = vec![0x01, 0xFF, 0x03, 0x04];
        let mask = vec![false, true, false, false];

        assert!(compare_with_mask(&a, &b, &mask));

        let mask_no_wild = vec![false, false, false, false];
        assert!(!compare_with_mask(&a, &b, &mask_no_wild));
    }

    #[test]
    fn test_encode_dns_name() {
        let encoded = encode_dns_name("example.com").unwrap();
        assert_eq!(encoded[0], 7); // Length of "example"
        assert_eq!(&encoded[1..8], b"example");
        assert_eq!(encoded[8], 3); // Length of "com"
        assert_eq!(&encoded[9..12], b"com");
        assert_eq!(encoded[12], 0); // Terminating zero

        // Empty label
        assert!(encode_dns_name("example..com").is_err());

        // Label too long
        let long_label = "a".repeat(64);
        assert!(matches!(
            encode_dns_name(&long_label),
            Err(DnsNameError::LabelTooLong { .. })
        ));
    }

    #[test]
    fn test_format_socket_addr() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        assert_eq!(format_socket_addr(&addr4), "192.168.1.1:53");

        let addr6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            53,
        );
        assert_eq!(format_socket_addr(&addr6), "[2001:db8::1]:53");
    }

    #[test]
    fn test_expand_buffer() {
        let mut buf = Vec::with_capacity(10);
        assert!(buf.capacity() >= 10);

        expand_buffer(&mut buf, 100);
        assert!(buf.capacity() >= 100);

        // Should not shrink
        expand_buffer(&mut buf, 50);
        assert!(buf.capacity() >= 100);
    }

    #[test]
    fn test_canonicalize_hostname_ascii() {
        let result = canonicalize_hostname("example.com").unwrap();
        assert_eq!(result, "example.com");
    }
}
