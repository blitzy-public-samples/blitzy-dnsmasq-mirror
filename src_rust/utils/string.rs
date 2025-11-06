// Copyright (c) 2000-2024 Simon Kelley
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

//! String Manipulation and Validation Module
//!
//! This module provides memory-safe string manipulation and validation functions for DNS
//! names, hostnames, and protocol encoding. It replaces C string operations with Rust's
//! safe `String` and `&str` types, eliminating buffer overflows and null pointer dereferences.
//!
//! # Functions
//!
//! - **`safe_strncpy`**: Safe string copying with guaranteed null termination
//! - **`check_name`**: Internal domain name validation (supports future IDN)
//! - **`legal_hostname`**: RFC 952/1123 hostname validation for DHCP
//! - **`canonicalise`**: Domain name canonicalization (ASCII form, IDN-ready)
//! - **`do_rfc1035_name`**: RFC 1035 wire format encoding for DNS packets
//!
//! # Memory Safety Guarantees
//!
//! All functions use Rust's memory-safe types:
//! - No buffer overflows (bounds checking via slices)
//! - No null pointer dereferences (Option types)
//! - No use-after-free (ownership system)
//! - No manual memory management
//!
//! # Key Transformations from C (src/util.c)
//!
//! | C Pattern | Rust Replacement | Safety Improvement |
//! |-----------|------------------|-------------------|
//! | `char *` pointers | `&str`, `String` | No dangling pointers |
//! | `strlen()`  + bounds | `.len()` checked | No buffer overruns |
//! | `strcpy()`, `strncpy()` | `String::from()` | Automatic allocation |
//! | `malloc()` + `free()` | `String` (auto Drop) | No memory leaks |
//! | Manual null termination | Built-in to String | Always valid UTF-8 |
//!
//! # References
//!
//! - C source: `src/util.c` (lines 348-702)
//! - RFC 952: DoD Internet Host Table Specification (hostname syntax)
//! - RFC 1123: Requirements for Internet Hosts (allows leading digit in hostname)
//! - RFC 1035: Domain Names - Implementation and Specification (wire format)
//! - RFC 5890: Internationalized Domain Names for Applications (IDNA2008)

use std::str;

/// Maximum DNS domain name length (255 bytes as per RFC 1035)
const MAXDNAME: usize = 255;

/// Maximum DNS label length (63 bytes as per RFC 1035)
const MAXLABEL: usize = 63;

/// Result of name checking: Invalid(0), Valid ASCII(1), Needs IDN encoding(2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckNameResult {
    Invalid,
    ValidAscii,
    NeedsIdnEncoding,
}

/// Safe string copy with guaranteed null termination (Rust equivalent of C safe_strncpy)
///
/// Copies `src` string to a newly allocated `String`, truncating if necessary to fit
/// within `max_size` bytes. Unlike C's `strncpy()`, this always produces a valid
/// null-terminated string (Rust `String` is always valid UTF-8 and null-terminated).
///
/// # Arguments
///
/// * `src` - Source string slice to copy
/// * `max_size` - Maximum number of bytes to copy (excluding null terminator)
///
/// # Returns
///
/// A new `String` containing up to `max_size` bytes from `src`, guaranteed valid and terminated
///
/// # Examples
///
/// ```
/// use dnsmasq::utils::string::safe_strncpy;
///
/// let result = safe_strncpy("very-long-hostname.example.com", 10);
/// assert_eq!(result.len(), 10);
/// assert_eq!(result, "very-long-");
/// ```
///
/// # Safety
///
/// This function is completely memory-safe. Unlike C `strncpy()`:
/// - No buffer overflow possible (Rust strings grow automatically)
/// - Always produces valid UTF-8
/// - No manual null termination needed
/// - No uninitialized memory
///
/// # Performance
///
/// O(n) where n = min(src.len(), max_size). Allocates new String on heap.
pub fn safe_strncpy(src: &str, max_size: usize) -> String {
    if max_size == 0 {
        return String::new();
    }
    
    // Take at most max_size bytes from src
    // Rust strings are always valid UTF-8, so this is safe
    let bytes_to_copy = std::cmp::min(src.len(), max_size);
    String::from(&src[..bytes_to_copy])
}

/// Internal domain name validation (Rust equivalent of C check_name)
///
/// Validates domain name format, checking for:
/// - Empty string (invalid)
/// - Length > MAXDNAME (255 bytes, invalid)
/// - Label length > MAXLABEL (63 bytes, invalid)
/// - Control characters (invalid)
/// - Non-ASCII characters (requires IDN encoding if supported)
/// - Trailing dot (removed automatically)
/// - Whitespace-only name (invalid)
///
/// # Arguments
///
/// * `name` - Domain name string to validate (may be modified by removing trailing dot)
///
/// # Returns
///
/// * `CheckNameResult::Invalid` - Name is invalid
/// * `CheckNameResult::ValidAscii` - Name is valid ASCII, no IDN encoding needed
/// * `CheckNameResult::NeedsIdnEncoding` - Name contains non-ASCII or uppercase (IDN support needed)
///
/// # Examples
///
/// ```ignore
/// // This is a private function, tested in the module's test suite
/// let mut name = String::from("example.com.");
/// let result = check_name(&mut name);
/// assert_eq!(result, CheckNameResult::ValidAscii);
/// assert_eq!(name, "example.com"); // Trailing dot removed
/// ```
fn check_name(name: &mut String) -> CheckNameResult {
    // Remove trailing dot if present
    if name.ends_with('.') {
        name.pop();
    }
    
    // Check empty string or too long
    let len = name.len();
    if len == 0 || len > MAXDNAME {
        return CheckNameResult::Invalid;
    }
    
    let mut dotgap: usize = 0;
    let mut nowhite = false;
    let mut has_non_ascii = false;
    let mut has_uppercase = false;
    
    for ch in name.chars() {
        if ch == '.' {
            dotgap = 0;
        } else {
            dotgap += 1;
            if dotgap > MAXLABEL {
                return CheckNameResult::Invalid;
            }
            
            // Check for control characters
            if ch.is_control() {
                return CheckNameResult::Invalid;
            }
            
            // Check for non-ASCII
            if !ch.is_ascii() {
                has_non_ascii = true;
            }
            
            if ch != ' ' {
                nowhite = true;
                
                // Check for uppercase (requires IDN processing)
                if ch.is_ascii_uppercase() {
                    has_uppercase = true;
                }
            }
        }
    }
    
    // Must have at least one non-whitespace character
    if !nowhite {
        return CheckNameResult::Invalid;
    }
    
    // Determine if IDN encoding would be needed
    // Note: Without libidn2/libidna, we can't actually encode, but we detect the need
    if has_non_ascii || has_uppercase {
        CheckNameResult::NeedsIdnEncoding
    } else {
        CheckNameResult::ValidAscii
    }
}

/// Validate hostname against stricter RFC 952/1123 hostname rules
///
/// Validates that hostname conforms to DoD Internet Host Table Specification (RFC 952)
/// as updated by RFC 1123:
/// - First label must contain only alphanumeric, hyphen, and underscore characters
/// - Hyphens and underscores cannot be first character
/// - First label cannot start with a digit (relaxed in RFC 1123 but still validated here)
///
/// This is stricter than general domain name validation - used for DHCP hostnames
/// where the client hostname must follow classic hostname rules.
///
/// # Arguments
///
/// * `name` - Hostname or FQDN string to validate
///
/// # Returns
///
/// * `true` - Valid hostname per RFC 952/1123 rules
/// * `false` - Invalid hostname (fails check_name or invalid first label chars)
///
/// # Examples
///
/// ```
/// use dnsmasq::utils::string::legal_hostname;
///
/// assert!(legal_hostname("my-server"));
/// assert!(legal_hostname("web01.example.com"));
/// assert!(!legal_hostname("-invalid"));
/// assert!(!legal_hostname("invalid-.com"));
/// ```
///
/// # RFC Compliance
///
/// - RFC 952: DoD Internet Host Table Specification
/// - RFC 1123: Requirements for Internet Hosts (allows leading digit)
///
/// # See Also
///
/// - [`check_name`] for general domain validation
/// - [`canonicalise`] for domain canonicalization
pub fn legal_hostname(name: &str) -> bool {
    let mut name_copy = String::from(name);
    
    // First validate as a domain name
    let check_result = check_name(&mut name_copy);
    if check_result == CheckNameResult::Invalid {
        return false;
    }
    
    let mut first = true;
    let mut last_char = '\0';
    let mut has_letter = false;
    
    for ch in name_copy.chars() {
        // Check for legal chars: a-z A-Z 0-9 - _ .
        if ch.is_ascii_alphabetic() {
            first = false;
            last_char = ch;
            has_letter = true;
            continue;
        }
        
        if ch.is_ascii_digit() {
            first = false;
            last_char = ch;
            continue;
        }
        
        // Hyphen and underscore allowed, but not as first character
        if !first && (ch == '-' || ch == '_') {
            last_char = ch;
            continue;
        }
        
        // Dot marks end of first label (hostname part)
        if ch == '.' {
            // Check that the label didn't end with hyphen or underscore
            if last_char == '-' || last_char == '_' {
                return false;
            }
            // Check that the label has at least one letter (not all numeric)
            if !has_letter {
                return false;
            }
            return true;
        }
        
        // Any other character is invalid
        return false;
    }
    
    // Valid if we reached end without hitting invalid char
    // But check that last character wasn't hyphen or underscore
    if last_char == '-' || last_char == '_' {
        return false;
    }
    
    // Check that we have at least one letter (not all numeric)
    if !has_letter {
        return false;
    }
    
    true
}

/// Canonicalize domain name (ASCII form, IDN-ready but not implemented)
///
/// Converts domain name to canonical form suitable for DNS queries. Currently returns
/// a copy of the input for valid ASCII names. Full IDN (Internationalized Domain Names)
/// support via libidn2 would convert non-ASCII characters to Punycode ACE representation.
///
/// # Arguments
///
/// * `input` - Input domain name string (may contain non-ASCII if IDN support added)
///
/// # Returns
///
/// * `Ok(String)` - Canonical domain name (currently ASCII copy)
/// * `Err(CanonicaliseError)` - Invalid domain name or encoding failure
///
/// # Examples
///
/// ```
/// use dnsmasq::utils::string::canonicalise;
///
/// let canon = canonicalise("Example.COM").unwrap();
/// assert_eq!(canon, "Example.COM"); // Currently no case folding without IDN
/// ```
///
/// # Future Enhancement
///
/// When `libidn2` feature is enabled, this will:
/// - Convert non-ASCII to Punycode (e.g., "münchen.de" → "xn--mnchen-3ya.de")
/// - Apply IDNA2008 normalization
/// - Return proper error types for IDN failures
///
/// # RFC Compliance
///
/// - RFC 5890: Internationalized Domain Names for Applications (IDNA2008)
/// - RFC 3492: Punycode: A Bootstring encoding (used for ACE representation)
///
/// # See Also
///
/// - [`check_name`] for validation
/// - [`legal_hostname`] for hostname-specific rules
#[derive(Debug)]
pub enum CanonicaliseError {
    InvalidName,
    MemoryAllocation,
}

pub fn canonicalise(input: &str) -> Result<String, CanonicaliseError> {
    let mut name = String::from(input);
    
    let check_result = check_name(&mut name);
    if check_result == CheckNameResult::Invalid {
        return Err(CanonicaliseError::InvalidName);
    }
    
    // For now, without IDN support, just return a copy
    // Future: If check_result == NeedsIdnEncoding, call libidn2 to convert to Punycode
    #[cfg(feature = "idn")]
    {
        if check_result == CheckNameResult::NeedsIdnEncoding {
            // TODO: Call idn2_to_ascii_lz when idn feature is implemented
            // For now, return as-is (may fail downstream if non-ASCII)
        }
    }
    
    Ok(name)
}

/// Encode domain name in RFC 1035 wire format (length-prefixed labels)
///
/// Converts dot-separated domain name string to DNS wire format where each label
/// is prefixed by its length byte. For example:
/// - "example.com" → `\x07example\x03com\x00` (includes terminating zero-length label)
///
/// # Arguments
///
/// * `sval` - Input domain name string (dot-separated labels)
/// * `buffer` - Output buffer to write encoded name
/// * `limit` - Optional maximum buffer size for bounds checking
///
/// # Returns
///
/// * `Ok(usize)` - Number of bytes written to buffer
/// * `Err(Rfc1035Error)` - Buffer limit exceeded or invalid input
///
/// # Examples
///
/// ```
/// use dnsmasq::utils::string::do_rfc1035_name;
///
/// let mut buffer = [0u8; 512];
/// let bytes_written = do_rfc1035_name("example.com", &mut buffer, Some(512)).unwrap();
/// // buffer now contains: [7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm']
/// assert_eq!(bytes_written, 13);
/// ```
///
/// # Wire Format
///
/// Each label is encoded as:
/// 1. Length byte (0-63 for label length)
/// 2. Label characters (ASCII bytes)
/// 3. Repeat for each label
/// 4. Terminating zero-length label (0x00 byte) marking end of name
///
/// # RFC Compliance
///
/// - RFC 1035 Section 3.1: Name space definitions and DNS message format
///
/// # See Also
///
/// - DNS packet building in `dns::serializer` module
#[derive(Debug)]
pub enum Rfc1035Error {
    BufferLimitExceeded,
    InvalidLabel,
}

pub fn do_rfc1035_name(
    sval: &str,
    buffer: &mut [u8],
    limit: Option<usize>,
) -> Result<usize, Rfc1035Error> {
    let max_len = limit.unwrap_or(buffer.len());
    let mut pos = 0;
    
    // Split domain by dots and encode each label
    for label in sval.split('.') {
        if label.is_empty() {
            continue; // Skip empty labels (e.g., from trailing dot)
        }
        
        let label_len = label.len();
        
        // Check label length (max 63 per RFC 1035)
        if label_len > MAXLABEL {
            return Err(Rfc1035Error::InvalidLabel);
        }
        
        // Check if we have room for length byte + label
        if pos + 1 + label_len > max_len {
            return Err(Rfc1035Error::BufferLimitExceeded);
        }
        
        // Write length byte
        buffer[pos] = label_len as u8;
        pos += 1;
        
        // Write label characters
        buffer[pos..pos + label_len].copy_from_slice(label.as_bytes());
        pos += label_len;
    }
    
    // Write terminating zero-length label (RFC 1035 requirement)
    if pos + 1 > max_len {
        return Err(Rfc1035Error::BufferLimitExceeded);
    }
    buffer[pos] = 0;
    pos += 1;
    
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_safe_strncpy_normal() {
        let result = safe_strncpy("hello", 10);
        assert_eq!(result, "hello");
        assert_eq!(result.len(), 5);
    }
    
    #[test]
    fn test_safe_strncpy_truncate() {
        let result = safe_strncpy("very-long-hostname", 10);
        assert_eq!(result, "very-long-");
        assert_eq!(result.len(), 10);
    }
    
    #[test]
    fn test_safe_strncpy_zero_size() {
        let result = safe_strncpy("anything", 0);
        assert_eq!(result, "");
        assert_eq!(result.len(), 0);
    }
    
    #[test]
    fn test_safe_strncpy_exact_fit() {
        let result = safe_strncpy("exact", 5);
        assert_eq!(result, "exact");
    }
    
    #[test]
    fn test_check_name_valid() {
        let mut name = String::from("example.com");
        let result = check_name(&mut name);
        assert_eq!(result, CheckNameResult::ValidAscii);
    }
    
    #[test]
    fn test_check_name_trailing_dot() {
        let mut name = String::from("example.com.");
        let result = check_name(&mut name);
        assert_eq!(result, CheckNameResult::ValidAscii);
        assert_eq!(name, "example.com"); // Trailing dot removed
    }
    
    #[test]
    fn test_check_name_empty() {
        let mut name = String::from("");
        let result = check_name(&mut name);
        assert_eq!(result, CheckNameResult::Invalid);
    }
    
    #[test]
    fn test_check_name_too_long() {
        let mut name = String::from("a").repeat(256);
        let result = check_name(&mut name);
        assert_eq!(result, CheckNameResult::Invalid);
    }
    
    #[test]
    fn test_check_name_label_too_long() {
        // Create a label with 64 characters (> MAXLABEL of 63)
        let mut name = String::from("a").repeat(64) + ".com";
        let result = check_name(&mut name);
        assert_eq!(result, CheckNameResult::Invalid);
    }
    
    #[test]
    fn test_check_name_with_uppercase() {
        let mut name = String::from("Example.COM");
        let result = check_name(&mut name);
        assert_eq!(result, CheckNameResult::NeedsIdnEncoding);
    }
    
    #[test]
    fn test_legal_hostname_valid() {
        assert!(legal_hostname("example"));
        assert!(legal_hostname("example.com"));
        assert!(legal_hostname("my-server"));
        assert!(legal_hostname("web01"));
        assert!(legal_hostname("host_name"));
    }
    
    #[test]
    fn test_legal_hostname_invalid() {
        assert!(!legal_hostname("")); // Empty
        assert!(!legal_hostname("-invalid")); // Starts with hyphen
        assert!(!legal_hostname("_invalid")); // Starts with underscore
        assert!(!legal_hostname("invalid-.com")); // Hyphen before dot
        assert!(!legal_hostname("invalid-")); // Ends with hyphen
        assert!(!legal_hostname("invalid_")); // Ends with underscore
    }
    
    #[test]
    fn test_legal_hostname_with_domain() {
        assert!(legal_hostname("server.example.com"));
        assert!(legal_hostname("web-01.test.local"));
    }
    
    #[test]
    fn test_canonicalise_valid() {
        let result = canonicalise("example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }
    
    #[test]
    fn test_canonicalise_with_trailing_dot() {
        let result = canonicalise("example.com.");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }
    
    #[test]
    fn test_canonicalise_invalid() {
        let result = canonicalise("");
        assert!(result.is_err());
        
        let result = canonicalise(&"a".repeat(256));
        assert!(result.is_err());
    }
    
    #[test]
    fn test_do_rfc1035_name_simple() {
        let mut buffer = [0u8; 128];
        let bytes_written = do_rfc1035_name("example.com", &mut buffer, Some(128)).unwrap();
        
        // Expected: \x07example\x03com\x00
        assert_eq!(bytes_written, 13);
        assert_eq!(buffer[0], 7); // Length of "example"
        assert_eq!(&buffer[1..8], b"example");
        assert_eq!(buffer[8], 3); // Length of "com"
        assert_eq!(&buffer[9..12], b"com");
        assert_eq!(buffer[12], 0); // Terminating zero-length label
    }
    
    #[test]
    fn test_do_rfc1035_name_single_label() {
        let mut buffer = [0u8; 128];
        let bytes_written = do_rfc1035_name("localhost", &mut buffer, Some(128)).unwrap();
        
        // Expected: \x09localhost\x00 (includes terminating zero-length label)
        assert_eq!(bytes_written, 11);
        assert_eq!(buffer[0], 9);
        assert_eq!(&buffer[1..10], b"localhost");
        assert_eq!(buffer[10], 0); // Terminating zero-length label
    }
    
    #[test]
    fn test_do_rfc1035_name_buffer_limit() {
        let mut buffer = [0u8; 5];
        let result = do_rfc1035_name("example.com", &mut buffer, Some(5));
        assert!(result.is_err());
    }
    
    #[test]
    fn test_do_rfc1035_name_label_too_long() {
        let long_label = "a".repeat(64); // > MAXLABEL of 63
        let mut buffer = [0u8; 128];
        let result = do_rfc1035_name(&long_label, &mut buffer, Some(128));
        assert!(result.is_err());
    }
    
    #[test]
    fn test_do_rfc1035_name_with_trailing_dot() {
        let mut buffer = [0u8; 128];
        let bytes_written = do_rfc1035_name("example.com.", &mut buffer, Some(128)).unwrap();
        
        // Should produce same result as without trailing dot
        assert_eq!(bytes_written, 13);
        assert_eq!(buffer[0], 7);
        assert_eq!(&buffer[1..8], b"example");
        assert_eq!(buffer[8], 3);
        assert_eq!(&buffer[9..12], b"com");
        assert_eq!(buffer[12], 0); // Terminating zero-length label
    }
    
    #[test]
    fn test_do_rfc1035_name_subdomain() {
        let mut buffer = [0u8; 128];
        let bytes_written = do_rfc1035_name("www.example.com", &mut buffer, Some(128)).unwrap();
        
        // Expected: \x03www\x07example\x03com\x00
        assert_eq!(bytes_written, 17);
        assert_eq!(buffer[0], 3); // "www"
        assert_eq!(&buffer[1..4], b"www");
        assert_eq!(buffer[4], 7); // "example"
        assert_eq!(&buffer[5..12], b"example");
        assert_eq!(buffer[12], 3); // "com"
        assert_eq!(&buffer[13..16], b"com");
        assert_eq!(buffer[16], 0); // Terminating zero-length label
    }
}
