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

//! Pattern matching utilities for DNS name validation and wildcard matching
//!
//! # Purpose
//!
//! This module implements DNS name validation according to RFC 1123 specifications and
//! provides glob-style pattern matching capabilities specifically designed for connection
//! tracking integration. The validation functions ensure DNS names conform to RFC 1123
//! requirements: 1-253 characters total length, labels of 1-63 characters, consisting of
//! alphanumeric characters and hyphens (not starting or ending with hyphens), with fully
//! qualified domain names containing at least two labels where the final label is not
//! fully numeric and not the "local" pseudo-TLD.
//!
//! The pattern matching functionality extends basic DNS name validation with wildcard
//! support, allowing the asterisk (*) character to match zero or more characters within
//! a label boundary. Wildcards never cross label boundaries (dots), enabling fine-grained
//! matching patterns like "*.example.com" (matches "api.example.com" but not
//! "api.us.example.com"). Up to two wildcards per label are permitted, with the constraint
//! that patterns must end with at least two literal (non-wildcard) labels for security.
//!
//! All functionality in this module is used for pattern-based connection marking in the
//! connection tracking subsystem.
//!
//! # Key Responsibilities
//!
//! - [`is_valid_dns_name()`] - Validates DNS names against RFC 1123 specifications
//! - [`is_valid_dns_name_pattern()`] - Validates DNS name patterns with wildcard support
//! - [`is_dns_name_matching_pattern()`] - Matches DNS names against wildcard patterns
//! - `is_string_matching_glob_pattern()` - Internal glob matching algorithm implementation
//!
//! # RFC Compliance
//!
//! Implements RFC 1123 Section 2.1 "Host Names and Numbers" with additional constraints
//! requiring fully qualified domain names (minimum 2 labels) and rejection of the "local"
//! pseudo-TLD commonly used for mDNS which should not be processed by DNS forwarders.
//!
//! # Thread Safety
//!
//! All functions in this module are re-entrant and safe for use in async contexts.
//! Functions operate only on provided parameters without accessing global state (except
//! for logging via tracing macros).

use tracing::debug;

#[cfg(debug_assertions)]
use tracing::error;

/// Match string against glob pattern with wildcard support
///
/// Implements efficient glob pattern matching allowing '*' wildcards that match zero or
/// more characters. The algorithm performs case-insensitive matching by converting both
/// value and pattern characters to uppercase during comparison. Uses a backtracking
/// approach optimized for common matching scenarios, as described by Russ Cox in
/// "Glob Matching Can Be Simple And Fast Too" (<https://research.swtch.com/glob>).
/// The implementation handles multiple wildcards efficiently without exponential
/// time complexity by maintaining restart positions for backtracking.
///
/// # Arguments
///
/// * `value` - String value to match
/// * `pattern` - Glob pattern containing optional '*' wildcards
///
/// # Returns
///
/// Returns `true` if the value matches the glob pattern, `false` otherwise.
///
/// # Notes
///
/// - Matching is case-insensitive: lowercase letters are converted to uppercase
/// - Wildcards match greedily but use backtracking to find valid matches
/// - This function is internal and called exclusively by [`is_dns_name_matching_pattern()`]
///   for label-by-label matching
///
/// # Algorithm Attribution
///
/// Based on Russ Cox's simplified glob matching approach which avoids recursive
/// backtracking and exponential time complexity.
///
/// # Thread Safety
///
/// This function is re-entrant and thread-safe. It operates only on the provided
/// parameters using local stack variables without accessing any global state or
/// modifying the input parameters.
///
/// # Examples
///
/// ```ignore
/// let name = "api-prod";
/// let pattern = "api-*";
/// if is_string_matching_glob_pattern(name, pattern) {
///     println!("Match found");
/// }
/// ```
fn is_string_matching_glob_pattern(value: &str, pattern: &str) -> bool {
    let value_bytes = value.as_bytes();
    let pattern_bytes = pattern.as_bytes();
    let num_value_bytes = value_bytes.len();
    let num_pattern_bytes = pattern_bytes.len();
    
    let mut value_index = 0;
    let mut next_value_index = 0;
    let mut pattern_index = 0;
    let mut next_pattern_index = 0;
    
    while value_index < num_value_bytes || pattern_index < num_pattern_bytes {
        if pattern_index < num_pattern_bytes {
            let pattern_character = (pattern_bytes[pattern_index] as char).to_ascii_uppercase();
            
            if pattern_character == '*' {
                // zero-or-more-character wildcard
                // Try to match at value_index, otherwise restart at value_index + 1 next.
                next_pattern_index = pattern_index;
                pattern_index += 1;
                if value_index < num_value_bytes {
                    next_value_index = value_index + 1;
                } else {
                    next_value_index = 0;
                }
                continue;
            }
            // ordinary character
            if value_index < num_value_bytes {
                let value_character = (value_bytes[value_index] as char).to_ascii_uppercase();
                if value_character == pattern_character {
                    pattern_index += 1;
                    value_index += 1;
                    continue;
                }
            }
        }
        
        if next_value_index != 0 {
            pattern_index = next_pattern_index;
            value_index = next_value_index;
            continue;
        }
        
        return false;
    }
    
    true
}

/// Validate DNS name conformance to RFC 1123
///
/// Validates that a string represents a properly formatted DNS name according to RFC 1123
/// specifications. The algorithm iterates through the string character-by-character,
/// validating label boundaries, character constraints, and overall structure. Each label
/// is validated for length (1-63 characters), valid character set (alphanumeric and hyphen),
/// and proper start/end characters (no leading or trailing hyphens). The complete name
/// must be 1-253 characters, fully qualified (minimum 2 labels), with a non-numeric
/// final label that is not the "local" pseudo-TLD.
///
/// # Arguments
///
/// * `value` - String value to validate as DNS name
///
/// # Returns
///
/// Returns `true` if the string is a valid RFC 1123 DNS name, `false` otherwise.
///
/// # RFC 1123 Requirements
///
/// - Total length: 1-253 characters
/// - Label length: 1-63 characters each
/// - Character set: ASCII letters (a-z, A-Z), digits (0-9), hyphen (-)
/// - Label constraints: No leading or trailing hyphens
/// - Minimum structure: At least 2 labels (fully qualified domain name)
/// - Final label: Not fully numeric (prevents IP address confusion)
/// - Pseudo-TLD: "local" pseudo-TLD is rejected (case-insensitive)
///
/// # Notes
///
/// - Empty labels (consecutive dots or leading/trailing dots) are rejected
/// - Validation failures are logged at DEBUG level with specific reasons
///
/// # Examples of Valid Names
///
/// - "example.com"
/// - "api.example.com"
/// - "my-server.example.org"
///
/// # Examples of Invalid Names
///
/// - "ipcamera" (single label)
/// - "ipcamera.local" (local TLD)
/// - "8.8.8.8" (numeric final label)
/// - "example..com" (empty label)
/// - "-test.com" (hyphen start)
///
/// # Thread Safety
///
/// This function is re-entrant and safe for use in async contexts.
/// Operates only on the provided parameter using local stack variables.
///
/// # Examples
///
/// ```ignore
/// if is_valid_dns_name("example.com") {
///     println!("Valid DNS name");
/// }
/// if !is_valid_dns_name("8.8.8.8") {
///     println!("Invalid: numeric final label");
/// }
/// ```
pub fn is_valid_dns_name(value: &str) -> bool {
    let mut num_bytes = 0;
    let mut num_labels = 0;
    let mut label_start: Option<usize> = None;
    let mut is_label_numeric = true;
    let chars: Vec<char> = value.chars().collect();
    
    let mut i = 0;
    loop {
        let c = if i < chars.len() { Some(chars[i]) } else { None };
        
        // Validate character
        if let Some(ch) = c {
            if ch != '-' && ch != '.' && !ch.is_ascii_digit() && !ch.is_ascii_alphabetic() {
                debug!("Invalid DNS name: Invalid character {}.", ch);
                return false;
            }
            num_bytes += 1;
        }
        
        // Start of label processing
        if label_start.is_none() {
            if c.is_none() || c == Some('.') {
                debug!("Invalid DNS name: Empty label.");
                return false;
            }
            if c == Some('-') {
                debug!("Invalid DNS name: Label starts with hyphen.");
                return false;
            }
            label_start = Some(i);
        }
        
        // Within label processing
        if let Some(ch) = c {
            if ch != '.'
                && !ch.is_ascii_digit() {
                    is_label_numeric = false;
                }
        }
        
        // End of label processing
        if c.is_none() || c == Some('.') {
            if let Some(start_idx) = label_start {
                // Check for trailing hyphen
                if i > 0 && chars[i - 1] == '-' {
                    debug!("Invalid DNS name: Label ends with hyphen.");
                    return false;
                }
                
                let num_label_bytes = i - start_idx;
                if num_label_bytes > 63 {
                    debug!("Invalid DNS name: Label is too long ({}).", num_label_bytes);
                    return false;
                }
                
                num_labels += 1;
                
                // End of entire name processing
                if c.is_none() {
                    if num_labels < 2 {
                        debug!("Invalid DNS name: Not enough labels ({}).", num_labels);
                        return false;
                    }
                    if is_label_numeric {
                        debug!("Invalid DNS name: Final label is fully numeric.");
                        return false;
                    }
                    
                    // Check for "local" pseudo-TLD (case-insensitive)
                    if num_label_bytes == 5 {
                        let label: String = chars[start_idx..i].iter().collect();
                        if label.eq_ignore_ascii_case("local") {
                            debug!("Invalid DNS name: \"local\" pseudo-TLD.");
                            return false;
                        }
                    }
                    
                    if !(1..=253).contains(&num_bytes) {
                        debug!("DNS name has invalid length ({}).", num_bytes);
                        return false;
                    }
                    
                    return true;
                }
                
                label_start = None;
                is_label_numeric = true;
            }
        }
        
        if c.is_none() {
            break;
        }
        i += 1;
    }
    
    false
}

/// Validate DNS name pattern with wildcard support
///
/// Validates that a string represents a properly formatted DNS name pattern according to
/// RFC 1123 DNS name requirements extended with wildcard support. The algorithm performs
/// similar validation to [`is_valid_dns_name()`] but additionally permits asterisk (*)
/// wildcard characters within labels. Wildcards are constrained to a maximum of two per
/// label and must not appear in the final two labels (security requirement to prevent
/// overly broad matching like "*.com"). Wildcards never match across label boundaries
/// (dots), enabling precise subdomain matching. The pattern length calculation excludes
/// wildcard characters when validating against the 253-character limit.
///
/// # Arguments
///
/// * `value` - String value to validate as DNS name pattern
///
/// # Returns
///
/// Returns `true` if the string is a valid DNS name pattern with proper wildcard
/// constraints, `false` otherwise.
///
/// # Wildcard Constraints
///
/// - Maximum 2 wildcards per label (e.g., "*-prod-*" is valid, "*-*-*" is not)
/// - Wildcards never match dots (label boundaries)
/// - Pattern must end with 2 literal labels (no wildcards in final two labels)
/// - Wildcard characters excluded from 253-character length calculation
///
/// # RFC 1123 Constraints
///
/// Inherits all constraints from [`is_valid_dns_name()`]:
/// - Label length 1-63 characters (excluding wildcards)
/// - Valid characters: alphanumeric, hyphen, asterisk
/// - No leading/trailing hyphens in labels
/// - Minimum 2 labels, non-numeric final label, no "local" pseudo-TLD
///
/// # Valid Pattern Examples
///
/// - "*.example.com" (matches any single-label subdomain)
/// - "video*.example.com" (matches video1, video-prod, etc.)
/// - "*-prod-*.example.com" (matches app1-prod-east, api-prod-west, etc.)
/// - "api*.*.example.com" (matches api1.us.example.com, api-test.staging.example.com)
///
/// # Invalid Pattern Examples
///
/// - "*.com" (wildcard in final two labels)
/// - "*" (single label, wildcard in final)
/// - "***test.example.com" (more than 2 wildcards per label)
/// - "ipcamera.local" (local pseudo-TLD)
///
/// # Thread Safety
///
/// This function is re-entrant and safe for async contexts.
/// Operates only on the provided parameter using local stack variables.
///
/// # Examples
///
/// ```ignore
/// if is_valid_dns_name_pattern("*.example.com") {
///     println!("Valid pattern");
/// }
/// if !is_valid_dns_name_pattern("*.com") {
///     println!("Invalid: wildcard in final two labels");
/// }
/// ```
pub fn is_valid_dns_name_pattern(value: &str) -> bool {
    let mut num_bytes = 0;
    let mut num_labels = 0;
    let mut label_start: Option<usize> = None;
    let mut is_label_numeric = true;
    let mut num_wildcards = 0;
    let mut previous_label_has_wildcard = true;
    let chars: Vec<char> = value.chars().collect();
    
    let mut i = 0;
    loop {
        let c = if i < chars.len() { Some(chars[i]) } else { None };
        
        // Validate character (now including asterisk)
        if let Some(ch) = c {
            if ch != '*' && ch != '-' && ch != '.' && !ch.is_ascii_digit() && !ch.is_ascii_alphabetic() {
                debug!("Invalid DNS name pattern: Invalid character {}.", ch);
                return false;
            }
            if ch != '*' {
                num_bytes += 1;
            }
        }
        
        // Start of label processing
        if label_start.is_none() {
            if c.is_none() || c == Some('.') {
                debug!("Invalid DNS name pattern: Empty label.");
                return false;
            }
            if c == Some('-') {
                debug!("Invalid DNS name pattern: Label starts with hyphen.");
                return false;
            }
            label_start = Some(i);
        }
        
        // Within label processing
        if let Some(ch) = c {
            if ch != '.' {
                if !ch.is_ascii_digit() {
                    is_label_numeric = false;
                }
                if ch == '*' {
                    if num_wildcards >= 2 {
                        debug!("Invalid DNS name pattern: Wildcard character used more than twice per label.");
                        return false;
                    }
                    num_wildcards += 1;
                }
            }
        }
        
        // End of label processing
        if c.is_none() || c == Some('.') {
            if let Some(start_idx) = label_start {
                // Check for trailing hyphen
                if i > 0 && chars[i - 1] == '-' {
                    debug!("Invalid DNS name pattern: Label ends with hyphen.");
                    return false;
                }
                
                let num_label_bytes = (i - start_idx) - num_wildcards;
                if num_label_bytes > 63 {
                    debug!("Invalid DNS name pattern: Label is too long ({}).", num_label_bytes);
                    return false;
                }
                
                num_labels += 1;
                
                // End of entire pattern processing
                if c.is_none() {
                    if num_labels < 2 {
                        debug!("Invalid DNS name pattern: Not enough labels ({}).", num_labels);
                        return false;
                    }
                    if num_wildcards != 0 || previous_label_has_wildcard {
                        debug!("Invalid DNS name pattern: Wildcard within final two labels.");
                        return false;
                    }
                    if is_label_numeric {
                        debug!("Invalid DNS name pattern: Final label is fully numeric.");
                        return false;
                    }
                    
                    // Check for "local" pseudo-TLD (case-insensitive)
                    if num_label_bytes == 5 {
                        let label: String = chars[start_idx..i].iter().collect();
                        if label.eq_ignore_ascii_case("local") {
                            debug!("Invalid DNS name pattern: \"local\" pseudo-TLD.");
                            return false;
                        }
                    }
                    
                    if !(1..=253).contains(&num_bytes) {
                        debug!("DNS name pattern has invalid length after removing wildcards ({}).", num_bytes);
                        return false;
                    }
                    
                    return true;
                }
                
                label_start = None;
                is_label_numeric = true;
                previous_label_has_wildcard = num_wildcards != 0;
                num_wildcards = 0;
            }
        }
        
        if c.is_none() {
            break;
        }
        i += 1;
    }
    
    false
}

/// Match DNS name against wildcard pattern
///
/// Determines whether a DNS name matches a DNS name pattern by performing label-by-label
/// comparison from left to right. The algorithm splits both the name and pattern into
/// labels delimited by dots, then invokes [`is_string_matching_glob_pattern()`] for each
/// corresponding label pair. Matching succeeds only if all label pairs match and both
/// name and pattern have the same number of labels (complete traversal). This ensures
/// wildcards never match across label boundaries, providing precise subdomain matching
/// control for connection tracking mark assignment.
///
/// # Arguments
///
/// * `name` - Valid DNS name to match (should pass [`is_valid_dns_name()`])
/// * `pattern` - Valid DNS name pattern (should pass [`is_valid_dns_name_pattern()`])
///
/// # Returns
///
/// Returns `true` if the DNS name matches the pattern, `false` if no match.
///
/// # Notes
///
/// - Matching is performed label-by-label from left to right
/// - Each label in the name is matched against the corresponding label in the pattern
///   using case-insensitive glob matching
/// - Wildcards in pattern labels match zero or more characters within that label only
///   and never cross dot boundaries
/// - The function assumes both name and pattern have been pre-validated by their
///   respective validation functions
///
/// # Matching Examples
///
/// - "api.example.com" matches "*.example.com" ✓
/// - "api.us.example.com" does NOT match "*.example.com" (label count mismatch) ✗
/// - "video1.example.com" matches "video*.example.com" ✓
/// - "app1-prod-east.example.com" matches "*-prod-*.example.com" ✓
///
/// # Thread Safety
///
/// This function is fully re-entrant and thread-safe. It operates exclusively on the
/// provided parameters using local stack variables without accessing any global state.
/// Can be safely called concurrently from multiple execution contexts.
///
/// # Examples
///
/// ```ignore
/// let name = "api.example.com";
/// let pattern = "*.example.com";
/// if is_valid_dns_name(name) && is_valid_dns_name_pattern(pattern) {
///     if is_dns_name_matching_pattern(name, pattern) {
///         println!("Match found");
///     }
/// }
/// ```
pub fn is_dns_name_matching_pattern(name: &str, pattern: &str) -> bool {
    // In debug builds, log precondition violations
    #[cfg(debug_assertions)]
    {
        if !is_valid_dns_name(name) {
            error!("is_dns_name_matching_pattern: name parameter is not a valid DNS name");
        }
        if !is_valid_dns_name_pattern(pattern) {
            error!("is_dns_name_matching_pattern: pattern parameter is not a valid DNS name pattern");
        }
    }
    
    let mut name_iter = name.split('.');
    let mut pattern_iter = pattern.split('.');
    
    loop {
        match (name_iter.next(), pattern_iter.next()) {
            (Some(name_label), Some(pattern_label)) => {
                if !is_string_matching_glob_pattern(name_label, pattern_label) {
                    return false;
                }
            }
            (None, None) => {
                // Both exhausted at the same time - perfect match
                return true;
            }
            _ => {
                // One exhausted before the other - label count mismatch
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for is_string_matching_glob_pattern
    
    #[test]
    fn test_glob_exact_match() {
        assert!(is_string_matching_glob_pattern("api-prod", "api-prod"));
        assert!(is_string_matching_glob_pattern("test", "test"));
    }
    
    #[test]
    fn test_glob_case_insensitive() {
        assert!(is_string_matching_glob_pattern("API", "api"));
        assert!(is_string_matching_glob_pattern("api", "API"));
        assert!(is_string_matching_glob_pattern("TeSt", "tEsT"));
    }
    
    #[test]
    fn test_glob_wildcard_prefix() {
        assert!(is_string_matching_glob_pattern("api-prod", "api-*"));
        assert!(is_string_matching_glob_pattern("api-", "api-*"));
        assert!(is_string_matching_glob_pattern("api-staging-west", "api-*"));
    }
    
    #[test]
    fn test_glob_wildcard_suffix() {
        assert!(is_string_matching_glob_pattern("prod-api", "*-api"));
        assert!(is_string_matching_glob_pattern("-api", "*-api"));
    }
    
    #[test]
    fn test_glob_wildcard_middle() {
        assert!(is_string_matching_glob_pattern("api-prod-east", "api-*-east"));
        assert!(is_string_matching_glob_pattern("api-staging-west", "*-staging-*"));
    }
    
    #[test]
    fn test_glob_multiple_wildcards() {
        assert!(is_string_matching_glob_pattern("app1-prod-east", "*-prod-*"));
        assert!(is_string_matching_glob_pattern("api-prod-west", "*-prod-*"));
    }
    
    #[test]
    fn test_glob_no_match() {
        assert!(!is_string_matching_glob_pattern("api-prod", "api-staging"));
        assert!(!is_string_matching_glob_pattern("test", "staging"));
    }
    
    #[test]
    fn test_glob_empty_strings() {
        assert!(is_string_matching_glob_pattern("", ""));
        assert!(is_string_matching_glob_pattern("", "*"));
        assert!(!is_string_matching_glob_pattern("test", ""));
    }

    // Tests for is_valid_dns_name
    
    #[test]
    fn test_valid_dns_names() {
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("api.example.com"));
        assert!(is_valid_dns_name("my-server.example.org"));
        assert!(is_valid_dns_name("test-123.example.net"));
    }
    
    #[test]
    fn test_invalid_single_label() {
        assert!(!is_valid_dns_name("ipcamera"));
        assert!(!is_valid_dns_name("localhost"));
    }
    
    #[test]
    fn test_invalid_local_tld() {
        assert!(!is_valid_dns_name("ipcamera.local"));
        assert!(!is_valid_dns_name("test.LOCAL"));
        assert!(!is_valid_dns_name("device.LoCaL"));
    }
    
    #[test]
    fn test_invalid_numeric_final_label() {
        assert!(!is_valid_dns_name("example.123"));
        assert!(!is_valid_dns_name("8.8.8.8"));
    }
    
    #[test]
    fn test_invalid_empty_label() {
        assert!(!is_valid_dns_name("example..com"));
        assert!(!is_valid_dns_name(".example.com"));
        assert!(!is_valid_dns_name("example.com."));
    }
    
    #[test]
    fn test_invalid_hyphen_position() {
        assert!(!is_valid_dns_name("-test.example.com"));
        assert!(!is_valid_dns_name("test-.example.com"));
        assert!(!is_valid_dns_name("test.-example.com"));
        assert!(!is_valid_dns_name("test.example-.com"));
    }
    
    #[test]
    fn test_invalid_character() {
        assert!(!is_valid_dns_name("test_123.example.com"));
        assert!(!is_valid_dns_name("test@example.com"));
        assert!(!is_valid_dns_name("test.exam ple.com"));
    }
    
    #[test]
    fn test_valid_hyphen_usage() {
        assert!(is_valid_dns_name("my-api-server.example.com"));
        assert!(is_valid_dns_name("test-123-prod.example.net"));
    }
    
    #[test]
    fn test_label_length_limits() {
        // Valid: 63 character label
        let label_63 = "a".repeat(63);
        assert!(is_valid_dns_name(&format!("{}.com", label_63)));
        
        // Invalid: 64 character label
        let label_64 = "a".repeat(64);
        assert!(!is_valid_dns_name(&format!("{}.com", label_64)));
    }
    
    #[test]
    fn test_total_length_limits() {
        // Valid: 253 characters total (with valid label lengths <= 63)
        // Create a name with multiple 63-char labels to reach 253 total
        // 63 + 1 (dot) + 63 + 1 (dot) + 63 + 1 (dot) + 61 = 253
        let long_name = format!("{}.{}.{}.{}", 
            "a".repeat(63), 
            "b".repeat(63), 
            "c".repeat(63), 
            "d".repeat(61));
        assert_eq!(long_name.len(), 253);
        assert!(is_valid_dns_name(&long_name));
        
        // Invalid: 254 characters total
        let too_long = format!("{}.{}.{}.{}", 
            "a".repeat(63), 
            "b".repeat(63), 
            "c".repeat(63), 
            "d".repeat(62));
        assert_eq!(too_long.len(), 254);
        assert!(!is_valid_dns_name(&too_long));
    }

    // Tests for is_valid_dns_name_pattern
    
    #[test]
    fn test_valid_dns_patterns() {
        assert!(is_valid_dns_name_pattern("*.example.com"));
        assert!(is_valid_dns_name_pattern("video*.example.com"));
        assert!(is_valid_dns_name_pattern("*-prod-*.example.com"));
        assert!(is_valid_dns_name_pattern("api*.*.example.com"));
    }
    
    #[test]
    fn test_invalid_wildcard_in_final_two_labels() {
        assert!(!is_valid_dns_name_pattern("*.com"));
        assert!(!is_valid_dns_name_pattern("test.*.com"));
        assert!(!is_valid_dns_name_pattern("example.*"));
    }
    
    #[test]
    fn test_invalid_too_many_wildcards_per_label() {
        assert!(!is_valid_dns_name_pattern("***test.example.com"));
        assert!(!is_valid_dns_name_pattern("*-*-*.example.com"));
    }
    
    #[test]
    fn test_valid_two_wildcards_per_label() {
        assert!(is_valid_dns_name_pattern("*-prod-*.example.com"));
        assert!(is_valid_dns_name_pattern("api*-*.example.com"));
    }
    
    #[test]
    fn test_pattern_inherits_dns_name_rules() {
        // Invalid due to local TLD
        assert!(!is_valid_dns_name_pattern("*.local"));
        
        // Invalid due to single label
        assert!(!is_valid_dns_name_pattern("*"));
        
        // Invalid due to hyphen position
        assert!(!is_valid_dns_name_pattern("-*.example.com"));
        assert!(!is_valid_dns_name_pattern("*-.example.com"));
    }
    
    #[test]
    fn test_pattern_length_excludes_wildcards() {
        // Pattern with wildcards should still be valid if length without wildcards is valid
        // Use 2 wildcards per label (max allowed) in first label
        // Each label must be <= 63 chars (excluding wildcards)
        // Build a pattern with multiple labels to test length calculation
        let pattern_with_wildcards = format!("*-prod-*.{}.{}.{}", 
            "a".repeat(60), 
            "b".repeat(60), 
            "c".repeat(60));
        // Length calculation without wildcards: 
        // First label: "-prod-" (6 chars, 2 wildcards excluded)
        // Second label: 60 a's
        // Third label: 60 b's  
        // Fourth label: 60 c's
        // Dots: 3
        // Total: 6 + 60 + 60 + 60 + 3 = 189 chars (well within 253 limit)
        // The wildcards are excluded from length count
        assert!(is_valid_dns_name_pattern(&pattern_with_wildcards));
    }

    // Tests for is_dns_name_matching_pattern
    
    #[test]
    fn test_exact_match_no_wildcard() {
        assert!(is_dns_name_matching_pattern("example.com", "example.com"));
        assert!(is_dns_name_matching_pattern("api.example.com", "api.example.com"));
    }
    
    #[test]
    fn test_single_wildcard_label() {
        assert!(is_dns_name_matching_pattern("api.example.com", "*.example.com"));
        assert!(is_dns_name_matching_pattern("www.example.com", "*.example.com"));
        
        // Label count mismatch
        assert!(!is_dns_name_matching_pattern("api.us.example.com", "*.example.com"));
    }
    
    #[test]
    fn test_wildcard_within_label() {
        assert!(is_dns_name_matching_pattern("video1.example.com", "video*.example.com"));
        assert!(is_dns_name_matching_pattern("video-prod.example.com", "video*.example.com"));
        assert!(!is_dns_name_matching_pattern("audio1.example.com", "video*.example.com"));
    }
    
    #[test]
    fn test_multiple_wildcards() {
        assert!(is_dns_name_matching_pattern("app1-prod-east.example.com", "*-prod-*.example.com"));
        assert!(is_dns_name_matching_pattern("api-prod-west.example.com", "*-prod-*.example.com"));
        assert!(!is_dns_name_matching_pattern("app1-staging-east.example.com", "*-prod-*.example.com"));
    }
    
    #[test]
    fn test_wildcards_in_multiple_labels() {
        assert!(is_dns_name_matching_pattern("api1.us.example.com", "api*.*.example.com"));
        assert!(is_dns_name_matching_pattern("api-test.staging.example.com", "api*.*.example.com"));
    }
    
    #[test]
    fn test_case_insensitive_matching() {
        assert!(is_dns_name_matching_pattern("API.EXAMPLE.COM", "*.example.com"));
        assert!(is_dns_name_matching_pattern("api.example.com", "*.EXAMPLE.COM"));
        assert!(is_dns_name_matching_pattern("Video1.Example.Com", "video*.example.com"));
    }
    
    #[test]
    fn test_no_match_different_structure() {
        assert!(!is_dns_name_matching_pattern("api.example.com", "www.example.com"));
        assert!(!is_dns_name_matching_pattern("api.example.org", "*.example.com"));
    }
}
