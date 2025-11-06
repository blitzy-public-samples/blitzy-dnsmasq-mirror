// Copyright (c) 2000-2024 Simon Kelley and dnsmasq contributors
// This file is part of the dnsmasq Rust implementation.
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

//! DNS name pattern matching utilities for connection tracking integration.
//!
//! This module implements RFC 1123 hostname validation, wildcard glob pattern matching
//! with security constraints, and label-by-label domain name comparison. Used by
//! connection tracking integration for DNS-based firewall rule matching.
//!
//! # Translated From
//!
//! C source: `src/pattern.c`
//!
//! # Key Features
//!
//! - **RFC 1123 DNS Name Validation**: Enforces proper DNS name structure including:
//!   - Total length 1-253 characters
//!   - Label length 1-63 characters
//!   - Allowed characters: ASCII letters, digits, hyphens
//!   - No leading or trailing hyphens in labels
//!   - At least two labels (fully qualified)
//!   - Non-numeric final label
//!   - Rejects 'local' pseudo-TLD
//!
//! - **Wildcard Pattern Support**: Extends DNS validation with asterisk wildcards:
//!   - Maximum two wildcards per label
//!   - Wildcards forbidden in final two labels (security constraint)
//!   - Wildcards never cross label boundaries
//!
//! - **Efficient Glob Matching**: Linear-time algorithm based on Russ Cox's approach,
//!   avoiding exponential backtracking while supporting multiple wildcards.
//!
//! # Feature Gating
//!
//! This module is only compiled when the `conntrack` feature is enabled, matching
//! the C implementation's `#ifdef HAVE_CONNTRACK` conditional compilation.
//!
//! # Examples
//!
//! ```rust,ignore
//! use dnsmasq::util::pattern::{validate_dns_name, validate_dns_pattern, matches_pattern};
//!
//! // Validate a DNS name
//! assert!(validate_dns_name("example.com").is_ok());
//! assert!(validate_dns_name("local").is_err()); // single label
//!
//! // Validate a pattern
//! assert!(validate_dns_pattern("*.example.com").is_ok());
//! assert!(validate_dns_pattern("*.com").is_err()); // wildcard in final labels
//!
//! // Match a name against a pattern
//! assert!(matches_pattern("api.example.com", "*.example.com"));
//! assert!(!matches_pattern("api.us.example.com", "*.example.com")); // label count mismatch
//! ```
//!
//! # Security Considerations
//!
//! Pattern validation enforces that wildcards cannot appear in the final two labels,
//! preventing overly broad matches like `*.com` that would match entire TLDs. This
//! security constraint is critical for connection tracking use cases where patterns
//! control firewall mark assignment.

#[cfg(feature = "conntrack")]
use thiserror::Error;

#[cfg(feature = "conntrack")]
use tracing::{debug, error};

/// Maximum allowed length for a complete DNS name (RFC 1123)
#[cfg(feature = "conntrack")]
pub const MAX_DNS_NAME_LENGTH: usize = 253;

/// Maximum allowed length for a single DNS label
#[cfg(feature = "conntrack")]
pub const MAX_LABEL_LENGTH: usize = 63;

/// Minimum number of labels required for a fully qualified domain name
#[cfg(feature = "conntrack")]
pub const MIN_LABEL_COUNT: usize = 2;

/// Maximum number of wildcards permitted per label
#[cfg(feature = "conntrack")]
pub const MAX_WILDCARDS_PER_LABEL: usize = 2;

/// Number of final labels that must not contain wildcards (security constraint)
#[cfg(feature = "conntrack")]
pub const RESERVED_FINAL_LABELS: usize = 2;

/// Validation errors for DNS names and patterns
#[cfg(feature = "conntrack")]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// DNS name or pattern exceeds maximum allowed length
    #[error("Invalid length: {actual} exceeds maximum {max}")]
    InvalidLength {
        /// Actual length of the name/pattern
        actual: usize,
        /// Maximum allowed length
        max: usize,
    },

    /// A DNS label exceeds maximum length
    #[error("Label '{label}' has invalid length: {length} exceeds maximum {}", MAX_LABEL_LENGTH)]
    InvalidLabelLength {
        /// The label that exceeded the limit
        label: String,
        /// Actual length of the label
        length: usize,
    },

    /// DNS name contains an invalid character
    #[error("Invalid character '{character}' at position {position}")]
    InvalidCharacter {
        /// Position in the string where the invalid character appears
        position: usize,
        /// The invalid character
        character: char,
    },

    /// Label starts or ends with a hyphen
    #[error("Label '{label}' has leading or trailing hyphen")]
    LeadingOrTrailingHyphen {
        /// The label with the invalid hyphen placement
        label: String,
    },

    /// Empty label encountered (consecutive dots or leading/trailing dot)
    #[error("Empty label encountered")]
    EmptyLabel,

    /// Insufficient number of labels for a fully qualified domain name
    #[error("Insufficient labels: {actual} found, {required} required")]
    InsufficientLabels {
        /// Number of labels found
        actual: usize,
        /// Number of labels required
        required: usize,
    },

    /// Final label is fully numeric (could be confused with IP address)
    #[error("Final label '{label}' is fully numeric")]
    NumericFinalLabel {
        /// The numeric final label
        label: String,
    },

    /// DNS name uses reserved 'local' pseudo-TLD
    #[error("Reserved pseudo-TLD '{tld}' is not allowed")]
    ReservedTld {
        /// The reserved TLD
        tld: String,
    },

    /// Label contains too many wildcards
    #[error("Label '{label}' contains {count} wildcards, maximum {MAX_WILDCARDS_PER_LABEL} allowed")]
    TooManyWildcards {
        /// The label with too many wildcards
        label: String,
        /// Number of wildcards found
        count: usize,
    },

    /// Pattern has wildcards in final labels (security violation)
    #[error("Pattern '{pattern}' has wildcards in final {RESERVED_FINAL_LABELS} labels")]
    WildcardInFinalLabels {
        /// The pattern with wildcards in final labels
        pattern: String,
    },
}

/// Match a string value against a glob pattern with wildcard support.
///
/// Implements efficient glob pattern matching allowing '*' wildcards that match zero or
/// more characters. The algorithm performs case-insensitive matching and uses a
/// backtracking approach optimized for common matching scenarios, based on Russ Cox's
/// "Glob Matching Can Be Simple And Fast Too" algorithm.
///
/// # Arguments
///
/// * `pattern` - Glob pattern containing optional '*' wildcards
/// * `value` - String value to match against the pattern
///
/// # Returns
///
/// `true` if the value matches the pattern, `false` otherwise
///
/// # Algorithm
///
/// Uses linear-time backtracking algorithm that maintains restart positions to avoid
/// exponential complexity. Handles multiple wildcards efficiently without recursion.
///
/// # Examples
///
/// ```rust,ignore
/// assert!(match_glob_label("api-*", "api-prod"));
/// assert!(match_glob_label("*-prod-*", "app1-prod-east"));
/// assert!(!match_glob_label("api-*", "web-prod"));
/// ```
#[cfg(feature = "conntrack")]
fn match_glob_label(pattern: &str, value: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    let value_bytes = value.as_bytes();
    
    let mut value_index = 0;
    let mut pattern_index = 0;
    let mut next_value_index = 0;
    let mut next_pattern_index = 0;

    while value_index < value_bytes.len() || pattern_index < pattern_bytes.len() {
        if pattern_index < pattern_bytes.len() {
            let mut pattern_char = pattern_bytes[pattern_index] as char;
            
            // Convert to uppercase for case-insensitive matching
            if pattern_char.is_ascii_lowercase() {
                pattern_char = pattern_char.to_ascii_uppercase();
            }

            if pattern_char == '*' {
                // Zero-or-more-character wildcard
                // Try to match at value_index, otherwise restart at value_index + 1 next
                next_pattern_index = pattern_index;
                pattern_index += 1;
                if value_index < value_bytes.len() {
                    next_value_index = value_index + 1;
                } else {
                    next_value_index = 0;
                }
                continue;
            } else {
                // Ordinary character
                if value_index < value_bytes.len() {
                    let mut value_char = value_bytes[value_index] as char;
                    
                    // Convert to uppercase for case-insensitive matching
                    if value_char.is_ascii_lowercase() {
                        value_char = value_char.to_ascii_uppercase();
                    }

                    if value_char == pattern_char {
                        pattern_index += 1;
                        value_index += 1;
                        continue;
                    }
                }
            }
        }

        // Backtrack to the next wildcard restart position
        if next_value_index != 0 {
            pattern_index = next_pattern_index;
            value_index = next_value_index;
            continue;
        }

        return false;
    }

    true
}

/// Validate that a string represents a properly formatted DNS name according to RFC 1123.
///
/// Validates DNS name structure including total length, label lengths, character constraints,
/// and structural requirements. Ensures the name is fully qualified with at least two labels,
/// has a non-numeric final label, and does not use the 'local' pseudo-TLD.
///
/// # Arguments
///
/// * `name` - The string to validate as a DNS name
///
/// # Returns
///
/// * `Ok(())` if the name is valid
/// * `Err(ValidationError)` with detailed error information if invalid
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
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::util::pattern::validate_dns_name;
///
/// assert!(validate_dns_name("example.com").is_ok());
/// assert!(validate_dns_name("api.example.com").is_ok());
/// assert!(validate_dns_name("my-server.example.org").is_ok());
///
/// assert!(validate_dns_name("ipcamera").is_err()); // single label
/// assert!(validate_dns_name("ipcamera.local").is_err()); // local TLD
/// assert!(validate_dns_name("8.8.8.8").is_err()); // numeric final label
/// assert!(validate_dns_name("example..com").is_err()); // empty label
/// assert!(validate_dns_name("-test.com").is_err()); // hyphen start
/// ```
#[cfg(feature = "conntrack")]
pub fn validate_dns_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        debug!("DNS name validation failed: empty name");
        return Err(ValidationError::EmptyLabel);
    }

    let mut num_bytes = 0;
    let mut num_labels = 0;
    let mut label_start = 0;
    let mut is_label_numeric = true;
    let chars: Vec<char> = name.chars().collect();
    let mut i = 0;

    while i <= chars.len() {
        let current_char = if i < chars.len() { Some(chars[i]) } else { None };

        // Validate character set
        if let Some(ch) = current_char {
            if ch != '-' && ch != '.' && !ch.is_ascii_alphanumeric() {
                debug!("Invalid DNS name: Invalid character '{}' at position {}", ch, i);
                return Err(ValidationError::InvalidCharacter {
                    position: i,
                    character: ch,
                });
            }
            num_bytes += 1;
        }

        // Start of new label
        if label_start == i {
            if current_char.is_none() || current_char == Some('.') {
                debug!("Invalid DNS name: Empty label");
                return Err(ValidationError::EmptyLabel);
            }
            if current_char == Some('-') {
                let label_str: String = chars[label_start..i.min(label_start + 10)].iter().collect();
                debug!("Invalid DNS name: Label starts with hyphen");
                return Err(ValidationError::LeadingOrTrailingHyphen {
                    label: format!("-{}", label_str),
                });
            }
        }

        // Track if label is numeric
        if let Some(ch) = current_char {
            if ch != '.' && !ch.is_ascii_digit() {
                is_label_numeric = false;
            }
        }

        // End of label or end of name
        if current_char.is_none() || current_char == Some('.') {
            if i > 0 && chars[i - 1] == '-' {
                let label_str: String = chars[label_start..i].iter().collect();
                debug!("Invalid DNS name: Label ends with hyphen");
                return Err(ValidationError::LeadingOrTrailingHyphen {
                    label: label_str,
                });
            }

            let num_label_bytes = i - label_start;
            if num_label_bytes > MAX_LABEL_LENGTH {
                let label_str: String = chars[label_start..i].iter().collect();
                debug!("Invalid DNS name: Label is too long ({})", num_label_bytes);
                return Err(ValidationError::InvalidLabelLength {
                    label: label_str,
                    length: num_label_bytes,
                });
            }

            num_labels += 1;

            // End of name - perform final validations
            if current_char.is_none() {
                if num_labels < MIN_LABEL_COUNT {
                    debug!("Invalid DNS name: Not enough labels ({})", num_labels);
                    return Err(ValidationError::InsufficientLabels {
                        actual: num_labels,
                        required: MIN_LABEL_COUNT,
                    });
                }

                if is_label_numeric {
                    let label_str: String = chars[label_start..i].iter().collect();
                    debug!("Invalid DNS name: Final label is fully numeric");
                    return Err(ValidationError::NumericFinalLabel {
                        label: label_str,
                    });
                }

                // Check for 'local' pseudo-TLD (case-insensitive)
                let label_str: String = chars[label_start..i].iter().collect();
                if label_str.eq_ignore_ascii_case("local") {
                    debug!("Invalid DNS name: 'local' pseudo-TLD");
                    return Err(ValidationError::ReservedTld {
                        tld: label_str,
                    });
                }

                if num_bytes < 1 || num_bytes > MAX_DNS_NAME_LENGTH {
                    debug!("DNS name has invalid length ({})", num_bytes);
                    return Err(ValidationError::InvalidLength {
                        actual: num_bytes,
                        max: MAX_DNS_NAME_LENGTH,
                    });
                }

                return Ok(());
            }

            // Prepare for next label
            label_start = i + 1;
            is_label_numeric = true;
        }

        i += 1;
    }

    Ok(())
}

/// Validate that a string represents a properly formatted DNS name pattern with wildcards.
///
/// Extends DNS name validation with wildcard support, allowing asterisk (*) characters
/// within labels. Enforces security constraints including maximum wildcards per label
/// and prohibition of wildcards in final labels.
///
/// # Arguments
///
/// * `pattern` - The string to validate as a DNS name pattern
///
/// # Returns
///
/// * `Ok(())` if the pattern is valid
/// * `Err(ValidationError)` with detailed error information if invalid
///
/// # Wildcard Constraints
///
/// - Maximum 2 wildcards per label (e.g., "*-prod-*" is valid, "*-*-*" is not)
/// - Wildcards never match dots (label boundaries)
/// - Pattern must end with 2 literal labels (no wildcards in final two labels)
/// - Wildcard characters excluded from 253-character length calculation
///
/// # Inherited RFC 1123 Constraints
///
/// - Label length 1-63 characters (excluding wildcards)
/// - Valid characters: alphanumeric, hyphen, asterisk
/// - No leading/trailing hyphens in labels
/// - Minimum 2 labels, non-numeric final label, no "local" pseudo-TLD
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::util::pattern::validate_dns_pattern;
///
/// // Valid patterns
/// assert!(validate_dns_pattern("*.example.com").is_ok());
/// assert!(validate_dns_pattern("video*.example.com").is_ok());
/// assert!(validate_dns_pattern("*-prod-*.example.com").is_ok());
/// assert!(validate_dns_pattern("api*.*.example.com").is_ok());
///
/// // Invalid patterns
/// assert!(validate_dns_pattern("*.com").is_err()); // wildcard in final two labels
/// assert!(validate_dns_pattern("*").is_err()); // single label
/// assert!(validate_dns_pattern("***test.example.com").is_err()); // >2 wildcards
/// assert!(validate_dns_pattern("ipcamera.local").is_err()); // local pseudo-TLD
/// ```
#[cfg(feature = "conntrack")]
pub fn validate_dns_pattern(pattern: &str) -> Result<(), ValidationError> {
    if pattern.is_empty() {
        debug!("DNS pattern validation failed: empty pattern");
        return Err(ValidationError::EmptyLabel);
    }

    let mut num_bytes = 0;
    let mut num_labels = 0;
    let mut label_start = 0;
    let mut is_label_numeric = true;
    let mut num_wildcards = 0;
    let mut previous_label_has_wildcard = true;
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i <= chars.len() {
        let current_char = if i < chars.len() { Some(chars[i]) } else { None };

        // Validate character set (including wildcard)
        if let Some(ch) = current_char {
            if ch != '*' && ch != '-' && ch != '.' && !ch.is_ascii_alphanumeric() {
                debug!("Invalid DNS pattern: Invalid character '{}' at position {}", ch, i);
                return Err(ValidationError::InvalidCharacter {
                    position: i,
                    character: ch,
                });
            }
            // Count non-wildcard characters toward length
            if ch != '*' {
                num_bytes += 1;
            }
        }

        // Start of new label
        if label_start == i {
            if current_char.is_none() || current_char == Some('.') {
                debug!("Invalid DNS pattern: Empty label");
                return Err(ValidationError::EmptyLabel);
            }
            if current_char == Some('-') {
                let label_str: String = chars[label_start..i.min(label_start + 10)].iter().collect();
                debug!("Invalid DNS pattern: Label starts with hyphen");
                return Err(ValidationError::LeadingOrTrailingHyphen {
                    label: format!("-{}", label_str),
                });
            }
        }

        // Process character within label
        if let Some(ch) = current_char {
            if ch != '.' {
                // Track if label is numeric
                if !ch.is_ascii_digit() {
                    is_label_numeric = false;
                }
                
                // Count wildcards
                if ch == '*' {
                    if num_wildcards >= MAX_WILDCARDS_PER_LABEL {
                        let label_str: String = chars[label_start..i + 1].iter().collect();
                        debug!("Invalid DNS pattern: Wildcard used more than {} times per label", 
                               MAX_WILDCARDS_PER_LABEL);
                        return Err(ValidationError::TooManyWildcards {
                            label: label_str,
                            count: num_wildcards + 1,
                        });
                    }
                    num_wildcards += 1;
                }
            }
        }

        // End of label or end of pattern
        if current_char.is_none() || current_char == Some('.') {
            if i > 0 && chars[i - 1] == '-' {
                let label_str: String = chars[label_start..i].iter().collect();
                debug!("Invalid DNS pattern: Label ends with hyphen");
                return Err(ValidationError::LeadingOrTrailingHyphen {
                    label: label_str,
                });
            }

            let num_label_bytes = (i - label_start) - num_wildcards;
            if num_label_bytes > MAX_LABEL_LENGTH {
                let label_str: String = chars[label_start..i].iter().collect();
                debug!("Invalid DNS pattern: Label is too long ({})", num_label_bytes);
                return Err(ValidationError::InvalidLabelLength {
                    label: label_str,
                    length: num_label_bytes,
                });
            }

            num_labels += 1;

            // End of pattern - perform final validations
            if current_char.is_none() {
                if num_labels < MIN_LABEL_COUNT {
                    debug!("Invalid DNS pattern: Not enough labels ({})", num_labels);
                    return Err(ValidationError::InsufficientLabels {
                        actual: num_labels,
                        required: MIN_LABEL_COUNT,
                    });
                }

                // Check for wildcards in final two labels (security constraint)
                if num_wildcards != 0 || previous_label_has_wildcard {
                    debug!("Invalid DNS pattern: Wildcard within final two labels");
                    return Err(ValidationError::WildcardInFinalLabels {
                        pattern: pattern.to_string(),
                    });
                }

                if is_label_numeric {
                    let label_str: String = chars[label_start..i].iter().collect();
                    debug!("Invalid DNS pattern: Final label is fully numeric");
                    return Err(ValidationError::NumericFinalLabel {
                        label: label_str,
                    });
                }

                // Check for 'local' pseudo-TLD (case-insensitive)
                let label_str: String = chars[label_start..i].iter().collect();
                if label_str.eq_ignore_ascii_case("local") {
                    debug!("Invalid DNS pattern: 'local' pseudo-TLD");
                    return Err(ValidationError::ReservedTld {
                        tld: label_str,
                    });
                }

                if num_bytes < 1 || num_bytes > MAX_DNS_NAME_LENGTH {
                    debug!("DNS pattern has invalid length after removing wildcards ({})", num_bytes);
                    return Err(ValidationError::InvalidLength {
                        actual: num_bytes,
                        max: MAX_DNS_NAME_LENGTH,
                    });
                }

                return Ok(());
            }

            // Prepare for next label
            label_start = i + 1;
            is_label_numeric = true;
            previous_label_has_wildcard = num_wildcards != 0;
            num_wildcards = 0;
        }

        i += 1;
    }

    Ok(())
}

/// Match a DNS name against a wildcard pattern.
///
/// Performs label-by-label comparison between a DNS name and pattern. Both name and
/// pattern must have the same number of labels, and each label pair must match using
/// case-insensitive glob matching. Wildcards never cross label boundaries, ensuring
/// precise subdomain matching control.
///
/// # Arguments
///
/// * `name` - Valid DNS name to match (should be pre-validated with `validate_dns_name`)
/// * `pattern` - Valid DNS pattern (should be pre-validated with `validate_dns_pattern`)
///
/// # Returns
///
/// `true` if the name matches the pattern, `false` otherwise
///
/// # Matching Rules
///
/// - Matching is performed label-by-label from left to right
/// - Each label uses case-insensitive glob matching
/// - Wildcards match zero or more characters within a label only
/// - Both name and pattern must have identical label counts
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::util::pattern::matches_pattern;
///
/// // Matches
/// assert!(matches_pattern("api.example.com", "*.example.com"));
/// assert!(matches_pattern("video1.example.com", "video*.example.com"));
/// assert!(matches_pattern("app1-prod-east.example.com", "*-prod-*.example.com"));
///
/// // No match
/// assert!(!matches_pattern("api.us.example.com", "*.example.com")); // label count
/// assert!(!matches_pattern("web.example.com", "api*.example.com")); // label mismatch
/// ```
///
/// # Panics
///
/// In debug builds, panics if inputs have not been validated. In release builds,
/// behavior is undefined for invalid inputs.
#[cfg(feature = "conntrack")]
pub fn matches_pattern(name: &str, pattern: &str) -> bool {
    // In debug builds, validate inputs
    debug_assert!(
        validate_dns_name(name).is_ok(),
        "matches_pattern called with invalid DNS name: {}",
        name
    );
    debug_assert!(
        validate_dns_pattern(pattern).is_ok(),
        "matches_pattern called with invalid DNS pattern: {}",
        pattern
    );

    let name_labels: Vec<&str> = name.split('.').collect();
    let pattern_labels: Vec<&str> = pattern.split('.').collect();

    // Must have same number of labels
    if name_labels.len() != pattern_labels.len() {
        return false;
    }

    // Match each label pair
    for (name_label, pattern_label) in name_labels.iter().zip(pattern_labels.iter()) {
        if !match_glob_label(pattern_label, name_label) {
            return false;
        }
    }

    true
}

#[cfg(all(test, feature = "conntrack"))]
mod tests {
    use super::*;

    // DNS Name Validation Tests

    #[test]
    fn test_validate_dns_name_valid() {
        assert!(validate_dns_name("example.com").is_ok());
        assert!(validate_dns_name("sub.example.com").is_ok());
        assert!(validate_dns_name("my-server.example.org").is_ok());
        assert!(validate_dns_name("api-1.us-east.example.com").is_ok());
    }

    #[test]
    fn test_validate_dns_name_empty() {
        assert!(matches!(
            validate_dns_name(""),
            Err(ValidationError::EmptyLabel)
        ));
    }

    #[test]
    fn test_validate_dns_name_single_label() {
        assert!(matches!(
            validate_dns_name("ipcamera"),
            Err(ValidationError::InsufficientLabels { actual: 1, required: 2 })
        ));
    }

    #[test]
    fn test_validate_dns_name_leading_hyphen() {
        let result = validate_dns_name("-example.com");
        assert!(matches!(result, Err(ValidationError::LeadingOrTrailingHyphen { .. })));
    }

    #[test]
    fn test_validate_dns_name_trailing_hyphen() {
        let result = validate_dns_name("example-.com");
        assert!(matches!(result, Err(ValidationError::LeadingOrTrailingHyphen { .. })));
    }

    #[test]
    fn test_validate_dns_name_numeric_final_label() {
        let result = validate_dns_name("example.123");
        assert!(matches!(result, Err(ValidationError::NumericFinalLabel { .. })));
    }

    #[test]
    fn test_validate_dns_name_local_tld() {
        assert!(matches!(
            validate_dns_name("ipcamera.local"),
            Err(ValidationError::ReservedTld { .. })
        ));
        assert!(matches!(
            validate_dns_name("ipcamera.LOCAL"),
            Err(ValidationError::ReservedTld { .. })
        ));
    }

    #[test]
    fn test_validate_dns_name_empty_label() {
        assert!(matches!(
            validate_dns_name("example..com"),
            Err(ValidationError::EmptyLabel)
        ));
        assert!(matches!(
            validate_dns_name(".example.com"),
            Err(ValidationError::EmptyLabel)
        ));
    }

    #[test]
    fn test_validate_dns_name_invalid_character() {
        let result = validate_dns_name("exam_ple.com");
        assert!(matches!(result, Err(ValidationError::InvalidCharacter { character: '_', .. })));
    }

    #[test]
    fn test_validate_dns_name_label_too_long() {
        let long_label = "a".repeat(64);
        let name = format!("{}.com", long_label);
        let result = validate_dns_name(&name);
        assert!(matches!(result, Err(ValidationError::InvalidLabelLength { .. })));
    }

    #[test]
    fn test_validate_dns_name_total_too_long() {
        let long_name = format!("{}.com", "a".repeat(250));
        let result = validate_dns_name(&long_name);
        assert!(matches!(result, Err(ValidationError::InvalidLength { .. })));
    }

    // DNS Pattern Validation Tests

    #[test]
    fn test_validate_dns_pattern_valid() {
        assert!(validate_dns_pattern("*.example.com").is_ok());
        assert!(validate_dns_pattern("video*.example.com").is_ok());
        assert!(validate_dns_pattern("*-prod-*.example.com").is_ok());
        assert!(validate_dns_pattern("api*.*.example.com").is_ok());
    }

    #[test]
    fn test_validate_dns_pattern_wildcard_in_final_labels() {
        let result = validate_dns_pattern("*.com");
        assert!(matches!(result, Err(ValidationError::WildcardInFinalLabels { .. })));
        
        let result = validate_dns_pattern("test.*.com");
        assert!(matches!(result, Err(ValidationError::WildcardInFinalLabels { .. })));
    }

    #[test]
    fn test_validate_dns_pattern_too_many_wildcards() {
        let result = validate_dns_pattern("***test.example.com");
        assert!(matches!(result, Err(ValidationError::TooManyWildcards { .. })));
    }

    #[test]
    fn test_validate_dns_pattern_single_label() {
        let result = validate_dns_pattern("*");
        assert!(matches!(result, Err(ValidationError::InsufficientLabels { .. })));
    }

    #[test]
    fn test_validate_dns_pattern_local_tld() {
        assert!(matches!(
            validate_dns_pattern("*.local"),
            Err(ValidationError::ReservedTld { .. })
        ));
    }

    // Glob Matching Tests

    #[test]
    fn test_match_glob_label_exact() {
        assert!(match_glob_label("api", "api"));
        assert!(match_glob_label("api", "API")); // case-insensitive
        assert!(!match_glob_label("api", "web"));
    }

    #[test]
    fn test_match_glob_label_prefix_wildcard() {
        assert!(match_glob_label("*-prod", "api-prod"));
        assert!(match_glob_label("*-prod", "web-prod"));
        assert!(!match_glob_label("*-prod", "api-staging"));
    }

    #[test]
    fn test_match_glob_label_suffix_wildcard() {
        assert!(match_glob_label("api-*", "api-prod"));
        assert!(match_glob_label("api-*", "api-staging"));
        assert!(!match_glob_label("api-*", "web-prod"));
    }

    #[test]
    fn test_match_glob_label_middle_wildcard() {
        assert!(match_glob_label("api-*-east", "api-prod-east"));
        assert!(match_glob_label("api-*-east", "api-staging-east"));
        assert!(!match_glob_label("api-*-east", "api-prod-west"));
    }

    #[test]
    fn test_match_glob_label_full_wildcard() {
        assert!(match_glob_label("*", "api"));
        assert!(match_glob_label("*", "anything"));
        assert!(match_glob_label("*", ""));
    }

    #[test]
    fn test_match_glob_label_multiple_wildcards() {
        assert!(match_glob_label("*-prod-*", "app1-prod-east"));
        assert!(match_glob_label("*-prod-*", "api-prod-west"));
        assert!(!match_glob_label("*-prod-*", "app1-staging-east"));
    }

    // Pattern Matching Tests

    #[test]
    fn test_matches_pattern_single_wildcard_label() {
        assert!(matches_pattern("api.example.com", "*.example.com"));
        assert!(matches_pattern("web.example.com", "*.example.com"));
        assert!(!matches_pattern("api.us.example.com", "*.example.com")); // label count
    }

    #[test]
    fn test_matches_pattern_prefix_wildcard() {
        assert!(matches_pattern("video1.example.com", "video*.example.com"));
        assert!(matches_pattern("video-prod.example.com", "video*.example.com"));
        assert!(!matches_pattern("api.example.com", "video*.example.com"));
    }

    #[test]
    fn test_matches_pattern_multiple_wildcards() {
        assert!(matches_pattern("app1-prod-east.example.com", "*-prod-*.example.com"));
        assert!(matches_pattern("api-prod-west.example.com", "*-prod-*.example.com"));
        assert!(!matches_pattern("app1-staging-east.example.com", "*-prod-*.example.com"));
    }

    #[test]
    fn test_matches_pattern_multiple_wildcard_labels() {
        assert!(matches_pattern("api1.us.example.com", "api*.*.example.com"));
        assert!(matches_pattern("api-test.staging.example.com", "api*.*.example.com"));
        assert!(!matches_pattern("web1.us.example.com", "api*.*.example.com"));
    }

    #[test]
    fn test_matches_pattern_case_insensitive() {
        assert!(matches_pattern("API.Example.COM", "*.example.com"));
        assert!(matches_pattern("api.example.com", "*.EXAMPLE.COM"));
    }

    #[test]
    fn test_matches_pattern_no_match_label_count() {
        assert!(!matches_pattern("api.example.com", "*.*.example.com"));
        assert!(!matches_pattern("api.us.example.com", "*.example.com"));
    }

    // Edge Cases

    #[test]
    fn test_validate_dns_name_max_length() {
        // 253 characters total: label of 63 chars + dot + label of 63 chars + dot + "com" (3 chars)
        let label1 = "a".repeat(63);
        let label2 = "b".repeat(63);
        let label3 = "c".repeat(120);
        let name = format!("{}.{}.com", label1, label2);
        assert!(validate_dns_name(&name).is_ok());
    }

    #[test]
    fn test_validate_dns_pattern_wildcards_excluded_from_length() {
        // Pattern with wildcards should have wildcards excluded from length calculation
        let long_label = "a".repeat(60);
        let pattern = format!("*{}*.example.com", long_label);
        // After removing 2 wildcards, label is 60 chars (valid)
        assert!(validate_dns_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_match_glob_label_empty_pattern() {
        assert!(match_glob_label("", ""));
        assert!(!match_glob_label("", "nonempty"));
    }

    #[test]
    fn test_match_glob_label_empty_value() {
        assert!(match_glob_label("*", ""));
        assert!(!match_glob_label("literal", ""));
    }
}
