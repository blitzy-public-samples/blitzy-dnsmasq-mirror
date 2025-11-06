//! DNS domain name utilities
//!
//! Provides safe domain name manipulation, replacing C's manual string handling
//! from domain.c with Rust's String type.

/// Maximum length of a DNS domain name (including labels and dots)
pub const MAX_DOMAIN_LENGTH: usize = 253;

/// Maximum length of a single DNS label
pub const MAX_LABEL_LENGTH: usize = 63;

/// Domain name validation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// Domain name is too long
    TooLong,
    /// Label is too long
    LabelTooLong,
    /// Empty label
    EmptyLabel,
    /// Invalid character in domain name
    InvalidCharacter(char),
    /// Empty domain name
    Empty,
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DomainError::TooLong => write!(f, "Domain name exceeds maximum length"),
            DomainError::LabelTooLong => write!(f, "Label exceeds maximum length"),
            DomainError::EmptyLabel => write!(f, "Empty label in domain name"),
            DomainError::InvalidCharacter(c) => write!(f, "Invalid character: '{c}'"),
            DomainError::Empty => write!(f, "Empty domain name"),
        }
    }
}

impl std::error::Error for DomainError {}

/// Validate a DNS domain name
///
/// # Arguments
///
/// * `domain` - Domain name to validate (e.g., "example.com")
///
/// # Returns
///
/// Returns Ok(()) if valid, Err(DomainError) if invalid.
///
/// # Errors
///
/// Returns an error if the domain name is empty, too long, or contains invalid labels.
pub fn validate_domain_name(domain: &str) -> Result<(), DomainError> {
    if domain.is_empty() {
        return Err(DomainError::Empty);
    }

    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(DomainError::TooLong);
    }

    // Split into labels and validate each
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(DomainError::EmptyLabel);
        }

        if label.len() > MAX_LABEL_LENGTH {
            return Err(DomainError::LabelTooLong);
        }

        // Check for valid characters (alphanumeric and hyphen)
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                return Err(DomainError::InvalidCharacter(c));
            }
        }

        // Label cannot start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainError::InvalidCharacter('-'));
        }
    }

    Ok(())
}

/// Normalize a domain name to lowercase
///
/// DNS names are case-insensitive, so we normalize to lowercase for comparison.
///
/// # Arguments
///
/// * `domain` - Domain name to normalize
///
/// # Returns
///
/// Returns normalized domain name in lowercase.
#[must_use] 
pub fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase()
}

/// Check if a domain name ends with a specific suffix
///
/// # Arguments
///
/// * `domain` - Full domain name (e.g., "www.example.com")
/// * `suffix` - Suffix to check (e.g., "example.com")
///
/// # Returns
///
/// Returns true if domain ends with suffix (case-insensitive).
#[must_use] 
pub fn is_subdomain(domain: &str, suffix: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    let suffix_lower = suffix.to_lowercase();

    if domain_lower == suffix_lower {
        return true;
    }

    // Check if it ends with "." + suffix
    domain_lower.ends_with(&format!(".{suffix_lower}"))
}

/// Extract the parent domain from a domain name
///
/// # Arguments
///
/// * `domain` - Domain name (e.g., "www.example.com")
///
/// # Returns
///
/// Returns Some(parent) if there is a parent, None if this is a TLD.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::parent_domain;
/// assert_eq!(parent_domain("www.example.com"), Some("example.com".to_string()));
/// assert_eq!(parent_domain("example.com"), Some("com".to_string()));
/// assert_eq!(parent_domain("com"), None);
/// ```
#[must_use] 
pub fn parent_domain(domain: &str) -> Option<String> {
    let first_dot = domain.find('.')?;
    Some(domain[first_dot + 1..].to_string())
}

/// Count the number of labels in a domain name
///
/// # Arguments
///
/// * `domain` - Domain name
///
/// # Returns
///
/// Returns the number of labels.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::label_count;
/// assert_eq!(label_count("www.example.com"), 3);
/// assert_eq!(label_count("example.com"), 2);
/// ```
#[must_use] 
pub fn label_count(domain: &str) -> usize {
    if domain.is_empty() {
        return 0;
    }
    domain.split('.').count()
}

/// Get the top-level domain (TLD) from a domain name
///
/// # Arguments
///
/// * `domain` - Domain name (e.g., "www.example.com")
///
/// # Returns
///
/// Returns the TLD (e.g., "com").
#[must_use] 
pub fn tld(domain: &str) -> &str {
    domain
        .rsplit('.')
        .next()
        .unwrap_or(domain)
}

/// Check if two domain names are equal (case-insensitive)
///
/// # Arguments
///
/// * `domain1` - First domain name
/// * `domain2` - Second domain name
///
/// # Returns
///
/// Returns true if domains are equal (case-insensitive).
#[must_use] 
pub fn domain_equals(domain1: &str, domain2: &str) -> bool {
    domain1.eq_ignore_ascii_case(domain2)
}

/// Reverse a domain name for PTR queries
///
/// Converts an IP address to its reverse DNS lookup format.
///
/// # Arguments
///
/// * `ip` - IP address as string
///
/// # Returns
///
/// Returns reversed domain for PTR lookup.
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::domain::reverse_domain_ipv4;
/// assert_eq!(reverse_domain_ipv4("192.168.1.1"), "1.1.168.192.in-addr.arpa");
/// ```
#[must_use] 
pub fn reverse_domain_ipv4(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return ip.to_string(); // Invalid IP, return as-is
    }
    format!("{}.{}.{}.{}.in-addr.arpa", parts[3], parts[2], parts[1], parts[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_domain_name_valid() {
        assert!(validate_domain_name("example.com").is_ok());
        assert!(validate_domain_name("www.example.com").is_ok());
        assert!(validate_domain_name("sub.domain.example.com").is_ok());
        assert!(validate_domain_name("a-b.example.com").is_ok());
    }

    #[test]
    fn test_validate_domain_name_invalid() {
        assert_eq!(validate_domain_name(""), Err(DomainError::Empty));
        assert_eq!(
            validate_domain_name("example..com"),
            Err(DomainError::EmptyLabel)
        );
        
        // Label too long (>63 chars)
        let long_label = "a".repeat(64);
        assert_eq!(
            validate_domain_name(&format!("{}.com", long_label)),
            Err(DomainError::LabelTooLong)
        );
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("Example.COM"), "example.com");
        assert_eq!(normalize_domain("WWW.EXAMPLE.COM"), "www.example.com");
    }

    #[test]
    fn test_is_subdomain() {
        assert!(is_subdomain("www.example.com", "example.com"));
        assert!(is_subdomain("example.com", "example.com"));
        assert!(!is_subdomain("example.com", "other.com"));
        assert!(is_subdomain("a.b.c.example.com", "example.com"));
        
        // Case insensitive
        assert!(is_subdomain("WWW.EXAMPLE.COM", "example.com"));
    }

    #[test]
    fn test_parent_domain() {
        assert_eq!(parent_domain("www.example.com"), Some("example.com".to_string()));
        assert_eq!(parent_domain("example.com"), Some("com".to_string()));
        assert_eq!(parent_domain("com"), None);
    }

    #[test]
    fn test_label_count() {
        assert_eq!(label_count("www.example.com"), 3);
        assert_eq!(label_count("example.com"), 2);
        assert_eq!(label_count("com"), 1);
        assert_eq!(label_count(""), 0);
    }

    #[test]
    fn test_tld() {
        assert_eq!(tld("www.example.com"), "com");
        assert_eq!(tld("example.org"), "org");
        assert_eq!(tld("localhost"), "localhost");
    }

    #[test]
    fn test_domain_equals() {
        assert!(domain_equals("example.com", "EXAMPLE.COM"));
        assert!(domain_equals("WWW.Example.COM", "www.example.com"));
        assert!(!domain_equals("example.com", "example.org"));
    }

    #[test]
    fn test_reverse_domain_ipv4() {
        assert_eq!(reverse_domain_ipv4("192.168.1.1"), "1.1.168.192.in-addr.arpa");
        assert_eq!(reverse_domain_ipv4("8.8.8.8"), "8.8.8.8.in-addr.arpa");
    }
}
