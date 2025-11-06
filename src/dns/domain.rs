// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// Domain name utilities and matching
//
// Translated from: src/domain.c, src/domain-match.c

//! Domain name utilities including canonicalization, wildcard matching,
//! and domain comparison.

use crate::types::errors::DnsError;

/// Synthetic domain configuration for local DNS responses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthDomain {
    pub domain: String,
    pub prefix: String,
}

impl SynthDomain {
    /// Create a new synthetic domain
    pub fn new(domain: String, prefix: String) -> Self {
        Self { domain, prefix }
    }

    /// Check if a name matches this synthetic domain
    pub fn matches(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        let domain_lower = self.domain.to_lowercase();
        name_lower.ends_with(&domain_lower)
    }
}

/// Conditional forwarding domain configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalDomain {
    pub domain: String,
    pub servers: Vec<String>,
}

impl ConditionalDomain {
    /// Create a new conditional domain
    pub fn new(domain: String, servers: Vec<String>) -> Self {
        Self { domain, servers }
    }

    /// Check if a name should use this conditional domain
    pub fn matches(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        let domain_lower = self.domain.to_lowercase();
        
        // Exact match or subdomain match
        name_lower == domain_lower || name_lower.ends_with(&format!(".{}", domain_lower))
    }
}

/// Canonicalize a domain name
pub fn canonicalize(name: &str) -> String {
    let mut canonical = name.to_lowercase();
    
    // Remove trailing dot if present
    if canonical.ends_with('.') {
        canonical.pop();
    }
    
    canonical
}

/// Check if two domain names are equal (case-insensitive)
pub fn domain_equal(a: &str, b: &str) -> bool {
    canonicalize(a) == canonicalize(b)
}

/// Check if name is a subdomain of domain
pub fn is_subdomain(name: &str, domain: &str) -> bool {
    let name_canon = canonicalize(name);
    let domain_canon = canonicalize(domain);
    
    name_canon == domain_canon || name_canon.ends_with(&format!(".{}", domain_canon))
}

/// Extract the labels from a domain name
pub fn extract_labels(name: &str) -> Vec<String> {
    canonicalize(name)
        .split('.')
        .map(|s| s.to_string())
        .collect()
}

/// Count the number of labels in a domain name
pub fn label_count(name: &str) -> usize {
    if name.is_empty() {
        0
    } else {
        extract_labels(name).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize() {
        assert_eq!(canonicalize("Example.COM"), "example.com");
        assert_eq!(canonicalize("example.com."), "example.com");
        assert_eq!(canonicalize("EXAMPLE.COM."), "example.com");
    }

    #[test]
    fn test_domain_equal() {
        assert!(domain_equal("example.com", "EXAMPLE.COM"));
        assert!(domain_equal("example.com.", "example.com"));
        assert!(!domain_equal("example.com", "example.org"));
    }

    #[test]
    fn test_is_subdomain() {
        assert!(is_subdomain("www.example.com", "example.com"));
        assert!(is_subdomain("example.com", "example.com"));
        assert!(!is_subdomain("example.com", "www.example.com"));
        assert!(!is_subdomain("example.org", "example.com"));
    }

    #[test]
    fn test_extract_labels() {
        let labels = extract_labels("www.example.com");
        assert_eq!(labels, vec!["www", "example", "com"]);
        
        let labels = extract_labels("example.com.");
        assert_eq!(labels, vec!["example", "com"]);
    }

    #[test]
    fn test_label_count() {
        assert_eq!(label_count("www.example.com"), 3);
        assert_eq!(label_count("example.com"), 2);
        assert_eq!(label_count("com"), 1);
        assert_eq!(label_count(""), 0);
    }

    #[test]
    fn test_synthetic_domain() {
        let synth = SynthDomain::new("local".to_string(), "test".to_string());
        assert!(synth.matches("host.local"));
        assert!(synth.matches("test.host.local"));
        assert!(!synth.matches("example.com"));
    }

    #[test]
    fn test_conditional_domain() {
        let cond = ConditionalDomain::new(
            "corp.example.com".to_string(),
            vec!["10.0.0.1".to_string()],
        );
        
        assert!(cond.matches("corp.example.com"));
        assert!(cond.matches("www.corp.example.com"));
        assert!(!cond.matches("example.com"));
    }
}
