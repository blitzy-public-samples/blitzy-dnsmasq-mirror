//! DNS domain pattern matching
//!
//! Provides wildcard pattern matching for domain names, replacing C implementation
//! from domain-match.c with safe Rust implementation.

/// Domain pattern matcher
///
/// Supports wildcard patterns for domain matching:
/// - `*` matches any sequence of labels
/// - Exact matches
///
/// # Examples
///
/// ```
/// use dnsmasq::dns::pattern::DomainPattern;
///
/// let pattern = DomainPattern::new("*.example.com");
/// assert!(pattern.matches("www.example.com"));
/// assert!(pattern.matches("mail.example.com"));
/// assert!(!pattern.matches("example.com"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPattern {
    /// The pattern string
    pattern: String,
    
    /// Whether this is a wildcard pattern
    is_wildcard: bool,
    
    /// The suffix to match (for wildcard patterns)
    suffix: Option<String>,
}

impl DomainPattern {
    /// Create a new domain pattern
    ///
    /// # Arguments
    ///
    /// * `pattern` - Pattern string (e.g., "*.example.com" or "example.com")
    #[must_use] 
    pub fn new(pattern: &str) -> Self {
        let pattern = pattern.to_lowercase();
        
        // Extract suffix if wildcard pattern
        let suffix = pattern.strip_prefix("*.").map(ToString::to_string);
        let is_wildcard = suffix.is_some();
        
        Self {
            pattern,
            is_wildcard,
            suffix,
        }
    }

    /// Check if a domain matches this pattern
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to check
    ///
    /// # Returns
    ///
    /// Returns true if the domain matches the pattern.
    #[must_use] 
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        
        if self.is_wildcard {
            if let Some(ref suffix) = self.suffix {
                // For wildcard patterns, check if domain ends with suffix
                // but is not exactly the suffix (must have at least one more label)
                if domain == *suffix {
                    return false;
                }
                domain.ends_with(&format!(".{suffix}"))
            } else {
                false
            }
        } else {
            // Exact match
            domain == self.pattern
        }
    }

    /// Get the pattern string
    #[must_use] 
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Check if this is a wildcard pattern
    #[must_use] 
    pub fn is_wildcard(&self) -> bool {
        self.is_wildcard
    }
}

/// A collection of domain patterns for efficient matching
pub struct DomainPatternMatcher {
    /// Exact match patterns (domain -> true)
    exact_matches: std::collections::HashSet<String>,
    
    /// Wildcard patterns
    wildcard_patterns: Vec<DomainPattern>,
}

impl DomainPatternMatcher {
    /// Create a new empty pattern matcher
    #[must_use] 
    pub fn new() -> Self {
        Self {
            exact_matches: std::collections::HashSet::new(),
            wildcard_patterns: Vec::new(),
        }
    }

    /// Add a pattern to the matcher
    ///
    /// # Arguments
    ///
    /// * `pattern` - Pattern string to add
    pub fn add_pattern(&mut self, pattern: &str) {
        let pattern_obj = DomainPattern::new(pattern);
        
        if pattern_obj.is_wildcard() {
            self.wildcard_patterns.push(pattern_obj);
        } else {
            self.exact_matches.insert(pattern_obj.pattern().to_string());
        }
    }

    /// Check if a domain matches any pattern
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to check
    ///
    /// # Returns
    ///
    /// Returns true if the domain matches any pattern.
    #[must_use] 
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // Check exact matches first (faster)
        if self.exact_matches.contains(&domain_lower) {
            return true;
        }
        
        // Check wildcard patterns
        for pattern in &self.wildcard_patterns {
            if pattern.matches(domain) {
                return true;
            }
        }
        
        false
    }

    /// Get the number of patterns
    #[must_use] 
    pub fn len(&self) -> usize {
        self.exact_matches.len() + self.wildcard_patterns.len()
    }

    /// Check if matcher has no patterns
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.exact_matches.is_empty() && self.wildcard_patterns.is_empty()
    }

    /// Clear all patterns
    pub fn clear(&mut self) {
        self.exact_matches.clear();
        self.wildcard_patterns.clear();
    }
}

impl Default for DomainPatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_pattern() {
        let pattern = DomainPattern::new("example.com");
        
        assert!(!pattern.is_wildcard());
        assert!(pattern.matches("example.com"));
        assert!(pattern.matches("EXAMPLE.COM")); // Case insensitive
        assert!(!pattern.matches("www.example.com"));
        assert!(!pattern.matches("example.org"));
    }

    #[test]
    fn test_wildcard_pattern() {
        let pattern = DomainPattern::new("*.example.com");
        
        assert!(pattern.is_wildcard());
        assert!(pattern.matches("www.example.com"));
        assert!(pattern.matches("mail.example.com"));
        assert!(pattern.matches("a.b.example.com"));
        assert!(!pattern.matches("example.com")); // Wildcard requires at least one label
        assert!(!pattern.matches("example.org"));
    }

    #[test]
    fn test_wildcard_case_insensitive() {
        let pattern = DomainPattern::new("*.EXAMPLE.COM");
        
        assert!(pattern.matches("www.example.com"));
        assert!(pattern.matches("WWW.EXAMPLE.COM"));
    }

    #[test]
    fn test_pattern_matcher_empty() {
        let matcher = DomainPatternMatcher::new();
        
        assert!(matcher.is_empty());
        assert_eq!(matcher.len(), 0);
        assert!(!matcher.matches("example.com"));
    }

    #[test]
    fn test_pattern_matcher_exact() {
        let mut matcher = DomainPatternMatcher::new();
        
        matcher.add_pattern("example.com");
        matcher.add_pattern("example.org");
        
        assert_eq!(matcher.len(), 2);
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("example.org"));
        assert!(!matcher.matches("www.example.com"));
    }

    #[test]
    fn test_pattern_matcher_wildcard() {
        let mut matcher = DomainPatternMatcher::new();
        
        matcher.add_pattern("*.example.com");
        matcher.add_pattern("*.test.org");
        
        assert_eq!(matcher.len(), 2);
        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("mail.test.org"));
        assert!(!matcher.matches("example.com"));
        assert!(!matcher.matches("test.org"));
    }

    #[test]
    fn test_pattern_matcher_mixed() {
        let mut matcher = DomainPatternMatcher::new();
        
        matcher.add_pattern("example.com");
        matcher.add_pattern("*.example.org");
        
        assert_eq!(matcher.len(), 2);
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("www.example.org"));
        assert!(!matcher.matches("www.example.com"));
    }

    #[test]
    fn test_pattern_matcher_clear() {
        let mut matcher = DomainPatternMatcher::new();
        
        matcher.add_pattern("example.com");
        matcher.add_pattern("*.example.org");
        assert_eq!(matcher.len(), 2);
        
        matcher.clear();
        assert!(matcher.is_empty());
        assert_eq!(matcher.len(), 0);
    }
}
