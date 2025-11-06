//! DNS resource record filtering
//!
//! Provides filtering and compression fixup for DNS resource records.
//! Replaces C implementation from rrfilter.c.

use crate::dns::protocol::DnsRrType;

/// RR filter action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    /// Allow this RR to pass through
    Allow,
    /// Block this RR
    Block,
    /// Modify this RR
    Modify,
}

/// RR filter rule
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// RR type to filter
    pub rr_type: Option<DnsRrType>,
    
    /// Domain pattern to match (None = match all)
    pub domain_pattern: Option<String>,
    
    /// Action to take
    pub action: FilterAction,
}

impl FilterRule {
    /// Create a new filter rule
    ///
    /// # Arguments
    ///
    /// * `rr_type` - Optional RR type to filter (None = all types)
    /// * `domain_pattern` - Optional domain pattern (None = all domains)
    /// * `action` - Action to take when rule matches
    #[must_use] 
    pub fn new(
        rr_type: Option<DnsRrType>,
        domain_pattern: Option<String>,
        action: FilterAction,
    ) -> Self {
        Self {
            rr_type,
            domain_pattern,
            action,
        }
    }

    /// Check if this rule matches an RR
    ///
    /// # Arguments
    ///
    /// * `rr_type` - RR type to check
    /// * `domain` - Domain name to check
    ///
    /// # Returns
    ///
    /// Returns true if the rule matches.
    #[must_use] 
    pub fn matches(&self, rr_type: DnsRrType, domain: &str) -> bool {
        // Check RR type match
        if let Some(filter_type) = self.rr_type {
            if filter_type != rr_type {
                return false;
            }
        }

        // Check domain pattern match
        if let Some(ref pattern) = self.domain_pattern {
            let domain_lower = domain.to_lowercase();
            let pattern_lower = pattern.to_lowercase();
            
            if let Some(suffix) = pattern_lower.strip_prefix('*') {
                // Wildcard pattern
                // Remove '*' -> ".example.com"
                
                // Match if domain ends with suffix (subdomains)
                // OR if domain equals suffix without leading dot (base domain)
                if !domain_lower.ends_with(suffix) {
                    // Check if it matches the base domain
                    if let Some(base_domain) = suffix.strip_prefix('.') {
                        // Remove leading '.'
                        if domain_lower != base_domain {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            } else if domain_lower != pattern_lower {
                // Exact match
                return false;
            }
        }

        true
    }
}

/// RR filter engine
///
/// Applies filtering rules to DNS resource records.
pub struct RrFilter {
    /// List of filter rules (applied in order)
    rules: Vec<FilterRule>,
    
    /// Default action when no rules match
    default_action: FilterAction,
}

impl RrFilter {
    /// Create a new RR filter with default allow action
    #[must_use] 
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: FilterAction::Allow,
        }
    }

    /// Create a new RR filter with specified default action
    #[must_use] 
    pub fn with_default_action(default_action: FilterAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    /// Add a filter rule
    pub fn add_rule(&mut self, rule: FilterRule) {
        self.rules.push(rule);
    }

    /// Filter an RR and determine the action
    ///
    /// # Arguments
    ///
    /// * `rr_type` - RR type
    /// * `domain` - Domain name
    ///
    /// # Returns
    ///
    /// Returns the action to take for this RR.
    #[must_use] 
    pub fn filter(&self, rr_type: DnsRrType, domain: &str) -> FilterAction {
        // Apply rules in order, first match wins
        for rule in &self.rules {
            if rule.matches(rr_type, domain) {
                return rule.action;
            }
        }

        // No rule matched, use default
        self.default_action
    }

    /// Get the number of rules
    #[must_use] 
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if there are no rules
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Clear all rules
    pub fn clear(&mut self) {
        self.rules.clear();
    }
}

impl Default for RrFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Common filter configurations
impl RrFilter {
    /// Create a filter that blocks all AAAA records
    #[must_use] 
    pub fn block_aaaa() -> Self {
        let mut filter = Self::new();
        filter.add_rule(FilterRule::new(
            Some(DnsRrType::AAAA),
            None,
            FilterAction::Block,
        ));
        filter
    }

    /// Create a filter that blocks specific domains
    #[must_use] 
    pub fn block_domains(domains: &[&str]) -> Self {
        let mut filter = Self::new();
        for domain in domains {
            filter.add_rule(FilterRule::new(
                None,
                Some((*domain).to_string()),
                FilterAction::Block,
            ));
        }
        filter
    }

    /// Create a filter that allows only specific RR types
    #[must_use] 
    pub fn allow_only_types(types: &[DnsRrType]) -> Self {
        let mut filter = Self::with_default_action(FilterAction::Block);
        for rr_type in types {
            filter.add_rule(FilterRule::new(
                Some(*rr_type),
                None,
                FilterAction::Allow,
            ));
        }
        filter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_rule_match_type() {
        let rule = FilterRule::new(
            Some(DnsRrType::A),
            None,
            FilterAction::Block,
        );

        assert!(rule.matches(DnsRrType::A, "example.com"));
        assert!(!rule.matches(DnsRrType::AAAA, "example.com"));
    }

    #[test]
    fn test_filter_rule_match_domain_exact() {
        let rule = FilterRule::new(
            None,
            Some("example.com".to_string()),
            FilterAction::Block,
        );

        assert!(rule.matches(DnsRrType::A, "example.com"));
        assert!(rule.matches(DnsRrType::A, "EXAMPLE.COM")); // Case insensitive
        assert!(!rule.matches(DnsRrType::A, "www.example.com"));
    }

    #[test]
    fn test_filter_rule_match_domain_wildcard() {
        let rule = FilterRule::new(
            None,
            Some("*.example.com".to_string()),
            FilterAction::Block,
        );

        assert!(rule.matches(DnsRrType::A, "www.example.com"));
        assert!(rule.matches(DnsRrType::A, "mail.example.com"));
        assert!(rule.matches(DnsRrType::A, "example.com")); // Wildcard includes base
    }

    #[test]
    fn test_filter_rule_match_combined() {
        let rule = FilterRule::new(
            Some(DnsRrType::A),
            Some("*.example.com".to_string()),
            FilterAction::Block,
        );

        assert!(rule.matches(DnsRrType::A, "www.example.com"));
        assert!(!rule.matches(DnsRrType::AAAA, "www.example.com"));
        assert!(!rule.matches(DnsRrType::A, "example.org"));
    }

    #[test]
    fn test_rr_filter_empty() {
        let filter = RrFilter::new();
        
        assert!(filter.is_empty());
        assert_eq!(filter.len(), 0);
        
        // Default action is allow
        assert_eq!(
            filter.filter(DnsRrType::A, "example.com"),
            FilterAction::Allow
        );
    }

    #[test]
    fn test_rr_filter_single_rule() {
        let mut filter = RrFilter::new();
        
        filter.add_rule(FilterRule::new(
            Some(DnsRrType::AAAA),
            None,
            FilterAction::Block,
        ));

        assert_eq!(filter.len(), 1);
        assert_eq!(
            filter.filter(DnsRrType::AAAA, "example.com"),
            FilterAction::Block
        );
        assert_eq!(
            filter.filter(DnsRrType::A, "example.com"),
            FilterAction::Allow
        );
    }

    #[test]
    fn test_rr_filter_multiple_rules_first_match() {
        let mut filter = RrFilter::new();
        
        // First rule: block all A records
        filter.add_rule(FilterRule::new(
            Some(DnsRrType::A),
            None,
            FilterAction::Block,
        ));
        
        // Second rule: allow example.com (should not be reached for A records)
        filter.add_rule(FilterRule::new(
            None,
            Some("example.com".to_string()),
            FilterAction::Allow,
        ));

        // First rule should match and block
        assert_eq!(
            filter.filter(DnsRrType::A, "example.com"),
            FilterAction::Block
        );
    }

    #[test]
    fn test_rr_filter_block_aaaa() {
        let filter = RrFilter::block_aaaa();
        
        assert_eq!(
            filter.filter(DnsRrType::AAAA, "example.com"),
            FilterAction::Block
        );
        assert_eq!(
            filter.filter(DnsRrType::A, "example.com"),
            FilterAction::Allow
        );
    }

    #[test]
    fn test_rr_filter_block_domains() {
        let filter = RrFilter::block_domains(&["blocked.com", "evil.org"]);
        
        assert_eq!(
            filter.filter(DnsRrType::A, "blocked.com"),
            FilterAction::Block
        );
        assert_eq!(
            filter.filter(DnsRrType::A, "evil.org"),
            FilterAction::Block
        );
        assert_eq!(
            filter.filter(DnsRrType::A, "allowed.com"),
            FilterAction::Allow
        );
    }

    #[test]
    fn test_rr_filter_allow_only_types() {
        let filter = RrFilter::allow_only_types(&[DnsRrType::A, DnsRrType::AAAA]);
        
        assert_eq!(
            filter.filter(DnsRrType::A, "example.com"),
            FilterAction::Allow
        );
        assert_eq!(
            filter.filter(DnsRrType::AAAA, "example.com"),
            FilterAction::Allow
        );
        assert_eq!(
            filter.filter(DnsRrType::MX, "example.com"),
            FilterAction::Block
        );
    }

    #[test]
    fn test_rr_filter_clear() {
        let mut filter = RrFilter::new();
        
        filter.add_rule(FilterRule::new(
            Some(DnsRrType::A),
            None,
            FilterAction::Block,
        ));
        assert!(!filter.is_empty());
        
        filter.clear();
        assert!(filter.is_empty());
        assert_eq!(filter.len(), 0);
    }
}
