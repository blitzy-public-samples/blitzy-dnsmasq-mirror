//! DNSSEC validation

/// Configuration for DNSSEC validation
#[derive(Debug, Clone)]
pub struct DnssecConfig {
    /// Enable DNSSEC validation
    pub enabled: bool,
    /// Trust anchor file path
    pub trust_anchor_file: Option<String>,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            trust_anchor_file: None,
        }
    }
}

/// Result of DNSSEC validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// Validation succeeded - signature is valid
    Secure,
    /// Validation failed - signature is invalid
    Bogus,
    /// Validation could not be performed - no DNSSEC data
    Insecure,
    /// Validation is indeterminate - awaiting more data
    Indeterminate,
}

/// DNSSEC validator for signature verification
pub struct DnssecValidator {
    config: DnssecConfig,
}

impl DnssecValidator {
    /// Create a new DNSSEC validator with default configuration
    pub fn new() -> Self {
        Self {
            config: DnssecConfig::default(),
        }
    }

    /// Create a new DNSSEC validator with custom configuration
    pub fn with_config(config: DnssecConfig) -> Self {
        Self { config }
    }
}
