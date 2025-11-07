//! DNSSEC validation

/// DNSSEC type definitions (keys, signatures, validation status)
pub mod types;

/// Cryptographic operations for DNSSEC validation
pub mod crypto;

/// Trust anchor management for DNSSEC chain of trust establishment
pub mod trust_anchor;

/// Configuration for DNSSEC validation
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct DnssecConfig {
    /// Enable DNSSEC validation
    pub enabled: bool,
    /// Trust anchor file path
    pub trust_anchor_file: Option<String>,
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
    _config: DnssecConfig,
}

impl Default for DnssecValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl DnssecValidator {
    /// Create a new DNSSEC validator with default configuration
    #[must_use] 
    pub fn new() -> Self {
        Self {
            _config: DnssecConfig::default(),
        }
    }

    /// Create a new DNSSEC validator with custom configuration
    #[must_use] 
    pub fn with_config(config: DnssecConfig) -> Self {
        Self { _config: config }
    }
}
