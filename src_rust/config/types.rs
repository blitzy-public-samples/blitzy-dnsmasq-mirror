//! Configuration data structures

use serde::{Deserialize, Serialize};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// DNS port (0 to disable)
    pub dns_port: u16,
    
    /// DHCP enabled
    pub dhcp_enabled: bool,
    
    /// DNSSEC validation enabled
    pub dnssec_enabled: bool,
    
    /// Configuration file path
    pub config_file: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns_port: 53,
            dhcp_enabled: true,
            dnssec_enabled: false,
            config_file: None,
        }
    }
}
