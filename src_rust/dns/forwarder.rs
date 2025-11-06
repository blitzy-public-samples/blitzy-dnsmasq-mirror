//! DNS query forwarder

use std::net::SocketAddr;
use std::time::Duration;

/// Configuration for DNS query forwarder
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Upstream DNS servers
    pub upstreams: Vec<SocketAddr>,
    /// Query timeout duration
    pub timeout: Duration,
    /// Maximum concurrent queries
    pub max_concurrent: usize,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            timeout: Duration::from_secs(5),
            max_concurrent: 150,
        }
    }
}

/// Represents a DNS query to be forwarded
#[derive(Debug, Clone)]
pub struct ForwardQuery {
    /// Query ID for matching responses
    pub id: u16,
    /// Domain name being queried
    pub domain: String,
    /// Query type (A, AAAA, etc.)
    pub qtype: u16,
}

/// DNS query forwarder for upstream resolution
pub struct Forwarder {
    _config: ForwardConfig,
}

impl Default for Forwarder {
    fn default() -> Self {
        Self::new()
    }
}

impl Forwarder {
    /// Create a new DNS forwarder instance with default configuration
    #[must_use] 
    pub fn new() -> Self {
        Self {
            _config: ForwardConfig::default(),
        }
    }

    /// Create a new DNS forwarder with custom configuration
    #[must_use] 
    pub fn with_config(config: ForwardConfig) -> Self {
        Self { _config: config }
    }
}
