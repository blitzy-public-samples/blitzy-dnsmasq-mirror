//! DNS cache implementation

/// Configuration for DNS cache
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of cache entries (default: 150)
    pub max_entries: usize,
    /// Enable negative caching (default: true)
    pub negative_caching: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 150,
            negative_caching: true,
        }
    }
}

/// DNS cache for storing resolved queries
pub struct Cache {
    config: CacheConfig,
}

impl Cache {
    /// Create a new DNS cache instance with default configuration
    pub fn new() -> Self {
        Self {
            config: CacheConfig::default(),
        }
    }

    /// Create a new DNS cache instance with custom configuration
    pub fn with_config(config: CacheConfig) -> Self {
        Self { config }
    }
}
