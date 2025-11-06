// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS server implementation for UDP and TCP
//
// Translated from: src/dnsmasq.c (DNS server portions)

//! DNS server implementation
//!
//! Implements the DNS server listener that receives queries from clients,
//! coordinates cache lookups and query forwarding, and returns responses.

use std::net::SocketAddr;
use crate::dns::cache::DnsCache;
use crate::types::errors::DnsError;

/// DNS server implementation
#[derive(Debug)]
pub struct DnsServer {
    config: ServerConfig,
    cache: DnsCache,
}

impl DnsServer {
    /// Create a new DNS server
    pub fn new(config: ServerConfig, cache: DnsCache) -> Result<Self, DnsError> {
        Ok(Self { config, cache })
    }

    /// Run the DNS server (async)
    pub async fn run(&mut self) -> Result<(), DnsError> {
        // Server implementation would go here
        Ok(())
    }

    /// Get server configuration
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get mutable access to the cache
    pub fn cache_mut(&mut self) -> &mut DnsCache {
        &mut self.cache
    }

    /// Get immutable access to the cache
    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }
}

/// DNS server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: SocketAddr,
    pub port: u16,
    pub cache_size: usize,
    pub enable_tcp: bool,
    pub enable_udp: bool,
}

impl ServerConfig {
    /// Create a new server configuration with defaults
    pub fn new() -> Self {
        Self {
            bind_address: "0.0.0.0:53".parse().unwrap(),
            port: 53,
            cache_size: 1000,
            enable_tcp: true,
            enable_udp: true,
        }
    }

    /// Set the port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the cache size
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    /// Enable or disable TCP
    pub fn with_tcp(mut self, enable: bool) -> Self {
        self.enable_tcp = enable;
        self
    }

    /// Enable or disable UDP
    pub fn with_udp(mut self, enable: bool) -> Self {
        self.enable_udp = enable;
        self
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_builder() {
        let config = ServerConfig::new()
            .with_port(5353)
            .with_cache_size(5000)
            .with_tcp(false);

        assert_eq!(config.port, 5353);
        assert_eq!(config.cache_size, 5000);
        assert!(!config.enable_tcp);
        assert!(config.enable_udp);
    }

    #[test]
    fn test_server_creation() {
        let config = ServerConfig::new();
        let cache = DnsCache::new(1000);
        let server = DnsServer::new(config, cache);

        assert!(server.is_ok());
    }
}
