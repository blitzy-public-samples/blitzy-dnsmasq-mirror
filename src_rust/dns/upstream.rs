//! Upstream DNS server management
//!
//! Handles upstream DNS server selection, health tracking, and failover.
//! Replaces C's upstream server logic from forward.c.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Upstream DNS server health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamStatus {
    /// Server is healthy and responding
    Healthy,
    /// Server is temporarily unavailable
    Degraded,
    /// Server is down or not responding
    Down,
}

/// Statistics for an upstream server
#[derive(Debug, Clone)]
pub struct UpstreamStats {
    /// Total queries sent to this server
    pub queries_sent: u64,
    
    /// Total successful responses
    pub responses_received: u64,
    
    /// Total timeouts
    pub timeouts: u64,
    
    /// Total errors
    pub errors: u64,
    
    /// Average response time in milliseconds
    pub avg_response_time_ms: u64,
    
    /// Last query timestamp
    pub last_query: Option<Instant>,
    
    /// Last successful response timestamp
    pub last_success: Option<Instant>,
}

impl UpstreamStats {
    /// Create new empty statistics
    #[must_use] 
    pub fn new() -> Self {
        Self {
            queries_sent: 0,
            responses_received: 0,
            timeouts: 0,
            errors: 0,
            avg_response_time_ms: 0,
            last_query: None,
            last_success: None,
        }
    }

    /// Calculate success rate (0.0 to 1.0)
    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        if self.queries_sent == 0 {
            0.0
        } else {
            // Precision loss acceptable for ratio calculation
            #[allow(clippy::cast_precision_loss)]
            let rate = self.responses_received as f64 / self.queries_sent as f64;
            rate
        }
    }

    /// Record a query being sent
    pub fn record_query(&mut self) {
        self.queries_sent += 1;
        self.last_query = Some(Instant::now());
    }

    /// Record a successful response
    pub fn record_response(&mut self, response_time_ms: u64) {
        self.responses_received += 1;
        self.last_success = Some(Instant::now());
        
        // Update moving average
        if self.avg_response_time_ms == 0 {
            self.avg_response_time_ms = response_time_ms;
        } else {
            // Exponential moving average with alpha = 0.2
            self.avg_response_time_ms = 
                (self.avg_response_time_ms * 4 + response_time_ms) / 5;
        }
    }

    /// Record a timeout
    pub fn record_timeout(&mut self) {
        self.timeouts += 1;
    }

    /// Record an error
    pub fn record_error(&mut self) {
        self.errors += 1;
    }
}

impl Default for UpstreamStats {
    fn default() -> Self {
        Self::new()
    }
}

/// An upstream DNS server
#[derive(Debug, Clone)]
pub struct UpstreamServer {
    /// Server socket address
    pub address: SocketAddr,
    
    /// Current health status
    pub status: UpstreamStatus,
    
    /// Statistics for this server
    pub stats: UpstreamStats,
    
    /// Server priority (lower = higher priority)
    pub priority: u8,
    
    /// Server-specific timeout
    pub timeout: Duration,
}

impl UpstreamServer {
    /// Create a new upstream server
    ///
    /// # Arguments
    ///
    /// * `address` - Server socket address
    /// * `priority` - Server priority (0 = highest)
    /// * `timeout` - Query timeout duration
    #[must_use] 
    pub fn new(address: SocketAddr, priority: u8, timeout: Duration) -> Self {
        Self {
            address,
            status: UpstreamStatus::Healthy,
            stats: UpstreamStats::new(),
            priority,
            timeout,
        }
    }

    /// Check if the server is available for queries
    #[must_use] 
    pub fn is_available(&self) -> bool {
        matches!(self.status, UpstreamStatus::Healthy | UpstreamStatus::Degraded)
    }

    /// Update server status based on statistics
    pub fn update_status(&mut self) {
        let success_rate = self.stats.success_rate();
        
        // Determine status based on success rate
        self.status = if success_rate >= 0.8 {
            UpstreamStatus::Healthy
        } else if success_rate >= 0.3 {
            UpstreamStatus::Degraded
        } else if self.stats.queries_sent > 5 {
            // Need at least 5 queries before marking as down
            UpstreamStatus::Down
        } else {
            UpstreamStatus::Healthy // Not enough data yet
        };
    }

    /// Get the last time this server was successfully queried
    #[must_use] 
    pub fn last_success(&self) -> Option<Instant> {
        self.stats.last_success
    }
}

/// Upstream server pool manager
///
/// Manages multiple upstream servers with health checking and load balancing.
pub struct UpstreamPool {
    /// List of upstream servers
    servers: Vec<UpstreamServer>,
    
    /// Current server index (for round-robin)
    current_index: usize,
}

impl UpstreamPool {
    /// Create a new empty upstream pool
    #[must_use] 
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            current_index: 0,
        }
    }

    /// Add a server to the pool
    pub fn add_server(&mut self, server: UpstreamServer) {
        self.servers.push(server);
        self.sort_by_priority();
    }

    /// Get the next available server (round-robin with health checking)
    pub fn next_server(&mut self) -> Option<&mut UpstreamServer> {
        if self.servers.is_empty() {
            return None;
        }

        let server_count = self.servers.len();
        let mut selected_index = None;

        // Try each server once
        for _ in 0..server_count {
            let current_idx = self.current_index;
            self.current_index = (self.current_index + 1) % server_count;
            
            if self.servers[current_idx].is_available() {
                selected_index = Some(current_idx);
                break;
            }
        }

        // If no healthy server found, use first one anyway
        let index = selected_index.unwrap_or(0);
        if selected_index.is_none() {
            self.current_index = 0;
        }
        
        Some(&mut self.servers[index])
    }

    /// Get all servers
    #[must_use] 
    pub fn servers(&self) -> &[UpstreamServer] {
        &self.servers
    }

    /// Get all servers mutably
    pub fn servers_mut(&mut self) -> &mut [UpstreamServer] {
        &mut self.servers
    }

    /// Update status for all servers
    pub fn update_all_status(&mut self) {
        for server in &mut self.servers {
            server.update_status();
        }
    }

    /// Sort servers by priority
    fn sort_by_priority(&mut self) {
        self.servers.sort_by_key(|s| s.priority);
    }

    /// Get number of servers in pool
    #[must_use] 
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Check if pool is empty
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Get count of healthy servers
    #[must_use] 
    pub fn healthy_count(&self) -> usize {
        self.servers
            .iter()
            .filter(|s| s.status == UpstreamStatus::Healthy)
            .count()
    }
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_upstream_stats_basic() {
        let mut stats = UpstreamStats::new();
        
        assert!((stats.success_rate() - 0.0).abs() < f64::EPSILON);
        
        stats.record_query();
        stats.record_response(50);
        
        assert_eq!(stats.queries_sent, 1);
        assert_eq!(stats.responses_received, 1);
        assert!((stats.success_rate() - 1.0).abs() < f64::EPSILON);
        assert_eq!(stats.avg_response_time_ms, 50);
    }

    #[test]
    fn test_upstream_stats_avg_response_time() {
        let mut stats = UpstreamStats::new();
        
        stats.record_query();
        stats.record_response(100);
        assert_eq!(stats.avg_response_time_ms, 100);
        
        stats.record_query();
        stats.record_response(200);
        // EMA: (100 * 4 + 200) / 5 = 120
        assert_eq!(stats.avg_response_time_ms, 120);
    }

    #[test]
    fn test_upstream_server_status() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let mut server = UpstreamServer::new(addr, 0, Duration::from_secs(5));
        
        assert_eq!(server.status, UpstreamStatus::Healthy);
        assert!(server.is_available());
        
        // Simulate failures
        for _ in 0..10 {
            server.stats.record_query();
            server.stats.record_timeout();
        }
        
        server.update_status();
        assert_eq!(server.status, UpstreamStatus::Down);
        assert!(!server.is_available());
    }

    #[test]
    fn test_upstream_pool_basic() {
        let mut pool = UpstreamPool::new();
        
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let server1 = UpstreamServer::new(addr1, 0, Duration::from_secs(5));
        pool.add_server(server1);
        
        assert!(!pool.is_empty());
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.healthy_count(), 1);
    }

    #[test]
    fn test_upstream_pool_round_robin() {
        let mut pool = UpstreamPool::new();
        
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53);
        
        pool.add_server(UpstreamServer::new(addr1, 0, Duration::from_secs(5)));
        pool.add_server(UpstreamServer::new(addr2, 1, Duration::from_secs(5)));
        
        let server1 = pool.next_server().unwrap();
        let first_addr = server1.address;
        
        let server2 = pool.next_server().unwrap();
        let second_addr = server2.address;
        
        // Should alternate
        assert_ne!(first_addr, second_addr);
    }

    #[test]
    fn test_upstream_pool_priority_sorting() {
        let mut pool = UpstreamPool::new();
        
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53);
        
        // Add with lower priority first
        pool.add_server(UpstreamServer::new(addr2, 10, Duration::from_secs(5)));
        pool.add_server(UpstreamServer::new(addr1, 0, Duration::from_secs(5)));
        
        // First server should be the one with priority 0
        assert_eq!(pool.servers()[0].priority, 0);
        assert_eq!(pool.servers()[1].priority, 10);
    }
}
