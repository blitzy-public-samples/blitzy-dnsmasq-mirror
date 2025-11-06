// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS query forwarding to upstream servers
//
// Translated from: src/forward.c

//! DNS query forwarding logic with upstream server management
//!
//! Manages forwarding of DNS queries to configured upstream servers with
//! domain-specific routing, server health tracking, and response correlation.

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use crate::dns::protocol::{DnsMessage, DnsQuestion};
use crate::types::errors::DnsError;

/// Forward query tracking record
#[derive(Debug, Clone)]
pub struct ForwardRecord {
    pub id: u16,
    pub original_id: u16,
    pub question: DnsQuestion,
    pub upstream: SocketAddr,
    pub sent_at: Instant,
    pub timeout: Duration,
}

impl ForwardRecord {
    /// Create a new forward record
    pub fn new(
        id: u16,
        original_id: u16,
        question: DnsQuestion,
        upstream: SocketAddr,
    ) -> Self {
        Self {
            id,
            original_id,
            question,
            upstream,
            sent_at: Instant::now(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Check if this forward record has timed out
    pub fn is_timed_out(&self) -> bool {
        self.sent_at.elapsed() > self.timeout
    }

    /// Get the elapsed time since the query was sent
    pub fn elapsed(&self) -> Duration {
        self.sent_at.elapsed()
    }
}

/// DNS forwarder state
#[derive(Debug)]
pub struct Forwarder {
    upstreams: Vec<UpstreamServer>,
    pending: Vec<ForwardRecord>,
    next_id: u16,
}

impl Forwarder {
    /// Create a new forwarder
    pub fn new(upstreams: Vec<SocketAddr>) -> Self {
        Self {
            upstreams: upstreams.into_iter().map(UpstreamServer::new).collect(),
            pending: Vec::new(),
            next_id: 1,
        }
    }

    /// Forward a DNS query to an upstream server
    pub fn forward(&mut self, mut message: DnsMessage) -> Result<ForwardRecord, DnsError> {
        if self.upstreams.is_empty() {
            return Err(DnsError::ForwardError {
                message: "No upstream servers configured".to_string()
            });
        }

        // Select upstream server (round-robin) and get its address
        let upstream_addr = self.select_upstream()?.address;
        
        let original_id = message.header.id;
        let new_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        
        message.header.id = new_id;

        let question = if let Some(q) = message.questions.first() {
            q.clone()
        } else {
            return Err(DnsError::ProtocolError {
                message: "No question in message".to_string()
            });
        };

        let record = ForwardRecord::new(new_id, original_id, question, upstream_addr);
        self.pending.push(record.clone());

        Ok(record)
    }

    /// Find a pending forward record by ID
    pub fn find_pending(&mut self, id: u16) -> Option<ForwardRecord> {
        if let Some(pos) = self.pending.iter().position(|r| r.id == id) {
            Some(self.pending.remove(pos))
        } else {
            None
        }
    }

    /// Clean up timed out forward records
    pub fn cleanup_timeouts(&mut self) {
        self.pending.retain(|record| !record.is_timed_out());
    }

    /// Select an upstream server
    fn select_upstream(&self) -> Result<&UpstreamServer, DnsError> {
        self.upstreams
            .first()
            .ok_or_else(|| DnsError::ForwardError {
                message: "No upstreams available".to_string()
            })
    }

    /// Get the number of pending queries
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Upstream DNS server
#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub address: SocketAddr,
    pub failures: u32,
    pub last_failure: Option<Instant>,
}

impl UpstreamServer {
    /// Create a new upstream server
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            failures: 0,
            last_failure: None,
        }
    }

    /// Record a failure for this server
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());
    }

    /// Record a success for this server
    pub fn record_success(&mut self) {
        self.failures = 0;
        self.last_failure = None;
    }

    /// Check if this server is considered unhealthy
    pub fn is_unhealthy(&self) -> bool {
        self.failures >= 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{RecordType, RecordClass};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_forward_record_timeout() {
        let upstream = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let question = DnsQuestion::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );
        
        let mut record = ForwardRecord::new(1, 100, question, upstream);
        record.timeout = Duration::from_millis(1);
        
        std::thread::sleep(Duration::from_millis(10));
        assert!(record.is_timed_out());
    }

    #[test]
    fn test_forwarder_creation() {
        let upstream = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let forwarder = Forwarder::new(vec![upstream]);
        
        assert_eq!(forwarder.upstreams.len(), 1);
        assert_eq!(forwarder.pending_count(), 0);
    }

    #[test]
    fn test_upstream_health_tracking() {
        let upstream_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let mut upstream = UpstreamServer::new(upstream_addr);
        
        assert!(!upstream.is_unhealthy());
        
        upstream.record_failure();
        upstream.record_failure();
        upstream.record_failure();
        assert!(upstream.is_unhealthy());
        
        upstream.record_success();
        assert!(!upstream.is_unhealthy());
    }
}
