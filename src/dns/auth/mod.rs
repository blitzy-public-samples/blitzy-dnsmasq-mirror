// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// Authoritative DNS server functionality
//
// Translated from: src/auth.c

//! Authoritative DNS server implementation
//!
//! Provides authoritative DNS responses for configured zones,
//! supporting SOA, NS, A, AAAA, and other record types.

pub mod zone;

pub use zone::AuthZone;

use crate::dns::protocol::{DnsMessage, DnsQuestion, ResourceRecord};
use crate::types::errors::DnsError;

/// Authoritative DNS server
#[derive(Debug)]
pub struct AuthServer {
    zones: Vec<AuthZone>,
}

impl AuthServer {
    /// Create a new authoritative server
    pub fn new() -> Self {
        Self { zones: Vec::new() }
    }

    /// Add a zone to the authoritative server
    pub fn add_zone(&mut self, zone: AuthZone) {
        self.zones.push(zone);
    }

    /// Check if a question is within an authoritative zone
    pub fn is_authoritative(&self, question: &DnsQuestion) -> bool {
        self.zones.iter().any(|zone| zone.contains(&question.qname))
    }

    /// Generate an authoritative response for a question
    pub fn generate_response(
        &self,
        question: &DnsQuestion,
    ) -> Result<Vec<ResourceRecord>, DnsError> {
        for zone in &self.zones {
            if zone.contains(&question.qname) {
                return zone.lookup(question);
            }
        }

        Err(DnsError::NotFound {
            message: format!("No authoritative zone for {}", question.qname),
        })
    }

    /// Get the number of configured zones
    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }
}

impl Default for AuthServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{RecordClass, RecordType};

    #[test]
    fn test_auth_server_creation() {
        let server = AuthServer::new();
        assert_eq!(server.zone_count(), 0);
    }

    #[test]
    fn test_add_zone() {
        let mut server = AuthServer::new();
        let soa = zone::SoaRecord {
            primary_ns: "ns1.example.com".to_string(),
            admin_email: "admin.example.com".to_string(),
            serial: 1,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum: 86400,
        };
        let zone = AuthZone::new("example.com".to_string(), soa);

        server.add_zone(zone);
        assert_eq!(server.zone_count(), 1);
    }

    #[test]
    fn test_is_authoritative() {
        let mut server = AuthServer::new();
        let soa = zone::SoaRecord {
            primary_ns: "ns1.example.com".to_string(),
            admin_email: "admin.example.com".to_string(),
            serial: 1,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum: 86400,
        };
        let zone = AuthZone::new("example.com".to_string(), soa);
        server.add_zone(zone);

        let question = DnsQuestion::new(
            "www.example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );

        assert!(server.is_authoritative(&question));
    }

    #[test]
    fn test_not_authoritative() {
        let mut server = AuthServer::new();
        let soa = zone::SoaRecord {
            primary_ns: "ns1.example.com".to_string(),
            admin_email: "admin.example.com".to_string(),
            serial: 1,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum: 86400,
        };
        let zone = AuthZone::new("example.com".to_string(), soa);
        server.add_zone(zone);

        let question = DnsQuestion::new(
            "www.example.org".to_string(),
            RecordType::A,
            RecordClass::IN,
        );

        assert!(!server.is_authoritative(&question));
    }
}
