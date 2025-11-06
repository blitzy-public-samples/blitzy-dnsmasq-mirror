//! Authoritative DNS server
//!
//! Provides authoritative DNS responses for configured zones.
//! Replaces C implementation from auth.c.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;

use crate::dns::protocol::DnsRrType;

/// Authoritative zone resource record
#[derive(Debug, Clone)]
pub enum AuthRecord {
    /// IPv4 address record
    A { address: Ipv4Addr },
    
    /// IPv6 address record
    Aaaa { address: Ipv6Addr },
    
    /// Canonical name record
    Cname { target: String },
    
    /// Name server record
    Ns { nameserver: String },
    
    /// Mail exchange record
    Mx { priority: u16, hostname: String },
    
    /// Text record
    Txt { data: Vec<String> },
    
    /// Start of authority record
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
}

impl AuthRecord {
    /// Get the RR type for this record
    pub fn rr_type(&self) -> DnsRrType {
        match self {
            AuthRecord::A { .. } => DnsRrType::A,
            AuthRecord::Aaaa { .. } => DnsRrType::AAAA,
            AuthRecord::Cname { .. } => DnsRrType::CNAME,
            AuthRecord::Ns { .. } => DnsRrType::NS,
            AuthRecord::Mx { .. } => DnsRrType::MX,
            AuthRecord::Txt { .. } => DnsRrType::TXT,
            AuthRecord::Soa { .. } => DnsRrType::SOA,
        }
    }
}

/// Authoritative zone entry
#[derive(Debug, Clone)]
pub struct ZoneEntry {
    /// Domain name for this entry
    pub name: String,
    
    /// Resource records for this name
    pub records: Vec<AuthRecord>,
    
    /// TTL for all records in this entry
    pub ttl: u32,
}

impl ZoneEntry {
    /// Create a new zone entry
    pub fn new(name: String, ttl: u32) -> Self {
        Self {
            name: name.to_lowercase(),
            records: Vec::new(),
            ttl,
        }
    }

    /// Add a record to this entry
    pub fn add_record(&mut self, record: AuthRecord) {
        self.records.push(record);
    }

    /// Get records of a specific type
    pub fn get_records(&self, rr_type: DnsRrType) -> Vec<&AuthRecord> {
        self.records
            .iter()
            .filter(|r| r.rr_type() == rr_type)
            .collect()
    }
}

/// Authoritative DNS zone
#[derive(Debug, Clone)]
pub struct AuthZone {
    /// Zone name (e.g., "example.com")
    pub zone: String,
    
    /// Zone entries (domain name -> entry)
    entries: HashMap<String, ZoneEntry>,
    
    /// Default TTL for the zone
    pub default_ttl: u32,
}

impl AuthZone {
    /// Create a new authoritative zone
    ///
    /// # Arguments
    ///
    /// * `zone` - Zone name (e.g., "example.com")
    /// * `default_ttl` - Default TTL for records
    pub fn new(zone: String, default_ttl: u32) -> Self {
        Self {
            zone: zone.to_lowercase(),
            entries: HashMap::new(),
            default_ttl,
        }
    }

    /// Add a zone entry
    pub fn add_entry(&mut self, entry: ZoneEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Look up a name in the zone
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name to look up
    ///
    /// # Returns
    ///
    /// Returns Some(entry) if found, None otherwise.
    pub fn lookup(&self, name: &str) -> Option<&ZoneEntry> {
        let name_lower = name.to_lowercase();
        self.entries.get(&name_lower)
    }

    /// Check if a name is in this zone
    pub fn contains(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        
        // Check exact match
        if name_lower == self.zone {
            return true;
        }
        
        // Check if subdomain
        name_lower.ends_with(&format!(".{}", self.zone))
    }

    /// Get the number of entries in the zone
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the zone has no entries
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Authoritative DNS server
///
/// Manages multiple authoritative zones and answers queries for them.
pub struct AuthServer {
    /// Map from zone name to zone
    zones: HashMap<String, AuthZone>,
}

impl AuthServer {
    /// Create a new authoritative server
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
        }
    }

    /// Add a zone to the server
    pub fn add_zone(&mut self, zone: AuthZone) {
        self.zones.insert(zone.zone.clone(), zone);
    }

    /// Find the zone for a given domain name
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to query
    ///
    /// # Returns
    ///
    /// Returns Some(zone) if a matching zone is found, None otherwise.
    pub fn find_zone(&self, domain: &str) -> Option<&AuthZone> {
        let domain_lower = domain.to_lowercase();
        
        // Try exact match first
        if let Some(zone) = self.zones.get(&domain_lower) {
            return Some(zone);
        }
        
        // Try to find a parent zone
        for zone in self.zones.values() {
            if zone.contains(&domain_lower) {
                return Some(zone);
            }
        }
        
        None
    }

    /// Query for records in authoritative zones
    ///
    /// # Arguments
    ///
    /// * `domain` - Domain name to query
    /// * `rr_type` - Record type to query
    ///
    /// # Returns
    ///
    /// Returns Some(records) if found in an authoritative zone, None otherwise.
    pub fn query(&self, domain: &str, rr_type: DnsRrType) -> Option<Vec<&AuthRecord>> {
        let zone = self.find_zone(domain)?;
        let entry = zone.lookup(domain)?;
        
        let records = entry.get_records(rr_type);
        if records.is_empty() {
            None
        } else {
            Some(records)
        }
    }

    /// Get the number of zones
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Check if there are no zones
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
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

    #[test]
    fn test_auth_record_type() {
        let record_a = AuthRecord::A {
            address: Ipv4Addr::new(192, 168, 1, 1),
        };
        assert_eq!(record_a.rr_type(), DnsRrType::A);

        let record_aaaa = AuthRecord::Aaaa {
            address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        };
        assert_eq!(record_aaaa.rr_type(), DnsRrType::AAAA);
    }

    #[test]
    fn test_zone_entry_basic() {
        let mut entry = ZoneEntry::new("www.example.com".to_string(), 300);
        
        entry.add_record(AuthRecord::A {
            address: Ipv4Addr::new(192, 168, 1, 1),
        });
        
        assert_eq!(entry.records.len(), 1);
        assert_eq!(entry.ttl, 300);
    }

    #[test]
    fn test_zone_entry_filter_by_type() {
        let mut entry = ZoneEntry::new("example.com".to_string(), 300);
        
        entry.add_record(AuthRecord::A {
            address: Ipv4Addr::new(192, 168, 1, 1),
        });
        entry.add_record(AuthRecord::Aaaa {
            address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        });
        
        let a_records = entry.get_records(DnsRrType::A);
        assert_eq!(a_records.len(), 1);
        
        let aaaa_records = entry.get_records(DnsRrType::AAAA);
        assert_eq!(aaaa_records.len(), 1);
        
        let mx_records = entry.get_records(DnsRrType::MX);
        assert_eq!(mx_records.len(), 0);
    }

    #[test]
    fn test_auth_zone_basic() {
        let zone = AuthZone::new("example.com".to_string(), 300);
        
        assert_eq!(zone.zone, "example.com");
        assert_eq!(zone.default_ttl, 300);
        assert!(zone.is_empty());
    }

    #[test]
    fn test_auth_zone_add_lookup() {
        let mut zone = AuthZone::new("example.com".to_string(), 300);
        
        let mut entry = ZoneEntry::new("www.example.com".to_string(), 300);
        entry.add_record(AuthRecord::A {
            address: Ipv4Addr::new(192, 168, 1, 1),
        });
        
        zone.add_entry(entry);
        
        assert_eq!(zone.len(), 1);
        
        let found = zone.lookup("www.example.com");
        assert!(found.is_some());
        
        let not_found = zone.lookup("mail.example.com");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_auth_zone_contains() {
        let zone = AuthZone::new("example.com".to_string(), 300);
        
        assert!(zone.contains("example.com"));
        assert!(zone.contains("www.example.com"));
        assert!(zone.contains("mail.example.com"));
        assert!(!zone.contains("example.org"));
    }

    #[test]
    fn test_auth_server_basic() {
        let server = AuthServer::new();
        
        assert!(server.is_empty());
        assert_eq!(server.len(), 0);
    }

    #[test]
    fn test_auth_server_add_zone() {
        let mut server = AuthServer::new();
        
        let zone = AuthZone::new("example.com".to_string(), 300);
        server.add_zone(zone);
        
        assert_eq!(server.len(), 1);
        assert!(!server.is_empty());
    }

    #[test]
    fn test_auth_server_find_zone() {
        let mut server = AuthServer::new();
        
        let zone = AuthZone::new("example.com".to_string(), 300);
        server.add_zone(zone);
        
        assert!(server.find_zone("example.com").is_some());
        assert!(server.find_zone("www.example.com").is_some());
        assert!(server.find_zone("example.org").is_none());
    }

    #[test]
    fn test_auth_server_query() {
        let mut server = AuthServer::new();
        
        let mut zone = AuthZone::new("example.com".to_string(), 300);
        
        let mut entry = ZoneEntry::new("www.example.com".to_string(), 300);
        entry.add_record(AuthRecord::A {
            address: Ipv4Addr::new(192, 168, 1, 1),
        });
        zone.add_entry(entry);
        
        server.add_zone(zone);
        
        let result = server.query("www.example.com", DnsRrType::A);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
        
        let no_result = server.query("www.example.com", DnsRrType::AAAA);
        assert!(no_result.is_none());
    }
}
