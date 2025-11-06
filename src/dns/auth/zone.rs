// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// Authoritative DNS zone management
//
// Translated from: src/auth.c (zone management portions)

//! DNS zone data management for authoritative server
//!
//! Manages DNS zone records and provides query responses for authoritative zones.

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::dns::protocol::{DnsQuestion, ResourceRecord, RecordType, RecordClass};
use crate::types::errors::DnsError;

/// Authoritative DNS zone
#[derive(Debug, Clone)]
pub struct AuthZone {
    pub name: String,
    pub records: Vec<ZoneRecord>,
    pub soa: Option<SoaRecord>,
}

impl AuthZone {
    /// Create a new authoritative zone
    pub fn new(name: String) -> Self {
        Self {
            name: name.to_lowercase(),
            records: Vec::new(),
            soa: None,
        }
    }

    /// Add a record to the zone
    pub fn add_record(&mut self, record: ZoneRecord) {
        self.records.push(record);
    }

    /// Set the SOA record for the zone
    pub fn set_soa(&mut self, soa: SoaRecord) {
        self.soa = Some(soa);
    }

    /// Check if a name is within this zone
    pub fn contains(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        let zone_lower = self.name.to_lowercase();
        
        name_lower == zone_lower || name_lower.ends_with(&format!(".{}", zone_lower))
    }

    /// Look up records matching a question
    pub fn lookup(&self, question: &DnsQuestion) -> Result<Vec<ResourceRecord>, DnsError> {
        let mut results = Vec::new();

        for record in &self.records {
            if record.matches(question) {
                results.push(record.to_resource_record());
            }
        }

        if results.is_empty() {
            Err(DnsError::NotFound {
                message: format!("No records for {}", question.qname)
            })
        } else {
            Ok(results)
        }
    }

    /// Get the number of records in the zone
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

/// Zone record entry
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub name: String,
    pub record_type: RecordType,
    pub class: RecordClass,
    pub ttl: u32,
    pub data: ZoneRecordData,
}

impl ZoneRecord {
    /// Check if this record matches a DNS question
    pub fn matches(&self, question: &DnsQuestion) -> bool {
        let name_match = self.name.eq_ignore_ascii_case(&question.qname);
        let type_match = self.record_type == question.qtype || question.qtype == RecordType::ANY;
        let class_match = self.class == question.qclass || question.qclass == RecordClass::ANY;

        name_match && type_match && class_match
    }

    /// Convert to a ResourceRecord
    pub fn to_resource_record(&self) -> ResourceRecord {
        match &self.data {
            ZoneRecordData::A { address } => ResourceRecord::A {
                name: self.name.clone(),
                class: self.class,
                ttl: self.ttl,
                address: *address,
            },
            ZoneRecordData::AAAA { address } => ResourceRecord::AAAA {
                name: self.name.clone(),
                class: self.class,
                ttl: self.ttl,
                address: *address,
            },
            ZoneRecordData::CNAME { cname } => ResourceRecord::CNAME {
                name: self.name.clone(),
                class: self.class,
                ttl: self.ttl,
                cname: cname.clone(),
            },
            ZoneRecordData::NS { nsdname } => ResourceRecord::NS {
                name: self.name.clone(),
                class: self.class,
                ttl: self.ttl,
                nsdname: nsdname.clone(),
            },
            ZoneRecordData::PTR { ptrdname } => ResourceRecord::PTR {
                name: self.name.clone(),
                class: self.class,
                ttl: self.ttl,
                ptrdname: ptrdname.clone(),
            },
            ZoneRecordData::TXT { text } => ResourceRecord::TXT {
                name: self.name.clone(),
                class: self.class,
                ttl: self.ttl,
                data: text.clone(),
            },
        }
    }
}

/// Zone record data
#[derive(Debug, Clone)]
pub enum ZoneRecordData {
    A { address: Ipv4Addr },
    AAAA { address: Ipv6Addr },
    CNAME { cname: String },
    NS { nsdname: String },
    PTR { ptrdname: String },
    TXT { text: Vec<String> },
}

/// SOA (Start of Authority) record
#[derive(Debug, Clone)]
pub struct SoaRecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl SoaRecord {
    /// Create a new SOA record
    pub fn new(mname: String, rname: String) -> Self {
        Self {
            mname,
            rname,
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 300,
        }
    }

    /// Convert to a ResourceRecord
    pub fn to_resource_record(&self, zone_name: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord::SOA {
            name: zone_name.to_string(),
            class: RecordClass::IN,
            ttl,
            mname: self.mname.clone(),
            rname: self.rname.clone(),
            serial: self.serial,
            refresh: self.refresh,
            retry: self.retry,
            expire: self.expire,
            minimum: self.minimum,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_creation() {
        let zone = AuthZone::new("example.com".to_string());
        assert_eq!(zone.name, "example.com");
        assert_eq!(zone.record_count(), 0);
    }

    #[test]
    fn test_zone_contains() {
        let zone = AuthZone::new("example.com".to_string());
        
        assert!(zone.contains("example.com"));
        assert!(zone.contains("www.example.com"));
        assert!(zone.contains("mail.example.com"));
        assert!(!zone.contains("example.org"));
    }

    #[test]
    fn test_add_record() {
        let mut zone = AuthZone::new("example.com".to_string());
        
        let record = ZoneRecord {
            name: "www.example.com".to_string(),
            record_type: RecordType::A,
            class: RecordClass::IN,
            ttl: 300,
            data: ZoneRecordData::A {
                address: Ipv4Addr::new(93, 184, 216, 34),
            },
        };
        
        zone.add_record(record);
        assert_eq!(zone.record_count(), 1);
    }

    #[test]
    fn test_record_matches() {
        let record = ZoneRecord {
            name: "www.example.com".to_string(),
            record_type: RecordType::A,
            class: RecordClass::IN,
            ttl: 300,
            data: ZoneRecordData::A {
                address: Ipv4Addr::new(93, 184, 216, 34),
            },
        };

        let question = DnsQuestion::new(
            "www.example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );

        assert!(record.matches(&question));
    }

    #[test]
    fn test_zone_lookup() {
        let mut zone = AuthZone::new("example.com".to_string());
        
        let record = ZoneRecord {
            name: "www.example.com".to_string(),
            record_type: RecordType::A,
            class: RecordClass::IN,
            ttl: 300,
            data: ZoneRecordData::A {
                address: Ipv4Addr::new(93, 184, 216, 34),
            },
        };
        
        zone.add_record(record);

        let question = DnsQuestion::new(
            "www.example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );

        let results = zone.lookup(&question);
        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 1);
    }

    #[test]
    fn test_soa_record() {
        let soa = SoaRecord::new(
            "ns1.example.com".to_string(),
            "admin.example.com".to_string(),
        );

        assert_eq!(soa.mname, "ns1.example.com");
        assert_eq!(soa.rname, "admin.example.com");
        assert_eq!(soa.serial, 1);
    }
}
