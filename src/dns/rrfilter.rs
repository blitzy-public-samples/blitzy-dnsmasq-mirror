// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// Resource record filtering
//
// Translated from: src/rrfilter.c

//! DNS resource record filtering
//!
//! Filters DNS resource records based on query type and configured policies
//! to control which records are returned to clients.

use crate::dns::protocol::{ResourceRecord, RecordType};

/// Resource record filter
#[derive(Debug, Clone)]
pub struct RRFilter {
    allowed_types: Vec<RecordType>,
    blocked_types: Vec<RecordType>,
}

impl RRFilter {
    /// Create a new RR filter
    pub fn new() -> Self {
        Self {
            allowed_types: Vec::new(),
            blocked_types: Vec::new(),
        }
    }

    /// Allow a specific record type
    pub fn allow_type(mut self, record_type: RecordType) -> Self {
        self.allowed_types.push(record_type);
        self
    }

    /// Block a specific record type
    pub fn block_type(mut self, record_type: RecordType) -> Self {
        self.blocked_types.push(record_type);
        self
    }

    /// Check if a record should be filtered out
    pub fn should_filter(&self, record: &ResourceRecord) -> bool {
        let record_type = record.record_type();

        // If explicitly blocked, filter it
        if self.blocked_types.contains(&record_type) {
            return true;
        }

        // If we have an allow list and the type is not in it, filter it
        if !self.allowed_types.is_empty() && !self.allowed_types.contains(&record_type) {
            return true;
        }

        false
    }

    /// Filter a list of records
    pub fn filter_records(&self, records: Vec<ResourceRecord>) -> Vec<ResourceRecord> {
        records
            .into_iter()
            .filter(|record| !self.should_filter(record))
            .collect()
    }
}

impl Default for RRFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::dns::protocol::RecordClass;

    #[test]
    fn test_filter_creation() {
        let filter = RRFilter::new();
        assert!(filter.allowed_types.is_empty());
        assert!(filter.blocked_types.is_empty());
    }

    #[test]
    fn test_block_type() {
        let filter = RRFilter::new().block_type(RecordType::A);
        
        let a_record = ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(1, 2, 3, 4),
        };

        let cname_record = ResourceRecord::CNAME {
            name: "www.example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            cname: "example.com".to_string(),
        };

        assert!(filter.should_filter(&a_record));
        assert!(!filter.should_filter(&cname_record));
    }

    #[test]
    fn test_allow_type() {
        let filter = RRFilter::new().allow_type(RecordType::A);
        
        let a_record = ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(1, 2, 3, 4),
        };

        let cname_record = ResourceRecord::CNAME {
            name: "www.example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            cname: "example.com".to_string(),
        };

        assert!(!filter.should_filter(&a_record));
        assert!(filter.should_filter(&cname_record));
    }

    #[test]
    fn test_filter_records() {
        let filter = RRFilter::new().block_type(RecordType::A);
        
        let records = vec![
            ResourceRecord::A {
                name: "example.com".to_string(),
                class: RecordClass::IN,
                ttl: 300,
                address: Ipv4Addr::new(1, 2, 3, 4),
            },
            ResourceRecord::CNAME {
                name: "www.example.com".to_string(),
                class: RecordClass::IN,
                ttl: 300,
                cname: "example.com".to_string(),
            },
        ];

        let filtered = filter.filter_records(records);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].record_type(), RecordType::CNAME);
    }
}
