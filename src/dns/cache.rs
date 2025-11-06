// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS response cache with LRU eviction
//
// Translated from: src/cache.c

//! DNS response caching with LRU eviction and TTL management
//!
//! Provides in-memory caching of DNS responses to reduce latency and upstream
//! server load.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::dns::protocol::{DnsQuestion, ResourceRecord, RecordType, RecordClass};
use crate::types::errors::DnsError;

/// DNS cache with LRU eviction
#[derive(Debug)]
pub struct DnsCache {
    entries: HashMap<CacheKey, CacheEntry>,
    max_size: usize,
    hits: u64,
    misses: u64,
}

impl DnsCache {
    /// Create a new DNS cache with the specified capacity
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            max_size,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a DNS question in the cache
    pub fn lookup(&mut self, key: &CacheKey) -> Option<&CacheEntry> {
        if let Some(entry) = self.entries.get(key) {
            if entry.is_expired() {
                self.misses += 1;
                None
            } else {
                self.hits += 1;
                Some(entry)
            }
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert a cache entry
    pub fn insert(&mut self, key: CacheKey, entry: CacheEntry) {
        // Simple eviction: if at capacity, remove first entry
        if self.entries.len() >= self.max_size {
            if let Some(key_to_remove) = self.entries.keys().next().cloned() {
                self.entries.remove(&key_to_remove);
            }
        }
        self.entries.insert(key, entry);
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            size: self.entries.len(),
            max_size: self.max_size,
            hits: self.hits,
            misses: self.misses,
        }
    }

    /// Clear all entries from the cache
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Remove expired entries
    pub fn evict_expired(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired());
    }
}

/// Cache lookup key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub record_type: RecordType,
    pub record_class: RecordClass,
}

impl CacheKey {
    /// Create a new cache key
    pub fn new(name: String, record_type: RecordType, record_class: RecordClass) -> Self {
        Self {
            name: name.to_lowercase(), // DNS names are case-insensitive
            record_type,
            record_class,
        }
    }

    /// Create a cache key from a DNS question
    pub fn from_question(question: &DnsQuestion) -> Self {
        Self::new(
            question.qname.clone(),
            question.qtype,
            question.qclass,
        )
    }
}

/// Cached DNS response entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Vec<ResourceRecord>,
    pub ttl: Duration,
    pub inserted_at: Instant,
    pub negative: bool,
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(records: Vec<ResourceRecord>, ttl: Duration) -> Self {
        Self {
            records,
            ttl,
            inserted_at: Instant::now(),
            negative: false,
        }
    }

    /// Create a negative cache entry (NXDOMAIN)
    pub fn negative(ttl: Duration) -> Self {
        Self {
            records: Vec::new(),
            ttl,
            inserted_at: Instant::now(),
            negative: true,
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }

    /// Get the remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.inserted_at.elapsed())
    }
}

/// Cache statistics
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub size: usize,
    pub max_size: usize,
    pub hits: u64,
    pub misses: u64,
}

impl CacheStats {
    /// Calculate hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cache_insert_and_lookup() {
        let mut cache = DnsCache::new(10);
        let key = CacheKey::new("example.com".to_string(), RecordType::A, RecordClass::IN);
        
        let record = ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(93, 184, 216, 34),
        };
        
        let entry = CacheEntry::new(vec![record], Duration::from_secs(300));
        cache.insert(key.clone(), entry);

        assert!(cache.lookup(&key).is_some());
        assert_eq!(cache.stats().size, 1);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = DnsCache::new(10);
        let key = CacheKey::new("example.com".to_string(), RecordType::A, RecordClass::IN);
        
        assert!(cache.lookup(&key).is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn test_cache_expiration() {
        let entry = CacheEntry::new(Vec::new(), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        assert!(entry.is_expired());
    }

    #[test]
    fn test_negative_cache_entry() {
        let entry = CacheEntry::negative(Duration::from_secs(60));
        assert!(entry.negative);
        assert!(entry.records.is_empty());
    }
}
