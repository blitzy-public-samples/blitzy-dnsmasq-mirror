//! DNS cache data structures
//!
//! Defines types for DNS cache entries, replacing C structs from cache.c.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// Cache entry type discriminator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheEntryType {
    /// IPv4 address record
    A,
    /// IPv6 address record
    Aaaa,
    /// Canonical name record
    Cname,
    /// Pointer record (reverse lookup)
    Ptr,
    /// Mail exchange record
    Mx,
    /// Service record
    Srv,
    /// Text record
    Txt,
    /// Negative cache entry (NXDOMAIN or NODATA)
    Negative,
}

/// Cache entry data payload
#[derive(Debug, Clone)]
pub enum CacheData {
    /// IPv4 address
    A(Ipv4Addr),
    /// IPv6 address
    Aaaa(Ipv6Addr),
    /// Canonical name
    Cname(String),
    /// Pointer (reverse lookup domain)
    Ptr(String),
    /// Mail exchange (priority, hostname)
    Mx { priority: u16, hostname: String },
    /// Service record
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Text record
    Txt(Vec<String>),
    /// Negative cache entry
    Negative,
}

impl CacheData {
    /// Get the cache entry type for this data
    pub fn entry_type(&self) -> CacheEntryType {
        match self {
            CacheData::A(_) => CacheEntryType::A,
            CacheData::Aaaa(_) => CacheEntryType::Aaaa,
            CacheData::Cname(_) => CacheEntryType::Cname,
            CacheData::Ptr(_) => CacheEntryType::Ptr,
            CacheData::Mx { .. } => CacheEntryType::Mx,
            CacheData::Srv { .. } => CacheEntryType::Srv,
            CacheData::Txt(_) => CacheEntryType::Txt,
            CacheData::Negative => CacheEntryType::Negative,
        }
    }
}

/// A single DNS cache entry
///
/// Replaces C's struct crec from cache.c with safe Rust implementation.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Domain name (e.g., "example.com")
    pub name: String,
    
    /// Resource record data
    pub data: CacheData,
    
    /// Time when this entry was created
    pub created_at: Instant,
    
    /// Time-to-live in seconds (from DNS response)
    pub ttl: u32,
    
    /// Flags for this cache entry
    pub flags: CacheFlags,
}

impl CacheEntry {
    /// Create a new cache entry
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name
    /// * `data` - Resource record data
    /// * `ttl` - Time-to-live in seconds
    pub fn new(name: String, data: CacheData, ttl: u32) -> Self {
        Self {
            name,
            data,
            created_at: Instant::now(),
            ttl,
            flags: CacheFlags::default(),
        }
    }

    /// Check if this cache entry has expired
    pub fn is_expired(&self) -> bool {
        let elapsed = self.created_at.elapsed();
        elapsed >= Duration::from_secs(self.ttl as u64)
    }

    /// Get remaining TTL in seconds
    pub fn remaining_ttl(&self) -> u32 {
        let elapsed = self.created_at.elapsed().as_secs() as u32;
        self.ttl.saturating_sub(elapsed)
    }

    /// Get the entry type
    pub fn entry_type(&self) -> CacheEntryType {
        self.data.entry_type()
    }
}

/// Cache entry flags
///
/// Replaces C bit flags with type-safe bitflags.
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheFlags {
    /// Entry came from /etc/hosts or static configuration
    pub is_static: bool,
    
    /// Entry has been validated by DNSSEC
    pub is_dnssec_validated: bool,
    
    /// Entry is a negative cache (NXDOMAIN or NODATA)
    pub is_negative: bool,
    
    /// Entry is from authoritative nameserver
    pub is_authoritative: bool,
}

impl CacheFlags {
    /// Create default flags
    pub fn new() -> Self {
        Self::default()
    }

    /// Create flags for static entry
    pub fn static_entry() -> Self {
        Self {
            is_static: true,
            ..Default::default()
        }
    }

    /// Create flags for negative cache entry
    pub fn negative_entry() -> Self {
        Self {
            is_negative: true,
            ..Default::default()
        }
    }
}

/// Cache lookup key
///
/// Used for efficient cache lookups combining name and type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Domain name
    pub name: String,
    /// Entry type
    pub entry_type: CacheEntryType,
}

impl CacheKey {
    /// Create a new cache key
    pub fn new(name: String, entry_type: CacheEntryType) -> Self {
        Self { name, entry_type }
    }
}

/// Cache statistics
///
/// Tracks cache performance metrics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total number of cache hits
    pub hits: u64,
    
    /// Total number of cache misses
    pub misses: u64,
    
    /// Total number of insertions
    pub insertions: u64,
    
    /// Total number of evictions
    pub evictions: u64,
    
    /// Current number of entries
    pub entries: usize,
}

impl CacheStats {
    /// Create new empty statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate cache hit rate (0.0 to 1.0)
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Record a cache hit
    pub fn record_hit(&mut self) {
        self.hits += 1;
    }

    /// Record a cache miss
    pub fn record_miss(&mut self) {
        self.misses += 1;
    }

    /// Record an insertion
    pub fn record_insertion(&mut self) {
        self.insertions += 1;
    }

    /// Record an eviction
    pub fn record_eviction(&mut self) {
        self.evictions += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_cache_entry_basic() {
        let entry = CacheEntry::new(
            "example.com".to_string(),
            CacheData::A(Ipv4Addr::new(93, 184, 216, 34)),
            300,
        );

        assert_eq!(entry.name, "example.com");
        assert_eq!(entry.ttl, 300);
        assert_eq!(entry.entry_type(), CacheEntryType::A);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_ttl() {
        let entry = CacheEntry::new(
            "example.com".to_string(),
            CacheData::A(Ipv4Addr::new(93, 184, 216, 34)),
            1, // 1 second TTL
        );

        assert!(!entry.is_expired());
        assert_eq!(entry.remaining_ttl(), 1);

        // Sleep for 2 seconds to let it expire
        thread::sleep(StdDuration::from_secs(2));
        
        assert!(entry.is_expired());
        assert_eq!(entry.remaining_ttl(), 0);
    }

    #[test]
    fn test_cache_data_types() {
        let data_a = CacheData::A(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(data_a.entry_type(), CacheEntryType::A);

        let data_aaaa = CacheData::Aaaa(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(data_aaaa.entry_type(), CacheEntryType::Aaaa);

        let data_cname = CacheData::Cname("alias.example.com".to_string());
        assert_eq!(data_cname.entry_type(), CacheEntryType::Cname);
    }

    #[test]
    fn test_cache_flags() {
        let mut flags = CacheFlags::new();
        assert!(!flags.is_static);
        assert!(!flags.is_dnssec_validated);

        flags.is_static = true;
        assert!(flags.is_static);

        let static_flags = CacheFlags::static_entry();
        assert!(static_flags.is_static);
    }

    #[test]
    fn test_cache_key() {
        let key1 = CacheKey::new("example.com".to_string(), CacheEntryType::A);
        let key2 = CacheKey::new("example.com".to_string(), CacheEntryType::A);
        let key3 = CacheKey::new("example.com".to_string(), CacheEntryType::Aaaa);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_stats() {
        let mut stats = CacheStats::new();
        
        assert_eq!(stats.hit_rate(), 0.0);
        
        stats.record_hit();
        stats.record_hit();
        stats.record_miss();
        
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 2.0 / 3.0);
    }
}
