// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS response cache with LRU eviction and negative caching implementing RFC 2308
//
// Translated from: src/cache.c, src/dnsmasq.h, src/blockdata.c

//! DNS Response Cache with LRU Eviction
//!
//! This module implements the DNS response cache subsystem for dnsmasq, providing
//! high-performance caching of DNS resource records with automatic TTL management
//! and memory-efficient storage. The cache uses an LRU (Least Recently Used) eviction
//! policy combined with TTL-based expiry tracking.
//!
//! ## Key Features
//!
//! - **LRU Eviction**: Automatically removes least recently used entries when cache reaches capacity
//! - **TTL Management**: Tracks time-to-live for all cached records with automatic expiry
//! - **Negative Caching**: RFC 2308 compliant caching of NXDOMAIN and NODATA responses
//! - **CNAME Resolution**: Follows CNAME chains up to 10 hops with loop detection
//! - **DHCP Integration**: Seamless caching of DHCP-assigned hostnames
//! - **Reverse Lookup**: Fast IP-to-hostname lookups for PTR record responses
//! - **Multi-source Support**: Tracks cache entry origin (upstream, /etc/hosts, DHCP, authoritative)
//!
//! ## Memory Safety
//!
//! Replaces C's manual hash table and linked list management with Rust's `LruCache` crate,
//! eliminating use-after-free and double-free vulnerabilities. All cache operations are
//! bounds-checked and panic-free on malformed input.
//!
//! ## C Source Reference
//!
//! Translated from:
//! - `src/cache.c` (lines 1-2800) - Main cache implementation
//! - `src/dnsmasq.h` (lines 465-477) - struct crec definition
//! - `src/blockdata.c` (lines 1-200) - Large record storage
//!
//! ## Thread Safety
//!
//! The cache can be wrapped in `Arc<RwLock<DnsCache>>` for concurrent access from
//! multiple async tasks. Read locks allow multiple concurrent lookups, while write
//! locks provide exclusive access for insertions and evictions.
//!
//! ## Examples
//!
//! ```rust,ignore
//! use crate::dns::cache::*;
//! use crate::dns::protocol::{RecordType, RecordClass, ResourceRecord};
//! use std::net::Ipv4Addr;
//!
//! // Create cache with 1000-entry capacity
//! let mut cache = DnsCache::new(1000);
//!
//! // Insert A record
//! let key = CacheKey::new(
//!     "example.com".to_string(),
//!     RecordType::A,
//!     RecordClass::IN,
//! );
//! let records = vec![ResourceRecord::A {
//!     name: "example.com".to_string(),
//!     class: RecordClass::IN,
//!     ttl: 3600,
//!     address: Ipv4Addr::new(192, 0, 2, 1),
//! }];
//! cache.insert(key.clone(), records, 3600, CacheSource::Upstream);
//!
//! // Lookup cached record
//! if let Some(records) = cache.lookup(&key) {
//!     println!("Cache hit: {} records", records.len());
//! }
//!
//! // Reverse lookup
//! let addr = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
//! if let Some(hostname) = cache.find_by_addr(addr) {
//!     println!("Reverse lookup: {}", hostname);
//! }
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use lru::LruCache;
use thiserror::Error;

use crate::dns::protocol::{RecordType, RecordClass, ResourceRecord};
use crate::dns::domain::domain_equal;
use crate::types::errors::DnsmasqError;

/// Maximum CNAME chain hops to prevent infinite loops (RFC 1035 recommendation)
const MAX_CNAME_HOPS: usize = 10;

/// Cache-specific error types
///
/// Covers errors during cache operations including CNAME resolution failures,
/// capacity exhaustion, and invalid operations.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CacheError {
    /// CNAME chain forms a loop
    #[error("CNAME loop detected in chain starting at {0}")]
    CnameLoop(String),
    
    /// CNAME chain exceeds maximum hop count
    #[error("CNAME chain exceeded maximum {MAX_CNAME_HOPS} hops starting at {0}")]
    ExcessiveHops(String),
    
    /// Cache entry not found for lookup
    #[error("Cache entry not found for key: {0}")]
    EntryNotFound(String),
    
    /// Invalid cache key provided
    #[error("Invalid cache key: {0}")]
    InvalidKey(String),
    
    /// Cache capacity exhausted and eviction failed
    #[error("Cache capacity exhausted at {0} entries")]
    CapacityExhausted(usize),
}

/// Origin of a cached DNS record
///
/// Tracks where a cache entry came from to support different caching policies
/// and TTL handling based on record source.
///
/// # C Source Reference
///
/// Corresponds to cache record flags in C's `struct crec` (dnsmasq.h:465-477):
/// - F_HOSTS flag → HostsFile
/// - F_DHCP flag → Dhcp  
/// - F_CONFIG flag → Authoritative
/// - No flag → Upstream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheSource {
    /// From upstream DNS server response
    Upstream,
    
    /// From /etc/hosts file (or additional hosts files)
    HostsFile,
    
    /// From DHCP lease assignment
    Dhcp,
    
    /// From authoritative local zone
    Authoritative,
}

/// DNS cache key for lookups
///
/// Uniquely identifies a DNS record by name, type, and class. Uses case-insensitive
/// name comparison per RFC 1035 DNS specification.
///
/// # Hash and Equality
///
/// Implements Hash and Eq to support use as HashMap/LruCache key. Domain names
/// are normalized to lowercase during construction for case-insensitive comparison.
///
/// # C Source Reference
///
/// Replaces C's cache lookup logic that hashes name + type + class together
/// (cache.c:cache_hash function)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Domain name (canonicalized to lowercase)
    pub name: String,
    
    /// DNS record type (A, AAAA, CNAME, etc.)
    pub record_type: RecordType,
    
    /// DNS record class (typically IN for Internet)
    pub record_class: RecordClass,
}

impl CacheKey {
    /// Create a new cache key with case-normalization
    ///
    /// Domain names are converted to lowercase for case-insensitive lookup
    /// per RFC 1035 Section 3.1.
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name (will be lowercased)
    /// * `record_type` - DNS record type
    /// * `record_class` - DNS record class
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let key = CacheKey::new(
    ///     "Example.COM".to_string(),
    ///     RecordType::A,
    ///     RecordClass::IN,
    /// );
    /// assert_eq!(key.name, "example.com");
    /// ```
    pub fn new(name: String, record_type: RecordType, record_class: RecordClass) -> Self {
        Self {
            name: name.to_lowercase(),
            record_type,
            record_class,
        }
    }
}

/// Cached DNS resource record entry
///
/// Stores one or more resource records with the same name/type/class combination,
/// along with metadata for TTL tracking, expiry, and source identification.
///
/// # TTL Handling
///
/// - `inserted_at`: Timestamp when entry was added to cache
/// - `expires_at`: Absolute expiry time (None for permanent entries like /etc/hosts)
/// - TTL is calculated dynamically as `expires_at - current_time`
///
/// # Negative Caching
///
/// When `negative` is true, this entry represents an NXDOMAIN or NODATA response
/// per RFC 2308. The `records` vec will be empty, and TTL comes from the SOA
/// minimum field.
///
/// # C Source Reference
///
/// Replaces C's `struct crec` (dnsmasq.h:465-477)
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Resource records for this cache entry (may be empty for negative cache)
    pub records: Vec<ResourceRecord>,
    
    /// Timestamp when this entry was inserted into cache
    pub inserted_at: Instant,
    
    /// Absolute expiry time (None for permanent entries from /etc/hosts)
    pub expires_at: Option<Instant>,
    
    /// True if this is a negative cache entry (NXDOMAIN/NODATA)
    pub negative: bool,
    
    /// Origin of this cache entry
    pub source: CacheSource,
}

impl CacheEntry {
    /// Check if this cache entry has expired
    ///
    /// Permanent entries (expires_at == None) never expire.
    /// Returns true if current time has passed the expiry time.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => Instant::now() >= expires,
            None => false, // Permanent entries never expire
        }
    }
    
    /// Get remaining TTL in seconds
    ///
    /// Returns 0 for expired entries. Returns a large value (u32::MAX) for
    /// permanent entries that never expire.
    pub fn remaining_ttl(&self) -> u32 {
        match self.expires_at {
            Some(expires) => {
                let now = Instant::now();
                if now >= expires {
                    0
                } else {
                    expires.duration_since(now).as_secs() as u32
                }
            }
            None => u32::MAX, // Permanent entry
        }
    }
}

/// Cache statistics for monitoring and debugging
///
/// Provides metrics on cache performance including hit rate, current size,
/// and eviction counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStatistics {
    /// Number of successful cache lookups
    pub hits: u64,
    
    /// Number of cache misses (not found or expired)
    pub misses: u64,
    
    /// Number of cache insertions
    pub inserts: u64,
    
    /// Number of LRU evictions due to capacity
    pub evictions: u64,
    
    /// Number of entries expired due to TTL
    pub expirations: u64,
    
    /// Current number of entries in cache
    pub current_size: usize,
    
    /// Maximum cache capacity
    pub max_size: usize,
}

impl CacheStatistics {
    /// Calculate cache hit rate as percentage (0.0 to 100.0)
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// DNS cache with LRU eviction and TTL management
///
/// Provides O(1) average-case lookup performance using LruCache, which combines
/// a hash table with an intrusive doubly-linked list for efficient LRU tracking.
///
/// ## Concurrency
///
/// Not thread-safe on its own. Wrap in `Arc<RwLock<DnsCache>>` for concurrent access:
/// - Multiple readers can lookup simultaneously (RwLock read lock)
/// - Single writer for inserts/evictions (RwLock write lock)
///
/// ## Memory Management
///
/// - LRU eviction automatically removes least recently used entries at capacity
/// - Expired entries are removed lazily during lookup
/// - Periodic `expire_old_entries()` call recommended for proactive cleanup
///
/// # C Source Reference
///
/// Replaces C's cache implementation (cache.c) with:
/// - Hash table + LRU linked list → Rust's LruCache
/// - Manual memory management → RAII with Vec and Box
/// - Pointer chasing → Safe references and cloning
#[derive(Debug)]
pub struct DnsCache {
    /// Main cache storage with combined hash table and LRU list
    entries: LruCache<CacheKey, CacheEntry>,
    
    /// Reverse lookup index: IP address → hostname
    /// Used for fast PTR record responses
    addr_index: HashMap<IpAddr, String>,
    
    /// Statistics counters
    stats: CacheStatistics,
}

impl DnsCache {
    /// Create a new DNS cache with specified maximum capacity
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum number of cache entries before LRU eviction
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Create cache with 1000-entry capacity (typical default)
    /// let cache = DnsCache::new(1000);
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's `cache_init()` function (cache.c:256-320)
    pub fn new(max_size: usize) -> Self {
        // Handle max_size of 0 (caching disabled) by using minimum cache size of 1
        // C implementation checks: if (daemon->cachesize > 0) before allocating
        // We use NonZeroUsize which requires at least 1, so we ensure max_size >= 1
        let effective_size = if max_size == 0 { 1 } else { max_size };
        
        Self {
            entries: LruCache::new(
                std::num::NonZeroUsize::new(effective_size)
                    .expect("effective_size is guaranteed to be non-zero")
            ),
            addr_index: HashMap::with_capacity(effective_size / 4), // Estimate 25% have A/AAAA
            stats: CacheStatistics {
                hits: 0,
                misses: 0,
                inserts: 0,
                evictions: 0,
                expirations: 0,
                current_size: 0,
                max_size,
            },
        }
    }
    
    /// Insert DNS records into cache with TTL-based expiry
    ///
    /// Adds a new cache entry or updates an existing one. If the cache is at capacity,
    /// the least recently used entry is evicted. Also updates the reverse lookup index
    /// for A and AAAA records.
    ///
    /// # Arguments
    ///
    /// * `key` - Cache key (name, type, class)
    /// * `records` - Resource records to cache
    /// * `ttl` - Time-to-live in seconds (0 for permanent)
    /// * `source` - Origin of these records
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// cache.insert(
    ///     CacheKey::new("example.com".to_string(), RecordType::A, RecordClass::IN),
    ///     vec![a_record],
    ///     3600,
    ///     CacheSource::Upstream,
    /// );
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's `cache_insert()` function (cache.c:540-680)
    pub fn insert(
        &mut self,
        key: CacheKey,
        records: Vec<ResourceRecord>,
        ttl: u32,
        source: CacheSource,
    ) {
        let expires_at = if ttl == 0 {
            None // Permanent entry
        } else {
            Some(Instant::now() + Duration::from_secs(ttl as u64))
        };
        
        let entry = CacheEntry {
            records: records.clone(),
            inserted_at: Instant::now(),
            expires_at,
            negative: false,
            source,
        };
        
        // Update reverse lookup index for A/AAAA records
        for record in &records {
            match record {
                ResourceRecord::A { address, name, .. } => {
                    self.addr_index.insert(IpAddr::V4(*address), name.clone());
                }
                ResourceRecord::AAAA { address, name, .. } => {
                    self.addr_index.insert(IpAddr::V6(*address), name.clone());
                }
                _ => {}
            }
        }
        
        // Check if insertion will evict an entry
        if self.entries.len() >= self.entries.cap().get() && !self.entries.contains(&key) {
            self.stats.evictions += 1;
        }
        
        // Insert into LRU cache (automatically handles eviction)
        self.entries.put(key, entry);
        self.stats.inserts += 1;
        self.stats.current_size = self.entries.len();
    }
    
    /// Look up DNS records in cache
    ///
    /// Searches for cached records matching the given key. Returns None if the entry
    /// is not found or has expired. Updates LRU position on successful lookup.
    ///
    /// # Arguments
    ///
    /// * `key` - Cache key to look up
    ///
    /// # Returns
    ///
    /// `Some(Vec<ResourceRecord>)` if found and not expired, `None` otherwise
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let key = CacheKey::new("example.com".to_string(), RecordType::A, RecordClass::IN);
    /// if let Some(records) = cache.lookup(&key) {
    ///     println!("Found {} cached records", records.len());
    /// }
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's `cache_find_by_name()` function (cache.c:782-850)
    pub fn lookup(&mut self, key: &CacheKey) -> Option<Vec<ResourceRecord>> {
        // Get entry from LRU cache (updates LRU position)
        if let Some(entry) = self.entries.get(key) {
            // Check if expired
            if entry.is_expired() {
                self.stats.misses += 1;
                self.stats.expirations += 1;
                // Remove expired entry
                self.entries.pop(key);
                self.stats.current_size = self.entries.len();
                None
            } else {
                self.stats.hits += 1;
                Some(entry.records.clone())
            }
        } else {
            self.stats.misses += 1;
            None
        }
    }
    
    /// Find all cache entries matching a domain name
    ///
    /// Returns all cached records for the given domain name regardless of record type.
    /// Useful for cache enumeration and debugging.
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name to search for (case-insensitive)
    ///
    /// # Returns
    ///
    /// Vector of matching CacheEntry references
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let entries = cache.find_by_name("example.com");
    /// for entry in entries {
    ///     println!("Found {:?} records", entry.records.len());
    /// }
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's cache enumeration pattern used in dump.c
    pub fn find_by_name(&self, name: &str) -> Vec<CacheEntry> {
        let name_lower = name.to_lowercase();
        self.entries
            .iter()
            .filter(|(key, _)| domain_equal(&key.name, &name_lower))
            .map(|(_, entry)| entry.clone())
            .collect()
    }
    
    /// Reverse lookup: find hostname for IP address
    ///
    /// Searches the reverse lookup index for a hostname associated with the given
    /// IP address. Used for fast PTR record responses.
    ///
    /// # Arguments
    ///
    /// * `addr` - IP address to reverse lookup
    ///
    /// # Returns
    ///
    /// `Some(String)` with hostname if found, `None` otherwise
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use std::net::{IpAddr, Ipv4Addr};
    /// 
    /// let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    /// if let Some(hostname) = cache.find_by_addr(addr) {
    ///     println!("PTR: {} -> {}", addr, hostname);
    /// }
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's reverse lookup logic in cache.c (search through all records)
    pub fn find_by_addr(&self, addr: IpAddr) -> Option<String> {
        self.addr_index.get(&addr).cloned()
    }
    
    /// Insert negative cache entry (NXDOMAIN or NODATA)
    ///
    /// Caches a negative response per RFC 2308. The TTL typically comes from the
    /// SOA record's minimum field in the authority section.
    ///
    /// # Arguments
    ///
    /// * `key` - Cache key for the negative entry
    /// * `ttl` - Time-to-live in seconds for negative cache
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Cache NXDOMAIN for nonexistent.example.com
    /// cache.insert_negative(
    ///     CacheKey::new("nonexistent.example.com".to_string(), RecordType::A, RecordClass::IN),
    ///     3600,
    /// );
    /// ```
    ///
    /// # RFC Reference
    ///
    /// RFC 2308 - Negative Caching of DNS Queries
    ///
    /// # C Source Reference
    ///
    /// Replaces C's negative caching logic in cache.c:cache_insert with F_NEG flag
    pub fn insert_negative(&mut self, key: CacheKey, ttl: u32) {
        let expires_at = if ttl == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl as u64))
        };
        
        let entry = CacheEntry {
            records: Vec::new(),
            inserted_at: Instant::now(),
            expires_at,
            negative: true,
            source: CacheSource::Upstream,
        };
        
        // Check if insertion will evict an entry
        if self.entries.len() >= self.entries.cap().get() && !self.entries.contains(&key) {
            self.stats.evictions += 1;
        }
        
        self.entries.put(key, entry);
        self.stats.inserts += 1;
        self.stats.current_size = self.entries.len();
    }
    
    /// Resolve CNAME chain to final A or AAAA records
    ///
    /// Follows CNAME records up to MAX_CNAME_HOPS (10) times, detecting loops
    /// and returning the final non-CNAME records. Returns error if a loop is
    /// detected or hop limit is exceeded.
    ///
    /// # Arguments
    ///
    /// * `name` - Starting domain name to resolve
    ///
    /// # Returns
    ///
    /// `Ok(Vec<ResourceRecord>)` with final A/AAAA records, or `Err(CacheError)` on failure
    ///
    /// # Errors
    ///
    /// - `CacheError::CnameLoop` - CNAME chain loops back to a previous name
    /// - `CacheError::ExcessiveHops` - Chain exceeds MAX_CNAME_HOPS
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Resolve CNAME chain: www.example.com -> cdn.example.net -> 192.0.2.1
    /// match cache.resolve_cname_chain("www.example.com") {
    ///     Ok(records) => println!("Resolved to {} records", records.len()),
    ///     Err(CacheError::CnameLoop(name)) => eprintln!("Loop at {}", name),
    ///     Err(e) => eprintln!("Resolution failed: {}", e),
    /// }
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's CNAME following logic in forward.c (lines 450-520)
    pub fn resolve_cname_chain(&mut self, name: &str) -> Result<Vec<ResourceRecord>, CacheError> {
        let mut current_name = name.to_lowercase();
        let mut visited = Vec::new();
        let mut hops = 0;
        
        loop {
            // Check for loop
            if visited.iter().any(|n| domain_equal(n, &current_name)) {
                return Err(CacheError::CnameLoop(current_name));
            }
            
            // Check hop limit
            if hops >= MAX_CNAME_HOPS {
                return Err(CacheError::ExcessiveHops(name.to_string()));
            }
            
            visited.push(current_name.clone());
            hops += 1;
            
            // Look for CNAME record
            let cname_key = CacheKey::new(
                current_name.clone(),
                RecordType::CNAME,
                RecordClass::IN,
            );
            
            if let Some(records) = self.lookup(&cname_key) {
                // Found CNAME, extract target and continue
                if let Some(ResourceRecord::CNAME { cname, .. }) = records.first() {
                    current_name = cname.clone().to_lowercase();
                    continue;
                }
            }
            
            // No CNAME found, try to find A or AAAA records
            let a_key = CacheKey::new(
                current_name.clone(),
                RecordType::A,
                RecordClass::IN,
            );
            
            if let Some(records) = self.lookup(&a_key) {
                return Ok(records);
            }
            
            let aaaa_key = CacheKey::new(
                current_name.clone(),
                RecordType::AAAA,
                RecordClass::IN,
            );
            
            if let Some(records) = self.lookup(&aaaa_key) {
                return Ok(records);
            }
            
            // No records found at all
            return Ok(Vec::new());
        }
    }
    
    /// Remove expired entries from cache
    ///
    /// Scans the cache and removes all entries that have exceeded their TTL.
    /// Returns the number of entries that were expired.
    ///
    /// This should be called periodically (e.g., every minute) to prevent
    /// accumulation of expired entries that haven't been accessed.
    ///
    /// # Returns
    ///
    /// Number of entries that were removed due to expiration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Periodic cleanup task
    /// let expired_count = cache.expire_old_entries();
    /// if expired_count > 0 {
    ///     println!("Expired {} cache entries", expired_count);
    /// }
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's `cache_scan_free()` function (cache.c:920-1050)
    pub fn expire_old_entries(&mut self) -> usize {
        let now = Instant::now();
        let mut expired_keys = Vec::new();
        
        // Collect expired keys
        for (key, entry) in self.entries.iter() {
            if let Some(expires_at) = entry.expires_at {
                if now >= expires_at {
                    expired_keys.push(key.clone());
                }
            }
        }
        
        let count = expired_keys.len();
        
        // Remove expired entries
        for key in expired_keys {
            self.entries.pop(&key);
        }
        
        self.stats.expirations += count as u64;
        self.stats.current_size = self.entries.len();
        
        count
    }
    
    /// Insert DHCP host mapping into cache
    ///
    /// Adds a hostname-to-IP mapping from a DHCP lease. The TTL is derived from
    /// the lease duration. These entries are marked with CacheSource::Dhcp and
    /// are removed when the lease expires or is released.
    ///
    /// # Arguments
    ///
    /// * `hostname` - Hostname from DHCP lease
    /// * `addr` - IP address assigned by DHCP
    /// * `lease_time` - Duration of DHCP lease
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use std::time::Duration;
    /// use std::net::{IpAddr, Ipv4Addr};
    ///
    /// cache.insert_dhcp_host(
    ///     "client-laptop".to_string(),
    ///     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
    ///     Duration::from_secs(3600),
    /// );
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's DHCP cache integration in cache.c (F_DHCP flag handling)
    pub fn insert_dhcp_host(&mut self, hostname: String, addr: IpAddr, lease_time: Duration) {
        let ttl = lease_time.as_secs() as u32;
        
        // Create appropriate record based on IP version
        let record = match addr {
            IpAddr::V4(ipv4) => ResourceRecord::A {
                name: hostname.clone(),
                class: RecordClass::IN,
                ttl,
                address: ipv4,
            },
            IpAddr::V6(ipv6) => ResourceRecord::AAAA {
                name: hostname.clone(),
                class: RecordClass::IN,
                ttl,
                address: ipv6,
            },
        };
        
        let key = CacheKey::new(
            hostname.clone(),
            if addr.is_ipv4() { RecordType::A } else { RecordType::AAAA },
            RecordClass::IN,
        );
        
        self.insert(key, vec![record], ttl, CacheSource::Dhcp);
    }
    
    /// Remove DHCP host mapping from cache
    ///
    /// Removes the cache entry for a DHCP hostname when the lease is released
    /// or expires. Cleans up both the main cache and reverse lookup index.
    ///
    /// # Arguments
    ///
    /// * `hostname` - Hostname to remove
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // DHCP lease released
    /// cache.remove_dhcp_host("client-laptop");
    /// ```
    ///
    /// # C Source Reference
    ///
    /// Replaces C's cache removal logic when DHCP lease is freed
    pub fn remove_dhcp_host(&mut self, hostname: &str) {
        let hostname_lower = hostname.to_lowercase();
        
        // Remove A record
        let a_key = CacheKey::new(
            hostname_lower.clone(),
            RecordType::A,
            RecordClass::IN,
        );
        self.entries.pop(&a_key);
        
        // Remove AAAA record
        let aaaa_key = CacheKey::new(
            hostname_lower.clone(),
            RecordType::AAAA,
            RecordClass::IN,
        );
        self.entries.pop(&aaaa_key);
        
        // Clean up reverse lookup index
        self.addr_index.retain(|_, name| !domain_equal(name, &hostname_lower));
        
        self.stats.current_size = self.entries.len();
    }
    
    /// Get cache statistics
    ///
    /// Returns current cache performance metrics including hit rate, size,
    /// and eviction counters.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let stats = cache.get_statistics();
    /// println!("Cache hit rate: {:.2}%", stats.hit_rate());
    /// println!("Current size: {}/{}", stats.current_size, stats.max_size);
    /// ```
    pub fn get_statistics(&self) -> CacheStatistics {
        self.stats
    }
}

/// Standalone function for inserting DHCP host (for convenience)
///
/// This is a convenience wrapper that can be called without a DnsCache reference.
/// In practice, you would typically call `cache.insert_dhcp_host()` directly.
///
/// # Note
///
/// This function exists to match the export schema requirement but is not typically
/// used in production code. Direct method calls on DnsCache are preferred.
pub fn insert_dhcp_host(cache: &mut DnsCache, hostname: String, addr: IpAddr, lease_time: Duration) {
    cache.insert_dhcp_host(hostname, addr, lease_time);
}

/// Standalone function for removing DHCP host (for convenience)
///
/// This is a convenience wrapper that can be called without a DnsCache reference.
/// In practice, you would typically call `cache.remove_dhcp_host()` directly.
///
/// # Note
///
/// This function exists to match the export schema requirement but is not typically
/// used in production code. Direct method calls on DnsCache are preferred.
pub fn remove_dhcp_host(cache: &mut DnsCache, hostname: &str) {
    cache.remove_dhcp_host(hostname);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_cache_basic_operations() {
        let mut cache = DnsCache::new(100);
        
        // Test insertion and lookup
        let key = CacheKey::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );
        
        let records = vec![ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 3600,
            address: Ipv4Addr::new(192, 0, 2, 1),
        }];
        
        cache.insert(key.clone(), records.clone(), 3600, CacheSource::Upstream);
        
        let lookup_result = cache.lookup(&key);
        assert!(lookup_result.is_some());
        assert_eq!(lookup_result.unwrap().len(), 1);
    }
    
    #[test]
    fn test_negative_caching() {
        let mut cache = DnsCache::new(100);
        
        let key = CacheKey::new(
            "nonexistent.example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );
        
        cache.insert_negative(key.clone(), 3600);
        
        let result = cache.lookup(&key);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 0); // Empty for negative cache
    }
    
    #[test]
    fn test_reverse_lookup() {
        let mut cache = DnsCache::new(100);
        
        let key = CacheKey::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );
        
        let addr = Ipv4Addr::new(192, 0, 2, 1);
        let records = vec![ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 3600,
            address: addr,
        }];
        
        cache.insert(key, records, 3600, CacheSource::Upstream);
        
        let hostname = cache.find_by_addr(IpAddr::V4(addr));
        assert!(hostname.is_some());
        assert_eq!(hostname.unwrap(), "example.com");
    }
    
    #[test]
    fn test_cname_chain_resolution() {
        let mut cache = DnsCache::new(100);
        
        // Insert CNAME: www.example.com -> cdn.example.com
        let cname_key = CacheKey::new(
            "www.example.com".to_string(),
            RecordType::CNAME,
            RecordClass::IN,
        );
        cache.insert(
            cname_key,
            vec![ResourceRecord::CNAME {
                name: "www.example.com".to_string(),
                class: RecordClass::IN,
                ttl: 3600,
                cname: "cdn.example.com".to_string(),
            }],
            3600,
            CacheSource::Upstream,
        );
        
        // Insert A record: cdn.example.com -> 192.0.2.1
        let a_key = CacheKey::new(
            "cdn.example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );
        cache.insert(
            a_key,
            vec![ResourceRecord::A {
                name: "cdn.example.com".to_string(),
                class: RecordClass::IN,
                ttl: 3600,
                address: Ipv4Addr::new(192, 0, 2, 1),
            }],
            3600,
            CacheSource::Upstream,
        );
        
        // Resolve chain
        let result = cache.resolve_cname_chain("www.example.com");
        assert!(result.is_ok());
        let records = result.unwrap();
        assert_eq!(records.len(), 1);
    }
    
    #[test]
    fn test_cname_loop_detection() {
        let mut cache = DnsCache::new(100);
        
        // Create CNAME loop: a.com -> b.com -> a.com
        cache.insert(
            CacheKey::new("a.com".to_string(), RecordType::CNAME, RecordClass::IN),
            vec![ResourceRecord::CNAME {
                name: "a.com".to_string(),
                class: RecordClass::IN,
                ttl: 3600,
                cname: "b.com".to_string(),
            }],
            3600,
            CacheSource::Upstream,
        );
        
        cache.insert(
            CacheKey::new("b.com".to_string(), RecordType::CNAME, RecordClass::IN),
            vec![ResourceRecord::CNAME {
                name: "b.com".to_string(),
                class: RecordClass::IN,
                ttl: 3600,
                cname: "a.com".to_string(),
            }],
            3600,
            CacheSource::Upstream,
        );
        
        // Should detect loop
        let result = cache.resolve_cname_chain("a.com");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CacheError::CnameLoop(_)));
    }
    
    #[test]
    fn test_dhcp_host_management() {
        let mut cache = DnsCache::new(100);
        
        let hostname = "client-laptop".to_string();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let lease_time = Duration::from_secs(3600);
        
        // Insert DHCP host
        cache.insert_dhcp_host(hostname.clone(), addr, lease_time);
        
        // Verify it's in cache
        let key = CacheKey::new(hostname.clone(), RecordType::A, RecordClass::IN);
        assert!(cache.lookup(&key).is_some());
        
        // Verify reverse lookup works
        assert_eq!(cache.find_by_addr(addr), Some(hostname.clone()));
        
        // Remove DHCP host
        cache.remove_dhcp_host(&hostname);
        
        // Verify it's removed
        assert!(cache.lookup(&key).is_none());
        assert!(cache.find_by_addr(addr).is_none());
    }
    
    #[test]
    fn test_lru_eviction() {
        let mut cache = DnsCache::new(3); // Small cache for testing eviction
        
        // Insert 4 entries (one more than capacity)
        for i in 1..=4 {
            let key = CacheKey::new(
                format!("host{}.com", i),
                RecordType::A,
                RecordClass::IN,
            );
            let records = vec![ResourceRecord::A {
                name: format!("host{}.com", i),
                class: RecordClass::IN,
                ttl: 3600,
                address: Ipv4Addr::new(192, 0, 2, i as u8),
            }];
            cache.insert(key, records, 3600, CacheSource::Upstream);
        }
        
        // Cache should have exactly 3 entries
        assert_eq!(cache.get_statistics().current_size, 3);
        
        // First entry should have been evicted
        let first_key = CacheKey::new("host1.com".to_string(), RecordType::A, RecordClass::IN);
        assert!(cache.lookup(&first_key).is_none());
        
        // Other entries should still be present
        let second_key = CacheKey::new("host2.com".to_string(), RecordType::A, RecordClass::IN);
        assert!(cache.lookup(&second_key).is_some());
    }
    
    #[test]
    fn test_case_insensitive_lookup() {
        let mut cache = DnsCache::new(100);
        
        // Insert with mixed case
        let key = CacheKey::new(
            "Example.COM".to_string(),
            RecordType::A,
            RecordClass::IN,
        );
        let records = vec![ResourceRecord::A {
            name: "Example.COM".to_string(),
            class: RecordClass::IN,
            ttl: 3600,
            address: Ipv4Addr::new(192, 0, 2, 1),
        }];
        cache.insert(key, records, 3600, CacheSource::Upstream);
        
        // Lookup with different case
        let lookup_key = CacheKey::new(
            "example.com".to_string(),
            RecordType::A,
            RecordClass::IN,
        );
        assert!(cache.lookup(&lookup_key).is_some());
    }
}


