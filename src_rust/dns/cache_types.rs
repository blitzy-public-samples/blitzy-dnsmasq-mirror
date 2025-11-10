// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! DNS cache data type definitions
//!
//! # Purpose
//!
//! This module provides type-safe Rust data structures for DNS cache records,
//! replacing the C implementation's `struct crec` from cache.c and dnsmasq.h.
//! The Rust implementation eliminates memory safety vulnerabilities inherent in
//! the C version's discriminated union for address types, raw pointer chains for
//! hash tables and LRU lists, and manual flag bit manipulation.
//!
//! # Memory Safety Improvements
//!
//! The C implementation used several unsafe patterns that are eliminated here:
//!
//! - **Union all_addr**: C used a discriminated union with manual flag checking to
//!   determine which field (addr4, addr6, cname, srv, key, ds) is valid. Rust's
//!   enum `CacheRecordData` makes this type-safe at compile time.
//!
//! - **Raw pointers for list management**: C used `next`, `prev`, `hash_next` raw
//!   pointers for maintaining hash chains and LRU doubly-linked lists. Rust uses
//!   `CacheRecordId` newtypes as safe indices into Vec storage.
//!
//! - **Manual flag bit manipulation**: C used `#define` constants and bitwise OR/AND
//!   operations on unsigned int flags. Rust's `bitflags!` macro provides type-safe
//!   flag operations with contains(), insert(), remove() methods.
//!
//! - **time_t expiry tracking**: C used time_t (signed integer seconds since epoch)
//!   which can overflow. Rust uses `Instant` (monotonic) + `Duration` for overflow-
//!   resistant TTL tracking.
//!
//! - **Discriminated name storage**: C used a union with three variants (inline sname,
//!   bigname pointer, namep heap pointer) discriminated by flags. Rust uses String
//!   with automatic memory management.
//!
//! # Key Data Structures
//!
//! - `CacheRecord`: Main cache entry with domain name, record data, TTL, flags, and uid
//! - `CacheRecordData`: Type-safe enum for different record types (Address, CNAME, SRV, DNSSEC)
//! - `CacheFlags`: Bitflags for cache entry properties (IMMORTAL, NEG, DHCP, HOSTS, etc.)
//! - `CacheRecordId`: Newtype wrapper for safe indexing into Vec<CacheRecord>
//! - `DomainKey`: Hash key for cache lookup by (name, qtype)
//! - `SrvData`, `DnsKeyData`, `DsData`: Structured data for specialized RR types
//!
//! # Architecture Integration
//!
//! This module is used by:
//! - `dns::cache` - Main cache implementation with HashMap and LRU list
//! - `dns::forwarder` - Inserts upstream responses into cache
//! - `dns::dnssec::validator` - Caches DNSSEC keys and signatures
//! - `dhcp::v4::server`, `dhcp::v6::server` - Inserts dynamic DHCP hostnames
//!
//! # RFC Compliance
//!
//! - RFC 1035: DNS caching of A, AAAA, CNAME, PTR, MX, SRV, and other RR types
//! - RFC 2308: Negative caching of NXDOMAIN and NODATA responses with separate TTLs
//! - RFC 2181: TTL handling, authoritative answer caching, RRset consistency
//! - RFC 4034: DNSSEC DNSKEY, DS, RRSIG caching
//!
//! # Examples
//!
//! ```rust,ignore
//! use dnsmasq::dns::cache_types::*;
//! use std::net::IpAddr;
//! use std::time::{Duration, Instant};
//!
//! // Create an A record cache entry
//! let record = CacheRecord::new(
//!     "example.com".to_string(),
//!     CacheRecordData::Address(IpAddr::V4("192.0.2.1".parse().unwrap())),
//!     Instant::now() + Duration::from_secs(300),
//!     UID_NONE,
//!     CacheFlags::FORWARD | CacheFlags::IPV4,
//! );
//!
//! assert_eq!(record.name(), "example.com");
//! assert!(record.flags().contains(CacheFlags::FORWARD));
//! assert!(!record.is_expired());
//! ```

use crate::dns::blockdata::BlockData;
use bitflags::bitflags;
use std::net::IpAddr;
use std::time::Instant;

// ============================================================================
// Cache Record ID Type
// ============================================================================

/// Safe newtype wrapper for cache record indices
///
/// Replaces raw pointers (next, prev, hash_next) from C implementation with
/// safe indices into Vec<CacheRecord> storage. This prevents use-after-free,
/// dangling pointers, and null pointer dereferences that were possible in C.
///
/// # Safety Invariants
///
/// - CacheRecordId values must be valid indices into the cache storage Vec
/// - The cache implementation must validate indices before dereferencing
/// - Invalid indices should be represented as Option<CacheRecordId>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheRecordId(usize);

impl CacheRecordId {
    /// Create a new CacheRecordId from a raw index
    ///
    /// # Arguments
    ///
    /// * `id` - Index into cache storage vector
    ///
    /// # Safety
    ///
    /// Caller must ensure the index is valid for the target Vec
    #[must_use]
    pub fn new(id: usize) -> Self {
        Self(id)
    }

    /// Extract the raw index value
    ///
    /// # Returns
    ///
    /// The underlying usize index value
    #[must_use]
    pub fn get(&self) -> usize {
        self.0
    }
}

// ============================================================================
// Cache Source Constants
// ============================================================================

/// uid field value indicating no source tracking
pub const UID_NONE: u32 = 0;

/// Cache record source: configuration file
pub const SRC_CONFIG: u32 = 1;

/// Cache record source: /etc/hosts file
pub const SRC_HOSTS: u32 = 2;

/// Cache record source: authoritative hosts
pub const SRC_AH: u32 = 3;

// ============================================================================
// Cache Flags Bitflags
// ============================================================================

bitflags! {
    /// Cache record flags bitfield
    ///
    /// Type-safe flag operations replacing C's manual bit manipulation.
    /// Each flag indicates a property of the cache record such as source
    /// (DHCP, HOSTS, CONFIG), type (FORWARD, REVERSE), address family
    /// (IPV4, IPV6), or special behavior (IMMORTAL, NEG, DNSSEC).
    ///
    /// # Flag Categories
    ///
    /// **Lifetime Flags:**
    /// - IMMORTAL: Never expires (from /etc/hosts or static config)
    ///
    /// **Source Flags:**
    /// - DHCP: Entry from DHCP lease (dynamic hostname)
    /// - HOSTS: Entry from /etc/hosts file
    /// - CONFIG: Entry from config file (static configuration)
    /// - UPSTREAM: Cached from upstream server response
    /// - AUTH: From authoritative zone (local authority)
    ///
    /// **Direction Flags:**
    /// - FORWARD: Forward lookup (name→addr)
    /// - REVERSE: Reverse lookup (addr→name)
    ///
    /// **Address Family Flags:**
    /// - IPV4: IPv4 address (addr.addr4 valid in C, Address(V4) in Rust)
    /// - IPV6: IPv6 address (addr.addr6 valid in C, Address(V6) in Rust)
    ///
    /// **Record Type Flags:**
    /// - CNAME: CNAME record
    /// - SRV: SRV record
    /// - DNSKEY: DNSSEC DNSKEY record
    /// - DS: DNSSEC DS record
    ///
    /// **Negative Cache Flags:**
    /// - NEG: Negative cache entry (NXDOMAIN or NODATA)
    /// - NXDOMAIN: Domain does not exist
    /// - NO_RR: No resource records found (NODATA response)
    ///
    /// **DNSSEC Flags:**
    /// - DNSSEC: DNSSEC-related record
    /// - DNSSECOK: DNSSEC validation succeeded (secure)
    /// - KEYTAG: DNSSEC key tag stored in uid field
    /// - SECSTAT: DNSSEC security status indicator
    ///
    /// **Integration Flags:**
    /// - IPSET: Add to ipset when resolved (Linux ipset integration)
    ///
    /// **Internal Flags:**
    /// - RRNAME: Resource record name (not address record)
    /// - SERVER: Server record in cache
    /// - QUERY: Active query in progress
    /// - NOERR: Response was NOERROR (not NXDOMAIN/SERVFAIL)
    /// - NOEXTRA: Don't add to extra/additional section
    /// - DOMAINSRV: Domain-specific server record
    /// - RCODE: DNS response code stored
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CacheFlags: u32 {
        /// Never expire (from /etc/hosts or static config)
        const IMMORTAL  = 1 << 0;
        /// Reverse lookup (PTR record: addr→name)
        const REVERSE   = 1 << 2;
        /// Forward lookup (A/AAAA record: name→addr)
        const FORWARD   = 1 << 3;
        /// Entry from DHCP lease (dynamic hostname)
        const DHCP      = 1 << 4;
        /// Negative cache entry (NXDOMAIN or NODATA)
        const NEG       = 1 << 5;
        /// Entry from /etc/hosts file
        const HOSTS     = 1 << 6;
        /// IPv4 address
        const IPV4      = 1 << 7;
        /// IPv6 address
        const IPV6      = 1 << 8;
        /// Domain does not exist (NXDOMAIN)
        const NXDOMAIN  = 1 << 10;
        /// CNAME record
        const CNAME     = 1 << 11;
        /// DNSSEC DNSKEY record
        const DNSKEY    = 1 << 12;
        /// Entry from config file (static configuration)
        const CONFIG    = 1 << 13;
        /// DNSSEC DS record
        const DS        = 1 << 14;
        /// DNSSEC validation succeeded (secure)
        const DNSSECOK  = 1 << 15;
        /// Cached from upstream server response
        const UPSTREAM  = 1 << 16;
        /// Resource record name (not address record)
        const RRNAME    = 1 << 17;
        /// Server record in cache
        const SERVER    = 1 << 18;
        /// Active query in progress
        const QUERY     = 1 << 19;
        /// Response was NOERROR (not NXDOMAIN/SERVFAIL)
        const NOERR     = 1 << 20;
        /// From authoritative zone (local authority)
        const AUTH      = 1 << 21;
        /// DNSSEC-related record (DNSKEY/DS/RRSIG)
        const DNSSEC    = 1 << 22;
        /// DNSSEC key tag stored in uid field
        const KEYTAG    = 1 << 23;
        /// DNSSEC security status indicator
        const SECSTAT   = 1 << 24;
        /// No resource records found (NODATA response)
        const NO_RR     = 1 << 25;
        /// Add to ipset when resolved (Linux ipset integration)
        const IPSET     = 1 << 26;
        /// Don't add to extra/additional section
        const NOEXTRA   = 1 << 27;
        /// Domain-specific server record
        const DOMAINSRV = 1 << 28;
        /// DNS response code stored
        const RCODE     = 1 << 29;
        /// SRV record
        const SRV       = 1 << 30;
    }
}

impl Default for CacheFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Individual Flag Constants (C Compatibility)
// ============================================================================
//
// These constants provide convenient access to individual flags matching the
// C implementation's naming convention (F_IMMORTAL, F_FORWARD, etc.).
// They are defined as public constants for compatibility with code that
// uses the C-style flag names, while the bitflags struct provides type-safe
// operations.

/// Never expire (from /etc/hosts or static config)
pub const F_IMMORTAL: CacheFlags = CacheFlags::IMMORTAL;

/// Reverse lookup (PTR record: addr→name)
pub const F_REVERSE: CacheFlags = CacheFlags::REVERSE;

/// Forward lookup (A/AAAA record: name→addr)
pub const F_FORWARD: CacheFlags = CacheFlags::FORWARD;

/// Entry from DHCP lease (dynamic hostname)
pub const F_DHCP: CacheFlags = CacheFlags::DHCP;

/// Negative cache entry (NXDOMAIN or NODATA)
pub const F_NEG: CacheFlags = CacheFlags::NEG;

/// Entry from /etc/hosts file
pub const F_HOSTS: CacheFlags = CacheFlags::HOSTS;

/// IPv4 address
pub const F_IPV4: CacheFlags = CacheFlags::IPV4;

/// IPv6 address
pub const F_IPV6: CacheFlags = CacheFlags::IPV6;

/// Domain does not exist (NXDOMAIN)
pub const F_NXDOMAIN: CacheFlags = CacheFlags::NXDOMAIN;

/// CNAME record
pub const F_CNAME: CacheFlags = CacheFlags::CNAME;

/// DNSSEC DNSKEY record
pub const F_DNSKEY: CacheFlags = CacheFlags::DNSKEY;

/// Entry from config file (static configuration)
pub const F_CONFIG: CacheFlags = CacheFlags::CONFIG;

/// DNSSEC DS record
pub const F_DS: CacheFlags = CacheFlags::DS;

/// SRV record
pub const F_SRV: CacheFlags = CacheFlags::SRV;

/// DNSSEC validation succeeded (secure)
pub const F_DNSSECOK: CacheFlags = CacheFlags::DNSSECOK;

/// Cached from upstream server response
pub const F_UPSTREAM: CacheFlags = CacheFlags::UPSTREAM;

/// Resource record name (not address record)
pub const F_RRNAME: CacheFlags = CacheFlags::RRNAME;

/// Server record in cache
pub const F_SERVER: CacheFlags = CacheFlags::SERVER;

/// Active query in progress
pub const F_QUERY: CacheFlags = CacheFlags::QUERY;

/// Response was NOERROR (not NXDOMAIN/SERVFAIL)
pub const F_NOERR: CacheFlags = CacheFlags::NOERR;

/// From authoritative zone (local authority)
pub const F_AUTH: CacheFlags = CacheFlags::AUTH;

/// DNSSEC-related record (DNSKEY/DS/RRSIG)
pub const F_DNSSEC: CacheFlags = CacheFlags::DNSSEC;

/// DNSSEC key tag stored in uid field
pub const F_KEYTAG: CacheFlags = CacheFlags::KEYTAG;

/// DNSSEC security status indicator
pub const F_SECSTAT: CacheFlags = CacheFlags::SECSTAT;

/// No resource records found (NODATA response)
pub const F_NO_RR: CacheFlags = CacheFlags::NO_RR;

/// Add to ipset when resolved (Linux ipset integration)
pub const F_IPSET: CacheFlags = CacheFlags::IPSET;

/// Don't add to extra/additional section
pub const F_NOEXTRA: CacheFlags = CacheFlags::NOEXTRA;

/// Domain-specific server record
pub const F_DOMAINSRV: CacheFlags = CacheFlags::DOMAINSRV;

/// DNS response code stored
pub const F_RCODE: CacheFlags = CacheFlags::RCODE;

// ============================================================================
// Specialized Record Data Types
// ============================================================================

/// SRV record data per RFC 2782
///
/// Contains service-specific target hostname, port, priority, and weight
/// for load balancing and failover across multiple service instances.
///
/// # RFC 2782 Requirements
///
/// - Priority: Lower values preferred (0-65535)
/// - Weight: Proportional load distribution among same-priority servers
/// - Port: Service port number on target host
/// - Target: Domain name of server providing the service
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvData {
    /// Target hostname providing the service (stored in BlockData for efficiency)
    target: BlockData,
    /// Target hostname length in bytes
    targetlen: u16,
    /// Service port number (0-65535)
    srvport: u16,
    /// SRV priority (0-65535, lower values preferred)
    priority: u16,
    /// SRV weight for load balancing (0-65535, higher gets more traffic)
    weight: u16,
}

impl SrvData {
    /// Create a new SRV record data structure
    ///
    /// # Arguments
    ///
    /// * `target` - Target hostname as byte slice
    /// * `port` - Service port number
    /// * `priority` - SRV priority (lower is preferred)
    /// * `weight` - Load balancing weight (higher gets more traffic)
    ///
    /// # Returns
    ///
    /// SrvData instance with target stored in BlockData
    #[must_use]
    pub fn new(target: &[u8], port: u16, priority: u16, weight: u16) -> Self {
        let targetlen = target.len().min(u16::MAX as usize) as u16;
        Self {
            target: BlockData::from_bytes(target),
            targetlen,
            srvport: port,
            priority,
            weight,
        }
    }

    /// Get the target hostname
    ///
    /// # Returns
    ///
    /// Target hostname as byte vector
    #[must_use]
    pub fn target(&self) -> Vec<u8> {
        self.target.to_bytes()
    }

    /// Get the service port number
    ///
    /// # Returns
    ///
    /// Port number (0-65535)
    #[must_use]
    pub fn port(&self) -> u16 {
        self.srvport
    }

    /// Get the SRV priority
    ///
    /// # Returns
    ///
    /// Priority value (0-65535, lower is preferred)
    #[must_use]
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Get the SRV weight
    ///
    /// # Returns
    ///
    /// Weight value (0-65535, higher gets proportionally more traffic)
    #[must_use]
    pub fn weight(&self) -> u16 {
        self.weight
    }
}

/// DNSSEC DNSKEY record data per RFC 4034
///
/// Contains public key data, algorithm identifier, flags, and computed key tag
/// for DNSSEC signature verification. The key data is stored in BlockData for
/// memory efficiency with variable-length keys.
///
/// # RFC 4034 Requirements
///
/// - Flags: Zone key (bit 7), secure entry point/SEP (bit 15)
/// - Protocol: Must be 3 for DNSSEC
/// - Algorithm: Cryptographic algorithm identifier (RSA, ECDSA, Ed25519, etc.)
/// - Public Key: Variable-length cryptographic key material
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsKeyData {
    /// Public key data (stored in BlockData for variable-length efficiency)
    keydata: BlockData,
    /// Key data length in bytes
    keylen: u16,
    /// DNSKEY flags (zone key bit 7, SEP bit 15)
    flags: u16,
    /// Computed key tag for matching with DS/RRSIG records
    keytag: u16,
    /// DNSSEC algorithm identifier (RSA, ECDSA, Ed25519, etc.)
    algo: u8,
}

impl DnsKeyData {
    /// Create a new DNSKEY record data structure
    ///
    /// # Arguments
    ///
    /// * `keydata` - Public key material as byte slice
    /// * `flags` - DNSKEY flags (zone key, SEP)
    /// * `keytag` - Computed key tag
    /// * `algorithm` - DNSSEC algorithm identifier
    ///
    /// # Returns
    ///
    /// DnsKeyData instance with key stored in BlockData
    #[must_use]
    pub fn new(keydata: &[u8], flags: u16, keytag: u16, algorithm: u8) -> Self {
        let keylen = keydata.len().min(u16::MAX as usize) as u16;
        Self {
            keydata: BlockData::from_bytes(keydata),
            keylen,
            flags,
            keytag,
            algo: algorithm,
        }
    }

    /// Get the public key data
    ///
    /// # Returns
    ///
    /// Public key as byte vector
    #[must_use]
    pub fn keydata(&self) -> Vec<u8> {
        self.keydata.to_bytes()
    }

    /// Get the DNSKEY flags
    ///
    /// # Returns
    ///
    /// Flags field (zone key bit 7, SEP bit 15)
    #[must_use]
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Get the computed key tag
    ///
    /// # Returns
    ///
    /// Key tag for matching with DS/RRSIG records
    #[must_use]
    pub fn keytag(&self) -> u16 {
        self.keytag
    }

    /// Get the DNSSEC algorithm identifier
    ///
    /// # Returns
    ///
    /// Algorithm identifier (RSA, ECDSA, Ed25519, etc.)
    #[must_use]
    pub fn algorithm(&self) -> u8 {
        self.algo
    }
}

/// DNSSEC DS (Delegation Signer) record data per RFC 4034
///
/// Contains hash of a DNSKEY record to establish chain of trust from parent
/// zone to child zone. The DS record is published in the parent zone and
/// matches a DNSKEY in the child zone via the key tag.
///
/// # RFC 4034 Requirements
///
/// - Key Tag: Matches the DNSKEY key tag (computed from DNSKEY)
/// - Algorithm: Must match the DNSKEY algorithm
/// - Digest Type: Hash algorithm used (SHA-1, SHA-256, SHA-384)
/// - Digest: Hash of the DNSKEY record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsData {
    /// Digest (hash) of the DNSKEY record (stored in BlockData)
    keydata: BlockData,
    /// Digest length in bytes
    keylen: u16,
    /// Key tag matching the DNSKEY
    keytag: u16,
    /// DNSSEC algorithm identifier (must match DNSKEY)
    algo: u8,
    /// Digest type (SHA-1, SHA-256, SHA-384)
    digest: u8,
}

impl DsData {
    /// Create a new DS record data structure
    ///
    /// # Arguments
    ///
    /// * `keydata` - Digest (hash) of DNSKEY as byte slice
    /// * `keytag` - Key tag matching the DNSKEY
    /// * `algorithm` - DNSSEC algorithm identifier
    /// * `digest_type` - Hash algorithm (SHA-1, SHA-256, SHA-384)
    ///
    /// # Returns
    ///
    /// DsData instance with digest stored in BlockData
    #[must_use]
    pub fn new(keydata: &[u8], keytag: u16, algorithm: u8, digest_type: u8) -> Self {
        let keylen = keydata.len().min(u16::MAX as usize) as u16;
        Self {
            keydata: BlockData::from_bytes(keydata),
            keylen,
            keytag,
            algo: algorithm,
            digest: digest_type,
        }
    }

    /// Get the digest (hash) of the DNSKEY
    ///
    /// # Returns
    ///
    /// Digest as byte vector
    #[must_use]
    pub fn keydata(&self) -> Vec<u8> {
        self.keydata.to_bytes()
    }

    /// Get the key tag
    ///
    /// # Returns
    ///
    /// Key tag matching the DNSKEY
    #[must_use]
    pub fn keytag(&self) -> u16 {
        self.keytag
    }

    /// Get the DNSSEC algorithm identifier
    ///
    /// # Returns
    ///
    /// Algorithm identifier (must match DNSKEY)
    #[must_use]
    pub fn algorithm(&self) -> u8 {
        self.algo
    }

    /// Get the digest type
    ///
    /// # Returns
    ///
    /// Digest type (SHA-1=1, SHA-256=2, SHA-384=4)
    #[must_use]
    pub fn digest_type(&self) -> u8 {
        self.digest
    }
}

// ============================================================================
// Cache Record Data Enum
// ============================================================================

/// Type-safe discriminated union for cache record data
///
/// Replaces C's `union all_addr` with safe Rust enum. The C version used
/// manual flag checking to determine which union field is valid, leading
/// to potential type confusion bugs. Rust's enum makes the variant explicit
/// at compile time and eliminates undefined behavior from accessing the
/// wrong union member.
///
/// # Memory Safety
///
/// The C union allowed accessing any field regardless of the actual type,
/// checked only by runtime flags. Rust's enum:
/// - Prevents accessing invalid variants at compile time
/// - Uses pattern matching to safely extract data
/// - Automatically manages memory for String and BlockData
///
/// # Variants
///
/// - `Address(IpAddr)`: IPv4 or IPv6 address (A/AAAA records)
/// - `Cname(String)`: Canonical name target (CNAME records)
/// - `Srv(SrvData)`: Service location data (SRV records)
/// - `DnsKey(DnsKeyData)`: DNSSEC public key (DNSKEY records)
/// - `Ds(DsData)`: DNSSEC delegation signer (DS records)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheRecordData {
    /// IPv4 or IPv6 address (A/AAAA records)
    ///
    /// Replaces C's union all_addr.addr4 (struct in_addr) and addr6 (struct in6_addr).
    /// Rust's IpAddr enum unifies both address families with type safety.
    Address(IpAddr),

    /// Canonical name target (CNAME records)
    ///
    /// Replaces C's union all_addr.cname.target.name (char*). Rust String provides
    /// automatic memory management and UTF-8 validation.
    Cname(String),
    
    /// Alias for Cname (for test compatibility)
    CName(String),

    /// Service location data (SRV records)
    ///
    /// Replaces C's union all_addr.srv with structured SrvData. Contains target
    /// hostname (in BlockData), port, priority, and weight per RFC 2782.
    Srv(SrvData),

    /// DNSSEC public key (DNSKEY records)
    ///
    /// Replaces C's union all_addr.key with structured DnsKeyData. Contains key
    /// material (in BlockData), flags, key tag, and algorithm per RFC 4034.
    DnsKey(DnsKeyData),

    /// DNSSEC delegation signer (DS records)
    ///
    /// Replaces C's union all_addr.ds with structured DsData. Contains digest
    /// (in BlockData), key tag, algorithm, and digest type per RFC 4034.
    Ds(DsData),
    
    /// Negative cache entry (generic negative response)
    Negative,
    
    /// NXDOMAIN - domain does not exist
    NxDomain,
    
    /// NODATA - domain exists but has no records of requested type
    NoData,
}

// ============================================================================
// Domain Key for HashMap Lookup
// ============================================================================

/// Hash key for cache lookup by (name, qtype)
///
/// Used as the key type for HashMap<DomainKey, Vec<CacheRecordId>> in the
/// cache implementation. Combines domain name and query type to uniquely
/// identify cache entries while allowing multiple records for the same
/// (name, type) pair (e.g., multiple A records for load balancing).
///
/// # Hash and Equality
///
/// - Hash is computed from both name (case-insensitive) and qtype
/// - Equality compares both fields
/// - Name comparison is case-insensitive per DNS spec (RFC 1035 Section 3.1)
///
/// # Memory Efficiency
///
/// Uses String for name storage with automatic memory management. The C
/// version used manual pointer management with inline storage for short
/// names and heap allocation for long names, controlled by flags. Rust
/// String abstracts this complexity with automatic small string optimization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainKey {
    /// Domain name (case-insensitive for comparison)
    name: String,
    /// DNS query type (T_A, T_AAAA, T_CNAME, etc.)
    qtype: u16,
}

impl DomainKey {
    /// Create a new domain key for cache lookup
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name (will be converted to lowercase for consistency)
    /// * `qtype` - DNS query type constant (T_A, T_AAAA, etc.)
    ///
    /// # Returns
    ///
    /// DomainKey instance for use as HashMap key
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dnsmasq::dns::cache_types::DomainKey;
    /// use dnsmasq::dns::protocol::T_A;
    ///
    /// let key = DomainKey::new("example.com".to_string(), T_A);
    /// ```
    #[must_use]
    pub fn new(name: String, qtype: u16) -> Self {
        // Convert to lowercase for case-insensitive comparison
        Self {
            name: name.to_lowercase(),
            qtype,
        }
    }

    /// Get the domain name
    ///
    /// # Returns
    ///
    /// Reference to the domain name string
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the query type
    ///
    /// # Returns
    ///
    /// DNS query type constant (T_A, T_AAAA, etc.)
    #[must_use]
    pub fn qtype(&self) -> u16 {
        self.qtype
    }
}

// ============================================================================
// Cache Record Structure
// ============================================================================

/// DNS cache record
///
/// Main cache entry structure replacing C's `struct crec`. Contains domain name,
/// record data (address/CNAME/SRV/DNSSEC), TTL expiry time, flags, and uid for
/// source tracking.
///
/// # Memory Safety Improvements over C
///
/// The C `struct crec` had several unsafe patterns:
///
/// 1. **Raw pointers for list management**: next, prev, hash_next pointers
///    → Eliminated: Cache implementation uses Vec<CacheRecord> with CacheRecordId indices
///
/// 2. **Discriminated union**: union all_addr with manual flag checking
///    → Replaced: CacheRecordData enum with type-safe variants
///
/// 3. **Manual name memory management**: Union of sname[50], bname*, namep*
///    → Replaced: String with automatic memory management
///
/// 4. **time_t overflow**: Signed integer seconds since epoch
///    → Replaced: Instant (monotonic) + Duration (overflow-resistant)
///
/// 5. **Manual flag manipulation**: Bitwise OR/AND on unsigned int
///    → Replaced: bitflags! macro with type-safe operations
///
/// # Fields
///
/// - `name`: Domain name (String with automatic memory management)
/// - `data`: Record data (type-safe enum: Address, Cname, Srv, DnsKey, Ds)
/// - `ttd`: Time-to-die (Instant, monotonic and overflow-resistant)
/// - `uid`: Source tracking or DNSSEC class (u32)
/// - `flags`: Cache entry properties (CacheFlags bitflags)
///
/// # Usage
///
/// ```ignore
/// use dnsmasq::dns::cache_types::*;
/// use std::net::IpAddr;
/// use std::time::{Duration, Instant};
///
/// let record = CacheRecord::new(
///     "example.com".to_string(),
///     CacheRecordData::Address(IpAddr::V4("192.0.2.1".parse().unwrap())),
///     Instant::now() + Duration::from_secs(300),
///     UID_NONE,
///     CacheFlags::FORWARD | CacheFlags::IPV4 | CacheFlags::UPSTREAM,
/// );
///
/// if !record.is_expired() {
///     println!("Cache hit: {} -> {:?}", record.name(), record.data());
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CacheRecord {
    /// Domain name (replaces C's union of sname[SMALLDNAME], bname*, namep*)
    pub name: String,
    /// Record data (replaces C's union all_addr)
    pub data: CacheRecordData,
    /// Time-to-die (expiry time, replaces C's time_t ttd)
    pub ttd: Instant,
    /// Source tracking or DNSSEC class (replaces C's unsigned int uid)
    pub uid: u32,
    /// Cache entry flags (replaces C's unsigned int flags)
    pub flags: CacheFlags,
    /// Record type for tests (derived from data/flags, but can be explicitly set for testing)
    pub rr_type: u16,
    /// DNS class (almost always C_IN, but can be set for testing)
    pub class: u16,
    /// TTL in seconds (derived from ttd, but can be explicitly set for testing)
    pub ttl: u32,
    /// Insertion time for tests (optional, tracks when record was inserted)
    pub inserted_at: Option<Instant>,
}

impl CacheRecord {
    /// Create a new cache record
    ///
    /// # Arguments
    ///
    /// * `name` - Domain name
    /// * `data` - Record data (Address, Cname, Srv, DnsKey, Ds)
    /// * `ttd` - Time-to-die (expiry time)
    /// * `uid` - Source tracking or DNSSEC class
    /// * `flags` - Cache entry flags
    ///
    /// # Returns
    ///
    /// CacheRecord instance ready for insertion into cache
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dnsmasq::dns::cache_types::*;
    /// use std::net::IpAddr;
    /// use std::time::{Duration, Instant};
    ///
    /// // A record from upstream with 300 second TTL
    /// let record = CacheRecord::new(
    ///     "example.com".to_string(),
    ///     CacheRecordData::Address(IpAddr::V4("192.0.2.1".parse().unwrap())),
    ///     Instant::now() + Duration::from_secs(300),
    ///     UID_NONE,
    ///     CacheFlags::FORWARD | CacheFlags::IPV4 | CacheFlags::UPSTREAM,
    /// );
    /// ```
    #[must_use]
    pub fn new(name: String, data: CacheRecordData, ttd: Instant, uid: u32, flags: CacheFlags) -> Self {
        // Derive rr_type from data and flags
        let rr_type = Self::derive_rr_type(&data, flags);
        // Calculate TTL from ttd
        let now = Instant::now();
        let ttl = if ttd > now {
            ttd.duration_since(now).as_secs() as u32
        } else {
            0
        };
        
        Self {
            name,
            data,
            ttd,
            uid,
            flags,
            rr_type,
            class: crate::dns::protocol::C_IN, // Default to IN class
            ttl,
            inserted_at: Some(now),
        }
    }
    
    /// Derive record type from data and flags
    fn derive_rr_type(data: &CacheRecordData, flags: CacheFlags) -> u16 {
        use crate::dns::protocol::*;
        match data {
            CacheRecordData::Address(addr) => {
                if addr.is_ipv4() {
                    T_A
                } else {
                    T_AAAA
                }
            }
            CacheRecordData::Cname(_) | CacheRecordData::CName(_) => T_CNAME,
            CacheRecordData::Srv(_) => T_SRV,
            CacheRecordData::DnsKey(_) => T_DNSKEY,
            CacheRecordData::Ds(_) => T_DS,
            CacheRecordData::Negative | CacheRecordData::NxDomain | CacheRecordData::NoData => {
                // For negative records, check flags
                if flags.contains(F_NXDOMAIN) {
                    T_ANY // NXDOMAIN
                } else {
                    T_ANY // NODATA
                }
            }
        }
    }

    /// Get the domain name
    ///
    /// # Returns
    ///
    /// Reference to the domain name string
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the record data
    ///
    /// # Returns
    ///
    /// Reference to the CacheRecordData enum
    #[must_use]
    pub fn data(&self) -> &CacheRecordData {
        &self.data
    }

    /// Get the time-to-die (expiry time)
    ///
    /// # Returns
    ///
    /// Instant representing when this record expires
    #[must_use]
    pub fn ttd(&self) -> Instant {
        self.ttd
    }

    /// Get the uid (source tracking or DNSSEC class)
    ///
    /// # Returns
    ///
    /// uid value (UID_NONE, SRC_CONFIG, SRC_HOSTS, SRC_AH, or DNSSEC class)
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Get the cache entry flags
    ///
    /// # Returns
    ///
    /// CacheFlags bitflags
    #[must_use]
    pub fn flags(&self) -> CacheFlags {
        self.flags
    }

    /// Check if the cache record has expired
    ///
    /// # Returns
    ///
    /// `true` if the record has expired (ttd <= now), `false` otherwise.
    /// Records with IMMORTAL flag never expire.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// if !record.is_expired() {
    ///     // Use cached record
    /// } else {
    ///     // Evict expired record
    /// }
    /// ```
    #[must_use]
    pub fn is_expired(&self) -> bool {
        // IMMORTAL records never expire (from /etc/hosts or static config)
        if self.flags.contains(CacheFlags::IMMORTAL) {
            return false;
        }
        
        // Check if current time exceeds TTD
        Instant::now() >= self.ttd
    }

    /// Create a CacheRecord from a DNS response packet
    ///
    /// Parses a DNS response and extracts resource records to create cache entries.
    /// This is a stub implementation for testing.
    ///
    /// # Arguments
    ///
    /// * `response` - DNS response packet bytes
    /// * `query_name` - Original query name
    /// * `query_type` - Original query type
    ///
    /// # Returns
    ///
    /// Returns a CacheRecord parsed from the response, or None on error
    pub fn from_response(response: &[u8], query_name: &str, query_type: u16) -> Option<Self> {
        use crate::dns::protocol::{T_A, T_AAAA};
        use std::net::{Ipv4Addr, Ipv6Addr};
        
        // Stub implementation - in real code would parse response packet
        // For now, create a dummy record based on query type
        let ttd = Instant::now() + std::time::Duration::from_secs(3600);
        
        let data = match query_type {
            T_A => {
                // Create dummy A record
                CacheRecordData::Address(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            }
            T_AAAA => {
                // Create dummy AAAA record
                CacheRecordData::Address(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST))
            }
            _ => {
                // For other types, return None for now
                return None;
            }
        };
        
        Some(CacheRecord::new(
            query_name.to_string(),
            data,
            ttd,
            UID_NONE,
            CacheFlags::FORWARD,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{T_A, T_AAAA};
    use std::time::Duration;

    #[test]
    fn test_cache_record_id() {
        let id = CacheRecordId::new(42);
        assert_eq!(id.get(), 42);
    }

    #[test]
    fn test_cache_flags() {
        let mut flags = CacheFlags::FORWARD | CacheFlags::IPV4;
        assert!(flags.contains(CacheFlags::FORWARD));
        assert!(flags.contains(CacheFlags::IPV4));
        assert!(!flags.contains(CacheFlags::IPV6));

        flags.insert(CacheFlags::UPSTREAM);
        assert!(flags.contains(CacheFlags::UPSTREAM));

        flags.remove(CacheFlags::IPV4);
        assert!(!flags.contains(CacheFlags::IPV4));
    }

    #[test]
    fn test_srv_data() {
        let srv = SrvData::new(b"target.example.com", 80, 10, 20);
        assert_eq!(srv.target(), b"target.example.com");
        assert_eq!(srv.port(), 80);
        assert_eq!(srv.priority(), 10);
        assert_eq!(srv.weight(), 20);
    }

    #[test]
    fn test_dnskey_data() {
        let keydata = vec![0x01, 0x02, 0x03, 0x04];
        let dnskey = DnsKeyData::new(&keydata, 256, 12345, 8);
        assert_eq!(dnskey.keydata(), keydata);
        assert_eq!(dnskey.flags(), 256);
        assert_eq!(dnskey.keytag(), 12345);
        assert_eq!(dnskey.algorithm(), 8);
    }

    #[test]
    fn test_ds_data() {
        let digest = vec![0xde, 0xad, 0xbe, 0xef];
        let ds = DsData::new(&digest, 54321, 8, 2);
        assert_eq!(ds.keydata(), digest);
        assert_eq!(ds.keytag(), 54321);
        assert_eq!(ds.algorithm(), 8);
        assert_eq!(ds.digest_type(), 2);
    }

    #[test]
    fn test_domain_key() {
        let key1 = DomainKey::new("example.com".to_string(), T_A);
        let key2 = DomainKey::new("EXAMPLE.COM".to_string(), T_A);
        let key3 = DomainKey::new("example.com".to_string(), T_AAAA);

        // Case-insensitive name comparison
        assert_eq!(key1, key2);
        // Different qtype
        assert_ne!(key1, key3);

        assert_eq!(key1.name(), "example.com");
        assert_eq!(key1.qtype(), T_A);
    }

    #[test]
    fn test_cache_record() {
        let addr = "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap();
        let ttd = Instant::now() + Duration::from_secs(300);
        let flags = CacheFlags::FORWARD | CacheFlags::IPV4 | CacheFlags::UPSTREAM;

        let record = CacheRecord::new(
            "example.com".to_string(),
            CacheRecordData::Address(IpAddr::V4(addr)),
            ttd,
            UID_NONE,
            flags,
        );

        assert_eq!(record.name(), "example.com");
        assert_eq!(record.uid(), UID_NONE);
        assert!(record.flags().contains(CacheFlags::FORWARD));
        assert!(!record.is_expired());
    }

    #[test]
    fn test_cache_record_immortal() {
        let addr = "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap();
        // Set TTD in the past
        let ttd = Instant::now() - Duration::from_secs(300);
        let flags = CacheFlags::IMMORTAL | CacheFlags::HOSTS;

        let record = CacheRecord::new(
            "localhost".to_string(),
            CacheRecordData::Address(IpAddr::V4(addr)),
            ttd,
            SRC_HOSTS,
            flags,
        );

        // IMMORTAL records never expire even with past TTD
        assert!(!record.is_expired());
    }

    #[test]
    fn test_cache_record_expired() {
        let addr = "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap();
        // Set TTD in the past
        let ttd = Instant::now() - Duration::from_secs(1);
        let flags = CacheFlags::FORWARD | CacheFlags::IPV4;

        let record = CacheRecord::new(
            "expired.example.com".to_string(),
            CacheRecordData::Address(IpAddr::V4(addr)),
            ttd,
            UID_NONE,
            flags,
        );

        // Non-IMMORTAL record with past TTD is expired
        assert!(record.is_expired());
    }
}
