// Copyright (C) 2024 Blitzy - dnsmasq Rust Implementation
//
// This file is part of the dnsmasq Rust port, translating C's union all_addr
// and union mysockaddr into type-safe Rust enums and utilizing std::net types.
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! IP address types and utilities for dnsmasq Rust implementation.
//!
//! This module provides safe abstractions for IPv4/IPv6 addresses, socket addresses,
//! and DNS-specific address types. It replaces C's `union all_addr` and
//! `union mysockaddr` with type-safe Rust enums, eliminating unsafe pointer casting
//! and providing compile-time type safety for all address operations throughout
//! the DNS and DHCP subsystems.
//!
//! # Key Types
//!
//! - [`AllAddr`]: Universal address container for IPv4, IPv6, CNAME, DNSSEC keys,
//!   DS records, and SRV records
//! - [`CnameData`]: CNAME target reference with unique identifier
//! - [`DnsKeyData`]: DNSSEC DNSKEY record data
//! - [`DsData`]: DNSSEC DS (Delegation Signer) record data
//! - [`SrvData`]: DNS SRV record data for service location
//!
//! # IPv6 Address Classification
//!
//! This module provides utility functions for IPv6 address classification:
//! - [`is_addr_ula`]: Check for Unique Local Addresses (RFC 4193 fd00::/8)
//! - [`is_addr_ula_zero`]: Check for exactly fd00:: (ULA prefix boundary)
//! - [`is_addr_link_local_zero`]: Check for exactly fe80:: (link-local prefix)
//!
//! # Socket Addresses
//!
//! For socket addresses, this module relies on Rust's standard library
//! `std::net::SocketAddr` which provides type-safe IPv4/IPv6 socket address
//! handling, replacing C's `union mysockaddr`.
//!
//! # Memory Safety
//!
//! All types in this module are memory-safe with no unsafe blocks required.
//! The Rust type system prevents:
//! - Buffer overflows through slice bounds checking
//! - Use-after-free through ownership and borrowing
//! - Type confusion through enum discriminants
//! - Null pointer dereferences through Option types

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Universal address container for DNS and DHCP operations.
///
/// This enum replaces C's `union all_addr`, providing type-safe storage for
/// various address and DNS record types. The Rust enum ensures that only one
/// variant is active at a time, with compile-time verification, eliminating
/// the unsafe union access patterns from the C implementation.
///
/// # Variants
///
/// - `Ipv4`: IPv4 address (corresponds to C's `struct in_addr addr4`)
/// - `Ipv6`: IPv6 address (corresponds to C's `struct in6_addr addr6`)
/// - `Cname`: CNAME target reference (corresponds to C's `cname` struct)
/// - `DnsKey`: DNSSEC DNSKEY record (corresponds to C's `key` struct)
/// - `DelegationSigner`: DNSSEC DS record (corresponds to C's `ds` struct)
/// - `ServiceRecord`: DNS SRV record (corresponds to C's `srv` struct)
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use dnsmasq::types::addresses::AllAddr;
///
/// let ipv4_addr = AllAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));
/// assert!(ipv4_addr.is_ipv4());
///
/// if let Some(addr) = ipv4_addr.as_ipv4() {
///     println!("IPv4 address: {}", addr);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllAddr {
    /// IPv4 address variant
    Ipv4(Ipv4Addr),

    /// IPv6 address variant
    Ipv6(Ipv6Addr),

    /// CNAME record target data
    Cname(CnameData),

    /// DNSSEC DNSKEY record data
    DnsKey(DnsKeyData),

    /// DNSSEC DS (Delegation Signer) record data
    DelegationSigner(DsData),

    /// DNS SRV record data for service location
    ServiceRecord(SrvData),
}

impl AllAddr {
    /// Creates a new `AllAddr` from an IPv4 address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IPv4 address to wrap
    ///
    /// # Returns
    ///
    /// An `AllAddr::Ipv4` variant containing the provided address
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use dnsmasq::types::addresses::AllAddr;
    ///
    /// let addr = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));
    /// assert!(addr.is_ipv4());
    /// ```
    pub fn from_ipv4(addr: Ipv4Addr) -> Self {
        AllAddr::Ipv4(addr)
    }

    /// Creates a new `AllAddr` from an IPv6 address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IPv6 address to wrap
    ///
    /// # Returns
    ///
    /// An `AllAddr::Ipv6` variant containing the provided address
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::addresses::AllAddr;
    ///
    /// let addr = AllAddr::from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    /// assert!(addr.is_ipv6());
    /// ```
    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        AllAddr::Ipv6(addr)
    }

    /// Attempts to extract an IPv4 address from this `AllAddr`.
    ///
    /// # Returns
    ///
    /// `Some(Ipv4Addr)` if this is an `Ipv4` variant, `None` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use dnsmasq::types::addresses::AllAddr;
    ///
    /// let addr = AllAddr::from_ipv4(Ipv4Addr::new(172, 16, 0, 1));
    /// assert_eq!(addr.as_ipv4(), Some(Ipv4Addr::new(172, 16, 0, 1)));
    /// ```
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            AllAddr::Ipv4(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Attempts to extract an IPv6 address from this `AllAddr`.
    ///
    /// # Returns
    ///
    /// `Some(Ipv6Addr)` if this is an `Ipv6` variant, `None` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::addresses::AllAddr;
    ///
    /// let addr = AllAddr::from_ipv6(Ipv6Addr::LOCALHOST);
    /// assert_eq!(addr.as_ipv6(), Some(Ipv6Addr::LOCALHOST));
    /// ```
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            AllAddr::Ipv6(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Converts this `AllAddr` to a standard `IpAddr` if it contains an IP address.
    ///
    /// # Returns
    ///
    /// `Some(IpAddr)` if this is an `Ipv4` or `Ipv6` variant, `None` for other variants
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use dnsmasq::types::addresses::AllAddr;
    ///
    /// let addr = AllAddr::from_ipv4(Ipv4Addr::new(8, 8, 8, 8));
    /// assert_eq!(addr.to_ip_addr(), Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    /// ```
    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        match self {
            AllAddr::Ipv4(addr) => Some(IpAddr::V4(*addr)),
            AllAddr::Ipv6(addr) => Some(IpAddr::V6(*addr)),
            _ => None,
        }
    }

    /// Checks if this `AllAddr` contains an IPv4 address.
    ///
    /// # Returns
    ///
    /// `true` if this is an `Ipv4` variant, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use dnsmasq::types::addresses::AllAddr;
    ///
    /// let addr = AllAddr::from_ipv4(Ipv4Addr::LOCALHOST);
    /// assert!(addr.is_ipv4());
    /// ```
    pub fn is_ipv4(&self) -> bool {
        matches!(self, AllAddr::Ipv4(_))
    }

    /// Checks if this `AllAddr` contains an IPv6 address.
    ///
    /// # Returns
    ///
    /// `true` if this is an `Ipv6` variant, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv6Addr;
    /// use dnsmasq::types::addresses::AllAddr;
    ///
    /// let addr = AllAddr::from_ipv6(Ipv6Addr::LOCALHOST);
    /// assert!(addr.is_ipv6());
    /// ```
    pub fn is_ipv6(&self) -> bool {
        matches!(self, AllAddr::Ipv6(_))
    }
}

/// CNAME record target data.
///
/// This struct represents a CNAME (Canonical Name) record target, replacing
/// C's anonymous struct within `union all_addr`. It contains either a direct
/// name string or a reference to a cached record, along with a unique identifier
/// for tracking CNAME chains.
///
/// # Fields
///
/// - `target`: The CNAME target as a String (replaces C's char* name or cache pointer)
/// - `uid`: Unique identifier for this CNAME entry, used for loop detection
///
/// # C Mapping
///
/// This corresponds to the C struct:
/// ```c
/// struct {
///     union {
///         struct crec *cache;
///         char *name;
///     } target;
///     unsigned int uid;
///     int is_name_ptr;  // discriminator
/// } cname;
/// ```
///
/// In Rust, we use a String for the target, eliminating the need for the
/// discriminator field since Rust's type system provides memory safety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnameData {
    /// CNAME target name
    pub target: String,

    /// Unique identifier for CNAME chain tracking and loop detection
    pub uid: u32,
}

impl CnameData {
    /// Creates a new `CnameData` instance.
    ///
    /// # Arguments
    ///
    /// * `target` - The CNAME target name
    /// * `uid` - Unique identifier for this CNAME entry
    ///
    /// # Returns
    ///
    /// A new `CnameData` instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::types::addresses::CnameData;
    ///
    /// let cname = CnameData::new("example.com".to_string(), 12345);
    /// assert_eq!(cname.target, "example.com");
    /// assert_eq!(cname.uid, 12345);
    /// ```
    pub fn new(target: String, uid: u32) -> Self {
        CnameData { target, uid }
    }
}

/// DNSSEC DNSKEY record data.
///
/// This struct represents a DNSSEC DNSKEY (DNS Public Key) record, replacing
/// C's anonymous `key` struct within `union all_addr`. It contains the public
/// key data and associated metadata for DNSSEC validation.
///
/// # Fields
///
/// - `keydata`: The raw public key data as a byte vector
/// - `flags`: DNSKEY flags (Zone Key, Secure Entry Point, etc.)
/// - `keytag`: Key tag for quick key identification (16-bit hash)
/// - `algorithm`: Cryptographic algorithm identifier (RSA, ECDSA, Ed25519, etc.)
///
/// # C Mapping
///
/// This corresponds to the C struct:
/// ```c
/// struct {
///     struct blockdata *keydata;
///     unsigned short keylen, flags, keytag;
///     unsigned char algo;
/// } key;
/// ```
///
/// In Rust, we use `Vec<u8>` for keydata instead of the C blockdata pointer,
/// providing automatic memory management and bounds checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsKeyData {
    /// Raw public key data bytes
    pub keydata: Vec<u8>,

    /// DNSKEY flags (bit 7: Zone Key, bit 15: Secure Entry Point)
    pub flags: u16,

    /// Key tag for quick identification (16-bit hash of key data)
    pub keytag: u16,

    /// Cryptographic algorithm (5=RSA/SHA-1, 8=RSA/SHA-256, 13=ECDSA-P256, 15=Ed25519)
    pub algorithm: u8,
}

impl DnsKeyData {
    /// Creates a new `DnsKeyData` instance.
    ///
    /// # Arguments
    ///
    /// * `keydata` - The raw public key data bytes
    /// * `flags` - DNSKEY flags
    /// * `keytag` - Key tag for identification
    /// * `algorithm` - Cryptographic algorithm identifier
    ///
    /// # Returns
    ///
    /// A new `DnsKeyData` instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::types::addresses::DnsKeyData;
    ///
    /// let key = DnsKeyData::new(
    ///     vec![0x03, 0x01, 0x00, 0x01], // Example RSA exponent
    ///     257, // Zone Key + Secure Entry Point
    ///     12345,
    ///     8, // RSA/SHA-256
    /// );
    /// assert_eq!(key.algorithm, 8);
    /// ```
    pub fn new(keydata: Vec<u8>, flags: u16, keytag: u16, algorithm: u8) -> Self {
        DnsKeyData {
            keydata,
            flags,
            keytag,
            algorithm,
        }
    }
}

/// DNSSEC DS (Delegation Signer) record data.
///
/// This struct represents a DNSSEC DS record, replacing C's anonymous `ds`
/// struct within `union all_addr`. DS records are used in the DNSSEC chain
/// of trust to link parent and child zones.
///
/// # Fields
///
/// - `keydata`: The digest (hash) of the child zone's DNSKEY
/// - `keytag`: Key tag of the DNSKEY this DS record refers to
/// - `algorithm`: Algorithm of the referenced DNSKEY
/// - `digest_type`: Hash algorithm used for the digest (1=SHA-1, 2=SHA-256, 4=SHA-384)
///
/// # C Mapping
///
/// This corresponds to the C struct:
/// ```c
/// struct {
///     struct blockdata *keydata;
///     unsigned short keylen, keytag;
///     unsigned char algo;
///     unsigned char digest;
/// } ds;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsData {
    /// Digest of the referenced DNSKEY record
    pub keydata: Vec<u8>,

    /// Key tag of the referenced DNSKEY
    pub keytag: u16,

    /// Algorithm of the referenced DNSKEY
    pub algorithm: u8,

    /// Digest algorithm (1=SHA-1, 2=SHA-256, 4=SHA-384)
    pub digest_type: u8,
}

impl DsData {
    /// Creates a new `DsData` instance.
    ///
    /// # Arguments
    ///
    /// * `keydata` - The digest bytes
    /// * `keytag` - Key tag of the referenced DNSKEY
    /// * `algorithm` - Algorithm of the referenced DNSKEY
    /// * `digest_type` - Digest algorithm identifier
    ///
    /// # Returns
    ///
    /// A new `DsData` instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::types::addresses::DsData;
    ///
    /// let ds = DsData::new(
    ///     vec![0xAB, 0xCD, 0xEF], // Example digest
    ///     54321,
    ///     8, // RSA/SHA-256
    ///     2, // SHA-256 digest
    /// );
    /// assert_eq!(ds.digest_type, 2);
    /// ```
    pub fn new(keydata: Vec<u8>, keytag: u16, algorithm: u8, digest_type: u8) -> Self {
        DsData {
            keydata,
            keytag,
            algorithm,
            digest_type,
        }
    }
}

/// DNS SRV record data for service location.
///
/// This struct represents a DNS SRV (Service) record, replacing C's anonymous
/// `srv` struct within `union all_addr`. SRV records provide information about
/// available services, including the hostname, port, and load balancing parameters.
///
/// # Fields
///
/// - `target`: Target hostname providing the service
/// - `port`: TCP or UDP port number of the service
/// - `priority`: Priority of this target (lower values preferred)
/// - `weight`: Relative weight for load balancing among same-priority targets
///
/// # C Mapping
///
/// This corresponds to the C struct:
/// ```c
/// struct {
///     struct blockdata *target;
///     unsigned short targetlen, srvport, priority, weight;
/// } srv;
/// ```
///
/// In Rust, we use a String for the target hostname instead of blockdata,
/// providing automatic memory management.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvData {
    /// Target hostname providing the service
    pub target: String,

    /// TCP or UDP port number
    pub port: u16,

    /// Priority (lower values have higher priority)
    pub priority: u16,

    /// Relative weight for load balancing
    pub weight: u16,
}

impl SrvData {
    /// Creates a new `SrvData` instance.
    ///
    /// # Arguments
    ///
    /// * `target` - Target hostname
    /// * `port` - Service port number
    /// * `priority` - Priority value (lower is better)
    /// * `weight` - Load balancing weight
    ///
    /// # Returns
    ///
    /// A new `SrvData` instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dnsmasq::types::addresses::SrvData;
    ///
    /// let srv = SrvData::new(
    ///     "server.example.com".to_string(),
    ///     443,
    ///     10,
    ///     50,
    /// );
    /// assert_eq!(srv.port, 443);
    /// assert_eq!(srv.priority, 10);
    /// ```
    pub fn new(target: String, port: u16, priority: u16, weight: u16) -> Self {
        SrvData {
            target,
            port,
            priority,
            weight,
        }
    }
}

/// Checks if an IPv6 address is a Unique Local Address (ULA).
///
/// Tests whether the provided IPv6 address falls within the Unique Local Address
/// (ULA) range defined by RFC 4193. ULA addresses use the fd00::/8 prefix and are
/// analogous to IPv4 private addresses (RFC 1918).
///
/// This function replaces the C macro `IN6_IS_ADDR_ULA(a)` from ip6addr.h with
/// a safe Rust function that operates on `Ipv6Addr`.
///
/// # Arguments
///
/// * `addr` - Reference to the IPv6 address to test
///
/// # Returns
///
/// `true` if the address is within fd00::/8 ULA range, `false` otherwise
///
/// # Examples
///
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::types::addresses::is_addr_ula;
///
/// let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
/// assert!(is_addr_ula(&ula));
///
/// let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
/// assert!(!is_addr_ula(&global));
/// ```
///
/// # C Mapping
///
/// Replaces the C macro:
/// ```c
/// #define IN6_IS_ADDR_ULA(a) \
///     ((((__const uint32_t *) (a))[0] & htonl (0xff000000)) \
///      == htonl (0xfd000000))
/// ```
pub fn is_addr_ula(addr: &Ipv6Addr) -> bool {
    // Get the segments (16-bit values) of the IPv6 address
    let segments = addr.segments();

    // Check if the first byte (high 8 bits of first segment) is 0xfd
    // segments[0] is in host byte order, so we check the high byte
    (segments[0] & 0xff00) == 0xfd00
}

/// Checks if an IPv6 address is exactly fd00:: (ULA prefix with all-zero host).
///
/// Tests whether the provided IPv6 address is exactly fd00:0000:0000:0000:0000:0000:0000:0000
/// (abbreviated as fd00::), representing a Unique Local Address prefix with all host
/// portion bits set to zero. This specific address format is used to denote ULA network
/// prefixes in DHCPv6 configuration.
///
/// This function replaces the C macro `IN6_IS_ADDR_ULA_ZERO(a)` from ip6addr.h.
///
/// # Arguments
///
/// * `addr` - Reference to the IPv6 address to test
///
/// # Returns
///
/// `true` if the address is exactly fd00::, `false` otherwise
///
/// # Examples
///
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::types::addresses::is_addr_ula_zero;
///
/// let ula_zero = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
/// assert!(is_addr_ula_zero(&ula_zero));
///
/// let ula_host = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
/// assert!(!is_addr_ula_zero(&ula_host));
/// ```
///
/// # C Mapping
///
/// Replaces the C macro:
/// ```c
/// #define IN6_IS_ADDR_ULA_ZERO(a) \
///     (((__const uint32_t *) (a))[0] == htonl (0xfd000000) \
///      && ((__const uint32_t *) (a))[1] == 0 \
///      && ((__const uint32_t *) (a))[2] == 0 \
///      && ((__const uint32_t *) (a))[3] == 0)
/// ```
pub fn is_addr_ula_zero(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();

    // Check if address is exactly fd00::
    // First segment must be 0xfd00, all others must be 0
    segments[0] == 0xfd00
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
        && segments[6] == 0
        && segments[7] == 0
}

/// Checks if an IPv6 address is exactly fe80:: (link-local prefix with all-zero host).
///
/// Tests whether the provided IPv6 address is exactly fe80:0000:0000:0000:0000:0000:0000:0000
/// (abbreviated as fe80::), representing the link-local address prefix with all host portion
/// bits set to zero. Link-local addresses (RFC 4291 Section 2.5.6) use the fe80::/10 prefix.
///
/// This function replaces the C macro `IN6_IS_ADDR_LINK_LOCAL_ZERO(a)` from ip6addr.h.
///
/// # Arguments
///
/// * `addr` - Reference to the IPv6 address to test
///
/// # Returns
///
/// `true` if the address is exactly fe80::, `false` otherwise
///
/// # Examples
///
/// ```
/// use std::net::Ipv6Addr;
/// use dnsmasq::types::addresses::is_addr_link_local_zero;
///
/// let link_local_zero = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
/// assert!(is_addr_link_local_zero(&link_local_zero));
///
/// let link_local_host = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
/// assert!(!is_addr_link_local_zero(&link_local_host));
/// ```
///
/// # C Mapping
///
/// Replaces the C macro:
/// ```c
/// #define IN6_IS_ADDR_LINK_LOCAL_ZERO(a) \
///     (((__const uint32_t *) (a))[0] == htonl (0xfe800000) \
///      && ((__const uint32_t *) (a))[1] == 0 \
///      && ((__const uint32_t *) (a))[2] == 0 \
///      && ((__const uint32_t *) (a))[3] == 0)
/// ```
pub fn is_addr_link_local_zero(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();

    // Check if address is exactly fe80::
    // First segment must be 0xfe80, all others must be 0
    segments[0] == 0xfe80
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
        && segments[6] == 0
        && segments[7] == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alladdr_ipv4() {
        let ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let addr = AllAddr::from_ipv4(ipv4);

        assert!(addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert_eq!(addr.as_ipv4(), Some(ipv4));
        assert_eq!(addr.as_ipv6(), None);
        assert_eq!(addr.to_ip_addr(), Some(IpAddr::V4(ipv4)));
    }

    #[test]
    fn test_alladdr_ipv6() {
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr = AllAddr::from_ipv6(ipv6);

        assert!(addr.is_ipv6());
        assert!(!addr.is_ipv4());
        assert_eq!(addr.as_ipv6(), Some(ipv6));
        assert_eq!(addr.as_ipv4(), None);
        assert_eq!(addr.to_ip_addr(), Some(IpAddr::V6(ipv6)));
    }

    #[test]
    fn test_cname_data() {
        let cname = CnameData::new("example.com".to_string(), 42);
        assert_eq!(cname.target, "example.com");
        assert_eq!(cname.uid, 42);

        let addr = AllAddr::Cname(cname);
        assert!(!addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert_eq!(addr.to_ip_addr(), None);
    }

    #[test]
    fn test_dnskey_data() {
        let keydata = vec![0x03, 0x01, 0x00, 0x01];
        let dnskey = DnsKeyData::new(keydata.clone(), 257, 12345, 8);

        assert_eq!(dnskey.keydata, keydata);
        assert_eq!(dnskey.flags, 257);
        assert_eq!(dnskey.keytag, 12345);
        assert_eq!(dnskey.algorithm, 8);
    }

    #[test]
    fn test_ds_data() {
        let digest = vec![0xAB, 0xCD, 0xEF];
        let ds = DsData::new(digest.clone(), 54321, 8, 2);

        assert_eq!(ds.keydata, digest);
        assert_eq!(ds.keytag, 54321);
        assert_eq!(ds.algorithm, 8);
        assert_eq!(ds.digest_type, 2);
    }

    #[test]
    fn test_srv_data() {
        let srv = SrvData::new("server.example.com".to_string(), 443, 10, 50);

        assert_eq!(srv.target, "server.example.com");
        assert_eq!(srv.port, 443);
        assert_eq!(srv.priority, 10);
        assert_eq!(srv.weight, 50);
    }

    #[test]
    fn test_is_addr_ula() {
        // ULA addresses (fd00::/8)
        let ula1 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let ula2 = Ipv6Addr::new(
            0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        );

        assert!(is_addr_ula(&ula1));
        assert!(is_addr_ula(&ula2));

        // Non-ULA addresses
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let fc00 = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);

        assert!(!is_addr_ula(&global));
        assert!(!is_addr_ula(&link_local));
        assert!(!is_addr_ula(&fc00)); // fc00::/8 is reserved, not fd00::/8
    }

    #[test]
    fn test_is_addr_ula_zero() {
        // Exactly fd00::
        let ula_zero = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        assert!(is_addr_ula_zero(&ula_zero));

        // Not fd00:: (has host bits set)
        let ula_host = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let ula_subnet = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0);
        let fd01 = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 0);

        assert!(!is_addr_ula_zero(&ula_host));
        assert!(!is_addr_ula_zero(&ula_subnet));
        assert!(!is_addr_ula_zero(&fd01));
    }

    #[test]
    fn test_is_addr_link_local_zero() {
        // Exactly fe80::
        let link_local_zero = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        assert!(is_addr_link_local_zero(&link_local_zero));

        // Not fe80:: (has host bits set)
        let link_local_host = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let link_local_interface = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let fe81 = Ipv6Addr::new(0xfe81, 0, 0, 0, 0, 0, 0, 0);

        assert!(!is_addr_link_local_zero(&link_local_host));
        assert!(!is_addr_link_local_zero(&link_local_interface));
        assert!(!is_addr_link_local_zero(&fe81));
    }

    #[test]
    fn test_alladdr_equality() {
        let ipv4_1 = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let ipv4_2 = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let ipv4_3 = AllAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 2));

        assert_eq!(ipv4_1, ipv4_2);
        assert_ne!(ipv4_1, ipv4_3);

        let cname_1 = AllAddr::Cname(CnameData::new("example.com".to_string(), 1));
        let cname_2 = AllAddr::Cname(CnameData::new("example.com".to_string(), 1));
        let cname_3 = AllAddr::Cname(CnameData::new("example.org".to_string(), 1));

        assert_eq!(cname_1, cname_2);
        assert_ne!(cname_1, cname_3);
        assert_ne!(ipv4_1, cname_1);
    }
}
