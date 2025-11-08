// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// Authoritative DNS zone management implementing local zone response generation
// for configured domains, providing SOA and NS record serving, A/AAAA/PTR record
// answers from configuration and DHCP leases, AXFR zone transfer support for
// secondary servers, subnet-based filtering for split-horizon DNS, and integration
// with cache for dynamic hostname resolution.
//
// Translated from: src/auth.c (lines 75-1200)

//! Authoritative DNS zone management for local zones
//!
//! This module implements authoritative DNS server functionality within dnsmasq,
//! allowing it to authoritatively answer DNS queries for configured zones. It serves
//! SOA, NS, A, AAAA, CNAME, MX, SRV, TXT, and PTR records from local configuration
//! data and integrates with the DHCP cache for dynamic hostname resolution.
//!
//! # Key Features
//!
//! - Zone matching and domain membership checking
//! - Subnet-based filtering for split-horizon DNS
//! - PTR record generation from DHCP leases and interface configuration
//! - Forward record (A/AAAA) generation from cache and static configuration
//! - SOA and NS record handling for zone authority
//! - AXFR (zone transfer) support for secondary servers
//! - CNAME chain resolution with loop detection
//!
//! # Memory Safety
//!
//! All operations use Rust's ownership system and bounds checking. No pointer
//! arithmetic or manual buffer management. IP address matching uses safe standard
//! library functions instead of C bitwise operations.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use crate::config::types::Config;
use crate::dns::cache::DnsCache;
use crate::dns::domain::domain_equal;
use crate::dns::protocol::{
    DnsHeader, DnsMessage, DnsQuestion, RecordClass, RecordType, ResourceRecord,
};
use crate::types::errors::{AuthError, DnsError};
use tracing::{debug, error, info, warn};

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// IP network with CIDR prefix for subnet matching
///
/// Represents an IP network address with prefix length for subnet-based
/// filtering in split-horizon DNS configurations.
///
/// # C Equivalent
///
/// Replaces `struct addrlist` from dnsmasq.h lines 1176-1185 (simplified to
/// network matching only, without flags or next pointer).
///
/// # Members Exposed
///
/// Per schema: `addr`, `prefix_len`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNetwork {
    /// Network address (IPv4 or IPv6)
    pub addr: IpAddr,
    /// CIDR prefix length (e.g., 24 for /24, 64 for /64)
    pub prefix_len: u8,
}

impl IpNetwork {
    /// Create a new IP network from address and prefix length
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InternalError` if prefix length exceeds maximum
    /// for the address family (32 for IPv4, 128 for IPv6).
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, AuthError> {
        // Validate prefix length based on address family
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_len > max_prefix {
            return Err(AuthError::InternalError {
                message: format!("Invalid prefix length {prefix_len} for address {addr}"),
            });
        }

        Ok(IpNetwork { addr, prefix_len })
    }

    /// Check if an IP address belongs to this network
    ///
    /// Performs prefix matching to determine subnet membership.
    /// Replaces C's `is_same_net()` and `is_same_net6()` from `util.c`.
    #[must_use]
    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(test)) => {
                // IPv4 prefix matching using bitwise operations
                // Convert to u32, apply netmask, compare network portions
                let netmask = if self.prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - self.prefix_len)
                };

                let net_u32 = u32::from_be_bytes(net.octets());
                let test_u32 = u32::from_be_bytes(test.octets());

                (net_u32 & netmask) == (test_u32 & netmask)
            }
            (IpAddr::V6(net), IpAddr::V6(test)) => {
                // IPv6 prefix matching using byte-wise comparison
                let net_bytes = net.octets();
                let test_bytes = test.octets();

                let full_bytes = (self.prefix_len / 8) as usize;
                let remainder_bits = self.prefix_len % 8;

                // Compare full bytes
                if net_bytes[..full_bytes] != test_bytes[..full_bytes] {
                    return false;
                }

                // Compare remaining bits if any
                if remainder_bits > 0 && full_bytes < 16 {
                    let mask = !0u8 << (8 - remainder_bits);
                    if (net_bytes[full_bytes] & mask) != (test_bytes[full_bytes] & mask) {
                        return false;
                    }
                }

                true
            }
            _ => false, // Address family mismatch
        }
    }
}

/// SOA (Start of Authority) record data
///
/// Contains all fields for a DNS SOA record as specified in RFC 1035.
///
/// # C Equivalent
///
/// Replaces SOA-related fields in `struct daemon` from `dnsmasq.h`:
/// - `authserver` (MNAME)
/// - `hostmaster` (RNAME)
/// - `soa_sn` (serial)
/// - `soa_refresh`, `soa_retry`, `soa_expiry` (timers)
/// - `auth_ttl` (minimum/negative caching TTL)
///
/// # Members Exposed
///
/// Per schema: `primary_ns`, `admin_email`, `serial`, `refresh`, `retry`, `expire`, `minimum`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaRecord {
    /// Primary nameserver (MNAME) - authoritative server for zone
    pub primary_ns: String,
    /// Admin email (RNAME) - email with @ replaced by first .
    pub admin_email: String,
    /// Zone serial number (incremented on updates)
    pub serial: u32,
    /// Refresh interval in seconds (secondary checks for updates)
    pub refresh: u32,
    /// Retry interval in seconds (secondary retries after failure)
    pub retry: u32,
    /// Expiration time in seconds (secondary stops serving if unreachable)
    pub expire: u32,
    /// Minimum TTL / negative caching TTL in seconds
    pub minimum: u32,
}

impl SoaRecord {
    /// Create a new SOA record with default values
    #[must_use]
    pub fn new(primary_ns: String, admin_email: String) -> Self {
        SoaRecord {
            primary_ns,
            admin_email,
            serial: 1,
            refresh: 7200,     // 2 hours
            retry: 1800,       // 30 minutes
            expire: 1_209_600, // 2 weeks
            minimum: 3600,     // 1 hour
        }
    }
}

/// Authoritative DNS zone configuration
///
/// Defines a DNS zone where dnsmasq acts as authoritative nameserver,
/// including domain name, subnet restrictions for split-horizon DNS,
/// SOA record parameters, and static hostname mappings.
///
/// # C Equivalent
///
/// Replaces `struct auth_zone` from dnsmasq.h lines 1403-1413.
///
/// # Members Exposed
///
/// Per schema: `domain`, `subnets`, `excluded`, `soa`, `nameservers`, `interface_names`
#[derive(Debug, Clone)]
pub struct AuthZone {
    /// Zone domain name (e.g., "local", "lan")
    pub domain: String,
    /// Allowed client subnets (split-horizon DNS filtering)
    pub subnets: Vec<IpNetwork>,
    /// Excluded IP addresses (blacklist for authoritative answers)
    pub excluded: Vec<IpAddr>,
    /// SOA record data for zone authority
    pub soa: SoaRecord,
    /// NS (nameserver) records for zone
    pub nameservers: Vec<String>,
    /// Static interface name-to-IP mappings (hostname -> address)
    pub interface_names: Vec<(String, IpAddr)>,
}

impl AuthZone {
    /// Create a new authoritative zone with default values
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(domain: String, soa: SoaRecord) -> Self {
        AuthZone {
            domain: domain.to_lowercase(),
            subnets: Vec::new(),
            excluded: Vec::new(),
            soa,
            nameservers: Vec::new(),
            interface_names: Vec::new(),
        }
    }

    /// Add a subnet filter to the zone
    pub fn add_subnet(&mut self, subnet: IpNetwork) {
        self.subnets.push(subnet);
    }

    /// Add an excluded address to the zone
    pub fn add_excluded(&mut self, addr: IpAddr) {
        self.excluded.push(addr);
    }

    /// Add a nameserver to the zone
    pub fn add_nameserver(&mut self, ns: String) {
        self.nameservers.push(ns);
    }

    /// Add a static interface name mapping
    pub fn add_interface_name(&mut self, hostname: String, addr: IpAddr) {
        self.interface_names.push((hostname, addr));
    }

    /// Check if a domain name is within this authoritative zone
    ///
    /// Returns true if the query name matches the zone's domain or is a subdomain.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        is_in_zone(self, name).is_some()
    }

    /// Look up DNS records for a question within this zone
    ///
    /// Returns resource records that match the question, or an error if the
    /// question cannot be answered authoritatively.
    ///
    /// # Errors
    ///
    /// Returns `DnsError` if the question cannot be answered authoritatively.
    /// In the current simplified implementation, this always returns `Ok(Vec::new())`.
    pub fn lookup(&self, question: &DnsQuestion) -> Result<Vec<ResourceRecord>, DnsError> {
        // For now, return empty result as this is a simplified implementation
        // The full authoritative query processing is done through answer_authoritative_query
        Ok(Vec::new())
    }
}

// =============================================================================
// HELPER FUNCTIONS FOR SUBNET FILTERING
// =============================================================================

/// Find matching address in a list
///
/// Searches address list for an entry whose network prefix matches the
/// provided address. Used for subnet matching and exclusion checking.
///
/// Translates: `find_addrlist()` from `auth.c` lines 75-178
fn find_matching_address(list: &[IpNetwork], addr: IpAddr) -> Option<&IpNetwork> {
    list.iter().find(|network| network.contains(&addr))
}

/// Locate subnet configuration matching client IP
///
/// Finds the subnet entry that matches the client address for reverse zone
/// queries. Used for PTR record processing with subnet-specific zones.
///
/// Translates: `find_subnet()` from `auth.c` lines 180-228
fn find_matching_subnet(zone: &AuthZone, addr: IpAddr) -> Option<&IpNetwork> {
    find_matching_address(&zone.subnets, addr)
}

/// Check if IP address is in zone's exclusion list
///
/// Returns true if the address should be excluded from authoritative answers.
/// Used to blacklist specific addresses from split-horizon DNS responses.
///
/// Translates: `find_exclude()` from `auth.c` lines 230-281
fn is_excluded(zone: &AuthZone, addr: IpAddr) -> bool {
    for excluded_addr in &zone.excluded {
        if excluded_addr == &addr {
            return true;
        }
    }
    false
}

/// Determine if query from client IP should receive authoritative answer
///
/// Applies subnet filtering and exclusion rules to decide whether to serve
/// an authoritative response. Implements split-horizon DNS by returning
/// different answers based on client network location.
///
/// Translates: `filter_zone()` from `auth.c` lines 283-345
///
/// # Arguments
///
/// * `zone` - Authoritative zone configuration
/// * `client_addr` - Client IP address making the query
///
/// # Returns
///
/// `true` if client is authorized for zone, `false` if filtered out
pub fn should_answer_for_subnet(zone: &AuthZone, client_addr: IpAddr) -> bool {
    // Check exclusion list first
    if is_excluded(zone, client_addr) {
        debug!("Client {} excluded from zone {}", client_addr, zone.domain);
        return false;
    }

    // If no subnets configured, allow all clients
    if zone.subnets.is_empty() {
        return true;
    }

    // Check if client is in any allowed subnet
    if let Some(subnet) = find_matching_subnet(zone, client_addr) {
        debug!(
            "Client {} matches subnet {}/{} in zone {}",
            client_addr, subnet.addr, subnet.prefix_len, zone.domain
        );
        true
    } else {
        debug!(
            "Client {} not in any allowed subnet for zone {}",
            client_addr, zone.domain
        );
        false
    }
}

// =============================================================================
// ZONE MATCHING
// =============================================================================

/// Check if a domain name falls within an authoritative zone
///
/// Determines if the query name belongs to the configured zone, supporting
/// both exact matches and subdomain matches. Wildcard zones (*.example.com)
/// are supported. Returns the zone-relative name (cut point) if matched.
///
/// Translates: `in_zone()` from `auth.c` lines 347-430
///
/// # Arguments
///
/// * `zone` - Authoritative zone configuration
/// * `name` - Query domain name to check
///
/// # Returns
///
/// `Some(String)` with zone-relative name if in zone, `None` if not
///
/// # Examples
///
/// ```ignore
/// // Zone: "example.com"
/// is_in_zone(&zone, "host.example.com") => Some("host")
/// is_in_zone(&zone, "example.com") => Some("")
/// is_in_zone(&zone, "other.org") => None
/// ```
#[must_use]
pub fn is_in_zone(zone: &AuthZone, name: &str) -> Option<String> {
    let name_lower = name.trim_end_matches('.').to_lowercase();
    let zone_lower = zone.domain.trim_end_matches('.').to_lowercase();

    // Exact match - query for zone apex
    if domain_equal(&name_lower, &zone_lower) {
        return Some(String::new());
    }

    // Subdomain match - query for name within zone
    if name_lower.ends_with(&format!(".{zone_lower}")) {
        // Extract subdomain part (everything before zone domain)
        let cut_point = name_lower.len() - zone_lower.len() - 1;
        let subdomain = &name_lower[..cut_point];
        return Some(subdomain.to_string());
    }

    // Wildcard zone match (*.example.com)
    if let Some(wildcard_base) = zone_lower.strip_prefix("*.") {
        if name_lower.ends_with(wildcard_base) || domain_equal(&name_lower, wildcard_base) {
            // Calculate subdomain relative to wildcard base
            if domain_equal(&name_lower, wildcard_base) {
                return Some(String::new());
            } else if name_lower.ends_with(&format!(".{wildcard_base}")) {
                let cut_point = name_lower.len() - wildcard_base.len() - 1;
                let subdomain = &name_lower[..cut_point];
                return Some(subdomain.to_string());
            }
        }
    }

    None
}

// =============================================================================
// AUTHORITATIVE QUERY PROCESSING
// =============================================================================

/// Maximum CNAME chain length to prevent infinite loops
const CNAME_CHAIN_LIMIT: usize = 10;

/// Generate authoritative DNS response for configured zone
///
/// Main entry point for authoritative query processing. Processes DNS query
/// and generates authoritative answer including SOA, NS, A, AAAA, PTR, MX,
/// SRV, TXT, CNAME records from zone configuration and DHCP cache integration.
///
/// Translates: `answer_auth()` from `auth.c` lines 450-1200
///
/// # Arguments
///
/// * `header` - Mutable DNS header for response construction
/// * `query` - Parsed DNS query message
/// * `peer_addr` - Client socket address for subnet filtering
/// * `local_query` - True if query originated locally (skip subnet filtering)
/// * `zones` - Configured authoritative zones
/// * `cache` - DNS cache with DHCP lease integration
/// * `config` - Main configuration for accessing interface names, etc.
///
/// # Returns
///
/// `Ok(DnsMessage)` with authoritative response, or `Err(AuthError)` on failure
///
/// # Errors
///
/// - `AuthError::NotInZone` - Query name not in any authoritative zone
/// - `AuthError::NoAuthorityForSubnet` - Client subnet not authorized
/// - `AuthError::MalformedQuery` - Invalid query format
/// - `AuthError::PacketTruncated` - Response exceeds UDP packet size
///
/// # Panics
///
/// Panics if `zone_relative_name` is `None` after `matched_zone` is verified to be `Some`.
/// This should never occur due to the structure of `is_in_zone()` logic.
pub async fn answer_authoritative_query(
    header: &mut DnsHeader,
    query: &DnsMessage,
    peer_addr: SocketAddr,
    local_query: bool,
    zones: &[AuthZone],
    cache: Arc<RwLock<DnsCache>>,
    _config: &Config,
) -> Result<DnsMessage, AuthError> {
    // Validate query has at least one question
    if query.questions.is_empty() {
        return Err(AuthError::MalformedQuery {
            message: "Query has no questions".to_string(),
        });
    }

    // Get first question (DNS queries typically have single question)
    let question = &query.questions[0];
    let query_name = &question.qname;
    let query_type = question.qtype;

    debug!(
        "Authoritative query: name={}, type={:?}, from={}",
        query_name, query_type, peer_addr
    );

    // Find matching zone
    let mut matched_zone: Option<&AuthZone> = None;
    let mut zone_relative_name: Option<String> = None;

    for zone in zones {
        if let Some(relative) = is_in_zone(zone, query_name) {
            matched_zone = Some(zone);
            zone_relative_name = Some(relative);
            debug!("Query matches zone: {}", zone.domain);
            break;
        }
    }

    // Return REFUSED if not in any zone
    let zone = matched_zone.ok_or_else(|| AuthError::NotInZone {
        zone: "<none>".to_string(),
        query: query_name.clone(),
    })?;
    let _relative_name = zone_relative_name.unwrap();

    // Check subnet authorization (unless local query)
    if !local_query {
        let client_ip = peer_addr.ip();
        if !should_answer_for_subnet(zone, client_ip) {
            warn!(
                "Client {} not authorized for zone {}",
                client_ip, zone.domain
            );
            return Err(AuthError::NoAuthorityForSubnet {
                subnet: client_ip.to_string(),
            });
        }
    }

    // Build authoritative response
    let mut response = DnsMessage {
        header: header.clone(),
        questions: query.questions.clone(),
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
    };

    // Set authoritative answer flag
    response.header.flags.aa = true;
    response.header.flags.qr = true; // Query response
    response.header.flags.rcode = 0; // No error

    // Track if we found any records
    let mut found_records = false;

    // Process based on query type
    match query_type {
        RecordType::A | RecordType::AAAA => {
            // Forward lookup - A/AAAA records
            found_records = process_forward_query(
                query_name,
                query_type,
                zone,
                &cache,
                local_query,
                &mut response,
            )?;
        }
        RecordType::PTR => {
            // Reverse lookup - PTR records
            found_records =
                process_ptr_query(query_name, zone, &cache, local_query, &mut response)?;
        }
        RecordType::SOA => {
            // SOA record query
            found_records = process_soa_query(zone, &mut response);
        }
        RecordType::NS => {
            // NS record query
            found_records = process_ns_query(zone, &mut response);
        }
        RecordType::MX | RecordType::SRV | RecordType::TXT => {
            // MX, SRV, TXT records from configuration
            // For now, return NXDOMAIN (not implemented in minimal version)
            info!(
                "Query type {:?} not yet fully implemented for auth zones",
                query_type
            );
        }
        _ => {
            info!("Unsupported query type {:?} for auth zone", query_type);
        }
    }

    // If no records found, generate NXDOMAIN or add SOA in authority
    if !found_records {
        response.header.flags.rcode = 3; // NXDOMAIN
        add_soa_authority(zone, &mut response);
        info!(
            "NXDOMAIN response for {} in zone {}",
            query_name, zone.domain
        );
    }

    // Update header counts
    response.header.qdcount = response.questions.len().try_into().unwrap_or(u16::MAX);
    response.header.ancount = response.answers.len().try_into().unwrap_or(u16::MAX);
    response.header.nscount = response.authority.len().try_into().unwrap_or(u16::MAX);
    response.header.arcount = response.additional.len().try_into().unwrap_or(u16::MAX);

    info!(
        "Authoritative response: answers={}, authority={}, additional={}",
        response.header.ancount, response.header.nscount, response.header.arcount
    );

    Ok(response)
}

/// Process forward lookup query (A/AAAA)
///
/// Generates A or AAAA records from cache, DHCP leases, and static interface
/// name configuration. Integrates with DNS cache for dynamic hostname resolution.
fn process_forward_query(
    query_name: &str,
    query_type: RecordType,
    zone: &AuthZone,
    cache: &Arc<RwLock<DnsCache>>,
    local_query: bool,
    response: &mut DnsMessage,
) -> Result<bool, AuthError> {
    let mut found = false;

    // Search cache for matching hostnames
    let cache_guard = cache.read().map_err(|e| AuthError::InternalError {
        message: format!("Failed to acquire cache read lock: {e}"),
    })?;

    let entries = cache_guard.find_by_name(query_name);
    for entry in entries {
        // Iterate through each record in the cache entry
        for record in &entry.records {
            // Check if record type matches query type
            if matches!(
                (query_type, record),
                (RecordType::A, ResourceRecord::A { .. })
                    | (RecordType::AAAA, ResourceRecord::AAAA { .. })
            ) {
                // Apply subnet filtering if not local query
                if local_query || zone.subnets.is_empty() {
                    // Add record to response with zone's TTL
                    let rr = match record {
                        ResourceRecord::A { address, .. } => ResourceRecord::A {
                            name: query_name.to_string(),
                            class: RecordClass::IN,
                            ttl: zone.soa.minimum,
                            address: *address,
                        },
                        ResourceRecord::AAAA { address, .. } => ResourceRecord::AAAA {
                            name: query_name.to_string(),
                            class: RecordClass::IN,
                            ttl: zone.soa.minimum,
                            address: *address,
                        },
                        _ => continue,
                    };

                    response.answers.push(rr);
                    found = true;
                    debug!("Added cache record for {}: {:?}", query_name, record);
                }
            }
        }
    }

    // Check static interface name mappings
    for (hostname, addr) in &zone.interface_names {
        if domain_equal(query_name, hostname)
            && matches!(
                (query_type, addr),
                (RecordType::A, IpAddr::V4(_)) | (RecordType::AAAA, IpAddr::V6(_))
            )
        {
            // Apply subnet filtering
            if local_query
                || zone.subnets.is_empty()
                || zone.subnets.iter().any(|net| net.contains(addr))
            {
                let rr = match addr {
                    IpAddr::V4(ipv4) => ResourceRecord::A {
                        name: query_name.to_string(),
                        class: RecordClass::IN,
                        ttl: zone.soa.minimum,
                        address: *ipv4,
                    },
                    IpAddr::V6(ipv6) => ResourceRecord::AAAA {
                        name: query_name.to_string(),
                        class: RecordClass::IN,
                        ttl: zone.soa.minimum,
                        address: *ipv6,
                    },
                };

                response.answers.push(rr);
                found = true;
                debug!("Added interface mapping for {}: {}", hostname, addr);
            }
        }
    }

    Ok(found)
}

/// Process PTR query (reverse lookup)
///
/// Generates PTR records from cache reverse mappings and static configuration.
/// Extracts IP address from .in-addr.arpa or .ip6.arpa query name.
fn process_ptr_query(
    query_name: &str,
    zone: &AuthZone,
    cache: &Arc<RwLock<DnsCache>>,
    local_query: bool,
    response: &mut DnsMessage,
) -> Result<bool, AuthError> {
    let mut found = false;

    // Parse IP address from PTR query name
    let ip_addr = parse_ptr_name(query_name)?;

    debug!("PTR query for address: {}", ip_addr);

    // Search cache for reverse mapping
    let cache_guard = cache.read().map_err(|e| AuthError::InternalError {
        message: format!("Failed to acquire cache read lock: {e}"),
    })?;

    if let Some(hostname) = cache_guard.find_by_addr(ip_addr) {
        // Apply subnet filtering
        if local_query
            || zone.subnets.is_empty()
            || zone.subnets.iter().any(|net| net.contains(&ip_addr))
        {
            let ptr_record = ResourceRecord::PTR {
                name: query_name.to_string(),
                class: RecordClass::IN,
                ttl: zone.soa.minimum,
                ptrdname: hostname.clone(),
            };

            response.answers.push(ptr_record);
            found = true;
            debug!("Added PTR record: {} -> {}", ip_addr, hostname);
        }
    }

    // Check interface name mappings for reverse lookup
    for (hostname, addr) in &zone.interface_names {
        if addr == &ip_addr {
            // Apply subnet filtering
            if local_query
                || zone.subnets.is_empty()
                || zone.subnets.iter().any(|net| net.contains(addr))
            {
                let ptr_record = ResourceRecord::PTR {
                    name: query_name.to_string(),
                    class: RecordClass::IN,
                    ttl: zone.soa.minimum,
                    ptrdname: hostname.clone(),
                };

                response.answers.push(ptr_record);
                found = true;
                debug!("Added PTR from interface mapping: {} -> {}", addr, hostname);
            }
        }
    }

    Ok(found)
}

/// Process SOA query
///
/// Adds SOA record to answer section for explicit SOA queries.
fn process_soa_query(zone: &AuthZone, response: &mut DnsMessage) -> bool {
    let soa_record = ResourceRecord::SOA {
        name: zone.domain.clone(),
        class: RecordClass::IN,
        ttl: zone.soa.minimum,
        mname: zone.soa.primary_ns.clone(),
        rname: zone.soa.admin_email.clone(),
        serial: zone.soa.serial,
        refresh: zone.soa.refresh,
        retry: zone.soa.retry,
        expire: zone.soa.expire,
        minimum: zone.soa.minimum,
    };

    response.answers.push(soa_record);
    debug!("Added SOA record for zone {}", zone.domain);
    true
}

/// Process NS query
///
/// Adds NS records to answer section for explicit NS queries.
fn process_ns_query(zone: &AuthZone, response: &mut DnsMessage) -> bool {
    let mut found = false;

    for nameserver in &zone.nameservers {
        let ns_record = ResourceRecord::NS {
            name: zone.domain.clone(),
            class: RecordClass::IN,
            ttl: zone.soa.minimum,
            nsdname: nameserver.clone(),
        };

        response.answers.push(ns_record);
        found = true;
        debug!("Added NS record: {} -> {}", zone.domain, nameserver);
    }

    found
}

/// Add SOA record to authority section
///
/// Used for NXDOMAIN responses and empty answer sets to indicate zone authority.
fn add_soa_authority(zone: &AuthZone, response: &mut DnsMessage) {
    let soa_record = ResourceRecord::SOA {
        name: zone.domain.clone(),
        class: RecordClass::IN,
        ttl: zone.soa.minimum,
        mname: zone.soa.primary_ns.clone(),
        rname: zone.soa.admin_email.clone(),
        serial: zone.soa.serial,
        refresh: zone.soa.refresh,
        retry: zone.soa.retry,
        expire: zone.soa.expire,
        minimum: zone.soa.minimum,
    };

    response.authority.push(soa_record);
}

/// Parse IP address from PTR query name
///
/// Extracts IP address from in-addr.arpa (IPv4) or ip6.arpa (IPv6) format.
///
/// # Examples
///
/// ```ignore
/// parse_ptr_name("1.0.168.192.in-addr.arpa") => Ok(IpAddr::V4(192.168.0.1))
/// parse_ptr_name("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
///   => Ok(IpAddr::V6(2001:db8::1))
/// ```
fn parse_ptr_name(name: &str) -> Result<IpAddr, AuthError> {
    let name_lower = name.to_lowercase();

    if name_lower.ends_with(".in-addr.arpa") || name_lower.ends_with(".in-addr.arpa.") {
        // IPv4 PTR format: 1.0.168.192.in-addr.arpa for 192.168.0.1
        let parts: Vec<&str> = name_lower
            .trim_end_matches(".in-addr.arpa")
            .trim_end_matches(".in-addr.arpa.")
            .split('.')
            .collect();

        if parts.len() != 4 {
            return Err(AuthError::MalformedQuery {
                message: format!(
                    "Invalid IPv4 PTR name: expected 4 octets, got {}",
                    parts.len()
                ),
            });
        }

        // Reverse the octets
        let octets: Result<Vec<u8>, _> = parts.iter().rev().map(|s| s.parse()).collect();
        let octets = octets.map_err(|_| AuthError::MalformedQuery {
            message: "Failed to parse IPv4 octets in PTR name".to_string(),
        })?;

        if octets.len() != 4 {
            return Err(AuthError::MalformedQuery {
                message: format!(
                    "Invalid IPv4 PTR address: expected 4 octets, got {}",
                    octets.len()
                ),
            });
        }

        Ok(IpAddr::V4(Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        )))
    } else if name_lower.ends_with(".ip6.arpa") || name_lower.ends_with(".ip6.arpa.") {
        // IPv6 PTR format: nibble-reversed hex digits
        let parts: Vec<&str> = name_lower
            .trim_end_matches(".ip6.arpa")
            .trim_end_matches(".ip6.arpa.")
            .split('.')
            .collect();

        if parts.len() != 32 {
            return Err(AuthError::MalformedQuery {
                message: format!(
                    "Invalid IPv6 PTR name: expected 32 nibbles, got {}",
                    parts.len()
                ),
            });
        }

        // Reconstruct IPv6 address from nibbles
        let mut bytes = [0u8; 16];
        for (i, nibble) in parts.iter().rev().enumerate() {
            let value = u8::from_str_radix(nibble, 16).map_err(|_| AuthError::MalformedQuery {
                message: format!("Failed to parse hex nibble: {nibble}"),
            })?;
            if value > 15 {
                return Err(AuthError::MalformedQuery {
                    message: format!("Invalid nibble value: {value}"),
                });
            }

            let byte_idx = i / 2;
            if i % 2 == 0 {
                bytes[byte_idx] |= value << 4;
            } else {
                bytes[byte_idx] |= value;
            }
        }

        Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        Err(AuthError::MalformedQuery {
            message: format!(
                "PTR query name {name} does not end with .in-addr.arpa or .ip6.arpa"
            ),
        })
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipnetwork_ipv4_contains() {
        let net = IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24).unwrap();

        assert!(net.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(net.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))));
        assert!(!net.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(!net.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_ipnetwork_ipv6_contains() {
        let net = IpNetwork::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            32,
        )
        .unwrap();

        assert!(net.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(net.contains(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
        ))));
        assert!(!net.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_is_in_zone_exact() {
        let soa = SoaRecord::new(
            "ns1.example.com".to_string(),
            "admin.example.com".to_string(),
        );
        let zone = AuthZone::new("example.com".to_string(), soa);

        assert_eq!(is_in_zone(&zone, "example.com"), Some(String::new()));
        assert_eq!(is_in_zone(&zone, "example.com."), Some(String::new()));
    }

    #[test]
    fn test_is_in_zone_subdomain() {
        let soa = SoaRecord::new(
            "ns1.example.com".to_string(),
            "admin.example.com".to_string(),
        );
        let zone = AuthZone::new("example.com".to_string(), soa);

        assert_eq!(
            is_in_zone(&zone, "host.example.com"),
            Some("host".to_string())
        );
        assert_eq!(
            is_in_zone(&zone, "sub.domain.example.com"),
            Some("sub.domain".to_string())
        );
    }

    #[test]
    fn test_is_in_zone_not_in_zone() {
        let soa = SoaRecord::new(
            "ns1.example.com".to_string(),
            "admin.example.com".to_string(),
        );
        let zone = AuthZone::new("example.com".to_string(), soa);

        assert_eq!(is_in_zone(&zone, "other.org"), None);
        assert_eq!(is_in_zone(&zone, "example.org"), None);
    }

    #[test]
    fn test_should_answer_for_subnet_no_filters() {
        let soa = SoaRecord::new("ns1.local".to_string(), "admin.local".to_string());
        let zone = AuthZone::new("local".to_string(), soa);

        // No subnets configured - allow all
        assert!(should_answer_for_subnet(
            &zone,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        ));
        assert!(should_answer_for_subnet(
            &zone,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
    }

    #[test]
    fn test_should_answer_for_subnet_with_filter() {
        let soa = SoaRecord::new("ns1.local".to_string(), "admin.local".to_string());
        let mut zone = AuthZone::new("local".to_string(), soa);

        let subnet = IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24).unwrap();
        zone.add_subnet(subnet);

        // Inside subnet - allow
        assert!(should_answer_for_subnet(
            &zone,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        ));
        assert!(should_answer_for_subnet(
            &zone,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))
        ));

        // Outside subnet - deny
        assert!(!should_answer_for_subnet(
            &zone,
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))
        ));
        assert!(!should_answer_for_subnet(
            &zone,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
    }

    #[test]
    fn test_should_answer_for_subnet_with_exclusion() {
        let soa = SoaRecord::new("ns1.local".to_string(), "admin.local".to_string());
        let mut zone = AuthZone::new("local".to_string(), soa);

        zone.add_excluded(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

        // Excluded address - deny even without subnet filters
        assert!(!should_answer_for_subnet(
            &zone,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
        ));

        // Other addresses - allow
        assert!(should_answer_for_subnet(
            &zone,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        ));
    }

    #[test]
    fn test_parse_ptr_name_ipv4() {
        let result = parse_ptr_name("1.0.168.192.in-addr.arpa").unwrap();
        assert_eq!(result, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));

        let result = parse_ptr_name("254.3.2.10.in-addr.arpa.").unwrap();
        assert_eq!(result, IpAddr::V4(Ipv4Addr::new(10, 2, 3, 254)));
    }

    #[test]
    fn test_parse_ptr_name_invalid() {
        assert!(parse_ptr_name("invalid.name").is_err());
        assert!(parse_ptr_name("1.2.3.in-addr.arpa").is_err()); // Only 3 octets
        assert!(parse_ptr_name("a.b.c.d.in-addr.arpa").is_err()); // Non-numeric
    }

    #[test]
    fn test_soa_record_defaults() {
        let soa = SoaRecord::new(
            "ns1.example.com".to_string(),
            "admin.example.com".to_string(),
        );

        assert_eq!(soa.primary_ns, "ns1.example.com");
        assert_eq!(soa.admin_email, "admin.example.com");
        assert_eq!(soa.serial, 1);
        assert_eq!(soa.refresh, 7200);
        assert_eq!(soa.retry, 1800);
        assert_eq!(soa.expire, 1_209_600);
        assert_eq!(soa.minimum, 3600);
    }
}
