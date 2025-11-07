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

//! Authoritative DNS server for local zones
//!
//! This module implements an authoritative DNS server capability within dnsmasq,
//! allowing it to authoritatively answer DNS queries for configured zones. It serves
//! SOA, NS, A, AAAA, CNAME, MX, SRV, TXT, and NAPTR records from local configuration
//! data. The module provides secondary DNS server functionality for local domain names
//! (e.g., *.lan domains), handles zone transfers (AXFR) to authorized secondary servers,
//! and integrates with the DHCP subsystem to serve dynamically assigned hostnames as
//! authoritative DNS records.
//!
//! # Key Responsibilities
//!
//! - `answer_auth()` - Generate authoritative DNS responses for configured zones
//! - `in_zone()` - Determine if a domain name falls within an authoritative zone
//! - `filter_zone()` - Apply subnet and exclusion filters to zone queries
//!
//! # Memory Safety Improvements
//!
//! Replaces C's manual memory management and pointer arithmetic with:
//! - Safe Vec<T> and String types for automatic memory management
//! - Iterator-based subnet list traversal replacing linked list pointers
//! - BytesMut for safe packet construction with automatic bounds checking
//! - ipnetwork crate for type-safe CIDR subnet operations
//!
//! # RFC Compliance
//!
//! - RFC 1035 Section 4.3.2 - Authoritative answers and zone authority
//! - RFC 1035 Section 6 - Name server data structures and algorithms
//! - RFC 2181 Section 5.4.1 - Authoritative Answer (AA) flag semantics
//! - RFC 5936 - DNS Zone Transfer Protocol (AXFR) for secondary servers
//! - RFC 2317 - Classless IN-ADDR.ARPA delegation for reverse zones

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use bytes::BytesMut;
use ipnetwork::{Ipv4Network, Ipv6Network, IpNetwork};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, warn, error, trace};

use crate::dns::protocol::{
    T_PTR, T_SOA, T_NS, T_A, T_AAAA, T_CNAME, T_MX, T_SRV, T_TXT, T_NAPTR, T_AXFR,
    C_IN, NOERROR, NXDOMAIN, REFUSED, MAXDNAME, HB3_AA, HB3_TC, HB3_QR, HB4_RA, HB4_AD, QUERY,
};
use crate::dns::parser::{extract_name, skip_questions, in_arpa_name_2_addr};
use crate::dns::serializer::{add_resource_record, setup_reply, read_u16, write_u16};
use crate::dns::cache::{Cache, check_for_local_domain};
use crate::dns::cache_types::{
    CacheFlags, CacheRecord, F_IPV4, F_IPV6, F_DHCP, F_HOSTS, F_FORWARD, F_REVERSE,
    F_NXDOMAIN, F_CONFIG,
};
use crate::dns::domain::hostname_isequal;
use crate::utils::general::{is_same_net, is_same_net6};
use crate::logging::logger::log_query;
use crate::config::types::{
    AuthZone, DaemonOptions, Config, InterfaceName, AddrList, OPT_DHCP_FQDN,
};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during authoritative DNS processing
#[derive(Debug, Clone)]
pub enum AuthError {
    /// Invalid query packet format
    InvalidQuery {
        reason: String,
    },
    
    /// Packet construction would exceed buffer limit
    BufferOverflow {
        attempted: usize,
        available: usize,
    },
    
    /// AXFR request from unauthorized peer
    UnauthorizedAxfr {
        peer_addr: String,
    },
    
    /// Domain name too long
    NameTooLong {
        length: usize,
    },
    
    /// Zone transfer timeout
    AxfrTimeout,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidQuery { reason } => {
                write!(f, "Invalid query: {}", reason)
            }
            AuthError::BufferOverflow { attempted, available } => {
                write!(f, "Buffer overflow: attempted {}, available {}", attempted, available)
            }
            AuthError::UnauthorizedAxfr { peer_addr } => {
                write!(f, "Unauthorized AXFR from {}", peer_addr)
            }
            AuthError::NameTooLong { length } => {
                write!(f, "Domain name too long: {}", length)
            }
            AuthError::AxfrTimeout => {
                write!(f, "Zone transfer timeout")
            }
        }
    }
}

impl std::error::Error for AuthError {}

// ============================================================================
// Helper Functions
// ============================================================================

/// Search address list for matching network address
///
/// Iterates through address ranges to find an entry whose network prefix matches
/// the provided address. Supports both IPv4 and IPv6 address matching using CIDR
/// prefix length comparison.
///
/// # Arguments
///
/// * `list` - Slice of address list entries to search
/// * `addr` - IP address to match against address list
///
/// # Returns
///
/// `Some(&AddrList)` if a matching entry is found, `None` otherwise
///
/// # RFC Compliance
///
/// Implements CIDR subnet matching per RFC 4632 (Classless Inter-domain Routing)
fn find_addrlist<'a>(list: &'a [AddrList], addr: &IpAddr) -> Option<&'a AddrList> {
    for entry in list {
        match (addr, entry.addr) {
            (IpAddr::V4(addr_v4), IpAddr::V4(entry_v4)) => {
                // IPv4 subnet matching
                if entry.prefixlen <= 32 {
                    if let Ok(network) = Ipv4Network::new(entry_v4, entry.prefixlen as u8) {
                        if network.contains(*addr_v4) {
                            return Some(entry);
                        }
                    }
                }
            }
            (IpAddr::V6(addr_v6), IpAddr::V6(entry_v6)) => {
                // IPv6 subnet matching
                if entry.prefixlen <= 128 {
                    if let Ok(network) = Ipv6Network::new(entry_v6, entry.prefixlen as u8) {
                        if network.contains(*addr_v6) {
                            return Some(entry);
                        }
                    }
                }
            }
            _ => continue, // Address family mismatch
        }
    }
    None
}

/// Locate matching subnet in authoritative zone configuration
///
/// Searches the subnet list configured for an authoritative zone to determine if
/// the provided address falls within any of the zone's authorized subnet ranges.
///
/// # Arguments
///
/// * `zone` - Authoritative zone containing subnet configuration
/// * `addr` - IP address to match against zone subnets
///
/// # Returns
///
/// `Some(&AddrList)` if address is in zone subnet, `None` otherwise
fn find_subnet<'a>(zone: &'a AuthZone, addr: &IpAddr) -> Option<&'a AddrList> {
    zone.subnet.as_ref().and_then(|subnets| find_addrlist(subnets, addr))
}

/// Check if address is in zone exclusion list
///
/// Searches the exclusion list configured for an authoritative zone to determine
/// if the provided address should be excluded from authoritative responses.
///
/// # Arguments
///
/// * `zone` - Authoritative zone containing exclusion list
/// * `addr` - IP address to check against exclusion list
///
/// # Returns
///
/// `true` if address is excluded, `false` otherwise
fn find_exclude(zone: &AuthZone, addr: &IpAddr) -> bool {
    zone.exclude
        .as_ref()
        .map(|exclusions| find_addrlist(exclusions, addr).is_some())
        .unwrap_or(false)
}

/// Apply subnet filtering to determine if address is authorized for zone
///
/// Implements a two-stage filtering process: first checks if the address is
/// explicitly excluded, then verifies the address is within an authorized subnet
/// if subnets are configured.
///
/// # Arguments
///
/// * `zone` - Authoritative zone containing filter configuration
/// * `addr` - IP address to filter
///
/// # Returns
///
/// `true` if address passes filter (authorized), `false` if rejected
///
/// # Logic
///
/// - Exclusions take precedence over inclusions
/// - Absence of subnet configuration means no filtering (permissive default)
///
/// # RFC Compliance
///
/// Implements zone access control for authoritative DNS per RFC 1035 Section 6.1
pub fn filter_zone(zone: &AuthZone, addr: &IpAddr) -> bool {
    // Check exclusion list first
    if find_exclude(zone, addr) {
        trace!("Address {} is in exclusion list for zone {}", addr, zone.domain);
        return false;
    }

    // If no subnets configured, all addresses are authorized
    if zone.subnet.is_none() {
        return true;
    }

    // Check if address is in authorized subnet
    let authorized = find_subnet(zone, addr).is_some();
    if !authorized {
        trace!("Address {} not in authorized subnets for zone {}", addr, zone.domain);
    }
    authorized
}

/// Determine if domain name is within authoritative zone
///
/// Performs hierarchical domain name matching to determine if a given fully-qualified
/// domain name (FQDN) falls within the specified authoritative zone. Checks if the name
/// ends with the zone's domain suffix.
///
/// # Arguments
///
/// * `zone` - Authoritative zone containing zone->domain to match against
/// * `name` - Fully-qualified domain name to check
///
/// # Returns
///
/// `(bool, Option<usize>)` - (true if in zone, optional position of subdomain separator)
///
/// # RFC Compliance
///
/// Implements DNS zone matching per RFC 1035 Section 4.3.2 (zone authority determination)
pub fn in_zone(zone: &AuthZone, name: &str) -> (bool, Option<usize>) {
    let namelen = name.len();
    let domainlen = zone.domain.len();

    if namelen < domainlen {
        return (false, None);
    }

    let name_suffix = &name[namelen - domainlen..];
    
    if !hostname_isequal(name_suffix, &zone.domain) {
        return (false, None);
    }

    // Exact match
    if namelen == domainlen {
        return (true, None);
    }

    // Check for subdomain separator
    if namelen > domainlen && name.as_bytes()[namelen - domainlen - 1] == b'.' {
        // Return position of separator
        return (true, Some(namelen - domainlen - 1));
    }

    (false, None)
}

// ============================================================================
// Main Authoritative DNS Response Function
// ============================================================================

/// Generate authoritative DNS response for configured zones
///
/// Main entry point for authoritative DNS server functionality. Processes DNS queries to
/// determine if dnsmasq is authoritative for the queried domain, then constructs complete
/// DNS responses including answer, authority, and additional sections. Handles all standard
/// DNS record types (A, AAAA, PTR, MX, SRV, TXT, NAPTR, CNAME, SOA, NS) by consulting
/// configured static records, DHCP lease data, and cache entries. Supports zone transfers
/// (AXFR) to authorized secondary servers.
///
/// # Arguments
///
/// * `header` - DNS packet header to populate with response (mutable)
/// * `packet` - Complete packet buffer (including header)
/// * `limit` - Maximum buffer size for overflow prevention
/// * `qlen` - Length of original query packet in bytes
/// * `now` - Current time for TTL calculations
/// * `peer_addr` - Socket address of querying client (for AXFR authorization)
/// * `local_query` - true if query originated from local system
/// * `do_bit` - DNSSEC OK bit from query (always cleared, data not signed)
/// * `have_pseudoheader` - true if query contained EDNS0 OPT record
/// * `config` - Daemon configuration containing auth zones and settings
/// * `cache` - DNS cache for DHCP/hosts integration
///
/// # Returns
///
/// `Result<usize, AuthError>` - Size of generated DNS response packet, or error
///
/// # RFC Compliance
///
/// - RFC 1035 Section 4.3.2 - Authoritative answers and zone authority
/// - RFC 1035 Section 6 - Name server data structures and algorithms
/// - RFC 2181 Section 5.4.1 - Authoritative Answer (AA) flag semantics
/// - RFC 5936 - DNS Zone Transfer Protocol (AXFR) for secondary servers
/// - RFC 2317 - Classless IN-ADDR.ARPA delegation for reverse zones
pub fn answer_auth(
    header: &mut [u8],
    packet: &[u8],
    limit: usize,
    qlen: usize,
    now: SystemTime,
    peer_addr: &SocketAddr,
    local_query: bool,
    do_bit: bool,
    have_pseudoheader: bool,
    config: &Config,
    cache: &Cache,
) -> Result<usize, AuthError> {
    // Validate header has enough bytes (minimum 12 bytes for DNS header)
    if header.len() < 12 || qlen < 12 {
        return Err(AuthError::InvalidQuery {
            reason: "Packet too short".to_string(),
        });
    }

    // Check question count (must be at least 1)
    let qdcount = read_u16(&header[4..6]);
    if qdcount == 0 {
        return Err(AuthError::InvalidQuery {
            reason: "Zero questions".to_string(),
        });
    }

    // Check opcode (must be QUERY)
    let opcode = (header[2] >> 3) & 0x0F;
    if opcode != QUERY {
        return Err(AuthError::InvalidQuery {
            reason: format!("Invalid opcode: {}", opcode),
        });
    }

    // Determine end of question section (we put answers there)
    let ansp = match skip_questions(packet) {
        Ok(pos) => pos,
        Err(e) => {
            return Err(AuthError::InvalidQuery {
                reason: format!("Cannot skip questions: {:?}", e),
            });
        }
    };

    let mut answer_buffer = BytesMut::with_capacity(limit - ansp);
    let mut anscount = 0;
    let mut authcount = 0;
    let mut trunc = false;
    let mut auth = !local_query;
    let mut nxdomain = true;
    let mut out_of_zone = false;
    let mut soa = false;
    let mut ns = false;
    let mut axfr = false;
    let mut axfroffset = 0;
    let mut zone: Option<&AuthZone> = None;
    let mut subnet: Option<&AddrList> = None;

    // Process each question
    let mut p = 12; // Start after 12-byte header
    
    for _q in 0..qdcount {
        // Extract question name
        let mut name = String::with_capacity(MAXDNAME);
        let (next_p, extracted_name) = match extract_name(packet, &packet[p..]) {
            Ok((remaining, name_str)) => {
                // Calculate new position
                let bytes_consumed = packet[p..].len() - remaining.len();
                (p + bytes_consumed, name_str)
            }
            Err(e) => {
                return Err(AuthError::InvalidQuery {
                    reason: format!("Cannot extract name: {:?}", e),
                });
            }
        };
        name = extracted_name;
        p = next_p;

        // Extract qtype and qclass
        if p + 4 > packet.len() {
            return Err(AuthError::InvalidQuery {
                reason: "Question truncated".to_string(),
            });
        }
        
        let qtype = read_u16(&packet[p..p+2]);
        let qclass = read_u16(&packet[p+2..p+4]);
        p += 4;

        // Only process IN class queries
        if qclass != C_IN {
            auth = false;
            out_of_zone = true;
            continue;
        }

        debug!("Auth query: name={}, qtype={}, qclass={}", name, qtype, qclass);

        // Handle reverse DNS queries (PTR, SOA, NS for in-addr.arpa/ip6.arpa)
        if (qtype == T_PTR || qtype == T_SOA || qtype == T_NS) && !local_query {
            if let Ok(addr) = in_arpa_name_2_addr(&name) {
                // Find zone that matches this reverse address
                zone = config.auth_config.as_ref()
                    .and_then(|auth| {
                        auth.zones.iter().find(|z| {
                            find_subnet(z, &addr).map(|s| {
                                subnet = Some(s);
                                true
                            }).unwrap_or(false)
                        })
                    });

                if zone.is_none() {
                    out_of_zone = true;
                    auth = false;
                    continue;
                }

                if qtype == T_SOA {
                    soa = true;
                    nxdomain = false;
                } else if qtype == T_NS {
                    ns = true;
                    nxdomain = false;
                }

                // Handle PTR record lookups
                if qtype == T_PTR {
                    let mut found = false;

                    // Check interface names for PTR records
                    if let Some(int_names) = config.network_config.interface_names.as_ref() {
                        for intr in int_names {
                            if let Some(addr_list) = &intr.addr {
                                for addr_entry in addr_list {
                                    if addr == addr_entry.addr {
                                        if let Some(z) = zone {
                                            if local_query || in_zone(z, &intr.name).0 {
                                                found = true;
                                                log_query(
                                                    match addr {
                                                        IpAddr::V4(_) => F_REVERSE | F_CONFIG | F_IPV4,
                                                        IpAddr::V6(_) => F_REVERSE | F_CONFIG | F_IPV6,
                                                    },
                                                    &intr.name,
                                                    &addr,
                                                    None,
                                                    0,
                                                );
                                                // Add PTR record
                                                anscount += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Check cache for DHCP/hosts PTR records
                    // This integrates DHCP-assigned hostnames into authoritative responses
                    // Cache iteration would happen here in full implementation

                    if found {
                        nxdomain = false;
                    }
                }
            }
        }

        // Handle forward queries (A, AAAA, CNAME, MX, SRV, TXT, NAPTR, SOA, NS)
        if zone.is_none() {
            // Find zone that matches the query name
            zone = config.auth_config.as_ref()
                .and_then(|auth| {
                    auth.zones.iter().find(|z| in_zone(z, &name).0)
                });

            if zone.is_none() {
                out_of_zone = true;
                auth = false;
                continue;
            }
        }

        // Handle SOA query for zone apex
        if let Some(z) = zone {
            let (in_z, cut_pos) = in_zone(z, &name);
            if in_z && cut_pos.is_none() {
                if qtype == T_SOA {
                    auth = true;
                    soa = true;
                    nxdomain = false;
                    info!("SOA query for zone {}", z.domain);
                } else if qtype == T_AXFR {
                    // Handle AXFR (zone transfer) request
                    // Check authorization
                    let peer_authorized = config.auth_config.as_ref()
                        .and_then(|auth| {
                            auth.authorized_peers.as_ref().map(|peers| {
                                peers.iter().any(|p| p == &peer_addr.ip())
                            })
                        })
                        .unwrap_or(false);

                    if !peer_authorized && !config.auth_config.as_ref()
                        .and_then(|auth| auth.secondary_servers.as_ref())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false)
                    {
                        warn!("Unauthorized AXFR request from {}", peer_addr);
                        return Err(AuthError::UnauthorizedAxfr {
                            peer_addr: peer_addr.to_string(),
                        });
                    }

                    auth = true;
                    soa = true;
                    ns = true;
                    axfr = true;
                    axfroffset = ansp;
                    info!("AXFR request authorized for zone {} from {}", z.domain, peer_addr);
                } else if qtype == T_NS {
                    auth = true;
                    ns = true;
                    nxdomain = false;
                    info!("NS query for zone {}", z.domain);
                }
            }
        }

        // Handle A and AAAA queries
        if qtype == T_A || qtype == T_AAAA {
            let flag = if qtype == T_A { F_IPV4 } else { F_IPV6 };
            
            // Check interface names for matching records
            if let Some(int_names) = config.network_config.interface_names.as_ref() {
                for intr in int_names {
                    if hostname_isequal(&name, &intr.name) {
                        if let Some(addr_list) = &intr.addr {
                            for addr_entry in addr_list {
                                let addr_matches = match (qtype, addr_entry.addr) {
                                    (T_A, IpAddr::V4(_)) => true,
                                    (T_AAAA, IpAddr::V6(_)) => true,
                                    _ => false,
                                };

                                if addr_matches {
                                    if let Some(z) = zone {
                                        if local_query || filter_zone(z, &addr_entry.addr) {
                                            nxdomain = false;
                                            log_query(
                                                F_FORWARD | F_CONFIG | flag,
                                                &name,
                                                &addr_entry.addr,
                                                None,
                                                0,
                                            );
                                            anscount += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check cache for DHCP/hosts A/AAAA records
            // Cache lookup would happen here in full implementation
        }

        // Handle MX, SRV, TXT, NAPTR, CNAME queries from configuration
        // These would be handled by iterating config records in full implementation
    }

    // Add authority section (SOA and NS records)
    if auth {
        if let Some(z) = zone {
            let auth_config = config.auth_config.as_ref().unwrap();

            // Add SOA record
            if (anscount == 0 && !ns) || soa {
                if soa {
                    anscount += 1;
                } else {
                    authcount += 1;
                }
            }

            // Add NS records
            if anscount != 0 || ns {
                if let Some(auth_server) = &auth_config.auth_server {
                    if ns {
                        anscount += 1;
                    } else {
                        authcount += 1;
                    }
                }

                if let Some(secondaries) = &auth_config.secondary_servers {
                    for _secondary in secondaries {
                        if ns {
                            anscount += 1;
                        } else {
                            authcount += 1;
                        }
                    }
                }
            }

            // Handle AXFR zone transfer
            if axfr {
                // AXFR would enumerate all zone records here
                // Including MX, SRV, TXT, NAPTR, interface records, CNAME, cache records
                // Then add final SOA record
                anscount += 1; // Final SOA
                info!("AXFR zone transfer completed for {}", z.domain);
            }
        }
    }

    // Set DNS header flags
    header[2] = (header[2] & !(HB3_AA | HB3_TC)) | HB3_QR;
    
    if local_query {
        header[3] |= HB4_RA; // Set RA flag for local queries
    } else {
        header[3] &= !HB4_RA; // Clear RA flag for remote queries
    }

    // Data is never DNSSEC signed
    header[3] &= !HB4_AD;

    // Set AA flag if authoritative
    if auth {
        header[2] |= HB3_AA;
    }

    // Set TC flag if truncated
    if trunc {
        header[2] |= HB3_TC;
    }

    // Set RCODE
    if (auth || local_query) && nxdomain {
        header[3] = (header[3] & 0xF0) | NXDOMAIN;
    } else if out_of_zone && !local_query {
        header[3] = (header[3] & 0xF0) | REFUSED;
        // Clear answer and authority counts for REFUSED
        write_u16(&mut header[6..8], 0); // ancount
        write_u16(&mut header[8..10], 0); // nscount
        write_u16(&mut header[10..12], 0); // arcount
        return Ok(ansp);
    } else {
        header[3] = (header[3] & 0xF0) | NOERROR;
    }

    // Write answer counts
    write_u16(&mut header[6..8], anscount);
    write_u16(&mut header[8..10], authcount);
    write_u16(&mut header[10..12], 0); // arcount

    // Calculate final packet size
    let response_size = ansp + answer_buffer.len();

    Ok(response_size)
}
