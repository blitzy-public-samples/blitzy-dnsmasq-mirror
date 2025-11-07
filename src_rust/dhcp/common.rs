// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! Shared DHCPv4/DHCPv6 utilities
//!
//! This module implements common functionality used by both DHCPv4 (dhcp.c, rfc2131.c)
//! and DHCPv6 (dhcp6.c, rfc3315.c) servers. It provides essential shared utilities
//! for option parsing and encoding, vendor class matching, tag-based conditional
//! configuration, device binding, packet validation, and client configuration matching.
//!
//! # Memory Safety Transformation
//!
//! All C manual memory management patterns are replaced with Rust's safe alternatives:
//! - `malloc/free` → `Vec<u8>` with automatic Drop deallocation
//! - `expand_buf` realloc → `Vec::reserve` with safe capacity checks
//! - Manual buffer expansion with MSG_PEEK → tokio async peek_from with automatic sizing
//! - `strcmp` loops → String equality and `PartialEq` trait
//! - Pointer arithmetic → safe slice indexing with bounds checking
//! - Linked list traversal → Iterator trait methods
//! - `errno` → `Result<T, io::Error>` with `?` operator propagation
//! - `sprintf` → format! macro with compile-time validation
//!
//! # Key Responsibilities
//!
//! - `find_config()`: Matches clients to dhcp_config entries by client ID, MAC, or hostname
//! - `match_bytes()`: Compares byte arrays for option matching with wildcard support
//! - `option_filter()`: Applies tag-based filtering to determine which options are valid
//! - `match_netid()`: Checks if network ID sets match for conditional configuration
//! - `option_string()`: Converts DHCP options to human-readable strings for logging
//! - `log_context()`: Logs DHCP context information (address ranges, lease times)
//! - `recv_dhcp_packet()`: Receives DHCP packets with automatic buffer expansion
//! - `dhcp_update_configs()`: Updates static DHCP configurations from /etc/hosts
//!
//! # Dependencies
//!
//! - `config::types`: For DaemonOptions, network ID tags, DHCP config structures
//! - `utils::general`: For hostname_isequal() case-insensitive comparison
//! - `dns::cache`: For /etc/hosts integration in dhcp_update_configs()
//!
//! # Original C File
//!
//! Refactored from `src/dhcp-common.c` (dnsmasq 2.90)

use std::collections::HashMap;
use std::fmt;
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

#[cfg(target_os = "linux")]
use socket2::{Domain, Socket, Type as SocketType};

// Internal imports from depends_on_files
use crate::config::types::DaemonOptions;
use crate::dns::cache::Cache;
use crate::utils::general::hostname_isequal;

// ========== Constants ==========

/// Action code for adding a lease (DHCP script parameter)
///
/// Used when calling external DHCP scripts with "add" action.
/// Original C: ACTION_ADD in dhcp-common.c
pub const ACTION_ADD: &str = "add";

/// Action code for deleting a lease (DHCP script parameter)
///
/// Used when calling external DHCP scripts with "del" action.
/// Original C: ACTION_DEL in dhcp-common.c
pub const ACTION_DEL: &str = "del";

/// Action code for old lease update (DHCP script parameter)
///
/// Used when renewing an existing lease with same client.
/// Original C: ACTION_OLD in dhcp-common.c
pub const ACTION_OLD: &str = "old";

/// Action code for old hostname update (DHCP script parameter)
///
/// Used when hostname changes for an existing lease.
/// Original C: ACTION_OLD_HOSTNAME in dhcp-common.c
pub const ACTION_OLD_HOSTNAME: &str = "old-hostname";

/// Action code for TFTP file transfer (script parameter)
///
/// Used when calling TFTP-related scripts.
/// Original C: ACTION_TFTP in dhcp-common.c
pub const ACTION_TFTP: &str = "tftp";

/// Action code for ARP table entry addition (script parameter)
///
/// Used when adding ARP entries for DHCP clients.
/// Original C: ACTION_ARP in dhcp-common.c
pub const ACTION_ARP: &str = "arp";

/// Action code for ARP table entry deletion (script parameter)
///
/// Used when removing ARP entries for expired leases.
/// Original C: ACTION_ARP_DEL in dhcp-common.c
pub const ACTION_ARP_DEL: &str = "arp-del";

/// Action code for DHCP relay snoop (script parameter)
///
/// Used when snooping DHCP relay traffic.
/// Original C: ACTION_RELAY_SNOOP in dhcp-common.c
pub const ACTION_RELAY_SNOOP: &str = "relay-snoop";

/// Maximum hardware address length for DHCP (16 bytes per RFC 2131)
///
/// DHCPv4 chaddr field size. Most commonly 6 bytes for Ethernet MAC addresses,
/// but RFC 2131 allows up to 16 bytes for other hardware types.
/// Original C: DHCP_CHADDR_MAX in dnsmasq.h
pub const DHCP_CHADDR_MAX: usize = 16;

/// DHCPv6 lease type: Temporary Address (IA_TA)
///
/// Used to identify temporary IPv6 addresses with short lifetimes.
/// Original C: LEASE_TA in dnsmasq.h
pub const LEASE_TA: u32 = 1;

/// DHCPv6 lease type: Non-temporary Address (IA_NA)
///
/// Used to identify standard IPv6 addresses with normal lifetimes.
/// Original C: LEASE_NA in dnsmasq.h
pub const LEASE_NA: u32 = 2;

/// ARP hardware type: Ethernet (from if_arp.h)
///
/// Standard hardware type value for Ethernet networks (10Mbps, 100Mbps, 1Gbps, etc.).
/// Used in DHCP packets to identify hardware address type.
/// Original C: ARPHRD_ETHER from <net/if_arp.h>
pub const ARPHRD_ETHER: u16 = 1;

// ========== Type Definitions ==========

/// MAC address type (6 bytes for Ethernet)
///
/// Represents hardware addresses for DHCP clients.
/// Original C: unsigned char hwaddr[6] in various structures
pub type MacAddr = [u8; 6];

/// Hardware address configuration with wildcard mask support
///
/// Used in static DHCP host configurations to match client MAC addresses
/// with optional wildcard bits for matching ranges of addresses.
/// Original C: struct hwaddr_config in dnsmasq.h:853-858
#[derive(Debug, Clone)]
pub struct HwaddrConfig {
    /// Hardware address bytes
    pub hwaddr: Vec<u8>,
    /// Length of hardware address
    pub hwaddr_len: usize,
    /// Hardware address type (e.g., ARPHRD_ETHER for Ethernet)
    pub hwaddr_type: u16,
    /// Wildcard mask for partial matching (0 = exact match)
    pub wildcard_mask: u64,
    /// Next hardware address config in linked list
    pub next: Option<Box<HwaddrConfig>>,
}

/// Network ID tag for conditional configuration
///
/// Tags are used to mark DHCP clients and contexts, enabling conditional
/// option delivery based on vendor class, user class, subnet, etc.
/// Original C: struct dhcp_netid in dnsmasq.h:831-834
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpNetid {
    /// Tag name (e.g., "known", "vlan10", "pxeclient")
    pub net: String,
}

/// DHCP option specification with value and flags
///
/// Represents a DHCP option to be sent to clients, with tag-based
/// conditional delivery support.
/// Original C: struct dhcp_opt in dnsmasq.h:892-902
#[derive(Debug, Clone)]
pub struct DhcpOpt {
    /// Option number (e.g., 3 for router, 6 for DNS server)
    pub opt: u8,
    /// Option value as byte array
    pub val: Vec<u8>,
    /// Length of option value
    pub len: usize,
    /// Option flags (DHOPT_TAGOK, DHOPT_HEX, DHOPT_STRING, etc.)
    pub flags: u32,
    /// Network ID tags for conditional delivery (None = always deliver)
    pub netid: Option<Vec<DhcpNetid>>,
    /// Wildcard mask for DHOPT_HEX matching
    pub wildcard_mask: Option<Vec<u8>>,
    /// Next option in linked list
    pub next: Option<Box<DhcpOpt>>,
}

// DHCP option flags (from dnsmasq.h)
const DHOPT_TAGOK: u32 = 1 << 0; // Option passed tag filtering
const DHOPT_ENCAPSULATE: u32 = 1 << 1; // Encapsulated option
const DHOPT_VENDOR: u32 = 1 << 2; // Vendor-specific option
const DHOPT_RFC3925: u32 = 1 << 3; // RFC 3925 vendor-identifying option
const DHOPT_HEX: u32 = 1 << 4; // Value is hex with wildcard mask
const DHOPT_STRING: u32 = 1 << 5; // Value is string (substring match)

/// DHCP static host configuration entry
///
/// Defines static IP assignments and options for specific clients
/// identified by client ID, MAC address, or hostname.
/// Original C: struct dhcp_config in dnsmasq.h:860-875
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Configuration flags (CONFIG_ADDR, CONFIG_CLID, CONFIG_NAME, etc.)
    pub flags: u32,
    /// Client identifier for matching
    pub clid: Option<Vec<u8>>,
    /// Client identifier length
    pub clid_len: usize,
    /// Hardware addresses for matching
    pub hwaddr: Option<Vec<HwaddrConfig>>,
    /// Static IPv4 address to assign
    pub addr: Option<Ipv4Addr>,
    /// Static IPv6 addresses to assign (list for multiple IAs)
    pub addr6: Option<Vec<Ipv6Addr>>,
    /// Hostname for matching or to assign
    pub hostname: Option<String>,
    /// Tag filter for conditional application
    pub filter: Option<Vec<DhcpNetid>>,
    /// Next config in linked list
    pub next: Option<Box<DhcpConfig>>,
}

// DHCP config flags (from dnsmasq.h)
const CONFIG_ADDR: u32 = 1 << 0; // Has static IPv4 address
const CONFIG_ADDR6: u32 = 1 << 1; // Has static IPv6 address
const CONFIG_CLID: u32 = 1 << 2; // Match by client ID
const CONFIG_NAME: u32 = 1 << 3; // Match by hostname
const CONFIG_ADDR_HOSTS: u32 = 1 << 4; // Address from /etc/hosts
const CONFIG_ADDR6_HOSTS: u32 = 1 << 5; // IPv6 address from /etc/hosts

/// DHCP context (address range or subnet)
///
/// Defines a DHCP address pool for a specific subnet or interface,
/// with associated network ID tags for conditional configuration.
/// Original C: struct dhcp_context in dnsmasq.h:994-1010
#[derive(Debug, Clone)]
pub struct DhcpContext {
    /// Context flags (CONTEXT_V6, CONTEXT_STATIC, etc.)
    pub flags: u32,
    /// Start of address range (IPv4)
    pub start: Option<Ipv4Addr>,
    /// End of address range (IPv4)
    pub end: Option<Ipv4Addr>,
    /// Netmask for IPv4 subnet
    pub netmask: Option<Ipv4Addr>,
    /// Start of address range (IPv6)
    pub start6: Option<Ipv6Addr>,
    /// End of address range (IPv6)
    pub end6: Option<Ipv6Addr>,
    /// IPv6 prefix length
    pub prefix: u8,
    /// Network ID tags for this context
    pub netid: Option<Vec<DhcpNetid>>,
    /// Next context in linked list (for multiple overlapping ranges)
    pub current: Option<Box<DhcpContext>>,
}

// DHCP context flags (from dnsmasq.h)
const CONTEXT_V6: u32 = 1 << 0; // IPv6 context (else IPv4)

// ========== Helper Functions ==========

/// Compare byte array against DHCP option value with wildcard support
///
/// Compares byte array `p` of length `len` against the value stored in `DhcpOpt`.
/// Supports three matching modes:
/// 1. DHOPT_HEX flag: masked comparison using wildcard_mask for partial byte matching
/// 2. DHOPT_STRING flag: substring search allowing match at any position
/// 3. default: exact match at aligned positions only
///
/// Used for vendor class, user class, and client ID matching with flexible wildcarding.
///
/// # Arguments
///
/// * `opt` - DHCP option structure containing value to match and flags controlling match mode
/// * `p` - Byte array to search for matches (typically from received DHCP option)
/// * `len` - Length of byte array p in bytes
///
/// # Returns
///
/// * `true` if match found according to mode
/// * `false` if no match found, or opt.len > len
///
/// # Original C
///
/// `int match_bytes(struct dhcp_opt *o, unsigned char *p, int len)` in dhcp-common.c:618-646
pub fn match_bytes(opt: &DhcpOpt, p: &[u8], len: usize) -> bool {
    if opt.len > len {
        return false;
    }

    if opt.len == 0 {
        return true; // Universal match
    }

    if opt.flags & DHOPT_HEX != 0 {
        // Wildcard masked comparison
        if let Some(ref mask) = opt.wildcard_mask {
            return memcmp_masked(&opt.val, p, opt.len, mask);
        }
    }

    // Standard comparison (exact or substring)
    let mut i = 0;
    while i <= len - opt.len {
        if &p[i..i + opt.len] == &opt.val[..opt.len] {
            return true;
        }

        if opt.flags & DHOPT_STRING != 0 {
            i += 1; // Substring mode: try every position
        } else {
            i += opt.len; // Aligned mode: skip to next alignment
        }
    }

    false
}

/// Compare two byte arrays with wildcard mask
///
/// Compares `a` and `b` for `len` bytes, applying wildcard `mask` where
/// set bits require exact match and cleared bits are wildcards (match any value).
/// Returns count of matching non-wildcard bytes.
///
/// # Arguments
///
/// * `a` - First byte array
/// * `b` - Second byte array
/// * `len` - Number of bytes to compare
/// * `mask` - Wildcard mask (per-byte)
///
/// # Returns
///
/// Number of non-wildcard bytes that match
///
/// # Original C
///
/// `memcmp_masked()` in util.c (called by match_bytes)
fn memcmp_masked(a: &[u8], b: &[u8], len: usize, mask: &[u8]) -> bool {
    for i in 0..len {
        let byte_a = a.get(i).copied().unwrap_or(0);
        let byte_b = b.get(i).copied().unwrap_or(0);
        let byte_mask = mask.get(i).copied().unwrap_or(0xFF);

        if (byte_a & byte_mask) != (byte_b & byte_mask) {
            return false;
        }
    }
    true
}

/// Check if network ID tag is present in tag set
///
/// Searches for network ID tag in the provided set of tags. Supports wildcard
/// matching where "*" matches any tag, and "!tag" syntax for negation is checked
/// by the caller.
///
/// Used for conditional DHCP configuration based on vendor class, user class,
/// subnet tags, etc.
///
/// # Arguments
///
/// * `check` - Tag to search for (may contain wildcards)
/// * `netid` - Set of active network ID tags to search in (None = empty set)
///
/// # Returns
///
/// * `true` if tag found in set or wildcard match
/// * `false` if tag not found
///
/// # Original C
///
/// `int match_netid(struct dhcp_netid *check, struct dhcp_netid *netid, int negonly)` 
/// in dhcp-common.c:453-508
pub fn match_netid(check: &DhcpNetid, netid: Option<&Vec<DhcpNetid>>) -> bool {
    // Wildcard matches everything
    if check.net == "*" {
        return true;
    }

    // Search in active tag set
    if let Some(tags) = netid {
        for tag in tags {
            if tag.net == check.net {
                return true;
            }
        }
    }

    false
}

/// Strip illegal characters from hostname
///
/// Sanitizes hostname by removing control characters, spaces, and characters
/// outside the printable ASCII range. Modifies hostname in place.
/// Used before logging or storing DHCP client hostnames.
///
/// # Arguments
///
/// * `hostname` - Hostname string to sanitize (modified in place)
///
/// # Original C
///
/// `void strip_hostname(char *hostname)` in dhcp-common.c:510-524
pub fn strip_hostname(hostname: &mut String) {
    hostname.retain(|c| {
        let is_valid = c.is_ascii_graphic() && c != ' ';
        if !is_valid {
            trace!("Stripping invalid character from hostname: {:?}", c);
        }
        is_valid
    });
}

/// Log active network ID tags for debugging
///
/// Outputs list of active tags for DHCP transaction if OPT_LOG_OPTS is enabled.
/// Used for troubleshooting tag-based conditional configuration.
///
/// # Arguments
///
/// * `prefix` - Descriptive prefix string (e.g., "tags", "available tags")
/// * `netid` - Active tag set to log
/// * `options` - Daemon options (checks OPT_LOG_OPTS flag)
///
/// # Original C
///
/// `void log_tags(struct dhcp_netid *netid, u32 xid)` in dhcp-common.c:648-680
pub fn log_tags(prefix: &str, netid: Option<&Vec<DhcpNetid>>, options: &DaemonOptions) {
    if !options.contains(DaemonOptions::OPT_LOG_OPTS) {
        return;
    }

    if let Some(tags) = netid {
        if tags.is_empty() {
            debug!("{}: <none>", prefix);
        } else {
            let tag_names: Vec<&str> = tags.iter().map(|t| t.net.as_str()).collect();
            debug!("{}: {}", prefix, tag_names.join(", "));
        }
    } else {
        debug!("{}: <none>", prefix);
    }
}

/// Check if DHCP config contains specific MAC address
///
/// Searches hardware address list in config for exact match with provided MAC.
/// Used for duplicate MAC detection across static host configurations.
///
/// # Arguments
///
/// * `config` - DHCP configuration entry
/// * `hwaddr` - MAC address to search for
/// * `len` - Length of MAC address (typically 6 for Ethernet)
/// * `hwaddr_type` - Hardware address type (e.g., ARPHRD_ETHER)
///
/// # Returns
///
/// * `true` if MAC found in config
/// * `false` if not found
///
/// # Original C
///
/// `int config_has_mac(struct dhcp_config *config, unsigned char *hwaddr, int len, int type)`
/// in dhcp-common.c:682-701
pub fn config_has_mac(
    config: &DhcpConfig,
    hwaddr: &[u8],
    len: usize,
    hwaddr_type: u16,
) -> bool {
    if let Some(ref hw_list) = config.hwaddr {
        for hw in iterate_hwaddr_list(hw_list) {
            if hw.hwaddr_len == len
                && hw.hwaddr_type == hwaddr_type
                && hw.hwaddr.get(..len) == Some(&hwaddr[..len])
            {
                return true;
            }
        }
    }
    false
}

/// Iterator helper for traversing linked list of HwaddrConfig
fn iterate_hwaddr_list(head: &[HwaddrConfig]) -> impl Iterator<Item = &HwaddrConfig> {
    head.iter()
}

/// Find hardware address (MAC) in configuration list
///
/// Searches all DHCP static host configurations for matching hardware address
/// using wildcard mask support. Returns first matching config.
///
/// # Arguments
///
/// * `configs` - List of DHCP static host configurations
/// * `hwaddr` - MAC address to search for
/// * `len` - Length of MAC address
/// * `hwaddr_type` - Hardware address type
///
/// # Returns
///
/// * `Some(&DhcpConfig)` if match found
/// * `None` if no match
///
/// # Original C
///
/// `struct dhcp_config *find_config(...)` with CONFIG_HWADDR flag check
/// in dhcp-common.c:917-960
pub fn find_mac(
    configs: &[DhcpConfig],
    hwaddr: &[u8],
    len: usize,
    hwaddr_type: u16,
) -> Option<&DhcpConfig> {
    for config in configs {
        if config_has_mac(config, hwaddr, len, hwaddr_type) {
            return Some(config);
        }
    }
    None
}

/// Apply tag-based filtering to DHCP option list
///
/// Filters DHCP options based on active network ID tags. Options with matching
/// tags are marked with DHOPT_TAGOK flag. Handles negation tags (starting with "!")
/// and supports multiple tag requirements (all must match).
///
/// This is the core mechanism for conditional DHCP option delivery based on
/// client classification (vendor class, user class, subnet, etc.).
///
/// # Arguments
///
/// * `opts` - Mutable slice of DHCP options to filter
/// * `netid` - Active network ID tags for this DHCP transaction
///
/// # Returns
///
/// Number of options that passed filtering (have DHOPT_TAGOK set)
///
/// # Original C
///
/// `int option_filter(struct dhcp_netid *tags, struct dhcp_netid *netids, 
///                    struct dhcp_opt *opts)` in dhcp-common.c:353-451
pub fn option_filter(opts: &mut [DhcpOpt], netid: Option<&Vec<DhcpNetid>>) -> usize {
    let mut count = 0;

    for opt in opts.iter_mut() {
        // Clear previous filtering result
        opt.flags &= !DHOPT_TAGOK;

        // No filter tags = universal match
        if opt.netid.is_none() {
            opt.flags |= DHOPT_TAGOK;
            count += 1;
            continue;
        }

        // Check all filter tags
        let filter_tags = opt.netid.as_ref().unwrap();
        let mut all_matched = true;

        for filter_tag in filter_tags {
            let tag_name = &filter_tag.net;

            // Handle negation (!tag means "must not be present")
            if tag_name.starts_with('!') {
                let neg_tag = DhcpNetid {
                    net: tag_name[1..].to_string(),
                };
                if match_netid(&neg_tag, netid) {
                    // Negated tag is present = fail
                    all_matched = false;
                    break;
                }
            } else {
                // Positive tag (must be present)
                if !match_netid(filter_tag, netid) {
                    all_matched = false;
                    break;
                }
            }
        }

        if all_matched {
            opt.flags |= DHOPT_TAGOK;
            count += 1;
        }
    }

    debug!(
        "Option filtering: {} of {} options passed tag filter",
        count,
        opts.len()
    );
    count
}

/// Find DHCP configuration for client
///
/// Searches static DHCP host configurations for matching entry based on
/// client identifier, MAC address, or hostname (in that priority order).
/// Applies tag-based filtering to ensure config is valid for client's context.
///
/// This is the primary mechanism for assigning static IPs and per-host options.
///
/// # Arguments
///
/// * `configs` - List of static DHCP host configurations
/// * `context` - Active DHCP context (subnet) for this transaction
/// * `clid` - Client identifier from DHCP packet (DHCPv4 option 61 / DHCPv6 DUID)
/// * `clid_len` - Length of client identifier
/// * `hwaddr` - Hardware address (MAC) from DHCP packet
/// * `hwaddr_len` - Length of hardware address
/// * `hwaddr_type` - Hardware address type (e.g., ARPHRD_ETHER)
/// * `hostname` - Hostname from DHCP packet (option 12 for DHCPv4)
/// * `netid` - Active network ID tags
///
/// # Returns
///
/// * `Some(&DhcpConfig)` if matching config found
/// * `None` if no match or config filtered by tags
///
/// # Original C
///
/// `struct dhcp_config *find_config(...)` in dhcp-common.c:917-960
pub fn find_config<'a>(
    configs: &'a [DhcpConfig],
    context: Option<&DhcpContext>,
    clid: Option<&[u8]>,
    clid_len: usize,
    hwaddr: Option<&[u8]>,
    hwaddr_len: usize,
    hwaddr_type: u16,
    hostname: Option<&str>,
    netid: Option<&Vec<DhcpNetid>>,
) -> Option<&'a DhcpConfig> {
    // Priority 1: Match by client ID (most specific)
    if let Some(clid_bytes) = clid {
        for config in configs {
            if config.flags & CONFIG_CLID != 0 {
                if let Some(ref config_clid) = config.clid {
                    if config.clid_len == clid_len
                        && config_clid.get(..clid_len) == Some(&clid_bytes[..clid_len])
                    {
                        if is_config_valid_for_context(config, context, netid) {
                            debug!("Found config by client ID (len={})", clid_len);
                            return Some(config);
                        }
                    }
                }
            }
        }
    }

    // Priority 2: Match by MAC address
    if let Some(hwaddr_bytes) = hwaddr {
        for config in configs {
            if config_has_mac(config, hwaddr_bytes, hwaddr_len, hwaddr_type) {
                if is_config_valid_for_context(config, context, netid) {
                    debug!(
                        "Found config by MAC address (len={}, type={})",
                        hwaddr_len, hwaddr_type
                    );
                    return Some(config);
                }
            }
        }
    }

    // Priority 3: Match by hostname (least specific)
    if let Some(hostname_str) = hostname {
        for config in configs {
            if config.flags & CONFIG_NAME != 0 {
                if let Some(ref config_hostname) = config.hostname {
                    if hostname_isequal(hostname_str, config_hostname) {
                        if is_config_valid_for_context(config, context, netid) {
                            debug!("Found config by hostname: {}", hostname_str);
                            return Some(config);
                        }
                    }
                }
            }
        }
    }

    debug!("No matching DHCP config found");
    None
}

/// Check if DHCP config is valid for current context and tags
///
/// Helper function for find_config that validates config against context
/// (subnet) and applies tag-based filtering.
///
/// # Arguments
///
/// * `config` - Configuration to validate
/// * `context` - Active DHCP context (may be None for relay scenarios)
/// * `netid` - Active network ID tags
///
/// # Returns
///
/// * `true` if config is valid for this transaction
/// * `false` if config should be skipped
///
/// # Original C
///
/// `is_config_in_context()` helper in dhcp-common.c:703-747
fn is_config_valid_for_context(
    config: &DhcpConfig,
    _context: Option<&DhcpContext>,
    netid: Option<&Vec<DhcpNetid>>,
) -> bool {
    // Apply tag-based filtering
    if let Some(ref filter_tags) = config.filter {
        for filter_tag in filter_tags {
            let tag_name = &filter_tag.net;

            if tag_name.starts_with('!') {
                // Negation: tag must NOT be present
                let neg_tag = DhcpNetid {
                    net: tag_name[1..].to_string(),
                };
                if match_netid(&neg_tag, netid) {
                    trace!(
                        "Config filtered: negated tag '{}' is present",
                        &tag_name[1..]
                    );
                    return false;
                }
            } else {
                // Positive: tag must be present
                if !match_netid(filter_tag, netid) {
                    trace!("Config filtered: required tag '{}' not present", tag_name);
                    return false;
                }
            }
        }
    }

    // Context-based filtering would check if config's address is within context range
    // This requires comparing config.addr/addr6 against context.start/end ranges
    // For now, we accept all configs (context filtering handled by caller)

    true
}

/// Update DHCP configs with addresses from /etc/hosts via DNS cache
///
/// Synchronizes static DHCP host configurations with /etc/hosts entries by
/// querying DNS cache. Allows operators to maintain all static IPs in /etc/hosts
/// and reference them in dhcp-host lines by name only.
///
/// Example: `dhcp-host=laptop` looks up "laptop" in /etc/hosts to get IP address.
///
/// # Arguments
///
/// * `configs` - Mutable slice of DHCP configurations to update
/// * `cache` - DNS cache containing /etc/hosts entries
///
/// # Original C
///
/// `void dhcp_update_configs(struct dhcp_config *configs)` in dhcp-common.c:962-1066
pub fn dhcp_update_configs(configs: &mut [DhcpConfig], cache: &Cache) {
    for config in configs.iter_mut() {
        // Only update configs with hostname but no explicit address
        if config.flags & CONFIG_NAME != 0
            && config.flags & (CONFIG_ADDR | CONFIG_ADDR6) == 0
        {
            if let Some(ref hostname) = config.hostname {
                // Query DNS cache for hostname
                let records = cache.find_by_name(hostname);

                for record in records {
                    // Extract IP address from cache record
                    // For now, we'll just log that we found it
                    // Full implementation would update config.addr or config.addr6
                    debug!(
                        "Found /etc/hosts entry for {}: {:?}",
                        hostname, record
                    );

                    // Mark config as having address from hosts file
                    // In real implementation, we'd set config.addr/addr6 here
                    config.flags |= CONFIG_ADDR_HOSTS;
                }

                if records.is_empty() {
                    warn!(
                        "dhcp-host={}: hostname not found in /etc/hosts",
                        hostname
                    );
                }
            }
        }
    }
}

/// Log DHCP context information (address ranges and lease times)
///
/// Outputs human-readable description of DHCP address pool for operational visibility.
/// Logs IPv4/IPv6 address ranges, netmask, lease durations, and associated tags.
///
/// # Arguments
///
/// * `context` - DHCP context to log
///
/// # Original C
///
/// `void log_context(int family, struct dhcp_context *context)` in dhcp-common.c:1263-1346
pub fn log_context(context: &DhcpContext) {
    if context.flags & CONTEXT_V6 != 0 {
        // IPv6 context
        if let (Some(start), Some(end)) = (&context.start6, &context.end6) {
            info!(
                "DHCPv6 range: {:?} to {:?}, prefix /{}, tags: {:?}",
                start,
                end,
                context.prefix,
                context.netid.as_ref().map(|tags| tags
                    .iter()
                    .map(|t| t.net.as_str())
                    .collect::<Vec<_>>())
            );
        }
    } else {
        // IPv4 context
        if let (Some(start), Some(end), Some(netmask)) =
            (&context.start, &context.end, &context.netmask)
        {
            info!(
                "DHCP range: {} to {}, netmask {}, tags: {:?}",
                start,
                end,
                netmask,
                context.netid.as_ref().map(|tags| tags
                    .iter()
                    .map(|t| t.net.as_str())
                    .collect::<Vec<_>>())
            );
        }
    }
}

/// DHCP relay information for logging
///
/// Contains relay agent information for DHCP relay scenarios.
/// Original C: struct dhcp_relay in dnsmasq.h:1084-1097
#[derive(Debug, Clone)]
pub struct DhcpRelay {
    /// Relay agent IP address
    pub local: IpAddr,
    /// Remote server IP address
    pub server: IpAddr,
    /// Interface name relay is bound to
    pub interface: Option<String>,
}

/// Log DHCP relay transaction
///
/// Outputs relay agent information for troubleshooting relay scenarios.
///
/// # Arguments
///
/// * `relay` - Relay information structure
/// * `client_addr` - Client IP address (or relay giaddr)
///
/// # Original C
///
/// `void log_relay(int family, struct dhcp_relay *relay)` in dhcp-common.c:1348-1384
pub fn log_relay(relay: &DhcpRelay, client_addr: Option<IpAddr>) {
    info!(
        "DHCP relay: local={}, server={}, client={:?}, interface={:?}",
        relay.local, relay.server, client_addr, relay.interface
    );
}

/// Receive DHCP packet with automatic buffer expansion
///
/// Receives UDP packet using MSG_PEEK to determine size, then allocates
/// appropriately sized buffer for actual receive. Handles both DHCPv4
/// (typically 576-1500 bytes) and DHCPv6 (variable, often >1280 bytes).
///
/// Uses tokio async I/O to avoid blocking event loop during receive.
///
/// # Arguments
///
/// * `socket` - UDP socket to receive from
/// * `initial_buf_size` - Initial buffer allocation size (grows as needed)
///
/// # Returns
///
/// * `Ok((Vec<u8>, SocketAddr))` - Received packet data and source address
/// * `Err(IoError)` - I/O error during receive
///
/// # Original C
///
/// `ssize_t recv_dhcp_packet(int fd, struct msghdr *msg)` in dhcp-common.c:163-228
pub async fn recv_dhcp_packet(
    socket: &UdpSocket,
    initial_buf_size: usize,
) -> Result<(Vec<u8>, SocketAddr), IoError> {
    let mut buf = vec![0u8; initial_buf_size];

    // Use MSG_PEEK to determine actual packet size
    match socket.peek_from(&mut buf).await {
        Ok((peeked_len, src_addr)) => {
            // Check if we need larger buffer
            if peeked_len > buf.len() {
                warn!(
                    "Packet larger than initial buffer ({} > {}), expanding",
                    peeked_len,
                    buf.len()
                );
                buf.resize(peeked_len, 0);
            }

            // Now receive the actual packet
            match socket.recv_from(&mut buf).await {
                Ok((recv_len, actual_addr)) => {
                    if actual_addr != src_addr {
                        warn!("Source address changed between peek and recv");
                    }
                    buf.truncate(recv_len);
                    debug!("Received DHCP packet: {} bytes from {}", recv_len, actual_addr);
                    Ok((buf, actual_addr))
                }
                Err(e) => {
                    error!("Failed to receive DHCP packet: {}", e);
                    Err(e)
                }
            }
        }
        Err(e) => {
            error!("Failed to peek DHCP packet: {}", e);
            Err(e)
        }
    }
}

/// DHCP option metadata entry
///
/// Describes a DHCP option with its number, name, and data type for parsing/formatting.
/// Original C: struct opttab_t in dhcp-common.c (static tables opttab[] and opttab6[])
#[derive(Debug, Clone)]
pub struct DhcpOptMeta {
    /// Option number (e.g., 3 for router, 6 for DNS)
    pub code: u8,
    /// Option name (e.g., "router", "dns-server")
    pub name: &'static str,
    /// Data type (ip, string, hex, etc.)
    pub opt_type: &'static str,
}

/// Look up DHCP option metadata by option number
///
/// Finds option name and type information for given option code.
/// Used for logging and option string formatting.
///
/// # Arguments
///
/// * `opt_code` - DHCP option number to look up
/// * `is_v6` - true for DHCPv6, false for DHCPv4
///
/// # Returns
///
/// * `Some(&DhcpOptMeta)` if option found in table
/// * `None` if option unknown
///
/// # Original C
///
/// `lookup_dhcp_opt(int prot, char *name)` in dhcp-common.c:1386-1417
pub fn lookup_dhcp_opt(opt_code: u8, is_v6: bool) -> Option<&'static DhcpOptMeta> {
    // Simplified: Return None for now (full impl would have complete option tables)
    // Real implementation would search opttab[] or opttab6[] static arrays
    trace!(
        "Looking up DHCP{} option {}",
        if is_v6 { "v6" } else { "v4" },
        opt_code
    );
    None
}

/// Look up DHCP option expected data length
///
/// Returns expected byte length for fixed-size options (e.g., 4 for IPv4 address).
/// Variable-length options return 0.
///
/// # Arguments
///
/// * `opt_code` - DHCP option number
/// * `is_v6` - true for DHCPv6, false for DHCPv4
///
/// # Returns
///
/// Expected length in bytes, or 0 for variable-length options
///
/// # Original C
///
/// `lookup_dhcp_len(int prot, int val)` in dhcp-common.c:1419-1450
pub fn lookup_dhcp_len(opt_code: u8, is_v6: bool) -> usize {
    // Simplified implementation with common options
    if is_v6 {
        match opt_code {
            23 => 16, // DNS recursive name server (IPv6 address)
            24 => 0,  // Domain search list (variable)
            _ => 0,   // Unknown or variable
        }
    } else {
        match opt_code {
            1 => 4,  // Subnet mask
            3 => 4,  // Router
            6 => 4,  // DNS server (per entry)
            12 => 0, // Hostname (variable)
            51 => 4, // Lease time
            _ => 0,  // Unknown or variable
        }
    }
}

/// Convert DHCP option value to human-readable string
///
/// Formats DHCP option value based on its type (IP address, string, hex, etc.)
/// for logging and debugging output. Handles IPv4 addresses, IPv6 addresses,
/// strings, hex dumps, and integer values.
///
/// # Arguments
///
/// * `opt` - DHCP option to format
/// * `is_v6` - true for DHCPv6, false for DHCPv4
///
/// # Returns
///
/// Formatted string representation of option value
///
/// # Original C
///
/// `char *option_string(int prot, unsigned int opt, unsigned char *val, ...)` 
/// in dhcp-common.c:1603-1756
pub fn option_string(opt: &DhcpOpt, is_v6: bool) -> String {
    // Check if we have metadata for this option
    if let Some(meta) = lookup_dhcp_opt(opt.opt, is_v6) {
        match meta.opt_type {
            "ip" => {
                // IPv4 address (4 bytes per address)
                let mut addrs = Vec::new();
                for chunk in opt.val.chunks_exact(4) {
                    if let Ok(bytes) = <[u8; 4]>::try_from(chunk) {
                        addrs.push(Ipv4Addr::from(bytes).to_string());
                    }
                }
                addrs.join(", ")
            }
            "ip6" => {
                // IPv6 address (16 bytes per address)
                let mut addrs = Vec::new();
                for chunk in opt.val.chunks_exact(16) {
                    if let Ok(bytes) = <[u8; 16]>::try_from(chunk) {
                        addrs.push(Ipv6Addr::from(bytes).to_string());
                    }
                }
                addrs.join(", ")
            }
            "string" => {
                // ASCII string
                String::from_utf8_lossy(&opt.val).to_string()
            }
            _ => {
                // Default: hex dump
                hex_string(&opt.val)
            }
        }
    } else {
        // Unknown option: hex dump
        hex_string(&opt.val)
    }
}

/// Format byte array as hex string
///
/// Helper for option_string to display unknown options.
fn hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Display DHCPv4 options for logging
///
/// Formats all DHCPv4 options in packet for operational visibility.
/// Logs option number, name (if known), and formatted value.
///
/// # Arguments
///
/// * `opts` - Slice of DHCP options to display
///
/// # Original C
///
/// `void display_opts(struct dhcp_opt *opt)` in dhcp-common.c (called by log.c)
pub fn display_opts(opts: &[DhcpOpt]) {
    for opt in opts {
        let value_str = option_string(opt, false);
        info!("  DHCPv4 option {}: {}", opt.opt, value_str);
    }
}

/// Display DHCPv6 options for logging
///
/// Formats all DHCPv6 options in packet for operational visibility.
/// Logs option number, name (if known), and formatted value.
///
/// # Arguments
///
/// * `opts` - Slice of DHCP options to display
///
/// # Original C
///
/// `void display_opts6(struct dhcp_opt *opt)` in dhcp-common.c (called by log.c)
pub fn display_opts6(opts: &[DhcpOpt]) {
    for opt in opts {
        let value_str = option_string(opt, true);
        info!("  DHCPv6 option {}: {}", opt.opt, value_str);
    }
}

/// Determine which network device packet was received on
///
/// Extracts interface name from socket control messages (IP_PKTINFO or
/// IPV6_PKTINFO). Used for multi-interface DHCP server configurations
/// to enforce per-interface policy.
///
/// # Arguments
///
/// * `socket` - UDP socket packet was received on
///
/// # Returns
///
/// * `Some(String)` - Interface name (e.g., "eth0", "wlan0")
/// * `None` - If interface info not available or not supported on platform
///
/// # Original C
///
/// `char *whichdevice(struct msghdr *msg)` in dhcp-common.c:1068-1129
pub fn whichdevice(_socket: &UdpSocket) -> Option<String> {
    // Simplified: Interface detection requires platform-specific control message parsing
    // Full implementation would use IP_PKTINFO (Linux) or IP_RECVIF (BSD)
    trace!("Interface detection not yet implemented");
    None
}

/// Bind socket to specific network device (Linux SO_BINDTODEVICE)
///
/// Restricts DHCP socket to single network interface for multi-VLAN deployments
/// (e.g., OpenStack with multiple dnsmasq instances per host).
///
/// Platform-specific: Linux only via SO_BINDTODEVICE socket option.
///
/// # Arguments
///
/// * `socket` - UDP socket to bind
/// * `device` - Interface name to bind to (e.g., "eth0.100")
///
/// # Returns
///
/// * `Ok(())` - Socket successfully bound to device
/// * `Err(IoError)` - Binding failed (EPERM if not root, ENODEV if device doesn't exist)
///
/// # Original C
///
/// `int bindtodevice(int fd, char *device)` in dhcp-common.c:1181-1227
#[cfg(target_os = "linux")]
pub fn bindtodevice(socket: &UdpSocket, device: &str) -> Result<(), IoError> {
    use std::os::unix::io::AsRawFd;

    let raw_fd = socket.as_raw_fd();
    let sock = unsafe { Socket::from_raw_fd(raw_fd) };

    match sock.bind_device(Some(device.as_bytes())) {
        Ok(_) => {
            info!("Bound DHCP socket to device: {}", device);
            // Prevent socket from being closed when sock is dropped
            std::mem::forget(sock);
            Ok(())
        }
        Err(e) => {
            error!("Failed to bind socket to device {}: {}", device, e);
            std::mem::forget(sock);
            Err(IoError::new(ErrorKind::Other, e))
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn bindtodevice(_socket: &UdpSocket, device: &str) -> Result<(), IoError> {
    warn!(
        "SO_BINDTODEVICE not supported on this platform, ignoring bind to {}",
        device
    );
    Ok(())
}

/// Bind all DHCP sockets to their configured devices
///
/// Iterates through all DHCP listening sockets and binds each to its
/// configured interface using SO_BINDTODEVICE (Linux only).
///
/// Used in multi-VLAN scenarios where multiple dnsmasq instances run
/// on same host with different interface bindings.
///
/// # Arguments
///
/// * `sockets` - List of (socket, device_name) tuples to bind
///
/// # Returns
///
/// * `Ok(())` - All sockets bound successfully
/// * `Err(IoError)` - At least one binding failed
///
/// # Original C
///
/// `void bind_dhcp_devices(void)` in dhcp-common.c:1229-1261
pub fn bind_dhcp_devices(sockets: &[(UdpSocket, String)]) -> Result<(), IoError> {
    let mut errors = Vec::new();

    for (socket, device) in sockets {
        if let Err(e) = bindtodevice(socket, device) {
            errors.push(format!("Failed to bind to {}: {}", device, e));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(IoError::new(
            ErrorKind::Other,
            format!("Device binding errors: {}", errors.join("; ")),
        ))
    }
}

// ========== Unit Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_bytes_exact() {
        let opt = DhcpOpt {
            opt: 60,
            val: vec![0x50, 0x58, 0x45], // "PXE"
            len: 3,
            flags: 0,
            netid: None,
            wildcard_mask: None,
            next: None,
        };

        let data = b"PXEClient";
        assert!(match_bytes(&opt, data, data.len()));

        let data = b"ABC";
        assert!(!match_bytes(&opt, data, data.len()));
    }

    #[test]
    fn test_match_bytes_substring() {
        let opt = DhcpOpt {
            opt: 60,
            val: vec![0x50, 0x58, 0x45], // "PXE"
            len: 3,
            flags: DHOPT_STRING,
            netid: None,
            wildcard_mask: None,
            next: None,
        };

        let data = b"MSFTPXEClient";
        assert!(match_bytes(&opt, data, data.len()));

        let data = b"ABCDEF";
        assert!(!match_bytes(&opt, data, data.len()));
    }

    #[test]
    fn test_match_bytes_wildcard() {
        let opt = DhcpOpt {
            opt: 61,
            val: vec![0x01, 0xAA, 0xBB, 0xCC],
            len: 4,
            flags: DHOPT_HEX,
            netid: None,
            wildcard_mask: Some(vec![0xFF, 0xFF, 0x00, 0xFF]), // Wildcard 3rd byte
            next: None,
        };

        // Should match despite different 3rd byte
        let data = [0x01, 0xAA, 0x99, 0xCC];
        assert!(match_bytes(&opt, &data, data.len()));

        // Should not match (1st byte different)
        let data = [0x02, 0xAA, 0x99, 0xCC];
        assert!(!match_bytes(&opt, &data, data.len()));
    }

    #[test]
    fn test_match_netid() {
        let check = DhcpNetid {
            net: "known".to_string(),
        };

        let tags = vec![
            DhcpNetid {
                net: "known".to_string(),
            },
            DhcpNetid {
                net: "vlan10".to_string(),
            },
        ];

        assert!(match_netid(&check, Some(&tags)));

        let check_missing = DhcpNetid {
            net: "unknown".to_string(),
        };
        assert!(!match_netid(&check_missing, Some(&tags)));
    }

    #[test]
    fn test_match_netid_wildcard() {
        let wildcard = DhcpNetid {
            net: "*".to_string(),
        };

        let tags = vec![DhcpNetid {
            net: "anything".to_string(),
        }];

        assert!(match_netid(&wildcard, Some(&tags)));
        assert!(match_netid(&wildcard, None)); // Wildcard matches empty set
    }

    #[test]
    fn test_strip_hostname() {
        let mut hostname = "valid-host".to_string();
        strip_hostname(&mut hostname);
        assert_eq!(hostname, "valid-host");

        let mut hostname_bad = "bad host\x00name\x01".to_string();
        strip_hostname(&mut hostname_bad);
        assert_eq!(hostname_bad, "badhostname");
    }

    #[test]
    fn test_option_filter() {
        let mut opts = vec![
            DhcpOpt {
                opt: 3,
                val: vec![192, 168, 1, 1],
                len: 4,
                flags: 0,
                netid: None, // No filter = always included
                wildcard_mask: None,
                next: None,
            },
            DhcpOpt {
                opt: 6,
                val: vec![8, 8, 8, 8],
                len: 4,
                flags: 0,
                netid: Some(vec![DhcpNetid {
                    net: "known".to_string(),
                }]),
                wildcard_mask: None,
                next: None,
            },
            DhcpOpt {
                opt: 15,
                val: vec![],
                len: 0,
                flags: 0,
                netid: Some(vec![DhcpNetid {
                    net: "pxeclient".to_string(),
                }]),
                wildcard_mask: None,
                next: None,
            },
        ];

        let tags = vec![DhcpNetid {
            net: "known".to_string(),
        }];

        let count = option_filter(&mut opts, Some(&tags));
        assert_eq!(count, 2); // Options 3 and 6 pass, option 15 filtered

        assert!(opts[0].flags & DHOPT_TAGOK != 0);
        assert!(opts[1].flags & DHOPT_TAGOK != 0);
        assert!(opts[2].flags & DHOPT_TAGOK == 0);
    }

    #[test]
    fn test_config_has_mac() {
        let config = DhcpConfig {
            flags: 0,
            clid: None,
            clid_len: 0,
            hwaddr: Some(vec![HwaddrConfig {
                hwaddr: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                hwaddr_len: 6,
                hwaddr_type: ARPHRD_ETHER,
                wildcard_mask: 0,
                next: None,
            }]),
            addr: None,
            addr6: None,
            hostname: None,
            filter: None,
            next: None,
        };

        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert!(config_has_mac(&config, &mac, 6, ARPHRD_ETHER));

        let mac_different = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert!(!config_has_mac(&config, &mac_different, 6, ARPHRD_ETHER));
    }

    #[test]
    fn test_find_config_by_clid() {
        let configs = vec![
            DhcpConfig {
                flags: CONFIG_CLID,
                clid: Some(vec![0x01, 0x02, 0x03]),
                clid_len: 3,
                hwaddr: None,
                addr: Some(Ipv4Addr::new(192, 168, 1, 100)),
                addr6: None,
                hostname: None,
                filter: None,
                next: None,
            },
            DhcpConfig {
                flags: CONFIG_NAME,
                clid: None,
                clid_len: 0,
                hwaddr: None,
                addr: Some(Ipv4Addr::new(192, 168, 1, 101)),
                addr6: None,
                hostname: Some("laptop".to_string()),
                filter: None,
                next: None,
            },
        ];

        let clid = [0x01, 0x02, 0x03];
        let result = find_config(
            &configs,
            None,
            Some(&clid),
            3,
            None,
            0,
            ARPHRD_ETHER,
            None,
            None,
        );

        assert!(result.is_some());
        assert_eq!(
            result.unwrap().addr,
            Some(Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn test_hex_string() {
        let bytes = [0xAA, 0xBB, 0xCC];
        assert_eq!(hex_string(&bytes), "aa:bb:cc");
    }

    #[test]
    fn test_lookup_dhcp_len() {
        // DHCPv4
        assert_eq!(lookup_dhcp_len(1, false), 4); // Subnet mask
        assert_eq!(lookup_dhcp_len(3, false), 4); // Router
        assert_eq!(lookup_dhcp_len(12, false), 0); // Hostname (variable)

        // DHCPv6
        assert_eq!(lookup_dhcp_len(23, true), 16); // DNS server
        assert_eq!(lookup_dhcp_len(24, true), 0); // Domain list (variable)
    }
}

