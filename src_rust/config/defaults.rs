// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
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

//! Default configuration values
//!
//! Provides default configuration values matching the C implementation from config.h
//! and dnsmasq.h. These defaults represent compile-time constants and safe starting
//! values for all configuration options.

use super::types::Config;

/// Default DNS port (from C: NAMESERVER_PORT in config.h)
pub const DEFAULT_DNS_PORT: u16 = 53;

/// Default DHCP server port (from C: DHCP_SERVER_PORT in config.h)
pub const DEFAULT_DHCP_SERVER_PORT: u16 = 67;

/// Default DHCPv6 server port (from C: DHCPV6_SERVER_PORT in config.h)
pub const DEFAULT_DHCP6_SERVER_PORT: u16 = 547;

/// Default TFTP port (from C: TFTP_PORT in config.h)
pub const DEFAULT_TFTP_PORT: u16 = 69;

/// Default DNS cache size (from C: CACHESIZ in config.h)
pub const DEFAULT_CACHE_SIZE: usize = 150;

/// Default forward table size (from C: FTABSIZ in config.h)
pub const DEFAULT_FTAB_SIZE: usize = 150;

/// Default lease time in seconds (from C: DEFAULT_LEASE_TIME in config.h)
pub const DEFAULT_LEASE_TIME: u32 = 3600; // 1 hour

/// Default EDNS packet max size (from C: EDNS_PKTSZ in config.h)
pub const DEFAULT_EDNS_PACKET_MAX: u16 = 4096;

/// Default configuration file path on Linux
#[cfg(target_os = "linux")]
pub const DEFAULT_CONFIG_FILE: &str = "/etc/dnsmasq.conf";

/// Default configuration file path on macOS
#[cfg(target_os = "macos")]
pub const DEFAULT_CONFIG_FILE: &str = "/usr/local/etc/dnsmasq.conf";

/// Default configuration file path on BSD
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub const DEFAULT_CONFIG_FILE: &str = "/usr/local/etc/dnsmasq.conf";

/// Default lease file path
#[cfg(target_os = "linux")]
pub const DEFAULT_LEASE_FILE: &str = "/var/lib/misc/dnsmasq.leases";

/// Default lease file path on macOS
#[cfg(target_os = "macos")]
pub const DEFAULT_LEASE_FILE: &str = "/var/db/dnsmasq.leases";

/// Default lease file path on BSD
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub const DEFAULT_LEASE_FILE: &str = "/var/db/dnsmasq.leases";

/// Create a default configuration
///
/// Returns a Config struct populated with default values matching the C implementation.
/// This configuration is suitable for basic DNS forwarding with minimal DHCP support.
///
/// # Default Configuration
///
/// - DNS port: 53
/// - Cache size: 150 entries
/// - DHCP disabled by default
/// - TFTP disabled by default
/// - No DNSSEC validation
/// - Listen on all interfaces
/// - Run as daemon
///
/// # Example
///
/// ```
/// use dnsmasq::config::default_config;
///
/// let config = default_config();
/// assert_eq!(config.dns.port, 53);
/// assert_eq!(config.dns.cache_size, 150);
/// ```
pub fn default_config() -> Config {
    // Use the Default trait implementation from types.rs
    // All subsystem defaults (DnsConfig, DhcpConfig, etc.) are defined in types.rs
    // with values derived from C's config.h constants
    Config::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DaemonOptions;

    #[test]
    fn test_default_config_has_correct_ports() {
        let config = default_config();
        assert_eq!(config.dns.port, 53);
        assert_eq!(config.dhcp.server_port, 67);
        assert_eq!(config.dhcp.client_port, 68);
        // Note: TFTP doesn't have a single port field, uses port_range
    }

    #[test]
    fn test_default_config_has_correct_cache_size() {
        let config = default_config();
        assert_eq!(config.dns.cache_size, 150);
        assert_eq!(config.dns.ftab_size, 150);
    }

    #[test]
    fn test_default_config_dhcp_disabled() {
        let config = default_config();
        assert!(config.dhcp.dhcp_ranges.is_empty());
        assert!(config.dhcp.dhcp6_ranges.is_empty());
    }

    #[test]
    fn test_default_config_tftp_disabled() {
        let config = default_config();
        // TFTP is disabled when tftp_root is None
        assert!(config.tftp.tftp_root.is_none());
    }

    #[test]
    fn test_default_config_no_dnssec() {
        let config = default_config();
        assert!(!config.options.contains(DaemonOptions::OPT_DNSSEC_VALID));
    }
}
