// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// EDNS0 (Extension Mechanisms for DNS) support
//
// Translated from: src/edns0.c

//! EDNS0 extension mechanisms for DNS (RFC 6891)
//!
//! Implements RFC 6891 EDNS0 features including larger UDP payloads,
//! extended response codes, and EDNS options like client subnet.

use crate::types::errors::DnsError;

/// EDNS OPT pseudo-record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptRecord {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub flags: u16,
    pub options: Vec<EdnsOption>,
}

impl OptRecord {
    /// Create a new OPT record with default values
    pub fn new() -> Self {
        Self {
            udp_payload_size: 1232, // RFC 6891 recommended minimum for IPv6
            extended_rcode: 0,
            version: 0,
            flags: 0,
            options: Vec::new(),
        }
    }

    /// Set the UDP payload size
    pub fn with_udp_size(mut self, size: u16) -> Self {
        self.udp_payload_size = size;
        self
    }

    /// Add an EDNS option
    pub fn with_option(mut self, option: EdnsOption) -> Self {
        self.options.push(option);
        self
    }

    /// Check if DNSSEC OK (DO) flag is set
    pub fn dnssec_ok(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Set the DNSSEC OK (DO) flag
    pub fn set_dnssec_ok(&mut self, value: bool) {
        if value {
            self.flags |= 0x8000;
        } else {
            self.flags &= !0x8000;
        }
    }
}

impl Default for OptRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// EDNS option types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdnsOption {
    /// Client Subnet (RFC 7871)
    ClientSubnet {
        family: u16,
        source_prefix_length: u8,
        scope_prefix_length: u8,
        address: Vec<u8>,
    },
    /// Cookie (RFC 7873)
    Cookie {
        client_cookie: Vec<u8>,
        server_cookie: Option<Vec<u8>>,
    },
    /// Padding (RFC 7830)
    Padding {
        length: u16,
    },
    /// Chain Query (RFC 7901)
    Chain {
        closest_trust_point: String,
    },
    /// Key Tag (RFC 8145)
    KeyTag {
        tags: Vec<u16>,
    },
    /// Unknown option (preserved for pass-through)
    Unknown {
        code: u16,
        data: Vec<u8>,
    },
}

impl EdnsOption {
    /// Get the option code
    pub fn code(&self) -> u16 {
        match self {
            EdnsOption::ClientSubnet { .. } => 8,
            EdnsOption::Cookie { .. } => 10,
            EdnsOption::Padding { .. } => 12,
            EdnsOption::Chain { .. } => 13,
            EdnsOption::KeyTag { .. } => 14,
            EdnsOption::Unknown { code, .. } => *code,
        }
    }

    /// Get the option data length
    pub fn len(&self) -> usize {
        match self {
            EdnsOption::ClientSubnet { address, .. } => 4 + address.len(),
            EdnsOption::Cookie { client_cookie, server_cookie } => {
                client_cookie.len() + server_cookie.as_ref().map(|c| c.len()).unwrap_or(0)
            }
            EdnsOption::Padding { length } => *length as usize,
            EdnsOption::Chain { closest_trust_point } => closest_trust_point.len(),
            EdnsOption::KeyTag { tags } => tags.len() * 2,
            EdnsOption::Unknown { data, .. } => data.len(),
        }
    }

    /// Check if the option is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opt_record_default() {
        let opt = OptRecord::new();
        assert_eq!(opt.udp_payload_size, 1232);
        assert_eq!(opt.version, 0);
        assert!(!opt.dnssec_ok());
    }

    #[test]
    fn test_opt_record_dnssec_flag() {
        let mut opt = OptRecord::new();
        assert!(!opt.dnssec_ok());
        
        opt.set_dnssec_ok(true);
        assert!(opt.dnssec_ok());
        
        opt.set_dnssec_ok(false);
        assert!(!opt.dnssec_ok());
    }

    #[test]
    fn test_opt_record_builder() {
        let opt = OptRecord::new()
            .with_udp_size(4096)
            .with_option(EdnsOption::Padding { length: 100 });

        assert_eq!(opt.udp_payload_size, 4096);
        assert_eq!(opt.options.len(), 1);
    }

    #[test]
    fn test_edns_option_codes() {
        assert_eq!(EdnsOption::ClientSubnet {
            family: 1,
            source_prefix_length: 24,
            scope_prefix_length: 0,
            address: vec![192, 168, 1],
        }.code(), 8);

        assert_eq!(EdnsOption::Cookie {
            client_cookie: vec![0; 8],
            server_cookie: None,
        }.code(), 10);

        assert_eq!(EdnsOption::Padding { length: 100 }.code(), 12);
    }

    #[test]
    fn test_edns_option_length() {
        let padding = EdnsOption::Padding { length: 100 };
        assert_eq!(padding.len(), 100);

        let cookie = EdnsOption::Cookie {
            client_cookie: vec![0; 8],
            server_cookie: Some(vec![0; 8]),
        };
        assert_eq!(cookie.len(), 16);
    }
}
