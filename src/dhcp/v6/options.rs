// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv6 Options Parsing
//!
//! Provides type-safe parsing of DHCPv6 options according to RFC 3315.
//!
//! DHCPv6 uses TLV (Type-Length-Value) encoding with 16-bit option codes
//! and 16-bit lengths in network byte order.

use std::net::Ipv6Addr;

/// DHCPv6 option codes (RFC 3315 and extensions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Dhcpv6OptionCode {
    ClientId = 1,
    ServerId = 2,
    IaNa = 3,
    IaTa = 4,
    IaAddr = 5,
    OptionRequest = 6,
    Preference = 7,
    ElapsedTime = 8,
    RelayMsg = 9,
    Auth = 11,
    Unicast = 12,
    StatusCode = 13,
    RapidCommit = 14,
    UserClass = 15,
    VendorClass = 16,
    VendorOpts = 17,
    InterfaceId = 18,
    ReconfMsg = 19,
    ReconfAccept = 20,
    DnsServers = 23,
    DomainList = 24,
}

/// DHCPv6 option
#[derive(Debug, Clone)]
pub enum Dhcpv6Option {
    /// Option 1: Client identifier (DUID)
    ClientId(Vec<u8>),
    
    /// Option 2: Server identifier (DUID)
    ServerId(Vec<u8>),
    
    /// Option 3: Identity Association for Non-temporary Addresses
    IaNa {
        iaid: u32,
        t1: u32,
        t2: u32,
        options: Vec<u8>,
    },
    
    /// Option 5: IA Address
    IaAddr {
        addr: Ipv6Addr,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        options: Vec<u8>,
    },
    
    /// Option 6: Option Request
    OptionRequest(Vec<u16>),
    
    /// Option 7: Preference
    Preference(u8),
    
    /// Option 8: Elapsed time (in 1/100th seconds)
    ElapsedTime(u16),
    
    /// Option 13: Status code
    StatusCode {
        code: u16,
        message: String,
    },
    
    /// Option 14: Rapid commit
    RapidCommit,
    
    /// Option 23: DNS recursive name servers
    DnsServers(Vec<Ipv6Addr>),
    
    /// Option 24: Domain search list
    DomainList(Vec<String>),
    
    /// Unknown option
    Unknown { code: u16, data: Vec<u8> },
}

impl Dhcpv6Option {
    /// Parse options from byte slice
    ///
    /// # Arguments
    ///
    /// * `data` - Option data (TLV encoded)
    ///
    /// # Returns
    ///
    /// Vector of parsed options
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut options = Vec::new();
        let mut i = 0;

        while i + 4 <= data.len() {
            let code = u16::from_be_bytes([data[i], data[i + 1]]);
            let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;

            if i + 4 + len > data.len() {
                break;
            }

            let option_data = &data[i + 4..i + 4 + len];
            let option = Self::parse_option(code, option_data);
            options.push(option);

            i += 4 + len;
        }

        options
    }

    /// Parse single option
    fn parse_option(code: u16, data: &[u8]) -> Self {
        match code {
            1 => Self::ClientId(data.to_vec()),
            2 => Self::ServerId(data.to_vec()),
            3 if data.len() >= 12 => {
                let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let t1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let t2 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                let options = if data.len() > 12 {
                    data[12..].to_vec()
                } else {
                    Vec::new()
                };
                Self::IaNa { iaid, t1, t2, options }
            }
            5 if data.len() >= 24 => {
                let addr = Ipv6Addr::from([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                    data[8], data[9], data[10], data[11],
                    data[12], data[13], data[14], data[15],
                ]);
                let preferred_lifetime = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
                let valid_lifetime = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
                let options = if data.len() > 24 {
                    data[24..].to_vec()
                } else {
                    Vec::new()
                };
                Self::IaAddr { addr, preferred_lifetime, valid_lifetime, options }
            }
            7 if data.len() == 1 => Self::Preference(data[0]),
            8 if data.len() == 2 => {
                Self::ElapsedTime(u16::from_be_bytes([data[0], data[1]]))
            }
            14 if data.is_empty() => Self::RapidCommit,
            23 => {
                let mut servers = Vec::new();
                for chunk in data.chunks_exact(16) {
                    servers.push(Ipv6Addr::from([
                        chunk[0], chunk[1], chunk[2], chunk[3],
                        chunk[4], chunk[5], chunk[6], chunk[7],
                        chunk[8], chunk[9], chunk[10], chunk[11],
                        chunk[12], chunk[13], chunk[14], chunk[15],
                    ]));
                }
                Self::DnsServers(servers)
            }
            _ => Self::Unknown {
                code,
                data: data.to_vec(),
            },
        }
    }

    /// Serialize option to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            Self::ClientId(duid) => {
                buf.extend_from_slice(&1u16.to_be_bytes());
                buf.extend_from_slice(&(duid.len() as u16).to_be_bytes());
                buf.extend_from_slice(duid);
            }
            Self::ServerId(duid) => {
                buf.extend_from_slice(&2u16.to_be_bytes());
                buf.extend_from_slice(&(duid.len() as u16).to_be_bytes());
                buf.extend_from_slice(duid);
            }
            Self::Preference(pref) => {
                buf.extend_from_slice(&7u16.to_be_bytes());
                buf.extend_from_slice(&1u16.to_be_bytes());
                buf.push(*pref);
            }
            Self::RapidCommit => {
                buf.extend_from_slice(&14u16.to_be_bytes());
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
            Self::Unknown { code, data } => {
                buf.extend_from_slice(&code.to_be_bytes());
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
            }
            _ => {} // TODO: Implement remaining options
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_id() {
        let data = &[
            0x00, 0x01, // Option code = 1 (ClientId)
            0x00, 0x04, // Length = 4
            0x12, 0x34, 0x56, 0x78, // DUID
        ];
        let options = Dhcpv6Option::parse_all(data);
        
        assert_eq!(options.len(), 1);
        match &options[0] {
            Dhcpv6Option::ClientId(duid) => {
                assert_eq!(duid, &vec![0x12, 0x34, 0x56, 0x78]);
            }
            _ => panic!("Expected ClientId"),
        }
    }

    #[test]
    fn test_serialize_preference() {
        let option = Dhcpv6Option::Preference(255);
        let serialized = option.serialize();
        
        assert_eq!(serialized, vec![
            0x00, 0x07, // Option code = 7
            0x00, 0x01, // Length = 1
            0xFF,       // Preference value
        ]);
    }
}
