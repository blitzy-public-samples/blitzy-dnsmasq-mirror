// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv4 Options Parsing
//!
//! Provides type-safe parsing of DHCPv4 options according to RFC 2132.
//!
//! Replaces parts of C implementation in `src/rfc2131.c` and `src/dhcp.c`.

use std::net::Ipv4Addr;

/// DHCPv4 option codes (RFC 2132)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcpv4OptionCode {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DnsServer = 6,
    HostName = 12,
    DomainName = 15,
    BroadcastAddress = 28,
    RequestedIpAddress = 50,
    IpAddressLeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    MaxDhcpMessageSize = 57,
    RenewalTime = 58,
    RebindingTime = 59,
    ClientIdentifier = 61,
    End = 255,
}

/// DHCPv4 option
#[derive(Debug, Clone)]
pub enum Dhcpv4Option {
    /// Option 0: Pad (no data)
    Pad,
    
    /// Option 1: Subnet mask
    SubnetMask(Ipv4Addr),
    
    /// Option 3: Router (default gateway)
    Router(Vec<Ipv4Addr>),
    
    /// Option 6: DNS servers
    DnsServer(Vec<Ipv4Addr>),
    
    /// Option 12: Host name
    HostName(String),
    
    /// Option 15: Domain name
    DomainName(String),
    
    /// Option 28: Broadcast address
    BroadcastAddress(Ipv4Addr),
    
    /// Option 50: Requested IP address
    RequestedIpAddress(Ipv4Addr),
    
    /// Option 51: IP address lease time (seconds)
    IpAddressLeaseTime(u32),
    
    /// Option 53: DHCP message type
    MessageType(u8),
    
    /// Option 54: Server identifier
    ServerIdentifier(Ipv4Addr),
    
    /// Option 55: Parameter request list
    ParameterRequestList(Vec<u8>),
    
    /// Option 56: Message
    Message(String),
    
    /// Option 57: Maximum DHCP message size
    MaxDhcpMessageSize(u16),
    
    /// Option 58: Renewal (T1) time
    RenewalTime(u32),
    
    /// Option 59: Rebinding (T2) time
    RebindingTime(u32),
    
    /// Option 61: Client identifier
    ClientIdentifier(Vec<u8>),
    
    /// Option 255: End marker
    End,
    
    /// Unknown option
    Unknown { code: u8, data: Vec<u8> },
}

impl Dhcpv4Option {
    /// Parse options from byte slice
    ///
    /// # Arguments
    ///
    /// * `data` - Option data (starting after magic cookie)
    ///
    /// # Returns
    ///
    /// Vector of parsed options
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut options = Vec::new();
        let mut i = 0;

        // Skip magic cookie if present
        if data.len() >= 4 && &data[0..4] == &[99, 130, 83, 99] {
            i = 4;
        }

        while i < data.len() {
            let code = data[i];
            
            // Handle pad and end options (no length field)
            if code == 0 {
                options.push(Self::Pad);
                i += 1;
                continue;
            }
            
            if code == 255 {
                options.push(Self::End);
                break;
            }

            // All other options have length field
            if i + 1 >= data.len() {
                break;
            }

            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                break;
            }

            let option_data = &data[i + 2..i + 2 + len];
            let option = Self::parse_option(code, option_data);
            options.push(option);

            i += 2 + len;
        }

        options
    }

    /// Parse single option
    fn parse_option(code: u8, data: &[u8]) -> Self {
        match code {
            1 if data.len() == 4 => {
                Self::SubnetMask(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            3 => {
                let mut routers = Vec::new();
                for chunk in data.chunks_exact(4) {
                    routers.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
                Self::Router(routers)
            }
            6 => {
                let mut servers = Vec::new();
                for chunk in data.chunks_exact(4) {
                    servers.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
                Self::DnsServer(servers)
            }
            12 => Self::HostName(String::from_utf8_lossy(data).to_string()),
            15 => Self::DomainName(String::from_utf8_lossy(data).to_string()),
            28 if data.len() == 4 => {
                Self::BroadcastAddress(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            50 if data.len() == 4 => {
                Self::RequestedIpAddress(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            51 if data.len() == 4 => {
                Self::IpAddressLeaseTime(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            53 if data.len() == 1 => Self::MessageType(data[0]),
            54 if data.len() == 4 => {
                Self::ServerIdentifier(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            55 => Self::ParameterRequestList(data.to_vec()),
            56 => Self::Message(String::from_utf8_lossy(data).to_string()),
            57 if data.len() == 2 => {
                Self::MaxDhcpMessageSize(u16::from_be_bytes([data[0], data[1]]))
            }
            58 if data.len() == 4 => {
                Self::RenewalTime(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            59 if data.len() == 4 => {
                Self::RebindingTime(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            61 => Self::ClientIdentifier(data.to_vec()),
            _ => Self::Unknown {
                code,
                data: data.to_vec(),
            },
        }
    }

    /// Serialize option to bytes
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Pad => vec![0],
            Self::End => vec![255],
            Self::SubnetMask(addr) => {
                let mut buf = vec![1, 4];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Self::MessageType(msg_type) => vec![53, 1, *msg_type],
            Self::ServerIdentifier(addr) => {
                let mut buf = vec![54, 4];
                buf.extend_from_slice(&addr.octets());
                buf
            }
            Self::IpAddressLeaseTime(seconds) => {
                let mut buf = vec![51, 4];
                buf.extend_from_slice(&seconds.to_be_bytes());
                buf
            }
            Self::RenewalTime(seconds) => {
                let mut buf = vec![58, 4];
                buf.extend_from_slice(&seconds.to_be_bytes());
                buf
            }
            Self::RebindingTime(seconds) => {
                let mut buf = vec![59, 4];
                buf.extend_from_slice(&seconds.to_be_bytes());
                buf
            }
            Self::Unknown { code, data } => {
                let mut buf = vec![*code, data.len() as u8];
                buf.extend_from_slice(data);
                buf
            }
            _ => vec![], // TODO: Implement remaining options
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_message_type() {
        let data = &[53, 1, 1]; // Message Type = DISCOVER
        let options = Dhcpv4Option::parse_all(data);
        
        assert_eq!(options.len(), 1);
        match &options[0] {
            Dhcpv4Option::MessageType(1) => {}
            _ => panic!("Expected MessageType"),
        }
    }

    #[test]
    fn test_serialize_message_type() {
        let option = Dhcpv4Option::MessageType(2); // OFFER
        let serialized = option.serialize();
        assert_eq!(serialized, vec![53, 1, 2]);
    }

    #[test]
    fn test_parse_with_magic_cookie() {
        let data = &[
            99, 130, 83, 99, // Magic cookie
            53, 1, 1,        // Message Type = DISCOVER
            255,             // End
        ];
        let options = Dhcpv4Option::parse_all(data);
        
        assert!(options.len() >= 1);
        match &options[0] {
            Dhcpv4Option::MessageType(1) => {}
            _ => panic!("Expected MessageType"),
        }
    }
}
