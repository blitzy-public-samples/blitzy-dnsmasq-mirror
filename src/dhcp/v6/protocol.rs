// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv6 Protocol Implementation (RFC 3315)
//!
//! Provides DHCPv6 packet parsing and serialization according to RFC 3315.
//!
//! Replaces C implementation in `src/rfc3315.c`.

use std::fmt;
use std::net::Ipv6Addr;

/// DHCPv6 message types (RFC 3315)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcpv6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForw = 12,
    RelayRepl = 13,
}

impl Dhcpv6MessageType {
    /// Convert u8 to Dhcpv6MessageType
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Solicit),
            2 => Some(Self::Advertise),
            3 => Some(Self::Request),
            4 => Some(Self::Confirm),
            5 => Some(Self::Renew),
            6 => Some(Self::Rebind),
            7 => Some(Self::Reply),
            8 => Some(Self::Release),
            9 => Some(Self::Decline),
            10 => Some(Self::Reconfigure),
            11 => Some(Self::InformationRequest),
            12 => Some(Self::RelayForw),
            13 => Some(Self::RelayRepl),
            _ => None,
        }
    }

    /// Convert Dhcpv6MessageType to u8
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }

    /// Check if this message type requires a response from the server
    pub fn requires_response(&self) -> bool {
        matches!(
            self,
            Self::Solicit
                | Self::Request
                | Self::Confirm
                | Self::Renew
                | Self::Rebind
                | Self::Release
                | Self::Decline
                | Self::InformationRequest
                | Self::RelayForw
        )
    }

    /// Check if this is a relay message type
    pub fn is_relay_message(&self) -> bool {
        matches!(self, Self::RelayForw | Self::RelayRepl)
    }
}

impl fmt::Display for Dhcpv6MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Solicit => "SOLICIT",
            Self::Advertise => "ADVERTISE",
            Self::Request => "REQUEST",
            Self::Confirm => "CONFIRM",
            Self::Renew => "RENEW",
            Self::Rebind => "REBIND",
            Self::Reply => "REPLY",
            Self::Release => "RELEASE",
            Self::Decline => "DECLINE",
            Self::Reconfigure => "RECONFIGURE",
            Self::InformationRequest => "INFORMATION-REQUEST",
            Self::RelayForw => "RELAY-FORW",
            Self::RelayRepl => "RELAY-REPL",
        };
        write!(f, "{}", name)
    }
}

/// DHCPv6 message structure (RFC 3315 Section 6)
#[derive(Debug, Clone)]
pub struct Dhcpv6Message {
    /// Message type
    pub msg_type: u8,

    /// Transaction ID (24 bits)
    pub transaction_id: [u8; 3],

    /// DHCPv6 options (TLV encoded)
    pub options: Vec<u8>,
}

impl Dhcpv6Message {
    /// Create new empty message
    pub fn new(msg_type: u8) -> Self {
        Self {
            msg_type,
            transaction_id: [0; 3],
            options: Vec::new(),
        }
    }

    /// Parse DHCPv6 message from bytes
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("Packet too short".to_string());
        }

        let msg_type = data[0];
        let transaction_id = [data[1], data[2], data[3]];
        let options = if data.len() > 4 {
            data[4..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            msg_type,
            transaction_id,
            options,
        })
    }

    /// Serialize message to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.options.len());
        buf.push(self.msg_type);
        buf.extend_from_slice(&self.transaction_id);
        buf.extend_from_slice(&self.options);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_message() {
        let msg = Dhcpv6Message::new(1); // SOLICIT
        assert_eq!(msg.msg_type, 1);
    }

    #[test]
    fn test_parse_serialize_roundtrip() {
        let mut msg = Dhcpv6Message::new(1);
        msg.transaction_id = [0x12, 0x34, 0x56];
        msg.options = vec![0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB];

        let serialized = msg.serialize();
        let parsed = Dhcpv6Message::parse(&serialized).unwrap();

        assert_eq!(parsed.msg_type, 1);
        assert_eq!(parsed.transaction_id, [0x12, 0x34, 0x56]);
        assert_eq!(parsed.options, vec![0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB]);
    }
}
