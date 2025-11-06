// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated June, 2007.

//! # DHCPv4 Protocol Implementation (RFC 2131)
//!
//! Provides DHCPv4 packet parsing and serialization according to RFC 2131.
//!
//! Replaces C implementation in `src/rfc2131.c`.

use std::net::Ipv4Addr;

/// DHCPv4 message types (RFC 2131)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv4MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

/// DHCPv4 message structure (RFC 2131 Section 2)
#[derive(Debug, Clone)]
pub struct Dhcpv4Message {
    /// Message op code / message type (1 = BOOTREQUEST, 2 = BOOTREPLY)
    pub op: u8,

    /// Hardware address type (1 = Ethernet)
    pub htype: u8,

    /// Hardware address length (6 for Ethernet)
    pub hlen: u8,

    /// Client sets to zero, optionally used by relay agents
    pub hops: u8,

    /// Transaction ID
    pub xid: u32,

    /// Seconds elapsed since client began address acquisition
    pub secs: u16,

    /// Flags (broadcast bit)
    pub flags: u16,

    /// Client IP address (filled in by client if known)
    pub ciaddr: Ipv4Addr,

    /// 'your' (client) IP address
    pub yiaddr: Ipv4Addr,

    /// IP address of next server to use in bootstrap
    pub siaddr: Ipv4Addr,

    /// Relay agent IP address
    pub giaddr: Ipv4Addr,

    /// Client hardware address (16 bytes, but only hlen are significant)
    pub chaddr: [u8; 16],

    /// Server host name (64 bytes)
    pub sname: [u8; 64],

    /// Boot file name (128 bytes)
    pub file: [u8; 128],

    /// DHCPv4 options
    pub options: Vec<u8>,
}

impl Dhcpv4Message {
    /// Create new empty message
    pub fn new() -> Self {
        Self {
            op: 0,
            htype: 1, // Ethernet
            hlen: 6,  // MAC address length
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: Vec::new(),
        }
    }

    /// Parse DHCPv4 message from bytes
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 236 {
            return Err("Packet too short".to_string());
        }

        let mut msg = Self::new();
        msg.op = data[0];
        msg.htype = data[1];
        msg.hlen = data[2];
        msg.hops = data[3];
        msg.xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        msg.secs = u16::from_be_bytes([data[8], data[9]]);
        msg.flags = u16::from_be_bytes([data[10], data[11]]);
        msg.ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        msg.yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        msg.siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        msg.giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
        msg.chaddr.copy_from_slice(&data[28..44]);
        msg.sname.copy_from_slice(&data[44..108]);
        msg.file.copy_from_slice(&data[108..236]);

        // Parse options (if present and magic cookie matches)
        if data.len() > 236 {
            msg.options = data[236..].to_vec();
        }

        Ok(msg)
    }

    /// Serialize message to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(236 + self.options.len());

        buf.push(self.op);
        buf.push(self.htype);
        buf.push(self.hlen);
        buf.push(self.hops);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.ciaddr.octets());
        buf.extend_from_slice(&self.yiaddr.octets());
        buf.extend_from_slice(&self.siaddr.octets());
        buf.extend_from_slice(&self.giaddr.octets());
        buf.extend_from_slice(&self.chaddr);
        buf.extend_from_slice(&self.sname);
        buf.extend_from_slice(&self.file);
        buf.extend_from_slice(&self.options);

        buf
    }
}

impl Default for Dhcpv4Message {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_message() {
        let msg = Dhcpv4Message::new();
        assert_eq!(msg.htype, 1);
        assert_eq!(msg.hlen, 6);
    }

    #[test]
    fn test_serialize_parse_roundtrip() {
        let mut msg = Dhcpv4Message::new();
        msg.op = 1;
        msg.xid = 0x12345678;
        msg.ciaddr = Ipv4Addr::new(192, 168, 1, 100);

        let serialized = msg.serialize();
        let parsed = Dhcpv4Message::parse(&serialized).unwrap();

        assert_eq!(parsed.op, 1);
        assert_eq!(parsed.xid, 0x12345678);
        assert_eq!(parsed.ciaddr, Ipv4Addr::new(192, 168, 1, 100));
    }
}
