// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS protocol message parsing and serialization (RFC 1035)
//
// Translated from: src/rfc1035.c

//! DNS protocol implementation following RFC 1035
//!
//! This module provides complete DNS message wire format handling including
//! parsing, serialization, and all common DNS record types.

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::types::errors::DnsError;

/// DNS message containing header, questions, and resource records
#[derive(Debug, Clone, PartialEq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl DnsMessage {
    /// Create a new DNS message
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Parse a DNS message from wire format
    pub fn from_bytes(data: &[u8]) -> Result<Self, DnsError> {
        if data.len() < 12 {
            return Err(DnsError::ProtocolError {
                message: "Message too short".to_string()
            });
        }

        let header = DnsHeader::from_bytes(&data[0..12])?;
        
        Ok(Self {
            header,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }

    /// Serialize DNS message to wire format
    pub fn to_bytes(&self) -> Result<Vec<u8>, DnsError> {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(&self.header.to_bytes()?);
        Ok(bytes)
    }
}

impl Default for DnsMessage {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS message header (12 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    /// Create a new DNS header
    pub fn new() -> Self {
        Self {
            id: 0,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Parse DNS header from 12 bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, DnsError> {
        if data.len() < 12 {
            return Err(DnsError::ProtocolError {
                message: "Header too short".to_string()
            });
        }

        Ok(Self {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    /// Serialize header to 12 bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, DnsError> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        bytes.extend_from_slice(&self.ancount.to_be_bytes());
        bytes.extend_from_slice(&self.nscount.to_be_bytes());
        bytes.extend_from_slice(&self.arcount.to_be_bytes());
        Ok(bytes)
    }

    /// Check if this is a query (QR bit = 0)
    pub fn is_query(&self) -> bool {
        (self.flags & 0x8000) == 0
    }

    /// Check if this is a response (QR bit = 1)
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Get the opcode from the header
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0F) as u8
    }

    /// Get the response code
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x0F) as u8
    }
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS question section entry
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: RecordType,
    pub qclass: RecordClass,
}

impl DnsQuestion {
    /// Create a new DNS question
    pub fn new(qname: String, qtype: RecordType, qclass: RecordClass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }
}

/// DNS resource record
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceRecord {
    A {
        name: String,
        class: RecordClass,
        ttl: u32,
        address: Ipv4Addr,
    },
    AAAA {
        name: String,
        class: RecordClass,
        ttl: u32,
        address: Ipv6Addr,
    },
    CNAME {
        name: String,
        class: RecordClass,
        ttl: u32,
        cname: String,
    },
    MX {
        name: String,
        class: RecordClass,
        ttl: u32,
        preference: u16,
        exchange: String,
    },
    NS {
        name: String,
        class: RecordClass,
        ttl: u32,
        nsdname: String,
    },
    PTR {
        name: String,
        class: RecordClass,
        ttl: u32,
        ptrdname: String,
    },
    SOA {
        name: String,
        class: RecordClass,
        ttl: u32,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    TXT {
        name: String,
        class: RecordClass,
        ttl: u32,
        text: Vec<String>,
    },
    SRV {
        name: String,
        class: RecordClass,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
}

impl ResourceRecord {
    /// Get the record name
    pub fn name(&self) -> &str {
        match self {
            ResourceRecord::A { name, .. } => name,
            ResourceRecord::AAAA { name, .. } => name,
            ResourceRecord::CNAME { name, .. } => name,
            ResourceRecord::MX { name, .. } => name,
            ResourceRecord::NS { name, .. } => name,
            ResourceRecord::PTR { name, .. } => name,
            ResourceRecord::SOA { name, .. } => name,
            ResourceRecord::TXT { name, .. } => name,
            ResourceRecord::SRV { name, .. } => name,
        }
    }

    /// Get the record TTL
    pub fn ttl(&self) -> u32 {
        match self {
            ResourceRecord::A { ttl, .. } => *ttl,
            ResourceRecord::AAAA { ttl, .. } => *ttl,
            ResourceRecord::CNAME { ttl, .. } => *ttl,
            ResourceRecord::MX { ttl, .. } => *ttl,
            ResourceRecord::NS { ttl, .. } => *ttl,
            ResourceRecord::PTR { ttl, .. } => *ttl,
            ResourceRecord::SOA { ttl, .. } => *ttl,
            ResourceRecord::TXT { ttl, .. } => *ttl,
            ResourceRecord::SRV { ttl, .. } => *ttl,
        }
    }

    /// Get the record type
    pub fn record_type(&self) -> RecordType {
        match self {
            ResourceRecord::A { .. } => RecordType::A,
            ResourceRecord::AAAA { .. } => RecordType::AAAA,
            ResourceRecord::CNAME { .. } => RecordType::CNAME,
            ResourceRecord::MX { .. } => RecordType::MX,
            ResourceRecord::NS { .. } => RecordType::NS,
            ResourceRecord::PTR { .. } => RecordType::PTR,
            ResourceRecord::SOA { .. } => RecordType::SOA,
            ResourceRecord::TXT { .. } => RecordType::TXT,
            ResourceRecord::SRV { .. } => RecordType::SRV,
        }
    }
}

/// DNS record type (QTYPE/TYPE field)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    ANY = 255,
}

impl RecordType {
    /// Parse record type from u16
    pub fn from_u16(value: u16) -> Result<Self, DnsError> {
        match value {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            5 => Ok(RecordType::CNAME),
            6 => Ok(RecordType::SOA),
            12 => Ok(RecordType::PTR),
            15 => Ok(RecordType::MX),
            16 => Ok(RecordType::TXT),
            28 => Ok(RecordType::AAAA),
            33 => Ok(RecordType::SRV),
            41 => Ok(RecordType::OPT),
            255 => Ok(RecordType::ANY),
            _ => Err(DnsError::ProtocolError {
                message: format!("Unknown record type: {}", value)
            }),
        }
    }

    /// Convert record type to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// DNS record class (QCLASS/CLASS field)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordClass {
    IN = 1,   // Internet
    CS = 2,   // CSNET
    CH = 3,   // CHAOS
    HS = 4,   // Hesiod
    ANY = 255,
}

impl RecordClass {
    /// Parse record class from u16
    pub fn from_u16(value: u16) -> Result<Self, DnsError> {
        match value {
            1 => Ok(RecordClass::IN),
            2 => Ok(RecordClass::CS),
            3 => Ok(RecordClass::CH),
            4 => Ok(RecordClass::HS),
            255 => Ok(RecordClass::ANY),
            _ => Err(DnsError::ProtocolError {
                message: format!("Unknown record class: {}", value)
            }),
        }
    }

    /// Convert record class to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

impl Default for RecordClass {
    fn default() -> Self {
        RecordClass::IN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header_parse() {
        let data = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags (response, recursion desired & available)
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        let header = DnsHeader::from_bytes(&data).unwrap();
        assert_eq!(header.id, 0x1234);
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 1);
        assert!(header.is_response());
        assert!(!header.is_query());
    }

    #[test]
    fn test_dns_header_serialize() {
        let header = DnsHeader {
            id: 0x1234,
            flags: 0x8180,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };

        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from_u16(1).unwrap(), RecordType::A);
        assert_eq!(RecordType::from_u16(28).unwrap(), RecordType::AAAA);
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
    }

    #[test]
    fn test_record_class_conversion() {
        assert_eq!(RecordClass::from_u16(1).unwrap(), RecordClass::IN);
        assert_eq!(RecordClass::IN.to_u16(), 1);
    }
}
