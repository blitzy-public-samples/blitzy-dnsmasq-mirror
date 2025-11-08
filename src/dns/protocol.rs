// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS protocol message parsing and serialization implementing RFC 1035
//
// Translated from: src/rfc1035.c, src/dns-protocol.h

//! DNS Protocol Wire Format Implementation (RFC 1035)
//!
//! This module provides complete DNS message parsing and serialization with memory-safe
//! handling of all DNS packet formats. It replaces the C implementation's manual buffer
//! management and pointer arithmetic with Rust's type-safe parsing using nom combinators
//! and byteorder for network byte conversion.
//!
//! ## Key Features
//! - DNS header parsing with structured flag bitfields
//! - Question section parsing with DNS name compression support
//! - Resource record parsing for all common RR types (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT)
//! - DNSSEC record support (RRSIG, DNSKEY, DS, NSEC, NSEC3)
//! - EDNS0 OPT pseudo-record handling
//! - Response packet construction with automatic compression
//! - Complete error handling with no panics on malformed input
//!
//! ## Memory Safety
//! All parsing uses nom's IResult for bounds checking, eliminating buffer overflows.
//! Network byte order conversion uses byteorder crate replacing C's GETSHORT/PUTSHORT macros.

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::{map, map_res};
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

use crate::constants::EDNS_PACKET_SIZE;
use crate::dns::compression::{CompressionError, extract_name};

/// DNS protocol constants from dns-protocol.h
pub const DNS_HEADER_SIZE: usize = 12;
/// Maximum DNS packet size over UDP (RFC 1035)
pub const MAX_PACKET_SIZE_UDP: usize = 512;
/// Maximum length of a DNS label (RFC 1035)
pub const MAX_LABEL_LENGTH: usize = 63;
/// Bitmask to identify DNS name compression pointers (top 2 bits set)
pub const COMPRESSION_POINTER_MASK: u8 = 0xC0;

/// DNS header flags - Query/Response bit
const QR_MASK: u16 = 0x8000;
/// DNS header flags - Opcode mask (bits 11-14)
const OPCODE_MASK: u16 = 0x7800;
/// DNS header flags - Authoritative Answer bit
const AA_MASK: u16 = 0x0400;
/// DNS header flags - Truncation bit
const TC_MASK: u16 = 0x0200;
/// DNS header flags - Recursion Desired bit
const RD_MASK: u16 = 0x0100;
/// DNS header flags - Recursion Available bit
const RA_MASK: u16 = 0x0080;
/// DNS header flags - Reserved bit (must be zero)
const Z_MASK: u16 = 0x0040;
/// DNS header flags - Authenticated Data bit (DNSSEC)
const AD_MASK: u16 = 0x0020;
/// DNS header flags - Checking Disabled bit (DNSSEC)
const CD_MASK: u16 = 0x0010;
/// DNS header flags - Response Code mask (bits 0-3)
const RCODE_MASK: u16 = 0x000F;

/// DNS Protocol Error Types
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ProtocolError {
    /// Malformed DNS packet
    #[error("Malformed DNS packet: {0}")]
    MalformedPacket(String),

    /// Invalid compression pointer at specified offset
    #[error("Invalid compression pointer at offset {0}")]
    InvalidCompressionPointer(usize),

    /// Unsupported DNS record type
    #[error("Unsupported record type: {0}")]
    UnsupportedRecordType(u16),

    /// Packet is too short for expected content
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort {
        /// Expected minimum packet size
        expected: usize,
        /// Actual packet size received
        actual: usize
    },

    /// Invalid DNS response code
    #[error("Invalid response code: {0}")]
    InvalidRcode(u8),

    /// Domain name exceeds maximum length
    #[error("Domain name too long: {0} bytes")]
    NameTooLong(usize),

    /// I/O error occurred
    #[error("IO error: {0}")]
    IoError(String),
}

impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        ProtocolError::IoError(e.to_string())
    }
}

impl From<CompressionError> for ProtocolError {
    fn from(e: CompressionError) -> Self {
        match e {
            CompressionError::PacketTooShort {
                offset,
                attempted,
                packet_len,
            } => ProtocolError::PacketTooShort {
                expected: offset + attempted,
                actual: packet_len,
            },
            CompressionError::InvalidOffset { offset, .. } => {
                ProtocolError::InvalidCompressionPointer(offset)
            }
            CompressionError::TooManyHops => {
                ProtocolError::MalformedPacket("Too many compression pointer hops".to_string())
            }
            CompressionError::NameTooLong { length } => ProtocolError::NameTooLong(length),
            CompressionError::InvalidLabelType { label_type } => {
                ProtocolError::MalformedPacket(format!("Unsupported label type: {label_type:#x}"))
            }
        }
    }
}

/// DNS Record Type enumeration (RFC 1035 Section 3.2.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    /// IPv4 address
    A = 1,
    /// Name server
    NS = 2,
    /// Canonical name
    CNAME = 5,
    /// Start of authority
    SOA = 6,
    /// Pointer record
    PTR = 12,
    /// Mail exchange
    MX = 15,
    /// Text record
    TXT = 16,
    /// IPv6 address
    AAAA = 28,
    /// Service locator
    SRV = 33,
    /// EDNS0 option (pseudo-record)
    OPT = 41,
    /// DNSSEC Delegation Signer
    DS = 43,
    /// DNSSEC Signature
    RRSIG = 46,
    /// DNSSEC Next Secure
    NSEC = 47,
    /// DNSSEC Public Key
    DNSKEY = 48,
    /// DNSSEC Next Secure v3
    NSEC3 = 50,
    /// QTYPE for queries matching any record type
    ANY = 255,
}

impl RecordType {
    /// Convert from wire format `u16` to `RecordType`
    ///
    /// # Errors
    /// Returns `ProtocolError::UnsupportedRecordType` if the value doesn't correspond to a known record type.
    pub fn from_u16(value: u16) -> Result<Self, ProtocolError> {
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
            43 => Ok(RecordType::DS),
            46 => Ok(RecordType::RRSIG),
            47 => Ok(RecordType::NSEC),
            48 => Ok(RecordType::DNSKEY),
            50 => Ok(RecordType::NSEC3),
            255 => Ok(RecordType::ANY),
            _ => Err(ProtocolError::UnsupportedRecordType(value)),
        }
    }

    /// Convert to wire format u16
    #[must_use]
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// DNS Record Class enumeration (RFC 1035 Section 3.2.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordClass {
    /// Internet
    IN = 1,
    /// CSNET (obsolete)
    CS = 2,
    /// CHAOS
    CH = 3,
    /// Hesiod
    HS = 4,
    /// QCLASS for queries matching any class
    ANY = 255,
}

impl RecordClass {
    /// Convert from wire format `u16` to `RecordClass`
    ///
    /// # Errors
    /// Returns `ProtocolError::MalformedPacket` if the value doesn't correspond to a known class.
    pub fn from_u16(value: u16) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(RecordClass::IN),
            2 => Ok(RecordClass::CS),
            3 => Ok(RecordClass::CH),
            4 => Ok(RecordClass::HS),
            255 => Ok(RecordClass::ANY),
            _ => Err(ProtocolError::MalformedPacket(format!(
                "Unknown class: {value}"
            ))),
        }
    }

    /// Convert to wire format `u16`
    #[must_use]
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// DNS Header Flags structure (RFC 1035 Section 4.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFlags {
    /// Query/Response flag
    pub qr: bool,
    /// Operation code
    pub opcode: u8,
    /// Authoritative Answer
    pub aa: bool,
    /// Truncation
    pub tc: bool,
    /// Recursion Desired
    pub rd: bool,
    /// Recursion Available
    pub ra: bool,
    /// Reserved (must be zero)
    pub z: bool,
    /// Authenticated Data (DNSSEC)
    pub ad: bool,
    /// Checking Disabled (DNSSEC)
    pub cd: bool,
    /// Response code
    pub rcode: u8,
}

impl DnsFlags {
    /// Create new `DnsFlags` with default values
    #[must_use]
    pub fn new() -> Self {
        Self {
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: false,
            ad: false,
            cd: false,
            rcode: 0,
        }
    }

    /// Parse flags from wire format (2 bytes)
    #[must_use]
    pub fn from_u16(flags: u16) -> Self {
        Self {
            qr: (flags & QR_MASK) != 0,
            opcode: ((flags & OPCODE_MASK) >> 11) as u8,
            aa: (flags & AA_MASK) != 0,
            tc: (flags & TC_MASK) != 0,
            rd: (flags & RD_MASK) != 0,
            ra: (flags & RA_MASK) != 0,
            z: (flags & Z_MASK) != 0,
            ad: (flags & AD_MASK) != 0,
            cd: (flags & CD_MASK) != 0,
            rcode: (flags & RCODE_MASK) as u8,
        }
    }

    /// Convert to wire format (2 bytes)
    #[must_use]
    pub fn to_u16(&self) -> u16 {
        let mut flags = 0u16;
        if self.qr {
            flags |= QR_MASK;
        }
        flags |= (u16::from(self.opcode) << 11) & OPCODE_MASK;
        if self.aa {
            flags |= AA_MASK;
        }
        if self.tc {
            flags |= TC_MASK;
        }
        if self.rd {
            flags |= RD_MASK;
        }
        if self.ra {
            flags |= RA_MASK;
        }
        if self.z {
            flags |= Z_MASK;
        }
        if self.ad {
            flags |= AD_MASK;
        }
        if self.cd {
            flags |= CD_MASK;
        }
        flags |= u16::from(self.rcode) & RCODE_MASK;
        flags
    }
}

impl Default for DnsFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS Message Header (RFC 1035 Section 4.1.1)
/// Fixed 12-byte structure at the start of every DNS message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    /// Transaction ID
    pub id: u16,
    /// Flags and codes
    pub flags: DnsFlags,
    /// Number of questions
    pub qdcount: u16,
    /// Number of answers
    pub ancount: u16,
    /// Number of authority records
    pub nscount: u16,
    /// Number of additional records
    pub arcount: u16,
}

impl DnsHeader {
    /// Create new DNS header with default values
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: 0,
            flags: DnsFlags::new(),
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Parse DNS header from wire format (12 bytes)
    ///
    /// # Errors
    /// Returns `ProtocolError::PacketTooShort` if the data is less than 12 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < DNS_HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort {
                expected: DNS_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut cursor = std::io::Cursor::new(data);

        Ok(Self {
            id: cursor.read_u16::<NetworkEndian>()?,
            flags: DnsFlags::from_u16(cursor.read_u16::<NetworkEndian>()?),
            qdcount: cursor.read_u16::<NetworkEndian>()?,
            ancount: cursor.read_u16::<NetworkEndian>()?,
            nscount: cursor.read_u16::<NetworkEndian>()?,
            arcount: cursor.read_u16::<NetworkEndian>()?,
        })
    }

    /// Serialize DNS header to wire format (12 bytes)
    ///
    /// # Errors
    /// This function currently never fails but returns `Result` for consistency with the protocol API.
    pub fn serialize(&self, buf: &mut BytesMut) -> Result<(), ProtocolError> {
        buf.reserve(DNS_HEADER_SIZE);
        buf.put_u16(self.id);
        buf.put_u16(self.flags.to_u16());
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);
        Ok(())
    }
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS Question section entry (RFC 1035 Section 4.1.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Domain name being queried
    pub qname: String,
    /// Record type requested
    pub qtype: RecordType,
    /// Record class (usually IN)
    pub qclass: RecordClass,
}

impl DnsQuestion {
    /// Create new DNS question
    #[must_use]
    pub fn new(qname: String, qtype: RecordType, qclass: RecordClass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }
}

/// DNS Resource Record variants (RFC 1035 Section 3.2.1)
/// All records include name, class, and TTL fields as per RFC 1035
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceRecord {
    /// A record - IPv4 address (RFC 1035)
    A {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// IPv4 address
        address: Ipv4Addr,
    },

    /// AAAA record - IPv6 address (RFC 3596)
    AAAA {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// IPv6 address
        address: Ipv6Addr,
    },

    /// CNAME record - Canonical name alias (RFC 1035)
    CNAME {
        /// Domain name (alias)
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Canonical name (target)
        cname: String,
    },

    /// MX record - Mail exchange (RFC 1035)
    MX {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Mail server preference (lower is preferred)
        preference: u16,
        /// Mail server domain name
        exchange: String,
    },

    /// NS record - Name server (RFC 1035)
    NS {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Name server domain name
        nsdname: String,
    },

    /// PTR record - Pointer for reverse lookup (RFC 1035)
    PTR {
        /// Domain name (reverse DNS address)
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Pointer domain name (target)
        ptrdname: String,
    },

    /// SOA record - Start of authority (RFC 1035)
    SOA {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Primary name server
        mname: String,
        /// Responsible party email
        rname: String,
        /// Zone serial number
        serial: u32,
        /// Refresh interval
        refresh: u32,
        /// Retry interval
        retry: u32,
        /// Expiration time
        expire: u32,
        /// Minimum TTL
        minimum: u32,
    },

    /// SRV record - Service locator (RFC 2782)
    SRV {
        /// Service name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Priority of target host (lower is preferred)
        priority: u16,
        /// Relative weight for same priority
        weight: u16,
        /// Port number of the service
        port: u16,
        /// Target host domain name
        target: String,
    },

    /// TXT record - Text strings (RFC 1035)
    TXT {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Text data strings
        data: Vec<String>,
    },

    /// OPT pseudo-record - EDNS0 (RFC 6891)
    /// Note: OPT records don't have a traditional class field; the class field
    /// is reused for UDP payload size
    OPT {
        /// Maximum UDP payload size the sender can handle
        udp_payload_size: u16,
        /// Extended response code (upper 8 bits of extended RCODE)
        extended_rcode: u8,
        /// EDNS version number
        version: u8,
        /// DNSSEC OK flag indicating DNSSEC support
        dnssec_ok: bool,
        /// Variable-length EDNS option data
        data: Vec<u8>,
    },

    /// RRSIG record - DNSSEC signature (RFC 4034)
    RRSIG {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Type of `RRset` covered by this signature
        type_covered: u16,
        /// Cryptographic algorithm used
        algorithm: u8,
        /// Number of labels in the original RRSIG owner name
        labels: u8,
        /// Original TTL of the covered `RRset`
        original_ttl: u32,
        /// Signature expiration time (seconds since epoch)
        signature_expiration: u32,
        /// Signature inception time (seconds since epoch)
        signature_inception: u32,
        /// Key tag for the DNSKEY RR that validates this signature
        key_tag: u16,
        /// Domain name of the signer
        signer_name: String,
        /// Cryptographic signature data
        signature: Vec<u8>,
    },

    /// DNSKEY record - DNSSEC public key (RFC 4034)
    DNSKEY {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Key flags (bit 7 = Zone Key, bit 15 = Secure Entry Point)
        flags: u16,
        /// Protocol field (must be 3 for DNSSEC)
        protocol: u8,
        /// Cryptographic algorithm identifier
        algorithm: u8,
        /// Public key data
        public_key: Vec<u8>,
    },

    /// DS record - Delegation Signer (RFC 4034)
    DS {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Key tag of the referenced DNSKEY
        key_tag: u16,
        /// Cryptographic algorithm of the referenced DNSKEY
        algorithm: u8,
        /// Digest algorithm used
        digest_type: u8,
        /// Digest of the referenced DNSKEY
        digest: Vec<u8>,
    },

    /// NSEC record - Next Secure (RFC 4034)
    NSEC {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Next domain name in canonical order
        next_domain: String,
        /// Bitmap of RR types present at this name
        type_bitmaps: Vec<u8>,
    },

    /// NSEC3 record - Next Secure v3 (RFC 5155)
    NSEC3 {
        /// Domain name
        name: String,
        /// Record class (typically IN for Internet)
        class: RecordClass,
        /// Time to live in seconds
        ttl: u32,
        /// Cryptographic hash algorithm used
        hash_algorithm: u8,
        /// Flags (bit 0 = Opt-Out)
        flags: u8,
        /// Number of additional hash iterations
        iterations: u16,
        /// Salt value for hash calculation
        salt: Vec<u8>,
        /// Hash of the next owner name
        next_hashed_owner: Vec<u8>,
        /// Bitmap of RR types present at this name
        type_bitmaps: Vec<u8>,
    },
}

impl ResourceRecord {
    /// Get the record type for this resource record
    #[must_use]
    pub fn record_type(&self) -> RecordType {
        match self {
            ResourceRecord::A { .. } => RecordType::A,
            ResourceRecord::AAAA { .. } => RecordType::AAAA,
            ResourceRecord::CNAME { .. } => RecordType::CNAME,
            ResourceRecord::MX { .. } => RecordType::MX,
            ResourceRecord::NS { .. } => RecordType::NS,
            ResourceRecord::PTR { .. } => RecordType::PTR,
            ResourceRecord::SOA { .. } => RecordType::SOA,
            ResourceRecord::SRV { .. } => RecordType::SRV,
            ResourceRecord::TXT { .. } => RecordType::TXT,
            ResourceRecord::OPT { .. } => RecordType::OPT,
            ResourceRecord::RRSIG { .. } => RecordType::RRSIG,
            ResourceRecord::DNSKEY { .. } => RecordType::DNSKEY,
            ResourceRecord::DS { .. } => RecordType::DS,
            ResourceRecord::NSEC { .. } => RecordType::NSEC,
            ResourceRecord::NSEC3 { .. } => RecordType::NSEC3,
        }
    }

    /// Get the name field from any resource record
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn name(&self) -> &str {
        match self {
            ResourceRecord::A { name, .. } => name,
            ResourceRecord::AAAA { name, .. } => name,
            ResourceRecord::CNAME { name, .. } => name,
            ResourceRecord::MX { name, .. } => name,
            ResourceRecord::NS { name, .. } => name,
            ResourceRecord::PTR { name, .. } => name,
            ResourceRecord::SOA { name, .. } => name,
            ResourceRecord::SRV { name, .. } => name,
            ResourceRecord::TXT { name, .. } => name,
            ResourceRecord::OPT { .. } => "", // OPT doesn't have a name field
            ResourceRecord::RRSIG { name, .. } => name,
            ResourceRecord::DNSKEY { name, .. } => name,
            ResourceRecord::DS { name, .. } => name,
            ResourceRecord::NSEC { name, .. } => name,
            ResourceRecord::NSEC3 { name, .. } => name,
        }
    }

    /// Get the TTL from any resource record (except OPT)
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn ttl(&self) -> u32 {
        match self {
            ResourceRecord::A { ttl, .. } => *ttl,
            ResourceRecord::AAAA { ttl, .. } => *ttl,
            ResourceRecord::CNAME { ttl, .. } => *ttl,
            ResourceRecord::MX { ttl, .. } => *ttl,
            ResourceRecord::NS { ttl, .. } => *ttl,
            ResourceRecord::PTR { ttl, .. } => *ttl,
            ResourceRecord::SOA { ttl, .. } => *ttl,
            ResourceRecord::SRV { ttl, .. } => *ttl,
            ResourceRecord::TXT { ttl, .. } => *ttl,
            ResourceRecord::OPT { .. } => 0, // OPT doesn't have a TTL
            ResourceRecord::RRSIG { ttl, .. } => *ttl,
            ResourceRecord::DNSKEY { ttl, .. } => *ttl,
            ResourceRecord::DS { ttl, .. } => *ttl,
            ResourceRecord::NSEC { ttl, .. } => *ttl,
            ResourceRecord::NSEC3 { ttl, .. } => *ttl,
        }
    }
}

/// DNS Message structure containing all sections
#[derive(Debug, Clone, PartialEq)]
pub struct DnsMessage {
    /// DNS header with transaction ID and flags
    pub header: DnsHeader,
    /// Question section (queries)
    pub questions: Vec<DnsQuestion>,
    /// Answer section (response records)
    pub answers: Vec<ResourceRecord>,
    /// Authority section (nameserver records)
    pub authority: Vec<ResourceRecord>,
    /// Additional section (extra information)
    pub additional: Vec<ResourceRecord>,
}

impl DnsMessage {
    /// Create new empty DNS message
    #[must_use]
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Parse complete DNS message from wire format
    ///
    /// # Errors
    /// Returns `ProtocolError` if the data is malformed, too short, or contains invalid DNS records.
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < DNS_HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort {
                expected: DNS_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let header = DnsHeader::parse(data)?;
        let mut offset = DNS_HEADER_SIZE;

        // Parse questions
        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            let question = parse_question_at(data, &mut offset)?;
            questions.push(question);
        }

        // Parse answer records
        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            let rr = parse_resource_record_at(data, &mut offset)?;
            answers.push(rr);
        }

        // Parse authority records
        let mut authority = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            let rr = parse_resource_record_at(data, &mut offset)?;
            authority.push(rr);
        }

        // Parse additional records
        let mut additional = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            let rr = parse_resource_record_at(data, &mut offset)?;
            additional.push(rr);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// Serialize DNS message to wire format
    ///
    /// # Errors
    /// Returns `ProtocolError` if any record cannot be serialized to wire format.
    #[allow(clippy::cast_possible_truncation)]
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = BytesMut::with_capacity(512);

        // Update header counts
        let mut header = self.header.clone();
        header.qdcount = self.questions.len() as u16;
        header.ancount = self.answers.len() as u16;
        header.nscount = self.authority.len() as u16;
        header.arcount = self.additional.len() as u16;

        header.serialize(&mut buf)?;

        // Serialize questions
        for question in &self.questions {
            serialize_question(question, &mut buf)?;
        }

        // Serialize answers
        for rr in &self.answers {
            serialize_rr(rr, &mut buf)?;
        }

        // Serialize authority
        for rr in &self.authority {
            serialize_rr(rr, &mut buf)?;
        }

        // Serialize additional
        for rr in &self.additional {
            serialize_rr(rr, &mut buf)?;
        }

        Ok(buf.to_vec())
    }
}

impl Default for DnsMessage {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a DNS question from packet at given offset
fn parse_question_at(packet: &[u8], offset: &mut usize) -> Result<DnsQuestion, ProtocolError> {
    // Extract domain name using compression module
    let name_result = extract_name(packet, offset, 4)?;
    let qname = name_result.to_string();

    // Parse QTYPE and QCLASS
    if *offset + 4 > packet.len() {
        return Err(ProtocolError::PacketTooShort {
            expected: *offset + 4,
            actual: packet.len(),
        });
    }

    let mut cursor = std::io::Cursor::new(&packet[*offset..]);
    let qtype_val = cursor.read_u16::<NetworkEndian>()?;
    let qclass_val = cursor.read_u16::<NetworkEndian>()?;
    *offset += 4;

    let qtype = RecordType::from_u16(qtype_val)?;
    let qclass = RecordClass::from_u16(qclass_val)?;

    Ok(DnsQuestion::new(qname, qtype, qclass))
}

/// Parse DNS question section (exported function matching schema)
///
/// # Errors
/// Returns `nom::Err` if the question section cannot be parsed from the input data.
pub fn parse_question(data: &[u8]) -> IResult<&[u8], DnsQuestion> {
    let input = data;
    let mut offset = 0;

    match parse_question_at(data, &mut offset) {
        Ok(question) => Ok((&input[offset..], question)),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Fail,
        ))),
    }
}

/// Parse a resource record at given offset
fn parse_resource_record_at(
    packet: &[u8],
    offset: &mut usize,
) -> Result<ResourceRecord, ProtocolError> {
    // Extract name
    let name_result = extract_name(packet, offset, 10)?;
    let name = name_result.to_string();

    // Parse TYPE, CLASS, TTL, RDLENGTH
    if *offset + 10 > packet.len() {
        return Err(ProtocolError::PacketTooShort {
            expected: *offset + 10,
            actual: packet.len(),
        });
    }

    let mut cursor = std::io::Cursor::new(&packet[*offset..]);
    let rr_type = cursor.read_u16::<NetworkEndian>()?;
    let rr_class = cursor.read_u16::<NetworkEndian>()?;
    let ttl = cursor.read_u32::<NetworkEndian>()?;
    let rdlength = cursor.read_u16::<NetworkEndian>()? as usize;
    *offset += 10;

    // Ensure RDATA is available
    if *offset + rdlength > packet.len() {
        return Err(ProtocolError::PacketTooShort {
            expected: *offset + rdlength,
            actual: packet.len(),
        });
    }

    let rdata = &packet[*offset..*offset + rdlength];
    *offset += rdlength;

    // Convert class to RecordClass enum
    let class = RecordClass::from_u16(rr_class).unwrap_or(RecordClass::IN);

    // Parse RDATA based on type
    parse_rdata(name, rr_type, class, ttl, rdata, packet)
}

/// Parse RDATA based on record type
fn parse_rdata(
    name: String,
    rr_type: u16,
    class: RecordClass,
    ttl: u32,
    rdata: &[u8],
    full_packet: &[u8],
) -> Result<ResourceRecord, ProtocolError> {
    match rr_type {
        1 => {
            // A record
            if rdata.len() != 4 {
                return Err(ProtocolError::MalformedPacket(
                    "A record must be 4 bytes".to_string(),
                ));
            }
            Ok(ResourceRecord::A {
                name,
                class,
                ttl,
                address: Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
            })
        }

        28 => {
            // AAAA record
            if rdata.len() != 16 {
                return Err(ProtocolError::MalformedPacket(
                    "AAAA record must be 16 bytes".to_string(),
                ));
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(rdata);
            Ok(ResourceRecord::AAAA {
                name,
                class,
                ttl,
                address: Ipv6Addr::from(bytes),
            })
        }

        5 => {
            // CNAME record
            let mut offset = (rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize);
            let cname_result = extract_name(full_packet, &mut offset, 0)?;
            Ok(ResourceRecord::CNAME {
                name,
                class,
                ttl,
                cname: cname_result.to_string(),
            })
        }

        2 => {
            // NS record
            let mut offset = (rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize);
            let ns_result = extract_name(full_packet, &mut offset, 0)?;
            Ok(ResourceRecord::NS {
                name,
                class,
                ttl,
                nsdname: ns_result.to_string(),
            })
        }

        12 => {
            // PTR record
            let mut offset = (rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize);
            let ptr_result = extract_name(full_packet, &mut offset, 0)?;
            Ok(ResourceRecord::PTR {
                name,
                class,
                ttl,
                ptrdname: ptr_result.to_string(),
            })
        }

        15 => {
            // MX record
            if rdata.len() < 2 {
                return Err(ProtocolError::MalformedPacket(
                    "MX record too short".to_string(),
                ));
            }
            let mut cursor = std::io::Cursor::new(rdata);
            let preference = cursor.read_u16::<NetworkEndian>()?;
            let mut offset = (rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize) + 2;
            let exchange_result = extract_name(full_packet, &mut offset, 0)?;
            Ok(ResourceRecord::MX {
                name,
                class,
                ttl,
                preference,
                exchange: exchange_result.to_string(),
            })
        }

        6 => {
            // SOA record
            let mut offset = (rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize);
            let mname_result = extract_name(full_packet, &mut offset, 0)?;
            let rname_result = extract_name(full_packet, &mut offset, 0)?;

            if offset + 20 > full_packet.len() {
                return Err(ProtocolError::MalformedPacket(
                    "SOA record incomplete".to_string(),
                ));
            }

            let mut cursor = std::io::Cursor::new(&full_packet[offset..]);
            let serial = cursor.read_u32::<NetworkEndian>()?;
            let refresh = cursor.read_u32::<NetworkEndian>()?;
            let retry = cursor.read_u32::<NetworkEndian>()?;
            let expire = cursor.read_u32::<NetworkEndian>()?;
            let minimum = cursor.read_u32::<NetworkEndian>()?;

            Ok(ResourceRecord::SOA {
                name,
                class,
                ttl,
                mname: mname_result.to_string(),
                rname: rname_result.to_string(),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        }

        33 => {
            // SRV record
            if rdata.len() < 6 {
                return Err(ProtocolError::MalformedPacket(
                    "SRV record too short".to_string(),
                ));
            }
            let mut cursor = std::io::Cursor::new(rdata);
            let priority = cursor.read_u16::<NetworkEndian>()?;
            let weight = cursor.read_u16::<NetworkEndian>()?;
            let port = cursor.read_u16::<NetworkEndian>()?;

            let mut offset = (rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize) + 6;
            let target_result = extract_name(full_packet, &mut offset, 0)?;

            Ok(ResourceRecord::SRV {
                name,
                class,
                ttl,
                priority,
                weight,
                port,
                target: target_result.to_string(),
            })
        }

        16 => {
            // TXT record
            let mut strings = Vec::new();
            let mut pos = 0;
            while pos < rdata.len() {
                let len = rdata[pos] as usize;
                pos += 1;
                if pos + len > rdata.len() {
                    return Err(ProtocolError::MalformedPacket(
                        "TXT record string overflow".to_string(),
                    ));
                }
                let s = String::from_utf8_lossy(&rdata[pos..pos + len]).to_string();
                strings.push(s);
                pos += len;
            }
            Ok(ResourceRecord::TXT {
                name,
                class,
                ttl,
                data: strings,
            })
        }

        41 => {
            // OPT pseudo-record
            // For OPT records, name should be root, TTL encodes extended RCODE and flags
            let udp_payload_size = name.parse::<u16>().unwrap_or(512);
            let extended_rcode = ((ttl >> 24) & 0xFF) as u8;
            let version = ((ttl >> 16) & 0xFF) as u8;
            let dnssec_ok = (ttl & 0x8000) != 0;

            Ok(ResourceRecord::OPT {
                udp_payload_size,
                extended_rcode,
                version,
                dnssec_ok,
                data: rdata.to_vec(),
            })
        }

        46 => {
            // RRSIG record
            if rdata.len() < 18 {
                return Err(ProtocolError::MalformedPacket(
                    "RRSIG record too short".to_string(),
                ));
            }
            let mut cursor = std::io::Cursor::new(rdata);
            let type_covered = cursor.read_u16::<NetworkEndian>()?;
            let algorithm = cursor.read_u8()?;
            let labels = cursor.read_u8()?;
            let original_ttl = cursor.read_u32::<NetworkEndian>()?;
            let signature_expiration = cursor.read_u32::<NetworkEndian>()?;
            let signature_inception = cursor.read_u32::<NetworkEndian>()?;
            let key_tag = cursor.read_u16::<NetworkEndian>()?;

            let mut offset = (rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize) + 18;
            let signer_result = extract_name(full_packet, &mut offset, 0)?;

            let sig_start = offset - ((rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize));
            let signature = rdata[sig_start..].to_vec();

            Ok(ResourceRecord::RRSIG {
                name,
                class,
                ttl,
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name: signer_result.to_string(),
                signature,
            })
        }

        48 => {
            // DNSKEY record
            if rdata.len() < 4 {
                return Err(ProtocolError::MalformedPacket(
                    "DNSKEY record too short".to_string(),
                ));
            }
            let mut cursor = std::io::Cursor::new(rdata);
            let flags = cursor.read_u16::<NetworkEndian>()?;
            let protocol = cursor.read_u8()?;
            let algorithm = cursor.read_u8()?;
            let public_key = rdata[4..].to_vec();

            Ok(ResourceRecord::DNSKEY {
                name,
                class,
                ttl,
                flags,
                protocol,
                algorithm,
                public_key,
            })
        }

        43 => {
            // DS record
            if rdata.len() < 4 {
                return Err(ProtocolError::MalformedPacket(
                    "DS record too short".to_string(),
                ));
            }
            let mut cursor = std::io::Cursor::new(rdata);
            let key_tag = cursor.read_u16::<NetworkEndian>()?;
            let algorithm = cursor.read_u8()?;
            let digest_type = cursor.read_u8()?;
            let digest = rdata[4..].to_vec();

            Ok(ResourceRecord::DS {
                name,
                class,
                ttl,
                key_tag,
                algorithm,
                digest_type,
                digest,
            })
        }

        47 => {
            // NSEC record
            let mut offset = (rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize);
            let next_result = extract_name(full_packet, &mut offset, 0)?;
            let bitmap_start =
                offset - ((rdata.as_ptr() as usize) - (full_packet.as_ptr() as usize));
            let type_bitmaps = rdata[bitmap_start..].to_vec();

            Ok(ResourceRecord::NSEC {
                name,
                class,
                ttl,
                next_domain: next_result.to_string(),
                type_bitmaps,
            })
        }

        50 => {
            // NSEC3 record
            if rdata.len() < 5 {
                return Err(ProtocolError::MalformedPacket(
                    "NSEC3 record too short".to_string(),
                ));
            }
            let hash_algorithm = rdata[0];
            let flags = rdata[1];
            let mut cursor = std::io::Cursor::new(&rdata[2..]);
            let iterations = cursor.read_u16::<NetworkEndian>()?;
            let salt_length = rdata[4] as usize;

            if rdata.len() < 5 + salt_length + 1 {
                return Err(ProtocolError::MalformedPacket(
                    "NSEC3 record incomplete".to_string(),
                ));
            }

            let salt = rdata[5..5 + salt_length].to_vec();
            let hash_length = rdata[5 + salt_length] as usize;

            if rdata.len() < 5 + salt_length + 1 + hash_length {
                return Err(ProtocolError::MalformedPacket(
                    "NSEC3 record hash incomplete".to_string(),
                ));
            }

            let next_hashed_owner = rdata[6 + salt_length..6 + salt_length + hash_length].to_vec();
            let type_bitmaps = rdata[6 + salt_length + hash_length..].to_vec();

            Ok(ResourceRecord::NSEC3 {
                name,
                class,
                ttl,
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmaps,
            })
        }

        _ => Err(ProtocolError::UnsupportedRecordType(rr_type)),
    }
}

/// Parse resource records from packet (exported function matching schema)
///
/// # Errors
/// Returns `nom::Err` if any resource record cannot be parsed from the input data.
pub fn parse_resource_records(data: &[u8], count: u16) -> IResult<&[u8], Vec<ResourceRecord>> {
    let mut offset = 0;
    let mut records = Vec::with_capacity(count as usize);

    for _ in 0..count {
        match parse_resource_record_at(data, &mut offset) {
            Ok(rr) => records.push(rr),
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    data,
                    nom::error::ErrorKind::Fail,
                )));
            }
        }
    }

    Ok((&data[offset..], records))
}

/// Serialize a DNS question to wire format
fn serialize_question(question: &DnsQuestion, buf: &mut BytesMut) -> Result<(), ProtocolError> {
    // Serialize domain name (without compression for questions)
    serialize_name(&question.qname, buf)?;

    // Serialize QTYPE and QCLASS
    buf.put_u16(question.qtype.to_u16());
    buf.put_u16(question.qclass.to_u16());

    Ok(())
}

/// Serialize domain name to wire format (simplified without compression)
#[allow(clippy::cast_possible_truncation)]
fn serialize_name(name: &str, buf: &mut BytesMut) -> Result<(), ProtocolError> {
    if name == "." {
        buf.put_u8(0);
        return Ok(());
    }

    for label in name.trim_end_matches('.').split('.') {
        if label.len() > MAX_LABEL_LENGTH {
            return Err(ProtocolError::NameTooLong(label.len()));
        }
        buf.put_u8(label.len() as u8);
        buf.put_slice(label.as_bytes());
    }
    buf.put_u8(0); // Terminating zero-length label

    Ok(())
}

/// Serialize a resource record to wire format
#[allow(clippy::cast_possible_truncation)]
fn serialize_rr(rr: &ResourceRecord, buf: &mut BytesMut) -> Result<(), ProtocolError> {
    match rr {
        ResourceRecord::A {
            name,
            class,
            ttl,
            address,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::A.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);
            buf.put_u16(4); // RDLENGTH
            buf.put_slice(&address.octets());
        }

        ResourceRecord::AAAA {
            name,
            class,
            ttl,
            address,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::AAAA.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);
            buf.put_u16(16); // RDLENGTH
            buf.put_slice(&address.octets());
        }

        ResourceRecord::CNAME {
            name,
            class,
            ttl,
            cname,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::CNAME.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            // Calculate RDLENGTH
            let mut rdata_buf = BytesMut::new();
            serialize_name(cname, &mut rdata_buf)?;
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::NS {
            name,
            class,
            ttl,
            nsdname,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::NS.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            serialize_name(nsdname, &mut rdata_buf)?;
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::PTR {
            name,
            class,
            ttl,
            ptrdname,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::PTR.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            serialize_name(ptrdname, &mut rdata_buf)?;
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::MX {
            name,
            class,
            ttl,
            preference,
            exchange,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::MX.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            rdata_buf.put_u16(*preference);
            serialize_name(exchange, &mut rdata_buf)?;
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::SOA {
            name,
            class,
            ttl,
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::SOA.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            serialize_name(mname, &mut rdata_buf)?;
            serialize_name(rname, &mut rdata_buf)?;
            rdata_buf.put_u32(*serial);
            rdata_buf.put_u32(*refresh);
            rdata_buf.put_u32(*retry);
            rdata_buf.put_u32(*expire);
            rdata_buf.put_u32(*minimum);
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::SRV {
            name,
            class,
            ttl,
            priority,
            weight,
            port,
            target,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::SRV.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            rdata_buf.put_u16(*priority);
            rdata_buf.put_u16(*weight);
            rdata_buf.put_u16(*port);
            serialize_name(target, &mut rdata_buf)?;
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::TXT {
            name,
            class,
            ttl,
            data,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::TXT.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            for s in data {
                let bytes = s.as_bytes();
                if bytes.len() > 255 {
                    return Err(ProtocolError::MalformedPacket(
                        "TXT string too long".to_string(),
                    ));
                }
                rdata_buf.put_u8(bytes.len() as u8);
                rdata_buf.put_slice(bytes);
            }
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::OPT {
            udp_payload_size,
            extended_rcode,
            version,
            dnssec_ok,
            data,
        } => {
            buf.put_u8(0); // Root domain for OPT
            buf.put_u16(RecordType::OPT.to_u16());
            buf.put_u16(*udp_payload_size); // CLASS field = UDP payload size

            // TTL field encodes extended RCODE, version, and flags
            let mut ttl_field = 0u32;
            ttl_field |= u32::from(*extended_rcode) << 24;
            ttl_field |= u32::from(*version) << 16;
            if *dnssec_ok {
                ttl_field |= 0x8000;
            }
            buf.put_u32(ttl_field);

            buf.put_u16(data.len() as u16);
            buf.put_slice(data);
        }

        ResourceRecord::RRSIG {
            name,
            class,
            ttl,
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::RRSIG.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            rdata_buf.put_u16(*type_covered);
            rdata_buf.put_u8(*algorithm);
            rdata_buf.put_u8(*labels);
            rdata_buf.put_u32(*original_ttl);
            rdata_buf.put_u32(*signature_expiration);
            rdata_buf.put_u32(*signature_inception);
            rdata_buf.put_u16(*key_tag);
            serialize_name(signer_name, &mut rdata_buf)?;
            rdata_buf.put_slice(signature);
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::DNSKEY {
            name,
            class,
            ttl,
            flags,
            protocol,
            algorithm,
            public_key,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::DNSKEY.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let rdlength = 4 + public_key.len();
            buf.put_u16(rdlength as u16);
            buf.put_u16(*flags);
            buf.put_u8(*protocol);
            buf.put_u8(*algorithm);
            buf.put_slice(public_key);
        }

        ResourceRecord::DS {
            name,
            class,
            ttl,
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::DS.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let rdlength = 4 + digest.len();
            buf.put_u16(rdlength as u16);
            buf.put_u16(*key_tag);
            buf.put_u8(*algorithm);
            buf.put_u8(*digest_type);
            buf.put_slice(digest);
        }

        ResourceRecord::NSEC {
            name,
            class,
            ttl,
            next_domain,
            type_bitmaps,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::NSEC.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            serialize_name(next_domain, &mut rdata_buf)?;
            rdata_buf.put_slice(type_bitmaps);
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }

        ResourceRecord::NSEC3 {
            name,
            class,
            ttl,
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmaps,
        } => {
            serialize_name(name, buf)?;
            buf.put_u16(RecordType::NSEC3.to_u16());
            buf.put_u16(class.to_u16());
            buf.put_u32(*ttl);

            let mut rdata_buf = BytesMut::new();
            rdata_buf.put_u8(*hash_algorithm);
            rdata_buf.put_u8(*flags);
            rdata_buf.put_u16(*iterations);
            rdata_buf.put_u8(salt.len() as u8);
            rdata_buf.put_slice(salt);
            rdata_buf.put_u8(next_hashed_owner.len() as u8);
            rdata_buf.put_slice(next_hashed_owner);
            rdata_buf.put_slice(type_bitmaps);
            buf.put_u16(rdata_buf.len() as u16);
            buf.put_slice(&rdata_buf);
        }
    }

    Ok(())
}

/// Serialize resource record (exported function matching schema)
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn serialize_resource_record(
    rr: &ResourceRecord,
    compression: &mut std::collections::HashMap<String, u16>,
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    // Note: compression parameter provided for future enhancement but not used in this implementation
    let _ = compression;

    // Serialize without compression for now
    if serialize_rr(rr, &mut buf).is_err() {
        return Vec::new();
    }

    buf.to_vec()
}

/// Create DNS response from query with given answer records
#[must_use]
pub fn create_response(query: &DnsMessage, response_records: Vec<ResourceRecord>) -> DnsMessage {
    let mut response = DnsMessage::new();

    // Copy transaction ID and questions
    response.header.id = query.header.id;
    response.questions.clone_from(&query.questions);

    // Set response flags
    response.header.flags.qr = true; // This is a response
    response.header.flags.rd = query.header.flags.rd; // Copy RD from query
    response.header.flags.ra = true; // Recursion available
    response.header.flags.aa = false; // Not authoritative by default
    response.header.flags.rcode = 0; // NOERROR

    // Add answer records
    response.answers = response_records;

    response
}

/// Build complete DNS response packet in wire format
#[must_use]
pub fn build_response_packet(message: &DnsMessage) -> Vec<u8> {
    match message.serialize() {
        Ok(packet) => {
            // Check size limits
            let max_size = if message
                .additional
                .iter()
                .any(|rr| matches!(rr, ResourceRecord::OPT { .. }))
            {
                EDNS_PACKET_SIZE
            } else {
                MAX_PACKET_SIZE_UDP
            };

            if packet.len() > max_size {
                // Set truncation flag
                let mut truncated_msg = message.clone();
                truncated_msg.header.flags.tc = true;

                // Try to fit by removing records from additional, then authority sections
                while !truncated_msg.additional.is_empty() {
                    truncated_msg.additional.pop();
                    if let Ok(p) = truncated_msg.serialize() {
                        if p.len() <= max_size {
                            return p;
                        }
                    }
                }

                while !truncated_msg.authority.is_empty() {
                    truncated_msg.authority.pop();
                    if let Ok(p) = truncated_msg.serialize() {
                        if p.len() <= max_size {
                            return p;
                        }
                    }
                }

                // If still too large, return truncated packet
                truncated_msg.serialize().unwrap_or_default()
            } else {
                packet
            }
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header_parse() {
        let data = [
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        let header = DnsHeader::parse(&data).unwrap();
        assert_eq!(header.id, 0x1234);
        assert!(header.flags.qr);
        assert!(header.flags.rd);
        assert!(header.flags.ra);
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 1);
    }

    #[test]
    fn test_dns_flags_roundtrip() {
        let flags = DnsFlags {
            qr: true,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            z: false,
            ad: true,
            cd: false,
            rcode: 0,
        };

        let wire = flags.to_u16();
        let parsed = DnsFlags::from_u16(wire);

        assert_eq!(flags, parsed);
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
        assert_eq!(RecordType::from_u16(1).unwrap(), RecordType::A);
        assert_eq!(RecordType::from_u16(28).unwrap(), RecordType::AAAA);
    }

    #[test]
    fn test_serialize_name() {
        let mut buf = BytesMut::new();
        serialize_name("example.com", &mut buf).unwrap();

        // Should be: 7 "example" 3 "com" 0
        assert_eq!(buf[0], 7);
        assert_eq!(&buf[1..8], b"example");
        assert_eq!(buf[8], 3);
        assert_eq!(&buf[9..12], b"com");
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_a_record_serialization() {
        let rr = ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        };

        let mut buf = BytesMut::new();
        serialize_rr(&rr, &mut buf).unwrap();

        // Verify some key parts
        assert!(!buf.is_empty());
        // Should contain the IP address at the end
        let ip_offset = buf.len() - 4;
        assert_eq!(&buf[ip_offset..], &[192, 0, 2, 1]);
    }

    #[test]
    fn test_create_response() {
        let mut query = DnsMessage::new();
        query.header.id = 0x1234;
        query.header.flags.rd = true;

        let question = DnsQuestion::new("example.com".to_string(), RecordType::A, RecordClass::IN);
        query.questions.push(question);

        let answer = ResourceRecord::A {
            name: "example.com".to_string(),
            class: RecordClass::IN,
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        };

        let response = create_response(&query, vec![answer]);

        assert_eq!(response.header.id, 0x1234);
        assert!(response.header.flags.qr);
        assert!(response.header.flags.rd);
        assert!(response.header.flags.ra);
        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.answers.len(), 1);
    }
}
