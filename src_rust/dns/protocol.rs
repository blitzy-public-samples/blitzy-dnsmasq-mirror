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

//! DNS protocol constants and structures per RFC 1035
//!
//! This module defines the fundamental DNS protocol structures, constants, and
//! types required for parsing and constructing DNS messages according to RFC 1035.
//! It provides the wire-format representation of DNS packets including the 12-byte
//! header structure, resource record type definitions, query classes, opcodes, and
//! response codes. The module also includes DNSSEC-related types (DNSKEY, RRSIG, DS,
//! NSEC, NSEC3) per RFCs 4033-4035, IPv6 AAAA records per RFC 3596, and EDNS0
//! extended options per RFC 6891 and RFC 8914.
//!
//! All structures and constants defined here represent the actual on-the-wire byte
//! layout of DNS protocol messages. Multi-byte integer fields are stored in network
//! byte order (big-endian) and are converted using standard Rust methods.
//!
//! # RFC Compliance
//!
//! - RFC 1035: Domain Names - Implementation and Specification (core DNS protocol)
//! - RFC 2535: Domain Name System Security Extensions (original DNSSEC, obsoleted)
//! - RFC 3596: DNS Extensions to Support IP Version 6 (AAAA records)
//! - RFC 4033-4035: DNS Security Extensions (DNSSEC)
//! - RFC 6891: Extension Mechanisms for DNS (EDNS0)
//! - RFC 8914: Extended DNS Errors (EDE codes)

// ============================================================================
// Port and Size Constants
// ============================================================================

/// Standard DNS server port number (53) per RFC 1035
pub const NAMESERVER_PORT: u16 = 53;

/// Standard TFTP server port number (69) per RFC 1350
pub const TFTP_PORT: u16 = 69;

/// First non-reserved port (1024) - ports below are privileged on Unix
pub const MIN_PORT: u16 = 1024;

/// Maximum valid port number (65535)
pub const MAX_PORT: u16 = 65535;

/// Default maximum DNS packet size (512 bytes) per RFC 1035 Section 4.2.1
pub const PACKETSZ: usize = 512;

/// Maximum presentation format domain name length (1025 bytes)
/// Wire format is limited to 255 bytes, but presentation format with
/// escape sequences requires larger buffer. Includes null terminator.
pub const MAXDNAME: usize = 1025;

/// Maximum length of single domain name label (63 bytes) per RFC 1035 Section 3.1
pub const MAXLABEL: usize = 63;

/// Fixed size of resource record header (10 bytes): TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
pub const RRFIXEDSZ: usize = 10;

/// Size of IPv4 address in bytes (4)
pub const INADDRSZ: usize = 4;

/// Size of IPv6 address in bytes (16)
pub const IN6ADDRSZ: usize = 16;

/// Escape character for presentation format domain names (internal to dnsmasq)
pub const NAME_ESCAPE: u8 = 1;

// ============================================================================
// DNS Response Codes (RCODE) - RFC 1035 Section 4.1.1
// ============================================================================

/// DNS response code 0: No error condition
pub const NOERROR: u8 = 0;

/// DNS response code 1: Format error - query could not be interpreted
pub const FORMERR: u8 = 1;

/// DNS response code 2: Server failure - temporary failure
pub const SERVFAIL: u8 = 2;

/// DNS response code 3: Non-existent domain - name does not exist
pub const NXDOMAIN: u8 = 3;

/// DNS response code 4: Not implemented - query kind not supported
pub const NOTIMP: u8 = 4;

/// DNS response code 5: Query refused - operation refused for policy reasons
pub const REFUSED: u8 = 5;

// ============================================================================
// DNS Opcodes - RFC 1035 Section 4.1.1
// ============================================================================

/// DNS opcode 0: Standard query
pub const QUERY: u8 = 0;

// ============================================================================
// DNS Classes - RFC 1035 Section 3.2.4
// ============================================================================

/// DNS class 1: Internet (IN) - standard class for Internet DNS
pub const C_IN: u16 = 1;

/// DNS class 3: CHAOS network (rarely used)
pub const C_CHAOS: u16 = 3;

/// DNS class 4: Hesiod name service
pub const C_HESIOD: u16 = 4;

/// DNS class 255: Wildcard match (ANY) for queries
pub const C_ANY: u16 = 255;

// ============================================================================
// DNS Resource Record Types - RFC 1035 and extensions
// ============================================================================

/// RR type 1: IPv4 address record
pub const T_A: u16 = 1;

/// RR type 2: Authoritative name server
pub const T_NS: u16 = 2;

/// RR type 3: Mail destination (obsolete)
pub const T_MD: u16 = 3;

/// RR type 4: Mail forwarder (obsolete)
pub const T_MF: u16 = 4;

/// RR type 5: Canonical name (alias)
pub const T_CNAME: u16 = 5;

/// RR type 6: Start of authority
pub const T_SOA: u16 = 6;

/// RR type 7: Mailbox domain name (experimental)
pub const T_MB: u16 = 7;

/// RR type 8: Mail group member (experimental)
pub const T_MG: u16 = 8;

/// RR type 9: Mail rename domain name (experimental)
pub const T_MR: u16 = 9;

/// RR type 12: Pointer record (reverse DNS)
pub const T_PTR: u16 = 12;

/// RR type 14: Mailbox information
pub const T_MINFO: u16 = 14;

/// RR type 15: Mail exchange
pub const T_MX: u16 = 15;

/// RR type 16: Text record
pub const T_TXT: u16 = 16;

/// RR type 17: Responsible person
pub const T_RP: u16 = 17;

/// RR type 18: AFS database location
pub const T_AFSDB: u16 = 18;

/// RR type 21: Route through
pub const T_RT: u16 = 21;

/// RR type 24: Signature (original DNSSEC, obsolete)
pub const T_SIG: u16 = 24;

/// RR type 26: Pointer to X.400 mapping information
pub const T_PX: u16 = 26;

/// RR type 28: IPv6 address record (RFC 3596)
pub const T_AAAA: u16 = 28;

/// RR type 30: Next record (original DNSSEC, obsolete)
pub const T_NXT: u16 = 30;

/// RR type 33: Service locator (RFC 2763)
pub const T_SRV: u16 = 33;

/// RR type 35: Naming authority pointer (RFC 2915)
pub const T_NAPTR: u16 = 35;

/// RR type 36: Key exchanger
pub const T_KX: u16 = 36;

/// RR type 39: Delegation name (RFC 6672)
pub const T_DNAME: u16 = 39;

/// RR type 41: EDNS0 option (pseudo-record, RFC 6891)
pub const T_OPT: u16 = 41;

/// RR type 43: Delegation signer (DNSSEC, RFC 4034)
pub const T_DS: u16 = 43;

/// RR type 46: Resource record signature (DNSSEC, RFC 4034)
pub const T_RRSIG: u16 = 46;

/// RR type 47: Next secure record (DNSSEC, RFC 4034)
pub const T_NSEC: u16 = 47;

/// RR type 48: DNS public key (DNSSEC, RFC 4034)
pub const T_DNSKEY: u16 = 48;

/// RR type 50: Next secure record version 3 (DNSSEC, RFC 5155)
pub const T_NSEC3: u16 = 50;

/// RR type 249: Transaction key (RFC 2930)
pub const T_TKEY: u16 = 249;

/// RR type 250: Transaction signature (RFC 2845)
pub const T_TSIG: u16 = 250;

/// RR type 252: Zone transfer (query type only)
pub const T_AXFR: u16 = 252;

/// RR type 253: Mailbox-related records (query type)
pub const T_MAILB: u16 = 253;

/// RR type 255: All records (query type)
pub const T_ANY: u16 = 255;

/// RR type 257: Certification authority authorization (RFC 6844)
pub const T_CAA: u16 = 257;

// ============================================================================
// Loop Detection Constants (dnsmasq-specific)
// ============================================================================

/// Resource record type for loop detection (special query)
pub const LOOP_TEST_TYPE: u16 = T_TXT;

/// Domain name used for loop detection probes
pub const LOOP_TEST_DOMAIN: &str = "test.";

// ============================================================================
// DNS Opcode Enum
// ============================================================================

/// DNS operation codes (OPCODE) per RFC 1035 Section 4.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOpcode {
    /// Standard query (OPCODE 0)
    Query,
    /// Inverse query (OPCODE 1) - obsolete
    IQuery,
    /// Server status request (OPCODE 2)
    Status,
}

impl DnsOpcode {
    /// Convert opcode value to enum variant
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            QUERY => Some(DnsOpcode::Query),
            _ => None,
        }
    }

    /// Convert enum variant to opcode value
    pub fn to_code(self) -> u8 {
        match self {
            DnsOpcode::Query => QUERY,
            DnsOpcode::IQuery => 1,
            DnsOpcode::Status => 2,
        }
    }
}

// ============================================================================
// DNS Resource Record Type Enum
// ============================================================================

/// DNS resource record types per RFC 1035 and extensions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRrType {
    /// IPv4 address (type 1)
    A,
    /// Name server (type 2)
    NS,
    /// Canonical name (type 5)
    CNAME,
    /// Start of authority (type 6)
    SOA,
    /// Pointer record (type 12)
    PTR,
    /// Mail exchange (type 15)
    MX,
    /// Text record (type 16)
    TXT,
    /// IPv6 address (type 28, RFC 3596)
    AAAA,
    /// Service locator (type 33, RFC 2763)
    SRV,
    /// Naming authority pointer (type 35, RFC 2915)
    NAPTR,
    /// Delegation signer (type 43, DNSSEC)
    DS,
    /// Resource record signature (type 46, DNSSEC)
    RRSIG,
    /// Next secure (type 47, DNSSEC)
    NSEC,
    /// DNS public key (type 48, DNSSEC)
    DNSKEY,
    /// Next secure version 3 (type 50, DNSSEC)
    NSEC3,
    /// Transaction signature (type 250, RFC 2845)
    TSIG,
    /// Zone transfer (type 252, query only)
    AXFR,
    /// All records (type 255, query only)
    ANY,
    /// Certification authority authorization (type 257, RFC 6844)
    CAA,
    /// Other/unknown type with numeric value
    Other(u16),
}

impl DnsRrType {
    /// Convert RR type value to enum variant
    pub fn from_code(code: u16) -> Self {
        match code {
            T_A => DnsRrType::A,
            T_NS => DnsRrType::NS,
            T_CNAME => DnsRrType::CNAME,
            T_SOA => DnsRrType::SOA,
            T_PTR => DnsRrType::PTR,
            T_MX => DnsRrType::MX,
            T_TXT => DnsRrType::TXT,
            T_AAAA => DnsRrType::AAAA,
            T_SRV => DnsRrType::SRV,
            T_NAPTR => DnsRrType::NAPTR,
            T_DS => DnsRrType::DS,
            T_RRSIG => DnsRrType::RRSIG,
            T_NSEC => DnsRrType::NSEC,
            T_DNSKEY => DnsRrType::DNSKEY,
            T_NSEC3 => DnsRrType::NSEC3,
            T_TSIG => DnsRrType::TSIG,
            T_AXFR => DnsRrType::AXFR,
            T_ANY => DnsRrType::ANY,
            T_CAA => DnsRrType::CAA,
            other => DnsRrType::Other(other),
        }
    }

    /// Convert enum variant to RR type value
    pub fn to_code(self) -> u16 {
        match self {
            DnsRrType::A => T_A,
            DnsRrType::NS => T_NS,
            DnsRrType::CNAME => T_CNAME,
            DnsRrType::SOA => T_SOA,
            DnsRrType::PTR => T_PTR,
            DnsRrType::MX => T_MX,
            DnsRrType::TXT => T_TXT,
            DnsRrType::AAAA => T_AAAA,
            DnsRrType::SRV => T_SRV,
            DnsRrType::NAPTR => T_NAPTR,
            DnsRrType::DS => T_DS,
            DnsRrType::RRSIG => T_RRSIG,
            DnsRrType::NSEC => T_NSEC,
            DnsRrType::DNSKEY => T_DNSKEY,
            DnsRrType::NSEC3 => T_NSEC3,
            DnsRrType::TSIG => T_TSIG,
            DnsRrType::AXFR => T_AXFR,
            DnsRrType::ANY => T_ANY,
            DnsRrType::CAA => T_CAA,
            DnsRrType::Other(code) => code,
        }
    }
}

// ============================================================================
// EDNS0 Option Codes
// ============================================================================

/// EDNS0 option code for client subnet information (RFC 7871)
pub const EDNS0_OPTION_CLIENT_SUBNET: u16 = 8;

/// EDNS0 option code for extended DNS errors (RFC 8914)
pub const EDNS0_OPTION_EDE: u16 = 15;

/// EDNS0 option code for MAC address (dyndns.org temporary assignment)
pub const EDNS0_OPTION_MAC: u16 = 65001;

/// EDNS0 option code for Cisco Umbrella identification
pub const EDNS0_OPTION_UMBRELLA: u16 = 20292;

/// EDNS0 option code for Nominum device ID
pub const EDNS0_OPTION_NOMDEVICEID: u16 = 65073;

/// EDNS0 option code for Nominum CPE ID
pub const EDNS0_OPTION_NOMCPEID: u16 = 65074;

// ============================================================================
// DNS Header Flag Bit Masks (for hb3 and hb4 bytes)
// ============================================================================

/// Query/Response flag bit in header byte 3 (bit 7, mask 0x80)
pub const HB3_QR: u8 = 0x80;

/// OPCODE field mask in header byte 3 (bits 6-3, mask 0x78)
pub const HB3_OPCODE: u8 = 0x78;

/// Authoritative Answer flag in header byte 3 (bit 2, mask 0x04)
pub const HB3_AA: u8 = 0x04;

/// Truncation flag in header byte 3 (bit 1, mask 0x02)
pub const HB3_TC: u8 = 0x02;

/// Recursion Desired flag in header byte 3 (bit 0, mask 0x01)
pub const HB3_RD: u8 = 0x01;

/// Recursion Available flag in header byte 4 (bit 7, mask 0x80)
pub const HB4_RA: u8 = 0x80;

/// Authenticated Data flag in header byte 4 (bit 5, mask 0x20)
pub const HB4_AD: u8 = 0x20;

/// Checking Disabled flag in header byte 4 (bit 4, mask 0x10)
pub const HB4_CD: u8 = 0x10;

/// Response code field mask in header byte 4 (bits 3-0, mask 0x0f)
pub const HB4_RCODE: u8 = 0x0f;

// ============================================================================
// EDNS0 Option Enum
// ============================================================================

/// EDNS0 option types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdnsOption {
    /// Client subnet information (RFC 7871)
    ClientSubnet,
    /// Extended DNS error (RFC 8914)
    ExtendedDnsError,
    /// MAC address (vendor extension)
    Mac,
    /// Cisco Umbrella identification
    Umbrella,
    /// Nominum device ID
    NomDeviceId,
    /// Nominum CPE ID
    NomCpeId,
}

impl EdnsOption {
    /// Convert option code to enum variant
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            EDNS0_OPTION_CLIENT_SUBNET => Some(EdnsOption::ClientSubnet),
            EDNS0_OPTION_EDE => Some(EdnsOption::ExtendedDnsError),
            EDNS0_OPTION_MAC => Some(EdnsOption::Mac),
            EDNS0_OPTION_UMBRELLA => Some(EdnsOption::Umbrella),
            EDNS0_OPTION_NOMDEVICEID => Some(EdnsOption::NomDeviceId),
            EDNS0_OPTION_NOMCPEID => Some(EdnsOption::NomCpeId),
            _ => None,
        }
    }

    /// Convert enum variant to option code
    pub fn to_code(self) -> u16 {
        match self {
            EdnsOption::ClientSubnet => EDNS0_OPTION_CLIENT_SUBNET,
            EdnsOption::ExtendedDnsError => EDNS0_OPTION_EDE,
            EdnsOption::Mac => EDNS0_OPTION_MAC,
            EdnsOption::Umbrella => EDNS0_OPTION_UMBRELLA,
            EdnsOption::NomDeviceId => EDNS0_OPTION_NOMDEVICEID,
            EdnsOption::NomCpeId => EDNS0_OPTION_NOMCPEID,
        }
    }
}

// ============================================================================
// Response Code Enum
// ============================================================================

/// DNS response codes with type safety
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    /// No error (RCODE 0)
    NoError,
    /// Format error (RCODE 1)
    FormErr,
    /// Server failure (RCODE 2)
    ServFail,
    /// Non-existent domain (RCODE 3)
    NxDomain,
    /// Not implemented (RCODE 4)
    NotImp,
    /// Query refused (RCODE 5)
    Refused,
}

impl ResponseCode {
    /// Convert RCODE value to enum variant
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            NOERROR => Some(ResponseCode::NoError),
            FORMERR => Some(ResponseCode::FormErr),
            SERVFAIL => Some(ResponseCode::ServFail),
            NXDOMAIN => Some(ResponseCode::NxDomain),
            NOTIMP => Some(ResponseCode::NotImp),
            REFUSED => Some(ResponseCode::Refused),
            _ => None,
        }
    }

    /// Convert enum variant to RCODE value
    pub fn to_code(self) -> u8 {
        match self {
            ResponseCode::NoError => NOERROR,
            ResponseCode::FormErr => FORMERR,
            ResponseCode::ServFail => SERVFAIL,
            ResponseCode::NxDomain => NXDOMAIN,
            ResponseCode::NotImp => NOTIMP,
            ResponseCode::Refused => REFUSED,
        }
    }
}

/// Type alias for DNS response code (preferred name in public API)
pub type DnsRcode = ResponseCode;

// ============================================================================
// Extended DNS Error Codes (RFC 8914)
// ============================================================================

/// Extended DNS error codes per RFC 8914
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedDnsError {
    /// No extended error available (dnsmasq internal)
    Unset,
    /// Other error (EDE 0)
    Other,
    /// Unsupported DNSKEY algorithm (EDE 1)
    UnsupportedDnskeyAlgorithm,
    /// Unsupported DS digest type (EDE 2)
    UnsupportedDsDigest,
    /// Stale answer (EDE 3)
    Stale,
    /// Forged answer (EDE 4)
    Forged,
    /// DNSSEC indeterminate (EDE 5)
    DnssecIndeterminate,
    /// DNSSEC bogus (EDE 6)
    DnssecBogus,
    /// Signature expired (EDE 7)
    SignatureExpired,
    /// Signature not yet valid (EDE 8)
    SignatureNotYetValid,
    /// DNSKEY missing (EDE 9)
    DnskeyMissing,
    /// RRSIGs missing (EDE 10)
    RrsigsMissing,
    /// No zone key bit set (EDE 11)
    NoZoneKeyBitSet,
    /// NSEC missing (EDE 12)
    NsecMissing,
    /// Cached error (EDE 13)
    CachedError,
    /// Not ready (EDE 14)
    NotReady,
    /// Blocked (EDE 15)
    Blocked,
    /// Censored (EDE 16)
    Censored,
    /// Filtered (EDE 17)
    Filtered,
    /// Prohibited (EDE 18)
    Prohibited,
    /// Stale NXDOMAIN (EDE 19)
    StaleNxdomain,
    /// Not authoritative (EDE 20)
    NotAuthoritative,
    /// Not supported (EDE 21)
    NotSupported,
    /// No reachable authority (EDE 22)
    NoReachableAuthority,
    /// Network error (EDE 23)
    NetworkError,
    /// Invalid data (EDE 24)
    InvalidData,
}

impl ExtendedDnsError {
    /// Convert EDE code to enum variant
    pub fn from_code(code: i16) -> Self {
        match code {
            -1 => ExtendedDnsError::Unset,
            0 => ExtendedDnsError::Other,
            1 => ExtendedDnsError::UnsupportedDnskeyAlgorithm,
            2 => ExtendedDnsError::UnsupportedDsDigest,
            3 => ExtendedDnsError::Stale,
            4 => ExtendedDnsError::Forged,
            5 => ExtendedDnsError::DnssecIndeterminate,
            6 => ExtendedDnsError::DnssecBogus,
            7 => ExtendedDnsError::SignatureExpired,
            8 => ExtendedDnsError::SignatureNotYetValid,
            9 => ExtendedDnsError::DnskeyMissing,
            10 => ExtendedDnsError::RrsigsMissing,
            11 => ExtendedDnsError::NoZoneKeyBitSet,
            12 => ExtendedDnsError::NsecMissing,
            13 => ExtendedDnsError::CachedError,
            14 => ExtendedDnsError::NotReady,
            15 => ExtendedDnsError::Blocked,
            16 => ExtendedDnsError::Censored,
            17 => ExtendedDnsError::Filtered,
            18 => ExtendedDnsError::Prohibited,
            19 => ExtendedDnsError::StaleNxdomain,
            20 => ExtendedDnsError::NotAuthoritative,
            21 => ExtendedDnsError::NotSupported,
            22 => ExtendedDnsError::NoReachableAuthority,
            23 => ExtendedDnsError::NetworkError,
            24 => ExtendedDnsError::InvalidData,
            _ => ExtendedDnsError::Unset,
        }
    }

    /// Convert enum variant to EDE code
    pub fn to_code(self) -> i16 {
        match self {
            ExtendedDnsError::Unset => -1,
            ExtendedDnsError::Other => 0,
            ExtendedDnsError::UnsupportedDnskeyAlgorithm => 1,
            ExtendedDnsError::UnsupportedDsDigest => 2,
            ExtendedDnsError::Stale => 3,
            ExtendedDnsError::Forged => 4,
            ExtendedDnsError::DnssecIndeterminate => 5,
            ExtendedDnsError::DnssecBogus => 6,
            ExtendedDnsError::SignatureExpired => 7,
            ExtendedDnsError::SignatureNotYetValid => 8,
            ExtendedDnsError::DnskeyMissing => 9,
            ExtendedDnsError::RrsigsMissing => 10,
            ExtendedDnsError::NoZoneKeyBitSet => 11,
            ExtendedDnsError::NsecMissing => 12,
            ExtendedDnsError::CachedError => 13,
            ExtendedDnsError::NotReady => 14,
            ExtendedDnsError::Blocked => 15,
            ExtendedDnsError::Censored => 16,
            ExtendedDnsError::Filtered => 17,
            ExtendedDnsError::Prohibited => 18,
            ExtendedDnsError::StaleNxdomain => 19,
            ExtendedDnsError::NotAuthoritative => 20,
            ExtendedDnsError::NotSupported => 21,
            ExtendedDnsError::NoReachableAuthority => 22,
            ExtendedDnsError::NetworkError => 23,
            ExtendedDnsError::InvalidData => 24,
        }
    }
}

// ============================================================================
// DNS Header Structure
// ============================================================================

/// DNS message header structure (12 bytes fixed size per RFC 1035 Section 4.1.1)
///
/// This structure represents the fixed 12-byte header present in all DNS messages.
/// All multi-byte fields are stored in network byte order (big-endian).
///
/// # Memory Layout
///
/// ```text
/// Offset 0-1:   id (16 bits)
/// Offset 2:     hb3 (8 bits) - QR, OPCODE, AA, TC, RD flags
/// Offset 3:     hb4 (8 bits) - RA, Z, AD, CD, RCODE flags
/// Offset 4-5:   qdcount (16 bits)
/// Offset 6-7:   ancount (16 bits)
/// Offset 8-9:   nscount (16 bits)
/// Offset 10-11: arcount (16 bits)
/// ```
///
/// Total size: 12 bytes
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    /// Transaction ID for matching queries and responses
    id: u16,
    /// Header byte 3 containing QR, OPCODE, AA, TC, RD flags
    hb3: u8,
    /// Header byte 4 containing RA, Z, AD, CD, RCODE flags
    hb4: u8,
    /// Question count: Number of entries in question section
    qdcount: u16,
    /// Answer count: Number of resource records in answer section
    ancount: u16,
    /// Authority count: Number of name server records in authority section
    nscount: u16,
    /// Additional count: Number of records in additional section
    arcount: u16,
}

impl DnsHeader {
    /// Size of DNS header in bytes
    pub const SIZE: usize = 12;

    /// Create a new DNS header with default values
    ///
    /// # Returns
    ///
    /// A new `DnsHeader` with all fields initialized to zero
    pub fn new() -> Self {
        Self {
            id: 0,
            hb3: 0,
            hb4: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Parse DNS header from byte slice
    ///
    /// # Arguments
    ///
    /// * `bytes` - Byte slice containing DNS header (must be at least 12 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(DnsHeader)` - Successfully parsed header
    /// * `Err(&str)` - Error message if buffer is too small
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < Self::SIZE {
            return Err("Buffer too small for DNS header");
        }

        Ok(Self {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            hb3: bytes[2],
            hb4: bytes[3],
            qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
            ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
            nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
            arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    /// Serialize DNS header to bytes
    ///
    /// # Returns
    ///
    /// 12-byte array containing the serialized header in network byte order
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2] = self.hb3;
        bytes[3] = self.hb4;
        bytes[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        bytes
    }

    /// Get transaction ID
    pub fn id(&self) -> u16 {
        u16::from_be(self.id)
    }

    /// Set transaction ID
    pub fn set_id(&mut self, id: u16) {
        self.id = id.to_be();
    }

    /// Get QR (Query/Response) flag
    ///
    /// # Returns
    ///
    /// * `false` - Query (QR=0)
    /// * `true` - Response (QR=1)
    pub fn qr(&self) -> bool {
        (self.hb3 & HB3_QR) != 0
    }

    /// Set QR (Query/Response) flag
    ///
    /// # Arguments
    ///
    /// * `is_response` - true for response, false for query
    pub fn set_qr(&mut self, is_response: bool) {
        if is_response {
            self.hb3 |= HB3_QR;
        } else {
            self.hb3 &= !HB3_QR;
        }
    }

    /// Get OPCODE field value
    ///
    /// # Returns
    ///
    /// OPCODE value (0=QUERY, 1=IQUERY, 2=STATUS)
    pub fn opcode(&self) -> u8 {
        (self.hb3 & HB3_OPCODE) >> 3
    }

    /// Set OPCODE field value
    ///
    /// # Arguments
    ///
    /// * `opcode` - OPCODE value (0-15)
    pub fn set_opcode(&mut self, opcode: u8) {
        self.hb3 = (self.hb3 & !HB3_OPCODE) | ((opcode << 3) & HB3_OPCODE);
    }

    /// Get AA (Authoritative Answer) flag
    pub fn aa(&self) -> bool {
        (self.hb3 & HB3_AA) != 0
    }

    /// Set AA (Authoritative Answer) flag
    pub fn set_aa(&mut self, authoritative: bool) {
        if authoritative {
            self.hb3 |= HB3_AA;
        } else {
            self.hb3 &= !HB3_AA;
        }
    }

    /// Get TC (Truncation) flag
    pub fn tc(&self) -> bool {
        (self.hb3 & HB3_TC) != 0
    }

    /// Set TC (Truncation) flag
    pub fn set_tc(&mut self, truncated: bool) {
        if truncated {
            self.hb3 |= HB3_TC;
        } else {
            self.hb3 &= !HB3_TC;
        }
    }

    /// Get RD (Recursion Desired) flag
    pub fn rd(&self) -> bool {
        (self.hb3 & HB3_RD) != 0
    }

    /// Set RD (Recursion Desired) flag
    pub fn set_rd(&mut self, recursion_desired: bool) {
        if recursion_desired {
            self.hb3 |= HB3_RD;
        } else {
            self.hb3 &= !HB3_RD;
        }
    }

    /// Get RA (Recursion Available) flag
    pub fn ra(&self) -> bool {
        (self.hb4 & HB4_RA) != 0
    }

    /// Set RA (Recursion Available) flag
    pub fn set_ra(&mut self, recursion_available: bool) {
        if recursion_available {
            self.hb4 |= HB4_RA;
        } else {
            self.hb4 &= !HB4_RA;
        }
    }

    /// Get AD (Authenticated Data) flag
    pub fn ad(&self) -> bool {
        (self.hb4 & HB4_AD) != 0
    }

    /// Set AD (Authenticated Data) flag
    pub fn set_ad(&mut self, authenticated: bool) {
        if authenticated {
            self.hb4 |= HB4_AD;
        } else {
            self.hb4 &= !HB4_AD;
        }
    }

    /// Get CD (Checking Disabled) flag
    pub fn cd(&self) -> bool {
        (self.hb4 & HB4_CD) != 0
    }

    /// Set CD (Checking Disabled) flag
    pub fn set_cd(&mut self, checking_disabled: bool) {
        if checking_disabled {
            self.hb4 |= HB4_CD;
        } else {
            self.hb4 &= !HB4_CD;
        }
    }

    /// Get RCODE (Response Code) field value
    pub fn rcode(&self) -> u8 {
        self.hb4 & HB4_RCODE
    }

    /// Set RCODE (Response Code) field value
    ///
    /// # Arguments
    ///
    /// * `rcode` - Response code (0-15)
    pub fn set_rcode(&mut self, rcode: u8) {
        self.hb4 = (self.hb4 & !HB4_RCODE) | (rcode & HB4_RCODE);
    }

    /// Get question count
    pub fn qdcount(&self) -> u16 {
        u16::from_be(self.qdcount)
    }

    /// Set question count
    pub fn set_qdcount(&mut self, count: u16) {
        self.qdcount = count.to_be();
    }

    /// Get answer count
    pub fn ancount(&self) -> u16 {
        u16::from_be(self.ancount)
    }

    /// Set answer count
    pub fn set_ancount(&mut self, count: u16) {
        self.ancount = count.to_be();
    }

    /// Get authority count
    pub fn nscount(&self) -> u16 {
        u16::from_be(self.nscount)
    }

    /// Set authority count
    pub fn set_nscount(&mut self, count: u16) {
        self.nscount = count.to_be();
    }

    /// Get additional count
    pub fn arcount(&self) -> u16 {
        u16::from_be(self.arcount)
    }

    /// Set additional count
    pub fn set_arcount(&mut self, count: u16) {
        self.arcount = count.to_be();
    }
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header_size() {
        assert_eq!(std::mem::size_of::<DnsHeader>(), 12);
    }

    #[test]
    fn test_dns_header_new() {
        let header = DnsHeader::new();
        assert_eq!(header.id(), 0);
        assert_eq!(header.qr(), false);
        assert_eq!(header.opcode(), 0);
        assert_eq!(header.rcode(), 0);
        assert_eq!(header.qdcount(), 0);
        assert_eq!(header.ancount(), 0);
        assert_eq!(header.nscount(), 0);
        assert_eq!(header.arcount(), 0);
    }

    #[test]
    fn test_dns_header_flags() {
        let mut header = DnsHeader::new();

        // Test QR flag
        header.set_qr(true);
        assert_eq!(header.qr(), true);
        header.set_qr(false);
        assert_eq!(header.qr(), false);

        // Test AA flag
        header.set_aa(true);
        assert_eq!(header.aa(), true);

        // Test TC flag
        header.set_tc(true);
        assert_eq!(header.tc(), true);

        // Test RD flag
        header.set_rd(true);
        assert_eq!(header.rd(), true);

        // Test RA flag
        header.set_ra(true);
        assert_eq!(header.ra(), true);

        // Test AD flag
        header.set_ad(true);
        assert_eq!(header.ad(), true);

        // Test CD flag
        header.set_cd(true);
        assert_eq!(header.cd(), true);
    }

    #[test]
    fn test_dns_header_opcode() {
        let mut header = DnsHeader::new();
        header.set_opcode(2);
        assert_eq!(header.opcode(), 2);
    }

    #[test]
    fn test_dns_header_rcode() {
        let mut header = DnsHeader::new();
        header.set_rcode(NXDOMAIN);
        assert_eq!(header.rcode(), NXDOMAIN);
    }

    #[test]
    fn test_dns_header_counts() {
        let mut header = DnsHeader::new();
        header.set_qdcount(1);
        header.set_ancount(2);
        header.set_nscount(3);
        header.set_arcount(4);

        assert_eq!(header.qdcount(), 1);
        assert_eq!(header.ancount(), 2);
        assert_eq!(header.nscount(), 3);
        assert_eq!(header.arcount(), 4);
    }

    #[test]
    fn test_dns_header_serialization() {
        let mut header = DnsHeader::new();
        header.set_id(0x1234);
        header.set_qr(true);
        header.set_opcode(QUERY);
        header.set_rd(true);
        header.set_ra(true);
        header.set_rcode(NOERROR);
        header.set_qdcount(1);
        header.set_ancount(2);

        let bytes = header.to_bytes();
        let parsed = DnsHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.id(), header.id());
        assert_eq!(parsed.qr(), header.qr());
        assert_eq!(parsed.opcode(), header.opcode());
        assert_eq!(parsed.rd(), header.rd());
        assert_eq!(parsed.ra(), header.ra());
        assert_eq!(parsed.rcode(), header.rcode());
        assert_eq!(parsed.qdcount(), header.qdcount());
        assert_eq!(parsed.ancount(), header.ancount());
    }

    #[test]
    fn test_response_code_conversion() {
        assert_eq!(ResponseCode::NoError.to_code(), NOERROR);
        assert_eq!(ResponseCode::NxDomain.to_code(), NXDOMAIN);
        assert_eq!(ResponseCode::from_code(SERVFAIL), Some(ResponseCode::ServFail));
    }

    #[test]
    fn test_edns_option_conversion() {
        assert_eq!(EdnsOption::ClientSubnet.to_code(), EDNS0_OPTION_CLIENT_SUBNET);
        assert_eq!(EdnsOption::from_code(EDNS0_OPTION_EDE), Some(EdnsOption::ExtendedDnsError));
    }

    #[test]
    fn test_extended_dns_error_conversion() {
        assert_eq!(ExtendedDnsError::DnssecBogus.to_code(), 6);
        assert_eq!(ExtendedDnsError::from_code(3), ExtendedDnsError::Stale);
    }
}

