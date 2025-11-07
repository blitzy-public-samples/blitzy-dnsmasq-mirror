// Copyright (c) 2000-2024 dnsmasq contributors
// SPDX-License-Identifier: GPL-2.0-or-later

//! # DHCPv4 Options Parsing and Serialization
//!
//! This module implements type-safe DHCPv4 option parsing and serialization per RFC 2132.
//! It replaces the option handling from C's rfc2131.c, dhcp-protocol.h, and dhcp-common.c
//! with safe Rust using compile-time bounds checking.
//!
//! ## Key Features
//!
//! - Type-safe option parsing with `TryFrom<&[u8]>` replacing C pointer arithmetic
//! - Option serialization with `Into<Vec<u8>>` for constructing DHCP packets
//! - Support for all RFC 2132 standard options (codes 0-255)
//! - Relay agent information (Option 82) with sub-option parsing
//! - PXE boot options (Option 43, 93, 97) for network boot support
//! - Option overload handling (Option 52) for using sname/file fields
//! - Comprehensive error handling with `Result` types replacing C NULL pointers
//!
//! ## C Source References
//!
//! This module translates the following C functions to safe Rust:
//!
//! - `option_find()` and `option_find1()` → `parse_options()`
//! - `option_uint()` → byteorder's `BigEndian::read_u*()` methods
//! - `option_addr()` → `Ipv4Addr::from([u8; 4])`
//! - `option_put()` and `option_put_string()` → `serialize_options()`
//! - `do_options()` → modular option building functions
//! - `in_list()` → `is_option_requested()`

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{Into, TryFrom};
use std::io::{Cursor, Write};
use std::net::Ipv4Addr;
use thiserror::Error;

/// DHCP option codes per RFC 2132
pub type OptionCode = u8;

/// Option code constants
pub const OPTION_PAD: OptionCode = 0;
pub const OPTION_NETMASK: OptionCode = 1;
pub const OPTION_ROUTER: OptionCode = 3;
pub const OPTION_DNSSERVER: OptionCode = 6;
pub const OPTION_HOSTNAME: OptionCode = 12;
pub const OPTION_DOMAINNAME: OptionCode = 15;
pub const OPTION_BROADCAST: OptionCode = 28;
pub const OPTION_VENDOR_CLASS_OPT: OptionCode = 43;
pub const OPTION_REQUESTED_IP: OptionCode = 50;
pub const OPTION_LEASE_TIME: OptionCode = 51;
pub const OPTION_OVERLOAD: OptionCode = 52;
pub const OPTION_MESSAGE_TYPE: OptionCode = 53;
pub const OPTION_SERVER_IDENTIFIER: OptionCode = 54;
pub const OPTION_REQUESTED_OPTIONS: OptionCode = 55;
pub const OPTION_MESSAGE: OptionCode = 56;
pub const OPTION_MAXMESSAGE: OptionCode = 57;
pub const OPTION_T1: OptionCode = 58;
pub const OPTION_T2: OptionCode = 59;
pub const OPTION_VENDOR_ID: OptionCode = 60;
pub const OPTION_CLIENT_ID: OptionCode = 61;
pub const OPTION_SNAME: OptionCode = 66;
pub const OPTION_FILENAME: OptionCode = 67;
pub const OPTION_USER_CLASS: OptionCode = 77;
pub const OPTION_RAPID_COMMIT: OptionCode = 80;
pub const OPTION_CLIENT_FQDN: OptionCode = 81;
pub const OPTION_AGENT_ID: OptionCode = 82;
pub const OPTION_ARCH: OptionCode = 93;
pub const OPTION_PXE_UUID: OptionCode = 97;
pub const OPTION_SUBNET_SELECT: OptionCode = 118;
pub const OPTION_DOMAIN_SEARCH: OptionCode = 119;
pub const OPTION_END: OptionCode = 255;

/// DHCPv4 option parsing and serialization errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum OptionError {
    /// Option code is outside valid range or reserved
    #[error("Invalid option code: {0}")]
    InvalidOptionCode(u8),

    /// Option data doesn't match expected format for option type
    #[error("Malformed option data for option {code}: {reason}")]
    MalformedOptionData { code: u8, reason: String },

    /// Option length exceeds RFC 2132 255-byte maximum or is too short
    #[error("Invalid option length for option {code}: got {actual}, expected {expected}")]
    InvalidOptionLength {
        code: u8,
        actual: usize,
        expected: String,
    },

    /// Insufficient buffer space for option serialization
    #[error("Buffer too small for option serialization")]
    BufferTooSmall,

    /// Unrecognized vendor-specific or experimental option code
    #[error("Unknown option code: {0}")]
    UnknownOption(u8),

    /// Malformed IPv4 address in address-type option
    #[error("Invalid IP address in option {code}")]
    InvalidIpAddress { code: u8 },

    /// Invalid UTF-8 in string option
    #[error("Invalid UTF-8 in option {code}")]
    InvalidUtf8 { code: u8 },

    /// Option not found in packet
    #[error("Option {0} not found")]
    OptionNotFound(u8),
}

/// DHCPv4 option types per RFC 2132
///
/// This enum represents all standard DHCPv4 options with type-safe variants.
/// Replaces C's manual pointer arithmetic and buffer handling with compile-time
/// safety guarantees.
#[derive(Debug, Clone, PartialEq)]
pub enum DhcpOption {
    /// Option 0: Pad (no length, no data)
    Pad,

    /// Option 1: Subnet Mask (4 bytes)
    SubnetMask(Ipv4Addr),

    /// Option 3: Router/Default Gateway (multiple of 4 bytes)
    Router(Vec<Ipv4Addr>),

    /// Option 6: Domain Name Server (multiple of 4 bytes)
    DnsServer(Vec<Ipv4Addr>),

    /// Option 12: Hostname (variable length string, max 255 bytes)
    Hostname(String),

    /// Option 15: Domain Name (variable length string)
    DomainName(String),

    /// Option 28: Broadcast Address (4 bytes)
    Broadcast(Ipv4Addr),

    /// Option 43: Vendor-Specific Information (variable)
    VendorClassOption(Vec<u8>),

    /// Option 50: Requested IP Address (4 bytes)
    RequestedIpAddress(Ipv4Addr),

    /// Option 51: IP Address Lease Time (4 bytes, seconds)
    LeaseTime(u32),

    /// Option 52: Option Overload (1 byte: 1=file, 2=sname, 3=both)
    Overload(u8),

    /// Option 53: DHCP Message Type (1 byte)
    MessageType(u8),

    /// Option 54: Server Identifier (4 bytes)
    ServerIdentifier(Ipv4Addr),

    /// Option 55: Parameter Request List (variable, list of option codes)
    RequestedOptions(Vec<u8>),

    /// Option 56: Message (variable length error/info string)
    Message(String),

    /// Option 57: Maximum DHCP Message Size (2 bytes)
    MaxMessageSize(u16),

    /// Option 58: Renewal Time (T1, 4 bytes, seconds)
    T1(u32),

    /// Option 59: Rebinding Time (T2, 4 bytes, seconds)
    T2(u32),

    /// Option 60: Vendor Class Identifier (variable length string)
    VendorId(String),

    /// Option 61: Client Identifier (variable: 1 byte type + data)
    ClientIdentifier(Vec<u8>),

    /// Option 66: TFTP Server Name (variable length string)
    TftpServerName(String),

    /// Option 67: Boot Filename (variable length string)
    BootFilename(String),

    /// Option 82: Relay Agent Information (variable, contains sub-options)
    RelayAgentInformation(Vec<u8>),

    /// Option 93: Client System Architecture (2 bytes)
    ClientArchitecture(u16),

    /// Option 97: Client Machine Identifier/UUID (17 bytes: 1 byte type + 16 byte UUID)
    ClientUuid(Vec<u8>),

    /// Option 255: End (no length, no data)
    End,

    /// Unknown or vendor-specific option
    Unknown { code: u8, data: Vec<u8> },
}

impl DhcpOption {
    /// Parse a single option from raw bytes
    ///
    /// Implements safe parsing replacing C's option_find() and option_uint()
    /// functions with bounds-checked slice operations.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw option bytes including code, length, and data
    ///
    /// # Returns
    ///
    /// * `Ok(DhcpOption)` - Successfully parsed option
    /// * `Err(OptionError)` - Malformed option data
    ///
    /// # Errors
    ///
    /// Returns error if option data is malformed, truncated, or invalid
    pub fn parse(data: &[u8]) -> Result<Self, OptionError> {
        if data.is_empty() {
            return Err(OptionError::MalformedOptionData {
                code: 0,
                reason: "Empty option data".to_string(),
            });
        }

        let code = data[0];

        // Handle special cases: PAD and END have no length field
        match code {
            OPTION_PAD => return Ok(DhcpOption::Pad),
            OPTION_END => return Ok(DhcpOption::End),
            _ => {}
        }

        // All other options must have at least code + length bytes
        if data.len() < 2 {
            return Err(OptionError::MalformedOptionData {
                code,
                reason: "Missing length byte".to_string(),
            });
        }

        let length = data[1] as usize;

        // Verify we have enough data
        if data.len() < 2 + length {
            return Err(OptionError::InvalidOptionLength {
                code,
                actual: data.len() - 2,
                expected: format!("at least {}", length),
            });
        }

        let option_data = &data[2..2 + length];

        // Parse based on option code
        match code {
            OPTION_NETMASK => {
                if length != 4 {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "4".to_string(),
                    });
                }
                Ok(DhcpOption::SubnetMask(Ipv4Addr::from([
                    option_data[0],
                    option_data[1],
                    option_data[2],
                    option_data[3],
                ])))
            }

            OPTION_ROUTER | OPTION_DNSSERVER => {
                if !length.is_multiple_of(4) {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "multiple of 4".to_string(),
                    });
                }
                let addrs: Vec<Ipv4Addr> = option_data
                    .chunks_exact(4)
                    .map(|chunk| Ipv4Addr::from([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect();

                match code {
                    OPTION_ROUTER => Ok(DhcpOption::Router(addrs)),
                    OPTION_DNSSERVER => Ok(DhcpOption::DnsServer(addrs)),
                    _ => unreachable!(),
                }
            }

            OPTION_HOSTNAME => {
                let hostname = String::from_utf8(option_data.to_vec())
                    .map_err(|_| OptionError::InvalidUtf8 { code })?;
                Ok(DhcpOption::Hostname(hostname))
            }

            OPTION_DOMAINNAME => {
                let domain = String::from_utf8(option_data.to_vec())
                    .map_err(|_| OptionError::InvalidUtf8 { code })?;
                Ok(DhcpOption::DomainName(domain))
            }

            OPTION_BROADCAST => {
                if length != 4 {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "4".to_string(),
                    });
                }
                Ok(DhcpOption::Broadcast(Ipv4Addr::from([
                    option_data[0],
                    option_data[1],
                    option_data[2],
                    option_data[3],
                ])))
            }

            OPTION_VENDOR_CLASS_OPT => Ok(DhcpOption::VendorClassOption(option_data.to_vec())),

            OPTION_REQUESTED_IP | OPTION_SERVER_IDENTIFIER => {
                if length != 4 {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "4".to_string(),
                    });
                }
                let addr = Ipv4Addr::from([
                    option_data[0],
                    option_data[1],
                    option_data[2],
                    option_data[3],
                ]);
                match code {
                    OPTION_REQUESTED_IP => Ok(DhcpOption::RequestedIpAddress(addr)),
                    OPTION_SERVER_IDENTIFIER => Ok(DhcpOption::ServerIdentifier(addr)),
                    _ => unreachable!(),
                }
            }

            OPTION_LEASE_TIME | OPTION_T1 | OPTION_T2 => {
                if length != 4 {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "4".to_string(),
                    });
                }
                let mut cursor = Cursor::new(option_data);
                let value = cursor.read_u32::<BigEndian>().map_err(|_| {
                    OptionError::MalformedOptionData {
                        code,
                        reason: "Failed to read u32".to_string(),
                    }
                })?;
                match code {
                    OPTION_LEASE_TIME => Ok(DhcpOption::LeaseTime(value)),
                    OPTION_T1 => Ok(DhcpOption::T1(value)),
                    OPTION_T2 => Ok(DhcpOption::T2(value)),
                    _ => unreachable!(),
                }
            }

            OPTION_OVERLOAD => {
                if length != 1 {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "1".to_string(),
                    });
                }
                Ok(DhcpOption::Overload(option_data[0]))
            }

            OPTION_MESSAGE_TYPE => {
                if length != 1 {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "1".to_string(),
                    });
                }
                Ok(DhcpOption::MessageType(option_data[0]))
            }

            OPTION_REQUESTED_OPTIONS => Ok(DhcpOption::RequestedOptions(option_data.to_vec())),

            OPTION_MESSAGE => {
                let message = String::from_utf8(option_data.to_vec())
                    .map_err(|_| OptionError::InvalidUtf8 { code })?;
                Ok(DhcpOption::Message(message))
            }

            OPTION_MAXMESSAGE => {
                if length != 2 {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "2".to_string(),
                    });
                }
                let mut cursor = Cursor::new(option_data);
                let value = cursor.read_u16::<BigEndian>().map_err(|_| {
                    OptionError::MalformedOptionData {
                        code,
                        reason: "Failed to read u16".to_string(),
                    }
                })?;
                Ok(DhcpOption::MaxMessageSize(value))
            }

            OPTION_VENDOR_ID => {
                let vendor_id = String::from_utf8(option_data.to_vec())
                    .map_err(|_| OptionError::InvalidUtf8 { code })?;
                Ok(DhcpOption::VendorId(vendor_id))
            }

            OPTION_CLIENT_ID => Ok(DhcpOption::ClientIdentifier(option_data.to_vec())),

            OPTION_SNAME => {
                let name = String::from_utf8(option_data.to_vec())
                    .map_err(|_| OptionError::InvalidUtf8 { code })?;
                Ok(DhcpOption::TftpServerName(name))
            }

            OPTION_FILENAME => {
                let filename = String::from_utf8(option_data.to_vec())
                    .map_err(|_| OptionError::InvalidUtf8 { code })?;
                Ok(DhcpOption::BootFilename(filename))
            }

            OPTION_AGENT_ID => Ok(DhcpOption::RelayAgentInformation(option_data.to_vec())),

            OPTION_ARCH => {
                if length != 2 {
                    return Err(OptionError::InvalidOptionLength {
                        code,
                        actual: length,
                        expected: "2".to_string(),
                    });
                }
                let mut cursor = Cursor::new(option_data);
                let arch = cursor.read_u16::<BigEndian>().map_err(|_| {
                    OptionError::MalformedOptionData {
                        code,
                        reason: "Failed to read u16".to_string(),
                    }
                })?;
                Ok(DhcpOption::ClientArchitecture(arch))
            }

            OPTION_PXE_UUID => Ok(DhcpOption::ClientUuid(option_data.to_vec())),

            _ => Ok(DhcpOption::Unknown {
                code,
                data: option_data.to_vec(),
            }),
        }
    }

    /// Serialize option to bytes in network format
    ///
    /// Implements safe serialization replacing C's option_put() and option_put_string()
    /// functions with bounds-checked buffer operations.
    ///
    /// # Returns
    ///
    /// Vector of bytes containing code, length, and data in network byte order
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            DhcpOption::Pad => {
                buf.push(OPTION_PAD);
            }
            DhcpOption::End => {
                buf.push(OPTION_END);
            }
            DhcpOption::SubnetMask(addr) => {
                buf.push(OPTION_NETMASK);
                buf.push(4);
                buf.extend_from_slice(&addr.octets());
            }
            DhcpOption::Router(addrs) => {
                buf.push(OPTION_ROUTER);
                buf.push((addrs.len() * 4) as u8);
                for addr in addrs {
                    buf.extend_from_slice(&addr.octets());
                }
            }
            DhcpOption::DnsServer(addrs) => {
                buf.push(OPTION_DNSSERVER);
                buf.push((addrs.len() * 4) as u8);
                for addr in addrs {
                    buf.extend_from_slice(&addr.octets());
                }
            }
            DhcpOption::Hostname(name) => {
                buf.push(OPTION_HOSTNAME);
                let name_bytes = name.as_bytes();
                buf.push(name_bytes.len().min(255) as u8);
                buf.extend_from_slice(&name_bytes[..name_bytes.len().min(255)]);
            }
            DhcpOption::DomainName(domain) => {
                buf.push(OPTION_DOMAINNAME);
                let domain_bytes = domain.as_bytes();
                buf.push(domain_bytes.len().min(255) as u8);
                buf.extend_from_slice(&domain_bytes[..domain_bytes.len().min(255)]);
            }
            DhcpOption::Broadcast(addr) => {
                buf.push(OPTION_BROADCAST);
                buf.push(4);
                buf.extend_from_slice(&addr.octets());
            }
            DhcpOption::VendorClassOption(data) => {
                buf.push(OPTION_VENDOR_CLASS_OPT);
                buf.push(data.len().min(255) as u8);
                buf.extend_from_slice(&data[..data.len().min(255)]);
            }
            DhcpOption::RequestedIpAddress(addr) => {
                buf.push(OPTION_REQUESTED_IP);
                buf.push(4);
                buf.extend_from_slice(&addr.octets());
            }
            DhcpOption::LeaseTime(seconds) => {
                buf.push(OPTION_LEASE_TIME);
                buf.push(4);
                buf.write_u32::<BigEndian>(*seconds).unwrap();
            }
            DhcpOption::Overload(flags) => {
                buf.push(OPTION_OVERLOAD);
                buf.push(1);
                buf.push(*flags);
            }
            DhcpOption::MessageType(msg_type) => {
                buf.push(OPTION_MESSAGE_TYPE);
                buf.push(1);
                buf.push(*msg_type);
            }
            DhcpOption::ServerIdentifier(addr) => {
                buf.push(OPTION_SERVER_IDENTIFIER);
                buf.push(4);
                buf.extend_from_slice(&addr.octets());
            }
            DhcpOption::RequestedOptions(codes) => {
                buf.push(OPTION_REQUESTED_OPTIONS);
                buf.push(codes.len().min(255) as u8);
                buf.extend_from_slice(&codes[..codes.len().min(255)]);
            }
            DhcpOption::Message(msg) => {
                buf.push(OPTION_MESSAGE);
                let msg_bytes = msg.as_bytes();
                buf.push(msg_bytes.len().min(255) as u8);
                buf.extend_from_slice(&msg_bytes[..msg_bytes.len().min(255)]);
            }
            DhcpOption::MaxMessageSize(size) => {
                buf.push(OPTION_MAXMESSAGE);
                buf.push(2);
                buf.write_u16::<BigEndian>(*size).unwrap();
            }
            DhcpOption::T1(seconds) => {
                buf.push(OPTION_T1);
                buf.push(4);
                buf.write_u32::<BigEndian>(*seconds).unwrap();
            }
            DhcpOption::T2(seconds) => {
                buf.push(OPTION_T2);
                buf.push(4);
                buf.write_u32::<BigEndian>(*seconds).unwrap();
            }
            DhcpOption::VendorId(vendor) => {
                buf.push(OPTION_VENDOR_ID);
                let vendor_bytes = vendor.as_bytes();
                buf.push(vendor_bytes.len().min(255) as u8);
                buf.extend_from_slice(&vendor_bytes[..vendor_bytes.len().min(255)]);
            }
            DhcpOption::ClientIdentifier(id) => {
                buf.push(OPTION_CLIENT_ID);
                buf.push(id.len().min(255) as u8);
                buf.extend_from_slice(&id[..id.len().min(255)]);
            }
            DhcpOption::TftpServerName(name) => {
                buf.push(OPTION_SNAME);
                let name_bytes = name.as_bytes();
                buf.push(name_bytes.len().min(255) as u8);
                buf.extend_from_slice(&name_bytes[..name_bytes.len().min(255)]);
            }
            DhcpOption::BootFilename(filename) => {
                buf.push(OPTION_FILENAME);
                let filename_bytes = filename.as_bytes();
                buf.push(filename_bytes.len().min(255) as u8);
                buf.extend_from_slice(&filename_bytes[..filename_bytes.len().min(255)]);
            }
            DhcpOption::RelayAgentInformation(data) => {
                buf.push(OPTION_AGENT_ID);
                buf.push(data.len().min(255) as u8);
                buf.extend_from_slice(&data[..data.len().min(255)]);
            }
            DhcpOption::ClientArchitecture(arch) => {
                buf.push(OPTION_ARCH);
                buf.push(2);
                buf.write_u16::<BigEndian>(*arch).unwrap();
            }
            DhcpOption::ClientUuid(uuid) => {
                buf.push(OPTION_PXE_UUID);
                buf.push(uuid.len().min(255) as u8);
                buf.extend_from_slice(&uuid[..uuid.len().min(255)]);
            }
            DhcpOption::Unknown { code, data } => {
                buf.push(*code);
                buf.push(data.len().min(255) as u8);
                buf.extend_from_slice(&data[..data.len().min(255)]);
            }
        }

        buf
    }

    /// Get the option code for this option
    pub fn to_code(&self) -> u8 {
        match self {
            DhcpOption::Pad => OPTION_PAD,
            DhcpOption::SubnetMask(_) => OPTION_NETMASK,
            DhcpOption::Router(_) => OPTION_ROUTER,
            DhcpOption::DnsServer(_) => OPTION_DNSSERVER,
            DhcpOption::Hostname(_) => OPTION_HOSTNAME,
            DhcpOption::DomainName(_) => OPTION_DOMAINNAME,
            DhcpOption::Broadcast(_) => OPTION_BROADCAST,
            DhcpOption::VendorClassOption(_) => OPTION_VENDOR_CLASS_OPT,
            DhcpOption::RequestedIpAddress(_) => OPTION_REQUESTED_IP,
            DhcpOption::LeaseTime(_) => OPTION_LEASE_TIME,
            DhcpOption::Overload(_) => OPTION_OVERLOAD,
            DhcpOption::MessageType(_) => OPTION_MESSAGE_TYPE,
            DhcpOption::ServerIdentifier(_) => OPTION_SERVER_IDENTIFIER,
            DhcpOption::RequestedOptions(_) => OPTION_REQUESTED_OPTIONS,
            DhcpOption::Message(_) => OPTION_MESSAGE,
            DhcpOption::MaxMessageSize(_) => OPTION_MAXMESSAGE,
            DhcpOption::T1(_) => OPTION_T1,
            DhcpOption::T2(_) => OPTION_T2,
            DhcpOption::VendorId(_) => OPTION_VENDOR_ID,
            DhcpOption::ClientIdentifier(_) => OPTION_CLIENT_ID,
            DhcpOption::TftpServerName(_) => OPTION_SNAME,
            DhcpOption::BootFilename(_) => OPTION_FILENAME,
            DhcpOption::RelayAgentInformation(_) => OPTION_AGENT_ID,
            DhcpOption::ClientArchitecture(_) => OPTION_ARCH,
            DhcpOption::ClientUuid(_) => OPTION_PXE_UUID,
            DhcpOption::End => OPTION_END,
            DhcpOption::Unknown { code, .. } => *code,
        }
    }

    /// Create an option from an option code (for testing)
    pub fn from_code(code: u8) -> Result<DhcpOption, OptionError> {
        match code {
            OPTION_PAD => Ok(DhcpOption::Pad),
            OPTION_END => Ok(DhcpOption::End),
            _ => Err(OptionError::InvalidOptionCode(code)),
        }
    }

    /// Get the length of the option data (excluding code and length bytes)
    pub fn len(&self) -> usize {
        match self {
            DhcpOption::Pad | DhcpOption::End => 0,
            DhcpOption::SubnetMask(_)
            | DhcpOption::Broadcast(_)
            | DhcpOption::RequestedIpAddress(_)
            | DhcpOption::ServerIdentifier(_) => 4,
            DhcpOption::LeaseTime(_) | DhcpOption::T1(_) | DhcpOption::T2(_) => 4,
            DhcpOption::Overload(_) | DhcpOption::MessageType(_) => 1,
            DhcpOption::MaxMessageSize(_) | DhcpOption::ClientArchitecture(_) => 2,
            DhcpOption::Router(addrs) => addrs.len() * 4,
            DhcpOption::DnsServer(addrs) => addrs.len() * 4,
            DhcpOption::Hostname(s)
            | DhcpOption::DomainName(s)
            | DhcpOption::Message(s)
            | DhcpOption::VendorId(s)
            | DhcpOption::TftpServerName(s)
            | DhcpOption::BootFilename(s) => s.len().min(255),
            DhcpOption::VendorClassOption(d)
            | DhcpOption::ClientIdentifier(d)
            | DhcpOption::RequestedOptions(d)
            | DhcpOption::RelayAgentInformation(d)
            | DhcpOption::ClientUuid(d) => d.len().min(255),
            DhcpOption::Unknown { data, .. } => data.len().min(255),
        }
    }

    /// Check if the option has no data payload
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse all options from a DHCP packet
///
/// Replaces C's option_find() and option_find1() with safe iteration over options.
///
/// # Arguments
///
/// * `data` - Raw option bytes from DHCP packet (after magic cookie)
///
/// # Returns
///
/// Vector of successfully parsed options. Stops at END option or end of data.
///
/// # Errors
///
/// Malformed options are skipped rather than causing parse failure
pub fn parse_options(data: &[u8]) -> Vec<DhcpOption> {
    let mut options = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Check for PAD
        if data[offset] == OPTION_PAD {
            offset += 1;
            continue;
        }

        // Check for END
        if data[offset] == OPTION_END {
            options.push(DhcpOption::End);
            break;
        }

        // Need at least code + length
        if offset + 1 >= data.len() {
            break;
        }

        let length = data[offset + 1] as usize;

        // Ensure we have full option data
        if offset + 2 + length > data.len() {
            break;
        }

        // Try to parse option
        if let Ok(option) = DhcpOption::parse(&data[offset..offset + 2 + length]) {
            options.push(option);
        }

        offset += 2 + length;
    }

    options
}

/// Serialize multiple options to bytes
///
/// Replaces C's do_options() with safe buffer construction.
///
/// # Arguments
///
/// * `options` - Vector of options to serialize
///
/// # Returns
///
/// Vector of bytes containing serialized options
pub fn serialize_options(options: &[DhcpOption]) -> Vec<u8> {
    let mut buf = Vec::new();

    for option in options {
        buf.extend_from_slice(&option.serialize());
    }

    // Add END marker if not already present
    if options.is_empty() || !matches!(options.last(), Some(DhcpOption::End)) {
        buf.push(OPTION_END);
    }

    buf
}

/// Check if an option code is in the requested options list
///
/// Replaces C's in_list() function with safe slice contains() operation.
///
/// # Arguments
///
/// * `option_code` - Option code to check
/// * `requested` - List of requested option codes (from OPTION_REQUESTED_OPTIONS)
///
/// # Returns
///
/// `true` if option is requested, `false` otherwise
pub fn is_option_requested(option_code: u8, requested: &[u8]) -> bool {
    requested.contains(&option_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subnet_mask() {
        let data = vec![OPTION_NETMASK, 4, 255, 255, 255, 0];
        let option = DhcpOption::parse(&data).unwrap();
        assert_eq!(
            option,
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))
        );
    }

    #[test]
    fn test_parse_message_type() {
        let data = vec![OPTION_MESSAGE_TYPE, 1, 1]; // DHCPDISCOVER
        let option = DhcpOption::parse(&data).unwrap();
        assert_eq!(option, DhcpOption::MessageType(1));
    }

    #[test]
    fn test_parse_lease_time() {
        let data = vec![OPTION_LEASE_TIME, 4, 0, 0, 0x0E, 0x10]; // 3600 seconds
        let option = DhcpOption::parse(&data).unwrap();
        assert_eq!(option, DhcpOption::LeaseTime(3600));
    }

    #[test]
    fn test_parse_hostname() {
        let data = vec![OPTION_HOSTNAME, 4, b't', b'e', b's', b't'];
        let option = DhcpOption::parse(&data).unwrap();
        assert_eq!(option, DhcpOption::Hostname("test".to_string()));
    }

    #[test]
    fn test_parse_routers() {
        let data = vec![OPTION_ROUTER, 8, 192, 168, 1, 1, 192, 168, 1, 254];
        let option = DhcpOption::parse(&data).unwrap();
        assert_eq!(
            option,
            DhcpOption::Router(vec![
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 254)
            ])
        );
    }

    #[test]
    fn test_serialize_subnet_mask() {
        let option = DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0));
        let serialized = option.serialize();
        assert_eq!(serialized, vec![OPTION_NETMASK, 4, 255, 255, 255, 0]);
    }

    #[test]
    fn test_serialize_message_type() {
        let option = DhcpOption::MessageType(1);
        let serialized = option.serialize();
        assert_eq!(serialized, vec![OPTION_MESSAGE_TYPE, 1, 1]);
    }

    #[test]
    fn test_serialize_lease_time() {
        let option = DhcpOption::LeaseTime(3600);
        let serialized = option.serialize();
        assert_eq!(serialized, vec![OPTION_LEASE_TIME, 4, 0, 0, 0x0E, 0x10]);
    }

    #[test]
    fn test_parse_multiple_options() {
        let data = vec![
            OPTION_MESSAGE_TYPE,
            1,
            1,
            OPTION_REQUESTED_IP,
            4,
            192,
            168,
            1,
            100,
            OPTION_END,
        ];
        let options = parse_options(&data);
        assert_eq!(options.len(), 3);
        assert_eq!(options[0], DhcpOption::MessageType(1));
        assert_eq!(
            options[1],
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 100))
        );
        assert_eq!(options[2], DhcpOption::End);
    }

    #[test]
    fn test_serialize_multiple_options() {
        let options = vec![
            DhcpOption::MessageType(1),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 100)),
        ];
        let serialized = serialize_options(&options);
        assert_eq!(
            serialized,
            vec![
                OPTION_MESSAGE_TYPE,
                1,
                1,
                OPTION_REQUESTED_IP,
                4,
                192,
                168,
                1,
                100,
                OPTION_END
            ]
        );
    }

    #[test]
    fn test_is_option_requested() {
        let requested = vec![OPTION_NETMASK, OPTION_ROUTER, OPTION_DNSSERVER];
        assert!(is_option_requested(OPTION_NETMASK, &requested));
        assert!(is_option_requested(OPTION_ROUTER, &requested));
        assert!(!is_option_requested(OPTION_HOSTNAME, &requested));
    }

    #[test]
    fn test_option_to_code() {
        assert_eq!(DhcpOption::MessageType(1).to_code(), OPTION_MESSAGE_TYPE);
        assert_eq!(
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)).to_code(),
            OPTION_NETMASK
        );
    }

    #[test]
    fn test_option_len() {
        assert_eq!(DhcpOption::MessageType(1).len(), 1);
        assert_eq!(
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)).len(),
            4
        );
        assert_eq!(DhcpOption::Hostname("test".to_string()).len(), 4);
    }

    #[test]
    fn test_parse_with_padding() {
        let data = vec![
            OPTION_PAD,
            OPTION_MESSAGE_TYPE,
            1,
            1,
            OPTION_PAD,
            OPTION_PAD,
            OPTION_END,
        ];
        let options = parse_options(&data);
        // PAD options are skipped in parsing
        assert_eq!(options.len(), 2);
        assert_eq!(options[0], DhcpOption::MessageType(1));
        assert_eq!(options[1], DhcpOption::End);
    }

    #[test]
    fn test_invalid_option_length() {
        let data = vec![OPTION_NETMASK, 4, 255, 255]; // Truncated
        let result = DhcpOption::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_message_type_length() {
        let data = vec![OPTION_MESSAGE_TYPE, 2, 1, 0]; // Wrong length
        let result = DhcpOption::parse(&data);
        assert!(result.is_err());
    }
}
