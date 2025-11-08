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

//! TFTP Protocol Implementation
//!
//! This module provides TFTP (Trivial File Transfer Protocol) protocol constants,
//! packet structures, and parsing/serialization logic implementing:
//! - RFC 1350: The TFTP Protocol (Revision 2)
//! - RFC 2347: TFTP Option Extension
//! - RFC 2348: TFTP Blocksize Option
//! - RFC 2349: TFTP Timeout Interval and Transfer Size Options
//!
//! The implementation provides safe Rust types for all TFTP packet formats,
//! replacing C's unsafe pointer casting and manual byte manipulation with
//! compile-time memory safety guarantees while maintaining protocol compatibility.
//!
//! # Packet Types
//!
//! - **RRQ/WRQ (Read/Write Request)**: Initiate file transfers with filename, mode, and options
//! - **DATA**: Transfer file data in numbered blocks
//! - **ACK**: Acknowledge received blocks
//! - **OACK**: Option acknowledgment for negotiated parameters
//! - **ERROR**: Report protocol or file errors
//!
//! # Examples
//!
//! ```rust
//! use dnsmasq::tftp::protocol::{TftpPacket, RequestPacket, AckPacket, TftpOpcode, TransferMode};
//!
//! // Parse a read request
//! let packet_data = vec![0, 1, /* RRQ opcode */
//!                        b'p', b'x', b'e', b'l', b'i', b'n', b'u', b'x', b'.', b'0', 0,
//!                        b'o', b'c', b't', b'e', b't', 0];
//! let packet = TftpPacket::parse(&packet_data).unwrap();
//!
//! // Serialize an ACK packet
//! let ack = AckPacket::new(42);
//! let bytes = ack.serialize();
//! ```

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::str::FromStr;
use thiserror::Error;

/// Maximum error message length to ensure packets stay under 512 bytes
/// Corresponds to MAXMESSAGE in C implementation
pub const MAX_ERROR_MESSAGE: usize = 500;

/// TFTP operation codes per RFC 1350 Section 5
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TftpOpcode {
    /// Read Request - opcode 1
    RRQ = 1,
    /// Write Request - opcode 2
    WRQ = 2,
    /// Data packet - opcode 3
    DATA = 3,
    /// Acknowledgment - opcode 4
    ACK = 4,
    /// Error packet - opcode 5
    ERROR = 5,
    /// Option Acknowledgment - opcode 6 (RFC 2347)
    OACK = 6,
}

impl TftpOpcode {
    /// Convert `u16` to `TftpOpcode`, returning `None` for invalid opcodes
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(TftpOpcode::RRQ),
            2 => Some(TftpOpcode::WRQ),
            3 => Some(TftpOpcode::DATA),
            4 => Some(TftpOpcode::ACK),
            5 => Some(TftpOpcode::ERROR),
            6 => Some(TftpOpcode::OACK),
            _ => None,
        }
    }

    /// Convert `TftpOpcode` to `u16`
    #[must_use]
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// TFTP error codes per RFC 1350 Section 5
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TftpErrorCode {
    /// Not defined, see error message (if any) - code 0
    NotDefined = 0,
    /// File not found - code 1
    FileNotFound = 1,
    /// Access violation - code 2
    AccessViolation = 2,
    /// Disk full or allocation exceeded - code 3
    DiskFull = 3,
    /// Illegal TFTP operation - code 4
    IllegalOperation = 4,
    /// Unknown transfer ID - code 5
    UnknownTransferId = 5,
}

impl TftpErrorCode {
    /// Convert `u16` to `TftpErrorCode`, returning `None` for invalid codes
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(TftpErrorCode::NotDefined),
            1 => Some(TftpErrorCode::FileNotFound),
            2 => Some(TftpErrorCode::AccessViolation),
            3 => Some(TftpErrorCode::DiskFull),
            4 => Some(TftpErrorCode::IllegalOperation),
            5 => Some(TftpErrorCode::UnknownTransferId),
            _ => None,
        }
    }

    /// Convert `TftpErrorCode` to `u16`
    #[must_use]
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// TFTP transfer modes per RFC 1350
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferMode {
    /// Network ASCII mode with CR-LF translation
    Netascii,
    /// Binary octet mode (no translation)
    Octet,
    /// Mail mode (obsolete, included for RFC compliance)
    Mail,
}

impl FromStr for TransferMode {
    type Err = ProtocolError;

    /// Parse transfer mode from string (case-insensitive)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "netascii" => Ok(TransferMode::Netascii),
            "octet" => Ok(TransferMode::Octet),
            "mail" => Ok(TransferMode::Mail),
            _ => Err(ProtocolError::InvalidOptions(format!(
                "Invalid transfer mode: {s}"
            ))),
        }
    }
}

impl TransferMode {
    /// Convert transfer mode to string
    #[must_use]
    pub fn to_str(&self) -> &'static str {
        match self {
            TransferMode::Netascii => "netascii",
            TransferMode::Octet => "octet",
            TransferMode::Mail => "mail",
        }
    }
}

/// Protocol-level errors during packet parsing or validation
#[derive(Error, Debug, PartialEq)]
pub enum ProtocolError {
    /// Invalid or unknown opcode encountered
    #[error("Invalid TFTP opcode: {0}")]
    InvalidOpcode(u16),

    /// Malformed packet structure (missing null terminators, truncated data)
    #[error("Malformed TFTP packet: {0}")]
    MalformedPacket(String),

    /// Invalid options in request or OACK
    #[error("Invalid TFTP options: {0}")]
    InvalidOptions(String),

    /// Packet exceeds maximum allowed size
    #[error("Buffer overflow: packet size {0} exceeds maximum")]
    BufferOverflow(usize),

    /// General parsing error
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Read Request (RRQ) or Write Request (WRQ) packet
///
/// Format per RFC 1350 Section 5:
/// ```text
/// 2 bytes     string    1 byte     string   1 byte
/// -----------------------------------------------
/// | Opcode |  Filename  |   0  |    Mode    |   0  |
/// -----------------------------------------------
/// ```
///
/// With RFC 2347 options:
/// ```text
/// | Opcode | Filename | 0 | Mode | 0 | Opt1 | 0 | Value1 | 0 | ... |
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPacket {
    /// Operation code (RRQ or WRQ)
    opcode: TftpOpcode,
    /// Requested filename
    filename: String,
    /// Transfer mode
    mode: TransferMode,
    /// Optional parameters (blksize, tsize, timeout, etc.)
    options: HashMap<String, String>,
}

impl RequestPacket {
    /// Create a new request packet
    ///
    /// # Arguments
    /// * `opcode` - Either RRQ or WRQ
    /// * `filename` - File to transfer
    /// * `mode` - Transfer mode (netascii, octet, mail)
    ///
    /// # Returns
    /// A `RequestPacket` with no options
    #[must_use]
    pub fn new(opcode: TftpOpcode, filename: String, mode: TransferMode) -> Self {
        RequestPacket {
            opcode,
            filename,
            mode,
            options: HashMap::new(),
        }
    }

    /// Create a request packet with options
    ///
    /// # Arguments
    /// * `opcode` - Either RRQ or WRQ
    /// * `filename` - File to transfer
    /// * `mode` - Transfer mode
    /// * `options` - Map of option name to value (e.g., "blksize" -> "1468")
    #[must_use]
    pub fn with_options(
        opcode: TftpOpcode,
        filename: String,
        mode: TransferMode,
        options: HashMap<String, String>,
    ) -> Self {
        RequestPacket {
            opcode,
            filename,
            mode,
            options,
        }
    }

    /// Parse a request packet from raw bytes
    ///
    /// # Arguments
    /// * `data` - Raw packet bytes starting with opcode
    ///
    /// # Returns
    /// Parsed `RequestPacket` or `ProtocolError`
    ///
    /// # Errors
    /// Returns error if packet is malformed, opcode is invalid, or required fields are missing
    ///
    /// # Panics
    /// Panics if opcode validation fails unexpectedly after successful `from_u16` check
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 4 {
            return Err(ProtocolError::MalformedPacket(
                "Request packet too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let opcode = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        let opcode = match TftpOpcode::from_u16(opcode) {
            Some(TftpOpcode::RRQ | TftpOpcode::WRQ) => TftpOpcode::from_u16(opcode).unwrap(),
            _ => return Err(ProtocolError::InvalidOpcode(opcode)),
        };

        let pos = usize::try_from(cursor.position())
            .map_err(|e| ProtocolError::ParseError(format!("Position overflow: {e}")))?;
        let rest = &data[pos..];

        // Parse null-terminated strings
        let filename = extract_null_terminated_string(rest).ok_or_else(|| {
            ProtocolError::MalformedPacket("Missing filename null terminator".to_string())
        })?;

        let mode_start = filename.len() + 1;
        if mode_start >= rest.len() {
            return Err(ProtocolError::MalformedPacket(
                "Missing mode field".to_string(),
            ));
        }

        let mode_str = extract_null_terminated_string(&rest[mode_start..]).ok_or_else(|| {
            ProtocolError::MalformedPacket("Missing mode null terminator".to_string())
        })?;

        let mode = TransferMode::from_str(&mode_str).map_err(|_| {
            ProtocolError::InvalidOptions(format!("Invalid transfer mode: {mode_str}"))
        })?;

        // Parse options (RFC 2347)
        let mut options = HashMap::new();
        let mut opt_start = mode_start + mode_str.len() + 1;

        while opt_start < rest.len() {
            if rest[opt_start] == 0 {
                break;
            }

            let opt_name = extract_null_terminated_string(&rest[opt_start..]).ok_or_else(|| {
                ProtocolError::MalformedPacket("Missing option name null terminator".to_string())
            })?;

            opt_start += opt_name.len() + 1;
            if opt_start >= rest.len() {
                return Err(ProtocolError::MalformedPacket(
                    "Missing option value".to_string(),
                ));
            }

            let opt_value =
                extract_null_terminated_string(&rest[opt_start..]).ok_or_else(|| {
                    ProtocolError::MalformedPacket(
                        "Missing option value null terminator".to_string(),
                    )
                })?;

            opt_start += opt_value.len() + 1;
            options.insert(opt_name.to_lowercase(), opt_value);
        }

        Ok(RequestPacket {
            opcode,
            filename,
            mode,
            options,
        })
    }

    /// Serialize request packet to bytes
    ///
    /// # Returns
    /// Serialized packet bytes with network byte order
    ///
    /// # Panics
    /// Panics if writing to the in-memory buffer fails (should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Write opcode
        buffer.write_u16::<BigEndian>(self.opcode.to_u16()).unwrap();

        // Write filename with null terminator
        buffer.extend_from_slice(self.filename.as_bytes());
        buffer.push(0);

        // Write mode with null terminator
        buffer.extend_from_slice(self.mode.to_str().as_bytes());
        buffer.push(0);

        // Write options
        for (key, value) in &self.options {
            buffer.extend_from_slice(key.as_bytes());
            buffer.push(0);
            buffer.extend_from_slice(value.as_bytes());
            buffer.push(0);
        }

        buffer
    }

    /// Get the opcode (RRQ or WRQ)
    #[must_use]
    pub fn opcode(&self) -> TftpOpcode {
        self.opcode
    }

    /// Get the filename
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Get the transfer mode
    #[must_use]
    pub fn mode(&self) -> TransferMode {
        self.mode
    }

    /// Get the options map
    #[must_use]
    pub fn options(&self) -> &HashMap<String, String> {
        &self.options
    }
}

/// DATA packet containing file data
///
/// Format per RFC 1350 Section 5:
/// ```text
/// 2 bytes     2 bytes      n bytes
/// ----------------------------------
/// | Opcode |   Block #  |   Data     |
/// ----------------------------------
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    /// Block number (1-65535, wraps for large files)
    block: u16,
    /// Data payload
    data: Vec<u8>,
}

impl DataPacket {
    /// Create a new DATA packet
    ///
    /// # Arguments
    /// * `block` - Block number
    /// * `data` - Block data
    #[must_use]
    pub fn new(block: u16, data: Vec<u8>) -> Self {
        DataPacket { block, data }
    }

    /// Parse a DATA packet from raw bytes
    ///
    /// # Arguments
    /// * `data` - Raw packet bytes starting with opcode
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the packet is malformed or has an invalid opcode.
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 4 {
            return Err(ProtocolError::MalformedPacket(
                "DATA packet too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let opcode = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        if opcode != TftpOpcode::DATA.to_u16() {
            return Err(ProtocolError::InvalidOpcode(opcode));
        }

        let block = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        let payload = data[4..].to_vec();

        Ok(DataPacket {
            block,
            data: payload,
        })
    }

    /// Serialize DATA packet to bytes
    ///
    /// # Returns
    /// Serialized packet bytes with network byte order
    ///
    /// # Panics
    /// Panics if writing to the in-memory buffer fails (should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4 + self.data.len());

        buffer
            .write_u16::<BigEndian>(TftpOpcode::DATA.to_u16())
            .unwrap();
        buffer.write_u16::<BigEndian>(self.block).unwrap();
        buffer.extend_from_slice(&self.data);

        buffer
    }

    /// Get the block number
    #[must_use]
    pub fn block(&self) -> u16 {
        self.block
    }

    /// Get the data payload
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// ACK packet acknowledging received block
///
/// Format per RFC 1350 Section 5:
/// ```text
/// 2 bytes     2 bytes
/// ---------------------
/// | Opcode |   Block #  |
/// ---------------------
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckPacket {
    /// Block number being acknowledged
    block: u16,
}

impl AckPacket {
    /// Create a new ACK packet
    ///
    /// # Arguments
    /// * `block` - Block number to acknowledge
    #[must_use]
    pub fn new(block: u16) -> Self {
        AckPacket { block }
    }

    /// Parse an ACK packet from raw bytes
    ///
    /// # Arguments
    /// * `data` - Raw packet bytes starting with opcode
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the packet is malformed or has an invalid opcode.
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() != 4 {
            return Err(ProtocolError::MalformedPacket(format!(
                "ACK packet must be exactly 4 bytes, got {}",
                data.len()
            )));
        }

        let mut cursor = Cursor::new(data);
        let opcode = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        if opcode != TftpOpcode::ACK.to_u16() {
            return Err(ProtocolError::InvalidOpcode(opcode));
        }

        let block = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        Ok(AckPacket { block })
    }

    /// Serialize ACK packet to bytes
    ///
    /// # Returns
    /// Serialized packet bytes (always 4 bytes)
    ///
    /// # Panics
    /// Panics if writing to the in-memory buffer fails (should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4);
        buffer
            .write_u16::<BigEndian>(TftpOpcode::ACK.to_u16())
            .unwrap();
        buffer.write_u16::<BigEndian>(self.block).unwrap();
        buffer
    }

    /// Get the block number
    #[must_use]
    pub fn block(&self) -> u16 {
        self.block
    }
}

/// OACK (Option Acknowledgment) packet per RFC 2347
///
/// Format:
/// ```text
/// 2 bytes     string   1 byte     string   1 byte
/// -----------------------------------------------
/// | Opcode |  Opt1  |   0  |  Value1  |   0  | ...
/// -----------------------------------------------
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OackPacket {
    /// Negotiated options
    options: HashMap<String, String>,
}

impl OackPacket {
    /// Create a new OACK packet
    ///
    /// # Arguments
    /// * `options` - Map of option names to values
    #[must_use]
    pub fn new(options: HashMap<String, String>) -> Self {
        OackPacket { options }
    }

    /// Parse an OACK packet from raw bytes
    ///
    /// # Arguments
    /// * `data` - Raw packet bytes starting with opcode
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the packet is malformed or has an invalid opcode.
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::MalformedPacket(
                "OACK packet too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let opcode = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        if opcode != TftpOpcode::OACK.to_u16() {
            return Err(ProtocolError::InvalidOpcode(opcode));
        }

        let rest = &data[2..];
        let mut options = HashMap::new();
        let mut pos = 0;

        while pos < rest.len() {
            if rest[pos] == 0 {
                break;
            }

            let opt_name = extract_null_terminated_string(&rest[pos..]).ok_or_else(|| {
                ProtocolError::MalformedPacket("Missing option name null terminator".to_string())
            })?;

            pos += opt_name.len() + 1;
            if pos >= rest.len() {
                return Err(ProtocolError::MalformedPacket(
                    "Missing option value".to_string(),
                ));
            }

            let opt_value = extract_null_terminated_string(&rest[pos..]).ok_or_else(|| {
                ProtocolError::MalformedPacket("Missing option value null terminator".to_string())
            })?;

            pos += opt_value.len() + 1;
            options.insert(opt_name.to_lowercase(), opt_value);
        }

        Ok(OackPacket { options })
    }

    /// Serialize OACK packet to bytes
    ///
    /// # Returns
    /// Serialized packet bytes with network byte order
    ///
    /// # Panics
    /// Panics if writing to the in-memory buffer fails (should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer
            .write_u16::<BigEndian>(TftpOpcode::OACK.to_u16())
            .unwrap();

        for (key, value) in &self.options {
            buffer.extend_from_slice(key.as_bytes());
            buffer.push(0);
            buffer.extend_from_slice(value.as_bytes());
            buffer.push(0);
        }

        buffer
    }

    /// Get the options map
    #[must_use]
    pub fn options(&self) -> &HashMap<String, String> {
        &self.options
    }
}

/// ERROR packet reporting protocol or file errors
///
/// Format per RFC 1350 Section 5:
/// ```text
/// 2 bytes     2 bytes      string    1 byte
/// -----------------------------------------
/// | Opcode |  ErrorCode |   ErrMsg   |   0  |
/// -----------------------------------------
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPacket {
    /// Error code
    error_code: TftpErrorCode,
    /// Human-readable error message
    message: String,
}

impl ErrorPacket {
    /// Create a new ERROR packet
    ///
    /// # Arguments
    /// * `error_code` - TFTP error code
    /// * `message` - Error message (truncated to `MAX_ERROR_MESSAGE` if needed)
    #[must_use]
    pub fn new(error_code: TftpErrorCode, message: String) -> Self {
        let message = if message.len() > MAX_ERROR_MESSAGE {
            message[..MAX_ERROR_MESSAGE].to_string()
        } else {
            message
        };

        ErrorPacket {
            error_code,
            message,
        }
    }

    /// Parse an ERROR packet from raw bytes
    ///
    /// # Arguments
    /// * `data` - Raw packet bytes starting with opcode
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the packet is malformed or has an invalid opcode or error code.
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 5 {
            return Err(ProtocolError::MalformedPacket(
                "ERROR packet too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let opcode = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        if opcode != TftpOpcode::ERROR.to_u16() {
            return Err(ProtocolError::InvalidOpcode(opcode));
        }

        let error_code_val = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        let error_code = TftpErrorCode::from_u16(error_code_val).ok_or_else(|| {
            ProtocolError::InvalidOptions(format!("Invalid error code: {error_code_val}"))
        })?;

        let message = extract_null_terminated_string(&data[4..])
            .ok_or_else(|| {
                ProtocolError::MalformedPacket("Missing error message null terminator".to_string())
            })?;

        Ok(ErrorPacket {
            error_code,
            message,
        })
    }

    /// Serialize ERROR packet to bytes
    ///
    /// # Returns
    /// Serialized packet bytes with network byte order
    ///
    /// # Panics
    /// Panics if writing to the in-memory buffer fails (should never happen in practice)
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer
            .write_u16::<BigEndian>(TftpOpcode::ERROR.to_u16())
            .unwrap();
        buffer
            .write_u16::<BigEndian>(self.error_code.to_u16())
            .unwrap();
        buffer.extend_from_slice(self.message.as_bytes());
        buffer.push(0);

        buffer
    }

    /// Get the error code
    #[must_use]
    pub fn error_code(&self) -> TftpErrorCode {
        self.error_code
    }

    /// Get the error message
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Unified TFTP packet enum containing all packet types
#[derive(Debug, Clone, PartialEq)]
pub enum TftpPacket {
    /// Read or Write Request
    Request(RequestPacket),
    /// Data block
    Data(DataPacket),
    /// Acknowledgment
    Ack(AckPacket),
    /// Option Acknowledgment
    Oack(OackPacket),
    /// Error
    Error(ErrorPacket),
}

impl TftpPacket {
    /// Parse any TFTP packet from raw bytes
    ///
    /// # Arguments
    /// * `data` - Raw packet bytes
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError` if the packet is malformed or has an invalid opcode.
    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::MalformedPacket(
                "Packet too short to contain opcode".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let opcode = cursor
            .read_u16::<BigEndian>()
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;

        match TftpOpcode::from_u16(opcode) {
            Some(TftpOpcode::RRQ | TftpOpcode::WRQ) => {
                Ok(TftpPacket::Request(RequestPacket::parse(data)?))
            }
            Some(TftpOpcode::DATA) => Ok(TftpPacket::Data(DataPacket::parse(data)?)),
            Some(TftpOpcode::ACK) => Ok(TftpPacket::Ack(AckPacket::parse(data)?)),
            Some(TftpOpcode::OACK) => Ok(TftpPacket::Oack(OackPacket::parse(data)?)),
            Some(TftpOpcode::ERROR) => Ok(TftpPacket::Error(ErrorPacket::parse(data)?)),
            None => Err(ProtocolError::InvalidOpcode(opcode)),
        }
    }

    /// Serialize packet to bytes
    ///
    /// # Returns
    /// Serialized packet bytes
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            TftpPacket::Request(pkt) => pkt.serialize(),
            TftpPacket::Data(pkt) => pkt.serialize(),
            TftpPacket::Ack(pkt) => pkt.serialize(),
            TftpPacket::Oack(pkt) => pkt.serialize(),
            TftpPacket::Error(pkt) => pkt.serialize(),
        }
    }
}

/// Parse a request packet from raw bytes (convenience function)
///
/// This function is provided for compatibility with the module's public API.
///
/// # Arguments
/// * `data` - Raw packet bytes
///
/// # Errors
///
/// Returns `ProtocolError` if the packet is malformed or has an invalid opcode.
pub fn parse_request_packet(data: &[u8]) -> Result<RequestPacket, ProtocolError> {
    RequestPacket::parse(data)
}

/// Sanitize a string for safe logging by removing non-printable characters
///
/// This function removes control characters and non-printable bytes to prevent
/// log injection attacks when logging filenames or error messages from untrusted
/// TFTP packets.
///
/// # Arguments
/// * `buf` - String to sanitize
///
/// # Returns
/// Sanitized string containing only printable ASCII characters
///
/// # Examples
/// ```
/// use dnsmasq::tftp::protocol::sanitise_string;
///
/// let malicious = "file\x07name\x1b.txt";
/// let safe = sanitise_string(malicious);
/// assert_eq!(safe, "filename.txt");
/// ```
#[must_use]
pub fn sanitise_string(buf: &str) -> String {
    buf.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .collect()
}

/// Extract null-terminated string from byte slice
///
/// # Arguments
/// * `data` - Byte slice potentially containing null-terminated string
///
/// # Returns
/// Some(string) if valid null-terminated string found, None otherwise
fn extract_null_terminated_string(data: &[u8]) -> Option<String> {
    // Find null terminator
    let null_pos = data.iter().position(|&b| b == 0)?;

    // Check that we have at least one byte before the null
    if null_pos == 0 {
        return Some(String::new());
    }

    // Convert bytes to string
    String::from_utf8(data[..null_pos].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_conversion() {
        assert_eq!(TftpOpcode::from_u16(1), Some(TftpOpcode::RRQ));
        assert_eq!(TftpOpcode::from_u16(6), Some(TftpOpcode::OACK));
        assert_eq!(TftpOpcode::from_u16(99), None);
        assert_eq!(TftpOpcode::DATA.to_u16(), 3);
    }

    #[test]
    fn test_error_code_conversion() {
        assert_eq!(
            TftpErrorCode::from_u16(1),
            Some(TftpErrorCode::FileNotFound)
        );
        assert_eq!(
            TftpErrorCode::from_u16(5),
            Some(TftpErrorCode::UnknownTransferId)
        );
        assert_eq!(TftpErrorCode::from_u16(99), None);
    }

    #[test]
    fn test_transfer_mode_parsing() {
        assert_eq!(TransferMode::from_str("octet"), Ok(TransferMode::Octet));
        assert_eq!(
            TransferMode::from_str("NETASCII"),
            Ok(TransferMode::Netascii)
        );
        assert!(TransferMode::from_str("invalid").is_err());
        assert_eq!(TransferMode::Octet.to_str(), "octet");
    }

    #[test]
    fn test_ack_packet_roundtrip() {
        let ack = AckPacket::new(42);
        let bytes = ack.serialize();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes, vec![0, 4, 0, 42]);

        let parsed = AckPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.block(), 42);
    }

    #[test]
    fn test_data_packet_roundtrip() {
        let data = DataPacket::new(1, vec![1, 2, 3, 4, 5]);
        let bytes = data.serialize();

        let parsed = DataPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.block(), 1);
        assert_eq!(parsed.data(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_error_packet_roundtrip() {
        let error = ErrorPacket::new(TftpErrorCode::FileNotFound, "File not found".to_string());
        let bytes = error.serialize();

        let parsed = ErrorPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.error_code(), TftpErrorCode::FileNotFound);
        assert_eq!(parsed.message(), "File not found");
    }

    #[test]
    fn test_request_packet_simple() {
        let req = RequestPacket::new(TftpOpcode::RRQ, "test.txt".to_string(), TransferMode::Octet);
        let bytes = req.serialize();

        let parsed = RequestPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.filename(), "test.txt");
        assert_eq!(parsed.mode(), TransferMode::Octet);
        assert!(parsed.options().is_empty());
    }

    #[test]
    fn test_request_packet_with_options() {
        let mut options = HashMap::new();
        options.insert("blksize".to_string(), "1468".to_string());
        options.insert("tsize".to_string(), "12345".to_string());

        let req = RequestPacket::with_options(
            TftpOpcode::RRQ,
            "bootfile".to_string(),
            TransferMode::Octet,
            options.clone(),
        );
        let bytes = req.serialize();

        let parsed = RequestPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.filename(), "bootfile");
        assert_eq!(parsed.options().get("blksize").unwrap(), "1468");
        assert_eq!(parsed.options().get("tsize").unwrap(), "12345");
    }

    #[test]
    fn test_oack_packet() {
        let mut options = HashMap::new();
        options.insert("blksize".to_string(), "1024".to_string());

        let oack = OackPacket::new(options);
        let bytes = oack.serialize();

        let parsed = OackPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.options().get("blksize").unwrap(), "1024");
    }

    #[test]
    fn test_sanitise_string() {
        assert_eq!(sanitise_string("hello"), "hello");
        assert_eq!(sanitise_string("file\x07name"), "filename");
        assert_eq!(sanitise_string("test\n\r\x1b"), "test");
        assert_eq!(sanitise_string("normal_file.txt"), "normal_file.txt");
    }

    #[test]
    fn test_tftp_packet_parse() {
        // Test ACK packet
        let ack_bytes = vec![0, 4, 0, 10];
        let packet = TftpPacket::parse(&ack_bytes).unwrap();
        match packet {
            TftpPacket::Ack(ack) => assert_eq!(ack.block(), 10),
            _ => panic!("Expected ACK packet"),
        }

        // Test ERROR packet
        let error_bytes = vec![0, 5, 0, 1, b'E', b'r', b'r', b'o', b'r', 0];
        let packet = TftpPacket::parse(&error_bytes).unwrap();
        match packet {
            TftpPacket::Error(err) => {
                assert_eq!(err.error_code(), TftpErrorCode::FileNotFound);
                assert_eq!(err.message(), "Error");
            }
            _ => panic!("Expected ERROR packet"),
        }
    }

    #[test]
    fn test_malformed_packets() {
        // Too short
        assert!(TftpPacket::parse(&[0]).is_err());

        // Invalid opcode
        assert!(TftpPacket::parse(&[0, 99]).is_err());

        // ACK with wrong length
        assert!(AckPacket::parse(&[0, 4, 0]).is_err());
    }

    #[test]
    fn test_extract_null_terminated_string() {
        assert_eq!(
            extract_null_terminated_string(b"hello\0world"),
            Some("hello".to_string())
        );
        assert_eq!(
            extract_null_terminated_string(b"test\0"),
            Some("test".to_string())
        );
        assert_eq!(extract_null_terminated_string(b"\0"), Some(String::new()));
        assert_eq!(extract_null_terminated_string(b"no null"), None);
    }

    #[test]
    fn test_error_message_truncation() {
        let long_msg = "x".repeat(600);
        let error = ErrorPacket::new(TftpErrorCode::NotDefined, long_msg);
        assert_eq!(error.message().len(), MAX_ERROR_MESSAGE);
    }
}
