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

//! TFTP (Trivial File Transfer Protocol) Subsystem
//!
//! This module implements a TFTP server for network boot and file transfer,
//! as specified in RFC 1350 (The TFTP Protocol) with extensions from:
//! - RFC 2347: TFTP Option Extension
//! - RFC 2348: TFTP Blocksize Option
//! - RFC 2349: TFTP Timeout Interval and Transfer Size Options
//!
//! The implementation provides memory-safe protocol handling replacing
//! the C implementation in tftp.c.

pub mod protocol;
pub mod transfer;

// Re-export commonly used types for convenience
pub use protocol::{
    AckPacket, DataPacket, ErrorPacket, OackPacket, ProtocolError, RequestPacket, TftpErrorCode,
    TftpOpcode, TftpPacket, TransferMode, sanitise_string,
};

pub use transfer::{
    FileMetadata, TftpFile, Transfer, TransferAction, TransferError, TransferOptions,
};
