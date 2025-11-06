// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # DHCPv6 Option Assembly and Packet Construction
//!
//! This module provides memory-safe DHCPv6 packet construction using Type-Length-Value (TLV)
//! encoding per RFC 3315 Section 22.1. Replaces C implementation in `src/outpacket.c`.
//!
//! ## Purpose
//!
//! Translates C's manual buffer management (`daemon->outpacket.iov_base` with `expand_buf()`)
//! to safe Rust using `Vec<u8>` with automatic capacity management. Eliminates buffer overflow
//! vulnerabilities through compile-time bounds checking.
//!
//! ## Key Differences from C Implementation
//!
//! - **Memory Safety**: `Vec<u8>` replaces `malloc/free` with automatic memory management
//! - **Byte Order**: `byteorder` crate replaces PUTSHORT/PUTLONG macros with safe encoding
//! - **Error Handling**: `Result` types replace NULL pointer returns on allocation failure
//! - **Encapsulation**: `OutPacketBuilder` struct replaces static `outpacket_counter` variable
//! - **API Design**: Methods return `Result<T, PacketBuildError>` for explicit error propagation
//!
//! ## C Function Mapping
//!
//! | C Function (outpacket.c) | Rust Method | Purpose |
//! |--------------------------|-------------|---------|
//! | `new_opt6(opt)` | `new_option(code)` | Begin DHCPv6 option with 16-bit code |
//! | `end_opt6(container)` | `end_option(pos)` | Finalize option by writing length field |
//! | `put_opt6_char(val)` | `put_u8(val)` | Append 8-bit value |
//! | `put_opt6_short(val)` | `put_u16(val)` | Append 16-bit value (network byte order) |
//! | `put_opt6_long(val)` | `put_u32(val)` | Append 32-bit value (network byte order) |
//! | `put_opt6(data, len)` | `put_data(data)` | Append arbitrary binary data |
//! | `put_opt6_string(s)` | `put_string(s)` | Append string (without null terminator) |
//! | `reset_counter()` | `clear()` | Clear buffer and reset position |
//! | `save_counter(-1)` | `save_position()` | Save current write position |
//! | `save_counter(newval)` | `restore_position(pos)` | Restore saved position |
//! | (implicit via daemon->outpacket) | `build()` | Consume builder and return packet bytes |
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use dnsmasq::dhcp::outpacket::{OutPacketBuilder, PacketBuildError};
//!
//! fn build_dhcpv6_reply() -> Result<Vec<u8>, PacketBuildError> {
//!     let mut builder = OutPacketBuilder::new();
//!
//!     // Build IA_NA option (OPTION6_IA_NA = 3)
//!     let ia_na_pos = builder.new_option(3)?;
//!     builder.put_u32(0x12345678)?; // IAID
//!     builder.put_u32(3600)?;        // T1 renewal time
//!     builder.put_u32(7200)?;        // T2 rebind time
//!
//!     // Nested IAADDR suboption (OPTION6_IAADDR = 5)
//!     let iaaddr_pos = builder.new_option(5)?;
//!     builder.put_data(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])?; // IPv6
//!     builder.put_u32(7200)?;   // Preferred lifetime
//!     builder.put_u32(14400)?;  // Valid lifetime
//!     builder.end_option(iaaddr_pos)?;
//!
//!     builder.end_option(ia_na_pos)?;
//!
//!     Ok(builder.build())
//! }
//! ```
//!
//! ## RFC 3315 Compliance
//!
//! DHCPv6 option format (Section 22.1):
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          option-code          |           option-len          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          option-data                          |
//! |                      (option-len octets)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - **option-code**: 16-bit identifier (0-65535)
//! - **option-len**: 16-bit length of option-data in octets (excludes 4-byte header)
//! - **option-data**: Variable-length payload
//!
//! Both fields use network byte order (big-endian) per RFC 3315 Section 5.2.

use byteorder::{BigEndian, WriteBytesExt};
use std::io::Write;

/// Errors that can occur during DHCPv6 packet construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketBuildError {
    /// Buffer size exceeded maximum limit
    BufferOverflow,

    /// Attempted to end option without starting one
    OptionNotStarted,

    /// Invalid option nesting structure
    InvalidOptionNesting,
}

impl std::fmt::Display for PacketBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketBuildError::BufferOverflow => {
                write!(f, "Packet buffer overflow: exceeded maximum size")
            }
            PacketBuildError::OptionNotStarted => {
                write!(f, "Cannot end option: no option was started")
            }
            PacketBuildError::InvalidOptionNesting => {
                write!(f, "Invalid option nesting structure")
            }
        }
    }
}

impl std::error::Error for PacketBuildError {}

/// DHCPv6 packet builder with automatic buffer management
///
/// Provides memory-safe alternative to C's manual buffer management with `daemon->outpacket.iov_base`.
/// Uses `Vec<u8>` for dynamic buffer growth, eliminating fixed-size limits and buffer overflow risks.
///
/// ## Design Notes
///
/// - Replaces C's static `outpacket_counter` variable with encapsulated `position` field
/// - Automatic capacity management via `Vec::reserve()` replaces `expand_buf()` from util.c
/// - Network byte order encoding via `byteorder` crate replaces PUTSHORT/PUTLONG macros
/// - All operations return `Result` for explicit error handling vs. C's NULL returns
///
/// ## Thread Safety
///
/// Not thread-safe (matches C implementation). Each DHCPv6 response construction uses
/// dedicated builder instance in dnsmasq's single-threaded event loop model.
pub struct OutPacketBuilder {
    /// Dynamic packet buffer with automatic growth
    ///
    /// Replaces C's `daemon->outpacket.iov_base` pointer with safe owned memory.
    /// Grows automatically when capacity exceeded, eliminating manual `expand_buf()` calls.
    buffer: Vec<u8>,

    /// Current write position in buffer
    ///
    /// Replaces C's static `outpacket_counter` variable. Tracks next byte to write.
    /// Always satisfies invariant: `position <= buffer.len()`
    position: usize,

    /// Maximum buffer size limit (safety bounds)
    ///
    /// Prevents unbounded memory growth. Set to 64KB (typical DHCPv6 max packet size).
    max_size: usize,
}

impl OutPacketBuilder {
    /// Maximum packet size (64KB - typical DHCPv6 limit)
    const MAX_PACKET_SIZE: usize = 65535;

    /// Default initial capacity (typical Ethernet MTU)
    const DEFAULT_CAPACITY: usize = 1500;

    /// Create new packet builder with default capacity
    ///
    /// Corresponds to initialization before first `new_opt6()` call in C.
    ///
    /// # Returns
    ///
    /// New builder with empty buffer and 1500-byte initial capacity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    ///
    /// let builder = OutPacketBuilder::new();
    /// assert_eq!(builder.len(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(Self::DEFAULT_CAPACITY),
            position: 0,
            max_size: Self::MAX_PACKET_SIZE,
        }
    }

    /// Create packet builder with specified capacity
    ///
    /// Useful for pre-allocating when expected packet size is known.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial buffer capacity in bytes
    ///
    /// # Returns
    ///
    /// New builder with specified initial capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            position: 0,
            max_size: Self::MAX_PACKET_SIZE,
        }
    }

    /// Clear buffer and reset position for new packet
    ///
    /// Corresponds to C's `reset_counter()` (outpacket.c:205-212).
    /// Zeroes buffer content and resets write position to start.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// let _ = builder.put_u16(42);
    /// builder.clear();
    /// assert_eq!(builder.len(), 0);
    /// ```
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.position = 0;
    }

    /// Begin new DHCPv6 option with 16-bit option code
    ///
    /// Corresponds to C's `new_opt6(opt)` (outpacket.c:439-451).
    ///
    /// Writes 4-byte option header:
    /// - Bytes 0-1: 16-bit option code (network byte order)
    /// - Bytes 2-3: 16-bit length field (initially 0, updated by `end_option()`)
    ///
    /// Returns position of header start for later length update.
    ///
    /// # Arguments
    ///
    /// * `option_code` - 16-bit DHCPv6 option code per RFC 3315 (e.g., 3=IA_NA, 5=IAADDR)
    ///
    /// # Returns
    ///
    /// - `Ok(position)` - Header position for `end_option()` call
    /// - `Err(BufferOverflow)` - Insufficient space for header
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// let pos = builder.new_option(1).unwrap(); // OPTION6_CLIENTID = 1
    /// builder.put_u32(0x12345678).unwrap();
    /// builder.end_option(pos).unwrap();
    /// ```
    pub fn new_option(&mut self, option_code: u16) -> Result<usize, PacketBuildError> {
        let start_pos = self.position;

        // Write option code (16-bit, network byte order)
        self.put_u16(option_code)?;

        // Reserve space for length field (16-bit), filled by end_option()
        self.put_u16(0)?;

        Ok(start_pos)
    }

    /// Finalize DHCPv6 option by calculating and writing length field
    ///
    /// Corresponds to C's `end_opt6(container)` (outpacket.c:143-149).
    ///
    /// Calculates option data length (current position - container - 4 header bytes)
    /// and updates 16-bit length field at `container + 2` in network byte order.
    ///
    /// # Arguments
    ///
    /// * `container` - Position returned by `new_option()`
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Option successfully finalized
    /// - `Err(OptionNotStarted)` - Invalid container position
    /// - `Err(InvalidOptionNesting)` - Position beyond current buffer
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// let pos = builder.new_option(1).unwrap();
    /// builder.put_u32(0x12345678).unwrap();
    /// builder.end_option(pos).unwrap();
    /// // Length field now contains 4 (32-bit value)
    /// ```
    pub fn end_option(&mut self, container: usize) -> Result<(), PacketBuildError> {
        // Validate container position
        if container + 4 > self.position {
            return Err(PacketBuildError::InvalidOptionNesting);
        }

        if container + 4 > self.buffer.len() {
            return Err(PacketBuildError::OptionNotStarted);
        }

        // Calculate data length (excludes 4-byte header)
        let data_len = self.position - container - 4;

        if data_len > u16::MAX as usize {
            return Err(PacketBuildError::BufferOverflow);
        }

        // Update length field at container + 2 (after option code)
        let len_pos = container + 2;
        self.buffer[len_pos] = (data_len >> 8) as u8;
        self.buffer[len_pos + 1] = (data_len & 0xff) as u8;

        Ok(())
    }

    /// Append arbitrary binary data to current option
    ///
    /// Corresponds to C's `put_opt6(data, len)` (outpacket.c:528-536).
    ///
    /// Copies byte slice to buffer at current position. Used for IPv6 addresses (16 bytes),
    /// DUIDs (variable length), and other binary payloads.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice to append (no byte order conversion applied)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Data successfully appended
    /// - `Err(BufferOverflow)` - Insufficient space
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// let ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    /// builder.put_data(&ipv6_addr).unwrap();
    /// assert_eq!(builder.len(), 16);
    /// ```
    pub fn put_data(&mut self, data: &[u8]) -> Result<(), PacketBuildError> {
        self.ensure_capacity(data.len())?;
        self.buffer.extend_from_slice(data);
        self.position += data.len();
        Ok(())
    }

    /// Append 8-bit unsigned integer
    ///
    /// Corresponds to C's `put_opt6_char(val)` (outpacket.c:763-769).
    ///
    /// No byte order conversion needed for single-byte values.
    ///
    /// # Arguments
    ///
    /// * `value` - 8-bit value to append (0-255)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Value successfully appended
    /// - `Err(BufferOverflow)` - Insufficient space
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// builder.put_u8(0x42).unwrap();
    /// assert_eq!(builder.as_slice(), &[0x42]);
    /// ```
    pub fn put_u8(&mut self, value: u8) -> Result<(), PacketBuildError> {
        self.ensure_capacity(1)?;
        self.buffer.push(value);
        self.position += 1;
        Ok(())
    }

    /// Append 16-bit unsigned integer in network byte order (big-endian)
    ///
    /// Corresponds to C's `put_opt6_short(val)` (outpacket.c:691-697).
    ///
    /// Uses `byteorder::WriteBytesExt::write_u16::<BigEndian>()` to replace
    /// C's PUTSHORT macro, ensuring correct network byte order encoding.
    ///
    /// # Arguments
    ///
    /// * `value` - 16-bit value in host byte order (automatically converted)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Value successfully appended
    /// - `Err(BufferOverflow)` - Insufficient space
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// builder.put_u16(0x1234).unwrap();
    /// assert_eq!(builder.as_slice(), &[0x12, 0x34]); // Big-endian
    /// ```
    pub fn put_u16(&mut self, value: u16) -> Result<(), PacketBuildError> {
        self.ensure_capacity(2)?;
        // Using write_u16 method from WriteBytesExt trait for network byte order
        self.buffer
            .write_u16::<BigEndian>(value)
            .map_err(|_| PacketBuildError::BufferOverflow)?;
        self.position += 2;
        Ok(())
    }

    /// Append 32-bit unsigned integer in network byte order (big-endian)
    ///
    /// Corresponds to C's `put_opt6_long(val)` (outpacket.c:607-613).
    ///
    /// Uses `byteorder::WriteBytesExt::write_u32::<BigEndian>()` to replace
    /// C's PUTLONG macro. Used for IAID, T1, T2 timers, and lifetimes per RFC 3315.
    ///
    /// # Arguments
    ///
    /// * `value` - 32-bit value in host byte order (automatically converted)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Value successfully appended
    /// - `Err(BufferOverflow)` - Insufficient space
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// builder.put_u32(0x12345678).unwrap();
    /// assert_eq!(builder.as_slice(), &[0x12, 0x34, 0x56, 0x78]); // Big-endian
    /// ```
    pub fn put_u32(&mut self, value: u32) -> Result<(), PacketBuildError> {
        self.ensure_capacity(4)?;
        // Using write_u32 method from WriteBytesExt trait for network byte order
        self.buffer
            .write_u32::<BigEndian>(value)
            .map_err(|_| PacketBuildError::BufferOverflow)?;
        self.position += 4;
        Ok(())
    }

    /// Append null-terminated string without null terminator
    ///
    /// Corresponds to C's `put_opt6_string(s)` (outpacket.c:849-852).
    ///
    /// DHCPv6 strings are NOT null-terminated on wire (length explicit via option-len field).
    /// Used for status messages, domain names, and other text fields per RFC 3315.
    ///
    /// # Arguments
    ///
    /// * `s` - String slice to append (null terminator excluded)
    ///
    /// # Returns
    ///
    /// - `Ok(())` - String successfully appended
    /// - `Err(BufferOverflow)` - Insufficient space
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// builder.put_string("Success").unwrap();
    /// assert_eq!(builder.as_slice(), b"Success"); // No null terminator
    /// ```
    pub fn put_string(&mut self, s: &str) -> Result<(), PacketBuildError> {
        self.put_data(s.as_bytes())
    }

    /// Consume builder and return constructed packet bytes
    ///
    /// Ownership transfer prevents further modifications after packet is built.
    ///
    /// # Returns
    ///
    /// Owned vector containing packet bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// let _ = builder.put_u32(0x12345678);
    /// let packet = builder.build();
    /// assert_eq!(packet.len(), 4);
    /// ```
    pub fn build(self) -> Vec<u8> {
        self.buffer
    }

    /// Save current write position
    ///
    /// Corresponds to C's `save_counter(-1)` (outpacket.c:277-285).
    ///
    /// Returns current position for later restoration with `restore_position()`.
    /// Useful for nested option construction or error recovery.
    ///
    /// # Returns
    ///
    /// Current write position (byte offset from buffer start)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// let _ = builder.put_u16(0x1234);
    /// let pos = builder.save_position();
    /// assert_eq!(pos, 2);
    /// ```
    pub fn save_position(&self) -> usize {
        self.position
    }

    /// Restore previously saved write position
    ///
    /// Corresponds to C's `save_counter(newval)` where newval != -1 (outpacket.c:277-285).
    ///
    /// Truncates buffer to saved position, discarding any data written after that point.
    /// Used for error recovery or conditional option writing.
    ///
    /// # Arguments
    ///
    /// * `pos` - Position from `save_position()`
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Position successfully restored
    /// - `Err(InvalidOptionNesting)` - Position beyond current buffer
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacketBuilder;
    /// let mut builder = OutPacketBuilder::new();
    /// let _ = builder.put_u16(0x1234);
    /// let pos = builder.save_position();
    /// let _ = builder.put_u16(0x5678); // This will be discarded
    /// builder.restore_position(pos).unwrap();
    /// assert_eq!(builder.len(), 2);
    /// ```
    pub fn restore_position(&mut self, pos: usize) -> Result<(), PacketBuildError> {
        if pos > self.buffer.len() {
            return Err(PacketBuildError::InvalidOptionNesting);
        }

        self.position = pos;
        self.buffer.truncate(pos);
        Ok(())
    }

    /// Get current packet length in bytes
    ///
    /// # Returns
    ///
    /// Number of bytes written to buffer
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if packet buffer is empty
    ///
    /// # Returns
    ///
    /// True if no data written
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get reference to packet bytes without consuming builder
    ///
    /// # Returns
    ///
    /// Byte slice reference
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    /// Ensure buffer has capacity for additional bytes
    ///
    /// Internal helper replacing C's `expand()` function (outpacket.c:355-367).
    ///
    /// # Arguments
    ///
    /// * `additional` - Number of additional bytes needed
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Capacity ensured
    /// - `Err(BufferOverflow)` - Would exceed max_size limit
    fn ensure_capacity(&mut self, additional: usize) -> Result<(), PacketBuildError> {
        let required = self.buffer.len() + additional;

        if required > self.max_size {
            return Err(PacketBuildError::BufferOverflow);
        }

        self.buffer.reserve(additional);
        Ok(())
    }
}

impl Default for OutPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_builder() {
        let builder = OutPacketBuilder::new();
        assert_eq!(builder.len(), 0);
        assert!(builder.is_empty());
    }

    #[test]
    fn test_put_u8() {
        let mut builder = OutPacketBuilder::new();
        builder.put_u8(0x42).unwrap();
        assert_eq!(builder.as_slice(), &[0x42]);
    }

    #[test]
    fn test_put_u16_network_byte_order() {
        let mut builder = OutPacketBuilder::new();
        builder.put_u16(0x1234).unwrap();
        // Should be big-endian (network byte order)
        assert_eq!(builder.as_slice(), &[0x12, 0x34]);
    }

    #[test]
    fn test_put_u32_network_byte_order() {
        let mut builder = OutPacketBuilder::new();
        builder.put_u32(0x12345678).unwrap();
        // Should be big-endian (network byte order)
        assert_eq!(builder.as_slice(), &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_put_data() {
        let mut builder = OutPacketBuilder::new();
        builder.put_data(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(builder.as_slice(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_put_string_no_null_terminator() {
        let mut builder = OutPacketBuilder::new();
        builder.put_string("test").unwrap();
        // Should NOT include null terminator
        assert_eq!(builder.as_slice(), b"test");
        assert_eq!(builder.len(), 4);
    }

    #[test]
    fn test_simple_option() {
        let mut builder = OutPacketBuilder::new();
        let pos = builder.new_option(1).unwrap(); // OPTION6_CLIENTID = 1
        builder.put_u32(0x12345678).unwrap();
        builder.end_option(pos).unwrap();

        let expected = vec![
            0x00, 0x01, // option code = 1
            0x00, 0x04, // length = 4 (only data, excludes header)
            0x12, 0x34, 0x56, 0x78, // data
        ];
        assert_eq!(builder.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_nested_options() {
        let mut builder = OutPacketBuilder::new();

        // Outer IA_NA option (OPTION6_IA_NA = 3)
        let ia_na_pos = builder.new_option(3).unwrap();
        builder.put_u32(0x11111111).unwrap(); // IAID
        builder.put_u32(3600).unwrap(); // T1
        builder.put_u32(7200).unwrap(); // T2

        // Inner IAADDR option (OPTION6_IAADDR = 5)
        let iaaddr_pos = builder.new_option(5).unwrap();
        builder
            .put_data(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            .unwrap(); // IPv6
        builder.put_u32(7200).unwrap(); // Preferred lifetime
        builder.put_u32(14400).unwrap(); // Valid lifetime
        builder.end_option(iaaddr_pos).unwrap();

        builder.end_option(ia_na_pos).unwrap();

        let data = builder.as_slice();

        // Verify outer option header
        assert_eq!(&data[0..2], &[0x00, 0x03]); // IA_NA option code

        // IA_NA length = 12 (IAID+T1+T2) + 4 (IAADDR header) + 24 (IAADDR data) = 40
        assert_eq!(&data[2..4], &[0x00, 40]);

        // Verify IAADDR header inside
        assert_eq!(&data[16..18], &[0x00, 0x05]); // IAADDR option code
        assert_eq!(&data[18..20], &[0x00, 24]); // IAADDR length = 16 (IPv6) + 8 (lifetimes)
    }

    #[test]
    fn test_clear() {
        let mut builder = OutPacketBuilder::new();
        builder.put_u32(0x12345678).unwrap();
        assert_eq!(builder.len(), 4);

        builder.clear();
        assert_eq!(builder.len(), 0);
        assert!(builder.is_empty());
    }

    #[test]
    fn test_position_save_restore() {
        let mut builder = OutPacketBuilder::new();
        builder.put_u16(0x1234).unwrap();

        let pos = builder.save_position();
        assert_eq!(pos, 2);

        builder.put_u16(0x5678).unwrap();
        assert_eq!(builder.len(), 4);

        builder.restore_position(pos).unwrap();
        assert_eq!(builder.len(), 2);
        assert_eq!(builder.as_slice(), &[0x12, 0x34]);
    }

    #[test]
    fn test_error_invalid_option_nesting() {
        let mut builder = OutPacketBuilder::new();
        builder.put_u16(0x1234).unwrap();

        // Try to end option that was never started (invalid position)
        let result = builder.end_option(10);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PacketBuildError::InvalidOptionNesting);
    }

    #[test]
    fn test_error_restore_invalid_position() {
        let mut builder = OutPacketBuilder::new();
        builder.put_u16(0x1234).unwrap();

        // Try to restore position beyond buffer
        let result = builder.restore_position(100);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PacketBuildError::InvalidOptionNesting);
    }

    #[test]
    fn test_build_consumes_builder() {
        let mut builder = OutPacketBuilder::new();
        builder.put_u32(0x12345678).unwrap();

        let packet = builder.build();
        assert_eq!(packet, vec![0x12, 0x34, 0x56, 0x78]);
        // builder is now consumed and cannot be used
    }

    #[test]
    fn test_status_code_option_with_message() {
        let mut builder = OutPacketBuilder::new();

        // Build STATUS_CODE option (OPTION6_STATUS_CODE = 13)
        let status_pos = builder.new_option(13).unwrap();
        builder.put_u16(0).unwrap(); // DHCP6SUCCESS = 0
        builder.put_string("Success").unwrap();
        builder.end_option(status_pos).unwrap();

        let data = builder.as_slice();
        assert_eq!(&data[0..2], &[0x00, 0x0d]); // Option code 13
        assert_eq!(&data[2..4], &[0x00, 0x09]); // Length = 2 (status) + 7 ("Success")
        assert_eq!(&data[4..6], &[0x00, 0x00]); // Status code 0
        assert_eq!(&data[6..], b"Success");
    }

    #[test]
    fn test_empty_option() {
        let mut builder = OutPacketBuilder::new();

        // Option with no data
        let pos = builder.new_option(100).unwrap();
        builder.end_option(pos).unwrap();

        let data = builder.as_slice();
        assert_eq!(&data[0..2], &[0x00, 0x64]); // Option code 100
        assert_eq!(&data[2..4], &[0x00, 0x00]); // Length = 0
    }
}
