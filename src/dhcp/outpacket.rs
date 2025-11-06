// Copyright (c) 2000-2024 dnsmasq contributors
// This file is part of the Rust implementation of dnsmasq.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! # DHCPv6 Option Assembly and Packet Construction
//!
//! This module provides functionality for building DHCPv6 response packets using the
//! Type-Length-Value (TLV) option encoding format specified in RFC 3315.
//!
//! Unlike DHCPv4 which uses single-byte option codes, DHCPv6 uses 16-bit option codes
//! and 16-bit lengths in network byte order (big-endian).
//!
//! ## Purpose
//!
//! Replaces C implementation in `src/outpacket.c` with memory-safe Rust:
//! - Sequential assembly of nested options (e.g., IA_NA containing IAADDR suboptions)
//! - Automatic buffer expansion when needed
//! - Position marking for later length field updates
//!
//! ## C Source Mapping
//!
//! | C Function | Rust Equivalent | Purpose |
//! |------------|-----------------|---------|
//! | `new_opt6()` | `OutPacket::begin_option()` | Start new DHCPv6 option |
//! | `end_opt6()` | `OutPacket::end_option()` | Finalize option with length |
//! | `put_opt6_char()` | `OutPacket::put_u8()` | Append 8-bit value |
//! | `put_opt6_short()` | `OutPacket::put_u16()` | Append 16-bit value |
//! | `put_opt6_long()` | `OutPacket::put_u32()` | Append 32-bit value |
//! | `put_opt6()` | `OutPacket::put_bytes()` | Append byte slice |
//! | `put_opt6_string()` | `OutPacket::put_string()` | Append string |
//! | `reset_counter()` | `OutPacket::reset()` | Clear buffer |
//! | `save_counter()` | `OutPacket::save_position()` | Save/restore position |
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use dnsmasq::dhcp::outpacket::OutPacket;
//!
//! let mut packet = OutPacket::new();
//!
//! // Build IA_NA option with nested IAADDR
//! let ia_na_pos = packet.begin_option(3); // OPTION6_IA_NA = 3
//! packet.put_u32(0x12345678); // IAID
//! packet.put_u32(3600); // T1
//! packet.put_u32(7200); // T2
//!
//! // Nested IAADDR suboption
//! let iaaddr_pos = packet.begin_option(5); // OPTION6_IAADDR = 5
//! packet.put_bytes(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // IPv6 address
//! packet.put_u32(7200); // Preferred lifetime
//! packet.put_u32(14400); // Valid lifetime
//! packet.end_option(iaaddr_pos);
//!
//! packet.end_option(ia_na_pos);
//!
//! let data = packet.as_bytes();
//! ```
//!
//! ## RFC 3315 Compliance
//!
//! Option format (Section 22.1):
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
//! The option-len field does NOT include the 4-byte option header itself.

use std::io::{self, Write};

/// DHCPv6 packet construction buffer
///
/// Provides memory-safe alternative to C's manual buffer management
pub struct OutPacket {
    /// Internal buffer for packet data
    buffer: Vec<u8>,
    
    /// Current write position
    position: usize,
}

impl OutPacket {
    /// Create new empty packet buffer
    ///
    /// # Example
    ///
    /// ```rust
    /// use dnsmasq::dhcp::outpacket::OutPacket;
    ///
    /// let packet = OutPacket::new();
    /// ```
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(1500), // Typical MTU
            position: 0,
        }
    }

    /// Create packet buffer with specified capacity
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial buffer capacity in bytes
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            position: 0,
        }
    }

    /// Reset buffer and position for new packet
    ///
    /// Corresponds to C's `reset_counter()` (outpacket.c:205-212)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacket;
    /// let mut packet = OutPacket::new();
    /// packet.put_u16(42);
    /// packet.reset();
    /// assert_eq!(packet.len(), 0);
    /// ```
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.position = 0;
    }

    /// Begin new DHCPv6 option
    ///
    /// Corresponds to C's `new_opt6()` (outpacket.c)
    ///
    /// Writes option code and reserves space for length field.
    /// Returns position marker for use with `end_option()`.
    ///
    /// # Arguments
    ///
    /// * `option_code` - 16-bit DHCPv6 option code
    ///
    /// # Returns
    ///
    /// Position of option header (for later length update)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacket;
    /// let mut packet = OutPacket::new();
    /// let pos = packet.begin_option(1); // OPTION6_CLIENTID
    /// packet.put_bytes(&[0x00, 0x01, 0x02, 0x03]);
    /// packet.end_option(pos);
    /// ```
    pub fn begin_option(&mut self, option_code: u16) -> usize {
        let start_pos = self.position;
        
        // Write option code (16-bit)
        self.put_u16(option_code);
        
        // Reserve space for length (16-bit), will be filled by end_option()
        self.put_u16(0);
        
        start_pos
    }

    /// Finalize DHCPv6 option by writing length
    ///
    /// Corresponds to C's `end_opt6()` (outpacket.c:143-149)
    ///
    /// Calculates option data length and updates the length field.
    ///
    /// # Arguments
    ///
    /// * `container` - Position returned by `begin_option()`
    ///
    /// # Example
    ///
    /// ```rust
    /// # use dnsmasq::dhcp::outpacket::OutPacket;
    /// let mut packet = OutPacket::new();
    /// let pos = packet.begin_option(1);
    /// packet.put_u32(0x12345678);
    /// packet.end_option(pos); // Writes length = 4
    /// ```
    pub fn end_option(&mut self, container: usize) {
        // Calculate data length (current position - container - 4 header bytes)
        let data_len = (self.position - container - 4) as u16;
        
        // Update length field at container + 2 (after option code)
        let len_pos = container + 2;
        self.buffer[len_pos] = (data_len >> 8) as u8;
        self.buffer[len_pos + 1] = (data_len & 0xff) as u8;
    }

    /// Append 8-bit value
    ///
    /// Corresponds to C's `put_opt6_char()`
    ///
    /// # Arguments
    ///
    /// * `value` - 8-bit value to append
    pub fn put_u8(&mut self, value: u8) {
        self.ensure_capacity(1);
        self.buffer.push(value);
        self.position += 1;
    }

    /// Append 16-bit value in network byte order (big-endian)
    ///
    /// Corresponds to C's `put_opt6_short()`
    ///
    /// # Arguments
    ///
    /// * `value` - 16-bit value to append
    pub fn put_u16(&mut self, value: u16) {
        self.ensure_capacity(2);
        self.buffer.extend_from_slice(&value.to_be_bytes());
        self.position += 2;
    }

    /// Append 32-bit value in network byte order (big-endian)
    ///
    /// Corresponds to C's `put_opt6_long()`
    ///
    /// # Arguments
    ///
    /// * `value` - 32-bit value to append
    pub fn put_u32(&mut self, value: u32) {
        self.ensure_capacity(4);
        self.buffer.extend_from_slice(&value.to_be_bytes());
        self.position += 4;
    }

    /// Append byte slice
    ///
    /// Corresponds to C's `put_opt6()`
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice to append
    pub fn put_bytes(&mut self, data: &[u8]) {
        self.ensure_capacity(data.len());
        self.buffer.extend_from_slice(data);
        self.position += data.len();
    }

    /// Append string (without null terminator)
    ///
    /// Corresponds to C's `put_opt6_string()`
    ///
    /// # Arguments
    ///
    /// * `s` - String to append
    pub fn put_string(&mut self, s: &str) {
        self.put_bytes(s.as_bytes());
    }

    /// Save current position
    ///
    /// Corresponds to C's `save_counter(-1)` (outpacket.c)
    ///
    /// # Returns
    ///
    /// Current write position
    pub fn save_position(&self) -> usize {
        self.position
    }

    /// Restore saved position
    ///
    /// Corresponds to C's `save_counter(newval)` where newval != -1
    ///
    /// # Arguments
    ///
    /// * `pos` - Position to restore
    ///
    /// # Panics
    ///
    /// Panics if position is beyond current buffer size
    pub fn restore_position(&mut self, pos: usize) {
        assert!(pos <= self.buffer.len(), "Position beyond buffer size");
        self.position = pos;
        self.buffer.truncate(pos);
    }

    /// Get current packet length
    ///
    /// # Returns
    ///
    /// Number of bytes written to packet
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if packet is empty
    ///
    /// # Returns
    ///
    /// True if no data written
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get packet data as byte slice
    ///
    /// # Returns
    ///
    /// Reference to packet bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume packet and return owned byte vector
    ///
    /// # Returns
    ///
    /// Owned vector of packet bytes
    pub fn into_vec(self) -> Vec<u8> {
        self.buffer
    }

    /// Ensure buffer has capacity for additional bytes
    fn ensure_capacity(&mut self, additional: usize) {
        self.buffer.reserve(additional);
    }
}

impl Default for OutPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for OutPacket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.put_bytes(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_packet() {
        let packet = OutPacket::new();
        assert_eq!(packet.len(), 0);
        assert!(packet.is_empty());
    }

    #[test]
    fn test_put_u8() {
        let mut packet = OutPacket::new();
        packet.put_u8(0x42);
        assert_eq!(packet.as_bytes(), &[0x42]);
    }

    #[test]
    fn test_put_u16() {
        let mut packet = OutPacket::new();
        packet.put_u16(0x1234);
        assert_eq!(packet.as_bytes(), &[0x12, 0x34]);
    }

    #[test]
    fn test_put_u32() {
        let mut packet = OutPacket::new();
        packet.put_u32(0x12345678);
        assert_eq!(packet.as_bytes(), &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_put_bytes() {
        let mut packet = OutPacket::new();
        packet.put_bytes(&[0x01, 0x02, 0x03]);
        assert_eq!(packet.as_bytes(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_put_string() {
        let mut packet = OutPacket::new();
        packet.put_string("test");
        assert_eq!(packet.as_bytes(), b"test");
    }

    #[test]
    fn test_simple_option() {
        let mut packet = OutPacket::new();
        let pos = packet.begin_option(1); // OPTION6_CLIENTID
        packet.put_u32(0x12345678);
        packet.end_option(pos);

        let expected = vec![
            0x00, 0x01, // option code = 1
            0x00, 0x04, // length = 4
            0x12, 0x34, 0x56, 0x78, // data
        ];
        assert_eq!(packet.as_bytes(), expected.as_slice());
    }

    #[test]
    fn test_nested_options() {
        let mut packet = OutPacket::new();
        
        // Outer IA_NA option
        let ia_na_pos = packet.begin_option(3); // OPTION6_IA_NA
        packet.put_u32(0x11111111); // IAID
        packet.put_u32(3600); // T1
        packet.put_u32(7200); // T2
        
        // Inner IAADDR option
        let iaaddr_pos = packet.begin_option(5); // OPTION6_IAADDR
        packet.put_bytes(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // IPv6 address
        packet.put_u32(7200); // Preferred
        packet.put_u32(14400); // Valid
        packet.end_option(iaaddr_pos);
        
        packet.end_option(ia_na_pos);

        // Verify structure
        let data = packet.as_bytes();
        
        // Check outer option header
        assert_eq!(data[0..2], [0x00, 0x03]); // IA_NA option code
        
        // IA_NA length should be 12 (IAID+T1+T2) + 4 (IAADDR header) + 24 (IAADDR data) = 40
        assert_eq!(data[2..4], [0x00, 40]);
    }

    #[test]
    fn test_reset() {
        let mut packet = OutPacket::new();
        packet.put_u32(0x12345678);
        assert_eq!(packet.len(), 4);
        
        packet.reset();
        assert_eq!(packet.len(), 0);
        assert!(packet.is_empty());
    }

    #[test]
    fn test_position_save_restore() {
        let mut packet = OutPacket::new();
        packet.put_u16(0x1234);
        
        let pos = packet.save_position();
        assert_eq!(pos, 2);
        
        packet.put_u16(0x5678);
        assert_eq!(packet.len(), 4);
        
        packet.restore_position(pos);
        assert_eq!(packet.len(), 2);
        assert_eq!(packet.as_bytes(), &[0x12, 0x34]);
    }
}
