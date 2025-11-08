// Copyright (c) 2000-2024 Simon Kelley and contributors
// Licensed under GPL-2.0-or-later
//
// DNS forwarding loop detection preventing infinite recursion
//
// Translated from: src/loop.c

//! DNS Forwarding Loop Detection
//!
//! This module implements probe-based loop detection to prevent infinite DNS forwarding loops
//! when upstream servers are misconfigured to point back to dnsmasq. The implementation sends
//! unique TXT queries to upstream servers and watches for those queries to return, indicating
//! a forwarding loop.
//!
//! ## Algorithm
//!
//! 1. Generate unique probe queries: "XXXXXXXX.test" TXT records where XXXXXXXX is a hex UID
//! 2. Periodically send probes to all default upstream DNS servers
//! 3. Monitor incoming queries for matching probe patterns
//! 4. Mark servers with SERV_LOOP flag when loops are detected
//! 5. Exclude looped servers from query forwarding
//!
//! ## Memory Safety
//!
//! Replaces C's global daemon->packet buffer and manual pointer arithmetic with:
//! - Vec<u8> for probe packet construction (automatic memory management)
//! - HashMap for UID tracking (type-safe server identification)
//! - Tokio async sockets (non-blocking I/O with automatic resource cleanup)
//!
//! ## RFC Compliance
//!
//! - RFC 2606: Uses reserved ".test" TLD to avoid conflicts with real DNS traffic
//! - RFC 1035: Generates valid DNS TXT query packets with proper header and question sections
//!
//! ## C Source Reference
//!
//! Translated from:
//! - `src/loop.c` (lines 1-339) - Complete loop detection implementation
//! - `src/dnsmasq.h` (lines 575-593) - struct server with uid field

use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::time::Duration;

use byteorder::{NetworkEndian, WriteBytesExt};
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, error, warn};

use crate::constants::DNS_PACKET_SIZE;
use crate::dns::forward::Server;
use crate::dns::protocol::RecordType;
use crate::types::errors::DnsmasqError;

/// Server flag indicating a detected forwarding loop (from C's `SERV_LOOP`)
///
/// This flag is set on upstream servers that return our own probe queries,
/// indicating they are forwarding DNS requests back to dnsmasq and creating
/// an infinite loop. Servers with this flag are excluded from query forwarding.
///
/// Value: 0x0020 (next available bit after `SERV_HAS_DOMAIN` = 0x0010)
pub const SERV_LOOP: u16 = 0x0020;

/// RFC 2606 reserved domain suffix for loop detection probes
///
/// Using ".test" TLD ensures probe queries never conflict with legitimate
/// DNS traffic since "test" is reserved for testing purposes and will never
/// be delegated in the global DNS.
const PROBE_DOMAIN_SUFFIX: &str = "test";

/// DNS TXT record type for probe queries (RFC 1035)
const PROBE_QUERY_TYPE: u16 = RecordType::TXT as u16;

/// Length of hexadecimal UID in probe domain name (8 hex digits = 32-bit u32)
const UID_HEX_LENGTH: usize = 8;

/// DNS query class IN (Internet) - RFC 1035 Section 3.2.4
const DNS_CLASS_IN: u16 = 1;

/// DNS header query/response bit - 0 for queries
const DNS_QR_QUERY: u16 = 0x0000;

/// DNS header opcode - 0 for standard query
const DNS_OPCODE_QUERY: u16 = 0x0000;

/// DNS header recursion desired bit
const DNS_RD_BIT: u16 = 0x0100;

/// Loop detection error types
#[derive(Debug, Error)]
pub enum LoopDetectError {
    /// Socket I/O error during probe transmission
    #[error("Socket error during loop detection: {0}")]
    SocketError(#[from] std::io::Error),

    /// Failed to construct probe packet
    #[error("Failed to build loop detection probe packet")]
    PacketBuildError,

    /// Invalid server configuration
    #[error("Invalid server configuration for loop detection")]
    InvalidServerConfig,
}

/// DNS forwarding loop detector with probe-based detection
///
/// Manages the lifecycle of loop detection probes, tracking unique identifiers
/// for each upstream server and monitoring incoming queries for probe matches.
///
/// ## Design
///
/// Unlike the C implementation which uses a global uid field in struct server,
/// this Rust implementation tracks UIDs in a `HashMap` keyed by server address.
/// This provides better separation of concerns and allows the Server struct
/// to remain simpler.
///
/// ## Usage
///
/// ```rust,ignore
/// let mut detector = LoopDetector::new(true, Duration::from_secs(30));
///
/// // Send probes periodically
/// detector.send_probes(&mut servers, &socket).await?;
///
/// // Check incoming queries
/// if let Some(uid) = detector.is_probe_query(&query_name, query_type) {
///     // Mark the server with matching UID as looped
///     for server in &mut servers {
///         if detector.get_server_uid(&server.addr) == Some(uid) {
///             server.flags |= SERV_LOOP;
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct LoopDetector {
    /// Enable/disable loop detection at runtime
    pub enabled: bool,

    /// Interval between probe transmissions
    pub probe_interval: Duration,

    /// Map of server addresses to unique identifiers for probe generation
    server_uids: HashMap<SocketAddr, u32>,

    /// Counter for generating unique UIDs
    uid_counter: u32,
}

impl LoopDetector {
    /// Create a new loop detector
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether loop detection is active
    /// * `probe_interval` - Time between sending probes to upstream servers
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use std::time::Duration;
    /// let detector = LoopDetector::new(true, Duration::from_secs(30));
    /// ```
    #[must_use]
    pub fn new(enabled: bool, probe_interval: Duration) -> Self {
        Self {
            enabled,
            probe_interval,
            server_uids: HashMap::new(),
            uid_counter: 1, // Start at 1 to avoid zero values
        }
    }

    /// Get or create a UID for the given server address
    ///
    /// Returns existing UID if server already has one, otherwise allocates
    /// a new UID and stores it in the tracking `HashMap`.
    ///
    /// # Arguments
    ///
    /// * `addr` - Server socket address
    ///
    /// # Returns
    ///
    /// Unique 32-bit identifier for this server
    fn get_or_create_uid(&mut self, addr: &SocketAddr) -> u32 {
        if let Some(&uid) = self.server_uids.get(addr) {
            uid
        } else {
            let uid = self.uid_counter;
            self.uid_counter = self.uid_counter.wrapping_add(1);
            self.server_uids.insert(*addr, uid);
            debug!(
                server_addr = %addr,
                uid = uid,
                "Assigned UID to upstream server for loop detection"
            );
            uid
        }
    }

    /// Get the UID for a server address if it exists
    ///
    /// # Arguments
    ///
    /// * `addr` - Server socket address
    ///
    /// # Returns
    ///
    /// Some(uid) if server has been assigned a UID, None otherwise
    #[must_use]
    pub fn get_server_uid(&self, addr: &SocketAddr) -> Option<u32> {
        self.server_uids.get(addr).copied()
    }

    /// Send loop detection probes to all default upstream servers
    ///
    /// Iterates through all servers without domain restrictions and sends
    /// a unique TXT query to each. Clears `SERV_LOOP` flag before sending to
    /// allow recovery if upstream configuration has been fixed.
    ///
    /// Corresponds to C's `loop_send_probes()` (loop.c lines 123-150)
    ///
    /// # Arguments
    ///
    /// * `servers` - Mutable slice of upstream server configurations
    /// * `socket` - UDP socket for sending probes
    ///
    /// # Returns
    ///
    /// Ok(()) on success, Err if socket operations fail
    ///
    /// # Errors
    ///
    /// Returns error if socket send operations fail
    ///
    /// # Async
    ///
    /// Uses `tokio::net::UdpSocket::send_to` for non-blocking transmission
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let socket = UdpSocket::bind("0.0.0.0:0").await?;
    /// detector.send_probes(&mut servers, &socket).await?;
    /// ```
    pub async fn send_probes(
        &mut self,
        servers: &mut [Server],
        socket: &UdpSocket,
    ) -> Result<(), LoopDetectError> {
        if !self.enabled {
            return Ok(());
        }

        debug!("Sending loop detection probes to upstream servers");

        for server in servers.iter_mut() {
            // Only probe default servers (no domain restrictions)
            // Skip servers marked for specific domains (SERV_HAS_DOMAIN would be the flag)
            if server.domain.is_some() {
                continue;
            }

            // Clear SERV_LOOP flag to allow recovery
            server.flags &= !SERV_LOOP;

            // Get or create UID for this server
            let uid = self.get_or_create_uid(&server.addr);

            // Build probe query packet
            let probe_packet = make_probe_query(uid)?;

            // Send probe to server
            match socket.send_to(&probe_packet, server.addr).await {
                Ok(bytes_sent) => {
                    debug!(
                        server_addr = %server.addr,
                        uid = uid,
                        bytes_sent = bytes_sent,
                        "Sent loop detection probe"
                    );
                }
                Err(e) => {
                    warn!(
                        server_addr = %server.addr,
                        uid = uid,
                        error = %e,
                        "Failed to send loop detection probe"
                    );
                    // Continue with other servers even if one fails
                }
            }
        }

        Ok(())
    }

    /// Check if an incoming DNS query is a loop detection probe
    ///
    /// Examines the query name and type to determine if it matches a probe
    /// previously sent by `send_probes()`. Valid probes have the format
    /// "XXXXXXXX.test" where XXXXXXXX is 8 hexadecimal digits.
    ///
    /// Corresponds to C's `detect_loop()` (loop.c lines 305-336)
    ///
    /// # Arguments
    ///
    /// * `query_name` - DNS query domain name (e.g., "12345678.test")
    /// * `query_type` - DNS query type (must be TXT for probes)
    ///
    /// # Returns
    ///
    /// Some(uid) if query matches a probe pattern, None otherwise
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if let Some(uid) = detector.is_probe_query("abcd1234.test", 16) {
    ///     println!("Detected loop with UID: {}", uid);
    /// }
    /// ```
    #[must_use]
    pub fn is_probe_query(&self, query_name: &str, query_type: u16) -> Option<u32> {
        if !self.enabled {
            return None;
        }

        // Check query type is TXT
        if query_type != PROBE_QUERY_TYPE {
            return None;
        }

        // Parse probe name: should be "XXXXXXXX.test"
        parse_probe_name(query_name)
    }
}

/// Generate a DNS TXT query packet for loop detection probe
///
/// Constructs a valid RFC 1035 DNS query with:
/// - Random query ID
/// - Recursion Desired (RD) flag set
/// - Question for "XXXXXXXX.test" TXT record
/// - Standard query opcode
///
/// Corresponds to C's `loop_make_probe()` (loop.c lines 209-235)
///
/// # Arguments
///
/// * `uid` - Unique identifier to encode in probe domain name
///
/// # Returns
///
/// Ok(Vec<u8>) containing complete DNS query packet
/// Err(LoopDetectError) if packet construction fails
///
/// # Wire Format
///
/// ```text
/// DNS Header (12 bytes):
///   ID: random 16-bit value
///   Flags: QR=0, OPCODE=0, RD=1, others=0
///   QDCOUNT: 1
///   ANCOUNT: 0
///   NSCOUNT: 0
///   ARCOUNT: 0
///
/// Question Section:
///   QNAME: 8 <hex-uid> 4 test 0
///   QTYPE: 16 (TXT)
///   QCLASS: 1 (IN)
/// ```
fn make_probe_query(uid: u32) -> Result<Vec<u8>, LoopDetectError> {
    // Allocate buffer for probe packet
    let mut packet = Vec::with_capacity(DNS_PACKET_SIZE);
    let mut cursor = Cursor::new(&mut packet);

    // DNS Header (12 bytes)
    // ID: Use a random value (or can use uid & 0xFFFF for determinism)
    cursor
        .write_u16::<NetworkEndian>((uid & 0xFFFF) as u16)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Flags: QR=0 (query), OPCODE=0 (standard query), RD=1 (recursion desired)
    let flags = DNS_QR_QUERY | DNS_OPCODE_QUERY | DNS_RD_BIT;
    cursor
        .write_u16::<NetworkEndian>(flags)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Question count = 1
    cursor
        .write_u16::<NetworkEndian>(1)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Answer count = 0
    cursor
        .write_u16::<NetworkEndian>(0)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Authority count = 0
    cursor
        .write_u16::<NetworkEndian>(0)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Additional count = 0
    cursor
        .write_u16::<NetworkEndian>(0)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Question Section: QNAME for "XXXXXXXX.test"
    // Format: <length-byte><label-bytes>...<length-byte><label-bytes><0x00>

    // First label: 8-character hex UID
    let uid_hex = format!("{uid:08x}");
    #[allow(clippy::cast_possible_truncation)]
    cursor
        .write_u8(UID_HEX_LENGTH as u8)
        .map_err(|_| LoopDetectError::PacketBuildError)?;
    cursor
        .write_all(uid_hex.as_bytes())
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Second label: "test"
    #[allow(clippy::cast_possible_truncation)]
    cursor
        .write_u8(PROBE_DOMAIN_SUFFIX.len() as u8)
        .map_err(|_| LoopDetectError::PacketBuildError)?;
    cursor
        .write_all(PROBE_DOMAIN_SUFFIX.as_bytes())
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Terminating zero byte
    cursor
        .write_u8(0)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // QTYPE: TXT (16)
    cursor
        .write_u16::<NetworkEndian>(PROBE_QUERY_TYPE)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // QCLASS: IN (1)
    cursor
        .write_u16::<NetworkEndian>(DNS_CLASS_IN)
        .map_err(|_| LoopDetectError::PacketBuildError)?;

    // Get final packet length
    #[allow(clippy::cast_possible_truncation)]
    let packet_len = cursor.position() as usize;
    // Cursor goes out of scope here, releasing the borrow

    packet.truncate(packet_len);

    debug!(
        uid = uid,
        packet_len = packet_len,
        query_name = format!("{}.{}", uid_hex, PROBE_DOMAIN_SUFFIX),
        "Built loop detection probe packet"
    );

    Ok(packet)
}

/// Parse a probe query name to extract the UID
///
/// Valid probe names have the format "XXXXXXXX.test" where:
/// - XXXXXXXX is exactly 8 hexadecimal digits (case insensitive)
/// - Domain ends with ".test" (RFC 2606 reserved TLD)
///
/// # Arguments
///
/// * `query_name` - Domain name from incoming DNS query
///
/// # Returns
///
/// Some(uid) if name matches probe pattern, None otherwise
///
/// # Examples
///
/// ```rust,ignore
/// assert_eq!(parse_probe_name("abcd1234.test"), Some(0xabcd1234));
/// assert_eq!(parse_probe_name("invalid.test"), None);
/// assert_eq!(parse_probe_name("12345678.com"), None);
/// ```
fn parse_probe_name(query_name: &str) -> Option<u32> {
    // Expected format: "XXXXXXXX.test"
    // Total length: 8 (hex) + 1 (dot) + 4 (test) = 13 characters
    let expected_len = UID_HEX_LENGTH + 1 + PROBE_DOMAIN_SUFFIX.len();
    if query_name.len() != expected_len {
        return None;
    }

    // Check if it ends with ".test"
    if !query_name.ends_with(&format!(".{PROBE_DOMAIN_SUFFIX}")) {
        return None;
    }

    // Extract the first 8 characters (hex UID)
    let hex_part = &query_name[..UID_HEX_LENGTH];

    // Validate all characters are hexadecimal
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    // Parse hex string to u32
    match u32::from_str_radix(hex_part, 16) {
        Ok(uid) => {
            debug!(
                query_name = query_name,
                uid = uid,
                "Detected loop detection probe query"
            );
            Some(uid)
        }
        Err(e) => {
            warn!(
                query_name = query_name,
                error = %e,
                "Failed to parse probe UID from query name"
            );
            None
        }
    }
}

/// Convenience function: send loop detection probes
///
/// Wrapper around `LoopDetector::send_probes()` for simpler API usage.
/// Exported for use by the forwarding subsystem.
///
/// # Arguments
///
/// * `detector` - Loop detector instance
/// * `servers` - Mutable slice of upstream servers
/// * `socket` - UDP socket for probe transmission
///
/// # Returns
///
/// Result indicating success or socket error
///
/// # Errors
///
/// Returns `LoopDetectError::SocketError` if UDP socket operations fail
pub async fn send_probes(
    detector: &mut LoopDetector,
    servers: &mut [Server],
    socket: &UdpSocket,
) -> Result<(), LoopDetectError> {
    detector.send_probes(servers, socket).await
}

/// Convenience function: check if query is a probe
///
/// Wrapper around `LoopDetector::is_probe_query()` for simpler API usage.
/// Exported for use by the DNS query processing pipeline.
///
/// # Arguments
///
/// * `detector` - Loop detector instance
/// * `query_name` - DNS query domain name
/// * `query_type` - DNS query type
///
/// # Returns
///
/// Some(uid) if query is a probe, None otherwise
#[must_use]
pub fn is_probe_query(detector: &LoopDetector, query_name: &str, query_type: u16) -> Option<u32> {
    detector.is_probe_query(query_name, query_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_loop_detector_creation() {
        let detector = LoopDetector::new(true, Duration::from_secs(30));
        assert!(detector.enabled);
        assert_eq!(detector.probe_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_uid_generation() {
        let mut detector = LoopDetector::new(true, Duration::from_secs(30));
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "8.8.4.4:53".parse().unwrap();

        let uid1 = detector.get_or_create_uid(&addr1);
        let uid2 = detector.get_or_create_uid(&addr2);
        let uid1_again = detector.get_or_create_uid(&addr1);

        assert_ne!(uid1, uid2);
        assert_eq!(uid1, uid1_again);
    }

    #[test]
    fn test_make_probe_query() {
        let uid = 0x1234_5678;
        let packet = make_probe_query(uid).unwrap();

        // Verify packet is not empty and has reasonable size
        assert!(!packet.is_empty());
        assert!(packet.len() < DNS_PACKET_SIZE);

        // Verify DNS header structure (12 bytes minimum)
        assert!(packet.len() >= 12);

        // Check question count is 1 (bytes 4-5 in big-endian)
        assert_eq!(packet[4], 0);
        assert_eq!(packet[5], 1);
    }

    #[test]
    fn test_parse_probe_name_valid() {
        assert_eq!(parse_probe_name("12345678.test"), Some(0x1234_5678));
        assert_eq!(parse_probe_name("abcdef01.test"), Some(0xabcd_ef01));
        assert_eq!(parse_probe_name("00000000.test"), Some(0x0000_0000));
        assert_eq!(parse_probe_name("ffffffff.test"), Some(0xffff_ffff));
        // Case insensitive hex
        assert_eq!(parse_probe_name("ABCDEF01.test"), Some(0xABCD_EF01));
    }

    #[test]
    fn test_parse_probe_name_invalid() {
        // Wrong length
        assert_eq!(parse_probe_name("1234567.test"), None);
        assert_eq!(parse_probe_name("123456789.test"), None);

        // Wrong TLD
        assert_eq!(parse_probe_name("12345678.com"), None);
        assert_eq!(parse_probe_name("12345678.net"), None);

        // Non-hex characters
        assert_eq!(parse_probe_name("1234567g.test"), None);
        assert_eq!(parse_probe_name("1234567-.test"), None);

        // Empty or malformed
        assert_eq!(parse_probe_name(""), None);
        assert_eq!(parse_probe_name(".test"), None);
        assert_eq!(parse_probe_name("test"), None);
    }

    #[test]
    fn test_is_probe_query_disabled() {
        let detector = LoopDetector::new(false, Duration::from_secs(30));
        assert_eq!(
            detector.is_probe_query("12345678.test", PROBE_QUERY_TYPE),
            None
        );
    }

    #[test]
    fn test_is_probe_query_wrong_type() {
        let detector = LoopDetector::new(true, Duration::from_secs(30));
        // Query type 1 (A record) should not be detected as probe
        assert_eq!(detector.is_probe_query("12345678.test", 1), None);
    }

    #[test]
    fn test_is_probe_query_valid() {
        let detector = LoopDetector::new(true, Duration::from_secs(30));
        let result = detector.is_probe_query("abcd1234.test", PROBE_QUERY_TYPE);
        assert_eq!(result, Some(0xabcd_1234));
    }

    #[test]
    fn test_serv_loop_flag_value() {
        // Ensure SERV_LOOP doesn't conflict with other server flags
        use crate::dns::forward::{
            SERV_FROM_DBUS, SERV_HAS_DOMAIN, SERV_LITERAL_ADDRESS, SERV_NO_REBIND, SERV_USE_RESOLV,
        };

        assert_ne!(SERV_LOOP & SERV_FROM_DBUS, SERV_FROM_DBUS);
        assert_ne!(SERV_LOOP & SERV_LITERAL_ADDRESS, SERV_LITERAL_ADDRESS);
        assert_ne!(SERV_LOOP & SERV_USE_RESOLV, SERV_USE_RESOLV);
        assert_ne!(SERV_LOOP & SERV_NO_REBIND, SERV_NO_REBIND);
        assert_ne!(SERV_LOOP & SERV_HAS_DOMAIN, SERV_HAS_DOMAIN);
    }

    #[tokio::test]
    async fn test_send_probes_disabled() {
        let mut detector = LoopDetector::new(false, Duration::from_secs(30));
        let mut servers = vec![];
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Should succeed but do nothing when disabled
        let result = detector.send_probes(&mut servers, &socket).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_probes_empty_servers() {
        let mut detector = LoopDetector::new(true, Duration::from_secs(30));
        let mut servers = vec![];
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let result = detector.send_probes(&mut servers, &socket).await;
        assert!(result.is_ok());
    }
}
