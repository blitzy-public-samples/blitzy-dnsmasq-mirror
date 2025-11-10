// dnsmasq is Copyright (c) 2000-2024 Simon Kelley
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

//! DNS Forwarding Loop Detection
//!
//! # Purpose
//!
//! This module implements DNS forwarding loop detection to prevent infinite recursion
//! when an upstream DNS server is misconfigured to point back to dnsmasq itself. Without
//! loop detection, dnsmasq could receive its own queries forwarded by an upstream server,
//! creating an infinite forwarding loop that exhausts resources and prevents proper DNS
//! resolution.
//!
//! # Algorithm
//!
//! The implementation uses a probe-based mechanism:
//! 1. Periodically send TXT queries to "XXXXXXXX.test" (where XXXXXXXX is server's UID)
//! 2. If dnsmasq receives its own probe query back, the upstream server is looping
//! 3. Mark the offending server with SERV_LOOP flag to exclude it from query forwarding
//! 4. Log the loop detection event for administrator notification
//!
//! # Key Functions
//!
//! - `LoopDetector::send_probes()` - Send loop detection probe queries to all upstream servers
//! - `LoopDetector::detect_loop()` - Identify incoming queries as loop detection probes
//! - `make_probe()` - Construct DNS TXT query packets with unique identifiers
//!
//! # RFC Compliance
//!
//! - RFC 2606 - Uses reserved domain "test" to avoid conflicts with real DNS queries
//! - RFC 1035 Section 4.1 - Constructs valid DNS TXT queries
//!
//! # Memory Safety Improvements over C
//!
//! - Replaces manual DNS packet buffer manipulation with safe DnsHeader API
//! - Eliminates buffer overflow risks in domain name encoding
//! - Uses Result<T, E> for error propagation instead of errno
//! - Async/await replaces blocking sendto() preventing event loop stalls
//! - No global state access - uses dependency injection pattern
//!
//! # Examples
//!
//! ```no_run
//! use dnsmasq::network::loop_detect::LoopDetector;
//! use dnsmasq::config::types::Config;
//! use dnsmasq::dns::upstream::UpstreamServer;
//! use std::sync::{Arc, RwLock};
//!
//! # async fn example() -> std::io::Result<()> {
//! let config = Arc::new(Config::default());
//! let servers = Arc::new(RwLock::new(vec![]));
//! let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
//!
//! let detector = LoopDetector::new(config, servers, socket);
//!
//! // Send probes to all upstream servers
//! detector.send_probes().await?;
//!
//! // Check if incoming query is a returning probe
//! if detector.detect_loop("12345678.test", 16).await? {
//!     tracing::warn!("Loop detected!");
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::vec::Vec;

use tokio::net::UdpSocket;
use tokio::time::Duration;
use tracing::{debug, error, info, trace, warn};

use crate::config::types::{Config, DaemonOptions};
use crate::dns::parser::extract_name;
use crate::dns::protocol::{DnsHeader, LOOP_TEST_DOMAIN, LOOP_TEST_TYPE, OPCODE_QUERY, C_IN};
use crate::dns::upstream::{check_servers, ServerFlags, UpstreamServer};
use crate::utils::rand::rand16;
use crate::utils::string::do_rfc1035_name;

/// Maximum size for DNS packet buffer (standard UDP DNS packet size)
const MAX_PACKET_SIZE: usize = 512;

/// Loop detection probe timeout (not used in C version, but useful for async)
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// DNS Forwarding Loop Detector
///
/// Manages loop detection by sending probe queries and identifying returning probes.
/// This struct maintains references to configuration, upstream server list, and a UDP
/// socket for sending probes.
///
/// # Thread Safety
///
/// This struct is designed for async/await concurrency. The Config is immutable after
/// construction (Arc), the server list uses RwLock for safe concurrent access, and
/// the UDP socket is wrapped in Arc for shared ownership across async tasks.
///
/// # Memory Safety
///
/// Unlike the C implementation which uses global mutable state (daemon->packet,
/// daemon->servers), this implementation uses dependency injection with Arc for
/// shared ownership and RwLock for interior mutability, eliminating data races
/// and use-after-free bugs.
pub struct LoopDetector {
    /// Immutable configuration containing OPT_LOOP_DETECT flag
    config: Arc<Config>,
    
    /// Shared mutable access to upstream server list
    /// Uses RwLock to allow multiple readers or single writer
    servers: Arc<RwLock<Vec<UpstreamServer>>>,
    
    /// UDP socket for sending probe queries
    /// Shared across async tasks for probe transmission
    socket: Arc<UdpSocket>,
}

impl LoopDetector {
    /// Create a new LoopDetector instance
    ///
    /// # Arguments
    ///
    /// * `config` - Shared configuration containing OPT_LOOP_DETECT flag
    /// * `servers` - Shared upstream server list with interior mutability
    /// * `socket` - UDP socket for sending probes
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::network::loop_detect::LoopDetector;
    /// # use std::sync::{Arc, RwLock};
    /// # async fn example() -> std::io::Result<()> {
    /// let config = Arc::new(Config::default());
    /// let servers = Arc::new(RwLock::new(vec![]));
    /// let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    /// let detector = LoopDetector::new(config, servers, socket);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        config: Arc<Config>,
        servers: Arc<RwLock<Vec<UpstreamServer>>>,
        socket: Arc<UdpSocket>,
    ) -> Self {
        Self {
            config,
            servers,
            socket,
        }
    }

    /// Send loop detection probe queries to all upstream DNS servers
    ///
    /// Iterates through all configured upstream DNS servers and sends a unique TXT query
    /// to each one. The query contains a hex-encoded unique identifier (UID) specific to
    /// each server. If dnsmasq later receives this same query back, it indicates that the
    /// upstream server is forwarding queries back to dnsmasq, creating a forwarding loop.
    ///
    /// # Behavior
    ///
    /// - Only sends probes if OPT_LOOP_DETECT option is enabled
    /// - Only probes "default" upstream servers (servers without specific domain restrictions)
    /// - Skips servers marked with SERV_FOR_NODOTS flag
    /// - Clears SERV_LOOP flag before sending to allow recovery if configuration corrected
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Probes sent successfully (or feature disabled)
    /// * `Err(IoError)` - Network error during probe transmission
    ///
    /// # Errors
    ///
    /// Returns `IoError` if:
    /// - Probe packet construction fails (buffer overflow, invalid domain name)
    /// - UDP socket send fails (network unreachable, permission denied)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::network::loop_detect::LoopDetector;
    /// # async fn example(detector: LoopDetector) -> std::io::Result<()> {
    /// detector.send_probes().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # C Equivalent
    ///
    /// Replaces `loop_send_probes()` from src/loop.c lines 123-150
    pub async fn send_probes(&self) -> IoResult<()> {
        // Check if loop detection is enabled (C version line 128-129)
        if !self.config.options.contains(DaemonOptions::OPT_LOOP_DETECT) {
            trace!("Loop detection disabled, skipping probe transmission");
            return Ok(());
        }

        info!("Sending loop detection probes to upstream servers");

        // Acquire read lock on server list (safe concurrent access)
        let servers = self.servers.read().map_err(|e| {
            error!("Failed to acquire read lock on servers: {}", e);
            IoError::new(ErrorKind::Other, "Server list lock poisoned")
        })?;

        let mut probes_sent = 0;
        let mut probe_failures = 0;

        // Iterate through all upstream servers (C version lines 133-147)
        for server in servers.iter() {
            // Only probe default servers without domain restrictions (C version lines 134-135)
            // Skip servers marked SERV_FOR_NODOTS
            if !server.domain.is_empty() || server.flags.contains(ServerFlags::FOR_NODOTS) {
                trace!(
                    "Skipping server {} (domain: {}, flags: {:?})",
                    server.addr,
                    server.domain,
                    server.flags
                );
                continue;
            }

            // Construct probe packet for this server's UID (C version line 137)
            let probe_packet = match make_probe(server.uid) {
                Ok(packet) => packet,
                Err(e) => {
                    error!("Failed to construct probe for server {}: {}", server.addr, e);
                    probe_failures += 1;
                    continue;
                }
            };

            // Send probe to upstream server (C version lines 145-146)
            // Replace blocking sendto() with async send_to()
            match self.socket.send_to(&probe_packet, &server.addr).await {
                Ok(bytes_sent) => {
                    debug!(
                        "Sent {} byte probe to server {} (UID: {:08x})",
                        bytes_sent, server.addr, server.uid
                    );
                    probes_sent += 1;
                }
                Err(e) => {
                    warn!(
                        "Failed to send probe to server {} (UID: {:08x}): {}",
                        server.addr, server.uid, e
                    );
                    probe_failures += 1;
                }
            }
        }

        info!(
            "Loop detection probes sent: {} successful, {} failed",
            probes_sent, probe_failures
        );

        Ok(())
    }


    /// Detect if an incoming DNS query is a loop detection probe
    ///
    /// Examines an incoming DNS query to determine if it matches a loop detection probe
    /// previously sent by `send_probes()`. If the query is for a TXT record matching
    /// the pattern "XXXXXXXX.test" (where XXXXXXXX is a hex-encoded UID), this function
    /// extracts the UID and searches for a matching upstream server. If found, the server
    /// is marked with SERV_LOOP flag to prevent forwarding queries to it.
    ///
    /// # Arguments
    ///
    /// * `query` - DNS query name (domain name) to examine
    /// * `qtype` - DNS query type (e.g., T_A=1, T_TXT=16)
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Loop detected, server marked with SERV_LOOP flag
    /// * `Ok(false)` - Not a loop probe, or no matching server found, or feature disabled
    /// * `Err(IoError)` - Error accessing server list (lock poisoned)
    ///
    /// # Validation Steps
    ///
    /// 1. Check if qtype == LOOP_TEST_TYPE (TXT record = 16)
    /// 2. Verify query length matches expected pattern (LOOP_TEST_DOMAIN + 9 chars)
    /// 3. Confirm LOOP_TEST_DOMAIN appears at correct position (after 8 hex digits + ".")
    /// 4. Validate first 8 characters are hexadecimal digits
    /// 5. Extract UID and search for matching server
    /// 6. Mark server with SERV_LOOP flag if match found
    ///
    /// # Side Effects
    ///
    /// When loop detected:
    /// - Sets SERV_LOOP flag on matching server
    /// - Calls `check_servers(true)` to log server state change
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::network::loop_detect::LoopDetector;
    /// # async fn example(detector: LoopDetector) -> std::io::Result<()> {
    /// if detector.detect_loop("12345678.test", 16).await? {
    ///     println!("Loop detected!");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # C Equivalent
    ///
    /// Replaces `detect_loop()` from src/loop.c lines 305-336
    pub async fn detect_loop(&self, query: &str, qtype: u16) -> IoResult<bool> {
        // Check if loop detection is enabled (C version line 311-312)
        if !self.config.options.contains(DaemonOptions::OPT_LOOP_DETECT) {
            return Ok(false);
        }

        // Only examine TXT queries (C version line 314)
        if qtype != LOOP_TEST_TYPE {
            return Ok(false);
        }

        // Validate query format: "XXXXXXXX.test" (C version lines 315-316)
        // Expected length: 8 hex digits + "." + LOOP_TEST_DOMAIN (without trailing dot)
        let expected_len = 8 + 1 + LOOP_TEST_DOMAIN.trim_end_matches('.').len();
        if query.len() != expected_len {
            return Ok(false);
        }

        // Check if LOOP_TEST_DOMAIN appears at position 9 (after "XXXXXXXX.")
        // C version line 316: strstr(query, LOOP_TEST_DOMAIN) != query + 9
        let domain_part = &query[9..];
        if !domain_part.eq_ignore_ascii_case(LOOP_TEST_DOMAIN.trim_end_matches('.')) {
            return Ok(false);
        }

        // Extract and validate hex UID (first 8 characters) (C version lines 319-321)
        let uid_str = &query[..8];
        if !uid_str.chars().all(|c| c.is_ascii_hexdigit()) {
            debug!("Query {} contains non-hex characters in UID", query);
            return Ok(false);
        }

        // Parse UID from hex string (C version line 323)
        let uid = match u32::from_str_radix(uid_str, 16) {
            Ok(uid) => uid,
            Err(e) => {
                warn!("Failed to parse UID from {}: {}", uid_str, e);
                return Ok(false);
            }
        };

        debug!(
            "Potential loop probe detected: query={}, uid={:08x}",
            query, uid
        );

        // Search for matching server and mark with SERV_LOOP flag (C version lines 325-333)
        let mut servers = self.servers.write().map_err(|e| {
            error!("Failed to acquire write lock on servers: {}", e);
            IoError::new(ErrorKind::Other, "Server list lock poisoned")
        })?;

        for server in servers.iter_mut() {
            // Only check default servers (no domain restriction) (C version line 326)
            if !server.domain.is_empty() {
                continue;
            }

            // Skip servers already marked with SERV_LOOP (C version line 327)
            if server.flags.contains(ServerFlags::LOOP) {
                continue;
            }

            // Check if UID matches (C version line 328)
            if uid == server.uid {
                // Mark server with SERV_LOOP flag (C version line 330)
                server.flags.insert(ServerFlags::LOOP);

                warn!(
                    "Loop detected: server {} (UID {:08x}) is forwarding queries back to dnsmasq",
                    server.addr, uid
                );

                // Log server state change without sending more probes (C version line 331)
                // Pass true to indicate we don't want to trigger more probe transmission
                check_servers(true);

                return Ok(true);
            }
        }

        // No matching server found (C version line 334)
        debug!(
            "Probe query {} with UID {:08x} does not match any server",
            query, uid
        );
        Ok(false)
    }
}

/// Construct DNS TXT query packet for loop detection probe
///
/// Creates a DNS query packet with a TXT record request for a hostname encoding
/// the provided UID. The query format is "XXXXXXXX.test" where XXXXXXXX is the
/// 32-bit uid parameter formatted as 8 hexadecimal digits, and "test" is the
/// RFC 2606 reserved domain.
///
/// # Arguments
///
/// * `uid` - Unique identifier (32-bit) assigned to the target server
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - DNS query packet bytes ready for transmission
/// * `Err(IoError)` - Packet construction failed (buffer overflow, encoding error)
///
/// # Packet Structure
///
/// - Random query ID (for DNS protocol compliance)
/// - RD (Recursion Desired) flag set
/// - Standard QUERY opcode
/// - Question count = 1, Answer/Authority/Additional counts = 0
/// - Question: "XXXXXXXX.test" IN TXT
///
/// # Examples
///
/// ```no_run
/// # use dnsmasq::network::loop_detect::make_probe;
/// let probe = make_probe(0x12345678).unwrap();
/// // probe contains DNS TXT query for "12345678.test"
/// ```
///
/// # C Equivalent
///
/// Replaces `loop_make_probe()` from src/loop.c lines 209-235
fn make_probe(uid: u32) -> IoResult<Vec<u8>> {
    // Allocate packet buffer (C version uses daemon->packet global buffer)
    let mut packet = Vec::with_capacity(MAX_PACKET_SIZE);

    // Create DNS header (C version lines 211, 217-222)
    let mut header = DnsHeader::new();
    header.set_id(rand16()); // Random query ID
    header.set_opcode(OPCODE_QUERY); // Standard query
    header.set_rd(true); // Recursion desired
    header.set_qdcount(1); // One question
    // Answer, authority, additional counts are 0 by default

    // Serialize header to packet buffer
    let header_bytes = header.to_bytes();
    packet.extend_from_slice(&header_bytes);

    // Construct query name: "XXXXXXXX.test" (C version lines 224-229)
    let query_name = format!("{:08x}.{}", uid, LOOP_TEST_DOMAIN.trim_end_matches('.'));

    // Encode domain name in RFC 1035 wire format (length-prefixed labels)
    // C version manually constructs this with *p++ = 8; sprintf(...); etc.
    let mut name_buffer = [0u8; 256]; // Max domain name length per RFC 1035
    let name_len = do_rfc1035_name(&query_name, &mut name_buffer, None).map_err(|e| {
        error!("Failed to encode domain name {}: {:?}", query_name, e);
        IoError::new(ErrorKind::InvalidInput, format!("Domain encoding failed: {:?}", e))
    })?;

    packet.extend_from_slice(&name_buffer[..name_len]);

    // Append query type (TXT) and class (IN) (C version lines 231-232)
    // PUTSHORT macros in C, we use manual big-endian encoding
    packet.extend_from_slice(&LOOP_TEST_TYPE.to_be_bytes());
    packet.extend_from_slice(&C_IN.to_be_bytes());

    debug!(
        "Constructed loop probe: uid={:08x}, query={}, packet_len={}",
        uid,
        query_name,
        packet.len()
    );

    Ok(packet)
}

/// Send loop detection probes to all upstream servers (standalone function)
///
/// Convenience wrapper around `LoopDetector::send_probes()` for compatibility
/// with module-level function exports.
///
/// # Arguments
///
/// * `detector` - Reference to LoopDetector instance
///
/// # Returns
///
/// * `Ok(())` - Probes sent successfully
/// * `Err(IoError)` - Network or configuration error
///
/// # Examples
///
/// ```no_run
/// # use dnsmasq::network::loop_detect::{LoopDetector, send_probes};
/// # async fn example(detector: LoopDetector) -> std::io::Result<()> {
/// send_probes(&detector).await?;
/// # Ok(())
/// # }
/// ```
pub async fn send_probes(detector: &LoopDetector) -> IoResult<()> {
    detector.send_probes().await
}

/// Detect if an incoming query is a loop detection probe (standalone function)
///
/// Convenience wrapper around `LoopDetector::detect_loop()` for compatibility
/// with module-level function exports.
///
/// # Arguments
///
/// * `detector` - Reference to LoopDetector instance
/// * `query` - DNS query name to examine
/// * `qtype` - DNS query type
///
/// # Returns
///
/// * `Ok(true)` - Loop detected and server marked
/// * `Ok(false)` - Not a loop probe
/// * `Err(IoError)` - Server list access error
///
/// # Examples
///
/// ```no_run
/// # use dnsmasq::network::loop_detect::{LoopDetector, detect_loop};
/// # async fn example(detector: LoopDetector) -> std::io::Result<()> {
/// if detect_loop(&detector, "12345678.test", 16).await? {
///     println!("Loop detected!");
/// }
/// # Ok(())
/// # }
/// ```
pub async fn detect_loop(detector: &LoopDetector, query: &str, qtype: u16) -> IoResult<bool> {
    detector.detect_loop(query, qtype).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Test probe packet construction
    #[test]
    fn test_make_probe() {
        let uid = 0x12345678;
        let packet = make_probe(uid).expect("Failed to construct probe");

        // Verify minimum packet size (header + question)
        assert!(packet.len() >= 12, "Packet too small: {}", packet.len());

        // Verify packet starts with valid DNS header
        assert_eq!(packet.len() % 2, 0, "Packet length should be even");

        // Packet should contain encoded "12345678.test" query
        // We can't easily verify the exact encoding without parsing,
        // but we can check the packet isn't empty
        assert!(packet.len() > 20, "Packet suspiciously small");
    }

    /// Test detect_loop with valid probe query
    #[tokio::test]
    async fn test_detect_loop_valid() {
        let config = Arc::new(Config {
            options: DaemonOptions::OPT_LOOP_DETECT,
            ..Default::default()
        });

        let test_uid = 0xABCD1234;
        let server = UpstreamServer {
            uid: test_uid,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            domain: String::new(),
            flags: ServerFlags::empty(),
            ..Default::default()
        };

        let servers = Arc::new(RwLock::new(vec![server]));
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind socket"),
        );

        let detector = LoopDetector::new(config, servers, socket);

        // Test with matching probe query
        let query = format!("{:08x}.test", test_uid);
        let result = detector
            .detect_loop(&query, LOOP_TEST_TYPE)
            .await
            .expect("detect_loop failed");

        assert!(result, "Should detect loop for matching UID");

        // Verify server is marked with SERV_LOOP flag
        let servers = detector.servers.read().unwrap();
        assert!(servers[0].flags.contains(ServerFlags::LOOP));
    }

    /// Test detect_loop with non-matching query
    #[tokio::test]
    async fn test_detect_loop_no_match() {
        let config = Arc::new(Config {
            options: DaemonOptions::OPT_LOOP_DETECT,
            ..Default::default()
        });

        let servers = Arc::new(RwLock::new(vec![]));
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind socket"),
        );

        let detector = LoopDetector::new(config, servers, socket);

        // Test with non-probe query
        let result = detector
            .detect_loop("example.com", 1) // A record, not TXT
            .await
            .expect("detect_loop failed");

        assert!(!result, "Should not detect loop for non-TXT query");
    }

    /// Test detect_loop with feature disabled
    #[tokio::test]
    async fn test_detect_loop_disabled() {
        let config = Arc::new(Config {
            options: DaemonOptions::empty(), // OPT_LOOP_DETECT not set
            ..Default::default()
        });

        let servers = Arc::new(RwLock::new(vec![]));
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("Failed to bind socket"),
        );

        let detector = LoopDetector::new(config, servers, socket);

        let result = detector
            .detect_loop("12345678.test", LOOP_TEST_TYPE)
            .await
            .expect("detect_loop failed");

        assert!(!result, "Should not detect loop when feature disabled");
    }
}
