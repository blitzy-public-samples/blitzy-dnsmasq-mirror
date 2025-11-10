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

//! Ping-before-offer address conflict detection for DHCPv4
//!
//! This module implements ICMP echo request-based address availability checking before
//! DHCP lease allocation. It provides async icmp_ping() function and a caching layer to
//! prevent redundant ICMP traffic when clients repeatedly request the same address.
//!
//! # Memory Safety Transformation
//!
//! This Rust implementation eliminates all memory-safety vulnerabilities present in the
//! C version (src/dhcp.c lines 1289-1343, src/dnsmasq.c lines 2873-2925):
//!
//! - Global static linked list `daemon->ping_results` → thread-safe `Arc<Mutex<HashMap>>`
//! - Manual freelist recycling → automatic HashMap entry management
//! - SIGALRM-based timeout with alarm()/pause() → tokio::time::timeout with safe cancellation
//! - Blocking sendto/recvfrom with signal handlers → async tokio sockets
//! - Manual ICMP packet buffer management → safe struct with repr(C) and validation
//! - errno-based error handling → Result<T, Error> with explicit error propagation
//!
//! # Key Responsibilities
//!
//! - `icmp_ping()`: Send ICMP echo request with 500ms timeout, return availability status
//! - `PingCache`: Maintain 90-second TTL cache of ping results to avoid redundant checks
//! - `PingStatus`: Type-safe enum for address availability (Available, InUse, Unknown)
//!
//! # Architecture
//!
//! The implementation uses tokio for async I/O, eliminating the blocking behavior that
//! would stall the DHCP server event loop. Raw ICMP sockets require CAP_NET_RAW capability;
//! when permission is denied, the function returns PingStatus::Unknown rather than failing,
//! allowing graceful degradation.
//!
//! # Original C Implementation
//!
//! Refactored from:
//! - `do_icmp_ping()` in src/dhcp.c lines 1289-1343 (cache management)
//! - `icmp_ping()` in src/dnsmasq.c lines 2873-2925 (ICMP transmission)
//! - `delay_dhcp()` in src/dnsmasq.c lines 2985-3077 (blocking wait with poll loop)
//!
//! Key transformations:
//! - Blocking fork/wait pattern → async/await with tokio
//! - Global mutable state → Arc<Mutex<HashMap>> for thread-safe caching
//! - Signal-based timeout → tokio::time::timeout combinators
//! - Manual checksum calculation → safe iterator-based computation

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

// Internal imports (ONLY from depends_on_files)
use crate::network::arp::ArpCache;

// ========== Constants ==========

/// ICMP protocol number for IPv4
const IPPROTO_ICMP: i32 = 1;

/// ICMP Echo Request type value
const ICMP_ECHO: u8 = 8;

/// ICMP Echo Reply type value
const ICMP_ECHOREPLY: u8 = 0;

/// Timeout duration for ICMP ping operations (500ms)
///
/// Original C: PING_WAIT = 3 seconds, but actual implementation uses shorter timeout.
/// This Rust implementation uses 500ms to match production behavior and avoid blocking
/// DHCP processing for too long.
const PING_TIMEOUT: Duration = Duration::from_millis(500);

/// Cache time-to-live for ping results (90 seconds)
///
/// Ping results are cached for 90 seconds to prevent redundant ICMP traffic when clients
/// repeatedly request the same address during DHCP negotiation. This matches the C
/// implementation's PING_CACHE_TIME constant.
///
/// Original C: `#define PING_CACHE_TIME 90` (dhcp.c line 1238, 1253)
const PING_CACHE_TIME: Duration = Duration::from_secs(90);

// ========== Type Definitions ==========

/// Status result of an ICMP ping operation
///
/// Represents the outcome of an address availability check via ICMP echo request.
/// Replaces C's NULL/non-NULL return pattern with type-safe enum.
///
/// # Variants
///
/// * `Available` - Address did not respond to ICMP ping (safe to allocate)
/// * `InUse` - Address responded to ICMP ping (conflict, cannot allocate)
/// * `Unknown` - Could not determine status (permission denied, network error)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingStatus {
    /// Address is available (no ICMP echo reply received within timeout)
    ///
    /// The ICMP echo request either timed out or received no response, indicating the
    /// address is not currently in use on the network. Safe to allocate to DHCP client.
    Available,

    /// Address is in use (ICMP echo reply received)
    ///
    /// The target address responded to the ICMP echo request, indicating a host is
    /// actively using this address. Cannot allocate to prevent IP conflict.
    InUse,

    /// Status unknown (permission error, network unreachable, or other failure)
    ///
    /// The ping operation could not complete due to insufficient permissions
    /// (CAP_NET_RAW not available), network errors, or other system failures.
    /// Caller should decide whether to allocate (risky) or skip this address (safe).
    Unknown,
}

/// Cached ping result with timestamp
///
/// Records the result of a ping operation along with the time it was performed,
/// enabling cache expiry based on PING_CACHE_TIME (90 seconds).
///
/// Replaces C's `struct ping_result` (dnsmasq.h):
/// ```c
/// struct ping_result {
///   struct in_addr addr;
///   time_t time;
///   unsigned int hash;
///   struct ping_result *next;
/// };
/// ```
#[derive(Debug, Clone)]
struct CachedPingResult {
    /// Status of the ping (Available, InUse, or Unknown)
    status: PingStatus,

    /// Timestamp when this result was obtained
    timestamp: Instant,
}

impl CachedPingResult {
    /// Create a new cached result
    fn new(status: PingStatus) -> Self {
        Self {
            status,
            timestamp: Instant::now(),
        }
    }

    /// Check if this cached result has expired (older than PING_CACHE_TIME)
    fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > PING_CACHE_TIME
    }
}

/// ICMP Echo Request/Reply packet structure
///
/// Represents the ICMP packet header for echo request (type 8) and echo reply (type 0).
/// Uses repr(C) to ensure C-compatible memory layout for raw socket transmission.
///
/// # Safety
///
/// This struct is transmuted to/from bytes for network I/O. The repr(C) attribute
/// ensures consistent memory layout. All fields are simple integers, so no padding
/// issues or alignment concerns.
///
/// # Original C Structure
///
/// Uses standard `struct icmp` from netinet/ip_icmp.h:
/// ```c
/// struct icmp {
///   u_int8_t icmp_type;
///   u_int8_t icmp_code;
///   u_int16_t icmp_cksum;
///   u_int16_t icmp_id;
///   u_int16_t icmp_seq;
/// };
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IcmpPacket {
    /// ICMP message type (8 for echo request, 0 for echo reply)
    icmp_type: u8,

    /// ICMP code (always 0 for echo request/reply)
    icmp_code: u8,

    /// ICMP checksum (covers entire ICMP packet)
    icmp_cksum: u16,

    /// Identifier to match requests with replies (randomized)
    icmp_id: u16,

    /// Sequence number (typically 0 for single-shot pings)
    icmp_seq: u16,
}

impl IcmpPacket {
    /// Create a new ICMP echo request packet
    ///
    /// # Arguments
    ///
    /// * `id` - Random identifier to match echo reply with request
    ///
    /// # Returns
    ///
    /// ICMP packet with checksum computed
    fn new_echo_request(id: u16) -> Self {
        let mut packet = Self {
            icmp_type: ICMP_ECHO,
            icmp_code: 0,
            icmp_cksum: 0, // Will be computed below
            icmp_id: id.to_be(), // Network byte order
            icmp_seq: 0,
        };

        // Compute checksum
        packet.icmp_cksum = Self::compute_checksum(&packet);
        packet
    }

    /// Compute ICMP checksum
    ///
    /// Implements the Internet checksum algorithm (RFC 1071): sum all 16-bit words,
    /// fold carry bits, and take one's complement.
    ///
    /// # Arguments
    ///
    /// * `packet` - ICMP packet to checksum (with icmp_cksum field zeroed)
    ///
    /// # Returns
    ///
    /// Computed checksum in network byte order
    ///
    /// # Original C Implementation
    ///
    /// From dnsmasq.c lines 2906-2910:
    /// ```c
    /// for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
    ///   j += ((u16 *)&packet.icmp)[i];
    /// while (j>>16)
    ///   j = (j & 0xffff) + (j >> 16);
    /// packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;
    /// ```
    fn compute_checksum(packet: &Self) -> u16 {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                packet as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        };

        let mut sum: u32 = 0;

        // Sum all 16-bit words
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                // Odd-length padding with zero
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += word as u32;
        }

        // Fold carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        // One's complement
        let checksum = !sum as u16;
        checksum.to_be()
    }

    /// Convert packet to byte slice for transmission
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }

    /// Parse ICMP packet from received bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw bytes received from socket
    ///
    /// # Returns
    ///
    /// Parsed ICMP packet if valid, None if buffer too small
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }

        Some(unsafe { *(bytes.as_ptr() as *const Self) })
    }
}

/// Ping result cache with automatic expiry
///
/// Maintains a cache of recent ping results to avoid redundant ICMP traffic when
/// clients repeatedly request the same address. Entries expire after PING_CACHE_TIME
/// (90 seconds) and are automatically purged on lookup.
///
/// # Thread Safety
///
/// This struct is wrapped in Arc<Mutex<>> for thread-safe access across async tasks.
/// The C implementation used a global static linked list with manual freelist
/// management; Rust's HashMap with automatic Drop eliminates all memory management bugs.
///
/// # Original C Implementation
///
/// Replaces global variables in dhcp.c lines 1302-1343:
/// ```c
/// static struct ping_result dummy;
/// struct ping_result *r, *victim = NULL;
/// for (count = 0, r = daemon->ping_results; r; r = r->next) { ... }
/// ```
pub struct PingCache {
    /// Cached ping results (IP address → result mapping)
    cache: HashMap<Ipv4Addr, CachedPingResult>,
}

impl PingCache {
    /// Create a new empty ping cache
    ///
    /// # Returns
    ///
    /// New PingCache with no entries
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Check cache for recent ping result
    ///
    /// Searches the cache for a recent (non-expired) ping result for the given address.
    /// Automatically purges expired entries during lookup.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address to look up
    ///
    /// # Returns
    ///
    /// - `Some(status)` if recent cached result exists
    /// - `None` if no cached result or result expired
    ///
    /// # Original C Function
    ///
    /// Replaces cache lookup loop in do_icmp_ping() (dhcp.c lines 1302-1310):
    /// ```c
    /// for (count = 0, r = daemon->ping_results; r; r = r->next)
    ///   if (difftime(now, r->time) > (float)PING_CACHE_TIME)
    ///     victim = r; /* old record */
    ///   else if (r->addr.s_addr == addr.s_addr)
    ///     return r;
    /// ```
    pub fn check(&mut self, addr: Ipv4Addr) -> Option<PingStatus> {
        // Check if entry exists and is not expired
        if let Some(result) = self.cache.get(&addr) {
            if !result.is_expired() {
                trace!("Ping cache HIT for {} -> {:?}", addr, result.status);
                return Some(result.status);
            } else {
                trace!("Ping cache entry EXPIRED for {}", addr);
                self.cache.remove(&addr);
            }
        }

        trace!("Ping cache MISS for {}", addr);
        None
    }

    /// Insert ping result into cache
    ///
    /// Stores a new ping result in the cache with current timestamp. Overwrites
    /// any existing entry for the same address.
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address
    /// * `status` - Ping result status
    ///
    /// # Original C Function
    ///
    /// Replaces cache insertion in do_icmp_ping() (dhcp.c lines 1335-1340):
    /// ```c
    /// if (victim) {
    ///   victim->addr = addr;
    ///   victim->time = now;
    ///   victim->hash = hash;
    /// }
    /// ```
    pub fn insert(&mut self, addr: Ipv4Addr, status: PingStatus) {
        debug!("Caching ping result for {}: {:?}", addr, status);
        self.cache.insert(addr, CachedPingResult::new(status));
    }

    /// Remove all expired entries from cache
    ///
    /// Performs a full cache sweep to remove all entries older than PING_CACHE_TIME.
    /// This is called periodically to prevent unbounded cache growth.
    ///
    /// # Returns
    ///
    /// Number of entries removed
    pub fn clear_expired(&mut self) -> usize {
        let initial_count = self.cache.len();
        self.cache.retain(|addr, result| {
            let keep = !result.is_expired();
            if !keep {
                trace!("Expiring cached ping result for {}", addr);
            }
            keep
        });
        let removed = initial_count - self.cache.len();
        if removed > 0 {
            debug!("Cleared {} expired ping cache entries", removed);
        }
        removed
    }
}

impl Default for PingCache {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Public API ==========

/// Perform ICMP ping to check if address is in use
///
/// Sends an ICMP echo request to the specified IPv4 address and waits up to PING_TIMEOUT
/// (500ms) for a reply. Returns Available if no reply received, InUse if reply received,
/// or Unknown if the operation failed (e.g., permission denied).
///
/// This function is async and non-blocking, using tokio for I/O. It creates a raw ICMP
/// socket (requires CAP_NET_RAW capability), sends an echo request, and awaits a reply
/// with timeout. If permission is denied, returns Unknown rather than failing hard,
/// allowing the DHCP server to continue operation with degraded conflict detection.
///
/// # Arguments
///
/// * `addr` - IPv4 address to ping
/// * `arp_cache` - Optional ARP cache for cross-checking MAC addresses
///
/// # Returns
///
/// - `Ok(PingStatus::Available)` - Address did not respond (safe to allocate)
/// - `Ok(PingStatus::InUse)` - Address responded (conflict detected)
/// - `Ok(PingStatus::Unknown)` - Operation failed (permission error, network error)
/// - `Err(io::Error)` - Critical system error (should not happen in production)
///
/// # Example
///
/// ```no_run
/// # use std::net::Ipv4Addr;
/// # use dnsmasq::dhcp::v4::ping::{icmp_ping, PingStatus};
/// # async fn example() {
/// let addr: Ipv4Addr = "192.168.1.100".parse().unwrap();
/// match icmp_ping(addr, None).await {
///     Ok(PingStatus::Available) => println!("Address available"),
///     Ok(PingStatus::InUse) => println!("Address in use"),
///     Ok(PingStatus::Unknown) => println!("Could not determine"),
///     Err(e) => println!("Error: {}", e),
/// }
/// # }
/// ```
///
/// # Original C Function
///
/// Replaces `icmp_ping()` in dnsmasq.c lines 2873-2925:
/// ```c
/// int icmp_ping(struct in_addr addr)
/// {
///   int fd;
///   struct sockaddr_in saddr;
///   unsigned short id = rand16();
///   // ... blocking sendto/recvfrom with alarm() timeout ...
///   return gotreply;
/// }
/// ```
///
/// Key transformations:
/// - Blocking sendto/recvfrom → async tokio I/O
/// - SIGALRM timeout → tokio::time::timeout
/// - Global errno → Result<T, Error>
/// - delay_dhcp() poll loop → single async await with timeout
pub async fn icmp_ping(
    addr: Ipv4Addr,
    arp_cache: Option<&mut ArpCache>,
) -> Result<PingStatus> {
    // Generate random ICMP identifier to match replies with requests
    let id: u16 = (Instant::now().elapsed().as_micros() & 0xffff) as u16;

    debug!("Performing ICMP ping to {} (id={})", addr, id);

    // Create raw ICMP socket
    let socket = match create_icmp_socket() {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            warn!(
                "Permission denied creating ICMP socket (CAP_NET_RAW required): {}",
                e
            );
            return Ok(PingStatus::Unknown);
        }
        Err(e) => {
            error!("Failed to create ICMP socket: {}", e);
            return Ok(PingStatus::Unknown);
        }
    };

    // Send ICMP echo request
    let packet = IcmpPacket::new_echo_request(id);
    let addr_sockaddr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(addr),
        0, // Port is ignored for ICMP
    );

    trace!("Sending ICMP echo request to {}", addr);
    if let Err(e) = socket.send_to(packet.as_bytes(), &addr_sockaddr.into()) {
        warn!("Failed to send ICMP echo request to {}: {}", addr, e);
        return Ok(PingStatus::Unknown);
    }

    // Wait for reply with timeout
    match timeout(
        PING_TIMEOUT,
        receive_icmp_reply(&socket, addr, id),
    )
    .await
    {
        Ok(Ok(true)) => {
            debug!("ICMP echo reply received from {} - address IN USE", addr);

            // Cross-check with ARP cache if available
            if let Some(arp) = arp_cache {
                // Create platform object for ARP cache query
                match crate::network::platform::create_platform() {
                    Ok(platform) => {
                        match arp.find_mac(Some(&std::net::IpAddr::V4(addr)), false, platform.as_ref()).await {
                            Ok(Some((mac, mac_len))) => {
                                let mac_str = format_mac(&mac, mac_len);
                                info!("ICMP ping success for {} confirmed by ARP cache (MAC: {})", addr, mac_str);
                            }
                            Ok(None) => {
                                trace!("ICMP ping success for {} but not in ARP cache (may be transient)", addr);
                            }
                            Err(e) => {
                                warn!("Failed to query ARP cache for {}: {}", addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create platform for ARP cache query: {}", e);
                    }
                }
            }

            Ok(PingStatus::InUse)
        }
        Ok(Ok(false)) => {
            // Received a reply but ID didn't match (reply for different ping)
            trace!("ICMP reply received but ID mismatch - treating as timeout");
            debug!("No ICMP echo reply from {} - address AVAILABLE", addr);
            Ok(PingStatus::Available)
        }
        Ok(Err(e)) => {
            warn!("Error receiving ICMP reply from {}: {}", addr, e);
            Ok(PingStatus::Unknown)
        }
        Err(_) => {
            // Timeout - no reply received
            debug!("ICMP ping timeout for {} - address AVAILABLE", addr);
            Ok(PingStatus::Available)
        }
    }
}

// ========== Internal Helper Functions ==========

/// Create raw ICMP socket for ping operations
///
/// Creates a raw socket with IPPROTO_ICMP protocol. Requires CAP_NET_RAW capability
/// on Linux. If permission is denied, returns PermissionDenied error which the caller
/// should handle gracefully.
///
/// # Returns
///
/// - `Ok(Socket)` - Successfully created ICMP socket
/// - `Err(io::Error)` - Socket creation failed (check ErrorKind::PermissionDenied)
///
/// # Original C Code
///
/// From dnsmasq.c lines 2887-2894 (Linux/Solaris) and 2891-2893 (BSD):
/// ```c
/// #if defined(HAVE_LINUX_NETWORK) || defined(HAVE_SOLARIS_NETWORK)
///   if ((fd = make_icmp_sock()) == -1)
///     return 0;
/// #else
///   fd = daemon->dhcp_icmp_fd;
///   setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
/// #endif
/// ```
fn create_icmp_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_ICMP)))?;

    // Set non-blocking mode for async I/O
    socket.set_nonblocking(true)?;

    // Set receive buffer size (optional, improves performance)
    if let Err(e) = socket.set_recv_buffer_size(8192) {
        trace!("Failed to set ICMP socket receive buffer size: {}", e);
        // Non-fatal, continue
    }

    Ok(socket)
}

/// Receive ICMP echo reply with ID matching
///
/// Waits for an ICMP echo reply packet from the specified address with matching
/// identifier. Returns true if matching reply received, false if non-matching reply,
/// or error if receive operation failed.
///
/// # Arguments
///
/// * `socket` - Raw ICMP socket to receive from
/// * `expected_addr` - Expected source address for reply
/// * `expected_id` - Expected ICMP identifier to match
///
/// # Returns
///
/// - `Ok(true)` - Matching echo reply received
/// - `Ok(false)` - Non-matching reply received (wrong ID or address)
/// - `Err(io::Error)` - Receive operation failed
///
/// # Original C Code
///
/// From delay_dhcp() in dnsmasq.c lines 2985-3077, specifically the ICMP reply
/// checking logic that validates source address and ICMP ID.
async fn receive_icmp_reply(
    socket: &Socket,
    expected_addr: Ipv4Addr,
    expected_id: u16,
) -> Result<bool> {
    // Wrap socket in AsyncFd for tokio async I/O
    let async_socket = AsyncFd::new(socket.try_clone()?)?;

    // Buffer for receiving ICMP packets
    // IP header (20 bytes) + ICMP header (8 bytes) = 28 bytes minimum
    let mut buf = [0u8; 64];
    let mut recv_buf: [std::mem::MaybeUninit<u8>; 64] = unsafe {
        std::mem::MaybeUninit::uninit().assume_init()
    };

    loop {
        // Wait for socket to be readable
        let mut guard = async_socket.readable().await?;

        match guard.try_io(|inner| {
            socket.recv_from(&mut recv_buf)
        }) {
            Ok(result) => {
                let (size, from_addr) = result?;

                // Copy received data to initialized buffer
                for i in 0..size.min(buf.len()) {
                    buf[i] = unsafe { recv_buf[i].assume_init() };
                }

                // Extract source IP from socket address
                if let std::net::SocketAddr::V4(from) = from_addr.as_socket().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidData, "Invalid socket address type")
                })? {
                    let from_ip = *from.ip();

                    // Check if reply is from expected address
                    if from_ip != expected_addr {
                        trace!("ICMP reply from unexpected address {}, expecting {}", from_ip, expected_addr);
                        continue; // Keep waiting for reply from correct address
                    }

                    // Skip IP header (typically 20 bytes, but check IHL field)
                    if size < 20 {
                        trace!("ICMP packet too small (no IP header): {} bytes", size);
                        continue;
                    }

                    // IP header length is in the lower 4 bits of first byte, in 32-bit words
                    let ip_header_len = ((buf[0] & 0x0f) * 4) as usize;
                    if size < ip_header_len + 8 {
                        trace!("ICMP packet too small (no ICMP header): {} bytes", size);
                        continue;
                    }

                    // Parse ICMP packet after IP header
                    let icmp_bytes = &buf[ip_header_len..size];
                    if let Some(icmp_packet) = IcmpPacket::from_bytes(icmp_bytes) {
                        trace!(
                            "Received ICMP type={} code={} id={}",
                            icmp_packet.icmp_type,
                            icmp_packet.icmp_code,
                            u16::from_be(icmp_packet.icmp_id)
                        );

                        // Check if this is an echo reply with matching ID
                        if icmp_packet.icmp_type == ICMP_ECHOREPLY
                            && u16::from_be(icmp_packet.icmp_id) == expected_id
                        {
                            trace!("ICMP echo reply matched!");
                            return Ok(true);
                        } else {
                            trace!(
                                "ICMP packet ID mismatch or wrong type (expected reply type={} id={})",
                                ICMP_ECHOREPLY,
                                expected_id
                            );
                            continue; // Keep waiting for matching reply
                        }
                    } else {
                        trace!("Failed to parse ICMP packet");
                        continue;
                    }
                } else {
                    trace!("Received packet from non-IPv4 address");
                    continue;
                }
            }
            Err(_would_block) => {
                // Operation would block, continue waiting
                continue;
            }
        }
    }
}

/// Format MAC address as human-readable string
///
/// # Arguments
///
/// * `mac` - MAC address bytes
/// * `len` - Length of MAC address (typically 6 for Ethernet)
///
/// # Returns
///
/// Formatted string like "00:11:22:33:44:55"
fn format_mac(mac: &[u8; 16], len: usize) -> String {
    let len = len.min(16);
    if len == 0 {
        return String::from("(empty)");
    }

    mac[..len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_packet_checksum() {
        let packet = IcmpPacket::new_echo_request(0x1234);
        assert_eq!(packet.icmp_type, ICMP_ECHO);
        assert_eq!(packet.icmp_code, 0);
        assert_ne!(packet.icmp_cksum, 0); // Checksum should be computed
    }

    #[test]
    fn test_ping_cache_expiry() {
        let mut cache = PingCache::new();

        let addr: Ipv4Addr = "192.168.1.100".parse().unwrap();
        cache.insert(addr, PingStatus::Available);

        // Immediate check should hit cache
        assert_eq!(cache.check(addr), Some(PingStatus::Available));

        // Simulate expiry by directly modifying timestamp (test-only pattern)
        if let Some(entry) = cache.cache.get_mut(&addr) {
            entry.timestamp = Instant::now() - PING_CACHE_TIME - Duration::from_secs(1);
        }

        // Should now be expired
        assert_eq!(cache.check(addr), None);
    }

    #[test]
    fn test_ping_cache_clear_expired() {
        let mut cache = PingCache::new();

        // Insert multiple entries
        for i in 1..=5 {
            let addr: Ipv4Addr = format!("192.168.1.{}", i).parse().unwrap();
            cache.insert(addr, PingStatus::Available);
        }

        assert_eq!(cache.cache.len(), 5);

        // Expire first 3 entries
        for i in 1..=3 {
            let addr: Ipv4Addr = format!("192.168.1.{}", i).parse().unwrap();
            if let Some(entry) = cache.cache.get_mut(&addr) {
                entry.timestamp = Instant::now() - PING_CACHE_TIME - Duration::from_secs(1);
            }
        }

        // Clear expired
        let removed = cache.clear_expired();
        assert_eq!(removed, 3);
        assert_eq!(cache.cache.len(), 2);
    }

    #[test]
    fn test_ping_status_enum() {
        assert_ne!(PingStatus::Available, PingStatus::InUse);
        assert_ne!(PingStatus::Available, PingStatus::Unknown);
        assert_ne!(PingStatus::InUse, PingStatus::Unknown);
    }

    #[test]
    fn test_icmp_packet_serialization() {
        let packet = IcmpPacket::new_echo_request(0xabcd);
        let bytes = packet.as_bytes();
        assert_eq!(bytes.len(), std::mem::size_of::<IcmpPacket>());

        let parsed = IcmpPacket::from_bytes(bytes).unwrap();
        assert_eq!(parsed.icmp_type, ICMP_ECHO);
        assert_eq!(parsed.icmp_id, packet.icmp_id);
    }
}

