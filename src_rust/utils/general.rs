// dnsmasq is Copyright (c) 2000-2022 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

//! General utility functions
//!
//! This module provides general utility functions for dnsmasq, including:
//! - Socket address comparison and manipulation
//! - Hostname comparison (case-insensitive, DNS-compliant)
//! - Time management
//! - Network address operations (IPv4/IPv6)
//! - Pretty-printing for addresses, time intervals, and MAC addresses
//! - Hex parsing for MAC addresses and byte arrays
//! - Buffer management
//! - I/O retry logic
//! - File descriptor management
//!
//! All functions are memory-safe, replacing C's manual memory management with Rust's
//! ownership system and RAII. Error handling uses Result types instead of errno.

use std::cmp::Ordering;
use std::fmt::Write as FmtWrite;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

#[cfg(target_os = "linux")]
use nix::sys::utsname::uname;
use nix::unistd::close as nix_close;

/// Compare two socket addresses for equality (IPv4 or IPv6)
///
/// Compares two socket addresses for complete equality including address family,
/// IP address, port number, and (for IPv6) scope ID.
///
/// # Arguments
/// * `s1` - First socket address
/// * `s2` - Second socket address
///
/// # Returns
/// * `true` if addresses are identical
/// * `false` if different families, addresses, ports, or scope IDs
///
/// # Example
/// ```
/// use dnsmasq::utils::general::sockaddr_isequal;
/// use std::net::{SocketAddr, IpAddr, Ipv4Addr};
/// 
/// let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
/// let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
/// assert!(sockaddr_isequal(&addr1, &addr2));
/// ```
pub fn sockaddr_isequal(s1: &SocketAddr, s2: &SocketAddr) -> bool {
    match (s1, s2) {
        (SocketAddr::V4(a1), SocketAddr::V4(a2)) => {
            a1.ip() == a2.ip() && a1.port() == a2.port()
        }
        (SocketAddr::V6(a1), SocketAddr::V6(a2)) => {
            a1.ip() == a2.ip() && a1.port() == a2.port() && a1.scope_id() == a2.scope_id()
        }
        _ => false,
    }
}

/// Calculate socket address structure size for IPv4 or IPv6
///
/// Returns the size in bytes of the socket address structure.
///
/// # Arguments
/// * `addr` - Socket address reference
///
/// # Returns
/// Size in bytes (16 for IPv4, 28 for IPv6 on most platforms)
///
/// # Example
/// ```
/// use dnsmasq::utils::general::sa_len;
/// use std::net::{SocketAddr, IpAddr, Ipv4Addr};
/// 
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
/// let size = sa_len(&addr);
/// ```
pub fn sa_len(addr: &SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(_) => size_of::<SocketAddrV4>(),
        SocketAddr::V6(_) => size_of::<SocketAddrV6>(),
    }
}

/// Compare two hostnames lexicographically (case-insensitive, locale-independent)
///
/// Performs case-insensitive hostname comparison without locale dependencies.
/// Converts A-Z to a-z during comparison. DNS names are case-insensitive per RFC 1035.
///
/// # Arguments
/// * `a` - First hostname string
/// * `b` - Second hostname string
///
/// # Returns
/// * `Ordering::Less` if a < b
/// * `Ordering::Equal` if a == b (case-insensitive)
/// * `Ordering::Greater` if a > b
///
/// # Example
/// ```
/// use dnsmasq::utils::general::hostname_order;
/// use std::cmp::Ordering;
/// 
/// assert_eq!(hostname_order("Example.COM", "example.com"), Ordering::Equal);
/// assert_eq!(hostname_order("aaa.com", "bbb.com"), Ordering::Less);
/// ```
pub fn hostname_order(a: &str, b: &str) -> Ordering {
    let mut chars_a = a.chars();
    let mut chars_b = b.chars();

    loop {
        match (chars_a.next(), chars_b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(c1), Some(c2)) => {
                let c1_lower = c1.to_ascii_lowercase();
                let c2_lower = c2.to_ascii_lowercase();
                match c1_lower.cmp(&c2_lower) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
        }
    }
}

/// Test hostname equality (case-insensitive)
///
/// Simple wrapper around hostname_order() returning true if hostnames are equal.
///
/// # Arguments
/// * `a` - First hostname string
/// * `b` - Second hostname string
///
/// # Returns
/// * `true` if hostnames equal (case-insensitive)
/// * `false` if different
///
/// # Example
/// ```
/// use dnsmasq::utils::general::hostname_isequal;
/// 
/// assert!(hostname_isequal("Example.COM", "example.com"));
/// ```
pub fn hostname_isequal(a: &str, b: &str) -> bool {
    hostname_order(a, b) == Ordering::Equal
}

/// Test if b is equal to or subdomain of a (case-insensitive)
///
/// Checks DNS hierarchy relationship by comparing hostnames from right to left.
///
/// # Arguments
/// * `a` - Parent domain name string
/// * `b` - Domain name to test against parent
///
/// # Returns
/// * `0` - b is not equal to and not subdomain of a
/// * `1` - b is proper subdomain of a (e.g., "www.example.com" is subdomain of "example.com")
/// * `2` - b equals a (same domain, case-insensitive)
///
/// # Example
/// ```
/// use dnsmasq::utils::general::hostname_issubdomain;
/// 
/// assert_eq!(hostname_issubdomain("example.com", "www.example.com"), 1);
/// assert_eq!(hostname_issubdomain("example.com", "example.com"), 2);
/// assert_eq!(hostname_issubdomain("example.com", "other.com"), 0);
/// ```
pub fn hostname_issubdomain(a: &str, b: &str) -> i32 {
    // a shorter than b or a empty
    if b.len() < a.len() || a.is_empty() {
        return 0;
    }

    // Compare from the end (right to left)
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    
    let mut i = a.len();
    let mut j = b.len();
    
    while i > 0 {
        i -= 1;
        j -= 1;
        
        let c1 = a_bytes[i].to_ascii_lowercase();
        let c2 = b_bytes[j].to_ascii_lowercase();
        
        if c1 != c2 {
            return 0;
        }
    }
    
    // If we've matched all of a
    if j == 0 {
        // Exact match
        return 2;
    }
    
    // Check if there's a dot separator
    if b_bytes[j - 1] == b'.' {
        return 1;
    }
    
    0
}

/// Get current time (real time or monotonic for embedded systems)
///
/// Returns current time in seconds. Uses SystemTime::now() which provides
/// monotonic-like behavior on most platforms.
///
/// # Returns
/// Current time as u64 (seconds since epoch or boot)
///
/// # Example
/// ```
/// use dnsmasq::utils::general::dnsmasq_time;
/// 
/// let now = dnsmasq_time();
/// let expires = now + 3600; // 1 hour from now
/// ```
pub fn dnsmasq_time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// Calculate CIDR prefix length from IPv4 netmask
///
/// Counts number of consecutive 1-bits in netmask from most significant bit.
///
/// # Arguments
/// * `mask` - IPv4 netmask
///
/// # Returns
/// CIDR prefix length (0-32)
///
/// # Example
/// ```
/// use dnsmasq::utils::general::netmask_length;
/// use std::net::Ipv4Addr;
/// 
/// let mask = Ipv4Addr::new(255, 255, 255, 0);
/// assert_eq!(netmask_length(mask), 24);
/// ```
pub fn netmask_length(mask: Ipv4Addr) -> u32 {
    let mask_u32 = u32::from(mask);
    mask_u32.leading_ones()
}

/// Test if two IPv4 addresses are in same network (with netmask)
///
/// Applies netmask to both addresses and compares result.
///
/// # Arguments
/// * `a` - First IPv4 address
/// * `b` - Second IPv4 address  
/// * `mask` - Network mask to apply
///
/// # Returns
/// * `true` if same network
/// * `false` if different networks
///
/// # Example
/// ```
/// use dnsmasq::utils::general::is_same_net;
/// use std::net::Ipv4Addr;
/// 
/// let addr1 = Ipv4Addr::new(192, 168, 1, 10);
/// let addr2 = Ipv4Addr::new(192, 168, 1, 20);
/// let mask = Ipv4Addr::new(255, 255, 255, 0);
/// assert!(is_same_net(addr1, addr2, mask));
/// ```
pub fn is_same_net(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let a_u32 = u32::from(a);
    let b_u32 = u32::from(b);
    let mask_u32 = u32::from(mask);
    
    (a_u32 & mask_u32) == (b_u32 & mask_u32)
}

/// Test if two IPv4 addresses are in same network (with CIDR prefix)
///
/// Convenience wrapper that constructs netmask from CIDR prefix length.
///
/// # Arguments
/// * `a` - First IPv4 address
/// * `b` - Second IPv4 address
/// * `prefix` - CIDR prefix length (0-32)
///
/// # Returns
/// * `true` if same network
/// * `false` if different networks
///
/// # Example
/// ```
/// use dnsmasq::utils::general::is_same_net_prefix;
/// use std::net::Ipv4Addr;
/// 
/// let addr1 = Ipv4Addr::new(192, 168, 1, 10);
/// let addr2 = Ipv4Addr::new(192, 168, 1, 20);
/// assert!(is_same_net_prefix(addr1, addr2, 24));
/// ```
pub fn is_same_net_prefix(a: Ipv4Addr, b: Ipv4Addr, prefix: u32) -> bool {
    if prefix > 32 {
        return false;
    }
    
    let mask_u32 = if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    
    let mask = Ipv4Addr::from(mask_u32);
    is_same_net(a, b, mask)
}

/// Test if two IPv6 addresses share same prefix
///
/// Compares first prefixlen bits of two IPv6 addresses.
///
/// # Arguments
/// * `a` - First IPv6 address
/// * `b` - Second IPv6 address
/// * `prefixlen` - IPv6 prefix length in bits (0-128)
///
/// # Returns
/// * `true` if addresses share prefix
/// * `false` if different prefixes
///
/// # Example
/// ```
/// use dnsmasq::utils::general::is_same_net6;
/// use std::net::Ipv6Addr;
/// 
/// let addr1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
/// let addr2 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
/// assert!(is_same_net6(&addr1, &addr2, 64));
/// ```
pub fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefixlen: u32) -> bool {
    if prefixlen > 128 {
        return false;
    }
    
    let a_bytes = a.octets();
    let b_bytes = b.octets();
    
    let pfbytes = (prefixlen / 8) as usize;
    let pfbits = prefixlen % 8;
    
    // Compare full bytes
    if a_bytes[..pfbytes] != b_bytes[..pfbytes] {
        return false;
    }
    
    // Compare partial byte if needed
    if pfbits == 0 || pfbytes >= 16 {
        return true;
    }
    
    let mask = 0xff << (8 - pfbits);
    (a_bytes[pfbytes] & mask) == (b_bytes[pfbytes] & mask)
}

/// Extract least significant 64 bits (host part) of IPv6 address
///
/// Extracts lower 64 bits (bytes 8-15) of IPv6 address as u64 value.
/// Used for manipulating interface identifiers in IPv6 addresses.
///
/// # Arguments
/// * `addr` - IPv6 address reference
///
/// # Returns
/// Lower 64 bits of IPv6 address as u64
///
/// # Example
/// ```
/// use dnsmasq::utils::general::addr6part;
/// use std::net::Ipv6Addr;
/// 
/// let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
/// let host_part = addr6part(&addr);
/// ```
pub fn addr6part(addr: &Ipv6Addr) -> u64 {
    let bytes = addr.octets();
    let mut ret: u64 = 0;
    
    for i in 8..16 {
        ret = (ret << 8) | (bytes[i] as u64);
    }
    
    ret
}

/// Set least significant 64 bits (host part) of IPv6 address
///
/// Writes u64 value into lower 64 bits (bytes 8-15) of IPv6 address,
/// leaving upper 64 bits (network prefix) unchanged.
///
/// # Arguments
/// * `addr` - Mutable IPv6 address reference
/// * `host` - 64-bit value to write as host portion
///
/// # Example
/// ```
/// use dnsmasq::utils::general::setaddr6part;
/// use std::net::Ipv6Addr;
/// 
/// let mut addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
/// setaddr6part(&mut addr, 0x123456789abcdef0);
/// ```
pub fn setaddr6part(addr: &mut Ipv6Addr, host: u64) {
    let mut bytes = addr.octets();
    let mut h = host;
    
    for i in (8..16).rev() {
        bytes[i] = (h & 0xff) as u8;
        h >>= 8;
    }
    
    *addr = Ipv6Addr::from(bytes);
}

/// Format socket address as human-readable string with optional scope
///
/// Converts socket address (IPv4 or IPv6) to string representation.
/// For IPv6 link-local addresses with scope_id, appends "%interface_name".
///
/// # Arguments
/// * `addr` - Socket address reference
///
/// # Returns
/// Tuple of (formatted address string, port number)
///
/// # Example
/// ```
/// use dnsmasq::utils::general::prettyprint_addr;
/// use std::net::{SocketAddr, IpAddr, Ipv4Addr};
/// 
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
/// let (addr_str, port) = prettyprint_addr(&addr);
/// assert_eq!(port, 53);
/// ```
pub fn prettyprint_addr(addr: &SocketAddr) -> (String, u16) {
    let port = addr.port();
    let addr_str = match addr {
        SocketAddr::V4(v4) => v4.ip().to_string(),
        SocketAddr::V6(v6) => {
            let mut s = v6.ip().to_string();
            if v6.scope_id() != 0 {
                // Try to get interface name from scope_id
                #[cfg(target_os = "linux")]
                if let Ok(name) = nix::net::if_::if_indextoname(v6.scope_id()) {
                    s.push('%');
                    s.push_str(&name.to_string_lossy());
                }
            }
            s
        }
    };
    
    (addr_str, port)
}

/// Format time interval as human-readable string (days/hours/minutes/seconds)
///
/// Converts seconds into human-friendly format with units: 1d2h3m4s.
/// Special value 0xffffffff (infinite) displayed as "infinite".
///
/// # Arguments
/// * `t` - Time in seconds (or 0xffffffff for infinite)
///
/// # Returns
/// Formatted time string
///
/// # Example
/// ```
/// use dnsmasq::utils::general::prettyprint_time;
/// 
/// assert_eq!(prettyprint_time(7322), "2h2m2s");
/// assert_eq!(prettyprint_time(0xffffffff), "infinite");
/// ```
pub fn prettyprint_time(t: u32) -> String {
    if t == 0xffffffff {
        return "infinite".to_string();
    }
    
    let mut result = String::new();
    
    let days = t / 86400;
    if days > 0 {
        let _ = write!(result, "{}d", days);
    }
    
    let hours = (t / 3600) % 24;
    if hours > 0 {
        let _ = write!(result, "{}h", hours);
    }
    
    let minutes = (t / 60) % 60;
    if minutes > 0 {
        let _ = write!(result, "{}m", minutes);
    }
    
    let seconds = t % 60;
    if seconds > 0 {
        let _ = write!(result, "{}s", seconds);
    }
    
    if result.is_empty() {
        result.push_str("0s");
    }
    
    result
}

/// Parse colon/hyphen-separated hexadecimal string (MAC addresses, hex data)
///
/// Parses hex string like "01:23:45:67:89:ab" or "01-23-45-67-89-ab" into byte array.
/// Supports wildcard "*" for any byte (tracked in wildcard_mask bitmask).
///
/// # Arguments
/// * `input` - Input hex string
/// * `maxlen` - Maximum bytes to parse, or None for unlimited
///
/// # Returns
/// * `Ok((bytes, wildcard_mask, mac_type))` on success
/// * `Err(())` on invalid characters
///
/// # Example
/// ```
/// use dnsmasq::utils::general::parse_hex;
/// 
/// let (bytes, wildcard, mac_type) = parse_hex("01:23:45:67:89:ab", Some(6)).unwrap();
/// assert_eq!(bytes.len(), 6);
/// ```
pub fn parse_hex(
    input: &str,
    maxlen: Option<usize>,
) -> Result<(Vec<u8>, u32, Option<i32>), ()> {
    let mut output = Vec::new();
    let mut wildcard_mask = 0u32;
    let mut mac_type = None;
    let mut is_first = true;
    
    for part in input.split(|c| c == ':' || c == '-' || c == ' ') {
        if part.is_empty() {
            continue;
        }
        
        // Check for mac_type in first segment with hyphen
        if is_first && input.contains('-') {
            if let Ok(val) = i32::from_str_radix(part, 16) {
                mac_type = Some(val);
                is_first = false;
                continue;
            }
        }
        is_first = false;
        
        // Check maxlen
        if let Some(max) = maxlen {
            if output.len() >= max {
                break;
            }
        }
        
        // Handle wildcard
        if part == "*" {
            wildcard_mask = (wildcard_mask << 1) | 1;
            output.push(0); // Placeholder byte
            continue;
        }
        
        // Validate hex characters
        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(());
        }
        
        // Parse hex bytes (can be 1 or 2 hex digits per byte)
        let bytes_to_parse = (part.len() + 1) / 2;
        for j in 0..bytes_to_parse {
            if let Some(max) = maxlen {
                if output.len() >= max {
                    break;
                }
            }
            
            let start = j * 2;
            let end = std::cmp::min(start + 2, part.len());
            let hex_str = &part[start..end];
            
            if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
                output.push(byte);
                wildcard_mask <<= 1;
            } else {
                return Err(());
            }
        }
    }
    
    Ok((output, wildcard_mask, mac_type))
}

/// Compare byte arrays with wildcard mask support
///
/// Compares arrays a and b byte-by-byte, skipping comparison where mask bit is 1 (wildcard).
///
/// # Arguments
/// * `a` - First byte array
/// * `b` - Second byte array
/// * `len` - Length of arrays in bytes
/// * `mask` - Wildcard bitmask (LSB=last byte, bit 1=wildcard/skip comparison)
///
/// # Returns
/// * `0` for mismatch
/// * `count+1` for match (count = number of matched non-wildcard bytes)
///
/// # Example
/// ```
/// use dnsmasq::utils::general::memcmp_masked;
/// 
/// let mac1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
/// let mac2 = [0x01, 0xFF, 0x03, 0x04, 0x05, 0x06];
/// let mask = 0x10; // Wildcard byte at index 1 (bit position 4 from LSB)
/// assert_eq!(memcmp_masked(&mac1, &mac2, 6, mask), 6);
/// ```
pub fn memcmp_masked(a: &[u8], b: &[u8], len: usize, mask: u32) -> i32 {
    let mut count = 1;
    let mut m = mask;
    
    for i in (0..len).rev() {
        if (m & 1) == 0 {
            if a[i] == b[i] {
                count += 1;
            } else {
                return 0;
            }
        }
        m >>= 1;
    }
    
    count
}

/// Expand Vec buffer to at least specified size
///
/// Ensures Vec buffer is at least 'size' bytes. If current len < size,
/// resizes the vector.
///
/// # Arguments
/// * `buf` - Mutable reference to Vec<u8> to expand
/// * `size` - Required minimum size in bytes
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(IoError)` on allocation failure
///
/// # Example
/// ```
/// use dnsmasq::utils::general::expand_buf;
/// 
/// let mut buf = Vec::new();
/// expand_buf(&mut buf, 1024).unwrap();
/// assert!(buf.len() >= 1024);
/// ```
pub fn expand_buf(buf: &mut Vec<u8>, size: usize) -> IoResult<()> {
    if buf.len() < size {
        buf.resize(size, 0);
    }
    Ok(())
}

/// Format MAC address or byte array as colon-separated hex string
///
/// Converts byte array (typically MAC address) to hex string format "01:23:45:67:89:ab".
///
/// # Arguments
/// * `mac` - Input byte array (MAC address or hex data)
///
/// # Returns
/// Formatted string
///
/// # Example
/// ```
/// use dnsmasq::utils::general::print_mac;
/// 
/// let mac = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab];
/// assert_eq!(print_mac(&mac), "01:23:45:67:89:ab");
/// ```
pub fn print_mac(mac: &[u8]) -> String {
    if mac.is_empty() {
        return "<null>".to_string();
    }
    
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Async retry logic for send operations
///
/// Analyzes error and decides if operation should be retried.
/// Handles EAGAIN/EWOULDBLOCK with backoff to prevent hang on interface removal.
///
/// # Arguments
/// * `error` - IO error to analyze
/// * `retry_count` - Current retry count
///
/// # Returns
/// * `Ok(true)` to retry send
/// * `Ok(false)` to stop retrying
/// * `Err(error)` for unrecoverable error
///
/// # Example
/// ```no_run
/// # use dnsmasq::utils::general::retry_send;
/// # use std::io::Error;
/// # async fn example() -> Result<(), Error> {
/// # let mut socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
/// # let data = vec![0u8; 10];
/// let mut retries = 0;
/// loop {
///     match socket.send(&data).await {
///         Ok(n) => break,
///         Err(e) => {
///             if !retry_send(&e, &mut retries).await? {
///                 return Err(e);
///             }
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub async fn retry_send(error: &IoError, retry_count: &mut u32) -> IoResult<bool> {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => {
            if *retry_count < 1000 {
                // Sleep 10μs to avoid busy-waiting
                sleep(Duration::from_micros(10)).await;
                *retry_count += 1;
                Ok(true)
            } else {
                // Exceeded retry limit (1 second total at 10μs per retry)
                Ok(false)
            }
        }
        ErrorKind::Interrupted => {
            // Always retry on interrupt
            Ok(true)
        }
        _ => {
            // Unrecoverable error
            Ok(false)
        }
    }
}

/// Reliable async read or write handling partial transfers and interrupts
///
/// Async wrapper that loops until all 'size' bytes transferred or error occurs.
/// Automatically retries on interrupts and transient errors.
///
/// # Arguments
/// * `reader_writer` - AsyncRead or AsyncWrite object
/// * `buffer` - Buffer for read/write data
/// * `is_read` - true for read, false for write
///
/// # Returns
/// * `Ok(())` if all bytes transferred
/// * `Err(IoError)` on error or premature EOF
///
/// # Example
/// ```no_run
/// # use dnsmasq::utils::general::read_write;
/// # use std::io::Error;
/// # async fn example() -> Result<(), Error> {
/// let mut file = tokio::fs::File::open("/dev/urandom").await?;
/// let mut entropy = vec![0u8; 32];
/// read_write(&mut file, &mut entropy, true).await?;
/// # Ok(())
/// # }
/// ```
pub async fn read_write<T>(
    reader_writer: &mut T,
    buffer: &mut [u8],
    is_read: bool,
) -> IoResult<()>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut done = 0;
    let size = buffer.len();
    
    while done < size {
        let mut retry_count = 0;
        
        loop {
            let result = if is_read {
                reader_writer.read(&mut buffer[done..]).await
            } else {
                reader_writer.write(&buffer[done..]).await
            };
            
            match result {
                Ok(0) => {
                    // EOF
                    return Err(IoError::new(ErrorKind::UnexpectedEof, "premature EOF"));
                }
                Ok(n) => {
                    done += n;
                    break;
                }
                Err(e) if e.kind() == ErrorKind::OutOfMemory => {
                    // Special case: retry on ENOMEM
                    sleep(Duration::from_millis(10)).await;
                    continue;
                }
                Err(e) => {
                    if !retry_send(&e, &mut retry_count).await? {
                        return Err(e);
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Close all file descriptors except standard streams and specified spares
///
/// Closes all open file descriptors from 0 to max_fd-1 except STDIN (0), STDOUT (1),
/// STDERR (2), and up to 3 spare fds. On Linux with /proc/self/fd, efficiently iterates
/// only open fds.
///
/// # Arguments
/// * `max_fd` - Upper limit of file descriptors to check
/// * `spare1` - First file descriptor to preserve (or None)
/// * `spare2` - Second file descriptor to preserve (or None)
/// * `spare3` - Third file descriptor to preserve (or None)
///
/// # Example
/// ```no_run
/// use dnsmasq::utils::general::close_fds;
/// 
/// let logfd = 5; // example file descriptor
/// close_fds(1024, Some(logfd), None, None);
/// ```
pub fn close_fds(max_fd: i32, spare1: Option<i32>, spare2: Option<i32>, spare3: Option<i32>) {
    let preserve = |fd: i32| -> bool {
        fd == 0 || fd == 1 || fd == 2 // stdin, stdout, stderr
            || Some(fd) == spare1
            || Some(fd) == spare2
            || Some(fd) == spare3
    };
    
    #[cfg(target_os = "linux")]
    {
        // Try Linux optimization: use /proc/self/fd
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(fd) = name.parse::<i32>() {
                        if !preserve(fd) {
                            let _ = nix_close(fd);
                        }
                    }
                }
            }
            return;
        }
    }
    
    // Fallback: iterate all possible fds
    for fd in 0..max_fd {
        if !preserve(fd) {
            let _ = nix_close(fd);
        }
    }
}

/// Get Linux kernel version as u32 (Linux only)
///
/// Parses kernel version from uname() into packed u32 format: (major << 16) | (minor << 8) | patch.
/// This allows simple numeric comparison of kernel versions.
///
/// # Returns
/// * Kernel version as u32 (e.g., version 5.15.3 returns 0x050F03)
/// * 0 on parse error or non-Linux platform
///
/// # Example
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use dnsmasq::utils::general::kernel_version;
/// 
/// let version = kernel_version();
/// if version >= 0x050F00 {
///     // Kernel 5.15 or later
/// }
/// # }
/// ```
#[cfg(target_os = "linux")]
pub fn kernel_version() -> u32 {
    match uname() {
        Ok(uts) => {
            let release = uts.release().to_string_lossy();
            let parts: Vec<&str> = release.split(&['.', '-'][..]).collect();
            
            if parts.len() >= 3 {
                let major = parts[0].parse::<u32>().unwrap_or(0);
                let minor = parts[1].parse::<u32>().unwrap_or(0);
                let patch = parts[2].parse::<u32>().unwrap_or(0);
                
                (major << 16) | (minor << 8) | patch
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn kernel_version() -> u32 {
    0
}

/// Safe memory allocation with automatic error handling
///
/// Rust replacement for C's whine_malloc(). In Rust, Vec::with_capacity and Box handle
/// allocation automatically, panicking on OOM. This function exists for API compatibility
/// but simply delegates to Vec allocation.
///
/// # Arguments
/// * `size` - Number of bytes to allocate
///
/// # Returns
/// * `Ok(Vec<u8>)` with capacity for size bytes
/// * `Err(IoError)` on allocation failure (rare, usually panics)
///
/// # Example
/// ```
/// use dnsmasq::utils::general::whine_malloc;
/// 
/// # fn example() -> std::io::Result<()> {
/// let buffer = whine_malloc(1024)?;
/// # Ok(())
/// # }
/// ```
pub fn whine_malloc(size: usize) -> IoResult<Vec<u8>> {
    // Rust's allocator panics on OOM, but we check for zero size
    if size == 0 {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "cannot allocate zero bytes",
        ));
    }
    
    // Try to allocate with error conversion
    let mut v = Vec::new();
    match v.try_reserve_exact(size) {
        Ok(()) => {
            Ok(v)
        }
        Err(_) => Err(IoError::new(ErrorKind::OutOfMemory, "allocation failed")),
    }
}

/// Set file descriptor to non-blocking and close-on-exec
///
/// Sets O_NONBLOCK (non-blocking I/O) and FD_CLOEXEC (close on exec) flags
/// on a file descriptor. Essential for socket handling in async contexts.
///
/// # Arguments
/// * `fd` - File descriptor to modify
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(IoError)` on fcntl failure
///
/// # Example
/// ```no_run
/// use dnsmasq::utils::general::fix_fd;
/// use std::os::unix::io::AsRawFd;
/// 
/// # fn example() -> std::io::Result<()> {
/// # let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
/// let socket_fd = socket.as_raw_fd();
/// fix_fd(socket_fd)?;
/// # Ok(())
/// # }
/// ```
pub fn fix_fd(fd: i32) -> IoResult<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    
    // Set O_NONBLOCK
    let mut flags = fcntl(fd, FcntlArg::F_GETFL)
        .map_err(|e| IoError::new(ErrorKind::Other, format!("F_GETFL failed: {}", e)))?;
    
    flags |= OFlag::O_NONBLOCK.bits();
    
    fcntl(fd, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags)))
        .map_err(|e| IoError::new(ErrorKind::Other, format!("F_SETFL failed: {}", e)))?;
    
    // Set FD_CLOEXEC
    let fd_flags = FdFlag::FD_CLOEXEC;
    fcntl(fd, FcntlArg::F_SETFD(fd_flags))
        .map_err(|e| IoError::new(ErrorKind::Other, format!("F_SETFD failed: {}", e)))?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    
    #[test]
    fn test_sockaddr_isequal() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 53);
        
        assert!(sockaddr_isequal(&addr1, &addr2));
        assert!(!sockaddr_isequal(&addr1, &addr3));
    }
    
    #[test]
    fn test_sa_len() {
        let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
        let addr6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
        
        assert_eq!(sa_len(&addr4), size_of::<SocketAddrV4>());
        assert_eq!(sa_len(&addr6), size_of::<SocketAddrV6>());
    }
    
    #[test]
    fn test_hostname_order() {
        assert_eq!(hostname_order("abc.example.com", "def.example.com"), Ordering::Less);
        assert_eq!(hostname_order("example.com", "example.com"), Ordering::Equal);
        assert_eq!(hostname_order("ZZZ.COM", "zzz.com"), Ordering::Equal);
    }
    
    #[test]
    fn test_hostname_isequal() {
        assert!(hostname_isequal("Example.COM", "example.com"));
        assert!(!hostname_isequal("example.com", "example.org"));
    }
    
    #[test]
    fn test_hostname_issubdomain() {
        // Returns 1 for subdomain, 0 for no match, 2 for exact match
        // Parameters: (parent, child) - tests if child is subdomain of parent
        assert_eq!(hostname_issubdomain("example.com", "www.example.com"), 1);
        assert_eq!(hostname_issubdomain("example.com", "api.www.example.com"), 1);
        assert_eq!(hostname_issubdomain("example.com", "example.org"), 0);
        assert_eq!(hostname_issubdomain("example.com", "example.com"), 2); // Exact match, not subdomain
    }
    
    #[test]
    fn test_netmask_length() {
        assert_eq!(netmask_length(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_length(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_length(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(netmask_length(Ipv4Addr::new(0, 0, 0, 0)), 0);
        assert_eq!(netmask_length(Ipv4Addr::new(255, 255, 255, 128)), 25);
        // Non-contiguous netmask - just counts leading ones
        assert_eq!(netmask_length(Ipv4Addr::new(255, 0, 255, 0)), 8);
    }
    
    #[test]
    fn test_is_same_net() {
        let addr1 = Ipv4Addr::new(192, 168, 1, 10);
        let addr2 = Ipv4Addr::new(192, 168, 1, 20);
        let addr3 = Ipv4Addr::new(192, 168, 2, 10);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        
        assert!(is_same_net(addr1, addr2, mask));
        assert!(!is_same_net(addr1, addr3, mask));
    }
    
    #[test]
    fn test_is_same_net_prefix() {
        let addr1 = Ipv4Addr::new(192, 168, 1, 10);
        let addr2 = Ipv4Addr::new(192, 168, 1, 20);
        let addr3 = Ipv4Addr::new(192, 168, 2, 10);
        
        assert!(is_same_net_prefix(addr1, addr2, 24));
        assert!(!is_same_net_prefix(addr1, addr3, 24));
        assert!(is_same_net_prefix(addr1, addr3, 16));
    }
    
    #[test]
    fn test_is_same_net6() {
        let addr1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr2 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let addr3 = Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1);
        
        assert!(is_same_net6(&addr1, &addr2, 64));
        assert!(!is_same_net6(&addr1, &addr3, 64));
    }
    
    #[test]
    fn test_addr6part() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234);
        let low64 = addr6part(&addr);
        assert_eq!(low64, 0x1234);
    }
    
    #[test]
    fn test_setaddr6part() {
        let mut addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        setaddr6part(&mut addr, 0x5678);
        assert_eq!(addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x5678));
    }
    
    #[test]
    fn test_prettyprint_addr() {
        let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        let (addr_str, port) = prettyprint_addr(&addr4);
        assert_eq!(addr_str, "192.168.1.1");
        assert_eq!(port, 53);
        
        let addr6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 8080);
        let (addr_str, port) = prettyprint_addr(&addr6);
        assert_eq!(addr_str, "2001:db8::1");
        assert_eq!(port, 8080);
    }
    
    #[test]
    fn test_prettyprint_time() {
        assert_eq!(prettyprint_time(3661), "1h1m1s");
        assert_eq!(prettyprint_time(7200), "2h");
        assert_eq!(prettyprint_time(90), "1m30s");
        assert_eq!(prettyprint_time(45), "45s");
    }
    
    #[test]
    fn test_parse_hex() {
        let result = parse_hex("01:02:03:04:05:06", Some(6));
        assert!(result.is_ok());
        let (bytes, _mask, _mac_type) = result.unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6]);
        
        let result = parse_hex("aabbccdd", Some(4));
        assert!(result.is_ok());
        let (bytes, _mask, _mac_type) = result.unwrap();
        assert_eq!(bytes, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        
        let result = parse_hex("zz", Some(1));
        assert!(result.is_err());
    }
    
    #[test]
    fn test_memcmp_masked() {
        let data1 = vec![0xFF, 0xAA, 0x55, 0x00];
        let data2 = vec![0xFF, 0xBB, 0x55, 0x00];
        // mask bit pattern: bit 1 means ignore that byte position (from right)
        // Bit 1 (position 1 from right) corresponds to index 2
        let mask = 0b0010; // Ignore byte at index 2 when counting from right
        
        // mask=0: compare all bytes
        // data1 and data2 differ at index 1, so should return 0
        assert_eq!(memcmp_masked(&data1, &data2, 4, 0), 0);
        
        // With mask=0b0010, we skip index 2 (counting from right)
        // But data1[1] != data2[1], so still returns 0
        let data3 = vec![0xFF, 0xAA, 0x55, 0x00];
        let data4 = vec![0xFF, 0xAA, 0x55, 0x00];
        // Identical data should match
        assert!(memcmp_masked(&data3, &data4, 4, 0) > 0);
    }
    
    #[test]
    fn test_expand_buf() {
        let mut buf = vec![1, 2, 3];
        let _ = expand_buf(&mut buf, 10);
        assert!(buf.capacity() >= 10);
        assert_eq!(buf.len(), 10); // expand_buf resizes to specified size
        assert_eq!(buf[0], 1); // Original bytes preserved
        assert_eq!(buf[1], 2);
        assert_eq!(buf[2], 3);
    }
    
    #[test]
    fn test_print_mac() {
        let mac = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(print_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }
    
    #[test]
    fn test_whine_malloc() {
        let result = whine_malloc(1024);
        assert!(result.is_ok());
        
        let result = whine_malloc(0);
        assert!(result.is_err());
    }
    
    #[cfg(target_os = "linux")]
    #[test]
    fn test_kernel_version() {
        let version = kernel_version();
        // Should get a valid version on Linux
        assert!(version > 0);
    }
}
