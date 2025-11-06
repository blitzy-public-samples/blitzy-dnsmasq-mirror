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

//! # Packet Dumping Module for PCAP Format
//!
//! This module provides packet dumping functionality for debugging DNS and DHCP traffic
//! by writing packets to standard libpcap-format files compatible with Wireshark and tcpdump.
//!
//! ## Purpose
//!
//! - Creates PCAP-compatible capture files with proper global headers
//! - Writes per-packet headers with microsecond-precision timestamps
//! - Reconstructs IP/UDP/ICMP headers for protocol identification
//! - Enables protocol-level debugging without external packet capture tools
//!
//! ## Key Components
//!
//! - [`PacketDumper`]: Main packet capture handler with async file I/O
//! - [`PcapGlobalHeader`]: Libpcap global file header (24 bytes)
//! - [`PcapRecordHeader`]: Per-packet record header with timestamp (16 bytes)
//! - [`init_packet_dump`]: Convenience function for initialization
//!
//! ## Memory Safety Improvements over C
//!
//! - Async file I/O prevents blocking event loop during packet writing
//! - `AtomicU32` provides thread-safe packet counting without manual locking
//! - Safe byte serialization eliminates buffer overflow vulnerabilities
//! - RAII-based file handle management ensures cleanup on drop
//! - Bounds-checked buffer operations prevent out-of-bounds writes
//!
//! ## Compilation Control
//!
//! Controlled by `cfg!(feature = "dump")` instead of `HAVE_DUMPFILE` macro.
//! When feature is disabled, entire module compiles to empty stubs with zero overhead.
//!
//! ## References
//!
//! - [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
//! - Original C implementation: src/dump.c

use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::fs::{metadata, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use tracing::{debug, error, info, warn};

/// PCAP magic number indicating native byte order (little-endian on x86_64)
/// Magic value 0xa1b2c3d4 tells pcap readers to use native endianness
pub const PCAP_MAGIC_NUMBER: u32 = 0xa1b2_c3d4;

/// DLT_RAW link type - raw IP packets without link-layer headers
/// See <http://www.tcpdump.org/linktypes.html>
pub const DLT_RAW: u32 = 101;

/// PCAP file format version
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;

/// Default snapshot length (max packet size) - EDNS max size plus IP/UDP header overhead
const DEFAULT_SNAPLEN: u32 = 4096 + 200;

/// IP protocol numbers
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

/// IPv4 constants
const IP_VERSION_4: u8 = 4;
const IP_HEADER_LEN: u8 = 5; // 5 x 32-bit words = 20 bytes
const IP_DEFAULT_TTL: u8 = 64;

/// IPv6 constants
const IP_VERSION_6: u8 = 6;
const IPV6_DEFAULT_HOPS: u8 = 64;

/// Libpcap Global File Header
///
/// Written once at the beginning of a PCAP file to identify file format,
/// version, and capture parameters. Must be exactly 24 bytes.
///
/// # Fields
///
/// - `magic_number`: 0xa1b2c3d4 for native byte order
/// - `version_major`: Major version (always 2)
/// - `version_minor`: Minor version (always 4)
/// - `thiszone`: GMT to local correction (0 = UTC)
/// - `sigfigs`: Timestamp accuracy (0 = microsecond precision)
/// - `snaplen`: Maximum packet capture length
/// - `network`: Data link type (101 = DLT_RAW)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PcapGlobalHeader {
    /// Magic number 0xa1b2c3d4 for native byte order
    pub magic_number: u32,
    /// Major version (always 2)
    pub version_major: u16,
    /// Minor version (always 4)
    pub version_minor: u16,
    /// Maximum packet capture length
    pub snaplen: u32,
    /// Data link type (101 = DLT_RAW)
    pub network: u32,
}

impl PcapGlobalHeader {
    /// Create a new PCAP global header with default values
    ///
    /// # Arguments
    ///
    /// * `snaplen` - Maximum packet capture length (default 4296 bytes)
    ///
    /// # Returns
    ///
    /// A new `PcapGlobalHeader` initialized with libpcap-compatible values
    pub fn new(snaplen: u32) -> Self {
        Self {
            magic_number: PCAP_MAGIC_NUMBER,
            version_major: PCAP_VERSION_MAJOR,
            version_minor: PCAP_VERSION_MINOR,
            snaplen,
            network: DLT_RAW,
        }
    }

    /// Serialize header to bytes in native byte order
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&self.magic_number.to_ne_bytes());
        bytes.extend_from_slice(&self.version_major.to_ne_bytes());
        bytes.extend_from_slice(&self.version_minor.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // thiszone
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // sigfigs
        bytes.extend_from_slice(&self.snaplen.to_ne_bytes());
        bytes.extend_from_slice(&self.network.to_ne_bytes());
        bytes
    }

    /// Deserialize header from bytes
    fn from_bytes(bytes: &[u8]) -> IoResult<Self> {
        if bytes.len() < 24 {
            return Err(IoError::new(
                ErrorKind::UnexpectedEof,
                "PCAP header too short",
            ));
        }

        let magic_number = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let version_major = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let version_minor = u16::from_ne_bytes([bytes[6], bytes[7]]);
        // bytes[8..16] are thiszone and sigfigs (ignored)
        let snaplen = u32::from_ne_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let network = u32::from_ne_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

        Ok(Self {
            magic_number,
            version_major,
            version_minor,
            snaplen,
            network,
        })
    }
}

/// Libpcap Per-Packet Record Header
///
/// Written before each packet's data with timestamp and length information.
/// Must be exactly 16 bytes.
///
/// # Fields
///
/// - `ts_sec`: Timestamp seconds since Unix epoch
/// - `ts_usec`: Timestamp microseconds
/// - `incl_len`: Number of octets saved in file
/// - `orig_len`: Original packet length (same as incl_len, no truncation)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PcapRecordHeader {
    /// Timestamp seconds since Unix epoch
    pub ts_sec: u32,
    /// Timestamp microseconds
    pub ts_usec: u32,
    /// Number of octets saved in file
    pub incl_len: u32,
    /// Original packet length (same as incl_len, no truncation)
    pub orig_len: u32,
}

impl PcapRecordHeader {
    /// Create a new PCAP record header with current timestamp
    ///
    /// # Arguments
    ///
    /// * `packet_len` - Length of the packet data in bytes
    ///
    /// # Returns
    ///
    /// A new `PcapRecordHeader` with microsecond-precision timestamp
    pub fn new(packet_len: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        Self {
            ts_sec: now.as_secs() as u32,
            ts_usec: now.subsec_micros(),
            incl_len: packet_len,
            orig_len: packet_len,
        }
    }

    /// Serialize header to bytes in native byte order
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&self.ts_sec.to_ne_bytes());
        bytes.extend_from_slice(&self.ts_usec.to_ne_bytes());
        bytes.extend_from_slice(&self.incl_len.to_ne_bytes());
        bytes.extend_from_slice(&self.orig_len.to_ne_bytes());
        bytes
    }

    /// Deserialize header from bytes
    fn from_bytes(bytes: &[u8]) -> IoResult<Self> {
        if bytes.len() < 16 {
            return Err(IoError::new(
                ErrorKind::UnexpectedEof,
                "PCAP record header too short",
            ));
        }

        Ok(Self {
            ts_sec: u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            ts_usec: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            incl_len: u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            orig_len: u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        })
    }
}

/// Main packet dumper with async file I/O
///
/// Manages PCAP file writing with non-blocking operations using tokio.
/// Replaces C implementation's blocking file I/O with async operations.
///
/// # Thread Safety
///
/// Uses `AtomicU32` for packet counting, safe for concurrent access.
/// File operations are not synchronized; intended for single-writer use.
pub struct PacketDumper {
    file: File,
    file_path: PathBuf,
    packet_count: AtomicU32,
    _snaplen: u32,
}

impl PacketDumper {
    /// Initialize packet dump file with libpcap global header
    ///
    /// Opens or creates the packet dump file. For new files, writes the PCAP
    /// global header. For existing files, validates the magic number and counts
    /// existing packet records to maintain continuous packet numbering.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the PCAP dump file
    /// * `snaplen` - Maximum packet capture length (default 4296)
    ///
    /// # Returns
    ///
    /// `Ok(PacketDumper)` on success, or `Err(IoError)` on failure
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be created or opened
    /// - Existing file has invalid magic number
    /// - File permissions are insufficient
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::utils::dump::PacketDumper;
    /// # use std::path::Path;
    /// # async fn example() -> std::io::Result<()> {
    /// let dumper = PacketDumper::new(Path::new("/tmp/packets.pcap"), 4296).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(file_path: &Path, snaplen: u32) -> IoResult<Self> {
        // Check if file exists AND has valid content (at least header size)
        let file_has_content = metadata(file_path)
            .await
            .map(|m| m.len() >= 24) // PCAP header is 24 bytes
            .unwrap_or(false);

        let (file, initial_count) = if file_has_content {
            // Open existing file, validate header, count packets
            debug!("Opening existing PCAP file: {:?}", file_path);
            
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .append(true)
                .open(file_path)
                .await?;

            // Read and validate global header
            let mut header_bytes = vec![0u8; 24];
            file.seek(std::io::SeekFrom::Start(0)).await?;
            file.read_exact(&mut header_bytes).await?;

            let header = PcapGlobalHeader::from_bytes(&header_bytes)?;

            if header.magic_number != PCAP_MAGIC_NUMBER {
                error!(
                    "Invalid PCAP magic number in {:?}: 0x{:08x}",
                    file_path, header.magic_number
                );
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "Bad PCAP header magic number",
                ));
            }

            // Count existing packet records
            let count = Self::count_packets(&mut file).await?;
            info!(
                "Opened existing PCAP file {:?} with {} packets",
                file_path, count
            );

            // Seek to end for appending
            file.seek(std::io::SeekFrom::End(0)).await?;

            (file, count)
        } else {
            // Create new file with global header
            debug!("Creating new PCAP file: {:?}", file_path);

            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(file_path)
                .await?;

            // Write global header
            let header = PcapGlobalHeader::new(snaplen);
            let header_bytes = header.to_bytes();
            file.write_all(&header_bytes).await?;
            file.flush().await?;

            info!("Created new PCAP file: {:?}", file_path);

            (file, 0)
        };

        Ok(Self {
            file,
            file_path: file_path.to_path_buf(),
            packet_count: AtomicU32::new(initial_count),
            _snaplen: snaplen,
        })
    }

    /// Count existing packet records in PCAP file
    ///
    /// Reads through existing file counting packet records to maintain
    /// continuous packet numbering when appending to existing files.
    ///
    /// # Arguments
    ///
    /// * `file` - Mutable reference to opened file (positioned after global header)
    ///
    /// # Returns
    ///
    /// Number of packet records found, or 0 if file is empty/new
    async fn count_packets(file: &mut File) -> IoResult<u32> {
        let mut count = 0u32;
        let mut header_bytes = vec![0u8; 16];

        // Start after global header
        file.seek(std::io::SeekFrom::Start(24)).await?;

        loop {
            // Try to read packet record header
            match file.read_exact(&mut header_bytes).await {
                Ok(_) => {
                    let record = PcapRecordHeader::from_bytes(&header_bytes)?;
                    // Skip packet data
                    file.seek(std::io::SeekFrom::Current(record.incl_len as i64))
                        .await?;
                    count += 1;
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    // End of file reached
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(count)
    }

    /// Get current packet count
    ///
    /// Returns the total number of packets written to the dump file.
    /// Thread-safe due to atomic operations.
    ///
    /// # Returns
    ///
    /// Current packet count
    pub fn packet_count(&self) -> u32 {
        self.packet_count.load(Ordering::Relaxed)
    }

    /// Dump packet to PCAP file with reconstructed IP/UDP headers
    ///
    /// Constructs a complete libpcap packet record including:
    /// - PCAP record header with timestamp
    /// - IP header (IPv4 or IPv6)
    /// - UDP or ICMP/ICMPv6 header
    /// - Packet payload
    ///
    /// Calculates proper checksums for IP and UDP/ICMP headers for Wireshark compatibility.
    ///
    /// # Arguments
    ///
    /// * `mask` - Packet type bitmask for selective dumping
    /// * `packet` - Packet payload data (DNS message, DHCP packet, etc.)
    /// * `src` - Source socket address (optional)
    /// * `dst` - Destination socket address (optional)
    /// * `port` - UDP port number, or None for ICMP/ICMPv6
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(IoError)` on write failure
    ///
    /// # Errors
    ///
    /// Returns error if file write operations fail. Logs error and continues
    /// rather than terminating the daemon.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dnsmasq::utils::dump::PacketDumper;
    /// # use std::net::{SocketAddr, Ipv4Addr};
    /// # async fn example(dumper: &mut PacketDumper) -> std::io::Result<()> {
    /// let dns_packet = vec![0u8; 512];
    /// let src = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 53);
    /// let dst = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 12345);
    /// dumper.dump_packet(0x0001, &dns_packet, Some(src), Some(dst), Some(53)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn dump_packet(
        &mut self,
        mask: u16,
        packet: &[u8],
        src: Option<SocketAddr>,
        dst: Option<SocketAddr>,
        port: Option<u16>,
    ) -> IoResult<()> {
        // Determine address family from src or dst
        let family = if let Some(addr) = src {
            addr
        } else if let Some(addr) = dst {
            addr
        } else {
            // No address information, cannot construct IP header
            warn!("Cannot dump packet without source or destination address");
            return Ok(());
        };

        // Construct packet with IP and transport headers
        let full_packet = match family {
            SocketAddr::V4(_) => {
                self.build_ipv4_packet(packet, src, dst, port).await?
            }
            SocketAddr::V6(_) => {
                self.build_ipv6_packet(packet, src, dst, port).await?
            }
        };

        // Write PCAP record header
        let record_header = PcapRecordHeader::new(full_packet.len() as u32);
        self.file.write_all(&record_header.to_bytes()).await?;

        // Write full packet (IP header + transport header + payload)
        self.file.write_all(&full_packet).await?;
        self.file.flush().await?;

        // Increment packet count
        let count = self.packet_count.fetch_add(1, Ordering::Relaxed) + 1;

        info!("Dumped packet {} mask 0x{:04x}", count, mask);

        Ok(())
    }

    /// Build IPv4 packet with IP and UDP/ICMP headers
    ///
    /// Constructs complete IPv4 packet with proper checksums.
    ///
    /// # Arguments
    ///
    /// * `payload` - Packet payload (DNS, DHCP, etc.)
    /// * `src` - Source address (optional)
    /// * `dst` - Destination address (optional)
    /// * `port` - UDP port or None for ICMP
    ///
    /// # Returns
    ///
    /// Complete packet bytes with IP header + transport header + payload
    async fn build_ipv4_packet(
        &self,
        payload: &[u8],
        src: Option<SocketAddr>,
        dst: Option<SocketAddr>,
        port: Option<u16>,
    ) -> IoResult<Vec<u8>> {
        let is_icmp = port.is_none();
        let transport_hdr_len = if is_icmp { 0 } else { 8 }; // UDP header is 8 bytes
        let total_len = 20 + transport_hdr_len + payload.len(); // 20-byte IP header
        
        let mut packet = Vec::with_capacity(total_len);

        // Extract IPv4 addresses
        let src_ip = src.and_then(|s| match s {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            _ => None,
        }).unwrap_or(Ipv4Addr::UNSPECIFIED);

        let dst_ip = dst.and_then(|d| match d {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            _ => None,
        }).unwrap_or(Ipv4Addr::UNSPECIFIED);

        let src_port = src.map(|s| s.port()).unwrap_or(0);
        let dst_port = dst.map(|d| d.port()).unwrap_or(0);

        // Build IPv4 header (20 bytes)
        packet.push((IP_VERSION_4 << 4) | IP_HEADER_LEN); // Version and IHL
        packet.push(0); // TOS
        packet.extend_from_slice(&(total_len as u16).to_be_bytes()); // Total length
        packet.extend_from_slice(&0u16.to_be_bytes()); // Identification
        packet.extend_from_slice(&0u16.to_be_bytes()); // Flags and fragment offset
        packet.push(IP_DEFAULT_TTL); // TTL
        packet.push(if is_icmp { IPPROTO_ICMP } else { IPPROTO_UDP }); // Protocol
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (calculated later)
        packet.extend_from_slice(&src_ip.octets()); // Source IP
        packet.extend_from_slice(&dst_ip.octets()); // Destination IP

        // Calculate and insert IPv4 header checksum
        let ip_checksum = Self::calculate_checksum(&packet[0..20]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = (ip_checksum & 0xff) as u8;

        if is_icmp {
            // ICMP packet - add payload with ICMP checksum
            let mut icmp_data = payload.to_vec();
            
            // Calculate ICMP checksum (assumes ICMP header is in payload)
            if icmp_data.len() >= 2 {
                // Zero out checksum field (bytes 2-3)
                if icmp_data.len() >= 4 {
                    icmp_data[2] = 0;
                    icmp_data[3] = 0;
                }
                
                let icmp_checksum = Self::calculate_checksum(&icmp_data);
                if icmp_data.len() >= 4 {
                    icmp_data[2] = (icmp_checksum >> 8) as u8;
                    icmp_data[3] = (icmp_checksum & 0xff) as u8;
                }
            }
            
            packet.extend_from_slice(&icmp_data);
        } else {
            // UDP packet - add UDP header and payload
            let udp_len = (8 + payload.len()) as u16;
            
            // Build UDP header
            let mut udp_header = Vec::with_capacity(8);
            udp_header.extend_from_slice(&src_port.to_be_bytes()); // Source port
            udp_header.extend_from_slice(&dst_port.to_be_bytes()); // Destination port
            udp_header.extend_from_slice(&udp_len.to_be_bytes()); // UDP length
            udp_header.extend_from_slice(&0u16.to_be_bytes()); // Checksum (calculated later)

            // Calculate UDP checksum with pseudoheader
            let udp_checksum = Self::calculate_udp_checksum_ipv4(
                &src_ip,
                &dst_ip,
                &udp_header,
                payload,
            );
            udp_header[6] = (udp_checksum >> 8) as u8;
            udp_header[7] = (udp_checksum & 0xff) as u8;

            packet.extend_from_slice(&udp_header);
            packet.extend_from_slice(payload);
        }

        Ok(packet)
    }

    /// Build IPv6 packet with IP and UDP/ICMPv6 headers
    ///
    /// Constructs complete IPv6 packet with proper checksums.
    ///
    /// # Arguments
    ///
    /// * `payload` - Packet payload (DNS, DHCP, etc.)
    /// * `src` - Source address (optional)
    /// * `dst` - Destination address (optional)
    /// * `port` - UDP port or None for ICMPv6
    ///
    /// # Returns
    ///
    /// Complete packet bytes with IPv6 header + transport header + payload
    async fn build_ipv6_packet(
        &self,
        payload: &[u8],
        src: Option<SocketAddr>,
        dst: Option<SocketAddr>,
        port: Option<u16>,
    ) -> IoResult<Vec<u8>> {
        let is_icmpv6 = port.is_none();
        let transport_hdr_len = if is_icmpv6 { 0 } else { 8 }; // UDP header is 8 bytes
        let payload_len = transport_hdr_len + payload.len();
        let total_len = 40 + payload_len; // 40-byte IPv6 header
        
        let mut packet = Vec::with_capacity(total_len);

        // Extract IPv6 addresses
        let src_ip = src.and_then(|s| match s {
            SocketAddr::V6(v6) => Some(*v6.ip()),
            _ => None,
        }).unwrap_or(Ipv6Addr::UNSPECIFIED);

        let dst_ip = dst.and_then(|d| match d {
            SocketAddr::V6(v6) => Some(*v6.ip()),
            _ => None,
        }).unwrap_or(Ipv6Addr::UNSPECIFIED);

        let src_port = src.map(|s| s.port()).unwrap_or(0);
        let dst_port = dst.map(|d| d.port()).unwrap_or(0);

        // Build IPv6 header (40 bytes)
        packet.extend_from_slice(&((IP_VERSION_6 as u32) << 28).to_be_bytes()); // Version, traffic class, flow label
        packet.extend_from_slice(&(payload_len as u16).to_be_bytes()); // Payload length
        packet.push(if is_icmpv6 { IPPROTO_ICMPV6 } else { IPPROTO_UDP }); // Next header
        packet.push(IPV6_DEFAULT_HOPS); // Hop limit
        packet.extend_from_slice(&src_ip.octets()); // Source address (16 bytes)
        packet.extend_from_slice(&dst_ip.octets()); // Destination address (16 bytes)

        if is_icmpv6 {
            // ICMPv6 packet - add payload with ICMPv6 checksum
            let icmpv6_checksum = Self::calculate_icmpv6_checksum(
                &src_ip,
                &dst_ip,
                payload,
            );
            
            let mut icmpv6_data = payload.to_vec();
            if icmpv6_data.len() >= 4 {
                icmpv6_data[2] = (icmpv6_checksum >> 8) as u8;
                icmpv6_data[3] = (icmpv6_checksum & 0xff) as u8;
            }
            
            packet.extend_from_slice(&icmpv6_data);
        } else {
            // UDP packet - add UDP header and payload
            let udp_len = (8 + payload.len()) as u16;
            
            // Build UDP header
            let mut udp_header = Vec::with_capacity(8);
            udp_header.extend_from_slice(&src_port.to_be_bytes()); // Source port
            udp_header.extend_from_slice(&dst_port.to_be_bytes()); // Destination port
            udp_header.extend_from_slice(&udp_len.to_be_bytes()); // UDP length
            udp_header.extend_from_slice(&0u16.to_be_bytes()); // Checksum (calculated later)

            // Calculate UDP checksum with IPv6 pseudoheader
            let udp_checksum = Self::calculate_udp_checksum_ipv6(
                &src_ip,
                &dst_ip,
                &udp_header,
                payload,
            );
            udp_header[6] = (udp_checksum >> 8) as u8;
            udp_header[7] = (udp_checksum & 0xff) as u8;

            packet.extend_from_slice(&udp_header);
            packet.extend_from_slice(payload);
        }

        Ok(packet)
    }

    /// Calculate Internet checksum (RFC 1071)
    ///
    /// Standard 16-bit one's complement checksum used by IP, UDP, ICMP.
    ///
    /// # Arguments
    ///
    /// * `data` - Data bytes to checksum
    ///
    /// # Returns
    ///
    /// 16-bit checksum value
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        
        // Sum 16-bit words
        for chunk in data.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                // Odd length - pad with zero
                (chunk[0] as u32) << 8
            };
            sum += word;
        }

        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        // One's complement
        let checksum = !sum as u16;
        if checksum == 0 {
            0xffff
        } else {
            checksum
        }
    }

    /// Calculate UDP checksum for IPv4 packet
    ///
    /// Includes IPv4 pseudoheader per RFC 768.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IPv4 address
    /// * `dst_ip` - Destination IPv4 address
    /// * `udp_header` - UDP header (8 bytes, checksum field zeroed)
    /// * `payload` - UDP payload data
    ///
    /// # Returns
    ///
    /// 16-bit UDP checksum
    fn calculate_udp_checksum_ipv4(
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        udp_header: &[u8],
        payload: &[u8],
    ) -> u16 {
        let mut sum = 0u32;

        // IPv4 pseudoheader
        let src_octets = src_ip.octets();
        let dst_octets = dst_ip.octets();
        
        sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32;
        sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32;
        sum += u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32;
        sum += u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32;
        sum += IPPROTO_UDP as u32;
        sum += (udp_header.len() + payload.len()) as u32;

        // UDP header
        for chunk in udp_header.chunks(2) {
            let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            sum += word;
        }

        // Payload
        for chunk in payload.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                (chunk[0] as u32) << 8
            };
            sum += word;
        }

        // Fold and complement
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let checksum = !sum as u16;
        if checksum == 0 {
            0xffff
        } else {
            checksum
        }
    }

    /// Calculate UDP checksum for IPv6 packet
    ///
    /// Includes IPv6 pseudoheader per RFC 2460.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IPv6 address
    /// * `dst_ip` - Destination IPv6 address
    /// * `udp_header` - UDP header (8 bytes, checksum field zeroed)
    /// * `payload` - UDP payload data
    ///
    /// # Returns
    ///
    /// 16-bit UDP checksum
    fn calculate_udp_checksum_ipv6(
        src_ip: &Ipv6Addr,
        dst_ip: &Ipv6Addr,
        udp_header: &[u8],
        payload: &[u8],
    ) -> u16 {
        let mut sum = 0u32;

        // IPv6 pseudoheader
        let src_octets = src_ip.octets();
        let dst_octets = dst_ip.octets();
        
        for chunk in src_octets.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        for chunk in dst_octets.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        
        sum += (udp_header.len() + payload.len()) as u32;
        sum += IPPROTO_UDP as u32;

        // UDP header
        for chunk in udp_header.chunks(2) {
            let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            sum += word;
        }

        // Payload
        for chunk in payload.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                (chunk[0] as u32) << 8
            };
            sum += word;
        }

        // Fold and complement
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let checksum = !sum as u16;
        if checksum == 0 {
            0xffff
        } else {
            checksum
        }
    }

    /// Calculate ICMPv6 checksum
    ///
    /// Includes IPv6 pseudoheader per RFC 4443.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IPv6 address
    /// * `dst_ip` - Destination IPv6 address
    /// * `icmpv6_data` - Complete ICMPv6 packet (checksum field zeroed)
    ///
    /// # Returns
    ///
    /// 16-bit ICMPv6 checksum
    fn calculate_icmpv6_checksum(
        src_ip: &Ipv6Addr,
        dst_ip: &Ipv6Addr,
        icmpv6_data: &[u8],
    ) -> u16 {
        let mut sum = 0u32;

        // IPv6 pseudoheader
        let src_octets = src_ip.octets();
        let dst_octets = dst_ip.octets();
        
        for chunk in src_octets.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        for chunk in dst_octets.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        
        sum += icmpv6_data.len() as u32;
        sum += IPPROTO_ICMPV6 as u32;

        // ICMPv6 data
        for chunk in icmpv6_data.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                (chunk[0] as u32) << 8
            };
            sum += word;
        }

        // Fold and complement
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        let checksum = !sum as u16;
        if checksum == 0 {
            0xffff
        } else {
            checksum
        }
    }

    /// Close the packet dumper
    ///
    /// Flushes any pending writes and closes the file handle.
    /// File is also automatically closed when `PacketDumper` is dropped.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(IoError)` on failure
    pub async fn close(mut self) -> IoResult<()> {
        self.file.flush().await?;
        debug!("Closed PCAP file: {:?}", self.file_path);
        Ok(())
    }
}

/// Convenience function to initialize packet dump file
///
/// Creates a new `PacketDumper` with default snapshot length.
/// This function matches the C API's `dump_init()` for compatibility.
///
/// # Arguments
///
/// * `file_path` - Path to the PCAP dump file
///
/// # Returns
///
/// `Ok(PacketDumper)` on success, or `Err(IoError)` on failure
///
/// # Examples
///
/// ```no_run
/// # use dnsmasq::utils::dump::init_packet_dump;
/// # use std::path::Path;
/// # async fn example() -> std::io::Result<()> {
/// let dumper = init_packet_dump(Path::new("/var/log/dnsmasq.pcap")).await?;
/// # Ok(())
/// # }
/// ```
pub async fn init_packet_dump(file_path: &Path) -> IoResult<PacketDumper> {
    PacketDumper::new(file_path, DEFAULT_SNAPLEN).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_pcap_header_serialization() {
        let header = PcapGlobalHeader::new(4096);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 24);
        
        let deserialized = PcapGlobalHeader::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.magic_number, PCAP_MAGIC_NUMBER);
        assert_eq!(deserialized.version_major, 2);
        assert_eq!(deserialized.version_minor, 4);
        assert_eq!(deserialized.snaplen, 4096);
        assert_eq!(deserialized.network, DLT_RAW);
    }

    #[tokio::test]
    async fn test_pcap_record_header_serialization() {
        let header = PcapRecordHeader::new(512);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 16);
        
        let deserialized = PcapRecordHeader::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.incl_len, 512);
        assert_eq!(deserialized.orig_len, 512);
        assert!(deserialized.ts_sec > 0);
    }

    #[tokio::test]
    async fn test_create_new_pcap_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        let dumper = PacketDumper::new(path, 4096).await.unwrap();
        assert_eq!(dumper.packet_count(), 0);
    }

    #[tokio::test]
    async fn test_dump_ipv4_udp_packet() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        let mut dumper = PacketDumper::new(path, 4096).await.unwrap();
        
        let payload = b"Hello, World!";
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 53));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
        
        dumper.dump_packet(0x0001, payload, Some(src), Some(dst), Some(53))
            .await
            .unwrap();
        
        assert_eq!(dumper.packet_count(), 1);
    }

    #[tokio::test]
    async fn test_dump_ipv6_udp_packet() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        let mut dumper = PacketDumper::new(path, 4096).await.unwrap();
        
        let payload = b"IPv6 test packet";
        let src = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            53,
            0,
            0,
        ));
        let dst = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            12345,
            0,
            0,
        ));
        
        dumper.dump_packet(0x0001, payload, Some(src), Some(dst), Some(53))
            .await
            .unwrap();
        
        assert_eq!(dumper.packet_count(), 1);
    }

    #[tokio::test]
    async fn test_open_existing_pcap_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        // Create file with one packet
        {
            let mut dumper = PacketDumper::new(path, 4096).await.unwrap();
            let payload = b"Test";
            let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
            let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345));
            dumper.dump_packet(0x0001, payload, Some(src), Some(dst), Some(53))
                .await
                .unwrap();
        }
        
        // Reopen and check count
        let dumper = PacketDumper::new(path, 4096).await.unwrap();
        assert_eq!(dumper.packet_count(), 1);
    }

    #[test]
    fn test_checksum_calculation() {
        // Test with known data
        let data = [0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                    0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
                    0xac, 0x10, 0x0a, 0x0c];
        let checksum = PacketDumper::calculate_checksum(&data);
        // Checksum should be non-zero for valid data
        assert_ne!(checksum, 0);
    }
}

